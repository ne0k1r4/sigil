use sigil::analyzer::{parse_authenticode, pe_data_directory, read_file};
/// Tests for parse_authenticode and pe_data_directory — Authenticode
/// certificate table detection and heuristic identity-string extraction.
///
/// NOTE: parse_authenticode is a triage signal only (presence + readable
/// strings from the cert blob), not signature verification.
use std::path::PathBuf;

fn fixture(name: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures");
    p.push(name);
    p.to_string_lossy().to_string()
}

#[test]
fn minimal_pe_is_not_signed() {
    let data = read_file(&fixture("minimal.exe"), false).unwrap();
    let lfanew = 64u32; // matches the fixture generator
    assert!(parse_authenticode(&data, lfanew).is_none());
}

#[test]
fn pe_data_directory_out_of_bounds_returns_zero() {
    let data = vec![0u8; 16];
    let (rva, size) = pe_data_directory(&data, 0x1000, 4);
    assert_eq!((rva, size), (0, 0));
}

#[test]
fn synthetic_certificate_table_extracts_identity_strings() {
    // Build a minimal PE32+ optional header skeleton with a certificate
    // table data directory (index 4) pointing at a fake WIN_CERTIFICATE
    // containing readable "identity-like" strings, as would appear inside
    // a DER-encoded X.509 certificate's Subject/Issuer fields.
    let lfanew = 0x80u32;
    let mut data = vec![0u8; 0x400];

    // PE signature at lfanew
    data[lfanew as usize..lfanew as usize + 4].copy_from_slice(b"PE\0\0");
    // Optional header magic (PE32+) at lfanew+4+20
    let opt_off = lfanew as usize + 4 + 20;
    data[opt_off..opt_off + 2].copy_from_slice(&0x20Bu16.to_le_bytes());

    // Data directories start at opt_off + 112 for PE32+; cert table is index 4
    let dd_base = opt_off + 112;
    let cert_dir_off = dd_base + 4 * 8;

    // Place the WIN_CERTIFICATE at file offset 0x300
    let cert_off: u32 = 0x300;
    let cert_blob = b"O=Acme Corporation, CN=Acme Code Signing CA, C=US";
    let dw_length: u32 = 8 + cert_blob.len() as u32;

    data[cert_dir_off..cert_dir_off + 4].copy_from_slice(&cert_off.to_le_bytes());
    data[cert_dir_off + 4..cert_dir_off + 8].copy_from_slice(&dw_length.to_le_bytes());

    // WIN_CERTIFICATE header: dwLength, wRevision, wCertificateType
    let co = cert_off as usize;
    data[co..co + 4].copy_from_slice(&dw_length.to_le_bytes());
    data[co + 4..co + 6].copy_from_slice(&0x0200u16.to_le_bytes()); // WIN_CERT_REVISION_2_0
    data[co + 6..co + 8].copy_from_slice(&0x0002u16.to_le_bytes()); // WIN_CERT_TYPE_PKCS_SIGNED_DATA
    data[co + 8..co + 8 + cert_blob.len()].copy_from_slice(cert_blob);

    let auth = parse_authenticode(&data, lfanew).expect("expected Authenticode info");
    assert_eq!(auth.cert_revision, 0x0200);
    assert_eq!(auth.cert_type, 0x0002);
    assert_eq!(auth.size, dw_length);

    // The cert blob's readable strings should surface as candidate identities
    let joined = auth.candidate_identities.join(" ");
    assert!(
        joined.contains("Acme"),
        "expected 'Acme' in candidate identities, got: {:?}",
        auth.candidate_identities
    );
}

#[test]
fn zero_cert_directory_returns_none() {
    let data = vec![0u8; 512];
    // lfanew=64, but data directory 4 is all zero -> None
    assert!(parse_authenticode(&data, 64).is_none());
}
