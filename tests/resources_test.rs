use goblin::Object;
use sigil::analyzer::{parse_pe_resources, pe_data_directory, read_file};
/// Tests for parse_pe_resources — walking the PE resource directory tree
/// to find VS_VERSIONINFO (RT_VERSION) and RT_ICON resources.
use std::path::PathBuf;

fn fixture(name: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures");
    p.push(name);
    p.to_string_lossy().to_string()
}

#[test]
fn minimal_pe_has_no_resource_directory() {
    let data = read_file(&fixture("minimal.exe"), false).unwrap();
    let pe = match Object::parse(&data).unwrap() {
        Object::PE(pe) => pe,
        _ => panic!("expected PE"),
    };
    let lfanew = pe.header.dos_header.pe_pointer;

    // Confirm directly: data directory 2 (resources) is zero in our fixture
    let (rsrc_rva, _) = pe_data_directory(&data, lfanew, 2);
    assert_eq!(rsrc_rva, 0);

    let (version_info, icon_hashes) = parse_pe_resources(&data, lfanew, &pe.sections);
    assert!(version_info.is_none());
    assert!(icon_hashes.is_empty());
}

#[test]
fn out_of_bounds_lfanew_returns_empty_without_panic() {
    let data = vec![0u8; 32];
    let (vi, icons) = parse_pe_resources(&data, 0x9999, &[]);
    assert!(vi.is_none());
    assert!(icons.is_empty());
}

#[test]
fn nonzero_rva_with_unresolvable_section_returns_empty() {
    // Build a buffer where data directory 2 has a non-zero RVA, but no
    // section covers that RVA — rva_to_offset returns None, and
    // parse_pe_resources must handle that gracefully.
    let lfanew = 0x80u32;
    let mut data = vec![0u8; 0x200];
    data[lfanew as usize..lfanew as usize + 4].copy_from_slice(b"PE\0\0");
    let opt_off = lfanew as usize + 4 + 20;
    data[opt_off..opt_off + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
    let dd_base = opt_off + 112;
    let rsrc_dir_off = dd_base + 2 * 8;
    // Non-zero RVA, but `sections` is empty so it can't be resolved
    data[rsrc_dir_off..rsrc_dir_off + 4].copy_from_slice(&0x5000u32.to_le_bytes());
    data[rsrc_dir_off + 4..rsrc_dir_off + 8].copy_from_slice(&0x100u32.to_le_bytes());

    let (vi, icons) = parse_pe_resources(&data, lfanew, &[]);
    assert!(vi.is_none());
    assert!(icons.is_empty());
}
