/// Tests for compute_overlay_info — detecting trailing data appended after
/// the last PE section ("overlay"): common in SFX archives, installers,
/// and Authenticode-signed binaries.

use std::path::PathBuf;
use goblin::Object;
use sha2::Digest;
use sigil::analyzer::{compute_overlay_info, read_file, shannon_entropy};

fn fixture(name: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures");
    p.push(name);
    p.to_string_lossy().to_string()
}

#[test]
fn minimal_pe_has_no_overlay() {
    // Our hand-crafted minimal PE ends exactly at the end of .data —
    // there should be no overlay.
    let data = read_file(&fixture("minimal.exe"), false).unwrap();
    let pe = match Object::parse(&data).unwrap() {
        Object::PE(pe) => pe,
        _ => panic!("expected PE"),
    };
    let overlay = compute_overlay_info(&data, &pe.sections);
    assert!(overlay.is_none(), "minimal PE should have no overlay, got {:?}", overlay);
}

#[test]
fn appended_bytes_are_detected_as_overlay() {
    // Take the minimal PE and append extra bytes — these should be
    // reported as an overlay with the correct offset/size/hash/entropy.
    let mut data = read_file(&fixture("minimal.exe"), false).unwrap();
    let original_len = data.len();

    let extra = b"THIS_IS_OVERLAY_DATA_APPENDED_AFTER_SECTIONS";
    data.extend_from_slice(extra);

    let pe = match Object::parse(&data).unwrap() {
        Object::PE(pe) => pe,
        _ => panic!("expected PE"),
    };
    let overlay = compute_overlay_info(&data, &pe.sections)
        .expect("expected an overlay after appending bytes");

    assert_eq!(overlay.offset, original_len as u64);
    assert_eq!(overlay.size, extra.len() as u64);
    assert_eq!(overlay.sha256, format!("{:x}", sha2::Sha256::digest(extra)));
    assert!((overlay.entropy - shannon_entropy(extra)).abs() < 1e-9);
}

#[test]
fn empty_sections_list_does_not_panic() {
    let data = vec![0u8; 100];
    let overlay = compute_overlay_info(&data, &[]);
    // last_end stays 0, which is excluded by the `last_end > 0` check
    assert!(overlay.is_none());
}
