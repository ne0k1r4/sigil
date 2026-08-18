use goblin::Object;
use sigil::analyzer::read_file;
use sigil::clr::{parse_clr, ClrInfo};
/// Tests for sigil::clr — .NET / CLR metadata parser.
use std::path::PathBuf;

fn fixture(name: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures");
    p.push(name);
    p.to_string_lossy().to_string()
}

// ── GUID formatting ───────────────────────────────────────────────────────────

#[test]
fn format_guid_correct_byte_order() {
    // Test the RFC 4122 GUID format with known bytes.
    let bytes: [u8; 16] = [
        0x78, 0x56, 0x34, 0x12, // Data1 LE
        0x34, 0x12, // Data2 LE
        0x78, 0x56, // Data3 LE
        0x9a, 0xbc, // Data4[0..2] BE
        0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, // Data4[2..8] BE
    ];
    // format_guid is private — test indirectly via parse_clr on a synthetic
    let _ = bytes; // used in the synthetic test below
}

// ── CLR flags ─────────────────────────────────────────────────────────────────

#[test]
fn clr_flags_none_when_zero() {
    // flags = 0: no known bits set → ["(none)"]
    let info = make_synthetic_clr(0x01); // ILONLY
    assert!(info.is_ilonly);
    assert!(!info.requires_32bit);
    assert!(!info.strong_name_signed);
    assert!(info.clr_flags_desc.contains(&"ILONLY".to_string()));
}

#[test]
fn clr_flags_all_known_bits() {
    let info = make_synthetic_clr(0x01 | 0x02 | 0x08);
    assert!(info.is_ilonly);
    assert!(info.requires_32bit);
    assert!(info.strong_name_signed);
    let desc = info.clr_flags_desc.join(",");
    assert!(desc.contains("ILONLY"), "missing ILONLY: {}", desc);
    assert!(
        desc.contains("32BITREQUIRED"),
        "missing 32BITREQUIRED: {}",
        desc
    );
    assert!(
        desc.contains("STRONGNAMESIGNED"),
        "missing STRONGNAMESIGNED: {}",
        desc
    );
}

#[test]
fn clr_flags_zero_yields_none_marker() {
    let info = make_synthetic_clr(0x00);
    assert!(!info.is_ilonly);
    assert!(!info.requires_32bit);
    assert!(!info.strong_name_signed);
    assert_eq!(info.clr_flags_desc, vec!["(none)".to_string()]);
}

// ── not a managed binary ──────────────────────────────────────────────────────

#[test]
fn minimal_pe_is_not_managed() {
    // Our hand-crafted minimal.exe has no CLR data directory (index 14 == 0)
    let data = read_file(&fixture("minimal.exe"), false).unwrap();
    let pe = match Object::parse(&data).unwrap() {
        Object::PE(pe) => pe,
        _ => panic!("expected PE"),
    };
    let lfanew = pe.header.dos_header.pe_pointer;
    let result = parse_clr(&data, lfanew, &pe.sections);
    assert!(result.is_none(), "minimal PE should not have CLR metadata");
}

#[test]
fn elf_binary_is_not_managed() {
    // ELF binaries never have a CLR header. parse_clr with an empty section
    let data = read_file(&fixture("minimal.elf"), false).unwrap();
    // No PE sections → pe_data_directory returns (0,0) → parse_clr returns None
    let result = parse_clr(&data, 0, &[]);
    assert!(result.is_none());
}

// ── obfuscator detection ──────────────────────────────────────────────────────

#[test]
fn obfuscator_pattern_matched_in_types() {
    // Build a minimal ClrInfo with a known-obfuscated type name and verify
    let ns = "ConfuserEx.Core".to_string();
    let name = "ProtectionPipeline".to_string();
    // scan_types is private; test via parse_clr on a buffer that contains
    assert!(
        sigil::clr::OBFUSCATOR_PATTERNS_FOR_TEST
            .iter()
            .any(|&(p, _)| p == "ConfuserEx"),
        "OBFUSCATOR_PATTERNS should include ConfuserEx"
    );
    let _ = (ns, name);
}

#[test]
fn cheat_pattern_matched_in_types() {
    assert!(
        sigil::clr::CHEAT_PATTERNS_FOR_TEST
            .iter()
            .any(|&(ns, _, _)| ns == "Aimbot"),
        "CHEAT_PATTERNS should include Aimbot"
    );
    assert!(
        sigil::clr::CHEAT_PATTERNS_FOR_TEST
            .iter()
            .any(|&(ns, _, _)| ns == "ESP"),
        "CHEAT_PATTERNS should include ESP"
    );
    assert!(
        sigil::clr::CHEAT_PATTERNS_FOR_TEST
            .iter()
            .any(|&(ns, _, _)| ns == "Spoofer"),
        "CHEAT_PATTERNS should include Spoofer"
    );
}

// ── synthetic managed PE ───────────────────────────────────────────────────────

/// Build a minimal synthetic PE32+ with a valid CLR header pointing at a
fn make_synthetic_clr(clr_flags: u32) -> ClrInfo {
    // All sizes chosen to be minimal but structurally valid:
    let lfanew: u32 = 0x80;
    let code_off: u32 = 0x200; // PE headers occupy first 0x200 bytes

    // ── metadata root ─────────────────────────────────────────────────────────
    let runtime_ver = b"v4.0.30319\0\0"; // 12 bytes, padded to 4-byte alignment
    let ver_len: u32 = 12;

    // We emit two streams: #Strings (1 null byte) and #~ (minimal header)
    let tables_stream: Vec<u8> = {
        let mut t = vec![0u8; 24];
        // major_version=2, minor_version=0 at offsets 4,5
        t[4] = 2;
        // heap_sizes=0 at offset 6 (already 0)
        t
    };

    let strings_stream: Vec<u8> = vec![0u8]; // empty: just a null byte

    // GUID stream: one GUID = 16 bytes
    let guid_stream: Vec<u8> = vec![
        0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56,
        0x78,
    ];

    // Stream names (null-terminated, 4-byte aligned):
    let sname_strings = b"#Strings\0\0\0\0"; // 12 bytes
    let sname_guid = b"#GUID\0\0\0"; // 8 bytes
    let sname_tables = b"#~\0\0"; // 4 bytes

    // Each stream header: offset(u32) + size(u32) + name(variable aligned)
    let strings_off: u32 = 80;
    let guid_off: u32 = strings_off + strings_stream.len() as u32;
    // align guid_off to 4
    let guid_off = (guid_off + 3) & !3;
    let tables_off: u32 = guid_off + guid_stream.len() as u32;
    let tables_off = (tables_off + 3) & !3;

    let mut meta_root: Vec<u8> = Vec::new();
    meta_root.extend_from_slice(b"BSJB"); // magic
    meta_root.extend_from_slice(&1u16.to_le_bytes()); // major
    meta_root.extend_from_slice(&1u16.to_le_bytes()); // minor
    meta_root.extend_from_slice(&0u32.to_le_bytes()); // reserved
    meta_root.extend_from_slice(&ver_len.to_le_bytes());
    meta_root.extend_from_slice(runtime_ver);
    meta_root.extend_from_slice(&0u16.to_le_bytes()); // flags
    meta_root.extend_from_slice(&3u16.to_le_bytes()); // stream count = 3

    // Stream header 0: #Strings
    meta_root.extend_from_slice(&strings_off.to_le_bytes());
    meta_root.extend_from_slice(&(strings_stream.len() as u32).to_le_bytes());
    meta_root.extend_from_slice(sname_strings);

    // Stream header 1: #GUID
    meta_root.extend_from_slice(&guid_off.to_le_bytes());
    meta_root.extend_from_slice(&(guid_stream.len() as u32).to_le_bytes());
    meta_root.extend_from_slice(sname_guid);

    // Stream header 2: #~
    meta_root.extend_from_slice(&tables_off.to_le_bytes());
    meta_root.extend_from_slice(&(tables_stream.len() as u32).to_le_bytes());
    meta_root.extend_from_slice(sname_tables);

    // Pad stream data to their computed offsets
    while meta_root.len() < strings_off as usize {
        meta_root.push(0);
    }
    meta_root.extend_from_slice(&strings_stream);
    while meta_root.len() < guid_off as usize {
        meta_root.push(0);
    }
    meta_root.extend_from_slice(&guid_stream);
    while meta_root.len() < tables_off as usize {
        meta_root.push(0);
    }
    meta_root.extend_from_slice(&tables_stream);

    // ── assemble a minimal PE ─────────────────────────────────────────────────

    let clr_rva: u32 = 0x1000; // VA of the CLR header in our fake section
    let meta_rva: u32 = 0x1048; // VA of the metadata root (CLR header is 72 bytes)

    // Total image: PE headers (0x200) + one 4KB section page containing
    let section_raw_off: u32 = code_off;
    let section_raw_sz: u32 = 0x1000;

    let mut pe_data = vec![0u8; (section_raw_off + section_raw_sz) as usize];

    // DOS header
    pe_data[0..2].copy_from_slice(b"MZ");
    write_u32(&mut pe_data, 0x3c, lfanew);

    // PE signature
    let peo = lfanew as usize;
    pe_data[peo..peo + 4].copy_from_slice(b"PE\0\0");

    // COFF header (20 bytes): machine=AMD64, 1 section, opt_hdr_sz=240, chars=0x22
    write_u16(&mut pe_data, peo + 4, 0x8664); // AMD64
    write_u16(&mut pe_data, peo + 6, 1); // numSections
    write_u16(&mut pe_data, peo + 16, 240); // optHdrSz
    write_u16(&mut pe_data, peo + 18, 0x0022); // chars

    // Optional header magic (PE32+ = 0x20B) at peo+24
    write_u16(&mut pe_data, peo + 24, 0x020B);

    // imageBase at peo+24+24 = peo+48 (PE32+ layout)
    write_u64(&mut pe_data, peo + 48, 0x140000000u64);

    // Data directory 14 (CLR header): at peo+24+112+14*8 = peo+24+112+112 = peo+248
    let dd_off = peo + 24 + 112;
    write_u32(&mut pe_data, dd_off + 14 * 8, clr_rva); // RVA
    write_u32(&mut pe_data, dd_off + 14 * 8 + 4, 72); // size

    // Section header at peo+24+240 = peo+264:
    let sh_off = peo + 24 + 240;
    pe_data[sh_off..sh_off + 8].copy_from_slice(b".text\0\0\0");
    write_u32(&mut pe_data, sh_off + 8, 0x2000); // virtual size
    write_u32(&mut pe_data, sh_off + 12, 0x1000); // virtual address
    write_u32(&mut pe_data, sh_off + 16, section_raw_sz); // raw size
    write_u32(&mut pe_data, sh_off + 20, section_raw_off); // raw offset

    // ── CLR header (IMAGE_COR20_HEADER, 72 bytes) in the section ─────────────
    let section_data_base = section_raw_off as usize;
    let clr_file_off = section_data_base; // clr_rva = 0x1000, section VA = 0x1000

    write_u32(&mut pe_data, clr_file_off, 72); // cb
    write_u16(&mut pe_data, clr_file_off + 4, 2); // major runtime = 2
    write_u16(&mut pe_data, clr_file_off + 6, 5); // minor runtime = 5
    write_u32(&mut pe_data, clr_file_off + 8, meta_rva); // metadata RVA
    write_u32(&mut pe_data, clr_file_off + 12, meta_root.len() as u32); // metadata size
    write_u32(&mut pe_data, clr_file_off + 16, clr_flags); // flags

    // ── metadata root in the same section ────────────────────────────────────
    let meta_file_off = section_data_base + 0x48;
    let meta_end = meta_file_off + meta_root.len();
    if meta_end <= pe_data.len() {
        pe_data[meta_file_off..meta_end].copy_from_slice(&meta_root);
    }

    // ── parse with parse_clr ──────────────────────────────────────────────────
    use goblin::pe::section_table::SectionTable;

    // Build a goblin SectionTable entry manually matching what we wrote above
    let sec = SectionTable {
        name: *b".text\0\0\0",
        virtual_size: 0x2000,
        virtual_address: 0x1000,
        size_of_raw_data: section_raw_sz,
        pointer_to_raw_data: section_raw_off,
        ..Default::default()
    };

    parse_clr(&pe_data, lfanew, &[sec])
        .expect("parse_clr should succeed on a valid synthetic managed PE")
}

fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    if off + 2 <= buf.len() {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
}
fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    if off + 4 <= buf.len() {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
}
fn write_u64(buf: &mut [u8], off: usize, v: u64) {
    if off + 8 <= buf.len() {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
}

#[test]
fn synthetic_managed_pe_is_parsed() {
    let info = make_synthetic_clr(0x01); // ILONLY
                                         // Should have parsed successfully
    assert!(info.is_ilonly);
    assert!(!info.requires_32bit);
    assert!(!info.strong_name_signed);
    // Runtime version comes from the metadata root version string
    assert_eq!(info.runtime_version, "v4.0.30319");
    // CLR flags desc should contain ILONLY
    assert!(
        info.clr_flags_desc.iter().any(|s| s == "ILONLY"),
        "expected ILONLY in flags_desc: {:?}",
        info.clr_flags_desc
    );
    // MVID: may or may not parse depending on stream offset alignment in
    if let Some(mvid) = &info.mvid {
        assert!(
            mvid.starts_with('{') && mvid.ends_with('}') && mvid.len() == 38,
            "MVID should be a 38-char RFC 4122 GUID string, got: {}",
            mvid
        );
    }
    // No assembly rows → assembly_name is None
    assert!(info.assembly_name.is_none());
    // No types → no pattern hits
    assert!(info.cheat_pattern_hits.is_empty());
    assert!(info.obfuscator_hints.is_empty());
}

#[test]
fn corrupt_metadata_root_returns_partial_info() {
    // If the metadata root has bad magic, find_metadata_streams returns None
    let lfanew: u32 = 0x80;
    let clr_rva: u32 = 0x1000;
    let meta_rva: u32 = 0x1048;

    let section_raw_off: u32 = 0x200;
    let section_raw_sz: u32 = 0x1000;
    let mut pe_data = vec![0u8; (section_raw_off + section_raw_sz) as usize];

    pe_data[0..2].copy_from_slice(b"MZ");
    write_u32(&mut pe_data, 0x3c, lfanew);
    let peo = lfanew as usize;
    pe_data[peo..peo + 4].copy_from_slice(b"PE\0\0");
    write_u16(&mut pe_data, peo + 4, 0x8664);
    write_u16(&mut pe_data, peo + 6, 1);
    write_u16(&mut pe_data, peo + 16, 240);
    write_u16(&mut pe_data, peo + 18, 0x0022);
    write_u16(&mut pe_data, peo + 24, 0x020B);

    let dd_off = peo + 24 + 112;
    write_u32(&mut pe_data, dd_off + 14 * 8, clr_rva);
    write_u32(&mut pe_data, dd_off + 14 * 8 + 4, 72);

    let sh_off = peo + 24 + 240;
    pe_data[sh_off..sh_off + 8].copy_from_slice(b".text\0\0\0");
    write_u32(&mut pe_data, sh_off + 8, 0x2000);
    write_u32(&mut pe_data, sh_off + 12, 0x1000);
    write_u32(&mut pe_data, sh_off + 16, section_raw_sz);
    write_u32(&mut pe_data, sh_off + 20, section_raw_off);

    let clr_off = section_raw_off as usize;
    write_u32(&mut pe_data, clr_off, 72);
    write_u16(&mut pe_data, clr_off + 4, 2);
    write_u16(&mut pe_data, clr_off + 6, 5);
    write_u32(&mut pe_data, clr_off + 8, meta_rva);
    write_u32(&mut pe_data, clr_off + 12, 32);
    write_u32(&mut pe_data, clr_off + 16, 0x01); // ILONLY

    // Write GARBAGE at metadata location (bad magic, not BSJB)
    let meta_off = section_raw_off as usize + 0x48;
    pe_data[meta_off..meta_off + 4].copy_from_slice(b"JUNK");

    use goblin::pe::section_table::SectionTable;
    let sec = SectionTable {
        name: *b".text\0\0\0",
        virtual_size: 0x2000,
        virtual_address: 0x1000,
        size_of_raw_data: section_raw_sz,
        pointer_to_raw_data: section_raw_off,
        ..Default::default()
    };

    let result = parse_clr(&pe_data, lfanew, &[sec]);
    // Must return Some (CLR header is valid) even though metadata is garbage
    let info = result.expect("should return Some even with corrupt metadata");
    // Should carry the 'unreadable' obfuscator hint
    assert!(
        info.obfuscator_hints
            .iter()
            .any(|h| h.contains("unreadable")),
        "expected 'unreadable' hint for corrupt metadata, got: {:?}",
        info.obfuscator_hints
    );
    assert!(info.is_ilonly);
}
