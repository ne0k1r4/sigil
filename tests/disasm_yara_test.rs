/// Tests for full-binary disassembly and YARA scanning.

use std::path::PathBuf;
use sigil::disasm::disassemble_full;

fn fixture(name: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures");
    p.push(name);
    p.to_string_lossy().to_string()
}

// ── full disassembly ──────────────────────────────────────────────────────────

#[test]
fn full_disasm_pe_finds_text_section() {
    let data = std::fs::read(fixture("minimal.exe")).unwrap();
    let fd = disassemble_full(&data, 1000).unwrap();
    assert!(!fd.sections.is_empty(), "expected at least one executable section");
    assert!(fd.sections.iter().any(|s| s.section_name.contains("text")),
        "expected .text section in full disasm");
}

#[test]
fn full_disasm_pe_produces_instructions() {
    let data = std::fs::read(fixture("minimal.exe")).unwrap();
    let fd = disassemble_full(&data, 1000).unwrap();
    assert!(fd.total_insns > 0, "expected at least one instruction");
    // Our minimal PE has: xor eax,eax; ret — so at least 2 instructions
    assert!(fd.total_insns >= 2);
}

#[test]
fn full_disasm_pe_mnemonic_freq_populated() {
    let data = std::fs::read(fixture("minimal.exe")).unwrap();
    let fd = disassemble_full(&data, 1000).unwrap();
    assert!(!fd.mnemonic_freq.is_empty(), "mnemonic_freq should be populated");
    // xor and ret must appear since our fixture starts with those
    assert!(fd.mnemonic_freq.contains_key("xor"), "expected 'xor' in mnemonic freq");
    assert!(fd.mnemonic_freq.contains_key("ret"), "expected 'ret' in mnemonic freq");
}

#[test]
fn full_disasm_elf_finds_text_section() {
    let data = std::fs::read(fixture("minimal.elf")).unwrap();
    let fd = disassemble_full(&data, 1000).unwrap();
    assert!(!fd.sections.is_empty(), "ELF: expected at least one executable section");
    assert!(fd.total_insns > 0, "ELF: expected at least one instruction");
}

#[test]
fn full_disasm_section_cap_respected() {
    let data = std::fs::read(fixture("minimal.exe")).unwrap();
    // Cap at 1 instruction per section
    let fd = disassemble_full(&data, 1).unwrap();
    for sec in &fd.sections {
        assert!(sec.instructions.len() <= 1,
            "section '{}' has {} insns, cap was 1", sec.section_name, sec.instructions.len());
    }
}

#[test]
fn full_disasm_arch_correct_for_pe() {
    let data = std::fs::read(fixture("minimal.exe")).unwrap();
    let fd = disassemble_full(&data, 10).unwrap();
    assert_eq!(fd.arch, "x86_64");
    assert!(fd.is_64);
}

#[test]
fn full_disasm_arch_correct_for_elf() {
    let data = std::fs::read(fixture("minimal.elf")).unwrap();
    let fd = disassemble_full(&data, 10).unwrap();
    assert_eq!(fd.arch, "x86_64");
    assert!(fd.is_64);
}

// ── YARA scanning ─────────────────────────────────────────────────────────────

#[cfg(feature = "yara")]
mod yara_tests {
    use sigil::yara_scan::scan;
    use std::io::Write;

    struct TempFile(std::path::PathBuf);
    impl TempFile {
        fn new(name: &str, content: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!("sigil_yara_test_{}_{}", std::process::id(), name));
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(content.as_bytes()).unwrap();
            TempFile(path)
        }
        fn path(&self) -> String { self.0.to_str().unwrap().to_string() }
    }
    impl Drop for TempFile {
        fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); }
    }

    #[test]
    fn yara_matches_mz_header() {
        let rule = r#"
rule MZ_header {
    meta:
        description = "Matches MZ header"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}
"#;
        let f = TempFile::new("mz.yar", rule);
        let data = b"MZ\x00\x00rest of pe";
        let matches = scan(data, &[f.path()]).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule, "MZ_header");
        assert!(!matches[0].string_matches.is_empty());
    }

    #[test]
    fn yara_no_match_returns_empty() {
        let rule = r#"
rule Never_matches {
    strings:
        $x = "THIS_WILL_NEVER_APPEAR_XYZZY_12345"
    condition:
        $x
}
"#;
        let f = TempFile::new("nomatch.yar", rule);
        let data = b"hello world";
        let matches = scan(data, &[f.path()]).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn yara_empty_rule_list_returns_empty() {
        let data = b"anything";
        let matches = scan(data, &[]).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn yara_missing_rule_file_returns_err() {
        let result = scan(b"data", &["/nonexistent/path/rules.yar".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn yara_metadata_extracted() {
        let rule = r#"
rule With_meta {
    meta:
        author = "sigil test"
        severity = 5
    strings:
        $a = "hello"
    condition:
        $a
}
"#;
        let f = TempFile::new("meta.yar", rule);
        let matches = scan(b"hello world", &[f.path()]).unwrap();
        assert_eq!(matches.len(), 1);
        let meta_keys: Vec<&str> = matches[0].meta.iter().map(|(k,_)| k.as_str()).collect();
        assert!(meta_keys.contains(&"author"));
        assert!(meta_keys.contains(&"severity"));
    }
}
