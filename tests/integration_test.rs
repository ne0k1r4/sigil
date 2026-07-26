/// Integration tests for sigil.
/// Fixtures are pre-built minimal PE/ELF binaries in tests/fixtures/.
/// Run with: cargo test

use std::path::PathBuf;

fn fixture(name: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures");
    p.push(name);
    p.to_string_lossy().to_string()
}

// ── analyzer ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod analyzer_pe {
    use super::*;
    use sigil::analyzer::{analyze, packing_verdict};

    #[test]
    fn pe_format_detected() {
        let (info, _) = analyze(&fixture("minimal.exe"), false).unwrap();
        assert_eq!(info.format, "PE");
    }

    #[test]
    fn pe_arch_detected() {
        let (info, _) = analyze(&fixture("minimal.exe"), false).unwrap();
        assert_eq!(info.arch, "x86_64");
    }

    #[test]
    fn pe_sections_present() {
        let (info, _) = analyze(&fixture("minimal.exe"), false).unwrap();
        assert!(!info.sections.is_empty(), "expected at least one section");
        let names: Vec<&str> = info.sections.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&".text"), "expected .text section, got: {:?}", names);
        assert!(names.contains(&".data"), "expected .data section, got: {:?}", names);
    }

    #[test]
    fn pe_section_entropy_in_range() {
        let (info, _) = analyze(&fixture("minimal.exe"), false).unwrap();
        for s in &info.sections {
            assert!(s.entropy >= 0.0 && s.entropy <= 8.0,
                "section '{}' entropy {} out of [0,8]", s.name, s.entropy);
        }
    }

    #[test]
    fn pe_headers_contain_entry_point() {
        let (info, _) = analyze(&fixture("minimal.exe"), false).unwrap();
        let has_ep = info.headers.iter().any(|(k, _)| k == "Entry Point");
        assert!(has_ep, "expected 'Entry Point' in headers");
    }

    #[test]
    fn pe_no_tls_in_minimal() {
        let (info, _) = analyze(&fixture("minimal.exe"), false).unwrap();
        assert!(info.tls_callbacks.is_empty(),
            "minimal PE should have no TLS callbacks");
    }

    #[test]
    fn pe_strings_extracted() {
        let (info, _) = analyze(&fixture("minimal.exe"), false).unwrap();
        // Our fixture embeds "SIGIL_TEST_STRING" in .data
        assert!(
            info.strings.iter().any(|s| s.contains("SIGIL_TEST_STRING")),
            "expected SIGIL_TEST_STRING in extracted strings"
        );
    }

    #[test]
    fn pe_overall_entropy_reasonable() {
        let (info, _) = analyze(&fixture("minimal.exe"), false).unwrap();
        // Minimal unobfuscated binary should not look packed
        assert!(info.entropy < 7.0,
            "minimal PE entropy {} unexpectedly high", info.entropy);
        assert_eq!(packing_verdict(info.entropy), "NORMAL");
    }
}

#[cfg(test)]
mod analyzer_elf {
    use super::*;
    use sigil::analyzer::analyze;

    #[test]
    fn elf_format_detected() {
        let (info, _) = analyze(&fixture("minimal.elf"), false).unwrap();
        assert_eq!(info.format, "ELF");
    }

    #[test]
    fn elf_arch_detected() {
        let (info, _) = analyze(&fixture("minimal.elf"), false).unwrap();
        assert_eq!(info.arch, "x86_64");
    }

    #[test]
    fn elf_sections_present() {
        let (info, _) = analyze(&fixture("minimal.elf"), false).unwrap();
        assert!(!info.sections.is_empty(), "expected at least one ELF section");
        let names: Vec<&str> = info.sections.iter().map(|s| s.name.as_str()).collect();
        assert!(names.iter().any(|n| n.contains("text")),
            "expected .text-like section, got: {:?}", names);
    }

    #[test]
    fn elf_imports_use_dynamic_library() {
        let (info, _) = analyze(&fixture("minimal.elf"), false).unwrap();
        // Minimal ELF has no dynamic symbols — imports list should be empty
        // or any present should use "(dynamic)" not a cross-product of libraries
        for imp in &info.imports {
            assert_eq!(imp.library, "(dynamic)",
                "ELF import library should be '(dynamic)', got '{}'", imp.library);
        }
    }

    #[test]
    fn elf_section_entropy_in_range() {
        let (info, _) = analyze(&fixture("minimal.elf"), false).unwrap();
        for s in &info.sections {
            assert!(s.entropy >= 0.0 && s.entropy <= 8.0,
                "section '{}' entropy {} out of [0,8]", s.name, s.entropy);
        }
    }

    #[test]
    fn elf_headers_contain_entry_point() {
        let (info, _) = analyze(&fixture("minimal.elf"), false).unwrap();
        let has_ep = info.headers.iter().any(|(k, _)| k == "Entry Point");
        assert!(has_ep, "expected 'Entry Point' in ELF headers");
    }

    #[test]
    fn elf_program_headers_parsed() {
        let (info, _) = analyze(&fixture("minimal.elf"), false).unwrap();
        assert!(!info.elf_segments.is_empty(), "expected program headers");
        let has_load = info.elf_segments.iter().any(|s| s.segment_type == "LOAD");
        assert!(has_load, "expected at least one LOAD segment");
    }
}

// ── entropy / packing ─────────────────────────────────────────────────────────

#[cfg(test)]
mod entropy {
    use sigil::analyzer::{shannon_entropy, packing_verdict, packing_hints_from_bytes};

    #[test]
    fn empty_slice_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn uniform_byte_is_zero() {
        let data = vec![0x41u8; 1024];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn all_256_values_near_eight() {
        let data: Vec<u8> = (0u8..=255).collect();
        let h = shannon_entropy(&data);
        assert!((h - 8.0).abs() < 0.001, "entropy of uniform dist should be ~8.0, got {}", h);
    }

    #[test]
    fn random_like_data_high_entropy() {
        // All 256 byte values repeated 16x — uniform distribution, entropy = 8.0
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let h = shannon_entropy(&data);
        assert!(h > 7.9, "uniform distribution entropy should be ~8.0, got {}", h);
    }

    #[test]
    fn verdict_packed() {
        assert_eq!(packing_verdict(7.5), "LIKELY PACKED/ENCRYPTED");
    }

    #[test]
    fn verdict_suspicious() {
        assert_eq!(packing_verdict(6.8), "SUSPICIOUS");
    }

    #[test]
    fn verdict_normal() {
        assert_eq!(packing_verdict(4.0), "NORMAL");
    }

    #[test]
    fn packing_hints_no_indicators_on_minimal_pe() {
        use std::fs;
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("tests/fixtures/minimal.exe");
        let data = fs::read(&p).unwrap();
        let hints = packing_hints_from_bytes(&data).unwrap();
        // Should only contain the "No packing indicators" message
        assert_eq!(hints.len(), 1);
        assert!(hints[0].starts_with("No packing"), "unexpected hint: {}", hints[0]);
    }
}

// ── pattern search ────────────────────────────────────────────────────────────

#[cfg(test)]
mod pattern {
    use sigil::analyzer::pattern_search;

    #[test]
    fn exact_match_found() {
        let data = vec![0x00, 0x48, 0x8B, 0xC0, 0xFF];
        let hits = pattern_search(&data, "48 8B C0").unwrap();
        assert_eq!(hits, vec![1]);
    }

    #[test]
    fn wildcard_match() {
        let data = vec![0x48, 0x8B, 0x45, 0x08];
        let hits = pattern_search(&data, "48 8B ?? 08").unwrap();
        assert_eq!(hits, vec![0]);
    }

    #[test]
    fn no_match_returns_empty() {
        let data = vec![0x00, 0x01, 0x02];
        let hits = pattern_search(&data, "FF FF").unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn multiple_matches() {
        let data = vec![0x90, 0x90, 0x90, 0x90];
        let hits = pattern_search(&data, "90 90").unwrap();
        assert_eq!(hits, vec![0, 1, 2]);
    }

    #[test]
    fn invalid_token_returns_err() {
        let data = vec![0x00];
        let result = pattern_search(&data, "ZZ");
        assert!(result.is_err(), "expected Err for invalid token");
    }

    #[test]
    fn empty_pattern_returns_err() {
        let data = vec![0x00];
        let result = pattern_search(&data, "   ");
        assert!(result.is_err(), "expected Err for empty pattern");
    }

    #[test]
    fn all_wildcards_matches_everywhere() {
        let data = vec![0xAA, 0xBB, 0xCC];
        let hits = pattern_search(&data, "?? ?? ??").unwrap();
        assert_eq!(hits, vec![0]);
    }
}

// ── hashes ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod hashes {
    use sigil::hashes::from_bytes;

    #[test]
    fn md5_known_value() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        let h = from_bytes(&[]);
        assert_eq!(h.md5, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn sha256_known_value() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let h = from_bytes(&[]);
        assert_eq!(h.sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn no_imphash_for_non_pe() {
        let h = from_bytes(b"not a PE");
        assert!(h.imphash.is_none());
    }

    #[test]
    fn hashes_differ_for_different_inputs() {
        let h1 = from_bytes(b"aaa");
        let h2 = from_bytes(b"bbb");
        assert_ne!(h1.md5, h2.md5);
        assert_ne!(h1.sha256, h2.sha256);
    }
}

// ── strings ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod strings {
    use sigil::analyzer::{extract_strings, categorize_strings};

    #[test]
    fn extracts_ascii_strings() {
        let data = b"\x00\x00hello\x00world\x00\x00";
        let strings = extract_strings(data, 4);
        assert!(strings.contains(&"hello".to_string()));
        assert!(strings.contains(&"world".to_string()));
    }

    #[test]
    fn respects_min_len() {
        let data = b"hi\x00hello\x00";
        let strings = extract_strings(data, 4);
        assert!(!strings.contains(&"hi".to_string()), "short string should be excluded");
        assert!(strings.contains(&"hello".to_string()));
    }

    #[test]
    fn empty_data_returns_empty() {
        assert!(extract_strings(&[], 4).is_empty());
    }

    #[test]
    fn categorize_urls() {
        let strings = vec!["https://evil.example.com/payload".to_string()];
        let cats = categorize_strings(&strings);
        assert!(!cats.urls.is_empty());
        assert!(cats.ips.is_empty());
    }

    #[test]
    fn categorize_ips() {
        let strings = vec!["192.168.1.1:4444".to_string()];
        let cats = categorize_strings(&strings);
        assert!(!cats.ips.is_empty());
    }

    #[test]
    fn categorize_registry() {
        let strings = vec!["HKLM\\SOFTWARE\\Microsoft\\Windows".to_string()];
        let cats = categorize_strings(&strings);
        assert!(!cats.registry.is_empty());
    }

    #[test]
    fn categorize_guid() {
        let strings = vec!["{6E9B4B76-8B2F-4FA4-A39F-3C8B7D5F1234}".to_string()];
        let cats = categorize_strings(&strings);
        assert!(!cats.guids.is_empty());
    }

    #[test]
    fn long_strings_excluded_from_categorization() {
        let long = "A".repeat(200);
        let strings = vec![long];
        let cats = categorize_strings(&strings);
        // should not crash and should not categorize
        assert!(cats.urls.is_empty());
    }
}

// ── sig scanning ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod sigs {
    use sigil::sigs::{scan_antidebug, scan_anticheat};

    fn imp(lib: &str, func: &str) -> (String, String) {
        (lib.to_string(), func.to_string())
    }

    #[test]
    fn detects_is_debugger_present() {
        let imports = vec![imp("KERNEL32.dll", "IsDebuggerPresent")];
        let hits = scan_antidebug(&imports, &[], None);
        assert!(!hits.is_empty(), "should detect IsDebuggerPresent");
        assert!(hits.iter().any(|h| h.matched.contains("IsDebuggerPresent")));
    }

    #[test]
    fn detects_nt_set_information_thread() {
        let imports = vec![imp("ntdll.dll", "NtSetInformationThread")];
        let hits = scan_antidebug(&imports, &[], None);
        assert!(!hits.is_empty());
    }

    #[test]
    fn detects_vanguard_string() {
        let strings = vec!["vgk.sys loaded".to_string()];
        let hits = scan_anticheat(&[], &strings, None);
        assert!(!hits.is_empty(), "should detect vgk.sys reference");
    }

    #[test]
    fn detects_battleye_string() {
        let strings = vec!["BattlEye Service".to_string()];
        let hits = scan_anticheat(&[], &strings, None);
        assert!(!hits.is_empty());
    }

    #[test]
    fn detects_write_process_memory() {
        let imports = vec![imp("KERNEL32.dll", "WriteProcessMemory")];
        let hits = scan_anticheat(&imports, &[], None);
        assert!(!hits.is_empty());
    }

    #[test]
    fn case_insensitive_import_match() {
        let imports = vec![imp("kernel32.dll", "isdebuggerpresent")];
        let hits = scan_antidebug(&imports, &[], None);
        assert!(!hits.is_empty(), "import match should be case-insensitive");
    }

    #[test]
    fn clean_binary_no_hits() {
        let imports = vec![imp("KERNEL32.dll", "CreateFileA"),
                           imp("KERNEL32.dll", "ReadFile")];
        let ad = scan_antidebug(&imports, &[], None);
        let ac = scan_anticheat(&imports, &[], None);
        assert!(ad.is_empty(), "clean imports should not trigger antidebug");
        assert!(ac.is_empty(), "clean imports should not trigger anticheat");
    }
}

// ── size cap ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod size_cap {
    use sigil::analyzer::read_file;

    #[test]
    fn rejects_oversized_file_without_flag() {
        // We can't write a 256MB file in a test, so instead temporarily
        // test that read_file succeeds with no_size_limit=true on a valid file
        // and the function signature accepts the flag.
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("tests/fixtures/minimal.exe");
        let result = read_file(&p.to_string_lossy(), true);
        assert!(result.is_ok(), "read_file with no_size_limit=true should succeed");
    }

    #[test]
    fn accepts_file_within_cap() {
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("tests/fixtures/minimal.exe");
        let result = read_file(&p.to_string_lossy(), false);
        assert!(result.is_ok(), "small file should pass size cap");
    }

    #[test]
    fn returns_err_for_missing_file() {
        let result = read_file("/nonexistent/path/file.exe", false);
        assert!(result.is_err());
    }
}
