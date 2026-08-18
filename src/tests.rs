#[cfg(test)]
mod unit_tests {
    use crate::analyzer::{
        categorize_strings, extract_strings, parse_rich_header, pattern_search, shannon_entropy,
    };
    use crate::hashes::from_bytes;
    use crate::sigs::{ExternalSigs, SigRule};

    #[test]
    fn test_shannon_entropy() {
        // Empty data has 0 entropy
        assert_eq!(shannon_entropy(&[]), 0.0);

        // Constant data has 0 entropy
        assert_eq!(shannon_entropy(&[0xaa; 100]), 0.0);

        // Two values with equal probability has 1.0 entropy
        let data_1 = vec![0x00, 0x01];
        assert_eq!(shannon_entropy(&data_1), 1.0);

        // Four values with equal probability has 2.0 entropy
        let data_2 = vec![0x00, 0x01, 0x02, 0x03];
        assert_eq!(shannon_entropy(&data_2), 2.0);
    }

    #[test]
    fn test_pattern_search() {
        let data = b"Hello \x12\x34\x56 World \x78\x9a\xbc\xde End";

        // Exact pattern search
        let res1 = pattern_search(data, "12 34 56").unwrap();
        assert_eq!(res1, vec![6]);

        // Pattern search with wildcards
        let res2 = pattern_search(data, "12 ?? 56").unwrap();
        assert_eq!(res2, vec![6]);

        let res3 = pattern_search(data, "?? 9a ?? de").unwrap();
        assert_eq!(res3, vec![16]);

        // No match
        let res4 = pattern_search(data, "ff ff ff").unwrap();
        assert!(res4.is_empty());

        // Error cases
        assert!(pattern_search(data, "").is_err());
        assert!(pattern_search(data, "invalid").is_err());
    }

    #[test]
    fn test_extract_strings() {
        let data = b"\x00\x01Hello\x00\x02World!\x03\x04\xff";
        let res = extract_strings(data, 4);
        assert_eq!(res, vec!["Hello", "World!"]);

        // Too short strings should be skipped
        let short_data = b"abc\x00de\x00f";
        let res_short = extract_strings(short_data, 4);
        assert!(res_short.is_empty());
    }

    #[test]
    fn test_categorize_strings() {
        let strings = vec![
            "https://google.com/index.html".to_string(),
            "192.168.1.1:8080".to_string(),
            "HKLM\\Software\\Microsoft".to_string(),
            "C:\\Windows\\System32\\calc.exe".to_string(),
            "/proc/self/cmdline".to_string(),
            "{12345678-1234-1234-1234-123456789012}".to_string(),
            "Hello World".to_string(),
        ];

        let cats = categorize_strings(&strings);
        assert_eq!(cats.urls, vec!["https://google.com/index.html"]);
        assert_eq!(cats.ips, vec!["192.168.1.1:8080"]);
        assert_eq!(cats.registry, vec!["HKLM\\Software\\Microsoft"]);
        assert_eq!(
            cats.paths,
            vec!["C:\\Windows\\System32\\calc.exe", "/proc/self/cmdline"]
        );
        assert_eq!(cats.guids, vec!["{12345678-1234-1234-1234-123456789012}"]);
        assert_eq!(cats.other, vec!["Hello World"]);
    }

    #[test]
    fn test_imphash_none_on_invalid_pe() {
        // Non-PE dummy data
        let dummy_data = b"MZ\x00\x00notapefile";
        assert!(from_bytes(dummy_data).imphash.is_none());
    }

    // ── rich header tests ────────────────────────────────────────────

    #[test]
    fn test_rich_header_basic() {
        // build a minimal fake PE stub with a valid rich header
        let lfanew: u32 = 0x200;
        let key: u32 = 0xDEADBEEF;
        let dans_marker: u32 = 0x536E_6144; // "DanS"

        // one entry: comp_id = 0x00010002, count = 5
        let comp_id: u32 = 0x0001_0002;
        let count: u32 = 5;

        let mut data = vec![0u8; 0x200];
        // MZ signature
        data[0] = b'M';
        data[1] = b'Z';
        // lfanew at offset 0x3C
        data[0x3C..0x40].copy_from_slice(&lfanew.to_le_bytes());

        // place rich header starting at 0x80
        let off = 0x80;
        // DanS ^ key
        let enc_dans = dans_marker ^ key;
        data[off..off + 4].copy_from_slice(&enc_dans.to_le_bytes());
        // 3 padding dwords (all XOR'd with key, so just key since original is 0)
        for i in 1..4 {
            data[off + i * 4..off + (i + 1) * 4].copy_from_slice(&key.to_le_bytes());
        }
        // entry: comp_id ^ key, count ^ key
        let entry_off = off + 16;
        data[entry_off..entry_off + 4].copy_from_slice(&(comp_id ^ key).to_le_bytes());
        data[entry_off + 4..entry_off + 8].copy_from_slice(&(count ^ key).to_le_bytes());
        // "Rich" marker
        let rich_off = entry_off + 8;
        data[rich_off..rich_off + 4].copy_from_slice(b"Rich");
        // XOR key after "Rich"
        data[rich_off + 4..rich_off + 8].copy_from_slice(&key.to_le_bytes());

        let result = parse_rich_header(&data, lfanew);
        assert!(result.is_some(), "should parse our synthetic rich header");

        let rh = result.unwrap();
        assert_eq!(rh.entries.len(), 1);
        assert_eq!(rh.entries[0].comp_id, comp_id);
        assert_eq!(rh.entries[0].product_id, 1); // high 16 of 0x00010002
        assert_eq!(rh.entries[0].build_number, 2); // low 16 of 0x00010002
        assert_eq!(rh.entries[0].count, count);
        // hash should be a valid 32-char hex md5
        assert_eq!(rh.hash.len(), 32);
        assert!(rh.hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_rich_header_no_marker() {
        // data that has no "Rich" marker at all should return None
        let data = vec![0u8; 0x200];
        assert!(parse_rich_header(&data, 0x200).is_none());
    }

    #[test]
    fn test_rich_header_too_small() {
        // lfanew less than 0x80 should bail early
        let data = vec![0u8; 0x100];
        assert!(parse_rich_header(&data, 0x40).is_none());
    }

    // ── external sigs tests ──────────────────────────────────────────

    #[test]
    fn test_external_sigs_deserialize() {
        // make sure our json schema actually works the way we expect
        let json = r#"{
            "antidebug_imports": [
                {"name": "NtQueryInformationProcess", "desc": "custom ntquery check"}
            ],
            "antidebug_strings": null,
            "anticheat_imports": [],
            "anticheat_strings": [
                {"name": "BattlEye", "desc": "battleye string match"}
            ]
        }"#;

        let sigs: ExternalSigs = serde_json::from_str(json).unwrap();
        assert_eq!(sigs.antidebug_imports.as_ref().unwrap().len(), 1);
        assert_eq!(
            sigs.antidebug_imports.as_ref().unwrap()[0].name,
            "NtQueryInformationProcess"
        );
        assert!(sigs.antidebug_strings.is_none());
        assert!(sigs.anticheat_imports.as_ref().unwrap().is_empty());
        assert_eq!(sigs.anticheat_strings.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_external_sigs_empty_json() {
        // completely empty object should work — all fields Optional
        let json = "{}";
        let sigs: ExternalSigs = serde_json::from_str(json).unwrap();
        assert!(sigs.antidebug_imports.is_none());
        assert!(sigs.antidebug_strings.is_none());
        assert!(sigs.anticheat_imports.is_none());
        assert!(sigs.anticheat_strings.is_none());
    }

    #[test]
    fn test_external_sigs_scan_integration() {
        // external rules should actually produce hits when matched
        use crate::sigs::scan_antidebug;

        let imports = vec![
            ("kernel32.dll".to_string(), "IsDebuggerPresent".to_string()),
            ("custom.dll".to_string(), "MyCustomFunc".to_string()),
        ];
        let strings = vec!["some random string".to_string()];

        let ext = ExternalSigs {
            antidebug_imports: Some(vec![SigRule {
                name: "MyCustomFunc".to_string(),
                desc: "custom anti-debug func".to_string(),
            }]),
            antidebug_strings: None,
            anticheat_imports: None,
            anticheat_strings: None,
        };

        // scan with ext sigs — should find both the built-in IsDebuggerPresent
        let hits = scan_antidebug(&imports, &strings, Some(&ext));
        let custom_hit = hits.iter().find(|h| h.matched.contains("MyCustomFunc"));
        assert!(custom_hit.is_some(), "external sig should produce a hit");
    }

    #[test]
    fn test_detect_section_anomalies_packer_names() {
        use crate::analyzer::{detect_section_anomalies, SectionInfo};

        let sections = vec![
            SectionInfo {
                name: ".text".to_string(),
                size: 1000,
                entropy: 3.5,
            },
            SectionInfo {
                name: "UPX0".to_string(),
                size: 2000,
                entropy: 4.0,
            },
            SectionInfo {
                name: ".aspack".to_string(),
                size: 500,
                entropy: 2.0,
            },
            SectionInfo {
                name: ".data".to_string(),
                size: 5000,
                entropy: 7.95, // high entropy, and size > 1024
            },
        ];

        let warnings = detect_section_anomalies(&sections);
        assert_eq!(warnings.len(), 3);
        assert!(warnings[0].contains("UPX0"));
        assert!(warnings[1].contains(".aspack"));
        assert!(warnings[2].contains(".data"));
    }
}
