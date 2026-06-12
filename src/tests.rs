#[cfg(test)]
mod tests {
    use crate::analyzer::{
        categorize_strings, extract_strings, pattern_search, shannon_entropy,
    };
    use crate::hashes::compute_imphash;

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
        let res = extract_strings(data);
        assert_eq!(res, vec!["Hello", "World!"]);

        // Too short strings should be skipped
        let short_data = b"abc\x00de\x00f";
        let res_short = extract_strings(short_data);
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
        assert_eq!(cats.paths, vec!["C:\\Windows\\System32\\calc.exe", "/proc/self/cmdline"]);
        assert_eq!(cats.guids, vec!["{12345678-1234-1234-1234-123456789012}"]);
        assert_eq!(cats.other, vec!["Hello World"]);
    }

    #[test]
    fn test_imphash_none_on_invalid_pe() {
        // Non-PE dummy data
        let dummy_data = b"MZ\x00\x00notapefile";
        assert!(compute_imphash(dummy_data).is_none());
    }
}
