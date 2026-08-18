/// Tests for parse_version_info — heuristic extraction of VS_VERSIONINFO
use sigil::analyzer::parse_version_info;

/// Encode a UTF-16LE string (no null terminator) as raw bytes.
fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

/// Build a `key\0value\0` UTF-16LE pair, 4-byte aligned after the key's
fn key_value(key: &str, value: &str) -> Vec<u8> {
    let mut buf = utf16le(key);
    buf.extend_from_slice(&0u16.to_le_bytes()); // null terminator for key
    while !buf.len().is_multiple_of(4) {
        buf.push(0); // alignment padding
    }
    buf.extend_from_slice(&utf16le(value));
    buf.extend_from_slice(&0u16.to_le_bytes()); // null terminator for value
    buf
}

#[test]
fn empty_blob_yields_default() {
    let info = parse_version_info(&[]);
    assert!(info.company_name.is_none());
    assert!(info.file_description.is_none());
    assert!(info.product_name.is_none());
}

#[test]
fn extracts_single_field() {
    let blob = key_value("CompanyName", "Acme Corp");
    let info = parse_version_info(&blob);
    assert_eq!(info.company_name, Some("Acme Corp".to_string()));
    assert!(info.product_name.is_none());
}

#[test]
fn extracts_multiple_fields() {
    let mut blob = Vec::new();
    blob.extend(key_value("CompanyName", "Acme Corp"));
    blob.extend(key_value("ProductName", "Acme Tool"));
    blob.extend(key_value("FileVersion", "1.2.3.4"));
    blob.extend(key_value("OriginalFilename", "acmetool.exe"));

    let info = parse_version_info(&blob);
    assert_eq!(info.company_name, Some("Acme Corp".to_string()));
    assert_eq!(info.product_name, Some("Acme Tool".to_string()));
    assert_eq!(info.file_version, Some("1.2.3.4".to_string()));
    assert_eq!(info.original_filename, Some("acmetool.exe".to_string()));
    // Fields not present remain None
    assert!(info.legal_copyright.is_none());
}

#[test]
fn garbage_data_does_not_panic() {
    let blob = vec![0xFFu8; 1024];
    let info = parse_version_info(&blob);
    assert!(info.company_name.is_none());
}

#[test]
fn truncated_value_does_not_panic() {
    // Key present but buffer ends immediately after — read_utf16_string
    let mut blob = utf16le("CompanyName");
    blob.extend_from_slice(&0u16.to_le_bytes());
    // no value bytes follow
    let info = parse_version_info(&blob);
    // No value found -> field stays None (empty string is treated as "not found")
    assert!(info.company_name.is_none());
}
