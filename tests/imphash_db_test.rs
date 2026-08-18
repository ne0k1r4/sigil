/// Tests for sigs::load_imphash_db and sigs::check_imphash_db — loading an
use sigil::sigs::{check_imphash_db, load_imphash_db};
use std::io::Write;

/// Write `content` to a temp file and return its path. The file is cleaned
struct TempFile(std::path::PathBuf);
impl TempFile {
    fn new(name: &str, content: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("sigil_test_{}_{}", std::process::id(), name));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        TempFile(path)
    }
    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn loads_csv_with_header_row() {
    let csv = "imphash,signature\n\
               a909b3c8d3d1ce4ae0a4f607a37a8129,CobaltStrike\n\
               deadbeefdeadbeefdeadbeefdeadbeef,SomeFamily\n";
    let f = TempFile::new("with_header", csv);
    let db = load_imphash_db(f.path()).unwrap();

    // The header row's first field ("imphash") is not 32 hex chars, so it's
    assert_eq!(db.len(), 2);
    assert_eq!(db[0].hash, "a909b3c8d3d1ce4ae0a4f607a37a8129");
    assert_eq!(db[0].description, "CobaltStrike");
}

#[test]
fn loads_csv_without_header_row() {
    let csv = "deadbeefdeadbeefdeadbeefdeadbeef,SomeFamily\n";
    let f = TempFile::new("no_header", csv);
    let db = load_imphash_db(f.path()).unwrap();
    assert_eq!(db.len(), 1);
    assert_eq!(db[0].hash, "deadbeefdeadbeefdeadbeefdeadbeef");
}

#[test]
fn handles_quoted_fields_and_blank_lines() {
    let csv = "\"a909b3c8d3d1ce4ae0a4f607a37a8129\",\"Cobalt Strike Beacon\"\n\
               \n\
               \"deadbeefdeadbeefdeadbeefdeadbeef\",\"Another Family\"\n";
    let f = TempFile::new("quoted", csv);
    let db = load_imphash_db(f.path()).unwrap();
    assert_eq!(db.len(), 2);
    assert_eq!(db[0].description, "Cobalt Strike Beacon");
}

#[test]
fn missing_description_gets_placeholder() {
    let csv = "a909b3c8d3d1ce4ae0a4f607a37a8129\n";
    let f = TempFile::new("no_desc", csv);
    let db = load_imphash_db(f.path()).unwrap();
    assert_eq!(db.len(), 1);
    assert_eq!(db[0].description, "(no signature name)");
}

#[test]
fn nonexistent_file_returns_err() {
    let result = load_imphash_db("/nonexistent/path/imphash_db.csv");
    assert!(result.is_err());
}

#[test]
fn check_imphash_db_matches_case_insensitively() {
    let csv = "A909B3C8D3D1CE4AE0A4F607A37A8129,CobaltStrike\n";
    let f = TempFile::new("uppercase", csv);
    let db = load_imphash_db(f.path()).unwrap();

    // load_imphash_db lowercases hashes on load
    assert_eq!(db[0].hash, "a909b3c8d3d1ce4ae0a4f607a37a8129");

    let result = check_imphash_db("A909B3C8D3D1CE4AE0A4F607A37A8129", &db);
    assert_eq!(result, Some("CobaltStrike".to_string()));
}

#[test]
fn check_imphash_db_no_match_returns_none() {
    let db = vec![];
    assert!(check_imphash_db("a909b3c8d3d1ce4ae0a4f607a37a8129", &db).is_none());
}
