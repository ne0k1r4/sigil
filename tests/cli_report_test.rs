use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(test_name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sigil_{test_name}_{}_{}",
            std::process::id(),
            nonce
        ));
        fs::create_dir_all(&path).expect("temporary directory should be created");
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_sigil(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .args(args)
        .output()
        .expect("sigil CLI should start")
}

#[test]
fn scan_json_includes_schema_and_tool_version() {
    let fixture = fixture("minimal.exe");
    let output = run_sigil(&[
        "--quiet",
        "scan",
        fixture.to_str().expect("fixture path is UTF-8"),
        "--json",
    ]);

    assert!(
        output.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("scan output should be JSON");
    assert_eq!(report["schema_version"], "1.0");
    assert_eq!(report["tool_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(report["format"], "PE");
}

#[test]
fn report_json_writes_new_file_and_refuses_overwrite() {
    let temp_dir = TempDir::new("json_report");
    let output_path = temp_dir.join("analysis.json");
    let fixture = fixture("minimal.exe");
    let output_path_str = output_path.to_str().expect("temporary path is UTF-8");
    let fixture_str = fixture.to_str().expect("fixture path is UTF-8");

    let first = run_sigil(&[
        "--quiet",
        "report",
        fixture_str,
        "--output",
        output_path_str,
    ]);
    assert!(
        first.status.success(),
        "JSON report export failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let report: Value = serde_json::from_str(
        &fs::read_to_string(&output_path)
            .expect("JSON report should be written to the requested path"),
    )
    .expect("written report should be valid JSON");
    assert_eq!(report["schema_version"], "1.0");
    assert_eq!(report["tool_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(report["format"], "PE");

    let second = run_sigil(&[
        "--quiet",
        "report",
        fixture_str,
        "--output",
        output_path_str,
    ]);
    assert!(
        !second.status.success(),
        "report export must not overwrite an existing file"
    );
    assert!(String::from_utf8_lossy(&second.stderr).contains("already exists"));
}

#[test]
fn batch_json_is_sorted_and_fail_on_error_is_opt_in() {
    let temp_dir = TempDir::new("batch_failure_signaling");
    let valid_path = temp_dir.join("a_valid.exe");
    let invalid_path = temp_dir.join("z_invalid.bin");
    fs::copy(fixture("minimal.exe"), &valid_path).expect("valid fixture should be copied");
    fs::write(&invalid_path, b"not a PE or ELF binary").expect("invalid fixture should be written");
    let temp_dir_str = temp_dir.0.to_str().expect("temporary path is UTF-8");

    let default_run = run_sigil(&["--quiet", "batch", temp_dir_str, "--json"]);
    assert!(
        default_run.status.success(),
        "default batch scan should preserve success status: {}",
        String::from_utf8_lossy(&default_run.stderr)
    );

    let results: Value =
        serde_json::from_slice(&default_run.stdout).expect("batch output should be valid JSON");
    let results = results.as_array().expect("batch output should be an array");
    assert_eq!(results.len(), 2);
    assert!(
        results[0]["path"]
            .as_str()
            .expect("result path should be a string")
            .ends_with("a_valid.exe"),
        "batch output must be sorted by path"
    );
    assert_eq!(results[0]["format"], "PE");
    assert!(results[1].get("error").is_some());

    let strict_run = run_sigil(&[
        "--quiet",
        "batch",
        temp_dir_str,
        "--json",
        "--fail-on-error",
    ]);
    assert!(
        !strict_run.status.success(),
        "--fail-on-error should return a non-zero status for partial failures"
    );
    let strict_results: Value = serde_json::from_slice(&strict_run.stdout)
        .expect("strict batch output should remain valid JSON");
    assert_eq!(strict_results, Value::Array(results.to_vec()));
    assert!(String::from_utf8_lossy(&strict_run.stderr)
        .contains("batch scan completed with 1 failed file"));
}
