/// YARA rule scanning for sigil.
///
/// Loads .yar / .yara rule files and scans a binary's raw bytes against
/// them. Uses the `yara` crate which wraps libyara. Returns structured
/// match results including rule name, tags, metadata, and matched string
/// offsets.
///
/// Installation requirement: libyara must be installed on the system.
///   Arch:   sudo pacman -S yara
///   Debian: sudo apt install libyara-dev
///   macOS:  brew install yara

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct YaraMatch {
    /// Rule identifier
    pub rule: String,
    /// Rule namespace (usually the filename without extension)
    pub namespace: String,
    /// Tags declared on the rule e.g. `rule Foo : malware packer { ... }`
    pub tags: Vec<String>,
    /// key=value metadata from the `meta:` section
    pub meta: Vec<(String, String)>,
    /// Individual string matches within the binary
    pub string_matches: Vec<YaraStringMatch>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct YaraStringMatch {
    /// The string identifier in the rule e.g. `$a`, `$mz_header`
    pub identifier: String,
    /// File offsets where this string was found
    pub offsets: Vec<u64>,
}

/// Load one or more YARA rule files and scan `data` against them.
///
/// `rule_paths` may contain individual `.yar` / `.yara` files or
/// directories — directories are searched non-recursively for `*.yar`
/// and `*.yara` files.
///
/// Returns a list of `YaraMatch` records, one per matching rule.
/// Returns an empty list if no rules match (not an error).
pub fn scan(data: &[u8], rule_paths: &[String]) -> Result<Vec<YaraMatch>> {
    if rule_paths.is_empty() {
        return Ok(vec![]);
    }

    // Collect individual rule files from paths (files + directory scan)
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for path in rule_paths {
        let p = std::path::Path::new(path);
        if p.is_dir() {
            let entries = std::fs::read_dir(p)
                .with_context(|| format!("cannot read rules directory '{}'", path))?;
            for entry in entries.flatten() {
                let fp = entry.path();
                if let Some(ext) = fp.extension().and_then(|e| e.to_str()) {
                    if ext == "yar" || ext == "yara" {
                        files.push(fp);
                    }
                }
            }
        } else if p.exists() {
            files.push(p.to_path_buf());
        } else {
            anyhow::bail!("YARA rule path not found: '{}'", path);
        }
    }

    if files.is_empty() {
        return Ok(vec![]);
    }

    // Compile all rules into a single scanner
    let mut compiler = yara::Compiler::new()
        .map_err(|e| anyhow::anyhow!("YARA compiler init: {}", e))?;

    for file in &files {
        let namespace = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("default")
            .to_string();
        compiler
            .add_rules_file_with_namespace(file, &namespace)
            .with_context(|| format!("failed to compile YARA rules from '{}'", file.display()))?;
    }

    let rules = compiler
        .compile_rules()
        .map_err(|e| anyhow::anyhow!("YARA compile: {}", e))?;

    // Scan the raw bytes
    let matches = rules
        .scan_mem(data, 30) // 30 second timeout
        .map_err(|e| anyhow::anyhow!("YARA scan: {}", e))?;

    // Convert libyara results to our serialisable types
    let out = matches
        .iter()
        .map(|m| {
            let tags: Vec<String> = m.tags.iter().map(|t| t.to_string()).collect();

            let meta: Vec<(String, String)> = m
                .metadatas
                .iter()
                .map(|md| {
                    let val = match &md.value {
                        yara::MetadataValue::Integer(i) => i.to_string(),
                        yara::MetadataValue::Boolean(b) => b.to_string(),
                        yara::MetadataValue::String(s)  => s.clone(),
                    };
                    (md.identifier.to_string(), val)
                })
                .collect();

            let string_matches: Vec<YaraStringMatch> = m
                .strings
                .iter()
                .map(|s| YaraStringMatch {
                    identifier: s.identifier.to_string(),
                    offsets: s.matches.iter().map(|om| om.offset as u64).collect(),
                })
                .collect();

            YaraMatch {
                rule:      m.identifier.to_string(),
                namespace: m.namespace.to_string(),
                tags,
                meta,
                string_matches,
            }
        })
        .collect();

    Ok(out)
}
