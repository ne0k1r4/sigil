/// YARA rule scanning for sigil.
///
/// Uses yara_x — VirusTotal's official pure-Rust YARA reimplementation.
/// No libyara dependency, no bindgen, no C headers required.
/// 99% compatible with existing .yar / .yara rule files.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct YaraMatch {
    /// Rule identifier
    pub rule: String,
    /// Rule namespace (usually the filename without extension)
    pub namespace: String,
    /// Tags declared on the rule
    pub tags: Vec<String>,
    /// key=value metadata from the meta: section
    pub meta: Vec<(String, String)>,
    /// Per-pattern match offsets within the binary
    pub pattern_matches: Vec<PatternMatch>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PatternMatch {
    /// Pattern identifier e.g. `$mz`, `$a`
    pub identifier: String,
    /// File offsets where this pattern was found
    pub offsets: Vec<u64>,
}

/// Load one or more YARA rule files / directories and scan `data` against them.
///
/// `rule_paths` may contain individual `.yar`/`.yara` files or directories.
/// Directories are searched non-recursively for `*.yar` and `*.yara` files.
///
/// Returns a list of `YaraMatch` records (one per matching rule), or an empty
/// vec when no rules match. Returns `Err` on missing paths or compile errors.
pub fn scan(data: &[u8], rule_paths: &[String]) -> Result<Vec<YaraMatch>> {
    if rule_paths.is_empty() {
        return Ok(vec![]);
    }

    // Collect individual rule files
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

    // Compile all rules
    let mut compiler = yara_x::Compiler::new();
    for file in &files {
        let namespace = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("default");
        let source = std::fs::read_to_string(file)
            .with_context(|| format!("failed to read rule file '{}'", file.display()))?;
        compiler
            .new_namespace(namespace)
            .add_source(source.as_str())
            .with_context(|| format!("failed to compile '{}'", file.display()))?;
    }
    let rules = compiler.build();

    // Scan
    let mut scanner = yara_x::Scanner::new(&rules);
    let results = scanner
        .scan(data)
        .map_err(|e| anyhow::anyhow!("YARA scan error: {}", e))?;

    let mut out = Vec::new();
    for m in results.matching_rules() {
        let tags: Vec<String> = m.tags().map(|t| t.identifier().to_string()).collect();

        let meta: Vec<(String, String)> = m
            .metadata()
            .map(|(k, v)| {
                let val = match v {
                    yara_x::MetaValue::Integer(i) => i.to_string(),
                    yara_x::MetaValue::Float(f)   => f.to_string(),
                    yara_x::MetaValue::Bool(b)     => b.to_string(),
                    yara_x::MetaValue::String(s)   => s.to_string(),
                    yara_x::MetaValue::Bytes(b)    => format!("{:?}", b),
                };
                (k.to_string(), val)
            })
            .collect();

        let pattern_matches: Vec<PatternMatch> = m
            .patterns()
            .map(|p| PatternMatch {
                identifier: p.identifier().to_string(),
                offsets: p.matches().map(|om| om.range().start as u64).collect(),
            })
            .collect();

        out.push(YaraMatch {
            rule:      m.identifier().to_string(),
            namespace: m.namespace().to_string(),
            tags,
            meta,
            pattern_matches,
        });
    }

    Ok(out)
}

