use crate::analyzer::pattern_search;
use crate::sigs::SigHit;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;

/// A single custom detection rule.
#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    pub name: String,
    #[serde(default = "default_category")]
    pub category: String,
    pub hex_pattern: Option<String>,
    pub string_match: Option<String>,
    #[serde(default)]
    pub case_insensitive: bool,
}

fn default_category() -> String {
    "custom".to_string()
}

#[derive(Debug, Deserialize, Default)]
pub struct RuleFile {
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Load a rule file from disk and parse it as TOML.
pub fn load_rules(path: &str) -> Result<RuleFile> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read rules file '{}'", path))?;
    toml::from_str(&content)
        .with_context(|| format!("failed to parse rules file '{}' as TOML", path))
}

/// Evaluate custom rules against a binary's raw bytes and extracted strings.
pub fn scan_rules(rules: &RuleFile, data: &[u8], strings: &[String]) -> Vec<SigHit> {
    let mut hits = Vec::new();

    for rule in &rules.rules {
        if let Some(pat) = &rule.hex_pattern {
            match pattern_search(data, pat) {
                Ok(offsets) if !offsets.is_empty() => {
                    let matched = if offsets.len() == 1 {
                        format!("hex match at 0x{:x}", offsets[0])
                    } else {
                        format!("{} hex matches, first at 0x{:x}", offsets.len(), offsets[0])
                    };
                    hits.push(SigHit {
                        category: rule.category.clone(),
                        technique: rule.name.clone(),
                        matched,
                    });
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "sigil: warning: rule '{}' has invalid hex_pattern: {}",
                        rule.name, e
                    );
                }
            }
        }

        if let Some(sub) = &rule.string_match {
            let needle = if rule.case_insensitive {
                sub.to_lowercase()
            } else {
                sub.clone()
            };
            for s in strings {
                let hay = if rule.case_insensitive {
                    s.to_lowercase()
                } else {
                    s.clone()
                };
                if hay.contains(&needle) {
                    hits.push(SigHit {
                        category: rule.category.clone(),
                        technique: rule.name.clone(),
                        matched: s.clone(),
                    });
                    break;
                }
            }
        }
    }

    hits
}
