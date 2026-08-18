use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

/// A single user-defined signature entry.
#[derive(Debug, Deserialize, Clone)]
pub struct SigEntry {
    pub pattern: String,
    pub description: String,
}

/// Layout of `~/.sigil.toml`. All sections are optional — an empty or
#[derive(Debug, Deserialize, Default)]
pub struct SigilConfig {
    #[serde(default)]
    pub antidebug_imports: Vec<SigEntry>,
    #[serde(default)]
    pub antidebug_strings: Vec<SigEntry>,
    #[serde(default)]
    pub anticheat_imports: Vec<SigEntry>,
    #[serde(default)]
    pub anticheat_strings: Vec<SigEntry>,
    #[serde(default)]
    pub known_imphashes: Vec<SigEntry>,
}

/// Locate and load `~/.sigil.toml`, if present.
pub fn load_user_config() -> SigilConfig {
    let path = match config_path() {
        Some(p) => p,
        None => return SigilConfig::default(),
    };
    if !path.exists() {
        return SigilConfig::default();
    }
    match fs::read_to_string(&path) {
        Ok(content) => match toml::from_str(&content) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("sigil: warning: failed to parse {}: {}", path.display(), e);
                SigilConfig::default()
            }
        },
        Err(e) => {
            eprintln!("sigil: warning: failed to read {}: {}", path.display(), e);
            SigilConfig::default()
        }
    }
}

fn config_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".sigil.toml"))
}
