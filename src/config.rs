use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

/// A single user-defined signature entry.
///
/// For import/string signatures, `pattern` is matched the same way as the
/// built-in tables in `sigs.rs` (case-insensitive exact match for imports,
/// case-insensitive substring match for strings).
#[derive(Debug, Deserialize, Clone)]
pub struct SigEntry {
    pub pattern: String,
    pub description: String,
}

/// Layout of `~/.sigil.toml`. All sections are optional — an empty or
/// missing file behaves identically to no config at all.
///
/// Example:
/// ```toml
/// [[antidebug_imports]]
/// pattern = "MyCustomDebugCheck"
/// description = "Internal debug-check wrapper used by our build"
///
/// [[anticheat_strings]]
/// pattern = "myac_driver.sys"
/// description = "Our internal anti-cheat kernel driver"
///
/// [[known_imphashes]]
/// pattern = "a909b3c8d3d1ce4ae0a4f607a37a8129"
/// description = "Known Cobalt Strike stager (internal threat intel)"
/// ```
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
///
/// Returns an empty (default) config if the file does not exist, `$HOME`
/// is unset, or the file fails to parse. Parse errors are reported on
/// stderr as warnings rather than hard failures — a malformed user config
/// should never prevent sigil from analysing a binary.
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
