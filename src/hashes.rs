use anyhow::Result;
use goblin::Object;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::analyzer::read_file;

#[derive(Debug, Serialize, Deserialize)]
pub struct Hashes {
    pub md5: String,
    pub sha256: String,
    pub imphash: Option<String>,
}

/// Compute hashes from a path — reads the file once.
pub fn compute(path: &str, no_size_limit: bool) -> Result<Hashes> {
    let data = read_file(path, no_size_limit)?;
    Ok(from_bytes(&data))
}

/// Compute hashes from pre-read bytes — use this when you already have the
/// data in memory to avoid a redundant read.
pub fn from_bytes(data: &[u8]) -> Hashes {
    let md5 = format!("{:x}", md5::compute(data));
    let sha256 = format!("{:x}", Sha256::digest(data));
    let imphash = compute_imphash(data);
    Hashes {
        md5,
        sha256,
        imphash,
    }
}

/// PE imphash: MD5 of lowercased "lib.func,lib.func,..." in import order.
fn compute_imphash(data: &[u8]) -> Option<String> {
    match Object::parse(data).ok()? {
        Object::PE(pe) => {
            let entries: Vec<String> = pe
                .imports
                .iter()
                .map(|i| {
                    let lib = i.dll.to_lowercase().trim_end_matches(".dll").to_string();
                    let func = i.name.to_lowercase();
                    format!("{}.{}", lib, func)
                })
                .collect();
            if entries.is_empty() {
                return None;
            }
            let combined = entries.join(",");
            Some(format!("{:x}", md5::compute(combined.as_bytes())))
        }
        _ => None,
    }
}
