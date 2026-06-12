use anyhow::Result;
use sha2::{Digest as _, Sha256};
use goblin::Object;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
pub struct Hashes {
    pub md5: String,
    pub sha256: String,
    pub imphash: Option<String>,
}

pub fn compute(path: &str) -> Result<Hashes> {
    let data = fs::read(path)?;
    let md5 = format!("{:x}", md5::compute(&data));
    let sha256 = format!("{:x}", Sha256::digest(&data));
    let imphash = compute_imphash(&data);
    Ok(Hashes { md5, sha256, imphash })
}

/// standard PE imphash: md5 of "lib.func" sorted by order of imports
pub fn compute_imphash(data: &[u8]) -> Option<String> {
    match Object::parse(data).ok()? {
        Object::PE(pe) => {
            let entries: Vec<String> = pe.imports.iter().map(|i| {
                let lib = i.dll.to_lowercase().trim_end_matches(".dll").to_string();
                let func = i.name.to_lowercase();
                format!("{}.{}", lib, func)
            }).collect();
            if entries.is_empty() { return None; }
            let combined = entries.join(",");
            Some(format!("{:x}", md5::compute(combined.as_bytes())))
        }
        _ => None,
    }
}
