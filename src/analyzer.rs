use anyhow::{Context, Result};
use goblin::Object;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub path: String,
    pub format: String,
    pub arch: String,
    pub headers: Vec<(String, String)>,
    pub imports: Vec<ImportEntry>,
    pub exports: Vec<ExportEntry>,
    pub symbols: Vec<SymbolEntry>,
    pub tls_callbacks: Vec<String>,
    pub strings: Vec<String>,
    pub entropy: f64,
    pub sections: Vec<SectionInfo>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ImportEntry {
    pub library: String,
    pub function: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportEntry {
    pub name: String,
    pub rva: u64,
    pub ordinal: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SymbolEntry {
    pub name: String,
    pub address: u64,
    pub kind: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub size: u64,
    pub entropy: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CategorizedStrings {
    pub urls: Vec<String>,
    pub ips: Vec<String>,
    pub registry: Vec<String>,
    pub paths: Vec<String>,
    pub guids: Vec<String>,
    pub other: Vec<String>,
}

pub fn analyze(path: &str) -> Result<BinaryInfo> {
    let data = fs::read(path).context("failed to read file")?;
    let entropy = shannon_entropy(&data);
    match Object::parse(&data)? {
        Object::PE(pe) => parse_pe(path, &pe, &data, entropy),
        Object::Elf(elf) => parse_elf(path, &elf, &data, entropy),
        _ => anyhow::bail!("unsupported format (only PE and ELF supported)"),
    }
}

fn rva_to_file_offset(pe: &goblin::pe::PE, rva: u64) -> Option<u64> {
    for section in &pe.sections {
        let start = section.virtual_address as u64;
        let mut v_sz = section.virtual_size as u64;
        if v_sz == 0 {
            v_sz = section.size_of_raw_data as u64;
        }
        let end = start + v_sz;
        if rva >= start && rva < end {
            return Some(rva - start + section.pointer_to_raw_data as u64);
        }
    }
    None
}

fn parse_pe(path: &str, pe: &goblin::pe::PE, data: &[u8], entropy: f64) -> Result<BinaryInfo> {
    let arch = if pe.is_64 { "x86_64" } else { "x86" }.to_string();
    let mut headers = vec![
        ("Format".into(), "PE".into()),
        ("Arch".into(), arch.clone()),
        ("Entry Point".into(), format!("0x{:x}", pe.entry)),
        ("Image Base".into(), format!("0x{:x}", pe.image_base)),
        ("Is DLL".into(), pe.is_lib.to_string()),
    ];
    if let Some(opt) = &pe.header.optional_header {
        headers.push(("Subsystem".into(), format!("{}", opt.windows_fields.subsystem)));
        headers.push(("Timestamp".into(), format!("{}", pe.header.coff_header.time_date_stamp)));
        headers.push(("Compiler Stamp".into(), format!("0x{:x}", pe.header.coff_header.time_date_stamp)));
    }

    let imports: Vec<ImportEntry> = pe.imports.iter()
        .map(|i| ImportEntry { library: i.dll.to_string(), function: i.name.to_string() })
        .collect();

    let exports: Vec<ExportEntry> = pe.exports.iter()
        .map(|ex| ExportEntry {
            name: ex.name.unwrap_or("(ordinal)").to_string(),
            rva: ex.rva as u64,
            ordinal: None,
        })
        .collect();

    let mut tls_callbacks: Vec<String> = Vec::new();
    if let Some(opt) = &pe.header.optional_header {
        if let Some(tls_dir) = opt.data_directories.get_tls_table() {
            if tls_dir.virtual_address > 0 && tls_dir.size > 0 {
                if let Some(offset) = rva_to_file_offset(pe, tls_dir.virtual_address as u64) {
                    let offset = offset as usize;
                    if pe.is_64 {
                        if let Some(addr_of_callbacks_bytes) = data.get(offset + 24..offset + 32) {
                            let addr_of_callbacks = u64::from_le_bytes(addr_of_callbacks_bytes.try_into().unwrap());
                            if addr_of_callbacks > 0 {
                                let callbacks_rva = addr_of_callbacks.saturating_sub(pe.image_base as u64);
                                if let Some(mut callbacks_offset) = rva_to_file_offset(pe, callbacks_rva) {
                                    loop {
                                        if let Some(cb_bytes) = data.get(callbacks_offset as usize..callbacks_offset as usize + 8) {
                                            let cb_va = u64::from_le_bytes(cb_bytes.try_into().unwrap());
                                            if cb_va == 0 {
                                                break;
                                            }
                                            tls_callbacks.push(format!("0x{:x}", cb_va));
                                            callbacks_offset += 8;
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        if let Some(addr_of_callbacks_bytes) = data.get(offset + 12..offset + 16) {
                            let addr_of_callbacks = u32::from_le_bytes(addr_of_callbacks_bytes.try_into().unwrap()) as u64;
                            if addr_of_callbacks > 0 {
                                let callbacks_rva = addr_of_callbacks.saturating_sub(pe.image_base as u64);
                                if let Some(mut callbacks_offset) = rva_to_file_offset(pe, callbacks_rva) {
                                    loop {
                                        if let Some(cb_bytes) = data.get(callbacks_offset as usize..callbacks_offset as usize + 4) {
                                            let cb_va = u32::from_le_bytes(cb_bytes.try_into().unwrap()) as u64;
                                            if cb_va == 0 {
                                                break;
                                            }
                                            tls_callbacks.push(format!("0x{:x}", cb_va));
                                            callbacks_offset += 4;
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let sections: Vec<SectionInfo> = pe.sections.iter()
        .map(|s| {
            let off = s.pointer_to_raw_data as usize;
            let sz = s.size_of_raw_data as usize;
            let sec_data = data.get(off..off + sz).unwrap_or(&[]);
            SectionInfo {
                name: String::from_utf8_lossy(&s.name).trim_matches('\0').to_string(),
                size: sz as u64,
                entropy: shannon_entropy(sec_data),
            }
        })
        .collect();

    Ok(BinaryInfo {
        path: path.to_string(),
        format: "PE".into(),
        arch,
        headers,
        imports,
        exports,
        symbols: vec![],
        tls_callbacks,
        strings: extract_strings(data),
        entropy,
        sections,
    })
}

fn parse_elf(path: &str, elf: &goblin::elf::Elf, data: &[u8], entropy: f64) -> Result<BinaryInfo> {
    let arch = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => "x86_64",
        goblin::elf::header::EM_386   => "x86",
        goblin::elf::header::EM_AARCH64 => "aarch64",
        goblin::elf::header::EM_ARM   => "arm",
        _ => "unknown",
    }.to_string();

    let headers = vec![
        ("Format".into(), "ELF".into()),
        ("Arch".into(), arch.clone()),
        ("Entry Point".into(), format!("0x{:x}", elf.header.e_entry)),
        ("Class".into(), if elf.is_64 { "ELF64" } else { "ELF32" }.to_string()),
        ("Endian".into(), if elf.little_endian { "Little" } else { "Big" }.to_string()),
        ("Type".into(), format!("{}", elf.header.e_type)),
        ("Interpreter".into(), elf.interpreter.unwrap_or("(none)").to_string()),
    ];

    let imports: Vec<ImportEntry> = elf.libraries.iter()
        .flat_map(|lib| {
            elf.dynsyms.iter()
                .filter(|sym| sym.is_import())
                .map(move |sym| ImportEntry {
                    library: lib.to_string(),
                    function: elf.dynstrtab.get_at(sym.st_name).unwrap_or("??").to_string(),
                })
        })
        .collect();

    let exports: Vec<ExportEntry> = elf.dynsyms.iter()
        .filter(|s| !s.is_import() && s.st_value != 0)
        .map(|s| ExportEntry {
            name: elf.dynstrtab.get_at(s.st_name).unwrap_or("??").to_string(),
            rva: s.st_value,
            ordinal: None,
        })
        .collect();

    let symbols: Vec<SymbolEntry> = elf.syms.iter()
        .filter(|s| s.st_value != 0)
        .map(|s| SymbolEntry {
            name: elf.strtab.get_at(s.st_name).unwrap_or("??").to_string(),
            address: s.st_value,
            kind: sym_type_str(s.st_type()),
        })
        .collect();

    let sections: Vec<SectionInfo> = elf.section_headers.iter()
        .filter(|s| s.sh_size > 0)
        .map(|s| {
            let off = s.sh_offset as usize;
            let sz = s.sh_size as usize;
            let sec_data = data.get(off..off + sz).unwrap_or(&[]);
            SectionInfo {
                name: elf.shdr_strtab.get_at(s.sh_name).unwrap_or("").to_string(),
                size: sz as u64,
                entropy: shannon_entropy(sec_data),
            }
        })
        .collect();

    Ok(BinaryInfo {
        path: path.to_string(),
        format: "ELF".into(),
        arch,
        headers,
        imports,
        exports,
        symbols,
        tls_callbacks: vec![],
        strings: extract_strings(data),
        entropy,
        sections,
    })
}

fn sym_type_str(t: u8) -> String {
    match t {
        goblin::elf::sym::STT_FUNC   => "func",
        goblin::elf::sym::STT_OBJECT => "object",
        goblin::elf::sym::STT_SECTION => "section",
        goblin::elf::sym::STT_FILE   => "file",
        _ => "other",
    }.to_string()
}

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u64; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    counts.iter().filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / len; -p * p.log2() })
        .sum()
}

pub fn extract_strings(data: &[u8]) -> Vec<String> {
    let mut results = Vec::new();
    let mut cur = Vec::new();
    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            cur.push(b);
        } else {
            if cur.len() >= 4 { results.push(String::from_utf8_lossy(&cur).to_string()); }
            cur.clear();
        }
    }
    if cur.len() >= 4 { results.push(String::from_utf8_lossy(&cur).to_string()); }
    results
}

pub fn categorize_strings(strings: &[String]) -> CategorizedStrings {
    use std::sync::OnceLock;
    use regex::Regex;

    static URL_RE: OnceLock<Regex> = OnceLock::new();
    static IP_RE: OnceLock<Regex> = OnceLock::new();
    static REG_RE: OnceLock<Regex> = OnceLock::new();
    static PATH_RE: OnceLock<Regex> = OnceLock::new();
    static GUID_RE: OnceLock<Regex> = OnceLock::new();

    let url_re = URL_RE.get_or_init(|| Regex::new(r"(?i)https?://[^\s]{4,}").unwrap());
    let ip_re = IP_RE.get_or_init(|| Regex::new(r"\b(\d{1,3}\.){3}\d{1,3}(:\d+)?\b").unwrap());
    let reg_re = REG_RE.get_or_init(|| Regex::new(r"(?i)(HKEY_|HKLM|HKCU|HKCR|SOFTWARE\\|SYSTEM\\)").unwrap());
    let path_re = PATH_RE.get_or_init(|| Regex::new(r"(?i)([A-Za-z]:\\|/proc/|/sys/|/dev/|/etc/)").unwrap());
    let guid_re = GUID_RE.get_or_init(|| Regex::new(r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}").unwrap());

    let mut cats = CategorizedStrings { urls: vec![], ips: vec![], registry: vec![], paths: vec![], guids: vec![], other: vec![] };
    for s in strings {
        if s.len() > 150 { continue; } // skip long junk blobs
        if url_re.is_match(s)  { cats.urls.push(s.clone()); }
        else if ip_re.is_match(s)   { cats.ips.push(s.clone()); }
        else if reg_re.is_match(s)  { cats.registry.push(s.clone()); }
        else if path_re.is_match(s) { cats.paths.push(s.clone()); }
        else if guid_re.is_match(s) { cats.guids.push(s.clone()); }
        else                         { cats.other.push(s.clone()); }
    }
    cats
}

/// search for hex pattern, ?? is wildcard
pub fn pattern_search(data: &[u8], pattern: &str) -> Result<Vec<usize>> {
    let tokens: Vec<&str> = pattern.split_whitespace().collect();
    if tokens.is_empty() { anyhow::bail!("empty pattern"); }
    let pat: Vec<Option<u8>> = tokens.iter().map(|t| {
        if *t == "??" || *t == "?" { None }
        else {
            match u8::from_str_radix(t, 16) {
                Ok(b) => Some(b),
                Err(_) => {
                    eprintln!("sigil: invalid hex token '{}' in pattern — expected XX or ??", t);
                    Some(0xFF) // error placeholder
                }
            }
        }
    }).collect();
    // check if hex is valid
    for (i, t) in tokens.iter().enumerate() {
        if *t != "??" && *t != "?" && u8::from_str_radix(t, 16).is_err() {
            anyhow::bail!("invalid hex token '{}' — use format: '48 8B ?? ??' ", t);
        }
        let _ = i;
    }
    let len = pat.len();
    let mut hits = Vec::new();
    'outer: for i in 0..=data.len().saturating_sub(len) {
        for (j, p) in pat.iter().enumerate() {
            if let Some(b) = p {
                if data[i + j] != *b { continue 'outer; }
            }
        }
        hits.push(i);
    }
    Ok(hits)
}

/// finds the first executable section
pub fn code_section(path: &str) -> Result<(usize, usize, u64, String)> {
    let data = fs::read(path)?;
    match Object::parse(&data)? {
        Object::PE(pe) => {
            for s in &pe.sections {
                if s.characteristics & 0x20000020 != 0 {
                    let off = s.pointer_to_raw_data as usize;
                    let sz = s.size_of_raw_data as usize;
                    let va = pe.image_base as u64 + s.virtual_address as u64;
                    let arch = if pe.is_64 { "x86_64" } else { "x86" }.to_string();
                    return Ok((off, sz, va, arch));
                }
            }
            anyhow::bail!("no executable section found")
        }
        Object::Elf(elf) => {
            for sh in &elf.section_headers {
                if sh.sh_flags & 0x4 != 0 && sh.sh_size > 0 {
                    let arch = match elf.header.e_machine {
                        goblin::elf::header::EM_X86_64 => "x86_64",
                        goblin::elf::header::EM_386   => "x86",
                        goblin::elf::header::EM_AARCH64 => "aarch64",
                        goblin::elf::header::EM_ARM   => "arm",
                        _ => "unknown",
                    }.to_string();
                    return Ok((sh.sh_offset as usize, sh.sh_size as usize, sh.sh_addr, arch));
                }
            }
            anyhow::bail!("no executable section found")
        }
        _ => anyhow::bail!("unsupported format"),
    }
}

pub fn packing_hints(path: &str) -> Result<Vec<String>> {
    let data = fs::read(path)?;
    let mut hints = Vec::new();
    match Object::parse(&data)? {
        Object::PE(pe) => {
            let mut last_end = 0usize;
            for s in &pe.sections {
                let off = s.pointer_to_raw_data as usize;
                let sz = s.size_of_raw_data as usize;
                let sec_data = data.get(off..off + sz).unwrap_or(&[]);
                let ent = shannon_entropy(sec_data);
                let name = String::from_utf8_lossy(&s.name).trim_matches('\0').to_string();
                if ent > 7.0 { hints.push(format!("HIGH ENTROPY section '{}': {:.3} — likely packed/encrypted", name, ent)); }
                if name.is_empty() || name == "." { hints.push(format!("UNNAMED section at offset 0x{:x} size {} — packer artefact", off, sz)); }
                last_end = last_end.max(off + sz);
            }
            if last_end < data.len() {
                let overlay = data.len() - last_end;
                if overlay > 512 { hints.push(format!("OVERLAY detected: {} bytes after last section (SFX/appended payload?)", overlay)); }
            }
        }
        Object::Elf(elf) => {
            for sh in &elf.section_headers {
                if sh.sh_size == 0 { continue; }
                let off = sh.sh_offset as usize;
                let sz = sh.sh_size as usize;
                let sec_data = data.get(off..off + sz).unwrap_or(&[]);
                let ent = shannon_entropy(sec_data);
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                if ent > 7.0 { hints.push(format!("HIGH ENTROPY section '{}': {:.3}", name, ent)); }
            }
        }
        _ => {}
    }
    if hints.is_empty() { hints.push("No packing indicators found.".into()); }
    Ok(hints)
}

pub fn import_tuples(info: &BinaryInfo) -> Vec<(String, String)> {
    info.imports.iter().map(|i| (i.library.clone(), i.function.clone())).collect()
}

pub fn packing_verdict(entropy: f64) -> &'static str {
    if entropy > 7.2 { "LIKELY PACKED/ENCRYPTED" }
    else if entropy > 6.5 { "SUSPICIOUS" }
    else { "NORMAL" }
}
