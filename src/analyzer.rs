use anyhow::{Context, Result};
use goblin::Object;
use serde::{Deserialize, Serialize};
use std::fs;

// Maximum file size accepted (256 MB) — prevents OOM on adversarial input
pub const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;

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

/// Read and validate a binary file, enforcing the size cap.
pub fn read_file(path: &str) -> Result<Vec<u8>> {
    let meta = fs::metadata(path)
        .with_context(|| format!("cannot stat '{}'", path))?;
    if meta.len() > MAX_FILE_SIZE {
        anyhow::bail!(
            "file is {:.1} MB — exceeds the {:.0} MB safety cap; use --no-size-limit to override",
            meta.len() as f64 / 1_048_576.0,
            MAX_FILE_SIZE as f64 / 1_048_576.0,
        );
    }
    fs::read(path).with_context(|| format!("failed to read '{}'", path))
}

/// Analyse a binary, returning the parsed info *and* the raw bytes so callers
/// can pass them on to packing_hints / hashes without re-reading the file.
pub fn analyze(path: &str) -> Result<(BinaryInfo, Vec<u8>)> {
    let data = read_file(path)?;
    let entropy = shannon_entropy(&data);
    let info = match Object::parse(&data)? {
        Object::PE(pe) => parse_pe(path, &pe, &data, entropy),
        Object::Elf(elf) => parse_elf(path, &elf, &data, entropy),
        _ => anyhow::bail!("unsupported format (only PE and ELF supported)"),
    }?;
    Ok((info, data))
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
        headers.push((
            "Subsystem".into(),
            format!("{}", opt.windows_fields.subsystem),
        ));
        headers.push((
            "Timestamp".into(),
            format!("{}", pe.header.coff_header.time_date_stamp),
        ));
        // Rich header / linker fingerprint would go here; for now just the COFF stamp
    }

    let imports: Vec<ImportEntry> = pe
        .imports
        .iter()
        .map(|i| ImportEntry {
            library: i.dll.to_string(),
            function: i.name.to_string(),
        })
        .collect();

    let exports: Vec<ExportEntry> = pe
        .exports
        .iter()
        .map(|ex| ExportEntry {
            name: ex.name.unwrap_or("(ordinal)").to_string(),
            rva: ex.rva as u64,
            ordinal: None,
        })
        .collect();

    // NOTE: This detects the .tls *section* which is a reliable indicator, but
    // does not enumerate actual TLS callback VAs from the data directory.
    // Full callback enumeration (walking IMAGE_TLS_DIRECTORY) is tracked as a
    // future improvement.
    let tls_callbacks: Vec<String> = pe
        .sections
        .iter()
        .filter(|s| {
            String::from_utf8_lossy(&s.name)
                .trim_matches('\0')
                .eq_ignore_ascii_case(".tls")
        })
        .map(|s| {
            format!(
                ".tls section at VA 0x{:x}, raw size {}",
                s.virtual_address, s.size_of_raw_data
            )
        })
        .collect();

    let sections: Vec<SectionInfo> = pe
        .sections
        .iter()
        .map(|s| {
            let off = s.pointer_to_raw_data as usize;
            let sz = s.size_of_raw_data as usize;
            let sec_data = data.get(off..off + sz).unwrap_or(&[]);
            SectionInfo {
                name: String::from_utf8_lossy(&s.name)
                    .trim_matches('\0')
                    .to_string(),
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
        strings: extract_strings(data, 4),
        entropy,
        sections,
    })
}

fn parse_elf(path: &str, elf: &goblin::elf::Elf, data: &[u8], entropy: f64) -> Result<BinaryInfo> {
    let arch = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => "x86_64",
        goblin::elf::header::EM_386 => "x86",
        goblin::elf::header::EM_AARCH64 => "aarch64",
        goblin::elf::header::EM_ARM => "arm",
        _ => "unknown",
    }
    .to_string();

    let headers = vec![
        ("Format".into(), "ELF".into()),
        ("Arch".into(), arch.clone()),
        ("Entry Point".into(), format!("0x{:x}", elf.header.e_entry)),
        (
            "Class".into(),
            if elf.is_64 { "ELF64" } else { "ELF32" }.to_string(),
        ),
        (
            "Endian".into(),
            if elf.little_endian { "Little" } else { "Big" }.to_string(),
        ),
        ("Type".into(), format!("{}", elf.header.e_type)),
        (
            "Interpreter".into(),
            elf.interpreter.unwrap_or("(none)").to_string(),
        ),
    ];

    // ELF does not map individual symbols to their source library at the
    // symbol-table level (unlike PE's import descriptor table).  We list
    // unresolved dynamic symbols and note the required shared libraries
    // separately so callers get accurate data instead of a cross-product.
    let imports: Vec<ImportEntry> = elf
        .dynsyms
        .iter()
        .filter(|sym| sym.is_import())
        .map(|sym| ImportEntry {
            // "(dynamic)" makes it clear we don't know the exact source lib
            library: "(dynamic)".to_string(),
            function: elf
                .dynstrtab
                .get_at(sym.st_name)
                .unwrap_or("??")
                .to_string(),
        })
        .collect();

    let exports: Vec<ExportEntry> = elf
        .dynsyms
        .iter()
        .filter(|s| !s.is_import() && s.st_value != 0)
        .map(|s| ExportEntry {
            name: elf
                .dynstrtab
                .get_at(s.st_name)
                .unwrap_or("??")
                .to_string(),
            rva: s.st_value,
            ordinal: None,
        })
        .collect();

    let symbols: Vec<SymbolEntry> = elf
        .syms
        .iter()
        .filter(|s| s.st_value != 0)
        .map(|s| SymbolEntry {
            name: elf
                .strtab
                .get_at(s.st_name)
                .unwrap_or("??")
                .to_string(),
            address: s.st_value,
            kind: sym_type_str(s.st_type()),
        })
        .collect();

    let sections: Vec<SectionInfo> = elf
        .section_headers
        .iter()
        .filter(|s| s.sh_size > 0)
        .map(|s| {
            let off = s.sh_offset as usize;
            let sz = s.sh_size as usize;
            let sec_data = data.get(off..off + sz).unwrap_or(&[]);
            SectionInfo {
                name: elf
                    .shdr_strtab
                    .get_at(s.sh_name)
                    .unwrap_or("")
                    .to_string(),
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
        strings: extract_strings(data, 4),
        entropy,
        sections,
    })
}

fn sym_type_str(t: u8) -> String {
    match t {
        goblin::elf::sym::STT_FUNC => "func",
        goblin::elf::sym::STT_OBJECT => "object",
        goblin::elf::sym::STT_SECTION => "section",
        goblin::elf::sym::STT_FILE => "file",
        _ => "other",
    }
    .to_string()
}

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Extract printable ASCII strings of at least `min_len` bytes.
pub fn extract_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut results = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            cur.push(b);
        } else {
            if cur.len() >= min_len {
                results.push(String::from_utf8_lossy(&cur).to_string());
            }
            cur.clear();
        }
    }
    if cur.len() >= min_len {
        results.push(String::from_utf8_lossy(&cur).to_string());
    }
    results
}

pub fn categorize_strings(strings: &[String]) -> CategorizedStrings {
    let url_re = regex::Regex::new(r"(?i)https?://[^\s]{4,}").unwrap();
    let ip_re = regex::Regex::new(r"\b(\d{1,3}\.){3}\d{1,3}(:\d+)?\b").unwrap();
    let reg_re =
        regex::Regex::new(r"(?i)(HKEY_|HKLM|HKCU|HKCR|SOFTWARE\\|SYSTEM\\)").unwrap();
    let path_re =
        regex::Regex::new(r"(?i)([A-Za-z]:\\|/proc/|/sys/|/dev/|/etc/)").unwrap();
    let guid_re = regex::Regex::new(
        r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}",
    )
    .unwrap();

    let mut cats = CategorizedStrings {
        urls: vec![],
        ips: vec![],
        registry: vec![],
        paths: vec![],
        guids: vec![],
        other: vec![],
    };
    for s in strings {
        if s.len() > 150 {
            continue;
        }
        if url_re.is_match(s) {
            cats.urls.push(s.clone());
        } else if ip_re.is_match(s) {
            cats.ips.push(s.clone());
        } else if reg_re.is_match(s) {
            cats.registry.push(s.clone());
        } else if path_re.is_match(s) {
            cats.paths.push(s.clone());
        } else if guid_re.is_match(s) {
            cats.guids.push(s.clone());
        } else {
            cats.other.push(s.clone());
        }
    }
    cats
}

/// Search binary for a hex byte pattern with `??` wildcards.
/// Returns a list of offsets where the pattern matched.
pub fn pattern_search(data: &[u8], pattern: &str) -> Result<Vec<usize>> {
    let tokens: Vec<&str> = pattern.split_whitespace().collect();
    if tokens.is_empty() {
        anyhow::bail!("empty pattern");
    }

    // Parse in a single pass — fail fast on any invalid token
    let pat: Vec<Option<u8>> = tokens
        .iter()
        .map(|t| match *t {
            "??" | "?" => Ok(None),
            t => u8::from_str_radix(t, 16)
                .map(Some)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "invalid hex token '{}' — expected XX or ?? (e.g. '48 8B ?? ??')",
                        t
                    )
                }),
        })
        .collect::<Result<_>>()?;

    let pat_len = pat.len();
    let mut hits = Vec::new();

    'outer: for i in 0..=data.len().saturating_sub(pat_len) {
        for (j, p) in pat.iter().enumerate() {
            if let Some(b) = p {
                if data[i + j] != *b {
                    continue 'outer;
                }
            }
        }
        hits.push(i);
    }
    Ok(hits)
}

/// Returns `(offset, size, base_va, is_64)` for the first executable section.
/// Takes pre-read bytes to avoid a redundant file read.
pub fn code_section_from_bytes(data: &[u8]) -> Result<(usize, usize, u64, bool)> {
    match Object::parse(data)? {
        Object::PE(pe) => {
            for s in &pe.sections {
                // IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE
                if s.characteristics & 0x2000_0020 != 0 {
                    let off = s.pointer_to_raw_data as usize;
                    let sz = s.size_of_raw_data as usize;
                    let va = pe.image_base as u64 + s.virtual_address as u64;
                    return Ok((off, sz, va, pe.is_64));
                }
            }
            anyhow::bail!("no executable section found")
        }
        Object::Elf(elf) => {
            for sh in &elf.section_headers {
                if sh.sh_flags & 0x4 != 0 && sh.sh_size > 0 {
                    return Ok((
                        sh.sh_offset as usize,
                        sh.sh_size as usize,
                        sh.sh_addr,
                        elf.is_64,
                    ));
                }
            }
            anyhow::bail!("no executable section found")
        }
        _ => anyhow::bail!("unsupported format"),
    }
}

/// Packing / obfuscation heuristics from pre-read bytes.
pub fn packing_hints_from_bytes(data: &[u8]) -> Result<Vec<String>> {
    let mut hints = Vec::new();
    match Object::parse(data)? {
        Object::PE(pe) => {
            let mut last_end = 0usize;
            for s in &pe.sections {
                let off = s.pointer_to_raw_data as usize;
                let sz = s.size_of_raw_data as usize;
                let sec_data = data.get(off..off + sz).unwrap_or(&[]);
                let ent = shannon_entropy(sec_data);
                let name = String::from_utf8_lossy(&s.name)
                    .trim_matches('\0')
                    .to_string();
                if ent > 7.0 {
                    hints.push(format!(
                        "HIGH ENTROPY section '{}': {:.3} — likely packed/encrypted",
                        name, ent
                    ));
                }
                if name.is_empty() || name == "." {
                    hints.push(format!(
                        "UNNAMED section at offset 0x{:x} size {} — packer artefact",
                        off, sz
                    ));
                }
                last_end = last_end.max(off + sz);
            }
            if last_end < data.len() {
                let overlay = data.len() - last_end;
                if overlay > 512 {
                    hints.push(format!(
                        "OVERLAY detected: {} bytes after last section (SFX/appended payload?)",
                        overlay
                    ));
                }
            }
        }
        Object::Elf(elf) => {
            for sh in &elf.section_headers {
                if sh.sh_size == 0 {
                    continue;
                }
                let off = sh.sh_offset as usize;
                let sz = sh.sh_size as usize;
                let sec_data = data.get(off..off + sz).unwrap_or(&[]);
                let ent = shannon_entropy(sec_data);
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                if ent > 7.0 {
                    hints.push(format!("HIGH ENTROPY section '{}': {:.3}", name, ent));
                }
            }
        }
        _ => {}
    }
    if hints.is_empty() {
        hints.push("No packing indicators found.".into());
    }
    Ok(hints)
}

pub fn import_tuples(info: &BinaryInfo) -> Vec<(String, String)> {
    info.imports
        .iter()
        .map(|i| (i.library.clone(), i.function.clone()))
        .collect()
}

pub fn packing_verdict(entropy: f64) -> &'static str {
    if entropy > 7.2 {
        "LIKELY PACKED/ENCRYPTED"
    } else if entropy > 6.5 {
        "SUSPICIOUS"
    } else {
        "NORMAL"
    }
}
