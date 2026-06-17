use anyhow::{Context, Result};
use goblin::Object;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::sync::OnceLock;

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
    /// PE-only: parsed Rich header (compiler/linker fingerprint), if present
    pub rich_header: Option<RichHeaderInfo>,
    /// PE-only: trailing data appended after the last section, if any
    pub overlay: Option<OverlayInfo>,
    /// PE-only: Authenticode certificate table info, if present
    pub authenticode: Option<AuthenticodeInfo>,
    /// PE-only: VS_VERSIONINFO fields (CompanyName, OriginalFilename, etc.)
    pub version_info: Option<VersionInfo>,
    /// PE-only: SHA-256 of each RT_ICON resource, for cross-sample comparison
    pub icon_hashes: Vec<String>,
    /// PE-only: CLR / .NET assembly metadata, present only in managed binaries
    pub clr: Option<crate::clr::ClrInfo>,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RichHeaderEntry {
    /// Raw CompID dword (productId << 16 | buildNumber)
    pub comp_id: u32,
    pub product_id: u16,
    pub build_number: u16,
    pub count: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RichHeaderInfo {
    pub entries: Vec<RichHeaderEntry>,
    /// MD5 of the decoded entry table — a compiler/linker toolchain
    /// fingerprint. Two binaries built with the same toolchain and the
    /// same set of object files tend to share this hash.
    pub hash: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OverlayInfo {
    /// File offset where the overlay begins (= end of the last section)
    pub offset: u64,
    pub size: u64,
    pub sha256: String,
    pub entropy: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthenticodeInfo {
    /// wCertificateType from WIN_CERTIFICATE (0x0002 = PKCS#7 SignedData)
    pub cert_type: u16,
    /// wRevision from WIN_CERTIFICATE (0x0200 = WIN_CERT_REVISION_2_0)
    pub cert_revision: u16,
    /// Size in bytes of the certificate table entry
    pub size: u32,
    /// Printable strings extracted from the raw DER-encoded certificate
    /// blob — typically includes Subject/Issuer Common Names and
    /// Organization fields from the X.509 certificate(s).
    ///
    /// NOTE: this is a heuristic string scan, *not* signature
    /// verification. A binary having an Authenticode certificate table
    /// does not mean the signature is valid, unexpired, or trusted —
    /// only that one is present.
    pub candidate_identities: Vec<String>,
}

/// Standard VS_VERSIONINFO StringFileInfo fields, extracted heuristically
/// by scanning the RT_VERSION resource for known UTF-16LE key names and
/// reading the value that follows.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct VersionInfo {
    pub company_name: Option<String>,
    pub file_description: Option<String>,
    pub file_version: Option<String>,
    pub internal_name: Option<String>,
    pub legal_copyright: Option<String>,
    pub original_filename: Option<String>,
    pub product_name: Option<String>,
    pub product_version: Option<String>,
}

impl VersionInfo {
    fn is_empty(&self) -> bool {
        self.company_name.is_none()
            && self.file_description.is_none()
            && self.file_version.is_none()
            && self.internal_name.is_none()
            && self.legal_copyright.is_none()
            && self.original_filename.is_none()
            && self.product_name.is_none()
            && self.product_version.is_none()
    }
}

// ── little-endian byte readers ─────────────────────────────────────────────

fn r16le(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() { return 0; }
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn r32le(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() { return 0; }
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn r64le(data: &[u8], off: usize) -> u64 {
    if off + 8 > data.len() { return 0; }
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[off..off + 8]);
    u64::from_le_bytes(b)
}

/// Read and validate a binary file.
/// Set `no_size_limit = true` to bypass the 256 MB cap (e.g. for large firmware blobs).
pub fn read_file(path: &str, no_size_limit: bool) -> Result<Vec<u8>> {
    let meta = fs::metadata(path)
        .with_context(|| format!("cannot stat '{}'", path))?;
    if !no_size_limit && meta.len() > MAX_FILE_SIZE {
        anyhow::bail!(
            "file is {:.1} MB — exceeds the {:.0} MB safety cap; pass --no-size-limit to override",
            meta.len() as f64 / 1_048_576.0,
            MAX_FILE_SIZE as f64 / 1_048_576.0,
        );
    }
    fs::read(path).with_context(|| format!("failed to read '{}'", path))
}

/// Convert an RVA to a file offset using the PE section table.
fn rva_to_offset(rva: u64, sections: &[goblin::pe::section_table::SectionTable]) -> Option<usize> {
    for s in sections {
        let va = s.virtual_address as u64;
        let size = (s.virtual_size as u64).max(s.size_of_raw_data as u64);
        if rva >= va && rva < va + size {
            return Some((s.pointer_to_raw_data as u64 + (rva - va)) as usize);
        }
    }
    None
}

/// Parse the (undocumented) PE "Rich" header — an XOR-obfuscated table of
/// linker/compiler tool identifiers that MSVC embeds between the DOS stub
/// and the PE header. Useful as a build-toolchain fingerprint: two binaries
/// compiled from the same project with the same toolchain tend to produce
/// the same hash, while a packed/repacked binary often has none at all.
///
/// Returns `None` if no "Rich" marker is found (common for non-MSVC
/// toolchains, hand-crafted PEs, or binaries where the DOS stub was
/// stripped/overwritten by a packer).
pub fn parse_rich_header(data: &[u8], lfanew: u32) -> Option<RichHeaderInfo> {
    let lfanew = lfanew as usize;
    if lfanew < 0x80 || lfanew > data.len() {
        return None;
    }

    // Search for the "Rich" marker in the DOS-stub region [0x80, lfanew)
    let region = &data[0x80..lfanew];
    let rich_rel = region.windows(4).position(|w| w == b"Rich")?;
    let rich_abs = 0x80 + rich_rel;
    if rich_abs + 8 > data.len() {
        return None;
    }
    // The 4 bytes immediately after "Rich" are the XOR key
    let key = r32le(data, rich_abs + 4);

    // Walk backwards in 4-byte steps looking for the XOR-encoded "DanS"
    // marker (0x536E6144), which marks the start of the table
    let mut dans_pos = None;
    let mut p = rich_abs;
    while p >= 0x80 + 4 {
        p -= 4;
        if r32le(data, p) ^ key == 0x536E_6144 {
            dans_pos = Some(p);
            break;
        }
    }
    let dans_pos = dans_pos?;

    // DanS is followed by 3 zero-padding dwords, then pairs of
    // (CompID dword, Count dword) up to the "Rich" marker
    let entries_start = dans_pos + 16;
    if entries_start > rich_abs {
        return None;
    }

    let mut entries = Vec::new();
    let mut raw = Vec::new();
    let mut p = entries_start;
    while p + 8 <= rich_abs {
        let comp = r32le(data, p) ^ key;
        let count = r32le(data, p + 4) ^ key;
        entries.push(RichHeaderEntry {
            comp_id: comp,
            product_id: (comp >> 16) as u16,
            build_number: (comp & 0xFFFF) as u16,
            count,
        });
        raw.extend_from_slice(&comp.to_le_bytes());
        raw.extend_from_slice(&count.to_le_bytes());
        p += 8;
    }
    if entries.is_empty() {
        return None;
    }
    let hash = format!("{:x}", md5::compute(&raw));
    Some(RichHeaderInfo { entries, hash })
}

/// Walk the PE TLS data directory (IMAGE_TLS_DIRECTORY) to enumerate actual
/// TLS callback virtual addresses. These execute *before* the program's
/// normal entry point and are a well-known anti-debug / anti-cheat-bypass
/// execution vector — far more precise than just noting that a `.tls`
/// section exists.
///
/// Returns a list of callback VAs (empty if there is no TLS directory, or
/// it has no callbacks).
pub fn parse_tls_callbacks(data: &[u8], lfanew: u32, image_base: u64, sections: &[goblin::pe::section_table::SectionTable]) -> Vec<u64> {
    let mut callbacks = Vec::new();
    let lfanew = lfanew as usize;

    // Optional header starts after the 4-byte PE signature and 20-byte COFF header
    let opt_off = lfanew + 4 + 20;
    if opt_off + 2 > data.len() {
        return callbacks;
    }
    let magic = r16le(data, opt_off);
    let is64 = magic == 0x20B;

    // Data directories begin 96 bytes into the optional header for PE32,
    // or 112 bytes in for PE32+. TLS table is data directory index 9.
    let dd_base = opt_off + if is64 { 112 } else { 96 };
    let tls_dir_off = dd_base + 9 * 8;
    if tls_dir_off + 8 > data.len() {
        return callbacks;
    }
    let tls_rva = r32le(data, tls_dir_off);
    if tls_rva == 0 {
        return callbacks;
    }
    let tls_off = match rva_to_offset(tls_rva as u64, sections) {
        Some(o) => o,
        None => return callbacks,
    };

    // AddressOfCallBacks: offset 24 in IMAGE_TLS_DIRECTORY64, offset 12 in
    // IMAGE_TLS_DIRECTORY32
    let (cb_va, ptr_size) = if is64 {
        (r64le(data, tls_off + 24), 8usize)
    } else {
        (r32le(data, tls_off + 12) as u64, 4usize)
    };
    if cb_va == 0 {
        return callbacks;
    }
    let cb_rva = cb_va.saturating_sub(image_base);
    let mut off = match rva_to_offset(cb_rva, sections) {
        Some(o) => o,
        None => return callbacks,
    };

    // Walk the null-terminated array of callback VAs (cap at 64 to bound
    // execution on a corrupt/adversarial binary)
    for _ in 0..64 {
        if off + ptr_size > data.len() {
            break;
        }
        let cb = if ptr_size == 8 { r64le(data, off) } else { r32le(data, off) as u64 };
        if cb == 0 {
            break;
        }
        callbacks.push(cb);
        off += ptr_size;
    }
    callbacks
}

/// Read a PE data directory entry (RVA/offset + size) by index.
/// Index 2 = resource table, 4 = certificate table, 9 = TLS table, etc.
///
/// NOTE: for the certificate table (index 4) the first field is a *file
/// offset*, not an RVA — this is the one exception in the PE spec. Callers
/// must handle that distinction; this function just returns the raw value.
pub fn pe_data_directory(data: &[u8], lfanew: u32, index: usize) -> (u32, u32) {
    let lfanew = lfanew as usize;
    let opt_off = lfanew + 4 + 20;
    if opt_off + 2 > data.len() {
        return (0, 0);
    }
    let magic = r16le(data, opt_off);
    let is64 = magic == 0x20B;
    let dd_base = opt_off + if is64 { 112 } else { 96 };
    let dir_off = dd_base + index * 8;
    if dir_off + 8 > data.len() {
        return (0, 0);
    }
    (r32le(data, dir_off), r32le(data, dir_off + 4))
}

/// Compute info about any data appended after the last section ("overlay").
/// Common for self-extracting archives, installers, and signed binaries
/// (the Authenticode signature itself often lives in the overlay region).
pub fn compute_overlay_info(data: &[u8], sections: &[goblin::pe::section_table::SectionTable]) -> Option<OverlayInfo> {
    let mut last_end = 0usize;
    for s in sections {
        let end = s.pointer_to_raw_data as usize + s.size_of_raw_data as usize;
        last_end = last_end.max(end);
    }
    if last_end > 0 && last_end < data.len() {
        let overlay = &data[last_end..];
        Some(OverlayInfo {
            offset: last_end as u64,
            size: overlay.len() as u64,
            sha256: format!("{:x}", Sha256::digest(overlay)),
            entropy: shannon_entropy(overlay),
        })
    } else {
        None
    }
}

/// Parse the Authenticode certificate table (data directory index 4), if
/// present. Extracts the WIN_CERTIFICATE header fields and runs a printable
/// string scan over the embedded DER-encoded certificate blob to surface
/// likely Subject/Issuer identity strings.
///
/// This is a fast triage signal only — it does NOT verify the signature.
pub fn parse_authenticode(data: &[u8], lfanew: u32) -> Option<AuthenticodeInfo> {
    // Certificate table: field 1 is a file OFFSET (not RVA, per spec)
    let (cert_off, cert_size) = pe_data_directory(data, lfanew, 4);
    if cert_off == 0 || cert_size == 0 {
        return None;
    }
    let off = cert_off as usize;
    if off + 8 > data.len() {
        return None;
    }
    let dw_length = r32le(data, off) as usize;
    let cert_revision = r16le(data, off + 4);
    let cert_type = r16le(data, off + 6);

    let blob_start = (off + 8).min(data.len());
    let blob_end = (off.saturating_add(dw_length)).min(data.len()).max(blob_start);
    let blob = &data[blob_start..blob_end];

    // DER-encoded X.509 fields (CN=, O=, etc.) appear as printable ASCII
    // runs inside the otherwise-binary PKCS#7 structure. Filter to
    // plausible identity-like strings (contains a letter, reasonable length).
    let candidate_identities: Vec<String> = extract_strings(blob, 4)
        .into_iter()
        .filter(|s| s.len() >= 4 && s.len() <= 80 && s.chars().any(|c| c.is_alphabetic()))
        .take(25)
        .collect();

    Some(AuthenticodeInfo {
        cert_type,
        cert_revision,
        size: cert_size,
        candidate_identities,
    })
}

const VERSION_INFO_KEYS: &[&str] = &[
    "CompanyName", "FileDescription", "FileVersion", "InternalName",
    "LegalCopyright", "OriginalFilename", "ProductName", "ProductVersion",
];

/// Read a null-terminated UTF-16LE string starting at `start`, capped at
/// 256 code units to bound execution on adversarial input.
fn read_utf16_string(blob: &[u8], start: usize) -> String {
    let mut units = Vec::new();
    let mut i = start;
    while i + 2 <= blob.len() {
        let u = u16::from_le_bytes([blob[i], blob[i + 1]]);
        if u == 0 {
            break;
        }
        units.push(u);
        i += 2;
        if units.len() >= 256 {
            break;
        }
    }
    String::from_utf16_lossy(&units)
}

/// Heuristically extract VS_VERSIONINFO StringFileInfo fields from an
/// RT_VERSION resource blob.
///
/// Rather than walking the exact (and fiddly, 4-byte-aligned, nested)
/// VS_VERSIONINFO/StringFileInfo/StringTable/String structure, this scans
/// the blob for each well-known field name encoded as UTF-16LE, then reads
/// the UTF-16LE value that immediately follows (after the key's null
/// terminator and 4-byte alignment padding). This is robust against minor
/// structural variations and cannot panic on malformed input.
pub fn parse_version_info(blob: &[u8]) -> VersionInfo {
    let mut info = VersionInfo::default();
    let mut i = 0usize;
    while i + 4 <= blob.len() {
        for &key in VERSION_INFO_KEYS {
            let key_bytes: Vec<u8> = key.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
            if blob[i..].starts_with(&key_bytes) {
                let mut j = i + key_bytes.len() + 2; // skip key + null terminator
                while j % 4 != 0 && j < blob.len() {
                    j += 1; // 4-byte alignment padding
                }
                let val = read_utf16_string(blob, j);
                if !val.is_empty() {
                    match key {
                        "CompanyName" => info.company_name = Some(val),
                        "FileDescription" => info.file_description = Some(val),
                        "FileVersion" => info.file_version = Some(val),
                        "InternalName" => info.internal_name = Some(val),
                        "LegalCopyright" => info.legal_copyright = Some(val),
                        "OriginalFilename" => info.original_filename = Some(val),
                        "ProductName" => info.product_name = Some(val),
                        "ProductVersion" => info.product_version = Some(val),
                        _ => {}
                    }
                }
                i = j;
                break;
            }
        }
        i += 2; // UTF-16 code unit granularity
    }
    info
}

/// PE resource type IDs we care about
const RT_ICON: u32 = 3;
const RT_VERSION: u32 = 16;

/// Walk the PE resource directory tree (Type → Name → Language → data) and
/// collect (type_id, data_rva, size) for every leaf entry. The tree is
/// always exactly 3 levels deep, so this never recurses beyond `level == 2`
/// and cannot loop indefinitely even on a malformed/adversarial tree.
fn walk_resource_dir(
    data: &[u8],
    rsrc_base_off: usize,
    dir_off: usize,
    level: usize,
    type_id: Option<u32>,
    out: &mut Vec<(u32, usize, u32)>,
) {
    if dir_off + 16 > data.len() || out.len() > 4096 {
        return; // bounds / runaway-tree guard
    }
    let num_named = r16le(data, dir_off + 12) as usize;
    let num_id = r16le(data, dir_off + 14) as usize;
    let total = (num_named + num_id).min(512); // cap fan-out per directory

    for i in 0..total {
        let entry_off = dir_off + 16 + i * 8;
        if entry_off + 8 > data.len() {
            break;
        }
        let name_or_id = r32le(data, entry_off);
        let offset_to_data = r32le(data, entry_off + 4);
        let id = name_or_id & 0x7FFF_FFFF;
        let is_subdir = offset_to_data & 0x8000_0000 != 0;
        let sub_rel = (offset_to_data & 0x7FFF_FFFF) as usize;
        let sub_abs = rsrc_base_off + sub_rel;

        match level {
            0 => {
                if is_subdir {
                    walk_resource_dir(data, rsrc_base_off, sub_abs, 1, Some(id), out);
                }
            }
            1 => {
                if is_subdir {
                    walk_resource_dir(data, rsrc_base_off, sub_abs, 2, type_id, out);
                }
            }
            _ => {
                if !is_subdir && sub_abs + 16 <= data.len() {
                    let data_rva = r32le(data, sub_abs);
                    let size = r32le(data, sub_abs + 4);
                    out.push((type_id.unwrap_or(0), data_rva as usize, size));
                }
            }
        }
    }
}

/// Parse the PE resource directory (data directory index 2) to extract
/// VS_VERSIONINFO fields (RT_VERSION) and SHA-256 hashes of each RT_ICON
/// resource (useful for cross-sample icon comparison — many cheats reuse
/// a stolen or stock icon across builds).
///
/// Returns `(None, vec![])` if there is no resource directory, or it
/// cannot be parsed.
pub fn parse_pe_resources(
    data: &[u8],
    lfanew: u32,
    sections: &[goblin::pe::section_table::SectionTable],
) -> (Option<VersionInfo>, Vec<String>) {
    let (rsrc_rva, _rsrc_size) = pe_data_directory(data, lfanew, 2);
    if rsrc_rva == 0 {
        return (None, vec![]);
    }
    let rsrc_off = match rva_to_offset(rsrc_rva as u64, sections) {
        Some(o) => o,
        None => return (None, vec![]),
    };

    let mut leaves = Vec::new();
    walk_resource_dir(data, rsrc_off, rsrc_off, 0, None, &mut leaves);

    let mut version_info = None;
    let mut icon_hashes = Vec::new();

    for (type_id, data_rva, size) in leaves {
        let off = match rva_to_offset(data_rva as u64, sections) {
            Some(o) => o,
            None => continue,
        };
        let end = (off + size as usize).min(data.len());
        if off >= end {
            continue;
        }
        let blob = &data[off..end];

        match type_id {
            RT_VERSION => {
                let vi = parse_version_info(blob);
                if !vi.is_empty() && version_info.is_none() {
                    version_info = Some(vi);
                }
            }
            RT_ICON => {
                icon_hashes.push(format!("{:x}", Sha256::digest(blob)));
            }
            _ => {}
        }
    }

    (version_info, icon_hashes)
}

/// Analyse a binary, returning the parsed info *and* the raw bytes so callers
/// can pass them on to packing_hints / hashes without re-reading the file.
pub fn analyze(path: &str, no_size_limit: bool) -> Result<(BinaryInfo, Vec<u8>)> {
    let data = read_file(path, no_size_limit)?;
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

    // Enumerate actual TLS callback VAs from the data directory. Falling
    // back to noting the .tls section by name if the directory walk finds
    // nothing (e.g. a .tls section exists but has an empty callback array).
    let lfanew = pe.header.dos_header.pe_pointer;
    let callback_vas = parse_tls_callbacks(data, lfanew, pe.image_base as u64, &pe.sections);
    let tls_callbacks: Vec<String> = if !callback_vas.is_empty() {
        callback_vas.iter().map(|va| format!("TLS callback at VA 0x{:x}", va)).collect()
    } else {
        pe.sections
            .iter()
            .filter(|s| {
                String::from_utf8_lossy(&s.name)
                    .trim_matches('\0')
                    .eq_ignore_ascii_case(".tls")
            })
            .map(|s| {
                format!(
                    ".tls section at VA 0x{:x}, raw size {} (no callbacks enumerated)",
                    s.virtual_address, s.size_of_raw_data
                )
            })
            .collect()
    };

    let rich_header = parse_rich_header(data, lfanew);
    if let Some(rh) = &rich_header {
        headers.push(("Rich Header Hash".into(), rh.hash.clone()));
    }

    let overlay = compute_overlay_info(data, &pe.sections);
    if let Some(ov) = &overlay {
        headers.push((
            "Overlay".into(),
            format!("{} bytes at 0x{:x} (entropy {:.2})", ov.size, ov.offset, ov.entropy),
        ));
    }

    let authenticode = parse_authenticode(data, lfanew);
    headers.push(("Digitally Signed".into(), authenticode.is_some().to_string()));

    let (version_info, icon_hashes) = parse_pe_resources(data, lfanew, &pe.sections);
    if let Some(vi) = &version_info {
        if let Some(name) = &vi.original_filename {
            headers.push(("Original Filename".into(), name.clone()));
        }
        if let Some(name) = &vi.product_name {
            headers.push(("Product Name".into(), name.clone()));
        }
        if let Some(company) = &vi.company_name {
            headers.push(("Company Name".into(), company.clone()));
        }
    }

    // Parse CLR metadata if this is a managed (.NET) assembly.
    // Data directory 14 (COM_DESCRIPTOR) being non-zero is the definitive
    // signal — unmanaged PE files leave it zeroed.
    let clr = crate::clr::parse_clr(data, lfanew, &pe.sections);
    if let Some(ref ci) = clr {
        headers.push(("Managed (.NET)".into(), "YES".into()));
        if let Some(ref name) = ci.assembly_name {
            headers.push(("Assembly Name".into(), name.clone()));
        }
        if let Some(ref ver) = ci.assembly_version {
            headers.push(("Assembly Version".into(), ver.clone()));
        }
        headers.push(("CLR Runtime".into(), ci.runtime_version.clone()));
        headers.push(("CLR Flags".into(), ci.clr_flags_desc.join(", ")));
        if let Some(ref mvid) = ci.mvid {
            headers.push(("MVID".into(), mvid.clone()));
        }
        if ci.strong_name_signed {
            headers.push(("Strong-Name Signed".into(), "YES".into()));
        }
        if !ci.obfuscator_hints.is_empty() {
            headers.push(("Obfuscator Hints".into(),
                format!("{} detected", ci.obfuscator_hints.len())));
        }
        if !ci.cheat_pattern_hits.is_empty() {
            headers.push(("C# Cheat Patterns".into(),
                format!("{} hit(s)", ci.cheat_pattern_hits.len())));
        }
    } else {
        headers.push(("Managed (.NET)".into(), "NO".into()));
    }

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
        rich_header,
        overlay,
        authenticode,
        version_info,
        icon_hashes,
        clr,
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
        rich_header: None,
        overlay: None,
        authenticode: None,
        version_info: None,
        icon_hashes: vec![],
        clr: None,
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

static RE_URL:  OnceLock<Regex> = OnceLock::new();
static RE_IP:   OnceLock<Regex> = OnceLock::new();
static RE_REG:  OnceLock<Regex> = OnceLock::new();
static RE_PATH: OnceLock<Regex> = OnceLock::new();
static RE_GUID: OnceLock<Regex> = OnceLock::new();

pub fn categorize_strings(strings: &[String]) -> CategorizedStrings {
    let url_re  = RE_URL.get_or_init(|| Regex::new(r"(?i)https?://[^\s]{4,}").unwrap());
    let ip_re   = RE_IP.get_or_init(|| Regex::new(r"\b(\d{1,3}\.){3}\d{1,3}(:\d+)?\b").unwrap());
    let reg_re  = RE_REG.get_or_init(|| Regex::new(r"(?i)(HKEY_|HKLM|HKCU|HKCR|SOFTWARE\\|SYSTEM\\)").unwrap());
    let path_re = RE_PATH.get_or_init(|| Regex::new(r"(?i)([A-Za-z]:\\|/proc/|/sys/|/dev/|/etc/)").unwrap());
    let guid_re = RE_GUID.get_or_init(|| Regex::new(r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}").unwrap());

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
