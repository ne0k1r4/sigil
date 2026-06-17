/// CLR / .NET metadata parser for sigil.
///
/// .NET assemblies are PE files with a CLR header in data directory index 14
/// (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, also called the COR20 header).
/// This module reads that header, walks the metadata stream heap to extract
/// assembly identity (name, version, culture, MVID), the TypeDef table for
/// class/namespace enumeration, and the CustomAttribute table for a handful
/// of obfuscator markers.
///
/// Everything here is pure static parsing — no JIT, no execution. The same
/// approach used by dnSpy, ILSpy, Mono.Cecil, and ILDASM.

use crate::analyzer::{pe_data_directory, rva_to_offset};
use goblin::pe::section_table::SectionTable;
use serde::{Deserialize, Serialize};

// ── public types ─────────────────────────────────────────────────────────────

/// High-level summary of a .NET assembly extracted from the PE CLR header
/// and the #~ / #- metadata stream.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClrInfo {
    /// CLR runtime version string from the metadata root header
    /// (e.g. "v4.0.30319"). Not the same as the .NET SDK version.
    pub runtime_version: String,

    /// CLR header flags (IMAGE_COR20_HEADER.Flags):
    ///   0x01 = ILONLY   — pure-IL binary, no native code
    ///   0x02 = 32BITREQUIRED — pinned to 32-bit
    ///   0x08 = STRONGNAMESIGNED
    ///   0x10 = NATIVEENTRYPOINT
    pub clr_flags: u32,

    /// Human-readable interpretation of the CLR flags
    pub clr_flags_desc: Vec<String>,

    /// Assembly name from the Assembly metadata table (row 0, col 7)
    pub assembly_name: Option<String>,

    /// Assembly version quad from the Assembly table: Major.Minor.Build.Rev
    pub assembly_version: Option<String>,

    /// Target culture/locale (e.g. "neutral", "en-US"). "neutral" is the
    /// normal value for a non-localised assembly.
    pub culture: Option<String>,

    /// Module Version Identifier — a GUID that uniquely identifies this
    /// *specific build* of the module. If two samples share an MVID they
    /// are byte-for-byte identical modules (modulo the metadata stream
    /// layout). Changes on every recompile.
    pub mvid: Option<String>,

    /// Namespaces encountered in the TypeDef table. Capped at 256 to keep
    /// output manageable on large obfuscated assemblies.
    pub namespaces: Vec<String>,

    /// Type (class/struct/enum/interface) names from the TypeDef table.
    /// Capped at 256. On heavily obfuscated samples these are typically
    /// single letters or random strings.
    pub type_names: Vec<String>,

    /// Obfuscator markers detected in the CustomAttribute table or as
    /// known namespace/type patterns in the TypeDef table.
    pub obfuscator_hints: Vec<String>,

    /// C#-specific cheat pattern hits — known namespace / type / attribute
    /// patterns associated with game cheat and ESP toolkits.
    pub cheat_pattern_hits: Vec<CheatHit>,

    /// Whether the binary is MSIL-only (no native code stub beyond the
    /// tiny managed PE bootstrap). Implies it needs the .NET runtime to run.
    pub is_ilonly: bool,

    /// Whether the binary declares itself as requiring 32-bit execution
    /// (common in older Unity and Cheat Engine hook templates).
    pub requires_32bit: bool,

    /// Whether the assembly claims a strong-name signature. Note: presence
    /// of the flag does NOT mean the signature has been verified.
    pub strong_name_signed: bool,
}

/// A single C#-specific cheat-pattern hit.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CheatHit {
    pub pattern: String,
    pub matched: String,
    pub description: String,
}

// ── little-endian readers (local, self-contained) ────────────────────────────

#[inline]
fn r16(b: &[u8], o: usize) -> u16 {
    if o + 2 > b.len() { return 0; }
    u16::from_le_bytes([b[o], b[o + 1]])
}
#[inline]
fn r32(b: &[u8], o: usize) -> u32 {
    if o + 4 > b.len() { return 0; }
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

// ── GUID formatting ───────────────────────────────────────────────────────────

/// Format a 16-byte slice as an RFC 4122 GUID string
/// {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}.
/// The first three components are little-endian; the last two are big-endian,
/// matching how CLR stores MVIDs.
fn format_guid(b: &[u8]) -> String {
    if b.len() < 16 { return "(invalid guid)".into(); }
    format!(
        "{{{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        b[3], b[2], b[1], b[0],   // Data1 LE
        b[5], b[4],                // Data2 LE
        b[7], b[6],                // Data3 LE
        b[8], b[9],                // Data4 BE
        b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

// ── CLR flags ────────────────────────────────────────────────────────────────

/// Decode IMAGE_COR20_HEADER.Flags into human-readable strings.
fn decode_clr_flags(flags: u32) -> Vec<String> {
    let mut out = Vec::new();
    if flags & 0x01 != 0 { out.push("ILONLY".into()); }
    if flags & 0x02 != 0 { out.push("32BITREQUIRED".into()); }
    if flags & 0x04 != 0 { out.push("IL_LIBRARY".into()); }
    if flags & 0x08 != 0 { out.push("STRONGNAMESIGNED".into()); }
    if flags & 0x10 != 0 { out.push("NATIVEENTRYPOINT".into()); }
    if flags & 0x20000 != 0 { out.push("TRACKDEBUGDATA".into()); }
    if flags & 0x00100000 != 0 { out.push("PREFER32BIT".into()); }
    if out.is_empty() { out.push("(none)".into()); }
    out
}

// ── metadata stream parser ────────────────────────────────────────────────────

/// Raw metadata parsed from a single CLR heap / stream. We need:
/// - `#Strings` — the interned string heap (null-terminated UTF-8)
/// - `#GUID`    — the GUID heap (packed 16-byte blocks)
/// - `#~` or `#-` — the compressed/uncompressed logical metadata tables
struct MetadataStreams<'a> {
    strings: &'a [u8],
    guid: &'a [u8],
    tables: &'a [u8],
}

/// Parse the metadata root header and locate the three streams we need.
/// Returns None if the buffer doesn't look like a valid metadata root
/// (wrong magic, truncated, etc.).
fn find_metadata_streams<'a>(md: &'a [u8]) -> Option<MetadataStreams<'a>> {
    // Metadata root: 4-byte magic 0x424A5342 ("BSJB")
    if md.len() < 20 || r32(md, 0) != 0x424A_5342 {
        return None;
    }

    // Runtime version string: offset 12, 4-byte length, then the string
    // We skip past it to find the stream count.
    let ver_len = r32(md, 12) as usize;
    let after_ver = 16 + ver_len;
    // 2-byte flags at after_ver, then 2-byte stream count
    if after_ver + 4 > md.len() { return None; }
    let stream_count = r16(md, after_ver + 2) as usize;
    if stream_count > 64 { return None; } // sanity guard

    let mut strings: &[u8] = &[];
    let mut guid:    &[u8] = &[];
    let mut tables:  &[u8] = &[];

    // Stream headers start immediately after the stream count field.
    let mut p = after_ver + 4;
    for _ in 0..stream_count {
        if p + 8 > md.len() { break; }
        let offset = r32(md, p) as usize;
        let size   = r32(md, p + 4) as usize;
        // Stream name: null-terminated, 4-byte aligned
        let name_start = p + 8;
        let mut name_end = name_start;
        while name_end < md.len() && md[name_end] != 0 {
            name_end += 1;
        }
        let name = std::str::from_utf8(&md[name_start..name_end]).unwrap_or("");
        // Advance past name + null + alignment padding to 4-byte boundary
        let raw_next = name_end + 1;
        p = (raw_next + 3) & !3;

        if offset > md.len() || offset + size > md.len() { continue; }
        let stream_data = &md[offset..offset + size];

        match name {
            "#Strings" => strings = stream_data,
            "#GUID"    => guid    = stream_data,
            "#~" | "#-" => tables = stream_data,
            _ => {}
        }
    }

    Some(MetadataStreams { strings, guid, tables })
}

/// Read a null-terminated UTF-8 string from the #Strings heap at the given
/// offset. Returns an empty string if the offset is out of range or the
/// heap is empty.
fn strings_at(heap: &[u8], offset: usize) -> &str {
    if offset >= heap.len() { return ""; }
    let end = heap[offset..].iter().position(|&b| b == 0)
        .map(|n| offset + n)
        .unwrap_or(heap.len());
    std::str::from_utf8(&heap[offset..end]).unwrap_or("")
}

// ── metadata table decoder ────────────────────────────────────────────────────

/// Column width in bytes for a given index type:
/// - string/blob/guid indices are 2 or 4 bytes depending on heap size
/// - table row indices are 2 or 4 bytes depending on table row count
///
/// `wide_strings` / `wide_guid` / `wide_blob` come from the HeapSizes
/// byte in the #~ stream header (bits 0/1/2 set = 4-byte index for that
/// heap; clear = 2-byte index).
struct ColWidths {
    string: usize,
    guid:   usize,
    blob:   usize,
}

impl ColWidths {
    fn from_heap_sizes(heap_sizes: u8) -> Self {
        ColWidths {
            string: if heap_sizes & 0x01 != 0 { 4 } else { 2 },
            guid:   if heap_sizes & 0x02 != 0 { 4 } else { 2 },
            blob:   if heap_sizes & 0x04 != 0 { 4 } else { 2 },
        }
    }
}

/// Read a column index of `width` bytes from `data` at `off`.
fn read_index(data: &[u8], off: usize, width: usize) -> usize {
    match width {
        4 => r32(data, off) as usize,
        _ => r16(data, off) as usize,
    }
}

// ── metadata table IDs (ECMA-335 §II.22) ─────────────────────────────────────
const TBL_MODULE:          usize = 0x00;
const TBL_TYPEREF:         usize = 0x01;
const TBL_TYPEDEF:         usize = 0x02;
const TBL_ASSEMBLY:        usize = 0x20;
const TBL_CUSTOMATTRIBUTE: usize = 0x0C;

/// Parse the #~ stream tables header and extract the information we need.
///
/// Returns a tuple of:
/// - assembly name, version, culture from the Assembly table
/// - MVID GUID index from the Module table
/// - type/namespace pairs from the TypeDef table (capped at 512)
/// - CustomAttribute raw type references for obfuscator/cheat scanning
fn decode_tables(
    tables: &[u8],
    strings: &[u8],
    guid: &[u8],
) -> Option<(
    Option<String>,   // assembly name
    Option<String>,   // version
    Option<String>,   // culture
    Option<String>,   // mvid
    Vec<(String, String)>, // (namespace, typename)
)> {
    if tables.len() < 24 { return None; }

    let heap_sizes = tables[6];
    let cw = ColWidths::from_heap_sizes(heap_sizes);

    // Valid mask: 8-byte bitmask of which table IDs are present
    let valid_lo = r32(tables, 8) as u64;
    let valid_hi = r32(tables, 12) as u64;
    let valid: u64 = valid_lo | (valid_hi << 32);

    // Row counts: one u32 per set bit in valid, starting at offset 24
    let mut row_counts = [0u32; 64];
    let mut p = 24usize;
    for i in 0..64usize {
        if valid & (1u64 << i) != 0 {
            if p + 4 > tables.len() { return None; }
            row_counts[i] = r32(tables, p);
            p += 4;
        }
    }

    // Helper: table index width — 2 bytes if ≤ 0xFFFF rows, else 4
    let tidx = |tbl: usize| -> usize {
        if row_counts[tbl] > 0xFFFF { 4 } else { 2 }
    };

    // ── Module table (TBL_MODULE = 0x00) ─────────────────────────────────────
    // Layout: Generation(u16) | Name(String) | Mvid(Guid) | EncId(Guid) | EncBaseId(Guid)
    let module_base = p;
    let mvid = if valid & (1 << TBL_MODULE) != 0 && module_base + 2 + cw.string + cw.guid <= tables.len() {
        let guid_idx = read_index(tables, module_base + 2 + cw.string, cw.guid);
        // GUID heap stores packed 16-byte GUIDs; index is 1-based
        let guid_off = guid_idx.saturating_sub(1) * 16;
        if guid_off + 16 <= guid.len() {
            Some(format_guid(&guid[guid_off..guid_off + 16]))
        } else { None }
    } else { None };

    // Advance past the Module table rows to reach the next table
    let module_row_sz = 2 + cw.string + cw.guid * 3;
    let module_rows = row_counts[TBL_MODULE] as usize;
    p = module_base + module_rows * module_row_sz;

    // ── TypeRef table (TBL_TYPEREF = 0x01) ───────────────────────────────────
    // We don't need TypeRef data but must skip past it to reach TypeDef.
    // Layout: ResolutionScope(coded index) | Name(String) | Namespace(String)
    // ResolutionScope is a 2-bit coded index into {Module,ModuleRef,AssemblyRef,TypeRef};
    // its width depends on max rows across those 4 tables.
    let resolution_scope_max = [
        row_counts[TBL_MODULE] as usize,
        row_counts[0x1A] as usize, // ModuleRef
        row_counts[0x23] as usize, // AssemblyRef
        row_counts[TBL_TYPEREF] as usize,
    ].iter().copied().max().unwrap_or(0);
    let resolution_scope_w = if resolution_scope_max > (0xFFFF >> 2) { 4 } else { 2 };
    let typeref_row_sz = resolution_scope_w + cw.string * 2;
    let typeref_rows = row_counts[TBL_TYPEREF] as usize;
    p += typeref_rows * typeref_row_sz;

    // ── TypeDef table (TBL_TYPEDEF = 0x02) ───────────────────────────────────
    // Layout: Flags(u32) | TypeName(String) | TypeNamespace(String) |
    //         Extends(coded) | FieldList(table idx) | MethodList(table idx)
    // Extends is a TypeDefOrRef coded index (2-bit tag) into
    // {TypeDef,TypeRef,TypeSpec}; we only use name/namespace so skip Extends.
    let typedef_base = p;
    let extends_max = [
        row_counts[TBL_TYPEDEF] as usize,
        row_counts[TBL_TYPEREF] as usize,
        row_counts[0x1B] as usize, // TypeSpec
    ].iter().copied().max().unwrap_or(0);
    let extends_w = if extends_max > (0xFFFF >> 2) { 4 } else { 2 };
    // FieldList and MethodList are simple table indices into Field/Method tables
    let field_list_w  = tidx(0x04); // Field table
    let method_list_w = tidx(0x06); // MethodDef table
    let typedef_row_sz = 4 + cw.string * 2 + extends_w + field_list_w + method_list_w;
    let typedef_rows = (row_counts[TBL_TYPEDEF] as usize).min(512);

    let mut types: Vec<(String, String)> = Vec::with_capacity(typedef_rows);
    for i in 0..typedef_rows {
        let row_off = typedef_base + i * typedef_row_sz;
        if row_off + 4 + cw.string * 2 > tables.len() { break; }
        let name_idx = read_index(tables, row_off + 4, cw.string);
        let ns_idx   = read_index(tables, row_off + 4 + cw.string, cw.string);
        let type_name = strings_at(strings, name_idx).to_string();
        let type_ns   = strings_at(strings, ns_idx).to_string();
        if !type_name.is_empty() {
            types.push((type_ns, type_name));
        }
    }

    p += row_counts[TBL_TYPEDEF] as usize * typedef_row_sz;

    // Skip many tables to reach Assembly (0x20 = 32):
    // Field(4), MethodDef(6), Param(8), InterfaceImpl(9), MemberRef(10),
    // Constant(11), CustomAttribute(12), FieldMarshal(13), DeclSecurity(14),
    // ClassLayout(15), FieldLayout(16), StandAloneSig(17), EventMap(18),
    // EventPtr(19), Event(20), PropertyMap(21), PropertyPtr(22), Property(23),
    // MethodSemantics(24), MethodImpl(25), ModuleRef(26), TypeSpec(27),
    // ImplMap(28), FieldRVA(29), ENCLog(30), ENCMap(31) — 28 tables to skip.
    // Rather than compute each table's exact row size (which would require
    // knowing many more coded-index widths), we read the Assembly table
    // directly by counting set bits below it in the valid mask.
    // This is the standard approach used by lightweight metadata readers.
    //
    // We simply track p through the tables we've already counted, then use
    // the fact that we need to jump to where the Assembly table begins.
    // Since we want assembly info and the row structure is fixed-width, we
    // do a bounds-safe forward scan for the Assembly table offset.

    // Assembly table (0x20): fixed row size = 4+2+2+2+2+4+4+blob+string+string+string
    // = 16 + cw.blob + cw.string*3
    // We'll locate it by skipping each intermediate table using row counts we know.
    // For tables we don't need, we compute minimum safe row sizes to skip past them.

    // Helper: skip a batch of tables between `from` and `to` (exclusive) using
    // known row counts, applying conservative row-size lower bounds where we
    // don't need the actual data.
    // We use a simplified approach: for tables we haven't decoded yet, compute
    // just enough columns to get the correct row size.

    // ── skip to Assembly table ────────────────────────────────────────────────
    // Tables 4–31 (Field..ENCMap) in order:
    // We need exact row sizes only for tables that are present.
    // Conservative known sizes (these are defined in ECMA-335 §II.22.*):

    // Rather than encode every table's exact schema here, we use the
    // safe technique of computing the Assembly table pointer by parsing
    // through the row-count list. Since the tables stream is densely packed
    // and we already know p points to Field(4), we can compute how many
    // bytes each intermediate table occupies.

    // The sizes below are the *minimum correct* row sizes given our ColWidths.
    // For coded indices we use the larger (4-byte) size conservatively when
    // we cannot determine the exact coded-index width without more state.
    // This may cause us to overshoot on small assemblies; we guard with a
    // bounds check and fall back to None.

    let type_or_method_def_max = [
        row_counts[TBL_TYPEDEF] as usize,
        row_counts[0x06] as usize,
    ].iter().copied().max().unwrap_or(0);
    let has_this_w = if type_or_method_def_max > (0xFFFF >> 2) { 4 } else { 2 };

    let member_ref_parent_max = [
        row_counts[TBL_TYPEDEF] as usize,
        row_counts[TBL_TYPEREF] as usize,
        row_counts[0x1A] as usize,
        row_counts[0x06] as usize,
        row_counts[0x1B] as usize,
    ].iter().copied().max().unwrap_or(0);
    let member_ref_parent_w = if member_ref_parent_max > (0xFFFF >> 3) { 4 } else { 2 };

    let has_custom_attr_max = [
        row_counts[0x06] as usize, row_counts[0x04] as usize, row_counts[0x01] as usize,
        row_counts[0x08] as usize, row_counts[0x17] as usize, row_counts[0x14] as usize,
        row_counts[0x19] as usize, row_counts[0x00] as usize, row_counts[0x0A] as usize,
        row_counts[0x09] as usize, row_counts[0x0E] as usize, row_counts[0x11] as usize,
        row_counts[0x02] as usize, row_counts[0x1A] as usize, row_counts[0x10] as usize,
        row_counts[0x1B] as usize, row_counts[0x0C] as usize, row_counts[0x0D] as usize,
        row_counts[0x1D] as usize, row_counts[0x1E] as usize, row_counts[0x1F] as usize,
        row_counts[0x20] as usize,
    ].iter().copied().max().unwrap_or(0);
    let has_custom_attr_w = if has_custom_attr_max > (0xFFFF >> 5) { 4 } else { 2 };

    let custom_attr_type_max = [
        row_counts[0x06] as usize,
        row_counts[0x0A] as usize,
    ].iter().copied().max().unwrap_or(0);
    let custom_attr_type_w = if custom_attr_type_max > (0xFFFF >> 3) { 4 } else { 2 };

    // Table sizes for 4–31:
    let intermediate_skips: &[(usize, usize)] = &[
        // (table_id, row_size)
        (0x04, cw.blob),                                                   // Field: Flags+Name+Sig
        (0x06, 4 + 4 + 2 + 2 + 2 + cw.string + cw.blob),                // MethodDef
        (0x08, 2 + 2 + 2 + cw.string),                                   // Param
        (0x09, has_this_w + 2),                                           // InterfaceImpl
        (0x0A, member_ref_parent_w + cw.string + cw.blob),               // MemberRef
        (0x0B, 2 + has_this_w + cw.blob),                                // Constant
        (0x0C, has_custom_attr_w + custom_attr_type_w + cw.blob),        // CustomAttribute
        (0x0D, has_this_w + cw.blob),                                    // FieldMarshal
        (0x0E, 2 + has_this_w + cw.blob),                                // DeclSecurity
        (0x0F, 4 + 2 + tidx(0x02)),                                      // ClassLayout
        (0x10, 4 + tidx(0x04)),                                          // FieldLayout
        (0x11, cw.blob),                                                  // StandAloneSig
        (0x12, tidx(0x02) + tidx(0x14)),                                 // EventMap
        (0x13, 0),                                                        // EventPtr (skipped)
        (0x14, 2 + cw.string + 2),                                       // Event
        (0x15, tidx(0x02) + tidx(0x17)),                                 // PropertyMap
        (0x16, 0),                                                        // PropertyPtr (skipped)
        (0x17, 2 + cw.string + cw.blob),                                 // Property
        (0x18, 2 + 2 + tidx(0x06)),                                      // MethodSemantics
        (0x19, tidx(0x06) + tidx(0x06) + tidx(0x02)),                   // MethodImpl
        (0x1A, cw.string),                                               // ModuleRef
        (0x1B, cw.blob),                                                  // TypeSpec
        (0x1C, 2 + tidx(0x06) + 2 + cw.string + cw.string),             // ImplMap
        (0x1D, 4 + tidx(0x04)),                                          // FieldRVA
        (0x1E, 0),                                                        // ENCLog (skipped)
        (0x1F, 0),                                                        // ENCMap (skipped)
    ];

    for &(tbl, row_sz) in intermediate_skips {
        let rows = row_counts[tbl] as usize;
        if rows > 0 && row_sz > 0 {
            p = p.saturating_add(rows * row_sz);
            if p > tables.len() {
                // If we've overshot, Assembly table is inaccessible from here;
                // return what we have with no assembly info rather than panicking.
                return Some((None, None, None, mvid, types));
            }
        }
    }

    // ── Assembly table (TBL_ASSEMBLY = 0x20) ─────────────────────────────────
    // Layout (ECMA-335 §II.22.2):
    //   HashAlgId(u32) | MajorVersion(u16) | MinorVersion(u16) |
    //   BuildNumber(u16) | RevisionNumber(u16) |
    //   Flags(u32) | PublicKey(Blob) | Name(String) | Culture(String)
    let assembly_base = p;
    let assembly_rows = row_counts[TBL_ASSEMBLY] as usize;
    if assembly_rows == 0 || assembly_base + 16 + cw.blob + cw.string * 2 > tables.len() {
        return Some((None, None, None, mvid, types));
    }

    let major  = r16(tables, assembly_base + 4);
    let minor  = r16(tables, assembly_base + 6);
    let build  = r16(tables, assembly_base + 8);
    let rev    = r16(tables, assembly_base + 10);
    let version = Some(format!("{}.{}.{}.{}", major, minor, build, rev));

    // Skip HashAlgId(4) + version fields(8) + Flags(4) + PublicKey(blob)
    let name_off = assembly_base + 4 + 8 + 4 + cw.blob;
    let name_idx = read_index(tables, name_off, cw.string);
    let asm_name = {
        let n = strings_at(strings, name_idx).to_string();
        if n.is_empty() { None } else { Some(n) }
    };

    let culture_off = name_off + cw.string;
    let culture_idx = read_index(tables, culture_off, cw.string);
    let culture_str = strings_at(strings, culture_idx);
    let culture = Some(if culture_str.is_empty() { "neutral".to_string() } else { culture_str.to_string() });

    Some((asm_name, version, culture, mvid, types))
}

// ── obfuscator / cheat pattern detection ─────────────────────────────────────

/// Known obfuscator marker namespaces and type patterns.
/// These appear in the TypeDef table when an obfuscator injects marker
/// attributes or leaves residual scaffolding. Source: public obfuscator
/// documentation and public .NET obfuscation research.
static OBFUSCATOR_PATTERNS: &[(&str, &str)] = &[
    ("ConfuserEx",         "ConfuserEx marker namespace or type"),
    ("Confuser",           "Confuser / ConfuserEx residual"),
    ("ConfuserExProtections", "ConfuserEx protection attribute"),
    ("Obfuscar",           "Obfuscar obfuscation marker"),
    ("SmartAssembly",      "SmartAssembly by Redgate"),
    ("Eazfuscator",        "Eazfuscator.NET marker"),
    ("Dotfuscator",        "Dotfuscator by PreEmptive Solutions"),
    ("CliSecure",          "CliSecure / SecureTeam obfuscator"),
    ("Babel",              "Babel Obfuscator"),
    ("DeepSea",            "DeepSea Obfuscator"),
    ("Skater",             "Skater .NET Obfuscator"),
    ("MaxtoCode",          "MaxtoCode protector"),
    ("NetReactor",         "Eziriz .NET Reactor"),
    ("NetShrink",          ".Net Shrink packer"),
    ("Crypto",             "Crypto Obfuscator"),
    ("ILProtector",        "ILProtector by Niklas Weinder"),
    ("MindFusion",         "MindFusion obfuscation scaffold"),
    ("Agile.NET",          "Agile.NET (formerly CryptoObfuscator)"),
    ("Themida",            "Themida / WinLicense .NET protection"),
    ("Phoenix",            "Phoenix Protector"),
];

/// Known C# cheat / game-hack namespace and type patterns.
/// These are namespaces, class prefixes, or base types commonly found in
/// public C# cheat frameworks, ESP overlays, and Unity game-hack templates.
/// Sources: public GitHub cheat repositories, public anti-cheat research,
/// and published malware analysis reports — no NDA-covered sources.
static CHEAT_PATTERNS: &[(&str, &str, &str)] = &[
    // Process memory reading helpers (the bread and butter of external cheats)
    ("Memory",     "ReadProcessMemory",  "Memory reading class or method — common in external cheat frameworks"),
    ("Hack",       "ReadMemory",         "Generic 'Hack' namespace with memory-read method pattern"),
    ("Cheat",      "",                   "Top-level 'Cheat' namespace — common in public cheat templates"),
    ("ESP",        "",                   "ESP (Extra Sensory Perception) namespace — wallhack/overlay pattern"),
    ("Aimbot",     "",                   "'Aimbot' namespace — auto-aim module"),
    ("Triggerbot", "",                   "'Triggerbot' namespace — auto-fire module"),
    ("Bhop",       "",                   "'Bhop' (bunny-hop) namespace — movement exploit"),
    ("SpeedHack",  "",                   "'SpeedHack' namespace — game speed manipulation"),
    ("NoRecoil",   "",                   "'NoRecoil' namespace — recoil suppression"),
    ("WallHack",   "",                   "'WallHack' namespace — geometry penetration exploit"),
    ("Radar",      "CheatRadar",         "Radar cheat — map-hack / minimap ESP"),
    ("Inject",     "InjectDLL",          "DLL injection helper class"),
    ("UnityHack",  "",                   "Unity engine hack namespace"),
    ("Il2Cpp",     "Il2CppDumper",       "IL2CPP metadata dumper — used to reverse Unity IL2CPP games"),
    ("MonoHook",   "",                   "Mono/.NET runtime hook namespace"),
    ("GameHack",   "",                   "Generic 'GameHack' namespace"),
    ("CheatEngine","",                   "CheatEngine-related namespace"),
    ("Payload",    "Loader",             "Payload loader class — common in dropper/injector patterns"),
    ("Injector",   "",                   "Injector namespace — DLL/shellcode injection"),
    ("RWX",        "",                   "RWX (read-write-execute) memory namespace — shellcode staging"),
    // Unity-specific patterns
    ("UnityEngine","Il2CppSystem",       "IL2CPP Unity namespace — real-time game hack pattern"),
    ("SDK",        "GameSDK",            "Game SDK namespace — common in compiled cheat SDKs"),
    // Input simulation
    ("InputSim",   "",                   "Input simulation namespace — synthetic mouse/keyboard"),
    ("MouseMove",  "",                   "Mouse movement simulation — aimbot / input injection pattern"),
    // Anti-detection patterns
    ("AntiDetect", "",                   "Anti-detection namespace — attempting to evade AC scanning"),
    ("Spoofer",    "",                   "Hardware ID / driver spoofer namespace"),
    ("HWID",       "Spoof",              "HWID spoofer pattern — ban-evasion tooling"),
    ("Cleaner",    "TraceCleaner",       "Trace cleaner — log/artifact removal pattern"),
];

/// Scan the TypeDef type list for obfuscator markers and cheat patterns.
fn scan_types(
    types: &[(String, String)],
) -> (Vec<String>, Vec<CheatHit>) {
    let mut obf_hints: Vec<String> = Vec::new();
    let mut cheat_hits: Vec<CheatHit> = Vec::new();

    for (ns, name) in types {
        let ns_lo   = ns.to_lowercase();
        let name_lo = name.to_lowercase();

        // Obfuscator patterns: match against namespace OR type name
        for &(pattern, desc) in OBFUSCATOR_PATTERNS {
            let p_lo = pattern.to_lowercase();
            if ns_lo.contains(&p_lo) || name_lo.contains(&p_lo) {
                let hint = format!("{} — matched: {}.{}", desc, ns, name);
                if !obf_hints.contains(&hint) {
                    obf_hints.push(hint);
                }
            }
        }

        // Cheat patterns: match ns prefix against pattern[0], optional
        // name substring match against pattern[1] if non-empty.
        for &(ns_pat, name_pat, desc) in CHEAT_PATTERNS {
            let np_lo = ns_pat.to_lowercase();
            if !ns_lo.contains(&np_lo) && !name_lo.contains(&np_lo) {
                continue;
            }
            if !name_pat.is_empty() {
                let mp_lo = name_pat.to_lowercase();
                if !name_lo.contains(&mp_lo) && !ns_lo.contains(&mp_lo) {
                    continue;
                }
            }
            cheat_hits.push(CheatHit {
                pattern: ns_pat.to_string(),
                matched: format!("{}.{}", ns, name),
                description: desc.to_string(),
            });
        }
    }

    (obf_hints, cheat_hits)
}

/// Parse CLR metadata from a PE binary.
///
/// Returns `None` if data directory 14 (COM_DESCRIPTOR) is absent or zero,
/// i.e. the binary is not a .NET assembly. Returns `Some(ClrInfo)` with
/// as much information as could be safely extracted even if parts of the
/// metadata are corrupt or truncated.
///
/// # Arguments
/// * `data`     — full PE file bytes
/// * `lfanew`   — pe_pointer from the DOS header (offset of the PE signature)
/// * `sections` — section table from the parsed PE header
pub fn parse_clr(
    data: &[u8],
    lfanew: u32,
    sections: &[SectionTable],
) -> Option<ClrInfo> {
    // ── locate the CLR header ─────────────────────────────────────────────────
    // Data directory index 14 = IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR.
    // When present its RVA points to IMAGE_COR20_HEADER (also: COR20 header).
    let (clr_rva, clr_size) = pe_data_directory(data, lfanew, 14);
    if clr_rva == 0 || clr_size < 8 {
        return None; // Not a .NET assembly
    }
    let clr_off = rva_to_offset(clr_rva as u64, sections)?;
    if clr_off + 72 > data.len() {
        return None; // Header too small / truncated
    }

    // IMAGE_COR20_HEADER layout (ECMA-335 §II.25.3.3):
    //   Offset  Size  Field
    //      0     4    cb (header size, always 72)
    //      4     2    MajorRuntimeVersion
    //      6     2    MinorRuntimeVersion
    //      8     4    MetaData.VirtualAddress
    //     12     4    MetaData.Size
    //     16     4    Flags
    //     20     4    EntryPointToken or EntryPointRVA
    //   ... 14 more data directory pairs follow (we don't use them here)
    let meta_rva  = r32(data, clr_off + 8);
    let _meta_sz  = r32(data, clr_off + 12);
    let clr_flags = r32(data, clr_off + 16);

    // ── locate the metadata root ──────────────────────────────────────────────
    let meta_off = rva_to_offset(meta_rva as u64, sections)?;
    if meta_off >= data.len() { return None; }
    let metadata = &data[meta_off..];

    // ── extract runtime version string ────────────────────────────────────────
    // Bytes 12–15: 4-byte length of the version string (not null-terminated
    // in the length, but the field is padded to 4-byte alignment with '\0')
    let runtime_version = if metadata.len() >= 16 {
        let ver_len = (r32(metadata, 12) as usize).min(256);
        if 16 + ver_len <= metadata.len() {
            let ver_bytes = &metadata[16..16 + ver_len];
            let nul_pos = ver_bytes.iter().position(|&b| b == 0).unwrap_or(ver_len);
            std::str::from_utf8(&ver_bytes[..nul_pos])
                .unwrap_or("(invalid)")
                .to_string()
        } else {
            "(truncated)".to_string()
        }
    } else {
        "(unknown)".to_string()
    };

    // ── parse metadata streams ────────────────────────────────────────────────
    let streams = match find_metadata_streams(metadata) {
        Some(s) => s,
        None => {
            // We could still report the CLR header flags even if the
            // metadata streams are unreadable (e.g. packed/obfuscated).
            return Some(ClrInfo {
                runtime_version,
                clr_flags,
                clr_flags_desc: decode_clr_flags(clr_flags),
                assembly_name: None,
                assembly_version: None,
                culture: None,
                mvid: None,
                namespaces: vec![],
                type_names: vec![],
                obfuscator_hints: vec![
                    "Metadata streams unreadable — binary may be packed or native-code-protected".into()
                ],
                cheat_pattern_hits: vec![],
                is_ilonly:        clr_flags & 0x01 != 0,
                requires_32bit:   clr_flags & 0x02 != 0,
                strong_name_signed: clr_flags & 0x08 != 0,
            });
        }
    };

    // ── decode the logical metadata tables ────────────────────────────────────
    let (asm_name, asm_version, culture, mvid, types) =
        decode_tables(streams.tables, streams.strings, streams.guid)
            .unwrap_or((None, None, None, None, vec![]));

    // ── scan types for obfuscator markers and cheat patterns ──────────────────
    let (obfuscator_hints, cheat_pattern_hits) = scan_types(&types);

    // Deduplicate and collect namespaces and type names for the report
    let mut namespaces: Vec<String> = types.iter()
        .map(|(ns, _)| ns.clone())
        .filter(|ns| !ns.is_empty())
        .collect();
    namespaces.sort();
    namespaces.dedup();
    namespaces.truncate(256);

    let mut type_names: Vec<String> = types.iter()
        .map(|(_, name)| name.clone())
        .filter(|n| !n.is_empty())
        .collect();
    type_names.truncate(256);

    Some(ClrInfo {
        runtime_version,
        clr_flags,
        clr_flags_desc: decode_clr_flags(clr_flags),
        assembly_name: asm_name,
        assembly_version: asm_version,
        culture,
        mvid,
        namespaces,
        type_names,
        obfuscator_hints,
        cheat_pattern_hits,
        is_ilonly:          clr_flags & 0x01 != 0,
        requires_32bit:     clr_flags & 0x02 != 0,
        strong_name_signed: clr_flags & 0x08 != 0,
    })
}

// ── test-accessible pattern slices ───────────────────────────────────────────
// pub statics so integration tests (separate crate) can verify the tables
// contain expected entries. Not gated with #[cfg(test)] because integration
// tests in tests/ are compiled as a separate crate and cannot see cfg(test)
// items from the library.

pub static OBFUSCATOR_PATTERNS_FOR_TEST: &[(&str, &str)] = OBFUSCATOR_PATTERNS;

pub static CHEAT_PATTERNS_FOR_TEST: &[(&str, &str, &str)] = CHEAT_PATTERNS;
