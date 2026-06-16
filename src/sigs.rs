use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SigHit {
    pub category: String,
    pub technique: String,
    pub matched: String,
}

static ANTIDEBUG_IMPORTS: &[(&str, &str)] = &[
    ("IsDebuggerPresent",           "Debugger presence check (PEB.BeingDebugged)"),
    ("CheckRemoteDebuggerPresent",  "Remote debugger check"),
    ("NtQueryInformationProcess",   "Process debug port / NtGlobalFlag query"),
    ("ZwQueryInformationProcess",   "Process debug port (Zw variant)"),
    ("OutputDebugStringA",          "OutputDebugString timing trick"),
    ("OutputDebugStringW",          "OutputDebugString timing trick"),
    ("FindWindowA",                 "Debugger window title enumeration"),
    ("FindWindowW",                 "Debugger window title enumeration"),
    ("BlockInput",                  "Input blocking during anti-debug"),
    ("DebugActiveProcess",          "Self-debug attachment trick"),
    ("NtSetInformationThread",      "HideThreadFromDebugger trick"),
    ("CloseHandle",                 "CloseHandle invalid handle exception trick"),
    ("RaiseException",              "Exception-based anti-debug"),
    ("NtQuerySystemInformation",    "System kernel debugger flag check"),
    ("GetTickCount",                "Timing-based anti-debug"),
    ("QueryPerformanceCounter",     "Timing-based anti-debug (high res)"),
    ("NtQueryObject",               "ObjectAllTypesInformation debug check"),
    ("SetUnhandledExceptionFilter", "Exception filter manipulation"),
    ("CreateToolhelp32Snapshot",    "Process enumeration (detect debugger process)"),
    ("EnumProcesses",               "Process enumeration (detect debugger process)"),
];

static ANTIDEBUG_STRINGS: &[(&str, &str)] = &[
    ("x64dbg",                      "x64dbg debugger"),
    ("x32dbg",                      "x32dbg debugger"),
    ("ollydbg",                     "OllyDbg debugger"),
    ("windbg",                      "WinDbg debugger"),
    ("idaq64",                      "IDA Pro 64-bit"),
    ("idaq",                        "IDA Pro"),
    ("ida.exe",                     "IDA Pro"),
    ("devenv",                      "Visual Studio debugger"),
    ("cheatengine",                 "Cheat Engine"),
    ("processhacker",               "Process Hacker"),
    ("procmon",                     "Process Monitor"),
    ("wireshark",                   "Network capture tool"),
    ("VBoxGuest",                   "VirtualBox guest detection"),
    ("vmware",                      "VMware detection"),
    ("QEMU",                        "QEMU VM detection"),
    ("DbgBreakPoint",               "Breakpoint patching reference"),
    ("SeDebugPrivilege",            "Debug privilege enumeration"),
    ("HARDWARE\\DESCRIPTION\\System","Registry VM/hardware check"),
    ("\\BaseNamedObjects\\",        "Mutex-based debugger detection"),
];

static ANTICHEAT_IMPORTS: &[(&str, &str)] = &[
    ("NtLoadDriver",                "Kernel driver loading (AC kernel component)"),
    ("ZwLoadDriver",                "Kernel driver loading (Zw variant)"),
    ("DeviceIoControl",             "Driver IOCTL communication"),
    ("OpenProcess",                 "Process handle acquisition"),
    ("ReadProcessMemory",           "External process memory read"),
    ("WriteProcessMemory",          "External process memory write"),
    ("VirtualQueryEx",              "Remote process memory map enumeration"),
    ("CreateRemoteThread",          "Remote thread injection"),
    ("SetWindowsHookEx",            "Global hook installation"),
    ("NtOpenProcess",               "Low-level process open"),
    ("ZwOpenProcess",               "Low-level process open (Zw)"),
    ("EnumDeviceDrivers",           "Driver enumeration"),
    ("GetDeviceDriverBaseNameA",    "Driver name enumeration"),
    ("K32EnumDeviceDrivers",        "Driver enumeration (K32)"),
    ("MiniDumpWriteDump",           "Memory dump"),
    ("GetAsyncKeyState",            "Key state polling (aimbot/triggerbot)"),
    ("mouse_event",                 "Synthetic mouse input (aimbot)"),
    ("SendInput",                   "Synthetic input injection"),
    ("keybd_event",                 "Synthetic keyboard input"),
];

static ANTICHEAT_STRINGS: &[(&str, &str)] = &[
    ("EasyAntiCheat",               "EasyAntiCheat reference"),
    ("BattlEye",                    "BattlEye reference"),
    ("vgk.sys",                     "Vanguard kernel driver"),
    ("vanguard",                    "Riot Vanguard AC"),
    ("mhyprot2",                    "miHoYo kernel AC driver v2"),
    ("mhyprot",                     "miHoYo kernel AC driver"),
    ("nProtect",                    "nProtect GameGuard"),
    ("GameGuard",                   "nProtect GameGuard process"),
    ("HackShield",                  "AhnLab HackShield"),
    ("XignCode",                    "XIGNCODE3 AC"),
    ("Themida",                     "Themida protector"),
    ("BeService",                   "BattlEye service"),
    ("EasyAntiCheat.sys",           "EAC kernel driver"),
    ("NtCreateThreadEx",            "Stealthy thread creation"),
    ("LdrLoadDll",                  "Manual DLL load (bypass AC hooks)"),
    ("\\KnownDlls\\",              "KnownDlls hijack reference"),
    ("KeServiceDescriptorTable",    "SSDT hook reference"),
    ("MmGetSystemRoutineAddress",   "Kernel symbol resolution"),
    ("ObRegisterCallbacks",         "Object callback registration"),
    ("PsSetCreateProcessNotifyRoutine", "Process notify callback (AC)"),
    ("IoCreateDevice",              "Driver device creation"),
    ("RtlAdjustPrivilege",          "Privilege escalation"),
    ("\\\\.\\",                     "Device path prefix (driver IOCTL)"),
    ("\\Device\\",                  "Kernel device path"),
    ("\\\\GLOBALROOT",              "Device path (driver comms)"),
];

/// Match sig against individual strings — returns a short window around the match.
fn match_strings(strings: &[String], sig: &str) -> Option<String> {
    let sig_lo = sig.to_lowercase();
    for s in strings {
        let s_lo = s.to_lowercase();
        if let Some(pos) = s_lo.find(&sig_lo) {
            // Return a 80-char window centered on the match
            let start = pos.saturating_sub(20);
            let end = (pos + sig.len() + 40).min(s.len());
            let window = &s[start..end];
            return Some(if start > 0 { format!("…{}", window) } else { window.to_string() });
        }
    }
    None
}

pub fn scan_antidebug(imports: &[(String, String)], strings: &[String]) -> Vec<SigHit> {
    let mut hits = Vec::new();
    for (lib, func) in imports {
        for &(sig, desc) in ANTIDEBUG_IMPORTS {
            if func.eq_ignore_ascii_case(sig) {
                hits.push(SigHit { category: "anti-debug".into(), technique: desc.into(), matched: format!("{}!{}", lib, func) });
            }
        }
    }
    for &(sig, desc) in ANTIDEBUG_STRINGS {
        if let Some(m) = match_strings(strings, sig) {
            hits.push(SigHit { category: "anti-debug".into(), technique: desc.into(), matched: m });
        }
    }
    hits
}

pub fn scan_anticheat(imports: &[(String, String)], strings: &[String]) -> Vec<SigHit> {
    let mut hits = Vec::new();
    for (lib, func) in imports {
        for &(sig, desc) in ANTICHEAT_IMPORTS {
            if func.eq_ignore_ascii_case(sig) {
                hits.push(SigHit { category: "anti-cheat".into(), technique: desc.into(), matched: format!("{}!{}", lib, func) });
            }
        }
    }
    for &(sig, desc) in ANTICHEAT_STRINGS {
        if let Some(m) = match_strings(strings, sig) {
            hits.push(SigHit { category: "anti-cheat".into(), technique: desc.into(), matched: m });
        }
    }
    hits
}

// ── user-config-aware variants ────────────────────────────────────────────
//
// These wrap the built-in scanners above and additionally check entries
// loaded from ~/.sigil.toml (see config.rs). Kept separate from
// scan_antidebug/scan_anticheat so existing callers and tests that only
// care about the built-in tables are unaffected.

use crate::config::SigEntry;

pub fn scan_antidebug_with_config(
    imports: &[(String, String)],
    strings: &[String],
    extra_imports: &[SigEntry],
    extra_strings: &[SigEntry],
) -> Vec<SigHit> {
    let mut hits = scan_antidebug(imports, strings);
    for (lib, func) in imports {
        for sig in extra_imports {
            if func.eq_ignore_ascii_case(&sig.pattern) {
                hits.push(SigHit {
                    category: "anti-debug".into(),
                    technique: format!("{} (custom)", sig.description),
                    matched: format!("{}!{}", lib, func),
                });
            }
        }
    }
    for sig in extra_strings {
        if let Some(m) = match_strings(strings, &sig.pattern) {
            hits.push(SigHit {
                category: "anti-debug".into(),
                technique: format!("{} (custom)", sig.description),
                matched: m,
            });
        }
    }
    hits
}

pub fn scan_anticheat_with_config(
    imports: &[(String, String)],
    strings: &[String],
    extra_imports: &[SigEntry],
    extra_strings: &[SigEntry],
) -> Vec<SigHit> {
    let mut hits = scan_anticheat(imports, strings);
    for (lib, func) in imports {
        for sig in extra_imports {
            if func.eq_ignore_ascii_case(&sig.pattern) {
                hits.push(SigHit {
                    category: "anti-cheat".into(),
                    technique: format!("{} (custom)", sig.description),
                    matched: format!("{}!{}", lib, func),
                });
            }
        }
    }
    for sig in extra_strings {
        if let Some(m) = match_strings(strings, &sig.pattern) {
            hits.push(SigHit {
                category: "anti-cheat".into(),
                technique: format!("{} (custom)", sig.description),
                matched: m,
            });
        }
    }
    hits
}

// ── imphash clustering ───────────────────────────────────────────────────

/// Small starter set of imphashes that have been widely reported in public
/// threat-intel writeups. This is NOT a substitute for a real, current
/// database — imphashes are toolchain-dependent and a single value can
/// correspond to many different (and many *benign*) binaries built with
/// the same compiler/linker/import set. Treat a hit here as "worth a closer
/// look", not as a verdict.
///
/// For real coverage, load a MalwareBazaar-format imphash export via
/// `--imphash-db <path>` (see `load_imphash_db` below) — get one from
/// https://bazaar.abuse.ch/export/ — or add your own entries to
/// `~/.sigil.toml` under `[[known_imphashes]]`.
static KNOWN_IMPHASHES: &[(&str, &str)] = &[
    // Frequently cited in public reporting (2020-2023) as a default/common
    // Cobalt Strike beacon imphash. Cobalt Strike imphashes vary by version
    // and build options, so absence of a match means nothing — but a hit
    // is a strong signal worth investigating.
    ("a909b3c8d3d1ce4ae0a4f607a37a8129", "Commonly-reported Cobalt Strike beacon imphash — verify against current samples"),
];

/// A single imphash → description record, typically loaded from an
/// external database file via `load_imphash_db`.
#[derive(Debug, Clone)]
pub struct ImphashRecord {
    pub hash: String,
    pub description: String,
}

/// Load an imphash database from a CSV file.
///
/// Accepts the MalwareBazaar "imphash" export format
/// (https://bazaar.abuse.ch/export/) — comma-separated lines of
/// `imphash,signature[,...]`, optionally with a header row (any row whose
/// first field is not a 32-character hex string is skipped, so a header
/// like `imphash,signature` is handled automatically). Extra columns are
/// ignored. Quoted fields (`"..."`) have their quotes stripped.
pub fn load_imphash_db(path: &str) -> Result<Vec<ImphashRecord>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read imphash database '{}'", path))?;

    let mut records = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, ',');
        let hash = parts.next().unwrap_or("").trim().trim_matches('"');
        let desc = parts.next().unwrap_or("").trim().trim_matches('"');

        // Skip header rows / malformed lines: a real imphash is 32 hex chars
        if hash.len() != 32 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        records.push(ImphashRecord {
            hash: hash.to_lowercase(),
            description: if desc.is_empty() { "(no signature name)".to_string() } else { desc.to_string() },
        });
    }
    Ok(records)
}

/// Check a computed imphash against an externally-loaded database (see
/// `load_imphash_db`). Returns the matching record's description, if any.
pub fn check_imphash_db(hash: &str, db: &[ImphashRecord]) -> Option<String> {
    let hash_lower = hash.to_lowercase();
    db.iter()
        .find(|r| r.hash == hash_lower)
        .map(|r| r.description.clone())
}

/// Check a computed imphash against the built-in starter table and any
/// user-supplied entries from ~/.sigil.toml. Returns the description of
/// the first match, if any.
///
/// For broader coverage, also check `check_imphash_db` against a loaded
/// `--imphash-db` file.
pub fn check_imphash<'a>(hash: &str, extra: &'a [SigEntry]) -> Option<String> {
    for &(h, desc) in KNOWN_IMPHASHES {
        if h.eq_ignore_ascii_case(hash) {
            return Some(desc.to_string());
        }
    }
    for sig in extra {
        if sig.pattern.eq_ignore_ascii_case(hash) {
            return Some(format!("{} (custom)", sig.description));
        }
    }
    None
}
