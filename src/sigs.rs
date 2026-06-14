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

/// Small starter set of known imphashes for common packers/loaders, useful
/// as a quick triage signal. This list is intentionally minimal — extend it
/// via `~/.sigil.toml` (`[[known_imphashes]]`) with hashes relevant to your
/// own threat intel rather than relying on this list alone.
static KNOWN_IMPHASHES: &[(&str, &str)] = &[
    ("1f2d5f2b1d3b6e9a4c7d8e9f0a1b2c3d", "Example: generic UPX-packed stub (illustrative placeholder)"),
];

/// Check a computed imphash against the built-in table and any
/// user-supplied entries from ~/.sigil.toml. Returns the description of
/// the first match, if any.
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
