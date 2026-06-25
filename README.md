# sigil

`sigil` is a Rust command-line tool for quick static triage of PE and ELF
binaries. I use it for the first pass: headers, sections, imports, strings,
hashes, entropy, and the obvious "this sample is trying to notice tools around
it" signals.

It is not a verifier, decompiler, or sandbox. Most detections are import/string
heuristics, so treat hits as leads to inspect, not proof by themselves.

## What it can pull out

- PE and ELF headers, sections, imports, exports, symbols, and TLS callbacks.
- Printable strings, with optional buckets for URLs, IPs, registry keys, paths,
  and GUIDs.
- MD5, SHA-256, and PE imphash.
- Overall and per-section entropy, plus a small set of packing hints.
- Anti-debug and anti-cheat indicators from built-in signatures, optional JSON
  signature files, and user config.
- PE extras: Rich header, overlay data, Authenticode certificate-table metadata,
  VS_VERSIONINFO fields, icon hashes, and CLR/.NET metadata when present.
- ELF init handlers from `.init_array` and `.preinit_array`.
- Short entry/code-section disassembly, or capped full executable-section
  disassembly with mnemonic and call summaries.
- YARA scans through `yara-x`.
- JSON output for most subcommands, HTML for full reports.

## Build

You need a recent Rust toolchain.

```bash
cargo build --release
```

The binary will be at:

```bash
./target/release/sigil
```

## Common runs

```bash
# First-pass triage
sigil scan sample.exe

# Machine-readable output
sigil scan sample.exe --json

# Headers, sections, Rich header, overlay, signature-table metadata, version info
sigil headers sample.exe

# Imports only
sigil imports sample.exe

# Strings, grouped into useful buckets
sigil strings sample.exe --categorize

# Hashes, including PE imphash when available
sigil hashes sample.exe

# Entropy and packing hints
sigil entropy sample.exe

# Built-in anti-debug and anti-cheat signature checks
sigil antidebug sample.exe
sigil anticheat sample.exe

# Entry/code-section disassembly
sigil disasm sample.exe --count 40

# Full executable-section disassembly, capped per section by default
sigil full-disasm sample.exe --freq --calls

# Byte pattern search; ?? is a wildcard
sigil pattern sample.exe --hex "48 8b ?? ?? 89"

# Compare imports and hashes for two samples
sigil diff old.exe new.exe

# YARA scan
sigil yara sample.exe --rules rules/

# HTML report
sigil report sample.exe --html --output sample-report.html
```

If you are piping output into another tool, add `--quiet` to suppress the banner.
Files over 256 MB are blocked by default; pass `--no-size-limit` when you really
want to analyze one.

## Custom signatures

`--sigs` loads external anti-debug and anti-cheat signatures from JSON. The
shape is intentionally small:

```json
{
  "antidebug_imports": [
    { "name": "IsDebuggerPresent", "desc": "Debugger presence check" }
  ],
  "antidebug_strings": [],
  "anticheat_imports": [],
  "anticheat_strings": []
}
```

`--custom-rules` loads TOML rules for raw byte and string matching. `--imphash-db`
accepts CSV records in `imphash,signature` form, which is handy for checking a
local MalwareBazaar-style export.

## Notes

- Authenticode support reports that a certificate table exists and extracts
  candidate identity strings from the blob. It does not validate trust,
  timestamping, revocation, or whether the signature still covers the file.
- Disassembly is meant for orientation. It is not control-flow recovery.
- Signature hits are case-insensitive import/string matches. Expect false
  positives and confirm anything important manually.

## Tests

```bash
cargo test
```

## License

GPL-3.0. See [LICENSE](LICENSE).
