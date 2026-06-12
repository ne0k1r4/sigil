# 🔮 sigil

`sigil` is a lightweight, cross-platform static PE and ELF binary analysis tool optimized for anti-cheat and anti-debug research. Written in Rust.

## Features

- **Format Agnostic**: Unified parsing for both Windows PE and Linux ELF binaries.
- **Detections**: Identifies debugger checks, VM environments, and anti-cheat hooks.
- **Dynamic Disassembly**: Dynamic CPU architecture-aware disassembly (x86, x86_64, ARM, AArch64) using Capstone.
- **Deep Inspection**: Extracts headers, sections, imports/exports, strings (categorized by type), and computes Shannon entropy.
- **Security Signatures**: MD5, SHA-256, and Windows PE `imphash` computation.
- **Reporting & Diffing**: Compares two binaries (diff mode) or generates standalone HTML reports.
- **Automated Tests**: Comprehensive unit tests cover all core features.

## Installation

Ensure you have Rust and Cargo installed, then build the release binary:

```bash
cargo build --release
```

## Quick Start

```bash
# Scan a binary for metadata and security detections
./target/release/sigil scan <path-to-binary>

# Disassemble the entry point of a binary (dynamic CPU detection)
./target/release/sigil disasm <path-to-binary> --count 20

# Scan for debugger/virtual machine signatures
./target/release/sigil antidebug <path-to-binary>

# Export a full HTML analysis report
./target/release/sigil report <path-to-binary> --html --output report.html
```

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
