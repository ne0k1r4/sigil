#!/usr/bin/env bash
# add_yara_dep.sh — adds the yara crate to [dependencies] in Cargo.toml.
# Also ensures goblin is imported in disasm.rs (already in Cargo.toml).
# Safe to run multiple times.
set -euo pipefail

CARGO_TOML="Cargo.toml"
[[ -f "$CARGO_TOML" ]] || { echo "Cargo.toml not found — run from project root" >&2; exit 1; }

if grep -qE '^\s*yara\s*=' "$CARGO_TOML"; then
    echo "yara dependency already present — nothing to do"
    exit 0
fi

awk '
    /^\[dependencies\]/ { print; print "yara = \"0.18\""; next }
    { print }
' "$CARGO_TOML" > "$CARGO_TOML.tmp"
mv "$CARGO_TOML.tmp" "$CARGO_TOML"
echo "added: yara = \"0.18\" under [dependencies]"
echo ""
echo "NOTE: libyara must be installed on your system:"
echo "  Arch:   sudo pacman -S yara"
echo "  Debian: sudo apt install libyara-dev"
echo "  macOS:  brew install yara"
