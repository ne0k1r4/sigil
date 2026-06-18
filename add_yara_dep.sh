#!/usr/bin/env bash
# add_yara_dep.sh — adds yara-x to Cargo.toml (pure Rust, no libyara needed)
set -euo pipefail

CARGO_TOML="Cargo.toml"
[[ -f "$CARGO_TOML" ]] || { echo "Cargo.toml not found — run from project root" >&2; exit 1; }

# Remove old yara dep if present
sed -i '/^yara = /d' "$CARGO_TOML"

if grep -qE '^\s*yara-x\s*=' "$CARGO_TOML"; then
    echo "yara-x already present — nothing to do"
    exit 0
fi

awk '
    /^\[dependencies\]/ { print; print "yara-x = \"0.11\""; next }
    { print }
' "$CARGO_TOML" > "$CARGO_TOML.tmp"
mv "$CARGO_TOML.tmp" "$CARGO_TOML"
echo "added: yara-x = \"0.11\" (pure Rust, no libyara required)"
