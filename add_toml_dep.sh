#!/usr/bin/env bash
# add_toml_dep.sh — adds the `toml` crate to [dependencies] in Cargo.toml
# if it isn't already present. Safe to run multiple times.
set -euo pipefail

CARGO_TOML="Cargo.toml"

[[ -f "$CARGO_TOML" ]] || { echo "Cargo.toml not found — run from project root" >&2; exit 1; }

if grep -qE '^\s*toml\s*=' "$CARGO_TOML"; then
    echo "toml dependency already present — nothing to do"
    exit 0
fi

# Insert after the [dependencies] line
if grep -q '^\[dependencies\]' "$CARGO_TOML"; then
    awk '
        /^\[dependencies\]/ { print; print "toml = \"0.8\""; next }
        { print }
    ' "$CARGO_TOML" > "$CARGO_TOML.tmp"
    mv "$CARGO_TOML.tmp" "$CARGO_TOML"
    echo "added: toml = \"0.8\" under [dependencies]"
else
    echo "no [dependencies] section found — please add manually:" >&2
    echo '  toml = "0.8"' >&2
    exit 1
fi
