#!/usr/bin/env bash
# bump_version.sh — sets the package version in Cargo.toml to 0.3.0.
# Safe to run multiple times (no-op if already 0.3.0).
set -euo pipefail

CARGO_TOML="Cargo.toml"
NEW_VERSION="0.3.0"

[[ -f "$CARGO_TOML" ]] || { echo "Cargo.toml not found — run from project root" >&2; exit 1; }

if grep -qE "^version = \"$NEW_VERSION\"" "$CARGO_TOML"; then
    echo "Cargo.toml already at $NEW_VERSION — nothing to do"
    exit 0
fi

# Only touch the version line inside [package] (first "version = ..." line)
awk -v ver="$NEW_VERSION" '
    /^\[package\]/ { in_pkg=1 }
    /^\[/ && !/^\[package\]/ { in_pkg=0 }
    in_pkg && /^version[[:space:]]*=/ && !done {
        print "version = \"" ver "\""
        done=1
        next
    }
    { print }
' "$CARGO_TOML" > "$CARGO_TOML.tmp"
mv "$CARGO_TOML.tmp" "$CARGO_TOML"
echo "bumped [package] version to $NEW_VERSION"
