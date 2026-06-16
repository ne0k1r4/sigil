# Imphash Database Sources

`sigil` ships with a tiny built-in starter set of imphashes (in
`src/sigs.rs`) and supports loading a much larger external database via:

```bash
sigil --imphash-db /path/to/imphashes.csv scan target.exe
```

## Why the built-in list is intentionally small

An imphash is a hash of a PE's import table, computed in import order.
It is **toolchain-dependent**, not malware-specific: many different
binaries — including entirely benign ones — can share the same imphash
simply because they were built with the same compiler/linker and import
the same set of functions in the same order.

A match against a known-bad imphash means "this binary's import table
looks like samples that have been seen before" — it's a lead worth
investigating, not a verdict. Treat `sigil`'s imphash output the same way
you'd treat a single AV engine flag on VirusTotal.

## Getting a real database: MalwareBazaar

[abuse.ch MalwareBazaar](https://bazaar.abuse.ch/) publishes CSV exports
mapping imphashes to malware family signatures, updated regularly:

```bash
curl -sL https://bazaar.abuse.ch/export/csv/imphash/full/ -o imphash_full.csv
sigil --imphash-db imphash_full.csv scan target.exe
```

`sigil`'s loader (`sigs::load_imphash_db`) accepts this format directly:

- Comma-separated `imphash,signature[,...]` per line
- Extra columns are ignored
- Quoted fields (`"..."`) have quotes stripped
- Any row whose first field isn't a 32-character hex string is skipped —
  so a header row like `imphash,signature` is handled automatically
- Hashes are lowercased on load and matched case-insensitively

## Other sources worth combining

- **VirusTotal / Hatching Triage** — if you have API access, both expose
  imphash alongside family classifications for samples you've already
  collected.
- **Your own corpus** — if you're tracking a specific anti-cheat or cheat
  loader family over time, build your own CSV from samples you've
  confirmed, and pass it via `--imphash-db`. This is usually far more
  precise than any general-purpose feed for a narrow research focus.

## Adding entries permanently

For a handful of hashes you want available without passing `--imphash-db`
every time, add them to `~/.sigil.toml` instead:

```toml
[[known_imphashes]]
pattern = "a909b3c8d3d1ce4ae0a4f607a37a8129"
description = "Cobalt Strike beacon — confirmed in our 2026-03 sample set"
```

These are checked via `sigs::check_imphash` (the built-in path) and are
reported separately from `--imphash-db` matches (`imphash_match` vs.
`imphash_db_match` in JSON output), so you can tell at a glance which
source flagged a hash.
