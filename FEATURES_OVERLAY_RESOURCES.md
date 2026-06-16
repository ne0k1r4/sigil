# New in this release: overlay, resources, Authenticode, imphash database

This release adds four analysis surfaces commonly used to triage
suspicious PE binaries — particularly relevant for anti-cheat / cheat
loader research, where repacked, renamed, and signed-but-stolen binaries
are common.

## `sigil overlay <path>`

Shows (and optionally extracts) data appended after the last PE section —
the "overlay". Common in self-extracting archives, installers, and
Authenticode-signed binaries (the signature itself often lives here).

```bash
# Show overlay info (offset, size, SHA-256, entropy)
sigil overlay target.exe

# Extract the overlay bytes to a file for further analysis
sigil overlay target.exe -o overlay.bin

# JSON output
sigil overlay target.exe --json
```

If there's no overlay, this reports cleanly rather than erroring.

## `sigil resources <path>`

Shows VS_VERSIONINFO fields (CompanyName, FileDescription, FileVersion,
InternalName, LegalCopyright, OriginalFilename, ProductName,
ProductVersion) and SHA-256 hashes of any RT_ICON resources.

```bash
sigil resources target.exe
sigil resources target.exe --json
```

**Why this matters:** `OriginalFilename` not matching the actual filename
on disk, or a `CompanyName`/`ProductName` that doesn't match what the
binary actually does, is one of the fastest "this has been
renamed/repackaged" signals available. Icon hashes let you spot the same
icon reused across different builds or families — cheats frequently reuse
stolen or stock icons.

## Authenticode info (in `scan` / `headers`)

`sigil scan` and `sigil headers` now report whether a PE has an
Authenticode certificate table, plus a heuristic scan of the certificate
blob for readable identity strings (Subject/Issuer Common Names,
Organization fields, etc.):

```bash
sigil scan target.exe
# ...
# Authenticode:
#   cert type 2 / revision 0x0200 / 4521 bytes
#   candidate identities (from cert blob, unverified):
#     Acme Corporation
#     DigiCert Trusted G4 Code Signing CA
```

**Important:** this is presence + string-extraction only, **not signature
verification**. A binary having a certificate table does not mean the
signature is valid, unexpired, unrevoked, or that the binary hasn't been
tampered with since signing. For real verification, check the binary on a
Windows host (`signtool verify /pa`) or with a proper Authenticode/PKCS#7
library.

The headers table also gains a `Digitally Signed: true/false` line, and
`Rich Header Hash` / `Overlay` lines when present (from earlier in this
project).

## `--imphash-db <path>`

Load an external imphash database (e.g. a MalwareBazaar CSV export) and
check every scanned binary's imphash against it:

```bash
sigil --imphash-db imphash_full.csv scan target.exe
sigil --imphash-db imphash_full.csv hashes target.exe
sigil --imphash-db imphash_full.csv report target.exe
```

See `IMPHASH_SOURCES.md` for where to get a database and how the format
is parsed. Results appear as `imphash_db_match` in JSON output, separate
from `imphash_match` (the built-in starter set + `~/.sigil.toml` entries).

## All of the above in `sigil report`

`sigil report target.exe --html -o report.html` includes Overlay,
Authenticode, Version Info, and Icon Resources sections alongside the
existing Rich Header, entropy, imports, and signature-scan sections.
