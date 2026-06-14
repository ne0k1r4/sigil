use crate::analyzer::{BinaryInfo, packing_verdict};
use crate::hashes::Hashes;
use crate::sigs::SigHit;
use anyhow::Result;
use std::fs;

pub fn generate_html(
    info: &BinaryInfo,
    ad_hits: &[SigHit],
    ac_hits: &[SigHit],
    packing_hints: &[String],
    hashes: &Hashes,
    out_path: &str,
) -> Result<()> {
    let imports_rows: String = info.imports.iter()
        .map(|i| format!("<tr><td>{}</td><td>{}</td></tr>", e(&i.library), e(&i.function)))
        .collect();

    let exports_rows: String = info.exports.iter()
        .map(|ex| format!("<tr><td>{}</td><td>{:#x}</td><td>{}</td></tr>",
            e(&ex.name), ex.rva, ex.ordinal.map(|o| o.to_string()).unwrap_or_default()))
        .collect();

    let sections_rows: String = info.sections.iter()
        .map(|s| {
            let cls = if s.entropy > 7.2 { "danger" } else if s.entropy > 6.5 { "warn" } else { "" };
            format!("<tr class=\"{}\"><td>{}</td><td>{}</td><td>{:.3}</td></tr>", cls, e(&s.name), s.size, s.entropy)
        })
        .collect();

    let sig_rows = |hits: &[SigHit]| -> String {
        if hits.is_empty() {
            return "<tr><td colspan=\"2\" class=\"ok\">None detected</td></tr>".into();
        }
        hits.iter().map(|h| format!("<tr><td>{}</td><td class=\"dim\">{}</td></tr>", e(&h.technique), e(&h.matched))).collect()
    };

    let hints_rows: String = packing_hints.iter()
        .map(|h| {
            let cls = if h.starts_with("No packing") { "ok" } else { "warn" };
            format!("<tr class=\"{}\"><td>{}</td></tr>", cls, e(h))
        })
        .collect();

    let strings_list: String = info.strings.iter().take(500)
        .map(|s| format!("<li>{}</li>", e(s)))
        .collect();

    let verdict = packing_verdict(info.entropy);
    let verdict_class = match verdict {
        "LIKELY PACKED/ENCRYPTED" => "danger",
        "SUSPICIOUS" => "warn",
        _ => "ok",
    };

    let imphash_row = hashes.imphash.as_deref().unwrap_or("N/A");
    let tls_rows: String = if info.tls_callbacks.is_empty() {
        "<tr><td class=\"ok\">No TLS callbacks found</td></tr>".into()
    } else {
        info.tls_callbacks.iter().map(|t| format!("<tr class=\"danger\"><td>{}</td></tr>", e(t))).collect()
    };

    let rich_section: String = match &info.rich_header {
        Some(rh) => {
            let rows: String = rh.entries.iter()
                .map(|en| format!(
                    "<tr><td>0x{:08x}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    en.comp_id, en.product_id, en.build_number, en.count
                ))
                .collect();
            format!(
                "<h2>Rich Header <span class=\"dim\">(hash: {})</span></h2>\n\
                 <table><thead><tr><th>CompID</th><th>ProductID</th><th>Build</th><th>Count</th></tr></thead><tbody>{}</tbody></table>",
                e(&rh.hash), rows
            )
        }
        None => String::new(),
    };

    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>sigil — {path}</title>
<style>
  body{{font-family:monospace;background:#0d0d0d;color:#c9d1d9;padding:2rem;max-width:1400px;margin:0 auto;}}
  h1{{color:#58a6ff;border-bottom:2px solid #21262d;padding-bottom:.5rem;}}
  h2{{color:#8b949e;border-bottom:1px solid #21262d;padding-bottom:4px;margin-top:2rem;}}
  table{{border-collapse:collapse;width:100%;margin-bottom:1rem;}}
  th{{background:#161b22;color:#58a6ff;padding:6px 12px;text-align:left;}}
  td{{padding:5px 12px;border-bottom:1px solid #21262d;font-size:.9rem;}}
  .danger td{{color:#f85149;}}.warn td{{color:#e3b341;}}.ok td{{color:#3fb950;}}
  .dim{{color:#444;font-size:.8rem;word-break:break-all;}}
  .badge{{padding:2px 8px;border-radius:4px;font-weight:bold;font-size:.85rem;}}
  .badge.danger{{background:#3d1f1f;color:#f85149;}}
  .badge.warn{{background:#3d2e00;color:#e3b341;}}
  .badge.ok{{background:#1a2e1a;color:#3fb950;}}
  .hash{{font-size:.85rem;color:#e3b341;word-break:break-all;}}
  ul{{list-style:none;padding:0;columns:3;}}
  li{{font-size:.75rem;color:#8b949e;word-break:break-all;padding:1px 0;}}
</style>
</head>
<body>
<h1>🔮 sigil <span style="font-size:1rem;color:#8b949e">— static analysis report</span></h1>
<p><strong>Target:</strong> <span style="color:#e3b341">{path}</span></p>

<h2>Hashes</h2>
<table>
  <tr><th>MD5</th><td class="hash">{md5}</td></tr>
  <tr><th>SHA-256</th><td class="hash">{sha256}</td></tr>
  <tr><th>imphash</th><td class="hash">{imphash}</td></tr>
</table>

<h2>Headers</h2>
<table><tr>{header_rows}</tr></table>

{rich_section}

<h2>Entropy <span class="badge {verdict_class}">{verdict}</span></h2>
<p>Overall: <strong>{entropy:.4}</strong> / 8.0</p>

<h2>Packing Hints</h2>
<table><tbody>{hints_rows}</tbody></table>

<h2>Sections</h2>
<table><thead><tr><th>Name</th><th>Size</th><th>Entropy</th></tr></thead><tbody>{sections_rows}</tbody></table>

<h2>TLS Callbacks</h2>
<table><tbody>{tls_rows}</tbody></table>

<h2>Anti-Debug Detections ({ad_count})</h2>
<table><thead><tr><th>Technique</th><th>Matched</th></tr></thead><tbody>{ad_rows}</tbody></table>

<h2>Anti-Cheat Detections ({ac_count})</h2>
<table><thead><tr><th>Technique</th><th>Matched</th></tr></thead><tbody>{ac_rows}</tbody></table>

<h2>Imports ({import_count})</h2>
<table><thead><tr><th>Library</th><th>Function</th></tr></thead><tbody>{imports_rows}</tbody></table>

<h2>Exports ({export_count})</h2>
<table><thead><tr><th>Name</th><th>RVA</th><th>Ordinal</th></tr></thead><tbody>{exports_rows}</tbody></table>

<h2>Strings (top 500)</h2>
<ul>{strings_list}</ul>

<footer><p style="color:#30363d;font-size:.7rem;margin-top:2rem">generated by sigil v0.2.0</p></footer>
</body></html>"#,
        path = info.path,
        md5 = hashes.md5,
        sha256 = hashes.sha256,
        imphash = imphash_row,
        header_rows = info.headers.iter()
            .map(|(k, v)| format!("<th>{}</th><td>{}</td>", k, v))
            .collect::<Vec<_>>().join("</tr><tr>"),
        rich_section = rich_section,
        verdict = verdict,
        verdict_class = verdict_class,
        entropy = info.entropy,
        hints_rows = hints_rows,
        sections_rows = sections_rows,
        tls_rows = tls_rows,
        ad_count = ad_hits.len(),
        ad_rows = sig_rows(ad_hits),
        ac_count = ac_hits.len(),
        ac_rows = sig_rows(ac_hits),
        import_count = info.imports.len(),
        imports_rows = imports_rows,
        export_count = info.exports.len(),
        exports_rows = exports_rows,
        strings_list = strings_list,
    );

    fs::write(out_path, html)?;
    Ok(())
}

#[inline]
fn e(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
