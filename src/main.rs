mod analyzer;
mod disasm;
mod hashes;
mod report;
mod sigs;

use analyzer::{
    analyze, categorize_strings, code_section_from_bytes, extract_strings,
    import_tuples, packing_hints_from_bytes, packing_verdict, pattern_search,
};
use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;

#[derive(Parser)]
#[command(name = "sigil", about = "Static PE/ELF binary analyzer", version = "0.2.0")]
struct Cli {
    /// Suppress banner and decorative output (safe for piping / scripting)
    #[arg(long, global = true)]
    quiet: bool,
    /// Bypass the 256 MB file size cap
    #[arg(long, global = true)]
    no_size_limit: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Full static analysis
    Scan   { path: String, #[arg(long)] json: bool },
    /// Show file headers and sections
    Headers { path: String, #[arg(long)] json: bool },
    /// Extract and categorize printable strings
    Strings {
        path: String,
        #[arg(short, long, default_value_t = 4)] min_len: usize,
        #[arg(short, long)] categorize: bool,
        #[arg(long)] json: bool,
    },
    /// Show import table
    Imports { path: String, #[arg(long)] json: bool },
    /// Show exports and symbols
    Symbols { path: String, #[arg(long)] json: bool },
    /// Show TLS callbacks (anti-cheat execution vectors)
    Tls     { path: String, #[arg(long)] json: bool },
    /// Compute MD5 / SHA-256 / imphash
    Hashes  { path: String, #[arg(long)] json: bool },
    /// Entropy + packing analysis
    Entropy { path: String, #[arg(long)] json: bool },
    /// Anti-debug technique detection
    Antidebug { path: String, #[arg(long)] json: bool },
    /// Anti-cheat engine detection
    Anticheat { path: String, #[arg(long)] json: bool },
    /// Disassemble code section entry bytes
    Disasm {
        path: String,
        #[arg(short, long, default_value_t = 64)] count: usize,
        #[arg(long)] json: bool,
    },
    /// Search for a hex byte pattern (supports ?? wildcards)
    Pattern {
        path: String,
        #[arg(short = 'p', long)] hex: String,
        #[arg(long)] json: bool,
    },
    /// Diff two binaries (imports / sections / hashes)
    Diff { a: String, b: String, #[arg(long)] json: bool },
    /// Export full report (HTML or JSON)
    Report {
        path: String,
        #[arg(long)] html: bool,
        #[arg(short, long)] output: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    let quiet = cli.quiet;
    let nsl   = cli.no_size_limit;

    if let Err(e) = run(cli.command, quiet, nsl) {
        // All errors go to stderr; never pollute stdout (breaks --json pipelines)
        eprintln!("{} {:#}", "error:".red().bold(), e);
        std::process::exit(1);
    }
}

fn run(command: Commands, quiet: bool, nsl: bool) -> Result<()> {
    match command {
        Commands::Scan { path, json } => {
            let (info, data) = analyze(&path, nsl)?;
            let tuples = import_tuples(&info);
            let ad     = sigs::scan_antidebug(&tuples, &info.strings);
            let ac     = sigs::scan_anticheat(&tuples, &info.strings);
            let hints  = packing_hints_from_bytes(&data).unwrap_or_default();
            if json {
                let mut obj = serde_json::to_value(&info)?;
                obj["antidebug"]     = serde_json::to_value(&ad)?;
                obj["anticheat"]     = serde_json::to_value(&ac)?;
                obj["packing_hints"] = serde_json::to_value(&hints)?;
                println!("{}", serde_json::to_string_pretty(&obj)?);
            } else {
                if !quiet { print_banner(&info.path, &info.format, &info.arch); }
                print_headers(&info.headers);
                print_entropy_summary(info.entropy, &info.sections);
                print_imports_summary(&info.imports);
                print_strings_summary(&info.strings);
                if !info.exports.is_empty() {
                    println!("\n{} {} exports", "Exports:".bold().cyan(), info.exports.len());
                }
                if !info.tls_callbacks.is_empty() {
                    println!("\n{}", "TLS Callbacks:".bold().red());
                    for t in &info.tls_callbacks { println!("  {} {}", "⚑".red(), t); }
                }
                if !ad.is_empty() || !ac.is_empty() {
                    println!("\n{}", "Detections:".bold().cyan());
                    println!("{}", "─".repeat(60).dimmed());
                    for h in ad.iter().chain(ac.iter()) {
                        let tag = if h.category == "anti-debug" { "[AD]".red() } else { "[AC]".magenta() };
                        println!("  {} {} — {}", tag, h.technique.bold(), h.matched.dimmed());
                    }
                }
            }
        }

        Commands::Headers { path, json } => {
            let (info, _) = analyze(&path, nsl)?;
            if json {
                println!("{}", serde_json::to_string_pretty(
                    &serde_json::json!({ "headers": info.headers, "sections": info.sections })
                )?);
            } else {
                if !quiet { print_banner(&info.path, &info.format, &info.arch); }
                print_headers(&info.headers);
                println!("\n{}", "Sections:".bold().cyan());
                println!("{:<24} {:>10} {:>10}", "Name".dimmed(), "Size".dimmed(), "Entropy".dimmed());
                println!("{}", "─".repeat(48).dimmed());
                for s in &info.sections {
                    let ent = format!("{:.3}", s.entropy);
                    let ec  = entropy_color(s.entropy, &ent);
                    println!("{:<24} {:>10} {:>10}", s.name, s.size, ec);
                }
            }
        }

        Commands::Strings { path, min_len, categorize, json } => {
            let data    = analyzer::read_file(&path, nsl)?;
            let strings = extract_strings(&data, min_len);
            if json {
                if categorize {
                    println!("{}", serde_json::to_string_pretty(&categorize_strings(&strings))?);
                } else {
                    println!("{}", serde_json::to_string_pretty(&strings)?);
                }
            } else if categorize {
                let cats = categorize_strings(&strings);
                if !quiet { println!("{}", "Categorized Strings:".bold().cyan()); }
                print_cat_section("URLs",     &cats.urls);
                print_cat_section("IPs",      &cats.ips);
                print_cat_section("Registry", &cats.registry);
                print_cat_section("Paths",    &cats.paths);
                print_cat_section("GUIDs",    &cats.guids);
                println!("\n{} {} other strings", "Other:".dimmed(), cats.other.len());
            } else {
                if !quiet {
                    println!("{} {} strings from {}", ">>".cyan(), strings.len(), path.yellow());
                    println!("{}", "─".repeat(60).dimmed());
                }
                for s in &strings { println!("{}", s); }
            }
        }

        Commands::Imports { path, json } => {
            let (info, _) = analyze(&path, nsl)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&info.imports)?);
            } else {
                if !quiet { print_banner(&info.path, &info.format, &info.arch); }
                if info.imports.is_empty() {
                    println!("{}", "No imports found.".yellow());
                    return Ok(());
                }
                println!("\n{} {} imports\n", ">>".cyan(), info.imports.len());
                let mut cur_lib = String::new();
                for imp in &info.imports {
                    if imp.library != cur_lib {
                        println!("\n  {} {}", "▸".yellow(), imp.library.bold().yellow());
                        cur_lib = imp.library.clone();
                    }
                    println!("    {}", imp.function.green());
                }
            }
        }

        Commands::Symbols { path, json } => {
            let (info, _) = analyze(&path, nsl)?;
            if json {
                println!("{}", serde_json::to_string_pretty(
                    &serde_json::json!({ "exports": info.exports, "symbols": info.symbols })
                )?);
            } else {
                if !quiet { print_banner(&info.path, &info.format, &info.arch); }
                if !info.exports.is_empty() {
                    println!("\n{} {} exports", "Exports:".bold().cyan(), info.exports.len());
                    println!("{}", "─".repeat(48).dimmed());
                    for e in &info.exports {
                        let ord = e.ordinal.map(|o| format!(" #{}", o)).unwrap_or_default();
                        println!("  {:016x}  {}{}", e.rva, e.name.yellow(), ord.dimmed());
                    }
                }
                if !info.symbols.is_empty() {
                    println!("\n{} {} symbols", "Symbols:".bold().cyan(), info.symbols.len());
                    println!("{}", "─".repeat(48).dimmed());
                    for sym in info.symbols.iter().take(200) {
                        println!("  {:016x}  {:<8} {}", sym.address, sym.kind.dimmed(), sym.name.green());
                    }
                    if info.symbols.len() > 200 {
                        println!("  ... {} more (use --json)", info.symbols.len() - 200);
                    }
                }
                if info.exports.is_empty() && info.symbols.is_empty() {
                    println!("{}", "No exports or symbols found.".yellow());
                }
            }
        }

        Commands::Tls { path, json } => {
            let (info, _) = analyze(&path, nsl)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&info.tls_callbacks)?);
            } else {
                if !quiet { print_banner(&info.path, &info.format, &info.arch); }
                println!("\n{}", "TLS Callbacks:".bold().red());
                println!("{}", "─".repeat(48).dimmed());
                if info.tls_callbacks.is_empty() {
                    println!("  {}", "No TLS callbacks found.".green());
                } else {
                    for t in &info.tls_callbacks { println!("  {} {}", "⚑".red(), t); }
                }
            }
        }

        Commands::Hashes { path, json } => {
            let h = hashes::compute(&path, nsl)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&h)?);
            } else {
                if !quiet {
                    println!("\n{}", "Hashes:".bold().cyan());
                    println!("{}", "─".repeat(72).dimmed());
                }
                println!("  {:<10} {}", "MD5".dimmed(),     h.md5.yellow());
                println!("  {:<10} {}", "SHA-256".dimmed(), h.sha256.yellow());
                if let Some(imp) = &h.imphash {
                    println!("  {:<10} {}", "imphash".dimmed(), imp.yellow());
                } else {
                    println!("  {:<10} {}", "imphash".dimmed(), "N/A".dimmed());
                }
            }
        }

        Commands::Entropy { path, json } => {
            let (info, data) = analyze(&path, nsl)?;
            let hints = packing_hints_from_bytes(&data).unwrap_or_default();
            if json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "overall":  info.entropy,
                    "verdict":  packing_verdict(info.entropy),
                    "hints":    hints,
                    "sections": info.sections,
                }))?);
            } else {
                if !quiet { print_banner(&path, &info.format, &info.arch); }
                println!("\n{}", "Entropy Analysis:".bold().cyan());
                println!("{}", "─".repeat(44).dimmed());
                println!("  Overall: {:.4} / 8.0", info.entropy);
                let verdict = packing_verdict(info.entropy);
                let vc = match verdict {
                    "LIKELY PACKED/ENCRYPTED" => verdict.red().bold(),
                    "SUSPICIOUS"              => verdict.yellow().bold(),
                    _                         => verdict.green().bold(),
                };
                println!("  Verdict: {}", vc);
                println!("\n{}", "Packing Hints:".bold().cyan());
                println!("{}", "─".repeat(44).dimmed());
                for h in &hints {
                    let icon = if h.starts_with("No packing") { "✓".green() } else { "⚠".yellow() };
                    println!("  {} {}", icon, h);
                }
                println!("\n{}", "Per-section entropy:".bold().cyan());
                println!("{:<24} {:>10} {:>10}", "Section".dimmed(), "Size".dimmed(), "Entropy".dimmed());
                println!("{}", "─".repeat(48).dimmed());
                for s in &info.sections {
                    let ent = format!("{:.3}", s.entropy);
                    let ec  = entropy_color(s.entropy, &ent);
                    println!("{:<24} {:>10} {:>10}", s.name, s.size, ec);
                }
            }
        }

        Commands::Antidebug { path, json } => {
            let (info, _) = analyze(&path, nsl)?;
            let hits = sigs::scan_antidebug(&import_tuples(&info), &info.strings);
            if json {
                println!("{}", serde_json::to_string_pretty(&hits)?);
            } else {
                if !quiet { print_banner(&info.path, &info.format, &info.arch); }
                println!("\n{} anti-debug scan — {} hits\n", "◈".red(), hits.len());
                println!("{}", "─".repeat(60).dimmed());
                if hits.is_empty() {
                    println!("  {}", "No anti-debug indicators detected.".green());
                } else {
                    for h in &hits {
                        println!("  {} {}", "⚑".red(), h.technique.bold());
                        println!("    {}", h.matched.dimmed());
                    }
                }
            }
        }

        Commands::Anticheat { path, json } => {
            let (info, _) = analyze(&path, nsl)?;
            let hits = sigs::scan_anticheat(&import_tuples(&info), &info.strings);
            if json {
                println!("{}", serde_json::to_string_pretty(&hits)?);
            } else {
                if !quiet { print_banner(&info.path, &info.format, &info.arch); }
                println!("\n{} anti-cheat scan — {} hits\n", "◈".magenta(), hits.len());
                println!("{}", "─".repeat(60).dimmed());
                if hits.is_empty() {
                    println!("  {}", "No anti-cheat indicators detected.".green());
                } else {
                    for h in &hits {
                        println!("  {} {}", "⚑".magenta(), h.technique.bold());
                        println!("    {}", h.matched.dimmed());
                    }
                }
            }
        }

        Commands::Disasm { path, count, json } => {
            let (info, data) = analyze(&path, nsl)?;
            let (off, sz, base, is64) = code_section_from_bytes(&data)?;
            let code  = data.get(off..off + sz).unwrap_or(&[]);
            let insns = disasm::disassemble(code, base, is64, count)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&insns)?);
            } else {
                if !quiet { print_banner(&info.path, &info.format, &info.arch); }
                println!("\n{} {} instructions from 0x{:x}\n", "◈ disasm".cyan().bold(), insns.len(), base);
                println!("{}", "─".repeat(70).dimmed());
                for i in &insns {
                    println!("  {:016x}  {:<32} {} {}",
                        i.addr, i.bytes.dimmed(), i.mnemonic.yellow().bold(), i.op_str.white());
                }
            }
        }

        Commands::Pattern { path, hex, json } => {
            let data = analyzer::read_file(&path, nsl)?;
            let hits = pattern_search(&data, &hex)?;
            if json {
                let v: Vec<String> = hits.iter().map(|o| format!("0x{:x}", o)).collect();
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                if !quiet {
                    println!("\n{} pattern {} — {} hits in {}",
                        "◈".cyan(), hex.yellow(), hits.len(), path.yellow());
                    println!("{}", "─".repeat(50).dimmed());
                }
                for offset in hits.iter().take(200) { println!("  0x{:016x}", offset); }
                if hits.len() > 200 {
                    println!("  ... {} more (use --json for full list)", hits.len() - 200);
                }
                if hits.is_empty() { println!("  {}", "No matches.".dimmed()); }
            }
        }

        Commands::Diff { a, b, json } => {
            let (ia, _) = analyze(&a, nsl)?;
            let (ib, _) = analyze(&b, nsl)?;
            let ha = hashes::compute(&a, nsl)?;
            let hb = hashes::compute(&b, nsl)?;

            let a_imports: std::collections::HashSet<String> =
                ia.imports.iter().map(|i| format!("{}!{}", i.library, i.function)).collect();
            let b_imports: std::collections::HashSet<String> =
                ib.imports.iter().map(|i| format!("{}!{}", i.library, i.function)).collect();
            let only_a: Vec<&String> = a_imports.difference(&b_imports).collect();
            let only_b: Vec<&String> = b_imports.difference(&a_imports).collect();

            let a_secs: std::collections::HashMap<&str, &analyzer::SectionInfo> =
                ia.sections.iter().map(|s| (s.name.as_str(), s)).collect();
            let b_secs: std::collections::HashMap<&str, &analyzer::SectionInfo> =
                ib.sections.iter().map(|s| (s.name.as_str(), s)).collect();

            if json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "a": { "path": a, "md5": ha.md5, "sha256": ha.sha256 },
                    "b": { "path": b, "md5": hb.md5, "sha256": hb.sha256 },
                    "imports_only_in_a": only_a,
                    "imports_only_in_b": only_b,
                }))?);
            } else {
                if !quiet {
                    println!("\n{} diff\n", "◈ sigil".bold().magenta());
                    println!("  A: {}  {}", a.yellow(), ha.md5.dimmed());
                    println!("  B: {}  {}", b.yellow(), hb.md5.dimmed());
                }
                println!("\n{}", "Hashes:".bold().cyan());
                println!("{}", "─".repeat(80).dimmed());
                println!("  {:<10} A: {}",   "MD5".dimmed(),     ha.md5.yellow());
                println!("  {:<10} B: {}",   "".dimmed(),         hb.md5.yellow());
                println!("  {:<10} A: {}", "SHA-256".dimmed(), ha.sha256.yellow());
                println!("  {:<10} B: {}", "".dimmed(),          hb.sha256.yellow());

                println!("\n{}", "Import diff:".bold().cyan());
                println!("{}", "─".repeat(50).dimmed());
                let mut only_a_s = only_a; only_a_s.sort();
                let mut only_b_s = only_b; only_b_s.sort();
                for s in &only_a_s { println!("  {} {}", "-".red(),   s.red()); }
                for s in &only_b_s { println!("  {} {}", "+".green(), s.green()); }
                if only_a_s.is_empty() && only_b_s.is_empty() {
                    println!("  {}", "Identical imports.".dimmed());
                }

                println!("\n{}", "Section entropy diff:".bold().cyan());
                println!("{}", "─".repeat(50).dimmed());
                let all: std::collections::BTreeSet<&str> =
                    a_secs.keys().chain(b_secs.keys()).copied().collect();
                for name in &all {
                    match (a_secs.get(name), b_secs.get(name)) {
                        (Some(a), Some(b)) => {
                            let delta = b.entropy - a.entropy;
                            let ds = format!("{:+.3}", delta);
                            let dc = if delta.abs() > 0.5 { ds.yellow() } else { ds.dimmed() };
                            println!("  {:<20} A:{:.3}  B:{:.3}  Δ{}", name, a.entropy, b.entropy, dc);
                        }
                        (Some(_), None) => println!("  {:<20} {}", name, "removed".red()),
                        (None, Some(_)) => println!("  {:<20} {}", name, "added".green()),
                        _ => {}
                    }
                }
            }
        }

        Commands::Report { path, html, output } => {
            let (info, data) = analyze(&path, nsl)?;
            let tuples  = import_tuples(&info);
            let ad_hits = sigs::scan_antidebug(&tuples, &info.strings);
            let ac_hits = sigs::scan_anticheat(&tuples, &info.strings);
            let hints   = packing_hints_from_bytes(&data).unwrap_or_default();
            let h       = hashes::from_bytes(&data);

            if html {
                let out = output.unwrap_or_else(|| format!("{}.html",
                    std::path::Path::new(&path).file_name()
                        .unwrap_or_default().to_string_lossy()));
                if std::path::Path::new(&out).exists() {
                    anyhow::bail!(
                        "output file '{}' already exists — pass -o <path> to choose a different name",
                        out
                    );
                }
                report::generate_html(&info, &ad_hits, &ac_hits, &hints, &h, &out)?;
                if !quiet {
                    println!("{} HTML report written to {}", ">>".green(), out.yellow());
                }
            } else {
                let mut obj = serde_json::to_value(&info)?;
                obj["antidebug"]     = serde_json::to_value(&ad_hits)?;
                obj["anticheat"]     = serde_json::to_value(&ac_hits)?;
                obj["packing_hints"] = serde_json::to_value(&hints)?;
                obj["hashes"]        = serde_json::to_value(&h)?;
                println!("{}", serde_json::to_string_pretty(&obj)?);
            }
        }
    }
    Ok(())
}

// ── display helpers ───────────────────────────────────────────────────────────

fn entropy_color<'a>(e: f64, s: &'a str) -> colored::ColoredString {
    if e > 7.2 { s.red() } else if e > 6.5 { s.yellow() } else { s.green() }
}

fn print_banner(path: &str, fmt: &str, arch: &str) {
    println!("\n{} {} {} {} {}\n",
        "◈ sigil".bold().magenta(), "▸".dimmed(),
        path.yellow(), format!("[{}]", fmt).cyan(), format!("[{}]", arch).cyan());
}

fn print_headers(headers: &[(String, String)]) {
    println!("{}", "Headers:".bold().cyan());
    println!("{}", "─".repeat(44).dimmed());
    for (k, v) in headers { println!("  {:<20} {}", k.dimmed(), v.bold()); }
}

fn print_entropy_summary(entropy: f64, sections: &[analyzer::SectionInfo]) {
    let verdict = packing_verdict(entropy);
    let vc = match verdict {
        "LIKELY PACKED/ENCRYPTED" => verdict.red().bold(),
        "SUSPICIOUS"              => verdict.yellow().bold(),
        _                         => verdict.green().bold(),
    };
    println!("\n{}", "Entropy:".bold().cyan());
    println!("{}", "─".repeat(44).dimmed());
    println!("  Overall: {:.4}  verdict: {}", entropy, vc);
    for s in sections {
        if s.entropy > 6.5 {
            println!("  {} '{}' {:.3}", "⚠".yellow(), s.name.bold(), s.entropy);
        }
    }
}

fn print_imports_summary(imports: &[analyzer::ImportEntry]) {
    println!("\n{} {} imports", "Imports:".bold().cyan(), imports.len());
    println!("{}", "─".repeat(44).dimmed());
    let mut cur = String::new();
    for imp in imports.iter().take(80) {
        if imp.library != cur {
            println!("\n  {}", imp.library.yellow().bold());
            cur = imp.library.clone();
        }
        println!("    {}", imp.function.green());
    }
    if imports.len() > 80 { println!("  ... {} more", imports.len() - 80); }
}

fn print_strings_summary(strings: &[String]) {
    println!("\n{} {} strings (top 30, use `sigil strings -c` to categorize)",
        "Strings:".bold().cyan(), strings.len());
    println!("{}", "─".repeat(44).dimmed());
    for s in strings.iter().take(30) { println!("  {}", s.dimmed()); }
    if strings.len() > 30 { println!("  ... {} more", strings.len() - 30); }
}

fn print_cat_section(label: &str, items: &[String]) {
    if items.is_empty() { return; }
    println!("\n{} ({})", label.bold().cyan(), items.len());
    println!("{}", "─".repeat(44).dimmed());
    for s in items.iter().take(50) { println!("  {}", s.yellow()); }
    if items.len() > 50 { println!("  ... {} more", items.len() - 50); }
}
