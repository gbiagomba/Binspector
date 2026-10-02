//! Report rendering. One module per output format, dispatched from here.

pub mod analysis;
pub mod csv;
pub mod exe_section;
pub mod fmt_util;
pub mod html;
pub mod intel_section;
pub mod json;
pub mod markdown;
pub mod pdb_section;
pub mod pe_section;
pub mod sarif;
pub mod signature_section;
pub mod sql;
pub mod targets_section;
pub mod text;

// The refactor safety net: a fixture in which every section renders, and goldens pinning what each
// format produces from it. See `golden.rs` for why these exist.
#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod golden;

#[cfg(feature = "sqlite")]
pub mod sqlite;

use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

use crate::cli::color::Theme;
use crate::cli::format::OutputFormat;
use crate::model::Report;
use crate::spool::SpoolReader;

pub struct RenderOpts {
    pub theme: Theme,
    pub matches_only: bool,
    pub dump: bool,
}

/// Render `report` to a stream.
pub fn render(
    fmt: OutputFormat,
    w: &mut dyn Write,
    report: &Report,
    spool: Option<&mut SpoolReader>,
    opts: &RenderOpts,
) -> Result<()> {
    match fmt {
        OutputFormat::Text => text::write(w, report, spool, opts),
        OutputFormat::Markdown => markdown::write(w, report, spool, opts),
        OutputFormat::Html => html::write(w, report, spool, opts),
        OutputFormat::Csv => csv::write(w, report, spool, opts),
        OutputFormat::Json => json::write(w, report, opts),
        OutputFormat::Sarif => sarif::write(w, report),
        OutputFormat::Sql => sql::write(w, report, spool, opts),
        OutputFormat::Sqlite => bail!("sqlite output must be written to a path, not a stream"),
    }
}

/// Render a format that needs a real file path.
pub fn render_to_path(
    fmt: OutputFormat,
    path: &Path,
    report: &Report,
    spool: Option<&mut SpoolReader>,
    opts: &RenderOpts,
) -> Result<()> {
    // The parent has to exist before either writer opens the file. `-o out/` now resolves to a
    // stem inside `out`, and `-o out/sub/report.txt` was already a plausible request that failed
    // with a bare "No such file or directory" from `File::create`. Creating it is the obvious
    // reading of a path the caller typed, and it is their own output directory, not a scanned one.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("creating {}: {}", parent.display(), e))?;
        }
    }
    match fmt {
        #[cfg(feature = "sqlite")]
        OutputFormat::Sqlite => sqlite::write(path, report, spool, opts),
        // Backstop only: `--format all` no longer offers sqlite in a build without it, and
        // naming it explicitly is rejected during CLI validation. Reaching here means a
        // caller built the format list itself.
        #[cfg(not(feature = "sqlite"))]
        OutputFormat::Sqlite => bail!("{}", OutputFormat::Sqlite.unavailable_message()),
        other => {
            let file = std::fs::File::create(path)
                .map_err(|e| anyhow::anyhow!("creating {}: {}", path.display(), e))?;
            let mut w = std::io::BufWriter::new(file);
            render(other, &mut w, report, spool, opts)?;
            w.flush()?;
            Ok(())
        }
    }
}

/// Group thousands with commas, so large counts stay readable.
pub fn thousands(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

/// Human-readable byte size.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{} B", n);
    }
    let mut v = n as f64;
    let mut idx = 0usize;
    while v >= 1024.0 && idx < UNITS.len() - 1 {
        v /= 1024.0;
        idx += 1;
    }
    format!("{:.1} {}", v, UNITS[idx])
}

/// Escape a value for CSV, quoting only when needed.
pub fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Escape a value for a single-quoted SQL string literal.
pub fn sql_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Escape text for HTML body content and attribute values.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            // `is_control` is category Cc only, so the bidi overrides in Cf have to be named.
            c if (c.is_control() && c != '\n' && c != '\t') || is_bidi_control(c) => {
                out.push('\u{FFFD}')
            }
            c => out.push(c),
        }
    }
    out
}

/// Make a value inert inside a Markdown cell.
///
/// Everything this touches is attacker-controlled: a context string is bytes lifted out of the
/// scanned file, and a member path, signer Common Name or carved description comes from a binary the
/// tool was pointed at. The markdown report is read in a browser and pasted into wikis, so a cell has
/// to be inert rather than merely well-formed.
///
/// Four hazards, each with a reason it is not enough to handle the others:
///
/// * `|` ends the cell, so an unescaped one silently shifts every column after it.
/// * A newline ends the row.
/// * A backtick **breaks out of a code span**. Most untrusted cells are wrapped in backticks by the
///   writer, which makes their contents literal and is why `<script>` inside one is not live. One
///   backtick in the value defeats that, so relying on the code span alone is not safe.
/// * `<` can open raw HTML, which Markdown permits by design. Two cells are not backticked at all
///   (the project name and the warnings list), so inertness cannot be delegated to the writer.
///
/// Escaping the angle brackets means hostile text displays as `&lt;script&gt;` inside a code span
/// rather than as the original characters. That is accepted deliberately: the text being mangled is
/// an attack string nobody needs to read exactly, and the alternative is a cell whose safety depends
/// on which of two call sites rendered it.
pub fn md_cell(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '|' => out.push_str("\\|"),
            '\n' | '\r' => out.push(' '),
            // Neutralised rather than escaped: there is no escape for a backtick that works both
            // inside and outside a code span.
            '`' => out.push('\''),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c if is_bidi_control(c) => out.push('\u{FFFD}'),
            c => out.push(c),
        }
    }
    out
}

/// Bidirectional override and isolate controls.
///
/// Not ASCII control characters, so `char::is_control` is false for every one of them: they are
/// Unicode category `Cf`, where `is_control` only covers `Cc`. They reorder the glyphs that follow
/// them in a terminal and in a browser, which makes them the one real spoofing vector in a name
/// rendered to a reviewer. `pe::signer` already strips them from signer Common Names, but carved
/// descriptions, loader module names, IPC API strings, section names and component names never pass
/// through that filter, and under format parity they reach HTML and Markdown.
///
/// The joiners that Arabic and Indic scripts legitimately need are deliberately left alone.
fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}'
    )
}

#[cfg(test)]
mod escape_tests {
    use super::{html_escape, md_cell};

    #[test]
    fn markup_is_escaped() {
        assert_eq!(
            html_escape("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(html_escape(r#"a"b'c&d"#), "a&quot;b&#39;c&amp;d");
    }

    /// The gap this closes: U+202E is Unicode category Cf, so `char::is_control()` is false and it
    /// used to pass straight through into the HTML report, reordering every glyph after it.
    #[test]
    fn bidi_overrides_are_neutralised_in_both_non_text_formats() {
        for bad in ['\u{202e}', '\u{202d}', '\u{2066}', '\u{2069}', '\u{200f}'] {
            assert!(!bad.is_control(), "{:?} is Cf, not Cc", bad);
            let s = format!("Microsoft{}Corporation", bad);
            assert!(
                !html_escape(&s).contains(bad),
                "{:?} survived html_escape",
                bad
            );
            assert!(!md_cell(&s).contains(bad), "{:?} survived md_cell", bad);
        }
    }

    #[test]
    fn a_pipe_cannot_break_a_markdown_row() {
        assert_eq!(md_cell("a|b"), "a\\|b");
        assert_eq!(md_cell("a\nb"), "a b");
        assert_eq!(md_cell("a\rb"), "a b");
    }

    /// The subtle one: most untrusted cells are wrapped in backticks by the writer, which makes
    /// their contents literal. A backtick in the value escapes that span, and then any markup in the
    /// rest of the cell becomes live.
    #[test]
    fn a_backtick_cannot_break_out_of_a_code_span() {
        let out = md_cell("safe` <script>alert(1)</script>");
        assert!(!out.contains('`'), "a backtick survived: {:?}", out);
        assert!(!out.contains('<'), "markup survived: {:?}", out);
    }

    #[test]
    fn markup_cannot_open_in_an_unbackticked_cell() {
        // The project name and the warnings list are not wrapped by the writer.
        assert_eq!(md_cell("<b>x</b>"), "&lt;b&gt;x&lt;/b&gt;");
    }

    /// Scripts that need them keep them: stripping a joiner would corrupt legitimate text.
    #[test]
    fn legitimate_joiners_survive() {
        for ok in ['\u{200c}', '\u{200d}'] {
            let s = format!("a{}b", ok);
            assert!(html_escape(&s).contains(ok), "{:?} was stripped", ok);
            assert!(md_cell(&s).contains(ok), "{:?} was stripped", ok);
        }
    }
}

/// Shared fixtures for the per-format tests.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::RenderOpts;
    use crate::cli::color::{Palette, Theme};
    use crate::model::{Coverage, CoverageEntry, HitRecord, MatchSummary, Report};
    use crate::scan::banned::{Category, Severity};
    use crate::scan::confidence::Confidence;
    use crate::scan::strings::Encoding;

    pub fn opts() -> RenderOpts {
        RenderOpts {
            theme: Theme::plain(Palette::Default),
            matches_only: false,
            dump: false,
        }
    }

    pub(crate) use super::fixtures::{pe_entry, rich_report};

    pub fn sample_report() -> Report {
        Report {
            tool: "binspector".to_string(),
            tool_version: "3.0.0".to_string(),
            binary: "bundle.msixbundle".into(),
            project: Some("PROJ-123".into()),
            timestamp: "2026-09-30T00:00:00Z".into(),
            file_size: 268_435_456,
            md5: "0123456789abcdef0123456789abcdef".into(),
            sha1: "0123456789abcdef0123456789abcdef01234567".into(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            min_len: 4,
            case_sensitive: false,
            banned_list_size: 197,
            strings_total: 3_150_271,
            banned_hit_count: 5,
            summary: vec![MatchSummary {
                function: "strcpy".into(),
                severity: Severity::Critical,
                base_severity: Some(Severity::Critical),
                category: Category::BufferOverflow,
                occurrences: 5,
                members: 2,
                excluded: 24_227,
            }],
            hits: vec![HitRecord {
                vendor: None,
                function: "strcpy".into(),
                severity: Severity::Critical,
                base_severity: Some(Severity::Critical),
                category: Category::BufferOverflow,
                member: "bundle :: app.msix :: App.exe".into(),
                offset: 0x1234,
                token_len: 6,
                string_offset: 0x1230,
                encoding: Encoding::Ascii,
                confidence: Confidence::Exact,
                context: "call strcpy here".into(),
                context_start: 5,
                context_end: 11,
                adjustments: Vec::new(),
            }],
            excluded_total: 24_227,
            excluded_top: vec![("system".to_string(), 24_227)],
            include_excluded: false,
            targets: Vec::new(),
            posture: Vec::new(),
            external_imports: Vec::new(),
            excluded_by_rule: Vec::new(),
            coverage: Coverage {
                root_format: "zip".into(),
                members_scanned: 3,
                total_unpacked_bytes: 400_000_000,
                entries: vec![CoverageEntry {
                    digests: None,
                    copies: 1,
                    pdb: None,
                    vendor: None,
                    member: "bundle :: app.msix :: App.exe".into(),
                    format: "pe".into(),
                    size: 1000,
                    strings: 10,
                    imports: Vec::new(),
                    import_source: String::new(),
                    unix: None,
                    unix_executable: false,
                    pe: None,
                }],
                carved: vec![],
                carve_ran: false,
            },
            iocs: Default::default(),
            intel: Default::default(),
            warnings: vec!["a coverage warning".into()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousands_groups_correctly() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(3_150_271), "3,150,271");
    }

    #[test]
    fn human_bytes_scales() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(268_435_456), "256.0 MiB");
    }

    #[test]
    fn csv_quotes_only_when_needed() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn sql_literal_escapes_quotes() {
        assert_eq!(sql_literal("it's"), "'it''s'");
        // A classic injection attempt stays inert inside the literal.
        assert_eq!(sql_literal("'); DROP TABLE x;--"), "'''); DROP TABLE x;--'");
    }

    #[test]
    fn html_escape_neutralizes_markup() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("\"q\""), "&quot;q&quot;");
    }

    #[test]
    fn md_cell_escapes_pipes() {
        assert_eq!(md_cell("a|b"), "a\\|b");
    }
}
