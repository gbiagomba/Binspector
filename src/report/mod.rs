//! Report rendering. One module per output format, dispatched from here.

pub mod csv;
pub mod html;
pub mod json;
pub mod markdown;
pub mod pe_section;
pub mod sarif;
pub mod sql;
pub mod targets_section;
pub mod text;

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
            c if c.is_control() && c != '\n' && c != '\t' => out.push('\u{FFFD}'),
            c => out.push(c),
        }
    }
    out
}

/// Escape pipe characters so a value cannot break a Markdown table row.
pub fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
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
            excluded_by_rule: Vec::new(),
            coverage: Coverage {
                root_format: "zip".into(),
                members_scanned: 3,
                total_unpacked_bytes: 400_000_000,
                entries: vec![CoverageEntry {
                    member: "bundle :: app.msix :: App.exe".into(),
                    format: "pe".into(),
                    size: 1000,
                    strings: 10,
                    imports: Vec::new(),
                    import_source: String::new(),
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
