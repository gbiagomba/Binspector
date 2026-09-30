//! Plain text report, the default human-facing output.

use anyhow::Result;
use std::io::Write;

use super::{human_bytes, thousands, RenderOpts};
use crate::cli::color::Theme;
use crate::model::Report;
use crate::scan::banned::Severity;
use crate::spool::SpoolReader;

pub fn write(
    w: &mut dyn Write,
    r: &Report,
    spool: Option<&mut SpoolReader>,
    opts: &RenderOpts,
) -> Result<()> {
    if opts.matches_only {
        return write_matches_only(w, r, opts);
    }

    writeln!(w, "{} {} report", r.tool, r.tool_version)?;
    writeln!(w, "Binary:  {}", r.binary)?;
    if let Some(p) = &r.project {
        writeln!(w, "Project: {}", p)?;
    }
    writeln!(w, "Scanned: {}", r.timestamp)?;
    writeln!(
        w,
        "Size:    {} ({} bytes)",
        human_bytes(r.file_size),
        thousands(r.file_size)
    )?;
    writeln!(w, "MD5:     {}", r.md5)?;
    writeln!(w, "SHA1:    {}", r.sha1)?;
    writeln!(w, "SHA256:  {}", r.sha256)?;
    writeln!(
        w,
        "Matching: {}, min string length {}, {} banned names",
        if r.case_sensitive {
            "case sensitive"
        } else {
            "case insensitive"
        },
        r.min_len,
        thousands(r.banned_list_size as u64)
    )?;
    writeln!(w)?;

    write_coverage(w, r)?;
    write_warnings(w, r, opts)?;
    write_summary(w, r, opts)?;
    write_occurrences(w, r, opts)?;

    if opts.dump {
        if let Some(sp) = spool {
            write_dump(w, sp, r, opts)?;
        }
    }
    Ok(())
}

fn write_coverage(w: &mut dyn Write, r: &Report) -> Result<()> {
    let c = &r.coverage;
    writeln!(w, "Coverage")?;
    writeln!(w, "  Container format: {}", c.root_format)?;
    writeln!(
        w,
        "  Members scanned:  {}",
        thousands(c.members_scanned as u64)
    )?;
    writeln!(
        w,
        "  Bytes unpacked:   {}",
        human_bytes(c.total_unpacked_bytes)
    )?;
    writeln!(
        w,
        "  Strings found:    {}",
        thousands(r.strings_total as u64)
    )?;
    if !r.reached_executable() {
        writeln!(w, "  Executable image reached: no")?;
    }
    // Largest members first: those are where real code lives.
    let mut entries = c.entries.clone();
    entries.sort_by_key(|e| std::cmp::Reverse(e.size));
    for e in entries.iter().take(25) {
        writeln!(
            w,
            "    [{}] {} ({}, {} strings)",
            e.format,
            e.member,
            human_bytes(e.size),
            thousands(e.strings as u64)
        )?;
    }
    if entries.len() > 25 {
        writeln!(w, "    ... and {} more members", entries.len() - 25)?;
    }
    writeln!(w)?;
    Ok(())
}

fn write_warnings(w: &mut dyn Write, r: &Report, _opts: &RenderOpts) -> Result<()> {
    if r.warnings.is_empty() {
        return Ok(());
    }
    writeln!(w, "Warnings")?;
    for warn in &r.warnings {
        writeln!(w, "  - {}", warn)?;
    }
    writeln!(w)?;
    Ok(())
}

fn write_summary(w: &mut dyn Write, r: &Report, opts: &RenderOpts) -> Result<()> {
    let (crit, high, med) = r.severity_counts();
    writeln!(
        w,
        "Findings: {} distinct functions, {} occurrences (critical {}, high {}, medium {})",
        thousands(r.summary.len() as u64),
        thousands(r.banned_hit_count as u64),
        thousands(crit as u64),
        thousands(high as u64),
        thousands(med as u64)
    )?;
    if r.summary.is_empty() {
        writeln!(w, "  No banned function references found.")?;
        if !r.reached_executable() {
            writeln!(
                w,
                "  Treat this as inconclusive: no executable image was reached."
            )?;
        }
        writeln!(w)?;
        return Ok(());
    }
    for s in &r.summary {
        writeln!(
            w,
            "  {:<3} {:<8} {:<28} {:>9} occurrences in {} member(s)  [{}]",
            Theme::marker(s.severity),
            s.severity.as_str(),
            opts.theme.highlight(&s.function, s.severity),
            thousands(s.occurrences as u64),
            s.members,
            s.category.as_str()
        )?;
    }
    writeln!(w)?;
    write_low_confidence(w, r)?;
    Ok(())
}

/// Disclose what confidence filtering removed, so suppression is auditable rather
/// than invisible.
fn write_low_confidence(w: &mut dyn Write, r: &Report) -> Result<()> {
    if r.low_confidence_total == 0 || r.include_low_confidence {
        return Ok(());
    }
    writeln!(
        w,
        "Suppressed as low confidence: {} occurrences",
        thousands(r.low_confidence_total as u64)
    )?;
    writeln!(
        w,
        "  These are whole-token matches inside namespace text or documentation prose,"
    )?;
    writeln!(
        w,
        "  such as System.Windows.Forms or \"Gets or sets\", not function references."
    )?;
    for (name, n) in &r.low_confidence_top {
        writeln!(w, "    {:<28} {:>9}", name, thousands(*n as u64))?;
    }
    writeln!(w, "  Re-run with --include-low-confidence to report them.")?;
    writeln!(w)?;
    Ok(())
}

fn write_occurrences(w: &mut dyn Write, r: &Report, opts: &RenderOpts) -> Result<()> {
    if r.hits.is_empty() {
        return Ok(());
    }
    writeln!(w, "Occurrences")?;
    for h in &r.hits {
        writeln!(
            w,
            "  {} {} in {} at offset 0x{:x} (string at 0x{:x}, {}, {} confidence)",
            Theme::marker(h.severity),
            opts.theme.bold(&h.function),
            h.member,
            h.offset,
            h.string_offset,
            h.encoding.as_str(),
            h.confidence.as_str()
        )?;
        let ctx = opts.theme.highlight_ranges(
            &h.context,
            &[(h.context_start, h.context_end)],
            h.severity,
        );
        writeln!(w, "      {}", ctx)?;
    }
    writeln!(w)?;
    Ok(())
}

fn write_matches_only(w: &mut dyn Write, r: &Report, _opts: &RenderOpts) -> Result<()> {
    // Tab separated so the output stays easy to cut, sort, and diff.
    for s in &r.summary {
        writeln!(
            w,
            "{}\t{}\t{}\t{}",
            s.function,
            s.occurrences,
            s.severity.as_str(),
            s.members
        )?;
    }
    Ok(())
}

fn write_dump(
    w: &mut dyn Write,
    spool: &mut SpoolReader,
    r: &Report,
    opts: &RenderOpts,
) -> Result<()> {
    writeln!(
        w,
        "Full string dump ({} strings)",
        thousands(r.strings_total as u64)
    )?;
    writeln!(
        w,
        "Banned references are marked with {} and highlighted.",
        if opts.theme.color {
            "color"
        } else {
            "angle brackets"
        }
    )?;
    writeln!(w)?;
    spool.for_each(|rec| {
        // Severity is per string; use the worst severity present for the highlight.
        let sev = worst_severity(r, &rec.text, &rec.hits);
        let rendered = opts.theme.highlight_ranges(&rec.text, &rec.hits, sev);
        let marker = if rec.hits.is_empty() {
            "   "
        } else {
            Theme::marker(sev)
        };
        writeln!(
            w,
            "{:<3} {} 0x{:<10x} {:<8} {}",
            marker,
            rec.member,
            rec.offset,
            rec.encoding.as_str(),
            rendered
        )?;
        Ok(())
    })?;
    Ok(())
}

/// Highest severity among the banned functions that matched inside one string.
fn worst_severity(r: &Report, text: &str, hits: &[(usize, usize)]) -> Severity {
    let mut worst = Severity::Medium;
    for (s, e) in hits {
        if *s >= *e || *e > text.len() {
            continue;
        }
        let token = &text[*s..*e];
        for summary in &r.summary {
            if summary.function.eq_ignore_ascii_case(token) && summary.severity < worst {
                worst = summary.severity;
            }
        }
    }
    worst
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::color::Palette;
    use crate::model::{Coverage, CoverageEntry, MatchSummary};
    use crate::scan::banned::Category;

    fn opts() -> RenderOpts {
        RenderOpts {
            theme: Theme::plain(Palette::Default),
            matches_only: false,
            dump: false,
        }
    }

    fn report() -> Report {
        Report {
            tool: "binspector",
            tool_version: "3.0.0",
            binary: "sample.msixbundle".into(),
            project: Some("PROJ-123".into()),
            timestamp: "2026-09-30T00:00:00Z".into(),
            file_size: 268_435_456,
            md5: "m".into(),
            sha1: "s".into(),
            sha256: "s2".into(),
            min_len: 4,
            case_sensitive: false,
            banned_list_size: 197,
            strings_total: 3_150_271,
            banned_hit_count: 5,
            summary: vec![MatchSummary {
                function: "strcpy".into(),
                severity: Severity::Critical,
                category: Category::BufferOverflow,
                occurrences: 5,
                members: 2,
                low_confidence: 0,
            }],
            hits: vec![],
            low_confidence_total: 0,
            low_confidence_top: vec![],
            include_low_confidence: false,
            coverage: Coverage {
                root_format: "zip".into(),
                members_scanned: 3,
                total_unpacked_bytes: 400_000_000,
                entries: vec![CoverageEntry {
                    member: "b :: app.msix :: App.exe".into(),
                    format: "pe".into(),
                    size: 1000,
                    strings: 10,
                }],
            },
            warnings: vec!["a warning".into()],
        }
    }

    fn render_to_string(r: &Report, o: &RenderOpts) -> String {
        let mut buf = Vec::new();
        write(&mut buf, r, None, o).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn includes_metadata_coverage_and_findings() {
        let out = render_to_string(&report(), &opts());
        assert!(out.contains("Binary:  sample.msixbundle"));
        assert!(out.contains("PROJ-123"));
        assert!(out.contains("Coverage"));
        assert!(out.contains("Container format: zip"));
        assert!(out.contains("App.exe"));
        assert!(out.contains("Warnings"));
        assert!(out.contains("a warning"));
        assert!(out.contains("strcpy"));
        assert!(out.contains("critical"));
    }

    #[test]
    fn formats_large_numbers_readably() {
        let out = render_to_string(&report(), &opts());
        assert!(out.contains("3,150,271"), "{}", out);
        assert!(out.contains("256 MiB"));
    }

    #[test]
    fn marks_hits_without_color() {
        let out = render_to_string(&report(), &opts());
        assert!(out.contains(">strcpy<"));
        assert!(!out.contains('\x1b'));
        assert!(out.contains("!!!"));
    }

    #[test]
    fn clean_scan_without_executable_is_reported_inconclusive() {
        let mut r = report();
        r.summary.clear();
        r.banned_hit_count = 0;
        r.coverage.entries[0].format = "unknown".into();
        let out = render_to_string(&r, &opts());
        assert!(out.contains("No banned function references found"));
        assert!(out.contains("inconclusive"));
    }

    #[test]
    fn matches_only_omits_metadata() {
        let o = RenderOpts {
            matches_only: true,
            ..opts()
        };
        let out = render_to_string(&report(), &o);
        assert!(!out.contains("Coverage"));
        assert!(out.starts_with("strcpy\t5\tcritical"));
    }
}
