//! Markdown report, for pasting into a ticket or wiki page.

use anyhow::Result;
use std::io::Write;

use super::{human_bytes, md_cell, thousands, RenderOpts};
use crate::cli::color::Theme;
use crate::model::Report;
use crate::spool::SpoolReader;

pub fn write(
    w: &mut dyn Write,
    r: &Report,
    spool: Option<&mut SpoolReader>,
    opts: &RenderOpts,
) -> Result<()> {
    if opts.matches_only {
        writeln!(
            w,
            "| Function | Severity | Category | Occurrences | Members |"
        )?;
        writeln!(w, "|---|---|---|---:|---:|")?;
        for s in &r.summary {
            writeln!(
                w,
                "| `{}` | {} | {} | {} | {} |",
                md_cell(&s.function),
                s.severity.as_str(),
                s.category.as_str(),
                thousands(s.occurrences as u64),
                s.members
            )?;
        }
        return Ok(());
    }

    writeln!(w, "# Binspector report")?;
    writeln!(w)?;
    if let Some(p) = &r.project {
        writeln!(w, "**Project:** {}", md_cell(p))?;
        writeln!(w)?;
    }
    writeln!(w, "| Field | Value |")?;
    writeln!(w, "|---|---|")?;
    writeln!(w, "| Binary | `{}` |", md_cell(&r.binary))?;
    writeln!(w, "| Scanned | {} |", r.timestamp)?;
    writeln!(
        w,
        "| Size | {} ({} bytes) |",
        human_bytes(r.file_size),
        thousands(r.file_size)
    )?;
    writeln!(w, "| MD5 | `{}` |", r.md5)?;
    writeln!(w, "| SHA1 | `{}` |", r.sha1)?;
    writeln!(w, "| SHA256 | `{}` |", r.sha256)?;
    writeln!(
        w,
        "| Matching | {} |",
        if r.case_sensitive {
            "case sensitive"
        } else {
            "case insensitive"
        }
    )?;
    writeln!(w, "| Min string length | {} |", r.min_len)?;
    writeln!(
        w,
        "| Banned names | {} |",
        thousands(r.banned_list_size as u64)
    )?;
    writeln!(w)?;

    let (crit, high, med, low) = r.severity_counts();
    writeln!(w, "## Findings")?;
    writeln!(w)?;
    writeln!(
        w,
        "{} distinct functions, {} occurrences. Critical {}, high {}, medium {}, low {}.",
        thousands(r.summary.len() as u64),
        thousands(r.banned_hit_count as u64),
        thousands(crit as u64),
        thousands(high as u64),
        thousands(med as u64),
        thousands(low as u64)
    )?;
    writeln!(w)?;
    if r.summary.is_empty() {
        writeln!(w, "No banned function references found.")?;
        if !r.reached_executable() {
            writeln!(w)?;
            writeln!(
                w,
                "> Treat this as inconclusive: no executable image was reached during the scan."
            )?;
        }
        writeln!(w)?;
    } else {
        writeln!(
            w,
            "| | Function | Severity | Category | Occurrences | Members |"
        )?;
        writeln!(w, "|---|---|---|---|---:|---:|")?;
        for s in &r.summary {
            writeln!(
                w,
                "| {} | `{}` | {} | {} | {} | {} |",
                Theme::marker(s.severity),
                md_cell(&s.function),
                s.severity.as_str(),
                s.category.as_str(),
                thousands(s.occurrences as u64),
                s.members
            )?;
        }
        writeln!(w)?;
    }

    if r.excluded_total > 0 && !r.include_excluded {
        writeln!(w, "### Suppressed as low confidence")?;
        writeln!(w)?;
        writeln!(
            w,
            "{} occurrences were whole-token matches inside namespace text or documentation \
             prose, such as `System.Windows.Forms` or \"Gets or sets\", rather than function \
             references. Re-run with `--include-low-confidence` to report them.",
            thousands(r.excluded_total as u64)
        )?;
        writeln!(w)?;
        writeln!(w, "| Function | Suppressed |")?;
        writeln!(w, "|---|---:|")?;
        for (name, n) in &r.excluded_top {
            writeln!(w, "| `{}` | {} |", md_cell(name), thousands(*n as u64))?;
        }
        writeln!(w)?;
    }

    writeln!(w, "## Coverage")?;
    writeln!(w)?;
    writeln!(
        w,
        "Container format `{}`, {} members, {} unpacked, {} strings.",
        r.coverage.root_format,
        thousands(r.coverage.members_scanned as u64),
        human_bytes(r.coverage.total_unpacked_bytes),
        thousands(r.strings_total as u64)
    )?;
    writeln!(w)?;
    writeln!(w, "| Member | Format | Size | Strings |")?;
    writeln!(w, "|---|---|---:|---:|")?;
    let mut entries = r.coverage.entries.clone();
    entries.sort_by_key(|e| std::cmp::Reverse(e.size));
    for e in entries.iter().take(50) {
        writeln!(
            w,
            "| `{}` | {} | {} | {} |",
            md_cell(&e.member),
            e.format,
            human_bytes(e.size),
            thousands(e.strings as u64)
        )?;
    }
    writeln!(w)?;

    if !r.warnings.is_empty() {
        writeln!(w, "## Warnings")?;
        writeln!(w)?;
        for warn in &r.warnings {
            writeln!(w, "- {}", md_cell(warn))?;
        }
        writeln!(w)?;
    }

    if !r.hits.is_empty() {
        writeln!(w, "## Occurrences")?;
        writeln!(w)?;
        writeln!(
            w,
            "| Function | Severity | Member | Offset | Encoding | Context |"
        )?;
        writeln!(w, "|---|---|---|---|---|---|")?;
        for h in r.reported_hits() {
            writeln!(
                w,
                "| `{}` | {} | `{}` | 0x{:x} | {} | `{}` |",
                md_cell(&h.function),
                h.severity.as_str(),
                md_cell(&h.member),
                h.offset,
                h.encoding.as_str(),
                md_cell(&h.context)
            )?;
        }
        writeln!(w)?;
    }

    if opts.dump {
        if let Some(sp) = spool {
            writeln!(w, "## Full string dump")?;
            writeln!(w)?;
            writeln!(w, "```")?;
            sp.for_each(|rec| {
                let marker = if rec.hits.is_empty() { "   " } else { "!!!" };
                writeln!(
                    w,
                    "{} {} 0x{:x} {}",
                    marker, rec.member, rec.offset, rec.text
                )?;
                Ok(())
            })?;
            writeln!(w, "```")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests_support::{opts, sample_report};

    fn render(r: &Report, o: &RenderOpts) -> String {
        let mut buf = Vec::new();
        write(&mut buf, r, None, o).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn has_headings_and_tables() {
        let out = render(&sample_report(), &opts());
        assert!(out.starts_with("# Binspector report"));
        assert!(out.contains("## Findings"));
        assert!(out.contains("## Coverage"));
        assert!(out.contains("## Occurrences"));
        assert!(out.contains("| `strcpy` | critical |"));
    }

    #[test]
    fn escapes_pipes_so_tables_do_not_break() {
        let mut r = sample_report();
        r.hits[0].context = "a|b".into();
        let out = render(&r, &opts());
        assert!(out.contains("a\\|b"));
    }

    #[test]
    fn matches_only_is_a_bare_table() {
        let o = RenderOpts {
            matches_only: true,
            ..opts()
        };
        let out = render(&sample_report(), &o);
        assert!(out.starts_with("| Function |"));
        assert!(!out.contains("# Binspector"));
    }

    #[test]
    fn clean_scan_without_executable_is_flagged() {
        let mut r = sample_report();
        r.summary.clear();
        r.coverage.entries[0].format = "unknown".into();
        let out = render(&r, &opts());
        assert!(out.contains("inconclusive"));
    }
}
