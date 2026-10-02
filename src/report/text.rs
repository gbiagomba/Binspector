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
    if r.is_manifest_digest() {
        // Named for what it is. The value is the SHA-256 of the newline-joined
        // "<sha256>  <label>" lines in target order, which is exactly what `sha256sum` emits, so a
        // reader can reproduce it by hand from the Targets table.
        writeln!(
            w,
            "Manifest SHA256:  {}  (over {} target digests, not a file hash)",
            r.sha256,
            r.targets.len()
        )?;
    } else {
        writeln!(w, "MD5:     {}", r.md5)?;
        writeln!(w, "SHA1:    {}", r.sha1)?;
        writeln!(w, "SHA256:  {}", r.sha256)?;
    }
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
    super::targets_section::write_text(w, r)?;
    write_posture_section(w, r)?;
    super::pe_section::write_text(w, r)?;
    super::pe_section::write_dll_search_text(w, r)?;
    super::exe_section::write_text(w, r)?;
    super::intel_section::write_carve_text(w, r)?;
    super::intel_section::write_intel_text(w, r)?;
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
    let (crit, high, med, low) = r.severity_counts();
    writeln!(
        w,
        "Findings: {} distinct functions, {} occurrences (critical {}, high {}, medium {}, \
         low {})",
        thousands(r.summary.len() as u64),
        thousands(r.banned_hit_count as u64),
        thousands(crit as u64),
        thousands(high as u64),
        thousands(med as u64),
        thousands(low as u64)
    )?;
    // The raw count is complete and the logical count is reviewable. Printed together, and only
    // when they differ, so a reader never has to re-derive the second to judge the first.
    let logical = r.logical_findings();
    if logical > 0 && logical < r.banned_hit_count {
        writeln!(
            w,
            "  {} distinct (module, function, severity) finding(s); the rest are the same module \
             shipped for another instruction set, so reviewing them is reviewing one thing",
            thousands(logical as u64)
        )?;
    }
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
    write_remediation(w, r)?;
    write_low_confidence(w, r)?;
    Ok(())
}

/// Disclose what confidence filtering removed, so suppression is auditable rather
/// than invisible.
/// How to fix the findings above, one entry per distinct function.
///
/// Mitigation findings have carried a `fix:` line since 5.0.0 and banned-function findings carried
/// none, which is backwards: a missing mitigation is one build flag, and replacing an unbounded
/// string call is the part that actually needs guidance.
///
/// Grouped by function rather than repeated per occurrence, because the advice is a property of the
/// function and 1,355 occurrences of the same ten names would otherwise print the same ten
/// paragraphs 1,355 times.
pub(super) fn write_remediation(w: &mut dyn Write, r: &Report) -> Result<()> {
    if r.summary.is_empty() {
        return Ok(());
    }
    writeln!(w, "Remediation")?;
    for s in &r.summary {
        writeln!(
            w,
            "  {} {}",
            Theme::marker(s.severity),
            opts_free_name(&s.function)
        )?;
        writeln!(
            w,
            "      {}",
            crate::scan::remediation::advice(&s.function, s.category)
        )?;
    }
    writeln!(w)?;
    Ok(())
}

/// The function name as the report prints it in this section, without theme decoration: the
/// remediation block is reference material and reads better unhighlighted.
fn opts_free_name(f: &str) -> &str {
    f
}

fn write_low_confidence(w: &mut dyn Write, r: &Report) -> Result<()> {
    if r.excluded_total == 0 || r.include_excluded {
        return Ok(());
    }
    writeln!(
        w,
        "Excluded by evidence: {} occurrences",
        thousands(r.excluded_total as u64)
    )?;
    // Per rule, so the total can be checked rather than believed. Each rule's premise is one
    // line, because a number with no reason attached is not auditable.
    for (rule, n) in &r.excluded_by_rule {
        let reason = rule_reason(rule);
        // A rule with no prose yet prints its identifier and count alone. Appending the separator
        // regardless left three trailing spaces on the line, which a diff of two reports shows as
        // a change and a terminal shows as nothing.
        if reason.is_empty() {
            writeln!(w, "    {:<30} {:>9}", rule, thousands(*n as u64))?;
        } else {
            writeln!(
                w,
                "    {:<30} {:>9}   {}",
                rule,
                thousands(*n as u64),
                reason
            )?;
        }
    }
    if !r.excluded_top.is_empty() {
        writeln!(w, "  Largest contributors by function:")?;
        for (name, n) in &r.excluded_top {
            writeln!(w, "    {:<30} {:>9}", name, thousands(*n as u64))?;
        }
    }
    writeln!(
        w,
        "  Re-run with --include-excluded to report them, each tagged with its rule."
    )?;
    writeln!(w)?;
    Ok(())
}

/// One line explaining why a rule removes an occurrence.
///
/// Stated in the report rather than only in the documentation: a reviewer reading a suppression
/// total should not have to go and look up what the rule meant.
fn rule_reason(rule: &str) -> &'static str {
    match rule {
        "prose" => "namespace text or documentation, not a function reference",
        "symbol-definition" => "a C++ method of that name, not a call to the CRT function",
        "ambiguous-name-no-import" => "an ordinary English word with no import backing it",
        "managed-no-native-call" => "a managed assembly has no native call site",
        // A rule with no prose yet prints its identifier alone, which is still auditable.
        _ => "",
    }
}

/// Missing exploit mitigations, which are findings rather than prose since 5.0.0.
///
/// Placed before the banned-function occurrences deliberately: a mitigation is confirmable
/// from metadata alone, needs no call-site analysis, and is fixable by changing a build flag,
/// which makes it the most actionable thing in the report.
pub(super) fn write_posture_section(w: &mut dyn Write, r: &Report) -> Result<()> {
    if r.posture.is_empty() {
        return Ok(());
    }
    writeln!(w, "Exploit mitigations: {} finding(s)", r.posture.len())?;
    for p in &r.posture {
        writeln!(
            w,
            "  {} {} [{}] {} image(s)",
            Theme::marker(p.severity),
            p.severity.as_str(),
            p.id,
            p.affected
        )?;
        writeln!(w, "      {}", p.title)?;
        writeln!(w, "      evidence: {}", p.evidence)?;
        writeln!(w, "      fix: {}", p.remediation)?;
        let shown: Vec<&str> = p
            .members
            .iter()
            .map(|m| super::fmt_util::short_name(m))
            .take(8)
            .collect();
        writeln!(
            w,
            "      images: {}{}",
            shown.join(", "),
            if p.affected > shown.len() {
                format!(", and {} more", p.affected - shown.len())
            } else {
                String::new()
            }
        )?;
        // Two different truncations, and conflating them misleads. The line above is display
        // truncation, where the full list is a field away. This is collection truncation: the
        // record itself holds only `members.len()` of `affected`, in scan order, so the stored
        // names are whatever the walk reached first. A reviewer read 50 of 179 as representative,
        // concluded the finding belonged to one vendor, and had to retract it.
        if p.affected > p.members.len() {
            writeln!(
                w,
                "      only {} of {} image name(s) were recorded, in scan order, so this list \
                 is not a sample to generalise from",
                p.members.len(),
                p.affected
            )?;
        }
    }
    writeln!(w)?;
    Ok(())
}

fn write_occurrences(w: &mut dyn Write, r: &Report, opts: &RenderOpts) -> Result<()> {
    if r.reported_hits().next().is_none() {
        return Ok(());
    }
    writeln!(w, "Occurrences")?;
    for h in r.reported_hits() {
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
/// Colour for a token in the `--dump` output.
///
/// Deliberately the **base** severity, not the adjusted one. A dump is a raw listing of every
/// extracted string, and the claim it makes about a highlighted token is only "this is a
/// banned name". The evidence rules judge a specific occurrence in a specific member, and this
/// function has neither: it is handed a line of spooled text and a byte range, and can only
/// join back to the summary by name. Since 5.0.0 one name can carry several adjusted
/// severities, so using the adjusted value here would colour by whichever occurrence happened
/// to be worst anywhere in the report, which is a claim about the wrong thing.
///
/// `usage.md` states this, so the difference between a dump colour and a findings severity is
/// documented rather than discovered.
fn worst_severity(r: &Report, text: &str, hits: &[(usize, usize)]) -> Severity {
    // Lowest of nothing is Low, not Medium: a token that matches no summary row should not
    // be painted as though it were a medium finding.
    let mut worst = Severity::Low;
    for (s, e) in hits {
        if *s >= *e || *e > text.len() {
            continue;
        }
        let token = &text[*s..*e];
        for summary in &r.summary {
            if summary.function.eq_ignore_ascii_case(token) && summary.base_severity() < worst {
                worst = summary.base_severity();
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
            tool: "binspector".to_string(),
            tool_version: "3.0.0".to_string(),
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
                base_severity: Some(Severity::Critical),
                category: Category::BufferOverflow,
                occurrences: 5,
                members: 2,
                excluded: 0,
            }],
            hits: vec![],
            excluded_total: 0,
            excluded_top: vec![],
            include_excluded: false,
            targets: Vec::new(),
            posture: Vec::new(),
            excluded_by_rule: Vec::new(),
            coverage: Coverage {
                root_format: "zip".into(),
                members_scanned: 3,
                total_unpacked_bytes: 400_000_000,
                entries: vec![CoverageEntry {
                    member: "b :: app.msix :: App.exe".into(),
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
        assert!(out.contains("256.0 MiB"));
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
