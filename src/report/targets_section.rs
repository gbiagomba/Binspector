//! Shared rendering of the per-target table, used when one report covers several targets.
//!
//! 5.1.0 scans several named binaries, or a directory walked for candidates, into a single
//! report. The aggregate numbers answer "how bad is this set", and nothing else in the report
//! answers "which target do I open first". That is this section's only job.
//!
//! Deliberately silent for a single target. The scalar fields on `Report` already say
//! everything a one-file table would repeat, and a 5.0.0 scan has to render byte-identically.

use super::fmt_util::{fit_middle, preview};
use anyhow::Result;
use std::io::Write;

use super::{human_bytes, thousands};
use crate::model::{Report, TargetInfo};

/// Rows before the table is cut off, following the 25-row and 50-row caps used elsewhere.
///
/// A 400-target directory scan is a claim on a reviewer's attention, not a listing. The sort
/// puts everything worth opening first, and the full set is in `--format json`.
const ROW_CAP: usize = 40;

/// Labels named in one `!!` summary line before the rest are counted.
const LABEL_PREVIEW: usize = 6;

/// Columns for the label. A label is a provenance root, so it can be a relative path such as
/// `arm64/Microsoft.WindowsAppRuntime.2.msix`, which is 40 characters and already over this.
const LABEL_W: usize = 38;

/// Columns for the container format. Every `container::detect::Format::as_str` fits ("unknown"
/// is the longest at 7), so truncation here is a backstop for a format added later.
const FORMAT_W: usize = 7;

const SIZE_W: usize = 9;
const MEMBERS_W: usize = 7;
const SEV_W: usize = 11;

/// Write the per-target table. Silent when the report covers one target, so a single-file
/// scan is byte-identical to 5.0.0.
pub fn write_text(w: &mut dyn Write, r: &Report) -> Result<()> {
    // The gate that keeps that promise: a single-target report gains no new text at all, so
    // the 5.0.0 output stays reproducible byte for byte.
    if r.targets.len() <= 1 {
        return Ok(());
    }

    let total = r.targets.len();
    let occurrences: usize = r.targets.iter().map(|t| t.banned_hit_count).sum();
    let members: usize = r.targets.iter().map(|t| t.members_scanned).sum();
    let reached = r.targets.iter().filter(|t| t.reached_executable).count();

    // True totals, stated before the table, because the table is capped and a reviewer must
    // not have to infer the scope of the scan from the rows that survived the cap.
    writeln!(
        w,
        "Targets ({}, {} occurrence(s), {} member(s) scanned, {} of {} reached an executable \
         image)",
        thousands(total as u64),
        thousands(occurrences as u64),
        thousands(members as u64),
        thousands(reached as u64),
        thousands(total as u64)
    )?;
    // Four numbers in one line, three of which a reader has no reason to be able to decode.
    // A real user reported this header as the thing in the report they understood least, so
    // each term says what it counts and, where it matters, what it does not.
    writeln!(
        w,
        "  a target is a file named on the command line or found by walking a directory; a \
         member is anything unpacked out of one, nested archives included"
    )?;
    writeln!(
        w,
        "  occurrences count every banned-name match that survived the evidence rules, so one \
         function in one file can contribute several"
    )?;
    if reached < total {
        writeln!(
            w,
            "  `{} of {} reached an executable image` means the other {} yielded no PE, ELF or \
             Mach-O to analyse, so their clean rows state what was not examined",
            thousands(reached as u64),
            thousands(total as u64),
            thousands((total - reached) as u64)
        )?;
    } else {
        writeln!(
            w,
            "  every target yielded at least one PE, ELF or Mach-O image, so no row is clean \
             merely for want of something to analyse"
        )?;
    }

    // Both easy-to-miss states are named here as well as marked on their rows. The sort is by
    // findings, so a target that reached no code has nothing to sort on and lands at the
    // bottom, which is exactly where the row cap bites. Summarising it above the table is the
    // only way the warning survives a 400-target scan.
    let unreached: Vec<&str> = r
        .targets
        .iter()
        .filter(|t| !t.reached_executable)
        .map(|t| t.label.as_str())
        .collect();
    if !unreached.is_empty() {
        writeln!(
            w,
            "  !! {} target(s) never reached an executable image, so a clean result from them \
             is not evidence: {}",
            unreached.len(),
            preview(&unreached, LABEL_PREVIEW)
        )?;
    }
    let warned: Vec<&str> = r
        .targets
        .iter()
        .filter(|t| !t.warnings.is_empty())
        .map(|t| t.label.as_str())
        .collect();
    if !warned.is_empty() {
        writeln!(
            w,
            "  !! {} target(s) carry their own scan warnings: {}",
            warned.len(),
            preview(&warned, LABEL_PREVIEW)
        )?;
    }

    // Worst first, not scan order: a directory walk hands back filesystem order, which tells a
    // reviewer nothing about where to start.
    let mut rows: Vec<&TargetInfo> = r.targets.iter().collect();
    rows.sort_by(|a, b| {
        b.critical
            .cmp(&a.critical)
            .then(b.high.cmp(&a.high))
            .then(b.banned_hit_count.cmp(&a.banned_hit_count))
            .then(a.label.cmp(&b.label))
    });

    write_row(
        w,
        "",
        "target",
        "format",
        "size",
        "members",
        "c/h/m/l",
        "selected by",
    )?;
    let shown: Vec<&&TargetInfo> = rows.iter().take(ROW_CAP).collect();
    let display = disambiguate(&shown);
    for (t, label) in shown.iter().zip(display.iter()) {
        let flagged = !t.reached_executable || !t.warnings.is_empty();
        write_row(
            w,
            if flagged { "!!" } else { "" },
            label,
            &fit_middle(&t.root_format, FORMAT_W),
            &human_bytes(t.file_size),
            &thousands(t.members_scanned as u64),
            &format!("{}/{}/{}/{}", t.critical, t.high, t.medium, t.low),
            &t.selected_by,
        )?;
        // Reasons go under the row rather than in a column: they are prose of no fixed width,
        // and widening the table to hold them is what makes a table wrap.
        if !t.reached_executable {
            writeln!(
                w,
                "     !! no executable image reached, so this row's counts are inconclusive"
            )?;
        }
        if !t.warnings.is_empty() {
            let shown: Vec<&str> = t.warnings.iter().take(2).map(|s| s.as_str()).collect();
            writeln!(
                w,
                "     !! {} warning(s): {}{}",
                t.warnings.len(),
                shown.join("; "),
                if t.warnings.len() > shown.len() {
                    format!(" (and {} more)", t.warnings.len() - shown.len())
                } else {
                    String::new()
                }
            )?;
        }
    }
    if total > ROW_CAP {
        writeln!(w, "  ... and {} more target(s)", total - ROW_CAP)?;
    }

    // Context for numbers that are otherwise easy to read as something else: the order is not
    // the scan order, a row is not the whole report, and the hashes are missing on purpose.
    writeln!(
        w,
        "  Worst first, not scan order: critical, then high, then total occurrences."
    )?;
    writeln!(
        w,
        "  Each row counts only its own target; the totals above are their sum."
    )?;
    writeln!(
        w,
        "  Per-target paths and hashes (MD5, SHA1, SHA256) are in --format json."
    )?;
    writeln!(w)?;
    Ok(())
}

/// One fixed-width row, used for the header as well so the two can never drift apart.
#[allow(clippy::too_many_arguments)]
fn write_row(
    w: &mut dyn Write,
    marker: &str,
    label: &str,
    format: &str,
    size: &str,
    members: &str,
    severities: &str,
    selected_by: &str,
) -> Result<()> {
    // `selected_by` is last and unpadded: a value longer than expected lengthens the line
    // instead of shifting a column.
    writeln!(
        w,
        "  {:<2} {:<lw$} {:<fw$} {:>sw$} {:>mw$} {:>vw$}  {}",
        marker,
        label,
        format,
        size,
        members,
        severities,
        selected_by,
        lw = LABEL_W,
        fw = FORMAT_W,
        sw = SIZE_W,
        mw = MEMBERS_W,
        vw = SEV_W
    )?;
    Ok(())
}

/// Display labels for the rows, guaranteeing that no two render identically.
///
/// Truncation can collapse distinct labels: `Microsoft.VCLibs.ARM.14.00.Desktop.appx` and
/// `Microsoft.VCLibs.ARM64.14.00.Desktop.appx` differ only in a middle segment and both elide to
/// the same string. Two identical rows in a security report is a defect, not a cosmetic issue, so
/// a collision gets a `#n` suffix keyed to the row's position. The full labels are in the JSON,
/// which the closing line already says.
fn disambiguate(rows: &[&&TargetInfo]) -> Vec<String> {
    let mut out: Vec<String> = rows.iter().map(|t| fit_middle(&t.label, LABEL_W)).collect();
    let mut seen: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for label in &out {
        *seen.entry(label.clone()).or_insert(0) += 1;
    }
    let mut nth: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for (i, label) in out.iter_mut().enumerate() {
        if seen.get(label.as_str()).copied().unwrap_or(0) < 2 {
            continue;
        }
        let n = nth.entry(label.clone()).or_insert(0);
        *n += 1;
        let tag = format!("#{}", n);
        // Re-elide to make room for the tag rather than overflowing the column.
        let base = fit_middle(&rows[i].label, LABEL_W.saturating_sub(tag.len()));
        *label = format!("{}{}", base, tag);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests_support::sample_report;

    /// One target. Centralised so a field added to `TargetInfo` is a one-line fix here.
    fn target(label: &str, critical: usize, high: usize, occurrences: usize) -> TargetInfo {
        TargetInfo {
            label: label.to_string(),
            path: format!("/scan/{}", label),
            file_size: 13_000_000,
            md5: "0".repeat(32),
            sha1: "0".repeat(40),
            sha256: "0".repeat(64),
            root_format: "zip".into(),
            members_scanned: 3,
            total_unpacked_bytes: 400_000,
            strings_total: 1_000,
            banned_hit_count: occurrences,
            critical,
            high,
            medium: 0,
            low: 0,
            reached_executable: true,
            selected_by: "explicit".into(),
            warnings: Vec::new(),
        }
    }

    fn rendered(targets: Vec<TargetInfo>) -> String {
        let mut r = sample_report();
        r.targets = targets;
        let mut buf = Vec::new();
        write_text(&mut buf, &r).unwrap();
        String::from_utf8(buf).unwrap()
    }

    /// Row lines only. Every row ends with its `selected_by`, which no other line carries.
    fn rows(out: &str) -> Vec<&str> {
        out.lines().filter(|l| l.contains("explicit")).collect()
    }

    #[test]
    fn silent_for_zero_or_one_target() {
        assert_eq!(rendered(Vec::new()), "");
        assert_eq!(rendered(vec![target("only.exe", 0, 0, 0)]), "");
    }

    #[test]
    fn lists_every_label_when_there_are_several() {
        let out = rendered(vec![
            target("first.exe", 1, 0, 1),
            target("second.exe", 0, 2, 2),
            target("third.exe", 0, 0, 0),
        ]);
        for label in ["first.exe", "second.exe", "third.exe"] {
            assert!(out.contains(label), "missing {} in:\n{}", label, out);
        }
        // Totals come from the targets, not from the report's scalar fields.
        assert!(
            out.contains("Targets (3, 3 occurrence(s), 9 member(s) scanned"),
            "{}",
            out
        );
    }

    #[test]
    fn findings_sort_above_clean_targets() {
        // Scan order puts the clean target first; the table must not.
        let out = rendered(vec![
            target("aaa-clean.exe", 0, 0, 0),
            target("zzz-critical.exe", 1, 0, 1),
        ]);
        let crit = out.find("zzz-critical.exe").expect("row present");
        let clean = out.find("aaa-clean.exe").expect("row present");
        assert!(
            crit < clean,
            "critical target sorted below a clean one:\n{}",
            out
        );
    }

    #[test]
    fn flags_a_target_that_never_reached_an_executable() {
        let mut t = target("installer.bin", 0, 0, 0);
        t.reached_executable = false;
        let out = rendered(vec![t, target("app.exe", 1, 0, 1)]);
        let row = rows(&out)
            .into_iter()
            .find(|l| l.contains("installer.bin"))
            .expect("row present");
        assert!(row.contains("!!"), "row not flagged: {}", row);
        assert!(out.contains("never reached an executable image"), "{}", out);
        assert!(out.contains("inconclusive"), "{}", out);
    }

    #[test]
    fn flags_a_target_with_its_own_warnings() {
        let mut t = target("odd.msix", 0, 0, 0);
        t.warnings = vec!["truncated central directory".into()];
        let out = rendered(vec![t, target("app.exe", 1, 0, 1)]);
        let row = rows(&out)
            .into_iter()
            .find(|l| l.contains("odd.msix"))
            .expect("row present");
        assert!(row.contains("!!"), "row not flagged: {}", row);
        assert!(out.contains("truncated central directory"), "{}", out);
    }

    #[test]
    fn cap_engages_past_forty_targets() {
        let targets: Vec<TargetInfo> = (0..45)
            .map(|i| target(&format!("t{:02}.exe", i), 0, 0, 0))
            .collect();
        let out = rendered(targets);
        // `rows` filters on the `selected_by` value, which only data rows carry: the column
        // header reads "selected by", so the count is the cap exactly, not the cap plus one.
        assert_eq!(rows(&out).len(), ROW_CAP, "exactly {} data rows", ROW_CAP);
        assert!(out.contains("... and 5 more target(s)"), "{}", out);
        // The true total is stated regardless of the cap.
        assert!(out.contains("Targets (45,"), "{}", out);
    }

    #[test]
    fn a_long_label_keeps_the_table_fixed_width() {
        let long = format!("{}/Payload.msix", "nested".repeat(20));
        let out = rendered(vec![target("short.exe", 0, 0, 0), target(&long, 0, 0, 0)]);
        let rows = rows(&out);
        let short_row = rows.iter().find(|l| l.contains("short.exe")).expect("row");
        let long_row = rows
            .iter()
            .find(|l| l.contains("Payload.msix"))
            .expect("row");
        assert_eq!(
            short_row.chars().count(),
            long_row.chars().count(),
            "label width leaked into the row:\n{}",
            out
        );
        assert!(
            long_row.chars().count() <= 100,
            "row too wide: {}",
            long_row
        );
        assert!(long_row.contains('~'), "no truncation marker: {}", long_row);
        assert!(
            !long_row.contains(&long),
            "label was not truncated: {}",
            long_row
        );
    }

    #[test]
    fn fit_middle_keeps_both_ends() {
        assert_eq!(fit_middle("app.exe", 10), "app.exe");
        assert_eq!(fit_middle("a\nb", 10), "a b");
        assert_eq!(fit_middle("", 0), "");
        // The case that forced middle elision over tail-only: two labels sharing a tail and
        // differing only in the head must stay distinguishable in the table.
        let a = fit_middle("arm64/Microsoft.WindowsAppRuntime.2.msix", 20);
        let b = fit_middle("x64/Microsoft.WindowsAppRuntime.2.msix", 20);
        assert_ne!(a, b, "a reader must tell {} from {}", a, b);
        assert!(a.starts_with("arm64"), "head survives: {}", a);
        assert!(a.ends_with("msix"), "tail survives: {}", a);
        assert_eq!(a.chars().count(), 20);
    }

    #[test]
    fn rows_that_elide_to_the_same_string_are_disambiguated() {
        // Real case: these two differ only in a middle segment, so truncation collapses them.
        let mut a = target("Microsoft.VCLibs.ARM.14.00.Desktop.appx", 4, 10, 58);
        let mut b = target("Microsoft.VCLibs.ARM64.14.00.Desktop.appx", 4, 14, 65);
        a.file_size = 6_200_000;
        b.file_size = 10_600_000;
        let out = rendered(vec![a, b]);
        let labels: Vec<&str> = rows(&out).iter().map(|l| l.trim()).collect();
        assert_eq!(labels.len(), 2);
        assert_ne!(
            labels[0], labels[1],
            "two rows rendered identically:\n{}",
            out
        );
        assert!(out.contains('#'), "a collision must be marked:\n{}", out);
    }

    #[test]
    fn hashes_stay_out_of_the_table() {
        let out = rendered(vec![
            target("first.exe", 1, 0, 1),
            target("second.exe", 0, 0, 0),
        ]);
        assert!(
            !out.contains(&"0".repeat(32)),
            "hash in the table:\n{}",
            out
        );
        assert!(out.contains("--format json"), "{}", out);
    }

    #[test]
    fn label_preview_counts_the_remainder() {
        let labels = vec!["a", "b", "c", "d"];
        assert_eq!(preview(&labels, 10), "a, b, c, d");
        assert_eq!(preview(&labels, 2), "a, b, and 2 more");
    }
}
