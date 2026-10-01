//! Folding several targets' reports into one.
//!
//! Separate from `scan::mod` because aggregation is cross-target by nature while the scan itself
//! is per-target, and because keeping both in one file pushed it past the project's 1000-line
//! split point.

use anyhow::Result;

use super::{run_labeled, ScanConfig, ScanOutput};
use crate::hashing;
use crate::model::{MatchSummary, Report};
use crate::observe::{Event, Observer};

/// Scan several targets and aggregate them into one report.
///
/// Each target is read, scanned, and dropped before the next, so peak memory stays near the
/// largest single target rather than the sum: a directory of four hundred images at tens of
/// megabytes each never holds more than one.
///
/// Per-target scans are independent by design. Every resource cap in `Limits` stays per target,
/// because `max_expansion_ratio` is defined against one root size and a shared byte budget would
/// let the first target silently eat the four hundredth's coverage. The fleet-level ceilings live
/// in `select::SelectConfig` instead, where they bound the number of files and the bytes read.
pub fn run_many(
    targets: &[crate::select::Target],
    cfg: &ScanConfig,
    observer: &dyn Observer,
) -> Result<ScanOutput> {
    match targets {
        [] => anyhow::bail!("no targets to scan"),
        // One target produces output byte-identical to a single-target scan, which is what
        // keeps every existing report, test, and downstream consumer working unchanged.
        [only] => run_labeled(&only.path, &only.label, &only.selected_by, cfg, observer),
        many => {
            let total = many.len();
            let mut merged: Option<ScanOutput> = None;
            // One spool for the whole run, appended to as each target finishes, so the cost is
            // linear in the total rather than quadratic in the number of targets.
            let mut dump: Option<crate::spool::Spool> = None;
            for (i, t) in many.iter().enumerate() {
                observer.on(&Event::Target {
                    label: &t.label,
                    index: i + 1,
                    total,
                    size: t.size,
                });
                let mut one = run_labeled(&t.path, &t.label, &t.selected_by, cfg, observer)?;
                if let Some(mut reader) = one.spool.take() {
                    let sink = match dump.as_mut() {
                        Some(s) => s,
                        None => {
                            dump = Some(crate::spool::Spool::new()?);
                            dump.as_mut().expect("just created")
                        }
                    };
                    sink.absorb(&mut reader)?;
                }
                merged = Some(match merged {
                    None => one,
                    Some(acc) => merge(acc, one),
                });
            }
            let mut out = merged.expect("at least two targets");
            finish_aggregate(&mut out.report);
            out.spool = match dump {
                Some(s) => Some(s.finish()?),
                None => None,
            };
            Ok(out)
        }
    }
}

/// Fold one target's report into the accumulated one.
fn merge(mut acc: ScanOutput, next: ScanOutput) -> ScanOutput {
    let a = &mut acc.report;
    let b = next.report;

    a.hits.extend(b.hits);
    a.coverage.entries.extend(b.coverage.entries);
    a.coverage.carved.extend(b.coverage.carved);
    a.coverage.members_scanned += b.coverage.members_scanned;
    a.coverage.total_unpacked_bytes += b.coverage.total_unpacked_bytes;
    a.coverage.carve_ran |= b.coverage.carve_ran;
    a.strings_total += b.strings_total;
    a.excluded_total += b.excluded_total;
    a.file_size += b.file_size;

    // Warnings are prefixed with the target they came from, so a warning in a four-hundred-file
    // run is attributable. The per-target copy on `TargetInfo` stays unprefixed.
    for t in &b.targets {
        for w in &t.warnings {
            let tagged = format!("{}: {}", t.label, w);
            if !a.warnings.contains(&tagged) {
                a.warnings.push(tagged);
            }
        }
    }
    a.targets.extend(b.targets);
    // `b.warnings` is already covered by the per-target copies above for anything the scan
    // produced, but a warning added after assembly would be missed, so fold the remainder too.
    for w in b.warnings {
        if !a.warnings.contains(&w) && !a.warnings.iter().any(|existing| existing.ends_with(&w)) {
            a.warnings.push(w);
        }
    }

    merge_summary(&mut a.summary, b.summary);
    merge_counted(&mut a.excluded_by_rule, b.excluded_by_rule);
    merge_counted(&mut a.excluded_top, b.excluded_top);
    merge_iocs(&mut a.iocs, b.iocs);

    let mut components = std::mem::take(&mut a.intel.components);
    components.extend(b.intel.components);
    components.sort_by(|x, y| x.name.cmp(&y.name).then(x.version.cmp(&y.version)));
    components.dedup_by(|x, y| x.name == y.name && x.version == y.version);
    a.intel.components = components;

    a.banned_hit_count = a.summary.iter().map(|s| s.occurrences).sum();
    // Spools are accumulated by the caller into one for the whole run, so there is none to
    // merge here and none to lose.
    acc
}

/// Sum per-function rows across targets, keeping the worst severity seen for each.
fn merge_summary(acc: &mut Vec<MatchSummary>, next: Vec<MatchSummary>) {
    for row in next {
        match acc.iter_mut().find(|r| r.function == row.function) {
            Some(existing) => {
                existing.occurrences += row.occurrences;
                existing.members += row.members;
                existing.excluded += row.excluded;
                // Ord on Severity reads worst-first, so the lesser value is the worse one.
                if row.severity < existing.severity {
                    existing.severity = row.severity;
                }
            }
            None => acc.push(row),
        }
    }
}

/// Sum `(name, count)` pairs across targets.
fn merge_counted(acc: &mut Vec<(String, usize)>, next: Vec<(String, usize)>) {
    for (name, n) in next {
        match acc.iter_mut().find(|(k, _)| *k == name) {
            Some(slot) => slot.1 += n,
            None => acc.push((name, n)),
        }
    }
}

fn merge_iocs(acc: &mut crate::pe::Iocs, next: crate::pe::Iocs) {
    fn fold(a: &mut Vec<String>, b: Vec<String>) {
        a.extend(b);
        a.sort();
        a.dedup();
    }
    fold(&mut acc.urls, next.urls);
    fold(&mut acc.ips, next.ips);
    fold(&mut acc.emails, next.emails);
    fold(&mut acc.registry_keys, next.registry_keys);
    fold(&mut acc.file_paths, next.file_paths);
}

/// Restate the aggregate fields that only make sense once every target has been folded in.
fn finish_aggregate(r: &mut Report) {
    let n = r.targets.len();
    // `binary` named one file. With several it names the set, listing the first few so the
    // header still says something useful.
    let shown: Vec<&str> = r.targets.iter().take(3).map(|t| t.label.as_str()).collect();
    r.binary = if n > shown.len() {
        format!(
            "{} targets: {}, and {} more",
            n,
            shown.join(", "),
            n - shown.len()
        )
    } else {
        format!("{} targets: {}", n, shown.join(", "))
    };

    // A digest over a set of files is a manifest digest, not a file digest: the newline-joined
    // "<sha256>  <label>" lines in target order, which is exactly what `sha256sum` produces and
    // so is reproducible and checkable by hand. md5 and sha1 are cleared rather than filled with
    // something that looks like a file hash and is not.
    let manifest: String = r
        .targets
        .iter()
        .map(|t| format!("{}  {}\n", t.sha256, t.label))
        .collect();
    r.sha256 = hashing::digests(manifest.as_bytes()).sha256;
    r.md5 = String::new();
    r.sha1 = String::new();

    // One shared format, or "mixed".
    let first = r.targets.first().map(|t| t.root_format.clone());
    r.coverage.root_format = match first {
        Some(f) if r.targets.iter().all(|t| t.root_format == f) => f,
        _ => "mixed".to_string(),
    };

    r.summary.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then(b.occurrences.cmp(&a.occurrences))
            .then(a.function.cmp(&b.function))
    });
    r.posture = crate::pe::posture::findings(
        &r.coverage
            .entries
            .iter()
            .filter(|e| e.pe.is_some())
            .collect::<Vec<_>>(),
    );
}
