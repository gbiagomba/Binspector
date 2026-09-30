//! Table formatting for the browser, reusing the report crate's number helpers so the
//! browser and the text report agree on how a count or a size is written.

use crate::model::Report;
use crate::pe::mitigations::State;
use crate::report::{human_bytes, thousands};
use crate::scan::banned::Severity;

/// Left-aligned columns sized to their content, which keeps a 441-row matrix readable.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return "  (nothing to show)".to_string();
    }
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }
    let mut out = String::new();
    out.push_str("  ");
    for (i, h) in headers.iter().enumerate() {
        out.push_str(&format!("{:<w$}  ", h, w = widths[i]));
    }
    out.push('\n');
    out.push_str("  ");
    for w in &widths {
        out.push_str(&"-".repeat(*w));
        out.push_str("  ");
    }
    out.push('\n');
    for row in rows {
        out.push_str("  ");
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                out.push_str(&format!("{:<w$}  ", cell, w = widths[i]));
            }
        }
        out.push('\n');
    }
    out
}

/// The last element of a provenance chain, which is the file name.
pub fn short(member: &str) -> &str {
    member.rsplit(" :: ").next().unwrap_or(member)
}

pub fn summary(r: &Report) -> String {
    let (crit, high, med) = r.severity_counts();
    let mut s = format!(
        "  {} distinct functions, {} occurrences (critical {}, high {}, medium {})\n",
        thousands(r.summary.len() as u64),
        thousands(r.banned_hit_count as u64),
        thousands(crit as u64),
        thousands(high as u64),
        thousands(med as u64)
    );
    if r.low_confidence_total > 0 && !r.include_low_confidence {
        s.push_str(&format!(
            "  {} suppressed as low confidence (namespace or documentation text)\n",
            thousands(r.low_confidence_total as u64)
        ));
    }
    s.push('\n');
    let rows: Vec<Vec<String>> = r
        .summary
        .iter()
        .map(|m| {
            vec![
                m.function.clone(),
                m.severity.as_str().to_string(),
                m.category.as_str().to_string(),
                thousands(m.occurrences as u64),
                m.members.to_string(),
            ]
        })
        .collect();
    s.push_str(&table(
        &["function", "severity", "category", "count", "members"],
        &rows,
    ));
    s
}

pub fn coverage(r: &Report) -> String {
    let c = &r.coverage;
    let pe = r.pe_members().len();
    format!(
        "  container {}, {} members, {} unpacked, {} strings, {} PE image(s)\n  \
         import-backed occurrences: {}\n",
        c.root_format,
        thousands(c.members_scanned as u64),
        human_bytes(c.total_unpacked_bytes),
        thousands(r.strings_total as u64),
        thousands(pe as u64),
        thousands(r.definitive_hits() as u64)
    )
}

/// The mitigation matrix. This is the view `jq` handles worst and the reason the browser
/// exists.
pub fn mitigations(r: &Report, missing: Option<&str>) -> String {
    let mut rows = Vec::new();
    for e in r.pe_members() {
        let a = e.pe.as_ref().expect("filtered to PE members");
        let m = &a.mitigations;
        let off = |s: State| s == State::Disabled;
        let keep = match missing {
            None => true,
            Some("aslr") => off(m.aslr),
            Some("dep") => off(m.dep),
            Some("cfg") => off(m.cfg),
            Some("authenticode") => off(m.authenticode),
            Some("seh") => off(m.seh),
            // Not a header flag like the others: the verdict comes from the image's loader
            // imports and its strings, so it is carried on the loader surface rather than
            // duplicated into Mitigations.
            Some("dll-search") => a.loader.verdict.is_weak(),
            Some("any") => !m.weaknesses().is_empty() || a.loader.verdict.is_weak(),
            Some(_) => true,
        };
        if !keep {
            continue;
        }
        rows.push(vec![
            short(&e.member).to_string(),
            m.aslr.as_str().to_string(),
            m.dep.as_str().to_string(),
            m.cfg.as_str().to_string(),
            m.seh.as_str().to_string(),
            m.authenticode.as_str().to_string(),
            a.loader.verdict.as_str().to_string(),
            if a.is_managed { "managed" } else { "native" }.to_string(),
        ]);
    }
    let header = match missing {
        // `dll-search` is a verdict rather than an on/off flag, so "disabled" would be wrong.
        Some("dll-search") => format!("  PE images loading modules unsafely: {}\n\n", rows.len()),
        Some(k) => format!("  PE images with {} disabled: {}\n\n", k, rows.len()),
        None => format!("  {} PE image(s)\n\n", rows.len()),
    };
    header
        + &table(
            &[
                "image",
                "aslr",
                "dep",
                "cfg",
                "seh",
                "authenticode",
                "dll-search",
                "kind",
            ],
            &rows,
        )
}

pub fn hits(
    r: &Report,
    function: Option<&str>,
    severity: Option<&str>,
    confidence: Option<&str>,
) -> String {
    let rows: Vec<Vec<String>> = r
        .hits
        .iter()
        .filter(|h| function.is_none_or(|f| h.function.eq_ignore_ascii_case(f)))
        .filter(|h| severity.is_none_or(|s| h.severity.as_str() == s))
        .filter(|h| confidence.is_none_or(|c| h.confidence.as_str() == c))
        .map(|h| {
            vec![
                h.function.clone(),
                h.severity.as_str().to_string(),
                h.confidence.as_str().to_string(),
                format!("0x{:x}", h.offset),
                short(&h.member).to_string(),
            ]
        })
        .collect();
    format!("  {} occurrence(s)\n\n", rows.len())
        + &table(
            &["function", "severity", "confidence", "offset", "image"],
            &rows,
        )
}

pub fn member(r: &Report, pattern: &str) -> String {
    let needle = pattern.to_ascii_lowercase();
    let mut out = String::new();
    let mut found = 0;
    for e in &r.coverage.entries {
        if !e.member.to_ascii_lowercase().contains(&needle) {
            continue;
        }
        found += 1;
        if found > 20 {
            out.push_str("  ... more matches, narrow the pattern\n");
            break;
        }
        out.push_str(&format!(
            "  {}\n    format {}, {} , {} strings\n",
            e.member,
            e.format,
            human_bytes(e.size),
            thousands(e.strings as u64)
        ));
        if let Some(a) = &e.pe {
            out.push_str(&format!(
                "    {} {}, {} imports, {} exports, {} section(s), {} TLS callback(s)\n",
                a.machine,
                if a.is_managed { "managed" } else { "native" },
                thousands(a.imports.len() as u64),
                thousands(a.export_count as u64),
                a.sections.len(),
                a.tls_callbacks
            ));
            let w = a.mitigations.weaknesses();
            if w.is_empty() {
                out.push_str("    mitigations: all present\n");
            } else {
                for note in w {
                    out.push_str(&format!("    !! {}\n", note));
                }
            }
            for hint in &a.packer_hints {
                out.push_str(&format!("    !! {}\n", hint));
            }
        }
        let related: Vec<&str> = r
            .hits
            .iter()
            .filter(|h| h.member == e.member)
            .map(|h| h.function.as_str())
            .collect();
        if !related.is_empty() {
            out.push_str(&format!("    findings: {}\n", related.join(", ")));
        }
        out.push('\n');
    }
    if found == 0 {
        return format!("  no member matching {:?}\n", pattern);
    }
    out
}

pub fn severity_of(s: &str) -> Option<Severity> {
    match s {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests_support::sample_report;

    #[test]
    fn table_sizes_columns_to_content() {
        let t = table(&["a", "bb"], &[vec!["xxxx".into(), "y".into()]]);
        assert!(t.contains("xxxx"));
        // The header pads out to the widest cell.
        assert!(t.lines().next().unwrap().contains("a   "));
    }

    #[test]
    fn empty_table_says_so_rather_than_printing_headers() {
        assert_eq!(table(&["a"], &[]), "  (nothing to show)");
    }

    #[test]
    fn short_takes_the_last_chain_element() {
        assert_eq!(short("bundle :: app.msix :: App.exe"), "App.exe");
        assert_eq!(short("plain.exe"), "plain.exe");
    }

    #[test]
    fn summary_reports_counts_and_suppression() {
        let s = summary(&sample_report());
        assert!(s.contains("1 distinct functions"));
        assert!(s.contains("strcpy"));
        assert!(s.contains("24,227 suppressed"), "got: {}", s);
    }

    #[test]
    fn hits_filter_by_each_dimension() {
        let r = sample_report();
        assert!(hits(&r, Some("strcpy"), None, None).contains("1 occurrence"));
        assert!(hits(&r, Some("nosuch"), None, None).contains("0 occurrence"));
        assert!(hits(&r, None, Some("critical"), None).contains("1 occurrence"));
        assert!(hits(&r, None, Some("medium"), None).contains("0 occurrence"));
        assert!(hits(&r, None, None, Some("exact")).contains("1 occurrence"));
        assert!(hits(&r, None, None, Some("prose")).contains("0 occurrence"));
    }

    #[test]
    fn member_lookup_is_a_substring_match_and_reports_findings() {
        let r = sample_report();
        let out = member(&r, "app.exe");
        assert!(out.contains("App.exe"));
        assert!(out.contains("findings: strcpy"), "got: {}", out);
        assert!(member(&r, "zzz").contains("no member matching"));
    }

    #[test]
    fn coverage_names_the_import_backed_total() {
        let c = coverage(&sample_report());
        assert!(c.contains("container zip"));
        assert!(c.contains("import-backed"));
    }

    #[test]
    fn severity_of_parses_known_levels_only() {
        assert_eq!(severity_of("critical"), Some(Severity::Critical));
        assert_eq!(severity_of("nonsense"), None);
    }
}
