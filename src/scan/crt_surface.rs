//! Bounded memory primitives, counted as a surface instead of listed as findings.
//!
//! An adversarial review of this tool's output made the case plainly: `memcpy`, `memset`, and
//! `memmove` produce one occurrence per function per member, which on the reference bundle is 81
//! of 244 occurrences, a third of the report. That is a link-graph fact, not 81 findings. Every
//! native binary that does anything calls them, and the defect in a `memcpy` is a wrong size
//! computed somewhere an import table cannot see.
//!
//! So they are rolled up: counted, given a denominator, and **omitted from the occurrence list a
//! human reads**, while remaining complete in every machine-readable format. A human report is
//! curated and a machine record is not, which is a deliberate asymmetry the documentation states
//! rather than leaves to be discovered.
//!
//! Severity is untouched. This is a presentation decision, so `banned_hit_count`,
//! `severity_counts`, and `--fail-on` all see exactly what they saw before, and no pipeline
//! changes behaviour.

use std::collections::BTreeMap;

use crate::model::Report;

/// The functions this rolls up, matching `evidence::BOUNDED_MEMORY_PRIMITIVES`.
///
/// Kept as its own list rather than imported so the roll-up cannot silently change when the
/// demotion rule's membership changes: these two serve different purposes and a function could
/// reasonably be demoted without being rolled up.
const ROLLED_UP: &[&str] = &[
    "memcpy",
    "memmove",
    "memset",
    "wmemcpy",
    "wmemmove",
    "copymemory",
    "rtlcopymemory",
    "rtlmovememory",
];

/// Whether an occurrence of this function is rolled up rather than listed.
pub fn is_rolled_up(function: &str) -> bool {
    let lower = function.to_ascii_lowercase();
    let trimmed = lower.trim_start_matches('_');
    ROLLED_UP.contains(&trimmed)
}

/// The aggregate, computed from a finished report.
#[derive(Clone, Debug, Default)]
pub struct CrtSurface {
    /// Occurrences rolled up, per function, worst count first.
    pub per_function: Vec<(String, usize)>,
    pub total: usize,
    /// Distinct members contributing at least one.
    pub members: usize,
    /// Images that import at least one hardened `_s` variant, as the counterweight: an image
    /// importing hardened variants alongside `memcpy` is a different fact from one importing
    /// neither, and reporting only the raw count inverts that signal.
    pub hardened_images: usize,
}

impl CrtSurface {
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
}

/// Summarise the rolled-up occurrences in a report.
pub fn summarise(r: &Report) -> CrtSurface {
    let mut per: BTreeMap<String, usize> = BTreeMap::new();
    let mut members: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut total = 0usize;
    for h in &r.hits {
        if !is_rolled_up(&h.function) {
            continue;
        }
        *per.entry(h.function.clone()).or_insert(0) += 1;
        members.insert(h.member.as_str());
        total += 1;
    }
    let mut per_function: Vec<(String, usize)> = per.into_iter().collect();
    per_function.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    let hardened_images = r
        .pe_members()
        .into_iter()
        .filter(|e| e.pe.as_ref().is_some_and(|a| !a.safe_variants.is_empty()))
        .count();

    CrtSurface {
        per_function,
        total,
        members: members.len(),
        hardened_images,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bounded_primitives_are_rolled_up() {
        for f in ["memcpy", "memmove", "memset", "CopyMemory", "RtlCopyMemory"] {
            assert!(is_rolled_up(f), "{} should roll up", f);
        }
        // Leading underscores are decoration, as elsewhere in the codebase.
        assert!(is_rolled_up("_memcpy"));
        assert!(is_rolled_up("MEMCPY"));
    }

    #[test]
    fn nothing_else_is_rolled_up() {
        // The unbounded writes and the read-only primitives must keep their own rows: rolling up
        // a strcpy would hide the exact finding this tool exists to report.
        for f in [
            "strcpy", "strcat", "sprintf", "gets", "strlen", "memcmp", "system",
        ] {
            assert!(!is_rolled_up(f), "{} must stay in the occurrence list", f);
        }
    }

    #[test]
    fn an_empty_report_has_an_empty_surface() {
        let r = crate::report::tests_support::sample_report();
        let s = summarise(&r);
        assert!(s.is_empty(), "the sample has no bounded-primitive hits");
    }

    #[test]
    fn occurrences_are_counted_per_function_and_per_member() {
        let mut r = crate::report::tests_support::sample_report();
        let base = r.hits[0].clone();
        r.hits.clear();
        for (f, member) in [
            ("memcpy", "a.dll"),
            ("memcpy", "b.dll"),
            ("memset", "a.dll"),
            ("strcpy", "a.dll"),
        ] {
            let mut h = base.clone();
            h.function = f.to_string();
            h.member = member.to_string();
            r.hits.push(h);
        }
        let s = summarise(&r);
        assert_eq!(s.total, 3, "strcpy is not rolled up");
        assert_eq!(s.members, 2);
        assert_eq!(s.per_function[0], ("memcpy".to_string(), 2));
        assert_eq!(s.per_function[1], ("memset".to_string(), 1));
    }
}
