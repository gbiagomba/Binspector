//! Package-level roll-up of hardened against unbounded string primitives.
//!
//! The per-image facts come from `pe::credited::Hygiene`. This turns them into the three numbers
//! a reviewer actually argues about: how far ahead the hardened forms are, how many images are
//! part-way through, and which images are furthest behind.
//!
//! **Why a ratio and not a count.** A count of unsafe imports is what the banned-function list
//! already gives, and on its own it reads as a workload. The same 55 unbounded slots mean one
//! thing in a codebase with 650 hardened slots beside them and something else entirely in a
//! codebase with none, and an adversarial review of a real report named that inversion as the
//! single thing most likely to cost the tool credibility with the team being reviewed.
//!
//! **Slots, stated once so the number is not misread.** An import table holds one entry per
//! function per image however many times the code calls it, so these count distinct names per
//! member, not call sites. Two images importing `strcpy_s` are two slots. The same module shipped
//! for four instruction sets is four slots, which is deliberate: it is four files to fix.

use crate::model::Report;

/// How far along the migration is, across every image whose import table was read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Surface {
    pub credited_slots: usize,
    pub credited_members: usize,
    pub unbounded_slots: usize,
    pub unbounded_members: usize,
    /// Images importing both forms: a migration under way.
    pub mid_migration: usize,
    /// Images importing only hardened forms: a migration finished.
    pub fully_migrated: usize,
    /// Images importing only unbounded forms: a migration not started.
    pub not_started: usize,
    /// Distinct offender rows after collapsing architecture copies, for the "and N more" line.
    pub distinct_offenders: usize,
    /// Worst offenders, most unbounded slots first, with their credited count beside them so the
    /// row cannot be read as "this image does nothing right".
    pub worst: Vec<Worst>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Worst {
    pub member: String,
    pub unbounded: usize,
    pub credited: usize,
    /// Images with this leaf name and these counts.
    ///
    /// A package ships the same module for several instruction sets, so without collapsing them
    /// the six display rows were four copies of `mfc140u.dll` and two of `mfc140.dll`, which
    /// crowded out every other image while telling a reviewer one thing. The slot totals above
    /// still count each copy, because each copy is a file to change.
    pub copies: usize,
}

impl Surface {
    pub fn is_empty(&self) -> bool {
        self.credited_slots == 0 && self.unbounded_slots == 0
    }

    /// Hardened slots per unbounded slot.
    ///
    /// `None` when there are no unbounded slots at all, because "infinity to one" is not a
    /// useful thing to print and the caller should say "no unbounded imports" instead.
    pub fn ratio(&self) -> Option<f64> {
        if self.unbounded_slots == 0 {
            return None;
        }
        Some(self.credited_slots as f64 / self.unbounded_slots as f64)
    }
}

/// Roll the per-image hygiene up over every parsed PE in the report.
pub fn summarise(r: &Report, worst_cap: usize) -> Surface {
    let mut s = Surface::default();
    let mut rows: std::collections::BTreeMap<(String, usize, usize), usize> =
        std::collections::BTreeMap::new();

    for e in r.pe_members() {
        let Some(a) = e.pe.as_ref() else { continue };
        // An image whose import directory was never read says nothing either way, and counting
        // it as "not started" would charge a packed or resource-only image for a migration it
        // has no code to perform.
        if a.imports.is_empty() {
            continue;
        }
        let h = &a.hygiene;
        s.credited_slots += h.credited.len();
        s.unbounded_slots += h.unbounded.len();
        if !h.credited.is_empty() {
            s.credited_members += 1;
        }
        if !h.unbounded.is_empty() {
            s.unbounded_members += 1;
            let leaf = crate::report::fmt_util::short_name(&e.member).to_string();
            let key = (leaf, h.unbounded.len(), h.credited.len());
            *rows.entry(key).or_insert(0usize) += 1;
        }
        if h.mid_migration() {
            s.mid_migration += 1;
        } else if h.fully_migrated() {
            s.fully_migrated += 1;
        } else if !h.unbounded.is_empty() {
            s.not_started += 1;
        }
    }

    // Most unbounded first, then fewest credited, then by name. The second key matters: between
    // two images with six unbounded slots, the one with no hardened imports is the one to read
    // first. The third key only exists so the ordering is total and the output reproducible.
    let mut worst: Vec<Worst> = rows
        .into_iter()
        .map(|((member, unbounded, credited), copies)| Worst {
            member,
            unbounded,
            credited,
            copies,
        })
        .collect();
    worst.sort_by(|a, b| {
        b.unbounded
            .cmp(&a.unbounded)
            .then(a.credited.cmp(&b.credited))
            .then(a.member.cmp(&b.member))
    });
    s.distinct_offenders = worst.len();
    worst.truncate(worst_cap);
    s.worst = worst;
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::credited::Hygiene;
    use crate::pe::ImportRef;

    fn imports(names: &[&str]) -> Vec<ImportRef> {
        names
            .iter()
            .map(|n| ImportRef {
                library: "ucrtbase.dll".into(),
                name: (*n).to_string(),
            })
            .collect()
    }

    /// A report carrying three PE members with the given import sets.
    fn report_with(sets: &[(&str, &[&str])]) -> Report {
        let mut r = crate::report::tests_support::rich_report();
        r.coverage.entries.retain(|e| e.pe.is_none());
        for (name, names) in sets {
            let mut e = crate::report::tests_support::pe_entry(name);
            let imps = imports(names);
            let a = e.pe.as_mut().expect("fixture is a PE");
            a.hygiene = Hygiene::from_imports(&imps);
            a.imports = imps;
            r.coverage.entries.push(e);
        }
        r
    }

    #[test]
    fn the_three_migration_states_are_counted_separately() {
        let r = report_with(&[
            ("done.dll", &["strcpy_s", "wcscat_s"]),
            ("midway.dll", &["strcpy_s", "strcpy", "lstrcatW"]),
            ("untouched.dll", &["strcpy", "strcat"]),
        ]);
        let s = summarise(&r, 8);
        assert_eq!(s.fully_migrated, 1);
        assert_eq!(s.mid_migration, 1);
        assert_eq!(s.not_started, 1);
        assert_eq!(s.credited_slots, 3);
        assert_eq!(s.unbounded_slots, 4);
        assert_eq!(s.credited_members, 2);
        assert_eq!(s.unbounded_members, 2);
    }

    #[test]
    fn an_image_with_no_import_table_is_not_charged_with_a_migration() {
        // A packed or resource-only image has no code to migrate. Counting it as "not started"
        // would be the same class of error as reporting a data-only DLL for calling `system`.
        let r = report_with(&[("resource-only.dll", &[])]);
        let s = summarise(&r, 8);
        assert_eq!(s.not_started, 0);
        assert_eq!(s.fully_migrated, 0);
        assert!(s.is_empty());
    }

    #[test]
    fn the_worst_rows_carry_the_credited_count_beside_the_unbounded_one() {
        let r = report_with(&[
            (
                "mostly-good.dll",
                &["strcpy", "strcpy_s", "wcscat_s", "strtok_s"],
            ),
            ("bad.dll", &["strcpy", "strcat", "wcscpy"]),
        ]);
        let s = summarise(&r, 8);
        assert_eq!(s.worst[0].member, "bad.dll");
        assert_eq!(s.worst[0].copies, 1);
        assert_eq!(s.worst[0].unbounded, 3);
        assert_eq!(s.worst[0].credited, 0);
        // The row for the second image must show its three hardened imports, so one unbounded
        // slot is not read as a module that does nothing right.
        assert_eq!(s.worst[1].unbounded, 1);
        assert_eq!(s.worst[1].credited, 3);
    }

    #[test]
    fn between_equal_offenders_the_one_with_no_credit_sorts_first() {
        let r = report_with(&[
            ("has-some-credit.dll", &["strcpy", "strcat", "strcpy_s"]),
            ("has-none.dll", &["strcpy", "strcat"]),
        ]);
        let s = summarise(&r, 8);
        // Two unbounded each, so the credited count breaks the tie.
        assert_eq!(s.worst[0].member, "has-none.dll");
    }

    #[test]
    fn the_ratio_refuses_to_divide_by_zero() {
        let clean = report_with(&[("clean.dll", &["strcpy_s"])]);
        assert_eq!(summarise(&clean, 8).ratio(), None);
        let mixed = report_with(&[("mixed.dll", &["strcpy_s", "wcscpy_s", "strcpy"])]);
        assert_eq!(summarise(&mixed, 8).ratio(), Some(2.0));
    }

    #[test]
    fn the_same_module_shipped_for_four_architectures_is_one_row() {
        // Without collapsing, six display rows were four copies of one module and two of
        // another, which crowded out every other image while saying one thing. The slot totals
        // still count all four, because four copies are four files to change.
        // ` :: ` is the provenance-chain separator the scan builds, which is what `short_name`
        // reduces. A real package reaches this through four architecture sub-packages.
        let r = report_with(&[
            (
                "bundle :: arm64.msix :: mfc140u.dll",
                &["strcpy", "strcpy_s"],
            ),
            ("bundle :: x64.msix :: mfc140u.dll", &["strcpy", "strcpy_s"]),
            ("bundle :: x86.msix :: mfc140u.dll", &["strcpy", "strcpy_s"]),
            ("bundle :: arm.msix :: mfc140u.dll", &["strcpy", "strcpy_s"]),
        ]);
        let s = summarise(&r, 6);
        assert_eq!(s.worst.len(), 1, "{:?}", s.worst);
        assert_eq!(s.worst[0].copies, 4);
        assert_eq!(s.unbounded_members, 4);
        assert_eq!(s.unbounded_slots, 4);
    }
}
