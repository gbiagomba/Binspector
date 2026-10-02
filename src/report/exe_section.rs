//! The ELF and Mach-O analysis block, the non-PE counterpart to `pe_section`.
//!
//! Separate from `pe_section` for the same reason `exe::posture` is separate from `pe::posture`:
//! the two read different header bits, and a single table with eight labels that each apply to
//! one format would print six "not determinable" rows for every image. A reviewer looking at a
//! Linux tree should not have to read past SafeSEH to find RELRO.
//!
//! Silent when nothing in the report is an ELF or a Mach-O, which is the common case for a
//! Windows bundle and the reason this is not folded into the summary.

use anyhow::Result;
use std::io::Write;

use super::fmt_util::{preview, short_name};
use super::thousands;
use crate::exe::posture::UnixMitigations;
use crate::model::Report;
use crate::pe::mitigations::State;

/// Write the ELF and Mach-O analysis summary. Silent when no member carries one.
pub fn write_text(w: &mut dyn Write, r: &Report) -> Result<()> {
    let members = r.unix_members();
    if members.is_empty() {
        return Ok(());
    }

    writeln!(
        w,
        "Native analysis ({} ELF/Mach-O image(s))",
        thousands(members.len() as u64)
    )?;

    // Label paired with its accessor, the same shape `pe_section` uses, so adding a label
    // without an accessor is a compile error rather than a mislabelled row.
    type Pick = fn(&UnixMitigations) -> State;
    let checks: [(&str, Pick); 8] = [
        ("NX (non-executable stack)", |m| m.nx),
        ("Full RELRO", |m| m.relro),
        ("PIE", |m| m.pie),
        ("Stack canary", |m| m.canary),
        ("FORTIFY_SOURCE", |m| m.fortify),
        ("Non-executable stack (Mach-O)", |m| m.exec_stack),
        ("Non-executable heap (Mach-O)", |m| m.exec_heap),
        ("Code signature", |m| m.code_signature),
    ];

    let mut off: Vec<(&str, Vec<&str>)> = Vec::new();
    for (label, pick) in checks {
        let mut missing: Vec<&str> = Vec::new();
        for e in &members {
            let m = e.unix.as_ref().expect("filtered");
            // Unknown is never reported as missing. Most of these have a reading that means
            // "the headers do not say": a static image has no RELRO to lack, and a stripped
            // one has no symbol to prove a canary either way.
            if pick(m) == State::Disabled {
                missing.push(short_name(&e.member));
            }
        }
        if !missing.is_empty() {
            off.push((label, missing));
        }
    }

    if off.is_empty() {
        writeln!(
            w,
            "  Mitigations: NX, RELRO, PIE, canary, FORTIFY, and code signing present or not \
             determinable on every image"
        )?;
    } else {
        for (label, missing) in &off {
            writeln!(
                w,
                "  !! {} missing on {} of {} image(s): {}",
                label,
                missing.len(),
                members.len(),
                preview(missing, 6)
            )?;
        }
    }

    write_import_sources(w, r, members.len())?;
    Ok(())
}

/// Which mechanism supplied each image's imports, and how many supplied none.
///
/// Reported rather than assumed because the three mechanisms differ in what they can claim. The
/// bind opcodes and the chained import table attribute a symbol to a library; the ELF symbol
/// table cannot, because ELF has a flat namespace, and the Mach-O symbol table carries the
/// ordinal in a field goblin does not expose. An image with no readable table is the case where
/// the absence of an import is **not** evidence, and a reviewer has to be able to see which
/// images those were.
fn write_import_sources(w: &mut dyn Write, r: &Report, total: usize) -> Result<()> {
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    let mut unread = 0usize;
    for e in r.unix_members() {
        if e.import_source.is_empty() {
            unread += 1;
        } else {
            *counts.entry(e.import_source.as_str()).or_insert(0) += 1;
        }
    }
    if counts.is_empty() && unread == 0 {
        return Ok(());
    }
    let listed: Vec<String> = counts
        .iter()
        .map(|(src, n)| format!("{} via {}", n, src))
        .collect();
    if !listed.is_empty() {
        writeln!(w, "  Imports read: {}", listed.join(", "))?;
    }
    if unread > 0 {
        writeln!(
            w,
            "  {} of {} image(s) had no readable import table, so for those the absence of an \
             import is not evidence",
            unread, total
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CoverageEntry;

    fn entry(member: &str, m: UnixMitigations, source: &str) -> CoverageEntry {
        CoverageEntry {
            digests: None,
            copies: 1,
            pdb: None,
            vendor: None,
            member: member.to_string(),
            format: "macho".to_string(),
            size: 4096,
            strings: 0,
            pe: None,
            imports: Vec::new(),
            import_source: source.to_string(),
            unix: Some(m),
            unix_executable: true,
        }
    }

    fn render(entries: Vec<CoverageEntry>) -> String {
        let mut r = crate::report::tests_support::sample_report();
        r.coverage.entries = entries;
        let mut buf: Vec<u8> = Vec::new();
        write_text(&mut buf, &r).expect("render");
        String::from_utf8(buf).expect("utf8")
    }

    fn hardened() -> UnixMitigations {
        UnixMitigations {
            nx: State::Enabled,
            relro: State::Enabled,
            pie: State::Enabled,
            canary: State::Enabled,
            fortify: State::Enabled,
            exec_stack: State::Enabled,
            exec_heap: State::Enabled,
            code_signature: State::Enabled,
        }
    }

    #[test]
    fn a_windows_only_report_prints_nothing_at_all() {
        assert_eq!(render(Vec::new()), "");
    }

    #[test]
    fn a_hardened_image_gets_one_reassuring_line_and_no_warnings() {
        let out = render(vec![entry("app", hardened(), "macho-chained")]);
        assert!(
            out.contains("Native analysis (1 ELF/Mach-O image(s))"),
            "{}",
            out
        );
        assert!(out.contains("present or not determinable"), "{}", out);
        assert!(!out.contains("!!"), "{}", out);
        assert!(out.contains("1 via macho-chained"), "{}", out);
    }

    #[test]
    fn unknown_is_never_printed_as_missing() {
        // The whole point of the State::Unknown tier: a static ELF has no RELRO to lack.
        let out = render(vec![entry(
            "static",
            UnixMitigations::default(),
            "elf-dynsym",
        )]);
        assert!(
            !out.contains("!!"),
            "all-unknown must warn about nothing: {}",
            out
        );
    }

    #[test]
    fn a_disabled_mitigation_is_named_with_its_count_and_denominator() {
        let mut weak = hardened();
        weak.canary = State::Disabled;
        let out = render(vec![
            entry("weak", weak, "macho-chained"),
            entry("good", hardened(), "macho-chained"),
        ]);
        assert!(
            out.contains("!! Stack canary missing on 1 of 2 image(s): weak"),
            "{}",
            out
        );
    }

    #[test]
    fn an_unreadable_import_table_is_called_out_because_absence_stops_being_evidence() {
        let out = render(vec![
            entry("stripped", hardened(), ""),
            entry("ordinary", hardened(), "elf-dynsym"),
        ]);
        assert!(out.contains("1 via elf-dynsym"), "{}", out);
        assert!(
            out.contains("1 of 2 image(s) had no readable import table"),
            "{}",
            out
        );
    }

    #[test]
    fn a_long_member_list_is_previewed_rather_than_dumped() {
        let mut weak = hardened();
        weak.pie = State::Disabled;
        let entries: Vec<CoverageEntry> = (0..10)
            .map(|i| entry(&format!("bin{}", i), weak.clone(), "elf-dynsym"))
            .collect();
        let out = render(entries);
        assert!(out.contains("and 4 more"), "{}", out);
    }
}
