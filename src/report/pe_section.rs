//! Shared rendering of the PE analysis block, used by the text and markdown reports.

use anyhow::Result;
use std::io::Write;

use super::thousands;
use crate::model::Report;
use crate::pe::loader::Verdict;
use crate::pe::mitigations::State;

/// Write the PE analysis summary. Silent when no member parsed as a PE.
pub fn write_text(w: &mut dyn Write, r: &Report) -> Result<()> {
    let pes = r.pe_members();
    if pes.is_empty() {
        return Ok(());
    }

    writeln!(
        w,
        "Executable analysis ({} PE images)",
        thousands(pes.len() as u64)
    )?;

    // Mitigation posture across the whole bundle: the aggregate is what a reviewer
    // acts on, since one unhardened DLL undermines the process it loads into.
    // Label paired with its accessor, rather than a label matched to a field: the previous
    // form had a `_` arm that fell through to Authenticode, so adding a label without adding
    // a match arm would have silently reported one mitigation's state under another's name.
    type Pick = fn(&crate::pe::Mitigations) -> State;
    let checks: [(&str, Pick); 6] = [
        ("ASLR", |m| m.aslr),
        ("DEP", |m| m.dep),
        ("CFG", |m| m.cfg),
        ("/GS", |m| m.gs),
        ("SafeSEH", |m| m.safe_seh),
        ("Authenticode", |m| m.authenticode),
    ];
    let mut off: Vec<(&str, Vec<&str>)> = Vec::new();
    for (label, pick) in checks {
        let mut missing: Vec<&str> = Vec::new();
        for e in &pes {
            let a = e.pe.as_ref().expect("filtered");
            // Unknown is never reported as missing: a managed assembly has no load config,
            // and calling that "/GS off" would be a false claim.
            if pick(&a.mitigations) == State::Disabled {
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
            "  Mitigations: ASLR, DEP, CFG, /GS, SafeSEH, and Authenticode present or not \
             determinable on every image"
        )?;
    } else {
        for (label, missing) in &off {
            writeln!(
                w,
                "  !! {} missing on {} of {} image(s): {}",
                label,
                missing.len(),
                pes.len(),
                preview(missing, 6)
            )?;
        }
    }

    let managed = pes
        .iter()
        .filter(|e| e.pe.as_ref().unwrap().is_managed)
        .count();
    if managed > 0 {
        writeln!(
            w,
            "  {} managed .NET assembl{} (their embedded text is metadata, not native code)",
            managed,
            if managed == 1 { "y" } else { "ies" }
        )?;
    }

    // Packer and section anomalies, with the member that produced each.
    let mut anomalies = 0usize;
    for e in &pes {
        let a = e.pe.as_ref().expect("filtered");
        for hint in &a.packer_hints {
            if anomalies < 20 {
                writeln!(w, "  !! {}: {}", short_name(&e.member), hint)?;
            }
            anomalies += 1;
        }
        if a.tls_callbacks > 0 {
            if anomalies < 20 {
                writeln!(
                    w,
                    "  !! {}: {} TLS callback(s) run before the entry point",
                    short_name(&e.member),
                    a.tls_callbacks
                )?;
            }
            anomalies += 1;
        }
    }
    if anomalies > 20 {
        writeln!(w, "  ... and {} more anomalies", anomalies - 20)?;
    }
    if anomalies == 0 {
        writeln!(w, "  No packer or section anomalies detected")?;
    }

    // String hygiene, which the banned-function list alone reports upside down: an image can
    // import 23 hardened variants beside 5 unsafe ones, and naming only the five misleads.
    let hardened: usize = pes
        .iter()
        .filter(|e| !e.pe.as_ref().unwrap().safe_variants.is_empty())
        .count();
    if hardened > 0 {
        let total: usize = pes
            .iter()
            .map(|e| e.pe.as_ref().unwrap().safe_variants.len())
            .sum();
        writeln!(
            w,
            "  String hygiene: {} hardened CRT import(s) across {} of {} image(s)",
            thousands(total as u64),
            hardened,
            pes.len()
        )?;
    }

    let total_imports: usize = pes
        .iter()
        .map(|e| e.pe.as_ref().unwrap().imports.len())
        .sum();
    writeln!(w, "  Imports parsed: {}", thousands(total_imports as u64))?;
    if r.definitive_hits() > 0 {
        writeln!(
            w,
            "  {} occurrence(s) confirmed by the import table rather than inferred from text",
            thousands(r.definitive_hits() as u64)
        )?;
    }
    writeln!(w)?;

    if !r.iocs.is_empty() {
        writeln!(w, "Indicators ({} total)", thousands(r.iocs.total() as u64))?;
        emit_list(w, "URLs", &r.iocs.urls)?;
        emit_list(w, "IPs", &r.iocs.ips)?;
        emit_list(w, "Emails", &r.iocs.emails)?;
        emit_list(w, "Registry keys", &r.iocs.registry_keys)?;
        emit_list(w, "File paths", &r.iocs.file_paths)?;
        writeln!(w)?;
    }
    Ok(())
}

/// Everything about DLL search order, in one place.
///
/// Deliberately one section rather than facts spread across the executable analysis, the
/// findings list, and the mitigation matrix. Search-order hijacking is a single question, so
/// a reviewer should be able to answer it without cross-referencing three places: the calls
/// that are defects on sight, the images that load modules at runtime, and the evidence for
/// each are all here.
///
/// The `LoadLibrary` family is reported as a surface, not as findings, because
/// `LoadLibrary` with a fully qualified path is correct code and an import table does not
/// record the argument. What is stated is knowable; the conclusion is left to a reviewer.
pub fn write_dll_search_text(w: &mut dyn Write, r: &Report) -> Result<()> {
    let pes = r.pe_members();
    let loaders: Vec<_> = pes
        .iter()
        .filter(|e| e.pe.as_ref().is_some_and(|a| a.loader.loads_dynamically()))
        .collect();

    // Calls that are defects on sight, which live in the findings list as well.
    let mut finding_counts: Vec<(&str, usize)> = Vec::new();
    for cat in ["dll-hijacking", "process-creation"] {
        let n = r.hits.iter().filter(|h| h.category.as_str() == cat).count();
        if n > 0 {
            finding_counts.push((cat, n));
        }
    }

    if loaders.is_empty() && finding_counts.is_empty() {
        return Ok(());
    }

    writeln!(w, "DLL search order")?;

    for (cat, n) in &finding_counts {
        writeln!(
            w,
            "  {} occurrence(s) in category {}, listed with the other findings",
            thousands(*n as u64),
            cat
        )?;
    }

    if loaders.is_empty() {
        writeln!(w)?;
        return Ok(());
    }

    let mut hardened = 0usize;
    let mut unhardened = 0usize;
    // The pairing worth acting on: an image that names modules without a path *and* carries
    // no signature. Anyone who can write to the application directory gets code execution,
    // and nothing checks the file they dropped.
    let mut priority: Vec<&&&crate::model::CoverageEntry> = Vec::new();
    let mut unqualified: Vec<&&&crate::model::CoverageEntry> = Vec::new();
    for e in &loaders {
        let a = e.pe.as_ref().expect("filtered");
        match a.loader.verdict {
            Verdict::Hardened => hardened += 1,
            Verdict::Unqualified => {
                if a.mitigations.authenticode == State::Disabled {
                    priority.push(e);
                } else {
                    unqualified.push(e);
                }
            }
            _ => unhardened += 1,
        }
    }

    writeln!(
        w,
        "  {} of {} image(s) load modules at runtime: {} hardened, {} unhardened, {} naming \
         a module with no path",
        loaders.len(),
        pes.len(),
        hardened,
        unhardened,
        priority.len() + unqualified.len()
    )?;
    if hardened == 0 && !loaders.is_empty() {
        writeln!(
            w,
            "  !! no image restricts its own search path: none import SetDefaultDllDirectories \
             or AddDllDirectory"
        )?;
    }

    if !priority.is_empty() {
        writeln!(
            w,
            "  Unsigned and naming a module with no path ({}), review these first:",
            priority.len()
        )?;
        emit_loader_rows(w, &priority, 12)?;
    }
    if !unqualified.is_empty() {
        writeln!(
            w,
            "  Signed, naming a module with no path ({}):",
            unqualified.len()
        )?;
        emit_loader_rows(w, &unqualified, 8)?;
    }

    writeln!(
        w,
        "  A surface, not a defect: the module argument is not recoverable without \
         disassembly. Seek to the offsets above to confirm, and note that names already \
         resolved from the import table, the api-ms-win-* API sets, and self-references are \
         excluded."
    )?;
    writeln!(w)?;
    Ok(())
}

fn emit_loader_rows(
    w: &mut dyn Write,
    rows: &[&&&crate::model::CoverageEntry],
    max: usize,
) -> Result<()> {
    for e in rows.iter().take(max) {
        let a = e.pe.as_ref().expect("filtered");
        let names: Vec<String> = a
            .loader
            .unqualified_modules
            .iter()
            .take(4)
            .map(|m| format!("{} @ 0x{:x}", m.name, m.offset))
            .collect();
        writeln!(
            w,
            "    !! {}: {} plain LoadLibrary, {} LoadLibraryEx, names {}",
            short_name(&e.member),
            a.loader.load_library,
            a.loader.load_library_ex,
            names.join(", ")
        )?;
    }
    if rows.len() > max {
        writeln!(w, "    ... and {} more", rows.len() - max)?;
    }
    Ok(())
}

fn emit_list(w: &mut dyn Write, label: &str, items: &[String]) -> Result<()> {
    if items.is_empty() {
        return Ok(());
    }
    writeln!(w, "  {} ({})", label, items.len())?;
    for i in items.iter().take(15) {
        writeln!(w, "    {}", i)?;
    }
    if items.len() > 15 {
        writeln!(w, "    ... and {} more", items.len() - 15)?;
    }
    Ok(())
}

/// Last element of a provenance chain, which is the file name.
pub fn short_name(member: &str) -> &str {
    member.rsplit(" :: ").next().unwrap_or(member)
}

fn preview(items: &[&str], max: usize) -> String {
    if items.len() <= max {
        return items.join(", ");
    }
    format!(
        "{}, and {} more",
        items[..max].join(", "),
        items.len() - max
    )
}

/// Size of the largest PE, used by the markdown report's header line.
pub fn largest_pe(r: &Report) -> Option<(&str, u64)> {
    r.pe_members()
        .iter()
        .map(|e| (short_name(&e.member), e.size))
        .max_by_key(|(_, s)| *s)
}

/// Embedded signatures found by carving.
pub fn write_carve_text(w: &mut dyn Write, r: &Report) -> Result<()> {
    if !r.coverage.carve_ran {
        return Ok(());
    }
    let total = r.carved_total();
    let containers: usize = r
        .coverage
        .carved
        .iter()
        .flat_map(|c| c.items.iter())
        .filter(|i| i.class == crate::container::carve::Class::Container)
        .count();
    let markers: usize = r.coverage.carved.iter().map(|c| c.metadata_markers).sum();
    writeln!(
        w,
        "Carving ({} candidate embedded archive(s) or filesystem(s), {} other signature(s))",
        thousands(containers as u64),
        thousands(total.saturating_sub(containers) as u64)
    )?;
    if markers > 0 {
        writeln!(
            w,
            "  {} checksum, certificate, and text marker(s) excluded as not being embedded files.",
            thousands(markers as u64)
        )?;
    }
    if total == 0 {
        writeln!(w, "  No embedded file signatures found past offset 0.")?;
        writeln!(w)?;
        return Ok(());
    }
    if containers > 0 {
        writeln!(
            w,
            "  A signature match is a lead, not proof. Extract with `binwalk -e` to confirm."
        )?;
    }
    for c in r.coverage.carved.iter().take(40) {
        writeln!(w, "  {}", short_name(&c.member))?;
        for i in c.items.iter().take(10) {
            writeln!(
                w,
                "    [{}] {} at offset 0x{:x} ({} bytes){}  {}",
                match i.class {
                    crate::container::carve::Class::Container => "archive",
                    crate::container::carve::Class::Embedded => "embedded",
                    crate::container::carve::Class::Other => "other",
                },
                i.signature,
                i.offset,
                i.size,
                if i.confident { "" } else { " [low confidence]" },
                i.description
            )?;
        }
        if c.speculative > 0 {
            writeln!(
                w,
                "    plus {} speculative match(es) not listed",
                c.speculative
            )?;
        }
    }
    if r.coverage.carved.len() > 40 {
        writeln!(
            w,
            "  ... and {} more member(s)",
            r.coverage.carved.len() - 40
        )?;
    }
    writeln!(w)?;
    Ok(())
}

/// Reputation and CVE enrichment, when present.
pub fn write_intel_text(w: &mut dyn Write, r: &Report) -> Result<()> {
    if r.intel.is_empty() {
        return Ok(());
    }

    if !r.intel.components.is_empty() {
        writeln!(
            w,
            "Third-party components ({})",
            thousands(r.intel.components.len() as u64)
        )?;
        for c in r.intel.components.iter().take(30) {
            writeln!(w, "  {} {}", c.name, c.version)?;
        }
        if r.intel.components.len() > 30 {
            writeln!(w, "  ... and {} more", r.intel.components.len() - 30)?;
        }
        writeln!(w)?;
    }

    if let Some(rep) = &r.intel.reputation {
        writeln!(
            w,
            "Reputation (hash lookup only, no file content transmitted)"
        )?;
        writeln!(w, "  SHA256:       {}", rep.sha256)?;
        writeln!(w, "  VirusTotal:   {}", rep.virustotal.summary())?;
        writeln!(w, "  MetaDefender: {}", rep.metadefender.summary())?;
        if rep.virustotal.is_actionable() || rep.metadefender.is_actionable() {
            writeln!(w, "  !!! At least one service flagged this hash.")?;
        }
        writeln!(w)?;
    }

    if let Some(cves) = &r.intel.cves {
        writeln!(
            w,
            "Known CVEs ({} across {} component(s))",
            thousands(cves.total_cves() as u64),
            cves.components.len()
        )?;
        if let Some(worst) = cves.worst_cvss() {
            writeln!(w, "  Highest CVSS: {:.1}", worst)?;
        }
        for c in &cves.components {
            if let Some(err) = &c.error {
                writeln!(
                    w,
                    "  {} {}: lookup failed: {}",
                    c.component.name, c.component.version, err
                )?;
                continue;
            }
            if c.cves.is_empty() {
                continue;
            }
            writeln!(w, "  {} {}", c.component.name, c.component.version)?;
            for v in c.cves.iter().take(10) {
                let score = match v.cvss {
                    Some(s) => format!("{:.1}", s),
                    None => "n/a".to_string(),
                };
                writeln!(w, "    {} CVSS {} ({})  {}", v.id, score, v.severity, v.url)?;
            }
        }
        writeln!(w, "  {}", cves.coverage_note)?;
        writeln!(w)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests_support::sample_report;

    #[test]
    fn silent_when_no_pe_member_present() {
        let mut buf = Vec::new();
        write_text(&mut buf, &sample_report()).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn short_name_takes_the_last_chain_element() {
        assert_eq!(short_name("bundle :: app.msix :: App.exe"), "App.exe");
        assert_eq!(short_name("plain.exe"), "plain.exe");
    }

    #[test]
    fn preview_truncates_long_lists() {
        let items = vec!["a", "b", "c", "d"];
        assert_eq!(preview(&items, 10), "a, b, c, d");
        assert_eq!(preview(&items, 2), "a, b, and 2 more");
    }
}
