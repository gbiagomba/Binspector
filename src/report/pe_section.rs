//! Shared rendering of the PE analysis block, used by the text and markdown reports.

use anyhow::Result;
use std::io::Write;

use super::thousands;
use crate::model::Report;
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
    let mut off: Vec<(&str, Vec<&str>)> = Vec::new();
    for label in ["ASLR", "DEP", "CFG", "Authenticode"] {
        let mut missing: Vec<&str> = Vec::new();
        for e in &pes {
            let a = e.pe.as_ref().expect("filtered");
            let s = match label {
                "ASLR" => a.mitigations.aslr,
                "DEP" => a.mitigations.dep,
                "CFG" => a.mitigations.cfg,
                _ => a.mitigations.authenticode,
            };
            if s == State::Disabled {
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
            "  Mitigations: ASLR, DEP, CFG, and Authenticode present on every image"
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
