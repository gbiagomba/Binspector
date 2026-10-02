//! Carving results and the network-enrichment sections: components, reputation and CVEs.
//!
//! Split out of `pe_section` at the 1,000-line soft limit. These share a property the rest of that
//! module does not: every one of them is conditional on something the caller opted into, so each
//! has to distinguish "nothing was found" from "this did not run".

use anyhow::Result;
use std::io::Write;

use super::fmt_util::short_name;
use super::thousands;
use crate::model::Report;

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

    if !r.intel.reputation.is_empty() {
        writeln!(
            w,
            "Reputation ({} hash lookup(s), no file content transmitted)",
            thousands(r.intel.reputation.len() as u64)
        )?;
        // One block per target, each naming the file it is about. A single unlabelled block was
        // unreadable once a scan covered ten targets, and before 6.0.0 it was worse than
        // unreadable: the digest it reported was a manifest digest no service could know.
        for rep in &r.intel.reputation {
            writeln!(w, "  {}", super::fmt_util::short_name(&rep.label))?;
            writeln!(w, "    SHA256:       {}", rep.sha256)?;
            writeln!(w, "    VirusTotal:   {}", rep.virustotal.summary())?;
            writeln!(w, "    MetaDefender: {}", rep.metadefender.summary())?;
            if rep.virustotal.is_actionable() || rep.metadefender.is_actionable() {
                writeln!(w, "    !!! At least one service flagged this hash.")?;
            }
        }
        writeln!(w)?;
    }

    if let Some(sw) = &r.intel.sweep {
        if !sw.is_empty() {
            writeln!(
                w,
                "Member reputation ({} of {} distinct hash(es) answered, hash only)",
                thousands((sw.queried + sw.from_cache) as u64),
                thousands(sw.candidates as u64)
            )?;
            writeln!(
                w,
                "  {} asked of a service, {} from the local cache",
                thousands(sw.queried as u64),
                thousands(sw.from_cache as u64)
            )?;
            // The flagged ones first and loudest, because they are the only rows anybody acts on.
            let flagged: Vec<&crate::intel::Reputation> = sw
                .results
                .iter()
                .filter(|x| x.virustotal.is_actionable() || x.metadefender.is_actionable())
                .collect();
            for f in flagged.iter().take(20) {
                writeln!(w, "  !!! {}", super::fmt_util::short_name(&f.label))?;
                writeln!(w, "      {}", f.sha256)?;
                writeln!(w, "      VirusTotal:   {}", f.virustotal.summary())?;
                writeln!(w, "      MetaDefender: {}", f.metadefender.summary())?;
            }
            if flagged.len() > 20 {
                writeln!(
                    w,
                    "  ... and {} more flagged member(s)",
                    thousands((flagged.len() - 20) as u64)
                )?;
            }
            if flagged.is_empty() {
                writeln!(
                    w,
                    "  No member was flagged by a service. A hash nobody has submitted comes back \
                     unknown, which is not the same as clean."
                )?;
            }
            // The whole reason this section states a denominator. An unchecked member must never be
            // mistaken for one that came back clean.
            if sw.unchecked > 0 {
                writeln!(
                    w,
                    "  !! {} distinct hash(es) went unchecked because the request budget ran out. \
                     They are not clean results; they are absent ones. Raise --request-budget, or \
                     rerun: answers already received are cached.",
                    thousands(sw.unchecked as u64)
                )?;
            }
            if let Some(note) = &sw.tier_note {
                writeln!(w, "  note: {}", note)?;
            }
            writeln!(w)?;
        }
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
