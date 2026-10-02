//! Shared rendering of the PE analysis block, used by the text and markdown reports.

use anyhow::Result;
use std::io::Write;

use super::fmt_util::{preview, short_name, truncate};
use super::human_bytes;
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
    //
    // Deduplicated on the rendered line, because a package ships the same module for several
    // instruction sets and sometimes the very same file twice: in one real report
    // `Microsoft.UI.Xaml.Controls.dll: 2 TLS callback(s)` appeared three times and
    // `onnxruntime.dll` twice, and two of the architecture `.msix` members were byte-identical.
    // Repeating a line does not add evidence, and it pushed distinct anomalies past the limit.
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut anomalies = 0usize;
    let mut repeats = 0usize;
    for e in &pes {
        let a = e.pe.as_ref().expect("filtered");
        let mut lines: Vec<String> = a
            .packer_hints
            .iter()
            .map(|hint| format!("  !! {}: {}", short_name(&e.member), hint))
            .collect();
        if a.tls_callbacks > 0 {
            lines.push(format!(
                "  !! {}: {} TLS callback(s) run before the entry point",
                short_name(&e.member),
                a.tls_callbacks
            ));
        }
        for line in lines {
            if !seen.insert(line.clone()) {
                repeats += 1;
                continue;
            }
            if anomalies < 20 {
                writeln!(w, "{}", line)?;
            }
            anomalies += 1;
        }
    }
    if anomalies > 20 {
        writeln!(w, "  ... and {} more anomalies", anomalies - 20)?;
    }
    if repeats > 0 {
        writeln!(
            w,
            "  {} further anomaly line(s) were identical to one above, which is the same module \
             shipped for another instruction set rather than another finding",
            repeats
        )?;
    }
    // The number behind the sentence. `packer_hints` says a section "suggests compressed or
    // encrypted content"; the reader then wants the value and the threshold to judge it, and the
    // value reached JSON but no human format.
    // Deduplicated for the same reason as the anomalies above: `DirectML.dll `.rsrc`` at 7.99
    // appeared three times in one report, once per architecture package.
    let mut entropic: Vec<(String, f64, u64)> = Vec::new();
    let mut entropy_seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for e in &pes {
        let a = e.pe.as_ref().expect("filtered");
        for sec in &a.sections {
            if sec.is_high_entropy() && sec.raw_size > 4096 {
                let what = format!("{} `{}`", short_name(&e.member), sec.name);
                if !entropy_seen.insert(format!("{}|{:.2}|{}", what, sec.entropy, sec.raw_size)) {
                    continue;
                }
                entropic.push((what, sec.entropy, sec.raw_size as u64));
            }
        }
    }
    if !entropic.is_empty() {
        entropic.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        writeln!(
            w,
            "  Section entropy above 7.20 of 8.00 ({} section(s)); compressed, encrypted or packed",
            entropic.len()
        )?;
        for (what, value, size) in entropic.iter().take(8) {
            writeln!(
                w,
                "    {:>5.2}  {:>10}  {}",
                value,
                human_bytes(*size),
                truncate(what, 60)
            )?;
        }
        if entropic.len() > 8 {
            writeln!(w, "    ... and {} more", entropic.len() - 8)?;
        }
    }
    if anomalies == 0 {
        writeln!(w, "  No packer or section anomalies detected")?;
    }

    super::signature_section::write_origin(w, r, &pes)?;
    // Called here rather than from inside `write_origin`, which returns early when no finding is
    // attributable to a parsed PE. These two read `pes` and never touch `r.hits`, so gating them on
    // findings meant a clean scan of 441 signed images printed nothing at all about those
    // signatures, as did a scan whose occurrences all landed in non-PE members such as a package
    // manifest. The strongest output the tool has was conditional on the weakest.
    super::signature_section::write_signature_caveat(w, &pes)?;
    super::signature_section::write_chain_text(w, &pes)?;
    write_crt_surface_text(w, r)?;
    write_ipc_text(w, r)?;

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
        let d = &r.iocs.dropped;
        if d.total() > 0 {
            // Collection truncation, not display truncation: these were seen and never recorded, so
            // the counts above are a scan-order artifact rather than a total. Saying so is the same
            // obligation `excluded_by_rule` meets for suppressed findings.
            writeln!(
                w,
                "  {} further indicator(s) were seen after --ioc-cap ({}) was reached and not \
                 collected: {} URL(s), {} IP(s), {} email(s), {} registry key(s), {} path(s)",
                thousands(d.total() as u64),
                thousands(r.iocs.cap as u64),
                d.urls,
                d.ips,
                d.emails,
                d.registry_keys,
                d.file_paths
            )?;
        }
        writeln!(w)?;
    }
    write_build_provenance(w, r)?;
    write_capabilities(w, r)?;
    Ok(())
}

/// Analysis that was available and did not run.
///
/// Four of ten defects a user reported against one scan were capabilities that exist, are
/// documented in `--help`, and were simply never discovered: carving, reputation, CVE resolution,
/// and the extraction of indicators they had not realised were collected. The report said nothing
/// about any of them, so a reader had no way to tell "this bundle has no embedded archives" from
/// "nobody passed --carve".
///
/// The project already has this habit for coverage: a scan that reaches no executable image warns
/// that a clean result is not evidence. The same reasoning applies to a capability that did not run,
/// and it had never been applied.
fn write_capabilities(w: &mut dyn Write, r: &Report) -> Result<()> {
    let mut idle: Vec<&str> = Vec::new();
    if !r.coverage.carve_ran {
        idle.push("--carve           scan members for embedded archives and filesystems");
    }
    if r.intel.reputation.is_none() {
        idle.push(
            "--reputation      look the hash up with VirusTotal and MetaDefender (hash only)",
        );
    }
    if r.intel.cves.is_none() && !r.intel.components.is_empty() {
        idle.push("--cve             resolve the detected components against NVD");
    }
    if idle.is_empty() {
        return Ok(());
    }
    writeln!(w, "Analysis not run ({})", idle.len())?;
    for line in &idle {
        writeln!(w, "  {}", line)?;
    }
    writeln!(
        w,
        "  These are off by default and were not requested, so their absence from this report is \
         not a finding about the target."
    )?;
    writeln!(w)?;
    Ok(())
}

/// Paths rooted in a developer's home directory, which are three findings in one.
///
/// Reported as their own section rather than as rows in a 1,950-entry path dump, because that is
/// where this evidence went to die: an adversarial review had to recover a vendored OpenCV by
/// grepping the binaries, since the only trace of it was one build path that the indicator cap had
/// dropped in favour of a thousand near-identical compiler header paths.
fn write_build_provenance(w: &mut dyn Write, r: &Report) -> Result<()> {
    if r.iocs.build_paths.is_empty() {
        return Ok(());
    }
    writeln!(
        w,
        "Build provenance ({} developer path(s) in shipped binaries)",
        r.iocs.build_paths.len()
    )?;
    for p in r.iocs.build_paths.iter().take(12) {
        writeln!(w, "  !! {}", truncate(p, 110))?;
    }
    if r.iocs.build_paths.len() > 12 {
        writeln!(w, "  ... and {} more", r.iocs.build_paths.len() - 12)?;
    }
    writeln!(
        w,
        "  Each of these discloses a username, shows the artifact was built outside CI rather than \
         reproducibly, and names directories that frequently identify a statically linked \
         dependency absent from any manifest."
    )?;
    writeln!(
        w,
        "  fix: build in CI, and strip or remap source paths (`-fdebug-prefix-map`, `/PATHMAP`)."
    )?;
    writeln!(w)?;
    Ok(())
}

/// Named-pipe servers and whether they import any authorization primitive.
///
/// The question a reviewer actually has about a finding is whether the code is reachable from an
/// unauthenticated surface. Answering that needs a disassembler. What imports alone can say is
/// which images are pipe servers that check nobody, and that is where to look first.
///
/// Stated as narrowing, not reachability, because the difference matters: an unauthorized verdict
/// means no authorization primitive is linked, not that any particular finding is exploitable.
pub fn write_ipc_text(w: &mut dyn Write, r: &Report) -> Result<()> {
    use crate::pe::ipc::IpcVerdict;

    let servers: Vec<&crate::model::CoverageEntry> = r
        .pe_members()
        .into_iter()
        .filter(|e| e.pe.as_ref().is_some_and(|a| a.ipc.is_server()))
        .collect();
    if servers.is_empty() {
        return Ok(());
    }
    let unauthorized: Vec<&&crate::model::CoverageEntry> = servers
        .iter()
        .filter(|e| {
            e.pe.as_ref()
                .is_some_and(|a| a.ipc.verdict == IpcVerdict::ServerUnauthorized)
        })
        .collect();

    writeln!(
        w,
        "  Named-pipe servers: {} image(s), {} importing no authorization primitive",
        servers.len(),
        unauthorized.len()
    )?;
    for e in unauthorized.iter().take(10) {
        let a = e.pe.as_ref().expect("filtered");
        let serves = a.ipc.pipe_server.join(", ");
        writeln!(w, "    !! {}: serves {}", short_name(&e.member), serves)?;
        if !a.ipc.descriptor_builders.is_empty() {
            // The review's force came from "builds its own descriptor AND checks nobody", not
            // either half, so the descriptor work is named alongside rather than scored.
            writeln!(
                w,
                "       builds its own security descriptor: {}",
                a.ipc.descriptor_builders.join(", ")
            )?;
        }
        writeln!(
            w,
            "       imports none of ImpersonateNamedPipeClient, OpenThreadToken, \
             GetTokenInformation, CheckTokenMembership, AccessCheck"
        )?;
    }
    if unauthorized.len() > 10 {
        writeln!(w, "    ... and {} more", unauthorized.len() - 10)?;
    }
    // Name which primitive carried an authorized verdict, so a thin one is visible as thin.
    for e in servers.iter().take(10) {
        let a = e.pe.as_ref().expect("filtered");
        if a.ipc.verdict == IpcVerdict::Server && !a.ipc.authorization.is_empty() {
            writeln!(
                w,
                "    {}: authorized by {}",
                short_name(&e.member),
                a.ipc.authorization.join(", ")
            )?;
        }
    }
    writeln!(
        w,
        "    Narrowing, not reachability: an unauthorized verdict means no authorization \
         primitive is linked, not that a finding here is reachable. Absence is only evidence \
         where the import table was readable."
    )?;
    Ok(())
}

/// Bounded memory primitives, as a counted surface rather than a list of findings.
///
/// Mirrors `write_dll_search_text`: a denominator, the per-function breakdown, and a statement of
/// where the detail lives. The difference is that this one *replaces* rows in the occurrence list
/// rather than sitting beside them, because one occurrence per function per member is a
/// link-graph fact and on a real bundle they were a third of the report.
pub fn write_crt_surface_text(w: &mut dyn Write, r: &Report) -> Result<()> {
    let s = crate::scan::crt_surface::summarise(r);
    if s.is_empty() {
        return Ok(());
    }
    let images = r.pe_members().len();
    let breakdown = s
        .per_function
        .iter()
        .map(|(f, n)| format!("{} {}", f, n))
        .collect::<Vec<_>>()
        .join(", ");
    writeln!(
        w,
        "  Bounded memory primitives: {} import(s) across {} of {} image(s) ({})",
        thousands(s.total as u64),
        s.members,
        images,
        breakdown
    )?;
    if s.hardened_images > 0 {
        writeln!(
            w,
            "    {} of those image(s) also import hardened _s variants",
            s.hardened_images
        )?;
    }
    writeln!(
        w,
        "    A link-graph fact, not {} findings: every native image calls these, and the defect \
         would be a wrong size an import table cannot show. Omitted from the occurrence list \
         below; complete in --format json, csv, sql, sqlite, and sarif.",
        thousands(s.total as u64)
    )?;
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
/// Size of the largest PE, used by the markdown report's header line.
pub fn largest_pe(r: &Report) -> Option<(&str, u64)> {
    r.pe_members()
        .iter()
        .map(|e| (short_name(&e.member), e.size))
        .max_by_key(|(_, s)| *s)
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
