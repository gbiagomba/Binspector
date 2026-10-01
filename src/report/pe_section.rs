//! Shared rendering of the PE analysis block, used by the text and markdown reports.

use anyhow::Result;
use std::io::Write;

use super::fmt_util::{preview, short_name, truncate};
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

    write_origin(w, r, &pes)?;
    // Called here rather than from inside `write_origin`, which returns early when no finding is
    // attributable to a parsed PE. These two read `pes` and never touch `r.hits`, so gating them on
    // findings meant a clean scan of 441 signed images printed nothing at all about those
    // signatures, as did a scan whose occurrences all landed in non-PE members such as a package
    // manifest. The strongest output the tool has was conditional on the weakest.
    write_signature_caveat(w, &pes)?;
    write_chain_text(w, &pes)?;
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

/// Who the findings belong to, so a reviewer does not spend time on code they cannot patch.
///
/// Built from the Authenticode signer, with `--first-party` overriding it. The signer is an
/// identity *claim*: nothing here verifies a chain or compares the Authenticode hash against
/// the image, so this is for deprioritising a vendor's code, never for trusting it.
fn write_origin(w: &mut dyn Write, r: &Report, pes: &[&crate::model::CoverageEntry]) -> Result<()> {
    use std::collections::BTreeMap;

    // Occurrences per origin, not images: the question is where the findings are.
    let mut per_member: BTreeMap<&str, (Option<String>, bool)> = BTreeMap::new();
    for e in pes {
        let a = e.pe.as_ref().expect("filtered");
        let signer = a.signature.as_ref().and_then(|s| s.signer.clone());
        per_member.insert(e.member.as_str(), (signer, a.first_party));
    }
    let mut first_party = 0usize;
    let mut unsigned = 0usize;
    let mut by_signer: BTreeMap<String, usize> = BTreeMap::new();
    let mut unattributed = 0usize;
    for h in &r.hits {
        match per_member.get(h.member.as_str()) {
            Some((_, true)) => first_party += 1,
            Some((Some(signer), false)) => *by_signer.entry(signer.clone()).or_insert(0) += 1,
            Some((None, false)) => unsigned += 1,
            None => unattributed += 1,
        }
    }
    if by_signer.is_empty() && first_party == 0 && unsigned == 0 {
        return Ok(());
    }
    writeln!(w, "  Findings by origin")?;
    if first_party > 0 {
        writeln!(w, "    first-party (--first-party)   {:>6}", first_party)?;
    }
    if unsigned > 0 {
        writeln!(w, "    unsigned                     {:>6}", unsigned)?;
    }
    let mut signers: Vec<(&String, &usize)> = by_signer.iter().collect();
    signers.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (signer, n) in signers.iter().take(8) {
        writeln!(w, "    signed by {:<18} {:>6}", truncate(signer, 18), n)?;
    }
    if unattributed > 0 {
        writeln!(w, "    not a parsed image           {:>6}", unattributed)?;
    }
    Ok(())
}

/// The one line a reader relies on when deciding how much a signer name is worth.
///
/// Conditional since 5.3.0, because the flat statement "no chain or hash is checked" became false.
/// It names the digest counts across the images actually scanned rather than describing the tool's
/// capabilities, so a reviewer can tell an image whose bytes were verified from one where nothing
/// could be compared.
fn write_signature_caveat(w: &mut dyn Write, pes: &[&crate::model::CoverageEntry]) -> Result<()> {
    use crate::pe::authenticode::DigestState;

    let mut verified = 0usize;
    let mut mismatch = 0usize;
    let mut unchecked = 0usize;
    for e in pes {
        let a = e.pe.as_ref().expect("filtered");
        match a.signature.as_ref().map(|s| s.digest) {
            Some(DigestState::Verified) => verified += 1,
            Some(DigestState::Mismatch) => mismatch += 1,
            Some(DigestState::Unchecked) => unchecked += 1,
            None => {}
        }
    }
    if verified + mismatch + unchecked == 0 {
        writeln!(
            w,
            "  No image carried a signature, so no identity was claimed and none was checked."
        )?;
        return Ok(());
    }
    writeln!(
        w,
        "    Authenticode digest: {} verified, {} mismatched, {} not compared.",
        verified, mismatch, unchecked
    )?;
    if mismatch > 0 {
        writeln!(
            w,
            "    !! A mismatch means the shipped bytes are not the bytes that were signed, so the \
             signer name on those images is worth nothing."
        )?;
    }
    Ok(())
}

/// What the embedded certificates were found to be, and the anchor fingerprints to compare.
///
/// The fingerprints are the actionable part. No pure-Rust code-signing root store exists, so the
/// tool cannot say "trusted"; it says which anchor each chain reaches and what that anchor hashes to,
/// and the reviewer compares that against a published thumbprint. Without the fingerprint the claim
/// would be a shrug.
fn write_chain_text(w: &mut dyn Write, pes: &[&crate::model::CoverageEntry]) -> Result<()> {
    use crate::pe::chain::ChainState;
    use std::collections::BTreeMap;

    let mut states: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut anchors: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut broken: Vec<&str> = Vec::new();
    let mut expired = 0usize;
    for e in pes {
        let a = e.pe.as_ref().expect("filtered");
        let Some(c) = a.signature.as_ref().map(|s| &s.chain) else {
            continue;
        };
        if c.state == ChainState::Unverified && c.anchor.is_none() {
            continue;
        }
        *states.entry(c.state.as_str()).or_insert(0) += 1;
        expired += c.expired;
        if c.state == ChainState::Broken {
            broken.push(short_name(&e.member));
        }
        if let Some(anchor) = c.anchor.as_ref() {
            anchors
                .entry((anchor.clone(), c.anchor_fingerprint.clone()))
                .and_modify(|n| *n += 1)
                .or_insert(1);
        }
    }
    if states.is_empty() {
        return Ok(());
    }

    let summary: Vec<String> = states.iter().map(|(k, n)| format!("{} {}", n, k)).collect();
    writeln!(w, "    Certificate chain: {}.", summary.join(", "))?;
    if !broken.is_empty() {
        writeln!(
            w,
            "    !! {} chain(s) did not verify under the issuer they name: {}",
            broken.len(),
            preview(&broken, 6)
        )?;
    }
    // `partial` is the common and correct case, so it is explained rather than left looking like a
    // shortfall: Authenticode omits the root because Windows already has it.
    if states.contains_key("partial") {
        writeln!(
            w,
            "    A partial chain means every embedded certificate verified and the root is not in \
             the file, which is how Authenticode normally ships."
        )?;
    }
    if expired > 0 {
        writeln!(
            w,
            "    {} certificate(s) are outside their validity window, which is not a defect: \
             Authenticode is not expiry-sensitive when countersigned.",
            expired
        )?;
    }
    let mut listed: Vec<((String, String), usize)> = anchors.into_iter().collect();
    listed.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    for ((anchor, fingerprint), n) in listed.iter().take(6) {
        writeln!(
            w,
            "      anchor {:<40} {:>4}  sha256:{}",
            truncate(anchor, 40),
            n,
            &fingerprint[..16.min(fingerprint.len())]
        )?;
    }
    // Still the limit that matters, and the reason the fingerprints above are printed at all.
    writeln!(
        w,
        "    Verified is not trusted: no code-signing root store is consulted, because none exists \
         in pure Rust. Compare an anchor fingerprint against its published thumbprint. Revocation \
         is never checked."
    )?;
    Ok(())
}

#[cfg(test)]
mod signature_gate_tests {
    use crate::report::tests_support::rich_report;
    use crate::report::text;

    fn render(r: &crate::model::Report) -> String {
        let mut buf: Vec<u8> = Vec::new();
        text::write(&mut buf, r, None, &crate::report::tests_support::opts()).expect("render");
        String::from_utf8(buf).expect("utf8")
    }

    /// The defect: signature facts were reported only as a tail call of the findings-by-origin
    /// block, which returns early when no occurrence is attributable to a parsed PE. So a clean
    /// scan of a bundle full of signed images said nothing about any of them.
    #[test]
    fn signatures_are_reported_even_when_there_are_no_findings() {
        let mut r = rich_report();
        r.hits.clear();
        r.summary.clear();
        r.banned_hit_count = 0;
        let out = render(&r);
        assert!(
            out.contains("Authenticode digest:"),
            "a zero-finding scan must still report digests:\n{}",
            out
        );
        assert!(
            out.contains("Certificate chain:"),
            "and chain states:\n{}",
            out
        );
    }

    /// The subtler half: findings exist, but every one lands in a member that is not a parsed PE,
    /// such as a package manifest. All three origin counters stay zero and the guard still fired.
    #[test]
    fn signatures_are_reported_when_findings_miss_every_parsed_image() {
        let mut r = rich_report();
        for h in r.hits.iter_mut() {
            h.member = "bundle :: AppxManifest.xml".to_string();
        }
        let out = render(&r);
        assert!(
            out.contains("Authenticode digest:"),
            "findings in non-PE members must not suppress signature reporting:\n{}",
            out
        );
    }

    #[test]
    fn an_unsigned_set_says_so_rather_than_going_quiet() {
        let mut r = rich_report();
        for e in r.coverage.entries.iter_mut() {
            if let Some(pe) = e.pe.as_mut() {
                pe.signature = None;
            }
        }
        let out = render(&r);
        assert!(
            out.contains("No image carried a signature"),
            "an unsigned set is a statement, not silence:\n{}",
            out
        );
    }
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
