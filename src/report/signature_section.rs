//! Findings by origin, and what the Authenticode signature and certificate chain say.
//!
//! Split out of `pe_section` when that file crossed the 1,000-line soft limit. The split is along a
//! real seam rather than an arbitrary one: `write_origin` answers "whose code is this finding in",
//! which is a question about `r.hits`, while the two signature functions answer "do the bytes match
//! what was signed" and "do the certificates form a chain", which are questions about the images.
//!
//! That difference is why they are separate functions at all. They were once tail calls of
//! `write_origin`, which returns early when no finding is attributable to a parsed PE, so a clean
//! scan of a bundle full of signed images reported nothing about any of them.

use anyhow::Result;
use std::io::Write;

use super::fmt_util::{preview, short_name, truncate};
use crate::model::Report;

/// Who the findings belong to, so a reviewer does not spend time on code they cannot patch.
///
/// Built from the Authenticode signer, with `--first-party` overriding it. The signer is an
/// identity *claim*: nothing here verifies a chain or compares the Authenticode hash against
/// the image, so this is for deprioritising a vendor's code, never for trusting it.
pub(super) fn write_origin(
    w: &mut dyn Write,
    r: &Report,
    pes: &[&crate::model::CoverageEntry],
) -> Result<()> {
    use std::collections::BTreeMap;

    // Occurrences per origin, not images: the question is where the findings are.
    //
    // Counted over `reported_hits` rather than `hits` since 5.8.0, so this section and the
    // occurrence list below it are about the same set. They were not: the bounded memory
    // primitives are rolled up into their own counted surface and omitted from the occurrence
    // list, while this block counted them, so "Findings by origin" summed to a number no other
    // part of the report showed.
    let mut per_member: BTreeMap<&str, (Option<String>, bool)> = BTreeMap::new();
    for e in pes {
        let a = e.pe.as_ref().expect("filtered");
        // The vendor key, not the raw signer. One organisation signs with many subjects:
        // `Microsoft Corporation`, `Microsoft Windows`, `.NET` and `.NET DAC` were four rows a
        // reviewer had to merge by hand on every read.
        per_member.insert(e.member.as_str(), (e.vendor.clone(), a.first_party));
    }
    let mut first_party = 0usize;
    let mut unsigned = 0usize;
    let mut by_vendor: BTreeMap<String, usize> = BTreeMap::new();
    let mut unattributed = 0usize;
    for h in r.reported_hits() {
        match per_member.get(h.member.as_str()) {
            Some((_, true)) => first_party += 1,
            Some((Some(vendor), false)) => *by_vendor.entry(vendor.clone()).or_insert(0) += 1,
            Some((None, false)) => unsigned += 1,
            None => unattributed += 1,
        }
    }
    if by_vendor.is_empty() && first_party == 0 && unsigned == 0 {
        return Ok(());
    }
    writeln!(w, "  Findings by origin")?;
    if first_party > 0 {
        writeln!(w, "    first-party (--first-party)   {:>6}", first_party)?;
    }
    if unsigned > 0 {
        writeln!(w, "    unsigned                     {:>6}", unsigned)?;
    }
    let mut vendors: Vec<(&String, &usize)> = by_vendor.iter().collect();
    vendors.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    const SHOWN: usize = 8;
    for (vendor, n) in vendors.iter().take(SHOWN) {
        writeln!(w, "    signed by {:<18} {:>6}", truncate(vendor, 18), n)?;
    }
    // Until 5.8.0 the ninth vendor and beyond were dropped with nothing said, so a reader could
    // not tell a complete list from a truncated one. Collapsing vendor subjects makes the cap
    // bite far less often, which is not the same as it never biting.
    if vendors.len() > SHOWN {
        let rest: usize = vendors.iter().skip(SHOWN).map(|(_, n)| **n).sum();
        writeln!(
            w,
            "    {} more vendor(s)        {:>6}",
            vendors.len() - SHOWN,
            rest
        )?;
    }
    if unattributed > 0 {
        writeln!(w, "    not a parsed image           {:>6}", unattributed)?;
    }
    writeln!(
        w,
        "    Who signed each file, not who wrote the code in it: a third-party library compiled \
         into a vendor-signed image is attributed to that vendor."
    )?;
    Ok(())
}

/// The one line a reader relies on when deciding how much a signer name is worth.
///
/// Conditional since 5.3.0, because the flat statement "no chain or hash is checked" became false.
/// It names the digest counts across the images actually scanned rather than describing the tool's
/// capabilities, so a reviewer can tell an image whose bytes were verified from one where nothing
/// could be compared.
pub(super) fn write_signature_caveat(
    w: &mut dyn Write,
    pes: &[&crate::model::CoverageEntry],
) -> Result<()> {
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
pub(super) fn write_chain_text(
    w: &mut dyn Write,
    pes: &[&crate::model::CoverageEntry],
) -> Result<()> {
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
mod capability_tests {
    use crate::report::tests_support::rich_report;

    fn render(r: &crate::model::Report) -> String {
        let mut buf: Vec<u8> = Vec::new();
        crate::report::text::write(&mut buf, r, None, &crate::report::tests_support::opts())
            .expect("render");
        String::from_utf8(buf).expect("utf8")
    }

    /// Four of ten defects reported against one scan were capabilities that exist and were never
    /// discovered. The report has to distinguish "this bundle has no embedded archives" from
    /// "nobody passed --carve".
    #[test]
    fn a_default_run_names_the_analysis_it_did_not_do() {
        let mut r = rich_report();
        r.coverage.carve_ran = false;
        r.intel.reputation = None;
        r.intel.cves = None;
        let out = render(&r);
        assert!(out.contains("Analysis not run"), "{}", out);
        for flag in ["--carve", "--reputation", "--cve"] {
            assert!(out.contains(flag), "{} not named:\n{}", flag, out);
        }
        assert!(
            out.contains("not a finding about the target"),
            "absence must be disclaimed, not implied:\n{}",
            out
        );
    }

    /// And says nothing when everything ran, rather than printing an empty heading.
    #[test]
    fn a_fully_enriched_run_says_nothing() {
        let out = render(&rich_report());
        assert!(!out.contains("Analysis not run"), "{}", out);
    }

    /// --cve is only worth naming when there is something for it to resolve.
    #[test]
    fn cve_is_not_offered_when_no_component_was_detected() {
        let mut r = rich_report();
        r.intel.cves = None;
        r.intel.components.clear();
        let out = render(&r);
        assert!(!out.contains("--cve "), "{}", out);
    }
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
