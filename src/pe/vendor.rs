//! Who signed an image, collapsed to one key per organisation.
//!
//! **Why a separate field rather than the signer name.** One organisation signs with many
//! certificate subjects. The reference package carries `Microsoft Corporation`,
//! `Microsoft Windows`, `Microsoft Windows Phone Production PCA 2012`, `.NET` and `.NET DAC`,
//! which are five rows in a by-signer table and one vendor to a reviewer. The question people
//! actually ask of this output is "how many of these criticals are ours", and answering it meant
//! re-deriving the mapping by hand every time. An adversarial review asked for the field
//! directly: "an `owner` or `vendor` field, even heuristic, would prevent every consumer from
//! re-deriving it."
//!
//! **What this is not.** It is who signed the file, not who wrote the code in it. A third-party
//! library compiled into a vendor-signed DLL is attributed to the vendor, because that is what
//! the certificate says and there is nothing else in a PE to go on. On the reference package 244
//! occurrences sit in members whose root archive is the vendor's product while only 194 are in
//! vendor-authored code, and no signature can tell those apart. Compiland provenance can, which
//! is why it is a separate piece of work.
//!
//! The same caution already attaches to `signature` itself in `pe::PeAnalysis`: an identity claim,
//! never a trust decision. Nothing here verifies a chain, so a hostile binary self-signed as
//! "Adobe Inc." is attributed to Adobe. Use it to group and to deprioritise, never to grant
//! authority.

/// Subject common names that all mean Microsoft.
///
/// Prefixes rather than exact names, because the Windows PCAs embed a year and a product line
/// (`Microsoft Windows Phone Production PCA 2012`) and enumerating them would age badly.
const MICROSOFT_PREFIXES: &[&str] = &["microsoft", "windows", ".net", "msopr", "mspr"];

/// Suffixes a company appends to its legal name, which carry no information for grouping.
///
/// Order matters: the longer forms come first so `Corporation` is not left as `Corporatio` by a
/// shorter match. Each is tried as a whole trailing word, so a company genuinely called `Incite`
/// does not become `Ite`.
const LEGAL_SUFFIXES: &[&str] = &[
    "corporation",
    "incorporated",
    "limited",
    "holdings",
    "company",
    "gmbh",
    "corp.",
    "corp",
    "inc.",
    "inc",
    "ltd.",
    "ltd",
    "llc",
    "l.l.c.",
    "plc",
    "s.a.",
    "sa",
    "ag",
    "ab",
    "oy",
    "bv",
    "b.v.",
    "nv",
    "n.v.",
    "pty",
    "co.",
    "co",
];

/// Collapse a certificate subject common name to one vendor key.
///
/// `None` when the name carries nothing usable, which keeps an empty or punctuation-only subject
/// out of the grouping rather than creating a vendor called "".
pub fn from_signer(signer: &str) -> Option<String> {
    let lower = signer.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return None;
    }
    if MICROSOFT_PREFIXES.iter().any(|p| lower.starts_with(p)) {
        return Some("Microsoft".to_string());
    }

    // Drop trailing legal suffixes, repeatedly, so `Example Holdings Ltd.` reduces to `Example`.
    // Bounded by the word count so a name made only of suffixes cannot loop.
    let mut words: Vec<&str> = signer.split_whitespace().collect();
    while let Some(last) = words.last() {
        let bare = last.trim_end_matches(',').to_ascii_lowercase();
        if words.len() > 1 && LEGAL_SUFFIXES.contains(&bare.as_str()) {
            words.pop();
        } else {
            break;
        }
    }
    let out = words.join(" ").trim_end_matches(',').trim().to_string();
    if out.is_empty() {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microsofts_many_subjects_collapse_to_one_vendor() {
        // All five are real subject common names in the reference package, and they were five
        // rows in a by-signer table that a reviewer had to merge by hand on every read.
        for n in [
            "Microsoft Corporation",
            "Microsoft Windows",
            "Microsoft Windows Phone Production PCA 2012",
            "Microsoft Windows Software Compatibility Publisher",
            ".NET",
            ".NET DAC",
            "Windows Phone",
        ] {
            assert_eq!(from_signer(n).as_deref(), Some("Microsoft"), "{}", n);
        }
    }

    #[test]
    fn a_legal_suffix_is_not_part_of_the_vendor() {
        assert_eq!(from_signer("Adobe Inc.").as_deref(), Some("Adobe"));
        assert_eq!(
            from_signer("Adobe Systems Incorporated").as_deref(),
            Some("Adobe Systems")
        );
        assert_eq!(
            from_signer("Example Holdings Ltd.").as_deref(),
            Some("Example")
        );
        assert_eq!(
            from_signer("Oracle America, Inc.").as_deref(),
            Some("Oracle America")
        );
    }

    #[test]
    fn a_suffix_that_is_only_part_of_a_word_is_left_alone() {
        // `trim_end_matches` on a substring would turn these into nonsense, which is the same
        // class of error as an unconditional A/W strip turning `alloca` into `alloc`.
        assert_eq!(
            from_signer("Incite Security").as_deref(),
            Some("Incite Security")
        );
        assert_eq!(
            from_signer("Cointelligence").as_deref(),
            Some("Cointelligence")
        );
    }

    #[test]
    fn a_name_made_only_of_a_suffix_is_kept_rather_than_emptied() {
        // Pathological, but the loop must terminate and must not produce a vendor called "".
        assert_eq!(from_signer("Inc.").as_deref(), Some("Inc."));
    }

    #[test]
    fn an_empty_or_blank_subject_yields_no_vendor() {
        assert_eq!(from_signer(""), None);
        assert_eq!(from_signer("   "), None);
    }
}
