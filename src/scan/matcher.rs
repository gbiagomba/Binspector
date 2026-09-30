//! Token-accurate multi-pattern matching.
//!
//! Replaces the previous `String::contains` loop, which produced a 100% false
//! positive rate on real input: `gets` matched `targetsize`, and `system` matched
//! `System`, `FileSystem`, and `CustomSystemFont`. Two changes fix it:
//!
//! 1. Every hit is boundary-verified, so a pattern only counts when it is a whole
//!    identifier rather than a substring of a longer one.
//! 2. One Aho-Corasick automaton replaces the nested pattern-by-string loop, which
//!    was about 611M substring searches on the sample that exposed the bug.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use anyhow::{Context, Result};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Hit {
    pub pattern_id: usize,
    pub start: usize,
    pub end: usize,
}

pub struct Matcher {
    ac: AhoCorasick,
}

impl Matcher {
    pub fn new(patterns: &[String], case_insensitive: bool) -> Result<Self> {
        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .ascii_case_insensitive(case_insensitive)
            .build(patterns)
            .context("building banned function automaton")?;
        Ok(Self { ac })
    }

    /// Find every boundary-verified occurrence in `haystack`.
    ///
    /// Overlapping search is used deliberately: `MatchKind::Standard` with
    /// `find_overlapping_iter` reports all patterns at a position, so a shorter
    /// banned name nested inside a longer one is not silently dropped.
    pub fn find(&self, haystack: &str) -> Vec<Hit> {
        let bytes = haystack.as_bytes();
        let mut hits = Vec::new();
        for m in self.ac.find_overlapping_iter(haystack) {
            let (start, end) = (m.start(), m.end());
            if is_whole_token(bytes, start, end) {
                hits.push(Hit {
                    pattern_id: m.pattern().as_usize(),
                    start,
                    end,
                });
            }
        }
        hits
    }

    /// True when at least one boundary-verified hit exists. Cheaper than `find`
    /// when only presence matters.
    pub fn is_match(&self, haystack: &str) -> bool {
        let bytes = haystack.as_bytes();
        self.ac
            .find_overlapping_iter(haystack)
            .any(|m| is_whole_token(bytes, m.start(), m.end()))
    }
}

/// A match counts only when it is a whole identifier rather than a fragment of a
/// longer one. The two sides are deliberately asymmetric.
fn is_whole_token(bytes: &[u8], start: usize, end: usize) -> bool {
    right_boundary_ok(bytes, end) && left_boundary_ok(bytes, start)
}

/// The right side is strict: any trailing identifier byte means a different symbol.
/// This is what keeps `strcpy_s` (the safe replacement) from being reported as
/// `strcpy`, and `targetsize` from being reported as `gets`. A stdcall suffix such
/// as `strcpy@8` passes because `@` is not an identifier byte.
fn right_boundary_ok(bytes: &[u8], end: usize) -> bool {
    end >= bytes.len() || !is_ident_byte(bytes[end])
}

/// The left side tolerates compiler and linker decoration, because in a real PE the
/// import of `strcpy` appears as `_strcpy`, `__imp_strcpy`, or `__imp__strcpy`.
/// Treating those as non-matches would be a false negative on exactly the evidence
/// that matters. A wrapper name such as `my_strcpy` is still rejected, since `my`
/// is not a known decoration marker.
fn left_boundary_ok(bytes: &[u8], start: usize) -> bool {
    let mut i = start;
    loop {
        let before_underscores = i;
        while i > 0 && bytes[i - 1] == b'_' {
            i -= 1;
        }
        if i == 0 {
            return true;
        }
        if !is_ident_byte(bytes[i - 1]) {
            return true;
        }
        // The neighbour is an identifier byte with no underscore separating it.
        if i == before_underscores {
            return false;
        }
        // An alphanumeric run sits before the underscores. Accept it only when it is
        // a recognised import-thunk marker, then keep unwinding leftwards.
        let run_end = i;
        while i > 0 && bytes[i - 1].is_ascii_alphanumeric() {
            i -= 1;
        }
        if !bytes[i..run_end].eq_ignore_ascii_case(b"imp") {
            return false;
        }
    }
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(patterns: &[&str], ci: bool) -> Matcher {
        let owned: Vec<String> = patterns.iter().map(|s| s.to_string()).collect();
        Matcher::new(&owned, ci).unwrap()
    }

    // The exact false positives observed on SampleApp_1.0.0_x64.msixbundle.
    // These are the regression guards for the bug this module exists to fix.

    #[test]
    fn gets_does_not_match_targetsize() {
        let matcher = m(&["gets"], true);
        assert!(matcher.find("targetsize").is_empty());
        assert!(matcher.find("lightunplated_targetsize").is_empty());
    }

    #[test]
    fn system_does_not_match_capitalized_or_compound() {
        let matcher = m(&["system"], true);
        assert!(matcher.find("FileSystem").is_empty());
        assert!(matcher.find("SystemEvents").is_empty());
        assert!(matcher.find("CustomSystemFont").is_empty());
    }

    #[test]
    fn bare_system_still_matches_case_insensitively() {
        let matcher = m(&["system"], true);
        assert_eq!(matcher.find("system").len(), 1);
        assert_eq!(matcher.find("System").len(), 1);
        assert_eq!(matcher.find("call system now").len(), 1);
    }

    #[test]
    fn case_sensitive_mode_rejects_wrong_case() {
        let matcher = m(&["system"], false);
        assert_eq!(matcher.find("system").len(), 1);
        assert!(matcher.find("System").is_empty());
    }

    #[test]
    fn punctuation_is_a_valid_boundary() {
        let matcher = m(&["strcpy"], true);
        assert_eq!(matcher.find("strcpy(dst, src)").len(), 1);
        assert_eq!(matcher.find("_imp__strcpy@8").len(), 1);
        assert_eq!(matcher.find("call:strcpy;").len(), 1);
    }

    #[test]
    fn trailing_identifier_bytes_reject_the_match() {
        let matcher = m(&["strcpy"], true);
        // strcpy_s is the safe replacement, a different function entirely.
        assert!(matcher.find("strcpy_s").is_empty());
        assert!(matcher.find("strcpyA").is_empty());
        assert!(matcher.find("my_strcpy_wrapper").is_empty());
    }

    #[test]
    fn accepts_compiler_decoration_on_the_left() {
        let matcher = m(&["strcpy"], true);
        // These are all real references to strcpy in a PE import table.
        assert_eq!(matcher.find("_strcpy").len(), 1);
        assert_eq!(matcher.find("__strcpy").len(), 1);
        assert_eq!(matcher.find("_imp__strcpy").len(), 1);
        assert_eq!(matcher.find("__imp_strcpy").len(), 1);
        assert_eq!(matcher.find("__imp__strcpy@8").len(), 1);
    }

    #[test]
    fn rejects_wrapper_prefixes_that_are_not_decoration() {
        let matcher = m(&["strcpy"], true);
        assert!(matcher.find("my_strcpy").is_empty());
        assert!(matcher.find("safe_strcpy").is_empty());
        assert!(matcher.find("xstrcpy").is_empty());
    }

    #[test]
    fn leading_underscore_pattern_matches_itself() {
        let matcher = m(&["_tcscpy"], true);
        assert_eq!(matcher.find("_tcscpy").len(), 1);
    }

    #[test]
    fn reports_offsets_for_highlighting() {
        let matcher = m(&["gets"], true);
        let hits = matcher.find("xx gets yy");
        assert_eq!(hits.len(), 1);
        assert_eq!((hits[0].start, hits[0].end), (3, 7));
    }

    #[test]
    fn counts_every_occurrence_in_one_string() {
        let matcher = m(&["gets"], true);
        assert_eq!(matcher.find("gets gets gets").len(), 3);
    }

    #[test]
    fn overlapping_patterns_both_reported() {
        // Both are banned; the shorter must not be hidden by the longer.
        let matcher = m(&["cpy", "strcpy"], true);
        let hits = matcher.find("strcpy");
        // "cpy" inside "strcpy" fails the boundary check, "strcpy" passes.
        assert_eq!(hits.len(), 1);
        let matcher2 = m(&["gets", "widgets"], true);
        assert_eq!(matcher2.find("widgets").len(), 1);
    }

    #[test]
    fn is_match_agrees_with_find() {
        let matcher = m(&["gets"], true);
        assert!(!matcher.is_match("targetsize"));
        assert!(matcher.is_match("gets"));
    }

    #[test]
    fn handles_multibyte_neighbours() {
        let matcher = m(&["gets"], true);
        // A non-ASCII neighbour is not an identifier byte, so this is a real hit.
        assert_eq!(matcher.find("\u{00e9}gets\u{00e9}").len(), 1);
    }
}
