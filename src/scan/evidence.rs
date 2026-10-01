//! Evidence-based adjudication of one occurrence.
//!
//! Severity on its own is a property of a function *name*, decided by
//! [`banned::classify`](super::banned) before a single target byte is read. That is the
//! wrong unit of judgement, because it ignores the evidence sitting immediately next to
//! the match. A three-agent review of real output found four classes of defect, every one
//! of them decidable from the string the token was found in:
//!
//! - `?sprintf@WRStrSafe@@SAHPEAD_KPEBDZZ` was reported as a critical `sprintf`. It is the
//!   MSVC mangled name of `WRStrSafe::sprintf`, a safe wrapper taking an explicit
//!   destination capacity, so the tool was flagging the countermeasure as the defect.
//! - `cv::FileStorage::Impl::gets` was reported as a critical `gets`. C `gets` was removed
//!   in C11 and Windows exports only `gets_s`, so that import is not constructible.
//! - 52 occurrences sat in managed .NET assemblies, where no native call site can exist.
//! - `strlen`, `wcslen`, and `memcmp` were high, a quarter of the whole report, despite
//!   taking no destination pointer and being unable to overflow anything.
//!
//! This module is pure: no I/O, no scan-loop state, no allocation beyond the evidence
//! strings it hands back. [`adjudicate`] takes an [`Observation`] and returns a [`Ruling`],
//! so the rules can be tested exhaustively without a binary on disk.

use crate::container::Format;

use super::banned::Severity;
use super::confidence::{is_mangled_definition, is_qualified_name, Confidence};

/// The matched token is the name component of a C++ symbol rather than a reference to the
/// C runtime function of the same name.
pub const RULE_SYMBOL_DEFINITION: &str = "symbol-definition";
/// The function name is also an ordinary English word, and nothing but embedded text
/// backs the match.
pub const RULE_AMBIGUOUS_NAME: &str = "ambiguous-name-no-import";
/// The member is a managed assembly, so there is no native call site to find.
pub const RULE_MANAGED: &str = "managed-no-native-call";
/// The function reads memory and takes no destination pointer.
pub const RULE_READ_ONLY: &str = "read-only-primitive";
/// The function takes an explicit size, so the defect would be a wrong size rather than
/// the call itself.
pub const RULE_BOUNDED_MEMORY: &str = "bounded-memory-primitive";
/// The match is in a member that is not an executable image.
pub const RULE_NON_EXECUTABLE: &str = "non-executable-member";

/// One severity change, kept so a report can show why a number moved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Adjustment {
    pub rule: &'static str,
    pub from: Severity,
    pub to: Severity,
    pub evidence: String,
}

/// What the evidence says should happen to an occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Ruling {
    /// Report it, at this severity, with these adjustments recorded.
    Keep {
        severity: Severity,
        adjustments: Vec<Adjustment>,
    },
    /// Drop it. `rule` names why, for the exclusion accounting.
    Exclude {
        rule: &'static str,
        evidence: String,
    },
}

impl Ruling {
    pub fn is_excluded(&self) -> bool {
        matches!(self, Ruling::Exclude { .. })
    }

    /// The severity to report, or `None` when the occurrence was excluded.
    pub fn severity(&self) -> Option<Severity> {
        match self {
            Ruling::Keep { severity, .. } => Some(*severity),
            Ruling::Exclude { .. } => None,
        }
    }

    /// The exclusion rule, or `None` when the occurrence was kept.
    pub fn exclusion_rule(&self) -> Option<&'static str> {
        match self {
            Ruling::Keep { .. } => None,
            Ruling::Exclude { rule, .. } => Some(*rule),
        }
    }

    /// The recorded demotions, empty for an exclusion.
    pub fn adjustments(&self) -> &[Adjustment] {
        match self {
            Ruling::Keep { adjustments, .. } => adjustments,
            Ruling::Exclude { .. } => &[],
        }
    }
}

/// Everything knowable about one occurrence at the moment it is recorded.
#[derive(Clone, Debug)]
pub struct Observation<'a> {
    pub function: &'a str,
    pub base_severity: Severity,
    pub confidence: Confidence,
    /// The whole extracted string the token was found in.
    pub text: &'a str,
    /// Byte range of the matched token within `text`.
    pub start: usize,
    pub end: usize,
    pub member_format: Format,
    /// True only when the member parsed as a PE *and* carries a CLI header. A native
    /// image, and a member that never parsed as a PE at all, are both `false`, because
    /// neither is evidence that no native call site exists.
    pub is_managed: bool,
}

/// Names that are ordinary English words as well as C runtime functions.
///
/// Deliberately tiny. A name earns a place here only when a string matching it exactly is
/// more likely to be ordinary text than a call: "system" in a message, "gets" in
/// `Gets or sets the value`, "free" in a licence header, "random" in a comment. On the
/// SampleApp sample `system` alone had 24,160 matches suppressed as prose and 67 survive
/// as high with no import backing them, which is the shape of a name that cannot carry a
/// finding on text evidence alone. Anything whose name is not also a common word, such as
/// `strcpy` or `memcpy`, must not be listed here: text containing it really is suspicious.
const AMBIGUOUS_WORDS: &[&str] = &["system", "gets", "free", "rand", "random"];

/// Functions that read memory and take no destination pointer, so they cannot overflow a
/// buffer. `IsBad*Ptr` is worse than useless rather than dangerous: it swallows the
/// guard page the OS would otherwise use to catch a bad pointer.
const READ_ONLY_PRIMITIVES: &[&str] = &[
    "strlen",
    "wcslen",
    "tcslen",
    "memcmp",
    "wmemcmp",
    "isbadreadptr",
    "isbadwriteptr",
    "isbadcodeptr",
    "isbadstringptr",
];

/// Functions that take an explicit byte count. The defect in a `memcpy` is a wrong size
/// computed somewhere else, which an import table cannot show, so the call alone is a
/// place to look rather than a finding.
const BOUNDED_MEMORY_PRIMITIVES: &[&str] = &[
    "memcpy",
    "memmove",
    "memset",
    "wmemcpy",
    "wmemmove",
    "copymemory",
    "rtlcopymemory",
    "rtlmovememory",
];

/// The less severe of two severities, which is the only direction a demotion may move.
///
/// `Severity` derives `Ord` with `Critical` declared first, so badness runs opposite to
/// the ordering and the less severe value is the `Ord` maximum. Every demotion goes
/// through here, which makes raising a severity structurally impossible instead of a
/// convention somebody has to remember.
pub fn cap_severity(current: Severity, cap: Severity) -> Severity {
    current.max(cap)
}

/// Apply the evidence rules to one occurrence, in the order the module documents.
///
/// Exclusions come first and the first one wins, so an occurrence is attributed to a
/// single rule. Demotions then compose: each one that matches records its own
/// [`Adjustment`] and the severity only ever moves down.
pub fn adjudicate(o: &Observation) -> Ruling {
    if let Some(ruling) = exclusion(o) {
        return ruling;
    }

    let name = canonical_name(o.function);
    let mut severity = o.base_severity;
    let mut adjustments: Vec<Adjustment> = Vec::new();

    // 4. A read-only primitive cannot corrupt memory, whatever its family says.
    if READ_ONLY_PRIMITIVES.contains(&name.as_str()) {
        demote(
            &mut severity,
            &mut adjustments,
            RULE_READ_ONLY,
            Severity::Low,
            format!("{} reads memory and takes no destination pointer", o.function),
        );
    }

    // 5. A bounded primitive is a place to check a length computation, not a defect.
    if BOUNDED_MEMORY_PRIMITIVES.contains(&name.as_str()) {
        demote(
            &mut severity,
            &mut adjustments,
            RULE_BOUNDED_MEMORY,
            Severity::Medium,
            format!("{} takes an explicit size argument", o.function),
        );
    }

    // 6. No native call site is reachable from a member that is not an executable image.
    // Capped rather than excluded, because a shell script inside a bundle is a legitimate
    // place to find `system` and a reviewer should still see it.
    if !o.member_format.is_executable() && !o.confidence.is_definitive() {
        demote(
            &mut severity,
            &mut adjustments,
            RULE_NON_EXECUTABLE,
            Severity::Low,
            format!(
                "member format is {}, which is not an executable image",
                o.member_format.as_str()
            ),
        );
    }

    Ruling::Keep {
        severity,
        adjustments,
    }
}

/// Rules 1 to 3, in order. The first match wins so the exclusion accounting attributes
/// each dropped occurrence to exactly one cause.
fn exclusion(o: &Observation) -> Option<Ruling> {
    // An import is a linker-recorded fact. A mangled wrapper of the same name may well
    // also be in the string table, and it does not retract the import, so nothing below
    // may drop a definitive match.
    let inferred = !o.confidence.is_definitive();

    // 1. The token names a C++ method rather than referencing the CRT function.
    if inferred {
        if is_mangled_definition(o.text, o.start, o.end) {
            return Some(Ruling::Exclude {
                rule: RULE_SYMBOL_DEFINITION,
                evidence: format!(
                    "`{}` is an MSVC mangled definition of a method named {}",
                    snippet(o.text),
                    o.function
                ),
            });
        }
        if is_qualified_name(o.text, o.start) {
            return Some(Ruling::Exclude {
                rule: RULE_SYMBOL_DEFINITION,
                evidence: format!(
                    "`{}` is a qualified C++ name ending in {}",
                    snippet(o.text),
                    o.function
                ),
            });
        }
    }

    // 2. The name is an ordinary English word and only text backs the match.
    if inferred && AMBIGUOUS_WORDS.contains(&canonical_name(o.function).as_str()) {
        return Some(Ruling::Exclude {
            rule: RULE_AMBIGUOUS_NAME,
            evidence: format!(
                "{} is an ordinary English word and no import backs `{}`",
                o.function,
                snippet(o.text)
            ),
        });
    }

    // 3. A pure IL assembly has no native call site.
    if inferred && o.is_managed {
        return Some(Ruling::Exclude {
            rule: RULE_MANAGED,
            evidence: format!(
                "managed assembly, so `{}` cannot be a native call",
                snippet(o.text)
            ),
        });
    }

    None
}

/// Move `severity` down to at most `cap`, recording an [`Adjustment`] when it actually
/// moved. A rule that would raise the severity, or leave it alone, records nothing: the
/// adjustment list is an explanation of the number, so a no-op entry would be noise.
fn demote(
    severity: &mut Severity,
    adjustments: &mut Vec<Adjustment>,
    rule: &'static str,
    cap: Severity,
    evidence: String,
) {
    let to = cap_severity(*severity, cap);
    if to == *severity {
        return;
    }
    adjustments.push(Adjustment {
        rule,
        from: *severity,
        to,
        evidence,
    });
    *severity = to;
}

/// Fold a function name the way `banned::classify` does, so `_tcslen`, `tcslen`, and
/// `TcsLen` all reach the same rule.
fn canonical_name(name: &str) -> String {
    name.trim_start_matches('_').to_ascii_lowercase()
}

/// A bounded quotation of the string a match came from. Evidence belongs in the report,
/// but a 4 KiB extracted string does not, so this truncates on a character boundary.
fn snippet(text: &str) -> String {
    const MAX: usize = 120;
    if text.len() <= MAX {
        return text.to_string();
    }
    let mut cut = MAX;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}...", &text[..cut])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An occurrence in a native PE where the matched token is the function name itself.
    fn case<'a>(
        function: &'a str,
        base: Severity,
        confidence: Confidence,
        text: &'a str,
    ) -> Observation<'a> {
        let start = text
            .find(function)
            .expect("the function name appears in the text");
        Observation {
            function,
            base_severity: base,
            confidence,
            text,
            start,
            end: start + function.len(),
            member_format: Format::Pe,
            is_managed: false,
        }
    }

    // Rule 1: a wrapper is the countermeasure, not the defect.

    #[test]
    fn msvc_wrapper_is_not_the_crt_function() {
        for text in [
            "?sprintf@WRStrSafe@@SAHPEAD_KPEBDZZ",
            "?strncat@WRStrSafe@@SAHPEAD_KPEBD_K@Z",
            "?wcscat@WRStrSafe@@SAHPEA_W_KPEB_W@Z",
            "?wcscpy@WRStrSafe@@SAHPEA_W_KPEB_W@Z",
        ] {
            let function = text[1..].split('@').next().unwrap();
            let o = case(function, Severity::Critical, Confidence::Symbolic, text);
            let ruling = adjudicate(&o);
            assert_eq!(
                ruling.exclusion_rule(),
                Some(RULE_SYMBOL_DEFINITION),
                "{} should be excluded as a symbol definition",
                text
            );
        }
    }

    #[test]
    fn an_import_outranks_a_mangled_name() {
        // The critical counter-example. An import is recorded by the linker; a mangled
        // wrapper that happens to share the name does not retract it.
        let text = "?sprintf@WRStrSafe@@SAHPEAD_KPEBDZZ";
        let o = case("sprintf", Severity::Critical, Confidence::Import, text);
        let ruling = adjudicate(&o);
        assert!(!ruling.is_excluded());
        assert_eq!(ruling.severity(), Some(Severity::Critical));
        assert!(ruling.adjustments().is_empty());
    }

    #[test]
    fn opencv_member_function_is_not_gets() {
        let o = case(
            "gets",
            Severity::Critical,
            Confidence::Symbolic,
            "cv::FileStorage::Impl::gets",
        );
        let ruling = adjudicate(&o);
        assert_eq!(ruling.exclusion_rule(), Some(RULE_SYMBOL_DEFINITION));
        assert!(ruling.adjustments().is_empty());
        // The evidence has to be enough for a reviewer to agree without rerunning the scan.
        match ruling {
            Ruling::Exclude { evidence, .. } => {
                assert!(
                    evidence.contains("cv::FileStorage::Impl::gets"),
                    "{}",
                    evidence
                );
            }
            Ruling::Keep { .. } => unreachable!("already asserted excluded"),
        }
    }

    #[test]
    fn a_qualified_import_is_still_kept() {
        let o = case(
            "gets",
            Severity::Critical,
            Confidence::Import,
            "cv::FileStorage::Impl::gets",
        );
        assert_eq!(adjudicate(&o).severity(), Some(Severity::Critical));
    }

    // The baseline the whole report rests on: a real import, untouched.

    #[test]
    fn a_plain_import_keeps_its_severity() {
        let o = case("strcpy", Severity::Critical, Confidence::Import, "strcpy");
        let ruling = adjudicate(&o);
        assert_eq!(ruling.severity(), Some(Severity::Critical));
        assert!(ruling.adjustments().is_empty());
    }

    // Rule 2: an English word needs an import behind it.

    #[test]
    fn ambiguous_word_needs_an_import() {
        let o = case("system", Severity::High, Confidence::Exact, "system");
        assert_eq!(
            adjudicate(&o).exclusion_rule(),
            Some(RULE_AMBIGUOUS_NAME)
        );

        let o = case("system", Severity::High, Confidence::Import, "system");
        let ruling = adjudicate(&o);
        assert_eq!(ruling.severity(), Some(Severity::High));
        assert!(ruling.adjustments().is_empty());
    }

    #[test]
    fn the_ambiguous_list_stays_tiny() {
        // A name that is not also a common English word must keep carrying a finding on
        // text evidence, or boundary verification was for nothing.
        for function in ["strcpy", "sprintf", "memcpy", "alloca", "popen"] {
            let o = case(function, Severity::Critical, Confidence::Exact, function);
            assert!(
                !adjudicate(&o).is_excluded(),
                "{} must not be treated as an ordinary word",
                function
            );
        }
    }

    // Rule 3: managed assemblies have no native call sites.

    #[test]
    fn managed_assembly_has_no_native_call_site() {
        let mut o = case("strcpy", Severity::Critical, Confidence::Exact, "strcpy");
        o.is_managed = true;
        assert_eq!(adjudicate(&o).exclusion_rule(), Some(RULE_MANAGED));

        o.confidence = Confidence::Import;
        let ruling = adjudicate(&o);
        assert!(!ruling.is_excluded());
        assert_eq!(ruling.severity(), Some(Severity::Critical));
    }

    // Rule 4 and 5: what the primitive can actually do.

    #[test]
    fn read_only_primitive_is_demoted_to_low() {
        let o = case("strlen", Severity::High, Confidence::Import, "strlen");
        let ruling = adjudicate(&o);
        assert_eq!(ruling.severity(), Some(Severity::Low));
        assert_eq!(ruling.adjustments().len(), 1);
        assert_eq!(ruling.adjustments()[0].rule, RULE_READ_ONLY);
        assert_eq!(ruling.adjustments()[0].from, Severity::High);
        assert_eq!(ruling.adjustments()[0].to, Severity::Low);
    }

    #[test]
    fn read_only_matching_ignores_case_and_a_leading_underscore() {
        for function in ["_tcslen", "tcslen", "WCSLEN", "IsBadWritePtr"] {
            let o = case(function, Severity::High, Confidence::Import, function);
            assert_eq!(
                adjudicate(&o).severity(),
                Some(Severity::Low),
                "{} should be a read-only primitive",
                function
            );
        }
    }

    #[test]
    fn bounded_memory_primitive_is_demoted_to_medium() {
        let o = case("memcpy", Severity::High, Confidence::Import, "memcpy");
        let ruling = adjudicate(&o);
        assert_eq!(ruling.severity(), Some(Severity::Medium));
        assert_eq!(ruling.adjustments().len(), 1);
        assert_eq!(ruling.adjustments()[0].rule, RULE_BOUNDED_MEMORY);
    }

    // Rule 6: capped, not excluded.

    #[test]
    fn non_executable_member_caps_at_low() {
        let mut o = case("atoi", Severity::Medium, Confidence::Exact, "atoi");
        o.member_format = Format::Unknown;
        let ruling = adjudicate(&o);
        assert_eq!(ruling.severity(), Some(Severity::Low));
        assert_eq!(ruling.adjustments().len(), 1);
        assert_eq!(ruling.adjustments()[0].rule, RULE_NON_EXECUTABLE);
    }

    #[test]
    fn an_import_is_never_capped_for_its_member_format() {
        // A recorded import is evidence about the image, not about the string's
        // surroundings, so the member format cannot argue it away.
        let mut o = case("strcpy", Severity::Critical, Confidence::Import, "strcpy");
        o.member_format = Format::Zip;
        let ruling = adjudicate(&o);
        assert_eq!(ruling.severity(), Some(Severity::Critical));
        assert!(ruling.adjustments().is_empty());
    }

    #[test]
    fn demotions_compose_to_the_lower_of_the_two() {
        // A read-only primitive in a non-executable member: rule 4 already reached the
        // floor, so rule 6 has nothing left to move and records nothing.
        let mut o = case("strlen", Severity::High, Confidence::Exact, "strlen");
        o.member_format = Format::Unknown;
        let ruling = adjudicate(&o);
        assert_eq!(ruling.severity(), Some(Severity::Low));
        assert_eq!(ruling.adjustments().len(), 1);
        assert_eq!(ruling.adjustments()[0].rule, RULE_READ_ONLY);

        // A bounded primitive in a non-executable member moves twice, High to Medium to
        // Low, and both steps are recorded.
        let mut o = case("memcpy", Severity::High, Confidence::Exact, "memcpy");
        o.member_format = Format::Unknown;
        let ruling = adjudicate(&o);
        assert_eq!(ruling.severity(), Some(Severity::Low));
        let rules: Vec<&str> = ruling.adjustments().iter().map(|a| a.rule).collect();
        assert_eq!(rules, vec![RULE_BOUNDED_MEMORY, RULE_NON_EXECUTABLE]);
        assert_eq!(ruling.adjustments()[1].from, Severity::Medium);
        assert_eq!(ruling.adjustments()[1].to, Severity::Low);
    }

    // Order is part of the contract.

    #[test]
    fn symbol_definition_is_attributed_before_managed() {
        let mut o = case(
            "sprintf",
            Severity::Critical,
            Confidence::Symbolic,
            "?sprintf@WRStrSafe@@SAHPEAD_KPEBDZZ",
        );
        o.is_managed = true;
        assert_eq!(
            adjudicate(&o).exclusion_rule(),
            Some(RULE_SYMBOL_DEFINITION),
            "rule 1 runs before rule 3"
        );
    }

    #[test]
    fn ambiguous_name_is_attributed_before_managed() {
        let mut o = case("system", Severity::High, Confidence::Exact, "system");
        o.is_managed = true;
        assert_eq!(adjudicate(&o).exclusion_rule(), Some(RULE_AMBIGUOUS_NAME));
    }

    #[test]
    fn an_exclusion_beats_every_demotion() {
        // `free` is both an ambiguous word and nothing else; the exclusion wins outright
        // rather than producing a demoted finding.
        let o = case("free", Severity::High, Confidence::Symbolic, "x/free");
        let ruling = adjudicate(&o);
        assert!(ruling.is_excluded());
        assert!(ruling.adjustments().is_empty());
        assert_eq!(ruling.severity(), None);
    }

    // A demotion may never raise a severity.

    #[test]
    fn a_demotion_never_raises() {
        let o = case("memcpy", Severity::Low, Confidence::Import, "memcpy");
        let ruling = adjudicate(&o);
        assert_eq!(
            ruling.severity(),
            Some(Severity::Low),
            "bounded-memory-primitive must not raise Low to Medium"
        );
        assert!(ruling.adjustments().is_empty());
    }

    #[test]
    fn cap_severity_always_picks_the_milder_value() {
        use Severity::{Critical, High, Low, Medium};
        assert_eq!(cap_severity(Critical, Low), Low);
        assert_eq!(cap_severity(Critical, Medium), Medium);
        assert_eq!(cap_severity(Low, Medium), Low);
        assert_eq!(cap_severity(Low, Critical), Low);
        assert_eq!(cap_severity(Medium, Critical), Medium);
        assert_eq!(cap_severity(High, High), High);
    }

    #[test]
    fn snippet_truncates_on_a_character_boundary() {
        let long = "é".repeat(200);
        let cut = snippet(&long);
        assert!(cut.ends_with("..."));
        assert!(cut.len() <= 124);
        assert_eq!(snippet("short"), "short");
    }

    #[test]
    fn rule_names_are_stable() {
        // The exclusion accounting and the report both key off these strings.
        assert_eq!(RULE_SYMBOL_DEFINITION, "symbol-definition");
        assert_eq!(RULE_AMBIGUOUS_NAME, "ambiguous-name-no-import");
        assert_eq!(RULE_MANAGED, "managed-no-native-call");
        assert_eq!(RULE_READ_ONLY, "read-only-primitive");
        assert_eq!(RULE_BOUNDED_MEMORY, "bounded-memory-primitive");
        assert_eq!(RULE_NON_EXECUTABLE, "non-executable-member");
    }
}
