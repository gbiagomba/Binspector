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
/// `IsBad*Ptr`. Not a read-only primitive and not harmless: calling one swallows the guard
/// page the OS would otherwise use to turn a bad pointer into an immediate, clean crash, and
/// Microsoft's guidance is to never call them. Demoting these under a rule named "read-only"
/// would both lose a real finding class and mislabel it.
pub const RULE_POINTER_VALIDATION: &str = "deprecated-pointer-validation";
/// Allocator entry points. None takes a destination buffer, so by the same reasoning that
/// demotes `memcpy`, an imported `free` is not a defect on its own.
pub const RULE_ALLOCATOR: &str = "allocator-entry-point";
/// The function takes an explicit size, so the defect would be a wrong size rather than
/// the call itself.
pub const RULE_BOUNDED_MEMORY: &str = "bounded-memory-primitive";
/// The match is in a member that is not an executable image.
pub const RULE_NON_EXECUTABLE: &str = "non-executable-member";
/// The member carries no executable section and no import directory, so there is no code in
/// it to make the call. A resource-only or data-only DLL, which is a real and common shape:
/// ICU's locale data ships as a PE whose single `.rdata` section holds 34 MiB of CLDR keys.
pub const RULE_NO_CODE_SECTION: &str = "no-code-section";
/// The name is in this member's *export* table and not its import table, so the member is the
/// definition site. Flagging the C runtime for providing `memcpy` inverts the finding.
pub const RULE_DEFINITION_SITE: &str = "export-definition-site";
/// The function takes an explicit count, so like the memory primitives the defect would be a
/// wrong count rather than the call. Separate from the memory rule because the failure mode
/// differs: these truncate and leave the destination unterminated.
pub const RULE_BOUNDED_STRING: &str = "bounded-string-primitive";

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
    /// Whether a usable import table was read, so that the *absence* of an import is itself
    /// evidence.
    ///
    /// Two ways this is false, and both matter:
    ///
    /// - **Not a PE.** `Confidence::Import` is currently only derivable from a PE import
    ///   directory, so without this flag every rule requiring import backing would fire on
    ///   every ELF and Mach-O hit. Dropping a real `system()` call in a Linux binary because
    ///   the tool cannot yet read ELF imports would be a coverage loss wearing the costume of
    ///   precision.
    /// - **A PE with no import directory**, which is a packed image, a resource-only DLL, or
    ///   a managed assembly. There is no table for the name to be absent from, so absence
    ///   says nothing. A packed binary is exactly where a hidden `system` matters most.
    pub imports_known: bool,
    /// Whether the member has at least one section marked executable or carries code.
    ///
    /// `None` when the question was not answerable, which is every member that did not parse
    /// as a PE. Only `Some(false)` is evidence, and it is strong: a PE with no executable
    /// section and no import directory contains no instructions, so a matched name in it is
    /// data. Distinguishing `None` from `Some(false)` is the whole point, because defaulting
    /// an unparsed member to "no code" would silently drop findings in packed images.
    pub has_code: Option<bool>,
    /// Whether this member's export table contains the matched name.
    ///
    /// An exported `memcpy` with no corresponding import means the member *is* the C runtime.
    /// The matched string is its own export-directory name entry, not a call site.
    pub exported_here: bool,
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
const READ_ONLY_PRIMITIVES: &[&str] = &["strlen", "wcslen", "tcslen", "memcmp", "wmemcmp"];

/// `IsBad*Ptr`. Deliberately NOT in the read-only set: these are not harmless reads. Calling
/// one installs an exception handler over the access, which suppresses the guard page the OS
/// would otherwise use to turn a bad pointer into an immediate crash, and can mask a race.
/// Microsoft's guidance is to never call them, so this is a real finding class that merely
/// does not deserve `High`.
const POINTER_VALIDATION: &[&str] = &[
    "isbadreadptr",
    "isbadwriteptr",
    "isbadcodeptr",
    "isbadstringptr",
];

/// Allocator entry points. None takes a destination buffer, so an import of one is not a
/// defect by the same reasoning that demotes `memcpy`. A double free or use after free is a
/// real bug, but it is not visible from the fact that `free` is called.
const ALLOCATORS: &[&str] = &["malloc", "calloc", "realloc", "free", "aligned_malloc"];

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

/// Counted string primitives: an explicit maximum, so not an unbounded write.
///
/// Rated identically to `strcpy` until 5.7.0, which made the critical count indefensible:
/// 24 of 57 criticals in one real report were counted primitives, 15 of them `strncpy`. The
/// real failure mode is a destination left unterminated when the source fills the buffer,
/// [CWE-170](https://cwe.mitre.org/data/definitions/170.html), not the unbounded overflow of
/// [CWE-787](https://cwe.mitre.org/data/definitions/787.html). Worth finding, not worth the
/// same severity as a primitive that takes no count at all.
///
/// `snprintf` and the `vsn*` family are deliberately absent: they terminate, so their
/// weakness is the return value, which a different rule would have to reason about.
const BOUNDED_STRING_PRIMITIVES: &[&str] = &[
    "strncpy",
    "wcsncpy",
    "strncat",
    "wcsncat",
    "lstrcpyn",
    "lstrcpyna",
    "lstrcpynw",
    "lstrcatn",
    "lstrcatna",
    "lstrcatnw",
    "lstrncat",
    "stpncpy",
    "wcpncpy",
    "strcpyna",
    "strncpya",
    "strncpyw",
    "fstrncpy",
    "fstrncat",
    "tcsncpy",
    "tcsncat",
    "mbsncpy",
    "mbsncat",
    "mbsnbcpy",
    "mbsnbcat",
    "strcatn",
    "strcatna",
    "strcatnw",
    "strcpyn",
    "strcpynw",
    "strncata",
    "strncatw",
    "strncpya2",
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
            format!(
                "{} reads memory and takes no destination pointer",
                o.function
            ),
        );
    }

    // 4b. Pointer validation: its own rule, because "read-only" would mislabel it.
    if POINTER_VALIDATION.contains(&name.as_str()) {
        demote(
            &mut severity,
            &mut adjustments,
            RULE_POINTER_VALIDATION,
            Severity::Medium,
            format!(
                "{} suppresses the guard page that would otherwise crash cleanly",
                o.function
            ),
        );
    }

    // 4c. An allocator call takes no destination buffer.
    if ALLOCATORS.contains(&name.as_str()) {
        demote(
            &mut severity,
            &mut adjustments,
            RULE_ALLOCATOR,
            Severity::Medium,
            format!("{} takes no destination buffer", o.function),
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

    // 5b. Counted string primitives, by the same reasoning and with a different failure mode
    // named, so a reviewer knows what to look for rather than being told "bounded".
    if BOUNDED_STRING_PRIMITIVES.contains(&name.as_str()) {
        demote(
            &mut severity,
            &mut adjustments,
            RULE_BOUNDED_STRING,
            Severity::Medium,
            format!(
                "{} takes an explicit count, so the risk is a destination left unterminated \
                 (CWE-170) rather than an unbounded write",
                o.function
            ),
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
        if crate::scan::confidence::is_itanium_definition(o.text, o.start, o.end) {
            return Some(Ruling::Exclude {
                rule: RULE_SYMBOL_DEFINITION,
                evidence: format!(
                    "`{}` is an Itanium mangled definition of a method named {}",
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
    //
    // Two premises, and they need separating because one depends on the import table and the
    // other does not.
    if inferred && AMBIGUOUS_WORDS.contains(&canonical_name(o.function).as_str()) {
        // 2a. A symbolic match means the token sits inside a larger unbroken token, such as
        // `h-system` in an ICU locale table. That is never a call, whatever the member is, so
        // this does not depend on an import table existing.
        if o.confidence == Confidence::Symbolic {
            return Some(Ruling::Exclude {
                rule: RULE_AMBIGUOUS_NAME,
                evidence: format!(
                    "{} is an ordinary English word embedded in the larger token `{}`",
                    o.function,
                    snippet(o.text)
                ),
            });
        }
        // 2b. An exact match is a real standalone token, so it is only refutable by an import
        // table that was read and does not contain the name. Without such a table, absence is
        // not evidence: a stripped ELF carries a genuine `system` call as the exact string
        // `system` in its dynamic string table, and dropping it would be a coverage loss.
        if o.imports_known {
            return Some(Ruling::Exclude {
                rule: RULE_AMBIGUOUS_NAME,
                evidence: format!(
                    "{} is an ordinary English word and the import table does not contain it",
                    o.function
                ),
            });
        }
    }

    // 2c. The member contains no code at all, so nothing in it can call anything.
    //
    // Deliberately after the ambiguous-word rules and before the managed rule, because it is
    // the stronger statement: a managed assembly has no *native* call site, while this member
    // has no call site of any kind. Requires `Some(false)`, so a member that never parsed is
    // untouched.
    if inferred && o.has_code == Some(false) {
        return Some(Ruling::Exclude {
            rule: RULE_NO_CODE_SECTION,
            evidence: format!(
                "no executable section and no import directory, so `{}` is data in a \
                 resource-only or data-only image",
                snippet(o.text)
            ),
        });
    }

    // 2d. The member exports this name and does not import it, so it is the definition.
    //
    // `vcruntime140.dll` was reported for `memcpy`, `memmove`, `memset` and `memcmp`: the C
    // runtime flagged for supplying the primitives it exists to supply. The matched strings
    // were its own export-directory name entries. Guarded on `inferred`, so a member that
    // both exports and imports a name keeps the import finding.
    if inferred && o.exported_here {
        return Some(Ruling::Exclude {
            rule: RULE_DEFINITION_SITE,
            evidence: format!(
                "this member exports {} and does not import it, so the string is its own \
                 export table entry rather than a call",
                o.function
            ),
        });
    }

    // 3. A pure IL assembly has no native call site.
    if inferred && o.is_managed {
        // `is_managed` is only ever true for a parsed PE, so this needs no imports_known
        // guard: a managed assembly by definition had its headers read.
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
#[path = "evidence_tests.rs"]
mod tests;
