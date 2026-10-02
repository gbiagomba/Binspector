//! Hardened string and memory primitives an image imports, and what each one replaces.
//!
//! **Why this exists.** The banned-function list reports hygiene upside down. An image that
//! imports `strcpy_s` 12 times beside one `strcpy` is mid-migration and nearly done; an image
//! that imports only `strcpy` has not started. The list sees one occurrence in each and says the
//! same thing about both. An adversarial review of a real report put it plainly: a product team
//! reading the output "still cannot see that its own migration is ahead", and called that the
//! highest-value remaining gap after the severity model was fixed.
//!
//! **Why the previous version was wrong in both directions.** It tested `name.ends_with("_s")`
//! and nothing else, which is too wide and too narrow at once. Too wide, because `clearerr_s`,
//! `_controlfp_s`, `_gmtime64_s` and `qsort_s` all end in `_s` and have nothing to do with
//! string safety, so they inflated the hygiene number. Too narrow, because the StrSafe family
//! (`StringCchCopy`, `StringCbCat`) carries no `_s` suffix at all and was invisible.
//!
//! So a name is credited only when its *stem* names a primitive the banned list is about. The
//! stem families below were checked against the 64 credited-shaped import names in a real
//! 1,567-image package rather than written from the Microsoft documentation, which is why the
//! `_o_` forwarders are handled: the UCRT really does export `_o_wcsncpy_s` and `_o___stdio_common_vswprintf_s`.
//!
//! This changes no severity. It is context a reviewer needs in order not to misread a finding,
//! and the module is deliberately separate from `scan::banned` so a custom `--banned-list`
//! cannot silently change what counts as hygiene.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::ImportRef;

/// Stems whose hardened form is a string or memory safety improvement.
///
/// Membership is about the *family*, not the spelling: `wcsncpy_s` reduces to `wcsncpy`, which is
/// here, so it counts. `fopen_s` reduces to `fopen`, which is not, so it does not. Keeping this
/// list explicit rather than deriving it from the banned list means the two can disagree, which
/// is correct: a custom banned list is about what to flag, and this is about what to credit.
const CREDITED_STEMS: &[&str] = &[
    // Unbounded copies and concatenations, the families the hardened forms exist to replace.
    "strcpy",
    "strcat",
    "wcscpy",
    "wcscat",
    "tcscpy",
    "tcscat",
    "mbscpy",
    "mbscat",
    "lstrcpy",
    "lstrcat",
    "stpcpy",
    "wcpcpy",
    // Counted forms. Hardened versions report truncation instead of leaving the destination
    // unterminated, which is the CWE-170 failure the counted primitives actually have.
    "strncpy",
    "strncat",
    "wcsncpy",
    "wcsncat",
    "tcsncpy",
    "tcsncat",
    "mbsncpy",
    "mbsncat",
    "mbsnbcpy",
    "mbsnbcat",
    "stpncpy",
    "wcpncpy",
    // Formatted output into a buffer.
    "sprintf",
    "swprintf",
    "vsprintf",
    "vswprintf",
    "snprintf",
    "snwprintf",
    "vsnprintf",
    "vsnwprintf",
    "wsprintf",
    "scanf",
    "sscanf",
    "swscanf",
    "fscanf",
    "wscanf",
    // Reads with no destination bound at all.
    "gets",
    "getts",
    "gettws",
    // Tokenisers, which keep state in a static without the hardened form.
    "strtok",
    "wcstok",
    "mbstok",
    // Path composition and conversion, all of which write into a caller buffer.
    "makepath",
    "splitpath",
    "wmakepath",
    "wsplitpath",
    "itoa",
    "itow",
    "ltoa",
    "ltow",
    "ultoa",
    "ultow",
    "i64toa",
    "i64tow",
    "ui64toa",
    "ui64tow",
    "mbstowcs",
    "wcstombs",
    "mbscpy_s",
    "tmpnam",
    "mktemp",
    // Memory primitives. Bounded already, so these are credited rather than required, and the
    // hardened form adds a destination size the caller would otherwise have to get right.
    "memcpy",
    "memmove",
    "wmemcpy",
    "wmemmove",
];

/// Stems with no caller-supplied bound at all, which is what the ratio is measured against.
///
/// Deliberately the unbounded set only, matching what the banned list still rates Critical after
/// 5.7.0 moved the counted primitives to Medium. Counting `strncpy` as "unsafe" here would make
/// the ratio argue against a function the tool had just finished saying is not an unbounded
/// write, and counting `memcpy` would put the rolled-up link-graph surface into a hygiene number.
const UNBOUNDED_STEMS: &[&str] = &[
    "strcpy",
    "strcat",
    "wcscpy",
    "wcscat",
    "tcscpy",
    "tcscat",
    "mbscpy",
    "mbscat",
    "lstrcpy",
    "lstrcat",
    "stpcpy",
    "wcpcpy",
    "gets",
    "getts",
    "gettws",
    "sprintf",
    "swprintf",
    "vsprintf",
    "vswprintf",
    "wsprintf",
    "wvsprintf",
    "scanf",
    "sscanf",
    "swscanf",
];

/// Reduce an imported name to the family it belongs to.
///
/// Three real spellings have to collapse to one stem, and all three appear in the reference
/// package:
///
/// - The `_s` and `_s_l` hardened suffixes: `wcsncpy_s`, `_vsnprintf_s_l`.
/// - The UCRT's `_o_` forwarders, which prefix an already-decorated name:
///   `_o_wcsncpy_s`, and `_o___stdio_common_vswprintf_s` which carries both.
/// - The `__stdio_common_v*` backends, where the family is the front end MSVC compiled away:
///   `__stdio_common_vsprintf` is the `sprintf` family.
///
/// Leading underscores go last, after the prefixes, because `_o__controlfp_s` needs the `_o__`
/// removed as a unit rather than one underscore at a time.
pub fn stem(name: &str) -> String {
    let mut n = name.to_ascii_lowercase();
    for prefix in ["_o___", "_o__", "_o_"] {
        if let Some(rest) = n.strip_prefix(prefix) {
            n = rest.to_string();
            break;
        }
    }
    let n = n.trim_start_matches('_');
    // The UCRT backend names the front end rather than itself.
    if let Some(rest) = n.strip_prefix("stdio_common_v") {
        let rest = rest.strip_suffix("_s").unwrap_or(rest);
        return rest.to_string();
    }
    let n = n.strip_suffix("_s_l").unwrap_or(n);
    let n = n.strip_suffix("_s").unwrap_or(n);
    n.to_string()
}

/// Whether the name is written in one of the hardened spellings.
///
/// Shape only. Whether it *counts* is [`is_credited`], which also requires the stem to name a
/// family this module is about.
fn is_hardened_spelling(name: &str) -> bool {
    name.ends_with("_s")
        || name.ends_with("_s_l")
        || name.starts_with("StringCch")
        || name.starts_with("StringCb")
}

/// Membership test tolerating the Win32 ANSI and wide suffixes.
///
/// `lstrcatW` and `wsprintfW` are how these names really appear in an import table, and a table
/// listing every A and W permutation would double in length for no gain. The trailing character
/// is only dropped when doing so lands on a real entry, which is the same conditional-strip the
/// remediation lookup uses: an unconditional trim turns `alloca` into `alloc`.
fn in_family(table: &[&str], name: &str) -> bool {
    let st = stem(name);
    if table.contains(&st.as_str()) {
        return true;
    }
    match st.strip_suffix('a').or_else(|| st.strip_suffix('w')) {
        Some(trimmed) => table.contains(&trimmed),
        None => false,
    }
}

/// Whether an imported name is a hardened string or memory primitive worth crediting.
pub fn is_credited(name: &str) -> bool {
    if !is_hardened_spelling(name) {
        return false;
    }
    // StrSafe names its own family: StringCchCopyW reduces to a stem this table does not hold,
    // and asking it to would mean listing every A/W/Ex permutation.
    if name.starts_with("StringCch") || name.starts_with("StringCb") {
        return true;
    }
    in_family(CREDITED_STEMS, name)
}

/// Whether an imported name is an unbounded primitive, for the denominator of the ratio.
///
/// Requires the name *not* to be a hardened spelling, so `strcpy_s` is never counted against
/// `strcpy`: that is the whole point of the measurement.
pub fn is_unbounded(name: &str) -> bool {
    !is_hardened_spelling(name) && in_family(UNBOUNDED_STEMS, name)
}

/// What one image imports of each kind, as distinct names.
///
/// Slots rather than call sites, because an import table records one entry per function per image
/// however many times the code calls it. Two images importing `strcpy_s` are two slots, which is
/// the unit the review that asked for this used.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hygiene {
    /// Hardened names this image imports, sorted and deduplicated.
    pub credited: Vec<String>,
    /// Unbounded names this image imports, sorted and deduplicated.
    pub unbounded: Vec<String>,
}

impl Hygiene {
    pub fn from_imports(imports: &[ImportRef]) -> Self {
        let mut credited: BTreeSet<&str> = BTreeSet::new();
        let mut unbounded: BTreeSet<&str> = BTreeSet::new();
        for i in imports {
            let n = i.name.as_str();
            if is_credited(n) {
                credited.insert(n);
            } else if is_unbounded(n) {
                unbounded.insert(n);
            }
        }
        Self {
            credited: credited.into_iter().map(str::to_string).collect(),
            unbounded: unbounded.into_iter().map(str::to_string).collect(),
        }
    }

    /// Imports both forms, which is the signature of a migration in progress rather than one
    /// that never started or one that is finished.
    pub fn mid_migration(&self) -> bool {
        !self.credited.is_empty() && !self.unbounded.is_empty()
    }

    /// Imports only hardened forms. Distinct from an image with no string handling at all, which
    /// has neither list populated and deserves no credit either way.
    pub fn fully_migrated(&self) -> bool {
        !self.credited.is_empty() && self.unbounded.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn imports(names: &[&str]) -> Vec<ImportRef> {
        names
            .iter()
            .map(|n| ImportRef {
                library: "ucrtbase.dll".into(),
                name: (*n).to_string(),
            })
            .collect()
    }

    #[test]
    fn the_secure_crt_string_family_is_credited() {
        for n in [
            "strcpy_s",
            "strcat_s",
            "strncpy_s",
            "wcscpy_s",
            "wcsncat_s",
            "gets_s",
            "memcpy_s",
            "wmemcpy_s",
            "_splitpath_s",
            "_itoa_s",
            "strtok_s",
        ] {
            assert!(is_credited(n), "{} is a hardened string primitive", n);
        }
    }

    #[test]
    fn a_name_ending_in_underscore_s_is_not_credited_on_shape_alone() {
        // All of these are real imports in the reference package and all of them were counted as
        // string hygiene by the suffix test this module replaces.
        for n in [
            "clearerr_s",
            "_controlfp_s",
            "_gmtime64_s",
            "_localtime64_s",
            "qsort_s",
            "fopen_s",
            "_sopen_s",
            "rand_s",
            "strerror_s",
            "getenv_s",
            "_chsize_s",
            "_ftime64_s",
        ] {
            assert!(!is_credited(n), "{} is not about string safety", n);
        }
    }

    #[test]
    fn the_strsafe_family_is_credited_although_it_carries_no_underscore_s() {
        // Invisible to the suffix test, which is how an entire family went uncounted.
        for n in [
            "StringCchCopyW",
            "StringCchCatA",
            "StringCchPrintfW",
            "StringCbCopyNW",
            "StringCchCopyExW",
        ] {
            assert!(is_credited(n), "{} is StrSafe", n);
        }
    }

    #[test]
    fn the_ucrt_forwarders_reduce_to_their_family() {
        // Real spellings from the reference package. `_o___stdio_common_vswprintf_s` carries the
        // forwarder prefix, the backend prefix and the hardened suffix at once.
        assert_eq!(stem("_o_wcsncpy_s"), "wcsncpy");
        assert_eq!(stem("_o___stdio_common_vswprintf_s"), "swprintf");
        assert_eq!(stem("__stdio_common_vsprintf"), "sprintf");
        assert_eq!(stem("__stdio_common_vsnprintf_s"), "snprintf");
        assert_eq!(stem("_vsnprintf_s_l"), "vsnprintf");
        assert!(is_credited("_o_wcsncpy_s"));
        assert!(is_credited("_o___stdio_common_vswprintf_s"));
    }

    #[test]
    fn the_unbounded_denominator_excludes_counted_and_hardened_forms() {
        // The spellings that really appear in an import table, A and W suffixes included.
        for n in [
            "strcpy",
            "strcat",
            "lstrcpyA",
            "lstrcpyW",
            "lstrcatA",
            "lstrcatW",
            "wsprintfW",
            "wcscpy",
            "wcscat",
            "gets",
        ] {
            assert!(is_unbounded(n), "{} takes no caller-supplied bound", n);
        }
        // Counted, so 5.7.0 stopped rating it an unbounded write. Counting it here would argue
        // against a function the tool had just finished defending.
        assert!(!is_unbounded("strncpy"));
        assert!(!is_unbounded("wcsncat"));
        // Rolled up as a link-graph surface, not a hygiene signal.
        assert!(!is_unbounded("memcpy"));
        // And the hardened spelling is never its own denominator.
        assert!(!is_unbounded("strcpy_s"));
    }

    #[test]
    fn an_image_mid_migration_is_distinguished_from_one_that_finished() {
        let both = Hygiene::from_imports(&imports(&["strcpy_s", "strcpy", "wcscat_s"]));
        assert!(both.mid_migration());
        assert!(!both.fully_migrated());
        assert_eq!(both.credited.len(), 2);
        assert_eq!(both.unbounded, vec!["strcpy"]);

        let done = Hygiene::from_imports(&imports(&["strcpy_s", "StringCchCatW"]));
        assert!(done.fully_migrated());
        assert!(!done.mid_migration());

        // No string handling at all earns no credit in either direction, which is why
        // `fully_migrated` requires a non-empty credited list rather than an empty unsafe one.
        let neither = Hygiene::from_imports(&imports(&["CreateFileW", "RegOpenKeyExW"]));
        assert!(!neither.fully_migrated());
        assert!(!neither.mid_migration());
        assert!(neither.credited.is_empty());
    }

    #[test]
    fn slots_are_distinct_names_not_occurrences() {
        let h = Hygiene::from_imports(&imports(&["strcpy_s", "strcpy_s", "strcpy", "strcpy"]));
        assert_eq!(h.credited.len(), 1);
        assert_eq!(h.unbounded.len(), 1);
    }
}
