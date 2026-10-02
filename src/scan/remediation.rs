//! What to do about a banned-function finding.
//!
//! The asymmetry this closes: a missing exploit mitigation carried remediation from its rule
//! definition through the text report's `fix:` line into SARIF `help`, while a banned-function
//! finding carried none at any layer. A reader was told `strcpy` is critical and left to work out
//! the rest, which is the opposite way round from the two families' actual difficulty. A mitigation
//! is fixed by one build flag; replacing an unbounded string call is the part that needs guidance.
//!
//! Keyed on `Category` first, because the ten categories already encode the failure mode and
//! `classify` already derives one for every name, including names from a user-supplied
//! `--banned-list` that this module has never heard of. A per-function table would leave those with
//! nothing.
//!
//! The overrides are the point. Generic advice is wrong or dangerously incomplete for a handful of
//! functions whose failure mode is not their category's, and three of these came from an expert
//! review of a real scan rather than from documentation:
//!
//! * `strncpy` does not NUL-terminate when the source fills the buffer, so the "bounded" version of
//!   the advice produces an unterminated string and the next read runs off the end.
//! * `strncat`'s count bounds characters taken from the **source**, not the size of the
//!   destination, so the natural-looking `sizeof(dest)` overflows by up to `strlen(dest) + 1` while
//!   reading as correct.
//! * `PathCombineW` documents a destination of at least `MAX_PATH` and gives no parameter to
//!   enforce it, returns NULL on failure in a way callers routinely ignore, and truncates silently.
//!   Truncation is security-relevant on a trust boundary because a shortened path can resolve to a
//!   different object than the one that was validated.

use super::banned::Category;

/// Remediation for a finding, as the report and SARIF both render it.
pub fn advice(function: &str, category: Category) -> &'static str {
    if let Some(specific) = override_for(function) {
        return specific;
    }
    for_category(category)
}

/// Advice that holds for every member of a family.
fn for_category(category: Category) -> &'static str {
    match category {
        Category::BufferOverflow => {
            "replace with a bounded variant that takes the destination size and guarantees \
             termination (`strcpy_s`, `strlcpy`, `snprintf`), or use a type that owns its buffer. \
             A length check beside the call is not equivalent: it has to be right at every call site"
        }
        Category::FormatString => {
            "never pass caller-influenced data as the format argument. Use a literal format and \
             pass the data as a parameter, and prefer the `_s` or `n` variant that takes the \
             destination size"
        }
        Category::PathHandling => {
            "use the size-taking `PathCch*` successors, canonicalise before validating, and check \
             the return value. Validate the path after canonicalisation, never before"
        }
        Category::Conversion => {
            "use a conversion that reports failure (`strtol` with `errno`, `strtonum`, Rust's \
             `parse`) rather than one that returns zero for both a valid zero and an error"
        }
        Category::Randomness => {
            "use a cryptographically secure generator (`BCryptGenRandom`, `getrandom`, \
             `/dev/urandom`) for anything reachable by an attacker, including tokens, filenames \
             and nonces"
        }
        Category::MemoryManagement => {
            "check the allocation result, and compute the size with a checked multiply so an \
             integer overflow cannot produce an undersized buffer"
        }
        Category::SecurityDescriptor => {
            "build the descriptor explicitly rather than accepting a default or NULL DACL, and \
             grant the narrowest set of rights the caller needs"
        }
        Category::DllHijacking => {
            "load by a fully qualified path, and call `SetDefaultDllDirectories` with \
             `LOAD_LIBRARY_SEARCH_SYSTEM32` at startup so an attacker-writable directory is never \
             searched"
        }
        Category::ProcessCreation => {
            "pass a fully qualified, quoted application path rather than a bare name, so the \
             executable cannot be resolved out of a directory an attacker can write to"
        }
        Category::Other => {
            "review the call site: confirm the destination size is known and enforced, and that \
             every input is validated after canonicalisation"
        }
    }
}

/// Functions whose own failure mode differs from their family's.
///
/// Matched case-insensitively on the bare name, after any `A`/`W` suffix, because the list and the
/// binaries disagree on decoration.
fn override_for(function: &str) -> Option<&'static str> {
    let lower = function.to_ascii_lowercase();
    // Try the name as written first, then with a single ANSI/wide suffix removed. Stripping
    // unconditionally would be wrong in both directions: `trim_end_matches` is case-sensitive so it
    // misses an already-lowercased `pathcombinew`, and stripping from a lowercased name turns
    // `alloca` into `alloc` and loses its override entirely.
    exact(&lower).or_else(|| {
        let trimmed = lower
            .strip_suffix('a')
            .or_else(|| lower.strip_suffix('w'))?;
        exact(trimmed)
    })
}

fn exact(f: &str) -> Option<&'static str> {
    Some(match f {
        // The UCRT formatting backends. MSVC emits a call to one of these rather than to
        // `sprintf`, so they have to be on the list, but the import is weaker evidence than a
        // direct `sprintf` import and the remediation has to say so or 231 hits read as 231
        // defects. Each backend takes a `_BufferCount` that the front end supplies: `sprintf`
        // passes `(size_t)-1` and `snprintf` passes the real size, so linkage proves formatted
        // output into a buffer and cannot distinguish the two.
        //
        // Named explicitly rather than matched by prefix, because `override_for` lowercases and
        // strips one trailing a/w, which would not reach these.
        "__stdio_common_vsprintf"
        | "__stdio_common_vswprintf"
        | "__stdio_common_vsnprintf"
        | "__stdio_common_vsnwprintf"
        | "__stdio_common_vfprintf"
        | "__stdio_common_vfwprintf" => {
            "this is the shared UCRT backend the compiler emits, not a call site: `sprintf` and \
             `snprintf` both route through it and differ only in the buffer count they pass, so \
             the import does not say the call is unbounded. Read the call sites, and prefer the \
             `_s` forms or `snprintf` with an explicit size so the bound is in the source"
        }
        "strncpy" | "wcsncpy" | "_tcsncpy" => {
            "`strncpy` does not NUL-terminate when the source fills the buffer, so a bounded call \
             still yields an unterminated string. Use `strlcpy` or `strcpy_s`, or terminate \
             explicitly after the copy"
        }
        "strncat" | "wcsncat" | "_tcsncat" => {
            "`strncat`'s count bounds the characters taken from the *source*, not the size of the \
             destination, so `sizeof(dest)` overflows by up to `strlen(dest) + 1` while looking \
             correct. Use `strlcat` or `strcat_s`"
        }
        "pathcombine" | "pathappend" | "pathcanonicalize" => {
            "documents a destination of at least MAX_PATH and gives no parameter to enforce it, \
             returns NULL on failure in a way callers routinely ignore, and truncates silently. Use \
             `PathCchCombineEx` or `PathCchAppendEx`, which take the destination size, and check \
             the result"
        }
        "pathrenameextension" | "pathremoveextension" | "pathaddextension" => {
            "rewriting an extension is how a benign download target becomes executable. Use the \
             size-taking `PathCch*` successor and re-validate the resulting path against the \
             policy that allowed the original"
        }
        "memcpy" | "memmove" | "wmemcpy" | "wmemmove" => {
            "the call itself is ordinary; the defect is always the length. Confirm the length is \
             derived from the *destination* size rather than the source, and that it cannot be \
             influenced by input"
        }
        "gets" => {
            "`gets` cannot be used safely and was removed from C in C11. Use `fgets` with an \
             explicit size, or `gets_s`"
        }
        "alloca" => {
            "a caller-influenced size moves the stack pointer by an attacker-chosen amount. Use a \
             heap allocation with a checked size, or a fixed-size buffer"
        }
        "system" | "popen" | "_wsystem" => {
            "passes a string to a shell, so any metacharacter in it is code. Use an exec-family \
             call that takes an argument vector, with a fully qualified program path"
        }
        "isbadreadptr" | "isbadwriteptr" | "isbadcodeptr" | "isbadstringptr" => {
            "these cannot work: the probe races with other threads and suppresses the guard page \
             that would otherwise grow the stack. Validate pointers by construction instead, and \
             delete the call"
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_category_has_advice() {
        for c in [
            Category::BufferOverflow,
            Category::FormatString,
            Category::PathHandling,
            Category::Conversion,
            Category::Randomness,
            Category::MemoryManagement,
            Category::SecurityDescriptor,
            Category::DllHijacking,
            Category::ProcessCreation,
            Category::Other,
        ] {
            let a = for_category(c);
            assert!(!a.is_empty(), "{:?} has no advice", c);
            assert!(a.len() > 40, "{:?} advice is too thin: {}", c, a);
        }
    }

    /// The reason overrides exist: the category-level advice for these would be wrong, not merely
    /// vague.
    #[test]
    fn the_sharp_cases_say_what_is_actually_wrong() {
        assert!(advice("strncpy", Category::BufferOverflow).contains("does not NUL-terminate"));
        assert!(advice("strncat", Category::BufferOverflow).contains("source"));
        assert!(advice("PathCombineW", Category::PathHandling).contains("MAX_PATH"));
        assert!(advice("IsBadReadPtr", Category::Other).contains("races"));
    }

    #[test]
    fn decoration_does_not_defeat_the_lookup() {
        let bare = advice("PathCombine", Category::PathHandling);
        assert_eq!(advice("PathCombineW", Category::PathHandling), bare);
        assert_eq!(advice("PathCombineA", Category::PathHandling), bare);
        assert_eq!(advice("pathcombinew", Category::PathHandling), bare);
    }

    /// A name from a user-supplied --banned-list has no override and must still get advice.
    #[test]
    fn an_unknown_name_falls_back_to_its_family() {
        let a = advice("CompanySpecificUnsafeCopy", Category::BufferOverflow);
        assert_eq!(a, for_category(Category::BufferOverflow));
    }

    #[test]
    fn the_ucrt_backends_say_the_import_is_linkage_not_a_call_site() {
        // The field report accepted the High tier and asked for exactly this: a consumer reading
        // 231 hits at `high` would otherwise take them for 231 defects, when what the import
        // proves is that formatted output into a buffer happens somewhere in the module.
        for f in [
            "__stdio_common_vsprintf",
            "__stdio_common_vswprintf",
            "__stdio_common_vfprintf",
        ] {
            let a = advice(f, Category::FormatString);
            assert!(a.contains("shared UCRT backend"), "{}: {}", f, a);
            assert!(a.contains("does not say the call is unbounded"), "{}", f);
        }
        // A direct `sprintf` import keeps the ordinary format-string advice, because there the
        // call really is the finding.
        assert!(!advice("sprintf", Category::FormatString).contains("shared UCRT backend"));
    }
}
