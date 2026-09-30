//! Confidence scoring for a boundary-verified match.
//!
//! Boundary verification removes `targetsize` matching `gets`, but it cannot remove
//! everything, because some noise is a genuine whole token. On the SampleApp sample,
//! 24,227 of 24,445 high-severity hits came from two such sources:
//!
//! - .NET namespaces: `System.Windows.Forms` contains `System` as a whole token,
//!   because `.` is a valid boundary.
//! - XML documentation prose: `"Gets or sets the BindingContext"` contains `Gets`.
//!
//! Neither is a call to the C `system()` or `gets()`. The distinguishing signals are
//! how the token sits inside its string, and whether its case matches. C runtime
//! names are lowercase, so an uppercase variant inside prose is almost never a call.

use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// The name appears in the PE import directory. This is a linker-recorded
    /// dependency, so it is direct evidence that the binary calls the function,
    /// not an inference from embedded text.
    Import,
    /// The whole string is the function name, allowing for compiler decoration.
    Exact,
    /// The string looks like a symbol or path rather than a sentence: no whitespace,
    /// and the token is delimited by punctuation.
    Symbolic,
    /// The token sits inside natural language, or its case does not match a
    /// lowercase C runtime name. Reported separately and excluded by default.
    Prose,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Import => "import",
            Confidence::Exact => "exact",
            Confidence::Symbolic => "symbolic",
            Confidence::Prose => "prose",
        }
    }

    /// Whether a hit at this confidence is reported by default.
    pub fn is_reportable(self) -> bool {
        matches!(
            self,
            Confidence::Import | Confidence::Exact | Confidence::Symbolic
        )
    }

    /// True when the evidence is a recorded import rather than embedded text.
    pub fn is_definitive(self) -> bool {
        matches!(self, Confidence::Import)
    }
}

/// Score one match. `pattern` is the banned name as written in the list.
pub fn score(text: &str, start: usize, end: usize, pattern: &str) -> Confidence {
    if start >= end || end > text.len() {
        return Confidence::Prose;
    }
    let matched = &text[start..end];

    // A lowercase C runtime name that matched only by ignoring case is almost always
    // a namespace segment or an English word, not a call.
    let pattern_is_lowercase = !pattern.bytes().any(|b| b.is_ascii_uppercase());
    if pattern_is_lowercase && matched != pattern {
        return Confidence::Prose;
    }

    if is_whole_symbol(text, start, end) {
        return Confidence::Exact;
    }
    // Any ASCII whitespace means the string reads as text, not as a symbol.
    if text.bytes().any(|b| b == b' ' || b == b'\t') {
        return Confidence::Prose;
    }
    Confidence::Symbolic
}

/// True when the match spans the entire string once compiler decoration is removed:
/// leading underscores, an `imp` import-thunk marker, and a trailing `@N` stdcall
/// suffix. `strcpy`, `_strcpy`, `__imp__strcpy`, and `strcpy@8` all qualify.
fn is_whole_symbol(text: &str, start: usize, end: usize) -> bool {
    let bytes = text.as_bytes();

    // Trailing: allow @ followed by digits.
    let mut tail = end;
    if tail < bytes.len() && bytes[tail] == b'@' {
        let mut j = tail + 1;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        if j > tail + 1 {
            tail = j;
        }
    }
    if tail != bytes.len() {
        return false;
    }

    // Leading: underscores, optionally with an `imp` marker between them.
    let mut i = start;
    loop {
        while i > 0 && bytes[i - 1] == b'_' {
            i -= 1;
        }
        if i == 0 {
            return true;
        }
        let run_end = i;
        while i > 0 && bytes[i - 1].is_ascii_alphanumeric() {
            i -= 1;
        }
        if i == run_end || !bytes[i..run_end].eq_ignore_ascii_case(b"imp") {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str, token: &str, pattern: &str) -> Confidence {
        let s = text.find(token).expect("token present");
        score(text, s, s + token.len(), pattern)
    }

    // The two noise sources measured on the real SampleApp sample.

    #[test]
    fn dotnet_namespace_is_prose() {
        assert_eq!(
            at("System.Windows.Forms.dll", "System", "system"),
            Confidence::Prose
        );
        assert_eq!(
            at("System.Collections.Generic", "System", "system"),
            Confidence::Prose
        );
    }

    #[test]
    fn xml_documentation_prose_is_prose() {
        assert_eq!(
            at(
                "Gets or sets the BindingContext for this bindable Component.",
                "Gets",
                "gets"
            ),
            Confidence::Prose
        );
        assert_eq!(
            at(
                "Object without owner gets owned by the document.",
                "gets",
                "gets"
            ),
            Confidence::Prose
        );
    }

    // What a real import reference looks like.

    #[test]
    fn bare_symbol_is_exact() {
        assert_eq!(at("strcpy", "strcpy", "strcpy"), Confidence::Exact);
        assert_eq!(at("gets", "gets", "gets"), Confidence::Exact);
        assert_eq!(at("system", "system", "system"), Confidence::Exact);
    }

    #[test]
    fn decorated_symbol_is_exact() {
        assert_eq!(at("_strcpy", "strcpy", "strcpy"), Confidence::Exact);
        assert_eq!(at("__imp__strcpy", "strcpy", "strcpy"), Confidence::Exact);
        assert_eq!(at("__imp_strcpy", "strcpy", "strcpy"), Confidence::Exact);
        assert_eq!(at("strcpy@8", "strcpy", "strcpy"), Confidence::Exact);
        assert_eq!(at("_strcpy@4", "strcpy", "strcpy"), Confidence::Exact);
    }

    #[test]
    fn symbol_inside_a_path_or_qualified_name_is_symbolic() {
        assert_eq!(
            at("msvcrt.dll!strcpy", "strcpy", "strcpy"),
            Confidence::Symbolic
        );
        assert_eq!(
            at("api-ms-win-crt/strcpy", "strcpy", "strcpy"),
            Confidence::Symbolic
        );
    }

    #[test]
    fn mixed_case_windows_api_keeps_its_confidence() {
        // The banned list carries the exact casing, so this is not downgraded.
        assert_eq!(at("lstrcpyA", "lstrcpyA", "lstrcpyA"), Confidence::Exact);
        assert_eq!(
            at("KERNEL32.dll!lstrcpyA", "lstrcpyA", "lstrcpyA"),
            Confidence::Symbolic
        );
    }

    #[test]
    fn case_mismatch_on_a_lowercase_name_is_prose() {
        assert_eq!(at("STRCPY", "STRCPY", "strcpy"), Confidence::Prose);
        assert_eq!(at("Strcpy", "Strcpy", "strcpy"), Confidence::Prose);
    }

    #[test]
    fn sentence_containing_a_lowercase_name_is_prose() {
        assert_eq!(
            at("do not call strcpy here", "strcpy", "strcpy"),
            Confidence::Prose
        );
    }

    #[test]
    fn reportability_excludes_prose_only() {
        assert!(Confidence::Exact.is_reportable());
        assert!(Confidence::Symbolic.is_reportable());
        assert!(!Confidence::Prose.is_reportable());
    }

    #[test]
    fn out_of_range_is_safe() {
        assert_eq!(score("abc", 0, 99, "abc"), Confidence::Prose);
        assert_eq!(score("abc", 2, 1, "abc"), Confidence::Prose);
    }

    #[test]
    fn ordering_puts_exact_first() {
        let mut v = vec![Confidence::Prose, Confidence::Exact, Confidence::Symbolic];
        v.sort();
        assert_eq!(
            v,
            vec![Confidence::Exact, Confidence::Symbolic, Confidence::Prose]
        );
    }
}
