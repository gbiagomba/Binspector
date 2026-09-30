//! Banned function list loading, plus severity and category classification.
//!
//! The `rsc/` lists are flat name-per-line files. Classification is derived here
//! from the function family rather than stored in the list, so a custom list
//! supplied with `--banned-list` gets the same tiering for free.

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Compiled-in default list.
pub static DEFAULT_LIST: &str = include_str!("../../rsc/sdl_banned_funct.list");

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Unbounded write with no caller-supplied length. Memory corruption by design.
    Critical,
    /// Bounded but routinely misused, or a known weak primitive.
    High,
    /// Weak error handling or predictability. Worth reviewing, rarely exploitable alone.
    Medium,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
        }
    }

    /// SARIF level mapping.
    pub fn sarif_level(self) -> &'static str {
        match self {
            Severity::Critical => "error",
            Severity::High => "warning",
            Severity::Medium => "note",
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    BufferOverflow,
    FormatString,
    PathHandling,
    Conversion,
    Randomness,
    MemoryManagement,
    SecurityDescriptor,
    Other,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::BufferOverflow => "buffer-overflow",
            Category::FormatString => "format-string",
            Category::PathHandling => "path-handling",
            Category::Conversion => "conversion",
            Category::Randomness => "randomness",
            Category::MemoryManagement => "memory-management",
            Category::SecurityDescriptor => "security-descriptor",
            Category::Other => "other",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BannedEntry {
    pub name: String,
    pub severity: Severity,
    pub category: Category,
}

#[derive(Debug)]
pub struct BannedList {
    pub entries: Vec<BannedEntry>,
}

impl BannedList {
    /// Load from an explicit path, or fall back to the compiled-in default list.
    pub fn load(path: Option<&Path>, filter: Option<&Regex>) -> Result<Self> {
        let source: String = match path {
            Some(p) => fs::read_to_string(p)
                .with_context(|| format!("reading banned list {}", p.display()))?,
            None => DEFAULT_LIST.to_string(),
        };
        Ok(Self::parse(&source, filter))
    }

    pub fn parse(source: &str, filter: Option<&Regex>) -> Self {
        let mut names: BTreeSet<String> = BTreeSet::new();
        for line in source.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Legacy lists occasionally carry several tokens on one line, and some
            // were saved with zero-width characters embedded.
            for token in sanitize_token(line).split_whitespace() {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }
                if let Some(re) = filter {
                    if !re.is_match(token) {
                        continue;
                    }
                }
                names.insert(token.to_string());
            }
        }

        let entries = names
            .into_iter()
            .map(|name| {
                let (severity, category) = classify(&name);
                BannedEntry {
                    name,
                    severity,
                    category,
                }
            })
            .collect();

        BannedList { entries }
    }

    pub fn names(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.name.clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, id: usize) -> Option<&BannedEntry> {
        self.entries.get(id)
    }
}

/// Classify a function by family. Case-insensitive so `StrCpy` and `strcpy` agree.
fn classify(name: &str) -> (Severity, Category) {
    let n = name.to_ascii_lowercase();
    let n = n.trim_start_matches('_');

    // Unbounded copies and concatenations: no length parameter exists at all.
    const CRITICAL_BUFFER: &[&str] = &[
        "gets", "getts", "gettws", "strcpy", "strcpya", "strcpyw", "wcscpy", "tcscpy", "mbscpy",
        "lstrcpy", "lstrcpya", "lstrcpyw", "strcat", "strcata", "strcatw", "wcscat", "tcscat",
        "mbscat", "lstrcat", "lstrcata", "lstrcatw", "strncpy", "wcsncpy", "strncat", "wcsncat",
        "alloca", "getwd",
    ];
    // Format-string primitives that write into a caller buffer without a bound.
    const CRITICAL_FORMAT: &[&str] = &[
        "sprintf",
        "sprintfa",
        "sprintfw",
        "vsprintf",
        "vswprintf",
        "swprintf",
        "wsprintf",
        "wsprintfa",
        "wsprintfw",
        "vsprintfa",
        "vsprintfw",
    ];
    const HIGH_FORMAT: &[&str] = &[
        "scanf",
        "sscanf",
        "swscanf",
        "fscanf",
        "wscanf",
        "snprintf",
        "vsnprintf",
        "printf",
        "fprintf",
        "vprintf",
        "vfprintf",
        "syslog",
    ];
    const HIGH_MEMORY: &[&str] = &[
        "memcpy",
        "wmemcpy",
        "memmove",
        "wmemmove",
        "memset",
        "realloc",
        "free",
        "malloc",
        "calloc",
        "isbadreadptr",
        "isbadwriteptr",
        "isbadcodeptr",
        "isbadstringptr",
    ];
    const PATH_FNS: &[&str] = &[
        "makepath",
        "splitpath",
        "wmakepath",
        "wsplitpath",
        "tmakepath",
        "tsplitpath",
        "getenv",
        "wgetenv",
        "tgetenv",
        "mktemp",
        "tmpnam",
        "tempnam",
    ];
    const CONVERSION_FNS: &[&str] = &[
        "atoi", "atol", "atoll", "atof", "wtoi", "wtol", "wtoll", "ttoi", "ttol", "strtok",
        "wcstok", "tcstok",
    ];
    const RANDOM_FNS: &[&str] = &["rand", "srand", "random", "srandom", "drand48"];

    if CRITICAL_BUFFER.contains(&n) {
        return (Severity::Critical, Category::BufferOverflow);
    }
    if CRITICAL_FORMAT.contains(&n) {
        return (Severity::Critical, Category::FormatString);
    }
    if HIGH_FORMAT.contains(&n) {
        return (Severity::High, Category::FormatString);
    }
    if HIGH_MEMORY.contains(&n) {
        return (Severity::High, Category::MemoryManagement);
    }
    if PATH_FNS.contains(&n) {
        return (Severity::High, Category::PathHandling);
    }
    if CONVERSION_FNS.contains(&n) {
        return (Severity::Medium, Category::Conversion);
    }
    if RANDOM_FNS.contains(&n) {
        return (Severity::Medium, Category::Randomness);
    }
    if n.contains("securitydescriptor") || n.contains("setsecurity") {
        return (Severity::High, Category::SecurityDescriptor);
    }
    // Family fallbacks for the long tail of Windows string helpers.
    if n.starts_with("strcpy") || n.starts_with("strcat") || n.starts_with("lstrcp") {
        return (Severity::Critical, Category::BufferOverflow);
    }
    if n.contains("sprintf") {
        return (Severity::Critical, Category::FormatString);
    }
    if n.contains("scanf") || n.contains("printf") {
        return (Severity::High, Category::FormatString);
    }
    if n.contains("alloc") {
        return (Severity::High, Category::MemoryManagement);
    }

    (Severity::High, Category::Other)
}

/// Strip zero-width, format, and control characters seen in hand-edited lists.
pub fn sanitize_token(input: &str) -> String {
    input
        .chars()
        .filter(|&ch| !is_invisible_format_char(ch) && !ch.is_control())
        .collect()
}

fn is_invisible_format_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}'   // ZERO WIDTH SPACE
        | '\u{200C}' // ZERO WIDTH NON-JOINER
        | '\u{200D}' // ZERO WIDTH JOINER
        | '\u{FEFF}' // ZERO WIDTH NO-BREAK SPACE
        | '\u{2060}' // WORD JOINER
        | '\u{00AD}' // SOFT HYPHEN
        | '\u{034F}' // COMBINING GRAPHEME JOINER
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_dedupes() {
        let list = BannedList::parse("strcpy\n# comment\n\nstrcpy\ngets  atoi\n", None);
        let names = list.names();
        assert_eq!(names, vec!["atoi", "gets", "strcpy"]);
    }

    #[test]
    fn strips_zero_width_characters() {
        let list = BannedList::parse("str\u{200B}cpy\n", None);
        assert_eq!(list.names(), vec!["strcpy"]);
    }

    #[test]
    fn honors_regex_filter() {
        let re = Regex::new("^str").unwrap();
        let list = BannedList::parse("strcpy\ngets\n", Some(&re));
        assert_eq!(list.names(), vec!["strcpy"]);
    }

    #[test]
    fn classifies_severity_by_family() {
        assert_eq!(classify("gets").0, Severity::Critical);
        assert_eq!(classify("strcpy").0, Severity::Critical);
        assert_eq!(classify("sprintf").0, Severity::Critical);
        assert_eq!(classify("_tcscpy").0, Severity::Critical);
        assert_eq!(classify("memcpy").0, Severity::High);
        assert_eq!(classify("atoi").0, Severity::Medium);
        assert_eq!(classify("rand").0, Severity::Medium);
        assert_eq!(classify("SomeUnknownApi").0, Severity::High);
    }

    #[test]
    fn classifies_category() {
        assert_eq!(classify("strcpy").1, Category::BufferOverflow);
        assert_eq!(classify("sprintf").1, Category::FormatString);
        assert_eq!(classify("getenv").1, Category::PathHandling);
        assert_eq!(classify("atoi").1, Category::Conversion);
    }
}
