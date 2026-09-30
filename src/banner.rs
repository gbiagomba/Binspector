//! The wordmark, carried over from the v1 shell implementation.
//!
//! The legacy script drew this with `&` in place of `$` so it would survive shell quoting.
//! Rust has no such constraint, so the conventional glyph is restored.
//!
//! Printed to stderr, never stdout. Every output format has to stay machine readable, and
//! a report written to a file must not carry decoration, so the banner cannot share a
//! stream with either.

use std::io::{IsTerminal, Write};

const ART: &[&str] = &[
    r"/$$      /$$$$$$ /$$   /$$  /$$$$$$  /$$$$$$$  /$$$$$$$$  /$$$$$$  /$$$$$$$$ /$$$$$$  /$$$$$$$",
    r"| $$     |_  $$_/| $$$ | $$ /$$__  $$| $$__  $$| $$_____/ /$$__  $$|__  $$__//$$__  $$| $$__  $$",
    r"| $$$$$$$  | $$  | $$$$| $$| $$  \__/| $$  \ $$| $$      | $$  \__/   | $$  | $$  \ $$| $$  \ $$",
    r"| $$__  $$ | $$  | $$ $$ $$|  $$$$$$ | $$$$$$$/| $$$$$   | $$         | $$  | $$  | $$| $$$$$$$/",
    r"| $$  \ $$ | $$  | $$  $$$$ \____  $$| $$____/ | $$__/   | $$         | $$  | $$  | $$| $$__  $$",
    r"| $$  | $$ | $$  | $$\  $$$ /$$  \ $$| $$      | $$      | $$    $$   | $$  | $$  | $$| $$  \ $$",
    r"| $$$$$$$//$$$$$$| $$ \  $$|  $$$$$$/| $$      | $$$$$$$$|  $$$$$$/   | $$  |  $$$$$$/| $$  | $$",
    r"|_______/|______/|__/  \__/ \______/ |__/      |________/ \______/    |__/   \______/ |__/  |__/",
];

/// From the v1 banner. The tool's stated philosophy, and still apt.
pub const EPIGRAPH: &str =
    "Truth is confirmed by inspection and delay; falsehood by haste and uncertainly";
pub const EPIGRAPH_ATTRIBUTION: &str = "Tacitus";

/// The wordmark plus epigraph, as it is shown.
pub fn text() -> String {
    let mut s = String::new();
    for line in ART {
        s.push_str(line);
        s.push('\n');
    }
    s.push('\n');
    s.push_str(&format!("  {}\n  ... {}\n", EPIGRAPH, EPIGRAPH_ATTRIBUTION));
    s
}

/// Show the banner only when a human is watching.
///
/// Suppressed when stderr is redirected, so a captured log stays clean, and suppressed by
/// `--no-banner` for anyone who finds it tiresome.
pub fn print_if_interactive(suppressed: bool) {
    if suppressed || !std::io::stderr().is_terminal() {
        return;
    }
    let _ = write!(std::io::stderr(), "{}", text());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn art_spells_the_name() {
        // Eight rows of a figlet-style wordmark.
        assert_eq!(ART.len(), 8);
        for line in ART {
            assert!(
                line.len() > 80,
                "row too short to be the wordmark: {}",
                line
            );
        }
    }

    #[test]
    fn the_legacy_ampersand_substitution_is_undone() {
        for line in ART {
            assert!(!line.contains('&'), "legacy & survived in: {}", line);
        }
        assert!(ART.iter().any(|l| l.contains('$')));
    }

    #[test]
    fn text_includes_the_epigraph_and_attribution() {
        let t = text();
        assert!(t.contains(EPIGRAPH));
        assert!(t.contains("Tacitus"));
        assert_eq!(t.lines().count(), 8 + 1 + 2);
    }

    #[test]
    fn suppression_is_honoured_without_touching_stderr() {
        // Nothing to assert on the stream itself; this pins that the flag short-circuits.
        print_if_interactive(true);
    }
}
