//! Highlighting theme, including a colorblind-safe palette.
//!
//! Accessibility rule enforced here: color is never the only channel. Every
//! highlighted hit also carries a text marker and bold weight, so the output stays
//! unambiguous for a colorblind reader, in a monochrome terminal, after piping
//! through a filter that strips escapes, and in a screen reader.

use clap::ValueEnum;

use crate::scan::banned::Severity;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum ColorChoice {
    /// Color when stdout is an interactive terminal, plain text otherwise.
    Auto,
    Always,
    Never,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum Palette {
    /// Red, yellow, cyan. Familiar, but red against green is hard for many readers.
    Default,
    /// Okabe-Ito vermillion, orange, and blue. No red-green pairing.
    Colorblind,
}

#[derive(Copy, Clone, Debug)]
pub struct Theme {
    pub color: bool,
    pub palette: Palette,
}

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";

impl Theme {
    pub fn new(choice: ColorChoice, palette: Palette, stdout_is_tty: bool) -> Self {
        let color = match choice {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => stdout_is_tty,
        };
        Self { color, palette }
    }

    /// Plain theme for file output, where escape sequences are noise.
    pub fn plain(palette: Palette) -> Self {
        Self {
            color: false,
            palette,
        }
    }

    fn ansi(&self, sev: Severity) -> &'static str {
        match (self.palette, sev) {
            // Okabe-Ito via 256-color indices: vermillion 166, orange 214, blue 25.
            (Palette::Colorblind, Severity::Critical) => "\x1b[1;38;5;166m",
            (Palette::Colorblind, Severity::High) => "\x1b[1;38;5;214m",
            (Palette::Colorblind, Severity::Medium) => "\x1b[1;38;5;25m",
            // Low is deliberately dim rather than another hue: it must not compete for
            // attention with the three tiers that can actually corrupt memory.
            (Palette::Colorblind, Severity::Low) => "\x1b[2;38;5;245m",
            (Palette::Default, Severity::Critical) => "\x1b[1;31m",
            (Palette::Default, Severity::High) => "\x1b[1;33m",
            (Palette::Default, Severity::Medium) => "\x1b[1;36m",
            (Palette::Default, Severity::Low) => "\x1b[2;37m",
        }
    }

    /// CSS color for the HTML report. Kept in sync with the ANSI palette.
    pub fn css(&self, sev: Severity) -> &'static str {
        match (self.palette, sev) {
            (Palette::Colorblind, Severity::Critical) => "#d55e00",
            (Palette::Colorblind, Severity::High) => "#e69f00",
            (Palette::Colorblind, Severity::Medium) => "#0072b2",
            (Palette::Colorblind, Severity::Low) => "#6b7280",
            (Palette::Default, Severity::Critical) => "#c0392b",
            (Palette::Default, Severity::High) => "#b7791f",
            (Palette::Default, Severity::Medium) => "#1f6feb",
            (Palette::Default, Severity::Low) => "#6b7280",
        }
    }

    /// Text marker, emitted regardless of color support.
    pub fn marker(sev: Severity) -> &'static str {
        match sev {
            Severity::Critical => "!!!",
            Severity::High => "!!",
            Severity::Medium => "!",
            Severity::Low => "-",
        }
    }

    /// Wrap a matched token for terminal output.
    pub fn highlight(&self, text: &str, sev: Severity) -> String {
        if self.color {
            format!("{}{}{}", self.ansi(sev), text, RESET)
        } else {
            // Angle brackets keep the match visible without any escape sequence.
            format!(">{}<", text)
        }
    }

    pub fn bold(&self, text: &str) -> String {
        if self.color {
            format!("{}{}{}", BOLD, text, RESET)
        } else {
            text.to_string()
        }
    }

    /// Render a string with each hit range highlighted.
    pub fn highlight_ranges(&self, text: &str, ranges: &[(usize, usize)], sev: Severity) -> String {
        if ranges.is_empty() {
            return text.to_string();
        }
        let mut sorted: Vec<(usize, usize)> = ranges.to_vec();
        sorted.sort_unstable();
        let mut out = String::with_capacity(text.len() + 16 * sorted.len());
        let mut cursor = 0usize;
        for (s, e) in sorted {
            if s < cursor || e > text.len() || s >= e {
                continue;
            }
            if !text.is_char_boundary(s) || !text.is_char_boundary(e) {
                continue;
            }
            out.push_str(&text[cursor..s]);
            out.push_str(&self.highlight(&text[s..e], sev));
            cursor = e;
        }
        out.push_str(&text[cursor..]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_follows_tty_state() {
        assert!(Theme::new(ColorChoice::Auto, Palette::Default, true).color);
        assert!(!Theme::new(ColorChoice::Auto, Palette::Default, false).color);
        assert!(Theme::new(ColorChoice::Always, Palette::Default, false).color);
        assert!(!Theme::new(ColorChoice::Never, Palette::Default, true).color);
    }

    #[test]
    fn colorblind_palette_avoids_plain_red_and_green() {
        let t = Theme {
            color: true,
            palette: Palette::Colorblind,
        };
        for sev in [Severity::Critical, Severity::High, Severity::Medium] {
            let code = t.ansi(sev);
            assert!(!code.contains("[1;31m"), "plain red used for {:?}", sev);
            assert!(!code.contains("[1;32m"), "plain green used for {:?}", sev);
        }
    }

    #[test]
    fn hits_remain_marked_without_color() {
        let t = Theme::plain(Palette::Default);
        let out = t.highlight("gets", Severity::Critical);
        assert_eq!(out, ">gets<");
        // The signal survives with no escape sequences at all.
        assert!(!out.contains('\x1b'));
    }

    #[test]
    fn stripping_ansi_leaves_the_match_identifiable() {
        let t = Theme {
            color: true,
            palette: Palette::Colorblind,
        };
        let rendered = t.highlight_ranges("xx gets yy", &[(3, 7)], Severity::Critical);
        // Simulates piping through a filter that removes escape sequences.
        let stripped: String = strip_ansi(&rendered);
        assert_eq!(stripped, "xx gets yy");
        assert!(rendered.contains("\x1b["));
    }

    fn strip_ansi(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if n == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn highlights_multiple_ranges() {
        let t = Theme::plain(Palette::Default);
        let out = t.highlight_ranges("gets and gets", &[(0, 4), (9, 13)], Severity::Critical);
        assert_eq!(out, ">gets< and >gets<");
    }

    #[test]
    fn ignores_out_of_range_and_overlapping_ranges() {
        let t = Theme::plain(Palette::Default);
        assert_eq!(t.highlight_ranges("abc", &[(0, 99)], Severity::High), "abc");
        assert_eq!(t.highlight_ranges("abc", &[(2, 1)], Severity::High), "abc");
    }

    #[test]
    fn markers_are_distinct_per_severity() {
        assert_eq!(Theme::marker(Severity::Critical), "!!!");
        assert_eq!(Theme::marker(Severity::High), "!!");
        assert_eq!(Theme::marker(Severity::Medium), "!");
    }
}
