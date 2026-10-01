//! Golden-file tests: the refactor safety net.
//!
//! Why these exist, stated plainly because the gap they close was embarrassing. Every
//! executable-analysis section (mitigations, certificates, DLL search order, native analysis, CRT
//! surface, IPC, carving, components, indicators, targets) was rendered **only** by the text writer,
//! and no test noticed for three releases. `tests_support::sample_report` leaves `pe: None`, no
//! targets, `carve_ran: false` and default intel, so not one of those sections executed under test;
//! `pe_section`'s own test asserts the buffer comes back empty.
//!
//! So two things are locked down here before any of that code is touched:
//!
//! 1. **The text output cannot change.** A golden blessed from the pre-refactor binary is the
//!    contract. Byte equality, not a substring check.
//! 2. **Every section must reach every human format.** `NOT_YET_PORTED` is the list of sections
//!    text still renders alone; each migration step deletes an entry, and the constant goes away
//!    when the last one does. This is the test that would have caught the original defect.
//!
//! Blessing: `BINSPECTOR_BLESS=1 cargo test --lib golden`. Deliberately an environment variable
//! and a hand-rolled comparison rather than a snapshot crate, because the project takes no
//! dependency it can avoid.

use std::path::PathBuf;

use super::tests_support::{opts, rich_report};
use super::OutputFormat;
use crate::model::Report;

/// Sections that exist in the text report and nowhere else yet.
///
/// Shrinks by one entry per migration step. When it is empty the parity test is complete and this
/// constant, along with the allowance in `every_section_reaches_every_format`, is deleted.
const NOT_YET_PORTED: &[&str] = &[];

/// Section headings that must appear in text, markdown and HTML once porting is done.
const SECTIONS: &[&str] = &[
    "Targets",
    "Exploit mitigations",
    "Executable analysis",
    "DLL search order",
    "Native analysis",
    "Carving",
    "Third-party components",
    "Indicators",
    "Build provenance",
    "Findings",
    "Coverage",
    "Occurrences",
];

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

/// The report every golden is rendered from: the rich fixture with real posture findings computed
/// by the production rules, so the fixture cannot drift from them.
fn report() -> Report {
    let mut r = rich_report();
    r.posture = crate::scan::all_posture(&r.coverage.entries);
    r
}

fn render(fmt: OutputFormat) -> String {
    let r = report();
    let mut buf: Vec<u8> = Vec::new();
    super::render(fmt, &mut buf, &r, None, &opts()).expect("render");
    String::from_utf8(buf).expect("utf8")
}

/// Compare against the committed golden, or write it when blessing.
fn check(name: &str, actual: &str) {
    let path = golden_dir().join(name);
    if std::env::var_os("BINSPECTOR_BLESS").is_some() {
        std::fs::create_dir_all(golden_dir()).expect("golden dir");
        std::fs::write(&path, actual).expect("write golden");
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{} is missing ({e}). Bless it with BINSPECTOR_BLESS=1 cargo test --lib golden",
            path.display()
        )
    });
    if expected != actual {
        // Point at the first differing line rather than dumping two whole reports.
        let (mut line, mut col) = (1usize, 0usize);
        for (a, b) in expected.chars().zip(actual.chars()) {
            if a != b {
                break;
            }
            if a == '\n' {
                line += 1;
                col = 0;
            } else {
                col += 1;
            }
        }
        let got = actual.lines().nth(line - 1).unwrap_or("<past end>");
        let want = expected.lines().nth(line - 1).unwrap_or("<past end>");
        panic!(
            "{} differs at line {} col {}\n  expected: {:?}\n  actual:   {:?}\n\
             Re-bless only if the change is intended: BINSPECTOR_BLESS=1 cargo test --lib golden",
            path.display(),
            line,
            col,
            want,
            got
        );
    }
}

#[test]
fn text_output_is_unchanged() {
    check("rich_report.txt", &render(OutputFormat::Text));
}

#[test]
fn markdown_output_is_unchanged() {
    check("rich_report.md", &render(OutputFormat::Markdown));
}

#[test]
fn html_output_is_unchanged() {
    check("rich_report.html", &render(OutputFormat::Html));
}

#[test]
fn every_section_reaches_every_format() {
    let t = render(OutputFormat::Text);
    let m = render(OutputFormat::Markdown);
    let h = render(OutputFormat::Html);

    for section in SECTIONS {
        assert!(
            t.contains(section),
            "the text report lost the {} section",
            section
        );
        if NOT_YET_PORTED.contains(section) {
            continue;
        }
        assert!(
            m.contains(section),
            "{} is in text but not markdown; delete it from NOT_YET_PORTED only once it is",
            section
        );
        assert!(
            h.contains(section),
            "{} is in text but not HTML; delete it from NOT_YET_PORTED only once it is",
            section
        );
    }
}

/// The text report is read in a terminal and diffed between runs, so trailing whitespace is a
/// defect. It is also the failure mode a padded final table column introduces, which is why the
/// last column of every table must declare width 0.
#[test]
fn no_text_line_ends_in_whitespace() {
    for (n, line) in render(OutputFormat::Text).lines().enumerate() {
        assert_eq!(
            line.trim_end(),
            line,
            "line {} ends in whitespace: {:?}",
            n + 1,
            line
        );
    }
}

/// `opts()` builds a plain theme, so a golden must never contain an escape sequence. A colour leak
/// here would mean colour is being decided somewhere other than the theme.
#[test]
fn no_golden_carries_ansi() {
    for fmt in [
        OutputFormat::Text,
        OutputFormat::Markdown,
        OutputFormat::Html,
    ] {
        assert!(
            !render(fmt).contains('\x1b'),
            "{} output carries an escape sequence under a plain theme",
            fmt.name()
        );
    }
}

/// The fixture plants `<script>` and a bidi override in a signer Common Name, a pipe name, a carved
/// description and a component name. Those strings come from hostile binaries, and under the format
/// parity work they reach HTML and Markdown for the first time.
#[test]
fn hostile_text_is_escaped_in_html() {
    let h = render(OutputFormat::Html);
    assert!(
        !h.contains("<script>"),
        "an unescaped <script> reached the HTML report"
    );
    assert!(
        !h.contains('\u{202e}'),
        "a bidi override reached the HTML report, where it reorders the glyphs after it"
    );
}

#[test]
fn hostile_text_cannot_break_a_markdown_table() {
    let m = render(OutputFormat::Markdown);
    for line in m.lines() {
        // Only table rows matter, and an escaped pipe is `\|`.
        if !line.starts_with('|') {
            continue;
        }
        let raw = line.replace("\\|", "");
        assert!(
            !raw.contains("<script>"),
            "an unescaped <script> reached a markdown table row: {:?}",
            line
        );
    }
    assert!(
        !m.contains('\u{202e}'),
        "a bidi override reached the markdown report"
    );
}
