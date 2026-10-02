//! The executable-analysis sections, rendered into markdown and HTML.
//!
//! These sections (targets, exploit mitigations, PE analysis, DLL search order, native analysis,
//! carving, components and indicators) were written for the text report and reached only the text
//! report. A user running `--format all` got them in `.txt` and got four sections in `.md` and
//! `.html`, which is how a ten-target scan appeared to have no mitigation findings at all: the
//! reader opened the markdown.
//!
//! **Why this renders the text and re-emits it, rather than each section learning three formats.**
//! The alternative is a sink trait adopted by roughly a hundred `writeln!` call sites, which is the
//! right end state and a large change to make while the text output has to stay byte-identical.
//! This gets every section into every format now, at the cost of the bodies being preformatted
//! rather than native tables. The bodies are column-aligned already, so preformatted is honest
//! rather than lazy: the alignment is the layout.
//!
//! What this does add natively is structure. A section's first line is a heading in the source
//! format, so markdown gets `##` anchors and HTML gets `<h2>`, and both are navigable. Only the
//! aligned body stays verbatim.

use anyhow::Result;
use std::io::Write;

use super::{html_escape, RenderOpts};
use crate::model::Report;

/// Render every analysis section to a plain string, exactly as the text report emits them.
///
/// The one place that knows the section order, so text, markdown and HTML cannot drift apart.
fn render(r: &Report, opts: &RenderOpts) -> Result<String> {
    let mut buf: Vec<u8> = Vec::new();
    let w: &mut dyn Write = &mut buf;
    super::targets_section::write_text(w, r)?;
    super::text::write_posture_section(w, r)?;
    super::pe_section::write_text(w, r)?;
    super::pe_section::write_dll_search_text(w, r)?;
    super::pe_section::write_external_imports_text(w, r)?;
    super::exe_section::write_text(w, r)?;
    super::intel_section::write_carve_text(w, r)?;
    super::intel_section::write_intel_text(w, r)?;
    let _ = opts;
    Ok(String::from_utf8(buf)?)
}

/// One section: its heading line and the indented body beneath it.
struct Section<'a> {
    heading: &'a str,
    body: Vec<&'a str>,
}

/// Split the rendered text into sections.
///
/// A section starts at a line with no leading whitespace; everything indented beneath it is that
/// section's body. Blank lines separate sections and are dropped, because each format reintroduces
/// its own spacing.
fn split(text: &str) -> Vec<Section<'_>> {
    let mut out: Vec<Section> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            if let Some(last) = out.last_mut() {
                last.body.push(line);
            }
            // A body line before any heading cannot happen with the current writers, and is
            // dropped rather than guessed at if one ever emits it.
        } else {
            out.push(Section {
                heading: line,
                body: Vec::new(),
            });
        }
    }
    out
}

/// Render just the remediation block, which belongs after Findings rather than with the analysis
/// sections and so is emitted separately by the markdown and HTML writers.
fn render_remediation(r: &Report) -> Result<String> {
    let mut buf: Vec<u8> = Vec::new();
    super::text::write_remediation(&mut buf, r)?;
    Ok(String::from_utf8(buf)?)
}

/// Write the remediation block as markdown.
pub fn write_remediation_markdown(w: &mut dyn Write, r: &Report) -> Result<()> {
    emit_markdown(w, &render_remediation(r)?)
}

/// Write the remediation block as HTML.
pub fn write_remediation_html(w: &mut dyn Write, r: &Report) -> Result<()> {
    emit_html(w, &render_remediation(r)?)
}

/// Write the analysis sections as markdown: a real heading per section, the aligned body fenced.
pub fn write_markdown(w: &mut dyn Write, r: &Report, opts: &RenderOpts) -> Result<()> {
    emit_markdown(w, &render(r, opts)?)
}

fn emit_markdown(w: &mut dyn Write, text: &str) -> Result<()> {
    for s in split(text) {
        // Not `md_cell`: a heading is not a table cell, and escaping its angle brackets would
        // mangle counts like "(10, 1,355 occurrence(s))". Headings here are tool-generated text,
        // never attacker-controlled; every member name and signer reaches the fenced body, which
        // is literal by construction.
        writeln!(w, "## {}\n", s.heading)?;
        if s.body.is_empty() {
            continue;
        }
        writeln!(w, "```text")?;
        for line in &s.body {
            // A fence inside the body would end the block early. Nothing the writers emit starts
            // with a backtick, and a member name that did would be caught here.
            writeln!(w, "{}", line.replace("```", "'''"))?;
        }
        writeln!(w, "```\n")?;
    }
    Ok(())
}

/// Write the analysis sections as HTML, escaping every body line.
pub fn write_html(w: &mut dyn Write, r: &Report, opts: &RenderOpts) -> Result<()> {
    emit_html(w, &render(r, opts)?)
}

fn emit_html(w: &mut dyn Write, text: &str) -> Result<()> {
    for s in split(text) {
        writeln!(w, "<h2>{}</h2>", html_escape(s.heading))?;
        if s.body.is_empty() {
            continue;
        }
        writeln!(w, "<pre class=\"analysis\">")?;
        for line in &s.body {
            // Every one of these can carry attacker-controlled text: a signer Common Name, a
            // member path, a carved description, an IPC pipe name. `html_escape` also neutralises
            // the bidi overrides that `char::is_control` does not cover.
            writeln!(w, "{}", html_escape(line))?;
        }
        writeln!(w, "</pre>")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_heading_starts_a_section_and_indented_lines_are_its_body() {
        let s = split("Coverage\n  members: 3\n  bytes: 10\n\nTargets (2)\n  a\n  b\n");
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].heading, "Coverage");
        assert_eq!(s[0].body, vec!["  members: 3", "  bytes: 10"]);
        assert_eq!(s[1].heading, "Targets (2)");
        assert_eq!(s[1].body.len(), 2);
    }

    #[test]
    fn a_section_with_no_body_still_gets_a_heading() {
        let s = split("Empty\n\nNext\n  x\n");
        assert_eq!(s.len(), 2);
        assert!(s[0].body.is_empty());
    }

    /// The whole point: every section the text report emits must appear in both other formats.
    #[test]
    fn every_section_reaches_markdown_and_html() {
        let mut r = crate::report::tests_support::rich_report();
        r.posture = crate::scan::all_posture(&r.coverage.entries);
        let opts = crate::report::tests_support::opts();

        let text = render(&r, &opts).expect("render");
        let headings: Vec<&str> = split(&text).iter().map(|s| s.heading).collect();
        assert!(
            headings.len() >= 6,
            "the fixture should exercise most sections, got {:?}",
            headings
        );

        let mut md: Vec<u8> = Vec::new();
        write_markdown(&mut md, &r, &opts).expect("markdown");
        let md = String::from_utf8(md).expect("utf8");
        let mut html: Vec<u8> = Vec::new();
        write_html(&mut html, &r, &opts).expect("html");
        let html = String::from_utf8(html).expect("utf8");

        for h in headings {
            assert!(md.contains(h), "markdown lost the {:?} section", h);
            assert!(
                html.contains(&html_escape(h)),
                "HTML lost the {:?} section",
                h
            );
        }
    }

    #[test]
    fn hostile_text_in_a_body_cannot_escape_either_format() {
        let mut r = crate::report::tests_support::rich_report();
        r.posture = crate::scan::all_posture(&r.coverage.entries);
        let opts = crate::report::tests_support::opts();

        let mut html: Vec<u8> = Vec::new();
        write_html(&mut html, &r, &opts).expect("html");
        let html = String::from_utf8(html).expect("utf8");
        assert!(!html.contains("<script>"), "unescaped markup reached HTML");
        assert!(!html.contains('\u{202e}'), "a bidi override reached HTML");

        let mut md: Vec<u8> = Vec::new();
        write_markdown(&mut md, &r, &opts).expect("markdown");
        let md = String::from_utf8(md).expect("utf8");
        // A stray fence in a body would end the code block and let the rest render as markup.
        for block in md.split("```text").skip(1) {
            let body = block.split("```").next().unwrap_or("");
            assert!(
                !body.contains("```"),
                "a fence survived inside a fenced body"
            );
        }
    }
}
