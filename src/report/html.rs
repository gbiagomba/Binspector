//! Self-contained HTML report.
//!
//! No external assets, so the file works offline and can be attached to a ticket.
//! Colors come from the chosen palette, and every hit also carries a text marker
//! plus bold weight so the report never depends on color alone.

use anyhow::Result;
use std::io::Write;

use super::{html_escape, human_bytes, thousands, RenderOpts};
use crate::cli::color::Theme;
use crate::model::Report;
use crate::scan::banned::Severity;
use crate::spool::SpoolReader;

pub fn write(
    w: &mut dyn Write,
    r: &Report,
    spool: Option<&mut SpoolReader>,
    opts: &RenderOpts,
) -> Result<()> {
    let t = &opts.theme;
    writeln!(w, "<!DOCTYPE html>")?;
    writeln!(w, "<html lang=\"en\"><head><meta charset=\"utf-8\">")?;
    writeln!(
        w,
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
    )?;
    writeln!(w, "<title>Binspector report</title>")?;
    writeln!(w, "<style>{}</style>", style(t))?;
    writeln!(w, "</head><body>")?;
    writeln!(w, "<h1>Binspector report</h1>")?;

    if !opts.matches_only {
        writeln!(w, "<table class=\"meta\">")?;
        row(w, "Binary", &html_escape(&r.binary))?;
        if let Some(p) = &r.project {
            row(w, "Project", &html_escape(p))?;
        }
        row(w, "Scanned", &html_escape(&r.timestamp))?;
        row(
            w,
            "Size",
            &format!(
                "{} ({} bytes)",
                human_bytes(r.file_size),
                thousands(r.file_size)
            ),
        )?;
        row(w, "MD5", &format!("<code>{}</code>", html_escape(&r.md5)))?;
        row(w, "SHA1", &format!("<code>{}</code>", html_escape(&r.sha1)))?;
        row(
            w,
            "SHA256",
            &format!("<code>{}</code>", html_escape(&r.sha256)),
        )?;
        row(
            w,
            "Matching",
            if r.case_sensitive {
                "case sensitive"
            } else {
                "case insensitive"
            },
        )?;
        writeln!(w, "</table>")?;
    }

    let (crit, high, med) = r.severity_counts();
    writeln!(w, "<h2>Findings</h2>")?;
    writeln!(
        w,
        "<p>{} distinct functions, {} occurrences. \
         <span class=\"sev critical\">critical {}</span>, \
         <span class=\"sev high\">high {}</span>, \
         <span class=\"sev medium\">medium {}</span>.</p>",
        thousands(r.summary.len() as u64),
        thousands(r.banned_hit_count as u64),
        thousands(crit as u64),
        thousands(high as u64),
        thousands(med as u64)
    )?;

    if r.summary.is_empty() {
        writeln!(w, "<p>No banned function references found.</p>")?;
        if !r.reached_executable() {
            writeln!(
                w,
                "<p class=\"warn\">Treat this as inconclusive: no executable image was reached \
                 during the scan.</p>"
            )?;
        }
    } else {
        writeln!(
            w,
            "<table><thead><tr><th></th><th>Function</th><th>Severity</th><th>Category</th>\
             <th class=\"num\">Occurrences</th><th class=\"num\">Members</th></tr></thead><tbody>"
        )?;
        for s in &r.summary {
            writeln!(
                w,
                "<tr><td class=\"marker\">{}</td><td><code class=\"{}\">{}</code></td>\
                 <td><span class=\"sev {}\">{}</span></td><td>{}</td>\
                 <td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
                Theme::marker(s.severity),
                sev_class(s.severity),
                html_escape(&s.function),
                sev_class(s.severity),
                s.severity.as_str(),
                s.category.as_str(),
                thousands(s.occurrences as u64),
                s.members
            )?;
        }
        writeln!(w, "</tbody></table>")?;
    }

    if r.low_confidence_total > 0 && !r.include_low_confidence {
        writeln!(w, "<h3>Suppressed as low confidence</h3>")?;
        writeln!(
            w,
            "<p>{} occurrences were whole-token matches inside namespace text or documentation \
             prose, such as <code>System.Windows.Forms</code>, rather than function references. \
             Re-run with <code>--include-low-confidence</code> to report them.</p>",
            thousands(r.low_confidence_total as u64)
        )?;
        writeln!(
            w,
            "<table><thead><tr><th>Function</th><th class=\"num\">Suppressed</th></tr></thead><tbody>"
        )?;
        for (name, n) in &r.low_confidence_top {
            writeln!(
                w,
                "<tr><td><code>{}</code></td><td class=\"num\">{}</td></tr>",
                html_escape(name),
                thousands(*n as u64)
            )?;
        }
        writeln!(w, "</tbody></table>")?;
    }

    if !opts.matches_only {
        writeln!(w, "<h2>Coverage</h2>")?;
        writeln!(
            w,
            "<p>Container format <code>{}</code>, {} members, {} unpacked, {} strings.</p>",
            html_escape(&r.coverage.root_format),
            thousands(r.coverage.members_scanned as u64),
            human_bytes(r.coverage.total_unpacked_bytes),
            thousands(r.strings_total as u64)
        )?;
        writeln!(
            w,
            "<table><thead><tr><th>Member</th><th>Format</th><th class=\"num\">Size</th>\
             <th class=\"num\">Strings</th></tr></thead><tbody>"
        )?;
        let mut entries = r.coverage.entries.clone();
        entries.sort_by_key(|e| std::cmp::Reverse(e.size));
        for e in entries.iter().take(200) {
            writeln!(
                w,
                "<tr><td><code>{}</code></td><td>{}</td><td class=\"num\">{}</td>\
                 <td class=\"num\">{}</td></tr>",
                html_escape(&e.member),
                html_escape(&e.format),
                human_bytes(e.size),
                thousands(e.strings as u64)
            )?;
        }
        writeln!(w, "</tbody></table>")?;

        if !r.warnings.is_empty() {
            writeln!(w, "<h2>Warnings</h2><ul class=\"warn\">")?;
            for warn in &r.warnings {
                writeln!(w, "<li>{}</li>", html_escape(warn))?;
            }
            writeln!(w, "</ul>")?;
        }

        if !r.hits.is_empty() {
            writeln!(w, "<h2>Occurrences</h2>")?;
            for h in &r.hits {
                writeln!(
                    w,
                    "<div class=\"hit\"><span class=\"marker\">{}</span> \
                     <code class=\"{}\">{}</code> in <code>{}</code> at offset \
                     <code>0x{:x}</code> ({})<pre>{}</pre></div>",
                    Theme::marker(h.severity),
                    sev_class(h.severity),
                    html_escape(&h.function),
                    html_escape(&h.member),
                    h.offset,
                    h.encoding.as_str(),
                    highlight_html(&h.context, &[(h.context_start, h.context_end)], h.severity)
                )?;
            }
        }
    }

    if opts.dump {
        if let Some(sp) = spool {
            writeln!(w, "<h2>Full string dump</h2><pre class=\"dump\">")?;
            sp.for_each(|rec| {
                let sev = Severity::Critical;
                let marker = if rec.hits.is_empty() { "   " } else { "!!!" };
                writeln!(
                    w,
                    "{} {} 0x{:x} {}",
                    marker,
                    html_escape(&rec.member),
                    rec.offset,
                    highlight_html(&rec.text, &rec.hits, sev)
                )?;
                Ok(())
            })?;
            writeln!(w, "</pre>")?;
        }
    }

    writeln!(w, "</body></html>")?;
    Ok(())
}

fn row(w: &mut dyn Write, k: &str, v: &str) -> Result<()> {
    writeln!(w, "<tr><th>{}</th><td>{}</td></tr>", html_escape(k), v)?;
    Ok(())
}

fn sev_class(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
    }
}

/// Wrap each hit range in a highlight span. Escaping happens per segment so the
/// span markup is never itself escaped and the text is never left unescaped.
fn highlight_html(text: &str, ranges: &[(usize, usize)], sev: Severity) -> String {
    if ranges.is_empty() {
        return html_escape(text);
    }
    let mut sorted: Vec<(usize, usize)> = ranges.to_vec();
    sorted.sort_unstable();
    let mut out = String::new();
    let mut cursor = 0usize;
    for (s, e) in sorted {
        if s < cursor || e > text.len() || s >= e {
            continue;
        }
        if !text.is_char_boundary(s) || !text.is_char_boundary(e) {
            continue;
        }
        out.push_str(&html_escape(&text[cursor..s]));
        out.push_str(&format!(
            "<mark class=\"{}\">{}</mark>",
            sev_class(sev),
            html_escape(&text[s..e])
        ));
        cursor = e;
    }
    out.push_str(&html_escape(&text[cursor..]));
    out
}

fn style(t: &Theme) -> String {
    format!(
        "
:root {{
  --bg: #ffffff; --fg: #1f2328; --muted: #656d76; --border: #d0d7de; --code-bg: #f6f8fa;
  --critical: {crit}; --high: {high}; --medium: {med};
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --border: #30363d; --code-bg: #161b22;
  }}
}}
* {{ box-sizing: border-box; }}
body {{
  background: var(--bg); color: var(--fg); margin: 0 auto; padding: 24px 16px;
  max-width: 1100px;
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
}}
h1 {{ font-size: 1.6rem; }}
h2 {{ font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid var(--border); padding-bottom: .3rem; }}
code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .88em; }}
code {{ background: var(--code-bg); padding: .1em .35em; border-radius: 4px; }}
pre {{ background: var(--code-bg); padding: .7rem; border-radius: 6px; overflow-x: auto; }}
table {{ border-collapse: collapse; width: 100%; margin: .6rem 0 1rem; }}
th, td {{ border: 1px solid var(--border); padding: .4rem .55rem; text-align: left; vertical-align: top; }}
th {{ background: var(--code-bg); }}
td.num, th.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
table.meta {{ max-width: 720px; }}
table.meta th {{ width: 9rem; }}
.marker {{ font-weight: 700; letter-spacing: -1px; }}
.sev {{ font-weight: 700; }}
.critical {{ color: var(--critical); }}
.high {{ color: var(--high); }}
.medium {{ color: var(--medium); }}
mark {{ background: transparent; font-weight: 700; text-decoration: underline; text-underline-offset: 2px; }}
mark.critical {{ color: var(--critical); }}
mark.high {{ color: var(--high); }}
mark.medium {{ color: var(--medium); }}
.warn {{ color: var(--high); }}
.hit {{ margin: .5rem 0; padding: .5rem .7rem; border-left: 3px solid var(--border); }}
pre.dump {{ max-height: 70vh; overflow: auto; }}
@media (max-width: 600px) {{ body {{ padding: 16px; }} table {{ font-size: .85em; }} }}
",
        crit = t.css(Severity::Critical),
        high = t.css(Severity::High),
        med = t.css(Severity::Medium),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::color::Palette;
    use crate::report::tests_support::{opts, sample_report};

    fn render(r: &Report, o: &RenderOpts) -> String {
        let mut buf = Vec::new();
        write(&mut buf, r, None, o).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn is_self_contained_with_no_external_assets() {
        let out = render(&sample_report(), &opts());
        assert!(out.starts_with("<!DOCTYPE html>"));
        assert!(out.contains("<style>"));
        assert!(!out.contains("http://"));
        assert!(!out.contains("<script"));
        assert!(!out.contains("src="));
    }

    #[test]
    fn supports_light_and_dark_rendering() {
        let out = render(&sample_report(), &opts());
        assert!(out.contains("prefers-color-scheme: dark"));
        assert!(out.contains("--bg:"));
    }

    #[test]
    fn escapes_hostile_strings_from_the_binary() {
        let mut r = sample_report();
        r.hits[0].context = "<script>alert(1)</script>".into();
        r.hits[0].context_start = 0;
        r.hits[0].context_end = 0;
        let out = render(&r, &opts());
        assert!(!out.contains("<script>alert(1)"));
        assert!(out.contains("&lt;script&gt;"));
    }

    #[test]
    fn highlight_does_not_double_escape_markup() {
        let html = highlight_html("a<b>gets</b>c", &[(0, 1)], Severity::Critical);
        assert!(html.contains("<mark class=\"critical\">a</mark>"));
        assert!(html.contains("&lt;b&gt;"));
    }

    #[test]
    fn colorblind_palette_reaches_the_css() {
        let o = RenderOpts {
            theme: Theme::plain(Palette::Colorblind),
            ..opts()
        };
        let out = render(&sample_report(), &o);
        assert!(out.contains("#d55e00"));
        assert!(out.contains("#0072b2"));
    }

    #[test]
    fn marks_use_more_than_color() {
        let out = render(&sample_report(), &opts());
        // Underline plus bold, so the mark survives a monochrome print.
        assert!(out.contains("text-decoration: underline"));
        assert!(out.contains("class=\"marker\">!!!"));
    }
}
