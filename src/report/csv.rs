//! CSV output. One row per occurrence, or per string when dumping.
//!
//! 2.0.0 refused CSV unless --matches-only was also given; that restriction is gone.

use anyhow::Result;
use std::io::Write;

use super::{csv_field, RenderOpts};
use crate::model::Report;
use crate::spool::SpoolReader;

pub fn write(
    w: &mut dyn Write,
    r: &Report,
    spool: Option<&mut SpoolReader>,
    opts: &RenderOpts,
) -> Result<()> {
    if opts.matches_only {
        writeln!(w, "function,severity,category,occurrences,members")?;
        for s in &r.summary {
            writeln!(
                w,
                "{},{},{},{},{}",
                csv_field(&s.function),
                s.severity.as_str(),
                s.category.as_str(),
                s.occurrences,
                s.members
            )?;
        }
        return Ok(());
    }

    if opts.dump {
        if let Some(sp) = spool {
            writeln!(w, "member,offset,encoding,hit_count,matched,text")?;
            sp.for_each(|rec| {
                let matched: Vec<&str> = rec
                    .hits
                    .iter()
                    .filter(|(s, e)| *s < *e && *e <= rec.text.len())
                    .map(|(s, e)| &rec.text[*s..*e])
                    .collect();
                writeln!(
                    w,
                    "{},{},{},{},{},{}",
                    csv_field(&rec.member),
                    rec.offset,
                    rec.encoding.as_str(),
                    rec.hits.len(),
                    csv_field(&matched.join(" ")),
                    csv_field(&rec.text)
                )?;
                Ok(())
            })?;
            return Ok(());
        }
    }

    writeln!(
        w,
        "function,severity,category,member,offset,encoding,context"
    )?;
    for h in &r.hits {
        writeln!(
            w,
            "{},{},{},{},{},{},{}",
            csv_field(&h.function),
            h.severity.as_str(),
            h.category.as_str(),
            csv_field(&h.member),
            h.offset,
            h.encoding.as_str(),
            csv_field(&h.context)
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests_support::{opts, sample_report};

    #[test]
    fn full_report_emits_one_row_per_occurrence() {
        let mut buf = Vec::new();
        write(&mut buf, &sample_report(), None, &opts()).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("function,severity,category,member"));
        assert!(lines[1].contains("strcpy"));
        assert!(lines[1].contains("critical"));
    }

    #[test]
    fn matches_only_emits_the_summary() {
        let o = RenderOpts {
            matches_only: true,
            ..opts()
        };
        let mut buf = Vec::new();
        write(&mut buf, &sample_report(), None, &o).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.starts_with("function,severity,category,occurrences,members"));
        assert!(out.contains("strcpy,critical,buffer-overflow,5,2"));
    }

    #[test]
    fn quotes_fields_containing_commas() {
        let mut r = sample_report();
        r.hits[0].context = "a,b,c".into();
        let mut buf = Vec::new();
        write(&mut buf, &r, None, &opts()).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("\"a,b,c\""));
    }
}
