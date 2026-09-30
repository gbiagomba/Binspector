//! Portable SQL dump. Loadable by any SQLite client with `.read file.sql`.
//!
//! Needs no extra dependency, so it is the always-available alternative to the
//! binary `sqlite` format.

use anyhow::Result;
use std::io::Write;

use super::{sql_literal, RenderOpts};
use crate::model::Report;
use crate::spool::SpoolReader;

pub const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS scan (
  id INTEGER PRIMARY KEY, tool TEXT, tool_version TEXT, binary TEXT, project TEXT,
  timestamp TEXT, file_size INTEGER, md5 TEXT, sha1 TEXT, sha256 TEXT,
  min_len INTEGER, case_sensitive INTEGER, banned_list_size INTEGER,
  strings_total INTEGER, banned_hit_count INTEGER, root_format TEXT,
  members_scanned INTEGER, total_unpacked_bytes INTEGER, reached_executable INTEGER,
  low_confidence_total INTEGER, include_low_confidence INTEGER);
CREATE TABLE IF NOT EXISTS summary (
  function TEXT, severity TEXT, category TEXT, occurrences INTEGER, members INTEGER,
  low_confidence INTEGER);
CREATE TABLE IF NOT EXISTS hits (
  function TEXT, severity TEXT, category TEXT, member TEXT, offset INTEGER,
  token_len INTEGER, string_offset INTEGER, encoding TEXT, confidence TEXT,
  context TEXT, context_start INTEGER, context_end INTEGER);
CREATE TABLE IF NOT EXISTS coverage (
  member TEXT, format TEXT, size INTEGER, strings INTEGER);
CREATE TABLE IF NOT EXISTS warnings (message TEXT);
CREATE TABLE IF NOT EXISTS strings (
  member TEXT, offset INTEGER, encoding TEXT, hit_count INTEGER, text TEXT);
CREATE INDEX IF NOT EXISTS idx_hits_function ON hits(function);
CREATE INDEX IF NOT EXISTS idx_hits_severity ON hits(severity);
CREATE INDEX IF NOT EXISTS idx_hits_confidence ON hits(confidence);
CREATE TABLE IF NOT EXISTS low_confidence (function TEXT, suppressed INTEGER);
";

pub fn write(
    w: &mut dyn Write,
    r: &Report,
    spool: Option<&mut SpoolReader>,
    opts: &RenderOpts,
) -> Result<()> {
    writeln!(w, "BEGIN TRANSACTION;")?;
    w.write_all(SCHEMA.as_bytes())?;

    if !opts.matches_only {
        writeln!(
            w,
            "INSERT INTO scan VALUES (1,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{});",
            sql_literal(r.tool),
            sql_literal(r.tool_version),
            sql_literal(&r.binary),
            r.project
                .as_deref()
                .map(sql_literal)
                .unwrap_or_else(|| "NULL".into()),
            sql_literal(&r.timestamp),
            r.file_size,
            sql_literal(&r.md5),
            sql_literal(&r.sha1),
            sql_literal(&r.sha256),
            r.min_len,
            r.case_sensitive as u8,
            r.banned_list_size,
            r.strings_total,
            r.banned_hit_count,
            sql_literal(&r.coverage.root_format),
            r.coverage.members_scanned,
            r.coverage.total_unpacked_bytes,
            r.reached_executable() as u8,
            r.low_confidence_total,
            r.include_low_confidence as u8
        )?;
        for e in &r.coverage.entries {
            writeln!(
                w,
                "INSERT INTO coverage VALUES ({},{},{},{});",
                sql_literal(&e.member),
                sql_literal(&e.format),
                e.size,
                e.strings
            )?;
        }
        for warn in &r.warnings {
            writeln!(w, "INSERT INTO warnings VALUES ({});", sql_literal(warn))?;
        }
        for (name, n) in &r.low_confidence_top {
            writeln!(
                w,
                "INSERT INTO low_confidence VALUES ({},{});",
                sql_literal(name),
                n
            )?;
        }
    }

    for s in &r.summary {
        writeln!(
            w,
            "INSERT INTO summary VALUES ({},{},{},{},{},{});",
            sql_literal(&s.function),
            sql_literal(s.severity.as_str()),
            sql_literal(s.category.as_str()),
            s.occurrences,
            s.members,
            s.low_confidence
        )?;
    }

    if !opts.matches_only {
        for h in &r.hits {
            writeln!(
                w,
                "INSERT INTO hits VALUES ({},{},{},{},{},{},{},{},{},{},{},{});",
                sql_literal(&h.function),
                sql_literal(h.severity.as_str()),
                sql_literal(h.category.as_str()),
                sql_literal(&h.member),
                h.offset,
                h.token_len,
                h.string_offset,
                sql_literal(h.encoding.as_str()),
                sql_literal(h.confidence.as_str()),
                sql_literal(&h.context),
                h.context_start,
                h.context_end
            )?;
        }
    }

    if opts.dump {
        if let Some(sp) = spool {
            sp.for_each(|rec| {
                writeln!(
                    w,
                    "INSERT INTO strings VALUES ({},{},{},{},{});",
                    sql_literal(&rec.member),
                    rec.offset,
                    sql_literal(rec.encoding.as_str()),
                    rec.hits.len(),
                    sql_literal(&rec.text)
                )?;
                Ok(())
            })?;
        }
    }

    writeln!(w, "COMMIT;")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests_support::{opts, sample_report};

    fn render(r: &Report, o: &RenderOpts) -> String {
        let mut buf = Vec::new();
        write(&mut buf, r, None, o).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn emits_schema_and_transaction() {
        let out = render(&sample_report(), &opts());
        assert!(out.starts_with("BEGIN TRANSACTION;"));
        assert!(out.contains("CREATE TABLE IF NOT EXISTS hits"));
        assert!(out.trim_end().ends_with("COMMIT;"));
    }

    #[test]
    fn inserts_scan_summary_and_hits() {
        let out = render(&sample_report(), &opts());
        assert!(out.contains("INSERT INTO scan VALUES (1,'binspector'"));
        assert!(out.contains("INSERT INTO summary VALUES ('strcpy','critical'"));
        assert!(out.contains("INSERT INTO hits VALUES ('strcpy'"));
        assert!(out.contains("INSERT INTO coverage VALUES"));
    }

    #[test]
    fn escapes_quotes_so_hostile_strings_stay_inert() {
        let mut r = sample_report();
        r.hits[0].context = "'); DROP TABLE hits;--".into();
        let out = render(&r, &opts());
        assert!(out.contains("'''); DROP TABLE hits;--'"));
        assert!(!out.contains("); DROP TABLE hits;--');"));
    }

    #[test]
    fn null_project_is_emitted_as_sql_null() {
        let mut r = sample_report();
        r.project = None;
        let out = render(&r, &opts());
        assert!(out.contains(",NULL,"));
    }
}
