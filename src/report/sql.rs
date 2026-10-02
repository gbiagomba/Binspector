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
  excluded_total INTEGER, include_excluded INTEGER);
CREATE TABLE IF NOT EXISTS summary (
  function TEXT, severity TEXT, category TEXT, occurrences INTEGER, members INTEGER,
  excluded INTEGER);
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
CREATE TABLE IF NOT EXISTS excluded (function TEXT, suppressed INTEGER);
CREATE TABLE IF NOT EXISTS excluded_by_rule (rule TEXT, occurrences INTEGER);
CREATE TABLE IF NOT EXISTS posture (
  id TEXT, title TEXT, severity TEXT, affected INTEGER, members_listed INTEGER,
  members_truncated INTEGER, evidence TEXT, remediation TEXT);
CREATE TABLE IF NOT EXISTS posture_members (id TEXT, member TEXT);
CREATE TABLE IF NOT EXISTS external_imports (
  member TEXT, library TEXT, imports INTEGER, severity TEXT,
  signed INTEGER, restricts_search_path INTEGER);
CREATE INDEX IF NOT EXISTS idx_external_imports_library ON external_imports(library);
CREATE INDEX IF NOT EXISTS idx_posture_members_id ON posture_members(id);
CREATE TABLE IF NOT EXISTS indicators (kind TEXT, value TEXT);
CREATE TABLE IF NOT EXISTS indicators_dropped (kind TEXT, not_collected INTEGER, cap INTEGER);
CREATE INDEX IF NOT EXISTS idx_indicators_kind ON indicators(kind);
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
            sql_literal(&r.tool),
            sql_literal(&r.tool_version),
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
            r.excluded_total,
            r.include_excluded as u8
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
        for (name, n) in &r.excluded_top {
            writeln!(
                w,
                "INSERT INTO excluded VALUES ({},{});",
                sql_literal(name),
                n
            )?;
        }
        // Indicators were in JSON and in the human reports and in neither SQL format, so the one
        // audience that queries this output could not reach them. That matters most for
        // `build_path`: an undeclared statically linked dependency is found by asking for every
        // developer path, which is a query, not a thing to spot while scrolling a report.
        let i = &r.iocs;
        for (kind, values) in [
            ("url", &i.urls),
            ("ip", &i.ips),
            ("email", &i.emails),
            ("registry_key", &i.registry_keys),
            ("file_path", &i.file_paths),
            ("build_path", &i.build_paths),
        ] {
            for v in values {
                writeln!(
                    w,
                    "INSERT INTO indicators VALUES ({},{});",
                    sql_literal(kind),
                    sql_literal(v)
                )?;
            }
        }
        // What was not collected, so a count from this table is never mistaken for a total.
        let d = &i.dropped;
        for (kind, n) in [
            ("url", d.urls),
            ("ip", d.ips),
            ("email", d.emails),
            ("registry_key", d.registry_keys),
            ("file_path", d.file_paths),
            ("build_path", d.build_paths),
        ] {
            if n > 0 {
                writeln!(
                    w,
                    "INSERT INTO indicators_dropped VALUES ({},{},{});",
                    sql_literal(kind),
                    n,
                    i.cap
                )?;
            }
        }

        // The posture findings, which existed only in JSON. A reviewer working from the
        // database, which is what the documentation recommends, silently missed `posture.aslr`:
        // the highest-value output the tool produces and the only one that became a filed
        // finding on its own in a real engagement.
        //
        // `members_truncated` is stored because the stored list is capped and in scan order,
        // and a reader who takes 50 of 179 for the whole set draws a conclusion about one
        // vendor that the full list does not support. That happened and had to be retracted.
        for p in &r.posture {
            writeln!(
                w,
                "INSERT INTO posture VALUES ({},{},{},{},{},{},{},{});",
                sql_literal(&p.id),
                sql_literal(&p.title),
                sql_literal(p.severity.as_str()),
                p.affected,
                p.members.len(),
                (p.affected > p.members.len()) as u8,
                sql_literal(&p.evidence),
                sql_literal(&p.remediation)
            )?;
            for m in &p.members {
                writeln!(
                    w,
                    "INSERT INTO posture_members VALUES ({},{});",
                    sql_literal(&p.id),
                    sql_literal(m)
                )?;
            }
        }

        // One row per (image, missing module), so the obvious question is a one-line query:
        // which images depend on a module nobody ships, and how much of it do they use.
        for e in &r.external_imports {
            for m in &e.modules {
                writeln!(
                    w,
                    "INSERT INTO external_imports VALUES ({},{},{},{},{},{});",
                    sql_literal(&e.member),
                    sql_literal(&m.library),
                    m.imports,
                    sql_literal(e.severity.as_str()),
                    e.signed as u8,
                    e.restricts_search_path as u8
                )?;
            }
        }

        // The table existed and was never filled, so a consumer could not see that 33,334
        // occurrences were suppressed, which is the context that makes the remaining count
        // mean anything.
        for (rule, n) in &r.excluded_by_rule {
            writeln!(
                w,
                "INSERT INTO excluded_by_rule VALUES ({},{});",
                sql_literal(rule),
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
            s.excluded
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
        // Indicators reached JSON and the human reports and neither SQL format, so the audience
        // that queries this output could not ask for them. An undeclared statically linked
        // dependency is found by asking for every developer path, which is a query.
        assert!(out.contains("CREATE TABLE IF NOT EXISTS indicators"));
        assert!(out.contains("CREATE TABLE IF NOT EXISTS indicators_dropped"));
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
    #[test]
    fn indicators_are_emitted_by_kind_with_their_drop_counts() {
        let r = crate::report::tests_support::rich_report();
        let mut buf: Vec<u8> = Vec::new();
        super::write(&mut buf, &r, None, &crate::report::tests_support::opts()).expect("sql");
        let out = String::from_utf8(buf).expect("utf8");
        assert!(
            out.contains("INSERT INTO indicators VALUES ('build_path'"),
            "build paths must be queryable by kind"
        );
        assert!(
            out.contains("INSERT INTO indicators_dropped VALUES ('file_path'"),
            "and what was not collected must be recorded, or a count reads as a total"
        );
    }
}
