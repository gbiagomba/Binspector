//! Binary SQLite report, behind the `sqlite` cargo feature.
//!
//! The schema matches `report::sql`, so a consumer can read either form.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::Path;

use super::RenderOpts;
use crate::model::Report;
use crate::spool::SpoolReader;

pub fn write(
    path: &Path,
    r: &Report,
    spool: Option<&mut SpoolReader>,
    opts: &RenderOpts,
) -> Result<()> {
    // A stale database would silently mix two scans together.
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("replacing existing {}", path.display()))?;
    }
    let mut conn = Connection::open(path)
        .with_context(|| format!("opening sqlite database {}", path.display()))?;
    conn.execute_batch(super::sql::SCHEMA)?;

    let tx = conn.transaction()?;
    if !opts.matches_only {
        tx.execute(
            "INSERT INTO scan VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                r.tool,
                r.tool_version,
                r.binary,
                r.project,
                r.timestamp,
                r.file_size as i64,
                r.md5,
                r.sha1,
                r.sha256,
                r.min_len as i64,
                r.case_sensitive as i64,
                r.banned_list_size as i64,
                r.strings_total as i64,
                r.banned_hit_count as i64,
                r.coverage.root_format,
                r.coverage.members_scanned as i64,
                r.coverage.total_unpacked_bytes as i64,
                r.reached_executable() as i64,
                r.excluded_total as i64,
                r.include_excluded as i64,
            ],
        )?;
        // Prepared once and reused per row, rather than `execute` re-preparing the same statement
        // 50,000 times. Binding is what makes this injection-proof; preparing once is what makes it
        // fast, and a member name is attacker-controlled on both counts.
        {
            let mut st = tx.prepare("INSERT INTO coverage VALUES (?,?,?,?,?)")?;
            for e in &r.coverage.entries {
                st.execute(params![
                    e.member,
                    e.format,
                    e.size as i64,
                    e.strings as i64,
                    e.vendor
                ])?;
            }
        }
        for warn in &r.warnings {
            tx.execute("INSERT INTO warnings VALUES (?)", params![warn])?;
        }
        for (name, n) in &r.excluded_top {
            tx.execute(
                "INSERT INTO excluded VALUES (?,?)",
                params![name, *n as i64],
            )?;
        }
        // Mirrors `sql::write`, so the dump and the database answer the same queries. The schema
        // is shared, so a table added there and not populated here would be silently empty.
        let i = &r.iocs;
        for (kind, values) in [
            ("url", &i.urls),
            ("ip", &i.ips),
            ("email", &i.emails),
            ("registry_key", &i.registry_keys),
            ("file_path", &i.file_paths),
            ("build_path", &i.build_paths),
        ] {
            let mut st = tx.prepare("INSERT INTO indicators VALUES (?,?)")?;
            for v in values {
                st.execute(params![kind, v])?;
            }
        }
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
                tx.execute(
                    "INSERT INTO indicators_dropped VALUES (?,?,?)",
                    params![kind, n as i64, i.cap as i64],
                )?;
            }
        }
        // See sql.rs for why these two exist: the posture findings were JSON-only, and the
        // `excluded_by_rule` table was created and never filled.
        for p in &r.posture {
            tx.execute(
                "INSERT INTO posture VALUES (?,?,?,?,?,?,?,?)",
                params![
                    p.id,
                    p.title,
                    p.severity.as_str(),
                    p.affected as i64,
                    p.members.len() as i64,
                    (p.affected > p.members.len()) as i64,
                    p.evidence,
                    p.remediation
                ],
            )?;
            let mut st = tx.prepare("INSERT INTO posture_members VALUES (?,?)")?;
            for m in &p.members {
                st.execute(params![p.id, m])?;
            }
        }
        // Intel, which reached neither SQL export until 6.0.0. See sql.rs for why `scope` separates
        // a target verdict from a member one.
        {
            let mut st = tx.prepare("INSERT INTO reputation VALUES (?,?,?,?,?,?,?)")?;
            let empty = Vec::new();
            for (scope, reps) in [
                ("target", &r.intel.reputation),
                (
                    "member",
                    r.intel.sweep.as_ref().map(|s| &s.results).unwrap_or(&empty),
                ),
            ] {
                for rep in reps {
                    for (service, v) in [
                        ("virustotal", &rep.virustotal),
                        ("metadefender", &rep.metadefender),
                    ] {
                        let (kind, det, eng) = super::sql::verdict_columns(v);
                        st.execute(params![
                            scope,
                            rep.label,
                            rep.sha256,
                            service,
                            kind,
                            det.map(i64::from),
                            eng.map(i64::from)
                        ])?;
                    }
                }
            }
        }
        if let Some(sw) = r.intel.sweep.as_ref() {
            tx.execute(
                "INSERT INTO reputation_coverage VALUES (?,?,?,?)",
                params![
                    sw.candidates as i64,
                    sw.queried as i64,
                    sw.from_cache as i64,
                    sw.unchecked as i64
                ],
            )?;
        }
        {
            let mut st = tx.prepare("INSERT INTO components VALUES (?,?,?)")?;
            for c in &r.intel.components {
                st.execute(params![c.name, c.version, c.evidence])?;
            }
        }
        if let Some(cves) = r.intel.cves.as_ref() {
            let mut st = tx.prepare("INSERT INTO cves VALUES (?,?,?,?,?,?,?)")?;
            for c in &cves.components {
                if c.cves.is_empty() {
                    // One row carrying the error, so a query cannot read an absent row as "no CVEs".
                    st.execute(params![
                        c.component.name,
                        c.component.version,
                        None::<String>,
                        None::<f64>,
                        None::<String>,
                        None::<String>,
                        c.error
                    ])?;
                    continue;
                }
                for v in &c.cves {
                    st.execute(params![
                        c.component.name,
                        c.component.version,
                        v.id,
                        v.cvss,
                        v.severity,
                        v.url,
                        None::<String>
                    ])?;
                }
            }
        }
        {
            let mut st = tx.prepare("INSERT INTO member_digests VALUES (?,?,?,?,?,?,?)")?;
            for e in &r.coverage.entries {
                let Some(d) = e.digests.as_ref() else {
                    continue;
                };
                st.execute(params![
                    e.member,
                    d.md5,
                    d.sha1,
                    d.sha256,
                    e.size as i64,
                    e.format,
                    e.copies as i64
                ])?;
            }
        }
        for e in &r.coverage.entries {
            let Some(p) = e.pdb.as_ref() else { continue };
            // Keyed on (root, component), not the root alone. One tree legitimately appears
            // twice when it contributes both a component's objects and its own: the XMP toolkit
            // tree supplies 8 zlib objects and 120 of its own, and marking by root flagged all
            // 128 as part of the mixed-source finding.
            let mixed: std::collections::BTreeSet<(&str, Option<&str>)> = p
                .mixed
                .iter()
                .flat_map(|m| {
                    m.roots
                        .iter()
                        .map(|x| (x.root.as_str(), x.component.as_deref()))
                })
                .collect();
            for root in &p.roots {
                tx.execute(
                    "INSERT INTO pdb_source_roots VALUES (?,?,?,?,?,?)",
                    params![
                        e.member,
                        p.image_stem,
                        root.root,
                        root.objects as i64,
                        root.component,
                        mixed.contains(&(root.root.as_str(), root.component.as_deref())) as i64
                    ],
                )?;
            }
        }
        for e in &r.external_imports {
            for m in &e.modules {
                tx.execute(
                    "INSERT INTO external_imports VALUES (?,?,?,?,?,?)",
                    params![
                        e.member,
                        m.library,
                        m.imports as i64,
                        e.severity.as_str(),
                        e.signed as i64,
                        e.restricts_search_path as i64
                    ],
                )?;
            }
        }
        for (rule, n) in &r.excluded_by_rule {
            tx.execute(
                "INSERT INTO excluded_by_rule VALUES (?,?)",
                params![rule, *n as i64],
            )?;
        }
        // The largest table in the database: up to `--max-hits` rows, default 100,000.
        {
            let mut st = tx.prepare("INSERT INTO hits VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")?;
            for h in &r.hits {
                st.execute(params![
                    h.function,
                    h.severity.as_str(),
                    h.category.as_str(),
                    h.member,
                    h.offset as i64,
                    h.token_len as i64,
                    h.string_offset as i64,
                    h.encoding.as_str(),
                    h.confidence.as_str(),
                    h.context,
                    h.context_start as i64,
                    h.context_end as i64,
                    h.vendor,
                ])?;
            }
        }
    }
    for s in &r.summary {
        tx.execute(
            "INSERT INTO summary VALUES (?,?,?,?,?,?)",
            params![
                s.function,
                s.severity.as_str(),
                s.category.as_str(),
                s.occurrences as i64,
                s.members as i64,
                s.excluded as i64
            ],
        )?;
    }
    tx.commit()?;

    if opts.dump {
        if let Some(sp) = spool {
            let tx = conn.transaction()?;
            {
                let mut stmt = tx.prepare("INSERT INTO strings VALUES (?,?,?,?,?)")?;
                sp.for_each(|rec| {
                    stmt.execute(params![
                        rec.member,
                        rec.offset as i64,
                        rec.encoding.as_str(),
                        rec.hits.len() as i64,
                        rec.text
                    ])?;
                    Ok(())
                })?;
            }
            tx.commit()?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests_support::{opts, sample_report};

    #[test]
    fn writes_a_queryable_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.sqlite");
        write(&path, &sample_report(), None, &opts()).unwrap();

        let conn = Connection::open(&path).unwrap();
        let func: String = conn
            .query_row("SELECT function FROM summary LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(func, "strcpy");
        let hits: i64 = conn
            .query_row("SELECT COUNT(*) FROM hits", [], |r| r.get(0))
            .unwrap();
        assert_eq!(hits, 1);
        let sha: String = conn
            .query_row("SELECT sha256 FROM scan", [], |r| r.get(0))
            .unwrap();
        assert!(sha.starts_with("01234567"));
    }

    #[test]
    fn replaces_an_existing_database_instead_of_appending() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.sqlite");
        write(&path, &sample_report(), None, &opts()).unwrap();
        write(&path, &sample_report(), None, &opts()).unwrap();
        let conn = Connection::open(&path).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM summary", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "second scan must not accumulate rows");
    }

    /// Load the portable `.sql` dump of a hostile report into a real database.
    ///
    /// This is the test that matters for the text writer. `sqlite::write` binds every value, so it is
    /// injection-proof by construction and nothing here can change that. `sql::write` emits SQL text
    /// for another tool to execute, so its only defence is `sql_literal`, and the only way to know
    /// that holds is to run the output through SQLite and see whether the tables are still there.
    #[test]
    fn a_hostile_sql_dump_loads_with_every_table_intact() {
        use crate::report::tests_support::{opts, rich_report};
        let r = rich_report();
        // The fixture carries a member named `'); DROP TABLE hits;--` plus a NUL and an escape.
        assert!(
            r.coverage
                .entries
                .iter()
                .any(|e| e.member.contains("DROP TABLE")),
            "the fixture must carry the hostile name for this to mean anything"
        );

        let mut dump = Vec::new();
        crate::report::sql::write(&mut dump, &r, None, &opts()).expect("dump written");
        let dump = String::from_utf8(dump).expect("utf-8");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("loaded.sqlite");
        let conn = Connection::open(&path).unwrap();
        // Exactly what a reviewer following the documentation does: feed the dump to SQLite.
        conn.execute_batch(&dump)
            .expect("a hostile report's dump must still be loadable");

        // Every table the dump creates is still present and queryable. A successful injection
        // would have dropped one of these.
        for table in [
            "scan",
            "summary",
            "hits",
            "coverage",
            "member_digests",
            "warnings",
            "excluded",
            "excluded_by_rule",
            "posture",
            "posture_members",
            "indicators",
            "reputation",
            "reputation_coverage",
            "components",
            "cves",
            "pdb_source_roots",
            "external_imports",
        ] {
            let n: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {}", table), [], |r| r.get(0))
                .unwrap_or_else(|e| panic!("{} is gone or unreadable: {}", table, e));
            assert!(n >= 0);
        }

        // And the hostile name round-tripped as data rather than as syntax.
        let stored: i64 = conn
            .query_row(
                "SELECT count(*) FROM member_digests WHERE member LIKE ?",
                ["%DROP TABLE%"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, 1, "the name is stored, not executed");

        // The name round-tripped verbatim, quotes and all, rather than being mangled by the escape
        // or truncated by it. An escape that is too eager is its own bug.
        let name: String = conn
            .query_row(
                "SELECT member FROM member_digests WHERE member LIKE ?",
                ["%DROP TABLE%"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            name,
            crate::report::fixtures::HOSTILE_MEMBER,
            "the name must survive the round trip unchanged"
        );
    }

    #[test]
    fn intel_reaches_the_database_at_all() {
        // It reached neither SQL export before 6.0.0, so a reviewer working from the database the
        // documentation recommends silently missed every component, CVE and verdict.
        use crate::report::tests_support::{opts, rich_report};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("intel.sqlite");
        write(&path, &rich_report(), None, &opts()).unwrap();
        let conn = Connection::open(&path).unwrap();

        let count = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        assert!(count("SELECT count(*) FROM components") > 0, "components");
        assert!(count("SELECT count(*) FROM cves") > 0, "cves");
        // A target verdict and a member verdict are separate scopes: conflating them would report a
        // package as flagged because one member inside it was.
        assert!(
            count("SELECT count(*) FROM reputation WHERE scope = 'target'") > 0,
            "target verdicts"
        );
        assert!(
            count("SELECT count(*) FROM reputation WHERE scope = 'member'") > 0,
            "member verdicts"
        );
        // The denominator, so a query cannot mistake "not asked" for "came back clean".
        let unchecked: i64 = conn
            .query_row("SELECT unchecked FROM reputation_coverage", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(unchecked > 0, "the fixture sweep ran out of budget");
    }
}
