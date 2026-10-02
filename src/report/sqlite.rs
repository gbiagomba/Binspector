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
        for e in &r.coverage.entries {
            tx.execute(
                "INSERT INTO coverage VALUES (?,?,?,?,?)",
                params![
                    e.member,
                    e.format,
                    e.size as i64,
                    e.strings as i64,
                    e.vendor
                ],
            )?;
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
            for v in values {
                tx.execute("INSERT INTO indicators VALUES (?,?)", params![kind, v])?;
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
            for m in &p.members {
                tx.execute("INSERT INTO posture_members VALUES (?,?)", params![p.id, m])?;
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
        for h in &r.hits {
            tx.execute(
                "INSERT INTO hits VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                params![
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
                ],
            )?;
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
}
