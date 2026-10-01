//! Command parsing and execution for the browser.

use anyhow::{bail, Result};

use super::render;
use super::{Session, Source};
use crate::cli::color::{Palette, Theme};
use crate::cli::format;
use crate::report::{self, RenderOpts};

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Summary,
    Coverage,
    Hits {
        function: Option<String>,
        severity: Option<String>,
        confidence: Option<String>,
    },
    Member(String),
    Mitigations(Option<String>),
    Components,
    Cves,
    Iocs,
    Carved,
    Warnings,
    Sql(String),
    Export {
        format: String,
        path: String,
    },
    Help,
    Quit,
}

/// Parse one input line. `None` means the line was blank.
pub fn parse(line: &str) -> Result<Option<Command>> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(None);
    }
    let mut parts = line.split_whitespace();
    let verb = parts.next().unwrap_or("").to_ascii_lowercase();
    let rest: Vec<&str> = parts.collect();

    let cmd = match verb.as_str() {
        "summary" | "s" => Command::Summary,
        "coverage" | "cov" => Command::Coverage,
        "hits" | "h" => {
            let mut function = None;
            let mut severity = None;
            let mut confidence = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i] {
                    "--severity" | "--sev" => {
                        severity = rest.get(i + 1).map(|s| s.to_ascii_lowercase());
                        i += 2;
                    }
                    "--confidence" | "--conf" => {
                        confidence = rest.get(i + 1).map(|s| s.to_ascii_lowercase());
                        i += 2;
                    }
                    other if other.starts_with("--") => {
                        bail!("unknown option {}. Try: hits [function] [--severity s] [--confidence c]", other)
                    }
                    other => {
                        function = Some(other.to_string());
                        i += 1;
                    }
                }
            }
            if let Some(s) = &severity {
                if render::severity_of(s).is_none() {
                    bail!("unknown severity {:?}. Use critical, high, or medium.", s);
                }
            }
            Command::Hits {
                function,
                severity,
                confidence,
            }
        }
        "member" | "m" => match rest.first() {
            Some(p) => Command::Member(p.to_string()),
            None => bail!("member needs a name or fragment, for example: member App.exe"),
        },
        "mitigations" | "mit" => {
            let missing = match rest.first() {
                Some(&"--missing") => match rest.get(1) {
                    Some(k) => Some(k.to_ascii_lowercase()),
                    None => bail!(
                        "--missing needs one of: aslr, dep, cfg, seh, authenticode, \
                             dll-search, any"
                    ),
                },
                Some(other) => bail!(
                    "unknown option {}. Try: mitigations [--missing aslr]",
                    other
                ),
                None => None,
            };
            Command::Mitigations(missing)
        }
        "components" | "comp" => Command::Components,
        "cves" | "cve" => Command::Cves,
        "iocs" | "ioc" => Command::Iocs,
        "carved" | "carve" => Command::Carved,
        "warnings" | "warn" | "w" => Command::Warnings,
        "sql" => {
            let q = line[3..].trim();
            if q.is_empty() {
                bail!("sql needs a query, for example: sql select function, count(*) from hits group by 1");
            }
            Command::Sql(q.to_string())
        }
        "export" | "e" => match (rest.first(), rest.get(1)) {
            (Some(f), Some(p)) => Command::Export {
                format: f.to_string(),
                path: p.to_string(),
            },
            _ => bail!("export needs a format and a path, for example: export md out.md"),
        },
        "help" | "?" => Command::Help,
        "quit" | "exit" | "q" => Command::Quit,
        other => bail!("unknown command {:?}. Type `help` for the list.", other),
    };
    Ok(Some(cmd))
}

pub const HELP: &str = "\
  summary                          findings by severity, with suppression totals
  coverage                         what was opened, and the import-backed total
  hits [fn] [--severity s]         occurrences, filterable
       [--confidence c]            one of import, exact, symbolic, prose
  member <fragment>                full detail for matching members, including PE analysis
  mitigations [--missing k]        the mitigation matrix; k is aslr, dep, cfg, seh, gs,
                                   safe-seh, cet, authenticode, dll-search, or any
  components                       third-party libraries detected
  cves                             CVEs resolved against NVD, if --cve was used
  iocs                             URLs, IPs, emails, registry keys, file paths
  carved                           embedded signatures, if --carve was used
  warnings                         coverage warnings from the scan
  sql <query>                      raw query, SQLite reports only
  export <format> <path>           re-render through the normal writers
  help                             this list
  quit                             leave";

/// Run a command against the session. Returns false when the session should end.
pub fn execute(session: &Session, cmd: &Command) -> Result<bool> {
    let r = &session.report;
    match cmd {
        Command::Quit => return Ok(false),
        Command::Help => println!("{}", HELP),
        Command::Summary => print!("{}", render::summary(r)),
        Command::Coverage => print!("{}", render::coverage(r)),
        Command::Hits {
            function,
            severity,
            confidence,
        } => print!(
            "{}",
            render::hits(
                r,
                function.as_deref(),
                severity.as_deref(),
                confidence.as_deref()
            )
        ),
        Command::Member(p) => print!("{}", render::member(r, p)),
        Command::Mitigations(missing) => print!("{}", render::mitigations(r, missing.as_deref())),
        Command::Components => {
            if r.intel.components.is_empty() {
                println!("  no components detected");
            } else {
                let rows: Vec<Vec<String>> = r
                    .intel
                    .components
                    .iter()
                    .map(|c| vec![c.name.clone(), c.version.clone()])
                    .collect();
                print!("{}", render::table(&["component", "version"], &rows));
            }
        }
        Command::Cves => match &r.intel.cves {
            None => println!("  no CVE data in this report. Re-scan with --cve."),
            Some(c) => {
                let mut rows = Vec::new();
                for comp in &c.components {
                    for v in &comp.cves {
                        rows.push(vec![
                            comp.component.name.clone(),
                            comp.component.version.clone(),
                            v.id.clone(),
                            v.cvss
                                .map(|s| format!("{:.1}", s))
                                .unwrap_or_else(|| "n/a".into()),
                            v.severity.clone(),
                        ]);
                    }
                }
                print!(
                    "{}",
                    render::table(&["component", "version", "cve", "cvss", "severity"], &rows)
                );
                println!("\n  {}", c.coverage_note);
            }
        },
        Command::Iocs => {
            if r.iocs.is_empty() {
                println!("  no indicators");
            } else {
                for (label, items) in [
                    ("url", &r.iocs.urls),
                    ("ip", &r.iocs.ips),
                    ("email", &r.iocs.emails),
                    ("registry", &r.iocs.registry_keys),
                    ("path", &r.iocs.file_paths),
                ] {
                    if items.is_empty() {
                        continue;
                    }
                    println!("  {} ({})", label, items.len());
                    for i in items.iter().take(20) {
                        println!("    {}", i);
                    }
                    if items.len() > 20 {
                        println!("    ... and {} more", items.len() - 20);
                    }
                }
            }
        }
        Command::Carved => {
            if !r.coverage.carve_ran {
                println!("  carving did not run for this report. Re-scan with --carve.");
            } else if r.carved_total() == 0 {
                println!("  no embedded signatures found");
            } else {
                let mut rows = Vec::new();
                for m in &r.coverage.carved {
                    for i in &m.items {
                        rows.push(vec![
                            render::short(&m.member).to_string(),
                            i.signature.clone(),
                            format!("{:?}", i.class).to_ascii_lowercase(),
                            format!("0x{:x}", i.offset),
                        ]);
                    }
                }
                print!(
                    "{}",
                    render::table(&["image", "signature", "class", "offset"], &rows)
                );
            }
        }
        Command::Warnings => {
            if r.warnings.is_empty() {
                println!("  no warnings");
            } else {
                for w in &r.warnings {
                    println!("  {}", w);
                }
            }
        }
        Command::Sql(q) => return run_sql(session, q).map(|_| true),
        Command::Export { format: f, path } => {
            let formats = format::resolve(f)?;
            if formats.len() != 1 {
                bail!("export takes one format at a time");
            }
            let opts = RenderOpts {
                theme: Theme::plain(Palette::Default),
                matches_only: false,
                dump: false,
            };
            report::render_to_path(formats[0], std::path::Path::new(path), r, None, &opts)?;
            println!("  wrote {}", path);
        }
    }
    Ok(true)
}

#[cfg(feature = "sqlite")]
fn run_sql(session: &Session, query: &str) -> Result<()> {
    let path = match &session.source {
        Source::Sqlite(p) => p,
        Source::Json(_) => bail!(
            "sql needs a SQLite report. This session loaded JSON; re-scan with \
             --format sqlite, or use the other commands."
        ),
    };
    sqlite_support::query(path, query)
}

#[cfg(not(feature = "sqlite"))]
fn run_sql(_session: &Session, _query: &str) -> Result<()> {
    bail!("this build has no SQLite support. Rebuild with --features sqlite,repl.")
}

#[cfg(feature = "sqlite")]
pub mod sqlite_support {
    use anyhow::{Context, Result};
    use rusqlite::Connection;
    use std::path::Path;

    use crate::model::Report;

    /// Run an arbitrary query and print the rows.
    ///
    /// The connection is opened read-only, so a typo in a query cannot damage the report
    /// being examined.
    pub fn query(path: &Path, sql: &str) -> Result<()> {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .with_context(|| format!("opening {} read-only", path.display()))?;
        let mut stmt = conn.prepare(sql).context("preparing query")?;
        let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let mut rows = stmt.query([])?;
        let mut out: Vec<Vec<String>> = Vec::new();
        while let Some(row) = rows.next()? {
            let mut r = Vec::new();
            for i in 0..cols.len() {
                let v: rusqlite::types::Value = row.get(i)?;
                r.push(match v {
                    rusqlite::types::Value::Null => "NULL".to_string(),
                    rusqlite::types::Value::Integer(i) => i.to_string(),
                    rusqlite::types::Value::Real(f) => format!("{}", f),
                    rusqlite::types::Value::Text(t) => t,
                    rusqlite::types::Value::Blob(b) => format!("<{} bytes>", b.len()),
                });
            }
            out.push(r);
        }
        let headers: Vec<&str> = cols.iter().map(|s| s.as_str()).collect();
        print!("{}", super::render::table(&headers, &out));
        println!("  {} row(s)", out.len());
        Ok(())
    }

    /// Rebuild enough of a Report from the SQLite schema for the browser to work.
    pub fn load(path: &Path) -> Result<Report> {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .with_context(|| format!("opening {} read-only", path.display()))?;

        // The SQLite writer stores a flattened view rather than the whole model, so the
        // JSON report is the fuller source. What is here is what the schema carries.
        let mut summary = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT function, severity, category, occurrences, members, low_confidence \
                 FROM summary",
            )?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let sev: String = row.get(1)?;
                let cat: String = row.get(2)?;
                summary.push(crate::model::MatchSummary {
                    // The SQLite schema stores one severity per row; it is the adjusted
                    // value, and the base is not persisted, so leave it unset rather than
                    // claim they are equal.
                    base_severity: None,
                    function: row.get(0)?,
                    severity: parse_severity(&sev)?,
                    category: parse_category(&cat),
                    occurrences: row.get::<_, i64>(3)? as usize,
                    members: row.get::<_, i64>(4)? as usize,
                    low_confidence: row.get::<_, i64>(5)? as usize,
                });
            }
        }

        let (
            tool_version,
            binary,
            timestamp,
            strings_total,
            members,
            unpacked,
            root_format,
            low_total,
        ) = conn
            .query_row(
                "SELECT tool_version, binary, timestamp, strings_total, members_scanned, \
                 total_unpacked_bytes, root_format, low_confidence_total FROM scan LIMIT 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)? as usize,
                        r.get::<_, i64>(4)? as usize,
                        r.get::<_, i64>(5)? as u64,
                        r.get::<_, String>(6)?,
                        r.get::<_, i64>(7)? as usize,
                    ))
                },
            )
            .context("reading the scan row; is this a Binspector SQLite report?")?;

        let mut warnings = Vec::new();
        {
            let mut stmt = conn.prepare("SELECT message FROM warnings")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                warnings.push(row.get(0)?);
            }
        }

        let banned_hit_count = summary.iter().map(|s| s.occurrences).sum();
        Ok(Report {
            tool: "binspector".to_string(),
            // The SQLite schema stores no posture table, so a report reloaded from one has
            // none. Not the same as a scan that found an image hardened, and the browser says
            // so rather than showing an empty posture section as though it were a clean result.
            posture: Vec::new(),
            excluded_by_rule: Vec::new(),
            tool_version,
            binary,
            project: None,
            timestamp,
            file_size: 0,
            md5: String::new(),
            sha1: String::new(),
            sha256: String::new(),
            min_len: 0,
            case_sensitive: false,
            banned_list_size: 0,
            strings_total,
            banned_hit_count,
            summary,
            hits: Vec::new(),
            low_confidence_total: low_total,
            low_confidence_top: Vec::new(),
            include_low_confidence: false,
            coverage: crate::model::Coverage {
                root_format,
                members_scanned: members,
                total_unpacked_bytes: unpacked,
                entries: Vec::new(),
                carved: Vec::new(),
                carve_ran: false,
            },
            iocs: Default::default(),
            intel: Default::default(),
            warnings,
        })
    }

    /// Severity as stored in a SQLite report.
    ///
    /// Returns an error rather than guessing. The previous `_ => High` silently promoted any
    /// unrecognised value, which with a fourth level would turn a `low` row into a `high`
    /// one and misrepresent a report the browser is only supposed to be viewing.
    fn parse_severity(s: &str) -> Result<crate::scan::banned::Severity> {
        crate::repl::render::severity_of(s)
            .ok_or_else(|| anyhow::anyhow!("unknown severity {:?} in the report", s))
    }

    fn parse_category(s: &str) -> crate::scan::banned::Category {
        use crate::scan::banned::Category::*;
        match s {
            "buffer-overflow" => BufferOverflow,
            "format-string" => FormatString,
            "path-handling" => PathHandling,
            "conversion" => Conversion,
            "randomness" => Randomness,
            "memory-management" => MemoryManagement,
            "security-descriptor" => SecurityDescriptor,
            _ => Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_line_is_not_a_command() {
        assert_eq!(parse("").unwrap(), None);
        assert_eq!(parse("   ").unwrap(), None);
    }

    #[test]
    fn verbs_and_their_aliases_parse() {
        assert_eq!(parse("summary").unwrap(), Some(Command::Summary));
        assert_eq!(parse("s").unwrap(), Some(Command::Summary));
        assert_eq!(parse("QUIT").unwrap(), Some(Command::Quit));
        assert_eq!(parse("q").unwrap(), Some(Command::Quit));
        assert_eq!(parse("?").unwrap(), Some(Command::Help));
    }

    #[test]
    fn hits_parses_each_filter() {
        assert_eq!(
            parse("hits strcpy").unwrap(),
            Some(Command::Hits {
                function: Some("strcpy".into()),
                severity: None,
                confidence: None
            })
        );
        assert_eq!(
            parse("hits --severity critical --confidence import").unwrap(),
            Some(Command::Hits {
                function: None,
                severity: Some("critical".into()),
                confidence: Some("import".into())
            })
        );
    }

    #[test]
    fn hits_rejects_an_unknown_severity_rather_than_silently_matching_nothing() {
        let err = parse("hits --severity urgent").unwrap_err().to_string();
        assert!(err.contains("unknown severity"), "got: {}", err);
        assert!(err.contains("critical"));
    }

    #[test]
    fn hits_rejects_an_unknown_option() {
        assert!(parse("hits --nope x").is_err());
    }

    #[test]
    fn member_requires_an_argument() {
        assert_eq!(
            parse("member App.exe").unwrap(),
            Some(Command::Member("App.exe".into()))
        );
        assert!(parse("member")
            .unwrap_err()
            .to_string()
            .contains("needs a name"));
    }

    #[test]
    fn mitigations_parses_the_missing_filter() {
        assert_eq!(
            parse("mitigations").unwrap(),
            Some(Command::Mitigations(None))
        );
        assert_eq!(
            parse("mit --missing aslr").unwrap(),
            Some(Command::Mitigations(Some("aslr".into())))
        );
        assert!(parse("mitigations --missing").is_err());
    }

    #[test]
    fn sql_keeps_the_whole_query_including_spaces() {
        assert_eq!(
            parse("sql select function, count(*) from hits group by 1").unwrap(),
            Some(Command::Sql(
                "select function, count(*) from hits group by 1".into()
            ))
        );
        assert!(parse("sql").is_err());
    }

    #[test]
    fn export_needs_both_arguments() {
        assert_eq!(
            parse("export md out.md").unwrap(),
            Some(Command::Export {
                format: "md".into(),
                path: "out.md".into()
            })
        );
        assert!(parse("export md").is_err());
    }

    #[test]
    fn an_unknown_verb_points_at_help() {
        let err = parse("frobnicate").unwrap_err().to_string();
        assert!(err.contains("unknown command"));
        assert!(err.contains("help"));
    }

    #[test]
    fn help_text_lists_every_command() {
        for verb in [
            "summary",
            "coverage",
            "hits",
            "member",
            "mitigations",
            "components",
            "cves",
            "iocs",
            "carved",
            "warnings",
            "sql",
            "export",
            "help",
            "quit",
        ] {
            assert!(HELP.contains(verb), "help is missing {}", verb);
        }
    }
}
