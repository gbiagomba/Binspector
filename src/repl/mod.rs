//! Interactive browser over a saved report.
//!
//! Behind the `repl` cargo feature, off by default.
//!
//! Deliberately read-only. It loads a report the scan already produced and answers
//! questions about it; it never scans. That keeps it a viewer rather than a second entry
//! point into the analysis, so it cannot disagree with what the scan reported.
//!
//! `jq` and the `sqlite3` shell already cover much of this. Where they are genuinely
//! awkward is the cross-cutting view: a 441-image mitigation matrix, or "which images lack
//! ASLR and also import a critical function". Those are what this exists for.

pub mod commands;
pub mod render;

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

use crate::model::Report;

/// Where the loaded report came from, which decides whether `sql` is available.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Json(PathBuf),
    Sqlite(PathBuf),
}

impl Source {
    pub fn path(&self) -> &Path {
        match self {
            Source::Json(p) | Source::Sqlite(p) => p,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Source::Json(_) => "json",
            Source::Sqlite(_) => "sqlite",
        }
    }

    /// Decide by content rather than extension, matching how the scanner treats input.
    pub fn detect(path: &Path) -> Result<Self> {
        let mut head = [0u8; 16];
        let n = {
            use std::io::Read;
            let mut f =
                std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
            f.read(&mut head).unwrap_or(0)
        };
        if n >= 16 && &head[..15] == b"SQLite format 3" {
            return Ok(Source::Sqlite(path.to_path_buf()));
        }
        // A JSON report begins with an object, possibly after whitespace.
        if head[..n].contains(&b'{') {
            return Ok(Source::Json(path.to_path_buf()));
        }
        bail!(
            "{} is neither a JSON report nor a SQLite database. Produce one with \
             `binspector --format json -o report.json <binary>`.",
            path.display()
        )
    }
}

#[derive(Debug)]
pub struct Session {
    pub source: Source,
    pub report: Report,
}

impl Session {
    pub fn open(path: &Path) -> Result<Self> {
        let source = Source::detect(path)?;
        let report = match &source {
            Source::Json(p) => {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("reading {}", p.display()))?;
                let parsed: Report = serde_json::from_str(&text).with_context(|| {
                    format!(
                        "parsing {} as a Binspector JSON report. A --matches-only report is \
                         only the summary array, which the browser cannot load.",
                        p.display()
                    )
                })?;
                parsed
            }
            Source::Sqlite(p) => load_sqlite(p)?,
        };
        Ok(Self { source, report })
    }

    pub fn banner(&self) -> String {
        let r = &self.report;
        format!(
            "{} {} report, loaded from {} ({})\n\
             {} findings across {} occurrences, {} members, {} strings\n\
             Type `help` for commands, `quit` to exit.",
            r.tool,
            r.tool_version,
            self.source.path().display(),
            self.source.kind(),
            r.summary.len(),
            r.banned_hit_count,
            r.coverage.members_scanned,
            r.strings_total
        )
    }
}

/// Reconstruct a report from the SQLite writer's schema.
///
/// Only the fields the browser reads are populated; the schema is a flattened view rather
/// than a serialisation of the whole model, so a JSON report is the fuller source.
#[cfg(feature = "sqlite")]
fn load_sqlite(path: &Path) -> Result<Report> {
    commands::sqlite_support::load(path)
}

#[cfg(not(feature = "sqlite"))]
fn load_sqlite(_path: &Path) -> Result<Report> {
    bail!(
        "this build cannot read a SQLite report. Rebuild with --features sqlite,repl, or \
         load a JSON report instead."
    )
}

/// Run the interactive loop against a report.
pub fn run(path: &Path) -> Result<()> {
    let session = Session::open(path)?;
    println!("{}", session.banner());

    let mut editor = rustyline::DefaultEditor::new().context("starting the line editor")?;
    loop {
        match editor.readline("binspector> ") {
            Ok(line) => {
                let _ = editor.add_history_entry(line.as_str());
                match commands::parse(&line) {
                    Ok(None) => continue,
                    Ok(Some(cmd)) => match commands::execute(&session, &cmd) {
                        Ok(true) => {}
                        Ok(false) => break,
                        // A bad command must not end the session.
                        Err(e) => eprintln!("  {:#}", e),
                    },
                    Err(e) => eprintln!("  {:#}", e),
                }
            }
            // Ctrl-C clears the line, Ctrl-D ends the session, matching shell convention.
            Err(rustyline::error::ReadlineError::Interrupted) => continue,
            Err(rustyline::error::ReadlineError::Eof) => break,
            Err(e) => return Err(e).context("reading input"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(bytes).unwrap();
        p
    }

    #[test]
    fn detects_json_by_content_not_extension() {
        let d = tempfile::tempdir().unwrap();
        // Deliberately the wrong extension, to prove content wins.
        let p = write(d.path(), "report.sqlite", br#"{"tool":"binspector"}"#);
        assert_eq!(Source::detect(&p).unwrap(), Source::Json(p.clone()));
        assert_eq!(Source::detect(&p).unwrap().kind(), "json");
    }

    #[test]
    fn detects_sqlite_by_magic() {
        let d = tempfile::tempdir().unwrap();
        let mut bytes = b"SQLite format 3\0".to_vec();
        bytes.extend_from_slice(&[0u8; 32]);
        let p = write(d.path(), "report.json", &bytes);
        assert_eq!(Source::detect(&p).unwrap(), Source::Sqlite(p.clone()));
        assert_eq!(Source::detect(&p).unwrap().kind(), "sqlite");
    }

    #[test]
    fn rejects_something_that_is_neither() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "notes.txt", b"just some prose, no report here");
        let err = Source::detect(&p).unwrap_err().to_string();
        assert!(err.contains("neither a JSON report nor a SQLite database"));
        assert!(
            err.contains("--format json"),
            "error should say how to make one"
        );
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(Source::detect(Path::new("/nonexistent/report.json")).is_err());
    }

    #[test]
    fn loads_a_real_json_report_and_summarises_it() {
        let d = tempfile::tempdir().unwrap();
        let report = crate::report::tests_support::sample_report();
        let p = write(
            d.path(),
            "r.json",
            serde_json::to_string(&report).unwrap().as_bytes(),
        );
        let s = Session::open(&p).unwrap();
        assert_eq!(s.report.summary[0].function, "strcpy");
        let b = s.banner();
        assert!(b.contains("binspector"));
        assert!(b.contains("1 findings"), "banner was: {}", b);
    }

    #[test]
    fn a_matches_only_report_fails_with_a_useful_message() {
        let d = tempfile::tempdir().unwrap();
        // --matches-only emits a bare array, not the full object.
        let p = write(d.path(), "r.json", br#"[{"function":"strcpy"}]"#);
        let err = Session::open(&p).unwrap_err().to_string();
        assert!(
            err.contains("matches-only") || err.contains("JSON report"),
            "error was: {}",
            err
        );
    }
}
