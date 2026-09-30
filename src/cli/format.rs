//! Output format selection, including the alias spellings and `all`.

use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum OutputFormat {
    Text,
    Json,
    Csv,
    Html,
    Markdown,
    Sarif,
    Sqlite,
    Sql,
}

impl OutputFormat {
    /// Canonical short name, also used as the file extension for `all`.
    pub fn name(self) -> &'static str {
        match self {
            OutputFormat::Text => "txt",
            OutputFormat::Json => "json",
            OutputFormat::Csv => "csv",
            OutputFormat::Html => "html",
            OutputFormat::Markdown => "md",
            OutputFormat::Sarif => "sarif",
            OutputFormat::Sqlite => "sqlite",
            OutputFormat::Sql => "sql",
        }
    }

    /// Formats that can render a full per-string dump.
    pub fn supports_dump(self) -> bool {
        matches!(
            self,
            OutputFormat::Text
                | OutputFormat::Markdown
                | OutputFormat::Html
                | OutputFormat::Csv
                | OutputFormat::Sql
                | OutputFormat::Sqlite
        )
    }

    /// SQLite writes a binary database, so it needs a real path rather than a stream.
    pub fn requires_path(self) -> bool {
        matches!(self, OutputFormat::Sqlite)
    }

    pub fn all() -> Vec<OutputFormat> {
        vec![
            OutputFormat::Text,
            OutputFormat::Json,
            OutputFormat::Csv,
            OutputFormat::Html,
            OutputFormat::Markdown,
            OutputFormat::Sarif,
            OutputFormat::Sqlite,
            OutputFormat::Sql,
        ]
    }
}

/// Resolve a user-supplied format spec into the set of formats to emit.
///
/// Accepted spellings, case-insensitive: `text`, `txt`, `json`, `html`, `markdown`,
/// `md`, `sarif`, `sqlite`, `db`, `sql`, `csv`, `all`. Several may be given comma
/// separated.
pub fn resolve(spec: &str) -> Result<Vec<OutputFormat>> {
    let mut out: Vec<OutputFormat> = Vec::new();
    for raw in spec.split(',') {
        let token = raw.trim().to_ascii_lowercase();
        if token.is_empty() {
            continue;
        }
        if token == "all" {
            for f in OutputFormat::all() {
                if !out.contains(&f) {
                    out.push(f);
                }
            }
            continue;
        }
        let f = match token.as_str() {
            "text" | "txt" => OutputFormat::Text,
            "json" => OutputFormat::Json,
            "csv" => OutputFormat::Csv,
            "html" | "htm" => OutputFormat::Html,
            "markdown" | "md" => OutputFormat::Markdown,
            "sarif" => OutputFormat::Sarif,
            "sqlite" | "db" | "sqlite3" => OutputFormat::Sqlite,
            "sql" => OutputFormat::Sql,
            other => bail!(
                "unknown output format '{}'. Valid values: text/txt, json, html, markdown/md, \
                 sarif, sqlite/db, sql, csv, all",
                other
            ),
        };
        if !out.contains(&f) {
            out.push(f);
        }
    }
    if out.is_empty() {
        bail!("no output format given");
    }
    Ok(out)
}

/// Destination path for one format when several are written from one `-o` value.
///
/// A single format keeps the path exactly as given, so `-o report.txt` is not
/// rewritten. Several formats treat the value as a stem.
pub fn destination(base: &Path, fmt: OutputFormat, multiple: bool) -> PathBuf {
    if !multiple {
        return base.to_path_buf();
    }
    let stem = base
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "binspector".to_string());
    let mut p = base.to_path_buf();
    p.set_file_name(format!("{}.{}", stem, fmt.name()));
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_canonical_names() {
        assert_eq!(resolve("json").unwrap(), vec![OutputFormat::Json]);
        assert_eq!(resolve("sarif").unwrap(), vec![OutputFormat::Sarif]);
    }

    #[test]
    fn resolves_aliases() {
        assert_eq!(resolve("txt").unwrap(), vec![OutputFormat::Text]);
        assert_eq!(resolve("TEXT").unwrap(), vec![OutputFormat::Text]);
        assert_eq!(resolve("md").unwrap(), vec![OutputFormat::Markdown]);
        assert_eq!(resolve("markdown").unwrap(), vec![OutputFormat::Markdown]);
        assert_eq!(resolve("db").unwrap(), vec![OutputFormat::Sqlite]);
        assert_eq!(resolve("sqlite").unwrap(), vec![OutputFormat::Sqlite]);
    }

    #[test]
    fn all_expands_to_every_format() {
        let got = resolve("all").unwrap();
        assert_eq!(got.len(), 8);
        assert!(got.contains(&OutputFormat::Sarif));
        assert!(got.contains(&OutputFormat::Sqlite));
    }

    #[test]
    fn accepts_comma_separated_and_dedupes() {
        let got = resolve("json,csv,json").unwrap();
        assert_eq!(got, vec![OutputFormat::Json, OutputFormat::Csv]);
    }

    #[test]
    fn rejects_unknown_format() {
        let err = resolve("yaml").unwrap_err().to_string();
        assert!(err.contains("unknown output format"));
        assert!(err.contains("sarif"));
    }

    #[test]
    fn single_format_keeps_the_exact_path() {
        let p = destination(Path::new("out/report.txt"), OutputFormat::Text, false);
        assert_eq!(p, PathBuf::from("out/report.txt"));
    }

    #[test]
    fn multiple_formats_use_the_path_as_a_stem() {
        let p = destination(Path::new("out/report.txt"), OutputFormat::Json, true);
        assert_eq!(p, PathBuf::from("out/report.json"));
        let p = destination(Path::new("out/scan"), OutputFormat::Sqlite, true);
        assert_eq!(p, PathBuf::from("out/scan.sqlite"));
    }

    #[test]
    fn dump_capability_is_declared_per_format() {
        assert!(OutputFormat::Text.supports_dump());
        assert!(OutputFormat::Csv.supports_dump());
        assert!(!OutputFormat::Json.supports_dump());
        assert!(!OutputFormat::Sarif.supports_dump());
    }
}
