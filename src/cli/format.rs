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

    /// Whether this build can write the format at all.
    ///
    /// Only `sqlite` is conditional, and only on its cargo feature, which is on by default.
    pub fn is_available(self) -> bool {
        !matches!(self, OutputFormat::Sqlite) || cfg!(feature = "sqlite")
    }

    /// Why the format cannot be written, and what to do instead.
    pub fn unavailable_message(self) -> String {
        match self {
            OutputFormat::Sqlite => "this build has no SQLite support. Rebuild without                  --no-default-features, or use --format sql for an equivalent text dump that                  any SQLite client can load."
                .to_string(),
            other => format!("this build cannot write --format {}", other.name()),
        }
    }

    /// Every format, whether or not this build can write it.
    ///
    /// `Sql` precedes `Sqlite` deliberately: the text dump is the fallback for a build
    /// without SQLite support, so it must never be the casualty of the binary writer
    /// failing first.
    pub fn all() -> Vec<OutputFormat> {
        vec![
            OutputFormat::Text,
            OutputFormat::Json,
            OutputFormat::Csv,
            OutputFormat::Html,
            OutputFormat::Markdown,
            OutputFormat::Sarif,
            OutputFormat::Sql,
            OutputFormat::Sqlite,
        ]
    }

    /// The formats `all` expands to: every format this build can actually write.
    pub fn available() -> Vec<OutputFormat> {
        OutputFormat::all()
            .into_iter()
            .filter(|f| f.is_available())
            .collect()
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
            // `all` means every format this build can write. Naming an unavailable format
            // explicitly is still an error below, because that asked for something specific.
            for f in OutputFormat::available() {
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
        if !f.is_available() {
            bail!("{}", f.unavailable_message());
        }
        if !out.contains(&f) {
            out.push(f);
        }
    }
    if out.is_empty() {
        bail!("no output format given");
    }
    Ok(out)
}

/// The default output stem, used when `-o` is omitted.
///
/// Matches the v1 shell implementation's naming so output from either version sorts
/// together. Built from component accessors rather than a format description, so it needs
/// no extra `time` feature beyond what the crate already uses, and it cannot fail to
/// format.
pub fn default_stem() -> String {
    format!("binspector_output-{}", stamp())
}

/// The timestamp component, `YYYY.MM.DD-HH.MM.SS`.
///
/// Extracted so a caller can compute it **once per invocation**: a split run over four hundred
/// targets must not give four hundred different timestamps, or the output stops sorting as one
/// run. Built from component accessors rather than a format description, so it needs no extra
/// `time` feature and cannot fail to format.
pub fn stamp() -> String {
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    format!(
        "{:04}.{:02}.{:02}-{:02}.{:02}.{:02}",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// Output stem for one target in `--split` mode.
///
/// With no `-o`: `binspector_<slug>-<stamp>`. With `-o name`: `name_<slug>-<stamp>`. One rule
/// covers both, and the stamp is passed in so every target in a run shares it.
pub fn split_stem(base: Option<&Path>, slug: &str, stamp: &str) -> PathBuf {
    let prefix = base
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "binspector".to_string());
    PathBuf::from(format!("{}_{}-{}", prefix, slug, stamp))
}

/// How a format's extension is applied to the output path.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Naming {
    /// Use the path exactly as given. One explicit format, one explicit name.
    Exact,
    /// Replace the extension, so `-o report.txt` with several formats yields
    /// `report.json`, `report.csv`, and so on.
    ReplaceExtension,
    /// Append the extension without stripping anything.
    ///
    /// Required for the timestamped default, whose name contains dots: `file_stem` would
    /// read the seconds field of `binspector_output-2026.09.30-16.19.53` as an extension
    /// and silently truncate it.
    Append,
}

/// Destination path for one format.
pub fn destination(base: &Path, fmt: OutputFormat, naming: Naming) -> PathBuf {
    match naming {
        Naming::Exact => base.to_path_buf(),
        Naming::Append => PathBuf::from(format!("{}.{}", base.display(), fmt.name())),
        Naming::ReplaceExtension => {
            let stem = base
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "binspector".to_string());
            let mut p = base.to_path_buf();
            p.set_file_name(format!("{}.{}", stem, fmt.name()));
            p
        }
    }
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
        // The sqlite aliases only resolve where the build can write the format.
        if cfg!(feature = "sqlite") {
            assert_eq!(resolve("db").unwrap(), vec![OutputFormat::Sqlite]);
            assert_eq!(resolve("sqlite").unwrap(), vec![OutputFormat::Sqlite]);
        }
    }

    #[test]
    fn all_expands_to_every_format_this_build_can_write() {
        let got = resolve("all").unwrap();
        assert_eq!(got.len(), OutputFormat::available().len());
        assert!(got.contains(&OutputFormat::Sarif));
        assert_eq!(
            got.contains(&OutputFormat::Sqlite),
            cfg!(feature = "sqlite")
        );
        // The text dump is always present, which is the whole point of the ordering.
        assert!(got.contains(&OutputFormat::Sql));
    }

    #[test]
    fn sql_is_ordered_before_sqlite() {
        // A build without SQLite support must not lose the text dump to the binary
        // writer failing first, which is exactly what happened before this ordering.
        let all = OutputFormat::all();
        let sql = all.iter().position(|f| *f == OutputFormat::Sql).unwrap();
        let sqlite = all.iter().position(|f| *f == OutputFormat::Sqlite).unwrap();
        assert!(sql < sqlite, "got {:?}", all);
    }

    #[test]
    fn naming_an_unavailable_format_is_an_error_not_a_silent_skip() {
        // `all` skips what this build cannot write; naming it does not.
        let got = resolve("sqlite");
        assert_eq!(
            got.is_ok(),
            cfg!(feature = "sqlite"),
            "availability and resolution disagree"
        );
        match got {
            Ok(v) => assert_eq!(v, vec![OutputFormat::Sqlite]),
            Err(e) => assert!(e.to_string().contains("no SQLite support"), "{}", e),
        }
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
    fn split_stem_covers_both_naming_cases() {
        // No -o: the product name leads, so output from one run groups together.
        assert_eq!(
            split_stem(None, "app.exe", "2026.10.01-09.30.00"),
            PathBuf::from("binspector_app.exe-2026.10.01-09.30.00")
        );
        // With -o: the chosen name leads and the slug distinguishes the target.
        assert_eq!(
            split_stem(Some(Path::new("custom")), "app.exe", "2026.10.01-09.30.00"),
            PathBuf::from("custom_app.exe-2026.10.01-09.30.00")
        );
        // A directory prefix survives.
        assert_eq!(
            split_stem(Some(Path::new("out/run")), "b.dll", "2026.10.01-09.30.00"),
            PathBuf::from("out/run_b.dll-2026.10.01-09.30.00")
        );
    }

    #[test]
    fn a_split_stem_keeps_its_seconds_when_an_extension_is_appended() {
        // The reason split mode always uses Naming::Append: the stamp has dots, and
        // ReplaceExtension would read the seconds field as an extension and eat it.
        let base = split_stem(None, "app.exe", "2026.10.01-09.30.00");
        let p = destination(&base, OutputFormat::Json, Naming::Append);
        assert_eq!(
            p,
            PathBuf::from("binspector_app.exe-2026.10.01-09.30.00.json")
        );
    }

    #[test]
    fn stamp_is_stable_within_one_invocation() {
        // Not a clock test: the point is that a caller holds one value and reuses it, which is
        // what keeps a 400-target split run sorting as a single run.
        let s = stamp();
        assert_eq!(s.len(), 19, "got {:?}", s);
        assert_eq!(default_stem(), format!("binspector_output-{}", stamp()));
    }

    #[test]
    fn default_stem_matches_the_legacy_naming() {
        let s = default_stem();
        assert!(s.starts_with("binspector_output-"), "got {}", s);
        // binspector_output-YYYY.MM.DD-HH.MM.SS
        let stamp = s.trim_start_matches("binspector_output-");
        assert_eq!(stamp.len(), 19, "unexpected stamp {:?}", stamp);
        let (date, time_part) = stamp.split_once('-').expect("date-time separator");
        assert_eq!(date.split('.').count(), 3);
        assert_eq!(time_part.split('.').count(), 3);
        for c in stamp.chars() {
            assert!(
                c.is_ascii_digit() || c == '.' || c == '-',
                "bad char {:?}",
                c
            );
        }
    }

    #[test]
    fn exact_naming_keeps_the_path() {
        let p = destination(
            Path::new("out/report.txt"),
            OutputFormat::Text,
            Naming::Exact,
        );
        assert_eq!(p, PathBuf::from("out/report.txt"));
    }

    #[test]
    fn replace_extension_swaps_the_suffix() {
        let p = destination(
            Path::new("out/report.txt"),
            OutputFormat::Json,
            Naming::ReplaceExtension,
        );
        assert_eq!(p, PathBuf::from("out/report.json"));
        let p = destination(
            Path::new("out/scan"),
            OutputFormat::Sqlite,
            Naming::ReplaceExtension,
        );
        assert_eq!(p, PathBuf::from("out/scan.sqlite"));
    }

    #[test]
    fn append_preserves_a_dotted_timestamp() {
        // The whole reason Append exists: ReplaceExtension would eat the seconds.
        let stem = "binspector_output-2026.09.30-16.19.53";
        let appended = destination(Path::new(stem), OutputFormat::Json, Naming::Append);
        assert_eq!(
            appended,
            PathBuf::from("binspector_output-2026.09.30-16.19.53.json")
        );
        let replaced = destination(
            Path::new(stem),
            OutputFormat::Json,
            Naming::ReplaceExtension,
        );
        assert_eq!(
            replaced,
            PathBuf::from("binspector_output-2026.09.30-16.19.json"),
            "this truncation is why Append exists"
        );
    }

    #[test]
    fn append_works_with_a_directory_prefix() {
        let p = destination(
            Path::new("out/binspector_output-2026.09.30-16.19.53"),
            OutputFormat::Markdown,
            Naming::Append,
        );
        assert_eq!(
            p,
            PathBuf::from("out/binspector_output-2026.09.30-16.19.53.md")
        );
    }

    #[test]
    fn dump_capability_is_declared_per_format() {
        assert!(OutputFormat::Text.supports_dump());
        assert!(OutputFormat::Csv.supports_dump());
        assert!(!OutputFormat::Json.supports_dump());
        assert!(!OutputFormat::Sarif.supports_dump());
    }
}
