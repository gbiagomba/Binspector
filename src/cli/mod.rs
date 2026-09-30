//! Command line surface.

pub mod color;
pub mod format;

use anyhow::{bail, Result};
use clap::Parser;
use regex::Regex;
use std::path::PathBuf;

use crate::container::Limits;
use crate::scan::banned::Severity;
use crate::scan::ScanConfig;
use color::{ColorChoice, Palette};

#[derive(Parser, Debug)]
#[command(
    name = "binspector",
    version,
    about = "Scan binaries for banned C/C++ functions, descending into nested containers",
    long_about = "Binspector extracts printable strings from a binary and reports references to \
                  banned C/C++ functions.\n\nArchives are unpacked in memory, so a .msixbundle, \
                  .msix, .appx, .jar, .nupkg, or .zip is scanned by its real contents rather than \
                  its compressed bytes. Matches are verified against identifier boundaries, so a \
                  substring such as 'targetsize' is not reported as 'gets'."
)]
pub struct Cli {
    /// Path to the target binary or archive
    #[arg(value_name = "BINARY")]
    pub binary: PathBuf,

    /// Project name for output labeling
    #[arg(short, long)]
    pub project: Option<String>,

    /// Minimum string length to consider
    #[arg(short = 'l', long, default_value_t = 4, value_name = "N")]
    pub min_len: usize,

    /// Write output to a file. With several formats, this is used as a filename stem
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Output format: text/txt, json, html, markdown/md, sarif, sqlite/db, sql, csv, all.
    /// Several may be given comma separated
    #[arg(long, default_value = "text", value_name = "FORMAT")]
    pub format: String,

    /// Deprecated alias for --format json
    #[arg(long, hide = true)]
    pub json: bool,

    /// Custom banned list file, one function name per line
    #[arg(long, value_name = "FILE")]
    pub banned_list: Option<PathBuf>,

    /// Report only the matches, omitting metadata and coverage
    #[arg(long)]
    pub matches_only: bool,

    /// Include every extracted string, with banned functions highlighted.
    /// Supported by text, markdown, html, csv, sql, and sqlite
    #[arg(long)]
    pub dump: bool,

    /// Do not extract ASCII strings
    #[arg(long = "no-ascii")]
    pub no_ascii: bool,

    /// Do not extract UTF-16LE strings
    #[arg(long = "no-utf16")]
    pub no_utf16: bool,

    /// Match case sensitively. Matching is case insensitive by default
    #[arg(long = "case-sensitive")]
    pub case_sensitive: bool,

    /// Deprecated: matching is case insensitive by default
    #[arg(long = "ignore-case", hide = true)]
    pub ignore_case: bool,

    /// Consider only banned function names matching this regex
    #[arg(long = "banned-filter", value_name = "REGEX")]
    pub banned_filter: Option<String>,

    /// When to colorize terminal output
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    pub color: ColorChoice,

    /// Highlight palette. `colorblind` uses Okabe-Ito colors with no red-green pairing
    #[arg(long, value_enum, default_value_t = Palette::Default)]
    pub palette: Palette,

    /// Maximum container nesting depth
    #[arg(long, default_value_t = 4, value_name = "N")]
    pub max_depth: usize,

    /// Maximum total unpacked bytes
    #[arg(long, default_value_t = 2 * 1024 * 1024 * 1024, value_name = "BYTES")]
    pub max_unpacked_bytes: u64,

    /// Maximum bytes for any single member
    #[arg(long, default_value_t = 512 * 1024 * 1024, value_name = "BYTES")]
    pub max_member_bytes: u64,

    /// Maximum ratio of unpacked bytes to input size, as bomb protection
    #[arg(long, default_value_t = 100, value_name = "N")]
    pub max_expansion_ratio: u64,

    /// Maximum number of container members to visit
    #[arg(long, default_value_t = 50_000, value_name = "N")]
    pub max_members: usize,

    /// Maximum individually recorded occurrences. Aggregate counts stay complete
    #[arg(long, default_value_t = 100_000, value_name = "N")]
    pub max_hits: usize,

    /// Characters of surrounding context kept with each occurrence
    #[arg(long, default_value_t = 120, value_name = "N")]
    pub context: usize,

    /// Also report low-confidence matches: namespace segments such as
    /// System.Windows, and documentation prose such as "Gets or sets"
    #[arg(long = "include-low-confidence")]
    pub include_low_confidence: bool,

    /// Exit non-zero when a match at or above this severity is found
    #[arg(long, value_name = "SEVERITY")]
    pub fail_on: Option<FailOn>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum FailOn {
    Critical,
    High,
    Medium,
}

impl FailOn {
    pub fn threshold(self) -> Severity {
        match self {
            FailOn::Critical => Severity::Critical,
            FailOn::High => Severity::High,
            FailOn::Medium => Severity::Medium,
        }
    }
}

/// Fully validated invocation.
#[derive(Debug)]
pub struct Resolved {
    /// The target the scan runs against.
    pub binary: PathBuf,
    pub scan: ScanConfig,
    pub formats: Vec<format::OutputFormat>,
    pub output: Option<PathBuf>,
    pub matches_only: bool,
    pub dump: bool,
    pub color: ColorChoice,
    pub palette: Palette,
    pub fail_on: Option<FailOn>,
    /// Non-fatal notices to print before the report, such as deprecation warnings.
    pub notices: Vec<String>,
}

impl Cli {
    pub fn resolve(self) -> Result<Resolved> {
        let mut notices = Vec::new();

        if self.no_ascii && self.no_utf16 {
            bail!(
                "both --no-ascii and --no-utf16 are set, which disables every extraction \
                 source. Enable at least one."
            );
        }
        if self.min_len == 0 {
            bail!("--min-len must be at least 1");
        }

        if self.ignore_case {
            notices.push(
                "--ignore-case is deprecated and has no effect: matching is case insensitive by \
                 default. Use --case-sensitive for the opposite behavior."
                    .to_string(),
            );
        }
        if self.ignore_case && self.case_sensitive {
            bail!("--ignore-case and --case-sensitive contradict each other");
        }

        // The deprecated --json flag only applies when --format was left at its default.
        let mut spec = self.format.clone();
        if self.json {
            notices.push("--json is deprecated; use --format json.".to_string());
            if spec == "text" {
                spec = "json".to_string();
            }
        }
        let formats = format::resolve(&spec)?;

        if self.output.is_none() {
            if let Some(f) = formats.iter().find(|f| f.requires_path()) {
                bail!(
                    "--format {} writes a binary database and needs an output path; pass -o FILE",
                    f.name()
                );
            }
        }
        if formats.len() > 1 && self.output.is_none() {
            bail!("several output formats were requested; pass -o to use it as a filename stem");
        }

        if self.dump {
            let undumpable: Vec<&str> = formats
                .iter()
                .filter(|f| !f.supports_dump())
                .map(|f| f.name())
                .collect();
            if !undumpable.is_empty() {
                notices.push(format!(
                    "--dump is not applicable to {}; those formats report matches only.",
                    undumpable.join(", ")
                ));
            }
        }

        let banned_filter = match &self.banned_filter {
            Some(p) => Some(
                Regex::new(p)
                    .map_err(|e| anyhow::anyhow!("invalid --banned-filter regex: {}", e))?,
            ),
            None => None,
        };

        let scan = ScanConfig {
            project: self.project,
            min_len: self.min_len,
            ascii: !self.no_ascii,
            utf16: !self.no_utf16,
            case_sensitive: self.case_sensitive,
            banned_list: self.banned_list,
            banned_filter,
            limits: Limits {
                max_depth: self.max_depth,
                max_total_bytes: self.max_unpacked_bytes,
                max_member_bytes: self.max_member_bytes,
                max_expansion_ratio: self.max_expansion_ratio,
                max_members: self.max_members,
            },
            dump: self.dump,
            max_hits: self.max_hits,
            context_window: self.context,
            include_low_confidence: self.include_low_confidence,
        };

        Ok(Resolved {
            binary: self.binary,
            scan,
            formats,
            output: self.output,
            matches_only: self.matches_only,
            dump: self.dump,
            color: self.color,
            palette: self.palette,
            fail_on: self.fail_on,
            notices,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Result<Resolved> {
        let mut full = vec!["binspector"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full)?.resolve()
    }

    #[test]
    fn defaults_are_case_insensitive_and_text() {
        let r = parse(&["file.bin"]).unwrap();
        assert!(!r.scan.case_sensitive);
        assert_eq!(r.formats, vec![format::OutputFormat::Text]);
        assert!(!r.dump);
    }

    #[test]
    fn case_sensitive_flag_flips_the_default() {
        let r = parse(&["file.bin", "--case-sensitive"]).unwrap();
        assert!(r.scan.case_sensitive);
    }

    #[test]
    fn deprecated_ignore_case_is_accepted_with_a_notice() {
        // The command line from the original failing run must keep working.
        let r = parse(&[
            "-p",
            "PROJ-123",
            "-o",
            "out.txt",
            "--ignore-case",
            "file.bin",
        ])
        .unwrap();
        assert!(!r.scan.case_sensitive);
        assert!(r
            .notices
            .iter()
            .any(|n| n.contains("--ignore-case is deprecated")));
    }

    #[test]
    fn ignore_case_conflicts_with_case_sensitive() {
        assert!(parse(&["file.bin", "--ignore-case", "--case-sensitive"]).is_err());
    }

    #[test]
    fn deprecated_json_flag_maps_to_json_format() {
        let r = parse(&["file.bin", "--json"]).unwrap();
        assert_eq!(r.formats, vec![format::OutputFormat::Json]);
        assert!(r.notices.iter().any(|n| n.contains("--json is deprecated")));
    }

    #[test]
    fn explicit_format_wins_over_deprecated_json() {
        let r = parse(&["file.bin", "--json", "--format", "csv"]).unwrap();
        assert_eq!(r.formats, vec![format::OutputFormat::Csv]);
    }

    #[test]
    fn rejects_disabling_both_extractors() {
        let err = parse(&["file.bin", "--no-ascii", "--no-utf16"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("disables every extraction source"));
    }

    #[test]
    fn sqlite_requires_an_output_path() {
        let err = parse(&["file.bin", "--format", "sqlite"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("needs an output path"));
        assert!(parse(&["file.bin", "--format", "sqlite", "-o", "out.db"]).is_ok());
    }

    #[test]
    fn several_formats_require_an_output_stem() {
        assert!(parse(&["file.bin", "--format", "json,csv"]).is_err());
        assert!(parse(&["file.bin", "--format", "json,csv", "-o", "stem"]).is_ok());
    }

    #[test]
    fn csv_no_longer_requires_matches_only() {
        // 2.0.0 rejected this combination outright.
        let r = parse(&["file.bin", "--format", "csv"]).unwrap();
        assert_eq!(r.formats, vec![format::OutputFormat::Csv]);
        assert!(!r.matches_only);
    }

    #[test]
    fn dump_with_json_emits_a_notice_but_succeeds() {
        let r = parse(&["file.bin", "--format", "json", "--dump"]).unwrap();
        assert!(r
            .notices
            .iter()
            .any(|n| n.contains("--dump is not applicable")));
    }

    #[test]
    fn rejects_bad_regex_and_zero_min_len() {
        assert!(parse(&["file.bin", "--banned-filter", "("]).is_err());
        assert!(parse(&["file.bin", "--min-len", "0"]).is_err());
    }

    #[test]
    fn low_confidence_is_excluded_by_default() {
        let r = parse(&["file.bin"]).unwrap();
        assert!(!r.scan.include_low_confidence);
        let r = parse(&["file.bin", "--include-low-confidence"]).unwrap();
        assert!(r.scan.include_low_confidence);
    }

    #[test]
    fn limits_are_plumbed_through() {
        let r = parse(&["file.bin", "--max-depth", "2", "--max-expansion-ratio", "7"]).unwrap();
        assert_eq!(r.scan.limits.max_depth, 2);
        assert_eq!(r.scan.limits.max_expansion_ratio, 7);
    }
}
