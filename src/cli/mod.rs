//! Command line surface.

pub mod color;
pub mod format;
pub mod fuzz_args;

use anyhow::{bail, Result};
use clap::Parser;
use regex::Regex;
use std::path::PathBuf;

use crate::container::Limits;
use crate::scan::banned::Severity;
use crate::scan::ScanConfig;
use color::{ColorChoice, Palette};
use fuzz_args::FuzzArgs;

#[derive(Parser, Debug)]
#[command(
    name = "binspector",
    version,
    about = "Scan binaries for banned C/C++ functions, descending into nested containers",
    after_help = "Containers are unpacked in memory, so a .msixbundle, .msix, .appx, .jar, \
                  .nupkg, or .zip is scanned by its real contents rather than its compressed \
                  bytes. Matches are boundary-verified, so a substring such as 'targetsize' is \
                  never reported as 'gets'.\n\nFull reference: usage.md",
    // clap maps --help to its long renderer by default, which puts every option in its own
    // block with blank lines between them. The concise form is the useful one at a terminal
    // and the full reference lives in usage.md, so both flags print the short help.
    disable_help_flag = true
)]
pub struct Cli {
    /// Print help
    #[arg(short = 'h', long = "help", action = clap::ArgAction::HelpShort, global = true)]
    pub help: Option<bool>,

    /// Report what the scan is doing, to stderr. Repeat for more: -v phases and totals,
    /// -vv every member and decision, -vvv every string
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Do not print the banner
    #[arg(long = "no-banner")]
    pub no_banner: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Target binary, archive, or directory. Required unless a subcommand is used
    #[arg(value_name = "TARGET")]
    pub binary: Option<PathBuf>,

    /// Further targets. A directory is walked for executables and archives
    #[arg(value_name = "MORE", num_args = 0..)]
    pub more_targets: Vec<PathBuf>,

    /// Project name for output labeling
    #[arg(short, long)]
    pub project: Option<String>,

    /// Minimum string length to consider
    #[arg(short = 'l', long, default_value_t = 4, value_name = "N")]
    pub min_len: usize,

    /// Write output to a file, or a filename stem when several formats are given
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Output format, comma separated for several: text, json, csv, html, md, sarif, sqlite, sql, all
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

    /// Include every extracted string, with banned functions highlighted
    #[arg(long)]
    pub dump: bool,

    /// Do not extract ASCII strings
    #[arg(long = "no-ascii")]
    pub no_ascii: bool,

    /// Do not extract UTF-16LE strings
    #[arg(long = "no-utf16")]
    pub no_utf16: bool,

    /// Match case sensitively (default is case insensitive)
    #[arg(long = "case-sensitive")]
    pub case_sensitive: bool,

    /// Consider only banned function names matching this regex
    #[arg(long = "banned-filter", value_name = "REGEX")]
    pub banned_filter: Option<String>,

    /// When to colorize terminal output
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    pub color: ColorChoice,

    /// Highlight palette
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

    /// Maximum ratio of unpacked bytes to input size (bomb protection)
    #[arg(long, default_value_t = 100, value_name = "N")]
    pub max_expansion_ratio: u64,

    /// Maximum number of container members to visit
    #[arg(long, default_value_t = 50_000, value_name = "N")]
    pub max_members: usize,

    /// Maximum individually recorded occurrences
    #[arg(long, default_value_t = 100_000, value_name = "N")]
    pub max_hits: usize,

    /// Characters of context kept with each occurrence
    #[arg(long, default_value_t = 120, value_name = "N")]
    pub context: usize,

    /// Also report occurrences the evidence rules excluded, each tagged with its rule
    #[arg(
        long = "include-excluded",
        alias = "include-low-confidence",
        visible_alias = "include-low-confidence"
    )]
    pub include_excluded: bool,

    /// Scan members for embedded file signatures (needs --features carve)
    #[arg(long)]
    pub carve: bool,

    /// Write every unpacked member into this directory, under a hashed, sanitised name
    #[arg(long, value_name = "DIR")]
    pub extract: Option<PathBuf>,

    /// Skip executable parsing (headers, sections, imports, mitigations) for PE, ELF, and Mach-O
    #[arg(long = "no-exe", alias = "no-pe", visible_alias = "no-pe")]
    pub no_pe: bool,

    /// Maximum indicators of each kind to collect
    #[arg(long = "ioc-cap", default_value_t = 500, value_name = "N")]
    pub ioc_cap: usize,

    /// Look the hash up with VirusTotal and MetaDefender (hash only, never file content)
    #[arg(long)]
    pub reputation: bool,

    /// Resolve detected components against NVD for known CVEs
    #[arg(long)]
    pub cve: bool,

    /// Write one report per target instead of one combined report
    #[arg(long = "split")]
    pub split: bool,

    /// Scan every file found, not only executables and archives
    #[arg(long = "all-files")]
    pub all_files: bool,

    /// Maximum directory nesting depth when walking a directory target
    #[arg(long = "max-dir-depth", default_value_t = 16, value_name = "N")]
    pub max_dir_depth: usize,

    /// Maximum number of targets to scan in one run
    #[arg(long = "max-targets", default_value_t = 10_000, value_name = "N")]
    pub max_targets: usize,

    /// Maximum total bytes read from disk across all targets
    #[arg(long = "max-input-bytes", default_value_t = 64 * 1024 * 1024 * 1024, value_name = "BYTES")]
    pub max_input_bytes: u64,

    /// Mark images whose file name or Authenticode signer matches this regex as first-party
    #[arg(long = "first-party", value_name = "REGEX")]
    pub first_party: Option<String>,

    /// Skip third-party component detection (offline, on by default)
    #[arg(long = "no-components")]
    pub no_components: bool,

    /// Maximum CVEs to report per detected component
    #[arg(long = "cve-limit", default_value_t = 10, value_name = "N")]
    pub cve_limit: usize,

    /// Exit 1 when a finding at or above this severity is found, including a missing
    /// exploit mitigation
    #[arg(long, value_name = "SEVERITY")]
    pub fail_on: Option<FailOn>,
}

#[derive(clap::Subcommand, Debug)]
pub enum Commands {
    /// Fuzz Binspector's parsers, or drive an external engine
    ///
    /// Boxed because `FuzzArgs` is far larger than the other variant, and an enum sized for
    /// its biggest member would be copied around the scan path for no reason.
    Fuzz(Box<FuzzArgs>),
    /// Browse a saved report interactively (needs --features repl)
    Repl {
        /// A JSON or SQLite report produced by an earlier scan
        #[arg(value_name = "REPORT")]
        report: PathBuf,
    },
}

/// What the invocation asked for.
pub enum Action {
    Scan(Box<Resolved>),
    Fuzz(Box<FuzzArgs>),
    Repl(PathBuf),
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
    /// The target the scan runs against. For a multi-target run this is the first, kept so
    /// existing single-target call sites and messages read unchanged.
    pub binary: PathBuf,
    /// Every target named on the command line, before directory expansion.
    pub targets: Vec<PathBuf>,
    /// Write one report per target.
    pub split: bool,
    /// How a directory target is walked and filtered.
    pub select: crate::select::SelectConfig,
    /// Verbosity level from the `-v` count.
    pub verbose: u8,
    /// Suppress the banner.
    pub no_banner: bool,
    /// True when `output` is the timestamped default, so it is treated as a stem and gets
    /// a per-format extension.
    ///
    /// Also true when `-o` named a directory, because the stem inside it is that same timestamped
    /// default and needs the same naming mode.
    pub output_is_default: bool,
    /// Where to write unpacked members, when the caller asked for them.
    ///
    /// The only thing that makes a scan write anything from the target. Absent by default, which is
    /// what keeps the in-memory guarantee true for every ordinary run.
    pub extract: Option<PathBuf>,
    /// Network enrichment requested by the caller.
    pub reputation: bool,
    pub cve: bool,
    pub cve_limit: usize,
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

/// Whether a path as written ends in a separator, which is the caller stating "directory".
///
/// `Path` discards a trailing separator during component iteration, so this has to look at the
/// original text rather than ask `Path`. Both separators are accepted on Windows, where either is
/// valid in user input.
fn has_trailing_separator(p: &std::path::Path) -> bool {
    let s = p.as_os_str().to_string_lossy();
    s.ends_with('/') || (cfg!(windows) && s.ends_with('\\'))
}

impl Cli {
    pub fn resolve(self) -> Result<Action> {
        match self.command {
            Some(Commands::Fuzz(args)) => {
                args.validate()?;
                return Ok(Action::Fuzz(args));
            }
            Some(Commands::Repl { report }) => return Ok(Action::Repl(report)),
            None => {}
        }
        let binary = match self.binary.clone() {
            Some(b) => b,
            None => bail!(
                "no target given. Pass a binary to scan, or use `binspector fuzz --help` for \
                 the fuzzing modes."
            ),
        };
        // The first positional plus any extras, in the order given.
        let mut targets = vec![binary.clone()];
        targets.extend(self.more_targets.clone());
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

        // The deprecated --json flag only applies when --format was left at its default.
        let mut spec = self.format.clone();
        if self.json {
            notices.push("--json is deprecated; use --format json.".to_string());
            if spec == "text" {
                spec = "json".to_string();
            }
        }
        let formats = format::resolve(&spec)?;

        // `-o -` asks for stdout explicitly. Anything else, including no -o at all, writes
        // a file; without -o the name is a timestamped default matching the v1 naming.
        let to_stdout = self
            .output
            .as_deref()
            .is_some_and(|p| p == std::path::Path::new("-"));
        // An `-o` that names a directory is honoured as one. Without this, `-o out/` reached
        // `format::destination`, whose `Path::file_stem()` silently discards the trailing
        // separator, so the request became the stem `out` and the files landed *beside* the
        // directory rather than inside it. Reported against a real run where `tools/binspector/`
        // already existed and eight files were written next to it.
        //
        // Directory-ness is decided from either signal the caller can give: a trailing separator,
        // which is unambiguous intent, or an existing directory, which cannot be a file name.
        let given_is_dir = self
            .output
            .as_deref()
            .is_some_and(|p| !to_stdout && (has_trailing_separator(p) || p.is_dir()));

        let output: Option<PathBuf> = if to_stdout {
            None
        } else {
            Some(match self.output.clone() {
                // Inside the directory, under the same timestamped stem a bare run would use, so
                // `-o out/` and no `-o` at all differ only in where the files land.
                Some(dir) if given_is_dir => dir.join(format::default_stem()),
                Some(path) => path,
                None => PathBuf::from(format::default_stem()),
            })
        };
        if self.output.is_none() {
            notices.push(format!(
                "writing to {}.<format>. Pass -o FILE to choose a name, or -o - for stdout.",
                format::default_stem()
            ));
        }
        if given_is_dir {
            // Said plainly, because the resulting name is not the one the caller typed.
            if let Some(stem) = output.as_deref() {
                notices.push(format!(
                    "-o names a directory, so writing to {}.<format> inside it.",
                    stem.display()
                ));
            }
        }
        if to_stdout {
            if let Some(f) = formats.iter().find(|f| f.requires_path()) {
                bail!(
                    "--format {} writes a binary database and cannot go to stdout; pass -o FILE",
                    f.name()
                );
            }
            if formats.len() > 1 {
                bail!("several output formats cannot share stdout; pass -o to use as a stem");
            }
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

        // Compiled here so a bad pattern is a clear CLI error rather than a scan-time one.
        let first_party = match self.first_party.as_deref() {
            Some(p) => Some(
                Regex::new(p).map_err(|e| anyhow::anyhow!("invalid --first-party regex: {}", e))?,
            ),
            None => None,
        };
        // --dump across several targets works: the spools are concatenated, and every record
        // names its member, which is rooted at its target. It is simply large, so say so rather
        // than refusing: one bundle alone yields millions of strings.
        if self.dump && targets.len() > 1 {
            notices.push(format!(
                "--dump across {} targets writes every extracted string from all of them. Use \
                 -v or -vv to watch progress instead if you only want to see what the scan is \
                 doing.",
                targets.len()
            ));
        }
        // --split writes a file per target, so it cannot share stdout, mirroring the existing
        // rule for several formats.
        if self.split && to_stdout {
            bail!("--split writes one report per target and cannot share stdout; pass -o FILE");
        }
        let select = crate::select::SelectConfig {
            all_files: self.all_files,
            max_dir_depth: self.max_dir_depth,
            max_targets: self.max_targets,
            max_input_bytes: self.max_input_bytes,
            ..Default::default()
        };
        let scan = ScanConfig {
            extract: self.extract.clone(),
            first_party,
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
                carve: self.carve,
            },
            dump: self.dump,
            max_hits: self.max_hits,
            context_window: self.context,
            include_excluded: self.include_excluded,
            analyze_pe: !self.no_pe,
            ioc_cap: self.ioc_cap,
            detect_components: !self.no_components,
        };

        if self.verbose >= crate::observe::level::TRACE && self.banned_filter.is_none() {
            notices.push(
                "-vvv traces every extracted string, which is millions of lines on a large \
                 sample. Narrow it with --banned-filter or a larger --min-len, or expect the \
                 trace to be capped."
                    .to_string(),
            );
        }
        if self.carve && !crate::container::carve::available() {
            bail!("{}", crate::container::carve::unavailable_message());
        }
        if (self.reputation || self.cve) && self.no_components && self.cve {
            bail!("--cve needs component detection; remove --no-components");
        }

        Ok(Action::Scan(Box::new(Resolved {
            binary,
            targets,
            split: self.split,
            select,
            verbose: self.verbose,
            no_banner: self.no_banner,
            // A directory counts as default naming: the stem is the timestamped one, so it must
            // get `Naming::Append` and keep the dots in the stamp rather than having
            // `ReplaceExtension` treat `2026.10.01-15.34.50` as an extension to replace.
            output_is_default: (self.output.is_none() || given_is_dir) && !to_stdout,
            extract: self.extract.clone(),
            reputation: self.reputation,
            cve: self.cve,
            cve_limit: self.cve_limit,
            scan,
            formats,
            output,
            matches_only: self.matches_only,
            dump: self.dump,
            color: self.color,
            palette: self.palette,
            fail_on: self.fail_on,
            notices,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Result<Resolved> {
        let mut full = vec!["binspector"];
        full.extend_from_slice(args);
        match Cli::try_parse_from(full)?.resolve()? {
            Action::Scan(r) => Ok(*r),
            Action::Fuzz(_) => anyhow::bail!("expected a scan, got the fuzz subcommand"),
            Action::Repl(_) => anyhow::bail!("expected a scan, got the repl subcommand"),
        }
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
    fn removed_ignore_case_flag_is_rejected() {
        // Removed in 4.0.0. Matching is case insensitive by default, so the flag had
        // no effect; clap now reports it as unknown rather than silently accepting it.
        let err = Cli::try_parse_from(["binspector", "--ignore-case", "file.bin"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("--ignore-case"), "{}", err);
    }

    #[test]
    fn the_original_command_line_still_works_without_that_flag() {
        let r = parse(&["-p", "PROJ-123", "-o", "out.txt", "file.bin"]).unwrap();
        assert!(!r.scan.case_sensitive);
        assert_eq!(r.scan.project.as_deref(), Some("PROJ-123"));
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
    fn a_missing_output_gets_a_timestamped_default() {
        let r = parse(&["file.bin"]).unwrap();
        let path = r.output.expect("a default path").display().to_string();
        assert!(path.starts_with("binspector_output-"), "got {}", path);
        assert!(r.notices.iter().any(|n| n.contains("Pass -o FILE")));
    }

    #[test]
    fn the_default_stem_is_flagged_so_it_gains_an_extension() {
        assert!(parse(&["file.bin"]).unwrap().output_is_default);
        assert!(
            !parse(&["file.bin", "-o", "mine.txt"])
                .unwrap()
                .output_is_default
        );
        assert!(!parse(&["file.bin", "-o", "-"]).unwrap().output_is_default);
    }

    /// The reported bug: `-o tools/binspector/` wrote `tools/binspector.txt` beside the directory
    /// instead of inside it, because `format::destination` derives a stem through
    /// `Path::file_stem()`, which discards a trailing separator.
    #[test]
    fn a_trailing_separator_means_a_directory_not_a_stem() {
        let r = parse(&["file.bin", "-o", "tools/binspector/"]).unwrap();
        let path = r.output.expect("a path");
        assert_eq!(
            path.parent().map(|p| p.to_string_lossy().to_string()),
            Some("tools/binspector".to_string()),
            "the directory must be kept, got {}",
            path.display()
        );
        assert!(
            path.file_name()
                .map(|n| n.to_string_lossy().starts_with("binspector_output-"))
                .unwrap_or(false),
            "the timestamped stem goes inside it, got {}",
            path.display()
        );
        assert!(
            r.output_is_default,
            "a directory must use Naming::Append, or ReplaceExtension eats the stamp's dots"
        );
        assert!(r.notices.iter().any(|n| n.contains("names a directory")));
    }

    /// The other half of the same bug: an existing directory cannot be a file name, whether or not
    /// the caller typed a separator.
    #[test]
    fn an_existing_directory_is_treated_as_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let given = dir.path().to_string_lossy().to_string();
        let r = parse(&["file.bin", "-o", &given]).unwrap();
        let path = r.output.expect("a path");
        assert_eq!(path.parent(), Some(dir.path()));
        assert!(r.output_is_default);
    }

    /// And the case that must not change: a plain stem keeps today's exact semantics, so no
    /// existing invocation moves.
    #[test]
    fn a_plain_stem_is_still_a_stem() {
        let r = parse(&["file.bin", "-o", "out/scan"]).unwrap();
        assert_eq!(
            r.output.as_deref(),
            Some(std::path::Path::new("out/scan")),
            "a non-directory path is used verbatim"
        );
        assert!(!r.output_is_default);
        assert!(!r.notices.iter().any(|n| n.contains("names a directory")));
    }

    #[test]
    fn stdout_is_never_mistaken_for_a_directory() {
        let r = parse(&["file.bin", "-o", "-"]).unwrap();
        assert!(r.output.is_none());
        assert!(!r.output_is_default);
    }

    #[test]
    fn an_explicit_output_overrides_the_default() {
        let r = parse(&["file.bin", "-o", "mine.txt"]).unwrap();
        assert_eq!(r.output.unwrap().display().to_string(), "mine.txt");
    }

    #[test]
    fn dash_means_stdout() {
        let r = parse(&["file.bin", "-o", "-"]).unwrap();
        assert!(r.output.is_none(), "-o - should mean stdout");
    }

    #[test]
    fn sqlite_and_multi_format_now_work_without_an_output_flag() {
        // Both previously required -o; the timestamped default supplies one.
        assert!(parse(&["file.bin", "--format", "json,csv"]).is_ok());
        // Only meaningful where the format exists at all; a build without it rejects the
        // name outright, which `naming_an_unavailable_format_is_an_error_not_a_silent_skip`
        // covers.
        if cfg!(feature = "sqlite") {
            assert!(parse(&["file.bin", "--format", "sqlite"]).is_ok());
        }
    }

    #[test]
    fn stdout_still_cannot_take_sqlite_or_several_formats() {
        if cfg!(feature = "sqlite") {
            let err = parse(&["file.bin", "--format", "sqlite", "-o", "-"])
                .unwrap_err()
                .to_string();
            assert!(err.contains("cannot go to stdout"), "got {}", err);
        }
        let err = parse(&["file.bin", "--format", "json,csv", "-o", "-"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot share stdout"), "got {}", err);
    }

    #[test]
    fn no_banner_flag_is_carried_through() {
        assert!(!parse(&["file.bin"]).unwrap().no_banner);
        assert!(parse(&["file.bin", "--no-banner"]).unwrap().no_banner);
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
    fn verbose_count_reaches_resolved() {
        assert_eq!(parse(&["file.bin"]).unwrap().verbose, 0);
        assert_eq!(parse(&["file.bin", "-v"]).unwrap().verbose, 1);
        assert_eq!(parse(&["file.bin", "-vv"]).unwrap().verbose, 2);
        assert_eq!(parse(&["file.bin", "-vvv"]).unwrap().verbose, 3);
        assert_eq!(
            parse(&["file.bin", "--verbose", "--verbose"])
                .unwrap()
                .verbose,
            2
        );
    }

    #[test]
    fn trace_level_warns_about_volume_unless_narrowed() {
        let r = parse(&["file.bin", "-vvv"]).unwrap();
        assert!(r
            .notices
            .iter()
            .any(|n| n.contains("traces every extracted string")));
        // A filter means the user has already narrowed, so no lecture.
        let narrowed = parse(&["file.bin", "-vvv", "--banned-filter", "^str"]).unwrap();
        assert!(!narrowed.notices.iter().any(|n| n.contains("traces every")));
    }

    #[test]
    fn excluded_occurrences_are_omitted_by_default() {
        let r = parse(&["file.bin"]).unwrap();
        assert!(!r.scan.include_excluded);
        let r = parse(&["file.bin", "--include-low-confidence"]).unwrap();
        assert!(r.scan.include_excluded);
    }

    #[test]
    fn limits_are_plumbed_through() {
        let r = parse(&["file.bin", "--max-depth", "2", "--max-expansion-ratio", "7"]).unwrap();
        assert_eq!(r.scan.limits.max_depth, 2);
        assert_eq!(r.scan.limits.max_expansion_ratio, 7);
    }
}
