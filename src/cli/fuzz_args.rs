//! Arguments for the `fuzz` subcommand.

use anyhow::{bail, Result};
use clap::Args;
use std::path::PathBuf;
use std::time::Duration;

use crate::fuzz::differential;
use crate::fuzz::engine::Engine;

#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum FuzzTarget {
    Strings,
    Container,
    Pe,
    All,
}

impl From<FuzzTarget> for differential::Target {
    fn from(t: FuzzTarget) -> Self {
        match t {
            FuzzTarget::Strings => differential::Target::Strings,
            FuzzTarget::Container => differential::Target::Container,
            FuzzTarget::Pe => differential::Target::Pe,
            FuzzTarget::All => differential::Target::All,
        }
    }
}

#[derive(Args, Debug)]
#[command(
    about = "Fuzz Binspector's parsers, or drive an external engine",
    long_about = "Three modes.\n\n\
        --differential <FILE> mutates a sample and feeds the mutants to Binspector's own \
        parsers, looking for panics and hangs. It runs anywhere and never executes the \
        sample.\n\n\
        --corpus-from <FILE> unpacks a sample into a seed corpus, so an engine starts from \
        the real formats rather than random bytes.\n\n\
        --engine <ENGINE> prepares and runs AFL++, honggfuzz, libFuzzer, or WinAFL against \
        a harness you supply. These engines drive an instrumented harness; none of them can \
        blackbox-fuzz an arbitrary bundle with no harness and no entry point, and WinAFL \
        additionally needs a Windows host with DynamoRIO."
)]
pub struct FuzzArgs {
    /// Mutate this sample and feed the mutants to Binspector's own parsers
    #[arg(long, value_name = "FILE")]
    pub differential: Option<PathBuf>,

    /// Which parser to exercise in differential mode
    #[arg(long, value_enum, default_value_t = FuzzTarget::All)]
    pub target: FuzzTarget,

    /// Iterations to run in differential mode
    #[arg(long, default_value_t = 10_000, value_name = "N")]
    pub iterations: u64,

    /// Mutation seed. The same seed reproduces the same campaign
    #[arg(long, default_value_t = 0, value_name = "N")]
    pub seed: u64,

    /// An execution slower than this many seconds counts as a hang
    #[arg(long = "hang-secs", default_value_t = 5, value_name = "N")]
    pub hang_secs: u64,

    /// Build a seed corpus from this sample
    #[arg(long = "corpus-from", value_name = "FILE")]
    pub corpus_from: Option<PathBuf>,

    /// Corpus directory. Defaults to fuzz/corpus/<sample stem>
    #[arg(long, value_name = "DIR")]
    pub corpus: Option<PathBuf>,

    /// External engine to prepare or run
    #[arg(long, value_enum)]
    pub engine: Option<Engine>,

    /// Instrumented harness the engine should drive
    #[arg(long, value_name = "PATH")]
    pub harness: Option<PathBuf>,

    /// Engine output directory
    #[arg(long, default_value = "fuzz/out", value_name = "DIR")]
    pub output: PathBuf,

    /// Stop the engine after this many seconds
    #[arg(long = "run-secs", value_name = "N")]
    pub run_secs: Option<u64>,

    /// WinAFL: module to instrument
    #[arg(long = "target-module", value_name = "NAME")]
    pub target_module: Option<String>,

    /// WinAFL: offset of the function to exercise
    #[arg(long = "target-offset", value_name = "OFFSET")]
    pub target_offset: Option<String>,

    /// Print the engine command without running it
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// Where to write reproducing inputs from differential mode
    #[arg(
        long = "artifact-dir",
        default_value = "fuzz/artifacts",
        value_name = "DIR"
    )]
    pub artifact_dir: PathBuf,

    /// Emit the campaign result as JSON
    #[arg(long)]
    pub json: bool,

    /// Exit non-zero when the campaign finds anything
    #[arg(long = "fail-on-finding")]
    pub fail_on_finding: bool,
}

impl FuzzArgs {
    pub fn validate(&self) -> Result<()> {
        let modes = [
            self.differential.is_some(),
            self.corpus_from.is_some(),
            self.engine.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count();
        if modes == 0 {
            bail!(
                "pick a mode: --differential <FILE> to fuzz Binspector's parsers, \
                 --corpus-from <FILE> to build a seed corpus, or --engine <ENGINE> to drive an \
                 external fuzzer"
            );
        }
        if self.engine.is_some() && self.harness.is_none() {
            bail!(
                "--engine needs --harness: these engines drive an instrumented harness, and \
                 cannot fuzz an arbitrary binary without one"
            );
        }
        if self.iterations == 0 {
            bail!("--iterations must be at least 1");
        }
        Ok(())
    }

    pub fn differential_options(&self) -> differential::Options {
        differential::Options {
            target: self.target.into(),
            seed: self.seed,
            iterations: self.iterations,
            hang_threshold: Duration::from_secs(self.hang_secs.max(1)),
            max_len: 8 * 1024 * 1024,
            artifact_dir: Some(self.artifact_dir.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrapper {
        #[command(flatten)]
        args: FuzzArgs,
    }

    fn parse(extra: &[&str]) -> FuzzArgs {
        let mut v = vec!["fuzz"];
        v.extend_from_slice(extra);
        Wrapper::try_parse_from(v).expect("parses").args
    }

    #[test]
    fn requires_a_mode() {
        let err = parse(&[]).validate().unwrap_err().to_string();
        assert!(err.contains("pick a mode"));
        assert!(err.contains("--differential"));
    }

    #[test]
    fn differential_mode_validates() {
        assert!(parse(&["--differential", "s.bin"]).validate().is_ok());
    }

    #[test]
    fn engine_mode_requires_a_harness() {
        let err = parse(&["--engine", "afl-plus-plus"])
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("--harness"), "{}", err);
        assert!(parse(&["--engine", "afl-plus-plus", "--harness", "h"])
            .validate()
            .is_ok());
    }

    #[test]
    fn rejects_zero_iterations() {
        let err = parse(&["--differential", "s", "--iterations", "0"])
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("at least 1"));
    }

    #[test]
    fn target_maps_to_the_differential_target() {
        let a = parse(&["--differential", "s", "--target", "pe"]);
        assert_eq!(a.differential_options().target, differential::Target::Pe);
        let b = parse(&["--differential", "s"]);
        assert_eq!(b.differential_options().target, differential::Target::All);
    }

    #[test]
    fn seed_and_iterations_reach_the_options() {
        let a = parse(&["--differential", "s", "--seed", "7", "--iterations", "42"]);
        let o = a.differential_options();
        assert_eq!(o.seed, 7);
        assert_eq!(o.iterations, 42);
    }

    #[test]
    fn hang_threshold_is_never_zero() {
        let a = parse(&["--differential", "s", "--hang-secs", "0"]);
        assert!(a.differential_options().hang_threshold >= Duration::from_secs(1));
    }

    #[test]
    fn corpus_mode_validates_alone() {
        assert!(parse(&["--corpus-from", "s.msixbundle"]).validate().is_ok());
    }
}
