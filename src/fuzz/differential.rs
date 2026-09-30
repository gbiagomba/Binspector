//! Parser-differential fuzzing against a review sample.
//!
//! This is the modern equivalent of the legacy `zzuf ... objdump -x $bin` trick: it
//! mutates the sample and feeds the mutants to Binspector's own parsers, looking for
//! panics, hangs, and runaway allocation. It works on any host and, importantly, it
//! never executes the sample. Fuzzing a third-party binary by running it is a
//! different and far more dangerous activity, and is not what this does.

use anyhow::{Context, Result};
use serde::Serialize;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::time::{Duration, Instant};

use super::mutate::{mutate, Kind, Rng};
use crate::container::{self, Limits};
use crate::pe::PeAnalysis;
use crate::scan::strings;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Target {
    /// ASCII and UTF-16LE string extraction.
    Strings,
    /// Container detection and recursive unpacking.
    Container,
    /// PE header, section, and import parsing.
    Pe,
    /// Every parser in sequence, as a real scan would.
    All,
}

impl Target {
    pub fn name(self) -> &'static str {
        match self {
            Target::Strings => "strings",
            Target::Container => "container",
            Target::Pe => "pe",
            Target::All => "all",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub kind: String,
    pub target: Target,
    pub mutation: String,
    pub iteration: u64,
    pub seed: u64,
    pub input_len: usize,
    pub detail: String,
    /// Where the reproducing input was written.
    pub artifact: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Campaign {
    pub target: Target,
    pub seed: u64,
    pub iterations: u64,
    pub executions: u64,
    pub findings: Vec<Finding>,
    pub elapsed_secs: f64,
    /// Slowest single execution, which is how a hang shows up.
    pub slowest_ms: u128,
}

impl Campaign {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

pub struct Options {
    pub target: Target,
    pub seed: u64,
    pub iterations: u64,
    /// An execution slower than this is reported as a hang.
    pub hang_threshold: Duration,
    pub max_len: usize,
    /// Directory for reproducing inputs. None keeps findings in memory only.
    pub artifact_dir: Option<std::path::PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            target: Target::All,
            seed: 0,
            iterations: 1000,
            hang_threshold: Duration::from_secs(5),
            max_len: 8 * 1024 * 1024,
            artifact_dir: None,
        }
    }
}

/// Run a differential campaign against `seed_input`.
pub fn run(seed_input: &[u8], opts: &Options) -> Result<Campaign> {
    let started = Instant::now();
    let mut rng = Rng::new(opts.seed);
    let mut findings = Vec::new();
    let mut executions = 0u64;
    let mut slowest_ms = 0u128;

    // Panic messages are captured rather than printed, so a run of thousands of
    // iterations does not flood the terminal with backtraces.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    for iteration in 0..opts.iterations {
        let (input, kind) = mutate(seed_input, &mut rng, opts.max_len);
        let t0 = Instant::now();
        let outcome = exercise(&input, opts.target);
        let elapsed = t0.elapsed();
        executions += 1;
        slowest_ms = slowest_ms.max(elapsed.as_millis());

        if let Err(detail) = outcome {
            findings.push(make_finding(
                "panic", opts, kind, iteration, &input, detail, &mut rng,
            )?);
        } else if elapsed > opts.hang_threshold {
            findings.push(make_finding(
                "hang",
                opts,
                kind,
                iteration,
                &input,
                format!("took {} ms", elapsed.as_millis()),
                &mut rng,
            )?);
        }
    }

    std::panic::set_hook(prev_hook);

    Ok(Campaign {
        target: opts.target,
        seed: opts.seed,
        iterations: opts.iterations,
        executions,
        findings,
        elapsed_secs: started.elapsed().as_secs_f64(),
        slowest_ms,
    })
}

fn make_finding(
    kind: &str,
    opts: &Options,
    mutation: Kind,
    iteration: u64,
    input: &[u8],
    detail: String,
    _rng: &mut Rng,
) -> Result<Finding> {
    let artifact = match &opts.artifact_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
            let name = format!(
                "{}-{}-seed{}-iter{}.bin",
                kind,
                opts.target.name(),
                opts.seed,
                iteration
            );
            let path = dir.join(name);
            std::fs::write(&path, input).with_context(|| format!("writing {}", path.display()))?;
            Some(path.display().to_string())
        }
        None => None,
    };
    Ok(Finding {
        kind: kind.to_string(),
        target: opts.target,
        mutation: mutation.name().to_string(),
        iteration,
        seed: opts.seed,
        input_len: input.len(),
        detail,
        artifact,
    })
}

/// Drive the parsers. Returns Err with the panic message when one panics.
fn exercise(input: &[u8], target: Target) -> std::result::Result<(), String> {
    let result = catch_unwind(AssertUnwindSafe(|| match target {
        Target::Strings => {
            strings::extract(input, 4, true, true);
        }
        Target::Pe => {
            PeAnalysis::parse(input);
        }
        Target::Container => {
            let limits = tight_limits();
            let _ = container::walk_bytes(input, "fuzz".to_string(), limits, &mut |_| Ok(()));
        }
        Target::All => {
            strings::extract(input, 4, true, true);
            PeAnalysis::parse(input);
            let limits = tight_limits();
            let _ = container::walk_bytes(input, "fuzz".to_string(), limits, &mut |m| {
                strings::extract(m.data, 4, true, true);
                PeAnalysis::parse(m.data);
                Ok(())
            });
        }
    }));
    result.map_err(|e| panic_message(&e))
}

/// Tight caps so a mutated archive header cannot make the fuzzer itself the bomb.
fn tight_limits() -> Limits {
    Limits {
        max_depth: 3,
        max_total_bytes: 64 * 1024 * 1024,
        max_member_bytes: 16 * 1024 * 1024,
        max_expansion_ratio: 50,
        max_members: 500,
    }
}

fn panic_message(e: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = e.downcast_ref::<&str>() {
        return (*s).to_string();
    }
    if let Some(s) = e.downcast_ref::<String>() {
        return s.clone();
    }
    "panic with a non-string payload".to_string()
}

/// Read a seed input from disk.
pub fn read_seed(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading seed {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn zip_seed() -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
            w.start_file("a.bin", zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(b"\x00strcpy\x00some payload\x00").unwrap();
            w.finish().unwrap();
        }
        buf
    }

    #[test]
    fn campaign_runs_and_reports_executions() {
        let opts = Options {
            iterations: 200,
            seed: 1,
            ..Default::default()
        };
        let c = run(&zip_seed(), &opts).unwrap();
        assert_eq!(c.executions, 200);
        assert_eq!(c.iterations, 200);
        assert!(c.elapsed_secs >= 0.0);
    }

    /// The point of the whole mode: the parsers must survive arbitrary mutation.
    #[test]
    fn parsers_survive_mutation_of_a_zip_seed() {
        let opts = Options {
            iterations: 1500,
            seed: 20260930,
            ..Default::default()
        };
        let c = run(&zip_seed(), &opts).unwrap();
        assert!(c.is_clean(), "findings: {:?}", c.findings);
    }

    #[test]
    fn parsers_survive_mutation_of_pe_like_input() {
        let mut pe = vec![0u8; 0x200];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        let opts = Options {
            target: Target::Pe,
            iterations: 1500,
            seed: 4242,
            ..Default::default()
        };
        let c = run(&pe, &opts).unwrap();
        assert!(c.is_clean(), "findings: {:?}", c.findings);
    }

    #[test]
    fn each_target_can_be_selected() {
        for t in [Target::Strings, Target::Container, Target::Pe, Target::All] {
            let opts = Options {
                target: t,
                iterations: 50,
                ..Default::default()
            };
            let c = run(b"\x00seed bytes here\x00", &opts).unwrap();
            assert_eq!(c.target, t);
            assert!(c.is_clean(), "{} findings: {:?}", t.name(), c.findings);
        }
    }

    #[test]
    fn same_seed_gives_the_same_campaign() {
        let seed_input = zip_seed();
        let opts = || Options {
            iterations: 300,
            seed: 77,
            ..Default::default()
        };
        let a = run(&seed_input, &opts()).unwrap();
        let b = run(&seed_input, &opts()).unwrap();
        assert_eq!(a.findings.len(), b.findings.len());
        assert_eq!(a.executions, b.executions);
    }

    #[test]
    fn writes_a_reproducing_artifact_when_a_directory_is_given() {
        // Forced by a hang threshold of zero, so every execution is "slow".
        let dir = tempfile::tempdir().unwrap();
        let opts = Options {
            iterations: 1,
            hang_threshold: Duration::from_nanos(0),
            artifact_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let c = run(b"seed", &opts).unwrap();
        assert_eq!(c.findings.len(), 1);
        let path = c.findings[0].artifact.as_ref().expect("artifact path");
        assert!(std::path::Path::new(path).exists());
        assert_eq!(c.findings[0].kind, "hang");
    }

    #[test]
    fn empty_seed_is_handled() {
        let opts = Options {
            iterations: 100,
            ..Default::default()
        };
        assert!(run(b"", &opts).unwrap().is_clean());
    }
}
