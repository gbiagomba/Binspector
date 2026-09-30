//! External fuzzing engine orchestration.
//!
//! This is where the request and the tooling diverge, so the boundary is stated in the
//! code rather than left for a user to discover.
//!
//! AFL++, honggfuzz, and libFuzzer drive a *harness*: a program built with coverage
//! instrumentation that reads an input and feeds it to the code under test. WinAFL
//! instead instruments a Windows binary at runtime through DynamoRIO, and needs a
//! target module plus an offset for the function to exercise.
//!
//! None of these can blackbox-fuzz an arbitrary `.msixbundle` with no harness and no
//! entry point. What Binspector does is prepare and drive a campaign: build the seed
//! corpus from the members it already extracted, assemble the correct command line,
//! supervise the run, and parse the crash directory back into the standard report
//! formats. Running it still needs the engine installed, and for WinAFL a Windows host
//! with DynamoRIO.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Engine {
    /// AFL++ via afl-fuzz. Needs an instrumented harness.
    #[value(
        name = "afl++",
        alias = "afl",
        alias = "aflplusplus",
        alias = "afl-plus-plus"
    )]
    AflPlusPlus,
    /// honggfuzz. Needs an instrumented harness.
    #[value(name = "honggfuzz", alias = "hfuzz")]
    Honggfuzz,
    /// libFuzzer, usually through cargo-fuzz for Rust targets.
    #[value(name = "libfuzzer", alias = "lib-fuzzer", alias = "cargo-fuzz")]
    LibFuzzer,
    /// WinAFL through DynamoRIO. Windows only, needs a target module and offset.
    #[value(name = "winafl", alias = "win-afl")]
    WinAfl,
}

impl Engine {
    pub fn name(self) -> &'static str {
        match self {
            Engine::AflPlusPlus => "afl++",
            Engine::Honggfuzz => "honggfuzz",
            Engine::LibFuzzer => "libfuzzer",
            Engine::WinAfl => "winafl",
        }
    }

    pub fn binary(self) -> &'static str {
        match self {
            Engine::AflPlusPlus => "afl-fuzz",
            Engine::Honggfuzz => "honggfuzz",
            Engine::LibFuzzer => "cargo",
            Engine::WinAfl => "afl-fuzz.exe",
        }
    }

    /// Where this engine writes crashing inputs, relative to the output directory.
    pub fn crash_subdir(self) -> &'static str {
        match self {
            Engine::AflPlusPlus | Engine::WinAfl => "default/crashes",
            Engine::Honggfuzz => "",
            Engine::LibFuzzer => "artifacts",
        }
    }

    pub fn requires_windows(self) -> bool {
        matches!(self, Engine::WinAfl)
    }
}

pub struct Plan {
    pub engine: Engine,
    pub harness: PathBuf,
    pub corpus: PathBuf,
    pub output: PathBuf,
    pub timeout_secs: Option<u64>,
    /// WinAFL only: the module to instrument.
    pub target_module: Option<String>,
    /// WinAFL only: the offset of the function to exercise.
    pub target_offset: Option<String>,
    pub extra_args: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PreparedCommand {
    pub program: String,
    pub args: Vec<String>,
    /// The command as a copy-pasteable line.
    pub display: String,
    pub notes: Vec<String>,
}

/// Build the engine command line without running anything.
pub fn plan(p: &Plan) -> Result<PreparedCommand> {
    if !p.corpus.exists() {
        bail!(
            "corpus directory {} does not exist. Build one first with `binspector fuzz \
             --corpus-from <sample>`.",
            p.corpus.display()
        );
    }
    let mut notes = Vec::new();
    if p.engine.requires_windows() && !cfg!(windows) {
        notes.push(format!(
            "{} instruments Windows binaries through DynamoRIO and cannot run on this host. \
             The command below is prepared for a Windows machine.",
            p.engine.name()
        ));
    }

    let mut args: Vec<String> = Vec::new();
    match p.engine {
        Engine::AflPlusPlus => {
            args.push("-i".into());
            args.push(p.corpus.display().to_string());
            args.push("-o".into());
            args.push(p.output.display().to_string());
            if let Some(t) = p.timeout_secs {
                args.push("-V".into());
                args.push(t.to_string());
            }
            args.push("--".into());
            args.push(p.harness.display().to_string());
            args.push("@@".into());
        }
        Engine::Honggfuzz => {
            args.push("-i".into());
            args.push(p.corpus.display().to_string());
            args.push("-W".into());
            args.push(p.output.display().to_string());
            if let Some(t) = p.timeout_secs {
                args.push("--run_time".into());
                args.push(t.to_string());
            }
            args.push("--".into());
            args.push(p.harness.display().to_string());
            args.push("___FILE___".into());
        }
        Engine::LibFuzzer => {
            // cargo-fuzz owns the corpus and artifact layout.
            args.push("fuzz".into());
            args.push("run".into());
            args.push(
                p.harness
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "target".into()),
            );
            args.push(p.corpus.display().to_string());
            if let Some(t) = p.timeout_secs {
                args.push("--".into());
                args.push(format!("-max_total_time={}", t));
            }
        }
        Engine::WinAfl => {
            let module = p.target_module.as_ref().ok_or_else(|| {
                anyhow::anyhow!("winafl needs --target-module, the module to instrument")
            })?;
            let offset = p.target_offset.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "winafl needs --target-offset, the offset of the function to exercise"
                )
            })?;
            args.push("-i".into());
            args.push(p.corpus.display().to_string());
            args.push("-o".into());
            args.push(p.output.display().to_string());
            args.push("-D".into());
            args.push("C:\\DynamoRIO\\bin64".into());
            args.push("-t".into());
            args.push("20000".into());
            args.push("--".into());
            args.push("-coverage_module".into());
            args.push(module.clone());
            args.push("-target_module".into());
            args.push(module.clone());
            args.push("-target_offset".into());
            args.push(offset.clone());
            args.push("-nargs".into());
            args.push("1".into());
            args.push("--".into());
            args.push(p.harness.display().to_string());
            args.push("@@".into());
        }
    }
    args.extend(p.extra_args.iter().cloned());

    let program = p.engine.binary().to_string();
    let display = format!("{} {}", program, shell_join(&args));
    Ok(PreparedCommand {
        program,
        args,
        display,
        notes,
    })
}

/// True when the engine binary is on PATH.
pub fn is_installed(engine: Engine) -> bool {
    Command::new(engine.binary())
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success() || s.code() == Some(1))
        .unwrap_or(false)
}

/// Run a prepared campaign, streaming engine output through.
pub fn execute(cmd: &PreparedCommand) -> Result<i32> {
    let status = Command::new(&cmd.program)
        .args(&cmd.args)
        .status()
        .with_context(|| format!("running {}", cmd.program))?;
    Ok(status.code().unwrap_or(-1))
}

#[derive(Clone, Debug, Serialize)]
pub struct CrashReport {
    pub engine: Engine,
    pub crash_dir: String,
    pub crashes: Vec<String>,
}

/// Collect crashing inputs an engine left behind.
pub fn collect_crashes(engine: Engine, output: &Path) -> Result<CrashReport> {
    let dir = if engine.crash_subdir().is_empty() {
        output.to_path_buf()
    } else {
        output.join(engine.crash_subdir())
    };
    let mut crashes = Vec::new();
    if dir.exists() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .flatten()
        {
            let name = entry.file_name().to_string_lossy().to_string();
            // AFL writes bookkeeping files alongside the crashing inputs.
            if name == "README.txt" || name.starts_with('.') {
                continue;
            }
            if entry.path().is_file() {
                crashes.push(entry.path().display().to_string());
            }
        }
    }
    crashes.sort();
    Ok(CrashReport {
        engine,
        crash_dir: dir.display().to_string(),
        crashes,
    })
}

fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|a| {
            if a.contains(' ') {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(engine: Engine, dir: &Path) -> Plan {
        let corpus = dir.join("corpus");
        std::fs::create_dir_all(&corpus).unwrap();
        Plan {
            engine,
            harness: PathBuf::from("./target/release/harness"),
            corpus,
            output: dir.join("out"),
            timeout_secs: Some(60),
            target_module: None,
            target_offset: None,
            extra_args: vec![],
        }
    }

    #[test]
    fn afl_plan_uses_input_output_and_file_placeholder() {
        let d = tempfile::tempdir().unwrap();
        let c = plan(&base(Engine::AflPlusPlus, d.path())).unwrap();
        assert_eq!(c.program, "afl-fuzz");
        assert!(c.display.contains("-i "));
        assert!(c.display.contains("-o "));
        assert!(c.display.contains("-V 60"));
        assert!(c.display.trim_end().ends_with("@@"));
    }

    #[test]
    fn honggfuzz_plan_uses_its_own_placeholder() {
        let d = tempfile::tempdir().unwrap();
        let c = plan(&base(Engine::Honggfuzz, d.path())).unwrap();
        assert_eq!(c.program, "honggfuzz");
        assert!(c.display.contains("___FILE___"));
        assert!(c.display.contains("--run_time 60"));
    }

    #[test]
    fn libfuzzer_plan_goes_through_cargo_fuzz() {
        let d = tempfile::tempdir().unwrap();
        let c = plan(&base(Engine::LibFuzzer, d.path())).unwrap();
        assert_eq!(c.program, "cargo");
        assert!(c.args.starts_with(&["fuzz".to_string(), "run".to_string()]));
        assert!(c.display.contains("-max_total_time=60"));
    }

    #[test]
    fn winafl_requires_module_and_offset() {
        let d = tempfile::tempdir().unwrap();
        let err = plan(&base(Engine::WinAfl, d.path()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("--target-module"), "{}", err);

        let mut p = base(Engine::WinAfl, d.path());
        p.target_module = Some("App.exe".into());
        let err = plan(&p).unwrap_err().to_string();
        assert!(err.contains("--target-offset"), "{}", err);

        p.target_offset = Some("0x1234".into());
        let c = plan(&p).unwrap();
        assert!(c.display.contains("-target_module App.exe"));
        assert!(c.display.contains("-target_offset 0x1234"));
        assert!(c.display.contains("DynamoRIO"));
    }

    #[test]
    fn winafl_on_a_non_windows_host_says_so_rather_than_pretending() {
        let d = tempfile::tempdir().unwrap();
        let mut p = base(Engine::WinAfl, d.path());
        p.target_module = Some("App.exe".into());
        p.target_offset = Some("0x1".into());
        let c = plan(&p).unwrap();
        if !cfg!(windows) {
            assert!(
                c.notes
                    .iter()
                    .any(|n| n.contains("cannot run on this host")),
                "notes: {:?}",
                c.notes
            );
        }
    }

    #[test]
    fn missing_corpus_is_an_error_with_a_next_step() {
        let d = tempfile::tempdir().unwrap();
        let mut p = base(Engine::AflPlusPlus, d.path());
        p.corpus = d.path().join("absent");
        let err = plan(&p).unwrap_err().to_string();
        assert!(err.contains("does not exist"));
        assert!(err.contains("--corpus-from"));
    }

    #[test]
    fn collects_crashes_and_ignores_afl_bookkeeping() {
        let d = tempfile::tempdir().unwrap();
        let crashes = d.path().join("default/crashes");
        std::fs::create_dir_all(&crashes).unwrap();
        std::fs::write(crashes.join("id:000000,sig:11"), b"crashing input").unwrap();
        std::fs::write(crashes.join("README.txt"), b"afl notes").unwrap();
        let r = collect_crashes(Engine::AflPlusPlus, d.path()).unwrap();
        assert_eq!(r.crashes.len(), 1);
        assert!(r.crashes[0].contains("id:000000"));
    }

    #[test]
    fn absent_crash_dir_is_not_an_error() {
        let d = tempfile::tempdir().unwrap();
        let r = collect_crashes(Engine::AflPlusPlus, d.path()).unwrap();
        assert!(r.crashes.is_empty());
    }

    #[test]
    fn engine_values_use_natural_names() {
        use clap::ValueEnum;
        let names: Vec<String> = Engine::value_variants()
            .iter()
            .filter_map(|e| e.to_possible_value().map(|v| v.get_name().to_string()))
            .collect();
        assert_eq!(names, vec!["afl++", "honggfuzz", "libfuzzer", "winafl"]);
        // The derived kebab spellings stay accepted as aliases.
        for spelling in ["afl++", "afl", "aflplusplus", "afl-plus-plus"] {
            assert_eq!(
                Engine::from_str(spelling, true).unwrap(),
                Engine::AflPlusPlus,
                "spelling {}",
                spelling
            );
        }
        assert_eq!(
            Engine::from_str("libfuzzer", true).unwrap(),
            Engine::LibFuzzer
        );
        assert_eq!(Engine::from_str("winafl", true).unwrap(), Engine::WinAfl);
    }

    #[test]
    fn shell_join_quotes_paths_with_spaces() {
        let joined = shell_join(&["-i".into(), "/a path/corpus".into()]);
        assert_eq!(joined, "-i '/a path/corpus'");
    }
}
