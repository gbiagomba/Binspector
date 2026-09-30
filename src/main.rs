//! Binspector command line entry point.

use anyhow::Result;
use clap::Parser;
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use binspector::cli::color::{ColorChoice, Theme};
use binspector::cli::{format, Action, Cli};
use binspector::fuzz;
use binspector::intel;
use binspector::report::{self, RenderOpts};
use binspector::scan;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("binspector: {:#}", e);
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    match Cli::parse().resolve()? {
        Action::Fuzz(args) => run_fuzz(&args),
        Action::Scan(resolved) => run_scan(&resolved),
    }
}

fn run_fuzz(args: &binspector::cli::fuzz_args::FuzzArgs) -> Result<ExitCode> {
    let mut found_something = false;

    if let Some(sample) = &args.corpus_from {
        let dir = args
            .corpus
            .clone()
            .unwrap_or_else(|| fuzz::corpus::default_dir(sample));
        let r = fuzz::corpus::build(sample, &dir, &fuzz::corpus::Options::default())?;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&r)?);
        } else {
            println!(
                "Corpus: {} files, {} bytes into {}",
                r.files_written, r.bytes_written, r.dir
            );
            if r.skipped_duplicates > 0 || r.skipped_too_large > 0 {
                println!(
                    "  skipped {} duplicate(s) and {} oversized member(s)",
                    r.skipped_duplicates, r.skipped_too_large
                );
            }
            for (fmt, n) in &r.formats {
                println!("  {:<10} {}", fmt, n);
            }
        }
    }

    if let Some(sample) = &args.differential {
        let seed_input = fuzz::differential::read_seed(sample)?;
        let opts = args.differential_options();
        let campaign = fuzz::differential::run(&seed_input, &opts)?;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&campaign)?);
        } else {
            println!(
                "Differential campaign: target {}, {} executions in {:.1}s, seed {}",
                campaign.target.name(),
                campaign.executions,
                campaign.elapsed_secs,
                campaign.seed
            );
            println!("  slowest execution: {} ms", campaign.slowest_ms);
            if campaign.is_clean() {
                println!("  no panics or hangs found");
            } else {
                println!("  {} finding(s):", campaign.findings.len());
                for f in &campaign.findings {
                    println!(
                        "    {} via {} at iteration {} ({} bytes): {}",
                        f.kind, f.mutation, f.iteration, f.input_len, f.detail
                    );
                    if let Some(a) = &f.artifact {
                        println!("      reproducer: {}", a);
                    }
                }
            }
        }
        found_something |= !campaign.is_clean();
    }

    if let Some(engine) = args.engine {
        let harness = args
            .harness
            .clone()
            .expect("validated: --engine requires --harness");
        let corpus = args
            .corpus
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("fuzz/corpus"));
        let plan = fuzz::engine::Plan {
            engine,
            harness,
            corpus,
            output: args.output.clone(),
            timeout_secs: args.run_secs,
            target_module: args.target_module.clone(),
            target_offset: args.target_offset.clone(),
            extra_args: vec![],
        };
        let cmd = fuzz::engine::plan(&plan)?;
        for note in &cmd.notes {
            eprintln!("binspector: {}", note);
        }
        println!("{}", cmd.display);
        if !args.dry_run {
            if !fuzz::engine::is_installed(engine) {
                eprintln!(
                    "binspector: {} is not on PATH, so the command above was not run. Install it, \
                     or keep --dry-run.",
                    engine.name()
                );
            } else {
                let code = fuzz::engine::execute(&cmd)?;
                eprintln!("binspector: {} exited with {}", engine.name(), code);
                let crashes = fuzz::engine::collect_crashes(engine, &args.output)?;
                println!(
                    "  {} crashing input(s) in {}",
                    crashes.crashes.len(),
                    crashes.crash_dir
                );
                for c in crashes.crashes.iter().take(20) {
                    println!("    {}", c);
                }
                found_something |= !crashes.crashes.is_empty();
            }
        }
    }

    Ok(if args.fail_on_finding && found_something {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn run_scan(resolved: &binspector::cli::Resolved) -> Result<ExitCode> {
    for notice in &resolved.notices {
        eprintln!("binspector: {}", notice);
    }

    // Destructured so the report can be borrowed immutably while the spool is
    // borrowed mutably for streaming.
    let scan::ScanOutput {
        mut report,
        mut spool,
    } = scan::run(&resolved.binary, &resolved.scan)?;

    // Network enrichment runs after the scan and never blocks the report: a failed
    // lookup is recorded in the output rather than aborting a completed analysis.
    if resolved.reputation || resolved.cve {
        let creds = intel::Credentials::load()?;
        if resolved.reputation {
            if creds.virustotal.is_none() && creds.metadefender.is_none() {
                eprintln!(
                    "binspector: {}",
                    intel::Credentials::missing_message("reputation", "VT_API_KEY or MD_API_KEY")
                );
            }
            match intel::reputation::lookup(&report.sha256, &creds) {
                Ok(r) => report.intel.reputation = Some(r),
                Err(e) => eprintln!("binspector: reputation lookup unavailable: {:#}", e),
            }
        }
        if resolved.cve {
            if creds.nvd.is_none() {
                eprintln!("binspector: no NVD_API_KEY set, so the NVD rate limit will be very low");
            }
            let components = report.intel.components.clone();
            if components.is_empty() {
                eprintln!(
                    "binspector: no third-party components were detected, so there is nothing \
                     to resolve against NVD"
                );
            } else {
                let sig_count = intel::components::Detector::new(1).signature_count();
                match intel::cve::lookup(&components, sig_count, &creds, resolved.cve_limit) {
                    Ok(c) => report.intel.cves = Some(c),
                    Err(e) => eprintln!("binspector: CVE lookup unavailable: {:#}", e),
                }
            }
        }
    }

    // Terminal output may be colorized. File output is plain unless colour was
    // explicitly forced, since escape sequences in a saved report are noise.
    let stdout_theme = Theme::new(resolved.color, resolved.palette, io::stdout().is_terminal());
    let file_theme = match resolved.color {
        ColorChoice::Always => Theme::new(ColorChoice::Always, resolved.palette, true),
        _ => Theme::plain(resolved.palette),
    };

    let multiple = resolved.formats.len() > 1;
    for fmt in &resolved.formats {
        let dump_here = resolved.dump && fmt.supports_dump();
        match &resolved.output {
            Some(base) => {
                let path = format::destination(base, *fmt, multiple);
                let opts = RenderOpts {
                    theme: file_theme,
                    matches_only: resolved.matches_only,
                    dump: dump_here,
                };
                let sp = prepare_spool(&mut spool, dump_here)?;
                report::render_to_path(*fmt, &path, &report, sp, &opts)?;
                eprintln!("binspector: wrote {}", path.display());
            }
            None => {
                let opts = RenderOpts {
                    theme: stdout_theme,
                    matches_only: resolved.matches_only,
                    dump: dump_here,
                };
                let sp = prepare_spool(&mut spool, dump_here)?;
                let stdout = io::stdout();
                let mut w = io::BufWriter::new(stdout.lock());
                report::render(*fmt, &mut w, &report, sp, &opts)?;
                w.flush()?;
            }
        }
    }

    Ok(exit_code(resolved, &report))
}

/// Rewind the spool so each format streams it from the start.
fn prepare_spool(
    spool: &mut Option<binspector::spool::SpoolReader>,
    dump: bool,
) -> Result<Option<&mut binspector::spool::SpoolReader>> {
    if !dump {
        return Ok(None);
    }
    match spool.as_mut() {
        Some(sp) => {
            sp.rewind()?;
            Ok(Some(sp))
        }
        None => Ok(None),
    }
}

fn exit_code(resolved: &binspector::cli::Resolved, report: &binspector::model::Report) -> ExitCode {
    match resolved.fail_on {
        None => ExitCode::SUCCESS,
        Some(threshold) => {
            let t = threshold.threshold();
            let tripped = report.summary.iter().any(|s| s.severity <= t);
            if tripped {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}
