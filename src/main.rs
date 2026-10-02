//! Binspector command line entry point.

use anyhow::Result;
use clap::Parser;
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use binspector::cli::color::{ColorChoice, Theme};
use binspector::cli::{format, Action, Cli};
use binspector::fuzz;
use binspector::intel;
use binspector::observe::{self, Observer};
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
        Action::Cache(args) => run_cache(&args),
        Action::Repl(path) => run_repl(&path),
        Action::Scan(resolved) => run_scan(&resolved),
    }
}

/// `binspector cache --show | --prune | --purge`.
///
/// Paired on the feature the same way `run_repl` is, because the store is SQLite and a build without
/// it has nowhere to keep anything.
#[cfg(feature = "sqlite")]
fn run_cache(args: &binspector::cli::CacheArgs) -> Result<ExitCode> {
    use binspector::intel::cache;
    let Some(path) = cache::cache_path() else {
        anyhow::bail!(
            "no cache location: HOME is unset and BINSPECTOR_CACHE was not given, so there is \
             nowhere a cache could be"
        )
    };

    if args.purge {
        if cache::purge(&path)? {
            println!("binspector: removed {}", path.display());
        } else {
            println!("binspector: no cache at {}", path.display());
        }
        return Ok(ExitCode::SUCCESS);
    }

    if !path.exists() {
        println!("binspector: no cache at {}", path.display());
        return Ok(ExitCode::SUCCESS);
    }
    let c = cache::Cache::open(&path)?;
    let now = cache::now_unix();

    if args.prune {
        let n = c.prune(now)?;
        println!("binspector: dropped {} expired verdict(s)", n);
        return Ok(ExitCode::SUCCESS);
    }

    let st = c.stats(now)?;
    println!("Reputation cache: {}", path.display());
    println!("  verdicts:        {}", st.total);
    println!("  still usable:    {}", st.fresh);
    println!("  expired:         {}", st.expired);
    println!("  distinct hashes: {}", st.hashes);
    println!(
        "  size:            {}",
        binspector::report::human_bytes(st.bytes)
    );
    // Said plainly, because the file is more revealing than its size suggests.
    println!(
        "  This file records every binary hash looked up on this machine, across every scan and \
         every engagement. `--purge` deletes it."
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(not(feature = "sqlite"))]
fn run_cache(_args: &binspector::cli::CacheArgs) -> Result<ExitCode> {
    anyhow::bail!(
        "this build has no reputation cache. The store is SQLite, so rebuild with \
         --features sqlite."
    )
}

#[cfg(feature = "repl")]
fn run_repl(path: &std::path::Path) -> Result<ExitCode> {
    binspector::repl::run(path)?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(not(feature = "repl"))]
fn run_repl(_path: &std::path::Path) -> Result<ExitCode> {
    anyhow::bail!(
        "this build has no interactive browser. Rebuild with --features repl, or query the \
         report with jq or the sqlite3 shell."
    )
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

/// One line describing what `--extract` wrote, or nothing when it was not asked for.
///
/// Reported rather than silent, because writing files is a side effect the caller should see
/// accounted for, and it states what was *not* written as well as what was.
fn extraction_note(cfg: &scan::ScanConfig) -> Option<String> {
    let x = cfg.extract.as_ref()?.report();
    let mut note = format!(
        "extracted {} member(s), {} to {}",
        x.written,
        binspector::report::human_bytes(x.bytes),
        x.dir.display()
    );
    if x.duplicates > 0 {
        note.push_str(&format!("; {} duplicate(s) written once", x.duplicates));
    }
    if x.skipped > 0 {
        note.push_str(&format!("; {} not written (cap or write error)", x.skipped));
    }
    Some(note)
}

fn run_scan(resolved: &binspector::cli::Resolved) -> Result<ExitCode> {
    binspector::banner::print_if_interactive(resolved.no_banner);

    // Verbose output goes to stderr, so stdout stays a clean report even at -vvv.
    let observer: Box<dyn Observer> = if resolved.verbose > 0 {
        Box::new(observe::Stderr::new(resolved.verbose))
    } else {
        Box::new(observe::Null)
    };

    for notice in &resolved.notices {
        eprintln!("binspector: {}", notice);
    }

    // Resolve the command line into the files to scan. A directory is walked; a named path
    // that does not exist is a hard error here, so a typo is never reported as a clean scan.
    let plan = binspector::select::plan(&resolved.targets, &resolved.select, observer.as_ref())?;
    for w in &plan.warnings {
        eprintln!("binspector: {}", w);
    }

    // --split scans, writes, and drops one target at a time, so N reports never coexist.
    if resolved.split {
        return run_split(resolved, &plan, observer.as_ref());
    }

    // Destructured so the report can be borrowed immutably while the spool is
    // borrowed mutably for streaming.
    let scan::ScanOutput {
        mut report,
        mut spool,
    } = scan::run_many(&plan.targets, &resolved.scan, observer.as_ref())?;
    // One extraction line for the whole run, not one per target. The extractor is shared, so this
    // is the complete count and cross-target duplicates have already collapsed.
    if let Some(note) = extraction_note(&resolved.scan) {
        report.warnings.push(note);
    }
    // Selection warnings belong in the report, not only on stderr, so a reader of the file
    // knows what was filtered.
    for w in &plan.warnings {
        if !report.warnings.contains(w) {
            report.warnings.push(w.clone());
        }
    }

    enrich(&mut report, resolved)?;

    // Terminal output may be colorized. File output is plain unless colour was
    // explicitly forced, since escape sequences in a saved report are noise.
    let stdout_theme = Theme::new(resolved.color, resolved.palette, io::stdout().is_terminal());
    let file_theme = match resolved.color {
        ColorChoice::Always => Theme::new(ColorChoice::Always, resolved.palette, true),
        _ => Theme::plain(resolved.palette),
    };

    // A defaulted name carries dots in its timestamp, so its extension is appended
    // rather than substituted.
    let naming = if resolved.output_is_default {
        format::Naming::Append
    } else if resolved.formats.len() > 1 {
        format::Naming::ReplaceExtension
    } else {
        format::Naming::Exact
    };
    // With several formats requested, one failing writer must not discard the others: a
    // completed analysis is worth more than a tidy error. Failures are collected, every
    // writable format is written, and the run still exits 2 at the end. A single format
    // keeps failing outright, since there is nothing to salvage.
    let mut failures: Vec<String> = Vec::new();
    let several = resolved.formats.len() > 1;
    for fmt in &resolved.formats {
        let dump_here = resolved.dump && fmt.supports_dump();
        let outcome = match &resolved.output {
            Some(base) => {
                let path = format::destination(base, *fmt, naming);
                let opts = RenderOpts {
                    theme: file_theme,
                    matches_only: resolved.matches_only,
                    dump: dump_here,
                };
                let sp = prepare_spool(&mut spool, dump_here)?;
                report::render_to_path(*fmt, &path, &report, sp, &opts).map(|()| {
                    eprintln!("binspector: wrote {}", path.display());
                })
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
                report::render(*fmt, &mut w, &report, sp, &opts).and_then(|()| Ok(w.flush()?))
            }
        };
        match outcome {
            Ok(()) => {}
            Err(e) if several => {
                eprintln!("binspector: --format {} failed: {:#}", fmt.name(), e);
                failures.push(fmt.name().to_string());
            }
            Err(e) => return Err(e),
        }
    }
    if !failures.is_empty() {
        eprintln!(
            "binspector: {} of {} formats could not be written: {}",
            failures.len(),
            resolved.formats.len(),
            failures.join(", ")
        );
        return Ok(ExitCode::from(2));
    }

    Ok(exit_code(resolved, &report))
}

/// Rewind the spool so each format streams it from the start.
/// The member sweep, with the cache opened for the duration if one is available.
///
/// Separate from `enrich` because opening the cache is feature-gated and the borrow of it has to
/// outlive the sweep, which reads awkwardly inline.
fn sweep_members(
    report: &mut binspector::model::Report,
    resolved: &binspector::cli::Resolved,
    creds: &intel::Credentials,
) {
    let mut budget = intel::budget::Budget::new(resolved.rate_limit, resolved.request_budget);
    if let Some(note) = budget.tier_note() {
        // Once per run, and it continues rather than refusing: whether a given use is within a
        // service's terms is the operator's judgement, not something a scanner can determine.
        eprintln!("binspector: {}", note);
    }

    #[cfg(feature = "sqlite")]
    let cache = if resolved.no_cache {
        None
    } else {
        match intel::cache::cache_path() {
            Some(p) => match intel::cache::Cache::open(&p) {
                Ok(c) => Some(c),
                Err(e) => {
                    // A cache that cannot be opened is a slower scan, not a failed one.
                    eprintln!("binspector: reputation cache unavailable: {:#}", e);
                    None
                }
            },
            None => None,
        }
    };
    #[cfg(feature = "sqlite")]
    let store = cache
        .as_ref()
        .map(|c| c as &dyn intel::reputation::VerdictStore);
    // Without the feature there is nowhere to persist anything, so every lookup is a miss. That is
    // correct behaviour rather than a stub.
    #[cfg(not(feature = "sqlite"))]
    let store: Option<&dyn intel::reputation::VerdictStore> = None;

    match intel::reputation::sweep_members(report, creds, &mut budget, store) {
        Ok(s) => {
            if s.unchecked > 0 {
                eprintln!(
                    "binspector: {} of {} distinct member hash(es) went unchecked: the request \
                     budget of {} was reached. Raise --request-budget or rerun to continue from \
                     the cache.",
                    s.unchecked, s.candidates, resolved.request_budget
                );
            }
            report.intel.sweep = Some(s);
        }
        Err(e) => eprintln!("binspector: member sweep unavailable: {:#}", e),
    }
}

/// Network enrichment, shared by the combined and split paths.
///
/// Runs after the scan and never blocks the report: a failed lookup is recorded in the output
/// rather than aborting a completed analysis. Nothing here transmits file content.
fn enrich(
    report: &mut binspector::model::Report,
    resolved: &binspector::cli::Resolved,
) -> Result<()> {
    // Network enrichment runs after the scan and never blocks the report: a failed
    // lookup is recorded in the output rather than aborting a completed analysis.
    if resolved.reputation || resolved.cve {
        let creds = intel::Credentials::load_from(resolved.credentials.as_deref())?;
        if resolved.reputation {
            if creds.virustotal.is_none() && creds.metadefender.is_none() {
                eprintln!(
                    "binspector: {}",
                    intel::Credentials::missing_message("reputation", "VT_API_KEY or MD_API_KEY")
                );
            }
            // Per target, against each target's own file digest. This used to pass
            // `report.sha256`, which on a multi-target run is the synthesized manifest digest, so
            // the question went to a hash no service has ever seen.
            match intel::reputation::lookup_targets(&report.targets, &creds) {
                Ok(r) => report.intel.reputation = r,
                Err(e) => eprintln!("binspector: reputation lookup unavailable: {:#}", e),
            }
        }
        if resolved.reputation_members {
            sweep_members(report, resolved, &creds);
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
    Ok(())
}

/// `--split`: one report per target, written and dropped before the next is scanned.
///
/// Memory is the reason this is a separate path rather than a loop over the combined one: N
/// reports never coexist, so a four-hundred-target run costs one report at a time.
fn run_split(
    resolved: &binspector::cli::Resolved,
    plan: &binspector::select::Plan,
    observer: &dyn Observer,
) -> Result<ExitCode> {
    // One stamp for the whole invocation, so four hundred targets do not get four hundred
    // timestamps and the output sorts as one run.
    let stamp = format::stamp();
    let total = plan.targets.len();
    let mut any_tripped = false;
    let mut failures: Vec<String> = Vec::new();

    for (i, target) in plan.targets.iter().enumerate() {
        observer.on(&binspector::observe::Event::Target {
            label: &target.label,
            index: i + 1,
            total,
            size: target.size,
        });
        let one = std::slice::from_ref(target);
        let scan::ScanOutput {
            mut report,
            mut spool,
        } = scan::run_many(one, &resolved.scan, observer)?;
        enrich(&mut report, resolved)?;

        // `resolve` already turned a missing -o into the timestamped default stem, which in
        // split mode would stamp the name twice. The documented shape is
        // `binspector_<slug>-<stamp>`, so a defaulted output contributes no prefix of its own.
        let base = if resolved.output_is_default {
            format::split_stem(None, &target.slug, &stamp)
        } else {
            format::split_stem(resolved.output.as_deref(), &target.slug, &stamp)
        };
        let file_theme = match resolved.color {
            ColorChoice::Always => Theme::new(ColorChoice::Always, resolved.palette, true),
            _ => Theme::new(ColorChoice::Never, resolved.palette, false),
        };
        for fmt in &resolved.formats {
            let dump_here = resolved.dump && fmt.supports_dump();
            // Always Append in split mode: the stamp contains dots, which is exactly why
            // Naming::Append exists.
            let path = format::destination(&base, *fmt, format::Naming::Append);
            let opts = RenderOpts {
                theme: file_theme,
                matches_only: resolved.matches_only,
                dump: dump_here,
            };
            let sp = prepare_spool(&mut spool, dump_here)?;
            match report::render_to_path(*fmt, &path, &report, sp, &opts) {
                Ok(()) => eprintln!("binspector: wrote {}", path.display()),
                Err(e) => {
                    eprintln!("binspector: {} failed: {:#}", path.display(), e);
                    failures.push(path.display().to_string());
                }
            }
        }
        // A gate that passes because 399 of 400 targets were clean is not a gate.
        any_tripped |= tripped(resolved, &report);
    }

    if !failures.is_empty() {
        eprintln!(
            "binspector: {} of {} report file(s) could not be written",
            failures.len(),
            total * resolved.formats.len()
        );
        return Ok(ExitCode::from(2));
    }
    Ok(if any_tripped {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

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

/// Whether `--fail-on` should trip.
///
/// Considers banned-function findings **and** missing exploit mitigations. The posture half is
/// new in 5.0.0 and is a deliberate breaking change for pipelines: a bundle whose images load
/// at a predictable address now fails `--fail-on high`, where before it passed because the
/// mitigation was only ever prose in the text report. That was the whole complaint.
///
/// Severity is the adjusted value, so a gate no longer trips on a namespace string in .NET
/// metadata that happened to match a critical function name.
fn tripped(resolved: &binspector::cli::Resolved, report: &binspector::model::Report) -> bool {
    let t = match resolved.fail_on {
        Some(f) => f.threshold(),
        None => return false,
    };
    report.summary.iter().any(|s| s.severity <= t) || report.posture.iter().any(|p| p.severity <= t)
}

fn exit_code(resolved: &binspector::cli::Resolved, report: &binspector::model::Report) -> ExitCode {
    if tripped(resolved, report) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
