//! Binspector command line entry point.

use anyhow::Result;
use clap::Parser;
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use binspector::cli::color::{ColorChoice, Theme};
use binspector::cli::{format, Cli};
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
    let resolved = Cli::parse().resolve()?;

    for notice in &resolved.notices {
        eprintln!("binspector: {}", notice);
    }

    // Destructured so the report can be borrowed immutably while the spool is
    // borrowed mutably for streaming.
    let scan::ScanOutput { report, mut spool } = scan::run(&resolved.binary, &resolved.scan)?;

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

    Ok(exit_code(&resolved, &report))
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
