//! Fuzz the pe parser.
//!
//! Build with one of:
//!   cargo afl build --features afl-target --release --bin fuzz_pe
//!   cargo hfuzz build --features hfuzz-target --bin fuzz_pe

fn exercise(data: &[u8]) {
    if let Some(a) = binspector::pe::PeAnalysis::parse(data) {
        // Entropy is a probability measure and must stay in range whatever the
        // section table claims.
        for s in &a.sections {
            assert!(
                (0.0..=8.0).contains(&s.entropy),
                "entropy {} out of range for section {}",
                s.entropy,
                s.name
            );
        }
    }
}

#[cfg(feature = "afl-target")]
fn main() {
    afl::fuzz!(|data: &[u8]| {
        exercise(data);
    });
}

#[cfg(feature = "hfuzz-target")]
fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            exercise(data);
        });
    }
}

#[cfg(not(any(feature = "afl-target", feature = "hfuzz-target")))]
fn main() {
    let mut args = std::env::args_os().skip(1);
    match args.next() {
        Some(path) => match std::fs::read(&path) {
            Ok(data) => exercise(&data),
            Err(e) => {
                eprintln!("cannot read input: {}", e);
                std::process::exit(2);
            }
        },
        None => {
            eprintln!("usage: fuzz_pe <input-file>");
            std::process::exit(2);
        }
    }
}
