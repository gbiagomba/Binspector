//! Fuzz the pe parser.
//!
//! A file-reading harness, which is what AFL's `@@` and honggfuzz's `___FILE___`
//! placeholders substitute. For coverage-guided runs, instrument this same binary:
//!   cargo afl build --release --bin fuzz_pe
//!   cargo hfuzz build --bin fuzz_pe

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

fn main() {
    // A file-reading harness. AFL++ substitutes the path for `@@` and honggfuzz for
    // `___FILE___`, which is how both drive a non-persistent target, and what
    // `binspector fuzz --engine` emits.
    //
    // For coverage-guided runs, instrument this same binary:
    //   cargo afl build --release --bin fuzz_pe
    //   cargo hfuzz build --bin fuzz_pe
    //
    // The afl and honggfuzz persistent-mode macros are deliberately not used. They
    // require the engine's runtime symbols at link time, so a plain `cargo build` or
    // `cargo test --all-features` could not link the binary at all.
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
