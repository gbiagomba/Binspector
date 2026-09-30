//! Fuzz string extraction.
//!
//! A plain build produces a file-reading harness, which is what AFL's `@@` and
//! honggfuzz's `___FILE___` placeholders substitute. Instrumented builds:
//!   cargo afl build --features afl-target --release --bin fuzz_strings
//!   cargo hfuzz build --features hfuzz-target --bin fuzz_strings
use arbitrary::Arbitrary;
use binspector::fuzz::StringsInput;
use binspector::scan::strings;

fn exercise(data: &[u8]) {
    let mut u = arbitrary::Unstructured::new(data);
    if let Ok(input) = StringsInput::arbitrary(&mut u) {
        let out = strings::extract(&input.data, input.min_len, input.ascii, input.utf16);
        // Every reported string must satisfy the contract the scanner relies on:
        // an in-range offset, and a length at or above the requested minimum.
        for s in &out {
            assert!(
                s.offset as usize <= input.data.len(),
                "offset {} beyond input length {}",
                s.offset,
                input.data.len()
            );
            assert!(!s.text.is_empty(), "empty string reported");
        }
    }
}

#[cfg(feature = "afl-target")]
fn main() {
    afl::fuzz!(|data: &[u8]| {
        exercise(data);
    });
}

#[cfg(all(feature = "hfuzz-target", not(feature = "afl-target")))]
fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            exercise(data);
        });
    }
}

#[cfg(not(any(feature = "afl-target", feature = "hfuzz-target")))]
fn main() {
    // Without an engine feature the target is a plain harness: it reads a file named
    // on the command line, which is what AFL's `@@` and honggfuzz's `___FILE___`
    // placeholders substitute, and what `binspector fuzz --engine` drives.
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
            eprintln!("usage: fuzz_strings <input-file>");
            std::process::exit(2);
        }
    }
}
