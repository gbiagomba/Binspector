//! Fuzz string extraction.
//!
//! A file-reading harness, which is what AFL's `@@` and honggfuzz's `___FILE___`
//! placeholders substitute. For coverage-guided runs, instrument this same binary:
//!   cargo afl build --release --bin fuzz_strings
//!   cargo hfuzz build --bin fuzz_strings
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

fn main() {
    // A file-reading harness. AFL++ substitutes the path for `@@` and honggfuzz for
    // `___FILE___`, which is how both drive a non-persistent target, and what
    // `binspector fuzz --engine` emits.
    //
    // For coverage-guided runs, instrument this same binary:
    //   cargo afl build --release --bin fuzz_strings
    //   cargo hfuzz build --bin fuzz_strings
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
            eprintln!("usage: fuzz_strings <input-file>");
            std::process::exit(2);
        }
    }
}
