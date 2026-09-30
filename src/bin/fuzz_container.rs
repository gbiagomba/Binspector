//! Fuzz the container parser.
//!
//! A plain build produces a file-reading harness, which is what AFL's `@@` and
//! honggfuzz's `___FILE___` placeholders substitute. Instrumented builds:
//!   cargo afl build --features afl-target --release --bin fuzz_container
//!   cargo hfuzz build --features hfuzz-target --bin fuzz_container

fn exercise(data: &[u8]) {
    let limits = binspector::container::Limits {
        max_depth: 3,
        max_total_bytes: 64 * 1024 * 1024,
        max_member_bytes: 16 * 1024 * 1024,
        max_expansion_ratio: 50,
        max_members: 500,
        carve: false,
    };
    let _ = binspector::container::walk_bytes(data, "fuzz".to_string(), limits, &mut |m| {
        // Members must never be handed out with an empty provenance chain, since
        // reports and SARIF locations depend on it.
        assert!(!m.chain.is_empty(), "member with no provenance chain");
        Ok(())
    });
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
            eprintln!("usage: fuzz_container <input-file>");
            std::process::exit(2);
        }
    }
}
