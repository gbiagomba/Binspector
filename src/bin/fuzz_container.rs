//! Fuzz the container parser.
//!
//! A file-reading harness, which is what AFL's `@@` and honggfuzz's `___FILE___`
//! placeholders substitute. For coverage-guided runs, instrument this same binary:
//!   cargo afl build --release --bin fuzz_container
//!   cargo hfuzz build --bin fuzz_container

fn exercise(data: &[u8]) {
    let limits = binspector::container::Limits {
        max_depth: 3,
        max_total_bytes: 64 * 1024 * 1024,
        max_member_bytes: 16 * 1024 * 1024,
        max_expansion_ratio: 50,
        max_members: 500,
        carve: false,
    };
    let _ = binspector::container::walk_bytes(
        data,
        "fuzz".to_string(),
        limits,
        &binspector::observe::Null,
        &mut |m| {
            // Members must never be handed out with an empty provenance chain, since
            // reports and SARIF locations depend on it.
            assert!(!m.chain.is_empty(), "member with no provenance chain");
            Ok(())
        },
    );
}

fn main() {
    // A file-reading harness. AFL++ substitutes the path for `@@` and honggfuzz for
    // `___FILE___`, which is how both drive a non-persistent target, and what
    // `binspector fuzz --engine` emits.
    //
    // For coverage-guided runs, instrument this same binary:
    //   cargo afl build --release --bin fuzz_container
    //   cargo hfuzz build --bin fuzz_container
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
            eprintln!("usage: fuzz_container <input-file>");
            std::process::exit(2);
        }
    }
}
