//! Fuzz the ELF and Mach-O readers.
//!
//! Separate from `fuzz_pe` because these parsers reach bytes that `fuzz_pe` cannot: an ELF
//! `.dynsym`, a Mach-O fat header's slice offsets, and the `LC_DYLD_CHAINED_FIXUPS` blob, whose
//! header is seven attacker-controlled offsets into itself. That last one is the only place in the
//! tool that computes its own structure offsets rather than reading goblin's, so it is the one with
//! no upstream bounds checking behind it.
//!
//! A file-reading harness, which is what AFL's `@@` and honggfuzz's `___FILE___` placeholders
//! substitute. For coverage-guided runs, instrument this same binary:
//!   cargo afl build --release --bin fuzz_exe
//!   cargo hfuzz build --bin fuzz_exe

fn exercise(data: &[u8]) {
    let found = binspector::exe::read(data);
    // Source and content must agree. A source naming a mechanism with no imports behind it, or
    // imports with no mechanism named, would make `import_source` a claim the report cannot back,
    // and the evidence rules read exactly that field to decide whether the absence of an import
    // means anything.
    let named = found.source != binspector::exe::Source::None;
    assert_eq!(
        named,
        !found.imports.is_empty(),
        "source {:?} does not match {} imports",
        found.source,
        found.imports.len()
    );
    for i in &found.imports {
        assert!(!i.name.is_empty(), "an import with no name was reported");
        // One assembler underscore is stripped on every path, so a name must never arrive with
        // the shape the stripping was supposed to remove from a plain C symbol.
        assert!(
            !i.name.starts_with("_Z") || i.name.len() > 2,
            "truncated mangled name {:?}",
            i.name
        );
    }

    // Posture reads the same images through different fields: program headers and dynamic flags
    // for ELF, the header flag word and load commands for Mach-O.
    let _ = binspector::exe::posture::read(data);
    let _ = binspector::exe::posture::is_executable_image(data);
}

fn main() {
    // The afl and honggfuzz persistent-mode macros are deliberately not used. They require the
    // engine's runtime symbols at link time, so a plain `cargo build` could not link the binary.
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
            eprintln!("usage: fuzz_exe <input-file>");
            std::process::exit(2);
        }
    }
}
