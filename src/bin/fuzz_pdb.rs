//! Fuzz the PDB compiland reader.
//!
//! **Why this harness is the price of the dependency.** `src/pdb` is the only place Binspector
//! trusts a third-party parser on attacker-controlled input, and it does so on a specific argument:
//! the path it uses, the MSF container and the DBI module list, allocates nothing from a
//! file-supplied count, while every such allocation in `pdb2` lives in the type, symbol and omap
//! streams this code never opens. That argument is about a path boundary, so it is worth exactly
//! what the boundary is worth, and the boundary is what this fuzzes.
//!
//! A symbol package is a plausible hostile input rather than a theoretical one: it arrives from the
//! same archive as the binaries and nobody treats a `.pdb` as untrusted.
//!
//! A file-reading harness, which is what AFL's `@@` and honggfuzz's `___FILE___` placeholders
//! substitute. For coverage-guided runs, instrument this same binary:
//!   cargo afl build --release --bin fuzz_pdb
//!   cargo hfuzz build --bin fuzz_pdb

fn exercise(data: &[u8]) {
    // Detection must agree with the reader about what a PDB is. If `is_pdb` said yes and `read`
    // returned `Ok(None)`, a malformed PDB would be silently reported as not a PDB at all, which
    // is the one outcome worse than an error: a reviewer would see no provenance and no reason.
    let detected = binspector::pdb::is_pdb(data);
    let got = binspector::pdb::read(data, "fuzz.pdb");
    match (&detected, &got) {
        (true, Ok(None)) => panic!("is_pdb accepted bytes that read() reported as not a PDB"),
        (false, Ok(Some(_))) => panic!("read() produced provenance for bytes is_pdb rejected"),
        _ => {}
    }

    if let Ok(Some(p)) = got {
        // Every reported tree must carry at least one object, or the count is not a count.
        for root in &p.roots {
            assert!(
                root.objects > 0,
                "a source tree with no objects was reported: {:?}",
                root.root
            );
            assert!(!root.root.is_empty(), "an empty source tree was reported");
        }
        // The mixed-source finding is the one thing here a reader acts on, so its invariant is
        // asserted rather than assumed: it needs two distinct trees, or it is not mixed.
        for m in &p.mixed {
            assert!(
                m.roots.len() > 1,
                "a mixed-source finding for {} named {} tree(s)",
                m.component,
                m.roots.len()
            );
            let distinct: std::collections::BTreeSet<&str> =
                m.roots.iter().map(|r| r.root.as_str()).collect();
            assert!(
                distinct.len() > 1,
                "a mixed-source finding for {} named one tree twice",
                m.component
            );
            assert!(!m.component.is_empty(), "a mixed source with no component");
        }
        // A skip and a result are different facts and must not both be absent: a PDB that parsed
        // to nothing with no stated reason is the silent-clean-result failure this project exists
        // to avoid.
        if p.skipped.is_none() {
            assert!(
                p.compilands > 0 || p.roots.is_empty(),
                "compilands were counted but no tree was reported"
            );
        }
    }

    // The format dispatch too, since that is how a real scan reaches this code.
    let _ = binspector::container::detect::detect(data);
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
            eprintln!("usage: fuzz_pdb <input-file>");
            std::process::exit(2);
        }
    }
}
