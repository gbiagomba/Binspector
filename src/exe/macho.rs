//! Mach-O imports, with a fallback that is the normal path on modern binaries.
//!
//! `MachO::imports()` reads the dyld bind opcodes and gives real per-symbol library attribution,
//! which maps onto `ImportRef` exactly. But goblin only populates its bind interpreter from
//! `LC_DYLD_INFO` and `LC_DYLD_INFO_ONLY`. It recognises `LC_DYLD_CHAINED_FIXUPS` and never
//! interprets it, so on anything built by Xcode 13 or later, or targeting macOS 12 or later,
//! `imports()` returns an empty vector. That is indistinguishable from "this binary imports
//! nothing", which would silently zero out the strongest evidence tier on most of the platform.
//!
//! So three mechanisms, tried in order, with the one that answered recorded on the result because
//! they differ in fidelity. `exe::binds` first, which walks the `LC_DYLD_INFO` opcode stream here
//! rather than through goblin, whose interpreter both panics on an out-of-range library ordinal and
//! multiplies its output by an attacker-chosen repeat count. Then `exe::chained`, which reads the
//! `LC_DYLD_CHAINED_FIXUPS` import table and is the path a current toolchain produces. Then the
//! `LC_SYMTAB` undefined externals, which loses per-symbol library attribution.
//!
//! The symbol table is last, not second, because it cannot attribute a symbol to a library: the
//! dylib ordinal is in `n_desc`, which goblin does not expose. It usually lists the same names as
//! the chained table, so the cost of reaching it first would be silent loss of attribution rather
//! than loss of coverage, which is the harder kind of defect to notice. `/bin/ls` concealed the
//! whole question during development, being an older image that still carries bind opcodes.
//!
//! A universal binary carries one import set per architecture. They are **unioned**, because for
//! a banned-function scan the finding matters even if only one slice has it.

use goblin::mach::{Mach, MachO, SingleArch};

use super::{Source, UnixImports};
use crate::pe::ImportRef;

const MAX_IMPORTS: usize = 20_000;

/// Read Mach-O imports, or `None` when the bytes are not Mach-O.
pub fn read(data: &[u8]) -> Option<UnixImports> {
    if !is_macho_magic(data) {
        return None;
    }
    let mach = Mach::parse(data).ok()?;
    let mut acc: Vec<ImportRef> = Vec::new();
    let mut source = Source::None;

    match mach {
        Mach::Binary(bin) => {
            let (imports, used) = from_image(&bin, data, 0);
            acc.extend(imports);
            source = used;
        }
        Mach::Fat(multi) => {
            // Each slice is its own image, and its load-command file offsets are relative to the
            // slice rather than to the file, so the slice offset has to come along: reading a
            // linkedit blob at a file-absolute offset would read a different architecture's
            // bytes. `arches()` carries it; iterating `&multi` alone does not.
            let arches = multi.arches().unwrap_or_default();
            // goblin bounds `nfat_arch` only by the file length over 20 bytes, so a 150 KiB file
            // can claim 7,710 slices and each one costs a full `MachO::parse` here and again in
            // `exe::posture`. Fuzzing produced exactly that: a 3.9-second execution on one mutated
            // input. The cap is the same one detection uses to tell a fat header from a Java class
            // file, and it is well above anything Apple ships.
            if arches.len() > crate::container::detect::MAX_FAT_ARCHES as usize {
                return Some(UnixImports::default());
            }
            for (i, arch) in arches.iter().enumerate() {
                // Whole-file budget, not per-slice. The cap below is per image, and sixteen slices
                // each spending it is sixteen times the work for a set that dedups to roughly one
                // slice's worth, since the slices are the same program.
                if acc.len() >= MAX_IMPORTS {
                    break;
                }
                // A fat static library's slices are `ar` archives rather than Mach-O images, so
                // that arm is skipped rather than treated as an error.
                let Ok(SingleArch::MachO(bin)) = multi.get(i) else {
                    continue;
                };
                let (imports, used) = from_image(&bin, data, arch.offset as usize);
                acc.extend(imports);
                // Record the strongest source any slice managed.
                if rank(used) > rank(source) {
                    source = used;
                }
            }
        }
    }

    // Slices overlap almost completely, and a fat binary can resolve one slice through the bind
    // opcodes (which attribute a library) and another through the symbol table (which cannot).
    // Dedup by name, keeping whichever entry carries attribution, so a symbol appears once with
    // the best library information available rather than twice with and without it.
    acc.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            // Non-empty library first, so it is the one retained by dedup_by.
            .then_with(|| a.library.is_empty().cmp(&b.library.is_empty()))
            .then_with(|| a.library.cmp(&b.library))
    });
    acc.dedup_by(|a, b| a.name == b.name);
    acc.truncate(MAX_IMPORTS);

    Some(UnixImports {
        imports: acc,
        source,
    })
}

/// How much a source is worth when two slices disagree. Both the bind opcodes and the chained
/// import table attribute a symbol to a library; the symbol table cannot, so it ranks below them.
fn rank(s: Source) -> u8 {
    match s {
        Source::MachoBinds => 3,
        Source::MachoChained => 2,
        Source::MachoSymtab => 1,
        _ => 0,
    }
}

/// One image's imports, from the first of the three mechanisms that answers.
///
/// `base` is this image's file offset: zero for a thin binary, the slice offset within a
/// universal one.
fn from_image(bin: &MachO, data: &[u8], base: usize) -> (Vec<ImportRef>, Source) {
    if let Some(mut binds) = super::binds::imports(bin, data, base) {
        binds.truncate(MAX_IMPORTS);
        if !binds.is_empty() {
            return (binds, Source::MachoBinds);
        }
    }

    // The normal path on a modern binary: chained fixups, which goblin recognises and does not
    // interpret, so the table is read here.
    if let Some(mut chained) = super::chained::imports(bin, data, base) {
        chained.truncate(MAX_IMPORTS);
        if !chained.is_empty() {
            return (chained, Source::MachoChained);
        }
    }

    // An older image whose bind opcodes would not parse. Loses library attribution.
    let mut out: Vec<ImportRef> = Vec::new();
    for entry in bin.symbols() {
        if out.len() >= MAX_IMPORTS {
            break;
        }
        let Ok((name, nlist)) = entry else {
            continue;
        };
        // Undefined and external is the Mach-O analogue of ELF's SHN_UNDEF filter.
        if !nlist.is_undefined() || !nlist.is_global() {
            continue;
        }
        if name.is_empty() {
            continue;
        }
        out.push(ImportRef {
            // The library ordinal lives in the nlist description field, which goblin does not
            // expose an accessor for, so no attribution is claimed rather than guessed.
            library: String::new(),
            name: strip_underscore(name).to_string(),
        });
    }
    if out.is_empty() {
        (out, Source::None)
    } else {
        (out, Source::MachoSymtab)
    }
}

/// Mach-O C symbols carry a leading underscore from the assembler. Stripping it lets a banned
/// list written for C names match, which is the whole point of reading the table.
fn strip_underscore(name: &str) -> &str {
    name.strip_prefix('_').unwrap_or(name)
}

fn is_macho_magic(data: &[u8]) -> bool {
    matches!(
        data.get(..4),
        Some([0xFE, 0xED, 0xFA, 0xCE])
            | Some([0xCE, 0xFA, 0xED, 0xFE])
            | Some([0xFE, 0xED, 0xFA, 0xCF])
            | Some([0xCF, 0xFA, 0xED, 0xFE])
            | Some([0xCA, 0xFE, 0xBA, 0xBE])
            | Some([0xBE, 0xBA, 0xFE, 0xCA])
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_macho_input_is_declined() {
        assert!(read(b"\x7fELF\x02\x01\x01\x00 an ELF").is_none());
        assert!(read(b"MZ a PE").is_none());
        assert!(read(b"").is_none());
    }

    #[test]
    fn a_truncated_or_lying_header_does_not_panic() {
        for n in 4..80 {
            let mut v = vec![0xCF, 0xFA, 0xED, 0xFE];
            v.resize(n, 0);
            let _ = read(&v);
        }
        // A fat header claiming two slices that are not there.
        let mut fat = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02];
        fat.resize(40, 0);
        let _ = read(&fat);
    }

    #[test]
    fn a_leading_underscore_is_stripped_so_c_names_match() {
        assert_eq!(strip_underscore("_strcpy"), "strcpy");
        assert_eq!(strip_underscore("strcpy"), "strcpy");
        // A C++ mangled Itanium name keeps its shape; only the assembler prefix goes.
        assert_eq!(strip_underscore("__ZN2cv4getsEv"), "_ZN2cv4getsEv");
    }

    /// Real coverage comes from a system binary, which the macOS CI runners carry and the
    /// repository does not. `/bin/ls` is a universal binary built with chained fixups, so this
    /// also exercises both the fat path and the symbol-table fallback.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_real_universal_binary_yields_imports() {
        let data = match std::fs::read("/bin/ls") {
            Ok(d) => d,
            Err(_) => return,
        };
        let got = read(&data).expect("/bin/ls is Mach-O");
        assert!(
            !got.imports.is_empty(),
            "ls imports libSystem; an empty result means the fallback did not engage"
        );
        assert_ne!(got.source, Source::None);
        // Exactly one assembler underscore is removed, so a C name like `__stack_chk_fail`
        // keeps the two underscores it genuinely has while `_write` becomes `write`.
        assert!(
            got.imports.iter().any(|i| i.name == "__stack_chk_fail"),
            "one underscore stripped, not all of them"
        );
        // One entry per symbol: a fat binary must not report the same import twice because two
        // slices resolved it through different mechanisms.
        let mut names: Vec<&str> = got.imports.iter().map(|i| i.name.as_str()).collect();
        let before = names.len();
        names.sort();
        names.dedup();
        assert_eq!(before, names.len(), "imports must be deduplicated by name");
        // A real libc import is present under its C name.
        assert!(
            got.imports
                .iter()
                .any(|i| i.name == "write" || i.name == "printf"),
            "expected a recognisable libc import, got {:?}",
            got.imports
                .iter()
                .take(8)
                .map(|i| &i.name)
                .collect::<Vec<_>>()
        );
    }
}
