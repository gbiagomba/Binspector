//! Mach-O imports, with a fallback that is the normal path on modern binaries.
//!
//! `MachO::imports()` reads the dyld bind opcodes and gives real per-symbol library attribution,
//! which maps onto `ImportRef` exactly. But goblin only populates its bind interpreter from
//! `LC_DYLD_INFO` and `LC_DYLD_INFO_ONLY`. It recognises `LC_DYLD_CHAINED_FIXUPS` and never
//! interprets it, so on anything built by Xcode 13 or later, or targeting macOS 12 or later,
//! `imports()` returns an empty vector. That is indistinguishable from "this binary imports
//! nothing", which would silently zero out the strongest evidence tier on most of the platform.
//!
//! So: try the bind opcodes, and when they yield nothing fall back to the `LC_SYMTAB` undefined
//! externals, which are present on any non-stripped image regardless of fixup format. The
//! fallback loses per-symbol library attribution, so the source is recorded and the two are not
//! conflated.
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
            let (imports, used) = from_image(&bin);
            acc.extend(imports);
            source = used;
        }
        Mach::Fat(multi) => {
            // Each slice is its own image. A fat static library's slices are `ar` archives
            // rather than Mach-O images, so that arm is skipped rather than treated as an error.
            for slice in &multi {
                let Ok(SingleArch::MachO(bin)) = slice else {
                    continue;
                };
                let (imports, used) = from_image(&bin);
                acc.extend(imports);
                // Record the stronger source if any slice managed it.
                if source == Source::None || used == Source::MachoBinds {
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

/// One image's imports, preferring the bind opcodes and falling back to the symbol table.
fn from_image(bin: &MachO) -> (Vec<ImportRef>, Source) {
    if let Ok(binds) = bin.imports() {
        if !binds.is_empty() {
            let out: Vec<ImportRef> = binds
                .iter()
                .take(MAX_IMPORTS)
                .filter(|i| !i.name.is_empty())
                .map(|i| ImportRef {
                    library: dylib_name(i.dylib).to_string(),
                    // Stripped here too, not only in the fallback. A universal binary can take
                    // the bind path for one slice and the symbol-table path for another, and if
                    // the two normalise differently the same symbol appears twice under two
                    // spellings. Caught by probing a real two-slice binary.
                    name: strip_underscore(i.name).to_string(),
                })
                .collect();
            if !out.is_empty() {
                return (out, Source::MachoBinds);
            }
        }
    }

    // The normal path on a modern binary: chained fixups, which goblin does not interpret.
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

/// Last path component of a dylib path, so `/usr/lib/libSystem.B.dylib` reads as the library.
fn dylib_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
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

    #[test]
    fn a_dylib_path_reduces_to_its_name() {
        assert_eq!(
            dylib_name("/usr/lib/libSystem.B.dylib"),
            "libSystem.B.dylib"
        );
        assert_eq!(dylib_name("libfoo.dylib"), "libfoo.dylib");
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
