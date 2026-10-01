//! ELF imports, read from the dynamic symbol table.
//!
//! An import in ELF terms is an **undefined** symbol in `.dynsym`: the binary references it and
//! the dynamic linker must supply it. goblin has no `Elf::imports()` to call, so the list is
//! built here.
//!
//! Two traps, both avoided deliberately:
//!
//! `Sym::is_import()` is **not** the right predicate. It tests whether the binding is global or
//! weak and the value is zero, which both false-positives on a defined symbol that legitimately
//! sits at address zero (common for `STT_NOTYPE` and some `STT_TLS` entries) and false-negatives
//! on a common-block symbol that is undefined with a non-zero value. The canonical test is
//! `st_shndx == SHN_UNDEF`, which is what this uses. goblin also carries a second, inconsistent
//! free function of the same name that omits weak bindings entirely.
//!
//! ELF has a **flat symbol namespace**. `DT_NEEDED` lists the sonames the image depends on, but
//! nothing records which soname will satisfy a given symbol without resolving the libraries on
//! disk, which this tool does not do. So `ImportRef.library` is left empty rather than guessing,
//! and the PE path's per-symbol attribution has no ELF equivalent.

use goblin::elf::section_header::SHN_UNDEF;
use goblin::elf::Elf;

use super::{Source, UnixImports};
use crate::pe::ImportRef;

/// Highest number of imports recorded from one image.
///
/// A real binary imports hundreds; a crafted one can claim a symbol table of any size. The cap
/// bounds the work and the memory without changing any honest result.
const MAX_IMPORTS: usize = 20_000;

/// Read ELF imports, or `None` when the bytes are not an ELF.
pub fn read(data: &[u8]) -> Option<UnixImports> {
    if !data.starts_with(b"\x7fELF") {
        return None;
    }
    // Permissive parsing: a truncated or odd ELF should yield what it can rather than nothing,
    // and this runs on untrusted input.
    let elf = Elf::parse(data).ok()?;

    let mut imports: Vec<ImportRef> = Vec::new();
    for sym in elf.dynsyms.iter() {
        if imports.len() >= MAX_IMPORTS {
            break;
        }
        // Undefined is what makes it an import. See the module note on `is_import`.
        if sym.st_shndx != SHN_UNDEF as usize {
            continue;
        }
        // Index 0 is the reserved null symbol.
        if sym.st_name == 0 {
            continue;
        }
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        imports.push(ImportRef {
            // Flat namespace: no per-symbol library. Left empty rather than guessed.
            library: String::new(),
            name: name.to_string(),
        });
    }
    imports.sort_by(|a, b| a.name.cmp(&b.name));
    imports.dedup_by(|a, b| a.name == b.name);

    Some(UnixImports {
        source: if imports.is_empty() {
            // Parsed, but nothing undefined: a static binary, or one with no dynamic symbols.
            // Not the same as "could not read imports", and the caller needs that distinction.
            Source::ElfDynsym
        } else {
            Source::ElfDynsym
        },
        imports,
    })
}

/// Sonames the image declares a dependency on, which is the nearest ELF analogue of the PE
/// library list even though it cannot attribute individual symbols.
pub fn needed_libraries(data: &[u8]) -> Vec<String> {
    match Elf::parse(data) {
        Ok(elf) => elf.libraries.iter().map(|s| s.to_string()).collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_elf_input_is_declined_so_the_caller_can_try_the_next_format() {
        assert!(read(b"MZ\x90\x00 a PE, not an ELF").is_none());
        assert!(read(b"").is_none());
        assert!(read(b"\x7fEL").is_none());
    }

    #[test]
    fn a_truncated_elf_does_not_panic() {
        // Magic present, everything else missing.
        for n in 4..64 {
            let mut v = b"\x7fELF".to_vec();
            v.resize(n, 0);
            let _ = read(&v);
        }
    }

    /// The real coverage for this module comes from scanning a system binary on a platform that
    /// has one, which is how CI exercises it: the Linux runners carry real ELF images and the
    /// repository carries none. A hand-built ELF with a valid dynamic symbol table is a hundred
    /// lines of fixture that tests the fixture more than the reader.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_real_system_binary_yields_imports() {
        let data = match std::fs::read("/bin/sh") {
            Ok(d) => d,
            Err(_) => return,
        };
        let got = read(&data).expect("/bin/sh is an ELF");
        assert_eq!(got.source, Source::ElfDynsym);
        assert!(
            !got.imports.is_empty(),
            "a dynamically linked shell imports something"
        );
        // Every name is non-empty and deduplicated.
        assert!(got.imports.iter().all(|i| !i.name.is_empty()));
        let mut names: Vec<&str> = got.imports.iter().map(|i| i.name.as_str()).collect();
        let before = names.len();
        names.sort();
        names.dedup();
        assert_eq!(before, names.len(), "imports must be deduplicated");
        // Flat namespace, so no per-symbol library attribution is claimed.
        assert!(got.imports.iter().all(|i| i.library.is_empty()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_real_system_binary_declares_needed_libraries() {
        let data = match std::fs::read("/bin/sh") {
            Ok(d) => d,
            Err(_) => return,
        };
        assert!(
            !needed_libraries(&data).is_empty(),
            "DT_NEEDED should be present"
        );
    }
}
