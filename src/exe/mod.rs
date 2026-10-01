//! Import tables for the two formats that are not PE.
//!
//! Why this exists. `Confidence::Import` is the strongest evidence the tool has: an entry in an
//! import table is a linker-recorded dependency, so the binary demonstrably calls the function,
//! unlike a name that merely appears in its bytes. Until 5.2.0 that tier was derivable only from
//! a PE import directory, which meant `Report::definitive_hits()` was structurally zero for every
//! ELF and Mach-O binary scanned. The tool was quietly much weaker on Linux and macOS than on
//! Windows, and said nothing about it.
//!
//! Both readers produce the same `ImportRef` the PE path produces, so the evidence loop, the
//! severity rules, and every writer work unchanged.

pub mod binds;
pub mod chained;
pub mod elf;
pub mod macho;
pub mod posture;
pub mod posture_rules;

use crate::pe::ImportRef;

/// Imports read from a non-PE executable, with how they were obtained.
#[derive(Clone, Debug, Default)]
pub struct UnixImports {
    pub imports: Vec<ImportRef>,
    /// Which mechanism produced the list, because they carry different fidelity and a reviewer
    /// should be able to tell which one answered.
    ///
    /// A universal binary can resolve one architecture through the bind opcodes and the next
    /// through the chained import table, so for a fat image this names the **strongest** mechanism
    /// any slice used, in the order bind opcodes, chained table, symbol table. The distinction that
    /// matters to a reader is whether the entries are attributed to a library: the first two are,
    /// the symbol table is not.
    pub source: Source,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum Source {
    #[default]
    None,
    /// ELF `.dynsym` entries that are undefined, which is what an import is in ELF terms.
    ElfDynsym,
    /// Mach-O dyld bind opcodes, which carry per-symbol library attribution.
    MachoBinds,
    /// Mach-O `LC_DYLD_CHAINED_FIXUPS` import table, which carries library ordinals and is the
    /// only place imports live on an image built by a current toolchain.
    MachoChained,
    /// Mach-O `LC_SYMTAB` undefined externals. Used when the bind opcodes are unavailable,
    /// which is the normal case on a modern binary; loses library attribution.
    MachoSymtab,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::None => "none",
            Source::ElfDynsym => "elf-dynsym",
            Source::MachoBinds => "macho-binds",
            Source::MachoChained => "macho-chained",
            Source::MachoSymtab => "macho-symtab",
        }
    }
}

/// Read imports from a member already known to be an ELF or Mach-O image.
///
/// Returns an empty set rather than an error for anything unparseable: a member that cannot be
/// read is a coverage gap, not a scan failure, and the caller distinguishes "no imports found"
/// from "imports not readable" through `Source::None`.
pub fn read(data: &[u8]) -> UnixImports {
    if let Some(found) = elf::read(data) {
        return found;
    }
    if let Some(found) = macho::read(data) {
        return found;
    }
    UnixImports::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrecognised_bytes_yield_nothing_rather_than_an_error() {
        let got = read(b"not an executable of any kind, just text");
        assert!(got.imports.is_empty());
        assert_eq!(got.source, Source::None);
    }

    #[test]
    fn a_truncated_header_does_not_panic() {
        for bytes in [
            &b"\x7fELF"[..],
            &b"\x7fELF\x02\x01\x01"[..],
            &b"\xcf\xfa\xed\xfe"[..],
            &b"\xca\xfe\xba\xbe\x00\x00\x00\x02"[..],
        ] {
            let _ = read(bytes);
        }
    }

    #[test]
    fn source_labels_are_stable() {
        assert_eq!(Source::ElfDynsym.as_str(), "elf-dynsym");
        assert_eq!(Source::MachoBinds.as_str(), "macho-binds");
        assert_eq!(Source::MachoSymtab.as_str(), "macho-symtab");
    }
}
