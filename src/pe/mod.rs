//! PE analysis, mirroring the capabilities peframe surfaces.
//!
//! The import table is the most valuable part for Binspector's own purpose. A string
//! match is circumstantial: the name could be documentation, a namespace, or dead
//! data. An entry in the import directory is a linker-recorded dependency, which is
//! direct evidence that the binary calls the function.

pub mod ioc;
pub mod mitigations;
pub mod packer;
pub mod sections;

use serde::Serialize;

pub use ioc::Iocs;
pub use mitigations::Mitigations;
pub use sections::SectionInfo;

#[derive(Clone, Debug, Serialize)]
pub struct ImportRef {
    pub dll: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PeAnalysis {
    pub machine: String,
    pub is_dll: bool,
    pub is_64: bool,
    pub subsystem: String,
    /// Link timestamp as recorded in the COFF header.
    pub timestamp: u32,
    pub entry_point: u32,
    pub image_base: u64,
    /// True when the image carries a CLR header, meaning managed .NET code.
    pub is_managed: bool,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportRef>,
    pub libraries: Vec<String>,
    pub export_count: usize,
    pub tls_callbacks: usize,
    pub has_debug_info: bool,
    pub mitigations: Mitigations,
    pub packer_hints: Vec<String>,
    /// Bytes appended after the last section, a common payload hiding place.
    pub overlay_size: u64,
}

impl PeAnalysis {
    /// Parse a PE image. Returns `None` when the bytes are not a parseable PE, which
    /// is expected for resources and data files inside an application bundle.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let pe = goblin::pe::PE::parse(data).ok()?;

        let sections = sections::analyze(&pe, data);
        let imports: Vec<ImportRef> = pe
            .imports
            .iter()
            .map(|i| ImportRef {
                dll: i.dll.to_string(),
                name: i.name.to_string(),
            })
            .collect();
        let is_managed = pe.clr_data.is_some();
        let packer_hints = packer::hints(&sections, imports.len(), is_managed);

        let (subsystem, image_base) = match pe.header.optional_header {
            Some(oh) => (
                subsystem_name(oh.windows_fields.subsystem),
                oh.windows_fields.image_base,
            ),
            None => ("unknown".to_string(), pe.image_base),
        };

        // Overlay: anything past the end of the furthest raw section.
        let end_of_sections = pe
            .sections
            .iter()
            .map(|s| s.pointer_to_raw_data as u64 + s.size_of_raw_data as u64)
            .max()
            .unwrap_or(0);
        let overlay_size = (data.len() as u64).saturating_sub(end_of_sections);

        let tls_callbacks = pe.tls_data.as_ref().map(|t| t.callbacks.len()).unwrap_or(0);

        Some(Self {
            machine: machine_name(pe.header.coff_header.machine),
            is_dll: pe.is_lib,
            is_64: pe.is_64,
            subsystem,
            timestamp: pe.header.coff_header.time_date_stamp,
            entry_point: pe.entry,
            image_base,
            is_managed,
            sections,
            libraries: pe.libraries.iter().map(|s| s.to_string()).collect(),
            export_count: pe.exports.len(),
            imports,
            tls_callbacks,
            has_debug_info: pe.debug_data.is_some(),
            mitigations: Mitigations::from_pe(&pe),
            packer_hints,
            overlay_size,
        })
    }

    /// Imported function names, lowercased, for cross-referencing a banned list.
    pub fn imported_names(&self) -> Vec<&str> {
        self.imports.iter().map(|i| i.name.as_str()).collect()
    }

    /// Find the importing DLL for a function name, comparing case insensitively.
    pub fn importing_dll(&self, function: &str) -> Option<&str> {
        self.imports
            .iter()
            .find(|i| i.name.eq_ignore_ascii_case(function))
            .map(|i| i.dll.as_str())
    }

    /// Notes worth putting in front of a reviewer, beyond the raw fields.
    pub fn notes(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .mitigations
            .weaknesses()
            .iter()
            .map(|s| s.to_string())
            .collect();
        out.extend(self.packer_hints.iter().cloned());
        if self.tls_callbacks > 0 {
            out.push(format!(
                "{} TLS callback(s), which run before the entry point",
                self.tls_callbacks
            ));
        }
        if self.overlay_size > 1024 * 1024 {
            out.push(format!(
                "{} bytes of overlay data appended after the last section",
                self.overlay_size
            ));
        }
        if self.is_managed {
            out.push(
                "managed .NET assembly, so most embedded text is metadata and documentation \
                 rather than native code"
                    .to_string(),
            );
        }
        out
    }
}

fn machine_name(m: u16) -> String {
    match m {
        0x014c => "i386",
        0x8664 => "x86_64",
        0x01c0 => "arm",
        0x01c4 => "armv7",
        0xaa64 => "arm64",
        0x0200 => "ia64",
        0x5032 => "riscv32",
        0x5064 => "riscv64",
        0 => "unknown",
        _ => "other",
    }
    .to_string()
}

fn subsystem_name(s: u16) -> String {
    match s {
        1 => "native",
        2 => "windows-gui",
        3 => "windows-cui",
        5 => "os2-cui",
        7 => "posix-cui",
        9 => "windows-ce-gui",
        10 => "efi-application",
        14 => "xbox",
        16 => "windows-boot-application",
        _ => "unknown",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A syntactically valid minimal PE32+ is awkward to hand-build, so these tests
    /// cover the pieces that do not need a full image. End-to-end PE parsing is
    /// covered against the real sample in the integration tests.
    #[test]
    fn rejects_non_pe_input() {
        assert!(PeAnalysis::parse(b"not a pe at all").is_none());
        assert!(PeAnalysis::parse(&[]).is_none());
        assert!(PeAnalysis::parse(&[0x50, 0x4B, 0x03, 0x04]).is_none());
    }

    #[test]
    fn machine_names_cover_common_architectures() {
        assert_eq!(machine_name(0x8664), "x86_64");
        assert_eq!(machine_name(0xaa64), "arm64");
        assert_eq!(machine_name(0x014c), "i386");
        assert_eq!(machine_name(0x9999), "other");
    }

    #[test]
    fn subsystem_names_cover_common_values() {
        assert_eq!(subsystem_name(2), "windows-gui");
        assert_eq!(subsystem_name(3), "windows-cui");
        assert_eq!(subsystem_name(1), "native");
        assert_eq!(subsystem_name(99), "unknown");
    }

    fn analysis_with_imports(pairs: &[(&str, &str)]) -> PeAnalysis {
        PeAnalysis {
            machine: "x86_64".into(),
            is_dll: true,
            is_64: true,
            subsystem: "windows-gui".into(),
            timestamp: 0,
            entry_point: 0x1000,
            image_base: 0x1_4000_0000,
            is_managed: false,
            sections: vec![],
            imports: pairs
                .iter()
                .map(|(dll, name)| ImportRef {
                    dll: dll.to_string(),
                    name: name.to_string(),
                })
                .collect(),
            libraries: vec![],
            export_count: 0,
            tls_callbacks: 0,
            has_debug_info: false,
            mitigations: Mitigations {
                aslr: mitigations::State::Enabled,
                high_entropy_va: mitigations::State::Enabled,
                dep: mitigations::State::Enabled,
                cfg: mitigations::State::Enabled,
                seh: mitigations::State::Enabled,
                force_integrity: mitigations::State::Enabled,
                appcontainer: mitigations::State::Enabled,
                authenticode: mitigations::State::Enabled,
                relocations: mitigations::State::Enabled,
            },
            packer_hints: vec![],
            overlay_size: 0,
        }
    }

    #[test]
    fn finds_the_importing_dll_case_insensitively() {
        let a = analysis_with_imports(&[("msvcrt.dll", "strcpy"), ("KERNEL32.dll", "lstrcpyA")]);
        assert_eq!(a.importing_dll("strcpy"), Some("msvcrt.dll"));
        assert_eq!(a.importing_dll("STRCPY"), Some("msvcrt.dll"));
        assert_eq!(a.importing_dll("lstrcpya"), Some("KERNEL32.dll"));
        assert_eq!(a.importing_dll("memcpy"), None);
    }

    #[test]
    fn notes_flag_tls_callbacks_and_overlay() {
        let mut a = analysis_with_imports(&[]);
        a.tls_callbacks = 2;
        a.overlay_size = 5 * 1024 * 1024;
        let n = a.notes();
        assert!(n.iter().any(|s| s.contains("TLS callback")));
        assert!(n.iter().any(|s| s.contains("overlay")));
    }

    #[test]
    fn notes_explain_managed_assemblies() {
        let mut a = analysis_with_imports(&[]);
        a.is_managed = true;
        assert!(a.notes().iter().any(|s| s.contains("managed .NET")));
    }

    #[test]
    fn fully_hardened_pe_with_nothing_odd_has_no_notes() {
        assert!(analysis_with_imports(&[("k.dll", "f")]).notes().is_empty());
    }
}
