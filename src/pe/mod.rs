//! PE analysis, mirroring the capabilities peframe surfaces.
//!
//! The import table is the most valuable part for Binspector's own purpose. A string
//! match is circumstantial: the name could be documentation, a namespace, or dead
//! data. An entry in the import directory is a linker-recorded dependency, which is
//! direct evidence that the binary calls the function.

pub mod authenticode;
pub mod chain;
pub mod ioc;
pub mod ipc;
pub mod loader;
pub mod mitigations;
pub mod packer;
pub mod posture;
pub mod sections;
pub mod signer;

use serde::{Deserialize, Serialize};

pub use ioc::Iocs;
pub use ipc::IpcSurface;
pub use loader::LoaderSurface;
pub use mitigations::Mitigations;
pub use sections::SectionInfo;
pub use signer::Signature;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImportRef {
    /// The library this symbol comes from.
    ///
    /// Named `library` rather than `dll` because the same type now carries ELF and Mach-O
    /// imports. Empty when the format cannot attribute a symbol to a library: ELF has a flat
    /// namespace, and the Mach-O symbol-table fallback does not expose the library ordinal. The
    /// JSON key stays `dll` so existing reports and consumers are unaffected.
    #[serde(rename = "dll")]
    pub library: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    /// Which loader APIs the image imports, and whether it shows any sign of constraining
    /// the search order. A surface, not a set of findings: see `loader`.
    #[serde(default)]
    pub loader: LoaderSurface,
    /// Who the Authenticode certificate claims signed this image.
    ///
    /// `None` means unsigned. `Some` with `signer: None` means signed but unreadable, which is
    /// a different fact and is reported differently.
    ///
    /// **This is an identity claim, not a trust decision.** Nothing here verifies the chain,
    /// checks revocation, or compares the Authenticode hash against the image, so a hostile
    /// binary can self-sign as anyone. It is useful for deprioritising a finding in a vendor's
    /// code, never for granting authority.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
    /// Named-pipe IPC surface, and whether a pipe server imports any authorization primitive.
    ///
    /// Narrowing, not reachability: it says where to look first, not that any particular finding
    /// is reachable. See `ipc`.
    #[serde(default)]
    pub ipc: IpcSurface,
    /// Whether `--first-party` matched this image's path or its signer name.
    ///
    /// Explicit rather than guessed. A signer name alone cannot tell first-party code from a
    /// vendor's, and an unsigned internal binary has no signer at all, so the caller says.
    #[serde(default)]
    pub first_party: bool,
    /// Hardened CRT variants the image imports, such as `strcpy_s`.
    ///
    /// Reported because the absence of this was a real complaint about the tool: an image can
    /// import 23 `strcpy_s` beside 5 `strcpy`, and a report that mentions only the five
    /// inverts the hygiene signal. This changes no severity. It is context a reviewer needs
    /// in order not to misread a finding.
    #[serde(default)]
    pub safe_variants: Vec<String>,
    pub packer_hints: Vec<String>,
    /// Bytes appended after the last section, a common payload hiding place.
    pub overlay_size: u64,
    /// Names in the export directory, lowercased.
    ///
    /// Not serialized: `icudt74.dll` and the CRT export thousands of names and none of them
    /// belongs in a report. This exists so adjudication can tell a definition site from a call
    /// site, which is a question only answerable with the export table in hand.
    #[serde(skip)]
    pub exports: Vec<String>,
}

impl PeAnalysis {
    /// Whether this image contains instructions at all.
    ///
    /// A PE is a container format, and a perfectly ordinary use of it is to ship no code:
    /// ICU's `icudt74.dll` is one 34 MiB `.rdata` section of locale data, and MUI satellites
    /// are resources only. Such an image received five HIGH `system` findings in a real
    /// report, which is not a false positive in the usual sense but a physically impossible
    /// claim, since there is no code in the file to make a call.
    ///
    /// An import directory counts as code even with no executable section, because something
    /// has to call what it imports and the section flags may have been tampered with.
    pub fn has_code(&self) -> bool {
        !self.imports.is_empty()
            || self
                .sections
                .iter()
                .any(|sec| sec.executable || sec.contains_code)
    }

    /// Whether the export table carries this name, compared the way `importing_library` does.
    pub fn exports_name(&self, function: &str) -> bool {
        let want = function.trim_start_matches('_').to_ascii_lowercase();
        self.exports
            .iter()
            .any(|e| e.trim_start_matches('_') == want)
    }
}

/// Seconds since the Unix epoch, for certificate validity windows.
///
/// Zero when the clock is before the epoch, which only a misconfigured system reports and which
/// would otherwise make every certificate look not-yet-valid. Expiry is reported rather than treated
/// as broken, so a wrong clock cannot turn into a finding.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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
                library: i.dll.to_string(),
                name: i.name.to_string(),
            })
            .collect();
        let is_managed = pe.clr_data.is_some();
        let packer_hints = packer::hints(&sections, imports.len(), is_managed);
        let loader = LoaderSurface::from_imports(&imports);
        let safe_variants = collect_safe_variants(&imports);
        let exports: Vec<String> = pe
            .exports
            .iter()
            .filter_map(|e| e.name)
            .map(|n| n.to_ascii_lowercase())
            .collect();
        // A parsed PE with a non-empty import directory is the case where absence of an
        // authorization primitive is evidence; see `ipc`.
        let ipc = IpcSurface::from_imports(&imports, !imports.is_empty());
        let mut signature = signer::parse(&pe.certificates);
        // The digest needs the whole image, which `signer` does not see. Done here so an unsigned
        // image costs nothing and a signed one is compared exactly once.
        if let (Some(sig), Some(blob)) = (signature.as_mut(), signer::blob(&pe.certificates)) {
            sig.digest = authenticode::verify(&pe, data, blob);
            let certs = signer::certificates(blob);
            let refs: Vec<&x509_cert::Certificate> = certs.iter().collect();
            sig.chain = chain::verify(&refs, now_unix());
        }

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
            exports,
            imports,
            tls_callbacks,
            has_debug_info: pe.debug_data.is_some(),
            mitigations: Mitigations::from_pe(&pe),
            loader,
            ipc,
            signature,
            // Set by the scan, which knows the member path and the --first-party pattern.
            first_party: false,
            safe_variants,
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
        importing_library(&self.imports, function)
    }

    /// Kept for the PE path's own call sites; the free function below is what the scan uses so
    /// the same lookup serves ELF and Mach-O.
    #[allow(dead_code)]
    fn importing_dll_inner(&self, function: &str) -> Option<&str> {
        self.imports
            .iter()
            .find(|i| i.name.eq_ignore_ascii_case(function))
            .map(|i| i.library.as_str())
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

/// Find the library that supplies a function, comparing case insensitively and tolerating the
/// MSVC leading underscore.
///
/// A free function over the import slice rather than a method, so the one lookup serves PE, ELF,
/// and Mach-O. Returns `Some("")` where the format cannot attribute a symbol to a library (ELF's
/// flat namespace, the Mach-O symbol-table fallback): the symbol *is* imported, which is the fact
/// the evidence path needs, and the empty library says attribution was unavailable rather than
/// that there is no import.
pub fn importing_library<'a>(imports: &'a [ImportRef], function: &str) -> Option<&'a str> {
    // The UCRT exports the POSIX-named functions with a leading underscore: the import is
    // `_mktemp`, never `mktemp`. An exact compare therefore missed an entire family of real
    // imports and reported them as bare string matches, under-rating a genuine CWE-377 finding
    // to the tier used for text with no import backing. Stripping the underscore from both
    // sides is the whole fix, and it cannot create a false match because no two CRT entry
    // points differ only by a leading underscore.
    let want = function.trim_start_matches('_');
    imports
        .iter()
        .find(|i| i.name.trim_start_matches('_').eq_ignore_ascii_case(want))
        .map(|i| i.library.as_str())
}

/// Hardened CRT variants an image imports, sorted and deduplicated.
///
/// The `_s` suffix is Microsoft's secure-CRT convention (`strcpy_s`, `sprintf_s`). The
/// `__stdio_common_*_s` entries are the UCRT's internal targets for the `printf_s` family and
/// count as the same signal. `rand_s` and `gets_s` are included: they are the hardened
/// replacements for names the banned list flags.
fn collect_safe_variants(imports: &[ImportRef]) -> Vec<String> {
    let mut out: Vec<String> = imports
        .iter()
        .map(|i| i.name.as_str())
        .filter(|n| n.ends_with("_s") || n.ends_with("_s_l"))
        .map(|n| n.to_string())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Shared fixtures for tests in sibling modules, which cannot reach a private test module.
#[cfg(test)]
#[path = "pe_fixture.rs"]
mod pe_fixture;

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    pub use super::pe_fixture::pe_with_code;

    /// A fully hardened 64-bit native DLL with no imports. Callers mutate what they need.
    pub fn analysis() -> PeAnalysis {
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
            imports: vec![],
            libraries: vec![],
            export_count: 0,
            exports: Vec::new(),
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
                gs: mitigations::State::Enabled,
                safe_seh: mitigations::State::Enabled,
                cet: mitigations::State::Enabled,
            },
            loader: LoaderSurface::default(),
            ipc: IpcSurface::default(),
            signature: None,
            first_party: false,
            safe_variants: vec![],
            packer_hints: vec![],
            overlay_size: 0,
        }
    }
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
                    library: dll.to_string(),
                    name: name.to_string(),
                })
                .collect(),
            libraries: vec![],
            export_count: 0,
            exports: Vec::new(),
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
                gs: mitigations::State::Enabled,
                safe_seh: mitigations::State::Unknown,
                cet: mitigations::State::Unknown,
            },
            loader: LoaderSurface::default(),
            ipc: IpcSurface::default(),
            signature: None,
            first_party: false,
            safe_variants: vec![],
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
