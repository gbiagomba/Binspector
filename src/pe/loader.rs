//! Dynamic loading surface: which loader APIs an image imports, and whether it shows any
//! sign of constraining the search order.
//!
//! Why this is a surface rather than a set of findings. `LoadLibrary("version.dll")` is a
//! DLL preloading vulnerability; `LoadLibrary("C:\\Windows\\System32\\version.dll")` is
//! correct code. The difference is the argument, and an import table records only that the
//! function is called, never with what. Reporting every image that imports `LoadLibrary` as
//! defective would be inference dressed as evidence, which is the exact mistake the
//! boundary-verification work in 3.0.0 existed to correct. On the 441-image reference
//! bundle, 78 images import the family.
//!
//! So this module reports what is actually knowable, and says plainly what is not.
//!
//! Reference: <https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security>

use serde::{Deserialize, Serialize};

use super::ImportRef;

/// How much evidence there is that an image constrains its own search order.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Imports one of the search-path hardening APIs, so the search order was thought about.
    Hardened,
    /// Loads dynamically with no hardening import, but nothing further points at a problem.
    Unhardened,
    /// Plain `LoadLibrary`, no hardening import, and bare module-name strings in the image.
    /// The strongest signal available without a disassembler, and still not proof.
    Unqualified,
    /// No dynamic loading imports at all.
    #[default]
    None,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Hardened => "hardened",
            Verdict::Unhardened => "unhardened",
            Verdict::Unqualified => "unqualified",
            Verdict::None => "none",
        }
    }

    /// Whether this is worth a reviewer's attention, for the `--missing dll-search` filter.
    pub fn is_weak(self) -> bool {
        matches!(self, Verdict::Unhardened | Verdict::Unqualified)
    }
}

/// Hardening APIs. Importing any of these means the author restricted the search path.
const HARDENING: &[&str] = &[
    "SetDefaultDllDirectories",
    "AddDllDirectory",
    "RemoveDllDirectory",
];

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LoaderSurface {
    /// Plain `LoadLibrary`, which has no parameter that can constrain the search. A
    /// qualified path is the only available defence.
    pub load_library: usize,
    /// `LoadLibraryEx`, which accepts `LOAD_LIBRARY_SEARCH_*` flags and so *can* be called
    /// safely. The flags are immediates in code, not data, so their use is not visible here.
    pub load_library_ex: usize,
    /// `LoadPackagedLibrary`, which resolves within the package graph and is the safest of
    /// the three.
    pub load_packaged_library: usize,
    pub get_proc_address: usize,
    pub search_path: usize,
    pub set_dll_directory: usize,
    /// `WinExec`, `LoadModule`, `ShellExecute*`, `CreateProcess*`.
    pub process_creation: usize,
    /// Hardening APIs actually imported, named so the report can show which.
    pub hardening: Vec<String>,
    /// Bare module-name strings such as `version.dll`, with the offset of each. Evidence
    /// for the `Unqualified` verdict, and hand-verifiable at the offset given.
    #[serde(default)]
    pub unqualified_modules: Vec<UnqualifiedModule>,
    pub verdict: Verdict,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnqualifiedModule {
    pub name: String,
    pub offset: u64,
}

impl LoaderSurface {
    /// Count the loader imports. The verdict is provisional until `note_strings` runs,
    /// because the string evidence is not available at PE-parse time.
    pub fn from_imports(imports: &[ImportRef]) -> Self {
        let mut s = Self::default();
        for i in imports {
            let n = i.name.as_str();
            // Order matters: LoadLibraryEx and LoadPackagedLibrary both start with
            // "LoadLibrary" and "LoadPackagedLibrary" respectively, so the more specific
            // prefixes are tested first.
            if n.starts_with("LoadLibraryEx") {
                s.load_library_ex += 1;
            } else if n.starts_with("LoadPackagedLibrary") {
                s.load_packaged_library += 1;
            } else if n.starts_with("LoadLibrary") {
                s.load_library += 1;
            } else if n.starts_with("GetProcAddress") {
                s.get_proc_address += 1;
            } else if n.starts_with("SearchPath") {
                s.search_path += 1;
            } else if n.starts_with("SetDllDirectory") {
                s.set_dll_directory += 1;
            } else if n.starts_with("WinExec")
                || n.starts_with("LoadModule")
                || n.starts_with("ShellExecute")
                || n.starts_with("CreateProcess")
            {
                s.process_creation += 1;
            } else if HARDENING.contains(&n) {
                s.hardening.push(n.to_string());
            }
        }
        s.verdict = s.decide();
        s
    }

    /// True when the image loads anything dynamically, which gates the report section.
    pub fn loads_dynamically(&self) -> bool {
        self.load_library > 0
            || self.load_library_ex > 0
            || self.load_packaged_library > 0
            || self.search_path > 0
            || self.set_dll_directory > 0
    }

    /// Record bare module-name strings found in this image and settle the verdict.
    ///
    /// Only meaningful for an image that already imports the loader family, so the caller
    /// checks `loads_dynamically` first. Capped, because a large image can carry hundreds
    /// and the point is to give a reviewer a place to start, not an inventory.
    pub fn note_strings(&mut self, found: Vec<UnqualifiedModule>, cap: usize) {
        self.unqualified_modules = found;
        // Case-insensitive, because an image commonly carries both `KernelBase.dll` and
        // `kernelbase.dll` and listing each is noise for one module.
        self.unqualified_modules
            .sort_by_key(|m| m.name.to_ascii_lowercase());
        self.unqualified_modules
            .dedup_by(|a, b| a.name.eq_ignore_ascii_case(&b.name));
        self.unqualified_modules.truncate(cap);
        self.verdict = self.decide();
    }

    fn decide(&self) -> Verdict {
        if !self.loads_dynamically() {
            return Verdict::None;
        }
        if !self.hardening.is_empty() {
            return Verdict::Hardened;
        }
        // Plain LoadLibrary cannot restrict the search at all, so a bare module name in the
        // same image is the one combination worth calling out.
        if self.load_library > 0 && !self.unqualified_modules.is_empty() {
            return Verdict::Unqualified;
        }
        Verdict::Unhardened
    }
}

/// Decides which bare module names are actually `LoadLibrary` candidates for one image.
///
/// The syntactic check alone is far too generous. Every PE carries the names of the DLLs it
/// imports statically as strings, because they are in the import directory, so `KERNEL32.dll`
/// and `api-ms-win-crt-convert-l1-1-0.dll` appear in almost every image. Those are resolved
/// by the loader from the import table, not by a `LoadLibrary` call, and reporting them
/// turned 27 of 41 images into a warning that said nothing.
///
/// What remains after excluding them is the interesting set: a module named in the image's
/// text that it does *not* statically import, which is what a runtime load looks like.
pub struct ModuleFilter {
    static_libs: std::collections::BTreeSet<String>,
    self_name: String,
}

impl ModuleFilter {
    pub fn new(static_libs: &[String], self_name: &str) -> Self {
        Self {
            static_libs: static_libs.iter().map(|l| l.to_ascii_lowercase()).collect(),
            self_name: self_name.to_ascii_lowercase(),
        }
    }

    pub fn is_candidate(&self, s: &str) -> bool {
        if !is_bare_module_name(s) {
            return false;
        }
        let lower = s.to_ascii_lowercase();
        // Statically imported: the loader resolves it from the import directory.
        if self.static_libs.contains(&lower) {
            return false;
        }
        // API sets are resolved through the OS schema, not a filesystem search.
        if lower.starts_with("api-ms-win-") || lower.starts_with("ext-ms-") {
            return false;
        }
        // An image naming itself is a version or resource string, not a load.
        if lower == self.self_name {
            return false;
        }
        true
    }
}

/// Whether a string is a bare module name: a filename with a loadable extension and no
/// path separator, drive letter, or environment placeholder.
///
/// `version.dll` qualifies. `C:\Windows\System32\version.dll`, `./libfoo.so`, and
/// `%SystemRoot%\foo.dll` do not, because each names a location.
pub fn is_bare_module_name(s: &str) -> bool {
    if s.len() < 5 || s.len() > 64 {
        return false;
    }
    if s.contains(['/', '\\', ':', '%', ' ', '"']) {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    let stem = match lower
        .strip_suffix(".dll")
        .or_else(|| lower.strip_suffix(".so"))
        .or_else(|| lower.strip_suffix(".dylib"))
    {
        Some(stem) => stem,
        None => return false,
    };
    if stem.is_empty() || stem.starts_with('.') {
        return false;
    }
    // A module name is an identifier-ish token. This keeps prose such as
    // "see foo.dll" out, since the space already excluded it, and rejects oddities.
    stem.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn imports(names: &[&str]) -> Vec<ImportRef> {
        names
            .iter()
            .map(|n| ImportRef {
                library: "KERNEL32.dll".to_string(),
                name: n.to_string(),
            })
            .collect()
    }

    #[test]
    fn counts_the_three_load_variants_separately() {
        let s = LoaderSurface::from_imports(&imports(&[
            "LoadLibraryA",
            "LoadLibraryW",
            "LoadLibraryExW",
            "LoadPackagedLibrary",
        ]));
        assert_eq!(s.load_library, 2, "Ex must not be counted as plain");
        assert_eq!(s.load_library_ex, 1);
        assert_eq!(s.load_packaged_library, 1);
    }

    #[test]
    fn hardening_imports_win_the_verdict() {
        let s =
            LoaderSurface::from_imports(&imports(&["LoadLibraryW", "SetDefaultDllDirectories"]));
        assert_eq!(s.verdict, Verdict::Hardened);
        assert_eq!(s.hardening, vec!["SetDefaultDllDirectories"]);
        assert!(!s.verdict.is_weak());
    }

    #[test]
    fn plain_load_library_plus_a_bare_name_is_unqualified() {
        let mut s = LoaderSurface::from_imports(&imports(&["LoadLibraryW"]));
        assert_eq!(s.verdict, Verdict::Unhardened, "no string evidence yet");
        s.note_strings(
            vec![UnqualifiedModule {
                name: "version.dll".to_string(),
                offset: 0x1000,
            }],
            10,
        );
        assert_eq!(s.verdict, Verdict::Unqualified);
        assert!(s.verdict.is_weak());
    }

    #[test]
    fn load_library_ex_alone_is_not_escalated() {
        // LoadLibraryEx can take search flags, so a bare name is weaker evidence there.
        let mut s = LoaderSurface::from_imports(&imports(&["LoadLibraryExW"]));
        s.note_strings(
            vec![UnqualifiedModule {
                name: "version.dll".to_string(),
                offset: 1,
            }],
            10,
        );
        assert_eq!(s.verdict, Verdict::Unhardened);
    }

    #[test]
    fn no_loader_imports_means_no_verdict() {
        let s = LoaderSurface::from_imports(&imports(&["GetLastError", "Sleep"]));
        assert_eq!(s.verdict, Verdict::None);
        assert!(!s.loads_dynamically());
        assert!(!s.verdict.is_weak());
    }

    #[test]
    fn get_proc_address_is_counted_but_never_drives_a_verdict() {
        // It does not influence search order, so it is context only.
        let s = LoaderSurface::from_imports(&imports(&["GetProcAddress"]));
        assert_eq!(s.get_proc_address, 1);
        assert_eq!(s.verdict, Verdict::None);
    }

    #[test]
    fn process_creation_imports_are_grouped() {
        let s = LoaderSurface::from_imports(&imports(&[
            "WinExec",
            "ShellExecuteExW",
            "CreateProcessW",
            "LoadModule",
        ]));
        assert_eq!(s.process_creation, 4);
    }

    #[test]
    fn statically_imported_names_are_not_load_candidates() {
        // The exact noise this filter exists to remove: these appear as strings in almost
        // every PE because they are in its import directory.
        let f = ModuleFilter::new(
            &["KERNEL32.dll".to_string(), "ADVAPI32.dll".to_string()],
            "foo.dll",
        );
        assert!(!f.is_candidate("KERNEL32.dll"), "statically imported");
        assert!(!f.is_candidate("kernel32.dll"), "case must not matter");
        assert!(!f.is_candidate("advapi32.dll"));
        assert!(
            !f.is_candidate("api-ms-win-crt-convert-l1-1-0.dll"),
            "API sets resolve through the OS schema"
        );
        assert!(!f.is_candidate("ext-ms-win-foo-l1-1-0.dll"));
        assert!(!f.is_candidate("foo.dll"), "an image naming itself");
        // Not statically imported, so this is what a runtime load looks like.
        assert!(f.is_candidate("version.dll"));
        assert!(f.is_candidate("plugin_helper.dll"));
    }

    #[test]
    fn bare_module_names_are_recognised() {
        assert!(is_bare_module_name("version.dll"));
        assert!(is_bare_module_name("libssl-3.so"));
        assert!(is_bare_module_name("libfoo.dylib"));
        assert!(is_bare_module_name("api-ms-win-core-l1-1-0.dll"));
    }

    #[test]
    fn qualified_and_prose_names_are_rejected() {
        // Each of these names a location, so it is not a preloading candidate.
        assert!(!is_bare_module_name("C:\\Windows\\System32\\version.dll"));
        assert!(!is_bare_module_name("./libfoo.so"));
        assert!(!is_bare_module_name("/usr/lib/libfoo.dylib"));
        assert!(!is_bare_module_name("%SystemRoot%\\foo.dll"));
        assert!(!is_bare_module_name("see version.dll for details"));
        assert!(!is_bare_module_name(".dll"));
        assert!(!is_bare_module_name("foo.exe"));
        assert!(!is_bare_module_name("dll"));
    }

    #[test]
    fn noted_strings_are_deduped_sorted_and_capped() {
        let mut s = LoaderSurface::from_imports(&imports(&["LoadLibraryW"]));
        s.note_strings(
            vec![
                UnqualifiedModule {
                    name: "b.dll".to_string(),
                    offset: 2,
                },
                UnqualifiedModule {
                    name: "a.dll".to_string(),
                    offset: 1,
                },
                UnqualifiedModule {
                    name: "a.dll".to_string(),
                    offset: 9,
                },
                UnqualifiedModule {
                    name: "A.dll".to_string(),
                    offset: 7,
                },
                UnqualifiedModule {
                    name: "c.dll".to_string(),
                    offset: 3,
                },
            ],
            2,
        );
        let names: Vec<&str> = s
            .unqualified_modules
            .iter()
            .map(|m| m.name.as_str())
            .collect();
        assert_eq!(names, vec!["a.dll", "b.dll"]);
        // The first offset for a repeated name is kept, so it stays verifiable.
        assert_eq!(s.unqualified_modules[0].offset, 1);
    }
}
