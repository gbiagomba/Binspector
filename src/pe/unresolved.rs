//! Modules an image imports that the package does not contain.
//!
//! **What this finds.** A statically imported DLL that ships nowhere in the package and is not a
//! Windows component. The loader will search for it at load time, and whatever it finds first
//! wins, so the dependency is satisfied by the filesystem rather than by the vendor. In the
//! reference package `AdobePDFL.dll` statically imports 25 functions from `libcrypto-3-x64.dll`,
//! no `libcrypto` ships in any of the 4,281 members, that image is unsigned, and only 9 of 1,567
//! images import any search-path hardening API at all.
//!
//! **What this deliberately does not claim.** Absence from the package is not absence at runtime.
//! A system DLL, a side-by-side assembly, a redistributable installed separately and a module
//! loaded from the application directory all resolve perfectly well without shipping here. So the
//! finding is narrower than "this will fail to load" and narrower than "this is hijackable": the
//! module is imported, it is not in the package, and the tool does not recognise it as a Windows
//! component, so what satisfies it is decided by the search order rather than by the build.
//!
//! This is the same shape as `ipc`: narrowing, not reachability.
//!
//! **Why the allowlist is the whole problem, measured rather than assumed.** On the reference
//! package 169 of 202 imported libraries are absent from it, and almost every one is ordinary
//! Windows surface. Reporting those as findings would bury the three that matter under 166 that
//! do not. The list below takes it to three, and the count of what it suppressed is reported, so
//! a reader can see the filter worked rather than trusting that it did.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Name prefixes that are always a Windows component.
///
/// The API sets are the big win: `api-ms-win-*` and `ext-ms-win-*` are the umbrella libraries
/// every modern image links against, and they resolve through the apiset schema rather than from
/// a file on disk at all, so they could never be "shipped in the package".
const SYSTEM_PREFIXES: &[&str] = &[
    "api-ms-win-",
    "ext-ms-win-",
    "microsoft.windows.",
    "windows.",
    "vcruntime",
    "ucrtbase",
    "msvcp",
    "msvcr",
    "concrt",
    "d3d",
    "mfc",
    "atl",
];

/// Windows components by name.
///
/// Every entry was either present in the reference package's import set or is a near neighbour of
/// one that was. Ten of these were missed on a first pass and showed up as false findings, which
/// is the honest reason the list is this long: `d2d1`, `dxcore`, `shcore`, `xmllite`,
/// `bcp47langs`, `bcp47mrm`, `elscore`, `rometadata`, `sensapi` and `winspool.drv`.
const SYSTEM_NAMES: &[&str] = &[
    "advapi32.dll",
    "audioses.dll",
    "avrt.dll",
    "bcp47langs.dll",
    "bcp47mrm.dll",
    "bcrypt.dll",
    "bcryptprimitives.dll",
    "bthprops.cpl",
    "cabinet.dll",
    "cfgmgr32.dll",
    "clbcatq.dll",
    "combase.dll",
    "comctl32.dll",
    "comdlg32.dll",
    "coremessaging.dll",
    "credui.dll",
    "crypt32.dll",
    "cryptbase.dll",
    "cryptsp.dll",
    "d2d1.dll",
    "dbghelp.dll",
    "dcomp.dll",
    "devobj.dll",
    "dhcpcsvc.dll",
    "dnsapi.dll",
    "dsound.dll",
    "dwmapi.dll",
    "dwrite.dll",
    "dxcore.dll",
    "dxgi.dll",
    "dxva2.dll",
    "edputil.dll",
    "efswrt.dll",
    "elscore.dll",
    "esent.dll",
    "faultrep.dll",
    "fwpuclnt.dll",
    "gdi32.dll",
    "gdiplus.dll",
    "glu32.dll",
    "hid.dll",
    "httpapi.dll",
    "imm32.dll",
    "iphlpapi.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "logoncli.dll",
    "mf.dll",
    "mfplat.dll",
    "mfreadwrite.dll",
    "mmdevapi.dll",
    "mpr.dll",
    "mscoree.dll",
    "msi.dll",
    "msimg32.dll",
    "msvcrt.dll",
    "netapi32.dll",
    "netutils.dll",
    "normaliz.dll",
    "nsi.dll",
    "ntdll.dll",
    "ntmarta.dll",
    "ole32.dll",
    "oleacc.dll",
    "oleaut32.dll",
    "opengl32.dll",
    "powrprof.dll",
    "profapi.dll",
    "propsys.dll",
    "psapi.dll",
    "rasapi32.dll",
    "rasman.dll",
    "rometadata.dll",
    "rpcrt4.dll",
    "rtworkq.dll",
    "samcli.dll",
    "sechost.dll",
    "secur32.dll",
    "sensapi.dll",
    "setupapi.dll",
    "shcore.dll",
    "shell32.dll",
    "shlwapi.dll",
    "srvcli.dll",
    "sspicli.dll",
    "t2embed.dll",
    "tdh.dll",
    "twinapi.appcore.dll",
    "urlmon.dll",
    "user32.dll",
    "userenv.dll",
    "usp10.dll",
    "uxtheme.dll",
    "vcomp140.dll",
    "version.dll",
    "wer.dll",
    "wevtapi.dll",
    "win32u.dll",
    "windowscodecs.dll",
    "wininet.dll",
    "winhttp.dll",
    "winmm.dll",
    "winnsi.dll",
    "winspool.drv",
    "wintrust.dll",
    "wintypes.dll",
    "winusb.dll",
    "wldap32.dll",
    "wmiutils.dll",
    "ws2_32.dll",
    "wtsapi32.dll",
    "xinput1_4.dll",
    "xmllite.dll",
];

/// Whether an imported library name is a Windows component.
pub fn is_system_module(library: &str) -> bool {
    let lower = library.to_ascii_lowercase();
    SYSTEM_NAMES.contains(&lower.as_str()) || SYSTEM_PREFIXES.iter().any(|p| lower.starts_with(p))
}

/// One imported module that the package does not contain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unresolved {
    pub library: String,
    /// Functions imported from it, which is how much of the module's surface is in use.
    pub imports: usize,
}

/// What one image imports from outside the package.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct External {
    pub modules: Vec<Unresolved>,
    /// Imported modules recognised as Windows components, so the filter is visible rather than
    /// implicit. 166 of 169 on the reference package.
    pub system_resolved: usize,
}

impl External {
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }
}

/// Compare one image's imports against the names the package actually carries.
///
/// `package_leaves` is every scanned member's leaf name, lowercased, which the scan already
/// collects for component confirmation. Matching on the leaf rather than the full chain is
/// correct here: a DLL shipped anywhere in the package can satisfy the import, because the loader
/// resolves by name.
pub fn external_imports(
    imports: &[super::ImportRef],
    package_leaves: &BTreeSet<String>,
) -> External {
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for i in imports {
        if i.library.is_empty() {
            continue;
        }
        *counts.entry(i.library.as_str()).or_insert(0) += 1;
    }
    let mut modules = Vec::new();
    let mut system_resolved = 0usize;
    for (library, imports) in counts {
        if package_leaves.contains(&library.to_ascii_lowercase()) {
            continue;
        }
        if is_system_module(library) {
            system_resolved += 1;
            continue;
        }
        modules.push(Unresolved {
            library: library.to_string(),
            imports,
        });
    }
    // Most of the module's surface in use first, so the reader starts with the dependency the
    // image leans on hardest rather than one it touches once.
    modules.sort_by(|a, b| b.imports.cmp(&a.imports).then(a.library.cmp(&b.library)));
    External {
        modules,
        system_resolved,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::ImportRef;

    fn imports(pairs: &[(&str, &str)]) -> Vec<ImportRef> {
        pairs
            .iter()
            .map(|(lib, name)| ImportRef {
                library: (*lib).to_string(),
                name: (*name).to_string(),
            })
            .collect()
    }

    fn leaves(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| n.to_ascii_lowercase()).collect()
    }

    #[test]
    fn the_reference_finding_is_reported() {
        // AdobePDFL.dll really does import 25 functions from a libcrypto that ships nowhere.
        let mut v = imports(&[("libcrypto-3-x64.dll", "EVP_aes_256_cbc")]);
        for n in ["RAND_bytes", "EVP_sha256", "EVP_DigestInit_ex"] {
            v.push(ImportRef {
                library: "libcrypto-3-x64.dll".into(),
                name: n.into(),
            });
        }
        let e = external_imports(&v, &leaves(&["adobepdfl.dll", "icudt74.dll"]));
        assert_eq!(e.modules.len(), 1);
        assert_eq!(e.modules[0].library, "libcrypto-3-x64.dll");
        assert_eq!(e.modules[0].imports, 4);
    }

    #[test]
    fn windows_components_are_resolved_and_counted_rather_than_reported() {
        // 169 of 202 imported libraries are absent from the reference package and almost all are
        // these. Reporting them would bury the three that matter under 166 that do not.
        let v = imports(&[
            ("KERNEL32.dll", "CreateFileW"),
            ("api-ms-win-crt-string-l1-1-0.dll", "strcpy_s"),
            ("ext-ms-win-ntuser-dialogbox-l1-1-0.dll", "MessageBoxW"),
            ("d2d1.dll", "D2D1CreateFactory"),
            ("winspool.drv", "OpenPrinterW"),
            ("vcruntime140.dll", "memcpy"),
        ]);
        let e = external_imports(&v, &leaves(&["app.exe"]));
        assert!(e.is_empty(), "{:?}", e.modules);
        assert_eq!(e.system_resolved, 6);
    }

    #[test]
    fn a_module_shipped_anywhere_in_the_package_satisfies_the_import() {
        // The loader resolves by name, so a DLL in a sibling sub-package still satisfies it. The
        // leaf set is deliberately not scoped to the importing image's own directory.
        let v = imports(&[("EditorManagerBridge.dll", "DoThing")]);
        let e = external_imports(&v, &leaves(&["editormanagerbridge.dll"]));
        assert!(e.is_empty());
        assert_eq!(e.system_resolved, 0);
    }

    #[test]
    fn a_library_with_no_attribution_is_skipped() {
        // ELF's flat namespace and the Mach-O symbol-table fallback both yield an empty library,
        // which means attribution was unavailable rather than that the module is missing.
        let v = imports(&[("", "strcpy")]);
        let e = external_imports(&v, &leaves(&["app.exe"]));
        assert!(e.is_empty());
        assert_eq!(e.system_resolved, 0);
    }

    #[test]
    fn the_module_leaning_hardest_on_a_missing_dependency_sorts_first() {
        let mut v = imports(&[("aide.dll", "one")]);
        for n in ["a", "b", "c"] {
            v.push(ImportRef {
                library: "libcrypto-3-x64.dll".into(),
                name: n.into(),
            });
        }
        let e = external_imports(&v, &leaves(&["app.exe"]));
        assert_eq!(e.modules[0].library, "libcrypto-3-x64.dll");
        assert_eq!(e.modules[1].library, "aide.dll");
    }

    #[test]
    fn the_comparison_ignores_case_in_both_directions() {
        // Import tables spell `KERNEL32.dll` and member names arrive however the archive stored
        // them, so a case-sensitive compare would report a shipped DLL as missing.
        let v = imports(&[("MyHelper.DLL", "Go")]);
        let e = external_imports(&v, &leaves(&["myhelper.dll"]));
        assert!(e.is_empty());
    }
}
