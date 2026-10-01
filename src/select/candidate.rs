//! Deciding whether one file is worth scanning.
//!
//! Content first, name second. The project's standing position is that extension-based
//! detection was the original defect: `container::detect` reads magic bytes and never looks at
//! a filename, and `repl::Source::detect` distinguishes a JSON report from a SQLite one by
//! content even when the extension says otherwise.
//!
//! The extension allowlist here is therefore a backstop with one job: catching installer
//! formats whose magic `detect` does not parse, so a `.dmg` or an `.msi` is reported as a
//! coverage gap rather than silently skipped. It is not the primary mechanism, and an
//! extensionless Unix executable is picked up by magic alone.

use crate::container::{detect, Format};

/// What to do with a file found during selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    Take(Reason),
    /// Not a candidate. The reason is reported so `-vv` can account for every skip.
    Skip(&'static str),
}

/// Why a file was taken, which the report carries as `selected_by`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reason {
    /// Recognised by content.
    Magic(Format),
    /// Recognised only by extension: a container format the tool cannot open.
    Extension(&'static str),
    /// `--all-files` was given, so nothing was filtered.
    AllFiles,
    /// Named on the command line. Naming a file is an instruction, not a suggestion.
    Explicit,
}

impl Reason {
    /// Stable string for the report, e.g. `magic:pe` or `extension:dmg`.
    pub fn as_label(&self) -> String {
        match self {
            Reason::Magic(f) => format!("magic:{}", f.as_str()),
            Reason::Extension(e) => format!("extension:{}", e),
            Reason::AllFiles => "all-files".to_string(),
            Reason::Explicit => "explicit".to_string(),
        }
    }
}

/// Installer and package formats whose magic `container::detect` does not parse.
///
/// Every entry here earns its place by being a container the tool cannot currently open, so a
/// hit from this list becomes a reported coverage gap rather than a silent omission. Formats
/// already covered by magic (`exe`, `dll`, `so`, `dylib`, `msix`, `jar`, and the rest) are
/// deliberately absent: listing them would imply the extension mattered when it did not.
///
/// `Format::is_unsupported_archive` at `container/detect.rs` is the documented future home for
/// recognising these by content. `detect` is on the walk's hot path and every new variant means
/// touching every match arm plus the coverage schema string, so it is not extended here.
const INSTALLER_EXTENSIONS: &[&str] = &[
    // macOS
    "dmg", "pkg", "mpkg", "kext", // Windows
    "msi", "msp", "msm", "cat", // Linux
    "deb", "rpm", "appimage", "snap", "flatpak", "ko", // Cross-platform images and bundles
    "iso", "img", "wim", "vhd", "vhdx", "apk", "ipa", "xpi", "crx", "vsix", "whl",
];

/// Decide a file's fate from its name, the head of its contents, and its size.
///
/// `head` need only be the first few KiB: `detect` reads at most the first handful of bytes.
pub fn classify(name: &str, head: &[u8], size: u64, all_files: bool) -> Verdict {
    if size == 0 {
        return Verdict::Skip("empty file");
    }
    // `detect` returns Unknown below 4 bytes anyway, and nothing scannable is that small.
    if size < 4 {
        return Verdict::Skip("too small to identify");
    }
    if all_files {
        return Verdict::Take(Reason::AllFiles);
    }

    let format = detect::detect(head);
    // An executable image is the point of the tool. An archive may hold one, and a
    // single-stream wrapper decompresses to one child.
    if format.is_executable() || format.is_walkable_archive() || format.is_single_stream() {
        return Verdict::Take(Reason::Magic(format));
    }

    if let Some(ext) = installer_extension(name) {
        return Verdict::Take(Reason::Extension(ext));
    }

    Verdict::Skip("no executable or archive magic, and not a known installer extension")
}

/// The file's extension if it is in the installer allowlist, matched case-insensitively.
///
/// Returns the canonical lowercase spelling from the list rather than the name's own casing, so
/// `selected_by` reads the same for `Setup.MSI` and `setup.msi`.
fn installer_extension(name: &str) -> Option<&'static str> {
    let ext = name.rsplit_once('.').map(|(_, e)| e)?;
    if ext.is_empty() || ext.len() > 8 {
        return None;
    }
    INSTALLER_EXTENSIONS
        .iter()
        .find(|known| ext.eq_ignore_ascii_case(known))
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe() -> Vec<u8> {
        let mut v = vec![0u8; 0x100];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3C] = 0x80;
        // e_lfanew points past this buffer, so detect's bounds check must reject it; use a
        // layout that actually validates instead.
        v[0x3C] = 0x40;
        v[0x40..0x44].copy_from_slice(b"PE\0\0");
        v
    }

    #[test]
    fn an_executable_is_taken_by_magic_whatever_its_name_is() {
        // The case the extension allowlist cannot handle: no extension at all, which is most
        // Unix executables.
        let v = classify("tool", &pe(), 4096, false);
        assert_eq!(v, Verdict::Take(Reason::Magic(Format::Pe)));

        let elf = b"\x7fELF\x02\x01\x01\x00";
        assert_eq!(
            classify("bin/helper", elf, 4096, false),
            Verdict::Take(Reason::Magic(Format::Elf))
        );

        // And a PE wearing the wrong extension is still a PE.
        assert_eq!(
            classify("notes.txt", &pe(), 4096, false),
            Verdict::Take(Reason::Magic(Format::Pe))
        );
    }

    #[test]
    fn an_archive_is_taken_because_it_may_hold_an_executable() {
        let zip = b"PK\x03\x04\x14\x00\x00\x00";
        assert_eq!(
            classify("bundle.msixbundle", zip, 4096, false),
            Verdict::Take(Reason::Magic(Format::Zip))
        );
        let gz = b"\x1f\x8b\x08\x00\x00\x00\x00\x00";
        assert_eq!(
            classify("payload.gz", gz, 4096, false),
            Verdict::Take(Reason::Magic(Format::Gzip))
        );
    }

    #[test]
    fn an_installer_is_taken_by_extension_so_it_becomes_a_coverage_gap() {
        // A UDIF image has its magic in a trailer, so the head says nothing. Without the
        // allowlist this would be skipped silently, which is the failure being avoided.
        let opaque = b"\x00\x01\x02\x03nothing recognisable here";
        assert_eq!(
            classify("Installer.dmg", opaque, 4096, false),
            Verdict::Take(Reason::Extension("dmg"))
        );
        assert_eq!(
            classify("setup.MSI", opaque, 4096, false),
            Verdict::Take(Reason::Extension("msi")),
            "matching is case-insensitive and reports the canonical spelling"
        );
        assert_eq!(
            classify("pkg.deb", opaque, 4096, false),
            Verdict::Take(Reason::Extension("deb"))
        );
    }

    #[test]
    fn ordinary_files_are_skipped_with_a_reason() {
        for (name, body) in [
            ("README.md", &b"# A readme, which is just text\n"[..]),
            ("icon.png", &b"\x89PNG\r\n\x1a\n"[..]),
            ("config.json", &b"{\"key\": \"value\"}"[..]),
        ] {
            match classify(name, body, 4096, false) {
                Verdict::Skip(reason) => assert!(!reason.is_empty(), "{} needs a reason", name),
                other => panic!("{} should be skipped, got {:?}", name, other),
            }
        }
    }

    #[test]
    fn all_files_overrides_every_filter() {
        let v = classify("README.md", b"# just text", 4096, true);
        assert_eq!(v, Verdict::Take(Reason::AllFiles));
    }

    #[test]
    fn empty_and_tiny_files_are_skipped_before_anything_else() {
        // Even with --all-files: there is nothing in them to scan.
        assert_eq!(classify("x.exe", b"", 0, true), Verdict::Skip("empty file"));
        assert_eq!(
            classify("x.exe", b"MZ", 2, true),
            Verdict::Skip("too small to identify")
        );
    }

    #[test]
    fn a_bare_dot_or_a_long_suffix_is_not_an_extension() {
        assert_eq!(installer_extension("archive."), None);
        assert_eq!(installer_extension("noextension"), None);
        assert_eq!(installer_extension("x.verylongsuffix"), None);
        // A dotfile's name after the dot is not an extension in the sense meant here, but it
        // only matters that it does not match the allowlist.
        assert_eq!(installer_extension(".bashrc"), None);
    }

    #[test]
    fn formats_covered_by_magic_are_not_in_the_extension_list() {
        // Listing them would imply the extension decided it, when content did.
        for covered in [
            "exe", "dll", "so", "dylib", "msix", "appx", "jar", "zip", "cab",
        ] {
            assert!(
                !INSTALLER_EXTENSIONS.contains(&covered),
                "{} is detected by magic and must not be in the allowlist",
                covered
            );
        }
    }

    #[test]
    fn reason_labels_are_stable_strings_for_the_report() {
        assert_eq!(Reason::Magic(Format::Pe).as_label(), "magic:pe");
        assert_eq!(Reason::Extension("dmg").as_label(), "extension:dmg");
        assert_eq!(Reason::AllFiles.as_label(), "all-files");
        assert_eq!(Reason::Explicit.as_label(), "explicit");
    }
}
