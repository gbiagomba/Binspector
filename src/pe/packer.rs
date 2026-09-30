//! Packer and obfuscation heuristics.
//!
//! Each hint states the evidence rather than a verdict, because these signals also
//! appear in legitimately compressed installers and protected commercial software.

use std::collections::BTreeMap;

use super::sections::SectionInfo;

/// Section names that are strong indicators of a specific packer.
const KNOWN: &[(&str, &str)] = &[
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    ("UPX2", "UPX"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    (".themida", "Themida"),
    (".winlice", "WinLicense"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".enigma1", "Enigma"),
    (".enigma2", "Enigma"),
    ("pebundle", "PEBundle"),
    (".petite", "Petite"),
    (".mpress1", "MPRESS"),
    (".mpress2", "MPRESS"),
    (".nsp0", "NsPack"),
    (".taz", "PESpin"),
    ("BitArts", "Crunch"),
    (".packed", "generic packer"),
];

/// Evidence-based hints. An empty result means nothing stood out.
///
/// `is_managed` suppresses import-table heuristics: a pure .NET assembly legitimately
/// has no native import directory, so flagging its absence would fire on most of a
/// managed application rather than on anything unusual.
pub fn hints(sections: &[SectionInfo], import_count: usize, is_managed: bool) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    // A resource-only DLL carries no code, so having no imports is expected.
    let has_code = sections.iter().any(|s| s.executable || s.contains_code);

    // Group by packer so UPX0 plus UPX1 reads as one finding naming both sections,
    // rather than the same packer reported twice.
    let mut by_packer: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for s in sections {
        for (needle, packer) in KNOWN {
            if s.name.eq_ignore_ascii_case(needle) {
                by_packer.entry(packer).or_default().push(s.name.as_str());
            }
        }
    }
    for (packer, names) in by_packer {
        out.push(format!(
            "section{} {} match{} {}",
            if names.len() == 1 { "" } else { "s" },
            names
                .iter()
                .map(|n| format!("`{}`", n))
                .collect::<Vec<_>>()
                .join(", "),
            if names.len() == 1 { "es" } else { "" },
            packer
        ));
    }

    for s in sections {
        if s.is_write_execute() {
            out.push(format!(
                "section `{}` is writable and executable ({})",
                s.name,
                s.permissions()
            ));
        }
        // `.rsrc` holds icons, images, and manifests, which are already compressed,
        // so high entropy there is the norm rather than a packing signal. Code and
        // data sections are still checked.
        if s.is_high_entropy() && s.raw_size > 4096 && !s.name.eq_ignore_ascii_case(".rsrc") {
            out.push(format!(
                "section `{}` entropy {:.2} of 8.00 suggests compressed or encrypted content",
                s.name, s.entropy
            ));
        }
        if s.is_virtual_only() && s.virtual_size > 4096 {
            out.push(format!(
                "section `{}` has no raw data but {} virtual bytes, typical of an unpacking stub",
                s.name, s.virtual_size
            ));
        }
    }

    // A real native application imports far more than a handful of functions. A tiny
    // import table alongside a large high-entropy section is the classic packed layout.
    // Managed assemblies are exempt: the CLR resolves their dependencies.
    if !is_managed && import_count > 0 && import_count < 10 {
        let big_entropy = sections
            .iter()
            .any(|s| s.is_high_entropy() && s.raw_size > 64 * 1024);
        if big_entropy {
            out.push(format!(
                "only {} imports alongside a large high-entropy section, which is typical of a \
                 packed executable resolving its imports at runtime",
                import_count
            ));
        }
    }
    if !is_managed && has_code && import_count == 0 && !sections.is_empty() {
        out.push("no import table at all, so imports are resolved dynamically".to_string());
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sect(name: &str, entropy: f64, w: bool, x: bool, raw: u32, virt: u32) -> SectionInfo {
        SectionInfo {
            name: name.into(),
            virtual_size: virt,
            raw_size: raw,
            entropy,
            readable: true,
            writable: w,
            executable: x,
            contains_code: x,
        }
    }

    #[test]
    fn detects_upx_by_section_name() {
        let h = hints(
            &[sect("UPX1", 7.9, false, true, 100_000, 100_000)],
            50,
            false,
        );
        assert!(h.iter().any(|s| s.contains("matches UPX")), "{:?}", h);
        assert!(h.iter().any(|s| s.contains("`UPX1`")));
    }

    #[test]
    fn detects_vmprotect_and_themida() {
        assert!(
            hints(&[sect(".vmp0", 5.0, false, true, 100, 100)], 50, false)
                .iter()
                .any(|s| s.contains("VMProtect"))
        );
        assert!(
            hints(&[sect(".themida", 5.0, false, true, 100, 100)], 50, false)
                .iter()
                .any(|s| s.contains("Themida"))
        );
    }

    #[test]
    fn flags_write_execute_section() {
        let h = hints(&[sect(".text", 6.0, true, true, 4096, 4096)], 50, false);
        assert!(
            h.iter().any(|s| s.contains("writable and executable")),
            "{:?}",
            h
        );
    }

    #[test]
    fn flags_high_entropy_only_when_section_is_substantial() {
        let big = hints(
            &[sect(".data", 7.8, false, false, 100_000, 100_000)],
            50,
            false,
        );
        assert!(big.iter().any(|s| s.contains("entropy")));
        // A tiny high-entropy section is ordinary, for example an embedded certificate.
        let small = hints(&[sect(".rsrc", 7.9, false, false, 512, 512)], 50, false);
        assert!(!small.iter().any(|s| s.contains("entropy")));
    }

    #[test]
    fn flags_small_import_table_with_large_packed_section() {
        let h = hints(
            &[sect(".data", 7.9, false, false, 200_000, 200_000)],
            3,
            false,
        );
        assert!(h.iter().any(|s| s.contains("only 3 imports")), "{:?}", h);
    }

    #[test]
    fn managed_assemblies_are_exempt_from_import_table_heuristics() {
        let sections = vec![sect(".text", 6.0, false, true, 4096, 4096)];
        // A pure .NET assembly with no native imports is ordinary, not suspicious.
        assert!(hints(&sections, 0, true).is_empty());
        assert!(hints(&sections, 0, false)
            .iter()
            .any(|s| s.contains("no import table")));
        // The packed-layout heuristic is likewise suppressed.
        let packed = vec![sect(".data", 7.9, false, false, 200_000, 200_000)];
        assert!(!hints(&packed, 3, true)
            .iter()
            .any(|s| s.contains("only 3 imports")));
    }

    #[test]
    fn flags_absent_import_table_only_when_the_image_has_code() {
        let with_code = hints(&[sect(".text", 6.0, false, true, 4096, 4096)], 0, false);
        assert!(with_code.iter().any(|s| s.contains("no import table")));
        // A resource-only DLL has no code, so no imports is expected.
        let resource_only = hints(&[sect(".rsrc", 5.0, false, false, 4096, 4096)], 0, false);
        assert!(!resource_only.iter().any(|s| s.contains("no import table")));
    }

    #[test]
    fn rsrc_high_entropy_is_not_a_packing_signal() {
        // Compressed icons and images make .rsrc high entropy in ordinary binaries.
        let rsrc = hints(
            &[sect(".rsrc", 7.99, false, false, 500_000, 500_000)],
            50,
            false,
        );
        assert!(!rsrc.iter().any(|s| s.contains("entropy")), "{:?}", rsrc);
        // The same entropy in a code section still counts.
        let text = hints(
            &[sect(".text", 7.99, false, true, 500_000, 500_000)],
            50,
            false,
        );
        assert!(text.iter().any(|s| s.contains("entropy")));
    }

    #[test]
    fn ordinary_binary_produces_no_hints() {
        let sections = vec![
            sect(".text", 6.2, false, true, 100_000, 100_000),
            sect(".rdata", 5.1, false, false, 40_000, 40_000),
            sect(".data", 3.0, true, false, 8_000, 8_000),
        ];
        assert!(hints(&sections, 420, false).is_empty());
    }

    #[test]
    fn packer_name_is_not_duplicated_across_sections() {
        let sections = vec![
            sect("UPX0", 0.0, true, true, 0, 4096),
            sect("UPX1", 7.9, false, true, 100_000, 100_000),
        ];
        let h = hints(&sections, 5, false);
        // One packer-identification hint, naming both of its sections. Other hints
        // also mention the section names, so match on the packer phrase itself.
        let upx: Vec<&String> = h.iter().filter(|s| s.contains("match UPX")).collect();
        assert_eq!(upx.len(), 1, "{:?}", h);
        assert!(
            upx[0].contains("`UPX0`") && upx[0].contains("`UPX1`"),
            "{}",
            upx[0]
        );
    }
}
