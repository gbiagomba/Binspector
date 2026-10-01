//! Format detection by magic bytes.
//!
//! Extension-based detection is what let the original scan fail silently: a
//! `.msixbundle` is an ordinary ZIP, and nothing in the name says so.

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Format {
    Zip,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    SevenZip,
    Cab,
    Pe,
    Elf,
    MachO,
    Unknown,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Zip => "zip",
            Format::Gzip => "gzip",
            Format::Bzip2 => "bzip2",
            Format::Xz => "xz",
            Format::Zstd => "zstd",
            Format::SevenZip => "7z",
            Format::Cab => "cab",
            Format::Pe => "pe",
            Format::Elf => "elf",
            Format::MachO => "macho",
            Format::Unknown => "unknown",
        }
    }

    /// True when this format holds a member list Binspector can enumerate.
    pub fn is_walkable_archive(self) -> bool {
        matches!(self, Format::Zip | Format::SevenZip | Format::Cab)
    }

    /// True when the format wraps exactly one payload, which decompresses to one child.
    pub fn is_single_stream(self) -> bool {
        matches!(
            self,
            Format::Gzip | Format::Bzip2 | Format::Xz | Format::Zstd
        )
    }

    /// True when the format is a container Binspector recognises but cannot open. Kept
    /// so a future format is reported as a coverage gap rather than silently skipped.
    pub fn is_unsupported_archive(self) -> bool {
        false
    }

    /// True when the bytes are an executable image worth scanning directly.
    pub fn is_executable(self) -> bool {
        matches!(self, Format::Pe | Format::Elf | Format::MachO)
    }
}

pub fn detect(data: &[u8]) -> Format {
    if data.len() < 4 {
        return Format::Unknown;
    }
    match &data[..4] {
        // Local file header, empty archive, or spanned archive marker.
        [0x50, 0x4B, 0x03, 0x04] | [0x50, 0x4B, 0x05, 0x06] | [0x50, 0x4B, 0x07, 0x08] => {
            return Format::Zip
        }
        [0x7F, b'E', b'L', b'F'] => return Format::Elf,
        // Mach-O 32/64, both endiannesses, plus the universal binary magic.
        // Thin Mach-O, both widths and both endiannesses.
        [0xFE, 0xED, 0xFA, 0xCE]
        | [0xCE, 0xFA, 0xED, 0xFE]
        | [0xFE, 0xED, 0xFA, 0xCF]
        | [0xCF, 0xFA, 0xED, 0xFE] => return Format::MachO,
        // A universal binary, which needs disambiguating: see `is_fat_macho`.
        [0xCA, 0xFE, 0xBA, 0xBE] | [0xBE, 0xBA, 0xFE, 0xCA] => {
            if is_fat_macho(data) {
                return Format::MachO;
            }
        }
        [0xFD, b'7', b'z', b'X'] => return Format::Xz,
        [b'M', b'S', b'C', b'F'] => return Format::Cab,
        _ => {}
    }
    if data.starts_with(&[0x1F, 0x8B]) {
        return Format::Gzip;
    }
    if data.starts_with(b"BZh") {
        return Format::Bzip2;
    }
    if data.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return Format::SevenZip;
    }
    // zstd frame magic, little endian 0xFD2FB528.
    if data.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Format::Zstd;
    }
    if is_pe(data) {
        return Format::Pe;
    }
    Format::Unknown
}

/// Whether a `CAFEBABE` or `BEBAFECA` header is a Mach-O universal binary.
///
/// `0xCAFEBABE` is also the Java class-file magic, so treating it as Mach-O unconditionally made
/// every `.class` inside a JAR detect as a Mach-O image. The discriminator is the next field:
/// a fat header's `nfat_arch` counts architectures and is small, while a class file's bytes 4..8
/// are its minor and major version pair, and every real class file has a major version of at
/// least 45. So an implausible architecture count means this is not a fat binary.
///
/// `0xBEBAFECA` is `FAT_CIGAM`, the byte-swapped form, which was missing entirely.
fn is_fat_macho(data: &[u8]) -> bool {
    let Some(raw) = data.get(4..8) else {
        return false;
    };
    let bytes = [raw[0], raw[1], raw[2], raw[3]];
    let swapped = data[0] == 0xBE;
    let nfat_arch = if swapped {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    };
    // Apple has never shipped a fat binary with more than a handful of slices, and the lowest
    // Java major version in the wild is 45, so this separates them cleanly with room to spare.
    (1..=16).contains(&nfat_arch)
}

/// A PE starts with `MZ` and carries a `PE\0\0` signature at the e_lfanew offset.
fn is_pe(data: &[u8]) -> bool {
    if !data.starts_with(b"MZ") || data.len() < 0x40 {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    match data.get(e_lfanew..e_lfanew + 4) {
        Some(sig) => sig == b"PE\0\0",
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_java_class_file_is_not_a_mach_o() {
        // The pre-existing bug: CAFEBABE is also the Java class magic, so every .class inside a
        // JAR detected as a Mach-O image. Bytes 4..8 are minor and major version; major 52 is
        // Java 8, and any real class file is at least 45.
        let mut class = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34];
        class.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            detect(&class),
            Format::Unknown,
            "a .class is not an executable image"
        );

        // Java 21 is major 65, still far above the plausible slice count.
        let mut modern = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x41];
        modern.extend_from_slice(&[0u8; 32]);
        assert_eq!(detect(&modern), Format::Unknown);
    }

    #[test]
    fn a_universal_binary_is_still_a_mach_o() {
        // Two slices, which is what a real x86_64 plus arm64 binary carries.
        let mut fat = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02];
        fat.extend_from_slice(&[0u8; 48]);
        assert_eq!(detect(&fat), Format::MachO);
    }

    #[test]
    fn the_byte_swapped_fat_magic_is_recognised() {
        // FAT_CIGAM, which was absent entirely, so a big-endian-host fat binary was invisible.
        let mut fat = vec![0xBE, 0xBA, 0xFE, 0xCA, 0x02, 0x00, 0x00, 0x00];
        fat.extend_from_slice(&[0u8; 48]);
        assert_eq!(detect(&fat), Format::MachO);
    }

    #[test]
    fn a_truncated_fat_header_does_not_panic() {
        assert_eq!(detect(&[0xCA, 0xFE, 0xBA, 0xBE]), Format::Unknown);
        assert_eq!(detect(&[0xCA, 0xFE, 0xBA, 0xBE, 0x00]), Format::Unknown);
    }

    #[test]
    fn detects_zip() {
        // The exact magic from SampleApp_1.0.0_x64.msixbundle.
        assert_eq!(detect(&[0x50, 0x4B, 0x03, 0x04, 0x2D, 0x00]), Format::Zip);
        assert!(Format::Zip.is_walkable_archive());
    }

    #[test]
    fn detects_elf_and_macho() {
        assert_eq!(detect(&[0x7F, b'E', b'L', b'F', 2]), Format::Elf);
        assert_eq!(detect(&[0xCF, 0xFA, 0xED, 0xFE, 0]), Format::MachO);
    }

    #[test]
    fn detects_pe_only_with_valid_signature() {
        let mut pe = vec![0u8; 0x100];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert_eq!(detect(&pe), Format::Pe);

        // MZ without a PE signature is not a PE.
        let mut not_pe = vec![0u8; 0x100];
        not_pe[0] = b'M';
        not_pe[1] = b'Z';
        assert_eq!(detect(&not_pe), Format::Unknown);
    }

    #[test]
    fn detects_compressed_formats() {
        assert_eq!(detect(&[0x1F, 0x8B, 0x08, 0x00]), Format::Gzip);
        assert_eq!(detect(b"BZh91AY"), Format::Bzip2);
        assert_eq!(detect(&[0xFD, b'7', b'z', b'X', b'Z']), Format::Xz);
        assert_eq!(detect(&[0x28, 0xB5, 0x2F, 0xFD, 0x00]), Format::Zstd);
    }

    #[test]
    fn single_stream_and_walkable_are_distinct_categories() {
        for f in [Format::Gzip, Format::Bzip2, Format::Xz, Format::Zstd] {
            assert!(f.is_single_stream(), "{:?}", f);
            assert!(!f.is_walkable_archive(), "{:?}", f);
        }
        for f in [Format::Zip, Format::SevenZip, Format::Cab] {
            assert!(f.is_walkable_archive(), "{:?}", f);
            assert!(!f.is_single_stream(), "{:?}", f);
        }
        // Nothing is an unhandled archive any more.
        for f in [
            Format::Gzip,
            Format::Bzip2,
            Format::Xz,
            Format::Zstd,
            Format::SevenZip,
            Format::Cab,
        ] {
            assert!(!f.is_unsupported_archive(), "{:?}", f);
        }
    }

    #[test]
    fn detects_7z_and_cab() {
        assert_eq!(
            detect(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
            Format::SevenZip
        );
        assert_eq!(detect(b"MSCF\0\0\0\0"), Format::Cab);
    }

    #[test]
    fn short_input_is_unknown() {
        assert_eq!(detect(b""), Format::Unknown);
        assert_eq!(detect(b"MZ"), Format::Unknown);
    }
}
