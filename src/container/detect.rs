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
            Format::SevenZip => "7z",
            Format::Cab => "cab",
            Format::Pe => "pe",
            Format::Elf => "elf",
            Format::MachO => "macho",
            Format::Unknown => "unknown",
        }
    }

    /// True when this format is a container Binspector can descend into.
    pub fn is_walkable_archive(self) -> bool {
        matches!(self, Format::Zip)
    }

    /// True when the format is an archive Binspector recognises but cannot open yet.
    /// These are reported so a reviewer knows coverage was incomplete.
    pub fn is_unsupported_archive(self) -> bool {
        matches!(
            self,
            Format::Gzip | Format::Bzip2 | Format::Xz | Format::SevenZip | Format::Cab
        )
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
        [0xFE, 0xED, 0xFA, 0xCE]
        | [0xCE, 0xFA, 0xED, 0xFE]
        | [0xFE, 0xED, 0xFA, 0xCF]
        | [0xCF, 0xFA, 0xED, 0xFE]
        | [0xCA, 0xFE, 0xBA, 0xBE] => return Format::MachO,
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
    if is_pe(data) {
        return Format::Pe;
    }
    Format::Unknown
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
        assert!(Format::Gzip.is_unsupported_archive());
    }

    #[test]
    fn short_input_is_unknown() {
        assert_eq!(detect(b""), Format::Unknown);
        assert_eq!(detect(b"MZ"), Format::Unknown);
    }
}
