//! Signature-based carving of embedded data, via the binwalk library.
//!
//! Behind the `carve` cargo feature, which is **on** by default since 4.4.0. The runtime flag
//! `--carve` is what is off by default, because signature scanning every member costs time a
//! default scan should not spend.
//!
//! Carving answers a different question from unpacking. The unpackers above open a
//! container that declares its own member list. Carving scans for format signatures
//! anywhere in a blob, which finds a payload appended to an executable, embedded in a
//! resource, or sitting in a firmware image with no directory at all.
//!
//! It is off by default for two reasons. Signature scanning produces false positives on
//! ordinary compressed data, and the ZIP family plus the single-stream and archive
//! formats already cover every container in a normal application bundle. Carving earns
//! its cost on firmware and on samples where something is deliberately hidden.

use serde::{Deserialize, Serialize};

use super::limits::Budget;

/// What a carved signature actually represents.
///
/// Raw binwalk output on an ordinary application is dominated by markers that are not
/// embedded files at all. On the reference sample it reported 2,348 signatures, of which
/// the overwhelming majority were `copyright` strings and `pkcs_der_hash` markers. Those
/// say nothing about something being packed inside, so they are counted rather than
/// listed, and containers lead the report.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    /// An archive or filesystem embedded in the blob. The reason carving exists.
    Container,
    /// An embedded executable or media file.
    Embedded,
    /// A signature Binspector does not classify. Listed, so a format added to binwalk
    /// later is never silently dropped.
    Other,
}

/// Archives and filesystems: something is packed inside.
const CONTAINERS: &[&str] = &[
    "7zip",
    "apfs",
    "arj",
    "btrfs",
    "bzip2",
    "cab",
    "compressd",
    "cpio",
    "cramfs",
    "dahua_zip",
    "deb",
    "dmg",
    "ext",
    "fat",
    "gzip",
    "iso9660",
    "jffs2",
    "logfs",
    "lz4",
    "lzfse",
    "lzma",
    "lzop",
    "ntfs",
    "qcow",
    "rar",
    "romfs",
    "squashfs",
    "tarball",
    "ubi",
    "ubifs",
    "xz",
    "yaffs",
    "zip",
    "zlib",
    "zstd",
    "android_sparse",
    "uefi_capsule",
    "uefi_pi_volume",
];

/// Embedded executables and media.
const EMBEDDED: &[&str] = &[
    "bmp",
    "dxbc",
    "elf",
    "gif",
    "jpeg",
    "linux_kernel",
    "pdf",
    "pe",
    "png",
    "riff",
    "svg",
    "uimage",
    "vxworks_symtab",
    "wince",
    "wind_kernel",
];

/// Markers that are not embedded files: checksums, certificates, key material, text, and
/// binwalk's own internal and test signatures.
const METADATA: &[&str] = &[
    "accepting",
    "aes_acceleration_table",
    "aes_forward_table",
    "aes_rcon",
    "aes_reverse_table",
    "aes_sbox",
    "copyright",
    "crc32",
    "declining",
    "dpapi",
    "exact_len",
    "foobar",
    "gpg_signed",
    "inner",
    "low_confidence",
    "md5",
    "openssl",
    "outer",
    "oversized_full_search",
    "oversized_short",
    "pem_certificate",
    "pem_private_key",
    "pem_public_key",
    "pjl",
    "pkcs_der_hash",
    "rejecting",
    "retry_test",
    "rsa",
    "sha256",
    "sized",
    "srecord",
    "srecord_generic",
    "trailing_zeros",
    "unknown_size",
    "valid",
];

/// Validate a ZIP local file header at `offset`.
///
/// binwalk's ZIP signature is a bare four-byte magic, and `PK\x03\x04` collides readily
/// inside a large binary. On the reference sample it matched at offset 0x1d6c924 in a
/// 36 MB DLL, where the header fields turned out to be text: version 0, a zero-length
/// member name, an extra field of 22,635 bytes, and an uncompressed size of 0 against a
/// compressed size of 25,968. Checking the fields costs nothing and removes the whole
/// class of match.
pub fn plausible_zip_header(data: &[u8], offset: usize) -> bool {
    let h = match data.get(offset..offset + 30) {
        Some(h) => h,
        None => return false,
    };
    let u16at = |i: usize| u16::from_le_bytes([h[i], h[i + 1]]);
    let u32at = |i: usize| u32::from_le_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]);

    // Version needed to extract: real writers emit 10 through 63. Zero is never valid.
    let version = u16at(4);
    if version == 0 || version > 63 {
        return false;
    }
    // Only store and deflate are common; the rest are rare but legal.
    let method = u16at(8);
    if !matches!(method, 0 | 8 | 9 | 12 | 14 | 93 | 95 | 96 | 98) {
        return false;
    }
    // A member must have a name, and neither name nor extra field is ever huge.
    let name_len = u16at(26) as usize;
    let extra_len = u16at(28) as usize;
    if name_len == 0 || name_len > 512 || extra_len > 4096 {
        return false;
    }
    // A stored member's compressed and uncompressed sizes must agree. A zero
    // uncompressed size alongside a nonzero compressed size is contradictory unless the
    // sizes are deferred to the data descriptor, which sets bit 3 of the flags.
    let flags = u16at(6);
    let csize = u32at(18);
    let usize_ = u32at(22);
    let deferred = flags & 0x08 != 0;
    if !deferred {
        if method == 0 && csize != usize_ {
            return false;
        }
        if usize_ == 0 && csize != 0 {
            return false;
        }
    }
    // The name must actually be present and look like a path.
    match data.get(offset + 30..offset + 30 + name_len) {
        Some(name) => name
            .iter()
            .all(|&b| b >= 0x20 && b != 0x7F || b == b'/' || b == b'\\'),
        None => false,
    }
}

pub fn classify(signature: &str) -> Option<Class> {
    let s = signature.to_ascii_lowercase();
    if METADATA.contains(&s.as_str()) {
        return None;
    }
    if CONTAINERS.contains(&s.as_str()) {
        return Some(Class::Container);
    }
    if EMBEDDED.contains(&s.as_str()) {
        return Some(Class::Embedded);
    }
    Some(Class::Other)
}

/// One thing carving found inside a blob.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CarvedItem {
    /// Signature name as binwalk reports it, for example `gzip` or `squashfs`.
    pub signature: String,
    pub description: String,
    pub offset: u64,
    pub size: u64,
    pub class: Class,
    /// Whether binwalk considers the match confident rather than speculative.
    pub confident: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CarveReport {
    pub items: Vec<CarvedItem>,
    /// Checksums, certificates, and text markers. Counted, not listed.
    pub metadata_markers: usize,
    /// Signatures binwalk flagged as low confidence, counted but not listed.
    pub speculative: usize,
}

impl CarveReport {
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Embedded archives and filesystems, which is the number worth acting on.
    pub fn container_count(&self) -> usize {
        self.items
            .iter()
            .filter(|i| i.class == Class::Container)
            .count()
    }
}

/// Scan `data` for embedded file signatures.
///
/// Only matches that begin past offset zero are reported: a signature at the very start
/// is simply the file's own format, which detection already handled, and reporting it
/// would restate what the walk knows.
#[cfg(feature = "carve")]
pub fn scan(data: &[u8], at: &str, budget: &mut Budget, max_items: usize) -> CarveReport {
    let binwalker = binwalk_ng::Binwalk::new();
    let results = binwalker.scan(data);

    let mut items = Vec::new();
    let mut speculative = 0usize;
    let mut metadata_markers = 0usize;
    for r in results {
        if r.offset == 0 {
            continue;
        }
        if r.confidence < binwalk_ng::signatures::CONFIDENCE_MEDIUM {
            speculative += 1;
            continue;
        }
        let class = match classify(&r.name) {
            Some(c) => c,
            None => {
                metadata_markers += 1;
                continue;
            }
        };
        // A bare magic match is a lead, not a fact. Verify the formats whose signature
        // is short enough to collide.
        if r.name.eq_ignore_ascii_case("zip") && !plausible_zip_header(data, r.offset) {
            speculative += 1;
            continue;
        }
        if items.len() >= max_items {
            break;
        }
        items.push(CarvedItem {
            signature: r.name.clone(),
            description: r.description.clone(),
            offset: r.offset as u64,
            size: r.size as u64,
            class,
            confident: r.confidence >= binwalk_ng::signatures::CONFIDENCE_HIGH,
        });
    }
    // Containers first: an embedded archive matters more than an embedded icon.
    items.sort_by(|a, b| a.class.cmp(&b.class).then(a.offset.cmp(&b.offset)));

    let containers = items.iter().filter(|i| i.class == Class::Container).count();
    if containers > 0 {
        budget.warn(format!(
            "{}: carving found {} candidate embedded archive(s) or filesystem(s) past offset \
             0; a signature match is a lead, so extract with `binwalk -e` to confirm and scan \
             the contents",
            at, containers
        ));
    }
    CarveReport {
        items,
        metadata_markers,
        speculative,
    }
}

/// Carving is unavailable in this build.
#[cfg(not(feature = "carve"))]
pub fn scan(_data: &[u8], _at: &str, _budget: &mut Budget, _max_items: usize) -> CarveReport {
    CarveReport::default()
}

/// Whether this build can carve, so the report can say so rather than implying a clean
/// result.
pub const fn available() -> bool {
    cfg!(feature = "carve")
}

/// Message for a user who asked for carving from a build without it.
pub fn unavailable_message() -> &'static str {
    "this build has no carving support. Rebuild with --features carve to scan for embedded \
     file signatures."
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::limits::Limits;

    fn budget() -> Budget {
        Budget::new(Limits::default(), 1000)
    }

    #[test]
    fn availability_matches_the_feature() {
        assert_eq!(available(), cfg!(feature = "carve"));
    }

    #[test]
    fn unavailable_message_names_the_feature_flag() {
        assert!(unavailable_message().contains("--features carve"));
    }

    #[test]
    fn empty_report_is_empty() {
        assert!(CarveReport::default().is_empty());
        assert_eq!(CarveReport::default().container_count(), 0);
    }

    #[test]
    fn archives_and_filesystems_classify_as_containers() {
        for sig in [
            "gzip", "zip", "squashfs", "cpio", "7zip", "xz", "tarball", "ubifs",
        ] {
            assert_eq!(classify(sig), Some(Class::Container), "signature {}", sig);
        }
    }

    #[test]
    fn executables_and_media_classify_as_embedded() {
        for sig in ["pe", "elf", "png", "jpeg", "pdf"] {
            assert_eq!(classify(sig), Some(Class::Embedded), "signature {}", sig);
        }
    }

    /// The two signatures that dominated raw output on the reference sample.
    #[test]
    fn metadata_markers_are_excluded() {
        for sig in [
            "copyright",
            "pkcs_der_hash",
            "crc32",
            "md5",
            "sha256",
            "aes_sbox",
            "pem_certificate",
            "trailing_zeros",
        ] {
            assert_eq!(classify(sig), None, "signature {}", sig);
        }
    }

    #[test]
    fn classification_is_case_insensitive() {
        assert_eq!(classify("GZIP"), Some(Class::Container));
        assert_eq!(classify("Copyright"), None);
    }

    #[test]
    fn an_unrecognised_signature_is_still_listed() {
        // A format added to binwalk later must surface rather than vanish.
        assert_eq!(classify("some_new_firmware_format"), Some(Class::Other));
    }

    /// Built from the real false positive at offset 0x1d6c924 on the reference sample.
    #[test]
    fn rejects_the_zip_magic_collision_seen_in_the_wild() {
        let mut blob = vec![0u8; 64];
        blob[0..4].copy_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
        // version 0, name length 0, extra length 22635, uncompressed 0 vs compressed 25968.
        blob[4..6].copy_from_slice(&0u16.to_le_bytes());
        blob[8..10].copy_from_slice(&0u16.to_le_bytes());
        blob[18..22].copy_from_slice(&25_968u32.to_le_bytes());
        blob[22..26].copy_from_slice(&0u32.to_le_bytes());
        blob[26..28].copy_from_slice(&0u16.to_le_bytes());
        blob[28..30].copy_from_slice(&22_635u16.to_le_bytes());
        assert!(!plausible_zip_header(&blob, 0));
    }

    #[test]
    fn accepts_a_real_zip_local_file_header() {
        use std::io::Write;
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            w.start_file("member.txt", zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(b"contents").unwrap();
            w.finish().unwrap();
        }
        assert!(plausible_zip_header(&buf, 0));
        // And at a nonzero offset, which is how carving finds it.
        let mut appended = vec![0u8; 512];
        appended.extend_from_slice(&buf);
        assert!(plausible_zip_header(&appended, 512));
    }

    #[test]
    fn zip_validator_rejects_nonsense_fields() {
        let mut blob = vec![0u8; 64];
        blob[0..4].copy_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
        blob[4..6].copy_from_slice(&20u16.to_le_bytes());
        blob[8..10].copy_from_slice(&8u16.to_le_bytes());
        blob[26..28].copy_from_slice(&10u16.to_le_bytes());
        blob[28..30].copy_from_slice(&0u16.to_le_bytes());
        blob[30..40].copy_from_slice(b"member.txt");
        blob[18..22].copy_from_slice(&100u32.to_le_bytes());
        blob[22..26].copy_from_slice(&200u32.to_le_bytes());
        assert!(
            plausible_zip_header(&blob, 0),
            "a valid deflate header was rejected"
        );

        // An unknown compression method is not plausible.
        blob[8..10].copy_from_slice(&777u16.to_le_bytes());
        assert!(!plausible_zip_header(&blob, 0));
    }

    #[test]
    fn zip_validator_is_bounds_safe() {
        assert!(!plausible_zip_header(&[0x50, 0x4B, 0x03, 0x04], 0));
        assert!(!plausible_zip_header(&[], 0));
        assert!(!plausible_zip_header(&[0u8; 100], 90));
    }

    #[test]
    fn containers_sort_ahead_of_embedded_and_other() {
        let mut v = vec![Class::Other, Class::Embedded, Class::Container];
        v.sort();
        assert_eq!(v, vec![Class::Container, Class::Embedded, Class::Other]);
    }

    #[cfg(not(feature = "carve"))]
    #[test]
    fn without_the_feature_scanning_reports_nothing() {
        let mut b = budget();
        let r = scan(b"anything at all", "t", &mut b, 100);
        assert!(r.is_empty());
        assert!(b.warnings().is_empty());
    }

    #[cfg(feature = "carve")]
    #[test]
    fn finds_a_gzip_stream_appended_to_another_file() {
        use std::io::Write;
        // A PE-ish header followed by a real gzip stream, which is exactly the
        // appended-payload shape carving exists to catch.
        let mut blob = vec![0u8; 0x400];
        blob[0] = b'M';
        blob[1] = b'Z';
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"hidden payload with strcpy inside").unwrap();
        blob.extend_from_slice(&e.finish().unwrap());

        let mut b = budget();
        let r = scan(&blob, "t", &mut b, 100);
        assert!(
            r.items
                .iter()
                .any(|i| i.signature.contains("gzip") && i.offset >= 0x400),
            "items: {:?}",
            r.items
        );
        assert!(b.warnings().iter().any(|w| w.contains("carving found")));
    }

    #[cfg(feature = "carve")]
    #[test]
    fn a_signature_at_offset_zero_is_not_reported() {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"plain gzip file").unwrap();
        let gz = e.finish().unwrap();
        let mut b = budget();
        let r = scan(&gz, "t", &mut b, 100);
        // The file's own format is detection's job, not carving's.
        assert!(r.items.iter().all(|i| i.offset > 0), "items: {:?}", r.items);
    }

    #[cfg(feature = "carve")]
    #[test]
    fn honors_the_item_cap() {
        use std::io::Write;
        let mut blob = vec![0u8; 64];
        for _ in 0..20 {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(b"payload").unwrap();
            blob.extend_from_slice(&e.finish().unwrap());
        }
        let mut b = budget();
        assert!(scan(&blob, "t", &mut b, 3).items.len() <= 3);
    }
}
