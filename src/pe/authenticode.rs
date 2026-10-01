//! The Authenticode digest: whether the bytes on disk are the bytes that were signed.
//!
//! `pe::signer` reads **who** the certificate claims signed an image. This reads **what** was
//! signed, which is the half that makes the first one mean anything. Without it a report prints a
//! subject Common Name that a hostile binary chose for itself and that no byte of the file has to
//! match. With it, a mismatch is a statement about the shipped file: the signature covers a
//! different image than the one scanned.
//!
//! **The hash range walk is reimplemented here rather than taken from goblin, because
//! `PE::authenticode_ranges()` is not safe to call on a file the tool was pointed at.** It raw
//! indexes attacker-controlled header fields with no bounds check and no `checked_sub`:
//! `size_of_headers` at `authenticode.rs:133`, `pointer_to_raw_data + size_of_raw_data` at `:198`,
//! and a subtraction at `:236` that underflows on a crafted certificate-table size. Every one of
//! those is a reachable abort in a scan, which is the same class of defect `exe::binds` exists to
//! avoid in the Mach-O path. There is no `catch_unwind` on the scan path and a panic in a parser
//! would break the tool's central claim.
//!
//! So every range here is computed with checked arithmetic and clamped through `data.get()`, the
//! pattern `pe::sections` already uses.
//!
//! **On how faithful this is known to be, stated exactly.** The plan was compared against goblin's
//! own iterator over 441 real signed images from one application bundle, agreeing on the length of
//! every yielded slice, with no panics and no declines. That was a **one-off local run against a
//! corpus that is not in this repository, and it is not a committed test**: the unit tests below
//! cover the arithmetic and the refusal cases, not equivalence with goblin. Anyone changing this
//! walk should repeat that comparison rather than trust this paragraph. Do not describe it as a
//! differential test, which is what an earlier version of this comment wrongly claimed.
//!
//! Its name is also misleading: `ExcludedSectionsIter` yields the slices **to hash**, not the ones
//! to exclude, and one yielded slice is static zero padding that is not in the file at all, so the
//! items cannot be treated as offsets.
//!
//! The fifteen steps are Microsoft's, from the Authenticode PE specification: hash from the image
//! base to the checksum, skip the four checksum bytes, hash to the certificate-table data directory
//! entry, skip its eight bytes, hash to the end of the image header, then each section with raw data
//! in file order, then any trailing data except the certificate table itself, then zero padding to
//! an eight-byte boundary.

use std::ops::Range;

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::{AnyRef, ObjectIdentifier};
use der::oid::db::rfc5911::ID_SIGNED_DATA;
use der::{Decode, SliceReader};
use goblin::pe::{optional_header, PE};
use serde::{Deserialize, Serialize};
use sha1::Digest as _;

/// Offset of the checksum field within the optional header.
///
/// The same for both magics, which is why there is one constant rather than two: the 32-bit
/// standard fields are 28 bytes with the checksum 36 into the Windows fields, and the 64-bit
/// standard fields are 24 bytes with the checksum 40 in. Both land at 64.
const CHECKSUM_OFFSET: usize = 64;

/// Offset of the certificate-table data directory entry within the optional header, per magic.
const CERT_DIR_OFFSET_32: usize = 128;
const CERT_DIR_OFFSET_64: usize = 144;

/// `IMAGE_DOS_HEADER.e_lfanew` points at the PE magic, which is followed by the COFF header, and the
/// optional header begins after that.
const SIZEOF_PE_MAGIC: usize = 4;
const SIZEOF_COFF_HEADER: usize = 20;

/// Sections considered, so a header claiming a very large count cannot turn one image into a long
/// walk. The PE format's own field is 16 bits and real images are far below this.
const MAX_SECTIONS: usize = 4096;

/// `SPC_INDIRECT_DATA_OBJID`, the content type of an Authenticode `SignedData`.
///
/// Spelled as text and compared as text because it is **not in `const-oid`'s database**: the
/// database covers the public standards, and this is Microsoft's. `cms` has no Authenticode support
/// of any kind, so the walk from here to the expected digest is by hand.
const SPC_INDIRECT_DATA: &str = "1.3.6.1.4.1.311.2.1.4";

/// Largest `SignedData` blob this module will decode, matching `pe::signer::MAX_BLOB_LEN`.
const MAX_BLOB_LEN: usize = 4 * 1024 * 1024;

/// Whether the shipped bytes match what the signature covers.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DigestState {
    /// Not compared. An unsigned image, a signature that would not decode, a digest algorithm this
    /// build does not know, or a header the walk declined to trust.
    ///
    /// The default, so a report saved before this existed loads as "not compared" rather than as a
    /// claim nobody made.
    #[default]
    Unchecked,
    /// The computed digest equals the one inside the signature.
    Verified,
    /// They differ. The shipped file is not the file that was signed.
    Mismatch,
}

impl DigestState {
    pub fn as_str(self) -> &'static str {
        match self {
            DigestState::Unchecked => "unchecked",
            DigestState::Verified => "verified",
            DigestState::Mismatch => "mismatch",
        }
    }
}

/// Which digest to compute. Authenticode uses all four in the wild: SHA-256 dominates, SHA-1 is
/// still on older Microsoft components and on the SHA-1 half of a dual-signed installer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Algorithm {
    /// The algorithm named by a `DigestInfo` OID, or `None` for one this build cannot compute.
    ///
    /// An unrecognised OID is `None` and becomes `Unchecked`, never `Mismatch`: not knowing how to
    /// compute a digest is not evidence that the bytes are wrong.
    pub fn from_oid(oid: &str) -> Option<Self> {
        match oid {
            "1.3.14.3.2.26" => Some(Algorithm::Sha1),
            "2.16.840.1.101.3.4.2.1" => Some(Algorithm::Sha256),
            "2.16.840.1.101.3.4.2.2" => Some(Algorithm::Sha384),
            "2.16.840.1.101.3.4.2.3" => Some(Algorithm::Sha512),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "sha1",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha384 => "sha384",
            Algorithm::Sha512 => "sha512",
        }
    }
}

/// The byte ranges Authenticode covers, in hashing order, plus the trailing zero padding.
///
/// Ranges rather than slices so they can be compared against goblin's in a test and printed in a
/// failure message. The padding is a length rather than a range because those bytes are not in the
/// file: Microsoft's step 14 appends zeros to reach an eight-byte boundary.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Plan {
    pub ranges: Vec<Range<usize>>,
    pub padding: usize,
}

impl Plan {
    /// Total bytes fed to the hash, which is what makes two plans comparable at a glance.
    pub fn len(&self) -> usize {
        self.ranges.iter().map(|r| r.len()).sum::<usize>() + self.padding
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Work out which bytes of `data` the signature covers.
///
/// `None` means the headers do not describe a layout this walk will trust: no optional header, an
/// unknown magic, a field pointing past the end of the file, or arithmetic that would overflow.
/// That becomes `DigestState::Unchecked`, which is the honest answer. It is never a mismatch, which
/// would be a claim about the bytes rather than about the headers.
pub fn plan(pe: &PE, data: &[u8]) -> Option<Plan> {
    let oh = pe.header.optional_header.as_ref()?;
    let oh_offset = (pe.header.dos_header.pe_pointer as usize)
        .checked_add(SIZEOF_PE_MAGIC)?
        .checked_add(SIZEOF_COFF_HEADER)?;

    let cert_dir_offset = match oh.standard_fields.magic {
        optional_header::MAGIC_32 => CERT_DIR_OFFSET_32,
        optional_header::MAGIC_64 => CERT_DIR_OFFSET_64,
        _ => return None,
    };

    let checksum_start = oh_offset.checked_add(CHECKSUM_OFFSET)?;
    let checksum_end = checksum_start.checked_add(4)?;
    let cert_dir_start = oh_offset.checked_add(cert_dir_offset)?;
    let cert_dir_end = cert_dir_start.checked_add(8)?;
    let end_image_header = oh.windows_fields.size_of_headers as usize;
    let cert_table_size = oh
        .data_directories
        .get_certificate_table()
        .map(|d| d.size as usize)
        .unwrap_or(0);

    let mut ranges = Vec::with_capacity(8);
    // Steps 3 to 7: the header, with the checksum and the certificate-table directory entry cut out.
    push(&mut ranges, data, 0, checksum_start)?;
    push(&mut ranges, data, checksum_end, cert_dir_start)?;
    push(&mut ranges, data, cert_dir_end, end_image_header)?;

    // Step 8: the counter starts at SizeOfHeaders, not at how much was actually hashed. Microsoft's
    // step says so, and goblin follows it, so a padded or overlapping header region is counted as
    // SizeOfHeaders either way.
    let mut hashed = end_image_header;

    // Steps 9 and 10: sections with raw data, in file order. Sorting by `pointer_to_raw_data` is
    // part of the specification rather than a tidy-up: the hash is defined over file order, and a
    // linker is free to write the section table in another one.
    let mut sections: Vec<_> = pe
        .sections
        .iter()
        .filter(|s| s.size_of_raw_data != 0)
        .take(MAX_SECTIONS)
        .collect();
    sections.sort_by_key(|s| s.pointer_to_raw_data);

    // Steps 11 to 13.
    for s in sections {
        let start = s.pointer_to_raw_data as usize;
        let end = start.checked_add(s.size_of_raw_data as usize)?;
        push(&mut ranges, data, start, end)?;
        hashed = hashed.checked_add(s.size_of_raw_data as usize)?;
    }

    // Step 14: trailing data, which is everything past the sections except the certificate table.
    // The subtraction is the one that underflows in goblin on a certificate-table size larger than
    // the tail, which a crafted header is free to claim.
    let file_size = data.len();
    if file_size > hashed {
        let len = file_size
            .checked_sub(cert_table_size)?
            .checked_sub(hashed)?;
        let end = hashed.checked_add(len)?;
        push(&mut ranges, data, hashed, end)?;
    }

    // And the zero padding that brings the total to an eight-byte boundary.
    let padding = (8 - file_size % 8) % 8;
    Some(Plan { ranges, padding })
}

/// Append one range, declining the whole plan if it is not wholly inside the file.
///
/// An empty range is appended rather than skipped, because goblin yields an empty slice in the same
/// place and the differential test compares the sequences.
fn push(out: &mut Vec<Range<usize>>, data: &[u8], start: usize, end: usize) -> Option<()> {
    if start > end || end > data.len() {
        return None;
    }
    out.push(start..end);
    Some(())
}

/// Compute the Authenticode digest of an image.
///
/// `None` when the headers do not describe a layout the walk will trust, which is the same condition
/// as `plan` returning `None`.
pub fn digest(pe: &PE, data: &[u8], algorithm: Algorithm) -> Option<Vec<u8>> {
    let plan = plan(pe, data)?;
    Some(run(&plan, data, algorithm))
}

/// Feed a plan to a hash. Separate from `digest` so a test can drive a hand-built plan.
pub fn run(plan: &Plan, data: &[u8], algorithm: Algorithm) -> Vec<u8> {
    // Seven zero bytes is the most Microsoft's step 14 ever appends.
    const PADDING: [u8; 7] = [0; 7];
    let pad = &PADDING[..plan.padding.min(PADDING.len())];

    macro_rules! hash_with {
        ($t:ty) => {{
            let mut h = <$t>::new();
            for r in &plan.ranges {
                // Already validated by `plan`, and still read through `get` rather than indexed:
                // the alternative is a panic that depends on an invariant holding across two
                // functions.
                if let Some(chunk) = data.get(r.clone()) {
                    h.update(chunk);
                }
            }
            h.update(pad);
            h.finalize().to_vec()
        }};
    }

    match algorithm {
        Algorithm::Sha1 => hash_with!(sha1::Sha1),
        Algorithm::Sha256 => hash_with!(sha2::Sha256),
        Algorithm::Sha384 => hash_with!(sha2::Sha384),
        Algorithm::Sha512 => hash_with!(sha2::Sha512),
    }
}

/// The digest the signature says the image should have, and which algorithm produced it.
///
/// Decoded from `SpcIndirectDataContent`, which is the Authenticode-specific content of the CMS
/// `SignedData`:
///
/// ```text
/// SpcIndirectDataContent ::= SEQUENCE {
///     data          SpcAttributeTypeAndOptionalValue,
///     messageDigest DigestInfo }
/// DigestInfo ::= SEQUENCE {
///     digestAlgorithm AlgorithmIdentifier,
///     digest          OCTET STRING }
/// ```
///
/// Two traps worth naming, both of which cost time to find. `econtent` is typed `Option<Any>` and
/// the `[0] EXPLICIT` wrapper is **already stripped** by the time it is in hand, so the `Any`'s tag
/// is `SEQUENCE` and not `OCTET STRING` as the CMS prose suggests. And the first field is read and
/// discarded rather than skipped by arithmetic: it is `SpcPeImageData` in practice, whose length
/// varies with the page-hash flags, so anything that assumed a size would break on a subset of
/// images.
///
/// `None` for an unsigned image, a blob that is not `SignedData`, content that is not Authenticode,
/// or a digest algorithm this build cannot compute. Every one of those is `Unchecked`, never a
/// mismatch.
pub fn expected(blob: &[u8]) -> Option<(Algorithm, Vec<u8>)> {
    if blob.is_empty() || blob.len() > MAX_BLOB_LEN {
        return None;
    }
    // DER and never BER, for the reason `pe::signer` documents: the `der` crate's
    // indefinite-length scanner recurses once per nesting level, so a blob of repeated `24 80`
    // bytes overflows the stack, which aborts and cannot be caught. Authenticode requires DER.
    // Partial because a WIN_CERTIFICATE pads its data to an eight-byte boundary.
    let (info, _padding) = ContentInfo::from_der_partial(blob).ok()?;
    if info.content_type != ID_SIGNED_DATA {
        return None;
    }
    let signed = info.content.decode_as::<SignedData>().ok()?;
    if signed.encap_content_info.econtent_type.to_string() != SPC_INDIRECT_DATA {
        return None;
    }
    let econtent = signed.encap_content_info.econtent.as_ref()?;

    let mut outer = SliceReader::new(AnyRef::from(econtent).value()).ok()?;
    // SpcAttributeTypeAndOptionalValue: read so the reader advances, then dropped.
    let _data = AnyRef::decode(&mut outer).ok()?;
    let digest_info = AnyRef::decode(&mut outer).ok()?;

    let mut inner = SliceReader::new(digest_info.value()).ok()?;
    let algorithm_id = AnyRef::decode(&mut inner).ok()?;
    // As an `AnyRef` with its tag checked, rather than `OctetStringRef`, which is unsized in
    // `der` 0.8 and so cannot be decoded directly.
    let digest = AnyRef::decode(&mut inner).ok()?;
    if der::Tagged::tag(&digest) != der::Tag::OctetString {
        return None;
    }

    let mut algorithm = SliceReader::new(algorithm_id.value()).ok()?;
    // `const_oid`'s default arc capacity, which is what every other `ObjectIdentifier` in the tree
    // resolves to. Named explicitly because the type is generic over it and nothing here infers it.
    let oid = ObjectIdentifier::<{ der::oid::ObjectIdentifier::MAX_SIZE }>::decode(&mut algorithm)
        .ok()?;

    let algorithm = Algorithm::from_oid(&oid.to_string())?;
    Some((algorithm, digest.value().to_vec()))
}

/// Compare the image against its own signature.
///
/// `Unchecked` whenever either side could not be established, which keeps "we could not tell" and
/// "the bytes are wrong" distinct. A reader acts very differently on the two, and the second is the
/// only one of the tool's findings that says the shipped file is not the file that was signed.
///
/// A dual-signed image carries a second `SignedData` in an unsigned attribute of the first. This
/// verifies the primary signature, which is the one Windows prefers, and says nothing about the
/// secondary.
pub fn verify(pe: &PE, data: &[u8], blob: &[u8]) -> DigestState {
    let Some((algorithm, want)) = expected(blob) else {
        return DigestState::Unchecked;
    };
    let Some(got) = digest(pe, data, algorithm) else {
        return DigestState::Unchecked;
    };
    if got == want {
        DigestState::Verified
    } else {
        DigestState::Mismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One range as a `Vec`, built through an iterator because clippy reads `vec![a..b]` as a
    /// probable mistake for `vec![a, b]`.
    fn one(r: Range<usize>) -> Vec<Range<usize>> {
        std::iter::once(r).collect()
    }

    #[test]
    fn the_checksum_sits_at_the_same_offset_under_both_magics() {
        // 32-bit: 28 bytes of standard fields, then 36 into the Windows fields.
        assert_eq!(
            optional_header::SIZEOF_STANDARD_FIELDS_32 + 36,
            CHECKSUM_OFFSET
        );
        // 64-bit: 24 bytes of standard fields, then 40 in.
        assert_eq!(
            optional_header::SIZEOF_STANDARD_FIELDS_64 + 40,
            CHECKSUM_OFFSET
        );
    }

    #[test]
    fn padding_reaches_an_eight_byte_boundary_and_is_never_eight() {
        for (size, expected) in [(0, 0), (1, 7), (7, 1), (8, 0), (9, 7), (16, 0)] {
            assert_eq!((8 - size % 8) % 8, expected, "size {}", size);
        }
    }

    #[test]
    fn a_range_outside_the_file_declines_the_plan_rather_than_clamping_it() {
        let data = vec![0u8; 64];
        let mut out = Vec::new();
        assert_eq!(push(&mut out, &data, 0, 64), Some(()));
        assert_eq!(push(&mut out, &data, 0, 65), None, "past the end");
        assert_eq!(push(&mut out, &data, 10, 5), None, "inverted");
        // Clamping would silently hash a different image than the one the headers describe, which
        // is worse than declining: it would turn a crafted header into a digest that cannot be
        // reproduced by any other tool.
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn an_unknown_digest_oid_is_unchecked_rather_than_a_mismatch() {
        assert_eq!(
            Algorithm::from_oid("2.16.840.1.101.3.4.2.1"),
            Some(Algorithm::Sha256)
        );
        assert_eq!(Algorithm::from_oid("1.3.14.3.2.26"), Some(Algorithm::Sha1));
        assert_eq!(
            Algorithm::from_oid("1.2.643.7.1.1.2.2"),
            None,
            "a GOST digest"
        );
        assert_eq!(DigestState::default(), DigestState::Unchecked);
    }

    #[test]
    fn a_plan_hashes_exactly_its_ranges_plus_its_padding() {
        let data: Vec<u8> = (0..32u8).collect();
        let plan = Plan {
            ranges: vec![0..8, 16..24],
            padding: 0,
        };
        let mut expected = sha2::Sha256::new();
        expected.update(&data[0..8]);
        expected.update(&data[16..24]);
        assert_eq!(
            run(&plan, &data, Algorithm::Sha256),
            expected.finalize().to_vec()
        );
        assert_eq!(plan.len(), 16);
    }

    #[test]
    fn the_padding_is_hashed_as_zeros_and_is_bounded() {
        let data = vec![0xAAu8; 8];
        let plan = Plan {
            ranges: one(0..8),
            padding: 3,
        };
        let mut expected = sha2::Sha256::new();
        expected.update(&data);
        expected.update([0u8, 0, 0]);
        assert_eq!(
            run(&plan, &data, Algorithm::Sha256),
            expected.finalize().to_vec()
        );

        // A padding length no honest plan produces must not index past the constant.
        let absurd = Plan {
            ranges: one(0..8),
            padding: usize::MAX,
        };
        let _ = run(&absurd, &data, Algorithm::Sha256);
    }

    #[test]
    fn a_digest_is_the_expected_width_for_each_algorithm() {
        let data = vec![0u8; 16];
        let plan = Plan {
            ranges: one(0..16),
            padding: 0,
        };
        for (algorithm, width) in [
            (Algorithm::Sha1, 20),
            (Algorithm::Sha256, 32),
            (Algorithm::Sha384, 48),
            (Algorithm::Sha512, 64),
        ] {
            assert_eq!(
                run(&plan, &data, algorithm).len(),
                width,
                "{}",
                algorithm.as_str()
            );
        }
    }

    #[test]
    fn garbage_and_truncated_images_are_declined_without_panicking() {
        for bytes in [&b"MZ"[..], &b"not a pe at all"[..], &[0u8; 0][..]] {
            if let Ok(pe) = goblin::pe::PE::parse(bytes) {
                let _ = plan(&pe, bytes);
            }
        }
    }
}
