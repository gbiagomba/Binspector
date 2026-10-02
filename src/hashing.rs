//! File digests for the report header and for reputation lookups.

use md5::Md5;
use sha1::{Digest, Sha1};
use sha2::Sha256;

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Digests {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

/// Which algorithms to compute.
///
/// SHA-256 alone is enough for a reputation lookup and for content identity, and it is the only one
/// the scan strictly needs. MD5 and SHA-1 are what a reviewer pastes into another tool, so they are
/// worth having and worth being able to decline: computing all three is three passes over the
/// member bytes, and a scan that unpacks 1.6 GiB pays that three times over.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Which {
    /// All three, for the report header and the member digest table.
    All,
    /// SHA-256 only, when the digest is wanted for identity rather than for a human to copy.
    Sha256Only,
}

pub fn digests(data: &[u8]) -> Digests {
    compute(data, Which::All)
}

/// As [`digests`], computing only what was asked for.
///
/// The unasked-for fields come back empty rather than absent, so a caller cannot accidentally print
/// a blank where a digest belongs without the emptiness being visible.
pub fn compute(data: &[u8], which: Which) -> Digests {
    let mut sha256 = Sha256::new();
    sha256.update(data);
    let sha256 = hex::encode(sha256.finalize());
    if which == Which::Sha256Only {
        return Digests {
            md5: String::new(),
            sha1: String::new(),
            sha256,
        };
    }
    let mut md5 = Md5::new();
    md5.update(data);
    let mut sha1 = Sha1::new();
    sha1.update(data);
    Digests {
        md5: hex::encode(md5.finalize()),
        sha1: hex::encode(sha1.finalize()),
        sha256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors_for_empty_input() {
        let d = digests(b"");
        assert_eq!(d.md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(d.sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            d.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn known_vector_for_abc() {
        let d = digests(b"abc");
        assert_eq!(d.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            d.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_only_skips_the_other_two_and_says_so_by_being_empty() {
        let all = compute(b"binspector", Which::All);
        let one = compute(b"binspector", Which::Sha256Only);
        assert_eq!(all.sha256, one.sha256, "the shared algorithm must agree");
        assert!(one.md5.is_empty());
        assert!(one.sha1.is_empty());
        assert!(!all.md5.is_empty() && !all.sha1.is_empty());
    }
}
