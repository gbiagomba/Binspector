//! File digests for the report header and for reputation lookups.

use md5::Md5;
use sha1::{Digest, Sha1};
use sha2::Sha256;

pub struct Digests {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

pub fn digests(data: &[u8]) -> Digests {
    let mut md5 = Md5::new();
    md5.update(data);
    let mut sha1 = Sha1::new();
    sha1.update(data);
    let mut sha256 = Sha256::new();
    sha256.update(data);
    Digests {
        md5: hex::encode(md5.finalize()),
        sha1: hex::encode(sha1.finalize()),
        sha256: hex::encode(sha256.finalize()),
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
}
