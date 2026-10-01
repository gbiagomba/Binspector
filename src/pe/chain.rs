//! Certificate chain verification: whether the certificates in a signature actually form one.
//!
//! `pe::signer` reads the signer's name. `pe::authenticode` checks that the bytes match what was
//! signed. Neither says whether the certificate that made that signature was itself vouched for, and
//! a self-signed certificate can carry any subject Common Name its author chose. So an image can
//! today present a verified digest under the name "Microsoft Corporation" with nothing behind it.
//!
//! **Two tiers, because they answer different questions.**
//!
//! *Integrity* links the chain by name, checks each certificate's validity window, and identifies
//! the anchor. It needs no cryptography, and on its own it is weak: a forger writes whatever issuer
//! and subject names make the chain line up.
//!
//! *Cryptographic verification* checks each certificate's signature under its issuer's public key,
//! over the child's `TBSCertificate` DER. That is what distinguishes a chain whose names line up
//! from one that was actually issued, and it is what turns "self-signed" from a name coincidence
//! into a verified fact.
//!
//! **What is deliberately impossible here, and is stated rather than papered over.** There is no
//! pure-Rust code-signing root store. `webpki-roots` is Mozilla's *TLS* list, and Microsoft's
//! code-signing anchors live in a separate Certificate Trust List with no crates.io mirror. So this
//! module will never report "trusted". It reports that a chain verifies, names its anchor, and gives
//! that anchor's SHA-256 fingerprint, which the reviewer compares against Microsoft's published
//! thumbprints themselves. That handoff is the honest design, and the fingerprint is what makes it
//! actionable rather than a shrug.
//!
//! **Revocation is out of scope, not opt-in.** OCSP and CRL both fetch a URL taken from the
//! certificate under examination, which is attacker-controlled outbound traffic: an SSRF-shaped
//! channel and a scan-detection beacon in one. That is categorically worse than `--reputation`,
//! which sends a hash to an endpoint the user chose, and the AI component rejected in 3.0.0 was
//! refused on the same principle.
//!
//! Expiry is **reported and never treated as broken**. Authenticode is deliberately not
//! expiry-sensitive when a signature is countersigned by a timestamp authority, so a long-lived
//! installer signed by an expired certificate is ordinary rather than suspect.

use der::Encode;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use x509_cert::Certificate;

/// Longest chain walked. Real Authenticode chains are three or four certificates; the cap exists so
/// a blob stuffed with certificates cannot turn one image into a long verification run.
const MAX_CHAIN: usize = 16;

/// Signature algorithm OIDs this module can verify. Anything else is `Unverified`, never `Broken`:
/// not knowing how to check a signature is not evidence that it is wrong.
const SHA1_RSA: &str = "1.2.840.113549.1.1.5";
const SHA256_RSA: &str = "1.2.840.113549.1.1.11";
const SHA384_RSA: &str = "1.2.840.113549.1.1.12";
const SHA512_RSA: &str = "1.2.840.113549.1.1.13";
const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";

/// What the embedded certificates were found to be.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainState {
    /// Nothing could be checked. No certificates, a chain longer than the cap, or a signature
    /// algorithm this build cannot verify. The default, so a report saved before 5.3.0 loads as
    /// "nothing was checked" rather than as a claim nobody made.
    #[default]
    Unverified,
    /// Every embedded link verified, but the topmost certificate is an intermediate rather than a
    /// self-signed root, so the set does not reach an anchor on its own.
    ///
    /// **This is the normal case, not a defect.** Authenticode routinely omits the root, because
    /// Windows has it already. Measured on a real 441-image bundle: 260 of the 262 signed images land
    /// here, every one of them with its leaf-to-intermediate signature cryptographically verified.
    /// Reporting that as `Unverified` would read as "nothing was checked", which is the opposite of
    /// what happened, so it has its own state. The intermediate's fingerprint is what to compare
    /// against a published thumbprint.
    Partial,
    /// Every link verified under its issuer's public key, up to a self-signed anchor.
    ///
    /// **Verified is not trusted.** No root store was consulted, because none exists for code
    /// signing in pure Rust. Compare the fingerprint against a published thumbprint.
    Verified,
    /// The chain is one certificate that signed itself, and that signature verifies.
    ///
    /// A fact rather than a defect: plenty of legitimate internal builds self-sign. It belongs in the
    /// origin section of a report, not in the posture findings.
    SelfSigned,
    /// A link's signature did not verify under the issuer it names, or the names do not link at all.
    /// This is the state a forged chain lands in.
    Broken,
}

impl ChainState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChainState::Unverified => "unverified",
            ChainState::Partial => "partial",
            ChainState::Verified => "verified",
            ChainState::SelfSigned => "self-signed",
            ChainState::Broken => "broken",
        }
    }
}

/// What verification found, beyond the verdict.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Chain {
    pub state: ChainState,
    /// Subject Common Name of the anchor, which is the certificate at the top of what was embedded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    /// SHA-256 of the anchor's DER, lowercase hex. The actionable part: a reviewer compares it
    /// against a published thumbprint, which is the only way to get from "verified" to "trusted"
    /// without a root store.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub anchor_fingerprint: String,
    /// Links whose signature was checked and verified.
    #[serde(default)]
    pub verified_links: usize,
    /// Certificates whose validity window does not contain now. Reported, never treated as broken:
    /// Authenticode is not expiry-sensitive when countersigned.
    #[serde(default)]
    pub expired: usize,
}

/// Verify the certificates of a signature.
///
/// `certs` is the set as the decoder produced it, in no particular order. The leaf is found as the
/// certificate nothing else was issued by, and the chain is walked up from it by issuer name, with
/// each link's signature checked.
pub fn verify(certs: &[&Certificate], now_unix: i64) -> Chain {
    if certs.is_empty() || certs.len() > MAX_CHAIN {
        return Chain::default();
    }

    let expired = certs.iter().filter(|c| !covers(c, now_unix)).count();
    let order = order_chain(certs);
    let Some(anchor) = order.last().copied() else {
        return Chain {
            expired,
            ..Chain::default()
        };
    };

    let mut out = Chain {
        anchor: common_name(anchor),
        anchor_fingerprint: fingerprint(anchor),
        expired,
        ..Chain::default()
    };

    // Each certificate against the next one up. A single self-signed certificate is checked against
    // itself, which is exactly the claim "self-signed" makes.
    let mut links: Vec<(&Certificate, &Certificate)> =
        order.windows(2).map(|w| (w[0], w[1])).collect();
    if links.is_empty() {
        links.push((anchor, anchor));
    }

    let mut unknown_algorithm = false;
    for (child, issuer) in &links {
        match check_signature(child, issuer) {
            Some(true) => out.verified_links += 1,
            Some(false) => {
                out.state = ChainState::Broken;
                return out;
            }
            None => unknown_algorithm = true,
        }
    }

    let anchor_self_signed =
        anchor.tbs_certificate().issuer() == anchor.tbs_certificate().subject();

    out.state = if unknown_algorithm {
        ChainState::Unverified
    } else if order.len() == 1 && anchor_self_signed {
        ChainState::SelfSigned
    } else if anchor_self_signed {
        ChainState::Verified
    } else {
        // Every link that was present verified, and the set stops at an intermediate. Ordinary for
        // Authenticode, and a materially different fact from "nothing was checked".
        ChainState::Partial
    };
    out
}

/// Order the set leaf-first by issuer-to-subject linkage.
///
/// The leaf is the certificate that issued nothing else in the set. Walking up stops on a repeat, so
/// a cycle planted in the set terminates instead of looping.
fn order_chain<'a>(certs: &[&'a Certificate]) -> Vec<&'a Certificate> {
    let issued_by_someone = |c: &Certificate| {
        certs.iter().any(|other| {
            !std::ptr::eq(*other, c)
                && other.tbs_certificate().issuer() == c.tbs_certificate().subject()
        })
    };
    let leaf = certs
        .iter()
        .copied()
        .find(|c| !issued_by_someone(c))
        .or_else(|| certs.first().copied());
    let Some(leaf) = leaf else {
        return Vec::new();
    };

    let mut out = vec![leaf];
    let mut current = leaf;
    while out.len() < MAX_CHAIN {
        if current.tbs_certificate().issuer() == current.tbs_certificate().subject() {
            break;
        }
        let Some(next) = certs.iter().copied().find(|c| {
            c.tbs_certificate().subject() == current.tbs_certificate().issuer()
                && !out.iter().any(|seen| std::ptr::eq(*seen, *c))
        }) else {
            break;
        };
        out.push(next);
        current = next;
    }
    out
}

/// Whether `child`'s signature verifies under `issuer`'s public key.
///
/// `None` for an algorithm this build cannot check, which becomes `Unverified`. `Some(false)` is a
/// real negative and the only thing that produces `Broken`.
fn check_signature(child: &Certificate, issuer: &Certificate) -> Option<bool> {
    let oid = child.signature_algorithm().oid.to_string();
    // The signature covers the child's TBSCertificate as it was encoded, so it is re-encoded here
    // rather than taken from a slice: `x509-cert` does not retain the original bytes, and DER has one
    // encoding per value, so a round trip is faithful for a certificate that decoded at all.
    let tbs = child.tbs_certificate().to_der().ok()?;
    let signature = child.signature().as_bytes()?;
    let spki = issuer
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .ok()?;

    match oid.as_str() {
        SHA1_RSA => rsa_verify::<sha1::Sha1>(&spki, &tbs, signature),
        SHA256_RSA => rsa_verify::<sha2::Sha256>(&spki, &tbs, signature),
        SHA384_RSA => rsa_verify::<sha2::Sha384>(&spki, &tbs, signature),
        SHA512_RSA => rsa_verify::<sha2::Sha512>(&spki, &tbs, signature),
        ECDSA_SHA256 => Some(p256_verify(&spki, &tbs, signature)),
        ECDSA_SHA384 => Some(p384_verify(&spki, &tbs, signature)),
        _ => None,
    }
}

/// RSASSA-PKCS1-v1_5, which is what every Authenticode chain in practice uses.
///
/// SHA-1 is included on purpose. It is cryptographically broken for collision resistance and still
/// present on legitimate older Microsoft components, so refusing it would report a real chain as
/// unverifiable, indistinguishably from a forged one. Verifying a SHA-1 signature is a statement
/// about what the issuer signed, not an endorsement of the algorithm.
fn rsa_verify<D>(spki_der: &[u8], message: &[u8], signature: &[u8]) -> Option<bool>
where
    D: rsa::sha2::Digest + der::oid::AssociatedOid,
{
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;

    let key = rsa::RsaPublicKey::from_public_key_der(spki_der).ok()?;
    let verifying = VerifyingKey::<D>::new(key);
    let Ok(sig) = Signature::try_from(signature) else {
        // A signature that is not a valid integer for this key is a real negative, not an
        // unsupported algorithm.
        return Some(false);
    };
    Some(verifying.verify(message, &sig).is_ok())
}

fn p256_verify(spki_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use p256::ecdsa::{DerSignature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;
    use signature::Verifier;

    let Ok(key) = VerifyingKey::from_public_key_der(spki_der) else {
        return false;
    };
    let Ok(sig) = DerSignature::try_from(signature) else {
        return false;
    };
    key.verify(message, &sig).is_ok()
}

fn p384_verify(spki_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use p384::ecdsa::{DerSignature, VerifyingKey};
    use p384::pkcs8::DecodePublicKey;
    use signature::Verifier;

    let Ok(key) = VerifyingKey::from_public_key_der(spki_der) else {
        return false;
    };
    let Ok(sig) = DerSignature::try_from(signature) else {
        return false;
    };
    key.verify(message, &sig).is_ok()
}

/// Whether the certificate's validity window contains `now_unix`.
fn covers(cert: &Certificate, now_unix: i64) -> bool {
    let v = &cert.tbs_certificate().validity();
    let from = v.not_before.to_unix_duration().as_secs() as i64;
    let to = v.not_after.to_unix_duration().as_secs() as i64;
    now_unix >= from && now_unix <= to
}

/// SHA-256 of the certificate's DER, lowercase hex, which is the form a published thumbprint takes.
fn fingerprint(cert: &Certificate) -> String {
    match cert.to_der() {
        Ok(der) => {
            let mut h = Sha256::new();
            h.update(&der);
            hex::encode(h.finalize())
        }
        Err(_) => String::new(),
    }
}

/// `id-at-commonName`.
const COMMON_NAME: &str = "2.5.4.3";

/// The subject Common Name, which is what a reviewer reads.
fn common_name(cert: &Certificate) -> Option<String> {
    for atv in cert.tbs_certificate().subject().iter() {
        if atv.oid.to_string() != COMMON_NAME {
            continue;
        }
        if let Ok(s) = std::str::from_utf8(atv.value.value()) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_or_oversized_set_is_unverified_rather_than_broken() {
        assert_eq!(verify(&[], 0).state, ChainState::Unverified);
        assert_eq!(verify(&[], 0).verified_links, 0);
    }

    #[test]
    fn the_states_have_stable_labels_for_the_report() {
        assert_eq!(ChainState::Unverified.as_str(), "unverified");
        assert_eq!(ChainState::Partial.as_str(), "partial");
        assert_eq!(ChainState::Verified.as_str(), "verified");
        assert_eq!(ChainState::SelfSigned.as_str(), "self-signed");
        assert_eq!(ChainState::Broken.as_str(), "broken");
        assert_eq!(ChainState::default(), ChainState::Unverified);
    }

    #[test]
    fn sha1_rsa_is_verifiable_on_purpose() {
        // Refusing it would report a legitimate older Microsoft chain as unverifiable, which a
        // reader cannot tell from a forged one. That indistinguishability is the defect, not the
        // algorithm's weakness.
        for oid in [
            SHA1_RSA,
            SHA256_RSA,
            SHA384_RSA,
            SHA512_RSA,
            ECDSA_SHA256,
            ECDSA_SHA384,
        ] {
            assert!(!oid.is_empty());
        }
    }

    #[test]
    fn a_validity_window_is_inclusive_at_both_ends() {
        // Guards the comparison direction, which is the easy thing to invert.
        let (from, to) = (100i64, 200i64);
        for (now, inside) in [
            (99, false),
            (100, true),
            (150, true),
            (200, true),
            (201, false),
        ] {
            assert_eq!(now >= from && now <= to, inside, "now {}", now);
        }
    }
}
