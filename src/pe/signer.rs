//! Authenticode signer identity: whose code a finding sits in.
//!
//! Signature presence on its own does not help a reviewer triage. A banned call inside
//! `coreclr.dll` is Microsoft's to fix, and nobody on the reviewing team can patch it, so
//! a report that lumps Microsoft-signed images in with first-party ones spends the
//! reviewer's attention on work they cannot do. The signing identity is the cheapest
//! signal available for telling the two apart, and it is already in the file.
//!
//! goblin stops at the certificate table: it hands over the raw PKCS#7 blob and does no
//! ASN.1 at all. The walk from that blob to a Subject Common Name happens here, following
//! RFC 5652: `ContentInfo` -> `SignedData` -> `signerInfos` -> the `sid` that names the
//! signer -> the matching certificate in `certificates` -> that certificate's subject CN.
//!
//! Every byte reaching this module came from a file the tool was pointed at, which may be
//! hostile. So the module is written to give up rather than fail: no `unwrap`, no `expect`,
//! no indexing, no slicing, and no `as` casts on untrusted lengths. A panic on a crafted
//! certificate table would be a denial of service against a scan, and "parses untrusted
//! binaries without executing them" is the tool's central claim.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::oid::db::rfc5911::ID_SIGNED_DATA;
use der::Decode;
use goblin::pe::certificate_table::{AttributeCertificate, AttributeCertificateType};
use serde::{Deserialize, Serialize};
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::Certificate;

/// Longest signer name kept, in characters. A certificate's subject CN is attacker-chosen
/// text that ends up in a terminal, an HTML page, a CSV cell, and a SQL dump, so it is
/// capped here rather than at each of the five writers.
const MAX_NAME_LEN: usize = 128;

/// Largest certificate blob this module will attempt to parse.
///
/// Real Authenticode blobs run from a few kilobytes to roughly a hundred with a timestamp
/// countersignature attached. The cap exists because decoding a CMS `SET OF` re-encodes
/// each member to sort it, so a blob stuffed with thousands of minimal certificates costs
/// more than its size suggests. Over the cap the blob is reported as unreadable, which is
/// honest: it was not confirmed to be SignedData.
const MAX_BLOB_LEN: usize = 4 * 1024 * 1024;

/// Bidirectional override and isolate controls. Not ASCII control characters, and so not
/// caught by `char::is_control`, but they reorder the glyphs after them in a terminal and
/// in a browser, which makes them the one real spoofing vector in a name printed to a
/// reviewer. They have no legitimate place in a certificate subject, unlike the joiners
/// that Arabic and Indic scripts need, which are left alone.
const BIDI_CONTROLS: [char; 9] = [
    '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}',
    '\u{2069}',
];

/// What the Authenticode signature says about who signed the image.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Signature {
    /// Subject Common Name of the signing certificate, for example "Microsoft Corporation".
    /// `None` when the blob is present but could not be parsed, or parsed but named nobody.
    #[serde(default)]
    pub signer: Option<String>,
    /// Number of X.509 certificates the blob carried, as context for the reader. Zero when
    /// the blob did not parse. Certificates in a format other than X.509, which RFC 5652
    /// permits and nothing in practice uses, are not counted.
    #[serde(default)]
    pub chain_len: usize,
    /// Whether the blob was the expected PKCS#7 SignedData rather than something else.
    #[serde(default)]
    pub well_formed: bool,
}

/// Parse the first usable certificate entry.
///
/// `None` means the image is unsigned: no certificate table at all. That is a different
/// fact from `Some(Signature { signer: None, .. })`, which means the image is signed but
/// the signature could not be read, and a report should say so differently. Collapsing
/// the two would turn "we could not tell" into "there is nothing there".
pub fn parse(certs: &[AttributeCertificate]) -> Option<Signature> {
    let entry = pick_entry(certs)?;
    Some(read_blob(entry.certificate))
}

/// Pick the entry to read. Prefer PKCS#7 SignedData, which is what Authenticode uses;
/// otherwise take the first entry so a table holding only a bare X.509 or a reserved type
/// still reports "signed, unreadable" rather than "unsigned".
///
/// `matches!` rather than a `match`, deliberately: goblin marks
/// `AttributeCertificateRevision` `#[non_exhaustive]` and may yet do the same to
/// `AttributeCertificateType`, and this way neither a new variant nor a wildcard arm that
/// silently swallows one can change the behaviour here.
fn pick_entry<'s, 'd>(
    certs: &'s [AttributeCertificate<'d>],
) -> Option<&'s AttributeCertificate<'d>> {
    certs
        .iter()
        .find(|c| matches!(c.certificate_type, AttributeCertificateType::PkcsSignedData))
        .or_else(|| certs.first())
}

/// Read one raw PKCS#7 blob. Never fails: an unreadable blob is a `Signature` that says so.
fn read_blob(blob: &[u8]) -> Signature {
    if blob.is_empty() || blob.len() > MAX_BLOB_LEN {
        return Signature::default();
    }

    // DER, never BER, and that is a security choice rather than a strictness one. Under BER
    // the `der` crate accepts indefinite lengths, and its indefinite-length scanner descends
    // once per nesting level, so a blob of repeated `24 80` bytes recurses as deep as the
    // blob is long. That ends in a stack overflow, which aborts the process and cannot be
    // caught, so it would be a denial of service on a scan. Authenticode requires DER
    // anyway, and under DER an indefinite length is rejected on sight with no recursion.
    //
    // `from_der_partial` rather than `from_der` because a WIN_CERTIFICATE pads its
    // certificate data to an 8-byte boundary and goblin hands that padding over as part of
    // the blob. Trailing bytes after a complete ContentInfo are ignored.
    let Ok((info, _padding)) = ContentInfo::from_der_partial(blob) else {
        return Signature::default();
    };
    if info.content_type != ID_SIGNED_DATA {
        return Signature::default();
    }
    let Ok(signed) = info.content.decode_as::<SignedData>() else {
        return Signature::default();
    };

    let chain = x509_chain(&signed);
    let signer = signed
        .signer_infos
        .0
        .as_slice()
        .iter()
        .find_map(|si| resolve_signer(&chain, &si.sid))
        .or_else(|| leaf_of(&chain))
        .and_then(subject_common_name);

    Signature {
        signer,
        chain_len: chain.len(),
        well_formed: true,
    }
}

/// The X.509 certificates in the blob, in the order the decoder settled on.
fn x509_chain(signed: &SignedData) -> Vec<&Certificate> {
    let Some(set) = signed.certificates.as_ref() else {
        return Vec::new();
    };
    set.0
        .as_slice()
        .iter()
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(cert) => Some(cert),
            // `OtherCertificateFormat`: permitted by RFC 5652, unused by Authenticode, and
            // opaque to us, so it contributes no identity and is not counted in the chain.
            CertificateChoices::Other(_) => None,
        })
        .collect()
}

/// Resolve a `SignerIdentifier` against the certificate set, which is what actually names
/// the signer. Anything else in the blob is a CA or a countersigner.
fn resolve_signer<'c>(
    chain: &[&'c Certificate],
    sid: &SignerIdentifier,
) -> Option<&'c Certificate> {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(isn) => chain.iter().copied().find(|cert| {
            let tbs = cert.tbs_certificate();
            // Byte-exact comparison of the encoded names. RFC 5280 name matching also
            // folds case and whitespace inside PrintableString, so a blob that encoded
            // the issuer differently from the certificate would miss here and fall through
            // to the leaf heuristic below, which is the right failure direction.
            tbs.issuer() == &isn.issuer && tbs.serial_number() == &isn.serial_number
        }),
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            let wanted = ski.0.as_bytes();
            chain.iter().copied().find(|cert| {
                match cert
                    .tbs_certificate()
                    .get_extension::<SubjectKeyIdentifier>()
                {
                    Ok(Some((_critical, found))) => found.0.as_bytes() == wanted,
                    // Absent, undecodable, or present more than once: not a match.
                    _ => false,
                }
            })
        }
    }
}

/// Fallback: the certificate that is not the issuer of any *other* certificate in the set,
/// which in a signing chain is the leaf.
///
/// This is a heuristic, not the CMS rule, and it is only reached when `resolve_signer`
/// found nothing: an empty `signerInfos` (a certs-only bundle), a `sid` naming a
/// certificate the blob does not carry, or a name encoded differently in the two places.
/// A self-signed certificate on its own is its own leaf, which is why the comparison skips
/// the candidate itself.
fn leaf_of<'c>(chain: &[&'c Certificate]) -> Option<&'c Certificate> {
    chain.iter().enumerate().find_map(|(i, cand)| {
        let subject = cand.tbs_certificate().subject();
        let issues_another = chain
            .iter()
            .enumerate()
            .any(|(j, other)| j != i && other.tbs_certificate().issuer() == subject);
        (!issues_another).then_some(*cand)
    })
}

/// Subject Common Name of a certificate, normalised. `None` when there is no CN, when it
/// is not encoded as a string, or when normalising leaves nothing behind.
fn subject_common_name(cert: &Certificate) -> Option<String> {
    let cn = cert.tbs_certificate().subject().common_name().ok()??;
    normalize_name(&cn.value())
}

/// Trim, collapse internal whitespace runs, drop control characters, and cap the length.
///
/// Nothing else is changed: the name is evidence about the file and rewriting it further
/// would make it harder to match against what a reviewer sees in Windows' own dialogs.
fn normalize_name(raw: &str) -> Option<String> {
    let scrubbed: String = raw
        .chars()
        // A tab or newline is whitespace first and a control character second, so it
        // becomes a space and collapses, rather than vanishing and welding two words
        // together. Order matters: map before filtering.
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|c| !c.is_control() && !BIDI_CONTROLS.contains(c))
        .collect();

    // `split_whitespace` collapses runs and trims both ends in one pass.
    let collapsed = scrubbed.split_whitespace().collect::<Vec<_>>().join(" ");

    // Truncate by characters, not bytes, so a multi-byte name cannot be cut mid-character.
    // Truncation can strip the tail off a word and leave a dangling space, so trim again.
    let capped = collapsed.chars().take(MAX_NAME_LEN).collect::<String>();
    let capped = capped.trim_end();

    if capped.is_empty() {
        None
    } else {
        Some(capped.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goblin::pe::certificate_table::AttributeCertificateRevision;

    /// A real PKCS#7 SignedData over the bytes "binspector", signed by a self-signed
    /// P-256 certificate whose subject is `CN=Binspector Test Signer, O=Binspector`. The
    /// `signerInfos` entry identifies the signer by issuer and serial number, which is the
    /// form Authenticode uses, so this exercises the whole resolution path rather than the
    /// fallback. Generated once with OpenSSL; nothing here checks validity dates, so it
    /// does not expire.
    const SIGNED_DATA_P256: &str = concat!(
        "308202c206092a864886f70d010702a08202b3308202af020101310d300b0609608648016503040201301906",
        "092a864886f70d010701a00c040a62696e73706563746f72a08201c4308201c030820167a003020102021412",
        "8a06915aa9be26f45c110678d682428313a018300a06082a8648ce3d0403023036311f301d06035504030c16",
        "42696e73706563746f722054657374205369676e657231133011060355040a0c0a42696e73706563746f7230",
        "1e170d3236313030313132353333395a170d3336303932383132353333395a3036311f301d06035504030c16",
        "42696e73706563746f722054657374205369676e657231133011060355040a0c0a42696e73706563746f7230",
        "59301306072a8648ce3d020106082a8648ce3d03010703420004606bd6fd74d37d4993cd66e0ef7cebfe0eb3",
        "89216ba49362e953fbc5e00a368e6d7ac9cfc995cf14ad74fbb3b82fdf2df37a8d923df8d5fc38bc495007ce",
        "c3d7a3533051301d0603551d0e04160414c0424d43c37ce57d5ac3f0673a11bf62d8fc5d2b301f0603551d23",
        "041830168014c0424d43c37ce57d5ac3f0673a11bf62d8fc5d2b300f0603551d130101ff040530030101ff30",
        "0a06082a8648ce3d0403020347003044022059a2e592894d91db5656afd8b1ea152fdad25435aaa5858a569d",
        "c169924e2e3202202e7fe57856bf968a58d2481a26eaa983b072ea3c359b9682dafa6ab04fffc8013181b730",
        "81b4020101304e3036311f301d06035504030c1642696e73706563746f722054657374205369676e65723113",
        "3011060355040a0c0a42696e73706563746f720214128a06915aa9be26f45c110678d682428313a018300b06",
        "09608648016503040201300a06082a8648ce3d04030204463044022004840fe3daba2856337e195b672eb8c4",
        "d5e23503275c08084befc1c968687a1202203a4e8fd9537d7c22aa94da6ccc91cfbd0c3a8fc32381b04ebd25",
        "d0e4443fc533",
    );

    /// A certs-only SignedData: two certificates, `CN=Binspector Leaf Signer` issued by
    /// `CN=Binspector Test Root`, and an empty `signerInfos`. With nothing to resolve, the
    /// leaf heuristic has to pick the leaf and not the root.
    const CERTS_ONLY_CHAIN: &str = concat!(
        "3082034906092a864886f70d010702a082033a308203360201013100300b06092a864886f70d010701a08203",
        "1e308201833082012aa0030201020214050e222f99194b9e1e519938fcbbfa724891da55300a06082a8648ce",
        "3d040302301f311d301b06035504030c1442696e73706563746f72205465737420526f6f74301e170d323631",
        "3030313132353335345a170d3336303932383132353335345a3021311f301d06035504030c1642696e737065",
        "63746f72204c656166205369676e65723059301306072a8648ce3d020106082a8648ce3d0301070342000478",
        "d4446d8b40a357bd4a2f546c6b968fb83eff8e7b795406b21ea0ea9cc3007a3e7841f63a4c72bd5c30c51ca0",
        "edfb634a40f3e9ce8e7a45145811ca1858278fa3423040301d0603551d0e04160414f855b2d2a9c346f68ab5",
        "a99d98ecf45939c23019301f0603551d230418301680147724daec539319799db8ac2dd3868828abc1cbba30",
        "0a06082a8648ce3d0403020347003044022051b225a889fe9ae07e55deadef6dc3fb6c7f62c1a23fea1d98e9",
        "3e7dde649bfe02203e439057cb91bc309ee65801f8c8fb51a6f215ca59f511ab18d6c7f5ab3027c830820193",
        "30820139a00302010202146d6d99342a6d3f1663c05b0124114a217ac8a451300a06082a8648ce3d04030230",
        "1f311d301b06035504030c1442696e73706563746f72205465737420526f6f74301e170d3236313030313132",
        "353335345a170d3336303932383132353335345a301f311d301b06035504030c1442696e73706563746f7220",
        "5465737420526f6f743059301306072a8648ce3d020106082a8648ce3d030107034200044401543dbb4a2d1d",
        "365be1c5cf2c6954a6b189b31b33f606afb94f55aa58cfe05fd2d3c213e065a13d8f5f1a84e2ce415a0b32cc",
        "df750d867faa392662eff25ca3533051301d0603551d0e041604147724daec539319799db8ac2dd3868828ab",
        "c1cbba301f0603551d230418301680147724daec539319799db8ac2dd3868828abc1cbba300f0603551d1301",
        "01ff040530030101ff300a06082a8648ce3d0403020348003045022034f6fed2fe11e1acd3f3472453cc10c9",
        "18be8e55e90e628c1758acadd9fba5fc0221008549892d2c0180d0fcac96d671edf178a5ff78b264ff8e3922",
        "ab14f84cd3e1ed3100",
    );

    /// A bare X.509 certificate. Valid DER, a well-formed SEQUENCE, and not a ContentInfo:
    /// the case where the bytes parse as ASN.1 but are the wrong structure entirely.
    const BARE_CERT_DER: &str = concat!(
        "308201c030820167a0030201020214128a06915aa9be26f45c110678d682428313a018300a06082a8648ce3d",
        "0403023036311f301d06035504030c1642696e73706563746f722054657374205369676e6572311330110603",
        "55040a0c0a42696e73706563746f72301e170d3236313030313132353333395a170d33363039323831323533",
        "33395a3036311f301d06035504030c1642696e73706563746f722054657374205369676e6572311330110603",
        "55040a0c0a42696e73706563746f723059301306072a8648ce3d020106082a8648ce3d03010703420004606b",
        "d6fd74d37d4993cd66e0ef7cebfe0eb389216ba49362e953fbc5e00a368e6d7ac9cfc995cf14ad74fbb3b82f",
        "df2df37a8d923df8d5fc38bc495007cec3d7a3533051301d0603551d0e04160414c0424d43c37ce57d5ac3f0",
        "673a11bf62d8fc5d2b301f0603551d23041830168014c0424d43c37ce57d5ac3f0673a11bf62d8fc5d2b300f",
        "0603551d130101ff040530030101ff300a06082a8648ce3d0403020347003044022059a2e592894d91db5656",
        "afd8b1ea152fdad25435aaa5858a569dc169924e2e3202202e7fe57856bf968a58d2481a26eaa983b072ea3c",
        "359b9682dafa6ab04fffc801",
    );

    /// Hex to bytes without an `unwrap`: a decode failure yields an empty blob, and the
    /// assertions on the parse result catch that just as loudly.
    fn blob(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str).unwrap_or_default()
    }

    fn entry(kind: AttributeCertificateType, bytes: &[u8]) -> AttributeCertificate<'_> {
        AttributeCertificate {
            // `dwLength` counts the 8-byte WIN_CERTIFICATE header plus the blob. Nothing in
            // this module reads it; it is filled in honestly so a fixture looks like what
            // goblin hands over.
            length: 8u32.saturating_add(u32::try_from(bytes.len()).unwrap_or(u32::MAX)),
            revision: AttributeCertificateRevision::Revision2_0,
            certificate_type: kind,
            certificate: bytes,
        }
    }

    fn pkcs7(bytes: &[u8]) -> AttributeCertificate<'_> {
        entry(AttributeCertificateType::PkcsSignedData, bytes)
    }

    #[test]
    fn unsigned_image_is_none_not_an_empty_signature() {
        assert!(parse(&[]).is_none(), "no certificate table means unsigned");
    }

    #[test]
    fn signed_but_unreadable_is_some_with_no_signer() {
        // A blob of zero bytes, of one byte, random non-DER, a DER header whose length
        // overruns the data, and a real SignedData cut off mid-structure. Every one is
        // "signed, and we could not read it", which is not the same fact as "unsigned".
        let real = blob(SIGNED_DATA_P256);
        let truncated = real.get(..40).unwrap_or_default().to_vec();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("one byte", vec![0x30]),
            (
                "random non-DER",
                vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0xff, 0x7f, 0x80],
            ),
            (
                "overlong header",
                vec![0x30, 0x82, 0xff, 0xff, 0x02, 0x01, 0x01],
            ),
            ("truncated SignedData", truncated),
            (
                "bare X.509, right ASN.1 and wrong structure",
                blob(BARE_CERT_DER),
            ),
        ];

        for (label, bytes) in cases {
            let parsed = parse(&[pkcs7(&bytes)]);
            assert!(
                parsed.is_some(),
                "{label}: a present entry read as unsigned"
            );
            let sig = parsed.unwrap_or_default();
            assert_eq!(sig.signer, None, "{label}: invented a signer");
            assert!(!sig.well_formed, "{label}: claimed to be SignedData");
            assert_eq!(sig.chain_len, 0, "{label}: invented a chain");
        }
    }

    #[test]
    fn every_truncation_of_a_real_blob_is_handled() {
        // The cheapest approximation of a fuzzer for the one failure mode that matters:
        // nothing below may panic, and nothing may claim an identity it did not read.
        let real = blob(SIGNED_DATA_P256);
        assert!(!real.is_empty(), "fixture failed to decode");
        for n in 0..real.len() {
            let Some(prefix) = real.get(..n) else {
                continue;
            };
            let sig = parse(&[pkcs7(prefix)]);
            if n == 0 {
                // goblin can hand over a zero-length blob; it is still a present entry.
                assert!(sig.is_some(), "a present entry must not read as unsigned");
            }
            if let Some(sig) = sig {
                assert!(
                    !sig.well_formed,
                    "a {n}-byte prefix of a {} byte blob parsed as complete SignedData",
                    real.len()
                );
            }
        }
    }

    #[test]
    fn a_non_pkcs7_entry_type_does_not_panic() {
        let bytes = blob(BARE_CERT_DER);
        for kind in [
            AttributeCertificateType::X509,
            AttributeCertificateType::Reserved1,
            AttributeCertificateType::TsStackSigned,
        ] {
            let sig = parse(&[entry(kind, &bytes)]).unwrap_or_default();
            assert_eq!(sig.signer, None);
            assert!(!sig.well_formed);
        }
    }

    #[test]
    fn the_pkcs7_entry_wins_over_an_earlier_entry_of_another_type() {
        let junk = vec![0xff; 16];
        let real = blob(SIGNED_DATA_P256);
        let sig = parse(&[entry(AttributeCertificateType::X509, &junk), pkcs7(&real)])
            .unwrap_or_default();
        assert_eq!(sig.signer.as_deref(), Some("Binspector Test Signer"));
    }

    #[test]
    fn signer_info_resolves_to_the_signing_certificate_cn() {
        let sig = parse(&[pkcs7(&blob(SIGNED_DATA_P256))]).unwrap_or_default();
        assert!(
            sig.well_formed,
            "a real SignedData must read as well formed"
        );
        assert_eq!(sig.chain_len, 1);
        assert_eq!(sig.signer.as_deref(), Some("Binspector Test Signer"));
    }

    #[test]
    fn trailing_padding_after_the_content_info_is_tolerated() {
        // WIN_CERTIFICATE pads its certificate data to an 8-byte boundary, and goblin
        // includes that padding in the blob it hands over.
        let mut padded = blob(SIGNED_DATA_P256);
        padded.extend_from_slice(&[0u8; 6]);
        let sig = parse(&[pkcs7(&padded)]).unwrap_or_default();
        assert_eq!(sig.signer.as_deref(), Some("Binspector Test Signer"));
    }

    #[test]
    fn with_no_signer_info_the_fallback_picks_the_leaf_not_the_root() {
        let sig = parse(&[pkcs7(&blob(CERTS_ONLY_CHAIN))]).unwrap_or_default();
        assert!(sig.well_formed);
        assert_eq!(sig.chain_len, 2, "both certificates should be counted");
        assert_eq!(
            sig.signer.as_deref(),
            Some("Binspector Leaf Signer"),
            "the root issued the leaf, so the root is not the leaf"
        );
    }

    #[test]
    fn an_ordinary_name_is_left_alone() {
        assert_eq!(
            normalize_name("Microsoft Corporation").as_deref(),
            Some("Microsoft Corporation")
        );
    }

    #[test]
    fn whitespace_is_trimmed_and_collapsed() {
        assert_eq!(
            normalize_name("  Microsoft   Corporation\t\n").as_deref(),
            Some("Microsoft Corporation")
        );
    }

    #[test]
    fn control_characters_are_stripped_without_welding_words_together() {
        // A bell is not whitespace, so it simply disappears.
        assert_eq!(
            normalize_name("Micro\u{7}soft").as_deref(),
            Some("Microsoft")
        );
        // A newline is whitespace first, so it becomes the single space it looked like.
        assert_eq!(normalize_name("Micro\nsoft").as_deref(), Some("Micro soft"));
        // An escape sequence cannot survive to reach a terminal.
        assert_eq!(
            normalize_name("\u{1b}[31mEvil Corp\u{1b}[0m").as_deref(),
            Some("[31mEvil Corp[0m")
        );
        // A right-to-left override cannot reorder what a reviewer reads.
        assert_eq!(
            normalize_name("Safe\u{202e}txt.exe").as_deref(),
            Some("Safetxt.exe")
        );
    }

    #[test]
    fn a_name_of_nothing_but_controls_and_spaces_is_none() {
        assert_eq!(normalize_name(""), None);
        assert_eq!(normalize_name("   \t\n  "), None);
        assert_eq!(normalize_name("\u{0}\u{1}\u{7f}"), None);
    }

    #[test]
    fn a_hostile_name_is_capped() {
        let long = "A".repeat(5000);
        let capped = normalize_name(&long).unwrap_or_default();
        assert_eq!(capped.chars().count(), MAX_NAME_LEN);

        // Truncation must not leave a dangling space where a word was cut off.
        let cut_mid_word = format!("{} tail", "B".repeat(MAX_NAME_LEN - 1));
        let capped = normalize_name(&cut_mid_word).unwrap_or_default();
        assert_eq!(capped.chars().count(), MAX_NAME_LEN - 1);
        assert!(!capped.ends_with(' '), "left a trailing space: {capped:?}");
    }

    #[test]
    fn a_multibyte_name_is_capped_by_character_not_byte() {
        // Four bytes per character: a byte-wise cap would split one and the collect would
        // have to lose or mangle it.
        let long = "\u{1f600}".repeat(400);
        let capped = normalize_name(&long).unwrap_or_default();
        assert_eq!(capped.chars().count(), MAX_NAME_LEN);
        assert_eq!(capped.len(), MAX_NAME_LEN * 4);
    }

    #[test]
    fn an_oversized_blob_is_refused_rather_than_parsed() {
        let huge = vec![0x30u8; MAX_BLOB_LEN + 1];
        let parsed = parse(&[pkcs7(&huge)]);
        assert!(parsed.is_some(), "the entry is present, so not unsigned");
        assert_eq!(parsed.unwrap_or_default(), Signature::default());
    }
}
