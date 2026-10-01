//! Fuzz the pe parser.
//!
//! A file-reading harness, which is what AFL's `@@` and honggfuzz's `___FILE___`
//! placeholders substitute. For coverage-guided runs, instrument this same binary:
//!   cargo afl build --release --bin fuzz_pe
//!   cargo hfuzz build --bin fuzz_pe

fn exercise(data: &[u8]) {
    if let Some(a) = binspector::pe::PeAnalysis::parse(data) {
        // Entropy is a probability measure and must stay in range whatever the
        // section table claims.
        for s in &a.sections {
            assert!(
                (0.0..=8.0).contains(&s.entropy),
                "entropy {} out of range for section {}",
                s.entropy,
                s.name
            );
        }
        // Signer parsing walks an attacker-controlled PKCS#7 blob through an ASN.1 decoder,
        // which makes it the newest and least battle-tested parser in the tool. `parse` runs
        // inside `PeAnalysis::parse` already, so reaching here means it survived; assert the
        // invariant that a reader relies on, namely that a name is never reported without the
        // blob having been well formed.
        if let Some(sig) = a.signature.as_ref() {
            assert!(
                sig.signer.is_none() || sig.well_formed,
                "a signer name was reported for a blob that did not parse"
            );
        }
    }

    // Also drive the certificate path directly, so the fuzzer can reach the decoder with
    // bytes that are not a valid PE at all. goblin only hands over a certificate table for an
    // image it could parse, which would otherwise gate the ASN.1 code behind PE validity.
    let certs = [goblin::pe::certificate_table::AttributeCertificate {
        length: data.len() as u32,
        revision: goblin::pe::certificate_table::AttributeCertificateRevision::Revision2_0,
        certificate_type: goblin::pe::certificate_table::AttributeCertificateType::PkcsSignedData,
        certificate: data,
    }];
    let _ = binspector::pe::signer::parse(&certs);

    // The Authenticode decode and the chain walk, driven on the same arbitrary bytes. These are the
    // newest ASN.1 in the tool, and `chain` additionally feeds attacker-supplied DER to an RSA and an
    // ECDSA verifier, so a malformed key or signature must come back as a verdict rather than as a
    // panic. The certificate set can also describe a cycle, which the ordering walk has to terminate
    // on rather than follow.
    let _ = binspector::pe::authenticode::expected(data);
    let certificates = binspector::pe::signer::certificates(data);
    let refs: Vec<&x509_cert::Certificate> = certificates.iter().collect();
    let chain = binspector::pe::chain::verify(&refs, 0);
    // A verdict that names an anchor must name one that was actually there, and a fingerprint is
    // either a full SHA-256 in hex or absent: a truncated one would be compared against a published
    // thumbprint and silently fail to match.
    assert!(
        chain.anchor_fingerprint.is_empty() || chain.anchor_fingerprint.len() == 64,
        "fingerprint is {} characters",
        chain.anchor_fingerprint.len()
    );
    assert!(
        chain.verified_links <= certificates.len().max(1),
        "{} links verified across {} certificates",
        chain.verified_links,
        certificates.len()
    );
}

fn main() {
    // A file-reading harness. AFL++ substitutes the path for `@@` and honggfuzz for
    // `___FILE___`, which is how both drive a non-persistent target, and what
    // `binspector fuzz --engine` emits.
    //
    // For coverage-guided runs, instrument this same binary:
    //   cargo afl build --release --bin fuzz_pe
    //   cargo hfuzz build --bin fuzz_pe
    //
    // The afl and honggfuzz persistent-mode macros are deliberately not used. They
    // require the engine's runtime symbols at link time, so a plain `cargo build` or
    // `cargo test --all-features` could not link the binary at all.
    let mut args = std::env::args_os().skip(1);
    match args.next() {
        Some(path) => match std::fs::read(&path) {
            Ok(data) => exercise(&data),
            Err(e) => {
                eprintln!("cannot read input: {}", e);
                std::process::exit(2);
            }
        },
        None => {
            eprintln!("usage: fuzz_pe <input-file>");
            std::process::exit(2);
        }
    }
}
