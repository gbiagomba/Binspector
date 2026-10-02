//! Missing exploit mitigations as first-class findings.
//!
//! Until 5.0.0 the tool collected `pe.mitigations` for every image and reported it only as
//! prose in the text report. An adversarial review of real output called that out as the
//! single most actionable thing the scan produced and did not file:
//!
//! > Confirmable from binary metadata alone. No disassembly, no call site, no source access
//! > required. That makes it the most actionable item in the entire scan, and binspector
//! > collected `pe.mitigations` for all 441 members and fed none of it into severity.
//!
//! It is right. A banned-function hit says a dangerous name appears in an image; a missing
//! mitigation says a specific defence is switched off, which is attributable to a build flag
//! and fixable by changing it. The second is a better finding on every axis.
//!
//! These deliberately do not join `Report.summary` and `Report.hits`. A mitigation has no
//! function name, no byte offset, no encoding, and no confidence, so it would have to fake
//! six fields, and folding it into `banned_hit_count` would make the headline count a lie.
//! It gets its own vector instead.
//!
//! **`Unknown` is never a finding.** A managed assembly has no load config directory, so
//! reporting "/GS off" for one would be a false claim. The same argument the CFG reader has
//! made since 4.0.0.

use crate::model::{CoverageEntry, PostureFinding};
use crate::pe::mitigations::State;
use crate::scan::banned::Severity;

/// One mitigation's rule: how to read it, how bad its absence is, and what to say.
struct Rule {
    id: &'static str,
    title: &'static str,
    severity: Severity,
    evidence: &'static str,
    remediation: &'static str,
}

/// Highest cap on members named in one finding. The rest are counted.
///
/// A posture finding is about a build configuration, not about 179 individual files, so the human
/// reports show a handful and the record carries the set a query needs.
///
/// **Raised from 50 in 5.8.0, and the reason is a retraction.** The stored list is in scan order,
/// so the first 50 of 179 images missing Authenticode all came from one vendor. A reviewer read
/// that as representative, concluded the finding belonged to that vendor, and had to withdraw it
/// publicly. 5.7.0 added a `posture_members` table so the set could be queried instead of
/// eyeballed, and the table inherited this cap, which reproduced the trap it was added to remove.
///
/// It is still a cap rather than no cap, because a pathological input could otherwise name every
/// member of a 4,281-member package in every finding. 4,096 is far above any real build: the
/// largest finding on the reference package is 179.
const MEMBER_CAP: usize = 4096;

/// Derive posture findings from the images a scan parsed.
///
/// One finding per mitigation, listing the images that lack it, rather than one finding per
/// image: 179 unsigned images is a single statement about the build, and 179 findings would
/// bury everything else in the report.
pub fn findings(pes: &[&CoverageEntry]) -> Vec<PostureFinding> {
    let mut out = Vec::new();
    for rule in rules() {
        let mut members: Vec<String> = Vec::new();
        for e in pes {
            let a = match e.pe.as_ref() {
                Some(a) => a,
                None => continue,
            };
            if state_for(rule.id, a) == State::Disabled && applies(rule.id, a) {
                members.push(e.member.clone());
            }
        }
        if members.is_empty() {
            continue;
        }
        let total = members.len();
        members.truncate(MEMBER_CAP);
        out.push(PostureFinding {
            id: rule.id.to_string(),
            title: rule.title.to_string(),
            severity: rule.severity,
            affected: total,
            members,
            evidence: rule.evidence.to_string(),
            remediation: rule.remediation.to_string(),
        });
    }
    // Worst first, then by breadth, so the ordering is stable and reads usefully.
    out.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then(b.affected.cmp(&a.affected))
            .then(a.id.cmp(&b.id))
    });
    out
}

fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "aslr",
            title: "ASLR disabled: the image loads at a predictable address",
            severity: Severity::High,
            evidence: "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE absent from the optional header",
            remediation: "link with /DYNAMICBASE, which is the default in current toolchains",
        },
        Rule {
            id: "dep",
            title: "DEP disabled: data pages remain executable",
            severity: Severity::High,
            evidence: "IMAGE_DLLCHARACTERISTICS_NX_COMPAT absent from the optional header",
            remediation: "link with /NXCOMPAT",
        },
        Rule {
            id: "gs",
            title: "No stack cookie: a stack overflow is not detected on return",
            severity: Severity::Medium,
            evidence: "load config directory present with no usable SecurityCookie",
            remediation: "compile with /GS",
        },
        Rule {
            id: "cfg",
            title: "Control Flow Guard not instrumented: indirect calls are unchecked",
            severity: Severity::Medium,
            evidence: "load config guard flags present without IMAGE_GUARD_CF_INSTRUMENTED",
            remediation: "compile and link with /guard:cf",
        },
        Rule {
            id: "safe-seh",
            title: "No SafeSEH table: an overwritten exception record can redirect execution",
            severity: Severity::Medium,
            evidence: "x86-32 image whose load config registers no exception handlers",
            remediation: "link with /SAFESEH",
        },
        Rule {
            id: "authenticode",
            title: "No Authenticode signature: the file's origin cannot be verified",
            severity: Severity::Medium,
            evidence: "no certificate table in the image",
            remediation: "sign the shipped binaries, including third-party ones you rebuild",
        },
        Rule {
            id: "cet",
            title: "No CET shadow stack compatibility",
            severity: Severity::Low,
            evidence: "IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT absent",
            remediation: "build with /CETCOMPAT once the dependency chain supports it",
        },
        // The only finding in the tool that says the shipped file is not the file that was signed.
        // Critical because every other reading in this table is a statement about how an image was
        // built, and this one is a statement that its contents changed after someone vouched for
        // them. It is also the first posture rule able to trip `--fail-on critical`.
        Rule {
            id: "authenticode-digest",
            title: "Authenticode digest mismatch: the image does not match its own signature",
            severity: Severity::Critical,
            evidence: "the SpcIndirectDataContent digest differs from the digest of the shipped \
                       bytes over the Authenticode range",
            remediation: "do not trust the signer name on this image. Re-sign from a known-good \
                          build, and establish where the modification came from",
        },
    ]
}

fn state_for(id: &str, a: &crate::pe::PeAnalysis) -> State {
    let m = &a.mitigations;
    match id {
        "aslr" => m.aslr,
        "dep" => m.dep,
        "gs" => m.gs,
        "cfg" => m.cfg,
        "safe-seh" => m.safe_seh,
        "authenticode" => m.authenticode,
        "cet" => m.cet,
        // Not a header flag but a comparison: the digest inside the signature against the digest of
        // the shipped bytes. `Mismatch` maps to `Disabled` so it becomes a finding through the same
        // machinery, and `Unchecked` maps to `Unknown` so an unsigned image, a signature that would
        // not decode, and a digest algorithm this build cannot compute all emit nothing. See
        // `pe::authenticode`.
        "authenticode-digest" => match a.signature.as_ref().map(|s| s.digest) {
            Some(crate::pe::authenticode::DigestState::Mismatch) => State::Disabled,
            Some(crate::pe::authenticode::DigestState::Verified) => State::Enabled,
            _ => State::Unknown,
        },
        // Unreachable for the rule set above, and Unknown is never a finding, so an
        // unrecognised id reports nothing rather than guessing at a field.
        _ => State::Unknown,
    }
}

/// Whether the rule is meaningful for this image at all.
///
/// Scoped per rule, following the precedent in `pe::packer`: an exemption suppresses only the
/// inference whose premise the evidence invalidates, never the whole analysis.
pub(crate) fn applies(id: &str, a: &crate::pe::PeAnalysis) -> bool {
    match id {
        // The CLR controls code generation for a managed assembly, so /GS, CFG, and CET are
        // not properties of the shipped file. ASLR, DEP, and signing still are.
        "gs" | "cfg" | "cet" | "safe-seh" => !a.is_managed,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CoverageEntry;
    use crate::pe::mitigations::Mitigations;

    fn entry(member: &str, f: impl FnOnce(&mut Mitigations), managed: bool) -> CoverageEntry {
        let mut m = Mitigations {
            aslr: State::Enabled,
            high_entropy_va: State::Enabled,
            dep: State::Enabled,
            cfg: State::Enabled,
            seh: State::Enabled,
            force_integrity: State::Enabled,
            appcontainer: State::Enabled,
            authenticode: State::Enabled,
            relocations: State::Enabled,
            gs: State::Enabled,
            safe_seh: State::Enabled,
            cet: State::Enabled,
        };
        f(&mut m);
        let mut pe = crate::pe::tests_support::analysis();
        pe.mitigations = m;
        pe.is_managed = managed;
        CoverageEntry {
            digests: None,
            copies: 1,
            pdb: None,
            vendor: None,
            member: member.to_string(),
            format: "pe".to_string(),
            size: 1024,
            strings: 10,
            imports: Vec::new(),
            import_source: String::new(),
            unix: None,
            unix_executable: false,
            pe: Some(pe),
        }
    }

    fn findings_of(entries: &[CoverageEntry]) -> Vec<PostureFinding> {
        let refs: Vec<&CoverageEntry> = entries.iter().collect();
        findings(&refs)
    }

    #[test]
    fn a_fully_hardened_image_produces_nothing() {
        let e = vec![entry("a.dll", |_| {}, false)];
        assert!(findings_of(&e).is_empty());
    }

    #[test]
    fn disabled_aslr_is_a_high_finding_naming_its_images() {
        let e = vec![
            entry("BIB.dll", |m| m.aslr = State::Disabled, false),
            entry("BIBUtils.dll", |m| m.aslr = State::Disabled, false),
            entry("fine.dll", |_| {}, false),
        ];
        let f = findings_of(&e);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "aslr");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].affected, 2);
        assert_eq!(f[0].members, vec!["BIB.dll", "BIBUtils.dll"]);
        assert!(
            !f[0].remediation.is_empty(),
            "a finding must say what to do"
        );
    }

    #[test]
    fn unknown_is_never_a_finding() {
        // The whole point: a mitigation the headers cannot determine must not be reported as
        // switched off. A managed assembly has no load config directory.
        let e = vec![entry(
            "managed.dll",
            |m| {
                m.gs = State::Unknown;
                m.cfg = State::Unknown;
                m.safe_seh = State::Unknown;
                m.cet = State::Unknown;
            },
            true,
        )];
        assert!(findings_of(&e).is_empty());
    }

    #[test]
    fn code_generation_rules_do_not_apply_to_managed_assemblies() {
        // Even when the flags read Disabled rather than Unknown, /GS and CFG are the CLR's
        // business for an IL assembly. ASLR and signing are still the file's own.
        let e = vec![entry(
            "managed.dll",
            |m| {
                m.gs = State::Disabled;
                m.cfg = State::Disabled;
                m.cet = State::Disabled;
                m.safe_seh = State::Disabled;
                m.aslr = State::Disabled;
            },
            true,
        )];
        let f = findings_of(&e);
        let ids: Vec<&str> = f.iter().map(|x| x.id.as_str()).collect();
        assert_eq!(ids, vec!["aslr"]);
    }

    #[test]
    fn one_finding_per_rule_not_per_image() {
        let e: Vec<CoverageEntry> = (0..100)
            .map(|i| {
                entry(
                    &format!("img{}.dll", i),
                    |m| m.authenticode = State::Disabled,
                    false,
                )
            })
            .collect();
        let f = findings_of(&e);
        assert_eq!(f.len(), 1, "100 unsigned images is one statement");
        assert_eq!(f[0].affected, 100, "the true count is kept");
        // Every one is recorded. Until 5.8.0 this stopped at 50, in scan order, and a reviewer
        // who read the stored 50 of 179 as representative had to retract the conclusion.
        assert_eq!(f[0].members.len(), 100, "the whole set is recorded");
    }

    #[test]
    fn the_member_list_is_still_bounded_against_a_pathological_input() {
        // Not "no cap": a crafted package could otherwise name every member of a 4,281-member
        // archive in every finding. The bound is far above any real build.
        let e: Vec<CoverageEntry> = (0..MEMBER_CAP + 10)
            .map(|i| {
                entry(
                    &format!("img{}.dll", i),
                    |m| m.authenticode = State::Disabled,
                    false,
                )
            })
            .collect();
        let f = findings_of(&e);
        assert_eq!(f[0].affected, MEMBER_CAP + 10, "the true count is kept");
        assert_eq!(f[0].members.len(), MEMBER_CAP);
    }

    #[test]
    fn worst_severity_first_then_breadth() {
        let e = vec![
            entry(
                "a.dll",
                |m| {
                    m.cet = State::Disabled;
                    m.dep = State::Disabled;
                },
                false,
            ),
            entry("b.dll", |m| m.cet = State::Disabled, false),
        ];
        let f = findings_of(&e);
        assert_eq!(f[0].id, "dep", "high before low");
        assert_eq!(f.last().unwrap().id, "cet");
    }

    #[test]
    fn an_image_that_did_not_parse_is_skipped() {
        let mut e = entry("data.bin", |m| m.aslr = State::Disabled, false);
        e.pe = None;
        let entries = vec![e];
        assert!(findings_of(&entries).is_empty());
    }
}
