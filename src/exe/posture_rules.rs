//! The ELF and Mach-O posture rule table: what each missing mitigation is called, how bad it is,
//! and which images it applies to.
//!
//! Split out of `exe::posture` at the 1,000-line soft limit, along the seam that module's own
//! author identified: the readers there turn bytes into a `UnixMitigations`, and everything here
//! turns a `UnixMitigations` into findings. The two halves have no shared state and are tested
//! differently, the readers against real system binaries and the table against hand-built states.
//!
//! The ids are a documented stable filter surface, so they are new strings rather than overloads of
//! the PE set: making `aslr` also mean "ELF PIE" would silently change what an existing
//! `--filter aslr` selects. A test asserts they do not collide with `pe::posture`'s.

use super::posture::UnixMitigations;
use crate::model::PostureFinding;
use crate::pe::mitigations::State;
use crate::scan::banned::Severity;

/// Highest cap on members named in one finding. The rest are counted.
///
/// Same reasoning as `pe::posture::MEMBER_CAP`: a posture finding is a statement about a build
/// configuration, not about 179 individual files, so the list exists to let a reviewer start
/// somewhere rather than to be exhaustive. `affected` carries the true total.
const MEMBER_CAP: usize = 50;

/// Turn per-member mitigations into findings, one finding per mitigation listing its members.
///
/// One per mitigation rather than one per image, for the reason `pe::posture` gives: 179 images
/// with a writable GOT is a single statement about how the build was linked, and 179 findings
/// would bury everything else. The `bool` in each tuple is `is_executable_image`, which scopes
/// the rules that are meaningful only for a program the kernel loads. See `applies`.
pub fn findings(members: &[(String, UnixMitigations, bool)]) -> Vec<PostureFinding> {
    let mut out = Vec::new();
    for rule in rules() {
        let mut named: Vec<String> = Vec::new();
        for (member, m, is_exe) in members {
            if state_for(rule.id, m) == State::Disabled && applies(rule.id, *is_exe) {
                named.push(member.clone());
            }
        }
        if named.is_empty() {
            continue;
        }
        let total = named.len();
        named.truncate(MEMBER_CAP);
        out.push(PostureFinding {
            id: rule.id.to_string(),
            title: rule.title.to_string(),
            severity: rule.severity,
            affected: total,
            members: named,
            evidence: rule.evidence.to_string(),
            remediation: rule.remediation.to_string(),
        });
    }
    // Worst first, then breadth, then id, matching `pe::posture::findings` so a mixed report
    // reads the same way whichever format produced the finding.
    out.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then(b.affected.cmp(&a.affected))
            .then(a.id.cmp(&b.id))
    });
    out
}

/// One mitigation's rule: how bad its absence is, and what to say about it.
struct Rule {
    id: &'static str,
    title: &'static str,
    severity: Severity,
    evidence: &'static str,
    remediation: &'static str,
}

fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "nx",
            title: "Executable stack: stack data can be run as code",
            severity: Severity::High,
            evidence: "PT_GNU_STACK program header carries PF_X",
            remediation: "link with -Wl,-z,noexecstack, and give every hand-written assembly \
                          file a .note.GNU-stack marker so it stops forcing the flag on",
        },
        Rule {
            id: "exec-stack",
            title: "Executable stack allowed: the image opts out of stack NX",
            severity: Severity::High,
            evidence: "MH_ALLOW_STACK_EXECUTION set in the Mach-O header flags",
            remediation: "drop -Wl,-allow_stack_execute from the link",
        },
        Rule {
            id: "pie",
            title: "No PIE: the executable loads at a fixed address, so ASLR cannot apply",
            severity: Severity::High,
            evidence: "ELF e_type is ET_EXEC, or MH_PIE is absent from an MH_EXECUTE Mach-O",
            remediation: "compile with -fPIE and link with -pie",
        },
        Rule {
            id: "relro",
            title: "RELRO not full: the GOT stays writable after relocation",
            severity: Severity::Medium,
            evidence: "PT_GNU_RELRO absent, or present without BIND_NOW (no DF_BIND_NOW, \
                       DF_1_NOW, or DT_BIND_NOW in the dynamic section)",
            remediation: "link with -Wl,-z,relro,-z,now",
        },
        Rule {
            id: "canary",
            title: "No stack canary: a stack buffer overflow is not detected on return",
            severity: Severity::Medium,
            evidence: "the image has undefined symbols but __stack_chk_fail is not among them",
            remediation: "compile with -fstack-protector-strong",
        },
        Rule {
            id: "fortify",
            title: "No _FORTIFY_SOURCE: libc calls are not length-checked at runtime",
            severity: Severity::Medium,
            evidence: "the image has undefined symbols but no __*_chk libc variant \
                       (__memcpy_chk, __sprintf_chk) is among them",
            remediation: "compile with -D_FORTIFY_SOURCE=2 at -O2 or higher",
        },
        Rule {
            id: "exec-heap",
            title: "Executable heap allowed: heap data can be run as code",
            severity: Severity::Medium,
            evidence: "MH_NO_HEAP_EXECUTION absent from a 32-bit x86 Mach-O executable",
            remediation: "link with -Wl,-no_heap_execute, or drop the 32-bit x86 slice",
        },
        Rule {
            id: "macho-code-signature",
            title: "No code signature: the file's origin cannot be verified",
            severity: Severity::Medium,
            evidence: "no LC_CODE_SIGNATURE load command in the image",
            remediation: "codesign the shipped binaries, including third-party ones you rebuild",
        },
    ]
}

fn state_for(id: &str, m: &UnixMitigations) -> State {
    match id {
        "nx" => m.nx,
        "relro" => m.relro,
        "pie" => m.pie,
        "canary" => m.canary,
        "fortify" => m.fortify,
        "exec-stack" => m.exec_stack,
        "exec-heap" => m.exec_heap,
        "macho-code-signature" => m.code_signature,
        // Unreachable for the rule set above. Unknown rather than a panic or a guess, so an
        // unrecognised id reports nothing instead of inventing a finding.
        _ => State::Unknown,
    }
}

/// Whether the rule is meaningful for this image at all.
///
/// Scoped per rule the way `pe::posture::applies` is: an exemption suppresses only the
/// inference whose premise is invalid, never the whole analysis.
fn applies(id: &str, is_executable_image: bool) -> bool {
    match id {
        // PIE is not a property a shared object or a relocatable object can lack. The kernel
        // reads both Mach-O flags from the main executable's header only, and `ld` rejects
        // -allow_stack_execute for anything else, so neither says anything about a dylib.
        //
        // ELF `nx` is deliberately NOT in this list: the loader ORs PT_GNU_STACK across every
        // object it maps, so one shared library with an executable stack makes the whole
        // process's stack executable. That is the rule's best case, not an exception.
        "pie" | "exec-stack" | "exec-heap" => is_executable_image,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every mitigation set to one state, so a test names the reading it exercises rather than
    /// restating eight fields.
    fn all(s: State) -> UnixMitigations {
        UnixMitigations {
            nx: s,
            relro: s,
            pie: s,
            canary: s,
            fortify: s,
            exec_stack: s,
            exec_heap: s,
            code_signature: s,
        }
    }

    /// A hardened image with one mitigation switched off, following `pe::posture::tests`.
    fn off(f: impl FnOnce(&mut UnixMitigations)) -> UnixMitigations {
        let mut m = all(State::Enabled);
        f(&mut m);
        m
    }

    /// Findings for a single image. `is_exe` is `is_executable_image`.
    fn fire(m: UnixMitigations, is_exe: bool) -> Vec<PostureFinding> {
        findings(&[("app".to_string(), m, is_exe)])
    }

    fn ids(f: &[PostureFinding]) -> Vec<&str> {
        f.iter().map(|x| x.id.as_str()).collect()
    }

    fn sorted_ids(f: &[PostureFinding]) -> Vec<&str> {
        let mut v = ids(f);
        v.sort_unstable();
        v
    }

    #[test]
    fn a_fully_hardened_image_produces_nothing() {
        assert!(fire(all(State::Enabled), true).is_empty());
    }

    #[test]
    fn unknown_is_never_a_finding() {
        // The single most important rule in the module, and what every Unknown case above
        // exists to reach. A static, stripped ELF with no PT_GNU_STACK reads Unknown
        // throughout and must produce nothing at all, not a hedged low-severity note.
        assert!(fire(all(State::Unknown), true).is_empty());
        assert!(fire(all(State::Unknown), false).is_empty());
        // Including when mixed in with an image that does report something.
        let f = findings(&[
            ("static".to_string(), all(State::Unknown), true),
            ("app".to_string(), all(State::Disabled), true),
        ]);
        assert!(f
            .iter()
            .all(|x| x.members == vec!["app"] && x.affected == 1));
    }

    #[test]
    fn every_rule_fires_for_an_executable_with_everything_off() {
        assert_eq!(
            sorted_ids(&fire(all(State::Disabled), true)),
            vec![
                "canary",
                "exec-heap",
                "exec-stack",
                "fortify",
                "macho-code-signature",
                "nx",
                "pie",
                "relro",
            ]
        );
    }

    #[test]
    fn the_executable_only_rules_do_not_apply_to_a_library() {
        // PIE, and both Mach-O flags the kernel reads from the main executable only. ELF `nx`
        // is deliberately NOT exempt: the loader ORs PT_GNU_STACK across every object it maps,
        // so a library with an executable stack is that rule's most useful case.
        assert_eq!(
            sorted_ids(&fire(all(State::Disabled), false)),
            vec!["canary", "fortify", "macho-code-signature", "nx", "relro"]
        );
    }

    #[test]
    fn each_mitigation_maps_to_its_own_id_at_its_own_severity() {
        // High is reserved for the three that make data pages runnable or remove ASLR
        // outright. The rest are medium: real defects, but not on their own a way in.
        let h = Severity::High;
        let m = Severity::Medium;
        let cs = "macho-code-signature";
        for (img, id, sev) in [
            (off(|x| x.nx = State::Disabled), "nx", h),
            (off(|x| x.exec_stack = State::Disabled), "exec-stack", h),
            (off(|x| x.pie = State::Disabled), "pie", h),
            (off(|x| x.relro = State::Disabled), "relro", m),
            (off(|x| x.canary = State::Disabled), "canary", m),
            (off(|x| x.fortify = State::Disabled), "fortify", m),
            (off(|x| x.exec_heap = State::Disabled), "exec-heap", m),
            (off(|x| x.code_signature = State::Disabled), cs, m),
        ] {
            let f = fire(img, true);
            assert_eq!(ids(&f), vec![id], "one field must fire exactly one rule");
            assert_eq!(f[0].severity, sev, "{} has the wrong severity", id);
        }
    }

    #[test]
    fn one_finding_per_mitigation_not_per_image() {
        let members: Vec<(String, UnixMitigations, bool)> = (0..100)
            .map(|i| {
                let m = off(|m| m.code_signature = State::Disabled);
                (format!("img{}", i), m, true)
            })
            .collect();
        let f = findings(&members);
        assert_eq!(f.len(), 1, "100 unsigned images is one statement");
        assert_eq!(f[0].affected, 100, "the true total is kept");
        assert_eq!(f[0].members.len(), MEMBER_CAP, "the named list is capped");
        assert_eq!(
            f[0].members[0], "img0",
            "the cap truncates, it does not sample"
        );
    }

    #[test]
    fn worst_severity_first_then_breadth_then_id() {
        let wide = off(|m| {
            m.nx = State::Disabled;
            m.canary = State::Disabled;
            m.relro = State::Disabled;
        });
        let narrow = off(|m| m.canary = State::Disabled);
        let f = findings(&[
            ("a".to_string(), wide, true),
            ("b".to_string(), narrow, true),
        ]);
        // nx is High, so it leads. Then the Mediums widest first: canary covers two images,
        // relro one.
        assert_eq!(ids(&f), vec!["nx", "canary", "relro"]);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!((f[1].affected, f[2].affected), (2, 1));

        // Equal severity and equal breadth tie-break on the id, so the order is stable.
        let tied = off(|m| {
            m.canary = State::Disabled;
            m.fortify = State::Disabled;
            m.exec_heap = State::Disabled;
        });
        assert_eq!(
            ids(&fire(tied, true)),
            vec!["canary", "exec-heap", "fortify"]
        );
    }

    #[test]
    fn the_rule_table_is_well_formed_and_does_not_overload_a_pe_id() {
        // The PE ids are a documented stable filter surface. Overloading one here would
        // silently change what an existing --filter selects.
        let pe = [
            "aslr",
            "dep",
            "gs",
            "cfg",
            "safe-seh",
            "authenticode",
            "cet",
        ];
        let mut seen: Vec<&str> = Vec::new();
        for rule in rules() {
            assert!(!pe.contains(&rule.id), "{} overloads a PE id", rule.id);
            assert!(!seen.contains(&rule.id), "{} is declared twice", rule.id);
            assert!(!rule.title.is_empty(), "{} has no title", rule.id);
            assert!(!rule.evidence.is_empty(), "{} names no evidence", rule.id);
            let fix = rule.remediation;
            assert!(!fix.is_empty(), "{} names no fix", rule.id);
            // Every rule must be reachable through `state_for`, or it can never fire.
            assert_ne!(
                state_for(rule.id, &all(State::Disabled)),
                State::Unknown,
                "{} is not wired to a field",
                rule.id
            );
            seen.push(rule.id);
        }
        // And an id that is not in the table reports nothing rather than guessing at a field.
        assert_eq!(
            state_for("no-such-rule", &all(State::Disabled)),
            State::Unknown
        );
    }
}
