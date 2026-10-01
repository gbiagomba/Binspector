//! Exploit mitigation flags read from the PE optional header.
//!
//! This is the highest-value part of the PE analysis for a reviewer. A banned
//! function found in a binary with ASLR, DEP, and Control Flow Guard all enabled is
//! a materially smaller problem than the same function in a binary with none of
//! them, and nothing in a string scan can tell you which you are looking at.

use goblin::pe::debug::IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT;
use goblin::pe::dll_characteristic as dc;
use serde::{Deserialize, Serialize};

/// `IMAGE_GUARD_CF_INSTRUMENTED`: the module is built with CFG checks.
const IMAGE_GUARD_CF_INSTRUMENTED: u32 = 0x0000_0100;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Enabled,
    Disabled,
    /// Not determinable from the headers alone. Also the `Default`, which is what the
    /// `#[serde(default)]` fields below fall back to: a 4.4.0 report never wrote gs,
    /// safe_seh, or cet, and defaulting those to Disabled would invent a finding.
    #[default]
    Unknown,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Enabled => "enabled",
            State::Disabled => "disabled",
            State::Unknown => "unknown",
        }
    }

    fn from_flag(set: bool) -> Self {
        if set {
            State::Enabled
        } else {
            State::Disabled
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mitigations {
    /// ASLR. `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`.
    pub aslr: State,
    /// 64-bit ASLR entropy. `HIGH_ENTROPY_VA`.
    pub high_entropy_va: State,
    /// DEP. `NX_COMPAT`.
    pub dep: State,
    /// Control Flow Guard. Present in the load config guard flags.
    pub cfg: State,
    /// Structured exception handling present. `NO_SEH` inverted.
    pub seh: State,
    /// Code integrity enforced. `FORCE_INTEGRITY`.
    pub force_integrity: State,
    /// Runs in an AppContainer sandbox.
    pub appcontainer: State,
    /// Authenticode signature present in the certificate table.
    pub authenticode: State,
    /// Relocation data present, which ASLR needs to be effective.
    pub relocations: State,
    /// Stack cookie. Load config `SecurityCookie`, which /GS populates.
    #[serde(default)]
    pub gs: State,
    /// SafeSEH. Load config `SEHandlerTable`, 32-bit images only.
    #[serde(default)]
    pub safe_seh: State,
    /// CET shadow stack. `IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT` in the extended
    /// DLL characteristics debug entry.
    #[serde(default)]
    pub cet: State,
}

/// /GS from the load config `SecurityCookie`.
///
/// A non-zero cookie means the compiler emitted one. A present directory with no cookie,
/// or a cookie of zero, means it did not. No load config directory at all is not evidence
/// either way, so it stays Unknown: a managed .NET assembly has no load config and
/// reporting it as "/GS off" would be a false claim.
fn gs_state(cookie: Option<u64>, has_load_config: bool) -> State {
    if !has_load_config {
        return State::Unknown;
    }
    State::from_flag(cookie.unwrap_or(0) != 0)
}

/// SafeSEH from the load config `SEHandlerTable` and `SEHandlerCount`.
///
/// Only 32-bit images carry a SafeSEH table. On 64-bit, exception handling is table-driven
/// through the exception directory and /SAFESEH does not apply, so neither Enabled nor
/// Disabled would be true and the state is Unknown. A 32-bit image with no load config
/// directory is likewise undeterminable.
fn safe_seh_state(
    handler_table: Option<u64>,
    handler_count: Option<u64>,
    is_64: bool,
    has_load_config: bool,
) -> State {
    if is_64 || !has_load_config {
        return State::Unknown;
    }
    let registered = handler_table.unwrap_or(0) != 0 && handler_count.unwrap_or(0) != 0;
    State::from_flag(registered)
}

/// CET shadow stack from the extended DLL characteristics debug entry (type 20).
///
/// `None` means the entry is absent, which says nothing about the toolchain's intent, so
/// it is Unknown rather than Disabled.
fn cet_state(cet_compat: Option<bool>) -> State {
    match cet_compat {
        Some(set) => State::from_flag(set),
        None => State::Unknown,
    }
}

impl Mitigations {
    pub fn from_pe(pe: &goblin::pe::PE) -> Self {
        let dll_chars = pe
            .header
            .optional_header
            .map(|oh| oh.windows_fields.dll_characteristics)
            .unwrap_or(0);

        let has = |flag: u16| dll_chars & flag != 0;

        let load_config = pe.load_config_data.as_ref().map(|lc| &lc.directory);

        // CFG lives in the load config directory, not in dll_characteristics. A PE
        // with no load config directory cannot be judged, hence Unknown rather than
        // Disabled: reporting a missing directory as "CFG off" would be a false claim.
        // gs and safe_seh read the same directory and follow the same rule.
        let cfg = match load_config.and_then(|d| d.guard_flags) {
            Some(flags) => State::from_flag(flags & IMAGE_GUARD_CF_INSTRUMENTED != 0),
            None => State::Unknown,
        };

        let cet_compat = pe
            .debug_data
            .as_ref()
            .and_then(|d| d.ex_dll_characteristics_info)
            .map(|x| x.characteristics_ex & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT != 0);

        Self {
            aslr: State::from_flag(has(dc::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)),
            high_entropy_va: State::from_flag(has(dc::IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)),
            dep: State::from_flag(has(dc::IMAGE_DLLCHARACTERISTICS_NX_COMPAT)),
            cfg,
            // NO_SEH set means SEH is absent, so the flag is inverted.
            seh: State::from_flag(!has(dc::IMAGE_DLLCHARACTERISTICS_NO_SEH)),
            force_integrity: State::from_flag(has(dc::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)),
            appcontainer: State::from_flag(has(dc::IMAGE_DLLCHARACTERISTICS_APPCONTAINER)),
            authenticode: State::from_flag(!pe.certificates.is_empty()),
            relocations: State::from_flag(pe.relocation_data.is_some()),
            gs: gs_state(
                load_config.and_then(|d| d.security_cookie),
                load_config.is_some(),
            ),
            safe_seh: safe_seh_state(
                load_config.and_then(|d| d.se_handler_table),
                load_config.and_then(|d| d.se_handler_count),
                pe.is_64,
                load_config.is_some(),
            ),
            cet: cet_state(cet_compat),
        }
    }

    /// Mitigations that are off and worth raising, as short human-readable notes.
    pub fn weaknesses(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.aslr == State::Disabled {
            out.push("ASLR disabled (no DYNAMIC_BASE): image loads at a predictable address");
        } else if self.relocations == State::Disabled {
            out.push("ASLR requested but no relocation data present, so it cannot apply");
        }
        if self.dep == State::Disabled {
            out.push("DEP disabled (no NX_COMPAT): data pages remain executable");
        }
        if self.cfg == State::Disabled {
            out.push("Control Flow Guard not instrumented: indirect calls are unchecked");
        }
        if self.gs == State::Disabled {
            out.push("No stack cookie (/GS): stack buffer overflows are not detected on return");
        }
        if self.safe_seh == State::Disabled {
            out.push("No SafeSEH table: an overwritten exception record can redirect execution");
        }
        if self.seh == State::Disabled {
            out.push("No exception handler table (NO_SEH)");
        }
        if self.authenticode == State::Disabled {
            out.push("No Authenticode signature");
        }
        // cet is deliberately not listed. Shadow-stack adoption is still young, so an image
        // without CET_COMPAT usually reflects its toolchain rather than a weak build, and
        // raising it next to "DEP disabled" would misrepresent its weight. It is reported in
        // the mitigation matrix only.
        out
    }

    /// Count of enabled mitigations among the ones that are determinable.
    pub fn score(&self) -> (usize, usize) {
        // gs counts: /GS applies to every native image whatever its bitness, so scoring it
        // compares like with like. safe_seh does not count, because it is meaningful only on
        // 32-bit images and would make the score a function of bitness instead of hardening.
        // cet does not count for the same reason it is not a weakness: too young to penalise.
        let checks = [
            self.aslr,
            self.dep,
            self.cfg,
            self.gs,
            self.seh,
            self.authenticode,
        ];
        let known = checks.iter().filter(|s| **s != State::Unknown).count();
        let on = checks.iter().filter(|s| **s == State::Enabled).count();
        (on, known)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_inverts_negative_flags_correctly() {
        assert_eq!(State::from_flag(true), State::Enabled);
        assert_eq!(State::from_flag(false), State::Disabled);
    }

    #[test]
    fn weaknesses_lists_each_disabled_mitigation() {
        let m = Mitigations {
            aslr: State::Disabled,
            high_entropy_va: State::Disabled,
            dep: State::Disabled,
            cfg: State::Disabled,
            seh: State::Disabled,
            force_integrity: State::Disabled,
            appcontainer: State::Disabled,
            authenticode: State::Disabled,
            relocations: State::Enabled,
            gs: State::Disabled,
            safe_seh: State::Disabled,
            cet: State::Disabled,
        };
        let w = m.weaknesses();
        assert!(w.iter().any(|s| s.contains("ASLR disabled")));
        assert!(w.iter().any(|s| s.contains("DEP disabled")));
        assert!(w.iter().any(|s| s.contains("Control Flow Guard")));
        assert!(w.iter().any(|s| s.contains("stack cookie")));
        assert!(w.iter().any(|s| s.contains("SafeSEH")));
        assert!(w.iter().any(|s| s.contains("Authenticode")));
        // CET is matrix-only and must never reach the findings list, even when Disabled.
        assert!(!w.iter().any(|s| s.contains("CET")));
    }

    #[test]
    fn fully_hardened_binary_reports_no_weakness() {
        let m = Mitigations {
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
        assert!(m.weaknesses().is_empty());
        assert_eq!(m.score(), (6, 6));
    }

    #[test]
    fn aslr_without_relocations_is_called_out() {
        let m = Mitigations {
            aslr: State::Enabled,
            high_entropy_va: State::Enabled,
            dep: State::Enabled,
            cfg: State::Enabled,
            seh: State::Enabled,
            force_integrity: State::Enabled,
            appcontainer: State::Enabled,
            authenticode: State::Enabled,
            relocations: State::Disabled,
            gs: State::Enabled,
            safe_seh: State::Enabled,
            cet: State::Enabled,
        };
        let w = m.weaknesses();
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("cannot apply"));
    }

    #[test]
    fn unknown_states_are_excluded_from_the_score() {
        let m = Mitigations {
            aslr: State::Enabled,
            high_entropy_va: State::Unknown,
            dep: State::Enabled,
            cfg: State::Unknown,
            seh: State::Enabled,
            force_integrity: State::Unknown,
            appcontainer: State::Unknown,
            authenticode: State::Disabled,
            relocations: State::Enabled,
            gs: State::Unknown,
            safe_seh: State::Unknown,
            cet: State::Unknown,
        };
        assert_eq!(m.score(), (3, 4));
    }

    #[test]
    fn safe_seh_and_cet_stay_out_of_the_score() {
        // Both Disabled, and the score is unchanged from the all-Unknown-extras case: only
        // gs may move it. This is what keeps a 64-bit image from being penalised for a
        // mitigation that cannot apply to it.
        let m = Mitigations {
            aslr: State::Enabled,
            high_entropy_va: State::Unknown,
            dep: State::Enabled,
            cfg: State::Unknown,
            seh: State::Enabled,
            force_integrity: State::Unknown,
            appcontainer: State::Unknown,
            authenticode: State::Disabled,
            relocations: State::Enabled,
            gs: State::Unknown,
            safe_seh: State::Disabled,
            cet: State::Disabled,
        };
        assert_eq!(m.score(), (3, 4));
    }

    #[test]
    fn missing_fields_default_to_unknown() {
        // A 4.4.0 report has no gs, safe_seh, or cet. Deserializing one must not invent
        // Disabled for them.
        assert_eq!(State::default(), State::Unknown);
    }

    #[test]
    fn gs_is_unknown_without_a_load_config_directory() {
        // A managed .NET assembly has no load config. "No /GS" would be a false claim.
        assert_eq!(gs_state(None, false), State::Unknown);
        // Even a cookie value cannot make it Enabled if the directory was never there.
        assert_eq!(gs_state(Some(0x1000), false), State::Unknown);
    }

    #[test]
    fn gs_is_disabled_when_the_directory_has_no_usable_cookie() {
        assert_eq!(gs_state(None, true), State::Disabled);
        assert_eq!(gs_state(Some(0), true), State::Disabled);
    }

    #[test]
    fn gs_is_enabled_for_a_non_zero_cookie() {
        assert_eq!(gs_state(Some(0x1400_0A000), true), State::Enabled);
    }

    #[test]
    fn safe_seh_is_unknown_on_a_64_bit_image() {
        // 64-bit SEH is table-based in the exception directory, so an absent handler table
        // is neither Enabled nor Disabled.
        assert_eq!(safe_seh_state(None, None, true, true), State::Unknown);
        assert_eq!(safe_seh_state(None, None, true, false), State::Unknown);
        // And a populated table on a 64-bit image still does not mean /SAFESEH.
        assert_eq!(
            safe_seh_state(Some(0x40_2000), Some(7), true, true),
            State::Unknown
        );
    }

    #[test]
    fn safe_seh_is_unknown_on_32_bit_without_a_load_config_directory() {
        assert_eq!(safe_seh_state(None, None, false, false), State::Unknown);
    }

    #[test]
    fn safe_seh_reads_the_handler_table_on_32_bit() {
        assert_eq!(
            safe_seh_state(Some(0x40_2000), Some(7), false, true),
            State::Enabled
        );
        assert_eq!(safe_seh_state(None, None, false, true), State::Disabled);
        assert_eq!(
            safe_seh_state(Some(0), Some(0), false, true),
            State::Disabled
        );
        // A table pointer with a zero count registers no handlers.
        assert_eq!(
            safe_seh_state(Some(0x40_2000), Some(0), false, true),
            State::Disabled
        );
    }

    #[test]
    fn cet_is_unknown_without_the_extended_characteristics_entry() {
        assert_eq!(cet_state(None), State::Unknown);
    }

    #[test]
    fn cet_follows_the_compat_bit_when_the_entry_is_present() {
        assert_eq!(cet_state(Some(true)), State::Enabled);
        assert_eq!(cet_state(Some(false)), State::Disabled);
    }
}
