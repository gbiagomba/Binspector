//! Exploit mitigation flags read from the PE optional header.
//!
//! This is the highest-value part of the PE analysis for a reviewer. A banned
//! function found in a binary with ASLR, DEP, and Control Flow Guard all enabled is
//! a materially smaller problem than the same function in a binary with none of
//! them, and nothing in a string scan can tell you which you are looking at.

use goblin::pe::dll_characteristic as dc;
use serde::{Deserialize, Serialize};

/// `IMAGE_GUARD_CF_INSTRUMENTED`: the module is built with CFG checks.
const IMAGE_GUARD_CF_INSTRUMENTED: u32 = 0x0000_0100;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Enabled,
    Disabled,
    /// Not determinable from the headers alone.
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
}

impl Mitigations {
    pub fn from_pe(pe: &goblin::pe::PE) -> Self {
        let dll_chars = pe
            .header
            .optional_header
            .map(|oh| oh.windows_fields.dll_characteristics)
            .unwrap_or(0);

        let has = |flag: u16| dll_chars & flag != 0;

        // CFG lives in the load config directory, not in dll_characteristics. A PE
        // with no load config directory cannot be judged, hence Unknown rather than
        // Disabled: reporting a missing directory as "CFG off" would be a false claim.
        let cfg = match pe
            .load_config_data
            .as_ref()
            .and_then(|lc| lc.directory.guard_flags)
        {
            Some(flags) => State::from_flag(flags & IMAGE_GUARD_CF_INSTRUMENTED != 0),
            None => State::Unknown,
        };

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
        if self.seh == State::Disabled {
            out.push("No exception handler table (NO_SEH)");
        }
        if self.authenticode == State::Disabled {
            out.push("No Authenticode signature");
        }
        out
    }

    /// Count of enabled mitigations among the ones that are determinable.
    pub fn score(&self) -> (usize, usize) {
        let checks = [self.aslr, self.dep, self.cfg, self.seh, self.authenticode];
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
        };
        let w = m.weaknesses();
        assert!(w.iter().any(|s| s.contains("ASLR disabled")));
        assert!(w.iter().any(|s| s.contains("DEP disabled")));
        assert!(w.iter().any(|s| s.contains("Control Flow Guard")));
        assert!(w.iter().any(|s| s.contains("Authenticode")));
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
        };
        assert!(m.weaknesses().is_empty());
        assert_eq!(m.score(), (5, 5));
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
        };
        assert_eq!(m.score(), (3, 4));
    }
}
