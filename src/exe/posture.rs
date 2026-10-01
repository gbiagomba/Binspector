//! Exploit-mitigation posture for ELF and Mach-O, the non-PE half of `pe::posture`.
//!
//! `pe::posture` argues why a missing mitigation is a better finding than a banned name in a
//! byte range: it is attributable to a build flag and fixable by changing it. Nothing in that
//! argument is specific to Windows, and until this module existed the tool made it only for
//! Windows. An ELF with an executable stack and a Mach-O linked `-allow_stack_execute` were
//! both reported as hardened-by-silence.
//!
//! The split from `pe::posture` is structural. That reader works off `PeAnalysis`, which the
//! scan carries on every coverage entry; the other two formats have no equivalent, so `read`
//! takes the image's bytes and the scan hands the results back as
//! `(member, mitigations, is_executable_image)` triples. The ids are new for a related reason:
//! `aslr`, `dep`, `gs`, `cfg`, `safe-seh`, `authenticode`, and `cet` are a documented stable
//! filter surface naming specific PE header bits, and overloading `aslr` to also mean "ELF
//! PIE" would silently change what an existing `--filter aslr` selects.
//!
//! **`Unknown` is never a finding**, carried over verbatim from `pe::posture` and the reason
//! most of the logic below exists. Every one of these mitigations has a reading that means
//! "the headers do not say", and each of those must emit nothing rather than a hedged
//! low-severity note:
//!
//! * No `PT_GNU_STACK` program header. Modern kernels default to a non-executable stack, but
//!   the image does not say so, and "executable stack" would be an invented claim.
//! * No dynamic section, so RELRO and BIND_NOW have nothing to apply to.
//! * No dynamic symbols at all, so neither the stack canary nor the `_chk` fortify helpers
//!   can be looked for. A static or stripped binary is absence of evidence.
//! * `MH_PIE` on anything that is not `MH_EXECUTE`. A dylib and a bundle are
//!   position-independent by construction and do not set the bit.
//! * `MH_NO_HEAP_EXECUTION` on anything that is not 32-bit x86. See
//!   `macho_exec_heap_state`, which is the single sharpest edge in this file.
//!
//! **Deliberately absent: Mach-O hardened runtime and entitlements.** `CS_RUNTIME` is a flag
//! on the `CodeDirectory` blob inside the `CSMAGIC_EMBEDDED_SIGNATURE` SuperBlob, and goblin
//! exposes only that blob's offset and size, not its contents. Reading it means a from-scratch
//! big-endian SuperBlob parser over attacker-controlled bytes, which is a larger and riskier
//! piece of work than the rest of this module put together and belongs in its own reviewed
//! change rather than smuggled in here. The entitlement plist lives in another blob of the
//! same SuperBlob and is out for the same reason. So this module reports only whether a
//! signature is *present*, and claims nothing about what it asserts.

use goblin::elf::dynamic::{DF_1_NOW, DF_BIND_NOW, DT_BIND_NOW};
use goblin::elf::header::{ET_DYN, ET_EXEC};
use goblin::elf::program_header::{PT_GNU_RELRO, PT_GNU_STACK};
use goblin::elf::Elf;
use goblin::mach::cputype::CPU_TYPE_X86;
use goblin::mach::header::{MH_ALLOW_STACK_EXECUTION, MH_EXECUTE, MH_NO_HEAP_EXECUTION, MH_PIE};
use goblin::mach::load_command::CommandVariant;
use goblin::mach::{Mach, MachO, SingleArch};
use serde::{Deserialize, Serialize};

use super::UnixImports;
use crate::pe::mitigations::State;

/// The symbol every `-fstack-protector` build references when a canary check fails.
///
/// One name for both formats: the Mach-O table spells it `___stack_chk_fail`, and `exe::macho`
/// strips exactly one leading assembler underscore, leaving the two the C name genuinely has.
const STACK_CHK_FAIL: &str = "__stack_chk_fail";

/// Slice cap, shared with detection and `exe::macho`.
///
/// goblin bounds `nfat_arch` only by the file length over 20, so a 150 KiB file can claim 7,710
/// slices, and parsing each of them here is work a hostile header asked for. Fuzzing produced a
/// 3.9-second execution from one mutated input before this cap existed.
const MAX_FAT_ARCHES: usize = crate::container::detect::MAX_FAT_ARCHES as usize;

/// What one ELF or Mach-O member's headers say about its mitigations.
///
/// Every field defaults to `State::Unknown`, which is what makes the format split safe: an ELF
/// leaves the Mach-O-only fields alone and vice versa, and because Unknown is never a finding
/// neither is ever reported for a mitigation its format does not have. That is why there is no
/// `format` discriminant; adding one would be a second source of truth for the same fact.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UnixMitigations {
    /// Non-executable stack, from the ELF `PT_GNU_STACK` program header's `PF_X` bit.
    #[serde(default)]
    pub nx: State,
    /// Full RELRO: `PT_GNU_RELRO` plus BIND_NOW. Partial-only reads as `Disabled`.
    #[serde(default)]
    pub relro: State,
    /// Position-independent executable. ELF `ET_DYN`, or Mach-O `MH_PIE`.
    #[serde(default)]
    pub pie: State,
    /// Stack canary: `__stack_chk_fail` among the undefined symbols.
    #[serde(default)]
    pub canary: State,
    /// `_FORTIFY_SOURCE`: a `__*_chk` libc variant among the undefined symbols. ELF only.
    #[serde(default)]
    pub fortify: State,
    /// Non-executable stack on Mach-O, from `MH_ALLOW_STACK_EXECUTION` **inverted**.
    #[serde(default)]
    pub exec_stack: State,
    /// Non-executable heap on Mach-O, from `MH_NO_HEAP_EXECUTION`, 32-bit x86 only.
    #[serde(default)]
    pub exec_heap: State,
    /// An `LC_CODE_SIGNATURE` load command is present. Says nothing about what it asserts.
    #[serde(default)]
    pub code_signature: State,
}

/// Read an image's mitigations. `None` when the bytes are not ELF or Mach-O.
///
/// ELF first: its magic is four unambiguous bytes, where Mach-O has six accepted magics.
pub fn read(data: &[u8]) -> Option<UnixMitigations> {
    if let Some(found) = read_elf(data) {
        return Some(found);
    }
    read_macho(data)
}

/// Whether the image is a program the kernel loads rather than a library or object file.
///
/// Offered so the caller need not re-derive the `ET_DYN`-with-interpreter rule, which is the
/// easy part to get wrong: a PIE executable and a shared object are both `ET_DYN`, and only
/// `PT_INTERP` separates them. `false` for anything that is not ELF or Mach-O, which is the
/// safe answer because it suppresses rather than invents the rules this gates.
pub fn is_executable_image(data: &[u8]) -> bool {
    if data.starts_with(b"\x7fELF") {
        let Ok(elf) = Elf::parse(data) else {
            return false;
        };
        let t = elf.header.e_type;
        return t == ET_EXEC || (t == ET_DYN && elf.interpreter.is_some());
    }
    if !is_macho_magic(data) {
        return false;
    }
    match Mach::parse(data) {
        Ok(Mach::Binary(bin)) => bin.header.filetype == MH_EXECUTE,
        // A fat image is an executable when any slice is: the slices are the same program
        // built for different architectures, not different programs.
        Ok(Mach::Fat(multi)) => {
            for slice in (&multi).into_iter().take(MAX_FAT_ARCHES) {
                if matches!(slice, Ok(SingleArch::MachO(b)) if b.header.filetype == MH_EXECUTE) {
                    return true;
                }
            }
            false
        }
        Err(_) => false,
    }
}

// Per-mitigation decision logic, extracted so it can be tested without synthesising an ELF or
// a Mach-O. Follows `pe::mitigations`, which pulled `gs_state` and `safe_seh_state` out for the
// same reason: the interesting part of each is which inputs mean Unknown, and a hand-built
// fixture tests the fixture more than the rule.

/// `State` from a positive flag: set means the mitigation is on.
///
/// Local rather than `State::from_flag`, which is private to `pe::mitigations`. Also the honest
/// spelling for the two Mach-O flags, one of which must be inverted at its call site.
fn flag(set: bool) -> State {
    if set {
        State::Enabled
    } else {
        State::Disabled
    }
}

/// Non-executable stack from `PT_GNU_STACK`.
///
/// `None` is the absent-header case and must stay Unknown. Every current kernel defaults the
/// stack to non-executable when the header is missing, so Disabled would be wrong; but the
/// image makes no statement, so Enabled is unsupported too.
fn nx_state(gnu_stack_executable: Option<bool>) -> State {
    match gnu_stack_executable {
        Some(executable) => flag(!executable),
        None => State::Unknown,
    }
}

/// RELRO from `PT_GNU_RELRO` and BIND_NOW.
///
/// Three outcomes, not two. Full RELRO (segment plus BIND_NOW) is Enabled, because only then is
/// the GOT read-only once the dynamic linker has finished. Partial RELRO is Disabled: a
/// writable GOT is what the mitigation exists to prevent, and "partial" is no defence against
/// overwriting it. A static image has no dynamic section for any of it to apply to: Unknown.
fn relro_state(has_relro_segment: bool, bind_now: bool, has_dynamic: bool) -> State {
    if !has_dynamic {
        return State::Unknown;
    }
    if !has_relro_segment {
        return State::Disabled;
    }
    flag(bind_now)
}

/// PIE for an ELF.
///
/// goblin computes `is_pie` from `DF_1_PIE` internally and does not expose it, but folds it
/// into `is_lib`: `is_lib == (e_type == ET_DYN) && !is_pie`. So `is_lib` is how a genuine
/// shared object is told apart from a PIE executable here, and a library reports Unknown
/// because PIE is not a property a shared object can lack.
///
/// The error direction matters. A PIE executable whose linker omitted `DF_1_PIE` looks like a
/// library to goblin and so reports Unknown, costing a true positive nobody will miss. The
/// alternative, reading every `ET_DYN` without `DF_1_PIE` as a non-PIE executable, would file
/// a high-severity finding against every shared library on the system.
fn elf_pie_state(e_type: u16, is_lib: bool) -> State {
    if is_lib {
        return State::Unknown;
    }
    match e_type {
        ET_DYN => State::Enabled,
        ET_EXEC => State::Disabled,
        // ET_REL, ET_CORE, ET_NONE: not an image the kernel loads, so neither answer is true.
        _ => State::Unknown,
    }
}

/// Stack canary from the undefined symbols.
///
/// An empty symbol list is Unknown, not Disabled. A static or stripped binary may well be built
/// with `-fstack-protector-strong`, with the helper linked in rather than imported. Absence of
/// evidence is not evidence of absence, and Disabled here would file a false finding against
/// every static binary a scan opens.
fn canary_state(symbols: &[String]) -> State {
    if symbols.is_empty() {
        return State::Unknown;
    }
    flag(symbols.iter().any(|s| s == STACK_CHK_FAIL))
}

/// `_FORTIFY_SOURCE` from the undefined symbols.
///
/// The helpers are spelled `__<name>_chk`, so both ends of the name are required: a project
/// function called `validate_chk` is not evidence of a fortified libc. Same empty-list rule as
/// the canary, for the same reason.
fn fortify_state(symbols: &[String]) -> State {
    if symbols.is_empty() {
        return State::Unknown;
    }
    flag(
        symbols
            .iter()
            .any(|s| s.starts_with("__") && s.ends_with("_chk")),
    )
}

/// PIE for a Mach-O, gated on the file type.
///
/// `MH_PIE` is documented as meaningful only for `MH_EXECUTE`. `MH_DYLIB` and `MH_BUNDLE` are
/// position-independent by construction and routinely do not set the bit, so reading it as
/// "PIE off" for them would file a high-severity finding against every dylib on the system.
fn macho_pie_state(flags: u32, filetype: u32) -> State {
    if filetype != MH_EXECUTE {
        return State::Unknown;
    }
    flag(flags & MH_PIE != 0)
}

/// Non-executable stack for a Mach-O, from `MH_ALLOW_STACK_EXECUTION`.
///
/// **Inverted**, unlike every other flag here and unlike the whole PE convention in
/// `pe::mitigations`. This bit is an opt-*out*: it is set only when the link was told
/// `-allow_stack_execute`, and setting it switches the mitigation off, so the state is the
/// negation of the bit. Because it is an opt-out, absence is a real reading rather than
/// silence, which is why this one needs no Unknown case and the heap flag below does.
fn macho_exec_stack_state(flags: u32) -> State {
    flag(flags & MH_ALLOW_STACK_EXECUTION == 0)
}

/// Non-executable heap for a Mach-O, from `MH_NO_HEAP_EXECUTION`.
///
/// **Not inverted**, in direct contrast to `macho_exec_stack_state` immediately above. This bit
/// is an opt-*in*: set means the mitigation is on. The two flags sit in the same header word,
/// describe the same kind of protection, and run in opposite directions. Treating them alike is
/// the trap, and it fails silently in whichever direction you guessed.
///
/// It is also meaningful only on 32-bit x86, which is the second trap. Apple documents the flag
/// as affecting the i386 ABI; on x86_64 and on every arm64 variant the heap is non-executable
/// regardless and no current toolchain sets the bit. Reading absence as Disabled there would
/// file "executable heap" against every macOS binary in existence, Apple's own signed system
/// binaries included, which is exactly the invented finding the module rule forbids. So
/// anything that is not `CPU_TYPE_X86` is Unknown.
fn macho_exec_heap_state(flags: u32, cputype: u32) -> State {
    if cputype != CPU_TYPE_X86 {
        return State::Unknown;
    }
    flag(flags & MH_NO_HEAP_EXECUTION != 0)
}

/// Combine one mitigation's state across the slices of a universal binary.
///
/// A `Disabled` from any slice wins, on the same reasoning `exe::macho` uses to union imports:
/// a fat executable whose x86_64 slice loads at a fixed address is not position-independent,
/// whatever the arm64 slice does. An `Unknown` from one slice never erases a real reading from
/// another, which matters because the heap flag is Unknown on every non-x86-32 slice.
fn merge_state(a: State, b: State) -> State {
    if a == State::Disabled || b == State::Disabled {
        State::Disabled
    } else if a == State::Enabled || b == State::Enabled {
        State::Enabled
    } else {
        State::Unknown
    }
}

fn merge(a: &UnixMitigations, b: &UnixMitigations) -> UnixMitigations {
    UnixMitigations {
        nx: merge_state(a.nx, b.nx),
        relro: merge_state(a.relro, b.relro),
        pie: merge_state(a.pie, b.pie),
        canary: merge_state(a.canary, b.canary),
        fortify: merge_state(a.fortify, b.fortify),
        exec_stack: merge_state(a.exec_stack, b.exec_stack),
        exec_heap: merge_state(a.exec_heap, b.exec_heap),
        code_signature: merge_state(a.code_signature, b.code_signature),
    }
}

/// Undefined symbol names from one of the `exe` import readers.
///
/// Reuses `exe::elf::read` and `exe::macho::read` rather than re-deriving the undefined-symbol
/// predicate, which both document at length as easy to get wrong: `Sym::is_import()` is the
/// wrong ELF test, and `MachO::imports()` returns nothing on a chained-fixups binary.
fn symbol_names(found: Option<UnixImports>) -> Vec<String> {
    found
        .map(|u| u.imports.into_iter().map(|i| i.name).collect())
        .unwrap_or_default()
}

fn read_elf(data: &[u8]) -> Option<UnixMitigations> {
    if !data.starts_with(b"\x7fELF") {
        return None;
    }
    let elf = Elf::parse(data).ok()?;

    let mut gnu_stack_executable = None;
    let mut has_relro_segment = false;
    for ph in &elf.program_headers {
        if ph.p_type == PT_GNU_STACK {
            gnu_stack_executable = Some(ph.is_executable());
        } else if ph.p_type == PT_GNU_RELRO {
            has_relro_segment = true;
        }
    }

    // `DynamicInfo` has no `bind_now` field, so all three spellings are checked: the DT_FLAGS
    // bit, the DT_FLAGS_1 bit, and the standalone DT_BIND_NOW tag. Older linkers emit only the
    // tag, current ones only the flags, some both.
    let dynamic = elf.dynamic.as_ref();
    let bind_now = dynamic.is_some_and(|d| {
        d.info.flags & DF_BIND_NOW != 0
            || d.info.flags_1 & DF_1_NOW != 0
            || d.dyns.iter().any(|e| e.d_tag == DT_BIND_NOW)
    });

    let symbols = symbol_names(super::elf::read(data));

    Some(UnixMitigations {
        nx: nx_state(gnu_stack_executable),
        relro: relro_state(has_relro_segment, bind_now, dynamic.is_some()),
        pie: elf_pie_state(elf.header.e_type, elf.is_lib),
        canary: canary_state(&symbols),
        fortify: fortify_state(&symbols),
        // exec_stack, exec_heap, and code_signature are Mach-O header flags. Left Unknown so
        // an ELF is never reported for a mitigation its format does not have.
        ..UnixMitigations::default()
    })
}

fn read_macho(data: &[u8]) -> Option<UnixMitigations> {
    if !is_macho_magic(data) {
        return None;
    }
    let mach = Mach::parse(data).ok()?;
    // Read once for the whole file: `exe::macho::read` already unions the slices' symbols,
    // and the canary helper is linked per-slice from the same libSystem anyway.
    let symbols = symbol_names(super::macho::read(data));

    match mach {
        Mach::Binary(bin) => Some(from_macho_image(&bin, &symbols)),
        Mach::Fat(multi) => {
            let mut acc: Option<UnixMitigations> = None;
            for slice in (&multi).into_iter().take(MAX_FAT_ARCHES) {
                // A fat static library's slices are `ar` archives rather than Mach-O images,
                // so that arm is skipped rather than treated as an error, as in `exe::macho`.
                let Ok(SingleArch::MachO(bin)) = slice else {
                    continue;
                };
                let one = from_macho_image(&bin, &symbols);
                acc = Some(match acc {
                    Some(prev) => merge(&prev, &one),
                    None => one,
                });
            }
            // A fat file with no Mach-O slices is still Mach-O, so this reports all-Unknown
            // rather than `None`, which would mean "not one of these two formats": a different
            // and false statement.
            Some(acc.unwrap_or_default())
        }
    }
}

fn from_macho_image(bin: &MachO, symbols: &[String]) -> UnixMitigations {
    let signed = bin
        .load_commands
        .iter()
        .any(|lc| matches!(lc.command, CommandVariant::CodeSignature(_)));
    UnixMitigations {
        pie: macho_pie_state(bin.header.flags, bin.header.filetype),
        canary: canary_state(symbols),
        exec_stack: macho_exec_stack_state(bin.header.flags),
        exec_heap: macho_exec_heap_state(bin.header.flags, bin.header.cputype),
        code_signature: flag(signed),
        // nx, relro, and fortify stay Unknown. The first two are ELF program headers with no
        // Mach-O equivalent. fortify is left out on purpose: the `__*_chk` helpers do exist in
        // libSystem, but Apple's SDK headers enable the checks by default, so a binary with no
        // `_chk` import usually has no fortifiable call rather than an unfortified one, and the
        // symbol test cannot tell those apart.
        ..UnixMitigations::default()
    }
}

fn is_macho_magic(data: &[u8]) -> bool {
    matches!(
        data.get(..4),
        Some([0xFE, 0xED, 0xFA, 0xCE])
            | Some([0xCE, 0xFA, 0xED, 0xFE])
            | Some([0xFE, 0xED, 0xFA, 0xCF])
            | Some([0xCF, 0xFA, 0xED, 0xFE])
            | Some([0xCA, 0xFE, 0xBA, 0xBE])
            | Some([0xBE, 0xBA, 0xFE, 0xCA])
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exe::posture_rules::findings;
    use crate::model::PostureFinding;

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

    /// A hardened image with one mitigation switched off.
    fn off(f: impl FnOnce(&mut UnixMitigations)) -> UnixMitigations {
        let mut m = all(State::Enabled);
        f(&mut m);
        m
    }

    fn ids(f: &[PostureFinding]) -> Vec<&str> {
        f.iter().map(|x| x.id.as_str()).collect()
    }
    use goblin::elf::header::ET_REL;
    use goblin::mach::cputype::{CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_X86_64};
    use goblin::mach::header::{MH_BUNDLE, MH_DYLIB};

    fn syms(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn flag_is_positive_and_nx_is_unknown_without_the_header() {
        // The most load-bearing Unknown in the file. Current kernels default the stack to
        // non-executable, so Disabled would be a false claim; the image says nothing, so
        // Enabled would be unsupported.
        assert_eq!(flag(true), State::Enabled);
        assert_eq!(flag(false), State::Disabled);
        assert_eq!(nx_state(None), State::Unknown);
        assert_eq!(nx_state(Some(false)), State::Enabled);
        assert_eq!(nx_state(Some(true)), State::Disabled);
    }

    #[test]
    fn relro_needs_bind_now_to_count_as_full() {
        // No dynamic section, so there is nothing for RELRO to protect.
        assert_eq!(relro_state(false, false, false), State::Unknown);
        assert_eq!(relro_state(true, true, false), State::Unknown);
        assert_eq!(relro_state(true, true, true), State::Enabled);
        // Partial only: the segment is there, the GOT is still writable.
        assert_eq!(relro_state(true, false, true), State::Disabled);
        // No segment at all on a dynamic image is a real negative, not silence.
        assert_eq!(relro_state(false, true, true), State::Disabled);
    }

    #[test]
    fn elf_pie_reads_the_object_type_and_is_unknown_for_a_library() {
        // PIE is not a property a shared object can lack, so neither answer is true.
        assert_eq!(elf_pie_state(ET_DYN, true), State::Unknown);
        assert_eq!(elf_pie_state(ET_DYN, false), State::Enabled);
        assert_eq!(elf_pie_state(ET_EXEC, false), State::Disabled);
        // A relocatable object file is not an image the kernel loads.
        assert_eq!(elf_pie_state(ET_REL, false), State::Unknown);
    }

    #[test]
    fn canary_is_unknown_without_any_undefined_symbols() {
        // A static or stripped binary links the helper in rather than importing it, so an
        // empty symbol list is absence of evidence, not evidence of absence.
        assert_eq!(canary_state(&[]), State::Unknown);
        assert_eq!(fortify_state(&[]), State::Unknown);
    }

    #[test]
    fn canary_reads_stack_chk_fail() {
        assert_eq!(
            canary_state(&syms(&["malloc", STACK_CHK_FAIL])),
            State::Enabled
        );
        assert_eq!(canary_state(&syms(&["malloc", "write"])), State::Disabled);
    }

    #[test]
    fn fortify_reads_a_chk_variant() {
        assert_eq!(fortify_state(&syms(&["x", "__memcpy_chk"])), State::Enabled);
        assert_eq!(fortify_state(&syms(&["__sprintf_chk"])), State::Enabled);
        assert_eq!(fortify_state(&syms(&["malloc", "memcpy"])), State::Disabled);
        // The canary helper is not a fortify helper and must not be mistaken for one.
        assert_eq!(fortify_state(&syms(&[STACK_CHK_FAIL])), State::Disabled);
        // Both ends of the name are required, so a project function is not evidence.
        assert_eq!(fortify_state(&syms(&["validate_chk"])), State::Disabled);
    }

    #[test]
    fn macho_pie_is_unknown_for_anything_but_an_executable() {
        // A dylib and a bundle are position-independent by construction and do not set the
        // bit. Reading absence as "PIE off" would file a high finding against every dylib.
        assert_eq!(macho_pie_state(0, MH_DYLIB), State::Unknown);
        assert_eq!(macho_pie_state(0, MH_BUNDLE), State::Unknown);
        assert_eq!(macho_pie_state(MH_PIE, MH_EXECUTE), State::Enabled);
        assert_eq!(macho_pie_state(0, MH_EXECUTE), State::Disabled);
    }

    #[test]
    fn the_exec_stack_flag_is_inverted_in_both_directions() {
        // Set means the mitigation is OFF, the opposite of every other flag here.
        let on = MH_ALLOW_STACK_EXECUTION;
        assert_eq!(macho_exec_stack_state(on), State::Disabled);
        assert_eq!(macho_exec_stack_state(0), State::Enabled);
        // Unrelated bits in the same word must not move it.
        assert_eq!(macho_exec_stack_state(MH_PIE), State::Enabled);
        assert_eq!(macho_exec_stack_state(MH_PIE | on), State::Disabled);
    }

    #[test]
    fn the_exec_heap_flag_is_not_inverted() {
        // Set means the mitigation is ON, the opposite way round from the stack flag above.
        // Implement the two alike and exactly one of these two tests fails.
        let on = MH_NO_HEAP_EXECUTION;
        assert_eq!(macho_exec_heap_state(on, CPU_TYPE_X86), State::Enabled);
        assert_eq!(macho_exec_heap_state(0, CPU_TYPE_X86), State::Disabled);
    }

    #[test]
    fn exec_heap_is_unknown_off_32_bit_x86() {
        // The heap is non-executable regardless on x86_64 and arm64 and no toolchain sets the
        // bit there, so absence says nothing.
        for cpu in [CPU_TYPE_X86_64, CPU_TYPE_ARM64, CPU_TYPE_ARM] {
            assert_eq!(macho_exec_heap_state(0, cpu), State::Unknown);
            let set = macho_exec_heap_state(MH_NO_HEAP_EXECUTION, cpu);
            assert_eq!(set, State::Unknown);
        }
    }

    #[test]
    fn merging_slices_lets_a_disabled_one_win() {
        // A fat executable whose x86_64 slice is not PIE is not PIE.
        let d = State::Disabled;
        assert_eq!(merge_state(State::Enabled, d), d);
        assert_eq!(merge_state(d, State::Unknown), d);
        // And an Unknown slice never erases a real reading from another.
        assert_eq!(merge_state(State::Unknown, State::Enabled), State::Enabled);
        assert_eq!(merge_state(State::Unknown, State::Unknown), State::Unknown);
        // Whole-struct merge keeps each field independent.
        let merged = merge(&all(State::Enabled), &off(|m| m.nx = d));
        assert_eq!(merged.nx, d);
        assert_eq!(merged.relro, State::Enabled);
    }

    #[test]
    fn bytes_that_are_neither_format_are_declined_without_panicking() {
        assert!(read(b"").is_none());
        assert!(read(b"MZ\x90\x00 a PE, which pe::posture handles").is_none());
        assert!(read(b"not an executable of any kind, just text").is_none());
        assert!(!is_executable_image(b"just text"));
        for n in 4..96 {
            for magic in [&b"\x7fELF"[..], &[0xCF, 0xFA, 0xED, 0xFE][..]] {
                let mut v = magic.to_vec();
                v.resize(n, 0);
                let _ = read(&v);
                let _ = is_executable_image(&v);
            }
        }
        // A fat header claiming two slices that are not there.
        let mut fat = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02];
        fat.resize(40, 0);
        let _ = read(&fat);
        let _ = is_executable_image(&fat);
    }

    /// Real coverage comes from a system binary, the way `exe::elf` and `exe::macho` get
    /// theirs: the repository carries no ELF or Mach-O fixtures, and a hand-built one with a
    /// valid dynamic section and symbol table tests the fixture more than the reader.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_real_linux_binary_reads_as_hardened_where_it_is() {
        let Ok(data) = std::fs::read("/bin/sh") else {
            return;
        };
        let Some(m) = read(&data) else { return };

        // Every current distribution links /bin/sh with a non-executable stack.
        assert_eq!(m.nx, State::Enabled, "PT_GNU_STACK present without PF_X");
        // Dynamically linked, so the symbol-table and dynamic-section rules have something to
        // read and must not fall back to Unknown.
        assert_ne!(m.canary, State::Unknown, "a dynamic shell has dynsyms");
        assert_ne!(m.relro, State::Unknown, "and a DYNAMIC section");

        // The Mach-O-only fields must stay Unknown rather than default into a finding: this is
        // "Unknown is never a finding" checked against a real file rather than a fixture.
        assert_eq!(m.exec_stack, State::Unknown);
        assert_eq!(m.exec_heap, State::Unknown);
        assert_eq!(m.code_signature, State::Unknown);

        let is_exe = is_executable_image(&data);
        for f in &findings(&[("/bin/sh".to_string(), m, is_exe)]) {
            assert!(
                matches!(f.id.as_str(), "pie" | "relro" | "canary" | "fortify"),
                "unexpected finding on a system binary: {} ({})",
                f.id,
                f.evidence
            );
        }
    }

    /// `/bin/ls` is a signed universal binary built with chained fixups, so this exercises the
    /// fat path, the slice merge, and the symbol-table fallback as well as the flag readings.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_real_macos_binary_is_pie_signed_and_canaried() {
        let Ok(data) = std::fs::read("/bin/ls") else {
            return;
        };
        let Some(m) = read(&data) else { return };

        assert!(is_executable_image(&data), "/bin/ls is MH_EXECUTE");
        assert_eq!(m.pie, State::Enabled, "a system executable is PIE");
        assert_eq!(m.code_signature, State::Enabled, "and is signed");
        assert_eq!(
            m.exec_stack,
            State::Enabled,
            "MH_ALLOW_STACK_EXECUTION must not be set; Disabled here means the inversion is \
             the wrong way round"
        );
        assert_eq!(m.canary, State::Enabled, "libSystem supplies the helper");

        // The ELF-only fields stay Unknown, and so does the heap flag: it is meaningful only
        // on 32-bit x86, and reporting "executable heap" for an arm64 binary because a bit
        // nobody sets is clear is exactly the invented finding this module forbids.
        assert_eq!(m.nx, State::Unknown);
        assert_eq!(m.relro, State::Unknown);
        assert_eq!(m.fortify, State::Unknown);
        assert_eq!(
            m.exec_heap,
            State::Unknown,
            "an absent flag is not a finding"
        );

        let f = findings(&[("/bin/ls".to_string(), m, true)]);
        assert!(
            f.is_empty(),
            "a signed, PIE, canaried system binary should produce nothing, got {:?}",
            ids(&f)
        );
    }
}
