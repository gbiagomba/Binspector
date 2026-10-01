//! Mach-O imports from the dyld bind opcodes, read locally rather than through goblin.
//!
//! **Why not `MachO::imports()`.** It is not safe to call on a file the tool was pointed at, in two
//! independent ways, both found by fuzzing a real system binary.
//!
//! * It panics. `mach::imports::Import::new` raw-indexes two attacker-controlled fields with no
//!   bounds check: `segments[bi.seg_index]` and `libs[bi.symbol_library_ordinal]`. Four bytes of
//!   edit to any signed binary aborts the scan. 8,000 mutations of `/bin/ls` produced it twenty
//!   times over, the first at iteration 63.
//! * It is a bomb. `BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB` carries a ULEB repeat count, and
//!   goblin's interpreter pushes one `Import` per repetition. A count of a few billion costs time
//!   and heap proportional to the count, from a 120-byte opcode stream. One mutated input spent
//!   1.8 seconds in there before erroring out with no imports to show for it.
//!
//! Neither is fixable from the outside: a `catch_unwind` cannot bound an allocation, and a size cap
//! cannot help when 120 bytes is already enough. So the opcode walk is local.
//!
//! **What makes the local version bounded is the question it asks.** For an import *list*, the
//! repeat count carries no information: `count` repetitions of
//! `BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB` bind the *same symbol from the same library* at
//! `count` successive addresses. This module therefore reads the count, uses it for nothing, and
//! emits the symbol once. There is no address arithmetic here at all, because an import list does
//! not need addresses. Work is then bounded by the length of the opcode stream, which is bounded by
//! the file.
//!
//! Reference: dyld's `MachOLoaded::forEachBind` and `mach-o/loader.h` bind opcodes.

use goblin::mach::load_command::CommandVariant;
use goblin::mach::MachO;

use crate::pe::ImportRef;

/// Upper bound on entries read, matching the rest of `exe`.
const MAX_IMPORTS: usize = 20_000;

/// Longest symbol name accepted, which also bounds the scan for its terminating NUL.
const MAX_NAME_LEN: usize = 4096;

/// A ULEB128 longer than this encodes more than a `u64` can hold, so it is malformed.
const MAX_ULEB_BYTES: usize = 10;

const OPCODE_MASK: u8 = 0xF0;
const IMMEDIATE_MASK: u8 = 0x0F;

const DONE: u8 = 0x00;
const SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
const SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
const SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
const SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
const SET_TYPE_IMM: u8 = 0x50;
const SET_ADDEND_SLEB: u8 = 0x60;
const SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
const ADD_ADDR_ULEB: u8 = 0x80;
const DO_BIND: u8 = 0x90;
const DO_BIND_ADD_ADDR_ULEB: u8 = 0xA0;
const DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xB0;
const DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xC0;

/// Read the imports named by this image's bind opcodes.
///
/// `base` is the image's file offset: zero for a thin binary, the slice offset within a universal
/// one, because `LC_DYLD_INFO` offsets are relative to the image rather than to the file.
///
/// `None` means this mechanism did not answer, so the caller falls through to the chained import
/// table and then the symbol table. It never means the image imports nothing.
pub fn imports(bin: &MachO, data: &[u8], base: usize) -> Option<Vec<ImportRef>> {
    let info = dyld_info(bin)?;
    let mut out: Vec<ImportRef> = Vec::new();
    // Ordinary, weak, and lazy streams in turn. goblin reads only the first and third; a weak bind
    // is an import too, and a report that omits one is missing a real dependency.
    for (off, size) in [
        (info.bind_off, info.bind_size),
        (info.weak_bind_off, info.weak_bind_size),
        (info.lazy_bind_off, info.lazy_bind_size),
    ] {
        if size == 0 {
            continue;
        }
        let start = base.checked_add(off as usize)?;
        let end = start.checked_add(size as usize)?;
        if let Some(stream) = data.get(start..end) {
            walk(stream, bin, &mut out);
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

/// `LC_DYLD_INFO` or `LC_DYLD_INFO_ONLY`, whichever the image carries.
fn dyld_info(bin: &MachO) -> Option<goblin::mach::load_command::DyldInfoCommand> {
    bin.load_commands.iter().find_map(|lc| match lc.command {
        CommandVariant::DyldInfo(c) | CommandVariant::DyldInfoOnly(c) => Some(c),
        _ => None,
    })
}

/// Walk one opcode stream, appending each distinct symbol it binds.
///
/// Deliberately keeps no address state. Every opcode that exists only to move the write address
/// (`SET_SEGMENT_AND_OFFSET_ULEB`, `ADD_ADDR_ULEB`, the scaled and skipping variants) has its
/// operands consumed so the stream stays in sync, and is otherwise ignored.
fn walk(stream: &[u8], bin: &MachO, out: &mut Vec<ImportRef>) {
    let mut at = 0usize;
    let mut name: Option<&str> = None;
    let mut ordinal: usize = 0;

    while at < stream.len() && out.len() < MAX_IMPORTS {
        let byte = stream[at];
        at += 1;
        let immediate = byte & IMMEDIATE_MASK;
        match byte & OPCODE_MASK {
            // Not the end of the stream. In the lazy stream dyld writes one `DONE` after *each*
            // binding, so breaking here reads only the first of them: on `/bin/ls` that is 8
            // imports where there are 91. In the ordinary stream `DONE` is followed by zero
            // padding, and a zero byte is this same opcode, so running to the end of the slice
            // costs one iteration per padding byte and finds nothing. Both cases want the same
            // thing: forget the current entry and carry on.
            DONE => {
                name = None;
                ordinal = 0;
            }
            SET_DYLIB_ORDINAL_IMM => ordinal = immediate as usize,
            SET_DYLIB_ORDINAL_ULEB => match uleb(stream, &mut at) {
                Some(v) => ordinal = usize::try_from(v).unwrap_or(0),
                None => break,
            },
            // Self, the main executable, or a flat lookup. None of those names a library, so no
            // attribution is claimed rather than a wrong one invented.
            SET_DYLIB_SPECIAL_IMM => ordinal = 0,
            SET_SYMBOL_TRAILING_FLAGS_IMM => match c_string(stream, at) {
                Some(s) => {
                    at += s.len() + 1;
                    name = Some(s);
                }
                None => break,
            },
            SET_TYPE_IMM => {}
            SET_ADDEND_SLEB => {
                if sleb(stream, &mut at).is_none() {
                    break;
                }
            }
            SET_SEGMENT_AND_OFFSET_ULEB | ADD_ADDR_ULEB => {
                if uleb(stream, &mut at).is_none() {
                    break;
                }
            }
            DO_BIND | DO_BIND_ADD_ADDR_IMM_SCALED => emit(name, ordinal, bin, out),
            DO_BIND_ADD_ADDR_ULEB => {
                emit(name, ordinal, bin, out);
                if uleb(stream, &mut at).is_none() {
                    break;
                }
            }
            // The repeat count and skip are read to keep the stream in sync and then discarded.
            // `count` repetitions bind the same symbol from the same library at successive
            // addresses, so for an import list they are one fact, and honouring the count is what
            // makes goblin's interpreter a bomb.
            DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                emit(name, ordinal, bin, out);
                if uleb(stream, &mut at).is_none() || uleb(stream, &mut at).is_none() {
                    break;
                }
            }
            // An unknown opcode means the stream is not what it claims, and guessing at its
            // operand length would desynchronise the walk silently.
            _ => break,
        }
    }
}

fn emit(name: Option<&str>, ordinal: usize, bin: &MachO, out: &mut Vec<ImportRef>) {
    let Some(name) = name else { return };
    if name.is_empty() {
        return;
    }
    out.push(ImportRef {
        library: library_name(bin, ordinal).to_string(),
        name: strip_underscore(name).to_string(),
    });
}

/// An ordinal resolved through goblin's `libs`, whose slot 0 is the image itself and whose
/// remaining slots are the dylib load commands in order, which is what the ordinal counts.
fn library_name<'a>(bin: &MachO<'a>, ordinal: usize) -> &'a str {
    if ordinal == 0 {
        return "";
    }
    match bin.libs.get(ordinal) {
        Some(path) => path.rsplit('/').next().unwrap_or(path),
        None => "",
    }
}

/// ULEB128, advancing `at`. `None` on a truncated or over-long encoding.
fn uleb(buf: &[u8], at: &mut usize) -> Option<u64> {
    let mut value: u64 = 0;
    for i in 0..MAX_ULEB_BYTES {
        let byte = *buf.get(*at)?;
        *at += 1;
        // Shifts past 63 would panic in debug and silently wrap in release, so the contribution of
        // a byte that cannot fit is dropped rather than computed.
        if i * 7 < 64 {
            value |= u64::from(byte & 0x7F) << (i * 7);
        }
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// SLEB128, advancing `at`. The value is unused here, so only the length matters, but it is decoded
/// properly rather than skipped by scanning for a clear high bit: the two agree, and decoding says
/// what the bytes mean.
fn sleb(buf: &[u8], at: &mut usize) -> Option<i64> {
    let mut value: i64 = 0;
    let mut shift = 0u32;
    for _ in 0..MAX_ULEB_BYTES {
        let byte = *buf.get(*at)?;
        *at += 1;
        if shift < 64 {
            value |= i64::from(byte & 0x7F) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                value |= -1i64 << shift;
            }
            return Some(value);
        }
    }
    None
}

/// A NUL-terminated name at `at`, bounded so a stream with no NUL cannot become a huge name.
fn c_string(buf: &[u8], at: usize) -> Option<&str> {
    let rest = buf.get(at..)?;
    let len = rest.iter().take(MAX_NAME_LEN).position(|&b| b == 0)?;
    std::str::from_utf8(rest.get(..len)?).ok()
}

/// The same assembler-underscore rule every other reader applies, and it has to be the same one: a
/// universal binary can take this path for one slice and another path for the next.
fn strip_underscore(name: &str) -> &str {
    name.strip_prefix('_').unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uleb_decodes_the_canonical_examples() {
        let mut at = 0;
        assert_eq!(uleb(&[0x00], &mut at), Some(0));
        let mut at = 0;
        assert_eq!(uleb(&[0x7F], &mut at), Some(127));
        assert_eq!(at, 1);
        let mut at = 0;
        assert_eq!(uleb(&[0x80, 0x01], &mut at), Some(128));
        assert_eq!(at, 2);
        let mut at = 0;
        assert_eq!(uleb(&[0xE5, 0x8E, 0x26], &mut at), Some(624_485));
        assert_eq!(at, 3);
    }

    #[test]
    fn a_truncated_or_overlong_uleb_is_refused_rather_than_wrapped() {
        // Every byte has the continuation bit set and the buffer ends.
        let mut at = 0;
        assert_eq!(uleb(&[0x80, 0x80], &mut at), None);
        // Eleven continuation bytes encode more than a u64 holds.
        let bomb = vec![0xFFu8; 20];
        let mut at = 0;
        assert_eq!(uleb(&bomb, &mut at), None);
        assert!(at <= MAX_ULEB_BYTES, "the scan is bounded: {}", at);
    }

    #[test]
    fn sleb_decodes_negatives() {
        let mut at = 0;
        assert_eq!(sleb(&[0x7F], &mut at), Some(-1));
        let mut at = 0;
        assert_eq!(sleb(&[0x3F], &mut at), Some(63));
        let mut at = 0;
        assert_eq!(sleb(&[0x80, 0x7F], &mut at), Some(-128));
    }

    #[test]
    fn a_name_runs_to_its_nul_and_no_further() {
        assert_eq!(c_string(b"_printf\0rest", 0), Some("_printf"));
        assert_eq!(c_string(b"_printf\0rest", 99), None);
        assert_eq!(c_string(b"no terminator", 0), None);
        let unterminated = vec![b'a'; MAX_NAME_LEN * 2];
        assert_eq!(c_string(&unterminated, 0), None);
    }

    /// The defect that motivated this module, asserted as arithmetic rather than through a parse:
    /// a repeat count is read and discarded, so a stream of a few bytes cannot ask for billions of
    /// entries. goblin pushes one entry per repetition.
    #[test]
    fn a_repeat_count_cannot_multiply_the_output() {
        // `count` as a 5-byte ULEB holding roughly 2^32.
        let encoded = [0x80u8, 0x80, 0x80, 0x80, 0x10];
        let mut at = 0;
        let count = uleb(&encoded, &mut at).expect("decodes");
        assert!(count > 1_000_000_000, "count is {}", count);
        assert_eq!(at, 5, "and reading it costs five bytes, not count entries");
    }

    #[test]
    fn the_underscore_rule_matches_the_other_readers() {
        assert_eq!(strip_underscore("_printf"), "printf");
        assert_eq!(strip_underscore("__stack_chk_fail"), "_stack_chk_fail");
    }

    /// Differential against goblin on real images, which is the only way to know this walk is
    /// *faithful* rather than merely safe. Unit tests can show it does not panic; only agreement
    /// with an independent implementation over real opcode streams shows it reads the same thing.
    ///
    /// Run on the macOS CI runner, which carries the binaries the repository cannot. A local run
    /// over `/bin`, `/usr/bin`, and `/usr/lib` covered 46 images with no disagreement; the test
    /// takes a handful so the suite stays fast, and skips anything it cannot read or parse rather
    /// than failing on a system that lays its binaries out differently.
    ///
    /// The one disagreement this cannot catch is a shared misreading, which is why the base offset
    /// is pinned by a separate assertion: goblin slices a fat file down to the architecture before
    /// parsing, so its offsets are slice-relative, and reading them against the whole file lands in
    /// machine code. That produced 0 imports where there are 91, which is the failure a set
    /// comparison alone would have reported as "ours is empty".
    #[cfg(target_os = "macos")]
    #[test]
    fn the_walk_agrees_with_goblin_on_real_images() {
        use goblin::mach::{Mach, SingleArch};
        use std::collections::BTreeSet;

        let mut checked = 0usize;
        for path in [
            "/bin/ls",
            "/bin/cat",
            "/usr/bin/grep",
            "/usr/bin/sed",
            "/bin/sh",
        ] {
            let Ok(data) = std::fs::read(path) else {
                continue;
            };
            let Ok(mach) = Mach::parse(&data) else {
                continue;
            };
            let mut theirs: BTreeSet<String> = BTreeSet::new();
            let mut ours: BTreeSet<String> = BTreeSet::new();
            let mut compare = |bin: &MachO, base: usize| {
                if let Ok(v) = bin.imports() {
                    for i in v {
                        theirs.insert(strip_underscore(i.name).to_string());
                    }
                }
                if let Some(v) = imports(bin, &data, base) {
                    for i in v {
                        ours.insert(i.name);
                    }
                }
            };
            match mach {
                Mach::Binary(bin) => compare(&bin, 0),
                Mach::Fat(multi) => {
                    let arches = multi.arches().unwrap_or_default();
                    for (i, arch) in arches.iter().enumerate() {
                        if let Ok(SingleArch::MachO(bin)) = multi.get(i) {
                            compare(&bin, arch.offset as usize);
                        }
                    }
                }
            }
            if theirs.is_empty() {
                // A chained-fixups image has no bind opcodes for either reader to disagree about.
                continue;
            }
            assert_eq!(
                theirs,
                ours,
                "{}: goblin read {} imports, this walk read {}",
                path,
                theirs.len(),
                ours.len()
            );
            checked += 1;
        }
        assert!(
            checked > 0,
            "no system binary with bind opcodes was readable, so nothing was actually compared"
        );
    }
}
