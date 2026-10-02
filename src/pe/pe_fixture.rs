//! A structurally real PE image, for tests on both sides of the crate boundary.
//!
//! Included with `#[path]` from `pe::tests_support` and from `tests/cli.rs`, which cannot reach
//! a `pub(crate)` item. One copy, because three separate hand-rolled fixtures had all stopped
//! at the `PE\0\0` signature and declared zero sections.

/// Bytes of a minimal but structurally real PE32+ image: one `.text` section marked
/// executable, with `payload` as that section's raw contents.
///
/// The previous fixtures stopped at the `PE\0\0` signature and declared zero sections.
/// goblin parses that, so it served for years, but it is not a shape any linker emits and
/// since 5.7.0 it is excluded by the `no-code-section` rule, which is correct: an image
/// with no executable section and no import directory holds no instructions. A fixture
/// that cannot carry a finding cannot test the rules that weigh findings.
pub fn pe_with_code(payload: &[u8]) -> Vec<u8> {
    const LFANEW: usize = 0x80;
    const COFF: usize = LFANEW + 4;
    const OPT: usize = COFF + 20;
    const OPT_SIZE: usize = 0xF0;
    const SECTIONS: usize = OPT + OPT_SIZE;
    const HEADERS_END: usize = SECTIONS + 40;
    // Where the section's bytes start, aligned the way a linker would align them.
    const RAW: usize = 0x400;
    const CODE_RVA: u32 = 0x1000;

    let mut pe = vec![0u8; RAW];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&(LFANEW as u32).to_le_bytes());
    pe[LFANEW..LFANEW + 4].copy_from_slice(b"PE\0\0");

    // COFF header. One section, and an optional header big enough to be PE32+.
    pe[COFF..COFF + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // amd64
    pe[COFF + 2..COFF + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
    pe[COFF + 16..COFF + 18].copy_from_slice(&(OPT_SIZE as u16).to_le_bytes());
    pe[COFF + 18..COFF + 20].copy_from_slice(&0x2022u16.to_le_bytes()); // dll, executable

    // Optional header, only the fields a parser needs to accept the image.
    pe[OPT..OPT + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+ magic
    pe[OPT + 16..OPT + 20].copy_from_slice(&CODE_RVA.to_le_bytes()); // entry point
    pe[OPT + 20..OPT + 24].copy_from_slice(&CODE_RVA.to_le_bytes()); // base of code
    pe[OPT + 24..OPT + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes()); // image base
    pe[OPT + 32..OPT + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section alignment
    pe[OPT + 36..OPT + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file alignment
    pe[OPT + 56..OPT + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // size of image
    pe[OPT + 60..OPT + 64].copy_from_slice(&(HEADERS_END as u32).to_le_bytes());
    pe[OPT + 68..OPT + 70].copy_from_slice(&2u16.to_le_bytes()); // windows-gui
    pe[OPT + 108..OPT + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

    // One section header: `.text`, code, executable, readable.
    let raw_size = payload.len().max(1) as u32;
    pe[SECTIONS..SECTIONS + 8].copy_from_slice(b".text\0\0\0");
    pe[SECTIONS + 8..SECTIONS + 12].copy_from_slice(&raw_size.to_le_bytes()); // virtual size
    pe[SECTIONS + 12..SECTIONS + 16].copy_from_slice(&CODE_RVA.to_le_bytes());
    pe[SECTIONS + 16..SECTIONS + 20].copy_from_slice(&raw_size.to_le_bytes());
    pe[SECTIONS + 20..SECTIONS + 24].copy_from_slice(&(RAW as u32).to_le_bytes());
    pe[SECTIONS + 36..SECTIONS + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    pe.extend_from_slice(payload);
    pe
}
