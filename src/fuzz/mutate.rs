//! Deterministic mutation engine for the differential fuzzer.
//!
//! Deterministic on purpose: a crash found in CI must be reproducible from the seed
//! alone, without shipping the offending input around.

/// A small xorshift PRNG. Reproducibility matters more than statistical quality.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        // A zero state would be a fixed point.
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }

    pub fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }
}

/// Values that disproportionately trigger edge cases in size and offset handling.
const INTERESTING: &[u8] = &[0x00, 0x01, 0x7F, 0x80, 0xFF];
const INTERESTING_U32: &[u32] = &[0, 1, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF, 0xFFFF_FFF0];

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Kind {
    BitFlip,
    ByteSet,
    InterestingByte,
    InterestingU32,
    Truncate,
    Extend,
    DuplicateChunk,
    RemoveChunk,
    SwapChunks,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::BitFlip => "bit-flip",
            Kind::ByteSet => "byte-set",
            Kind::InterestingByte => "interesting-byte",
            Kind::InterestingU32 => "interesting-u32",
            Kind::Truncate => "truncate",
            Kind::Extend => "extend",
            Kind::DuplicateChunk => "duplicate-chunk",
            Kind::RemoveChunk => "remove-chunk",
            Kind::SwapChunks => "swap-chunks",
        }
    }

    pub const ALL: &'static [Kind] = &[
        Kind::BitFlip,
        Kind::ByteSet,
        Kind::InterestingByte,
        Kind::InterestingU32,
        Kind::Truncate,
        Kind::Extend,
        Kind::DuplicateChunk,
        Kind::RemoveChunk,
        Kind::SwapChunks,
    ];
}

/// Produce one mutant. The input is never modified.
pub fn mutate(input: &[u8], rng: &mut Rng, max_len: usize) -> (Vec<u8>, Kind) {
    let kind = Kind::ALL[rng.below(Kind::ALL.len())];
    let mut out = input.to_vec();

    match kind {
        Kind::BitFlip if !out.is_empty() => {
            let i = rng.below(out.len());
            out[i] ^= 1u8 << rng.below(8);
        }
        Kind::ByteSet if !out.is_empty() => {
            let i = rng.below(out.len());
            out[i] = rng.byte();
        }
        Kind::InterestingByte if !out.is_empty() => {
            let i = rng.below(out.len());
            out[i] = INTERESTING[rng.below(INTERESTING.len())];
        }
        Kind::InterestingU32 if out.len() >= 4 => {
            let i = rng.below(out.len() - 3);
            let v = INTERESTING_U32[rng.below(INTERESTING_U32.len())];
            out[i..i + 4].copy_from_slice(&v.to_le_bytes());
        }
        Kind::Truncate if !out.is_empty() => {
            let keep = rng.below(out.len());
            out.truncate(keep);
        }
        Kind::Extend => {
            let add = 1 + rng.below(64);
            for _ in 0..add {
                if out.len() >= max_len {
                    break;
                }
                out.push(rng.byte());
            }
        }
        Kind::DuplicateChunk if !out.is_empty() => {
            let len = 1 + rng.below(out.len().min(256));
            let from = rng.below(out.len() - len + 1);
            let chunk = out[from..from + len].to_vec();
            let at = rng.below(out.len() + 1);
            if out.len() + chunk.len() <= max_len {
                out.splice(at..at, chunk);
            }
        }
        Kind::RemoveChunk if out.len() > 1 => {
            let len = 1 + rng.below(out.len() - 1);
            let from = rng.below(out.len() - len + 1);
            out.drain(from..from + len);
        }
        Kind::SwapChunks if out.len() >= 4 => {
            let half = out.len() / 2;
            let len = 1 + rng.below(half);
            let a = rng.below(half);
            let b = half + rng.below(out.len() - half - len + 1);
            for k in 0..len {
                if a + k < out.len() && b + k < out.len() {
                    out.swap(a + k, b + k);
                }
            }
        }
        // Falls through when the input is too small for the chosen mutation.
        _ => {}
    }

    if out.len() > max_len {
        out.truncate(max_len);
    }
    (out, kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_is_deterministic_for_a_seed() {
        let a: Vec<u64> = (0..5).map(|_| Rng::new(42).next_u64()).collect();
        assert!(a.iter().all(|v| *v == a[0]));
        let mut r1 = Rng::new(7);
        let mut r2 = Rng::new(7);
        for _ in 0..50 {
            assert_eq!(r1.next_u64(), r2.next_u64());
        }
    }

    #[test]
    fn rng_zero_seed_does_not_stick() {
        let mut r = Rng::new(0);
        assert_ne!(r.next_u64(), 0);
        assert_ne!(r.next_u64(), r.next_u64());
    }

    #[test]
    fn below_stays_in_range() {
        let mut r = Rng::new(1);
        for _ in 0..500 {
            assert!(r.below(10) < 10);
        }
        assert_eq!(r.below(0), 0);
    }

    #[test]
    fn mutation_is_reproducible_from_the_seed() {
        let input = b"the quick brown fox jumps".to_vec();
        let run = || {
            let mut rng = Rng::new(99);
            (0..20)
                .map(|_| mutate(&input, &mut rng, 4096).0)
                .collect::<Vec<_>>()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn mutation_never_modifies_the_input() {
        let input = b"original bytes".to_vec();
        let copy = input.clone();
        let mut rng = Rng::new(3);
        for _ in 0..200 {
            mutate(&input, &mut rng, 4096);
        }
        assert_eq!(input, copy);
    }

    #[test]
    fn mutation_respects_the_length_cap() {
        let input = vec![0u8; 100];
        let mut rng = Rng::new(5);
        for _ in 0..500 {
            let (m, _) = mutate(&input, &mut rng, 128);
            assert!(m.len() <= 128, "len was {}", m.len());
        }
    }

    #[test]
    fn handles_empty_and_tiny_inputs_without_panicking() {
        let mut rng = Rng::new(11);
        for input in [vec![], vec![0u8], vec![0u8, 1], vec![0u8, 1, 2]] {
            for _ in 0..200 {
                let (m, _) = mutate(&input, &mut rng, 64);
                assert!(m.len() <= 64);
            }
        }
    }

    #[test]
    fn every_mutation_kind_is_reachable() {
        let input: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let mut rng = Rng::new(2024);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..5000 {
            seen.insert(mutate(&input, &mut rng, 4096).1);
        }
        assert_eq!(seen.len(), Kind::ALL.len(), "unreached: {:?}", seen);
    }

    #[test]
    fn kind_names_are_distinct() {
        let names: std::collections::BTreeSet<&str> = Kind::ALL.iter().map(|k| k.name()).collect();
        assert_eq!(names.len(), Kind::ALL.len());
    }
}
