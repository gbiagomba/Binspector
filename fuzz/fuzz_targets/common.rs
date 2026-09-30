//! Shared input shaping for the fuzz targets.
//!
//! `arbitrary` turns the engine's raw bytes into structured parameters, so the fuzzer
//! explores the option space (minimum length, which encodings are enabled) as well as
//! the byte space. Fuzzing only the bytes would leave those paths untested.

use arbitrary::{Arbitrary, Unstructured};

#[derive(Debug)]
pub struct StringsInput {
    pub min_len: usize,
    pub ascii: bool,
    pub utf16: bool,
    pub data: Vec<u8>,
}

impl<'a> Arbitrary<'a> for StringsInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // A zero min_len is rejected by the CLI, so the parser is only ever called
        // with at least 1; fuzzing 0 would report a difference that cannot occur.
        let min_len = (u8::arbitrary(u)? % 32) as usize + 1;
        let ascii = bool::arbitrary(u)?;
        let utf16 = bool::arbitrary(u)?;
        let data = u.arbitrary_iter::<u8>()?.collect::<arbitrary::Result<_>>()?;
        Ok(Self {
            min_len,
            // At least one extraction source must be on, which the CLI also enforces.
            ascii: ascii || !utf16,
            utf16,
            data,
        })
    }
}
