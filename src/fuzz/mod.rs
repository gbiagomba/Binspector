//! Fuzzing, in three modes that solve different problems.
//!
//! **Self-fuzzing** harnesses live in `src/bin/fuzz_*.rs`: AFL and honggfuzz targets
//! built with `arbitrary`, run against Binspector's own parsers. That is what protects
//! you when a hostile sample is the input. They are binaries of this crate rather than a
//! separate one, so an ordinary `cargo build` compiles them and a change to a library
//! type cannot break them unnoticed.
//!
//! **Parser-differential** ([`differential`]) mutates a review sample and feeds the
//! mutants to those same parsers in-process. It works on any host and never executes
//! the sample.
//!
//! **External engine orchestration** ([`engine`]) prepares and drives AFL++,
//! honggfuzz, libFuzzer, or WinAFL against a harness you supply, seeded from
//! [`corpus`]. The boundary is documented in `engine`: none of those engines can
//! blackbox-fuzz an arbitrary bundle without a harness and an entry point.

pub mod corpus;
pub mod differential;
pub mod engine;
pub mod input;
pub mod mutate;

pub use differential::{Campaign, Target};
pub use engine::Engine;
pub use input::StringsInput;
