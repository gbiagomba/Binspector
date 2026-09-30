//! Binspector: inspect binaries for banned C/C++ functions.
//!
//! The scan unpacks nested containers in memory, extracts printable strings with
//! their offsets, and matches banned function names with identifier-boundary
//! verification so a substring such as `targetsize` never counts as `gets`.

pub mod cli;
pub mod container;
pub mod hashing;
pub mod model;
pub mod report;
pub mod scan;
pub mod spool;
