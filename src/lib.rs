//! Binspector: inspect binaries for banned C/C++ functions.
//!
//! The scan unpacks nested containers in memory, writing members to disk only when asked, extracts printable strings with
//! their offsets, and matches banned function names with identifier-boundary
//! verification so a substring such as `targetsize` never counts as `gets`.

pub mod banner;
pub mod cli;
pub mod container;
pub mod exe;
pub mod fuzz;
pub mod hashing;
pub mod intel;
pub mod model;
pub mod observe;
pub mod pdb;
pub mod pe;
#[cfg(feature = "repl")]
pub mod repl;
pub mod report;
pub mod scan;
pub mod select;
pub mod spool;
