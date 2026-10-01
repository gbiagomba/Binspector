//! Choosing what to scan: several named targets, or a directory walked for candidates.
//!
//! A top-level module rather than part of `container`, which is explicitly an in-memory
//! concern, or `scan`, which is about what to do once bytes are in hand. This is the only part
//! of the tool that touches the filesystem looking for work.

pub mod candidate;
pub mod label;
pub mod walk;

use std::path::PathBuf;

pub use walk::plan;

/// How a target came to be scanned, which decides whether a failure is fatal.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Origin {
    /// Named on the command line. A failure here is a hard error: a typo in a path must never
    /// be reported as a clean scan.
    Explicit,
    /// Found by walking a directory. A failure here is a warning, because one unreadable file
    /// must not discard the other 399 results.
    Discovered,
}

/// One file to scan.
#[derive(Clone, Debug)]
pub struct Target {
    pub path: PathBuf,
    /// Root of this target's provenance chain, so a finding reads
    /// `label :: inner.msix :: App.exe`. Unique across the plan.
    pub label: String,
    /// Filesystem-safe short name for a `--split` output file. Unique across the plan.
    pub slug: String,
    /// Path relative to the directory root it was found under.
    pub relative: String,
    pub origin: Origin,
    pub size: u64,
    /// Why it was selected: `magic:pe`, `extension:dmg`, `all-files`, or `explicit`.
    pub selected_by: String,
}

/// Fleet-level limits. Every one degrades to a warning plus partial results, never an error,
/// matching how `container::Budget` treats a decompression bomb.
#[derive(Clone, Debug)]
pub struct SelectConfig {
    /// Scan every file, not only executables and archives.
    pub all_files: bool,
    /// Directory nesting depth. Deliberately **not** `--max-depth`, which means container
    /// nesting and defaults to 4: vendored and staged trees routinely exceed four directories
    /// and reusing that cap would silently truncate the walk.
    pub max_dir_depth: usize,
    pub max_targets: usize,
    /// Total bytes read from disk across the run, which is a different quantity from the
    /// per-target unpacked cap and the real guard against being pointed at a filesystem root.
    pub max_input_bytes: u64,
    /// How much of each file to read when deciding. `detect` needs only a handful of bytes.
    pub sniff_bytes: usize,
}

impl Default for SelectConfig {
    fn default() -> Self {
        Self {
            all_files: false,
            max_dir_depth: 16,
            max_targets: 10_000,
            max_input_bytes: 64 * 1024 * 1024 * 1024,
            sniff_bytes: 4096,
        }
    }
}

/// The result of selection.
#[derive(Debug)]
pub struct Plan {
    pub targets: Vec<Target>,
    /// Non-fatal problems, folded into `Report.warnings` so they cannot be missed by someone
    /// reading only the report.
    pub warnings: Vec<String>,
    pub considered: usize,
    pub skipped: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_depth_cap_is_not_the_container_cap() {
        // Reusing --max-depth (4) for a filesystem walk would silently truncate any ordinary
        // vendored tree, which is the mistake this separate field exists to prevent.
        let c = SelectConfig::default();
        assert_eq!(c.max_dir_depth, 16);
        assert!(
            c.max_dir_depth > crate::container::Limits::default().max_depth,
            "a directory tree is routinely deeper than container nesting"
        );
    }

    #[test]
    fn defaults_are_generous_enough_not_to_fire_on_honest_input() {
        let c = SelectConfig::default();
        assert_eq!(c.max_targets, 10_000);
        assert_eq!(c.max_input_bytes, 64 * 1024 * 1024 * 1024);
        assert!(
            !c.all_files,
            "filtering is the default; --all-files opts out"
        );
    }
}
