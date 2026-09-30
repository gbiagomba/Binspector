//! The report data model, shared by the scanner and every output format.

use serde::Serialize;

use crate::container::Format;
use crate::scan::banned::{Category, Severity};
use crate::scan::confidence::Confidence;
use crate::scan::strings::Encoding;

/// One banned function that matched, aggregated across the whole scan.
#[derive(Clone, Debug, Serialize)]
pub struct MatchSummary {
    pub function: String,
    pub severity: Severity,
    pub category: Category,
    pub occurrences: usize,
    /// Number of distinct members the function appeared in.
    pub members: usize,
    /// Occurrences excluded as low confidence (namespace or prose text).
    pub low_confidence: usize,
}

/// One concrete occurrence, with enough provenance to verify it by hand.
#[derive(Clone, Debug, Serialize)]
pub struct HitRecord {
    pub function: String,
    pub severity: Severity,
    pub category: Category,
    /// Provenance from the root inwards, joined with " :: ".
    pub member: String,
    /// Byte offset of the matched token within its member. Seek here to verify.
    pub offset: u64,
    /// Length of the matched token in member bytes (2 per character for UTF-16LE).
    pub token_len: usize,
    /// Byte offset of the containing string within its member.
    pub string_offset: u64,
    pub encoding: Encoding,
    pub confidence: Confidence,
    /// The containing string, possibly windowed for readability.
    pub context: String,
    /// Byte range of the match inside `context`.
    pub context_start: usize,
    pub context_end: usize,
}

/// What the walk actually opened, so a clean result can be distinguished from a
/// scan that never reached any real code.
#[derive(Clone, Debug, Serialize)]
pub struct CoverageEntry {
    pub member: String,
    pub format: String,
    pub size: u64,
    pub strings: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Coverage {
    pub root_format: String,
    pub members_scanned: usize,
    pub total_unpacked_bytes: u64,
    pub entries: Vec<CoverageEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub tool: &'static str,
    pub tool_version: &'static str,
    pub binary: String,
    pub project: Option<String>,
    pub timestamp: String,
    pub file_size: u64,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub min_len: usize,
    pub case_sensitive: bool,
    pub banned_list_size: usize,
    pub strings_total: usize,
    pub banned_hit_count: usize,
    pub summary: Vec<MatchSummary>,
    pub hits: Vec<HitRecord>,
    /// Total occurrences suppressed as low confidence.
    pub low_confidence_total: usize,
    /// Largest low-confidence contributors, so suppression stays auditable.
    pub low_confidence_top: Vec<(String, usize)>,
    /// Whether low-confidence hits were included in `summary` and `hits`.
    pub include_low_confidence: bool,
    pub coverage: Coverage,
    pub warnings: Vec<String>,
}

impl Report {
    pub fn severity_counts(&self) -> (usize, usize, usize) {
        let mut crit = 0;
        let mut high = 0;
        let mut med = 0;
        for s in &self.summary {
            match s.severity {
                Severity::Critical => crit += s.occurrences,
                Severity::High => high += s.occurrences,
                Severity::Medium => med += s.occurrences,
            }
        }
        (crit, high, med)
    }

    /// True when the walk reached at least one executable image. A clean result on
    /// a scan that never opened an executable is not evidence of safety.
    pub fn reached_executable(&self) -> bool {
        self.coverage
            .entries
            .iter()
            .any(|e| matches!(e.format.as_str(), "pe" | "elf" | "macho"))
    }
}

pub fn format_name(f: Format) -> String {
    f.as_str().to_string()
}
