//! The report data model, shared by the scanner and every output format.

use serde::{Deserialize, Serialize};

use crate::container::Format;
use crate::pe::PeAnalysis;
use crate::scan::banned::{Category, Severity};
use crate::scan::confidence::Confidence;
use crate::scan::strings::Encoding;

/// One evidence rule that changed an occurrence's severity.
///
/// Recorded rather than applied silently. A reviewer who disagrees with a demotion can see
/// exactly which rule fired and on what, and `--include-excluded` restores what was removed.
/// Severity that changes without saying why is not auditable, and auditability is the only
/// reason the adjustment exists.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Adjustment {
    /// Stable identifier, safe to filter on: "symbol-definition", "read-only-primitive", and
    /// so on.
    pub rule: String,
    pub from: Severity,
    pub to: Severity,
    /// The specific evidence, such as the mangled symbol or "managed assembly, no native
    /// import".
    pub evidence: String,
}

/// One banned function that matched, aggregated across the whole scan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatchSummary {
    pub function: String,
    /// Worst adjusted severity among this function's reported occurrences.
    ///
    /// A roll-up, because evidence can give two occurrences of one name different
    /// severities. `--fail-on` and the aggregate counts read this.
    pub severity: Severity,
    /// What the function-family table says, independent of any evidence.
    ///
    /// `None` in a report written before 5.0.0, where `severity` *was* the unadjusted family
    /// value. Read it through `base_severity()`, which falls back accordingly rather than
    /// inventing a level.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_severity: Option<Severity>,
    pub category: Category,
    pub occurrences: usize,
    /// Number of distinct members the function appeared in.
    pub members: usize,
    /// Occurrences excluded as low confidence (namespace or prose text).
    pub excluded: usize,
}

/// One concrete occurrence, with enough provenance to verify it by hand.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HitRecord {
    pub function: String,
    /// Severity after the evidence rules. This is what writers sort and colour by.
    pub severity: Severity,
    /// What the function-family table says on the name alone, before evidence.
    ///
    /// `None` in a report written before 5.0.0. See `base_severity()`.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_severity: Option<Severity>,
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
    /// Every rule that changed this occurrence's severity, in the order they fired. Empty
    /// when the evidence changed nothing.
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub adjustments: Vec<Adjustment>,
}

impl MatchSummary {
    /// The family-table severity, falling back to `severity` for a pre-5.0.0 report where
    /// the two were the same thing.
    pub fn base_severity(&self) -> Severity {
        self.base_severity.unwrap_or(self.severity)
    }
}

impl HitRecord {
    /// The family-table severity, falling back to `severity` for a pre-5.0.0 report.
    pub fn base_severity(&self) -> Severity {
        self.base_severity.unwrap_or(self.severity)
    }

    /// Whether the evidence changed this occurrence's severity.
    pub fn was_adjusted(&self) -> bool {
        !self.adjustments.is_empty()
    }
}

/// A missing exploit mitigation, reported as a finding rather than as prose.
///
/// Separate from `summary` and `hits` on purpose: a mitigation has no function name, no byte
/// offset, no encoding, and no confidence, so putting it there would mean faking six fields
/// and making `banned_hit_count` mean two different things.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostureFinding {
    /// Stable id: "aslr", "dep", "gs", "cfg", "safe-seh", "authenticode", "cet".
    pub id: String,
    pub title: String,
    pub severity: Severity,
    /// How many images lack it. May exceed `members.len()`, which is capped.
    pub affected: usize,
    /// The images, capped so one finding cannot fill the report.
    pub members: Vec<String>,
    /// What was read, so the claim is checkable against the file.
    pub evidence: String,
    pub remediation: String,
}

/// What the walk actually opened, so a clean result can be distinguished from a
/// scan that never reached any real code.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoverageEntry {
    pub member: String,
    pub format: String,
    pub size: u64,
    pub strings: usize,
    /// Present when the member parsed as a PE image.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pe: Option<PeAnalysis>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Coverage {
    pub root_format: String,
    pub members_scanned: usize,
    pub total_unpacked_bytes: u64,
    pub entries: Vec<CoverageEntry>,
    /// Embedded signatures found by carving, per member. Empty unless --carve ran.
    pub carved: Vec<CarvedMember>,
    /// Whether carving ran, so an empty result is not read as "nothing embedded".
    pub carve_ran: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CarvedMember {
    pub member: String,
    pub items: Vec<crate::container::CarvedItem>,
    /// Checksums, certificates, and text markers, counted rather than listed.
    pub metadata_markers: usize,
    pub speculative: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    // Owned rather than &'static str so a report round-trips through JSON, which the
    // repl browser relies on.
    pub tool: String,
    pub tool_version: String,
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
    pub excluded_total: usize,
    /// Largest low-confidence contributors, so suppression stays auditable.
    pub excluded_top: Vec<(String, usize)>,
    /// Occurrences removed, per evidence rule, so none disappears without a named reason.
    ///
    /// Sums to `excluded_total`. `prose` is the long-standing confidence filter; the
    /// rest are the 5.0.0 evidence rules.
    #[serde(default)]
    pub excluded_by_rule: Vec<(String, usize)>,
    /// Whether low-confidence hits were included in `summary` and `hits`.
    pub include_excluded: bool,
    pub coverage: Coverage,
    /// Missing exploit mitigations. Empty when every parsed image is hardened, or when no
    /// image parsed.
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub posture: Vec<PostureFinding>,
    /// Indicators aggregated across every member.
    pub iocs: crate::pe::Iocs,
    /// Reputation and CVE enrichment. Empty unless explicitly requested.
    #[serde(default)]
    #[serde(skip_serializing_if = "crate::intel::Intel::is_empty")]
    pub intel: crate::intel::Intel,
    pub warnings: Vec<String>,
}

impl Report {
    /// Occurrences per severity, worst first: (critical, high, medium, low).
    pub fn severity_counts(&self) -> (usize, usize, usize, usize) {
        let mut crit = 0;
        let mut high = 0;
        let mut med = 0;
        let mut low = 0;
        for s in &self.summary {
            match s.severity {
                Severity::Critical => crit += s.occurrences,
                Severity::High => high += s.occurrences,
                Severity::Medium => med += s.occurrences,
                Severity::Low => low += s.occurrences,
            }
        }
        (crit, high, med, low)
    }

    /// Members that parsed as a PE, with their analysis.
    pub fn pe_members(&self) -> Vec<&CoverageEntry> {
        self.coverage
            .entries
            .iter()
            .filter(|e| e.pe.is_some())
            .collect()
    }

    /// Total embedded signatures carving found across every member.
    pub fn carved_total(&self) -> usize {
        self.coverage.carved.iter().map(|c| c.items.len()).sum()
    }

    /// Occurrences backed by a recorded PE import rather than embedded text.
    pub fn definitive_hits(&self) -> usize {
        self.hits
            .iter()
            .filter(|h| h.confidence.is_definitive())
            .count()
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
