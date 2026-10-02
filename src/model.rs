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

/// One target a report covers.
///
/// Present even for a single-target scan, with one entry, so no consumer has to special-case
/// arity. The scalar fields on `Report` (`binary`, `file_size`, the digests) are the first
/// target's, which for a single-target run is exactly the same thing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetInfo {
    /// Root of this target's provenance chain, so a finding reads
    /// `label :: inner.msix :: App.exe`. Unique across the report.
    pub label: String,
    /// Path on disk as reachable.
    pub path: String,
    pub file_size: u64,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub root_format: String,
    pub members_scanned: usize,
    pub total_unpacked_bytes: u64,
    pub strings_total: usize,
    pub banned_hit_count: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    /// Whether this target reached a PE, ELF, or Mach-O image. A clean result from a target
    /// that never reached real code is the failure this tool exists to prevent, so it is
    /// tracked per target and not only in aggregate.
    pub reached_executable: bool,
    /// Why it was selected: "magic:pe", "extension:dmg", "all-files", or "explicit".
    pub selected_by: String,
    /// This target's own warnings, unprefixed.
    pub warnings: Vec<String>,
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
    /// Imports read from this member, whatever its format.
    ///
    /// Carried on the entry rather than only inside `pe` so the import-evidence path works for
    /// ELF and Mach-O too. Before 5.2.0, `Confidence::Import` was derivable only from a PE import
    /// directory, which made `definitive_hits()` structurally zero for every Linux and macOS
    /// binary the tool scanned.
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<crate::pe::ImportRef>,
    /// How those imports were obtained: `pe-directory`, `elf-dynsym`, `macho-binds`,
    /// `macho-symtab`, or empty when none were read. Recorded because the mechanisms differ in
    /// whether they can attribute a symbol to a library.
    #[serde(default)]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub import_source: String,
    /// Exploit-mitigation posture for an ELF or Mach-O member.
    ///
    /// `None` for a PE, whose posture is `pe.mitigations`, and for anything that is neither.
    /// Separate from `pe.mitigations` because the two name different header bits: overloading
    /// `aslr` to also mean ELF PIE would silently change what an existing `--filter aslr`
    /// selects.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unix: Option<crate::exe::posture::UnixMitigations>,
    /// Whether this member is a main executable image.
    ///
    /// Carried because three of the Mach-O flags say nothing about a dylib or a bundle: the
    /// kernel reads them from the main executable's header only. See
    /// `exe::posture::is_executable_image`.
    #[serde(default)]
    #[serde(skip_serializing_if = "is_false")]
    pub unix_executable: bool,
}

/// Serde skip predicate for a `bool` that is false in the overwhelming majority of entries.
fn is_false(b: &bool) -> bool {
    !*b
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
    /// Every target this report covers, one entry even for a single-target scan.
    #[serde(default)]
    pub targets: Vec<TargetInfo>,
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
        // Summed from the per-target rollups, which count per occurrence.
        //
        // This read from `summary` until 5.8.0, and a summary row carries one severity for the
        // whole function while the evidence rules decide each occurrence separately. So every
        // occurrence of a function was attributed to that function's worst severity, and the
        // most prominent number in the report disagreed with its own occurrence table: 39
        // critical against the 33 in `hits`, because three `strcpy` and three `strcat`
        // occurrences had been demoted individually and the rollup could not see it.
        //
        // 5.7.0 fixed exactly this defect for the `targets[]` rollup and missed this caller, so
        // the two then disagreed with each other. Reading the target fields rather than
        // recomputing keeps one source of truth, and they stay complete when the occurrence cap
        // truncates `hits`.
        self.targets.iter().fold((0, 0, 0, 0), |(c, h, m, l), t| {
            (c + t.critical, h + t.high, m + t.medium, l + t.low)
        })
    }

    /// Occurrences a human-facing report lists.
    ///
    /// Excludes the bounded memory primitives, which are rolled up into a counted surface
    /// instead: one occurrence per function per member is a link-graph fact rather than a
    /// finding, and on a real bundle they are a third of the report.
    ///
    /// A single method rather than a filter repeated in each writer, because the predicate would
    /// otherwise drift across the five sites that iterate `hits`. The machine-readable formats
    /// deliberately do **not** call this: JSON, CSV, SQL, SQLite, and SARIF stay complete, so no
    /// consumer silently loses rows. That asymmetry is documented in `usage.md`.
    pub fn reported_hits(&self) -> impl Iterator<Item = &HitRecord> {
        self.hits
            .iter()
            .filter(|h| !crate::scan::crt_surface::is_rolled_up(&h.function))
    }

    /// Members that parsed as a PE, with their analysis.
    /// Whether the digests describe a manifest over several targets rather than one file.
    ///
    /// A digest over a *set* of files is not a file hash, so `finish_aggregate` deliberately leaves
    /// `md5` and `sha1` empty rather than filling them with something that looks like one. The
    /// writers have to know that, or they print `MD5:` with nothing after it and the report reads
    /// as broken. Reported as a user-visible bug on a ten-target run.
    pub fn is_manifest_digest(&self) -> bool {
        self.targets.len() > 1
    }

    pub fn pe_members(&self) -> Vec<&CoverageEntry> {
        self.coverage
            .entries
            .iter()
            .filter(|e| e.pe.is_some())
            .collect()
    }

    /// Members that carry ELF or Mach-O mitigation posture, which is the non-PE half.
    pub fn unix_members(&self) -> Vec<&CoverageEntry> {
        self.coverage
            .entries
            .iter()
            .filter(|e| e.unix.is_some())
            .collect()
    }

    /// Total embedded signatures carving found across every member.
    pub fn carved_total(&self) -> usize {
        self.coverage.carved.iter().map(|c| c.items.len()).sum()
    }

    /// Occurrences backed by a recorded PE import rather than embedded text.
    /// Occurrences counted once per distinct module name, function, and severity.
    ///
    /// The raw count is honest and routinely misread as a workload. A real 1,355-occurrence
    /// report held 754 distinct `(module, function, severity)` triples: 207 of 314
    /// Microsoft-redistributable occurrences were one module recompiled for another instruction
    /// set, and 9 of those were the same bytes scanned twice, because two architecture `.msix`
    /// members had the same sha256. Reviewing those is reviewing one thing.
    ///
    /// Derived from `hits`, so when the occurrence cap truncates the detail this undercounts.
    /// It is reported beside the complete raw number rather than instead of it.
    pub fn logical_findings(&self) -> usize {
        let mut seen = std::collections::BTreeSet::new();
        for h in self.reported_hits() {
            seen.insert((
                crate::report::fmt_util::short_name(&h.member).to_string(),
                h.function.as_str(),
                h.severity,
            ));
        }
        seen.len()
    }

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
