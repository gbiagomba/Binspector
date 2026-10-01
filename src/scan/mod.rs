//! Scan orchestration: unpack once, extract strings, match, aggregate.

pub mod banned;
pub mod confidence;
pub mod evidence;
pub mod matcher;
pub mod strings;

use anyhow::Result;
use regex::Regex;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use crate::container::{self, Limits};
use crate::hashing;
use crate::intel;
use crate::model::{CarvedMember, Coverage, CoverageEntry, HitRecord, MatchSummary, Report};
use crate::observe::{level, Event, Observer};
use crate::pe::{ioc, loader as pe_loader, PeAnalysis};
use crate::spool::{Spool, SpoolReader};
use banned::{BannedList, Severity};
use confidence::Confidence;
use matcher::Matcher;

/// Bare module-name strings kept per image. Enough to give a reviewer a place to start;
/// a large image can carry hundreds and an inventory is not the point.
const UNQUALIFIED_MODULE_CAP: usize = 20;

#[derive(Clone, Debug)]
pub struct ScanConfig {
    pub project: Option<String>,
    pub min_len: usize,
    pub ascii: bool,
    pub utf16: bool,
    pub case_sensitive: bool,
    pub banned_list: Option<PathBuf>,
    pub banned_filter: Option<Regex>,
    pub limits: Limits,
    /// Spool every extracted string so dump-capable formats can stream it.
    pub dump: bool,
    /// Upper bound on individually recorded occurrences, to bound memory.
    pub max_hits: usize,
    /// Characters of surrounding text kept with each hit.
    pub context_window: usize,
    /// Report low-confidence hits (namespace segments, documentation prose) too.
    pub include_low_confidence: bool,
    /// Parse PE members for headers, sections, imports, and mitigations.
    pub analyze_pe: bool,
    /// Maximum indicators of each kind to collect.
    pub ioc_cap: usize,
    /// Detect third-party components and versions from strings. Offline.
    pub detect_components: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            project: None,
            min_len: 4,
            ascii: true,
            utf16: true,
            case_sensitive: false,
            banned_list: None,
            banned_filter: None,
            limits: Limits::default(),
            dump: false,
            max_hits: 100_000,
            context_window: 120,
            include_low_confidence: false,
            analyze_pe: true,
            ioc_cap: 500,
            detect_components: true,
        }
    }
}

pub struct ScanOutput {
    pub report: Report,
    /// Present only when `dump` was requested.
    pub spool: Option<SpoolReader>,
}

/// Per-pattern accumulator.
#[derive(Default)]
struct Agg {
    occurrences: usize,
    members: HashSet<String>,
    low_confidence: usize,
    /// Worst adjusted severity seen for this function. `None` until a hit is kept.
    ///
    /// Needed because evidence can give two occurrences of one name different severities, so
    /// the summary row cannot simply copy the family value any more.
    worst: Option<Severity>,
}

pub fn run(path: &Path, cfg: &ScanConfig, observer: &dyn Observer) -> Result<ScanOutput> {
    let started = std::time::Instant::now();
    observer.on(&Event::Phase {
        name: "loading banned list",
    });
    let list = BannedList::load(cfg.banned_list.as_deref(), cfg.banned_filter.as_ref())?;
    let names = list.names();
    let matcher = Matcher::new(&names, !cfg.case_sensitive)?;

    // Read once: the digests and the walk share the same bytes.
    let data =
        std::fs::read(path).map_err(|e| anyhow::anyhow!("reading {}: {}", path.display(), e))?;
    observer.on(&Event::Phase { name: "hashing" });
    let digests = hashing::digests(&data);
    let file_size = data.len() as u64;
    let root_name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string());

    let mut agg: BTreeMap<usize, Agg> = BTreeMap::new();
    let mut hits: Vec<HitRecord> = Vec::new();
    let mut strings_total = 0usize;
    let mut coverage_entries: Vec<CoverageEntry> = Vec::new();
    let mut hit_cap_reached = false;
    let mut low_confidence_total = 0usize;
    // Per-rule exclusion tally, so no occurrence can disappear without a named reason.
    let mut excluded_by_rule: BTreeMap<String, usize> = BTreeMap::new();
    let mut iocs = ioc::Extractor::new(cfg.ioc_cap);
    let mut components = intel::components::Detector::new(200);
    let mut spool = if cfg.dump { Some(Spool::new()?) } else { None };

    observer.on(&Event::Phase {
        name: "unpacking and scanning",
    });
    let walk_started = std::time::Instant::now();
    let outcome = container::walk_bytes(
        &data,
        root_name,
        cfg.limits.clone(),
        observer,
        &mut |member| -> Result<()> {
            let member_name = member.chain_display();
            let mut pe = if cfg.analyze_pe && member.format == crate::container::Format::Pe {
                PeAnalysis::parse(member.data)
            } else {
                None
            };

            // An entry in the import directory is direct evidence that the binary calls
            // the function, so it outranks anything inferred from embedded text. Imports
            // are recorded first, and string matches for the same function are then
            // skipped so one fact is not counted twice.
            if let Some(a) = pe.as_ref() {
                observer.on(&Event::Pe {
                    member: &member_name,
                    parsed: true,
                    managed: a.is_managed,
                    mitigations_off: a.mitigations.weaknesses().len(),
                });
            } else if member.format == crate::container::Format::Pe {
                observer.on(&Event::Pe {
                    member: &member_name,
                    parsed: false,
                    managed: false,
                    mitigations_off: 0,
                });
            }

            let mut imported: HashSet<String> = HashSet::new();
            if let Some(analysis) = pe.as_ref() {
                for (id, entry) in list.entries.iter().enumerate() {
                    let dll = match analysis.importing_dll(&entry.name) {
                        Some(d) => d.to_string(),
                        None => continue,
                    };
                    imported.insert(entry.name.to_ascii_lowercase());
                    let agg_entry = agg.entry(id).or_default();
                    // An import is never excluded: it is a linker-recorded fact. It can
                    // still be demoted, because `strlen` cannot overflow a buffer however it
                    // got into the binary.
                    let ruling = evidence::adjudicate(&evidence::Observation {
                        function: &entry.name,
                        base_severity: entry.severity,
                        confidence: Confidence::Import,
                        text: &entry.name,
                        start: 0,
                        end: entry.name.len(),
                        member_format: member.format,
                        is_managed: analysis.is_managed,
                        imports_known: true,
                    });
                    let (imp_severity, imp_adjustments) = match &ruling {
                        evidence::Ruling::Keep {
                            severity,
                            adjustments,
                        } => (
                            *severity,
                            adjustments
                                .iter()
                                .map(|a| crate::model::Adjustment {
                                    rule: a.rule.to_string(),
                                    from: a.from,
                                    to: a.to,
                                    evidence: a.evidence.clone(),
                                })
                                .collect::<Vec<_>>(),
                        ),
                        // Unreachable: every exclusion rule requires a non-definitive
                        // confidence. Kept explicit so a future rule cannot silently drop an
                        // import, which is the strongest evidence the tool has.
                        evidence::Ruling::Exclude { .. } => (entry.severity, Vec::new()),
                    };
                    agg_entry.occurrences += 1;
                    agg_entry.members.insert(member_name.clone());
                    agg_entry.worst = match agg_entry.worst {
                        Some(w) if w <= imp_severity => Some(w),
                        _ => Some(imp_severity),
                    };
                    observer.on(&Event::Hit {
                        function: &entry.name,
                        member: &member_name,
                        confidence: Confidence::Import,
                    });
                    if hits.len() < cfg.max_hits {
                        hits.push(HitRecord {
                            function: entry.name.clone(),
                            severity: imp_severity,
                            base_severity: Some(entry.severity),
                            category: entry.category,
                            member: member_name.clone(),
                            offset: 0,
                            token_len: entry.name.len(),
                            string_offset: 0,
                            encoding: strings::Encoding::Ascii,
                            confidence: Confidence::Import,
                            context: format!("imported from {}", dll),
                            context_start: 0,
                            context_end: 0,
                            adjustments: imp_adjustments,
                        });
                    } else {
                        hit_cap_reached = true;
                    }
                }
            }

            let extracted = strings::extract(member.data, cfg.min_len, cfg.ascii, cfg.utf16);
            strings_total += extracted.len();

            // A module named without a path is the one thing about a LoadLibrary call that
            // is visible without a disassembler, so it is collected here where the strings
            // already are. Only for an image that actually loads dynamically: bare module
            // names in anything else are just text.
            if let Some(a) = pe.as_mut() {
                if a.loader.loads_dynamically() {
                    let filter = pe_loader::ModuleFilter::new(
                        &a.libraries,
                        crate::report::pe_section::short_name(&member_name),
                    );
                    let found: Vec<pe_loader::UnqualifiedModule> = extracted
                        .iter()
                        .filter(|s| filter.is_candidate(&s.text))
                        .map(|s| pe_loader::UnqualifiedModule {
                            name: s.text.clone(),
                            offset: s.offset,
                        })
                        .collect();
                    a.loader.note_strings(found, UNQUALIFIED_MODULE_CAP);
                }
            }

            for s in &extracted {
                let found = matcher.find(&s.text);
                if !found.is_empty() {
                    for h in &found {
                        let be = match list.get(h.pattern_id) {
                            Some(be) => be,
                            None => continue,
                        };
                        // Already proven by the import table; counting the string too
                        // would inflate the occurrence count for the same fact.
                        if imported.contains(&be.name.to_ascii_lowercase()) {
                            continue;
                        }
                        let conf = confidence::score(&s.text, h.start, h.end, &be.name);
                        // Severity is a property of this observation, not of the name. The
                        // evidence that decides it is all in scope here: the confidence, the
                        // member's format, and whether the member is a managed assembly whose
                        // import table was read.
                        let ruling = evidence::adjudicate(&evidence::Observation {
                            function: &be.name,
                            base_severity: be.severity,
                            confidence: conf,
                            text: &s.text,
                            start: h.start,
                            end: h.end,
                            member_format: member.format,
                            is_managed: pe.as_ref().is_some_and(|a| a.is_managed),
                            // A usable table, not merely a parsed PE: an image with no
                            // import directory offers no evidence of absence.
                            imports_known: pe.as_ref().is_some_and(|a| !a.imports.is_empty()),
                        });
                        let entry = agg.entry(h.pattern_id).or_default();

                        let excluded_by = if !conf.is_reportable() {
                            Some("prose")
                        } else {
                            ruling.exclusion_rule()
                        };
                        if let Some(rule) = excluded_by {
                            if !cfg.include_low_confidence {
                                entry.low_confidence += 1;
                                low_confidence_total += 1;
                                *excluded_by_rule.entry(rule.to_string()).or_insert(0) += 1;
                                observer.on(&Event::Suppressed {
                                    function: &be.name,
                                    member: &member_name,
                                    reason: rule,
                                });
                                continue;
                            }
                        }
                        // With --include-excluded, an excluded occurrence is reported at its
                        // unadjusted severity so the reviewer sees what the rule removed
                        // rather than a silently re-tiered version of it.
                        let (severity, adjustments) = match (&ruling, excluded_by) {
                            (_, Some(_)) => (be.severity, Vec::new()),
                            (
                                evidence::Ruling::Keep {
                                    severity,
                                    adjustments,
                                },
                                None,
                            ) => (
                                *severity,
                                adjustments
                                    .iter()
                                    .map(|a| crate::model::Adjustment {
                                        rule: a.rule.to_string(),
                                        from: a.from,
                                        to: a.to,
                                        evidence: a.evidence.clone(),
                                    })
                                    .collect(),
                            ),
                            (evidence::Ruling::Exclude { .. }, None) => (be.severity, Vec::new()),
                        };

                        observer.on(&Event::Hit {
                            function: &be.name,
                            member: &member_name,
                            confidence: conf,
                        });
                        entry.occurrences += 1;
                        entry.members.insert(member_name.clone());
                        entry.worst = match entry.worst {
                            Some(w) if w <= severity => Some(w),
                            _ => Some(severity),
                        };

                        if hits.len() < cfg.max_hits {
                            let (context, cs, ce) =
                                window(&s.text, h.start, h.end, cfg.context_window);
                            // UTF-16LE source bytes are two per decoded character, so
                            // the in-member offset must be scaled or a reviewer seeks
                            // to the wrong place.
                            let stride = match s.encoding {
                                strings::Encoding::Ascii => 1u64,
                                strings::Encoding::Utf16Le => 2u64,
                            };
                            let token_len = (h.end - h.start) * stride as usize;
                            hits.push(HitRecord {
                                function: be.name.clone(),
                                severity,
                                base_severity: Some(be.severity),
                                category: be.category,
                                member: member_name.clone(),
                                offset: s.offset + (h.start as u64) * stride,
                                token_len,
                                string_offset: s.offset,
                                encoding: s.encoding,
                                confidence: conf,
                                context,
                                context_start: cs,
                                context_end: ce,
                                adjustments,
                            });
                        } else {
                            hit_cap_reached = true;
                        }
                    }
                }
                if observer.wants(level::TRACE) {
                    observer.on(&Event::String {
                        member: &member_name,
                        offset: s.offset,
                        hits: found.len(),
                        text: &s.text,
                    });
                }
                iocs.feed(&s.text);
                if cfg.detect_components {
                    components.feed(&s.text);
                }
                if let Some(sp) = spool.as_mut() {
                    let ranges: Vec<(usize, usize)> =
                        found.iter().map(|h| (h.start, h.end)).collect();
                    sp.push(&member_name, s, &ranges)?;
                }
            }

            observer.on(&Event::Member {
                chain: &member_name,
                format: member.format,
                size: member.data.len() as u64,
                depth: member.chain.len().saturating_sub(1),
                strings: extracted.len(),
            });
            coverage_entries.push(CoverageEntry {
                member: member_name,
                format: member.format.as_str().to_string(),
                size: member.data.len() as u64,
                strings: extracted.len(),
                pe,
            });
            Ok(())
        },
    )?;

    observer.on(&Event::Timing {
        phase: "unpack and scan",
        ms: walk_started.elapsed().as_millis(),
    });
    observer.on(&Event::Phase {
        name: "aggregating",
    });

    let mut summary: Vec<MatchSummary> = agg
        .iter()
        .filter(|(_, a)| a.occurrences > 0)
        .filter_map(|(id, a)| {
            list.get(*id).map(|be| MatchSummary {
                function: be.name.clone(),
                // Worst adjusted severity among this function's reported occurrences. The
                // family value is kept alongside it as base_severity.
                severity: a.worst.unwrap_or(be.severity),
                base_severity: Some(be.severity),
                category: be.category,
                occurrences: a.occurrences,
                members: a.members.len(),
                low_confidence: a.low_confidence,
            })
        })
        .collect();
    // Most severe first, then most frequent, then alphabetical for stable output.
    summary.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then(b.occurrences.cmp(&a.occurrences))
            .then(a.function.cmp(&b.function))
    });

    let mut warnings = outcome.warnings.clone();
    if hit_cap_reached {
        warnings.push(format!(
            "occurrence detail capped at {} records; aggregate counts remain complete",
            cfg.max_hits
        ));
    }
    if !coverage_entries
        .iter()
        .any(|e| matches!(e.format.as_str(), "pe" | "elf" | "macho"))
    {
        warnings.push(
            "no executable image (PE, ELF, or Mach-O) was reached, so a clean result is not \
             evidence that the binary is free of banned functions"
                .to_string(),
        );
    }

    // Largest suppressed contributors, so a reviewer can audit what was filtered.
    let mut low_top: Vec<(String, usize)> = agg
        .iter()
        .filter(|(_, a)| a.low_confidence > 0)
        .filter_map(|(id, a)| list.get(*id).map(|be| (be.name.clone(), a.low_confidence)))
        .collect();
    low_top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    low_top.truncate(15);

    if low_confidence_total > 0 {
        warnings.push(format!(
            "{} occurrences were suppressed as low confidence (namespace segments or \
             documentation prose rather than function references). Pass \
             --include-low-confidence to report them.",
            low_confidence_total
        ));
    }

    let banned_hit_count = summary.iter().map(|s| s.occurrences).sum();
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    let report = Report {
        tool: "binspector".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        binary: path.display().to_string(),
        project: cfg.project.clone(),
        timestamp,
        file_size,
        md5: digests.md5,
        sha1: digests.sha1,
        sha256: digests.sha256,
        min_len: cfg.min_len,
        case_sensitive: cfg.case_sensitive,
        banned_list_size: list.len(),
        strings_total,
        banned_hit_count,
        summary,
        hits,
        low_confidence_total,
        low_confidence_top: low_top,
        excluded_by_rule: excluded_by_rule.into_iter().collect(),
        include_low_confidence: cfg.include_low_confidence,
        iocs: iocs.finish(),
        intel: intel::Intel {
            reputation: None,
            cves: None,
            components: if cfg.detect_components {
                components.finish()
            } else {
                Vec::new()
            },
        },
        posture: crate::pe::posture::findings(
            &coverage_entries
                .iter()
                .filter(|e| e.pe.is_some())
                .collect::<Vec<_>>(),
        ),
        coverage: Coverage {
            root_format: outcome.root_format.as_str().to_string(),
            members_scanned: outcome.members_scanned,
            total_unpacked_bytes: outcome.total_unpacked,
            entries: coverage_entries,
            carved: outcome
                .carved
                .into_iter()
                .map(|(member, r)| CarvedMember {
                    member,
                    items: r.items,
                    metadata_markers: r.metadata_markers,
                    speculative: r.speculative,
                })
                .collect(),
            carve_ran: cfg.limits.carve,
        },
        warnings,
    };

    let spool = match spool {
        Some(sp) => Some(sp.finish()?),
        None => None,
    };

    observer.on(&Event::Timing {
        phase: "total",
        ms: started.elapsed().as_millis(),
    });

    Ok(ScanOutput { report, spool })
}

/// Clip `text` to a readable window around `[start, end)`, returning the window and
/// the match range translated into it. Clipping respects char boundaries.
fn window(text: &str, start: usize, end: usize, max: usize) -> (String, usize, usize) {
    if text.len() <= max {
        return (text.to_string(), start, end);
    }
    let hit_len = end - start;
    let slack = max.saturating_sub(hit_len) / 2;
    let mut from = start.saturating_sub(slack);
    let mut to = (end + slack).min(text.len());
    while from < text.len() && !text.is_char_boundary(from) {
        from += 1;
    }
    while to > from && !text.is_char_boundary(to) {
        to -= 1;
    }
    if from > start || to < end {
        // The hit itself must always stay inside the window.
        return (text[start..end].to_string(), 0, hit_len);
    }
    (text[from..to].to_string(), start - from, end - from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use confidence::Confidence;
    use std::io::{Cursor, Write};
    use tempfile::NamedTempFile;
    use zip::write::SimpleFileOptions;

    fn temp_with(data: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f.flush().unwrap();
        f
    }

    fn cfg_with_list(list: &str) -> (ScanConfig, NamedTempFile) {
        let lf = temp_with(list.as_bytes());
        let cfg = ScanConfig {
            banned_list: Some(lf.path().to_path_buf()),
            ..Default::default()
        };
        (cfg, lf)
    }

    #[test]
    fn finds_real_hit_with_provenance() {
        let (cfg, _lf) = cfg_with_list("gets\n");
        // Shaped like a real import table entry: a bare, NUL-delimited symbol.
        let target = temp_with(b"\x00gets\x00other\x00");
        let out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
        assert_eq!(out.report.banned_hit_count, 1);
        assert_eq!(out.report.summary[0].function, "gets");
        assert_eq!(out.report.hits.len(), 1);
        assert_eq!(out.report.hits[0].confidence, Confidence::Exact);
    }

    #[test]
    fn does_not_report_the_historical_false_positives() {
        let (cfg, _lf) = cfg_with_list("gets\nsystem\natoi\n");
        // Exactly the strings that produced the bogus 2.0.0 result.
        let target = temp_with(b"targetsize lightunplated_targetsize FileSystem CustomSystemFont");
        let out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
        assert_eq!(
            out.report.banned_hit_count, 0,
            "summary: {:?}",
            out.report.summary
        );
        assert!(out.report.summary.is_empty());
    }

    #[test]
    fn descends_into_nested_zip_and_attributes_the_member() {
        let inner = {
            let mut buf = Vec::new();
            let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
            w.start_file("App.exe", SimpleFileOptions::default())
                .unwrap();
            w.write_all(b"\x00gets\x00payload\x00").unwrap();
            w.finish().unwrap();
            buf
        };
        let bundle = {
            let mut buf = Vec::new();
            let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
            w.start_file("app.msix", SimpleFileOptions::default())
                .unwrap();
            w.write_all(&inner).unwrap();
            w.finish().unwrap();
            buf
        };
        let (cfg, _lf) = cfg_with_list("gets\n");
        let target = temp_with(&bundle);
        let out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
        assert_eq!(out.report.banned_hit_count, 1);
        let hit = &out.report.hits[0];
        assert!(hit.member.contains("app.msix"), "member: {}", hit.member);
        assert!(hit.member.contains("App.exe"), "member: {}", hit.member);
    }

    #[test]
    fn warns_when_no_executable_was_reached() {
        let (cfg, _lf) = cfg_with_list("gets\n");
        let target = temp_with(b"\x00gets\x00plain payload\x00");
        let out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
        assert!(out
            .report
            .warnings
            .iter()
            .any(|w| w.contains("no executable image")));
    }

    #[test]
    fn case_sensitive_mode_is_honored() {
        // lstrcpyA carries uppercase in the list, so neither spelling is demoted as
        // prose and the only difference is the case-sensitivity setting itself.
        let lf = temp_with(b"lstrcpyA\n");
        let target = temp_with(b"\x00lstrcpyA\x00lstrcpya\x00");

        let insensitive = ScanConfig {
            banned_list: Some(lf.path().to_path_buf()),
            ..Default::default()
        };
        assert_eq!(
            run(target.path(), &insensitive, &crate::observe::Null)
                .unwrap()
                .report
                .banned_hit_count,
            2
        );

        let sensitive = ScanConfig {
            banned_list: Some(lf.path().to_path_buf()),
            case_sensitive: true,
            ..Default::default()
        };
        assert_eq!(
            run(target.path(), &sensitive, &crate::observe::Null)
                .unwrap()
                .report
                .banned_hit_count,
            1
        );
    }

    #[test]
    fn dotnet_namespaces_and_doc_prose_are_suppressed_by_default() {
        // The two noise sources measured on the real SampleApp sample.
        let lf = temp_with(b"system\ngets\n");
        let target =
            temp_with(b"\x00System.Windows.Forms.dll\x00Gets or sets the BindingContext\x00");
        let cfg = ScanConfig {
            banned_list: Some(lf.path().to_path_buf()),
            ..Default::default()
        };
        let out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
        assert_eq!(
            out.report.banned_hit_count, 0,
            "summary: {:?}",
            out.report.summary
        );
        assert!(out.report.low_confidence_total >= 2);
        assert!(out
            .report
            .warnings
            .iter()
            .any(|w| w.contains("suppressed as low confidence")));
    }

    #[test]
    fn include_low_confidence_reports_the_suppressed_hits() {
        let lf = temp_with(b"system\n");
        let target = temp_with(b"\x00System.Windows.Forms.dll\x00");
        let cfg = ScanConfig {
            banned_list: Some(lf.path().to_path_buf()),
            include_low_confidence: true,
            ..Default::default()
        };
        let out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
        assert_eq!(out.report.banned_hit_count, 1);
        assert_eq!(out.report.hits[0].confidence, Confidence::Prose);
        assert_eq!(out.report.low_confidence_total, 0);
    }

    #[test]
    fn dump_spools_every_string() {
        let lf = temp_with(b"gets\n");
        let cfg = ScanConfig {
            banned_list: Some(lf.path().to_path_buf()),
            dump: true,
            ..Default::default()
        };
        let target = temp_with(b"aaaa\x00bbbb\x00gets\x00");
        let mut out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
        let mut n = 0;
        out.spool
            .as_mut()
            .unwrap()
            .for_each(|_| {
                n += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(n, 3);
    }

    /// Smallest byte sequence `container::detect` accepts as a PE, so a test can exercise the
    /// executable-member path without a real binary.
    fn fake_pe(payload: &[u8]) -> Vec<u8> {
        let mut pe = vec![0u8; 0x200];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe.extend_from_slice(payload);
        pe
    }

    #[test]
    fn summary_is_ordered_by_severity() {
        let lf = temp_with(b"atoi\nstrcpy\n");
        let cfg = ScanConfig {
            banned_list: Some(lf.path().to_path_buf()),
            ..Default::default()
        };
        // A PE, because since 5.0.0 a hit in a non-executable member is capped at Low and
        // the ordering would then be by count rather than by severity.
        let target = temp_with(&fake_pe(b"\x00atoi\x00atoi\x00atoi\x00strcpy\x00"));
        let out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
        // strcpy is critical, atoi is medium, so strcpy leads despite fewer hits.
        assert_eq!(out.report.summary[0].function, "strcpy");
    }

    #[test]
    fn a_hit_in_a_non_executable_member_is_capped_at_low() {
        // The same bytes without a PE header. Nothing in a data file is a critical finding,
        // and the cap is recorded as an adjustment rather than applied silently.
        let lf = temp_with(b"strcpy\n");
        let cfg = ScanConfig {
            banned_list: Some(lf.path().to_path_buf()),
            ..Default::default()
        };
        let target = temp_with(b"\x00strcpy\x00");
        let out = run(target.path(), &cfg, &crate::observe::Null).unwrap();
        let hit = &out.report.hits[0];
        assert_eq!(hit.severity, Severity::Low);
        assert_eq!(hit.base_severity(), Severity::Critical);
        assert_eq!(hit.adjustments[0].rule, "non-executable-member");
        assert_eq!(out.report.summary[0].severity, Severity::Low);
        assert_eq!(out.report.summary[0].base_severity(), Severity::Critical);
    }

    #[test]
    fn window_keeps_hit_inside() {
        let long = format!("{}gets{}", "a".repeat(500), "b".repeat(500));
        let (w, s, e) = window(&long, 500, 504, 120);
        assert_eq!(&w[s..e], "gets");
        assert!(w.len() <= 140);
    }

    #[test]
    fn window_returns_whole_short_string() {
        let (w, s, e) = window("xx gets yy", 3, 7, 120);
        assert_eq!(w, "xx gets yy");
        assert_eq!(&w[s..e], "gets");
    }
}
