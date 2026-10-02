//! Scan orchestration: unpack once, extract strings, match, aggregate.

pub mod aggregate;
pub mod banned;
pub mod confidence;
pub mod crt_surface;
pub mod evidence;
pub mod hygiene;
pub mod matcher;
pub mod remediation;
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
pub use aggregate::run_many;

use banned::{BannedList, Severity};
use confidence::Confidence;
use matcher::Matcher;

/// Bare module-name strings kept per image. Enough to give a reviewer a place to start;
/// a large image can carry hundreds and an inventory is not the point.
const UNQUALIFIED_MODULE_CAP: usize = 20;

#[derive(Clone, Debug)]
pub struct ScanConfig {
    /// Where to write unpacked members, when the caller asked with `--extract`.
    ///
    /// `None` for every ordinary run, which is what keeps "nothing from the target is written to
    /// disk" true by default rather than by convention.
    /// Shared across every target in the run, so the count is one number and a member that appears
    /// in several targets is written once.
    pub extract: Option<std::sync::Arc<crate::container::extract::Extractor>>,
    /// How many targets to scan at once. Always at least 1.
    ///
    /// Parallelism is across targets only. Every cap in `Limits` is defined per target, so a shared
    /// budget would let the first target consume the last one's coverage.
    pub threads: usize,
    pub project: Option<String>,
    pub min_len: usize,
    pub ascii: bool,
    pub utf16: bool,
    pub case_sensitive: bool,
    pub banned_list: Option<PathBuf>,
    pub banned_filter: Option<Regex>,
    /// Images whose path or signer matches are attributed to the reader's own code.
    pub first_party: Option<Regex>,
    pub limits: Limits,
    /// Spool every extracted string so dump-capable formats can stream it.
    pub dump: bool,
    /// Upper bound on individually recorded occurrences, to bound memory.
    pub max_hits: usize,
    /// Characters of surrounding text kept with each hit.
    pub context_window: usize,
    /// Report low-confidence hits (namespace segments, documentation prose) too.
    pub include_excluded: bool,
    /// Parse PE members for headers, sections, imports, and mitigations.
    pub analyze_pe: bool,
    /// Read compiland records from PDB members.
    pub analyze_pdb: bool,
    /// Maximum indicators of each kind to collect.
    pub ioc_cap: usize,
    /// Detect third-party components and versions from strings. Offline.
    pub detect_components: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            extract: None,
            threads: 1,
            project: None,
            min_len: 4,
            ascii: true,
            utf16: true,
            // Case-exact by default. Win32 and the CRT have one spelling per entry point, so
            // an insensitive match reports a camelCase local as an API call.
            case_sensitive: true,
            banned_list: None,
            banned_filter: None,
            first_party: None,
            limits: Limits::default(),
            dump: false,
            max_hits: 100_000,
            context_window: 120,
            include_excluded: false,
            analyze_pe: true,
            analyze_pdb: true,
            // Per kind, not overall. 500 made the field unusable on a real 553 MB target: 618
            // URLs and 1,902 paths were kept while 45,273 indicators were discarded, so the
            // list was a 5% sample of scan order presenting itself as a result. Collection and
            // display are separate concerns, and the report still truncates what it prints.
            ioc_cap: 10_000,
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
    excluded: usize,
    /// Worst adjusted severity seen for this function. `None` until a hit is kept.
    ///
    /// Needed because evidence can give two occurrences of one name different severities, so
    /// the summary row cannot simply copy the family value any more.
    worst: Option<Severity>,
    /// Occurrences per adjusted severity, in `Severity` order: critical, high, medium, low.
    ///
    /// Tracked per occurrence rather than derived from `worst`, because `worst` is one value for
    /// the whole function and the evidence rules work per occurrence. Attributing all of a
    /// function's occurrences to its worst bucket put the target rollup one off the hit rows in
    /// a real report: medium 104 and low 72 against 103 and 73. Counted here rather than from
    /// `hits` so the totals stay complete when the occurrence cap truncates the detail.
    per_severity: [usize; 4],
}

/// Index into `Agg::per_severity`.
fn severity_slot(s: Severity) -> usize {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
    }
}

pub fn run(path: &Path, cfg: &ScanConfig, observer: &dyn Observer) -> Result<ScanOutput> {
    let label = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string());
    run_labeled(path, &label, "explicit", cfg, observer)
}

/// Scan one target, naming its provenance-chain root explicitly.
///
/// A multi-target run needs the label to be the selector's, which disambiguates two files with
/// the same name in different directories, rather than the bare file name.
pub fn run_labeled(
    path: &Path,
    label: &str,
    selected_by: &str,
    cfg: &ScanConfig,
    observer: &dyn Observer,
) -> Result<ScanOutput> {
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
    let root_name = label.to_string();

    let mut agg: BTreeMap<usize, Agg> = BTreeMap::new();
    let mut hits: Vec<HitRecord> = Vec::new();
    let mut strings_total = 0usize;
    let mut coverage_entries: Vec<CoverageEntry> = Vec::new();
    let mut member_leaves: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut hit_cap_reached = false;
    let mut excluded_total = 0usize;
    // Per-rule exclusion tally, so no occurrence can disappear without a named reason.
    let mut excluded_by_rule: BTreeMap<String, usize> = BTreeMap::new();
    let mut iocs = ioc::Extractor::new(cfg.ioc_cap);
    let mut components = intel::components::Detector::new(200);
    let mut spool = if cfg.dump { Some(Spool::new()?) } else { None };
    // The only thing in a scan that writes bytes from the target. Created before the walk so an
    // unwritable directory fails immediately rather than after several minutes of analysis.

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
            if let Some(e) = cfg.extract.as_ref() {
                e.take(member);
            }
            let member_name = member.chain_display();
            // Leaf names only, lowercased: enough to confirm a filename-evidence component
            // actually ships, and cheap because the set is bounded by the member count.
            member_leaves
                .insert(crate::report::fmt_util::short_name(&member_name).to_ascii_lowercase());
            // Compiland provenance. A pure function of the member's bytes: it touches no
            // indicator collector, no component detector, no hit cap and no spool, which is what
            // makes it the one per-member analysis that could be parallelised without solving the
            // general problem 5.5.0 deferred. Measured first: see the release notes.
            let pdb_provenance =
                if cfg.analyze_pdb && member.format == crate::container::Format::Pdb {
                    let leaf = crate::report::fmt_util::short_name(&member_name);
                    match crate::pdb::read(member.data, leaf) {
                        Ok(found) => found,
                        // A PDB that cannot be read is a different fact from one that is absent, and
                        // saying so is the habit the coverage warnings already follow.
                        Err(e) => Some(crate::pdb::Provenance::skipped(
                            leaf.trim_end_matches(".pdb").to_string(),
                            format!("could not be read: {}", e),
                        )),
                    }
                } else {
                    None
                };

            let mut pe = if cfg.analyze_pe && member.format == crate::container::Format::Pe {
                PeAnalysis::parse(member.data)
            } else {
                None
            };
            // Imports for any executable format, not only PE. This is what makes
            // `Confidence::Import` reachable on ELF and Mach-O, where it was structurally
            // unavailable before 5.2.0.
            let (member_imports, import_source) = match pe.as_ref() {
                Some(a) => (a.imports.clone(), "pe-directory".to_string()),
                None if cfg.analyze_pe
                    && matches!(
                        member.format,
                        crate::container::Format::Elf | crate::container::Format::MachO
                    ) =>
                {
                    let found = crate::exe::read(member.data);
                    let src = if found.imports.is_empty() {
                        String::new()
                    } else {
                        found.source.as_str().to_string()
                    };
                    (found.imports, src)
                }
                _ => (Vec::new(), String::new()),
            };

            // Exploit-mitigation posture for the two formats `pe::posture` cannot read. Kept
            // off `PeAnalysis` because the header bits are different ones: overloading `aslr`
            // to also mean ELF PIE would change what an existing `--filter aslr` selects.
            let (unix, unix_executable) = if cfg.analyze_pe
                && matches!(
                    member.format,
                    crate::container::Format::Elf | crate::container::Format::MachO
                ) {
                (
                    crate::exe::posture::read(member.data),
                    crate::exe::posture::is_executable_image(member.data),
                )
            } else {
                (None, false)
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

            // One lookup per member rather than per occurrence: the signer cannot change
            // between two hits in the same file, and a 1,355-occurrence report would otherwise
            // normalise the same name a thousand times.
            let vendor = pe
                .as_ref()
                .and_then(|a| a.signature.as_ref())
                .and_then(|s| s.signer.as_deref())
                .and_then(crate::pe::vendor::from_signer);

            let mut imported: HashSet<String> = HashSet::new();
            if !member_imports.is_empty() {
                for (id, entry) in list.entries.iter().enumerate() {
                    let dll = match crate::pe::importing_library(&member_imports, &entry.name) {
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
                        is_managed: pe.as_ref().is_some_and(|a| a.is_managed),
                        imports_known: true,
                        has_code: pe.as_ref().map(|a| a.has_code()),
                        // An import of the name is proof it is called from here, whatever the
                        // export table also says, and both rules that read these fields are
                        // guarded on the match being inferred.
                        exported_here: false,
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
                    agg_entry.per_severity[severity_slot(imp_severity)] += 1;
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
                            vendor: vendor.clone(),
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
                            context: if dll.is_empty() {
                                // ELF's flat namespace and the Mach-O symbol-table fallback
                                // cannot say which library supplies a symbol, so the context
                                // states the fact that holds rather than inventing a library.
                                format!("imported ({})", import_source)
                            } else {
                                format!("imported from {}", dll)
                            },
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
                if let Some(re) = cfg.first_party.as_ref() {
                    let signer = a
                        .signature
                        .as_ref()
                        .and_then(|s| s.signer.as_deref())
                        .unwrap_or("");
                    // The image's own file name, not the whole provenance chain. A chain
                    // always begins with the scanned file's name, so matching it would make
                    // `^MyProduct` attribute every member of MyProduct.msixbundle to
                    // first-party, which is exactly the wrong answer.
                    let leaf = crate::report::fmt_util::short_name(&member_name);
                    a.first_party = re.is_match(leaf) || re.is_match(signer);
                }
                if a.loader.loads_dynamically() {
                    let filter = pe_loader::ModuleFilter::new(
                        &a.libraries,
                        crate::report::fmt_util::short_name(&member_name),
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
                            has_code: pe.as_ref().map(|a| a.has_code()),
                            exported_here: pe.as_ref().is_some_and(|a| a.exports_name(&be.name)),
                        });
                        let entry = agg.entry(h.pattern_id).or_default();

                        let excluded_by = if !conf.is_reportable() {
                            Some("prose")
                        } else {
                            ruling.exclusion_rule()
                        };
                        if let Some(rule) = excluded_by {
                            if !cfg.include_excluded {
                                entry.excluded += 1;
                                excluded_total += 1;
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
                        entry.per_severity[severity_slot(severity)] += 1;
                        entry.members.insert(member_name.clone());
                        entry.worst = match entry.worst {
                            Some(w) if w <= severity => Some(w),
                            _ => Some(severity),
                        };

                        if hits.len() < cfg.max_hits {
                            let (context, cs, ce) =
                                strings::window(&s.text, h.start, h.end, cfg.context_window);
                            // UTF-16LE source bytes are two per decoded character, so
                            // the in-member offset must be scaled or a reviewer seeks
                            // to the wrong place.
                            let stride = match s.encoding {
                                strings::Encoding::Ascii => 1u64,
                                strings::Encoding::Utf16Le => 2u64,
                            };
                            let token_len = (h.end - h.start) * stride as usize;
                            hits.push(HitRecord {
                                vendor: vendor.clone(),
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
                vendor: vendor.clone(),
                pdb: pdb_provenance,
                member: member_name,
                format: member.format.as_str().to_string(),
                size: member.data.len() as u64,
                strings: extracted.len(),
                pe,
                imports: member_imports,
                import_source,
                unix,
                unix_executable,
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
                excluded: a.excluded,
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

    // Occurrences in the same order the summary and the posture findings use, because the
    // occurrence list is read top-down and scan order buries the important rows. On a real
    // ten-target run the first 812 of 1,355 rows were low-severity matches inside a symbol
    // package and the first critical sat at index 812, so a reader who looked at the top of the
    // section reasonably concluded the tool had found nothing worth reporting.
    //
    // Confidence is the second key, not the member, because it is what the severity was derived
    // from: among equally severe rows the import-backed one is the one to read first. Member and
    // offset are last and exist only to make the order total, so two runs over the same input
    // produce byte-identical reports.
    hits.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then(a.confidence.cmp(&b.confidence))
            .then(a.member.cmp(&b.member))
            .then(a.offset.cmp(&b.offset))
    });

    // Paths feed component detection after collection, not during the string pass. A statically
    // linked library often embeds no banner, so the signature table cannot see it; the build path
    // its objects were compiled from names it exactly. This is what makes a vendored dependency
    // that appears in no manifest show up as a component rather than only as an indicator.
    let collected_iocs = iocs.finish();
    if cfg.detect_components {
        for p in collected_iocs
            .build_paths
            .iter()
            .chain(collected_iocs.file_paths.iter())
        {
            components.feed_path(p);
        }
    }

    let mut warnings = outcome.warnings.clone();
    if hit_cap_reached {
        warnings.push(format!(
            "occurrence detail capped at {} records; aggregate counts remain complete",
            cfg.max_hits
        ));
    }
    let reached_exe = coverage_entries
        .iter()
        .any(|e| matches!(e.format.as_str(), "pe" | "elf" | "macho"));
    if !reached_exe {
        warnings.push(
            "no executable image (PE, ELF, or Mach-O) was reached, so a clean result is not \
             evidence that the binary is free of banned functions"
                .to_string(),
        );
    }

    // Largest suppressed contributors, so a reviewer can audit what was filtered.
    let mut low_top: Vec<(String, usize)> = agg
        .iter()
        .filter(|(_, a)| a.excluded > 0)
        .filter_map(|(id, a)| list.get(*id).map(|be| (be.name.clone(), a.excluded)))
        .collect();
    low_top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    low_top.truncate(15);

    if excluded_total > 0 {
        warnings.push(format!(
            "{} occurrences were suppressed as low confidence (namespace segments or \
             documentation prose rather than function references). Pass \
             --include-low-confidence to report them.",
            excluded_total
        ));
    }

    let banned_hit_count: usize = summary.iter().map(|s| s.occurrences).sum();
    // Per-severity totals for this target's row, from the summary just assembled.
    let sev_counts = {
        let (mut c, mut h, mut m, mut l) = (0usize, 0usize, 0usize, 0usize);
        // Per occurrence, not per summary row. A summary row carries one severity for the whole
        // function while the evidence rules decide each occurrence separately, so bucketing by
        // the row put the rollup one off the hit table.
        for a in agg.values() {
            c += a.per_severity[0];
            h += a.per_severity[1];
            m += a.per_severity[2];
            l += a.per_severity[3];
        }
        // The targets table renders these four beside banned_hit_count, so a reader will read a
        // failure to sum as a bug in the tool. They are derived from the same summary rows, so
        // this is an invariant rather than a hope; assert it in debug builds.
        debug_assert_eq!(
            c + h + m + l,
            banned_hit_count,
            "per-severity buckets must sum to the occurrence count"
        );
        (c, h, m, l)
    };
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
        md5: digests.md5.clone(),
        sha1: digests.sha1.clone(),
        sha256: digests.sha256.clone(),
        min_len: cfg.min_len,
        case_sensitive: cfg.case_sensitive,
        banned_list_size: list.len(),
        strings_total,
        banned_hit_count,
        summary,
        hits,
        excluded_total,
        excluded_top: low_top,
        excluded_by_rule: excluded_by_rule.into_iter().collect(),
        include_excluded: cfg.include_excluded,
        iocs: collected_iocs,
        intel: intel::Intel {
            reputation: None,
            cves: None,
            components: if cfg.detect_components {
                components.finish(&member_leaves)
            } else {
                Vec::new()
            },
        },
        targets: vec![crate::model::TargetInfo {
            label: label.to_string(),
            path: path.display().to_string(),
            file_size,
            md5: digests.md5.clone(),
            sha1: digests.sha1.clone(),
            sha256: digests.sha256.clone(),
            root_format: outcome.root_format.as_str().to_string(),
            members_scanned: outcome.members_scanned,
            total_unpacked_bytes: outcome.total_unpacked,
            strings_total,
            banned_hit_count,
            critical: sev_counts.0,
            high: sev_counts.1,
            medium: sev_counts.2,
            low: sev_counts.3,
            reached_executable: reached_exe,
            selected_by: selected_by.to_string(),
            // The low-confidence disclosure is not a per-target warning: it is routine, it
            // already has its own "Excluded by evidence" section, and counting it here flagged
            // every row in a multi-target run, which drains the marker of meaning.
            warnings: warnings
                .iter()
                .filter(|w| !w.contains("suppressed as low confidence"))
                .cloned()
                .collect(),
        }],
        posture: all_posture(&coverage_entries),
        external_imports: all_external_imports(&coverage_entries, &member_leaves),
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

/// Every posture finding for a report, across all three executable formats.
///
/// One function rather than two call sites appending two lists, because concatenating two
/// already-sorted lists is not sorted: a Medium PE finding would print above a High ELF one.
/// The ordering here is `pe::posture`'s, applied to the union.
/// Which images import modules the package does not carry.
///
/// Computed after the walk for the same reason `all_posture` is: the question is "absent from the
/// package", and the package is only fully known once the scan has finished.
///
/// Severity is a property of the importer rather than of the missing module. An unsigned image
/// that restricts nothing about its own search path is a different proposition from a
/// vendor-signed one that calls `SetDefaultDllDirectories`, even for the same absent dependency,
/// because what satisfies the import is decided by the search order in the first case and
/// constrained by the build in the second.
pub fn all_external_imports(
    entries: &[CoverageEntry],
    package_leaves: &std::collections::BTreeSet<String>,
) -> Vec<crate::model::ExternalImport> {
    let mut out: Vec<crate::model::ExternalImport> = Vec::new();
    for e in entries {
        let Some(a) = e.pe.as_ref() else { continue };
        let found = crate::pe::unresolved::external_imports(&a.imports, package_leaves);
        if found.is_empty() {
            continue;
        }
        let signed = a.signature.is_some();
        let restricts = !a.loader.hardening.is_empty();
        // Unsigned and unrestricted is the AdobePDFL.dll case and the one worth reading first:
        // nothing about the build constrains what satisfies the import, and nothing about the
        // file lets a reviewer tell the vendor's copy from a substitute.
        let severity = match (signed, restricts) {
            (false, false) => Severity::High,
            (_, false) => Severity::Medium,
            _ => Severity::Low,
        };
        out.push(crate::model::ExternalImport {
            member: e.member.clone(),
            modules: found.modules,
            signed,
            restricts_search_path: restricts,
            severity,
        });
    }
    // Worst first, then by how much of the missing module's surface is used, then by name so the
    // ordering is total and the output reproducible.
    out.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| {
                let bs: usize = b.modules.iter().map(|m| m.imports).sum();
                let as_: usize = a.modules.iter().map(|m| m.imports).sum();
                bs.cmp(&as_)
            })
            .then(a.member.cmp(&b.member))
    });
    out
}

pub fn all_posture(entries: &[CoverageEntry]) -> Vec<crate::model::PostureFinding> {
    let pes: Vec<&CoverageEntry> = entries.iter().filter(|e| e.pe.is_some()).collect();
    let unix: Vec<(String, crate::exe::posture::UnixMitigations, bool)> = entries
        .iter()
        .filter_map(|e| {
            e.unix
                .clone()
                .map(|m| (e.member.clone(), m, e.unix_executable))
        })
        .collect();

    let mut out = crate::pe::posture::findings(&pes);
    out.extend(crate::exe::posture_rules::findings(&unix));
    out.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then(b.affected.cmp(&a.affected))
            .then(a.id.cmp(&b.id))
    });
    out
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
