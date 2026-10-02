//! Reputation lookups by hash.
//!
//! **No file content is ever transmitted.** Only the SHA-256 the scan already computed
//! is sent. The legacy shell implementation ran `vt scan $bin`, which uploads the
//! sample and publishes it to a third party permanently; for an unreleased binary that
//! is a disclosure event, so it is deliberately not reproduced here. An unknown hash
//! reports "not found" and stops.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::creds::Credentials;
use super::http;

const TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Debug, Serialize, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// The service has seen this hash and reported detections.
    Malicious { detections: u32, total: u32 },
    /// The service has seen this hash and reported no detections.
    Clean { total: u32 },
    /// The service has never seen this hash. Not evidence of safety.
    NotFound,
    /// The lookup could not be completed.
    Error(String),
    /// No credential configured for this service.
    NotConfigured,
}

impl Verdict {
    pub fn summary(&self) -> String {
        match self {
            Verdict::Malicious { detections, total } => {
                format!("{} of {} engines flagged this hash", detections, total)
            }
            Verdict::Clean { total } => {
                format!("no detections across {} engines", total)
            }
            Verdict::NotFound => {
                "hash not known to the service, which is not evidence that it is safe".to_string()
            }
            Verdict::Error(e) => format!("lookup failed: {}", e),
            Verdict::NotConfigured => "no API key configured".to_string(),
        }
    }

    pub fn is_actionable(&self) -> bool {
        matches!(self, Verdict::Malicious { detections, .. } if *detections > 0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reputation {
    /// What this digest is of: a target label, or a member's provenance chain.
    #[serde(default)]
    pub label: String,
    pub sha256: String,
    pub virustotal: Verdict,
    pub metadefender: Verdict,
    /// Restated in the report so the privacy property is visible to a reader.
    pub content_transmitted: bool,
}

/// Look the hash up with whichever services are configured.
///
/// `label` names what the digest is of, so the report can say which file was asked about. A
/// reputation answer with no subject is unreadable in a multi-target run, and worse, it used to be
/// wrong: see [`lookup_targets`].
pub fn lookup(label: &str, sha256: &str, creds: &Credentials) -> Result<Reputation> {
    http::ensure_available()?;
    Ok(Reputation {
        label: label.to_string(),
        sha256: sha256.to_string(),
        virustotal: match creds.virustotal.as_deref() {
            Some(key) => virustotal(sha256, key),
            None => Verdict::NotConfigured,
        },
        metadefender: match creds.metadefender.as_deref() {
            Some(key) => metadefender(sha256, key),
            None => Verdict::NotConfigured,
        },
        content_transmitted: false,
    })
}

/// One lookup per target, against each target's own file digest.
///
/// **The defect this replaces.** `lookup` used to be called once per report with `report.sha256`,
/// and on any multi-target run `finish_aggregate` has already overwritten that field with a
/// *manifest* digest: the SHA-256 of the newline-joined `"<sha256>  <label>"` lines. No service has
/// ever seen that value, so every multi-target reputation run asked about a hash the tool had
/// synthesized, got a 404, and printed "hash not known to the service, which is not evidence that
/// it is safe". A reader takes that as a statement about the package. It was a statement about a
/// digest that cannot exist.
///
/// `TargetInfo` has carried real `md5`, `sha1` and `sha256` all along, so the fix is to ask about
/// those instead. A manifest digest is now never sent anywhere, which `manifest_digest_is_refused`
/// asserts directly rather than by convention.
pub fn lookup_targets(
    targets: &[crate::model::TargetInfo],
    creds: &Credentials,
) -> Result<Vec<Reputation>> {
    http::ensure_available()?;
    let mut out = Vec::with_capacity(targets.len());
    for t in targets {
        out.push(Reputation {
            label: t.label.clone(),
            sha256: t.sha256.clone(),
            virustotal: match creds.virustotal.as_deref() {
                Some(key) => virustotal(&t.sha256, key),
                None => Verdict::NotConfigured,
            },
            metadefender: match creds.metadefender.as_deref() {
                Some(key) => metadefender(&t.sha256, key),
                None => Verdict::NotConfigured,
            },
            content_transmitted: false,
        });
    }
    Ok(out)
}

/// One member worth asking about, and why it ranked where it did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub member: String,
    pub sha256: String,
    /// Lower sorts first. See [`candidates`] for what each tier means.
    pub tier: u8,
    pub reason: &'static str,
}

/// What a member sweep did, and what it did not do.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Sweep {
    pub results: Vec<Reputation>,
    /// Distinct hashes worth asking about.
    pub candidates: usize,
    /// Answered by the service.
    pub queried: usize,
    /// Answered from the local cache, which is still an answer.
    pub from_cache: usize,
    /// Distinct hashes that went unasked because the budget ran out.
    ///
    /// Reported rather than dropped. An unchecked member is never rendered as clean, which is the
    /// habit `excluded_by_rule` and the indicator drop counters already follow.
    pub unchecked: usize,
    /// The terms warning, when the configured rate implies a free tier.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier_note: Option<String>,
}

impl Sweep {
    pub fn is_empty(&self) -> bool {
        self.results.is_empty() && self.unchecked == 0
    }

    /// Whether any member came back flagged.
    pub fn flagged(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.virustotal.is_actionable() || r.metadefender.is_actionable())
            .count()
    }
}

/// Smallest unknown-format member worth a lookup.
///
/// A handful of bytes of padding is not a sample anybody has an opinion about, and on the reference
/// package the unknown-format members are 2,714 of 4,281, so an unbounded sweep over them would
/// spend the whole budget on the least interesting tier.
const UNKNOWN_SIZE_FLOOR: u64 = 4096;

/// Which members to ask about, worst first, one entry per distinct hash.
///
/// **Deduplicated by content, which is the point.** On the reference package 4,281 members hold 3,799
/// distinct hashes, and among PE images 1,567 rows are 1,012 distinct files. Asking per row would
/// spend a third of the budget re-asking about bytes already answered for.
///
/// The ordering is the whole strategy, because the budget runs out long before the list does. A free
/// tier answers 500 a day and the reference package has 3,799 distinct hashes, roughly seven days.
/// Its 179 unsigned executables fit inside one day, and they are the tier worth having.
pub fn candidates(r: &crate::model::Report) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();

    for e in &r.coverage.entries {
        let Some(d) = e.digests.as_ref() else {
            continue;
        };
        if d.sha256.is_empty() || !seen.insert(d.sha256.as_str()) {
            continue;
        }
        let executable = e.pe.is_some() || e.unix_executable;
        let signed = e.pe.as_ref().is_some_and(|a| a.signature.is_some());
        let first_party = e.pe.as_ref().is_some_and(|a| a.first_party);

        let (tier, reason) = if executable && !signed {
            // The tier the whole feature exists for. An unsigned executable inside a signed package
            // is the one thing a hash lookup can speak to that nothing else here can.
            (0, "unsigned executable")
        } else if executable && !first_party {
            (1, "executable signed by a third party")
        } else if executable {
            (2, "first-party executable")
        } else if e.size >= UNKNOWN_SIZE_FLOOR {
            (3, "non-executable member")
        } else {
            // Too small to be a sample anybody has an opinion about.
            continue;
        };
        out.push(Candidate {
            member: e.member.clone(),
            sha256: d.sha256.clone(),
            tier,
            reason,
        });
    }

    // Tier first, then largest, then by name so the order is total and a rerun asks in the same
    // sequence. Largest within a tier because a bigger file is more likely to be a real payload than
    // a stub, and the budget may not reach the end of the tier.
    let size_of: std::collections::BTreeMap<&str, u64> = r
        .coverage
        .entries
        .iter()
        .map(|e| (e.member.as_str(), e.size))
        .collect();
    out.sort_by(|a, b| {
        a.tier
            .cmp(&b.tier)
            .then_with(|| {
                let sb = size_of.get(b.member.as_str()).copied().unwrap_or(0);
                let sa = size_of.get(a.member.as_str()).copied().unwrap_or(0);
                sb.cmp(&sa)
            })
            .then_with(|| a.member.cmp(&b.member))
    });
    out
}

/// Ask about as many members as the budget allows, worst first.
///
/// `cache` is consulted before every request and written after every answer. A cache hit costs
/// nothing against the budget, which is what makes a second scan of the same package nearly free.
pub fn sweep_members(
    r: &crate::model::Report,
    creds: &Credentials,
    budget: &mut super::budget::Budget,
    cache: Option<&dyn VerdictStore>,
) -> Result<Sweep> {
    let wanted = candidates(r);
    let mut out = Sweep {
        candidates: wanted.len(),
        tier_note: budget.tier_note().map(str::to_string),
        ..Default::default()
    };
    if wanted.is_empty() {
        return Ok(out);
    }
    // Checked once, not per candidate: a sweep of 3,799 hashes should not discover on the last one
    // that curl was never on PATH.
    http::ensure_available()?;
    let now = super::cache::now_unix();

    for c in &wanted {
        let mut rep = Reputation {
            label: c.member.clone(),
            sha256: c.sha256.clone(),
            virustotal: Verdict::NotConfigured,
            metadefender: Verdict::NotConfigured,
            content_transmitted: false,
        };
        let mut answered = false;
        let mut cached = false;
        let mut exhausted = false;

        for (service, key) in [
            ("virustotal", creds.virustotal.as_deref()),
            ("metadefender", creds.metadefender.as_deref()),
        ] {
            let Some(key) = key else { continue };
            // The cache first, always. A hit is an answer and must not cost a request.
            if let Some(hit) = cache.and_then(|c2| c2.lookup(&c.sha256, service, now)) {
                set(&mut rep, service, hit);
                answered = true;
                cached = true;
                continue;
            }
            if !budget.claim() {
                exhausted = true;
                continue;
            }
            let v = match service {
                "virustotal" => virustotal(&c.sha256, key),
                _ => metadefender(&c.sha256, key),
            };
            if let Some(store) = cache {
                // A failure to write the cache must not fail the scan: the answer is still good.
                store.remember(&c.sha256, service, &v, now);
            }
            set(&mut rep, service, v);
            answered = true;
        }

        if answered {
            if cached {
                out.from_cache += 1;
            } else {
                out.queried += 1;
            }
            out.results.push(rep);
        } else if exhausted {
            out.unchecked += 1;
        }
        // Neither answered nor exhausted means no key was configured for either service, which is
        // reported once by the caller rather than 3,799 times here.
    }
    Ok(out)
}

fn set(rep: &mut Reputation, service: &str, v: Verdict) {
    match service {
        "virustotal" => rep.virustotal = v,
        _ => rep.metadefender = v,
    }
}

/// The cache, behind a trait so the sweep does not depend on the `sqlite` feature.
///
/// Without that feature there is no store and every lookup is a miss, which is correct behaviour
/// rather than a stub: a build with no SQLite has nowhere to persist anything.
pub trait VerdictStore {
    fn lookup(&self, sha256: &str, service: &str, now: i64) -> Option<Verdict>;
    fn remember(&self, sha256: &str, service: &str, v: &Verdict, now: i64);
}

fn virustotal(sha256: &str, key: &str) -> Verdict {
    let url = format!("https://www.virustotal.com/api/v3/files/{}", sha256);
    let resp = match http::get(&url, &[("x-apikey", key)], TIMEOUT) {
        Ok(r) => r,
        Err(e) => return Verdict::Error(http::redact(&e.to_string())),
    };
    if resp.status == 404 {
        return Verdict::NotFound;
    }
    if resp.status == 401 || resp.status == 403 {
        return Verdict::Error("credential rejected by VirusTotal".to_string());
    }
    if resp.status == 429 {
        return Verdict::Error("VirusTotal rate limit reached".to_string());
    }
    if !resp.is_success() {
        return Verdict::Error(format!("VirusTotal returned HTTP {}", resp.status));
    }
    match resp.json() {
        Ok(v) => parse_vt(&v),
        Err(e) => Verdict::Error(e.to_string()),
    }
}

pub fn parse_vt(v: &serde_json::Value) -> Verdict {
    let stats = &v["data"]["attributes"]["last_analysis_stats"];
    let get = |k: &str| stats[k].as_u64().unwrap_or(0) as u32;
    let malicious = get("malicious");
    let suspicious = get("suspicious");
    let total = malicious + suspicious + get("undetected") + get("harmless");
    if total == 0 {
        return Verdict::NotFound;
    }
    let flagged = malicious + suspicious;
    if flagged > 0 {
        Verdict::Malicious {
            detections: flagged,
            total,
        }
    } else {
        Verdict::Clean { total }
    }
}

fn metadefender(hash: &str, key: &str) -> Verdict {
    let url = format!("https://api.metadefender.com/v4/hash/{}", hash);
    let resp = match http::get(&url, &[("apikey", key)], TIMEOUT) {
        Ok(r) => r,
        Err(e) => return Verdict::Error(http::redact(&e.to_string())),
    };
    if resp.status == 404 {
        return Verdict::NotFound;
    }
    if resp.status == 401 || resp.status == 403 {
        return Verdict::Error("credential rejected by MetaDefender".to_string());
    }
    if resp.status == 429 {
        return Verdict::Error("MetaDefender rate limit reached".to_string());
    }
    if !resp.is_success() {
        return Verdict::Error(format!("MetaDefender returned HTTP {}", resp.status));
    }
    match resp.json() {
        Ok(v) => parse_md(&v),
        Err(e) => Verdict::Error(e.to_string()),
    }
}

pub fn parse_md(v: &serde_json::Value) -> Verdict {
    // A "not found" body carries an error code rather than an HTTP 404 in some cases.
    if v.get("error").is_some() && v["scan_results"].is_null() {
        return Verdict::NotFound;
    }
    let results = &v["scan_results"];
    let detected = results["total_detected_avs"].as_u64();
    let total = results["total_avs"].as_u64();
    match (detected, total) {
        (Some(d), Some(t)) if t > 0 => {
            if d > 0 {
                Verdict::Malicious {
                    detections: d as u32,
                    total: t as u32,
                }
            } else {
                Verdict::Clean { total: t as u32 }
            }
        }
        _ => Verdict::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn vt_malicious_counts_suspicious_too() {
        let v = json!({"data":{"attributes":{"last_analysis_stats":{
            "malicious": 3, "suspicious": 2, "undetected": 60, "harmless": 0}}}});
        assert_eq!(
            parse_vt(&v),
            Verdict::Malicious {
                detections: 5,
                total: 65
            }
        );
    }

    #[test]
    fn vt_clean_reports_engine_total() {
        let v = json!({"data":{"attributes":{"last_analysis_stats":{
            "malicious": 0, "suspicious": 0, "undetected": 70, "harmless": 2}}}});
        assert_eq!(parse_vt(&v), Verdict::Clean { total: 72 });
    }

    #[test]
    fn vt_empty_stats_is_not_found() {
        assert_eq!(parse_vt(&json!({})), Verdict::NotFound);
    }

    #[test]
    fn md_parses_detections() {
        let v = json!({"scan_results":{"total_detected_avs": 4, "total_avs": 30}});
        assert_eq!(
            parse_md(&v),
            Verdict::Malicious {
                detections: 4,
                total: 30
            }
        );
        let clean = json!({"scan_results":{"total_detected_avs": 0, "total_avs": 30}});
        assert_eq!(parse_md(&clean), Verdict::Clean { total: 30 });
    }

    #[test]
    fn md_error_body_is_not_found() {
        let v = json!({"error": {"code": 404001, "messages": ["Not Found"]}});
        assert_eq!(parse_md(&v), Verdict::NotFound);
    }

    #[test]
    fn not_found_is_never_described_as_safe() {
        let s = Verdict::NotFound.summary();
        assert!(s.contains("not evidence that it is safe"));
        assert!(!Verdict::NotFound.is_actionable());
    }

    #[test]
    fn only_detections_are_actionable() {
        assert!(Verdict::Malicious {
            detections: 1,
            total: 70
        }
        .is_actionable());
        assert!(!Verdict::Clean { total: 70 }.is_actionable());
        assert!(!Verdict::NotConfigured.is_actionable());
        assert!(!Verdict::Error("x".into()).is_actionable());
    }

    #[test]
    fn a_manifest_digest_is_never_what_gets_looked_up() {
        // The defect 6.0.0 fixes, asserted structurally rather than by convention. `lookup_targets`
        // reads each target's own digest, so the manifest digest on the Report is unreachable from
        // the lookup path. If a future change routes `report.sha256` back in, this fails.
        let mut r = crate::report::tests_support::rich_report();
        assert!(
            r.is_manifest_digest(),
            "the fixture must be multi-target for this to mean anything"
        );
        let manifest = r.sha256.clone();
        assert!(
            r.targets.iter().all(|t| t.sha256 != manifest),
            "no target carries the manifest digest, so asking about it asks about no file"
        );
        // With no credentials configured nothing is sent, which is what lets this run offline: the
        // point under test is which digest each answer is *about*.
        r.intel.reputation = lookup_targets(&r.targets, &Credentials::default())
            .expect("no network needed when nothing is configured");
        assert_eq!(r.intel.reputation.len(), r.targets.len());
        for (rep, t) in r.intel.reputation.iter().zip(&r.targets) {
            assert_eq!(rep.sha256, t.sha256);
            assert_eq!(rep.label, t.label);
            assert_ne!(rep.sha256, manifest);
        }
    }

    #[test]
    fn every_answer_names_the_file_it_is_about() {
        // An unlabelled verdict is unreadable once a scan covers ten targets, and a reader cannot
        // tell which file a "flagged" line belongs to.
        let r = crate::report::tests_support::rich_report();
        let got = lookup_targets(&r.targets, &Credentials::default()).expect("offline");
        assert!(got.iter().all(|x| !x.label.is_empty()));
    }

    /// A store that answers from a map and records what it was asked to remember.
    struct StubStore {
        answers: std::collections::BTreeMap<(String, String), Verdict>,
        written: std::cell::RefCell<Vec<(String, String)>>,
    }

    impl VerdictStore for StubStore {
        fn lookup(&self, sha256: &str, service: &str, _now: i64) -> Option<Verdict> {
            self.answers
                .get(&(sha256.to_string(), service.to_string()))
                .cloned()
        }
        fn remember(&self, sha256: &str, service: &str, _v: &Verdict, _now: i64) {
            self.written
                .borrow_mut()
                .push((sha256.to_string(), service.to_string()));
        }
    }

    #[test]
    fn candidates_are_deduplicated_by_content_and_ordered_worst_first() {
        let r = crate::report::tests_support::rich_report();
        let c = candidates(&r);

        // One entry per distinct hash. Asking per row would re-ask about bytes already answered for:
        // on the reference package 4,281 rows are 3,799 distinct hashes.
        let hashes: std::collections::BTreeSet<&str> =
            c.iter().map(|x| x.sha256.as_str()).collect();
        assert_eq!(hashes.len(), c.len(), "a hash must appear once");

        // Tiers are non-decreasing, so the budget is spent on the worst first.
        assert!(
            c.windows(2).all(|w| w[0].tier <= w[1].tier),
            "{:?}",
            c.iter().map(|x| (x.tier, x.reason)).collect::<Vec<_>>()
        );
        // And an unsigned executable leads, which is the tier the feature exists for.
        if let Some(first) = c.first() {
            assert_eq!(first.tier, 0);
            assert_eq!(first.reason, "unsigned executable");
        }
    }

    #[test]
    fn a_member_too_small_to_have_an_opinion_about_is_not_a_candidate() {
        let mut r = crate::report::tests_support::rich_report();
        for e in r.coverage.entries.iter_mut() {
            e.pe = None;
            e.unix_executable = false;
            e.size = 16;
            e.digests = Some(crate::hashing::Digests {
                md5: "m".repeat(32),
                sha1: "s".repeat(40),
                sha256: format!("{:0>64}", e.member.len()),
            });
        }
        assert!(
            candidates(&r).is_empty(),
            "a handful of bytes of padding is not a sample"
        );
    }

    #[test]
    fn a_cache_hit_answers_without_spending_the_budget() {
        let mut r = crate::report::tests_support::rich_report();
        // One candidate, so the accounting is unambiguous.
        r.coverage.entries.truncate(1);
        let e = &mut r.coverage.entries[0];
        e.unix_executable = true;
        e.pe = None;
        e.size = 1 << 20;
        let sha = "a".repeat(64);
        e.digests = Some(crate::hashing::Digests {
            md5: "m".repeat(32),
            sha1: "s".repeat(40),
            sha256: sha.clone(),
        });

        let store = StubStore {
            answers: [(
                (sha.clone(), "virustotal".to_string()),
                Verdict::Clean { total: 70 },
            )]
            .into_iter()
            .collect(),
            written: Default::default(),
        };
        let creds = Credentials {
            virustotal: Some("key".into()),
            ..Default::default()
        };
        let mut budget = crate::intel::budget::Budget::dry(0, 10);
        let sw = sweep_members(&r, &creds, &mut budget, Some(&store)).expect("offline");

        assert_eq!(sw.from_cache, 1, "answered from the cache");
        assert_eq!(sw.queried, 0, "and no service was asked");
        assert_eq!(budget.spent(), 0, "so the budget is untouched");
        assert_eq!(sw.unchecked, 0);
        assert!(
            store.written.borrow().is_empty(),
            "a hit writes nothing back"
        );
    }

    #[test]
    fn a_budget_of_zero_asks_nothing_and_reports_everything_as_unchecked() {
        // The property the whole section rests on: an unchecked member must never read as clean.
        let mut r = crate::report::tests_support::rich_report();
        for (i, e) in r.coverage.entries.iter_mut().enumerate() {
            e.unix_executable = true;
            e.pe = None;
            e.size = 1 << 20;
            e.digests = Some(crate::hashing::Digests {
                md5: "m".repeat(32),
                sha1: "s".repeat(40),
                sha256: format!("{:0>64}", i),
            });
        }
        let creds = Credentials {
            virustotal: Some("key".into()),
            ..Default::default()
        };
        let mut budget = crate::intel::budget::Budget::dry(0, 0);
        let sw = sweep_members(&r, &creds, &mut budget, None).expect("offline");
        assert!(sw.results.is_empty(), "nothing was answered");
        assert_eq!(sw.unchecked, sw.candidates, "and all of it is declared");
        assert!(sw.candidates > 0);
    }

    #[test]
    fn with_no_key_configured_nothing_is_asked_and_nothing_is_called_unchecked() {
        // No key is not the same as no budget. Reporting these as unchecked would overstate what a
        // larger budget could have achieved.
        let mut r = crate::report::tests_support::rich_report();
        for (i, e) in r.coverage.entries.iter_mut().enumerate() {
            e.unix_executable = true;
            e.pe = None;
            e.size = 1 << 20;
            e.digests = Some(crate::hashing::Digests {
                md5: "m".repeat(32),
                sha1: "s".repeat(40),
                sha256: format!("{:0>64}", i),
            });
        }
        let mut budget = crate::intel::budget::Budget::dry(0, 100);
        let sw = sweep_members(&r, &Credentials::default(), &mut budget, None).expect("offline");
        assert!(sw.results.is_empty());
        assert_eq!(sw.unchecked, 0);
        assert_eq!(budget.spent(), 0);
    }
}
