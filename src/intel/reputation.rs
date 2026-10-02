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
}
