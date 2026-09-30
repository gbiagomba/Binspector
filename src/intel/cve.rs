//! CVE enrichment against the NVD 2.0 API.
//!
//! Detected components are resolved to known CVEs. Coverage is reported explicitly,
//! because the failure mode that matters here is a component the detector does not
//! know being read as a component with no vulnerabilities.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::components::Component;
use super::creds::Credentials;
use super::http;

const TIMEOUT: Duration = Duration::from_secs(30);
const NVD_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cve {
    pub id: String,
    pub cvss: Option<f64>,
    pub severity: String,
    pub description: String,
    /// NVD advisory URL, so the report can cite it.
    pub url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComponentCves {
    pub component: Component,
    pub cves: Vec<Cve>,
    /// Set when the lookup itself failed, as distinct from finding nothing.
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CveReport {
    pub components: Vec<ComponentCves>,
    /// How many detectors the curated signature set contains.
    pub signature_count: usize,
    /// Stated so a clean result is read correctly.
    pub coverage_note: String,
}

impl CveReport {
    pub fn total_cves(&self) -> usize {
        self.components.iter().map(|c| c.cves.len()).sum()
    }

    pub fn worst_cvss(&self) -> Option<f64> {
        self.components
            .iter()
            .flat_map(|c| c.cves.iter())
            .filter_map(|c| c.cvss)
            .fold(None, |acc: Option<f64>, v| {
                Some(acc.map_or(v, |a| a.max(v)))
            })
    }
}

/// Look up CVEs for each detected component.
pub fn lookup(
    components: &[Component],
    signature_count: usize,
    creds: &Credentials,
    max_per_component: usize,
) -> Result<CveReport> {
    http::ensure_available()?;
    let mut out = Vec::new();
    for c in components {
        let (cves, error) = match query(c, creds, max_per_component) {
            Ok(v) => (v, None),
            Err(e) => (Vec::new(), Some(http::redact(&e.to_string()))),
        };
        out.push(ComponentCves {
            component: c.clone(),
            cves,
            error,
        });
    }
    Ok(CveReport {
        components: out,
        signature_count,
        coverage_note: format!(
            "Component detection uses {} curated signatures, not an exhaustive set. A component \
             with no detector produces no CVEs, which is not the same as having none.",
            signature_count
        ),
    })
}

fn query(c: &Component, creds: &Credentials, max: usize) -> Result<Vec<Cve>> {
    // keywordSearch over "<name> <version>" is the portable query. A full CPE match
    // would be more precise but needs a per-product CPE name the detector does not have.
    let url = format!(
        "{}?keywordSearch={}%20{}&resultsPerPage={}",
        NVD_BASE,
        urlencode(&c.name),
        urlencode(&c.version),
        max.clamp(1, 50)
    );
    let headers: Vec<(&str, &str)> = match creds.nvd.as_deref() {
        Some(k) => vec![("apiKey", k)],
        None => vec![],
    };
    let resp = http::get(&url, &headers, TIMEOUT)?;
    if resp.status == 403 {
        anyhow::bail!("NVD rejected the request; without NVD_API_KEY the rate limit is very low");
    }
    if resp.status == 429 {
        anyhow::bail!("NVD rate limit reached; set NVD_API_KEY to raise it");
    }
    if !resp.is_success() {
        anyhow::bail!("NVD returned HTTP {}", resp.status);
    }
    Ok(parse_nvd(&resp.json()?, max))
}

pub fn parse_nvd(v: &serde_json::Value, max: usize) -> Vec<Cve> {
    let mut out = Vec::new();
    let empty = Vec::new();
    let items = v["vulnerabilities"].as_array().unwrap_or(&empty);
    for item in items.iter().take(max) {
        let cve = &item["cve"];
        let id = match cve["id"].as_str() {
            Some(s) => s.to_string(),
            None => continue,
        };
        let description = cve["descriptions"]
            .as_array()
            .and_then(|d| {
                d.iter()
                    .find(|x| x["lang"].as_str() == Some("en"))
                    .or_else(|| d.first())
            })
            .and_then(|x| x["value"].as_str())
            .unwrap_or("")
            .to_string();

        let (cvss, severity) = best_metric(&cve["metrics"]);
        out.push(Cve {
            id: id.clone(),
            cvss,
            severity,
            description: truncate(&description, 240),
            url: format!("https://nvd.nist.gov/vuln/detail/{}", id),
        });
    }
    // Most severe first.
    out.sort_by(|a, b| {
        b.cvss
            .unwrap_or(-1.0)
            .partial_cmp(&a.cvss.unwrap_or(-1.0))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.id.cmp(&b.id))
    });
    out
}

/// Prefer CVSS v3.1, then v3.0, then v2.
fn best_metric(metrics: &serde_json::Value) -> (Option<f64>, String) {
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        if let Some(arr) = metrics[key].as_array() {
            if let Some(first) = arr.first() {
                let score = first["cvssData"]["baseScore"].as_f64();
                let sev = first["cvssData"]["baseSeverity"]
                    .as_str()
                    .or_else(|| first["baseSeverity"].as_str())
                    .unwrap_or("unknown")
                    .to_ascii_lowercase();
                return (score, sev);
            }
        }
    }
    (None, "unknown".to_string())
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn nvd_body() -> serde_json::Value {
        json!({"vulnerabilities": [
            {"cve": {
                "id": "CVE-2021-3711",
                "descriptions": [{"lang":"en","value":"SM2 decryption buffer overflow."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}
            }},
            {"cve": {
                "id": "CVE-2021-3712",
                "descriptions": [{"lang":"en","value":"Read buffer overruns processing ASN.1 strings."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.4, "baseSeverity": "HIGH"}}]}
            }}
        ]})
    }

    #[test]
    fn parses_and_sorts_by_severity() {
        let c = parse_nvd(&nvd_body(), 10);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].id, "CVE-2021-3711");
        assert_eq!(c[0].cvss, Some(9.8));
        assert_eq!(c[0].severity, "critical");
        assert!(c[1].cvss.unwrap() < c[0].cvss.unwrap());
    }

    #[test]
    fn builds_a_citable_advisory_url() {
        let c = parse_nvd(&nvd_body(), 10);
        assert_eq!(c[0].url, "https://nvd.nist.gov/vuln/detail/CVE-2021-3711");
    }

    #[test]
    fn honors_the_result_cap() {
        assert_eq!(parse_nvd(&nvd_body(), 1).len(), 1);
    }

    #[test]
    fn empty_response_yields_nothing() {
        assert!(parse_nvd(&json!({}), 10).is_empty());
        assert!(parse_nvd(&json!({"vulnerabilities": []}), 10).is_empty());
    }

    #[test]
    fn falls_back_through_cvss_versions() {
        let v2 =
            json!({"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}]});
        assert_eq!(best_metric(&v2), (Some(5.0), "medium".to_string()));
        assert_eq!(best_metric(&json!({})), (None, "unknown".to_string()));
    }

    #[test]
    fn urlencodes_query_values() {
        assert_eq!(urlencode("openssl"), "openssl");
        assert_eq!(urlencode("1.1.1k"), "1.1.1k");
        assert_eq!(urlencode("a b&c=d"), "a%20b%26c%3Dd");
    }

    #[test]
    fn report_aggregates_worst_score() {
        let r = CveReport {
            components: vec![ComponentCves {
                component: Component {
                    name: "openssl".into(),
                    version: "1.1.1k".into(),
                    evidence: "OpenSSL 1.1.1k".into(),
                },
                cves: parse_nvd(&nvd_body(), 10),
                error: None,
            }],
            signature_count: 20,
            coverage_note: "note".into(),
        };
        assert_eq!(r.total_cves(), 2);
        assert_eq!(r.worst_cvss(), Some(9.8));
    }

    #[test]
    fn coverage_note_warns_that_absence_is_not_proof() {
        let r = lookup_note(20);
        assert!(r.contains("not the same as having none"));
    }

    fn lookup_note(n: usize) -> String {
        format!(
            "Component detection uses {} curated signatures, not an exhaustive set. A component \
             with no detector produces no CVEs, which is not the same as having none.",
            n
        )
    }
}
