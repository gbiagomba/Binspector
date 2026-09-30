//! SARIF 2.1.0 output.
//!
//! Built directly as JSON because the shape is small and fixed. Binary findings
//! have no line numbers, so each result is located by an artifact URI plus a byte
//! region, which SARIF supports natively via `address` and `region.byteOffset`.

use anyhow::Result;
use serde_json::{json, Map, Value};
use std::io::Write;

use crate::model::Report;

pub fn write(w: &mut dyn Write, r: &Report) -> Result<()> {
    // One rule per distinct banned function that actually matched.
    let mut rules: Vec<Value> = Vec::new();
    let mut rule_index: Map<String, Value> = Map::new();
    for (i, s) in r.summary.iter().enumerate() {
        rule_index.insert(s.function.clone(), json!(i));
        rules.push(json!({
            "id": format!("banned-function/{}", s.function),
            "name": format!("BannedFunction{}", s.function),
            "shortDescription": { "text": format!("Use of banned function {}", s.function) },
            "fullDescription": {
                "text": format!(
                    "The banned function {} was referenced. Category: {}. Severity: {}.",
                    s.function, s.category.as_str(), s.severity.as_str()
                )
            },
            "defaultConfiguration": { "level": s.severity.sarif_level() },
            "properties": {
                "category": s.category.as_str(),
                "severity": s.severity.as_str(),
                "occurrences": s.occurrences,
                "members": s.members
            }
        }));
    }

    let results: Vec<Value> = r
        .hits
        .iter()
        .map(|h| {
            let mut result = json!({
                "ruleId": format!("banned-function/{}", h.function),
                "level": h.severity.sarif_level(),
                "message": {
                    "text": format!(
                        "Banned function {} referenced in {} at offset 0x{:x}.",
                        h.function, h.member, h.offset
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": artifact_uri(&h.member) },
                        "region": {
                            "byteOffset": h.offset,
                            "byteLength": h.token_len,
                            "snippet": { "text": h.context }
                        },
                        "address": { "absoluteAddress": h.offset }
                    }
                }],
                "properties": {
                    "encoding": h.encoding.as_str(),
                    "category": h.category.as_str(),
                    "member": h.member
                }
            });
            if let Some(idx) = rule_index.get(&h.function) {
                result["ruleIndex"] = idx.clone();
            }
            result
        })
        .collect();

    let notifications: Vec<Value> = r
        .warnings
        .iter()
        .map(|warn| {
            json!({
                "level": "warning",
                "message": { "text": warn },
                "descriptor": { "id": "binspector/coverage" }
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "binspector",
                    "version": r.tool_version,
                    "informationUri": "https://github.com/gbiagomba/Binspector",
                    "rules": rules
                }
            },
            "invocations": [{
                "executionSuccessful": true,
                "endTimeUtc": r.timestamp,
                "toolExecutionNotifications": notifications
            }],
            "properties": {
                "binary": r.binary,
                "project": r.project,
                "sha256": r.sha256,
                "stringsExtracted": r.strings_total,
                "membersScanned": r.coverage.members_scanned,
                "reachedExecutable": r.reached_executable()
            },
            "results": results
        }]
    });

    w.write_all(serde_json::to_string_pretty(&sarif)?.as_bytes())?;
    w.write_all(b"\n")?;
    Ok(())
}

/// Turn a provenance chain into a URI-ish artifact path SARIF viewers accept.
fn artifact_uri(member: &str) -> String {
    member.replace(" :: ", "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests_support::sample_report;

    #[test]
    fn emits_sarif_2_1_0_skeleton() {
        let mut buf = Vec::new();
        write(&mut buf, &sample_report()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"]
            .as_str()
            .unwrap()
            .contains("sarif-schema-2.1.0"));
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "binspector");
    }

    #[test]
    fn maps_severity_to_sarif_level() {
        let mut buf = Vec::new();
        write(&mut buf, &sample_report()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let rule = &v["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(rule["defaultConfiguration"]["level"], "error");
        assert_eq!(rule["id"], "banned-function/strcpy");
    }

    #[test]
    fn locates_results_by_byte_offset_not_line() {
        let mut buf = Vec::new();
        write(&mut buf, &sample_report()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let loc = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert!(loc["region"]["byteOffset"].is_number());
        assert!(loc["region"].get("startLine").is_none());
        assert_eq!(loc["artifactLocation"]["uri"], "bundle/app.msix/App.exe");
    }

    #[test]
    fn warnings_become_tool_notifications() {
        let mut buf = Vec::new();
        write(&mut buf, &sample_report()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let n = &v["runs"][0]["invocations"][0]["toolExecutionNotifications"][0];
        assert_eq!(n["level"], "warning");
    }
}
