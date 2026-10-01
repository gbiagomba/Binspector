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
        rule_index.insert(format!("banned-function/{}", s.function), json!(i));
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
            // Posture rules have carried `help` since 5.3.0 and banned-function rules carried
            // none, so a code-scanning UI showed a fix for a missing mitigation and nothing for an
            // unbounded copy. Same source as the text report's Remediation section.
            "help": {
                "text": crate::scan::remediation::advice(&s.function, s.category)
            },
            "properties": {
                "category": s.category.as_str(),
                "severity": s.severity.as_str(),
                "occurrences": s.occurrences,
                "members": s.members
            }
        }));
    }

    // A second rule family for missing exploit mitigations, appended so every existing index is
    // unchanged and the four existing tests keep passing.
    for (i, p) in r.posture.iter().enumerate() {
        let id = format!("missing-mitigation/{}", p.id);
        rule_index.insert(id.clone(), json!(r.summary.len() + i));
        rules.push(json!({
            "id": id,
            "name": format!("MissingMitigation{}", p.id.replace('-', "_")),
            "shortDescription": { "text": p.title.clone() },
            "fullDescription": { "text": format!("{} Evidence: {}", p.title, p.evidence) },
            "defaultConfiguration": { "level": p.severity.sarif_level() },
            // Remediation is constant per rule id, so it belongs on the rule rather than being
            // duplicated into every result.
            "help": { "text": p.remediation.clone() },
            "properties": {
                "severity": p.severity.as_str(),
                "affected": p.affected,
                "category": "exploit-mitigation"
            }
        }));
    }

    let mut results: Vec<Value> = r
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
            if let Some(idx) = rule_index.get(&format!("banned-function/{}", h.function)) {
                result["ruleIndex"] = idx.clone();
            }
            result
        })
        .collect();

    // One result per posture finding, with one location per affected member. `result.locations`
    // is an array and multi-entry is the schema's intended encoding for a single defect at
    // several sites. `region` is optional and deliberately omitted: a posture finding has no byte
    // offset, and inventing `byteOffset: 0` would be a false claim about a verifiable field.
    for p in &r.posture {
        let id = format!("missing-mitigation/{}", p.id);
        let locations: Vec<Value> = p
            .members
            .iter()
            .map(|m| json!({ "physicalLocation": { "artifactLocation": { "uri": artifact_uri(m) } } }))
            .collect();
        let mut result = json!({
            "ruleId": id.clone(),
            "level": p.severity.sarif_level(),
            "message": { "text": format!("{}: {} image(s) affected.", p.title, p.affected) },
            "locations": locations,
            // Both counts, because the member list is capped: a consumer counting `locations`
            // would otherwise under-report the true number affected.
            "properties": {
                "affected": p.affected,
                "membersListed": p.members.len(),
                "evidence": p.evidence.clone(),
                "remediation": p.remediation.clone()
            },
            // No byte offset exists to anchor on, so the id keeps an alert stable across runs.
            "partialFingerprints": { "postureId": p.id.clone() }
        });
        if let Some(idx) = rule_index.get(&id) {
            result["ruleIndex"] = idx.clone();
        }
        results.push(result);
    }

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
    fn posture_findings_reach_sarif_with_one_location_per_member() {
        let mut r = crate::report::tests_support::sample_report();
        r.posture = vec![crate::model::PostureFinding {
            id: "aslr".into(),
            title: "ASLR disabled: the image loads at a predictable address".into(),
            severity: crate::scan::banned::Severity::High,
            affected: 179,
            members: vec!["b :: BIB.dll".into(), "b :: CoolType.dll".into()],
            evidence: "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE absent".into(),
            remediation: "link with /DYNAMICBASE".into(),
        }];
        let mut buf = Vec::new();
        write(&mut buf, &r).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        let posture_rule = rules
            .iter()
            .find(|x| x["id"] == "missing-mitigation/aslr")
            .expect("a posture rule is emitted");
        assert_eq!(posture_rule["defaultConfiguration"]["level"], "warning");
        // Remediation lives on the rule, not duplicated into every result.
        assert_eq!(posture_rule["help"]["text"], "link with /DYNAMICBASE");

        let results = v["runs"][0]["results"].as_array().unwrap();
        let posture = results
            .iter()
            .find(|x| x["ruleId"] == "missing-mitigation/aslr")
            .expect("a posture result is emitted");
        let locations = posture["locations"].as_array().unwrap();
        assert_eq!(locations.len(), 2, "one location per listed member");
        // No invented region: a posture finding has no byte offset.
        assert!(
            locations[0]["physicalLocation"].get("region").is_none(),
            "a posture location must not claim a byte offset"
        );
        // The cap means locations can under-count, so both numbers are present.
        assert_eq!(posture["properties"]["affected"], 179);
        assert_eq!(posture["properties"]["membersListed"], 2);
        assert_eq!(posture["partialFingerprints"]["postureId"], "aslr");
    }

    #[test]
    fn the_banned_function_rule_index_still_resolves_with_two_families() {
        // The index was keyed on a bare function name, which cannot distinguish two families.
        let mut r = crate::report::tests_support::sample_report();
        r.posture = vec![crate::model::PostureFinding {
            id: "dep".into(),
            title: "DEP disabled".into(),
            severity: crate::scan::banned::Severity::High,
            affected: 1,
            members: vec!["b :: x.dll".into()],
            evidence: "NX_COMPAT absent".into(),
            remediation: "link with /NXCOMPAT".into(),
        }];
        let mut buf = Vec::new();
        write(&mut buf, &r).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        for res in results {
            let idx = res["ruleIndex"]
                .as_u64()
                .expect("every result resolves a rule") as usize;
            assert_eq!(
                rules[idx]["id"], res["ruleId"],
                "ruleIndex must point at the matching rule"
            );
        }
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
