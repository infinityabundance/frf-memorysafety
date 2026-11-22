//! Phase 10.2 SARIF 2.1.0 projection and corruption-control tests.
//!
//! Each test copies the committed campaign into `target/etp-tests`, mutates one
//! SARIF field, and requires a typed refusal or an unchanged finding count.

use std::fs;
use std::path::{Path, PathBuf};

use frf_memorysafety::identity::canonical_bytes;
use frf_memorysafety::sarif::{verify_sarif_file, SarifRefusalCode, SarifReport, SarifStatus};
use serde_json::Value;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create destination");
    for entry in fs::read_dir(source).expect("read source") {
        let entry = entry.expect("entry");
        let path = entry.path();
        let target = destination.join(entry.file_name());
        if path.is_dir() {
            copy_directory(&path, &target);
        } else {
            fs::copy(&path, &target).expect("copy file");
        }
    }
}

fn temp_campaign(name: &str) -> PathBuf {
    let destination = repo()
        .join("target/etp-tests")
        .join(format!("{name}-{}", std::process::id()));
    if destination.exists() {
        fs::remove_dir_all(&destination).expect("remove old test campaign");
    }
    copy_directory(&repo().join("evaluation/earned-trust"), &destination);
    destination
}

fn load(directory: &Path) -> Value {
    serde_json::from_slice(&fs::read(directory.join("campaign.sarif")).expect("SARIF"))
        .expect("JSON")
}

fn store(directory: &Path, value: &Value) {
    let bytes = canonical_bytes(value).expect("canonical SARIF");
    fs::write(directory.join("campaign.sarif"), bytes).expect("write SARIF");
}

fn verify(directory: &Path) -> Result<SarifReport, frf_memorysafety::sarif::SarifError> {
    verify_sarif_file(&directory.join("campaign.sarif"))
}

fn codes(report: &SarifReport) -> Vec<SarifRefusalCode> {
    report.refusals.iter().map(|refusal| refusal.code).collect()
}

fn first_result(value: &mut Value) -> &mut Value {
    &mut value["runs"][0]["results"][0]
}

#[test]
fn committed_sarif_is_valid() {
    let directory = temp_campaign("valid");
    let report = verify(&directory).expect("verification");
    assert_eq!(report.status, SarifStatus::Valid);
    assert_eq!(report.result_count, 18);
    assert_eq!(report.rule_count, 11);
    assert_eq!(report.retained_finding_count, 18);
    assert_eq!(report.suppressed_result_count, 0);
    assert!(report.refusals.is_empty(), "{:?}", report.refusals);
}

#[test]
fn fabricated_location_is_refused() {
    let directory = temp_campaign("fabricated-location");
    let mut sarif = load(&directory);
    first_result(&mut sarif)["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] =
        Value::String("tests/native/fixtures/invented.c".to_owned());
    store(&directory, &sarif);
    let report = verify(&directory).expect("report");
    assert_eq!(report.status, SarifStatus::Refused);
    assert!(codes(&report).contains(&SarifRefusalCode::FabricatedLocation));
}

#[test]
fn suppression_without_fields_is_refused() {
    let directory = temp_campaign("suppression-empty");
    let mut sarif = load(&directory);
    first_result(&mut sarif)["suppressions"] = serde_json::json!([
        {
            "kind": "external",
            "justification": "",
            "properties": {
                "scope": "",
                "owner": "",
                "expiry": "",
                "invalidation": ""
            }
        }
    ]);
    store(&directory, &sarif);
    let report = verify(&directory).expect("report");
    assert_eq!(report.status, SarifStatus::Refused);
    assert!(codes(&report).contains(&SarifRefusalCode::UnauthorizedSuppression));
}

#[test]
fn suppression_does_not_remove_a_finding() {
    let directory = temp_campaign("suppression-valid");
    let mut sarif = load(&directory);
    first_result(&mut sarif)["suppressions"] = serde_json::json!([
        {
            "kind": "external",
            "justification": "declared review",
            "properties": {
                "scope": "one result",
                "owner": "declared-owner",
                "expiry": "2027-01-01",
                "invalidation": "candidate or instrument change"
            }
        }
    ]);
    store(&directory, &sarif);
    let report = verify(&directory).expect("report");
    assert_eq!(report.result_count, 18);
    assert_eq!(report.retained_finding_count, 18);
    assert!(report.suppressed_result_count >= 1);
}

#[test]
fn absent_tool_change_without_evidence_is_refused() {
    let directory = temp_campaign("absent-tool-change");
    let mut sarif = load(&directory);
    let result = first_result(&mut sarif);
    result["baselineState"] = Value::String("absent".to_owned());
    result["properties"]["absence_reason"] = Value::String("tool_change".to_owned());
    result["properties"]["absence_evidence"] = serde_json::json!([]);
    result["properties"]["previous_instrument_execution_identity"] = Value::String(String::new());
    store(&directory, &sarif);
    let report = verify(&directory).expect("report");
    assert_eq!(report.status, SarifStatus::Refused);
    assert!(codes(&report).contains(&SarifRefusalCode::InvalidBaselineState));
}

#[test]
fn incomplete_sharding_is_refused() {
    let directory = temp_campaign("incomplete-sharding");
    let mut sarif = load(&directory);
    sarif["runs"][0]["properties"]["completeness"]["complete"] = Value::Bool(false);
    sarif["runs"][0]["properties"]["completeness"]["shards"] = serde_json::json!([]);
    store(&directory, &sarif);
    let report = verify(&directory).expect("report");
    assert_eq!(report.status, SarifStatus::Refused);
    assert!(codes(&report).contains(&SarifRefusalCode::IncompleteSharding));
}

#[test]
fn limit_exceeded_is_refused() {
    let directory = temp_campaign("limit");
    let mut sarif = load(&directory);
    sarif["runs"][0]["properties"]["limits"]["max_results"] = serde_json::json!(1);
    store(&directory, &sarif);
    let report = verify(&directory).expect("report");
    assert_eq!(report.status, SarifStatus::Refused);
    assert!(codes(&report).contains(&SarifRefusalCode::LimitExceeded));
}

#[test]
fn missing_rule_is_refused() {
    let directory = temp_campaign("missing-rule");
    let mut sarif = load(&directory);
    let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array_mut()
        .expect("rules");
    let last = rules.len() - 1;
    rules.remove(last);
    store(&directory, &sarif);
    let report = verify(&directory).expect("report");
    assert_eq!(report.status, SarifStatus::Refused);
    assert!(codes(&report).contains(&SarifRefusalCode::MissingRule));
}

#[test]
fn unsupported_version_is_refused() {
    let directory = temp_campaign("version");
    let mut sarif = load(&directory);
    sarif["version"] = Value::String("2.0.0".to_owned());
    store(&directory, &sarif);
    let report = verify(&directory).expect("report");
    assert_eq!(report.status, SarifStatus::Refused);
    assert!(codes(&report).contains(&SarifRefusalCode::UnsupportedVersion));
}

#[test]
fn missing_native_manifest_is_refused() {
    let directory = temp_campaign("manifest");
    let mut sarif = load(&directory);
    sarif["runs"][0]["properties"]["completeness"]["native_manifest"] =
        Value::String("missing.json".to_owned());
    store(&directory, &sarif);
    let report = verify(&directory).expect("report");
    assert_eq!(report.status, SarifStatus::Refused);
    assert!(codes(&report).contains(&SarifRefusalCode::MissingNativeManifest));
}

#[test]
fn invented_region_is_refused_at_parse() {
    let directory = temp_campaign("region");
    let mut sarif = load(&directory);
    first_result(&mut sarif)["locations"][0]["physicalLocation"]["region"] =
        serde_json::json!({"startLine": 1, "startColumn": 1});
    store(&directory, &sarif);
    assert!(verify(&directory).is_err());
}

#[test]
fn inconsistent_result_count_is_refused() {
    let directory = temp_campaign("count");
    let mut sarif = load(&directory);
    sarif["runs"][0]["properties"]["result_count"] = serde_json::json!(17);
    store(&directory, &sarif);
    let report = verify(&directory).expect("report");
    assert_eq!(report.status, SarifStatus::Refused);
    assert!(codes(&report).contains(&SarifRefusalCode::InconsistentCount));
}
