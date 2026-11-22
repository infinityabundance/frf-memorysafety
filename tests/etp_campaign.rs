//! Phase 10.2 ETP campaign closure and lossless reconciliation tests.
//!
//! The valid case loads the committed campaign. Corrupted controls mutate an
//! in-memory bundle and require a typed refusal. None of these tests executes a
//! native fixture; the real native run is `ci/etp-gate.sh`.

use std::path::{Path, PathBuf};

use frf_memorysafety::etp_campaign::{
    load_bundle, verify_bundle, CampaignBundle, CampaignRefusalCode, CampaignStatus,
};
use frf_memorysafety::identity::canonical_bytes;
use serde_json::{json, Value};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn bundle() -> CampaignBundle {
    load_bundle(&repo().join("evaluation/earned-trust/MANIFEST.json")).expect("campaign bundle")
}

fn value(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("JSON")
}

fn encode(value: &Value) -> Vec<u8> {
    canonical_bytes(value).expect("canonical bytes")
}

fn state(bundle: &CampaignBundle) -> Value {
    value(&bundle.closure_bytes)
}

fn codes(report: &frf_memorysafety::etp_campaign::CampaignReport) -> Vec<CampaignRefusalCode> {
    report.refusals.iter().map(|refusal| refusal.code).collect()
}

fn receipt_path(case_id: &str) -> String {
    format!("receipts/{case_id}.json")
}

fn mutate_receipt(bundle: &mut CampaignBundle, case_id: &str, mutation: impl FnOnce(&mut Value)) {
    let path = receipt_path(case_id);
    let bytes = bundle.receipts.get(&path).expect("receipt").clone();
    let mut receipt = value(&bytes);
    mutation(&mut receipt);
    bundle.receipts.insert(path, encode(&receipt));
}

fn refresh_closure_reference(bundle: &mut CampaignBundle, case_id: &str) {
    let path = receipt_path(case_id);
    let digest =
        frf_memorysafety::etp_campaign::sha256_hex(bundle.receipts.get(&path).expect("receipt"));
    let mut closure = state(bundle);
    let entries = closure["receipts"].as_array_mut().expect("receipts");
    let mut found = false;
    for entry in entries {
        if entry["case_id"] == case_id {
            entry["sha256"] = Value::String(digest.clone());
            found = true;
        }
    }
    assert!(found, "closure reference for {case_id}");
    bundle.closure_bytes = encode(&closure);
}

#[test]
fn committed_campaign_is_accepted_with_exact_counts() {
    let bundle = bundle();
    let report = verify_bundle(&bundle).expect("reconciliation");
    assert_eq!(report.status, CampaignStatus::Accepted);
    assert_eq!(report.case_count, 13);
    assert_eq!(report.receipt_count, 13);
    assert_eq!(report.raw_evidence_count, 25);
    assert_eq!(report.accepted_cases.len(), 4);
    assert_eq!(report.retained_findings.len(), 9);
    assert!(report.refusals.is_empty(), "{:?}", report.refusals);
    let outcomes = report
        .outcomes
        .iter()
        .map(|count| (count.label.as_str(), count.count))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        outcomes.get("verified_compatible_within_transcript"),
        Some(&4)
    );
    assert_eq!(outcomes.get("observed_violation"), Some(&6));
    assert_eq!(outcomes.get("incomplete_transcript"), Some(&1));
    assert_eq!(outcomes.get("unresolved"), Some(&2));
}

#[test]
fn deleted_failed_evidence_is_refused() {
    let mut bundle = bundle();
    assert!(bundle
        .receipts
        .remove(&receipt_path("use-after-free-c"))
        .is_some());
    let report = verify_bundle(&bundle).expect("report");
    assert_eq!(report.status, CampaignStatus::Refused);
    assert!(codes(&report).contains(&CampaignRefusalCode::MissingReceipt));
}

#[test]
fn truncated_population_is_refused() {
    let mut bundle = bundle();
    let case_id = "use-after-free-c";
    assert!(bundle.receipts.remove(&receipt_path(case_id)).is_some());
    bundle
        .raw
        .remove("receipts/raw/use-after-free-c.transcript.json");
    bundle
        .raw
        .remove("receipts/raw/use-after-free-c.court.json");
    let mut closure = state(&bundle);
    let entries = closure["receipts"].as_array_mut().expect("receipts");
    entries.retain(|entry| entry["case_id"] != case_id);
    closure["receipt_count"] = json!(12);
    closure["raw_evidence_count"] = json!(23);
    bundle.closure_bytes = encode(&closure);
    let report = verify_bundle(&bundle).expect("report");
    assert_eq!(report.status, CampaignStatus::Refused);
    let refused = codes(&report);
    assert!(
        refused.contains(&CampaignRefusalCode::MissingReceipt)
            || refused.contains(&CampaignRefusalCode::TruncatedPopulation),
        "{refused:?}"
    );
}

#[test]
fn duplicate_receipt_rows_are_refused() {
    let mut bundle = bundle();
    let bytes = bundle
        .receipts
        .get(&receipt_path("use-after-free-c"))
        .expect("receipt")
        .clone();
    bundle
        .receipts
        .insert(receipt_path("use-after-free-c-copy"), bytes);
    let report = verify_bundle(&bundle).expect("report");
    assert_eq!(report.status, CampaignStatus::Refused);
    assert!(codes(&report).contains(&CampaignRefusalCode::DuplicateReceipt));
}

#[test]
fn inconsistent_summary_count_is_refused() {
    let mut bundle = bundle();
    let mut closure = state(&bundle);
    closure["receipt_count"] = json!(14);
    bundle.closure_bytes = encode(&closure);
    let report = verify_bundle(&bundle).expect("report");
    assert_eq!(report.status, CampaignStatus::Refused);
    assert!(codes(&report).contains(&CampaignRefusalCode::InconsistentCount));
}

#[test]
fn suppressed_finding_without_fields_is_refused() {
    let mut bundle = bundle();
    mutate_receipt(&mut bundle, "use-after-free-c", |receipt| {
        receipt["suppression"]["suppressed"] = json!(true);
    });
    let report = verify_bundle(&bundle).expect("report");
    assert_eq!(report.status, CampaignStatus::Refused);
    assert!(codes(&report).contains(&CampaignRefusalCode::UnauthorizedSuppression));
}

#[test]
fn valid_suppression_remains_a_retained_finding() {
    let mut bundle = bundle();
    mutate_receipt(&mut bundle, "use-after-free-c", |receipt| {
        receipt["suppression"] = json!({
            "suppressed": true,
            "justification": "retained for a declared review",
            "scope": "case use-after-free-c",
            "owner": "declared-owner",
            "expiry": "2027-01-01",
            "invalidation": "candidate or instrument identity change",
        });
    });
    refresh_closure_reference(&mut bundle, "use-after-free-c");
    let report = verify_bundle(&bundle).expect("report");
    assert_eq!(
        report.status,
        CampaignStatus::Accepted,
        "{:?}",
        report.refusals
    );
    assert!(report
        .retained_findings
        .iter()
        .any(|case_id| case_id == "use-after-free-c"));
}

#[test]
fn stripped_result_is_refused() {
    let mut bundle = bundle();
    mutate_receipt(&mut bundle, "use-after-free-c", |receipt| {
        receipt
            .as_object_mut()
            .expect("object")
            .remove("observation");
    });
    assert!(verify_bundle(&bundle).is_err());
}

#[test]
fn wrong_candidate_is_refused() {
    let mut bundle = bundle();
    mutate_receipt(&mut bundle, "use-after-free-c", |receipt| {
        receipt["candidate_identity"] = json!("a".repeat(64));
    });
    let report = verify_bundle(&bundle).expect("report");
    assert_eq!(report.status, CampaignStatus::Refused);
    assert!(codes(&report).contains(&CampaignRefusalCode::WrongCandidate));
}

#[test]
fn missing_raw_evidence_is_refused() {
    let mut bundle = bundle();
    bundle
        .raw
        .remove("receipts/raw/nondeterministic-c.transcript.json");
    let report = verify_bundle(&bundle).expect("report");
    assert_eq!(report.status, CampaignStatus::Refused);
    assert!(codes(&report).contains(&CampaignRefusalCode::MissingRawEvidence));
}

#[test]
fn unexpected_receipt_is_refused() {
    let mut bundle = bundle();
    let bytes = bundle
        .receipts
        .get(&receipt_path("use-after-free-c"))
        .expect("receipt")
        .clone();
    let mut receipt = value(&bytes);
    receipt["case_id"] = json!("invented-case");
    bundle
        .receipts
        .insert(receipt_path("invented-case"), encode(&receipt));
    let report = verify_bundle(&bundle).expect("report");
    assert_eq!(report.status, CampaignStatus::Refused);
    assert!(codes(&report).contains(&CampaignRefusalCode::UnexpectedReceipt));
}

#[test]
fn opening_digest_mismatch_is_refused() {
    let mut bundle = bundle();
    bundle.opening_sha256 = Some("b".repeat(64));
    let report = verify_bundle(&bundle).expect("report");
    assert_eq!(report.status, CampaignStatus::Refused);
    assert!(codes(&report).contains(&CampaignRefusalCode::OpeningDigestMismatch));
}

#[test]
fn typed_not_run_is_never_accepted() {
    let mut bundle = bundle();
    mutate_receipt(&mut bundle, "legal-transfer-free-c", |receipt| {
        receipt["observation"]["outcome"] = json!("not_run");
        receipt["observation"]["court_outcome"] = json!("");
        receipt["observation"]["findings"] = json!([]);
        receipt["adjudication"]["observed_outcome"] = json!("not_run");
        receipt["adjudication"]["decision"] = json!("not_run");
        receipt["adjudication"]["resolution"] = json!("not_applicable");
        receipt["release_decision"] = json!("blocked");
    });
    let mut closure = state(&bundle);
    let entries = closure["receipts"].as_array_mut().expect("receipts");
    for entry in entries {
        if entry["case_id"] == "legal-transfer-free-c" {
            entry["outcome"] = json!("not_run");
            entry["decision"] = json!("not_run");
        }
    }
    bundle.closure_bytes = encode(&closure);
    refresh_closure_reference(&mut bundle, "legal-transfer-free-c");
    let report = verify_bundle(&bundle).expect("report");
    assert_ne!(report.status, CampaignStatus::Accepted);
    let decisions = report
        .decisions
        .iter()
        .map(|count| (count.label.as_str(), count.count))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(decisions.get("not_run"), Some(&1));
}

#[test]
fn committed_manifest_and_receipts_are_canonical() {
    let bundle = bundle();
    assert_eq!(encode(&value(&bundle.closure_bytes)), bundle.closure_bytes);
    for (path, bytes) in &bundle.receipts {
        assert_eq!(
            encode(&value(bytes)),
            *bytes,
            "receipt {path} is not canonical"
        );
    }
}

#[test]
fn campaign_paths_are_relative_and_not_absolute() {
    let bundle = bundle();
    for path in bundle.receipts.keys().chain(bundle.raw.keys()) {
        assert!(!Path::new(path).is_absolute(), "{path}");
        assert!(!path.contains(".."), "{path}");
    }
}
