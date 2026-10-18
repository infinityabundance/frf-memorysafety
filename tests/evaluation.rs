//! Phase 9.1 evaluation-harness tests.
//!
//! These tests execute the harness's in-process paths and verify the committed
//! receipts. They never build or run anything on the host; the default gate runs
//! them inside the hardened container.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use frf_memorysafety::evaluation::{
    build_receipt, held_out, observe_case, parse_protocol, sha256_hex, verify_receipts, ArmSpec,
    CaseSpec, Environment, Measurement, Observation, NOT_RUN,
};
use frf_memorysafety::identity::canonical_bytes;
use serde_json::{json, Value};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "frf-memorysafety-eval-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temporary directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn protocol_path() -> PathBuf {
    PathBuf::from("evaluation/protocol.json")
}

fn protocol_bytes() -> Vec<u8> {
    fs::read(protocol_path()).expect("committed protocol")
}

fn copy_receipts(source: &Path, destination: &Path) {
    for entry in fs::read_dir(source).expect("receipt directory") {
        let entry = entry.expect("receipt entry");
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            let target = destination.join(path.file_name().expect("file name"));
            fs::copy(&path, &target).expect("copy receipt");
        }
    }
}

fn read_value(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("read value")).expect("parse value")
}

fn write_value(path: &Path, value: &Value) {
    let bytes = canonical_bytes(value).expect("canonical value");
    fs::write(path, bytes).expect("write value");
}

fn environment() -> Environment {
    Environment {
        crate_version: "0.9.0".to_owned(),
        rustc_version: "rustc test".to_owned(),
        image: "test-image".to_owned(),
        image_id: "test-id".to_owned(),
        command: vec!["frf-eval".to_owned(), "child".to_owned()],
    }
}

fn observation() -> Observation {
    Observation {
        observed: "unsupported".to_owned(),
        input_sha256: "a".repeat(64),
        detail: "test observation".to_owned(),
        vm_hwm_kb: None,
    }
}

fn case_and_arm() -> (CaseSpec, ArmSpec) {
    let protocol = parse_protocol(&protocol_bytes()).expect("protocol");
    let case_ref = protocol.case("S2-ungrounded-self-cycle").expect("case");
    let case = CaseSpec {
        id: case_ref.id.clone(),
        hypothesis: case_ref.hypothesis.clone(),
        category: case_ref.category.clone(),
        description: case_ref.description.clone(),
        truth: case_ref.truth.clone(),
        accept_outcomes: case_ref.accept_outcomes.clone(),
        arms: case_ref.arms.clone(),
    };
    let arm_ref = case.arms.iter().find(|arm| arm.id == "lfp").expect("arm");
    let arm = ArmSpec {
        id: arm_ref.id.clone(),
        kind: arm_ref.kind.clone(),
        expected: arm_ref.expected.clone(),
    };
    (case, arm)
}

#[test]
fn protocol_freeze_matches_the_companion_digest() {
    let bytes = protocol_bytes();
    let protocol = parse_protocol(&bytes).expect("protocol");
    let digest = sha256_hex(&bytes);
    let freeze = fs::read_to_string("evaluation/PRE-REGISTRATION.sha256").expect("freeze record");
    assert!(freeze.contains(&digest));
    let document =
        fs::read_to_string("evaluation/PRE-REGISTRATION.md").expect("pre-registration document");
    assert!(document.contains(&digest));
    assert_eq!(protocol.expected_receipts(), 60);
    assert_eq!(protocol.split_counts(), (20, 11));
}

#[test]
fn held_out_rule_is_fixed_and_nonempty() {
    assert!(held_out("S2-ungrounded-self-cycle"));
    assert!(!held_out("S1-grounded-cycle"));
    let held = (0..100)
        .filter(|index| held_out(&format!("case-{index}")))
        .count();
    assert!(held > 0 && held < 100);
}

#[test]
fn receipt_is_refused_without_required_measurements() {
    let (case, arm) = case_and_arm();
    let observation = observation();
    let environment = environment();
    let digest = "b".repeat(64);
    let error = build_receipt(
        &digest,
        &case,
        &arm,
        &observation,
        None,
        &environment,
        digest.clone(),
        digest.clone(),
    )
    .expect_err("no measurement");
    assert!(error.to_string().contains("missing measurement"));

    let zero = Measurement {
        wall_time_ms: 0,
        peak_rss_kb: 0,
        output_bytes: 10,
    };
    assert!(build_receipt(
        &digest,
        &case,
        &arm,
        &observation,
        Some(zero),
        &environment,
        digest.clone(),
        digest.clone(),
    )
    .is_err());

    let valid = Measurement {
        wall_time_ms: 1,
        peak_rss_kb: 1024,
        output_bytes: 10,
    };
    let receipt = build_receipt(
        &digest,
        &case,
        &arm,
        &observation,
        Some(valid),
        &environment,
        digest.clone(),
        digest.clone(),
    )
    .expect("valid receipt");
    assert!(receipt.pass);
    assert_eq!(receipt.observed, "unsupported");
}

#[test]
fn verification_rejects_missing_receipts() {
    let directory = TempDir::new("missing");
    let report = verify_receipts(&protocol_path(), directory.path()).expect("verification");
    assert_eq!(report.valid, 0);
    assert!(report
        .errors
        .iter()
        .any(|error| error.contains("missing receipt")));
    assert_eq!(report.receipt_count, 0);
}

#[test]
fn verification_rejects_a_fabricated_observation() {
    let directory = TempDir::new("fabricated");
    copy_receipts(Path::new("evaluation/receipts"), directory.path());
    let target = directory.path().join("S2-ungrounded-self-cycle__lfp.json");
    let mut value = read_value(&target);
    value["observed"] = json!("supported");
    value["pass"] = json!(false);
    write_value(&target, &value);

    let report = verify_receipts(&protocol_path(), directory.path()).expect("verification");
    assert_eq!(report.valid, 0);
    assert!(report.errors.iter().any(|error| {
        error.contains("observation digest mismatch")
            || error.contains("experiment digest mismatch")
    }));
}

#[test]
fn verification_detects_a_claim_without_a_matching_observation() {
    let directory = TempDir::new("claim");
    copy_receipts(Path::new("evaluation/receipts"), directory.path());
    let mut protocol = read_value(&protocol_path());
    let claims = protocol["claims"].as_array_mut().expect("claims");
    let c1 = claims
        .iter_mut()
        .find(|claim| claim["id"] == json!("C1"))
        .expect("C1");
    c1["requires"][0]["expected"] = json!("supported");
    claims.push(json!({
        "id": "C99",
        "hypothesis": "H1",
        "text": "A claim with no receipt.",
        "requires": [{"case": "NO-SUCH-CASE", "arm": "lfp", "expected": "x"}]
    }));
    let mutated = directory.path().join("protocol.json");
    write_value(&mutated, &protocol);

    let report = verify_receipts(&mutated, directory.path()).expect("verification");
    let c1 = report
        .claims
        .iter()
        .find(|claim| claim.id == "C1")
        .expect("C1 report");
    assert_eq!(c1.status, "falsified");
    assert!(c1
        .problems
        .iter()
        .any(|problem| problem.contains("claim requires")));
    let c99 = report
        .claims
        .iter()
        .find(|claim| claim.id == "C99")
        .expect("C99 report");
    assert_eq!(c99.status, "falsified");
    assert!(c99
        .problems
        .iter()
        .any(|problem| problem.contains("missing receipt")));
    assert_eq!(report.valid, 0);
}

#[test]
fn blocked_controls_are_typed_not_run() {
    for (case, arm) in [
        ("D6-detector-live-miri", "live_miri"),
        ("R5-proof-live-coq", "live_coq"),
        ("E6-discovery-authentic-chain", "bridge_verify"),
    ] {
        let observed = observe_case(case, arm).expect("observation");
        assert_eq!(observed.observed, NOT_RUN, "{case}");
        let path = PathBuf::from("evaluation/receipts").join(format!("{case}__{arm}.json"));
        let receipt = read_value(&path);
        assert_eq!(receipt["observed"], json!(NOT_RUN));
        assert!(
            receipt["blocked"].is_string(),
            "{case} has no blocked reason"
        );
    }
}

#[test]
fn production_and_naive_arms_exercise_the_declared_differences() {
    let cases = [
        ("S2-ungrounded-self-cycle", "lfp", "unsupported"),
        ("S2-ungrounded-self-cycle", "gfp", "supported"),
        (
            "S4-hidden-intermediate-cut",
            "all_node_certificates",
            "cut_applies",
        ),
        (
            "S4-hidden-intermediate-cut",
            "root_only_certificates",
            "cut_missed",
        ),
        (
            "P2-path-descendant-disjoint",
            "exact_footprint",
            "compatible_within_finite_footprint",
        ),
        (
            "P2-path-descendant-disjoint",
            "boolean_aliasing",
            "observed_conflict",
        ),
        (
            "D2-detector-raw-stdout-no-finding",
            "calibrated",
            "refused_missing_finding",
        ),
        (
            "D2-detector-raw-stdout-no-finding",
            "raw_stdout",
            "calibrated",
        ),
        (
            "R2-proof-unchecked-wrapper",
            "closure_and_correspondence",
            "rejected_unchecked_implementation",
        ),
        (
            "R2-proof-unchecked-wrapper",
            "parser_only",
            "accepted_within_scope",
        ),
        (
            "E1-discovery-modeled-provider",
            "bridge_verify",
            "refused_modeled_evidence",
        ),
        (
            "E1-discovery-modeled-provider",
            "provenance_ignored",
            "complete",
        ),
    ];
    for (case, arm, expected) in cases {
        let observed = observe_case(case, arm).expect("observation");
        assert_eq!(observed.observed, expected, "{case}::{arm}");
    }
}

#[test]
fn committed_receipts_verify_with_exact_counts() {
    let report =
        verify_receipts(&protocol_path(), Path::new("evaluation/receipts")).expect("verification");
    assert_eq!(report.valid, 1, "errors: {:?}", report.errors);
    assert_eq!(report.receipt_count, 60);
    assert_eq!(report.expected_receipt_count, 60);
    assert_eq!(report.held_out_cases, 20);
    assert_eq!(report.development_cases, 11);
    assert!(report.errors.is_empty());
    assert!(report
        .hypotheses
        .iter()
        .all(|hypothesis| hypothesis.failed == 0));
    assert!(report
        .claims
        .iter()
        .all(|claim| claim.status == "supported"));
    assert!(report.decision.held_out.contains_key("lfp"));
    assert!(report.decision.held_out.contains_key("parser_only"));
}
