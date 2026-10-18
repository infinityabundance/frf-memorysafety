//! Phase 5.1 detector evidence and calibration seal controls.
//!
//! Every test executes. None is ignored. The fixtures are canonical
//! `frf-memorysafety.detector-evidence.v1` receipts generated in-process.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use frf_memorysafety::detector::{
    evaluate_calibration_json, CalibrationOutcome, CalibrationRefusalCode, CalibrationReport,
    ControlStatus, DetectorOrigin, RefusalSeverity, DETECTOR_EVIDENCE_SCHEMA, DETECTOR_SPEC,
    MAX_CAPTURE_BYTES,
};
use frf_memorysafety::identity::{canonical_bytes, hex_lower, require_canonical};

const BAD_ID: &str = "asan-use-after-free";
const GOOD_ID: &str = "asan-clean-control";
const MARKER: &str = "AddressSanitizer: heap-use-after-free";

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "frf-detector-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
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

fn sha(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex_lower(&hasher.finalize())
}

fn stream(text: &str) -> Value {
    json!({"text": text, "sha256": sha(text), "truncated": false})
}

fn set_stream(case: &mut Value, name: &str, text: &str) {
    case["capture"]
        .as_object_mut()
        .unwrap()
        .insert(name.to_owned(), stream(text));
}

fn known_bad() -> Value {
    let fixture = sha("known-bad use-after-free fixture");
    json!({
        "case_id": BAD_ID,
        "role": "known_bad",
        "fixture_digest": fixture,
        "expected_mechanism": "address",
        "legality": "test_only",
        "capture": {
            "stdout": stream(""),
            "stderr": stream(&format!("{MARKER}\n")),
            "exit_code": 1,
            "signal": null,
            "duration_ms": 12
        },
        "provenance": {
            "origin": "authentic_live_tool",
            "case_id": BAD_ID,
            "fixture_digest": fixture,
            "mechanism": "address",
            "legality": "test_only"
        },
        "finding": {
            "mechanism": "address",
            "diagnostic_fingerprint": MARKER,
            "source": "stderr"
        }
    })
}

fn known_good() -> Value {
    let fixture = sha("known-good clean fixture");
    json!({
        "case_id": GOOD_ID,
        "role": "known_good",
        "fixture_digest": fixture,
        "expected_mechanism": "address",
        "legality": "test_only",
        "capture": {
            "stdout": stream("clean run\n"),
            "stderr": stream(""),
            "exit_code": 0,
            "signal": null,
            "duration_ms": 7
        },
        "provenance": {
            "origin": "authentic_live_tool",
            "case_id": GOOD_ID,
            "fixture_digest": fixture,
            "mechanism": "address",
            "legality": "test_only"
        },
        "finding": null
    })
}

fn base_evidence() -> Value {
    json!({
        "schema": DETECTOR_EVIDENCE_SCHEMA,
        "spec": DETECTOR_SPEC,
        "detector": {
            "kind": "address_sanitizer",
            "tool_name": "clang",
            "tool_version": "18.1.8",
            "executable_sha256": "a".repeat(64),
            "invocation_argv": ["clang", "-fsanitize=address", "canary.c"],
            "environment_digest": "b".repeat(64),
            "mechanism_enablement": ["address"],
            "build": {
                "flags": ["-fsanitize=address", "-O1", "-g"],
                "target": "x86_64-unknown-linux-gnu",
                "profile": "release",
                "build_directory": "/build/asan",
                "artifact_sha256": "c".repeat(64)
            },
            "baseline_build": {
                "flags": ["-O2"],
                "target": "x86_64-unknown-linux-gnu",
                "profile": "release",
                "build_directory": "/build/baseline",
                "artifact_sha256": "d".repeat(64)
            },
            "build_separation_verified": true
        },
        "cases": [known_bad(), known_good()]
    })
}

fn case_mut(value: &mut Value, index: usize) -> &mut Value {
    &mut value["cases"].as_array_mut().unwrap()[index]
}

fn calibrate(value: &Value) -> CalibrationReport {
    evaluate_calibration_json(&canonical_bytes(value).unwrap()).unwrap()
}

fn report_error_category(value: &Value) -> String {
    match evaluate_calibration_json(&canonical_bytes(value).unwrap()) {
        Ok(_) => "none".to_owned(),
        Err(error) => format!("{:?}", error.category()),
    }
}

fn write_fixture(value: &Value) -> (TempDir, PathBuf) {
    let temp = TempDir::new("receipt");
    let path = temp.path().join("receipt.json");
    fs::write(&path, canonical_bytes(value).unwrap()).unwrap();
    (temp, path)
}

fn run_cli(value: &Value) -> i32 {
    let (_temp, path) = write_fixture(value);
    frf_memorysafety::cli::run([
        "detector".to_owned(),
        "calibrate".to_owned(),
        path.to_str().unwrap().to_owned(),
        "--json".to_owned(),
    ])
}

fn has_code(report: &CalibrationReport, code: CalibrationRefusalCode) -> bool {
    report.refusals.iter().any(|refusal| refusal.code == code)
}

#[test]
fn positive_sensitivity_and_specificity_controls_calibrate() {
    let report = calibrate(&base_evidence());
    assert_eq!(report.outcome, CalibrationOutcome::Calibrated);
    assert_eq!(report.sensitivity.passed, 1);
    assert_eq!(report.sensitivity.total, 1);
    assert_eq!(report.specificity.passed, 1);
    assert_eq!(report.specificity.total, 1);
    assert_eq!(report.build_separation, ControlStatus::Pass);
    assert_eq!(report.authenticity, ControlStatus::Pass);
    assert_eq!(report.case_count, 2);
    assert!(report.refusals.is_empty());
    assert_eq!(report.mechanisms, vec!["address".to_owned()]);
}

#[test]
fn dead_detector_exit_zero_is_refused() {
    let mut value = base_evidence();
    case_mut(&mut value, 0)["capture"]["exit_code"] = json!(0);
    let report = calibrate(&value);
    assert_eq!(report.outcome, CalibrationOutcome::Refused);
    assert!(has_code(&report, CalibrationRefusalCode::DeadDetector));
    assert_eq!(report.sensitivity.passed, 0);
}

#[test]
fn dead_detector_without_finding_is_refused() {
    let mut value = base_evidence();
    case_mut(&mut value, 0)
        .as_object_mut()
        .unwrap()
        .remove("finding");
    let report = calibrate(&value);
    assert_eq!(report.outcome, CalibrationOutcome::Refused);
    assert!(has_code(&report, CalibrationRefusalCode::MissingFinding));
    assert_eq!(report.sensitivity.passed, 0);
}

#[test]
fn stdout_text_alone_is_not_a_finding() {
    let mut value = base_evidence();
    // The fake program prints the expected marker but supplies no typed
    // finding. Text alone can never establish detection.
    set_stream(case_mut(&mut value, 0), "stderr", &format!("{MARKER}\n"));
    case_mut(&mut value, 0)
        .as_object_mut()
        .unwrap()
        .remove("finding");
    let report = calibrate(&value);
    assert_eq!(report.outcome, CalibrationOutcome::Refused);
    assert!(has_code(&report, CalibrationRefusalCode::MissingFinding));
}

#[test]
fn misconfigured_build_flags_are_refused() {
    let mut value = base_evidence();
    value["detector"]["build"]["flags"] = json!(["-O1", "-g"]);
    let report = calibrate(&value);
    assert_eq!(report.outcome, CalibrationOutcome::Refused);
    assert!(has_code(
        &report,
        CalibrationRefusalCode::MisconfiguredBuildFlags
    ));
    assert_eq!(report.build_separation, ControlStatus::Fail);
    assert_eq!(report.sensitivity.passed, 0);
}

#[test]
fn missing_mechanism_enablement_is_refused() {
    let mut value = base_evidence();
    value["detector"]["mechanism_enablement"] = json!([]);
    let report = calibrate(&value);
    assert_eq!(report.outcome, CalibrationOutcome::Refused);
    assert!(has_code(
        &report,
        CalibrationRefusalCode::MissingMechanismEnablement
    ));
    assert_eq!(report.build_separation, ControlStatus::Fail);
}

#[test]
fn build_separation_pass_and_fail_are_distinguished() {
    let passing = calibrate(&base_evidence());
    assert_eq!(passing.build_separation, ControlStatus::Pass);

    let mut shared_directory = base_evidence();
    shared_directory["detector"]["baseline_build"]["build_directory"] = json!("/build/asan");
    let report = calibrate(&shared_directory);
    assert_eq!(report.build_separation, ControlStatus::Fail);
    assert!(has_code(
        &report,
        CalibrationRefusalCode::BuildSeparationMismatch
    ));

    let mut instrumented_baseline = base_evidence();
    instrumented_baseline["detector"]["baseline_build"]["flags"] =
        json!(["-fsanitize=address", "-O2"]);
    let report = calibrate(&instrumented_baseline);
    assert_eq!(report.build_separation, ControlStatus::Fail);
    assert!(has_code(
        &report,
        CalibrationRefusalCode::BuildSeparationMismatch
    ));

    let mut unverified = base_evidence();
    unverified["detector"]["build_separation_verified"] = json!(false);
    let report = calibrate(&unverified);
    assert_eq!(report.build_separation, ControlStatus::Fail);
    assert!(has_code(
        &report,
        CalibrationRefusalCode::BuildSeparationMismatch
    ));
}

#[test]
fn harmless_control_finding_is_refused() {
    let mut value = base_evidence();
    set_stream(case_mut(&mut value, 1), "stdout", MARKER);
    case_mut(&mut value, 1)["finding"] = json!({
        "mechanism": "address",
        "diagnostic_fingerprint": MARKER,
        "source": "stdout"
    });
    let report = calibrate(&value);
    assert_eq!(report.outcome, CalibrationOutcome::Refused);
    assert!(has_code(
        &report,
        CalibrationRefusalCode::HarmlessControlFinding
    ));
    assert_eq!(report.specificity.passed, 0);
    assert_eq!(report.specificity.total, 1);
}

#[test]
fn harmless_control_dirty_exit_is_refused() {
    let mut value = base_evidence();
    case_mut(&mut value, 1)["capture"]["exit_code"] = json!(1);
    let report = calibrate(&value);
    assert_eq!(report.outcome, CalibrationOutcome::Refused);
    assert!(has_code(
        &report,
        CalibrationRefusalCode::HarmlessControlDirtyExit
    ));
    assert_eq!(report.specificity.passed, 0);
}

#[test]
fn mock_provider_transport_is_refused() {
    let mut value = base_evidence();
    case_mut(&mut value, 0)["provenance"]["origin"] = json!("mock_provider");
    let report = calibrate(&value);
    assert_eq!(report.outcome, CalibrationOutcome::Refused);
    assert!(has_code(
        &report,
        CalibrationRefusalCode::MockProviderTransport
    ));
    assert_eq!(report.authenticity, ControlStatus::Fail);
    assert_eq!(report.sensitivity.passed, 0);
}

#[test]
fn substitute_and_modeled_provenance_are_refused() {
    for (origin, code) in [
        ("substitute", CalibrationRefusalCode::SubstituteTransport),
        ("modeled", CalibrationRefusalCode::ModeledEvidence),
    ] {
        let mut value = base_evidence();
        case_mut(&mut value, 0)["provenance"]["origin"] = json!(origin);
        let report = calibrate(&value);
        assert_eq!(report.outcome, CalibrationOutcome::Refused);
        assert!(has_code(&report, code), "expected {code:?} for {origin}");
        assert_eq!(report.sensitivity.passed, 0);
    }
}

#[test]
fn fake_stdout_marker_without_authentic_identity_is_refused() {
    let mut value = base_evidence();
    value["detector"]["tool_version"] = json!("unknown");
    value["detector"]["executable_sha256"] = json!("0".repeat(64));
    let report = calibrate(&value);
    assert_eq!(report.outcome, CalibrationOutcome::Refused);
    assert!(has_code(
        &report,
        CalibrationRefusalCode::UntrustedDetectorIdentity
    ));
    assert!(has_code(&report, CalibrationRefusalCode::FakeStdoutMarker));
    assert_eq!(report.authenticity, ControlStatus::Fail);
}

#[test]
fn diagnostic_fingerprint_must_appear_in_the_declared_stream() {
    let mut value = base_evidence();
    case_mut(&mut value, 0)["finding"]["diagnostic_fingerprint"] =
        json!("thread-sanitizer: data race");
    let report = calibrate(&value);
    assert_eq!(report.outcome, CalibrationOutcome::Refused);
    assert!(has_code(
        &report,
        CalibrationRefusalCode::FindingNotInCapture
    ));
    assert_eq!(report.sensitivity.passed, 0);
}

#[test]
fn mechanism_mismatch_is_refused() {
    let mut value = base_evidence();
    for case in [0, 1] {
        case_mut(&mut value, case)["expected_mechanism"] = json!("thread");
        case_mut(&mut value, case)["provenance"]["mechanism"] = json!("thread");
    }
    case_mut(&mut value, 0)["finding"]["mechanism"] = json!("thread");
    let report = calibrate(&value);
    assert_eq!(report.outcome, CalibrationOutcome::Refused);
    assert!(has_code(&report, CalibrationRefusalCode::MechanismMismatch));
}

#[test]
fn missing_sensitivity_or_specificity_case_is_refused() {
    let mut no_bad = base_evidence();
    no_bad["cases"].as_array_mut().unwrap().remove(0);
    let report = calibrate(&no_bad);
    assert_eq!(report.outcome, CalibrationOutcome::Refused);
    assert!(has_code(
        &report,
        CalibrationRefusalCode::MissingSensitivityCase
    ));

    let mut no_good = base_evidence();
    no_good["cases"].as_array_mut().unwrap().remove(1);
    let report = calibrate(&no_good);
    assert_eq!(report.outcome, CalibrationOutcome::Refused);
    assert!(has_code(
        &report,
        CalibrationRefusalCode::MissingSpecificityCase
    ));
}

#[test]
fn illegal_case_is_refused() {
    let mut value = base_evidence();
    case_mut(&mut value, 0)["legality"] = json!("illegal");
    case_mut(&mut value, 0)["provenance"]["legality"] = json!("illegal");
    let report = calibrate(&value);
    assert_eq!(report.outcome, CalibrationOutcome::Refused);
    assert!(has_code(&report, CalibrationRefusalCode::IllegalCase));
}

#[test]
fn tampered_stdout_digest_is_an_integrity_refusal() {
    let mut value = base_evidence();
    case_mut(&mut value, 1)["capture"]["stdout"]["text"] = json!("tampered after capture\n");
    let report = calibrate(&value);
    assert_eq!(report.outcome, CalibrationOutcome::Refused);
    assert!(has_code(
        &report,
        CalibrationRefusalCode::CaptureDigestMismatch
    ));
    assert_eq!(report.build_separation, ControlStatus::NotEvaluated);
    assert_eq!(report.authenticity, ControlStatus::NotEvaluated);
    assert_eq!(report.sensitivity.passed, 0);
    assert_eq!(report.specificity.passed, 0);
    assert!(report
        .refusals
        .iter()
        .any(|refusal| refusal.severity == RefusalSeverity::Integrity));
}

#[test]
fn tampered_stderr_digest_is_an_integrity_refusal() {
    let mut value = base_evidence();
    case_mut(&mut value, 0)["capture"]["stderr"]["sha256"] = json!(sha("different"));
    let report = calibrate(&value);
    assert!(has_code(
        &report,
        CalibrationRefusalCode::CaptureDigestMismatch
    ));
    assert!(report.integrity_failed());
}

#[test]
fn duplicate_case_identifier_is_an_integrity_refusal() {
    let mut value = base_evidence();
    case_mut(&mut value, 1)["case_id"] = json!(BAD_ID);
    case_mut(&mut value, 1)["provenance"]["case_id"] = json!(BAD_ID);
    let report = calibrate(&value);
    assert!(has_code(&report, CalibrationRefusalCode::DuplicateCaseId));
    assert!(report.integrity_failed());
}

#[test]
fn provenance_case_and_fixture_mismatches_are_integrity_refusals() {
    let mut case_mismatch = base_evidence();
    case_mut(&mut case_mismatch, 0)["provenance"]["case_id"] = json!("other-case");
    let report = calibrate(&case_mismatch);
    assert!(has_code(
        &report,
        CalibrationRefusalCode::ProvenanceCaseMismatch
    ));
    assert!(report.integrity_failed());

    let mut fixture_mismatch = base_evidence();
    case_mut(&mut fixture_mismatch, 0)["fixture_digest"] = json!(sha("other fixture"));
    let report = calibrate(&fixture_mismatch);
    assert!(has_code(
        &report,
        CalibrationRefusalCode::ProvenanceFixtureMismatch
    ));
    assert!(report.integrity_failed());
}

#[test]
fn oversized_and_truncated_captures_are_integrity_refusals() {
    let oversized = "x".repeat(MAX_CAPTURE_BYTES + 1);
    let mut value = base_evidence();
    set_stream(case_mut(&mut value, 1), "stdout", &oversized);
    let report = calibrate(&value);
    assert!(has_code(&report, CalibrationRefusalCode::CaptureOversized));
    assert!(report.integrity_failed());

    let mut truncated = base_evidence();
    case_mut(&mut truncated, 1)["capture"]["stdout"]["truncated"] = json!(true);
    let report = calibrate(&truncated);
    assert!(has_code(&report, CalibrationRefusalCode::CaptureTruncated));
    assert!(report.integrity_failed());
}

#[test]
fn unknown_fields_and_duplicate_json_keys_are_integrity_errors() {
    let mut unknown = base_evidence();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), json!(true));
    assert_eq!(report_error_category(&unknown), "Integrity");

    let mut nested_unknown = base_evidence();
    nested_unknown["detector"]
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), json!(true));
    assert_eq!(report_error_category(&nested_unknown), "Integrity");

    let canonical = String::from_utf8(canonical_bytes(&base_evidence()).unwrap()).unwrap();
    let duplicated = canonical.replacen(
        "\"schema\":\"frf-memorysafety.detector-evidence.v1\"",
        "\"schema\":\"frf-memorysafety.detector-evidence.v1\",\"schema\":\"duplicate\"",
        1,
    );
    assert_ne!(canonical, duplicated);
    let error = evaluate_calibration_json(duplicated.as_bytes()).unwrap_err();
    assert!(matches!(
        error.category(),
        frf_memorysafety::detector::DetectorErrorCategory::Integrity
    ));
}

#[test]
fn custom_detector_kind_calibrates_its_declared_mechanism() {
    let mut value = base_evidence();
    value["detector"]["kind"] = json!({"custom": "my-detector"});
    value["detector"]["tool_name"] = json!("my-detector");
    value["detector"]["tool_version"] = json!("1.2.3");
    value["detector"]["mechanism_enablement"] = json!(["my_mechanism"]);
    value["detector"]["build"]["flags"] = json!(["-Dcustom=1"]);
    value["detector"]["baseline_build"]["flags"] = json!(["-O2"]);
    for case in [0, 1] {
        case_mut(&mut value, case)["expected_mechanism"] = json!("my_mechanism");
        case_mut(&mut value, case)["provenance"]["mechanism"] = json!("my_mechanism");
    }
    case_mut(&mut value, 0)["finding"]["mechanism"] = json!("my_mechanism");
    let report = calibrate(&value);
    assert_eq!(report.outcome, CalibrationOutcome::Calibrated);
    assert_eq!(report.mechanisms, vec!["my_mechanism".to_owned()]);
}

#[test]
fn calibration_report_is_deterministic_and_canonical() {
    let bytes = canonical_bytes(&base_evidence()).unwrap();
    let first = evaluate_calibration_json(&bytes).unwrap();
    let second = evaluate_calibration_json(&bytes).unwrap();
    let first_bytes = first.canonical_bytes().unwrap();
    let second_bytes = second.canonical_bytes().unwrap();
    assert_eq!(first_bytes, second_bytes);
    require_canonical(&first_bytes).unwrap();
    assert_eq!(first.evidence_digest, second.evidence_digest);
    assert_eq!(first.identity_digest, second.identity_digest);
}

#[test]
fn cli_uses_section_14_statuses_and_emits_canonical_json() {
    assert_eq!(
        frf_memorysafety::cli::run(["detector".to_owned(), "calibrate".to_owned()]),
        2
    );
    assert_eq!(
        frf_memorysafety::cli::run([
            "detector".to_owned(),
            "calibrate".to_owned(),
            "--live".to_owned()
        ]),
        6
    );
    assert_eq!(
        frf_memorysafety::cli::run([
            "detector".to_owned(),
            "calibrate".to_owned(),
            "/definitely/not/a/receipt.json".to_owned()
        ]),
        2
    );

    assert_eq!(run_cli(&base_evidence()), 0);

    let mut dead = base_evidence();
    case_mut(&mut dead, 0)["capture"]["exit_code"] = json!(0);
    assert_eq!(run_cli(&dead), 5);

    let mut tampered = base_evidence();
    case_mut(&mut tampered, 1)["capture"]["stdout"]["text"] = json!("tampered\n");
    assert_eq!(run_cli(&tampered), 3);

    let (_temp, path) = write_fixture(&base_evidence());
    let binary = env!("CARGO_BIN_EXE_frf-memorysafety");
    let output = Command::new(binary)
        .args(["detector", "calibrate", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    require_canonical(&output.stdout).unwrap();
    let report: CalibrationReport = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report.outcome, CalibrationOutcome::Calibrated);
    assert_eq!(
        report.refusals.len(),
        0,
        "unexpected refusals: {:?}",
        report.refusals
    );
}

#[test]
fn report_preserves_refusal_severity_and_claim_ceiling() {
    let mut value = base_evidence();
    case_mut(&mut value, 0)["provenance"]["origin"] = json!("mock_provider");
    let report = calibrate(&value);
    assert!(report.refusals.iter().any(|refusal| {
        refusal.code == CalibrationRefusalCode::MockProviderTransport
            && refusal.severity == RefusalSeverity::Detector
    }));
    assert!(report
        .claim_ceiling
        .contains("mechanism- and case-specific"));
    let origin = DetectorOrigin::MockProvider;
    assert!(!origin.is_authentic());
}
