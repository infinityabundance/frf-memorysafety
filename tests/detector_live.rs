//! Phase 5.2 live detector seal controls.
//!
//! Every test executes; none is ignored. Without `FRF_DETECTOR_LIVE=1` each
//! test exercises the typed `NOT_RUN` path. With the flag set, the same tests
//! run the closed checked-in fixtures and either assert the live calibration or
//! print an honest `NOT_RUN` line with the exact reason. A mechanism that runs
//! but fails a control panics the test and is reported as a failure, never as a
//! pass.

#![cfg(unix)]

use frf_memorysafety::detector::live::{
    availability, calibrate_live, gate_kinds, live_enabled, LiveCalibration, LiveStatus, LIVE_ENV,
};
use frf_memorysafety::detector::{
    evaluate_calibration, CalibrationOutcome, CalibrationRefusalCode, CalibrationRole,
    CaptureStream, ControlStatus, DetectorOrigin,
};
use frf_memorysafety::DetectorKind;
use sha2::{Digest, Sha256};

fn sha_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut text = String::with_capacity(64);
    for byte in digest {
        let _ = write!(&mut text, "{byte:02x}");
    }
    text
}

fn assert_not_run(kind: &DetectorKind) {
    let result = calibrate_live(kind);
    assert_eq!(
        result.status,
        LiveStatus::NotRun,
        "expected typed NOT_RUN for {kind:?}"
    );
    assert!(result.is_not_run());
    assert!(result
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains(LIVE_ENV));
    assert!(result.evidence.is_none());
    assert!(result.report.is_none());
}

fn assert_live_evidence(result: &LiveCalibration) {
    let evidence = result.evidence.as_ref().expect("live evidence");
    let report = result.report.as_ref().expect("calibration report");
    assert_eq!(report.outcome, CalibrationOutcome::Calibrated);
    assert!(report.sensitivity.total >= 1);
    assert_eq!(report.sensitivity.passed, report.sensitivity.total);
    assert!(report.specificity.total >= 1);
    assert_eq!(report.specificity.passed, report.specificity.total);
    assert_eq!(report.build_separation, ControlStatus::Pass);
    assert_eq!(report.authenticity, ControlStatus::Pass);
    assert!(report.refusals.is_empty(), "{:?}", report.refusals);
    assert_eq!(report.case_count, evidence.cases.len());
    assert_eq!(evidence.detector.kind, result.detector);
    assert!(!evidence.detector.invocation_argv.is_empty());
    assert!(!evidence.detector.tool_version.trim().is_empty());
    assert_eq!(evidence.detector.executable_sha256.len(), 64);
    assert_eq!(evidence.detector.environment_digest.len(), 64);
    assert_ne!(
        evidence.detector.build.build_directory,
        evidence.detector.baseline_build.build_directory
    );
    assert_ne!(
        evidence.detector.build.artifact_sha256,
        evidence.detector.baseline_build.artifact_sha256
    );
    assert_eq!(
        evidence.detector.build.target,
        evidence.detector.baseline_build.target
    );
    assert_eq!(
        evidence.detector.build.profile,
        evidence.detector.baseline_build.profile
    );

    let mut has_bad = false;
    let mut has_good = false;
    for case in &evidence.cases {
        assert_eq!(case.provenance.origin, DetectorOrigin::AuthenticLiveTool);
        assert_eq!(case.legality, frf_memorysafety::CaseLegality::TestOnly);
        assert_eq!(
            case.capture.stdout.sha256,
            sha_hex(case.capture.stdout.text.as_bytes())
        );
        assert_eq!(
            case.capture.stderr.sha256,
            sha_hex(case.capture.stderr.text.as_bytes())
        );
        assert!(!case.capture.stdout.truncated);
        assert!(!case.capture.stderr.truncated);
        match case.role {
            CalibrationRole::KnownBad => {
                has_bad = true;
                assert_ne!(case.capture.exit_code, 0, "{} exited zero", case.case_id);
                let finding = case
                    .finding
                    .as_ref()
                    .unwrap_or_else(|| panic!("{} has no finding", case.case_id));
                let stream = match finding.source {
                    CaptureStream::Stdout => &case.capture.stdout,
                    CaptureStream::Stderr => &case.capture.stderr,
                };
                assert!(
                    stream.text.contains(&finding.diagnostic_fingerprint),
                    "{} fingerprint {:?} is absent",
                    case.case_id,
                    finding.diagnostic_fingerprint
                );
            }
            CalibrationRole::KnownGood => {
                has_good = true;
                assert_eq!(case.capture.exit_code, 0, "{} exited nonzero", case.case_id);
                assert!(
                    case.finding.is_none(),
                    "{} produced a finding",
                    case.case_id
                );
            }
        }
    }
    assert!(has_bad, "no known-bad sensitivity case");
    assert!(has_good, "no known-good specificity case");
}

fn assert_seal_controls(result: &LiveCalibration) {
    let evidence = result.evidence.as_ref().expect("live evidence");

    let mut missing = evidence.clone();
    let bad = missing
        .cases
        .iter_mut()
        .find(|case| case.role == CalibrationRole::KnownBad)
        .expect("known-bad case");
    bad.finding = None;
    let report = evaluate_calibration(&missing).expect("report");
    assert!(report
        .refusals
        .iter()
        .any(|refusal| refusal.code == CalibrationRefusalCode::MissingFinding));

    let mut mocked = evidence.clone();
    mocked.cases[0].provenance.origin = DetectorOrigin::MockProvider;
    let report = evaluate_calibration(&mocked).expect("report");
    assert!(report
        .refusals
        .iter()
        .any(|refusal| refusal.code == CalibrationRefusalCode::MockProviderTransport));

    let mut tampered = evidence.clone();
    let good = tampered
        .cases
        .iter_mut()
        .find(|case| case.role == CalibrationRole::KnownGood)
        .expect("known-good case");
    good.capture.stdout.text.push_str("tampered\n");
    let report = evaluate_calibration(&tampered).expect("report");
    assert!(report.integrity_failed());

    let mut marker_only = evidence.clone();
    let bad = marker_only
        .cases
        .iter_mut()
        .find(|case| case.role == CalibrationRole::KnownBad)
        .expect("known-bad case");
    bad.capture.exit_code = 0;
    bad.finding = None;
    let report = evaluate_calibration(&marker_only).expect("report");
    assert!(report
        .refusals
        .iter()
        .any(|refusal| refusal.code == CalibrationRefusalCode::DeadDetector));
    assert!(report
        .refusals
        .iter()
        .any(|refusal| refusal.code == CalibrationRefusalCode::MissingFinding));
}

fn run_live(kind: &DetectorKind) {
    let label = format!("{kind:?}");
    if !live_enabled() {
        assert_not_run(kind);
        return;
    }
    let result = calibrate_live(kind);
    match result.status {
        LiveStatus::NotRun => {
            println!(
                "LIVE_DETECTOR_RESULT kind={label} status=NOT_RUN reason={}",
                result.reason.as_deref().unwrap_or("instrument unavailable")
            );
        }
        LiveStatus::Refused => {
            let report = result.report.as_ref().expect("refused report");
            if let Some(evidence) = result.evidence.as_ref() {
                for case in &evidence.cases {
                    eprintln!(
                        "case={} exit={} stdout={:?} stderr={:?}",
                        case.case_id,
                        case.capture.exit_code,
                        case.capture.stdout.text,
                        case.capture.stderr.text
                    );
                }
            }
            panic!(
                "LIVE_DETECTOR_RESULT kind={label} status=REFUSED refusals={:?}",
                report.refusals
            );
        }
        LiveStatus::Calibrated => {
            assert_live_evidence(&result);
            assert_seal_controls(&result);
            println!("LIVE_DETECTOR_RESULT kind={label} status=PASS");
        }
    }
}

#[test]
fn disabled_live_adapter_reports_typed_not_run() {
    if live_enabled() {
        return;
    }
    for kind in [
        DetectorKind::Miri,
        DetectorKind::AddressSanitizer,
        DetectorKind::LeakSanitizer,
        DetectorKind::ThreadSanitizer,
        DetectorKind::Loom,
        DetectorKind::Kani,
        DetectorKind::Custom(frf_memorysafety::detector::live::OPENSSL_KAT_ID.to_owned()),
    ] {
        assert_not_run(&kind);
    }
}

#[test]
fn live_cli_reports_not_run_when_disabled() {
    if live_enabled() {
        return;
    }
    assert_eq!(
        frf_memorysafety::cli::run([
            "detector".to_owned(),
            "calibrate".to_owned(),
            "--live".to_owned(),
            "--detector".to_owned(),
            "miri".to_owned(),
            "--json".to_owned(),
        ]),
        6
    );
}

#[test]
fn availability_is_typed_and_covers_builtin_kinds() {
    let entries = availability();
    let ids: Vec<&str> = entries.iter().map(|entry| entry.id).collect();
    for id in gate_kinds() {
        assert!(ids.contains(&id), "missing availability entry for {id}");
    }
    for entry in entries {
        assert!(
            entry.status == "available" || entry.status == "not_run",
            "unexpected status {}",
            entry.status
        );
        assert!(!entry.detail.trim().is_empty());
    }
}

#[test]
fn miri_live_control() {
    run_live(&DetectorKind::Miri);
}

#[test]
fn asan_live_control() {
    run_live(&DetectorKind::AddressSanitizer);
}

#[test]
fn lsan_live_control() {
    run_live(&DetectorKind::LeakSanitizer);
}

#[test]
fn tsan_live_control() {
    run_live(&DetectorKind::ThreadSanitizer);
}

#[test]
fn loom_live_control() {
    run_live(&DetectorKind::Loom);
}

#[test]
fn kani_live_control() {
    run_live(&DetectorKind::Kani);
}

#[test]
fn openssl_live_control() {
    run_live(&DetectorKind::Custom(
        frf_memorysafety::detector::live::OPENSSL_KAT_ID.to_owned(),
    ));
}

#[test]
fn live_report_is_deterministic_in_shape() {
    if !live_enabled() {
        return;
    }
    let result = calibrate_live(&DetectorKind::AddressSanitizer);
    if result.status == LiveStatus::NotRun {
        return;
    }
    let report = result.report.as_ref().expect("report");
    let bytes = report.canonical_bytes().expect("canonical");
    frf_memorysafety::require_canonical(&bytes).expect("canonical form");
}
