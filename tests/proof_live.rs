//! Phase 6.2 live checked-proof seal tests.
//!
//! Every test executes. None is ignored. When `FRF_PROOF_GATE=1` and the
//! pinned Coq checker is installed, each test asserts one live seal outcome.
//! In the default gate the checker is absent, so every test executes the same
//! manifest through the adapter and asserts the typed `checker_unavailable`
//! path instead of silently skipping.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use frf_memorysafety::proof::{parse_manifest, run_live_checker, LiveCheckerOutcome};

const LIVE_ENV: &str = "FRF_PROOF_GATE";

fn live_enabled() -> bool {
    std::env::var(LIVE_ENV).ok().as_deref() == Some("1")
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/proof/coq")
}

fn manifest_path(name: &str) -> PathBuf {
    fixtures().join(name)
}

fn verify_live(name: &str) -> (i32, Value) {
    let path = manifest_path(name);
    let output = Command::new(env!("CARGO_BIN_EXE_frf-memorysafety"))
        .args([
            "proof",
            "verify",
            path.to_str().unwrap(),
            "--live",
            "--json",
        ])
        .output()
        .expect("cannot execute the frf-memorysafety binary");
    let status = output.status.code().unwrap_or(-1);
    let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "manifest {name} did not emit canonical JSON: {error}; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (status, value)
}

/// Assert that the adapter itself reports the typed unavailable path. This is
/// independent of any admission or correspondence rejection, so it runs for
/// every manifest in the default gate.
fn assert_checker_unavailable(name: &str) {
    let path = manifest_path(name);
    let bytes = fs::read(&path).expect("cannot read proof manifest fixture");
    let manifest = parse_manifest(&bytes).expect("proof manifest fixture must parse");
    match run_live_checker(&manifest, path.parent().unwrap()).expect("adapter must not error") {
        LiveCheckerOutcome::Unavailable { detail } => {
            assert!(!detail.is_empty(), "unavailable detail must be explicit");
        }
        other => panic!("expected checker_unavailable for {name}, got {other:?}"),
    }
}

#[test]
fn approved_independent_theorem_is_accepted_within_scope() {
    if !live_enabled() {
        assert_checker_unavailable("manifest-approved.json");
        let (status, report) = verify_live("manifest-approved.json");
        assert_eq!(status, 6);
        assert_eq!(report["outcome"], "checker_unavailable");
        assert_eq!(report["live_checker_invoked"], false);
        return;
    }

    let (status, report) = verify_live("manifest-approved.json");
    assert_eq!(status, 0, "report: {report}");
    assert_eq!(report["outcome"], "accepted_within_scope");
    assert_eq!(report["admission"]["outcome"], "accepted_within_scope");
    assert_eq!(report["correspondence"]["status"], "pass");
    assert_eq!(report["acceptance_basis"], "recorded_authentic_checker_run");
    assert_eq!(report["live_checker_configured"], true);
    assert_eq!(report["live_checker_invoked"], true);
    let run = &report["live_run"];
    assert_eq!(run["checker_kind"], "coq");
    assert_eq!(run["exit_code"], 0);
    assert_eq!(run["theorems"].as_array().unwrap().len(), 2);
    assert!(run["stdout_sha256"].as_str().unwrap().len() == 64);
    assert!(run["stderr_sha256"].as_str().unwrap().len() == 64);
    assert!(run["executable_sha256"].as_str().unwrap().len() == 64);
    assert!(run["argv"]
        .as_array()
        .unwrap()
        .iter()
        .all(|argv| argv.as_array().is_some_and(|items| !items.is_empty())));
    assert_eq!(report["universal_soundness"], "WITHHELD_NOT_RUN");
}

#[test]
fn admitted_dependency_is_rejected_assumption() {
    if !live_enabled() {
        assert_checker_unavailable("manifest-admitted.json");
        return;
    }

    let (status, report) = verify_live("manifest-admitted.json");
    assert_eq!(status, 4, "report: {report}");
    assert_eq!(report["outcome"], "rejected_assumption");
    assert_eq!(report["admission"]["outcome"], "rejected_assumption");
    assert!(report["admission"]["forbidden_findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["token"] == "Admitted"));
    assert!(report["live_run"]["theorems"]
        .as_array()
        .unwrap()
        .iter()
        .any(|theorem| theorem["name"] == "frf_support_fixed_point"
            && theorem["status"] == "admitted"));
}

#[test]
fn axiom_dependency_is_rejected_assumption() {
    if !live_enabled() {
        assert_checker_unavailable("manifest-axiom.json");
        return;
    }

    let (status, report) = verify_live("manifest-axiom.json");
    assert_eq!(status, 4, "report: {report}");
    assert_eq!(report["outcome"], "rejected_assumption");
    assert_eq!(report["admission"]["outcome"], "rejected_assumption");
    assert!(report["admission"]["forbidden_findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["token"] == "Axiom"));
    assert!(report["live_run"]["theorems"]
        .as_array()
        .unwrap()
        .iter()
        .any(|theorem| theorem["name"] == "frf_support_fixed_point"
            && theorem["status"] == "admitted"));
}

#[test]
fn unrelated_theorem_is_rejected_unrelated() {
    if !live_enabled() {
        assert_checker_unavailable("manifest-unrelated.json");
        return;
    }

    let (status, report) = verify_live("manifest-unrelated.json");
    assert_eq!(status, 4, "report: {report}");
    assert_eq!(report["outcome"], "rejected_unrelated");
    assert_eq!(report["admission"]["outcome"], "rejected_unrelated");
    assert!(report["admission"]["admission_theorems"]
        .as_array()
        .unwrap()
        .iter()
        .any(|theorem| theorem["name"] == "frf_unrelated_arithmetic"));
    assert_eq!(report["correspondence"]["status"], "pass");
    assert_eq!(report["live_run"]["exit_code"], 0);
}

#[test]
fn unchecked_wrapper_is_rejected_even_with_an_accepted_theorem() {
    if !live_enabled() {
        assert_checker_unavailable("manifest-unchecked.json");
        return;
    }

    let (status, report) = verify_live("manifest-unchecked.json");
    assert_eq!(status, 4, "report: {report}");
    assert_eq!(report["outcome"], "rejected_unchecked_implementation");
    assert_eq!(report["admission"]["outcome"], "accepted_within_scope");
    assert_eq!(report["correspondence"]["status"], "fail");
    assert_eq!(
        report["correspondence"]["outcome"],
        "rejected_unchecked_implementation"
    );
    assert!(!report["correspondence"]["unchecked_wrappers"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        report["live_run"]["theorems"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|theorem| theorem["status"] == "proved")
            .count(),
        2
    );
}

#[test]
fn missing_reentrant_transition_is_rejected_missing_transition() {
    if !live_enabled() {
        assert_checker_unavailable("manifest-missing-transition.json");
        return;
    }

    let (status, report) = verify_live("manifest-missing-transition.json");
    assert_eq!(status, 4, "report: {report}");
    assert_eq!(report["outcome"], "rejected_missing_transition");
    assert_eq!(report["admission"]["outcome"], "accepted_within_scope");
    assert_eq!(report["correspondence"]["status"], "fail");
    assert_eq!(
        report["correspondence"]["outcome"],
        "rejected_missing_transition"
    );
    assert!(report["correspondence"]["missing_transitions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|kind| kind == "reentrant_callback"));
    assert_eq!(report["live_run"]["exit_code"], 0);
}
