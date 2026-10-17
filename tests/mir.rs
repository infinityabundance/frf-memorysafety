//! Integration tests for the optional pinned MIR adapter and parser.

use std::path::Path;

use frf_memorysafety::identity::require_canonical;
use frf_memorysafety::mir::{
    parse_mir_text, MirAdapter, MirCalleeForm, MirDropKind, MirError, MirErrorCategory, MirLimits,
    MirNotRunReason, MirObservation, MirResolution, MirScanOutcome, MirStorageKind, MIR_TOOLCHAIN,
};

const SAMPLE: &str = include_str!("fixtures/mir/sample.mir");

fn fixture_source() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mir/source.rs")
}

fn sample_observation() -> MirObservation {
    parse_mir_text(SAMPLE, MirLimits::default()).expect("checked-in MIR fixture parses")
}

#[test]
fn checked_in_mir_fixture_is_parsed_conservatively() {
    let observation = sample_observation();
    assert!(observation.summary.format_warning_observed);
    assert_eq!(observation.functions.len(), 7);
    assert!(observation.summary.call_edges >= 7);
    assert_eq!(
        observation.summary.unresolved_call_edges,
        observation.summary.call_edges
    );
    assert!(observation.summary.indirect_call_edges >= 1);
    assert!(observation.summary.dereferences >= 3);
    assert!(observation.summary.storage_markers >= 10);
    assert_eq!(observation.summary.drops, 1);
    assert_eq!(observation.summary.unknown_constructs, 1);

    let foreign = observation
        .call_edges
        .iter()
        .find(|edge| edge.callee == "foreign_work")
        .expect("foreign_work call");
    assert_eq!(foreign.callee_form, MirCalleeForm::Path);
    assert_eq!(foreign.resolution, MirResolution::Unresolved);
    assert!(!foreign.same_name_local_definition_observed);
    assert!(foreign
        .uncertainty
        .iter()
        .any(|item| item == "external_foreign_or_provider_possible"));

    let add = observation
        .call_edges
        .iter()
        .find(|edge| edge.callee == "add")
        .expect("add call");
    assert!(add.same_name_local_definition_observed);
    assert_eq!(add.resolution, MirResolution::Unresolved);

    let indirect = observation
        .call_edges
        .iter()
        .find(|edge| edge.callee_form == MirCalleeForm::IndirectOperand)
        .expect("indirect call");
    assert!(indirect
        .uncertainty
        .iter()
        .any(|item| item == "call_target_not_identified"));

    assert!(observation
        .drops
        .iter()
        .any(|drop| drop.kind == MirDropKind::ExplicitDropCall));
    assert!(observation
        .storage_markers
        .iter()
        .any(|marker| marker.kind == MirStorageKind::Declared));
    assert!(observation
        .storage_markers
        .iter()
        .any(|marker| marker.kind == MirStorageKind::Dead));
    assert!(observation
        .unknowns
        .iter()
        .any(|unknown| unknown.text.contains("MysteryOp")));
}

#[test]
fn observation_is_canonical_and_deterministic() {
    let first = sample_observation().canonical_bytes().unwrap();
    let second = sample_observation().canonical_bytes().unwrap();
    assert_eq!(first, second);
    require_canonical(&first).unwrap();
}

#[test]
fn parser_limits_are_hard_errors() {
    let limits = MirLimits {
        max_calls: 1,
        ..MirLimits::default()
    };
    let error = parse_mir_text(SAMPLE, limits).unwrap_err();
    assert!(matches!(
        error,
        MirError::LimitExceeded {
            resource: "call_edges",
            limit: 1
        }
    ));
    assert_eq!(error.category(), MirErrorCategory::Integrity);
}

#[test]
fn source_bounds_are_checked_before_invocation() {
    let adapter = MirAdapter::new()
        .with_limits(MirLimits {
            max_source_bytes: 1,
            ..MirLimits::default()
        })
        .with_rustup_program("/nonexistent/frf-rustup-probe");
    let error = adapter.scan(fixture_source()).unwrap_err();
    assert!(matches!(
        error,
        MirError::LimitExceeded {
            resource: "source_bytes",
            limit: 1
        }
    ));
    assert_eq!(error.category(), MirErrorCategory::Integrity);
}

#[test]
fn adapter_returns_live_observations_or_a_typed_not_run() {
    let outcome = MirAdapter::new().scan(fixture_source()).unwrap();
    match outcome {
        MirScanOutcome::Live(observation) => {
            assert_eq!(observation.toolchain, MIR_TOOLCHAIN);
            assert!(observation.provenance.is_some());
            assert!(observation.summary.functions >= 6);
            assert!(observation.summary.call_edges >= 5);
            assert!(observation.summary.dereferences >= 1);
            assert!(observation
                .call_edges
                .iter()
                .all(|edge| edge.resolution == MirResolution::Unresolved));
        }
        MirScanOutcome::NotRun(not_run) => {
            assert_eq!(not_run.toolchain, MIR_TOOLCHAIN);
            assert!(matches!(
                not_run.reason,
                MirNotRunReason::RustupExecutableNotFound
                    | MirNotRunReason::ToolchainUnavailable
                    | MirNotRunReason::InvocationTimedOut
                    | MirNotRunReason::AdapterInvocationFailed
            ));
            assert!(!not_run.detail.is_empty());
        }
    }
}

#[test]
fn missing_rustup_is_not_run_not_a_fabricated_result() {
    let adapter = MirAdapter::new().with_rustup_program("/nonexistent/frf-rustup-probe");
    match adapter.scan(fixture_source()).unwrap() {
        MirScanOutcome::NotRun(not_run) => {
            assert_eq!(not_run.reason, MirNotRunReason::RustupExecutableNotFound);
        }
        MirScanOutcome::Live(_) => panic!("missing rustup must not produce a live observation"),
    }
}
