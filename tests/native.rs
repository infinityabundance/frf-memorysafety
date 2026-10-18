//! Phase 4.2 native harness tests.
//!
//! Without `FRF_NATIVE_HARNESS=1` every test exercises the typed `NOT_RUN` path.
//! With the flag set (and `cc`, `rustc`, and `prlimit` available) the same tests
//! compile, execute, record, and replay the checked-in fixtures.

#![cfg(all(unix, feature = "native-harness"))]

use frf_memorysafety::court::{CaseLegality, TranscriptOrigin, TranscriptOutcome};
use frf_memorysafety::native::{
    cases, native_harness_enabled, record_case, record_case_with, NativeOutcome, NativeRecord,
    NativeRecordOptions, ReplayStatus, NATIVE_HARNESS_ENV,
};
use std::collections::BTreeSet;

fn assert_not_run(case_id: &str) {
    let record = record_case(case_id);
    assert_eq!(
        record.outcome,
        NativeOutcome::NotRun,
        "expected typed NOT_RUN for {case_id}: {}",
        record.detail
    );
    assert!(record.is_not_run());
    assert!(record.detail.contains(NATIVE_HARNESS_ENV));
    assert!(record.transcript.is_none());
    assert!(record.report.is_none());
    assert!(record.provenance.is_none());
    assert_eq!(record.replay, ReplayStatus::NotPerformed);
}

fn live(case_id: &str) -> Option<NativeRecord> {
    if !native_harness_enabled() {
        assert_not_run(case_id);
        return None;
    }
    Some(record_case(case_id))
}

fn finding_codes(record: &NativeRecord) -> Vec<&str> {
    record
        .report
        .as_ref()
        .map(|report| {
            report
                .findings
                .iter()
                .map(|finding| finding.code.as_str())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn registry_is_closed_and_unique() {
    let mut ids = BTreeSet::new();
    for case in cases() {
        assert!(ids.insert(case.id), "duplicate case id {}", case.id);
        assert!(!case.source.is_empty());
        assert!(!case.threads.is_empty());
        assert!(case.expected_event_count > 0);
    }
    assert!(ids.contains("skipped-free-c"));
    assert!(ids.contains("nondeterministic-c"));
}

#[test]
fn disabled_harness_reports_typed_not_run_for_every_case() {
    if native_harness_enabled() {
        return;
    }
    for case in cases() {
        assert_not_run(case.id);
    }
}

#[test]
fn unknown_case_is_a_harness_failure() {
    let record = record_case("not-a-registered-case");
    assert_eq!(record.outcome, NativeOutcome::HarnessFailure);
    assert_eq!(record.case_id, "not-a-registered-case");
    assert!(record.detail.contains("unknown native case id"));
}

#[test]
fn legal_transfer_free_c_records_and_replays() {
    let Some(record) = live("legal-transfer-free-c") else {
        return;
    };
    assert_eq!(
        record.outcome,
        NativeOutcome::VerifiedCompatibleWithinTranscript,
        "{}",
        record.detail
    );
    assert!(matches!(record.replay, ReplayStatus::Identical { .. }));
    let report = record.report.as_ref().unwrap();
    assert_eq!(
        report.outcome,
        TranscriptOutcome::VerifiedCompatibleWithinTranscript
    );
    assert!(report.findings.is_empty());
    assert!(report.race_witnesses.is_empty());
}

#[test]
fn legal_transfer_free_rust_records_and_replays() {
    let Some(record) = live("legal-transfer-free-rust") else {
        return;
    };
    assert_eq!(
        record.outcome,
        NativeOutcome::VerifiedCompatibleWithinTranscript,
        "{}",
        record.detail
    );
    assert!(matches!(record.replay, ReplayStatus::Identical { .. }));
}

#[test]
fn use_after_free_pair_is_observed_violation() {
    for case_id in ["use-after-free-c", "use-after-free-rust"] {
        let Some(record) = live(case_id) else {
            continue;
        };
        assert_eq!(
            record.outcome,
            NativeOutcome::ObservedViolation,
            "{case_id}: {}",
            record.detail
        );
        assert!(
            finding_codes(&record).contains(&"use_after_free"),
            "{case_id} findings: {:?}",
            finding_codes(&record)
        );
    }
}

#[test]
fn mutable_alias_is_observed_violation() {
    let Some(record) = live("mutable-alias-c") else {
        return;
    };
    assert_eq!(record.outcome, NativeOutcome::ObservedViolation);
    assert!(
        finding_codes(&record).contains(&"borrow_conflict"),
        "findings: {:?}",
        finding_codes(&record)
    );
}

#[test]
fn stale_generation_after_realloc_is_observed_violation() {
    let Some(record) = live("stale-generation-c") else {
        return;
    };
    assert_eq!(record.outcome, NativeOutcome::ObservedViolation);
    assert!(
        finding_codes(&record).contains(&"stale_generation"),
        "findings: {:?}",
        finding_codes(&record)
    );
    assert!(record
        .transcript
        .as_ref()
        .is_some_and(|transcript| transcript
            .requirements
            .as_ref()
            .is_some_and(|requirements| !requirements.required_generation_transitions.is_empty())));
}

#[test]
fn synchronous_callback_is_verified() {
    let Some(record) = live("sync-callback-c") else {
        return;
    };
    assert_eq!(
        record.outcome,
        NativeOutcome::VerifiedCompatibleWithinTranscript,
        "{}",
        record.detail
    );
    assert!(record
        .transcript
        .as_ref()
        .is_some_and(|transcript| transcript
            .requirements
            .as_ref()
            .is_some_and(|requirements| requirements
                .required_callbacks
                .iter()
                .any(|callback| callback == "on_done"))));
}

#[test]
fn deferred_callback_after_free_is_observed_violation() {
    let Some(record) = live("deferred-callback-c") else {
        return;
    };
    assert_eq!(record.outcome, NativeOutcome::ObservedViolation);
    assert!(
        finding_codes(&record).contains(&"use_after_free"),
        "findings: {:?}",
        finding_codes(&record)
    );
}

#[test]
fn data_race_produces_a_race_witness() {
    let Some(record) = live("data-race-c") else {
        return;
    };
    assert_eq!(record.outcome, NativeOutcome::ObservedViolation);
    let report = record.report.as_ref().unwrap();
    assert!(
        !report.race_witnesses.is_empty(),
        "expected a race witness, findings: {:?}",
        finding_codes(&record)
    );
}

#[test]
fn atomic_control_is_verified() {
    let Some(record) = live("atomic-control-c") else {
        return;
    };
    assert_eq!(
        record.outcome,
        NativeOutcome::VerifiedCompatibleWithinTranscript,
        "{}",
        record.detail
    );
    let report = record.report.as_ref().unwrap();
    assert!(report.race_witnesses.is_empty());
    assert!(report.findings.is_empty());
}

#[test]
fn skipped_event_is_incomplete_and_fictitious_completeness_is_rejected() {
    if !native_harness_enabled() {
        assert_not_run("skipped-free-c");
        let record = record_case_with(
            "skipped-free-c",
            NativeRecordOptions {
                claimed_complete: Some(true),
                ..NativeRecordOptions::default()
            },
        );
        assert_eq!(record.outcome, NativeOutcome::NotRun);
        return;
    }

    let honest = record_case("skipped-free-c");
    assert_eq!(
        honest.outcome,
        NativeOutcome::IncompleteTranscript,
        "{}",
        honest.detail
    );
    let codes = finding_codes(&honest);
    assert!(
        codes.contains(&"required_free_missing") || codes.contains(&"outstanding_responsibility"),
        "findings: {codes:?}"
    );
    assert!(
        codes.contains(&"event_count_mismatch"),
        "findings: {codes:?}"
    );
    assert!(!codes.contains(&"fictitious_completeness"));

    let fictitious = record_case_with(
        "skipped-free-c",
        NativeRecordOptions {
            claimed_complete: Some(true),
            ..NativeRecordOptions::default()
        },
    );
    assert_eq!(fictitious.outcome, NativeOutcome::IncompleteTranscript);
    assert!(
        finding_codes(&fictitious).contains(&"fictitious_completeness"),
        "findings: {:?}",
        finding_codes(&fictitious)
    );
    assert_ne!(
        fictitious.outcome,
        NativeOutcome::VerifiedCompatibleWithinTranscript
    );
}

#[test]
fn nondeterministic_fixture_is_unresolved_on_replay() {
    let Some(record) = live("nondeterministic-c") else {
        return;
    };
    assert_eq!(
        record.outcome,
        NativeOutcome::Unresolved,
        "{}",
        record.detail
    );
    assert!(matches!(record.replay, ReplayStatus::Mismatch { .. }));
    assert!(record.detail.contains("replay mismatch"));
    let report = record.report.as_ref().unwrap();
    assert_eq!(report.outcome, TranscriptOutcome::Unresolved);
    assert!(finding_codes(&record).contains(&"replay_mismatch"));
}

#[test]
fn oversized_output_is_rejected() {
    let Some(record) = live("oversized-output-c") else {
        return;
    };
    assert_eq!(
        record.outcome,
        NativeOutcome::Unresolved,
        "{}",
        record.detail
    );
    assert!(record.detail.contains("exceeded"));
    assert!(record.transcript.is_none());
    assert!(record.report.is_none());
}

#[test]
fn provenance_records_authentic_native_identity_and_digests() {
    let Some(record) = live("legal-transfer-free-c") else {
        return;
    };
    let provenance = record.provenance.as_ref().unwrap();
    assert_eq!(provenance.origin, TranscriptOrigin::AuthenticNative);
    assert_eq!(provenance.case_legality, CaseLegality::TestOnly);
    assert_eq!(provenance.tool, "frf-native-fixture-harness");
    assert!(!provenance.tool_version.is_empty());
    assert!(provenance.scope.contains("case=legal-transfer-free-c"));
    assert!(provenance.claimed_complete);
    assert!(!provenance.library_versions.is_empty());
    assert!(provenance
        .library_versions
        .iter()
        .any(|library| library.name == "cc"));
    for digest in [
        &provenance.executable_digest,
        &provenance.fixture_digest,
        record.fixture_sha256.as_ref().unwrap(),
        record.executable_sha256.as_ref().unwrap(),
    ] {
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    }
    assert_eq!(
        Some(&provenance.fixture_digest),
        record.fixture_sha256.as_ref()
    );
    assert_eq!(
        Some(&provenance.executable_digest),
        record.executable_sha256.as_ref()
    );
    match &record.replay {
        ReplayStatus::Identical {
            first_sha256,
            second_sha256,
        } => assert_eq!(first_sha256, second_sha256),
        other => panic!("expected identical replay, got {other:?}"),
    }
}

#[test]
fn substitute_and_modeled_origins_are_unresolved() {
    if !native_harness_enabled() {
        assert_not_run("legal-transfer-free-c");
        return;
    }
    for origin in [TranscriptOrigin::Substitute, TranscriptOrigin::Modeled] {
        let record = record_case_with(
            "legal-transfer-free-c",
            NativeRecordOptions {
                origin: Some(origin),
                ..NativeRecordOptions::default()
            },
        );
        assert_eq!(
            record.outcome,
            NativeOutcome::Unresolved,
            "origin {origin:?}: {}",
            record.detail
        );
        assert!(
            finding_codes(&record).contains(&"non_authentic_origin"),
            "origin {origin:?} findings: {:?}",
            finding_codes(&record)
        );
    }
}
