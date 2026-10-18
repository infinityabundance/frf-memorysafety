//! Phase 4.1 court tests: token lifecycle, races, completeness, CLI statuses.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use frf_memorysafety::court::{
    verify_transcript_json, CourtError, CourtErrorCategory, CourtReport, TranscriptOutcome,
    COURT_SPEC, NATIVE_EVENT_TRANSCRIPT_SCHEMA,
};
use frf_memorysafety::identity::canonical_bytes;
use serde_json::{json, Value};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "frf-memorysafety-court-{label}-{}-{sequence}",
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

fn digest(character: char) -> String {
    std::iter::repeat(character).take(64).collect()
}

fn provenance(origin: &str, claimed_complete: bool) -> Value {
    json!({
        "origin": origin,
        "tool": "frf-court-test-recorder",
        "tool_version": "0.1.0",
        "library_versions": [{"name": "libc", "version": "0.2.0"}],
        "executable_digest": digest('a'),
        "fixture_digest": digest('b'),
        "case_legality": "test_only",
        "scope": "phase 4.1 transcript fixtures",
        "claimed_complete": claimed_complete,
    })
}

#[allow(clippy::needless_pass_by_value)]
fn transcript(objects: Value, threads: Value) -> Value {
    json!({
        "schema": NATIVE_EVENT_TRANSCRIPT_SCHEMA,
        "spec": COURT_SPEC,
        "provenance": provenance("authentic_native", true),
        "objects": objects,
        "threads": threads,
    })
}

fn report(value: &Value) -> CourtReport {
    let bytes = canonical_bytes(value).unwrap();
    verify_transcript_json(&bytes).unwrap()
}

fn outcome(value: &Value) -> TranscriptOutcome {
    report(value).outcome
}

fn own_object(id: &str, atomic: bool) -> Value {
    json!({"id": id, "atomic": atomic})
}

fn create(seq: u64, object: &str, token: &str, owner: &str, generation: u64) -> Value {
    json!({
        "seq": seq,
        "kind": "create",
        "object": object,
        "token": token,
        "owner": owner,
        "generation": generation,
    })
}

fn init(seq: u64, object: &str, token: &str) -> Value {
    json!({"seq": seq, "kind": "init_complete", "object": object, "token": token})
}

fn use_token(seq: u64, object: &str, token: &str, access: &str) -> Value {
    json!({"seq": seq, "kind": "use", "object": object, "token": token, "access": access})
}

#[allow(clippy::needless_pass_by_value)]
fn one_thread(events: Vec<Value>) -> Value {
    json!([{"id": "t0", "events": events}])
}

fn positive_lifecycle() -> Value {
    transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            json!({
                "seq": 1,
                "kind": "partial_init",
                "object": "obj",
                "token": "tok0",
                "initialized_length": 4,
            }),
            init(2, "obj", "tok0"),
            json!({
                "seq": 3,
                "kind": "borrow_shared",
                "object": "obj",
                "from_token": "tok0",
                "token": "b0",
            }),
            use_token(4, "obj", "b0", "read"),
            json!({"seq": 5, "kind": "borrow_end", "object": "obj", "token": "b0"}),
            json!({
                "seq": 6,
                "kind": "transfer",
                "object": "obj",
                "from_token": "tok0",
                "to_token": "tok1",
                "to_owner": "task-b",
            }),
            use_token(7, "obj", "tok1", "write"),
            json!({"seq": 8, "kind": "free", "object": "obj", "token": "tok1"}),
        ]),
    )
}

#[test]
fn positive_lifecycle_and_transfer_verifies() {
    let report = report(&positive_lifecycle());
    assert_eq!(
        report.outcome,
        TranscriptOutcome::VerifiedCompatibleWithinTranscript
    );
    assert!(report.race_witnesses.is_empty());
    assert!(report.findings.is_empty());
}

#[test]
fn transfer_then_old_token_use_is_violation() {
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            init(1, "obj", "tok0"),
            json!({
                "seq": 2,
                "kind": "transfer",
                "object": "obj",
                "from_token": "tok0",
                "to_token": "tok1",
                "to_owner": "task-b",
            }),
            use_token(3, "obj", "tok0", "read"),
            json!({"seq": 4, "kind": "free", "object": "obj", "token": "tok1"}),
        ]),
    );
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::ObservedViolation);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "use_after_transfer"));
}

#[test]
fn use_after_free_is_violation() {
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            json!({"seq": 1, "kind": "free", "object": "obj", "token": "tok0"}),
            use_token(2, "obj", "tok0", "read"),
        ]),
    );
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::ObservedViolation);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "use_after_free"));
}

#[test]
fn mutable_alias_is_violation() {
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            init(1, "obj", "tok0"),
            json!({
                "seq": 2,
                "kind": "borrow_mutable",
                "object": "obj",
                "from_token": "tok0",
                "token": "m0",
            }),
            json!({
                "seq": 3,
                "kind": "borrow_shared",
                "object": "obj",
                "from_token": "tok0",
                "token": "s0",
            }),
            json!({"seq": 4, "kind": "borrow_end", "object": "obj", "token": "m0"}),
            json!({"seq": 5, "kind": "free", "object": "obj", "token": "tok0"}),
        ]),
    );
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::ObservedViolation);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "borrow_conflict"));
}

#[test]
fn stale_generation_is_violation() {
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            init(1, "obj", "tok0"),
            json!({
                "seq": 2,
                "kind": "borrow_shared",
                "object": "obj",
                "from_token": "tok0",
                "token": "b0",
            }),
            json!({"seq": 3, "kind": "borrow_end", "object": "obj", "token": "b0"}),
            json!({
                "seq": 4,
                "kind": "reallocate",
                "object": "obj",
                "from_token": "tok0",
                "token": "tok1",
                "owner": "task-a",
                "generation": 1,
            }),
            use_token(5, "obj", "tok0", "read"),
            json!({"seq": 6, "kind": "free", "object": "obj", "token": "tok1"}),
        ]),
    );
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::ObservedViolation);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "stale_generation"));
}

#[test]
fn allocation_failure_without_use_verifies() {
    let value = transcript(
        json!([{"id": "obj"}]),
        one_thread(vec![json!({
            "seq": 0,
            "kind": "allocation_failure",
            "object": "obj",
            "owner": "task-a",
        })]),
    );
    assert_eq!(
        outcome(&value),
        TranscriptOutcome::VerifiedCompatibleWithinTranscript
    );
}

#[test]
fn allocation_failure_then_use_is_violation() {
    let value = transcript(
        json!([{"id": "obj"}]),
        one_thread(vec![
            json!({
                "seq": 0,
                "kind": "allocation_failure",
                "object": "obj",
                "owner": "task-a",
            }),
            use_token(1, "obj", "tok0", "read"),
        ]),
    );
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::ObservedViolation);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "use_of_unallocated"));
}

#[test]
fn callback_failure_poisons_token() {
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            init(1, "obj", "tok0"),
            json!({
                "seq": 2,
                "kind": "callback_enter",
                "object": "obj",
                "token": "tok0",
                "callback": "cb",
            }),
            json!({
                "seq": 3,
                "kind": "callback_exit",
                "object": "obj",
                "token": "tok0",
                "callback": "cb",
                "outcome": "failed",
            }),
            use_token(4, "obj", "tok0", "read"),
            json!({"seq": 5, "kind": "free", "object": "obj", "token": "tok0"}),
        ]),
    );
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::ObservedViolation);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "use_of_poisoned_token"));
}

#[test]
fn callback_success_verifies() {
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            init(1, "obj", "tok0"),
            json!({
                "seq": 2,
                "kind": "callback_enter",
                "object": "obj",
                "token": "tok0",
                "callback": "cb",
            }),
            json!({
                "seq": 3,
                "kind": "callback_exit",
                "object": "obj",
                "token": "tok0",
                "callback": "cb",
                "outcome": "ok",
            }),
            json!({"seq": 4, "kind": "free", "object": "obj", "token": "tok0"}),
        ]),
    );
    assert_eq!(
        outcome(&value),
        TranscriptOutcome::VerifiedCompatibleWithinTranscript
    );
}

#[test]
fn required_callback_missing_is_incomplete() {
    let mut value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            init(1, "obj", "tok0"),
            json!({"seq": 2, "kind": "free", "object": "obj", "token": "tok0"}),
        ]),
    );
    value["requirements"] = json!({"required_callbacks": ["cb"]});
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::IncompleteTranscript);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "required_callback_missing"));
}

#[test]
fn data_race_is_violation() {
    let value = json!({
        "schema": NATIVE_EVENT_TRANSCRIPT_SCHEMA,
        "spec": COURT_SPEC,
        "provenance": provenance("authentic_native", true),
        "objects": [own_object("obj", false)],
        "threads": [
            {"id": "t0", "events": [
                create(0, "obj", "tok0", "task-a", 0),
                init(1, "obj", "tok0"),
                use_token(2, "obj", "tok0", "write"),
                {"seq": 3, "kind": "free", "object": "obj", "token": "tok0"}
            ]},
            {"id": "t1", "events": [use_token(0, "obj", "tok0", "read")]}
        ]
    });
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::ObservedViolation);
    assert!(!report.race_witnesses.is_empty());
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "data_race"));
}

#[test]
fn atomic_writes_without_ordering_are_compatible() {
    let value = json!({
        "schema": NATIVE_EVENT_TRANSCRIPT_SCHEMA,
        "spec": COURT_SPEC,
        "provenance": provenance("authentic_native", true),
        "objects": [own_object("obj", true)],
        "threads": [
            {"id": "t0", "events": [
                create(0, "obj", "tok0", "task-a", 0),
                init(1, "obj", "tok0"),
                use_token(2, "obj", "tok0", "atomic_write"),
                {"seq": 3, "kind": "free", "object": "obj", "token": "tok0"}
            ]},
            {"id": "t1", "events": [use_token(0, "obj", "tok0", "atomic_write")]}
        ],
        "synchronizes_with": [
            {"from": {"thread": "t0", "seq": 1}, "to": {"thread": "t1", "seq": 0}},
            {"from": {"thread": "t1", "seq": 0}, "to": {"thread": "t0", "seq": 3}}
        ]
    });
    let report = report(&value);
    assert_eq!(
        report.outcome,
        TranscriptOutcome::VerifiedCompatibleWithinTranscript
    );
    assert!(report.race_witnesses.is_empty());
}

#[test]
fn atomic_vs_non_atomic_is_race() {
    let value = json!({
        "schema": NATIVE_EVENT_TRANSCRIPT_SCHEMA,
        "spec": COURT_SPEC,
        "provenance": provenance("authentic_native", true),
        "objects": [own_object("obj", true)],
        "threads": [
            {"id": "t0", "events": [
                create(0, "obj", "tok0", "task-a", 0),
                init(1, "obj", "tok0"),
                use_token(2, "obj", "tok0", "write"),
                {"seq": 3, "kind": "free", "object": "obj", "token": "tok0"}
            ]},
            {"id": "t1", "events": [use_token(0, "obj", "tok0", "atomic_write")]}
        ],
        "synchronizes_with": [
            {"from": {"thread": "t0", "seq": 1}, "to": {"thread": "t1", "seq": 0}},
            {"from": {"thread": "t1", "seq": 0}, "to": {"thread": "t0", "seq": 3}}
        ]
    });
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::ObservedViolation);
    assert!(!report.race_witnesses.is_empty());
}

#[test]
fn missing_free_is_incomplete() {
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            init(1, "obj", "tok0"),
        ]),
    );
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::IncompleteTranscript);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "outstanding_responsibility"));
}

#[test]
fn missing_borrow_end_is_incomplete() {
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            init(1, "obj", "tok0"),
            json!({
                "seq": 2,
                "kind": "borrow_shared",
                "object": "obj",
                "from_token": "tok0",
                "token": "b0",
            }),
        ]),
    );
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::IncompleteTranscript);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "borrow_not_ended"));
}

#[test]
fn missing_generation_transition_is_incomplete() {
    let mut value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            init(1, "obj", "tok0"),
            json!({"seq": 2, "kind": "free", "object": "obj", "token": "tok0"}),
        ]),
    );
    value["requirements"] = json!({"required_generation_transitions": ["obj"]});
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::IncompleteTranscript);
    assert!(report
        .findings
        .iter()
        .any(|finding| { finding.code == "required_generation_transition_missing" }));
}

#[test]
fn skipped_generation_bump_is_incomplete() {
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            init(1, "obj", "tok0"),
            json!({
                "seq": 2,
                "kind": "reallocate",
                "object": "obj",
                "from_token": "tok0",
                "token": "tok1",
                "owner": "task-a",
                "generation": 2,
            }),
            json!({"seq": 3, "kind": "free", "object": "obj", "token": "tok1"}),
        ]),
    );
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::IncompleteTranscript);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "skipped_generation_transition"));
}

#[test]
fn missing_create_is_incomplete() {
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![use_token(0, "obj", "tok0", "read")]),
    );
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::IncompleteTranscript);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "missing_create"));
}

#[test]
fn expected_event_count_mismatch_is_incomplete() {
    let mut value = positive_lifecycle();
    value["recording"] = json!({"seed": 7, "expected_event_count": 99});
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::IncompleteTranscript);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "event_count_mismatch"));
}

#[test]
fn fictitious_completeness_is_incomplete() {
    let mut value = positive_lifecycle();
    value["unknown_provider_edges"] = json!([{
        "provider": "provider-x",
        "detail": "dispatch target not recorded",
    }]);
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::IncompleteTranscript);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "fictitious_completeness"));
}

#[test]
fn unknown_provider_without_completeness_is_unresolved() {
    let mut value = positive_lifecycle();
    value["provenance"]["claimed_complete"] = json!(false);
    value["unknown_provider_edges"] = json!([{
        "provider": "provider-x",
        "detail": "dispatch target not recorded",
    }]);
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::Unresolved);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "unknown_provider_edge"));
}

#[test]
fn modeled_origin_is_unresolved() {
    let mut value = positive_lifecycle();
    value["provenance"]["origin"] = json!("modeled");
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::Unresolved);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "non_authentic_origin"));
}

#[test]
fn illegal_case_is_rejected() {
    let mut value = positive_lifecycle();
    value["provenance"]["case_legality"] = json!("illegal");
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::IllegalCase);
}

#[test]
fn malformed_duplicate_field_is_integrity_error() {
    let bytes = br#"{"schema":"native-event-transcript.v1","schema":"native-event-transcript.v1"}"#;
    let error = verify_transcript_json(bytes).unwrap_err();
    assert!(matches!(error, CourtError::Invalid { .. }));
    assert_eq!(error.category(), CourtErrorCategory::Integrity);
}

#[test]
fn unknown_field_is_integrity_error() {
    let mut value = positive_lifecycle();
    value["bogus"] = json!(true);
    let bytes = serde_json::to_vec(&value).unwrap();
    let error = verify_transcript_json(&bytes).unwrap_err();
    assert!(matches!(error, CourtError::Invalid { .. }));
}

#[test]
fn missing_required_field_is_integrity_error() {
    let value = json!({
        "schema": NATIVE_EVENT_TRANSCRIPT_SCHEMA,
        "spec": COURT_SPEC,
        "provenance": provenance("authentic_native", true),
        "objects": [{"id": "obj"}],
        "threads": [{"id": "t0", "events": [
            {"seq": 0, "kind": "create", "object": "obj", "token": "tok0", "owner": "a"}
        ]}]
    });
    let bytes = serde_json::to_vec(&value).unwrap();
    let error = verify_transcript_json(&bytes).unwrap_err();
    assert!(matches!(error, CourtError::Invalid { .. }));
}

#[test]
fn canonical_report_is_deterministic() {
    let value = positive_lifecycle();
    let first = report(&value).canonical_bytes().unwrap();
    let second = report(&value).canonical_bytes().unwrap();
    assert_eq!(first, second);
    frf_memorysafety::identity::require_canonical(&first).unwrap();
}

#[test]
fn partial_initialization_use_is_violation() {
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            json!({
                "seq": 1,
                "kind": "partial_init",
                "object": "obj",
                "token": "tok0",
                "initialized_length": 4,
            }),
            use_token(2, "obj", "tok0", "read"),
            json!({"seq": 3, "kind": "free", "object": "obj", "token": "tok0"}),
        ]),
    );
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::ObservedViolation);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "use_before_initialization"));
}

#[test]
fn failed_transfer_preserves_sender() {
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            init(1, "obj", "tok0"),
            json!({
                "seq": 2,
                "kind": "transfer_failure",
                "object": "obj",
                "from_token": "tok0",
                "to_owner": "task-b",
            }),
            use_token(3, "obj", "tok0", "write"),
            json!({"seq": 4, "kind": "free", "object": "obj", "token": "tok0"}),
        ]),
    );
    assert_eq!(
        outcome(&value),
        TranscriptOutcome::VerifiedCompatibleWithinTranscript
    );
}

#[test]
fn reborrow_chain_verifies() {
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            init(1, "obj", "tok0"),
            json!({
                "seq": 2,
                "kind": "borrow_mutable",
                "object": "obj",
                "from_token": "tok0",
                "token": "m0",
            }),
            json!({
                "seq": 3,
                "kind": "reborrow",
                "object": "obj",
                "from_token": "m0",
                "token": "r0",
                "borrow": "shared",
            }),
            use_token(4, "obj", "r0", "read"),
            json!({"seq": 5, "kind": "borrow_end", "object": "obj", "token": "r0"}),
            use_token(6, "obj", "m0", "write"),
            json!({"seq": 7, "kind": "borrow_end", "object": "obj", "token": "m0"}),
            json!({"seq": 8, "kind": "free", "object": "obj", "token": "tok0"}),
        ]),
    );
    assert_eq!(
        outcome(&value),
        TranscriptOutcome::VerifiedCompatibleWithinTranscript
    );
}

#[test]
fn escape_transfers_to_continuing_custody() {
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            init(1, "obj", "tok0"),
            json!({
                "seq": 2,
                "kind": "escape",
                "object": "obj",
                "token": "tok0",
                "provider": "provider-x",
            }),
        ]),
    );
    assert_eq!(
        outcome(&value),
        TranscriptOutcome::VerifiedCompatibleWithinTranscript
    );
}

#[test]
fn use_after_escape_is_violation() {
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            init(1, "obj", "tok0"),
            json!({
                "seq": 2,
                "kind": "escape",
                "object": "obj",
                "token": "tok0",
                "provider": "provider-x",
            }),
            use_token(3, "obj", "tok0", "read"),
        ]),
    );
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::ObservedViolation);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "use_of_escaped_token"));
}

#[test]
fn abort_is_incomplete() {
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            init(1, "obj", "tok0"),
            json!({"seq": 2, "kind": "abort", "object": "obj", "token": "tok0"}),
        ]),
    );
    let report = report(&value);
    assert_eq!(report.outcome, TranscriptOutcome::IncompleteTranscript);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "aborted_lifecycle"));
}

#[test]
fn cli_verified_returns_zero() {
    let temp = TempDir::new("verified");
    let path = temp.path().join("transcript.json");
    fs::write(&path, canonical_bytes(&positive_lifecycle()).unwrap()).unwrap();
    assert_eq!(
        frf_memorysafety::cli::run(["court", "verify", path.to_str().unwrap()]),
        0
    );
}

#[test]
fn cli_violation_returns_four() {
    let temp = TempDir::new("violation");
    let path = temp.path().join("transcript.json");
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            json!({"seq": 1, "kind": "free", "object": "obj", "token": "tok0"}),
            use_token(2, "obj", "tok0", "read"),
        ]),
    );
    fs::write(&path, canonical_bytes(&value).unwrap()).unwrap();
    assert_eq!(
        frf_memorysafety::cli::run(["court", "verify", path.to_str().unwrap()]),
        4
    );
}

#[test]
fn cli_incomplete_returns_five() {
    let temp = TempDir::new("incomplete");
    let path = temp.path().join("transcript.json");
    let value = transcript(
        json!([own_object("obj", false)]),
        one_thread(vec![
            create(0, "obj", "tok0", "task-a", 0),
            init(1, "obj", "tok0"),
        ]),
    );
    fs::write(&path, canonical_bytes(&value).unwrap()).unwrap();
    assert_eq!(
        frf_memorysafety::cli::run(["court", "verify", path.to_str().unwrap()]),
        5
    );
}

#[test]
fn cli_malformed_returns_three() {
    let temp = TempDir::new("malformed");
    let path = temp.path().join("transcript.json");
    fs::write(
        &path,
        br#"{"schema":"native-event-transcript.v1","schema":"native-event-transcript.v1"}"#,
    )
    .unwrap();
    assert_eq!(
        frf_memorysafety::cli::run(["court", "verify", path.to_str().unwrap()]),
        3
    );
}

#[test]
fn cli_usage_returns_two() {
    assert_eq!(frf_memorysafety::cli::run(["court", "verify"]), 2);
    assert_eq!(
        frf_memorysafety::cli::run(["court", "verify", "/nonexistent/transcript.json"]),
        2
    );
    assert_eq!(frf_memorysafety::cli::run(["court", "wat"]), 2);
}

#[test]
fn court_run_still_not_run() {
    assert_eq!(frf_memorysafety::cli::run(["court", "run"]), 6);
}
