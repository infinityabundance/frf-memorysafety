//! Phase 10.4b local transparency profile tests.
//!
//! Every test executes against the committed local log artifacts or against
//! freshly constructed local-test-only witness material. No external log,
//! witness, or network call exists. No private key is committed.

#![allow(clippy::too_many_lines)]

use std::fs;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use frf_memorysafety::etp_transparency::{
    parse_checkpoint, verify_checkpoint, verify_transparency, Checkpoint, TransparencyRefusalCode,
    TransparencyStatus,
};
use frf_memorysafety::etp_witness::{
    build_local_test_cosignature, verify_witness_state, WitnessRefusalCode,
};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn transparency_dir() -> PathBuf {
    repo().join("evaluation/earned-trust-1.2.0/transparency")
}

fn read(name: &str) -> Vec<u8> {
    fs::read(transparency_dir().join(name)).expect("read transparency artifact")
}

fn base_proof() -> Value {
    serde_json::from_slice(&read("proof.json")).expect("proof json")
}

fn base_policy() -> Value {
    serde_json::from_slice(&read("policy.json")).expect("policy json")
}

fn checkpoint() -> Vec<u8> {
    read("checkpoint-size-3.txt")
}

fn verify(
    proof: &Value,
    checkpoint: &[u8],
    policy: &Value,
) -> frf_memorysafety::etp_transparency::TransparencyReport {
    verify_transparency(
        &serde_json::to_vec(proof).expect("proof bytes"),
        checkpoint,
        &serde_json::to_vec(policy).expect("policy bytes"),
    )
}

fn refused(
    report: &frf_memorysafety::etp_transparency::TransparencyReport,
    code: TransparencyRefusalCode,
) -> bool {
    report.refusals.iter().any(|refusal| refusal.code == code)
}

#[test]
fn committed_local_log_verifies_with_every_dimension() {
    let report = verify(&base_proof(), &checkpoint(), &base_policy());
    assert_eq!(
        report.status,
        TransparencyStatus::Verified,
        "{:?}",
        report.refusals
    );
    assert_eq!(report.tree_size, Some(3));
    assert_eq!(report.leaf_index, Some(0));
    assert!(!report.external_trust);
    assert!(!report.public_transparency);
    assert_eq!(report.witness_observation, "not_observed");
    assert_eq!(report.dimensions.log_identity.as_str(), "valid");
    assert_eq!(report.dimensions.inclusion.as_str(), "valid");
    assert_eq!(report.dimensions.checkpoint_signature.as_str(), "valid");
    assert_eq!(report.dimensions.consistency.as_str(), "valid");
    assert_eq!(report.dimensions.anti_rollback.as_str(), "valid");
    assert_eq!(report.dimensions.tiled_reconstruction.as_str(), "valid");
    assert_eq!(report.dimensions.offline_verification.as_str(), "valid");
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn exact_entry_bytes_are_preserved_and_bound_to_the_leaf() {
    let proof = base_proof();
    let declared = proof["entry_base64"].as_str().expect("entry base64");
    let encoded = STANDARD.decode(declared).expect("canonical base64");
    let original = read("attestation-entry.bin");
    assert_eq!(encoded, original);
    let digest = frf_memorysafety::etp_transparency::sha256_hex(&encoded);
    assert_eq!(
        digest,
        proof["entry_sha256"].as_str().expect("entry digest")
    );
    let leaf = frf_memorysafety::identity::hex_lower(
        &frf_memorysafety::etp_transparency::leaf_hash(&encoded),
    );
    assert_eq!(leaf, proof["leaf_hash"].as_str().expect("leaf hash"));

    let original_checkpoint = checkpoint();
    let parsed = parse_checkpoint(&original_checkpoint).expect("checkpoint");
    assert_eq!(parsed.original, original_checkpoint);
    assert!(!parsed.note_text.is_empty());
}

#[test]
fn wrong_leaf_hash_is_refused() {
    let mut proof = base_proof();
    proof["leaf_hash"] = json!(frf_memorysafety::etp_transparency::sha256_hex(
        b"wrong leaf"
    ));
    let report = verify(&proof, &checkpoint(), &base_policy());
    assert!(refused(&report, TransparencyRefusalCode::LeafHashMismatch));
    assert_eq!(report.exit_code(), 4);
}

#[test]
fn wrong_entry_digest_is_refused() {
    let mut proof = base_proof();
    proof["entry_sha256"] = json!("00".repeat(32));
    let report = verify(&proof, &checkpoint(), &base_policy());
    assert!(refused(
        &report,
        TransparencyRefusalCode::EntryDigestMismatch
    ));
}

#[test]
fn wrong_index_invalidates_inclusion() {
    let mut proof = base_proof();
    proof["leaf_index"] = json!(1);
    let report = verify(&proof, &checkpoint(), &base_policy());
    assert!(refused(&report, TransparencyRefusalCode::InclusionInvalid));
}

#[test]
fn wrong_sibling_order_invalidates_inclusion() {
    let mut proof = base_proof();
    let mut path = proof["audit_path"].as_array().expect("audit path").clone();
    path.reverse();
    proof["audit_path"] = Value::Array(path);
    let report = verify(&proof, &checkpoint(), &base_policy());
    assert!(refused(&report, TransparencyRefusalCode::InclusionInvalid));
}

#[test]
fn wrong_root_is_refused() {
    let mut proof = base_proof();
    proof["root_hash"] = json!("11".repeat(32));
    let report = verify(&proof, &checkpoint(), &base_policy());
    assert!(refused(&report, TransparencyRefusalCode::RootMismatch));
}

#[test]
fn wrong_checkpoint_signature_is_refused() {
    let mut text = String::from_utf8(checkpoint()).expect("checkpoint utf8");
    let marker = "\u{2014} frf.local/etp-transparency-1.2.0 ";
    let start = text.find(marker).expect("signature line") + marker.len();
    let mut bytes = text.into_bytes();
    let replacement = if bytes[start] == b'A' { b'B' } else { b'A' };
    bytes[start] = replacement;
    text = String::from_utf8(bytes).expect("mutated utf8");
    assert_eq!(
        parse_checkpoint(text.as_bytes())
            .expect("parses")
            .signatures
            .len(),
        1
    );
    let report = verify(&base_proof(), text.as_bytes(), &base_policy());
    assert!(refused(
        &report,
        TransparencyRefusalCode::InvalidCheckpointSignature
    ));
    assert_eq!(report.exit_code(), 4);
}

#[test]
fn cross_log_proof_is_refused() {
    let mut proof = base_proof();
    proof["log_origin"] = json!("frf.local/other-transparency-log");
    proof["log_id"] = json!(format!(
        "sha256:{}",
        frf_memorysafety::etp_transparency::sha256_hex(b"frf.local/other-transparency-log")
    ));
    let report = verify(&proof, &checkpoint(), &base_policy());
    assert!(refused(&report, TransparencyRefusalCode::CrossLogProof));
    assert_eq!(report.exit_code(), 4);
}

#[test]
fn equal_size_conflicting_checkpoint_is_refused() {
    let mut policy = base_policy();
    policy["anti_rollback"]["known_horizons"] = json!([{
        "tree_size": 3,
        "root_hash": "22".repeat(32),
        "checkpoint_sha256": "04b46ebadab2684d1d659dc3450a22d47a02dea58ffa86aabc2a7068a05e908d"
    }]);
    let report = verify(&base_proof(), &checkpoint(), &policy);
    assert!(refused(
        &report,
        TransparencyRefusalCode::ConflictingCheckpoint
    ));
    assert_eq!(report.dimensions.conflict_detection.as_str(), "invalid");
}

#[test]
fn rolled_back_checkpoint_is_refused() {
    let mut policy = base_policy();
    policy["anti_rollback"]["known_horizons"] = json!([{
        "tree_size": 7,
        "root_hash": "33".repeat(32),
        "checkpoint_sha256": "44".repeat(32)
    }]);
    let report = verify(&base_proof(), &checkpoint(), &policy);
    assert!(refused(&report, TransparencyRefusalCode::Rollback));
    assert_eq!(report.dimensions.anti_rollback.as_str(), "invalid");
}

#[test]
fn missing_consistency_proof_is_refused() {
    let mut proof = base_proof();
    proof.as_object_mut().expect("object").remove("consistency");
    let report = verify(&proof, &checkpoint(), &base_policy());
    assert!(refused(
        &report,
        TransparencyRefusalCode::MissingConsistencyProof
    ));
}

#[test]
fn wrong_consistency_proof_is_refused() {
    let mut proof = base_proof();
    let mut path = proof["consistency"]["proof"]
        .as_array()
        .expect("proof")
        .clone();
    path.reverse();
    proof["consistency"]["proof"] = Value::Array(path);
    let report = verify(&proof, &checkpoint(), &base_policy());
    assert!(refused(
        &report,
        TransparencyRefusalCode::ConsistencyInvalid
    ));
}

#[test]
fn malformed_tile_is_refused() {
    let mut proof = base_proof();
    proof["tiles"][0]["width"] = json!(2);
    let report = verify(&proof, &checkpoint(), &base_policy());
    assert!(refused(&report, TransparencyRefusalCode::MalformedTile));
}

#[test]
fn tile_root_mismatch_is_refused() {
    let mut proof = base_proof();
    let encoded = proof["tiles"][0]["base64"]
        .as_str()
        .expect("tile")
        .to_owned();
    let mut bytes = STANDARD.decode(encoded).expect("tile bytes");
    bytes[0] ^= 0xff;
    let reencoded = STANDARD.encode(&bytes);
    proof["tiles"][0]["base64"] = json!(reencoded);
    proof["tiles"][0]["sha256"] = json!(frf_memorysafety::etp_transparency::sha256_hex(&bytes));
    let report = verify(&proof, &checkpoint(), &base_policy());
    assert!(refused(&report, TransparencyRefusalCode::TiledRootMismatch));
}

#[test]
fn unsupported_log_version_is_not_run() {
    let mut proof = base_proof();
    proof["log_version"] = json!("tlog-tiles-v2");
    let report = verify(&proof, &checkpoint(), &base_policy());
    assert_eq!(report.status, TransparencyStatus::NotRun);
    assert!(refused(
        &report,
        TransparencyRefusalCode::UnsupportedLogVersion
    ));
    assert_eq!(report.exit_code(), 6);
}

#[test]
fn checkpoint_verification_uses_the_pinned_key_and_horizon() {
    let policy = base_policy();
    let size_one = read("checkpoint-size-1.txt");
    let report = verify_checkpoint(
        &size_one,
        Some(&serde_json::to_vec(&policy).expect("policy")),
    );
    assert_eq!(
        report.status,
        TransparencyStatus::Verified,
        "{:?}",
        report.refusals
    );
    assert_eq!(report.signature.as_str(), "valid");

    let size_three = checkpoint();
    let report = verify_checkpoint(
        &size_three,
        Some(&serde_json::to_vec(&policy).expect("policy")),
    );
    assert_eq!(report.status, TransparencyStatus::Partial);
    assert_eq!(report.signature.as_str(), "valid");

    let mut wrong = size_one.clone();
    let marker = b"\xe2\x80\x94 frf.local/etp-transparency-1.2.0 ";
    let start = wrong
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("signature")
        + marker.len();
    wrong[start] = if wrong[start] == b'A' { b'B' } else { b'A' };
    let report = verify_checkpoint(&wrong, Some(&serde_json::to_vec(&policy).expect("policy")));
    assert!(report
        .refusals
        .iter()
        .any(|refusal| refusal.code == TransparencyRefusalCode::InvalidCheckpointSignature));
}

// ---------------------------------------------------------------------------
// Witness model
// ---------------------------------------------------------------------------

fn checkpoint_parsed() -> Checkpoint {
    parse_checkpoint(&checkpoint()).expect("checkpoint")
}

fn witness_state(
    counted: &[usize],
    domains: &[&str],
    quorum: (u32, u32, u32, u32),
    local_test_only: bool,
) -> Value {
    let checkpoint_bytes = checkpoint();
    let parsed = checkpoint_parsed();
    let seeds: [[u8; 32]; 3] = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let keys: Vec<SigningKey> = seeds.iter().map(SigningKey::from_bytes).collect();
    let names = [
        "frf.local/etp/witness-a",
        "frf.local/etp/witness-b",
        "frf.local/etp/witness-c",
    ];
    let ids = ["witness-a", "witness-b", "witness-c"];
    let mut witnesses = Vec::new();
    let mut observations = Vec::new();
    for index in 0..3 {
        let public = STANDARD.encode(keys[index].verifying_key().to_bytes());
        witnesses.push(json!({
            "id": ids[index],
            "name": names[index],
            "domain": domains[index],
            "public_key_base64": public,
            "correlation_group": null,
            "trust_assumptions": ["local-test-key"]
        }));
        let counted_index = counted.contains(&index);
        let cosignature = if counted_index {
            Value::String(build_local_test_cosignature(
                &keys[index],
                names[index],
                &parsed,
                1_795_300_000,
            ))
        } else {
            Value::Null
        };
        observations.push(json!({
            "id": ids[index],
            "status": if counted_index { "local_test_only" } else { "not_observed" },
            "last_observed_tree_size": parsed.size,
            "prior_max_tree_size": null,
            "checkpoint_sha256": frf_memorysafety::etp_transparency::sha256_hex(&checkpoint_bytes),
            "cosignature": cosignature,
            "observed_roots": []
        }));
    }
    json!({
        "schema": "frf-etp.witness-state.v1",
        "spec": "frf-etp-v1",
        "checkpoint_base64": STANDARD.encode(&checkpoint_bytes),
        "checkpoint_sha256": frf_memorysafety::etp_transparency::sha256_hex(&checkpoint_bytes),
        "external_witnessing": false,
        "local_test_only": local_test_only,
        "policy": {
            "schema": "frf-etp.witness-policy.v1",
            "spec": "frf-etp-v1",
            "policy_id": "test-local-witness-policy",
            "log_origin": parsed.origin,
            "log_id": "sha256:278f4d522bfa92ae9c73632f569f8946359c647db9fc891e337d06fa8b5f0580",
            "require_external_witnesses": false,
            "administrative_domains": [
                {"id": "a", "operator": "test-a", "independent": true, "shared_trust": ["test-kernel-a"], "single_fault_domain": true},
                {"id": "b", "operator": "test-b", "independent": true, "shared_trust": ["test-kernel-b"], "single_fault_domain": true},
                {"id": "c", "operator": "test-c", "independent": true, "shared_trust": ["test-kernel-c"], "single_fault_domain": true}
            ],
            "witnesses": witnesses,
            "quorum": {"n": quorum.0, "q": quorum.1, "f": quorum.2, "required_domains": quorum.3}
        },
        "observations": observations
    })
}

#[test]
fn committed_witness_state_reports_not_observed() {
    let bytes = read("witness-state.json");
    let report = verify_witness_state(&bytes);
    assert_eq!(report.status, TransparencyStatus::NotRun);
    assert_eq!(report.exit_code(), 6);
    assert_eq!(report.witness_observation, "not_observed");
    assert!(report
        .refusals
        .iter()
        .any(|refusal| refusal.code == WitnessRefusalCode::ExternalObservationRequired));
}

#[test]
fn local_test_quorum_is_met_without_claiming_external_witnessing() {
    let state = witness_state(&[0, 1], &["a", "b", "c"], (3, 2, 0, 2), true);
    let report = verify_witness_state(&serde_json::to_vec(&state).expect("state"));
    assert_eq!(
        report.status,
        TransparencyStatus::Verified,
        "{:?}",
        report.refusals
    );
    assert!(report.quorum.met);
    assert!(!report.external_witnessing);
    assert_eq!(report.witness_observation, "not_observed");
    assert_eq!(report.quorum.basis, "local_test_only");
    // The gate runs the CLI against this generated local-test-only state.
    let out = repo().join("target/etp-transparency-witness-local.json");
    fs::create_dir_all(out.parent().expect("parent")).expect("target");
    fs::write(out, serde_json::to_vec_pretty(&state).expect("state")).expect("write state");
}

#[test]
fn correlated_witnesses_are_detected() {
    let state = witness_state(&[0, 1], &["a", "a", "c"], (3, 2, 0, 2), true);
    let report = verify_witness_state(&serde_json::to_vec(&state).expect("state"));
    assert!(report
        .refusals
        .iter()
        .any(|refusal| refusal.code == WitnessRefusalCode::CorrelatedWitnesses));
    assert!(!report.quorum.met);
    assert_eq!(report.exit_code(), 4);
}

#[test]
fn quorum_failure_is_refused() {
    let state = witness_state(&[0], &["a", "b", "c"], (3, 2, 0, 2), true);
    let report = verify_witness_state(&serde_json::to_vec(&state).expect("state"));
    assert!(report
        .refusals
        .iter()
        .any(|refusal| refusal.code == WitnessRefusalCode::QuorumFailed));
}

#[test]
fn quorum_intersection_condition_is_enforced() {
    let state = witness_state(&[0, 1], &["a", "b", "c"], (3, 1, 2, 1), true);
    let report = verify_witness_state(&serde_json::to_vec(&state).expect("state"));
    assert!(!report.quorum.intersection_holds);
    assert!(report
        .refusals
        .iter()
        .any(|refusal| refusal.code == WitnessRefusalCode::QuorumAssumptionInvalid));
}

#[test]
fn rolled_back_witness_state_is_refused() {
    let mut state = witness_state(&[0, 1], &["a", "b", "c"], (3, 2, 0, 2), true);
    state["observations"][0]["prior_max_tree_size"] = json!(5);
    let report = verify_witness_state(&serde_json::to_vec(&state).expect("state"));
    assert!(report
        .refusals
        .iter()
        .any(|refusal| refusal.code == WitnessRefusalCode::WitnessStateRollback));
}

#[test]
fn conflicting_witness_checkpoints_are_refused() {
    let mut state = witness_state(&[0, 1], &["a", "b", "c"], (3, 2, 0, 2), true);
    state["observations"][0]["observed_roots"] = json!([
        {"tree_size": 3, "root_hash": "55".repeat(32)},
        {"tree_size": 3, "root_hash": "66".repeat(32)}
    ]);
    let report = verify_witness_state(&serde_json::to_vec(&state).expect("state"));
    assert!(report
        .refusals
        .iter()
        .any(|refusal| refusal.code == WitnessRefusalCode::ConflictingCheckpoints));
}

#[test]
fn invalid_witness_cosignature_is_refused() {
    let mut state = witness_state(&[0, 1], &["a", "b", "c"], (3, 2, 0, 2), true);
    let line = state["observations"][0]["cosignature"]
        .as_str()
        .expect("cosignature")
        .to_owned();
    let mut bytes = line.into_bytes();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
    state["observations"][0]["cosignature"] = json!(String::from_utf8(bytes).expect("utf8"));
    let report = verify_witness_state(&serde_json::to_vec(&state).expect("state"));
    assert!(report
        .refusals
        .iter()
        .any(|refusal| refusal.code == WitnessRefusalCode::InvalidWitnessSignature));
}
