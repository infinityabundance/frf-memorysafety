//! Phase 10.4a authenticated correction and revocation tests.
//!
//! Every test executes. Test-only Ed25519 keys are generated in memory from
//! fixed seeds; no private key is written to the repository. The tests exercise
//! the append-only chain, correction-authority authorization, duplicate and
//! replayed entries, stale policy, retained dissent, and the separation between
//! historical replay and present authorization.

#![allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]

use std::collections::BTreeSet;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use frf_memorysafety::etp::ETP_SPEC;
use frf_memorysafety::etp_auth::{
    pae, AuthorizedKey, DsseEnvelope, DsseSignatureEnvelope, TrustPolicy, TrustRole,
    ROLE_CORRECTION_AUTHORITY, ROLE_EVIDENCE_PRODUCER, TRUST_POLICY_SCHEMA,
};
use frf_memorysafety::etp_revocation::{
    committed_support_model, record_historical_verdict, verify_registry_bytes, RevocationAction,
    RevocationRefusalCode, RevocationReport, RevocationStatus, SupportModel,
    REVOCATION_ENTRY_PAYLOAD_TYPE,
};
use frf_memorysafety::identity::{canonical_bytes, hex_lower, parse_strict};
use frf_memorysafety::support::SupportState;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ISSUED: u64 = 1_795_305_600;
const EXPIRES: u64 = 1_826_841_600;
const NOW: u64 = 1_795_330_364;
const REGISTRY_ID: &str = "frf-etp-test-revocation-registry";
const POLICY_ID: &str = "frf-etp-test-revocation-policy";

fn test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn key_entry(
    keyid: &str,
    key: &SigningKey,
    actor: &str,
    not_before: u64,
    not_after: u64,
) -> AuthorizedKey {
    AuthorizedKey {
        keyid: keyid.to_owned(),
        algorithm: "ed25519".to_owned(),
        public_key_base64: STANDARD.encode(key.verifying_key().to_bytes()),
        actor: actor.to_owned(),
        not_before_unix: not_before,
        not_after_unix: not_after,
    }
}

fn role(id: &str, keys: Vec<AuthorizedKey>, threshold: u32) -> TrustRole {
    TrustRole {
        id: id.to_owned(),
        threshold,
        independent: false,
        scope: vec!["https://frf.dev/etp/campaign-closure/v1".to_owned()],
        keys,
    }
}

fn policy(
    correction: Vec<AuthorizedKey>,
    producer: Vec<AuthorizedKey>,
    expires: u64,
) -> TrustPolicy {
    TrustPolicy {
        schema: TRUST_POLICY_SCHEMA.to_owned(),
        spec: ETP_SPEC.to_owned(),
        policy_id: POLICY_ID.to_owned(),
        version: 1,
        issued_at_unix: ISSUED,
        expires_at_unix: expires,
        roles: vec![
            role(ROLE_CORRECTION_AUTHORITY, correction, 1),
            role(ROLE_EVIDENCE_PRODUCER, producer, 1),
        ],
    }
}

fn canon(value: &Value) -> Vec<u8> {
    canonical_bytes(value).expect("canonical bytes")
}

fn sha256(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn entry_value(
    registry_id: &str,
    sequence: u64,
    previous: Option<&str>,
    entry_id: &str,
    action: RevocationAction,
    claim_id: &str,
    evidence_ids: &[&str],
    statement: Option<&str>,
) -> Value {
    json!({
        "schema": "frf-etp.revocation-entry.v1",
        "spec": ETP_SPEC,
        "registry_id": registry_id,
        "policy_id": POLICY_ID,
        "policy_version": 1,
        "sequence": sequence,
        "previous_entry_sha256": previous,
        "entry_id": entry_id,
        "action": action.as_str(),
        "target": {
            "claim_id": claim_id,
            "policy_id": "frf-etp-phase10.4a-support-policy",
            "evidence_ids": evidence_ids,
            "subject_identity": "candidate:7fd038b34643743ca4dc36ceb7026973a8900fb0bd9697abc2a9ba64bea02746",
        },
        "reason": "declared Phase 10.4a test revocation",
        "effective_at_unix": NOW,
        "scope": "one founded-support derivation",
        "historical_replay": "valid_under_original_policy",
        "statement": statement,
        "corrects_entry_id": null
    })
}

fn sign_entry(value: &Value, keyid: &str, key: &SigningKey) -> DsseEnvelope {
    let payload = canon(value);
    let message = pae(REVOCATION_ENTRY_PAYLOAD_TYPE, &payload).expect("PAE");
    let signature = key.sign(&message);
    DsseEnvelope {
        payload_type: REVOCATION_ENTRY_PAYLOAD_TYPE.to_owned(),
        payload: STANDARD.encode(payload),
        signatures: vec![DsseSignatureEnvelope {
            keyid: keyid.to_owned(),
            sig: STANDARD.encode(signature.to_bytes()),
        }],
    }
}

fn entry_digest(envelope: &DsseEnvelope) -> String {
    sha256(&canon(
        &serde_json::to_value(envelope).expect("envelope value"),
    ))
}

fn registry_value(entries: Vec<DsseEnvelope>) -> Value {
    json!({
        "schema": "frf-etp.revocation-registry.v1",
        "spec": ETP_SPEC,
        "registry_id": REGISTRY_ID,
        "policy_id": POLICY_ID,
        "policy_version": 1,
        "issued_at_unix": ISSUED,
        "entries": entries
    })
}

fn single_revocation(key: &SigningKey) -> (Value, DsseEnvelope) {
    let value = entry_value(
        REGISTRY_ID,
        1,
        None,
        "rev-0001",
        RevocationAction::Revoke,
        "claim.campaign-closure",
        &["evidence.closure"],
        None,
    );
    let envelope = sign_entry(&value, "correct-1", key);
    (registry_value(vec![envelope.clone()]), envelope)
}

fn codes(report: &RevocationReport) -> BTreeSet<RevocationRefusalCode> {
    report.refusals.iter().map(|refusal| refusal.code).collect()
}

fn verify(
    registry: &Value,
    policy: &TrustPolicy,
    model: &SupportModel,
    now: u64,
) -> RevocationReport {
    let historical = record_historical_verdict(model).expect("historical verdict");
    verify_registry_bytes(
        &canon(registry),
        policy,
        Some(model),
        Some(&historical),
        now,
    )
    .expect("verification")
}

fn good_policy(key: &SigningKey) -> TrustPolicy {
    policy(
        vec![key_entry(
            "correct-1",
            key,
            "correction-authority",
            ISSUED,
            EXPIRES,
        )],
        vec![key_entry(
            "producer-1",
            &test_key(9),
            "producer",
            ISSUED,
            EXPIRES,
        )],
        EXPIRES,
    )
}

#[test]
fn valid_registry_applies_revocation_and_preserves_history() {
    let key = test_key(1);
    let model = committed_support_model().expect("model");
    let (registry, _envelope) = single_revocation(&key);
    let report = verify(&registry, &good_policy(&key), &model, NOW);
    assert_eq!(
        report.status,
        RevocationStatus::Verified,
        "{:?}",
        report.refusals
    );
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.dimensions.signature_validity.as_str(), "valid");
    assert_eq!(report.dimensions.authorization.as_str(), "valid");
    assert_eq!(report.dimensions.sequence_integrity.as_str(), "valid");
    assert_eq!(report.dimensions.historical_replay.as_str(), "valid");
    assert_eq!(report.dimensions.present_authorization.as_str(), "valid");
    let support = report.support.expect("support application");
    assert!(support.historical_verdict_valid);
    assert!(support
        .invalidated
        .contains(&"claim.campaign-closure".to_owned()));
    assert!(support
        .alternative_survives
        .contains(&"claim.campaign-closure-with-mirror".to_owned()));
    let target = support
        .claims
        .iter()
        .find(|claim| claim.claim_id == "claim.campaign-closure")
        .expect("target claim");
    assert_eq!(target.historical_state, SupportState::Supported);
    assert_ne!(target.present_state, SupportState::Supported);
    assert!(!target.present_admissible);
    assert_eq!(target.revoked_evidence, vec!["evidence.closure".to_owned()]);
}

#[test]
fn revoked_but_historically_valid_claim_is_inadmissible_now() {
    let key = test_key(1);
    let model = committed_support_model().expect("model");
    let (registry, _envelope) = single_revocation(&key);
    let report = verify(&registry, &good_policy(&key), &model, NOW);
    let support = report.support.as_ref().expect("support");
    let target = support
        .claims
        .iter()
        .find(|claim| claim.claim_id == "claim.campaign-closure")
        .expect("target claim");
    assert!(target.historically_supported);
    assert!(!target.presently_supported);
    assert!(!target.present_admissible);
    assert!(support.historical_verdict_valid);
    assert_eq!(
        support
            .claims
            .iter()
            .find(|claim| claim.claim_id == "claim.sarif-projection")
            .expect("contradictory claim")
            .contradictory_retained,
        vec!["contradiction.sarif-nondeterministic-case".to_owned()]
    );
}

#[test]
fn duplicate_revocation_is_refused() {
    let key = test_key(1);
    let model = committed_support_model().expect("model");
    let first = entry_value(
        REGISTRY_ID,
        1,
        None,
        "rev-0001",
        RevocationAction::Revoke,
        "claim.campaign-closure",
        &["evidence.closure"],
        None,
    );
    let first_envelope = sign_entry(&first, "correct-1", &key);
    let second = entry_value(
        REGISTRY_ID,
        2,
        Some(&entry_digest(&first_envelope)),
        "rev-0002",
        RevocationAction::Revoke,
        "claim.campaign-closure",
        &["evidence.closure"],
        None,
    );
    let second_envelope = sign_entry(&second, "correct-1", &key);
    let registry = registry_value(vec![first_envelope, second_envelope]);
    let report = verify(&registry, &good_policy(&key), &model, NOW);
    assert_eq!(report.status, RevocationStatus::Refused);
    assert!(codes(&report).contains(&RevocationRefusalCode::DuplicateRevocation));
}

#[test]
fn unauthorized_revocation_signer_is_refused_with_a_valid_signature_retained() {
    let correction = test_key(1);
    let producer = test_key(9);
    let model = committed_support_model().expect("model");
    let value = entry_value(
        REGISTRY_ID,
        1,
        None,
        "rev-0001",
        RevocationAction::Revoke,
        "claim.campaign-closure",
        &["evidence.closure"],
        None,
    );
    let envelope = sign_entry(&value, "producer-1", &producer);
    let registry = registry_value(vec![envelope]);
    let policy = policy(
        vec![key_entry(
            "correct-1",
            &correction,
            "correction-authority",
            ISSUED,
            EXPIRES,
        )],
        vec![key_entry(
            "producer-1",
            &producer,
            "producer",
            ISSUED,
            EXPIRES,
        )],
        EXPIRES,
    );
    let report = verify(&registry, &policy, &model, NOW);
    assert_eq!(report.status, RevocationStatus::Refused);
    assert!(codes(&report).contains(&RevocationRefusalCode::UnauthorizedRole));
    let signer = report.signers.first().expect("signer");
    assert!(signer.signature_valid);
    assert!(!signer.authorized);
}

#[test]
fn replayed_revocation_is_refused() {
    let key = test_key(1);
    let model = committed_support_model().expect("model");
    let value = entry_value(
        "another-registry",
        1,
        None,
        "rev-0001",
        RevocationAction::Revoke,
        "claim.campaign-closure",
        &["evidence.closure"],
        None,
    );
    let envelope = sign_entry(&value, "correct-1", &key);
    let registry = registry_value(vec![envelope]);
    let report = verify(&registry, &good_policy(&key), &model, NOW);
    assert_eq!(report.status, RevocationStatus::Refused);
    assert!(codes(&report).contains(&RevocationRefusalCode::ReplayedRevocation));
}

#[test]
fn stale_revocation_policy_is_refused() {
    let key = test_key(1);
    let model = committed_support_model().expect("model");
    let (registry, _envelope) = single_revocation(&key);
    let policy = policy(
        vec![key_entry(
            "correct-1",
            &key,
            "correction-authority",
            ISSUED,
            EXPIRES,
        )],
        vec![],
        NOW - 1,
    );
    let report = verify(&registry, &policy, &model, NOW);
    assert_eq!(report.status, RevocationStatus::Refused);
    assert!(codes(&report).contains(&RevocationRefusalCode::StalePolicy));
}

#[test]
fn expired_revocation_key_is_refused() {
    let key = test_key(1);
    let model = committed_support_model().expect("model");
    let (registry, _envelope) = single_revocation(&key);
    let policy = policy(
        vec![key_entry(
            "correct-1",
            &key,
            "correction-authority",
            ISSUED,
            NOW - 1,
        )],
        vec![],
        EXPIRES,
    );
    let report = verify(&registry, &policy, &model, NOW);
    assert_eq!(report.status, RevocationStatus::Refused);
    assert!(codes(&report).contains(&RevocationRefusalCode::ExpiredCredential));
}

#[test]
fn tampered_entry_is_refused() {
    let key = test_key(1);
    let model = committed_support_model().expect("model");
    let value = entry_value(
        REGISTRY_ID,
        1,
        None,
        "rev-0001",
        RevocationAction::Revoke,
        "claim.campaign-closure",
        &["evidence.closure"],
        None,
    );
    let mut envelope = sign_entry(&value, "correct-1", &key);
    let payload = STANDARD.decode(&envelope.payload).expect("payload base64");
    let mut parsed = parse_strict(&payload).expect("payload JSON");
    parsed["target"]["claim_id"] = Value::String("claim.attested-closure".to_owned());
    envelope.payload = STANDARD.encode(canon(&parsed));
    let registry = registry_value(vec![envelope]);
    let report = verify(&registry, &good_policy(&key), &model, NOW);
    assert_eq!(report.status, RevocationStatus::Refused);
    assert!(codes(&report).contains(&RevocationRefusalCode::InvalidSignature));
}

#[test]
fn chain_mismatch_is_an_integrity_failure() {
    let key = test_key(1);
    let model = committed_support_model().expect("model");
    let first = entry_value(
        REGISTRY_ID,
        1,
        None,
        "rev-0001",
        RevocationAction::Revoke,
        "claim.campaign-closure",
        &["evidence.closure"],
        None,
    );
    let first_envelope = sign_entry(&first, "correct-1", &key);
    let second = entry_value(
        REGISTRY_ID,
        2,
        Some(&"0".repeat(64)),
        "rev-0002",
        RevocationAction::Dissent,
        "claim.campaign-closure",
        &[],
        Some("retained dissent"),
    );
    let second_envelope = sign_entry(&second, "correct-1", &key);
    let registry = registry_value(vec![first_envelope, second_envelope]);
    let historical = record_historical_verdict(&model).expect("historical verdict");
    let error = verify_registry_bytes(
        &canon(&registry),
        &good_policy(&key),
        Some(&model),
        Some(&historical),
        NOW,
    )
    .expect_err("chain mismatch");
    assert_eq!(error.exit_code(), 3);
}

#[test]
fn duplicate_entry_id_is_an_integrity_failure() {
    let key = test_key(1);
    let model = committed_support_model().expect("model");
    let first = entry_value(
        REGISTRY_ID,
        1,
        None,
        "rev-0001",
        RevocationAction::Revoke,
        "claim.campaign-closure",
        &["evidence.closure"],
        None,
    );
    let first_envelope = sign_entry(&first, "correct-1", &key);
    let second = entry_value(
        REGISTRY_ID,
        2,
        Some(&entry_digest(&first_envelope)),
        "rev-0001",
        RevocationAction::Dissent,
        "claim.campaign-closure",
        &[],
        Some("retained dissent"),
    );
    let second_envelope = sign_entry(&second, "correct-1", &key);
    let registry = registry_value(vec![first_envelope, second_envelope]);
    let historical = record_historical_verdict(&model).expect("historical verdict");
    let error = verify_registry_bytes(
        &canon(&registry),
        &good_policy(&key),
        Some(&model),
        Some(&historical),
        NOW,
    )
    .expect_err("duplicate entry id");
    assert_eq!(error.exit_code(), 3);
}

#[test]
fn retained_dissent_and_correction_are_preserved() {
    let key = test_key(1);
    let model = committed_support_model().expect("model");
    let first = entry_value(
        REGISTRY_ID,
        1,
        None,
        "rev-0001",
        RevocationAction::Revoke,
        "claim.campaign-closure",
        &["evidence.closure"],
        None,
    );
    let first_envelope = sign_entry(&first, "correct-1", &key);
    let second = entry_value(
        REGISTRY_ID,
        2,
        Some(&entry_digest(&first_envelope)),
        "cor-0002",
        RevocationAction::Correct,
        "claim.campaign-closure",
        &[],
        Some("the claim statement is narrowed"),
    );
    let second_envelope = sign_entry(&second, "correct-1", &key);
    let third = entry_value(
        REGISTRY_ID,
        3,
        Some(&entry_digest(&second_envelope)),
        "dis-0003",
        RevocationAction::Dissent,
        "claim.campaign-closure",
        &[],
        Some("a dissenting observation is retained"),
    );
    let third_envelope = sign_entry(&third, "correct-1", &key);
    let registry = registry_value(vec![first_envelope, second_envelope, third_envelope]);
    let report = verify(&registry, &good_policy(&key), &model, NOW);
    assert_eq!(
        report.status,
        RevocationStatus::Verified,
        "{:?}",
        report.refusals
    );
    assert_eq!(report.corrections.len(), 1);
    assert!(report.corrections[0].retained);
    assert_eq!(report.retained_dissent.len(), 1);
    assert!(report.retained_dissent[0].retained);
}

#[test]
fn stale_support_policy_withholds_present_authorization() {
    let key = test_key(1);
    let model = committed_support_model().expect("model");
    let (registry, _envelope) = single_revocation(&key);
    let report = verify(&registry, &good_policy(&key), &model, EXPIRES + 1);
    assert_eq!(report.status, RevocationStatus::Refused);
    assert!(codes(&report).contains(&RevocationRefusalCode::StaleSupportPolicy));
    let support = report.support.expect("support");
    assert!(support.historical_verdict_valid);
    assert_eq!(support.present_freshness, "stale");
    assert!(support.claims.iter().all(|claim| !claim.present_admissible));
}

#[test]
fn missing_support_target_is_refused() {
    let key = test_key(1);
    let model = committed_support_model().expect("model");
    let value = entry_value(
        REGISTRY_ID,
        1,
        None,
        "rev-0001",
        RevocationAction::Revoke,
        "claim.not-in-model",
        &["evidence.closure"],
        None,
    );
    let envelope = sign_entry(&value, "correct-1", &key);
    let registry = registry_value(vec![envelope]);
    let report = verify(&registry, &good_policy(&key), &model, NOW);
    assert_eq!(report.status, RevocationStatus::Refused);
    assert!(codes(&report).contains(&RevocationRefusalCode::MissingSupport));
}
