//! Phase 10.3 authenticated-evidence tests.
//!
//! Every test executes. The committed campaign is loaded from disk. Test-only
//! Ed25519 keys are generated in memory from fixed seeds; no private key is
//! written to the repository and no test signs with a production key.
//!
//! The negative controls require a valid signature to be refused on
//! authorization, scope, freshness, independence, or semantics. A valid
//! signature alone is never acceptance.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use frf_memorysafety::etp::ETP_SPEC;
use frf_memorysafety::etp_auth::{
    campaign_expectation_from_bundle, load_policy, pae, parse_envelope, parse_policy,
    parse_statement, verify_envelope_bytes, AttestationRefusalCode, AttestationStatus,
    AuthorizedKey, CampaignClosurePredicate, CampaignExpectation, DimensionState, DsseEnvelope,
    DsseSignatureEnvelope, InTotoStatement, IndependentReviewState, PredicateCount,
    StatementSubject, TrustPolicy, TrustRole, DSSE_PAYLOAD_TYPE, IN_TOTO_STATEMENT_TYPE,
    MAX_PAYLOAD_BYTES, MAX_SIGNATURES, PREDICATE_SCHEMA_CAMPAIGN_CLOSURE,
    PREDICATE_TYPE_CAMPAIGN_CLOSURE, TRUST_POLICY_SCHEMA,
};
use frf_memorysafety::etp_campaign::{
    load_bundle, CampaignBundle, CampaignCount, CampaignStatus, ClosureStatus,
};
use frf_memorysafety::identity::canonical_bytes;
use serde_json::{json, Value};

const ISSUED: u64 = 1_795_305_600;
const EXPIRES: u64 = 1_826_841_600;
const NOW: u64 = 1_795_330_364;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn committed_bundle() -> CampaignBundle {
    load_bundle(&repo().join("evaluation/earned-trust-1.2.0/MANIFEST.json"))
        .expect("committed bundle")
}

fn expectation() -> CampaignExpectation {
    campaign_expectation_from_bundle(&committed_bundle()).expect("campaign expectation")
}

fn canon(value: &Value) -> Vec<u8> {
    canonical_bytes(value).expect("canonical bytes")
}

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

fn role(
    id: &str,
    keys: Vec<AuthorizedKey>,
    scope: &[&str],
    threshold: u32,
    independent: bool,
) -> TrustRole {
    TrustRole {
        id: id.to_owned(),
        threshold,
        independent,
        scope: scope.iter().map(|entry| (*entry).to_owned()).collect(),
        keys,
    }
}

fn policy(roles: Vec<TrustRole>) -> TrustPolicy {
    TrustPolicy {
        schema: TRUST_POLICY_SCHEMA.to_owned(),
        spec: ETP_SPEC.to_owned(),
        policy_id: "test-policy".to_owned(),
        version: 1,
        issued_at_unix: ISSUED,
        expires_at_unix: EXPIRES,
        roles,
    }
}

fn producer_policy(keyid: &str, key: &SigningKey) -> TrustPolicy {
    policy(vec![role(
        "evidence_producer",
        vec![key_entry(keyid, key, "producer", ISSUED, EXPIRES)],
        &[PREDICATE_TYPE_CAMPAIGN_CLOSURE],
        1,
        false,
    )])
}

fn counts(values: &[CampaignCount]) -> Vec<PredicateCount> {
    values
        .iter()
        .map(|count| PredicateCount {
            label: count.label.clone(),
            count: u64::try_from(count.count).unwrap_or(u64::MAX),
        })
        .collect()
}

fn derived_conclusion(report: &frf_memorysafety::etp_campaign::CampaignReport) -> &'static str {
    if report.status == CampaignStatus::Accepted {
        "accepted"
    } else if report.closure_status == ClosureStatus::Blocked {
        "blocked"
    } else {
        "withheld"
    }
}

fn campaign_predicate(expectation: &CampaignExpectation) -> CampaignClosurePredicate {
    let report = &expectation.report;
    CampaignClosurePredicate {
        schema: PREDICATE_SCHEMA_CAMPAIGN_CLOSURE.to_owned(),
        spec: ETP_SPEC.to_owned(),
        campaign_id: expectation.campaign_id.clone(),
        closure_sha256: expectation.closure_sha256.clone(),
        candidate_identity: expectation.candidate_identity.clone(),
        raw_evidence_sha256: expectation.evidence_root_sha256.clone(),
        case_count: u64::try_from(report.case_count).unwrap_or(u64::MAX),
        receipt_count: u64::try_from(report.receipt_count).unwrap_or(u64::MAX),
        raw_evidence_count: u64::try_from(report.raw_evidence_count).unwrap_or(u64::MAX),
        case_ids: expectation.case_ids.clone(),
        outcomes: counts(&report.outcomes),
        decisions: counts(&report.decisions),
        closure_status: report.closure_status.as_str().to_owned(),
        acceptance: report.acceptance.as_str().to_owned(),
        conclusion: derived_conclusion(report).to_owned(),
        independent_review: "not_established".to_owned(),
        claim_ceiling: report.claim_ceiling.clone(),
    }
}

fn statement(
    expectation: &CampaignExpectation,
    predicate: CampaignClosurePredicate,
) -> InTotoStatement {
    let digest = |value: &str| BTreeMap::from([("sha256".to_owned(), value.to_owned())]);
    InTotoStatement {
        statement_type: IN_TOTO_STATEMENT_TYPE.to_owned(),
        subject: vec![
            StatementSubject {
                name: format!("campaign-closure:{}", expectation.campaign_id),
                digest: digest(&expectation.closure_sha256),
            },
            StatementSubject {
                name: format!("candidate:{}", expectation.candidate_identity),
                digest: digest(&expectation.candidate_identity),
            },
            StatementSubject {
                name: format!("raw-evidence:{}", expectation.campaign_id),
                digest: digest(&expectation.evidence_root_sha256),
            },
        ],
        predicate_type: PREDICATE_TYPE_CAMPAIGN_CLOSURE.to_owned(),
        predicate: serde_json::to_value(predicate).expect("predicate JSON"),
    }
}

fn valid_statement(expectation: &CampaignExpectation) -> InTotoStatement {
    statement(expectation, campaign_predicate(expectation))
}

fn payload_of(statement: &InTotoStatement) -> Vec<u8> {
    canon(&serde_json::to_value(statement).expect("statement JSON"))
}

fn envelope(keyid: &str, key: &SigningKey, payload: &[u8], payload_type: &str) -> DsseEnvelope {
    let message = pae(payload_type, payload).expect("PAE");
    let signature = key.sign(&message);
    DsseEnvelope {
        payload_type: payload_type.to_owned(),
        payload: STANDARD.encode(payload),
        signatures: vec![DsseSignatureEnvelope {
            keyid: keyid.to_owned(),
            sig: STANDARD.encode(signature.to_bytes()),
        }],
    }
}

fn envelope_bytes(envelope: &DsseEnvelope) -> Vec<u8> {
    envelope.canonical_bytes().expect("envelope bytes")
}

fn codes(
    report: &frf_memorysafety::etp_auth::AttestationReport,
) -> BTreeSet<AttestationRefusalCode> {
    report.refusals.iter().map(|refusal| refusal.code).collect()
}

fn assert_refused(
    report: &frf_memorysafety::etp_auth::AttestationReport,
    code: AttestationRefusalCode,
) {
    assert_eq!(
        report.status,
        AttestationStatus::Refused,
        "{:?}",
        report.refusals
    );
    assert!(
        codes(report).contains(&code),
        "expected {code:?}, got {:?}",
        report.refusals
    );
}

#[test]
fn committed_attestation_is_accepted_with_separate_dimensions() {
    let expectation = expectation();
    let policy = load_policy(&repo().join("evaluation/earned-trust-1.2.0/trust-policy.json"))
        .expect("committed policy");
    let report = frf_memorysafety::etp_auth::verify_envelope_file(
        &repo().join("evaluation/earned-trust-1.2.0/attestations/campaign-closure.envelope.json"),
        &policy,
        Some(&expectation),
        NOW,
    )
    .expect("verification");
    assert_eq!(
        report.status,
        AttestationStatus::Accepted,
        "{:?}",
        report.refusals
    );
    assert_eq!(report.dimensions.signature_validity, DimensionState::Valid);
    assert_eq!(report.dimensions.payload_integrity, DimensionState::Valid);
    assert_eq!(report.dimensions.authorization, DimensionState::Valid);
    assert_eq!(report.dimensions.scope_applicability, DimensionState::Valid);
    assert_eq!(report.dimensions.freshness, DimensionState::Valid);
    assert_eq!(report.dimensions.semantic_support, DimensionState::Valid);
    assert_eq!(
        report.dimensions.independent_review,
        IndependentReviewState::NotEstablished
    );
    assert_eq!(report.independent_reviewers, 0);
    assert!(report.refusals.is_empty());
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn valid_signature_alone_is_not_acceptance() {
    let expectation = expectation();
    let key = test_key(1);
    let payload = payload_of(&valid_statement(&expectation));
    let bytes = envelope_bytes(&envelope("k1", &key, &payload, DSSE_PAYLOAD_TYPE));
    let report = verify_envelope_bytes(&bytes, &producer_policy("k1", &key), None, NOW)
        .expect("verification");
    assert_refused(&report, AttestationRefusalCode::SemanticSupportNotEvaluated);
    assert_eq!(report.dimensions.signature_validity, DimensionState::Valid);
    assert_eq!(
        report.dimensions.semantic_support,
        DimensionState::NotChecked
    );
}

#[test]
fn valid_test_signed_statement_is_accepted() {
    let expectation = expectation();
    let key = test_key(2);
    let payload = payload_of(&valid_statement(&expectation));
    let bytes = envelope_bytes(&envelope("k2", &key, &payload, DSSE_PAYLOAD_TYPE));
    let report = verify_envelope_bytes(
        &bytes,
        &producer_policy("k2", &key),
        Some(&expectation),
        NOW,
    )
    .expect("verification");
    assert_eq!(
        report.status,
        AttestationStatus::Accepted,
        "{:?}",
        report.refusals
    );
}

#[test]
fn wrong_key_is_refused() {
    let expectation = expectation();
    let signer = test_key(3);
    let other = test_key(4);
    let payload = payload_of(&valid_statement(&expectation));
    let bytes = envelope_bytes(&envelope("k3", &signer, &payload, DSSE_PAYLOAD_TYPE));
    let report = verify_envelope_bytes(
        &bytes,
        &producer_policy("k3", &other),
        Some(&expectation),
        NOW,
    )
    .expect("verification");
    assert_refused(&report, AttestationRefusalCode::InvalidSignature);
    assert_eq!(
        report.dimensions.signature_validity,
        DimensionState::Invalid
    );
}

#[test]
fn tampered_payload_is_refused() {
    let expectation = expectation();
    let key = test_key(5);
    let mut value = serde_json::to_value(valid_statement(&expectation)).expect("statement");
    value["predicate"]["case_count"] = json!(14);
    let tampered = canon(&value);
    let mut envelope = envelope(
        "k5",
        &key,
        &payload_of(&valid_statement(&expectation)),
        DSSE_PAYLOAD_TYPE,
    );
    envelope.payload = STANDARD.encode(&tampered);
    let report = verify_envelope_bytes(
        &envelope_bytes(&envelope),
        &producer_policy("k5", &key),
        Some(&expectation),
        NOW,
    )
    .expect("verification");
    assert_refused(&report, AttestationRefusalCode::InvalidSignature);
}

#[test]
fn malformed_pae_is_refused() {
    let expectation = expectation();
    let key = test_key(6);
    let payload = payload_of(&valid_statement(&expectation));
    assert!(pae("application/vnd.in-toto+json extra", &payload).is_err());
    let message = pae("application/vnd.in-toto+json-other", &payload).expect("wrong PAE");
    let signature = key.sign(&message);
    let envelope = DsseEnvelope {
        payload_type: DSSE_PAYLOAD_TYPE.to_owned(),
        payload: STANDARD.encode(&payload),
        signatures: vec![DsseSignatureEnvelope {
            keyid: "k6".to_owned(),
            sig: STANDARD.encode(signature.to_bytes()),
        }],
    };
    let report = verify_envelope_bytes(
        &envelope_bytes(&envelope),
        &producer_policy("k6", &key),
        Some(&expectation),
        NOW,
    )
    .expect("verification");
    assert_refused(&report, AttestationRefusalCode::InvalidSignature);
}

#[test]
fn substituted_subject_is_refused() {
    let expectation = expectation();
    let key = test_key(7);
    let mut value = serde_json::to_value(valid_statement(&expectation)).expect("statement");
    value["subject"][1]["digest"]["sha256"] = json!("1".repeat(64));
    let payload = canon(&value);
    let bytes = envelope_bytes(&envelope("k7", &key, &payload, DSSE_PAYLOAD_TYPE));
    let report = verify_envelope_bytes(
        &bytes,
        &producer_policy("k7", &key),
        Some(&expectation),
        NOW,
    )
    .expect("verification");
    assert_refused(&report, AttestationRefusalCode::CandidateMismatch);
    assert_eq!(report.dimensions.signature_validity, DimensionState::Valid);
}

#[test]
fn replayed_envelope_for_another_campaign_is_refused() {
    let expectation = expectation();
    let key = test_key(8);
    let payload = payload_of(&valid_statement(&expectation));
    let bytes = envelope_bytes(&envelope("k8", &key, &payload, DSSE_PAYLOAD_TYPE));
    let mut other = expectation.clone();
    other.campaign_id = "frf-etp-different-campaign".to_owned();
    other.closure_sha256 = "0".repeat(64);
    other.candidate_identity = "0".repeat(64);
    other.evidence_root_sha256 = "0".repeat(64);
    other.case_ids = vec!["invented-case".to_owned()];
    let report = verify_envelope_bytes(&bytes, &producer_policy("k8", &key), Some(&other), NOW)
        .expect("verification");
    assert_refused(&report, AttestationRefusalCode::CampaignMismatch);
    assert_eq!(report.dimensions.signature_validity, DimensionState::Valid);
}

#[test]
fn duplicate_json_keys_are_rejected() {
    let raw = br#"{"payloadType":"application/vnd.in-toto+json","payload":"e30=","payload":"e30=","signatures":[]}"#;
    assert!(parse_envelope(raw).is_err());
}

#[test]
fn oversized_payload_is_rejected() {
    let oversized = vec![b'a'; MAX_PAYLOAD_BYTES + 1];
    let envelope = DsseEnvelope {
        payload_type: DSSE_PAYLOAD_TYPE.to_owned(),
        payload: STANDARD.encode(&oversized),
        signatures: vec![DsseSignatureEnvelope {
            keyid: "k9".to_owned(),
            sig: STANDARD.encode([0_u8; 64]),
        }],
    };
    let raw = serde_json::to_vec(&envelope).expect("envelope JSON");
    assert!(parse_envelope(&raw).is_err());
}

#[test]
fn excessive_nesting_is_rejected() {
    let mut nested = String::from("[");
    for _ in 0..100 {
        nested.push('[');
    }
    for _ in 0..101 {
        nested.push(']');
    }
    let raw =
        format!(r#"{{"payloadType":"{DSSE_PAYLOAD_TYPE}","payload":{nested},"signatures":[]}}"#);
    assert!(parse_envelope(raw.as_bytes()).is_err());
}

#[test]
fn signature_count_abuse_is_rejected() {
    let key = test_key(10);
    let payload = payload_of(&valid_statement(&expectation()));
    let signature = DsseSignatureEnvelope {
        keyid: "k10".to_owned(),
        sig: STANDARD.encode(
            key.sign(&pae(DSSE_PAYLOAD_TYPE, &payload).expect("PAE"))
                .to_bytes(),
        ),
    };
    let mut signatures = Vec::new();
    for index in 0..=MAX_SIGNATURES {
        let mut entry = signature.clone();
        entry.keyid = format!("k10-{index}");
        signatures.push(entry);
    }
    let envelope = DsseEnvelope {
        payload_type: DSSE_PAYLOAD_TYPE.to_owned(),
        payload: STANDARD.encode(&payload),
        signatures,
    };
    assert!(parse_envelope(&envelope_bytes(&envelope)).is_err());

    let duplicate = DsseEnvelope {
        payload_type: DSSE_PAYLOAD_TYPE.to_owned(),
        payload: STANDARD.encode(&payload),
        signatures: vec![signature.clone(), signature],
    };
    assert!(parse_envelope(&envelope_bytes(&duplicate)).is_err());
}

#[test]
fn unsupported_algorithm_is_refused() {
    let expectation = expectation();
    let key = test_key(11);
    let payload = payload_of(&valid_statement(&expectation));
    let bytes = envelope_bytes(&envelope("k11", &key, &payload, DSSE_PAYLOAD_TYPE));
    let mut policy = producer_policy("k11", &key);
    policy.roles[0].keys[0].algorithm = "rsa".to_owned();
    let report =
        verify_envelope_bytes(&bytes, &policy, Some(&expectation), NOW).expect("verification");
    assert_refused(&report, AttestationRefusalCode::UnsupportedAlgorithm);

    let mut value = serde_json::to_value(&policy).expect("policy");
    value["schema"] = json!(TRUST_POLICY_SCHEMA);
    value["spec"] = json!(ETP_SPEC);
    assert!(parse_policy(&canon(&value)).is_err());
}

#[test]
fn unauthorized_role_is_refused() {
    let expectation = expectation();
    let key = test_key(12);
    let payload = payload_of(&valid_statement(&expectation));
    let bytes = envelope_bytes(&envelope("k12", &key, &payload, DSSE_PAYLOAD_TYPE));
    let policy = self::policy(vec![role(
        "release_authority",
        vec![key_entry("k12", &key, "release", ISSUED, EXPIRES)],
        &["https://frf.dev/etp/release-adjudication/v1"],
        1,
        false,
    )]);
    let report =
        verify_envelope_bytes(&bytes, &policy, Some(&expectation), NOW).expect("verification");
    assert_refused(&report, AttestationRefusalCode::UnauthorizedRole);
    assert_eq!(report.dimensions.signature_validity, DimensionState::Valid);
    assert_eq!(report.dimensions.authorization, DimensionState::Invalid);
}

#[test]
fn expired_key_is_refused() {
    let expectation = expectation();
    let key = test_key(13);
    let payload = payload_of(&valid_statement(&expectation));
    let bytes = envelope_bytes(&envelope("k13", &key, &payload, DSSE_PAYLOAD_TYPE));
    let policy = policy(vec![role(
        "evidence_producer",
        vec![key_entry(
            "k13",
            &key,
            "producer",
            ISSUED,
            NOW.saturating_sub(1),
        )],
        &[PREDICATE_TYPE_CAMPAIGN_CLOSURE],
        1,
        false,
    )]);
    let report =
        verify_envelope_bytes(&bytes, &policy, Some(&expectation), NOW).expect("verification");
    assert_refused(&report, AttestationRefusalCode::ExpiredCredential);
    assert_eq!(report.dimensions.signature_validity, DimensionState::Valid);
    assert_eq!(report.dimensions.freshness, DimensionState::Invalid);
}

#[test]
fn duplicate_actor_does_not_satisfy_an_independent_threshold() {
    let expectation = expectation();
    let producer = test_key(14);
    let adjudicator_one = test_key(15);
    let adjudicator_two = test_key(16);
    let mut predicate = campaign_predicate(&expectation);
    predicate.independent_review = "established".to_owned();
    let payload = payload_of(&statement(&expectation, predicate));
    let message = pae(DSSE_PAYLOAD_TYPE, &payload).expect("PAE");
    let signatures = [
        ("producer", &producer),
        ("adjudicator-one", &adjudicator_one),
        ("adjudicator-two", &adjudicator_two),
    ]
    .into_iter()
    .map(|(keyid, key)| DsseSignatureEnvelope {
        keyid: keyid.to_owned(),
        sig: STANDARD.encode(key.sign(&message).to_bytes()),
    })
    .collect();
    let envelope = DsseEnvelope {
        payload_type: DSSE_PAYLOAD_TYPE.to_owned(),
        payload: STANDARD.encode(&payload),
        signatures,
    };
    let policy = policy(vec![
        role(
            "evidence_producer",
            vec![key_entry(
                "producer", &producer, "producer", ISSUED, EXPIRES,
            )],
            &[PREDICATE_TYPE_CAMPAIGN_CLOSURE],
            1,
            false,
        ),
        role(
            "adjudicator",
            vec![
                key_entry(
                    "adjudicator-one",
                    &adjudicator_one,
                    "same-actor",
                    ISSUED,
                    EXPIRES,
                ),
                key_entry(
                    "adjudicator-two",
                    &adjudicator_two,
                    "same-actor",
                    ISSUED,
                    EXPIRES,
                ),
            ],
            &[PREDICATE_TYPE_CAMPAIGN_CLOSURE],
            2,
            true,
        ),
    ]);
    let report =
        verify_envelope_bytes(&envelope_bytes(&envelope), &policy, Some(&expectation), NOW)
            .expect("verification");
    assert_refused(
        &report,
        AttestationRefusalCode::InsufficientIndependentReview,
    );
    assert_eq!(report.independent_reviewers, 1);
    assert_eq!(report.dimensions.signature_validity, DimensionState::Valid);
    assert_eq!(
        report.dimensions.independent_review,
        IndependentReviewState::Insufficient
    );
}

#[test]
fn duplicate_policy_credentials_are_rejected() {
    let key = test_key(17);
    let entry = key_entry("dup-a", &key, "actor", ISSUED, EXPIRES);
    let mut duplicate = entry.clone();
    duplicate.keyid = "dup-b".to_owned();
    let mut value = serde_json::to_value(policy(vec![role(
        "evidence_producer",
        vec![entry, duplicate],
        &[PREDICATE_TYPE_CAMPAIGN_CLOSURE],
        2,
        false,
    )]))
    .expect("policy");
    value["schema"] = json!(TRUST_POLICY_SCHEMA);
    value["spec"] = json!(ETP_SPEC);
    assert!(parse_policy(&canon(&value)).is_err());
}

#[test]
fn correctly_signed_incomplete_closure_is_refused() {
    let complete = expectation();
    let key = test_key(18);
    let payload = payload_of(&valid_statement(&complete));

    let mut bundle = committed_bundle();
    assert!(bundle
        .receipts
        .remove("receipts/use-after-free-c.json")
        .is_some());
    let incomplete = campaign_expectation_from_bundle(&bundle).expect("incomplete expectation");
    assert_eq!(incomplete.report.status, CampaignStatus::Refused);

    let bytes = envelope_bytes(&envelope("k18", &key, &payload, DSSE_PAYLOAD_TYPE));
    let report = verify_envelope_bytes(
        &bytes,
        &producer_policy("k18", &key),
        Some(&incomplete),
        NOW,
    )
    .expect("verification");
    assert_refused(&report, AttestationRefusalCode::CampaignNotClosed);
    assert_eq!(report.dimensions.signature_validity, DimensionState::Valid);
    assert_eq!(report.dimensions.semantic_support, DimensionState::Invalid);
}

#[test]
fn correctly_signed_false_conclusion_is_refused() {
    let expectation = expectation();
    let key = test_key(19);
    let mut predicate = campaign_predicate(&expectation);
    predicate.conclusion = "withheld".to_owned();
    let payload = payload_of(&statement(&expectation, predicate));
    let bytes = envelope_bytes(&envelope("k19", &key, &payload, DSSE_PAYLOAD_TYPE));
    let report = verify_envelope_bytes(
        &bytes,
        &producer_policy("k19", &key),
        Some(&expectation),
        NOW,
    )
    .expect("verification");
    assert_refused(&report, AttestationRefusalCode::FalseConclusion);
    assert_eq!(report.dimensions.signature_validity, DimensionState::Valid);
    assert_eq!(report.dimensions.semantic_support, DimensionState::Invalid);
}

#[test]
fn policy_and_statement_versions_are_enforced() {
    let key = test_key(20);
    let mut value = serde_json::to_value(policy(vec![role(
        "evidence_producer",
        vec![key_entry("k20", &key, "producer", ISSUED, EXPIRES)],
        &[PREDICATE_TYPE_CAMPAIGN_CLOSURE],
        1,
        false,
    )]))
    .expect("policy");
    value["schema"] = json!("frf-etp.trust-policy.v2");
    assert!(parse_policy(&canon(&value)).is_err());
    value["schema"] = json!(TRUST_POLICY_SCHEMA);
    value["roles"][0]["id"] = json!("not_a_role");
    assert!(parse_policy(&canon(&value)).is_err());

    let expectation = expectation();
    let mut statement_value =
        serde_json::to_value(valid_statement(&expectation)).expect("statement");
    statement_value["_type"] = json!("https://in-toto.io/Statement/v2");
    assert!(parse_statement(&canon(&statement_value)).is_err());
}

#[test]
fn pae_matches_the_exact_dsse_v1_encoding() {
    let payload_type = "http://example.com/HelloWorld";
    let payload = b"hello world";
    let encoded = pae(payload_type, payload).expect("PAE");
    assert_eq!(
        encoded,
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
    );
}
