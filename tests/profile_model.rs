//! Finite three-rule profile: deterministic 24-record model and refusal checks.

use frf_memorysafety::identity::{digest_bytes, IdentityDomain};
use frf_memorysafety::model::Property;
use frf_memorysafety::profile::{
    buffer_model_policy, canonical_bundle_bytes, evaluate_profile, evaluate_profile_json,
    local_buffer_bundle, local_buffer_claims, local_buffer_records, observation_digest,
    BufferVariant, ClaimDisposition, EvidenceOrigin, FiniteCase, ProfileBundle, ProfileClaim,
    ProfileEvaluation, ProfileRefusalKind, BUFFER_RECORD_COUNT, CLAIMS_PER_VARIANT,
    SCENARIOS_PER_VARIANT, UNIVERSAL_SOUNDNESS,
};

fn claim_mut<'a>(bundle: &'a mut ProfileBundle, id: &str) -> &'a mut ProfileClaim {
    bundle
        .claims
        .iter_mut()
        .find(|claim| claim.id == id)
        .unwrap_or_else(|| panic!("missing claim {id}"))
}

fn has_refusal(evaluation: &ProfileEvaluation, kind: ProfileRefusalKind) -> bool {
    evaluation
        .refusals
        .iter()
        .any(|refusal| refusal.kind == kind)
}

#[test]
fn model_produces_24_records_with_paper_counts() {
    let records = local_buffer_records();
    assert_eq!(records.len(), BUFFER_RECORD_COUNT);
    assert_eq!(records.len(), 24);
    for variant in [BufferVariant::C0, BufferVariant::C1, BufferVariant::C2] {
        let cases: Vec<&FiniteCase> = records
            .iter()
            .filter(|case| case.variant == variant)
            .collect();
        assert_eq!(cases.len(), SCENARIOS_PER_VARIANT);
        let adjudicable = cases.iter().filter(|case| case.adjudicable).count();
        let conflicts = cases
            .iter()
            .filter(|case| case.model_violation.is_some())
            .count();
        let mismatches = cases
            .iter()
            .filter(|case| {
                case.adjudicable && case.model_replay_outcome != case.stipulated_oracle_outcome
            })
            .count();
        match variant {
            BufferVariant::C0 => assert_eq!((adjudicable, conflicts, mismatches), (6, 2, 0)),
            BufferVariant::C1 => assert_eq!((adjudicable, conflicts, mismatches), (8, 0, 0)),
            BufferVariant::C2 => assert_eq!((adjudicable, conflicts, mismatches), (8, 0, 4)),
        }
    }
}

#[test]
fn model_produces_five_claims_per_variant() {
    let claims = local_buffer_claims(&buffer_model_policy());
    assert_eq!(claims.len(), 3 * CLAIMS_PER_VARIANT);
    assert_eq!(claims.len(), 15);
    for prefix in ["c0", "c1", "c2"] {
        assert_eq!(
            claims
                .iter()
                .filter(|claim| claim.id.starts_with(prefix))
                .count(),
            CLAIMS_PER_VARIANT
        );
    }
}

#[test]
fn universal_soundness_is_always_withheld() {
    let evaluation = evaluate_profile(&local_buffer_bundle());
    assert_eq!(evaluation.universal_soundness, UNIVERSAL_SOUNDNESS);
    for prefix in ["c0", "c1", "c2"] {
        assert_eq!(
            evaluation.claims[&format!("{prefix}-universal")].disposition,
            ClaimDisposition::Withheld
        );
        assert!(!evaluation
            .established
            .contains(&format!("{prefix}-universal")));
    }
}

#[test]
fn canonical_bundle_round_trips_through_json() {
    let bundle = local_buffer_bundle();
    let bytes = canonical_bundle_bytes(&bundle).unwrap();
    let parsed = evaluate_profile_json(&bytes);
    let direct = evaluate_profile(&bundle);
    assert_eq!(parsed, direct);
}

#[test]
fn refusal_check_01_provider_scope_mismatch() {
    let mut bundle = local_buffer_bundle();
    let evidence = claim_mut(&mut bundle, "c1-clear")
        .evidence
        .as_mut()
        .unwrap();
    evidence.origin = EvidenceOrigin::NativeExecution;
    let evaluation = evaluate_profile(&bundle);
    assert!(has_refusal(
        &evaluation,
        ProfileRefusalKind::ProviderScopeMismatch
    ));
}

#[test]
fn refusal_check_02_altered_artifact() {
    let mut bundle = local_buffer_bundle();
    let evidence = claim_mut(&mut bundle, "c1-clear")
        .evidence
        .as_mut()
        .unwrap();
    evidence.artifact.supplied_digest =
        Some(digest_bytes(IdentityDomain::Execution, b"altered artifact"));
    let evaluation = evaluate_profile(&bundle);
    assert!(has_refusal(
        &evaluation,
        ProfileRefusalKind::ArtifactDigestMismatch
    ));
}

#[test]
fn refusal_check_03_honestly_rehashed_fabricated_observation() {
    let mut bundle = local_buffer_bundle();
    let evidence = claim_mut(&mut bundle, "c1-clear")
        .evidence
        .as_mut()
        .unwrap();
    let observation = &mut evidence.observations[0];
    observation.recorded_outcome = "fabricated".to_owned();
    observation.payload_digest =
        observation_digest(&observation.case_id, &observation.recorded_outcome);
    let evaluation = evaluate_profile(&bundle);
    assert!(has_refusal(
        &evaluation,
        ProfileRefusalKind::RehashedObservationMismatch
    ));
    assert!(!has_refusal(
        &evaluation,
        ProfileRefusalKind::ObservationDigestMismatch
    ));
}

#[test]
fn refusal_check_04_domain_expansion() {
    let mut bundle = local_buffer_bundle();
    let restriction = claim_mut(&mut bundle, "c1-restriction");
    restriction.target_cases.push("c0-01".to_owned());
    let evaluation = evaluate_profile(&bundle);
    assert!(has_refusal(
        &evaluation,
        ProfileRefusalKind::DomainExpansion
    ));
    assert_eq!(
        evaluation.claims["c1-restriction"].disposition,
        ClaimDisposition::Refused
    );
}

#[test]
fn refusal_check_05_property_substitution() {
    let mut bundle = local_buffer_bundle();
    claim_mut(&mut bundle, "c1-restriction").property = Property::ModelParity;
    let evaluation = evaluate_profile(&bundle);
    assert!(has_refusal(
        &evaluation,
        ProfileRefusalKind::PropertySubstitution
    ));
}

#[test]
fn refusal_check_06_self_dependent_claim() {
    let mut bundle = local_buffer_bundle();
    claim_mut(&mut bundle, "c1-restriction").premises = vec!["c1-restriction".to_owned()];
    let evaluation = evaluate_profile(&bundle);
    assert!(has_refusal(
        &evaluation,
        ProfileRefusalKind::SelfDependentClaim
    ));
}

#[test]
fn refusal_check_07_duplicate_identifier() {
    let mut bundle = local_buffer_bundle();
    let duplicate = bundle
        .claims
        .iter()
        .find(|claim| claim.id == "c1-clear")
        .unwrap()
        .clone();
    bundle.claims.push(duplicate);
    let evaluation = evaluate_profile(&bundle);
    assert!(has_refusal(
        &evaluation,
        ProfileRefusalKind::DuplicateIdentifier
    ));
}

#[test]
fn refusal_check_08_unknown_field() {
    let bundle = local_buffer_bundle();
    let mut value = serde_json::to_value(&bundle).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unexpected_field".to_owned(), serde_json::json!(true));
    let bytes = serde_json::to_vec(&value).unwrap();
    let evaluation = evaluate_profile_json(&bytes);
    assert!(has_refusal(&evaluation, ProfileRefusalKind::UnknownField));
}

#[test]
fn refusal_check_09_stale_policy_anchor() {
    let mut bundle = local_buffer_bundle();
    claim_mut(&mut bundle, "c1-clear").anchors.policy =
        digest_bytes(IdentityDomain::Policy, b"stale policy");
    let evaluation = evaluate_profile(&bundle);
    assert!(has_refusal(
        &evaluation,
        ProfileRefusalKind::StalePolicyAnchor
    ));
}

#[test]
fn absent_evidence_and_inexact_coverage_are_refused() {
    let mut bundle = local_buffer_bundle();
    claim_mut(&mut bundle, "c1-clear").evidence = None;
    let evaluation = evaluate_profile(&bundle);
    assert!(has_refusal(&evaluation, ProfileRefusalKind::AbsentEvidence));

    let mut bundle = local_buffer_bundle();
    claim_mut(&mut bundle, "c1-clear")
        .evidence
        .as_mut()
        .unwrap()
        .coverage
        .exact = false;
    let evaluation = evaluate_profile(&bundle);
    assert!(has_refusal(
        &evaluation,
        ProfileRefusalKind::InexactCoverage
    ));
}

#[test]
fn observation_digest_mismatch_is_refused() {
    let mut bundle = local_buffer_bundle();
    let evidence = claim_mut(&mut bundle, "c1-clear")
        .evidence
        .as_mut()
        .unwrap();
    evidence.observations[0].payload_digest =
        digest_bytes(IdentityDomain::Execution, b"not the payload");
    let evaluation = evaluate_profile(&bundle);
    assert!(has_refusal(
        &evaluation,
        ProfileRefusalKind::ObservationDigestMismatch
    ));
}

#[test]
fn all_nine_named_refusal_checks_are_constructible() {
    // A compact guard that the nine labels remain exactly the required set.
    let names = [
        ProfileRefusalKind::ProviderScopeMismatch,
        ProfileRefusalKind::ArtifactDigestMismatch,
        ProfileRefusalKind::RehashedObservationMismatch,
        ProfileRefusalKind::DomainExpansion,
        ProfileRefusalKind::PropertySubstitution,
        ProfileRefusalKind::SelfDependentClaim,
        ProfileRefusalKind::DuplicateIdentifier,
        ProfileRefusalKind::UnknownField,
        ProfileRefusalKind::StalePolicyAnchor,
    ];
    assert_eq!(names.len(), 9);
    let unique: std::collections::BTreeSet<&str> = names.iter().map(|kind| kind.as_str()).collect();
    assert_eq!(unique.len(), 9);
}
