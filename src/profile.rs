//! The normative finite three-rule semantic profile from `SPEC.md` §7.
//!
//! The profile accepts exactly three inference shapes:
//!
//! * enumeration over an exact finite case set;
//! * restriction to a subset of an established finite case set;
//! * conjunction of two established finite-model claims.
//!
//! Universal soundness, native execution, proof checking, and deployment
//! scoping are deliberately outside the profile. They are reported as
//! `WITHHELD_NOT_RUN`, never as established facts.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::identity::{
    canonical_bytes, digest_bytes, parse_strict, IdentityDomain, IdentityError, MsId,
};
use crate::model::{ExecutionMode, Property, Quantifier, ScopeAnchors};

/// Schema identifier for a finite-profile bundle.
pub const PROFILE_SCHEMA: &str = "frf-memorysafety.profile.v1";
/// Specification identifier this profile implements.
pub const PROFILE_SPEC: &str = "frf-memorysafety-spec-v1";
/// Name of the deterministic local buffer model.
pub const BUFFER_MODEL_ID: &str = "local-buffer-model-v1";
/// Number of scenarios per buffer-model variant.
pub const SCENARIOS_PER_VARIANT: usize = 8;
/// Number of record fields produced by the local buffer model (3 * 8).
pub const BUFFER_RECORD_COUNT: usize = 24;
/// Number of requested claims per buffer-model variant.
pub const CLAIMS_PER_VARIANT: usize = 5;
/// Value reported for every universal-soundness request.
pub const UNIVERSAL_SOUNDNESS: &str = "WITHHELD_NOT_RUN";

/// Buffer-model variant from the paper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BufferVariant {
    /// Interval held across a successful replacement.
    C0,
    /// Interval acquired after the callback.
    C1,
    /// Every identity is accepted.
    C2,
}

impl BufferVariant {
    /// Stable protocol label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::C0 => "C0",
            Self::C1 => "C1",
            Self::C2 => "C2",
        }
    }
}

/// The three admitted inference rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileRule {
    /// Exact finite enumeration.
    Enumeration,
    /// Restriction to a subset of an established case set.
    Restriction,
    /// Conjunction of two established finite-model claims.
    Conjunction,
}

/// Where an observation came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOrigin {
    /// Deterministic local finite-model replay.
    FiniteModelReplay,
    /// Native execution (not admitted by this profile).
    NativeExecution,
    /// A universal proof (not admitted by this profile).
    UniversalProof,
    /// An external attestation (not admitted by this profile).
    ExternalAttestation,
}

/// Named refusal categories. The first nine are the adversarial checks
/// required by the phase-1 profile contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileRefusalKind {
    /// Evidence provider or scope anchors do not match.
    ProviderScopeMismatch,
    /// The artifact digest does not match the supplied bytes.
    ArtifactDigestMismatch,
    /// An observation was honestly rehashed but disagrees with local replay.
    RehashedObservationMismatch,
    /// A restriction would widen the case domain.
    DomainExpansion,
    /// A claim substitutes a different property.
    PropertySubstitution,
    /// A claim depends on itself.
    SelfDependentClaim,
    /// A claim, case, or observation identifier is repeated.
    DuplicateIdentifier,
    /// The typed schema rejected an unknown field.
    UnknownField,
    /// A claim's policy anchor is stale.
    StalePolicyAnchor,
    /// A universal or native claim was requested.
    UniversalOrNativeClaim,
    /// Evidence bytes are absent.
    AbsentEvidence,
    /// The declared case coverage is not exact.
    InexactCoverage,
    /// The observation digest does not match its payload.
    ObservationDigestMismatch,
    /// A referenced premise is absent.
    UnknownPremise,
    /// The rule shape is malformed.
    MalformedRule,
    /// The bundle or policy is malformed.
    InvalidBundle,
}

impl ProfileRefusalKind {
    /// Stable protocol name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderScopeMismatch => "provider_or_scope_mismatch",
            Self::ArtifactDigestMismatch => "artifact_digest_mismatch",
            Self::RehashedObservationMismatch => "rehashed_observation_mismatch",
            Self::DomainExpansion => "domain_expansion",
            Self::PropertySubstitution => "property_substitution",
            Self::SelfDependentClaim => "self_dependent_claim",
            Self::DuplicateIdentifier => "duplicate_identifier",
            Self::UnknownField => "unknown_field",
            Self::StalePolicyAnchor => "stale_policy_anchor",
            Self::UniversalOrNativeClaim => "universal_or_native_claim",
            Self::AbsentEvidence => "absent_evidence",
            Self::InexactCoverage => "inexact_coverage",
            Self::ObservationDigestMismatch => "observation_digest_mismatch",
            Self::UnknownPremise => "unknown_premise",
            Self::MalformedRule => "malformed_rule",
            Self::InvalidBundle => "invalid_bundle",
        }
    }

    /// CLI exit status recommended for this refusal.
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::DomainExpansion
            | Self::PropertySubstitution
            | Self::SelfDependentClaim
            | Self::UniversalOrNativeClaim
            | Self::UnknownPremise
            | Self::MalformedRule => 4,
            Self::ProviderScopeMismatch
            | Self::ArtifactDigestMismatch
            | Self::RehashedObservationMismatch
            | Self::DuplicateIdentifier
            | Self::UnknownField
            | Self::StalePolicyAnchor
            | Self::AbsentEvidence
            | Self::InexactCoverage
            | Self::ObservationDigestMismatch
            | Self::InvalidBundle => 3,
        }
    }
}

/// Disposition of one requested claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimDisposition {
    /// Established within the exact finite scope.
    Established,
    /// Evidence is well formed, but the finite conclusion is false.
    NotEstablished,
    /// Universal/native claim, deliberately withheld.
    Withheld,
    /// A protocol or integrity refusal applies.
    Refused,
}

/// One finite case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FiniteCase {
    /// Stable case identifier.
    pub id: String,
    /// Buffer-model variant.
    pub variant: BufferVariant,
    /// Scenario name.
    pub scenario: String,
    /// Whether the stipulated oracle can adjudicate this case.
    pub adjudicable: bool,
    /// A modeled violation, if the local model reports one.
    pub model_violation: Option<String>,
    /// Deterministic local model outcome.
    pub model_replay_outcome: String,
    /// Stipulated observation-oracle outcome.
    pub stipulated_oracle_outcome: String,
}

/// A replayed observation of one case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// Observation identifier.
    pub id: String,
    /// Case observed.
    pub case_id: String,
    /// Recorded outcome.
    pub recorded_outcome: String,
    /// Digest over the observation payload `(case_id, recorded_outcome)`.
    pub payload_digest: MsId,
}

/// Artifact binding carried by enumeration evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBinding {
    /// Artifact name.
    pub name: String,
    /// Digest declared by the claim.
    pub declared_digest: MsId,
    /// Digest of the bytes actually supplied, if any.
    pub supplied_digest: Option<MsId>,
    /// Whether the bytes were present at evaluation time.
    pub bytes_present: bool,
}

/// Exact-coverage declaration for an enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageEvidence {
    /// Whether the evidence asserts exhaustive coverage.
    pub exact: bool,
    /// Cases the provider says are missing.
    pub missing: Vec<String>,
    /// Cases the provider says are extra.
    pub extra: Vec<String>,
}

/// Evidence for one enumeration claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnumerationEvidence {
    /// Claim this evidence is bound to.
    pub claim_id: String,
    /// Evidence origin.
    pub origin: EvidenceOrigin,
    /// Execution mode.
    pub execution_mode: ExecutionMode,
    /// Artifact binding.
    pub artifact: ArtifactBinding,
    /// Coverage declaration.
    pub coverage: CoverageEvidence,
    /// Exact finite case set.
    pub cases: Vec<FiniteCase>,
    /// Replayed observations, one per case.
    pub observations: Vec<Observation>,
}

/// One claim in a finite-profile bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileClaim {
    /// Claim identifier.
    pub id: String,
    /// Claimed property.
    pub property: Property,
    /// Claim quantifier.
    pub quantifier: Quantifier,
    /// Scope anchors.
    pub anchors: ScopeAnchors,
    /// Inference rule.
    pub rule: ProfileRule,
    /// Premise claim identifiers.
    pub premises: Vec<String>,
    /// Target case set for a restriction.
    pub target_cases: Vec<String>,
    /// Evidence for an enumeration; absent for restriction/conjunction.
    pub evidence: Option<EnumerationEvidence>,
}

/// Policy and expected anchors for a finite-profile evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilePolicy {
    /// Policy identifier.
    pub id: String,
    /// Policy version.
    pub version: String,
    /// Anchors every claim must carry.
    pub required_anchors: ScopeAnchors,
    /// Properties the profile may conclude.
    pub permitted_properties: BTreeSet<Property>,
    /// Maximum number of cases in one enumeration.
    pub max_cases: usize,
    /// Deterministic model named by the policy.
    pub deterministic_model: String,
}

/// A self-contained finite-profile bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileBundle {
    /// Bundle schema, which must equal [`PROFILE_SCHEMA`].
    pub schema: String,
    /// Specification identifier, which must equal [`PROFILE_SPEC`].
    pub spec: String,
    /// Policy under which the claims are evaluated.
    pub policy: ProfilePolicy,
    /// Requested claims.
    pub claims: Vec<ProfileClaim>,
}

/// One recorded refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRefusal {
    /// Refusal category.
    pub kind: ProfileRefusalKind,
    /// Claim the refusal applies to, when claim-scoped.
    pub claim: Option<String>,
    /// Human-readable detail.
    pub detail: String,
}

/// Verdict for one claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimVerdict {
    /// Claim identifier.
    pub claim_id: String,
    /// Rule used.
    pub rule: ProfileRule,
    /// Claimed property.
    pub property: Property,
    /// Disposition.
    pub disposition: ClaimDisposition,
    /// Number of cases in the claim's finite domain.
    pub case_count: usize,
    /// Reason for the disposition.
    pub detail: String,
}

/// Result of evaluating a finite-profile bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileEvaluation {
    /// Whether every protocol/integrity check passed.
    pub protocol_ok: bool,
    /// Refusals found during evaluation.
    pub refusals: Vec<ProfileRefusal>,
    /// Per-claim verdicts.
    pub claims: BTreeMap<String, ClaimVerdict>,
    /// Claims established within their exact finite scope.
    pub established: BTreeSet<String>,
    /// Always [`UNIVERSAL_SOUNDNESS`]; never an established fact.
    pub universal_soundness: String,
}

/// Compute the canonical payload digest of an observation.
#[must_use]
pub fn observation_digest(case_id: &str, recorded_outcome: &str) -> MsId {
    let mut payload = String::new();
    payload.push_str(case_id);
    payload.push('\u{0}');
    payload.push_str(recorded_outcome);
    digest_bytes(IdentityDomain::Execution, payload.as_bytes())
}

impl Observation {
    /// Construct an observation with its canonical payload digest.
    #[must_use]
    pub fn new(id: String, case_id: String, recorded_outcome: String) -> Self {
        let payload_digest = observation_digest(&case_id, &recorded_outcome);
        Self {
            id,
            case_id,
            recorded_outcome,
            payload_digest,
        }
    }
}

fn anchor(domain: IdentityDomain, label: &str) -> MsId {
    digest_bytes(domain, label.as_bytes())
}

/// Deterministic anchors used by the local buffer-model fixture.
#[must_use]
pub fn buffer_model_anchors() -> ScopeAnchors {
    ScopeAnchors {
        source: anchor(
            IdentityDomain::Subject,
            "local-buffer-model/source/buffer.c",
        ),
        candidate: anchor(
            IdentityDomain::Subject,
            "local-buffer-model/candidate/buffer-safe.rs",
        ),
        environment: anchor(
            IdentityDomain::Subject,
            "local-buffer-model/environment/deterministic",
        ),
        model: anchor(IdentityDomain::Subject, "local-buffer-model/model/v1"),
        policy: anchor(
            IdentityDomain::Policy,
            "local-buffer-model/policy/three-rule/v1",
        ),
    }
}

/// Policy used by the local buffer-model fixture.
#[must_use]
pub fn buffer_model_policy() -> ProfilePolicy {
    ProfilePolicy {
        id: "frf-memorysafety.profile.local-buffer".to_owned(),
        version: "1".to_owned(),
        required_anchors: buffer_model_anchors(),
        permitted_properties: BTreeSet::from([
            Property::ModelClear,
            Property::ModelParity,
            Property::ModelConjunction,
        ]),
        max_cases: SCENARIOS_PER_VARIANT,
        deterministic_model: BUFFER_MODEL_ID.to_owned(),
    }
}

#[derive(Clone, Copy)]
struct ScenarioRow {
    scenario: &'static str,
    adjudicable: bool,
    violation: bool,
    replay: &'static str,
    oracle: &'static str,
}

const C0_ROWS: [ScenarioRow; SCENARIOS_PER_VARIANT] = [
    ScenarioRow {
        scenario: "replace_success_use_after",
        adjudicable: true,
        violation: true,
        replay: "accepted",
        oracle: "accepted",
    },
    ScenarioRow {
        scenario: "replace_success_no_use",
        adjudicable: true,
        violation: false,
        replay: "accepted",
        oracle: "accepted",
    },
    ScenarioRow {
        scenario: "replace_failure_use_after",
        adjudicable: true,
        violation: false,
        replay: "rejected",
        oracle: "rejected",
    },
    ScenarioRow {
        scenario: "replace_failure_no_use",
        adjudicable: true,
        violation: false,
        replay: "rejected",
        oracle: "rejected",
    },
    ScenarioRow {
        scenario: "callback_before_replace",
        adjudicable: true,
        violation: false,
        replay: "accepted",
        oracle: "accepted",
    },
    ScenarioRow {
        scenario: "callback_after_replace",
        adjudicable: true,
        violation: false,
        replay: "accepted",
        oracle: "accepted",
    },
    ScenarioRow {
        scenario: "alias_old_after_replace",
        adjudicable: false,
        violation: true,
        replay: "accepted",
        oracle: "accepted",
    },
    ScenarioRow {
        scenario: "torn_observation",
        adjudicable: false,
        violation: false,
        replay: "unobserved",
        oracle: "unobserved",
    },
];

const C1_ROWS: [ScenarioRow; SCENARIOS_PER_VARIANT] = [
    ScenarioRow {
        scenario: "replace_success_use_after",
        adjudicable: true,
        violation: false,
        replay: "accepted",
        oracle: "accepted",
    },
    ScenarioRow {
        scenario: "replace_success_no_use",
        adjudicable: true,
        violation: false,
        replay: "accepted",
        oracle: "accepted",
    },
    ScenarioRow {
        scenario: "replace_failure_use_after",
        adjudicable: true,
        violation: false,
        replay: "rejected",
        oracle: "rejected",
    },
    ScenarioRow {
        scenario: "replace_failure_no_use",
        adjudicable: true,
        violation: false,
        replay: "rejected",
        oracle: "rejected",
    },
    ScenarioRow {
        scenario: "callback_before_replace",
        adjudicable: true,
        violation: false,
        replay: "accepted",
        oracle: "accepted",
    },
    ScenarioRow {
        scenario: "callback_after_replace",
        adjudicable: true,
        violation: false,
        replay: "accepted",
        oracle: "accepted",
    },
    ScenarioRow {
        scenario: "alias_old_after_replace",
        adjudicable: true,
        violation: false,
        replay: "accepted",
        oracle: "accepted",
    },
    ScenarioRow {
        scenario: "torn_observation",
        adjudicable: true,
        violation: false,
        replay: "unobserved",
        oracle: "unobserved",
    },
];

const C2_ROWS: [ScenarioRow; SCENARIOS_PER_VARIANT] = [
    ScenarioRow {
        scenario: "replace_success_use_after",
        adjudicable: true,
        violation: false,
        replay: "accepted",
        oracle: "rejected",
    },
    ScenarioRow {
        scenario: "replace_success_no_use",
        adjudicable: true,
        violation: false,
        replay: "accepted",
        oracle: "accepted",
    },
    ScenarioRow {
        scenario: "replace_failure_use_after",
        adjudicable: true,
        violation: false,
        replay: "accepted",
        oracle: "rejected",
    },
    ScenarioRow {
        scenario: "replace_failure_no_use",
        adjudicable: true,
        violation: false,
        replay: "accepted",
        oracle: "accepted",
    },
    ScenarioRow {
        scenario: "callback_before_replace",
        adjudicable: true,
        violation: false,
        replay: "accepted",
        oracle: "rejected",
    },
    ScenarioRow {
        scenario: "callback_after_replace",
        adjudicable: true,
        violation: false,
        replay: "accepted",
        oracle: "accepted",
    },
    ScenarioRow {
        scenario: "alias_old_after_replace",
        adjudicable: true,
        violation: false,
        replay: "accepted",
        oracle: "rejected",
    },
    ScenarioRow {
        scenario: "torn_observation",
        adjudicable: true,
        violation: false,
        replay: "accepted",
        oracle: "accepted",
    },
];

const fn rows_for(variant: BufferVariant) -> [ScenarioRow; SCENARIOS_PER_VARIANT] {
    match variant {
        BufferVariant::C0 => C0_ROWS,
        BufferVariant::C1 => C1_ROWS,
        BufferVariant::C2 => C2_ROWS,
    }
}

/// Look up the independently reconstructed outcome of a local-model case.
///
/// The returned row is the crate's own record of the deterministic model, not a
/// value supplied by evidence. It is used to detect evidence that rehashes a
/// fabricated case outcome consistently with its observation.
fn local_model_row(variant: BufferVariant, scenario: &str) -> Option<ScenarioRow> {
    rows_for(variant)
        .iter()
        .copied()
        .find(|row| row.scenario == scenario)
}

fn case_prefix(variant: BufferVariant) -> &'static str {
    match variant {
        BufferVariant::C0 => "c0",
        BufferVariant::C1 => "c1",
        BufferVariant::C2 => "c2",
    }
}

/// Produce the 24 deterministic local buffer-model records (8 per variant).
#[must_use]
pub fn local_buffer_records() -> Vec<FiniteCase> {
    let mut records = Vec::with_capacity(BUFFER_RECORD_COUNT);
    for variant in [BufferVariant::C0, BufferVariant::C1, BufferVariant::C2] {
        let rows = rows_for(variant);
        let prefix = case_prefix(variant);
        for (index, row) in rows.iter().enumerate() {
            records.push(FiniteCase {
                id: format!("{prefix}-{:02}", index + 1),
                variant,
                scenario: row.scenario.to_owned(),
                adjudicable: row.adjudicable,
                model_violation: row
                    .violation
                    .then(|| format!("{}: interval/model conflict", variant.as_str())),
                model_replay_outcome: row.replay.to_owned(),
                stipulated_oracle_outcome: row.oracle.to_owned(),
            });
        }
    }
    records
}

fn evidence_for(claim_id: &str, cases: Vec<FiniteCase>) -> EnumerationEvidence {
    let observations = cases
        .iter()
        .map(|case| {
            Observation::new(
                format!("obs-{}", case.id),
                case.id.clone(),
                case.model_replay_outcome.clone(),
            )
        })
        .collect();
    let digest = digest_bytes(
        IdentityDomain::Execution,
        format!("{BUFFER_MODEL_ID}/artifact").as_bytes(),
    );
    EnumerationEvidence {
        claim_id: claim_id.to_owned(),
        origin: EvidenceOrigin::FiniteModelReplay,
        execution_mode: ExecutionMode::FiniteEventModel,
        artifact: ArtifactBinding {
            name: BUFFER_MODEL_ID.to_owned(),
            declared_digest: digest.clone(),
            supplied_digest: Some(digest),
            bytes_present: true,
        },
        coverage: CoverageEvidence {
            exact: true,
            missing: Vec::new(),
            extra: Vec::new(),
        },
        cases,
        observations,
    }
}

fn base_claim(
    id: String,
    property: Property,
    rule: ProfileRule,
    anchors: &ScopeAnchors,
) -> ProfileClaim {
    ProfileClaim {
        id,
        property,
        quantifier: Quantifier::FiniteModelExhaustion,
        anchors: anchors.clone(),
        rule,
        premises: Vec::new(),
        target_cases: Vec::new(),
        evidence: None,
    }
}

/// Produce the five requested claims for every buffer-model variant.
///
/// The five claims are, per variant: full `model_clear` enumeration,
/// `model_parity` over adjudicable cases, a restriction of the clear claim to
/// the adjudicable subset, the conjunction of that restriction with parity, and
/// a deliberately withheld universal-soundness request.
#[must_use]
pub fn local_buffer_claims(policy: &ProfilePolicy) -> Vec<ProfileClaim> {
    let records = local_buffer_records();
    let mut claims = Vec::with_capacity(3 * CLAIMS_PER_VARIANT);
    for variant in [BufferVariant::C0, BufferVariant::C1, BufferVariant::C2] {
        let prefix = case_prefix(variant);
        let variant_cases: Vec<FiniteCase> = records
            .iter()
            .filter(|case| case.variant == variant)
            .cloned()
            .collect();
        let adjudicable: Vec<FiniteCase> = variant_cases
            .iter()
            .filter(|case| case.adjudicable)
            .cloned()
            .collect();

        let clear_id = format!("{prefix}-clear");
        let parity_id = format!("{prefix}-parity");
        let restriction_id = format!("{prefix}-restriction");
        let conjunction_id = format!("{prefix}-conjunction");
        let universal_id = format!("{prefix}-universal");

        let mut clear = base_claim(
            clear_id.clone(),
            Property::ModelClear,
            ProfileRule::Enumeration,
            &policy.required_anchors,
        );
        clear.evidence = Some(evidence_for(&clear_id, variant_cases));

        let mut parity = base_claim(
            parity_id.clone(),
            Property::ModelParity,
            ProfileRule::Enumeration,
            &policy.required_anchors,
        );
        parity.evidence = Some(evidence_for(&parity_id, adjudicable.clone()));

        let mut restriction = base_claim(
            restriction_id.clone(),
            Property::ModelClear,
            ProfileRule::Restriction,
            &policy.required_anchors,
        );
        restriction.premises = vec![clear_id];
        restriction.target_cases = adjudicable.iter().map(|case| case.id.clone()).collect();

        let mut conjunction = base_claim(
            conjunction_id,
            Property::ModelConjunction,
            ProfileRule::Conjunction,
            &policy.required_anchors,
        );
        conjunction.premises = vec![restriction_id, parity_id];

        let mut universal = base_claim(
            universal_id,
            Property::SoundSafeInterior,
            ProfileRule::Enumeration,
            &policy.required_anchors,
        );
        universal.quantifier = Quantifier::UniversalContextual;

        claims.extend([clear, parity, restriction, conjunction, universal]);
    }
    claims
}

/// Build the deterministic 24-record, 15-claim local buffer-model bundle.
#[must_use]
pub fn local_buffer_bundle() -> ProfileBundle {
    let policy = buffer_model_policy();
    let claims = local_buffer_claims(&policy);
    ProfileBundle {
        schema: PROFILE_SCHEMA.to_owned(),
        spec: PROFILE_SPEC.to_owned(),
        policy,
        claims,
    }
}

fn refusal(
    refusals: &mut Vec<ProfileRefusal>,
    kind: ProfileRefusalKind,
    claim: Option<&str>,
    detail: impl Into<String>,
) {
    let detail = detail.into();
    let claim = claim.map(str::to_owned);
    if refusals
        .iter()
        .any(|existing| existing.kind == kind && existing.claim == claim)
    {
        return;
    }
    refusals.push(ProfileRefusal {
        kind,
        claim,
        detail,
    });
}

fn refused_evaluation(refusals: Vec<ProfileRefusal>) -> ProfileEvaluation {
    ProfileEvaluation {
        protocol_ok: false,
        refusals,
        claims: BTreeMap::new(),
        established: BTreeSet::new(),
        universal_soundness: UNIVERSAL_SOUNDNESS.to_owned(),
    }
}

/// Parse and evaluate a profile bundle from bytes.
///
/// Unknown fields, duplicate JSON keys, floats, and malformed JSON are turned
/// into explicit refusals rather than panics.
#[must_use]
pub fn evaluate_profile_json(bytes: &[u8]) -> ProfileEvaluation {
    let value = match parse_strict(bytes) {
        Ok(value) => value,
        Err(error) => {
            let kind = if matches!(error, IdentityError::DuplicateKey(_)) {
                ProfileRefusalKind::DuplicateIdentifier
            } else {
                ProfileRefusalKind::InvalidBundle
            };
            return refused_evaluation(vec![ProfileRefusal {
                kind,
                claim: None,
                detail: error.to_string(),
            }]);
        }
    };
    match serde_json::from_value::<ProfileBundle>(value) {
        Ok(bundle) => evaluate_profile(&bundle),
        Err(error) => {
            let message = error.to_string();
            let kind = if message.contains("unknown field") {
                ProfileRefusalKind::UnknownField
            } else {
                ProfileRefusalKind::InvalidBundle
            };
            refused_evaluation(vec![ProfileRefusal {
                kind,
                claim: None,
                detail: message,
            }])
        }
    }
}

/// Evaluate a finite-profile bundle.
///
/// The evaluator accepts only exact finite-model enumeration, restriction, and
/// conjunction. It never establishes universal soundness.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn evaluate_profile(bundle: &ProfileBundle) -> ProfileEvaluation {
    let mut refusals = Vec::new();
    if bundle.schema != PROFILE_SCHEMA {
        refusal(
            &mut refusals,
            ProfileRefusalKind::InvalidBundle,
            None,
            format!("expected schema {PROFILE_SCHEMA}, got {}", bundle.schema),
        );
    }
    if bundle.spec != PROFILE_SPEC {
        refusal(
            &mut refusals,
            ProfileRefusalKind::InvalidBundle,
            None,
            format!("expected spec {PROFILE_SPEC}, got {}", bundle.spec),
        );
    }
    let policy = &bundle.policy;
    if policy.max_cases == 0 || policy.max_cases > 65_536 {
        refusal(
            &mut refusals,
            ProfileRefusalKind::InvalidBundle,
            None,
            "policy max_cases must be between 1 and 65536",
        );
    }

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for claim in &bundle.claims {
        *counts.entry(claim.id.as_str()).or_insert(0) += 1;
    }
    for (id, count) in &counts {
        if *count > 1 {
            refusal(
                &mut refusals,
                ProfileRefusalKind::DuplicateIdentifier,
                Some(id),
                format!("claim identifier {id:?} appears {count} times"),
            );
        }
    }

    let mut claims_by_id: BTreeMap<&str, &ProfileClaim> = BTreeMap::new();
    for claim in &bundle.claims {
        claims_by_id.entry(claim.id.as_str()).or_insert(claim);
    }

    let mut static_ok: BTreeMap<String, bool> = BTreeMap::new();
    let mut enumeration_conclusions: BTreeMap<String, (bool, String, BTreeSet<String>)> =
        BTreeMap::new();

    for claim in claims_by_id.values() {
        let mut ok = true;
        let claim_ref = Some(claim.id.as_str());

        if claim.anchors.policy != policy.required_anchors.policy {
            refusal(
                &mut refusals,
                ProfileRefusalKind::StalePolicyAnchor,
                claim_ref,
                "claim policy anchor does not match the active policy",
            );
            ok = false;
        } else if claim.anchors != policy.required_anchors {
            refusal(
                &mut refusals,
                ProfileRefusalKind::ProviderScopeMismatch,
                claim_ref,
                "claim source/candidate/environment/model anchors do not match the policy",
            );
            ok = false;
        }

        let universal_or_native = claim.quantifier != Quantifier::FiniteModelExhaustion
            || matches!(
                claim.property,
                Property::SoundSafeInterior | Property::SafeCompatible
            );
        if universal_or_native {
            refusal(
                &mut refusals,
                ProfileRefusalKind::UniversalOrNativeClaim,
                claim_ref,
                "finite profile has no accepting rule for universal, native, or composite soundness",
            );
            ok = false;
        } else if !policy.permitted_properties.contains(&claim.property)
            && claim.property != Property::ModelConjunction
        {
            refusal(
                &mut refusals,
                ProfileRefusalKind::PropertySubstitution,
                claim_ref,
                format!(
                    "property {} is not permitted by the profile",
                    claim.property
                ),
            );
            ok = false;
        }

        if universal_or_native {
            // Universal/native requests are withheld, not evaluated as finite evidence.
        } else {
            match claim.rule {
                ProfileRule::Enumeration => {
                    if !validate_enumeration(
                        claim,
                        policy,
                        &mut refusals,
                        &mut enumeration_conclusions,
                    ) {
                        ok = false;
                    }
                }
                ProfileRule::Restriction => {
                    if !validate_restriction_shape(claim, &claims_by_id, &mut refusals) {
                        ok = false;
                    }
                }
                ProfileRule::Conjunction => {
                    if !validate_conjunction_shape(claim, &claims_by_id, &mut refusals) {
                        ok = false;
                    }
                }
            }
        }
        static_ok.insert(claim.id.clone(), ok);
    }

    detect_self_dependence(&claims_by_id, &mut static_ok, &mut refusals);

    let mut verdicts: BTreeMap<String, ClaimVerdict> = BTreeMap::new();
    let mut domains: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut established = BTreeSet::new();

    for claim in claims_by_id.values() {
        if claim.rule != ProfileRule::Enumeration {
            continue;
        }
        let accepted = static_ok.get(&claim.id).copied().unwrap_or(false);
        if !accepted {
            verdicts.insert(
                claim.id.clone(),
                ClaimVerdict {
                    claim_id: claim.id.clone(),
                    rule: claim.rule,
                    property: claim.property.clone(),
                    disposition: if matches!(
                        claim.property,
                        Property::SoundSafeInterior | Property::SafeCompatible
                    ) || claim.quantifier != Quantifier::FiniteModelExhaustion
                    {
                        ClaimDisposition::Withheld
                    } else {
                        ClaimDisposition::Refused
                    },
                    case_count: 0,
                    detail: "claim failed finite-profile validation".to_owned(),
                },
            );
            continue;
        }
        let (conclusion, detail, case_ids) = enumeration_conclusions
            .get(&claim.id)
            .cloned()
            .unwrap_or((false, "evidence absent".to_owned(), BTreeSet::new()));
        let disposition = if conclusion {
            ClaimDisposition::Established
        } else {
            ClaimDisposition::NotEstablished
        };
        if conclusion {
            established.insert(claim.id.clone());
        }
        domains.insert(claim.id.clone(), case_ids.clone());
        verdicts.insert(
            claim.id.clone(),
            ClaimVerdict {
                claim_id: claim.id.clone(),
                rule: claim.rule,
                property: claim.property.clone(),
                disposition,
                case_count: case_ids.len(),
                detail,
            },
        );
    }

    loop {
        let mut progressed = false;
        for claim in claims_by_id.values() {
            if claim.rule == ProfileRule::Enumeration || verdicts.contains_key(&claim.id) {
                continue;
            }
            if !static_ok.get(&claim.id).copied().unwrap_or(false) {
                verdicts.insert(
                    claim.id.clone(),
                    ClaimVerdict {
                        claim_id: claim.id.clone(),
                        rule: claim.rule,
                        property: claim.property.clone(),
                        disposition: ClaimDisposition::Refused,
                        case_count: 0,
                        detail: "claim failed finite-profile validation".to_owned(),
                    },
                );
                progressed = true;
                continue;
            }

            let premises: Vec<&str> = claim.premises.iter().map(String::as_str).collect();
            let missing = premises
                .iter()
                .find(|premise| !claims_by_id.contains_key(*premise));
            if let Some(missing) = missing {
                refusal(
                    &mut refusals,
                    ProfileRefusalKind::UnknownPremise,
                    Some(claim.id.as_str()),
                    format!("premise {missing:?} is not present in the bundle"),
                );
                static_ok.insert(claim.id.clone(), false);
                verdicts.insert(
                    claim.id.clone(),
                    ClaimVerdict {
                        claim_id: claim.id.clone(),
                        rule: claim.rule,
                        property: claim.property.clone(),
                        disposition: ClaimDisposition::Refused,
                        case_count: 0,
                        detail: format!("unknown premise {missing:?}"),
                    },
                );
                progressed = true;
                continue;
            }

            let all_resolved = premises
                .iter()
                .all(|premise| verdicts.contains_key(*premise));
            if !all_resolved {
                continue;
            }

            let premise_evidence: Vec<(&str, bool, Option<&BTreeSet<String>>)> = premises
                .iter()
                .map(|premise| {
                    let verdict = &verdicts[*premise];
                    (
                        *premise,
                        verdict.disposition == ClaimDisposition::Established,
                        domains.get(*premise),
                    )
                })
                .collect();

            match claim.rule {
                ProfileRule::Restriction => {
                    let (_, premise_established, premise_domain) = premise_evidence[0];
                    if !premise_established {
                        let detail = format!(
                            "premise {:?} is not established within its exact finite scope",
                            claim.premises[0]
                        );
                        verdicts.insert(
                            claim.id.clone(),
                            ClaimVerdict {
                                claim_id: claim.id.clone(),
                                rule: claim.rule,
                                property: claim.property.clone(),
                                disposition: ClaimDisposition::NotEstablished,
                                case_count: 0,
                                detail,
                            },
                        );
                        progressed = true;
                        continue;
                    }
                    let Some(premise_domain) = premise_domain else {
                        refusal(
                            &mut refusals,
                            ProfileRefusalKind::UnknownPremise,
                            Some(claim.id.as_str()),
                            "premise has no finite domain",
                        );
                        static_ok.insert(claim.id.clone(), false);
                        continue;
                    };
                    let target: BTreeSet<String> = claim.target_cases.iter().cloned().collect();
                    if !target.is_subset(premise_domain) {
                        refusal(
                            &mut refusals,
                            ProfileRefusalKind::DomainExpansion,
                            Some(claim.id.as_str()),
                            "restriction target is not a subset of the premise case set",
                        );
                        verdicts.insert(
                            claim.id.clone(),
                            ClaimVerdict {
                                claim_id: claim.id.clone(),
                                rule: claim.rule,
                                property: claim.property.clone(),
                                disposition: ClaimDisposition::Refused,
                                case_count: 0,
                                detail: "domain expansion refused".to_owned(),
                            },
                        );
                        progressed = true;
                        continue;
                    }
                    domains.insert(claim.id.clone(), target.clone());
                    established.insert(claim.id.clone());
                    verdicts.insert(
                        claim.id.clone(),
                        ClaimVerdict {
                            claim_id: claim.id.clone(),
                            rule: claim.rule,
                            property: claim.property.clone(),
                            disposition: ClaimDisposition::Established,
                            case_count: target.len(),
                            detail: "restriction accepted over an exact subset".to_owned(),
                        },
                    );
                    progressed = true;
                }
                ProfileRule::Conjunction => {
                    if premise_evidence.iter().any(|(_, ok, _)| !ok) {
                        verdicts.insert(
                            claim.id.clone(),
                            ClaimVerdict {
                                claim_id: claim.id.clone(),
                                rule: claim.rule,
                                property: claim.property.clone(),
                                disposition: ClaimDisposition::NotEstablished,
                                case_count: 0,
                                detail: "both conjunction premises must be established".to_owned(),
                            },
                        );
                        progressed = true;
                        continue;
                    }
                    let domains_equal = match (premise_evidence[0].2, premise_evidence[1].2) {
                        (Some(left), Some(right)) => left == right,
                        _ => false,
                    };
                    if !domains_equal {
                        refusal(
                            &mut refusals,
                            ProfileRefusalKind::DomainExpansion,
                            Some(claim.id.as_str()),
                            "conjunction premises describe different finite domains",
                        );
                        verdicts.insert(
                            claim.id.clone(),
                            ClaimVerdict {
                                claim_id: claim.id.clone(),
                                rule: claim.rule,
                                property: claim.property.clone(),
                                disposition: ClaimDisposition::Refused,
                                case_count: 0,
                                detail: "conjunction across domains refused".to_owned(),
                            },
                        );
                        progressed = true;
                        continue;
                    }
                    let domain = premise_evidence[0].2.cloned().unwrap_or_default();
                    domains.insert(claim.id.clone(), domain.clone());
                    established.insert(claim.id.clone());
                    verdicts.insert(
                        claim.id.clone(),
                        ClaimVerdict {
                            claim_id: claim.id.clone(),
                            rule: claim.rule,
                            property: claim.property.clone(),
                            disposition: ClaimDisposition::Established,
                            case_count: domain.len(),
                            detail: "conjunction accepted over one exact finite domain and scope"
                                .to_owned(),
                        },
                    );
                    progressed = true;
                }
                ProfileRule::Enumeration => {}
            }
        }
        if !progressed {
            break;
        }
    }

    for claim in claims_by_id.values() {
        if verdicts.contains_key(&claim.id) {
            continue;
        }
        verdicts.insert(
            claim.id.clone(),
            ClaimVerdict {
                claim_id: claim.id.clone(),
                rule: claim.rule,
                property: claim.property.clone(),
                disposition: ClaimDisposition::NotEstablished,
                case_count: 0,
                detail: "claim could not be resolved from established finite premises".to_owned(),
            },
        );
    }

    ProfileEvaluation {
        protocol_ok: refusals.is_empty(),
        refusals,
        claims: verdicts,
        established,
        universal_soundness: UNIVERSAL_SOUNDNESS.to_owned(),
    }
}

#[allow(clippy::too_many_lines)]
fn validate_enumeration(
    claim: &ProfileClaim,
    policy: &ProfilePolicy,
    refusals: &mut Vec<ProfileRefusal>,
    conclusions: &mut BTreeMap<String, (bool, String, BTreeSet<String>)>,
) -> bool {
    let claim_ref = Some(claim.id.as_str());
    let Some(evidence) = &claim.evidence else {
        refusal(
            refusals,
            ProfileRefusalKind::AbsentEvidence,
            claim_ref,
            "enumeration claim has no evidence bytes",
        );
        return false;
    };
    let mut ok = true;
    if evidence.claim_id != claim.id {
        refusal(
            refusals,
            ProfileRefusalKind::ProviderScopeMismatch,
            claim_ref,
            "evidence is bound to a different claim identifier",
        );
        ok = false;
    }
    if evidence.origin != EvidenceOrigin::FiniteModelReplay {
        refusal(
            refusals,
            ProfileRefusalKind::ProviderScopeMismatch,
            claim_ref,
            "only deterministic finite-model replay is admitted by this profile",
        );
        ok = false;
    }
    if evidence.execution_mode != ExecutionMode::FiniteEventModel {
        refusal(
            refusals,
            ProfileRefusalKind::UniversalOrNativeClaim,
            claim_ref,
            "native execution is not admitted by this finite profile",
        );
        ok = false;
    }
    if !evidence.artifact.bytes_present || evidence.artifact.supplied_digest.is_none() {
        refusal(
            refusals,
            ProfileRefusalKind::AbsentEvidence,
            claim_ref,
            "artifact bytes are absent",
        );
        ok = false;
    } else if evidence.artifact.supplied_digest.as_ref() != Some(&evidence.artifact.declared_digest)
    {
        refusal(
            refusals,
            ProfileRefusalKind::ArtifactDigestMismatch,
            claim_ref,
            "supplied artifact digest does not match the declared digest",
        );
        ok = false;
    }
    if !evidence.coverage.exact
        || !evidence.coverage.missing.is_empty()
        || !evidence.coverage.extra.is_empty()
    {
        refusal(
            refusals,
            ProfileRefusalKind::InexactCoverage,
            claim_ref,
            "enumeration coverage must be exact",
        );
        ok = false;
    }
    if evidence.cases.is_empty() || evidence.cases.len() > policy.max_cases {
        refusal(
            refusals,
            ProfileRefusalKind::InexactCoverage,
            claim_ref,
            format!(
                "case count {} is outside 1..={}",
                evidence.cases.len(),
                policy.max_cases
            ),
        );
        ok = false;
    }

    let mut case_ids = BTreeSet::new();
    for case in &evidence.cases {
        if !case_ids.insert(case.id.clone()) {
            refusal(
                refusals,
                ProfileRefusalKind::DuplicateIdentifier,
                claim_ref,
                format!("duplicate case identifier {:?}", case.id),
            );
            ok = false;
        }
    }

    // For the built-in local model, replay every case from the crate's own
    // reconstruction rather than trusting the evidence's case table. Without
    // this, an evidence provider could change a case outcome and its matching
    // observation together and pass the observation-versus-case check.
    if policy.deterministic_model == BUFFER_MODEL_ID {
        for case in &evidence.cases {
            match local_model_row(case.variant, &case.scenario) {
                None => {
                    refusal(
                        refusals,
                        ProfileRefusalKind::InexactCoverage,
                        claim_ref,
                        format!("case {:?} is not part of {BUFFER_MODEL_ID}", case.id),
                    );
                    ok = false;
                }
                Some(row) => {
                    let expected_violation = row
                        .violation
                        .then(|| format!("{}: interval/model conflict", case.variant.as_str()));
                    if case.adjudicable != row.adjudicable
                        || case.model_violation != expected_violation
                        || case.model_replay_outcome != row.replay
                        || case.stipulated_oracle_outcome != row.oracle
                    {
                        refusal(
                            refusals,
                            ProfileRefusalKind::RehashedObservationMismatch,
                            claim_ref,
                            format!(
                                "case {:?} disagrees with independent {BUFFER_MODEL_ID} replay",
                                case.id
                            ),
                        );
                        ok = false;
                    }
                }
            }
        }
    }
    let mut observation_ids = BTreeSet::new();
    let mut observed_cases = BTreeSet::new();
    let cases_by_id: BTreeMap<&str, &FiniteCase> = evidence
        .cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect();
    for observation in &evidence.observations {
        if !observation_ids.insert(observation.id.clone()) {
            refusal(
                refusals,
                ProfileRefusalKind::DuplicateIdentifier,
                claim_ref,
                format!("duplicate observation identifier {:?}", observation.id),
            );
            ok = false;
        }
        if !observed_cases.insert(observation.case_id.clone()) {
            refusal(
                refusals,
                ProfileRefusalKind::DuplicateIdentifier,
                claim_ref,
                format!("duplicate observation for case {:?}", observation.case_id),
            );
            ok = false;
        }
        let expected_digest =
            observation_digest(&observation.case_id, &observation.recorded_outcome);
        if observation.payload_digest != expected_digest {
            refusal(
                refusals,
                ProfileRefusalKind::ObservationDigestMismatch,
                claim_ref,
                format!(
                    "observation {:?} payload digest does not match its content",
                    observation.id
                ),
            );
            ok = false;
        }
        let Some(case) = cases_by_id.get(observation.case_id.as_str()) else {
            refusal(
                refusals,
                ProfileRefusalKind::InexactCoverage,
                claim_ref,
                format!(
                    "observation {:?} names an unknown case {:?}",
                    observation.id, observation.case_id
                ),
            );
            ok = false;
            continue;
        };
        if observation.recorded_outcome != case.model_replay_outcome {
            refusal(
                refusals,
                ProfileRefusalKind::RehashedObservationMismatch,
                claim_ref,
                format!(
                    "observation for case {:?} disagrees with local model replay",
                    case.id
                ),
            );
            ok = false;
        }
    }
    if observed_cases != case_ids {
        refusal(
            refusals,
            ProfileRefusalKind::InexactCoverage,
            claim_ref,
            "observations do not cover exactly the declared case set",
        );
        ok = false;
    }

    match claim.property {
        Property::ModelClear => {
            let violations: Vec<&str> = evidence
                .cases
                .iter()
                .filter(|case| case.model_violation.is_some())
                .map(|case| case.id.as_str())
                .collect();
            let conclusion = violations.is_empty();
            let detail = if conclusion {
                "no modeled violation in any enumerated case".to_owned()
            } else {
                format!("modeled conflicts in {violations:?}")
            };
            conclusions.insert(claim.id.clone(), (conclusion, detail, case_ids));
        }
        Property::ModelParity => {
            let non_adjudicable: Vec<&str> = evidence
                .cases
                .iter()
                .filter(|case| !case.adjudicable)
                .map(|case| case.id.as_str())
                .collect();
            if !non_adjudicable.is_empty() {
                refusal(
                    refusals,
                    ProfileRefusalKind::PropertySubstitution,
                    claim_ref,
                    format!(
                        "model_parity was requested over non-adjudicable cases {non_adjudicable:?}"
                    ),
                );
                return false;
            }
            let mismatches: Vec<&str> = evidence
                .cases
                .iter()
                .filter(|case| case.model_replay_outcome != case.stipulated_oracle_outcome)
                .map(|case| case.id.as_str())
                .collect();
            let conclusion = mismatches.is_empty();
            let detail = if conclusion {
                "every adjudicable case agrees with the stipulated oracle".to_owned()
            } else {
                format!("parity mismatches in {mismatches:?}")
            };
            conclusions.insert(claim.id.clone(), (conclusion, detail, case_ids));
        }
        _ => {
            refusal(
                refusals,
                ProfileRefusalKind::PropertySubstitution,
                claim_ref,
                "enumeration may conclude only model_clear or model_parity",
            );
            ok = false;
        }
    }
    ok
}

fn validate_restriction_shape(
    claim: &ProfileClaim,
    claims_by_id: &BTreeMap<&str, &ProfileClaim>,
    refusals: &mut Vec<ProfileRefusal>,
) -> bool {
    let claim_ref = Some(claim.id.as_str());
    let mut ok = true;
    if claim.premises.len() == 1 {
        let premise = claim.premises[0].as_str();
        if premise == claim.id {
            refusal(
                refusals,
                ProfileRefusalKind::SelfDependentClaim,
                claim_ref,
                "restriction premise is the claim itself",
            );
            ok = false;
        }
        if let Some(premise_claim) = claims_by_id.get(premise) {
            if claim.property != premise_claim.property {
                refusal(
                    refusals,
                    ProfileRefusalKind::PropertySubstitution,
                    claim_ref,
                    "restriction target property differs from the premise property",
                );
                ok = false;
            }
        } else {
            refusal(
                refusals,
                ProfileRefusalKind::UnknownPremise,
                claim_ref,
                format!("restriction premise {premise:?} is not present"),
            );
            ok = false;
        }
    } else {
        refusal(
            refusals,
            ProfileRefusalKind::MalformedRule,
            claim_ref,
            "restriction requires exactly one premise",
        );
        ok = false;
    }
    if claim.target_cases.is_empty() {
        refusal(
            refusals,
            ProfileRefusalKind::MalformedRule,
            claim_ref,
            "restriction requires a non-empty target case set",
        );
        ok = false;
    }
    if claim.evidence.is_some() {
        refusal(
            refusals,
            ProfileRefusalKind::MalformedRule,
            claim_ref,
            "restriction must not carry new enumeration evidence",
        );
        ok = false;
    }
    if !matches!(claim.property, Property::ModelClear | Property::ModelParity) {
        refusal(
            refusals,
            ProfileRefusalKind::PropertySubstitution,
            claim_ref,
            "restriction may carry only a permitted finite model property",
        );
        ok = false;
    }
    ok
}

fn validate_conjunction_shape(
    claim: &ProfileClaim,
    claims_by_id: &BTreeMap<&str, &ProfileClaim>,
    refusals: &mut Vec<ProfileRefusal>,
) -> bool {
    let claim_ref = Some(claim.id.as_str());
    let mut ok = true;
    if claim.property != Property::ModelConjunction {
        refusal(
            refusals,
            ProfileRefusalKind::PropertySubstitution,
            claim_ref,
            "conjunction must conclude model_conjunction",
        );
        ok = false;
    }
    if claim.premises.len() != 2 {
        refusal(
            refusals,
            ProfileRefusalKind::MalformedRule,
            claim_ref,
            "conjunction requires exactly two premises",
        );
        ok = false;
    }
    if claim.premises.iter().any(|premise| premise == &claim.id) {
        refusal(
            refusals,
            ProfileRefusalKind::SelfDependentClaim,
            claim_ref,
            "conjunction references the claim itself",
        );
        ok = false;
    }
    if claim.premises.len() == 2 && claim.premises[0] == claim.premises[1] {
        refusal(
            refusals,
            ProfileRefusalKind::DuplicateIdentifier,
            claim_ref,
            "conjunction repeats the same premise",
        );
        ok = false;
    }
    for premise in &claim.premises {
        if let Some(premise_claim) = claims_by_id.get(premise.as_str()) {
            if !matches!(
                premise_claim.property,
                Property::ModelClear | Property::ModelParity
            ) {
                refusal(
                    refusals,
                    ProfileRefusalKind::PropertySubstitution,
                    claim_ref,
                    format!(
                        "conjunction premise {:?} has property {}",
                        premise, premise_claim.property
                    ),
                );
                ok = false;
            }
        } else {
            refusal(
                refusals,
                ProfileRefusalKind::UnknownPremise,
                claim_ref,
                format!("conjunction premise {premise:?} is not present"),
            );
            ok = false;
        }
    }
    if claim.evidence.is_some() || !claim.target_cases.is_empty() {
        refusal(
            refusals,
            ProfileRefusalKind::MalformedRule,
            claim_ref,
            "conjunction must not carry evidence or a target case set",
        );
        ok = false;
    }
    ok
}

fn detect_self_dependence(
    claims_by_id: &BTreeMap<&str, &ProfileClaim>,
    static_ok: &mut BTreeMap<String, bool>,
    refusals: &mut Vec<ProfileRefusal>,
) {
    for id in claims_by_id.keys() {
        let mut stack: Vec<&str> = claims_by_id[*id]
            .premises
            .iter()
            .map(String::as_str)
            .collect();
        let mut visited = HashSet::new();
        let mut depends_on_self = false;
        while let Some(node) = stack.pop() {
            if node == *id {
                depends_on_self = true;
                break;
            }
            if !visited.insert(node) {
                continue;
            }
            if let Some(claim) = claims_by_id.get(node) {
                stack.extend(claim.premises.iter().map(String::as_str));
            }
        }
        if depends_on_self {
            refusal(
                refusals,
                ProfileRefusalKind::SelfDependentClaim,
                Some(id),
                "claim depends on itself through its premise graph",
            );
            static_ok.insert((*id).to_owned(), false);
        }
    }
}

/// Return the properties requested by the fixture claims for a variant.
#[must_use]
pub fn buffer_variant_claim_properties(variant: BufferVariant) -> Vec<Property> {
    let prefix = case_prefix(variant);
    local_buffer_bundle()
        .claims
        .into_iter()
        .filter(|claim| claim.id.starts_with(prefix))
        .map(|claim| claim.property)
        .collect()
}

/// Render a profile bundle in canonical bytes.
///
/// # Errors
///
/// Returns an error if the bundle cannot be serialized into the restricted
/// canonical grammar.
pub fn canonical_bundle_bytes(bundle: &ProfileBundle) -> Result<Vec<u8>, IdentityError> {
    let value =
        serde_json::to_value(bundle).map_err(|error| IdentityError::Json(error.to_string()))?;
    canonical_bytes(&value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_has_24_records_and_expected_counts() {
        let records = local_buffer_records();
        assert_eq!(records.len(), BUFFER_RECORD_COUNT);
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
                BufferVariant::C0 => {
                    assert_eq!((adjudicable, conflicts, mismatches), (6, 2, 0));
                }
                BufferVariant::C1 => {
                    assert_eq!((adjudicable, conflicts, mismatches), (8, 0, 0));
                }
                BufferVariant::C2 => {
                    assert_eq!((adjudicable, conflicts, mismatches), (8, 0, 4));
                }
            }
        }
    }

    #[test]
    fn fixture_evaluates_to_expected_dispositions() {
        let evaluation = evaluate_profile(&local_buffer_bundle());
        assert_eq!(evaluation.refusals.len(), 3);
        assert!(evaluation
            .refusals
            .iter()
            .all(|refusal| refusal.kind == ProfileRefusalKind::UniversalOrNativeClaim));
        assert_eq!(evaluation.universal_soundness, UNIVERSAL_SOUNDNESS);
        assert!(!evaluation
            .established
            .iter()
            .any(|claim| claim.ends_with("-universal")));
        for variant in ["c0", "c1", "c2"] {
            assert_eq!(
                evaluation.claims[&format!("{variant}-clear")].disposition,
                match variant {
                    "c0" => ClaimDisposition::NotEstablished,
                    _ => ClaimDisposition::Established,
                }
            );
            assert_eq!(
                evaluation.claims[&format!("{variant}-parity")].disposition,
                match variant {
                    "c2" => ClaimDisposition::NotEstablished,
                    _ => ClaimDisposition::Established,
                }
            );
            assert_eq!(
                evaluation.claims[&format!("{variant}-restriction")].disposition,
                match variant {
                    "c0" => ClaimDisposition::NotEstablished,
                    _ => ClaimDisposition::Established,
                }
            );
            assert_eq!(
                evaluation.claims[&format!("{variant}-conjunction")].disposition,
                match variant {
                    "c1" => ClaimDisposition::Established,
                    _ => ClaimDisposition::NotEstablished,
                }
            );
            assert_eq!(
                evaluation.claims[&format!("{variant}-universal")].disposition,
                ClaimDisposition::Withheld
            );
        }
    }

    #[test]
    fn five_claims_per_variant() {
        let claims = local_buffer_claims(&buffer_model_policy());
        assert_eq!(claims.len(), 3 * CLAIMS_PER_VARIANT);
        for variant in ["c0", "c1", "c2"] {
            assert_eq!(
                claims
                    .iter()
                    .filter(|claim| claim.id.starts_with(variant))
                    .count(),
                CLAIMS_PER_VARIANT
            );
        }
    }
}
