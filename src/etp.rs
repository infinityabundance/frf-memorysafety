#![allow(clippy::module_name_repetitions)]

//! FRF Earned Trust Protocol (ETP) claim integrity.
//!
//! This module implements the Phase 10.1 constitution for a general-purpose,
//! additive assurance methodology. It validates a versioned claim algebra in
//! which twenty coordinates identify a claim and ten dimensions record distinct
//! status facts. It deliberately provides **no** single confidence score and no
//! accepting derivation for a stronger property than the existing 1.0.0
//! evidence supports.
//!
//! # Claim ceiling
//!
//! A successful validation establishes only that a supplied manifest is
//! structurally complete, versioned, internally consistent, and does not
//! promote an unresolved premise or erase a retained contradictory native
//! observation. It does **not** establish that the claim is true, that the
//! evidence is authentic, that a reviewer is independent, that a transparency
//! log contains the evidence, or that a deployment is secure. External evidence
//! layers confer no semantic proof credit.
//!
//! The validator refuses universal quantification, `sound_safe_interior`,
//! `safe_compatible`, unresolvable premises offered for release, and positive
//! outcomes that contradict a retained native observation. Unknown required
//! coordinates, dimensions, schemas, or scalar score fields are integrity
//! errors, never warnings.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::identity::{canonical_bytes, parse_strict, IdentityError};

/// Protocol specification identifier for the ETP schemas in this module.
pub const ETP_SPEC: &str = "frf-etp-v1";
/// Manifest schema identifier.
pub const ETP_MANIFEST_SCHEMA: &str = "frf-etp.manifest.v1";
/// Generalized claim schema identifier.
pub const ETP_CLAIM_SCHEMA: &str = "frf-etp.claim.v1";
/// Obligation-inventory schema identifier.
pub const ETP_OBLIGATION_SCHEMA: &str = "frf-etp.obligation-inventory.v1";
/// Status-dimensions schema identifier.
pub const ETP_STATUS_SCHEMA: &str = "frf-etp.status-dimensions.v1";
/// Validation-report schema identifier.
pub const ETP_REPORT_SCHEMA: &str = "frf-etp.validation-report.v1";
/// Frozen release named by every `frf-etp.manifest.v1` baseline.
pub const FROZEN_RELEASE: &str = "1.0.0";
/// Frozen 1.0.0 commit recorded by this subphase.
pub const FROZEN_COMMIT: &str = "02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab";
/// Frozen aggregate of the 1.0.0 evidence artifacts.
pub const FROZEN_EVIDENCE_ROOT_SHA256: &str =
    "508b495b56b28cb9d674094f21dd89153b28905d61fdf9ac227ea3ff1eac6d74";

/// Claim ceiling embedded in every validation report.
pub const ETP_CLAIM_CEILING: &str = "ETP validation is bookkeeping over declared coordinates and separate status dimensions. It does not establish truth, authenticity, independence, transparency inclusion, deployment security, memory safety, functional correctness, interoperability, or constant-time behaviour. Universal quantification, sound_safe_interior, and safe_compatible have no accepting rule in this subphase. A digest is not authentication, a signature is not truth, and a passing validator is not certification.";

/// Number of required claim coordinates.
pub const COORDINATE_COUNT: usize = 20;
/// Number of required status dimensions (excluding the schema and spec fields).
pub const DIMENSION_COUNT: usize = 10;
/// Maximum claims in one manifest.
pub const MAX_CLAIMS: usize = 256;
/// Maximum obligations in one inventory.
pub const MAX_OBLIGATIONS: usize = 1024;
/// Maximum assumptions in one claim.
pub const MAX_ASSUMPTIONS: usize = 128;
/// Maximum supporting or contradictory evidence entries in one claim.
pub const MAX_EVIDENCE: usize = 1024;
/// Maximum invalidation dependencies in one claim.
pub const MAX_INVALIDATION_DEPENDENCIES: usize = 256;
/// Maximum bytes in one textual coordinate or identifier.
pub const MAX_TEXT_BYTES: usize = 4096;

/// Property vocabulary. Adding a variant requires a new schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtpProperty {
    /// No modeled violation in a declared finite domain.
    ModelClear,
    /// Agreement with a stipulated finite observation oracle.
    ModelParity,
    /// Behavioral compatibility under a named court.
    BinaryCompatible,
    /// Functional compatibility under a named workload.
    FunctionallyCompatible,
    /// A property of an artifact's build reproducibility.
    ReproducibleBuild,
    /// Integrity of a claim, obligation, or adjudication record.
    ClaimIntegrity,
    /// Conformance of a declared engineering process.
    ProcessConformance,
    /// Interoperability of a named consumer with a named artifact.
    Interoperability,
    /// Memory safety under an explicit finite or bounded scope.
    MemorySafety,
    /// Constant-time behaviour under a named leakage model.
    ConstantTime,
    /// Cryptographic correctness under a named algorithm specification.
    CryptographicCorrectness,
    /// Deployment-scoped security under an explicit threat model.
    DeploymentSecurity,
    /// Contextual safe-interior soundness. No accepting rule exists here.
    SoundSafeInterior,
    /// Composite compatibility plus safe-interior soundness. No accepting rule.
    SafeCompatible,
}

impl EtpProperty {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModelClear => "model_clear",
            Self::ModelParity => "model_parity",
            Self::BinaryCompatible => "binary_compatible",
            Self::FunctionallyCompatible => "functionally_compatible",
            Self::ReproducibleBuild => "reproducible_build",
            Self::ClaimIntegrity => "claim_integrity",
            Self::ProcessConformance => "process_conformance",
            Self::Interoperability => "interoperability",
            Self::MemorySafety => "memory_safety",
            Self::ConstantTime => "constant_time",
            Self::CryptographicCorrectness => "cryptographic_correctness",
            Self::DeploymentSecurity => "deployment_security",
            Self::SoundSafeInterior => "sound_safe_interior",
            Self::SafeCompatible => "safe_compatible",
        }
    }

    /// Whether this property has no accepting rule in the 1.0.0 ceiling.
    #[must_use]
    pub const fn is_forbidden_strong_property(self) -> bool {
        matches!(self, Self::SoundSafeInterior | Self::SafeCompatible)
    }
}

/// Quantification of a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Quantification {
    /// A single concrete observation.
    FiniteObservation,
    /// Exhaustive enumeration of a declared finite case set.
    FiniteModelExhaustion,
    /// A bounded model-checking or analysis run.
    BoundedModel,
    /// A universal contextual argument. Refused in this subphase.
    UniversalContextual,
    /// A restriction to a declared deployment scope.
    DeploymentRestricted,
}

impl Quantification {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FiniteObservation => "finite_observation",
            Self::FiniteModelExhaustion => "finite_model_exhaustion",
            Self::BoundedModel => "bounded_model",
            Self::UniversalContextual => "universal_contextual",
            Self::DeploymentRestricted => "deployment_restricted",
        }
    }

    /// Whether this quantifier is universal.
    #[must_use]
    pub const fn is_universal(self) -> bool {
        matches!(self, Self::UniversalContextual)
    }
}

/// Legal domain to which a claim applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalDomain {
    /// A finite observation domain.
    FiniteObservation,
    /// A finite enumeration domain.
    FiniteModelExhaustion,
    /// A bounded model domain.
    BoundedModel,
    /// A universal contextual domain.
    UniversalContextual,
    /// A declared deployment-restricted domain.
    DeploymentRestricted,
}

impl LegalDomain {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FiniteObservation => "finite_observation",
            Self::FiniteModelExhaustion => "finite_model_exhaustion",
            Self::BoundedModel => "bounded_model",
            Self::UniversalContextual => "universal_contextual",
            Self::DeploymentRestricted => "deployment_restricted",
        }
    }

    /// Whether this legal domain is universal.
    #[must_use]
    pub const fn is_universal(self) -> bool {
        matches!(self, Self::UniversalContextual)
    }
}

/// Epistemic status: a kind of statement, not a point on a ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpistemicStatus {
    /// Required by the protocol but not otherwise established.
    Specified,
    /// Described by a model without execution.
    Modeled,
    /// A finite model or event stream was executed.
    ExecutedModel,
    /// Native code was executed.
    ExecutedNative,
    /// A proof checker accepted a proof under stated assumptions.
    CheckedProof,
    /// An argument was reviewed by a reviewer.
    ReviewedArgument,
    /// The check was not executed.
    NotRun,
    /// The check is unsupported by the build.
    Unsupported,
    /// The status is unknown.
    Unknown,
    /// A challenge withholds the claim.
    Challenged,
    /// The evidence is invalid.
    InvalidEvidence,
}

impl EpistemicStatus {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Specified => "specified",
            Self::Modeled => "modeled",
            Self::ExecutedModel => "executed_model",
            Self::ExecutedNative => "executed_native",
            Self::CheckedProof => "checked_proof",
            Self::ReviewedArgument => "reviewed_argument",
            Self::NotRun => "not_run",
            Self::Unsupported => "unsupported",
            Self::Unknown => "unknown",
            Self::Challenged => "challenged",
            Self::InvalidEvidence => "invalid_evidence",
        }
    }
}

/// How an observation or evidence object was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionModality {
    /// Authentic native execution.
    AuthenticNative,
    /// Native execution with instrumentation loaded.
    NativeInstrumented,
    /// Execution against a mock provider.
    MockProvider,
    /// Execution with a substituted FFI implementation.
    SubstitutedFfi,
    /// A finite model or event replay.
    FiniteEventModel,
    /// Execution is unavailable.
    Unsupported,
    /// Execution is not applicable to this claim.
    NotApplicable,
}

impl ExecutionModality {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticNative => "authentic_native",
            Self::NativeInstrumented => "native_instrumented",
            Self::MockProvider => "mock_provider",
            Self::SubstitutedFfi => "substituted_ffi",
            Self::FiniteEventModel => "finite_event_model",
            Self::Unsupported => "unsupported",
            Self::NotApplicable => "not_applicable",
        }
    }

    /// Whether this modality is a native execution.
    #[must_use]
    pub const fn is_native(self) -> bool {
        matches!(self, Self::AuthenticNative | Self::NativeInstrumented)
    }
}

/// Verification outcome of a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcome {
    /// Not executed.
    NotRun,
    /// Executed without a decisive result.
    Inconclusive,
    /// Supported within a finite scope.
    SupportedFinite,
    /// Proved within a declared scope and assumptions.
    ProvedWithinScope,
    /// Refuted by an observation or counterexample.
    Refuted,
    /// Withheld by a challenge.
    Challenged,
    /// Evidence is invalid.
    InvalidEvidence,
}

impl VerificationOutcome {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRun => "not_run",
            Self::Inconclusive => "inconclusive",
            Self::SupportedFinite => "supported_finite",
            Self::ProvedWithinScope => "proved_within_scope",
            Self::Refuted => "refuted",
            Self::Challenged => "challenged",
            Self::InvalidEvidence => "invalid_evidence",
        }
    }

    /// Whether this outcome is positive.
    #[must_use]
    pub const fn is_positive(self) -> bool {
        matches!(self, Self::SupportedFinite | Self::ProvedWithinScope)
    }
}

/// Validity of the evidence supporting a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceValidity {
    /// Evidence is current and internally consistent.
    Valid,
    /// Evidence is stale.
    Stale,
    /// A digest does not match.
    DigestMismatch,
    /// Evidence is unverified.
    Unverified,
    /// Evidence is invalid.
    Invalid,
    /// Evidence validity is unknown.
    Unknown,
}

impl EvidenceValidity {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Stale => "stale",
            Self::DigestMismatch => "digest_mismatch",
            Self::Unverified => "unverified",
            Self::Invalid => "invalid",
            Self::Unknown => "unknown",
        }
    }

    /// Whether the evidence is valid.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// Reproduction status of a claim or experiment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReproductionStatus {
    /// Reproduction was not attempted.
    NotAttempted,
    /// Reproduction succeeded.
    Reproduced,
    /// Reproduction failed.
    NotReproduced,
    /// Reproduction was unavailable.
    Unavailable,
    /// Reproduction status is unknown.
    Unknown,
}

impl ReproductionStatus {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAttempted => "not_attempted",
            Self::Reproduced => "reproduced",
            Self::NotReproduced => "not_reproduced",
            Self::Unavailable => "unavailable",
            Self::Unknown => "unknown",
        }
    }
}

/// Independence of the reviewer relative to the producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerIndependence {
    /// No review was recorded.
    None,
    /// The author reviewed the claim.
    Author,
    /// An independent reviewer is declared but not verified.
    IndependentDeclared,
    /// Independence was independently verified.
    IndependentlyVerified,
    /// Independence is unknown.
    Unknown,
}

impl ReviewerIndependence {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Author => "author",
            Self::IndependentDeclared => "independent_declared",
            Self::IndependentlyVerified => "independently_verified",
            Self::Unknown => "unknown",
        }
    }
}

/// Freshness of the evidence or claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    /// Current.
    Current,
    /// Stale.
    Stale,
    /// Expired.
    Expired,
    /// Freshness is not applicable.
    NotApplicable,
    /// Freshness is unknown.
    Unknown,
}

impl Freshness {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Stale => "stale",
            Self::Expired => "expired",
            Self::NotApplicable => "not_applicable",
            Self::Unknown => "unknown",
        }
    }

    /// Whether freshness permits release.
    #[must_use]
    pub const fn permits_release(self) -> bool {
        matches!(self, Self::Current | Self::NotApplicable)
    }
}

/// Transparency-log status. Inclusion is not completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparencyStatus {
    /// Not included in a transparency log.
    NotIncluded,
    /// Included in a transparency log.
    Included,
    /// Inclusion is consistent with the public record.
    Consistent,
    /// Inclusion is inconsistent with the public record.
    Inconsistent,
    /// Not applicable.
    NotApplicable,
    /// Status is unknown.
    Unknown,
}

impl TransparencyStatus {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotIncluded => "not_included",
            Self::Included => "included",
            Self::Consistent => "consistent",
            Self::Inconsistent => "inconsistent",
            Self::NotApplicable => "not_applicable",
            Self::Unknown => "unknown",
        }
    }

    /// Whether the transparency record contradicts release.
    #[must_use]
    pub const fn blocks_release(self) -> bool {
        matches!(self, Self::Inconsistent)
    }
}

/// Release eligibility. This is a status dimension, not a score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseEligibility {
    /// The producer requests release eligibility.
    Eligible,
    /// Release is withheld.
    Withheld,
    /// Release is blocked.
    Blocked,
    /// Release eligibility is not applicable.
    NotApplicable,
}

impl ReleaseEligibility {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::Withheld => "withheld",
            Self::Blocked => "blocked",
            Self::NotApplicable => "not_applicable",
        }
    }

    /// Whether the claim requests release eligibility.
    #[must_use]
    pub const fn is_eligible(self) -> bool {
        matches!(self, Self::Eligible)
    }
}

/// State of a declared assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssumptionState {
    /// Discharged by evidence.
    Discharged,
    /// Declared but not discharged.
    Declared,
    /// Unknown.
    Unknown,
    /// Refuted.
    Refuted,
    /// Inapplicable with evidence.
    NotApplicableWithEvidence,
}

impl AssumptionState {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discharged => "discharged",
            Self::Declared => "declared",
            Self::Unknown => "unknown",
            Self::Refuted => "refuted",
            Self::NotApplicableWithEvidence => "not_applicable_with_evidence",
        }
    }

    /// Whether this premise is resolved for promotion purposes.
    #[must_use]
    pub const fn is_resolved(self) -> bool {
        matches!(self, Self::Discharged | Self::NotApplicableWithEvidence)
    }
}

/// Lifecycle state of an obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationState {
    /// Unknown.
    Unknown,
    /// Contracted but not established.
    Contracted,
    /// Established but not independently checked.
    Established,
    /// Independently checked but not discharged.
    IndependentlyChecked,
    /// Discharged.
    Discharged,
    /// Blocked.
    Blocked,
    /// Stale.
    Stale,
    /// Inapplicable with evidence.
    InapplicableWithEvidence,
    /// Reopened.
    Reopened,
}

impl ObligationState {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Contracted => "contracted",
            Self::Established => "established",
            Self::IndependentlyChecked => "independently_checked",
            Self::Discharged => "discharged",
            Self::Blocked => "blocked",
            Self::Stale => "stale",
            Self::InapplicableWithEvidence => "inapplicable_with_evidence",
            Self::Reopened => "reopened",
        }
    }

    /// Whether this obligation is resolved for promotion purposes.
    #[must_use]
    pub const fn is_resolved(self) -> bool {
        matches!(self, Self::Discharged | Self::InapplicableWithEvidence)
    }
}

/// Kind of supporting evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// A digest-bound artifact.
    DigestBoundArtifact,
    /// An executed receipt.
    ExecutedReceipt,
    /// A proof object.
    ProofObject,
    /// An observation record.
    ObservationRecord,
    /// A review record.
    ReviewRecord,
    /// An external provider object.
    ExternalProviderObject,
    /// A policy document.
    PolicyDocument,
}

impl EvidenceKind {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DigestBoundArtifact => "digest_bound_artifact",
            Self::ExecutedReceipt => "executed_receipt",
            Self::ProofObject => "proof_object",
            Self::ObservationRecord => "observation_record",
            Self::ReviewRecord => "review_record",
            Self::ExternalProviderObject => "external_provider_object",
            Self::PolicyDocument => "policy_document",
        }
    }
}

/// Class of contradictory evidence. All classes are retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContradictionClass {
    /// A native observation.
    NativeObservation,
    /// A model observation.
    ModelObservation,
    /// A proof counterexample.
    ProofCounterexample,
    /// A review finding.
    ReviewFinding,
    /// An external observation.
    ExternalObservation,
}

impl ContradictionClass {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeObservation => "native_observation",
            Self::ModelObservation => "model_observation",
            Self::ProofCounterexample => "proof_counterexample",
            Self::ReviewFinding => "review_finding",
            Self::ExternalObservation => "external_observation",
        }
    }

    /// Whether a positive outcome must account for this contradiction.
    #[must_use]
    pub const fn is_decisive(self) -> bool {
        matches!(self, Self::NativeObservation | Self::ProofCounterexample)
    }
}

/// Resolution state of contradictory evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionState {
    /// Unresolved.
    Unresolved,
    /// Explained but not superseded.
    Explained,
    /// Resolved by new evidence.
    ResolvedByNewEvidence,
}

impl ResolutionState {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unresolved => "unresolved",
            Self::Explained => "explained",
            Self::ResolvedByNewEvidence => "resolved_by_new_evidence",
        }
    }

    /// Whether new evidence superseded the contradiction.
    #[must_use]
    pub const fn is_resolved(self) -> bool {
        matches!(self, Self::ResolvedByNewEvidence)
    }
}

/// Overall status of a validation report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtpValidationStatus {
    /// The manifest is valid and makes no refused promotion.
    Valid,
    /// The manifest is structurally valid but refuses one or more promotions.
    Refused,
}

/// Stable refusal codes produced by semantic validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtpRefusalCode {
    /// A property outside the current claim ceiling was requested.
    ForbiddenStrongProperty,
    /// Universal quantification has no accepting rule in this subphase.
    UniversalQuantification,
    /// A positive proof or finite result contradicts a retained native observation.
    ContradictoryNativeObservation,
    /// A contradictory observation was dropped instead of retained.
    ContradictionNotRetained,
    /// Release was requested while a required premise is unresolved.
    UnknownPremisePromotion,
    /// Release was requested while a blocking obligation is unresolved.
    BlockingObligationPromotion,
    /// Release was requested with non-positive or invalid evidence.
    IneligibleEvidence,
    /// The coordinate and status-dimension quantifiers disagree.
    DimensionMismatch,
    /// The epistemic status and execution modality disagree.
    ModalityMismatch,
    /// Stale or expired evidence was offered for release.
    StaleEvidence,
    /// An inconsistent transparency record was offered for release.
    InconsistentTransparency,
}

impl EtpRefusalCode {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ForbiddenStrongProperty => "forbidden_strong_property",
            Self::UniversalQuantification => "universal_quantification",
            Self::ContradictoryNativeObservation => "contradictory_native_observation",
            Self::ContradictionNotRetained => "contradiction_not_retained",
            Self::UnknownPremisePromotion => "unknown_premise_promotion",
            Self::BlockingObligationPromotion => "blocking_obligation_promotion",
            Self::IneligibleEvidence => "ineligible_evidence",
            Self::DimensionMismatch => "dimension_mismatch",
            Self::ModalityMismatch => "modality_mismatch",
            Self::StaleEvidence => "stale_evidence",
            Self::InconsistentTransparency => "inconsistent_transparency",
        }
    }
}

/// Frozen baseline reference. Every `v1` manifest names the 1.0.0 freeze.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineReference {
    /// Frozen release.
    pub release: String,
    /// Frozen full commit hash.
    pub commit: String,
    /// Frozen evidence-root digest.
    pub evidence_root_sha256: String,
}

/// One declared assumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtpAssumption {
    /// Stable identifier within the claim.
    pub id: String,
    /// Exact assumption statement.
    pub statement: String,
    /// Current assumption state.
    pub state: AssumptionState,
}

/// One obligation in the inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtpObligation {
    /// Stable identifier within the inventory.
    pub id: String,
    /// Exact obligation statement.
    pub statement: String,
    /// Current lifecycle state.
    pub state: ObligationState,
    /// Whether an unresolved state blocks promotion.
    pub blocking: bool,
    /// Supporting evidence identifiers.
    pub evidence: Vec<String>,
}

/// Versioned obligation inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObligationInventory {
    /// Inventory schema identifier.
    pub schema: String,
    /// Protocol specification identifier.
    pub spec: String,
    /// Declared obligations.
    pub obligations: Vec<EtpObligation>,
}

/// One supporting evidence reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportingEvidence {
    /// Stable identifier within the claim.
    pub id: String,
    /// Evidence kind.
    pub kind: EvidenceKind,
    /// Digest or opaque external identity. A digest is not authentication.
    pub digest: String,
    /// Location or provider reference.
    pub location: String,
}

/// One contradictory observation. Contradictions are retained, never erased.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContradictoryEvidence {
    /// Stable identifier within the claim.
    pub id: String,
    /// Class of contradiction.
    pub class: ContradictionClass,
    /// Exact contradictory statement.
    pub statement: String,
    /// Source of the contradiction.
    pub source: String,
    /// Whether the observation is retained. Must be `true`.
    pub retained: bool,
    /// Resolution state.
    pub resolution: ResolutionState,
}

/// The ten separately assessed status dimensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusDimensions {
    /// Dimensions schema identifier.
    pub schema: String,
    /// Protocol specification identifier.
    pub spec: String,
    /// Epistemic status (dimension 1).
    pub epistemic_status: EpistemicStatus,
    /// Execution modality (dimension 2).
    pub execution_modality: ExecutionModality,
    /// Quantification (dimension 3).
    pub quantification: Quantification,
    /// Verification outcome (dimension 4).
    pub verification_outcome: VerificationOutcome,
    /// Evidence validity (dimension 5).
    pub evidence_validity: EvidenceValidity,
    /// Reproduction status (dimension 6).
    pub reproduction_status: ReproductionStatus,
    /// Reviewer independence (dimension 7).
    pub reviewer_independence: ReviewerIndependence,
    /// Freshness (dimension 8).
    pub freshness: Freshness,
    /// Transparency status (dimension 9).
    pub transparency_status: TransparencyStatus,
    /// Release eligibility (dimension 10).
    pub release_eligibility: ReleaseEligibility,
}

impl StatusDimensions {
    /// The ten dimension names, in schema order.
    #[must_use]
    pub const fn names() -> [&'static str; DIMENSION_COUNT] {
        [
            "epistemic_status",
            "execution_modality",
            "quantification",
            "verification_outcome",
            "evidence_validity",
            "reproduction_status",
            "reviewer_independence",
            "freshness",
            "transparency_status",
            "release_eligibility",
        ]
    }
}

/// One generalized claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtpClaim {
    /// Claim schema identifier.
    pub schema: String,
    /// Protocol specification identifier.
    pub spec: String,
    /// Stable claim identifier.
    pub id: String,
    /// Property coordinate.
    pub property: EtpProperty,
    /// Interpretation coordinate: what the property means operationally.
    pub interpretation: String,
    /// Quantification coordinate.
    pub quantification: Quantification,
    /// Legal-domain coordinate.
    pub legal_domain: LegalDomain,
    /// Threat-model coordinate.
    pub threat_model: String,
    /// Leakage-model coordinate.
    pub leakage_model: String,
    /// Subject-identity coordinate.
    pub subject_identity: String,
    /// Source-identity coordinate.
    pub source_identity: String,
    /// Build-identity coordinate.
    pub build_identity: String,
    /// Artifact-identity coordinate.
    pub artifact_identity: String,
    /// Runtime-environment coordinate.
    pub runtime_environment: String,
    /// Deployment-scope coordinate.
    pub deployment_scope: String,
    /// Semantic-model coordinate.
    pub semantic_model: String,
    /// Assumptions coordinate.
    pub assumptions: Vec<EtpAssumption>,
    /// Trusted-computing-base coordinate.
    pub trusted_computing_base: Vec<String>,
    /// Obligation references coordinate.
    pub obligations: Vec<String>,
    /// Supporting-evidence coordinate.
    pub supporting_evidence: Vec<SupportingEvidence>,
    /// Contradictory-evidence coordinate.
    pub contradictory_evidence: Vec<ContradictoryEvidence>,
    /// Policy-identity coordinate.
    pub policy_identity: String,
    /// Invalidation-dependencies coordinate.
    pub invalidation_dependencies: Vec<String>,
    /// Separately assessed status dimensions.
    pub status_dimensions: StatusDimensions,
}

/// A versioned ETP manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtpManifest {
    /// Manifest schema identifier.
    pub schema: String,
    /// Protocol specification identifier.
    pub spec: String,
    /// Frozen 1.0.0 baseline reference.
    pub baseline: BaselineReference,
    /// Obligation inventory.
    pub obligation_inventory: ObligationInventory,
    /// Generalized claims.
    pub claims: Vec<EtpClaim>,
}

/// One semantic refusal in a validation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtpRefusal {
    /// Claim identifier.
    pub claim_id: String,
    /// Stable refusal code.
    pub code: EtpRefusalCode,
    /// Exact human-readable detail.
    pub detail: String,
}

/// Canonical validation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EtpValidationReport {
    /// Report schema identifier.
    pub schema: String,
    /// Protocol specification identifier.
    pub spec: String,
    /// Overall status.
    pub status: EtpValidationStatus,
    /// Frozen baseline reference copied from the manifest.
    pub baseline: BaselineReference,
    /// Number of claims validated.
    pub claims: usize,
    /// Number of obligations in the inventory.
    pub obligations: usize,
    /// Number of required coordinates per claim.
    pub coordinates_per_claim: usize,
    /// Number of status dimensions per claim.
    pub dimensions_per_claim: usize,
    /// Claims that requested release eligibility and produced no refusal.
    pub eligible_claims: Vec<String>,
    /// Semantic refusals. Structural errors return an `Err` instead.
    pub refusals: Vec<EtpRefusal>,
    /// Claim ceiling embedded in the report.
    pub claim_ceiling: String,
}

impl EtpValidationReport {
    /// Encode this report as strict `ms-canonical-json-v1` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EtpError::Canonical`] if the report cannot be represented.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EtpError> {
        let value = serde_json::to_value(self).map_err(|error| EtpError::Canonical {
            message: error.to_string(),
        })?;
        canonical_bytes(&value).map_err(|error| EtpError::Canonical {
            message: error.to_string(),
        })
    }

    /// Exit status for this report: `0` valid, `4` refused.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self.status {
            EtpValidationStatus::Valid => 0,
            EtpValidationStatus::Refused => 4,
        }
    }
}

/// Errors produced while parsing or validating ETP documents.
#[derive(Debug, thiserror::Error)]
pub enum EtpError {
    /// Strict JSON parsing failed.
    #[error("invalid ETP JSON: {0}")]
    Identity(#[from] IdentityError),
    /// The typed document failed a structural rule.
    #[error("invalid ETP document: {message}")]
    Invalid {
        /// Rule that failed.
        message: String,
    },
    /// A schema or specification version is not the supported version.
    #[error("ETP schema mismatch for {field}: expected {expected}, found {actual}")]
    SchemaMismatch {
        /// Field or object name.
        field: String,
        /// Expected identifier.
        expected: String,
        /// Observed identifier.
        actual: String,
    },
    /// A report could not be encoded canonically.
    #[error("cannot encode ETP report: {message}")]
    Canonical {
        /// Encoder diagnostic.
        message: String,
    },
}

impl EtpError {
    /// Category used to choose a `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Identity(_) | Self::Invalid { .. } | Self::SchemaMismatch { .. } => 3,
            Self::Canonical { .. } => 7,
        }
    }
}

fn check_text(label: &str, value: &str) -> Result<(), EtpError> {
    if value.trim().is_empty() {
        return Err(EtpError::Invalid {
            message: format!("{label} must not be empty"),
        });
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(EtpError::Invalid {
            message: format!("{label} exceeds {MAX_TEXT_BYTES} bytes"),
        });
    }
    Ok(())
}

fn check_schema(field: &str, actual: &str, expected: &str) -> Result<(), EtpError> {
    if actual != expected {
        return Err(EtpError::SchemaMismatch {
            field: field.to_owned(),
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

fn check_baseline(baseline: &BaselineReference) -> Result<(), EtpError> {
    check_schema("baseline.release", &baseline.release, FROZEN_RELEASE)?;
    check_schema("baseline.commit", &baseline.commit, FROZEN_COMMIT)?;
    check_schema(
        "baseline.evidence_root_sha256",
        &baseline.evidence_root_sha256,
        FROZEN_EVIDENCE_ROOT_SHA256,
    )
}

fn check_unique_ids<'a>(
    label: &str,
    ids: impl Iterator<Item = &'a String>,
) -> Result<(), EtpError> {
    let mut seen = BTreeSet::new();
    for id in ids {
        check_text(label, id)?;
        if !seen.insert(id) {
            return Err(EtpError::Invalid {
                message: format!("duplicate {label}: {id}"),
            });
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn check_claim_structure(
    claim: &EtpClaim,
    inventory: &ObligationInventory,
) -> Result<(), EtpError> {
    check_schema("claim.schema", &claim.schema, ETP_CLAIM_SCHEMA)?;
    check_schema("claim.spec", &claim.spec, ETP_SPEC)?;
    check_text("claim.id", &claim.id)?;
    for (label, value) in [
        ("interpretation", &claim.interpretation),
        ("threat_model", &claim.threat_model),
        ("leakage_model", &claim.leakage_model),
        ("subject_identity", &claim.subject_identity),
        ("source_identity", &claim.source_identity),
        ("build_identity", &claim.build_identity),
        ("artifact_identity", &claim.artifact_identity),
        ("runtime_environment", &claim.runtime_environment),
        ("deployment_scope", &claim.deployment_scope),
        ("semantic_model", &claim.semantic_model),
        ("policy_identity", &claim.policy_identity),
    ] {
        check_text(label, value)?;
    }

    if claim.assumptions.len() > MAX_ASSUMPTIONS {
        return Err(EtpError::Invalid {
            message: format!("claim {} exceeds {MAX_ASSUMPTIONS} assumptions", claim.id),
        });
    }
    check_unique_ids(
        "assumption id",
        claim.assumptions.iter().map(|assumption| &assumption.id),
    )?;
    for assumption in &claim.assumptions {
        check_text("assumption statement", &assumption.statement)?;
    }

    if claim.trusted_computing_base.is_empty() {
        return Err(EtpError::Invalid {
            message: format!(
                "claim {} must declare at least one trusted-computing-base component",
                claim.id
            ),
        });
    }
    for component in &claim.trusted_computing_base {
        check_text("trusted_computing_base component", component)?;
    }

    if claim.obligations.len() > MAX_OBLIGATIONS {
        return Err(EtpError::Invalid {
            message: format!("claim {} references too many obligations", claim.id),
        });
    }
    check_unique_ids("obligation reference", claim.obligations.iter())?;
    let inventory_ids: BTreeSet<&String> = inventory
        .obligations
        .iter()
        .map(|obligation| &obligation.id)
        .collect();
    for reference in &claim.obligations {
        if !inventory_ids.contains(reference) {
            return Err(EtpError::Invalid {
                message: format!(
                    "claim {} references unknown obligation {reference}",
                    claim.id
                ),
            });
        }
    }

    if claim.supporting_evidence.len() > MAX_EVIDENCE
        || claim.contradictory_evidence.len() > MAX_EVIDENCE
    {
        return Err(EtpError::Invalid {
            message: format!("claim {} exceeds {MAX_EVIDENCE} evidence entries", claim.id),
        });
    }
    check_unique_ids(
        "supporting evidence id",
        claim
            .supporting_evidence
            .iter()
            .map(|evidence| &evidence.id),
    )?;
    for evidence in &claim.supporting_evidence {
        check_text("supporting evidence digest", &evidence.digest)?;
        check_text("supporting evidence location", &evidence.location)?;
    }
    check_unique_ids(
        "contradictory evidence id",
        claim
            .contradictory_evidence
            .iter()
            .map(|evidence| &evidence.id),
    )?;
    for evidence in &claim.contradictory_evidence {
        check_text("contradictory evidence statement", &evidence.statement)?;
        check_text("contradictory evidence source", &evidence.source)?;
    }

    if claim.invalidation_dependencies.len() > MAX_INVALIDATION_DEPENDENCIES {
        return Err(EtpError::Invalid {
            message: format!(
                "claim {} exceeds {MAX_INVALIDATION_DEPENDENCIES} invalidation dependencies",
                claim.id
            ),
        });
    }
    for dependency in &claim.invalidation_dependencies {
        check_text("invalidation dependency", dependency)?;
    }

    check_schema(
        "status_dimensions.schema",
        &claim.status_dimensions.schema,
        ETP_STATUS_SCHEMA,
    )?;
    check_schema(
        "status_dimensions.spec",
        &claim.status_dimensions.spec,
        ETP_SPEC,
    )?;

    Ok(())
}

fn refusal(claim_id: &str, code: EtpRefusalCode, detail: impl Into<String>) -> EtpRefusal {
    EtpRefusal {
        claim_id: claim_id.to_owned(),
        code,
        detail: detail.into(),
    }
}

#[allow(clippy::too_many_lines)]
fn check_claim_semantics(claim: &EtpClaim, inventory: &ObligationInventory) -> Vec<EtpRefusal> {
    let mut refusals = Vec::new();
    let dimensions = &claim.status_dimensions;
    let outcome = dimensions.verification_outcome;

    if claim.property.is_forbidden_strong_property() {
        refusals.push(refusal(
            &claim.id,
            EtpRefusalCode::ForbiddenStrongProperty,
            format!(
                "property {} has no accepting rule in this subphase",
                claim.property.as_str()
            ),
        ));
    }

    if claim.quantification.is_universal()
        || claim.legal_domain.is_universal()
        || dimensions.quantification.is_universal()
    {
        refusals.push(refusal(
            &claim.id,
            EtpRefusalCode::UniversalQuantification,
            "universal quantification has no accepting rule in this subphase",
        ));
    }

    if claim.quantification != dimensions.quantification {
        refusals.push(refusal(
            &claim.id,
            EtpRefusalCode::DimensionMismatch,
            format!(
                "claim quantifier {} disagrees with status dimension {}",
                claim.quantification.as_str(),
                dimensions.quantification.as_str()
            ),
        ));
    }

    match dimensions.epistemic_status {
        EpistemicStatus::ExecutedNative if !dimensions.execution_modality.is_native() => {
            refusals.push(refusal(
                &claim.id,
                EtpRefusalCode::ModalityMismatch,
                format!(
                    "executed_native requires a native modality, found {}",
                    dimensions.execution_modality.as_str()
                ),
            ));
        }
        EpistemicStatus::ExecutedModel
            if dimensions.execution_modality != ExecutionModality::FiniteEventModel =>
        {
            refusals.push(refusal(
                &claim.id,
                EtpRefusalCode::ModalityMismatch,
                format!(
                    "executed_model requires finite_event_model, found {}",
                    dimensions.execution_modality.as_str()
                ),
            ));
        }
        _ => {}
    }

    for contradiction in &claim.contradictory_evidence {
        if !contradiction.retained {
            refusals.push(refusal(
                &claim.id,
                EtpRefusalCode::ContradictionNotRetained,
                format!(
                    "contradictory evidence {} must be retained",
                    contradiction.id
                ),
            ));
        }
        if contradiction.class.is_decisive()
            && !contradiction.resolution.is_resolved()
            && outcome.is_positive()
        {
            refusals.push(refusal(
                &claim.id,
                EtpRefusalCode::ContradictoryNativeObservation,
                format!(
                    "positive outcome {} would erase retained {} {}",
                    outcome.as_str(),
                    contradiction.class.as_str(),
                    contradiction.id
                ),
            ));
        }
    }

    if outcome.is_positive() && !dimensions.evidence_validity.is_valid() {
        refusals.push(refusal(
            &claim.id,
            EtpRefusalCode::IneligibleEvidence,
            format!(
                "positive outcome {} requires valid evidence, found {}",
                outcome.as_str(),
                dimensions.evidence_validity.as_str()
            ),
        ));
    }

    if dimensions.release_eligibility.is_eligible() {
        if !outcome.is_positive() {
            refusals.push(refusal(
                &claim.id,
                EtpRefusalCode::IneligibleEvidence,
                format!(
                    "release eligibility requires a positive outcome, found {}",
                    outcome.as_str()
                ),
            ));
        }
        for assumption in &claim.assumptions {
            if !assumption.state.is_resolved() {
                refusals.push(refusal(
                    &claim.id,
                    EtpRefusalCode::UnknownPremisePromotion,
                    format!(
                        "assumption {} is {} and blocks release",
                        assumption.id,
                        assumption.state.as_str()
                    ),
                ));
            }
        }
        for obligation in &inventory.obligations {
            if claim.obligations.contains(&obligation.id)
                && obligation.blocking
                && !obligation.state.is_resolved()
            {
                refusals.push(refusal(
                    &claim.id,
                    EtpRefusalCode::BlockingObligationPromotion,
                    format!(
                        "blocking obligation {} is {} and blocks release",
                        obligation.id,
                        obligation.state.as_str()
                    ),
                ));
            }
        }
        if !dimensions.freshness.permits_release() {
            refusals.push(refusal(
                &claim.id,
                EtpRefusalCode::StaleEvidence,
                format!("freshness {} blocks release", dimensions.freshness.as_str()),
            ));
        }
        if dimensions.transparency_status.blocks_release() {
            refusals.push(refusal(
                &claim.id,
                EtpRefusalCode::InconsistentTransparency,
                "inconsistent transparency status blocks release",
            ));
        }
    }

    refusals
}

/// Parse a manifest with strict JSON rules.
///
/// # Errors
///
/// Returns [`EtpError`] for malformed JSON, unknown fields, a missing required
/// coordinate, a missing status dimension, or an unsupported schema version.
pub fn parse_manifest(bytes: &[u8]) -> Result<EtpManifest, EtpError> {
    let value = parse_strict(bytes)?;
    let manifest: EtpManifest =
        serde_json::from_value(value).map_err(|error| EtpError::Invalid {
            message: error.to_string(),
        })?;
    check_schema("manifest.schema", &manifest.schema, ETP_MANIFEST_SCHEMA)?;
    check_schema("manifest.spec", &manifest.spec, ETP_SPEC)?;
    Ok(manifest)
}

/// Parse a standalone generalized claim.
///
/// # Errors
///
/// Returns [`EtpError`] for malformed JSON, unknown fields, a missing
/// coordinate, or an unsupported schema version.
pub fn parse_claim(bytes: &[u8]) -> Result<EtpClaim, EtpError> {
    let value = parse_strict(bytes)?;
    let claim: EtpClaim = serde_json::from_value(value).map_err(|error| EtpError::Invalid {
        message: error.to_string(),
    })?;
    check_schema("claim.schema", &claim.schema, ETP_CLAIM_SCHEMA)?;
    check_schema("claim.spec", &claim.spec, ETP_SPEC)?;
    check_schema(
        "status_dimensions.schema",
        &claim.status_dimensions.schema,
        ETP_STATUS_SCHEMA,
    )?;
    Ok(claim)
}

/// Parse a standalone obligation inventory.
///
/// # Errors
///
/// Returns [`EtpError`] for malformed JSON, unknown fields, or an unsupported
/// schema version.
pub fn parse_inventory(bytes: &[u8]) -> Result<ObligationInventory, EtpError> {
    let value = parse_strict(bytes)?;
    let inventory: ObligationInventory =
        serde_json::from_value(value).map_err(|error| EtpError::Invalid {
            message: error.to_string(),
        })?;
    check_schema(
        "obligation_inventory.schema",
        &inventory.schema,
        ETP_OBLIGATION_SCHEMA,
    )?;
    check_schema("obligation_inventory.spec", &inventory.spec, ETP_SPEC)?;
    Ok(inventory)
}

/// Parse a standalone status-dimensions document.
///
/// # Errors
///
/// Returns [`EtpError`] for malformed JSON, unknown fields, a missing dimension,
/// or an unsupported schema version.
pub fn parse_dimensions(bytes: &[u8]) -> Result<StatusDimensions, EtpError> {
    let value = parse_strict(bytes)?;
    let dimensions: StatusDimensions =
        serde_json::from_value(value).map_err(|error| EtpError::Invalid {
            message: error.to_string(),
        })?;
    check_schema(
        "status_dimensions.schema",
        &dimensions.schema,
        ETP_STATUS_SCHEMA,
    )?;
    check_schema("status_dimensions.spec", &dimensions.spec, ETP_SPEC)?;
    Ok(dimensions)
}

/// Validate a parsed manifest.
///
/// Structural violations return an error. Semantic violations are accumulated
/// in a [`EtpValidationReport`] with status
/// [`EtpValidationStatus::Refused`], so a caller can inspect every refusal.
///
/// # Errors
///
/// Returns [`EtpError`] for a schema mismatch, a baseline mismatch, an empty or
/// oversized coordinate, a missing dimension, a duplicate identifier, an
/// unknown obligation reference, or an over-limit collection.
#[allow(clippy::too_many_lines)]
pub fn validate_manifest(manifest: &EtpManifest) -> Result<EtpValidationReport, EtpError> {
    check_schema("manifest.schema", &manifest.schema, ETP_MANIFEST_SCHEMA)?;
    check_schema("manifest.spec", &manifest.spec, ETP_SPEC)?;
    check_baseline(&manifest.baseline)?;

    if manifest.claims.len() > MAX_CLAIMS {
        return Err(EtpError::Invalid {
            message: format!("manifest exceeds {MAX_CLAIMS} claims"),
        });
    }
    if manifest.obligation_inventory.obligations.len() > MAX_OBLIGATIONS {
        return Err(EtpError::Invalid {
            message: format!("inventory exceeds {MAX_OBLIGATIONS} obligations"),
        });
    }
    check_schema(
        "obligation_inventory.schema",
        &manifest.obligation_inventory.schema,
        ETP_OBLIGATION_SCHEMA,
    )?;
    check_schema(
        "obligation_inventory.spec",
        &manifest.obligation_inventory.spec,
        ETP_SPEC,
    )?;
    check_unique_ids(
        "inventory obligation id",
        manifest
            .obligation_inventory
            .obligations
            .iter()
            .map(|obligation| &obligation.id),
    )?;
    for obligation in &manifest.obligation_inventory.obligations {
        check_text("obligation statement", &obligation.statement)?;
        for reference in &obligation.evidence {
            check_text("obligation evidence reference", reference)?;
        }
    }
    check_unique_ids("claim id", manifest.claims.iter().map(|claim| &claim.id))?;

    let mut refusals = Vec::new();
    let mut eligible_claims = Vec::new();
    for claim in &manifest.claims {
        check_claim_structure(claim, &manifest.obligation_inventory)?;
        let claim_refusals = check_claim_semantics(claim, &manifest.obligation_inventory);
        if claim_refusals.is_empty() && claim.status_dimensions.release_eligibility.is_eligible() {
            eligible_claims.push(claim.id.clone());
        }
        refusals.extend(claim_refusals);
    }

    let status = if refusals.is_empty() {
        EtpValidationStatus::Valid
    } else {
        EtpValidationStatus::Refused
    };

    Ok(EtpValidationReport {
        schema: ETP_REPORT_SCHEMA.to_owned(),
        spec: ETP_SPEC.to_owned(),
        status,
        baseline: manifest.baseline.clone(),
        claims: manifest.claims.len(),
        obligations: manifest.obligation_inventory.obligations.len(),
        coordinates_per_claim: COORDINATE_COUNT,
        dimensions_per_claim: DIMENSION_COUNT,
        eligible_claims,
        refusals,
        claim_ceiling: ETP_CLAIM_CEILING.to_owned(),
    })
}

/// Parse and validate a manifest from bytes.
///
/// # Errors
///
/// Returns [`EtpError`] for any parse, schema, baseline, or structural failure.
pub fn validate_manifest_bytes(bytes: &[u8]) -> Result<EtpValidationReport, EtpError> {
    let manifest = parse_manifest(bytes)?;
    validate_manifest(&manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn valid_manifest() -> Value {
        serde_json::from_str(include_str!("../schemas/etp/vectors/valid/manifest.json"))
            .expect("valid manifest vector")
    }

    fn validate(value: &Value) -> Result<EtpValidationReport, EtpError> {
        let bytes = serde_json::to_vec(value).expect("json");
        validate_manifest_bytes(&bytes)
    }

    fn claim_mut(value: &mut Value) -> &mut serde_json::Map<String, Value> {
        value["claims"][0].as_object_mut().expect("claim")
    }

    fn dimensions_mut(value: &mut Value) -> &mut serde_json::Map<String, Value> {
        value["claims"][0]["status_dimensions"]
            .as_object_mut()
            .expect("dimensions")
    }

    #[test]
    fn valid_manifest_is_accepted_with_separate_coordinates_and_dimensions() {
        let report = validate(&valid_manifest()).expect("valid");
        assert_eq!(report.status, EtpValidationStatus::Valid);
        assert_eq!(report.claims, 1);
        assert_eq!(report.obligations, 1);
        assert_eq!(report.coordinates_per_claim, COORDINATE_COUNT);
        assert_eq!(report.dimensions_per_claim, DIMENSION_COUNT);
        assert!(report.eligible_claims.is_empty());
        let dimensions = StatusDimensions::names();
        let value = serde_json::to_value(dimensions).expect("json");
        assert_eq!(value.as_array().map(Vec::len), Some(DIMENSION_COUNT));
    }

    #[test]
    fn missing_coordinate_is_rejected_as_integrity_error() {
        let mut value = valid_manifest();
        claim_mut(&mut value).remove("threat_model");
        let error = validate(&value).expect_err("missing coordinate");
        assert_eq!(error.exit_code(), 3);
    }

    #[test]
    fn missing_dimension_is_rejected_as_integrity_error() {
        let mut value = valid_manifest();
        dimensions_mut(&mut value).remove("reviewer_independence");
        let error = validate(&value).expect_err("missing dimension");
        assert_eq!(error.exit_code(), 3);
    }

    #[test]
    fn confidence_scalar_is_rejected() {
        let mut value = valid_manifest();
        claim_mut(&mut value).insert("confidence".to_owned(), json!(90));
        let error = validate(&value).expect_err("scalar score");
        assert_eq!(error.exit_code(), 3);

        let mut value = valid_manifest();
        dimensions_mut(&mut value).insert("assurance_level".to_owned(), json!("high"));
        let error = validate(&value).expect_err("scalar assurance level");
        assert_eq!(error.exit_code(), 3);
    }

    #[test]
    fn contradictory_native_observation_blocks_positive_proof() {
        let mut value = valid_manifest();
        claim_mut(&mut value).insert(
            "contradictory_evidence".to_owned(),
            json!([{
                "id": "CE-1",
                "class": "native_observation",
                "statement": "Native execution observed a conflicting event.",
                "source": "recorded transcript",
                "retained": true,
                "resolution": "unresolved"
            }]),
        );
        dimensions_mut(&mut value).insert(
            "verification_outcome".to_owned(),
            json!("proved_within_scope"),
        );
        let report = validate(&value).expect("structurally valid");
        assert!(report
            .refusals
            .iter()
            .any(|item| { item.code == EtpRefusalCode::ContradictoryNativeObservation }));
        assert_eq!(report.exit_code(), 4);
    }

    #[test]
    fn dropped_contradiction_is_refused() {
        let mut value = valid_manifest();
        claim_mut(&mut value).insert(
            "contradictory_evidence".to_owned(),
            json!([{
                "id": "CE-1",
                "class": "native_observation",
                "statement": "Native execution observed a conflicting event.",
                "source": "recorded transcript",
                "retained": false,
                "resolution": "unresolved"
            }]),
        );
        let report = validate(&value).expect("structurally valid");
        assert!(report
            .refusals
            .iter()
            .any(|item| item.code == EtpRefusalCode::ContradictionNotRetained));
    }

    #[test]
    fn unknown_required_premise_blocks_promotion_but_not_withheld_claims() {
        let mut value = valid_manifest();
        value["claims"][0]["assumptions"][0]["state"] = json!("unknown");
        value["claims"][0]["status_dimensions"]["release_eligibility"] = json!("eligible");
        let report = validate(&value).expect("structurally valid");
        assert!(report
            .refusals
            .iter()
            .any(|item| item.code == EtpRefusalCode::UnknownPremisePromotion));
        assert!(report.eligible_claims.is_empty());

        let mut withheld = valid_manifest();
        withheld["claims"][0]["assumptions"][0]["state"] = json!("unknown");
        let report = validate(&withheld).expect("withheld is valid");
        assert_eq!(report.status, EtpValidationStatus::Valid);
    }

    #[test]
    fn blocked_obligation_blocks_eligibility() {
        let mut value = valid_manifest();
        value["obligation_inventory"]["obligations"][0]["state"] = json!("blocked");
        value["claims"][0]["status_dimensions"]["release_eligibility"] = json!("eligible");
        let report = validate(&value).expect("structurally valid");
        assert!(report
            .refusals
            .iter()
            .any(|item| { item.code == EtpRefusalCode::BlockingObligationPromotion }));
    }

    #[test]
    fn universal_quantification_is_refused() {
        let mut value = valid_manifest();
        claim_mut(&mut value).insert("quantification".to_owned(), json!("universal_contextual"));
        claim_mut(&mut value).insert("legal_domain".to_owned(), json!("universal_contextual"));
        dimensions_mut(&mut value)
            .insert("quantification".to_owned(), json!("universal_contextual"));
        dimensions_mut(&mut value).insert(
            "verification_outcome".to_owned(),
            json!("proved_within_scope"),
        );
        let report = validate(&value).expect("structurally valid");
        assert!(report
            .refusals
            .iter()
            .any(|item| item.code == EtpRefusalCode::UniversalQuantification));
    }

    #[test]
    fn forbidden_strong_property_is_refused() {
        let mut value = valid_manifest();
        claim_mut(&mut value).insert("property".to_owned(), json!("safe_compatible"));
        let report = validate(&value).expect("structurally valid");
        assert!(report
            .refusals
            .iter()
            .any(|item| { item.code == EtpRefusalCode::ForbiddenStrongProperty }));
    }

    #[test]
    fn unsupported_schema_versions_are_rejected() {
        let mut value = valid_manifest();
        claim_mut(&mut value).insert("schema".to_owned(), json!("frf-etp.claim.v2"));
        let error = validate(&value).expect_err("claim schema");
        assert_eq!(error.exit_code(), 3);

        let mut value = valid_manifest();
        value["schema"] = json!("frf-etp.manifest.v2");
        let error = validate(&value).expect_err("manifest schema");
        assert_eq!(error.exit_code(), 3);
    }

    #[test]
    fn frozen_baseline_cannot_be_rewritten() {
        let mut value = valid_manifest();
        value["baseline"]["commit"] = json!("0000000000000000000000000000000000000000");
        let error = validate(&value).expect_err("baseline");
        assert_eq!(error.exit_code(), 3);
    }

    #[test]
    fn standalone_documents_parse_and_reject_versions() {
        let value = valid_manifest();
        let claim = serde_json::to_vec(&value["claims"][0]).expect("json");
        assert!(parse_claim(&claim).is_ok());
        let inventory = serde_json::to_vec(&value["obligation_inventory"]).expect("json");
        assert!(parse_inventory(&inventory).is_ok());
        let dimensions =
            serde_json::to_vec(&value["claims"][0]["status_dimensions"]).expect("json");
        assert!(parse_dimensions(&dimensions).is_ok());

        let mut bad = value["claims"][0].clone();
        bad["schema"] = json!("frf-etp.claim.v9");
        let bytes = serde_json::to_vec(&bad).expect("json");
        assert_eq!(parse_claim(&bytes).expect_err("version").exit_code(), 3);
    }

    #[test]
    fn report_never_contains_a_scalar_score() {
        fn scan(value: &Value) {
            match value {
                Value::Object(map) => {
                    for key in map.keys() {
                        assert!(
                            !matches!(
                                key.as_str(),
                                "confidence" | "score" | "assurance_level" | "rating"
                            ),
                            "unexpected scalar field {key}"
                        );
                    }
                    for item in map.values() {
                        scan(item);
                    }
                }
                Value::Array(items) => {
                    for item in items {
                        scan(item);
                    }
                }
                _ => {}
            }
        }

        let report = validate(&valid_manifest()).expect("valid");
        let value = serde_json::to_value(&report).expect("json");
        scan(&value);
        assert!(!report.claim_ceiling.is_empty());
    }
}
