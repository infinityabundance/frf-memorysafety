//! Typed claims, scopes, obligations, hazards, and report vocabulary.
//!
//! These types deliberately keep distinct kinds of statement distinct. They
//! do not form a numeric confidence ladder.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::identity::MsId;

/// Manifest schema for local assessment bundles.
pub const MANIFEST_SCHEMA: &str = "frf-memorysafety.manifest.v1";
/// Claim schema.
pub const CLAIM_SCHEMA: &str = "frf-memorysafety.claim.v1";
/// Evidence schema.
pub const EVIDENCE_SCHEMA: &str = "frf-memorysafety.evidence.v1";
/// Graph schema.
pub const GRAPH_SCHEMA: &str = "frf-memorysafety.graph.v1";
/// Trace schema.
pub const TRACE_SCHEMA: &str = "frf-memorysafety.trace.v1";
/// Detector control schema.
pub const CONTROL_SCHEMA: &str = "frf-memorysafety.control.v1";
/// Handoff schema.
pub const HANDOFF_SCHEMA: &str = "frf-memorysafety.handoff.v1";
/// Report schema.
pub const REPORT_SCHEMA: &str = "frf-memorysafety.report.v1";

/// The four separately tracked promotion axes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimAxis {
    /// Binary compatibility for a named consumer.
    BinaryCompatible,
    /// Functional compatibility for a named workload.
    FunctionallyCompatible,
    /// Contextual safe-Rust soundness of the unsafe interior.
    SoundSafeInterior,
    /// Composite claim for an exact named consumer and workload.
    SafeCompatible,
}

impl ClaimAxis {
    /// Whether this axis is a memory-safety conclusion.
    #[must_use]
    pub const fn is_safety(self) -> bool {
        matches!(self, Self::SoundSafeInterior | Self::SafeCompatible)
    }

    /// Whether this axis is a compatibility observation.
    #[must_use]
    pub const fn is_compatibility(self) -> bool {
        matches!(
            self,
            Self::BinaryCompatible | Self::FunctionallyCompatible | Self::SafeCompatible
        )
    }
}

/// Property vocabulary. New properties require their own inference rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Property {
    /// No modeled memory-safety violation in a declared finite domain.
    ModelClear,
    /// Agreement with a stipulated finite observation oracle.
    ModelParity,
    /// Conjunction of permitted finite model properties.
    ModelConjunction,
    /// Behavioral compatibility under a named FRF court.
    BinaryCompatible,
    /// Functional compatibility under a named workload.
    FunctionallyCompatible,
    /// Contextual safe-Rust soundness of an unsafe abstraction.
    SoundSafeInterior,
    /// Composite for an exact named consumer, environment, and workload.
    SafeCompatible,
    /// Cryptographic correctness under a named algorithm specification.
    CryptographicCorrectness,
    /// A constant-time or leakage property under a named leakage model.
    ConstantTime,
    /// Secret storage and cleansing under a named lifecycle contract.
    SecretLifecycle,
    /// An arbitrary property supplied by an external policy.
    External(
        /// Policy-supplied property name.
        String,
    ),
}

impl fmt::Display for Property {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModelClear => f.write_str("model_clear"),
            Self::ModelParity => f.write_str("model_parity"),
            Self::ModelConjunction => f.write_str("model_conjunction"),
            Self::BinaryCompatible => f.write_str("binary_compatible"),
            Self::FunctionallyCompatible => f.write_str("functionally_compatible"),
            Self::SoundSafeInterior => f.write_str("sound_safe_interior"),
            Self::SafeCompatible => f.write_str("safe_compatible"),
            Self::CryptographicCorrectness => f.write_str("cryptographic_correctness"),
            Self::ConstantTime => f.write_str("constant_time"),
            Self::SecretLifecycle => f.write_str("secret_lifecycle"),
            Self::External(value) => write!(f, "external:{value}"),
        }
    }
}

/// Quantifier scope. Stronger quantifiers cannot be obtained by relabeling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Quantifier {
    /// A single concrete observation.
    FiniteObservation,
    /// Exhaustive enumeration of a declared finite case set.
    FiniteModelExhaustion,
    /// A bounded model-checking run.
    BoundedModel,
    /// A universal contextual argument (not admitted by the finite profile).
    UniversalContextual,
    /// A restriction to a declared deployment scope.
    DeploymentRestricted,
}

impl Quantifier {
    /// Only this quantifier is accepted by the built-in finite profile.
    #[must_use]
    pub const fn is_finite_exhaustion(self) -> bool {
        matches!(self, Self::FiniteModelExhaustion)
    }

    /// Human-readable label.
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
}

/// How an observation was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionMode {
    /// Authentic native execution of the candidate.
    AuthenticNative,
    /// Native execution with instrumentation loaded.
    NativeInstrumented,
    /// Execution against a mock provider.
    MockProvider,
    /// Execution with a substituted FFI implementation.
    SubstitutedFfi,
    /// A deterministic finite event/model replay.
    FiniteEventModel,
    /// Execution is unavailable or refused.
    Unsupported,
}

impl ExecutionMode {
    /// Authentic execution cannot be obtained by relabeling.
    #[must_use]
    pub const fn is_authentic(self) -> bool {
        matches!(self, Self::AuthenticNative | Self::NativeInstrumented)
    }

    /// Model-only execution is never native evidence.
    #[must_use]
    pub const fn is_model(self) -> bool {
        matches!(self, Self::FiniteEventModel)
    }
}

/// Epistemic status of a statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EpistemicStatus {
    /// Required by the protocol but not otherwise established.
    Specified,
    /// Described by a model, without execution.
    Modeled,
    /// A finite model was executed.
    ExecutedModel,
    /// Native code was executed.
    ExecutedNative,
    /// A proof checker accepted a proof under stated assumptions.
    CheckedProof,
    /// An argument was reviewed by an independent reviewer.
    ReviewedArgument,
    /// The check was not executed.
    NotRun,
    /// The check is unsupported by this build.
    Unsupported,
    /// The status is unknown.
    Unknown,
    /// An admitted challenge withholds the claim.
    Challenged,
    /// The supplied evidence failed integrity checks.
    InvalidEvidence,
}

impl EpistemicStatus {
    /// Whether this status is usable as admitted positive evidence.
    #[must_use]
    pub const fn is_admitted(self) -> bool {
        matches!(
            self,
            Self::ExecutedModel
                | Self::ExecutedNative
                | Self::CheckedProof
                | Self::ReviewedArgument
        )
    }
}

/// Final command outcome, deliberately not called `Pass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutcomeCategory {
    /// Checks completed only within the declared finite scope.
    CompleteWithinBoundedScope,
    /// A human review is required.
    ReviewRequired,
    /// A required premise is unknown or contradicted.
    Blocked,
    /// The outcome could not be determined.
    Indeterminate,
    /// A scope anchor is stale.
    Stale,
    /// Evidence failed integrity checks.
    InvalidEvidence,
    /// The required external run was not performed.
    NotRun,
    /// The harness itself failed.
    HarnessError,
}

/// The 12 hazard families from the specification and paper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hazard {
    /// Allocation provenance and layout.
    AllocationAndProvenance,
    /// Initialization and validity.
    InitializationAndValidity,
    /// Aliasing and reference validity.
    AliasingAndReferences,
    /// Ownership and lifecycle.
    OwnershipAndLifecycle,
    /// Callback and reentrancy behavior.
    CallbacksAndReentrancy,
    /// Concurrency, fork, and cancellation.
    ConcurrencyForkCancellation,
    /// Failure atomicity and unwinding.
    FailureAtomicityAndUnwind,
    /// Bounds and parsing.
    BoundsAndParsing,
    /// Secret material lifetime.
    SecretMaterialLifetime,
    /// Constant-time and protocol behavior.
    ConstantTimeAndProtocol,
    /// Runtime ABI and loaded state.
    RuntimeAbiAndLoadedState,
    /// Supply-chain and agentic integrity.
    SupplyChainAndAgenticIntegrity,
}

impl Hazard {
    /// Stable protocol name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllocationAndProvenance => "allocation.provenance",
            Self::InitializationAndValidity => "initialization.validity",
            Self::AliasingAndReferences => "alias.reference",
            Self::OwnershipAndLifecycle => "ownership.lifecycle",
            Self::CallbacksAndReentrancy => "callback.reentrancy",
            Self::ConcurrencyForkCancellation => "concurrency.fork",
            Self::FailureAtomicityAndUnwind => "failure.unwind",
            Self::BoundsAndParsing => "bounds.parsing",
            Self::SecretMaterialLifetime => "secret.lifecycle",
            Self::ConstantTimeAndProtocol => "security.constant-time",
            Self::RuntimeAbiAndLoadedState => "abi.loaded-state",
            Self::SupplyChainAndAgenticIntegrity => "supply-chain.integrity",
        }
    }
}

/// Conversion responsibility classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponsibilityChange {
    /// The responsibility was removed.
    Eliminated,
    /// The responsibility moved to another component.
    Relocated,
    /// The responsibility remains with the same component.
    Retained,
    /// A new responsibility was introduced.
    Introduced,
    /// A responsibility was concealed by the conversion.
    Hidden,
    /// The change is unknown.
    Unknown,
}

/// Lifecycle state of a safety obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObligationState {
    /// No obligation has been contracted.
    Unknown,
    /// The obligation scope and evidence shape are contracted.
    Contracted,
    /// Evidence within scope establishes the obligation locally.
    Established,
    /// An independent reviewer checked the established evidence.
    IndependentlyChecked,
    /// The obligation is discharged for the declared scope.
    Discharged,
    /// A required premise is missing or contradicted.
    Blocked,
    /// A scope anchor changed after evidence was recorded.
    Stale,
    /// The obligation does not apply, with typed evidence.
    InapplicableWithEvidence,
    /// A previously established obligation was reopened.
    Reopened,
}

impl ObligationState {
    /// Whether this state counts as a completed discharge.
    #[must_use]
    pub const fn is_discharged(self) -> bool {
        matches!(self, Self::Discharged)
    }

    /// Whether this state blocks a dependent promotion.
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(
            self,
            Self::Unknown | Self::Blocked | Self::Stale | Self::Reopened | Self::Contracted
        )
    }

    /// Explicit allowed transitions. `BLOCKED` is never a shortcut.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Unknown,
                Self::Contracted | Self::InapplicableWithEvidence
            ) | (
                Self::Contracted,
                Self::Established | Self::InapplicableWithEvidence
            ) | (Self::Established, Self::IndependentlyChecked)
                | (Self::IndependentlyChecked, Self::Discharged)
                | (
                    Self::Unknown
                        | Self::Contracted
                        | Self::Established
                        | Self::IndependentlyChecked
                        | Self::Discharged
                        | Self::InapplicableWithEvidence,
                    Self::Blocked
                )
                | (
                    Self::Unknown
                        | Self::Contracted
                        | Self::Established
                        | Self::IndependentlyChecked
                        | Self::Discharged
                        | Self::Blocked
                        | Self::InapplicableWithEvidence,
                    Self::Stale
                )
                | (
                    Self::Blocked | Self::Stale | Self::InapplicableWithEvidence,
                    Self::Reopened
                )
                | (Self::Reopened, Self::Contracted)
        )
    }
}

/// Detector outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DetectorOutcome {
    /// The detector reported its specific mechanism.
    Detected,
    /// The control ran but the detector did not report its mechanism.
    Missed,
    /// The detector was not run.
    NotRun,
    /// The detector family is unsupported by this build.
    Unsupported,
    /// The result is indeterminate.
    Indeterminate,
    /// The calibration evidence failed integrity checks.
    InvalidEvidence,
}

impl DetectorOutcome {
    /// `MISSED` is a STOP for dependent claims.
    #[must_use]
    pub const fn is_stop(self) -> bool {
        matches!(self, Self::Missed | Self::InvalidEvidence)
    }

    /// Whether the detector successfully established sensitivity for its control.
    #[must_use]
    pub const fn is_sensitive(self) -> bool {
        matches!(self, Self::Detected)
    }
}

/// Instrument family.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorKind {
    /// Miri.
    Miri,
    /// Address sanitizer.
    AddressSanitizer,
    /// Leak sanitizer.
    LeakSanitizer,
    /// Thread sanitizer.
    ThreadSanitizer,
    /// A constant-time or secret-lifecycle oracle (for example ctgrind or dudect).
    CryptoSecretOracle,
    /// Kani.
    Kani,
    /// Loom.
    Loom,
    /// FRF-Fuzz.
    FrfFuzz,
    /// FRF court.
    FrfCourt,
    /// cargo-fuzz.
    CargoFuzz,
    /// AFL++.
    AflPlusPlus,
    /// libAFL fuzzer.
    LibAfl,
    /// ctgrind.
    Ctgrind,
    /// dudect.
    Dudect,
    /// A policy-named detector.
    Custom(
        /// Policy-supplied detector name.
        String,
    ),
}

/// Typed certificate coordinate. Every coordinate is part of the proposition.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimKey {
    /// Claimed property.
    pub property: Property,
    /// Quantifier scope.
    pub quantifier: Quantifier,
    /// Named legal domain.
    pub legal_domain: String,
    /// Candidate identity.
    pub candidate: String,
    /// Environment identity.
    pub environment: String,
    /// Semantic model identity.
    pub semantic_model: String,
}

impl ClaimKey {
    /// Reject coordinates that cannot support the requested finite profile.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the quantifier or property is outside the
    /// finite profile.
    pub fn require_finite_model(&self) -> Result<(), String> {
        if !self.quantifier.is_finite_exhaustion() {
            return Err(format!(
                "finite profile requires finite_model_exhaustion, not {}",
                self.quantifier.as_str()
            ));
        }
        if matches!(
            self.property,
            Property::SoundSafeInterior | Property::SafeCompatible
        ) {
            return Err(
                "finite profile has no accepting rule for sound_safe_interior or safe_compatible"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

/// Candidate and policy anchors carried by evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeAnchors {
    /// Source tree identity.
    pub source: MsId,
    /// Candidate build identity.
    pub candidate: MsId,
    /// Execution environment identity.
    pub environment: MsId,
    /// Semantic model identity.
    pub model: MsId,
    /// Policy identity.
    pub policy: MsId,
}

impl ScopeAnchors {
    /// Exact anchor equality.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }
}

/// Trust-premise classes from the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PremiseKind {
    /// Contract and observation-oracle assumption.
    ContractAndOracle,
    /// Extractor and coverage assumption.
    ExtractorAndCoverage,
    /// Semantic model and mapping assumption.
    SemanticModelAndMapping,
    /// Checker and assumption set.
    CheckerAndAssumptions,
    /// Build and runtime closure assumption.
    BuildAndRuntime,
    /// Recorder and custody assumption.
    RecorderAndCustody,
    /// Inference-rule and challenge-policy assumption.
    RulesAndChallengePolicy,
}

/// A premise that a claimed result depends on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPremise {
    /// Premise identity.
    pub id: MsId,
    /// Premise class.
    pub kind: PremiseKind,
    /// Declared owner.
    pub owner: String,
    /// Premise version.
    pub version: String,
    /// Why the premise is required.
    pub rationale: String,
    /// Whether the premise remains unresolved.
    pub unresolved: bool,
    /// Other claims that rely on the same premise.
    pub shared_with: BTreeSet<MsId>,
}

/// A reviewer record. Independence is a declared, auditable claim, not an
/// authentication statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRecord {
    /// Review identity.
    pub id: MsId,
    /// Declared reviewer.
    pub reviewer: String,
    /// Declared independence class.
    pub independence_class: String,
    /// Reviewed scope.
    pub scope: String,
    /// Reviewed candidate.
    pub candidate: String,
    /// Review disposition.
    pub disposition: String,
    /// Review rationale.
    pub rationale: String,
    /// Challenges still open after review.
    pub open_challenges: Vec<String>,
    /// Sources consulted.
    pub sources: Vec<String>,
}

/// An immutable evidence reference with explicit origin and execution mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    /// Evidence identity.
    pub id: MsId,
    /// Evidence kind.
    pub kind: String,
    /// Declared producer/origin.
    pub origin: String,
    /// Execution mode of the evidence.
    pub execution_mode: ExecutionMode,
    /// Epistemic status of the evidence.
    pub status: EpistemicStatus,
    /// Artifact identity, when the evidence binds bytes.
    pub artifact: Option<MsId>,
    /// Declared limitation.
    pub limitation: String,
}

/// A safety obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Obligation {
    /// Obligation identity.
    pub id: MsId,
    /// Boundary the obligation applies to.
    pub boundary: MsId,
    /// Hazard family.
    pub hazard: Hazard,
    /// Proposition to establish.
    pub proposition: String,
    /// Required preconditions.
    pub preconditions: Vec<String>,
    /// Site where the obligation is established.
    pub establishing_site: String,
    /// Safe surface affected by the obligation.
    pub affected_safe_surface: Vec<String>,
    /// Dependency closure required for the obligation.
    pub closure: Vec<MsId>,
    /// Evidence that would falsify the obligation.
    pub falsifier: String,
    /// How conversion changed the responsibility.
    pub change: ResponsibilityChange,
    /// Current lifecycle state.
    pub state: ObligationState,
    /// Typed evidence identities.
    pub evidence: Vec<MsId>,
    /// Independent review identity, when present.
    pub review: Option<MsId>,
}

impl Obligation {
    /// Advance only along an explicit transition and only with a matching
    /// evidence/review record supplied by the caller.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic for an illegal transition or missing evidence and
    /// review records.
    pub fn advance(
        &mut self,
        next: ObligationState,
        evidence: &[MsId],
        review: Option<&MsId>,
    ) -> Result<(), String> {
        if !self.state.can_transition_to(next) {
            return Err(format!(
                "illegal obligation transition {:?} -> {:?}",
                self.state, next
            ));
        }
        if matches!(
            next,
            ObligationState::Established
                | ObligationState::IndependentlyChecked
                | ObligationState::Discharged
                | ObligationState::InapplicableWithEvidence
        ) && evidence.is_empty()
        {
            return Err("typed evidence is required for this transition".to_owned());
        }
        if next == ObligationState::IndependentlyChecked && review.is_none() {
            return Err("independent review record is required".to_owned());
        }
        self.state = next;
        self.evidence.extend(evidence.iter().cloned());
        if let Some(review) = review {
            self.review = Some(review.clone());
        }
        Ok(())
    }
}

/// A top-level claim with its policy and current admissibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRecord {
    /// Claim identity.
    pub id: MsId,
    /// Full claim coordinates.
    pub key: ClaimKey,
    /// Scope anchors at evaluation time.
    pub anchors: ScopeAnchors,
    /// Promotion axis the claim belongs to.
    pub axis: ClaimAxis,
    /// Status requested by the caller.
    pub requested_status: EpistemicStatus,
    /// Strongest status the evidence permits.
    pub highest_permitted: EpistemicStatus,
    /// Evidence identities.
    pub evidence: Vec<MsId>,
    /// Trust-premise identities.
    pub premises: Vec<MsId>,
    /// Whether an admitted challenge is unresolved.
    pub challenged: bool,
    /// Reason for the current disposition.
    pub reason: String,
}

impl ClaimRecord {
    /// The strongest admitted status, independent of promotion.
    #[must_use]
    pub fn admitted_status(&self) -> EpistemicStatus {
        if self.challenged {
            EpistemicStatus::Challenged
        } else {
            self.highest_permitted
        }
    }

    /// Refuse if the requested status exceeds the established maximum.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the requested status is stronger than the
    /// permitted status or when a challenge is unresolved.
    pub fn validate_status(&self) -> Result<(), String> {
        let rank = status_rank(self.requested_status);
        let permitted = status_rank(self.highest_permitted);
        if rank > permitted {
            return Err(format!(
                "requested {:?} exceeds highest permitted {:?}",
                self.requested_status, self.highest_permitted
            ));
        }
        if self.challenged && self.requested_status != EpistemicStatus::Challenged {
            return Err("claim has an unresolved admitted challenge".to_owned());
        }
        Ok(())
    }
}

const fn status_rank(status: EpistemicStatus) -> u8 {
    match status {
        EpistemicStatus::NotRun => 0,
        EpistemicStatus::Unsupported => 1,
        EpistemicStatus::Unknown => 2,
        EpistemicStatus::Specified => 3,
        EpistemicStatus::Modeled => 4,
        EpistemicStatus::ExecutedModel => 5,
        EpistemicStatus::ReviewedArgument => 6,
        EpistemicStatus::ExecutedNative => 7,
        EpistemicStatus::CheckedProof => 8,
        EpistemicStatus::Challenged => 9,
        EpistemicStatus::InvalidEvidence => 10,
    }
}

/// Provenance/closure status for a promotion candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClosureState {
    /// Only a declaration exists.
    Declared,
    /// An observation exists.
    Observed,
    /// Every supported interaction family has justified edges.
    JustifiedConservative,
    /// At least one edge is unknown.
    Unknown,
    /// An observation contradicts the declaration.
    Falsified,
}

/// Residual classification from the conversion loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidualClass {
    /// A Rust safety violation.
    RustSafetyViolation,
    /// Undefined behavior originating in the replaced authority.
    AuthorityUb,
    /// An intended safety divergence.
    IntendedSafetyDivergence,
    /// A legitimate compatibility difference.
    LegitimateIncompatibility,
    /// An artifact of the instrument.
    InstrumentArtifact,
    /// A harness error.
    HarnessError,
    /// Not yet classified.
    Unresolved,
}

/// An external identity is kept opaque and type-separated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FrfReceiptId(
    /// Opaque external FRF receipt/run identifier.
    pub String,
);

impl FrfReceiptId {
    /// Validate only the external textual shape. FRF remains the authority.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the text is not an FRF receipt identifier.
    pub fn parse(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        let hex = value
            .strip_prefix("receipt-")
            .and_then(|rest| rest.rsplit_once('-').map(|(_, hex)| hex));
        if let Some(hex) = hex {
            if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Ok(Self(value));
            }
        }
        Err(format!("not an FRF receipt identifier: {value}"))
    }
}

/// A Gemel GID kept opaque.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GemelGid(
    /// Opaque external Gemel GID.
    pub String,
);

impl GemelGid {
    /// Validate only the external textual shape.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the text is not a Gemel GID.
    pub fn parse(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        let Some((family, hex)) = value.split_once('.') else {
            return Err(format!("not a Gemel GID: {value}"));
        };
        if !family.is_empty()
            && hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Ok(Self(value));
        }
        Err(format!("not a Gemel GID: {value}"))
    }
}

/// A FRF-Fuzz content identifier, opaque and BLAKE3-typed externally.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FuzzContentId(
    /// Opaque external FRF-Fuzz content identifier.
    pub String,
);

impl FuzzContentId {
    /// Validate only the external textual shape.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the text is not a 64-digit lowercase hex
    /// content identifier.
    pub fn parse(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(Self(value))
        } else {
            Err(format!("not an FRF-Fuzz content identifier: {value}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_cannot_shortcut_discharge() {
        assert!(!ObligationState::Blocked.can_transition_to(ObligationState::Discharged));
        assert!(
            ObligationState::Established.can_transition_to(ObligationState::IndependentlyChecked)
        );
    }

    #[test]
    fn external_ids_are_textually_validated() {
        let receipt = format!("receipt-run-{}", "a".repeat(64));
        assert!(FrfReceiptId::parse(receipt).is_ok());
        assert!(FrfReceiptId::parse("receipt-bad").is_err());
        assert!(GemelGid::parse(format!("evidence.{}", "b".repeat(64))).is_ok());
        assert!(FuzzContentId::parse("c".repeat(64)).is_ok());
        assert!(FuzzContentId::parse("C".repeat(64)).is_err());
    }

    #[test]
    fn finite_profile_refuses_universal() {
        let key = ClaimKey {
            property: Property::SoundSafeInterior,
            quantifier: Quantifier::UniversalContextual,
            legal_domain: "all".to_owned(),
            candidate: "c".to_owned(),
            environment: "e".to_owned(),
            semantic_model: "m".to_owned(),
        };
        assert!(key.require_finite_model().is_err());
    }
}
