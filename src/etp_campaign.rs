#![allow(clippy::module_name_repetitions)]

//! Typed ETP campaign closure and lossless reconciliation.
//!
//! A campaign is an explicit, pre-registered population of cases. The opening
//! inventory declares the candidate, instrument, requirements, obligations,
//! expected terminal observations, mutation controls, exclusions, and resource
//! envelope. Per-case receipts record one terminal outcome. The closure
//! manifest is bookkeeping over that complete population; it is never a
//! population inference, a detector-sensitivity estimate, or a memory-safety
//! result.
//!
//! # Closure rules
//!
//! * Every declared case has exactly one receipt and exactly one terminal
//!   outcome.
//! * A missing, duplicate, unexpected, or truncated case blocks closure.
//! * Summary counts are derived only from the complete identified population.
//! * A missing population is not an empty population.
//! * Failures, contradictions, and unresolved observations are retained.
//! * Typed `NOT_RUN` is never a pass.
//! * An unresolved observation on a case that required a resolved observation
//!   withholds acceptance.
//! * A suppression without justification, scope, owner, expiry, and
//!   invalidation is refused, and remains a finding when valid.
//!
//! # Claim ceiling
//!
//! Closure establishes only that the declared finite campaign produced the
//! declared typed observations and that the bookkeeping is complete. It does
//! not establish memory safety, detector sensitivity, proof soundness,
//! population-level defect recall, reviewer independence, authentication, or
//! deployment security. A digest is not authentication.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::court;
use crate::identity::{canonical_bytes, hex_lower, parse_strict, IdentityError, MAX_BYTES};

/// Protocol specification identifier for the campaign schemas.
pub const CAMPAIGN_SPEC: &str = "frf-etp-v1";
/// Opening inventory (pre-registration) schema identifier.
pub const CAMPAIGN_PROTOCOL_SCHEMA: &str = "frf-etp.campaign-protocol.v1";
/// Per-case receipt schema identifier.
pub const CAMPAIGN_RECEIPT_SCHEMA: &str = "frf-etp.campaign-receipt.v1";
/// Closure manifest schema identifier.
pub const CAMPAIGN_CLOSURE_SCHEMA: &str = "frf-etp.campaign-closure.v1";
/// Reconciliation report schema identifier.
pub const CAMPAIGN_REPORT_SCHEMA: &str = "frf-etp.campaign-reconciliation.v1";
/// Canonical tree-digest algorithm for a declared file list.
pub const TREE_DIGEST_ALGORITHM: &str = "sha256-sorted-path-nul-digest-lf-v1";
/// Claim ceiling embedded in every reconciliation report.
pub const CAMPAIGN_CLAIM_CEILING: &str = "Campaign closure is bookkeeping over a finite, pre-registered case population. It establishes that every declared case has one retained typed observation and that the declared counts were derived from the complete population. It does not establish memory safety, functional correctness, detector sensitivity, proof soundness, population-level recall, reviewer independence, authentication, transparency completeness, or deployment security. A typed NOT_RUN is not a pass. A digest is not authentication.";
/// Maximum declared cases in one campaign.
pub const MAX_CASES: usize = 1024;
/// Maximum declared files in one candidate or instrument tree.
pub const MAX_FILES: usize = 4096;
/// Maximum text bytes in one campaign string.
pub const MAX_TEXT_BYTES: usize = 8192;
/// Maximum raw evidence bytes for one file.
pub const MAX_RAW_BYTES: usize = MAX_BYTES;

/// One terminal outcome for a declared case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcome {
    /// The recorded transcript verified cleanly within its declared scope.
    VerifiedCompatibleWithinTranscript,
    /// The recorded transcript contains a definite contradiction.
    ObservedViolation,
    /// A required event or completion fact is absent.
    IncompleteTranscript,
    /// The evidence cannot decide the question.
    Unresolved,
    /// The declared case or ordering graph is illegal.
    IllegalCase,
    /// The instrument or a required tool was unavailable.
    NotRun,
    /// The instrument failed internally.
    HarnessFailure,
}

impl TerminalOutcome {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedCompatibleWithinTranscript => "verified_compatible_within_transcript",
            Self::ObservedViolation => "observed_violation",
            Self::IncompleteTranscript => "incomplete_transcript",
            Self::Unresolved => "unresolved",
            Self::IllegalCase => "illegal_case",
            Self::NotRun => "not_run",
            Self::HarnessFailure => "harness_failure",
        }
    }

    /// Whether this outcome is the typed `NOT_RUN` path.
    #[must_use]
    pub const fn is_not_run(self) -> bool {
        matches!(self, Self::NotRun)
    }

    /// Whether this outcome is a clean transcript-scoped result.
    #[must_use]
    pub const fn is_clean(self) -> bool {
        matches!(self, Self::VerifiedCompatibleWithinTranscript)
    }

    /// Whether this outcome is a retained non-clean observation.
    #[must_use]
    pub const fn is_retained_finding(self) -> bool {
        matches!(
            self,
            Self::ObservedViolation
                | Self::IncompleteTranscript
                | Self::Unresolved
                | Self::IllegalCase
        )
    }

    /// Whether this outcome is an instrument failure.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::HarnessFailure)
    }
}

/// Decision for one case, derived from the pre-registered expectation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignDecision {
    /// The observed terminal outcome equals the pre-registered outcome.
    Pass,
    /// The observed terminal outcome differs, or the harness failed.
    Fail,
    /// The instrument was unavailable; this is never a pass.
    NotRun,
}

impl CampaignDecision {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::NotRun => "not_run",
        }
    }
}

/// Release decision recorded for one case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseDecision {
    /// A clean, mandatory-resolution case is eligible for its finite claim.
    Eligible,
    /// A retained finding or expected unresolved observation withholds release.
    Withheld,
    /// A failure, illegal case, or unavailable instrument blocks release.
    Blocked,
    /// The case makes no release request.
    NotApplicable,
}

impl ReleaseDecision {
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
}

/// Resolution state of one observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationResolution {
    /// The observation is decided within its declared scope.
    Resolved,
    /// The observation is retained as unresolved.
    Unresolved,
    /// No observation resolution applies (`NOT_RUN` or harness failure).
    NotApplicable,
}

impl ObservationResolution {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Unresolved => "unresolved",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// Closure status of the declared population.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClosureStatus {
    /// Every declared case has exactly one retained terminal receipt.
    Closed,
    /// The population is incomplete, duplicated, unexpected, or truncated.
    Blocked,
}

impl ClosureStatus {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Blocked => "blocked",
        }
    }
}

/// Acceptance status of a closed campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignAcceptance {
    /// Every case matched its pre-registered observation and no mandatory
    /// resolution was unmet.
    Accepted,
    /// The campaign is closed but acceptance is withheld.
    Withheld,
}

impl CampaignAcceptance {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Withheld => "withheld",
        }
    }
}

/// Overall reconciliation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    /// Closure complete and acceptance granted for the finite campaign claim.
    Accepted,
    /// Closure complete, acceptance withheld.
    Withheld,
    /// Closure blocked or evidence integrity failed.
    Refused,
}

impl CampaignStatus {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Withheld => "withheld",
            Self::Refused => "refused",
        }
    }
}

/// Stable refusal codes for campaign reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignRefusalCode {
    /// The opening manifest digest differs from the frozen digest.
    OpeningDigestMismatch,
    /// A declared candidate file is missing or changed.
    CandidateFileMismatch,
    /// A declared instrument file is missing or changed.
    InstrumentFileMismatch,
    /// The declared population is empty or inconsistent.
    InvalidPopulation,
    /// A declared case has no receipt.
    MissingReceipt,
    /// Two receipts claim the same case.
    DuplicateReceipt,
    /// A receipt names a case outside the declared population.
    UnexpectedReceipt,
    /// The closure manifest lists fewer receipts than the population.
    TruncatedPopulation,
    /// A summary count disagrees with recomputation.
    InconsistentCount,
    /// A receipt is missing a terminal outcome.
    MissingTerminalOutcome,
    /// The observed outcome differs from the pre-registered outcome.
    ExpectedObservationMismatch,
    /// A case that required a resolved observation observed `unresolved`.
    UnresolvedMandatoryObservation,
    /// A retained failure was recorded as a pass or dropped.
    FailureNotRetained,
    /// A suppression lacks a required field.
    UnauthorizedSuppression,
    /// Evidence does not apply to the declared case or artifact.
    InapplicableEvidence,
    /// A receipt names a different candidate.
    WrongCandidate,
    /// A receipt names a different instrument.
    WrongInstrument,
    /// Raw evidence named by a receipt is absent.
    MissingRawEvidence,
    /// A raw evidence file is not referenced by any receipt.
    UnexpectedRawEvidence,
    /// A declared digest does not match the bytes.
    DigestMismatch,
    /// A result was stripped of a required observation or finding.
    StrippedResult,
    /// Raw evidence could not be parsed or re-verified.
    InvalidRawEvidence,
    /// The recorded adjudication is not the derived adjudication.
    InconsistentAdjudication,
    /// The declared closure status is not the derived closure status.
    InconsistentClosureStatus,
    /// The declared acceptance is not the derived acceptance.
    InconsistentAcceptance,
    /// An exclusion removes a declared case from the population.
    UnauthorizedExclusion,
    /// The protocol permits `NOT_RUN` to count as a pass.
    NotRunIsNotAPass,
    /// The declared claim is not present in the protocol.
    UnknownClaim,
}

impl CampaignRefusalCode {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpeningDigestMismatch => "opening_digest_mismatch",
            Self::CandidateFileMismatch => "candidate_file_mismatch",
            Self::InstrumentFileMismatch => "instrument_file_mismatch",
            Self::InvalidPopulation => "invalid_population",
            Self::MissingReceipt => "missing_receipt",
            Self::DuplicateReceipt => "duplicate_receipt",
            Self::UnexpectedReceipt => "unexpected_receipt",
            Self::TruncatedPopulation => "truncated_population",
            Self::InconsistentCount => "inconsistent_count",
            Self::MissingTerminalOutcome => "missing_terminal_outcome",
            Self::ExpectedObservationMismatch => "expected_observation_mismatch",
            Self::UnresolvedMandatoryObservation => "unresolved_mandatory_observation",
            Self::FailureNotRetained => "failure_not_retained",
            Self::UnauthorizedSuppression => "unauthorized_suppression",
            Self::InapplicableEvidence => "inapplicable_evidence",
            Self::WrongCandidate => "wrong_candidate",
            Self::WrongInstrument => "wrong_instrument",
            Self::MissingRawEvidence => "missing_raw_evidence",
            Self::UnexpectedRawEvidence => "unexpected_raw_evidence",
            Self::DigestMismatch => "digest_mismatch",
            Self::StrippedResult => "stripped_result",
            Self::InvalidRawEvidence => "invalid_raw_evidence",
            Self::InconsistentAdjudication => "inconsistent_adjudication",
            Self::InconsistentClosureStatus => "inconsistent_closure_status",
            Self::InconsistentAcceptance => "inconsistent_acceptance",
            Self::UnauthorizedExclusion => "unauthorized_exclusion",
            Self::NotRunIsNotAPass => "not_run_is_not_a_pass",
            Self::UnknownClaim => "unknown_claim",
        }
    }
}

/// One declared file with its SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateFile {
    /// Repository-relative path using `/` separators.
    pub path: String,
    /// Lowercase SHA-256 of the exact bytes.
    pub sha256: String,
}

/// Candidate under test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignCandidate {
    /// Stable candidate identifier.
    pub id: String,
    /// Candidate version.
    pub version: String,
    /// Tree-digest algorithm.
    pub tree_sha256_algorithm: String,
    /// Digest over the declared file list.
    pub tree_sha256: String,
    /// Exact candidate files.
    pub files: Vec<CandidateFile>,
}

/// Instrument that produced the observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignInstrument {
    /// Stable instrument identifier.
    pub id: String,
    /// Recorder harness identifier.
    pub harness: String,
    /// Court verifier identifier.
    pub court: String,
    /// Crate version compiled into the instrument.
    pub crate_version: String,
    /// Required external tools.
    pub required_tools: Vec<String>,
    /// Tree-digest algorithm.
    pub tree_sha256_algorithm: String,
    /// Digest over the declared instrument file list.
    pub tree_sha256: String,
    /// Exact instrument files.
    pub files: Vec<CandidateFile>,
}

/// One declared requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignRequirement {
    /// Stable requirement identifier.
    pub id: String,
    /// Exact requirement statement.
    pub statement: String,
}

/// One declared obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignObligation {
    /// Stable obligation identifier.
    pub id: String,
    /// Exact obligation statement.
    pub statement: String,
    /// Whether an unresolved obligation blocks acceptance.
    pub blocking: bool,
}

/// One declared campaign case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignCase {
    /// Stable case identifier.
    pub id: String,
    /// Repository-relative fixture path.
    pub fixture: String,
    /// Case category used by the pre-registration.
    pub category: String,
    /// Pre-registered terminal outcome.
    pub expected_outcome: TerminalOutcome,
    /// Requirement identifier.
    pub requirement: String,
    /// Obligation identifiers.
    pub obligations: Vec<String>,
    /// Whether this case requires a resolved (non-unresolved) observation.
    pub mandatory_resolution: bool,
}

/// One declared mutation control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignMutationControl {
    /// Stable control identifier.
    pub id: String,
    /// What the control mutates.
    pub description: String,
    /// Expected reconciliation behavior.
    pub expected: String,
}

/// One permitted exclusion. Exclusions must not remove a declared case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermittedExclusion {
    /// Case identifier.
    pub case_id: String,
    /// Exact reason.
    pub reason: String,
}

/// Declared resource envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignResourceLimits {
    /// Hard memory limit in MiB.
    pub memory_mb: u64,
    /// Equal swap limit in MiB.
    pub swap_mb: u64,
    /// Process identifier limit.
    pub pids_limit: u64,
    /// CPU limit.
    pub cpus: u64,
    /// Open-file limit.
    pub nofile: u64,
    /// OOM score adjustment.
    pub oom_score_adj: i64,
    /// Wall-clock timeout in seconds.
    pub timeout_seconds: u64,
}

/// Pre-registered acceptance policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignAcceptancePolicy {
    /// Exact natural-language rule.
    pub rule: String,
    /// Expected declared case count.
    pub expected_case_count: usize,
    /// Expected receipt count.
    pub expected_receipt_count: usize,
    /// Expected raw evidence file count.
    pub expected_raw_evidence_count: usize,
    /// Expected pass decision count.
    pub expected_pass_count: usize,
    /// Expected retained finding count.
    pub expected_finding_count: usize,
    /// Whether raw evidence is mandatory.
    pub require_raw_evidence: bool,
    /// Whether clean cases must replay identically.
    pub require_replay_identical: bool,
    /// Must be false. `NOT_RUN` is never a pass.
    pub not_run_is_pass: bool,
}

/// Pre-registered completion expectations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignCompletionExpectations {
    /// Expected declared case count.
    pub case_count: usize,
    /// Expected receipt count.
    pub receipt_count: usize,
    /// Expected raw evidence file count.
    pub raw_evidence_count: usize,
    /// Expected closure status.
    pub closure_status: ClosureStatus,
    /// Expected acceptance.
    pub acceptance: CampaignAcceptance,
}

/// One claim declared by the campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignClaim {
    /// Stable claim identifier.
    pub id: String,
    /// Exact claim statement.
    pub statement: String,
}

/// Frozen opening inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignProtocol {
    /// Schema identifier.
    pub schema: String,
    /// Protocol specification identifier.
    pub spec: String,
    /// Stable campaign identifier.
    pub campaign_id: String,
    /// Freeze date.
    pub frozen: String,
    /// Declared scope.
    pub scope: String,
    /// Candidate under test.
    pub candidate: CampaignCandidate,
    /// Requirements.
    pub requirements: Vec<CampaignRequirement>,
    /// Threat model and excluded threats.
    pub threat_model: String,
    /// Declared assumptions.
    pub assumptions: Vec<String>,
    /// Full obligation inventory.
    pub obligations: Vec<CampaignObligation>,
    /// Declared population.
    pub population: Vec<CampaignCase>,
    /// Instrument identity.
    pub instrument: CampaignInstrument,
    /// Mutation controls exercised by tests.
    pub mutation_controls: Vec<CampaignMutationControl>,
    /// Permitted exclusions.
    pub permitted_exclusions: Vec<PermittedExclusion>,
    /// Resource envelope.
    pub resource_limits: CampaignResourceLimits,
    /// Acceptance policy.
    pub acceptance_policy: CampaignAcceptancePolicy,
    /// Completion expectations.
    pub completion_expectations: CampaignCompletionExpectations,
    /// Declared claims.
    pub claims: Vec<CampaignClaim>,
    /// Unsupported features.
    pub unsupported_features: Vec<String>,
    /// Claim ceiling.
    pub claim_ceiling: String,
}

/// One retained finding in a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignFinding {
    /// Stable finding code.
    pub code: String,
    /// Finding class.
    pub class: String,
    /// Finding subject.
    pub subject: String,
    /// Exact finding detail.
    pub detail: String,
    /// Number of events cited by the finding.
    pub events: usize,
}

/// Recorded observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignObservation {
    /// Terminal outcome.
    pub outcome: TerminalOutcome,
    /// Court outcome when a court report exists.
    pub court_outcome: String,
    /// Number of transcript events.
    pub event_count: usize,
    /// Retained findings.
    pub findings: Vec<CampaignFinding>,
    /// Number of race witnesses.
    pub race_witnesses: usize,
    /// Exact harness or court detail.
    pub detail: String,
}

/// Recorded execution identity and environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignExecution {
    /// Exact process argument vector.
    pub command: Vec<String>,
    /// Declared execution environment.
    pub environment: String,
    /// Container image identifier when known.
    pub image_id: String,
    /// Whether the native harness was enabled.
    pub native_harness: bool,
    /// Replay label: `identical`, `mismatch`, or `not_performed`.
    pub replay: String,
    /// First canonical transcript SHA-256 when replay ran.
    pub replay_first_sha256: String,
    /// Second canonical transcript SHA-256 when replay ran.
    pub replay_second_sha256: String,
    /// Exact compiler and library versions.
    pub tool_versions: Vec<String>,
    /// Executable SHA-256 when the harness recorded one.
    pub executable_sha256: String,
    /// Fixture path relative to the repository root.
    pub fixture_path: String,
    /// Fixture SHA-256.
    pub fixture_sha256: String,
}

/// One evidence reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignEvidence {
    /// Evidence kind: `transcript`, `court_report`, or `harness_detail`.
    pub kind: String,
    /// Path relative to the campaign directory.
    pub path: String,
    /// Lowercase SHA-256 of the exact bytes.
    pub sha256: String,
}

/// Adjudication recorded for one case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignAdjudication {
    /// Pre-registered outcome.
    pub expected_outcome: TerminalOutcome,
    /// Observed outcome.
    pub observed_outcome: TerminalOutcome,
    /// Derived decision.
    pub decision: CampaignDecision,
    /// Whether a resolved observation was required.
    pub mandatory_resolution: bool,
    /// Observation resolution.
    pub resolution: ObservationResolution,
}

/// Suppression record. A suppression never removes a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignSuppression {
    /// Whether a suppression is declared.
    pub suppressed: bool,
    /// Exact justification.
    pub justification: String,
    /// Suppression scope.
    pub scope: String,
    /// Administrative owner.
    pub owner: String,
    /// Expiry.
    pub expiry: String,
    /// Invalidation condition.
    pub invalidation: String,
}

/// One per-case ETP receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignReceipt {
    /// Schema identifier.
    pub schema: String,
    /// Protocol specification identifier.
    pub spec: String,
    /// Campaign identifier.
    pub campaign_id: String,
    /// Case identifier.
    pub case_id: String,
    /// Candidate identity.
    pub candidate_identity: String,
    /// Instrument identifier.
    pub instrument_id: String,
    /// Instrument-execution identity.
    pub instrument_execution_identity: String,
    /// Requirement identifier.
    pub requirement: String,
    /// Obligation identifiers.
    pub obligations: Vec<String>,
    /// Claim identifier.
    pub claim: String,
    /// Execution record.
    pub execution: CampaignExecution,
    /// Observation.
    pub observation: CampaignObservation,
    /// Adjudication.
    pub adjudication: CampaignAdjudication,
    /// Release decision.
    pub release_decision: ReleaseDecision,
    /// Raw evidence.
    pub evidence: Vec<CampaignEvidence>,
    /// Suppression record.
    pub suppression: CampaignSuppression,
}

/// One receipt reference in the closure manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignReceiptRef {
    /// Case identifier.
    pub case_id: String,
    /// Receipt path relative to the campaign directory.
    pub path: String,
    /// Receipt SHA-256.
    pub sha256: String,
    /// Observed outcome.
    pub outcome: TerminalOutcome,
    /// Derived decision.
    pub decision: CampaignDecision,
}

/// One labelled count.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignCount {
    /// Label.
    pub label: String,
    /// Count.
    pub count: usize,
}

/// Closure manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignClosure {
    /// Schema identifier.
    pub schema: String,
    /// Protocol specification identifier.
    pub spec: String,
    /// Campaign identifier.
    pub campaign_id: String,
    /// Opening manifest path relative to the campaign directory.
    pub opening_manifest_path: String,
    /// Frozen opening manifest SHA-256.
    pub opening_sha256: String,
    /// Candidate identity.
    pub candidate_identity: String,
    /// Instrument identifier.
    pub instrument_id: String,
    /// Declared case count.
    pub case_count: usize,
    /// Receipt count.
    pub receipt_count: usize,
    /// Raw evidence file count.
    pub raw_evidence_count: usize,
    /// Outcome counts.
    pub outcomes: Vec<CampaignCount>,
    /// Decision counts.
    pub decisions: Vec<CampaignCount>,
    /// Receipt references.
    pub receipts: Vec<CampaignReceiptRef>,
    /// Permitted exclusions that did not remove a declared case.
    pub exclusions: Vec<PermittedExclusion>,
    /// Closure status.
    pub closure_status: ClosureStatus,
    /// Acceptance.
    pub acceptance: CampaignAcceptance,
    /// Closure or withholding reasons.
    pub closure_reasons: Vec<String>,
    /// Claim ceiling.
    pub claim_ceiling: String,
}

/// One reconciliation refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignRefusal {
    /// Stable refusal code.
    pub code: CampaignRefusalCode,
    /// Case identifier, or the campaign identifier for campaign-level refusals.
    pub case_id: String,
    /// Exact detail.
    pub detail: String,
}

/// Reconciliation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignReport {
    /// Schema identifier.
    pub schema: String,
    /// Protocol specification identifier.
    pub spec: String,
    /// Campaign identifier.
    pub campaign_id: String,
    /// Overall status.
    pub status: CampaignStatus,
    /// Derived closure status.
    pub closure_status: ClosureStatus,
    /// Derived acceptance.
    pub acceptance: CampaignAcceptance,
    /// Opening manifest SHA-256.
    pub opening_sha256: String,
    /// Candidate identity.
    pub candidate_identity: String,
    /// Instrument identifier.
    pub instrument_id: String,
    /// Declared case count.
    pub case_count: usize,
    /// Provided receipt count.
    pub receipt_count: usize,
    /// Raw evidence file count.
    pub raw_evidence_count: usize,
    /// Derived outcome counts.
    pub outcomes: Vec<CampaignCount>,
    /// Derived decision counts.
    pub decisions: Vec<CampaignCount>,
    /// Cases whose observation matched and whose claim is eligible.
    pub accepted_cases: Vec<String>,
    /// Cases with a retained finding, unresolved observation, or valid suppression.
    pub retained_findings: Vec<String>,
    /// Refusals.
    pub refusals: Vec<CampaignRefusal>,
    /// Claim ceiling.
    pub claim_ceiling: String,
}

impl CampaignReport {
    /// Encode this report as strict canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignError::Canonical`] if the report cannot be encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CampaignError> {
        canonical_json(self)
    }

    /// Exit status: 0 accepted, 4 withheld/refused, 6 when every case is
    /// `NOT_RUN`.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if self.status == CampaignStatus::Accepted {
            return 0;
        }
        let all_not_run = self.case_count > 0
            && self
                .outcomes
                .iter()
                .any(|count| count.label == "not_run" && count.count == self.case_count);
        if all_not_run {
            6
        } else {
            4
        }
    }

    /// Whether the campaign produced a complete, reconciled closure.
    #[must_use]
    pub fn reconciliation_complete(&self) -> bool {
        self.closure_status == ClosureStatus::Closed
    }
}

/// Error type for campaign parsing, execution, and reconciliation.
#[derive(Debug, thiserror::Error)]
pub enum CampaignError {
    /// Strict JSON parsing failed.
    #[error("invalid campaign JSON: {0}")]
    Identity(#[from] IdentityError),
    /// A structural rule failed.
    #[error("invalid campaign: {message}")]
    Invalid {
        /// Diagnostic.
        message: String,
    },
    /// A schema or specification version is not supported.
    #[error("campaign schema mismatch for {field}: expected {expected}, found {actual}")]
    SchemaMismatch {
        /// Field name.
        field: String,
        /// Expected identifier.
        expected: String,
        /// Observed identifier.
        actual: String,
    },
    /// An I/O operation failed.
    #[error("campaign I/O failure: {message}")]
    Io {
        /// Diagnostic.
        message: String,
    },
    /// Canonical encoding failed.
    #[error("campaign encoding failure: {message}")]
    Canonical {
        /// Diagnostic.
        message: String,
    },
    /// A campaign operation is unsupported in this build.
    #[error("campaign operation unsupported: {message}")]
    Unsupported {
        /// Diagnostic.
        message: String,
    },
}

impl CampaignError {
    /// `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Canonical { .. } => 7,
            Self::Identity(_)
            | Self::Invalid { .. }
            | Self::SchemaMismatch { .. }
            | Self::Io { .. } => 3,
            Self::Unsupported { .. } => 6,
        }
    }
}

fn check_text(label: &str, value: &str) -> Result<(), CampaignError> {
    if value.trim().is_empty() {
        return Err(CampaignError::Invalid {
            message: format!("{label} must not be empty"),
        });
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(CampaignError::Invalid {
            message: format!("{label} exceeds {MAX_TEXT_BYTES} bytes"),
        });
    }
    Ok(())
}

fn check_schema(field: &str, actual: &str, expected: &str) -> Result<(), CampaignError> {
    if actual != expected {
        return Err(CampaignError::SchemaMismatch {
            field: field.to_owned(),
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

/// Canonical JSON bytes for a serializable value.
///
/// # Errors
///
/// Returns [`CampaignError::Canonical`] if the value cannot be represented.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CampaignError> {
    let value = serde_json::to_value(value).map_err(|error| CampaignError::Canonical {
        message: error.to_string(),
    })?;
    canonical_bytes(&value).map_err(|error| CampaignError::Canonical {
        message: error.to_string(),
    })
}

/// Lowercase SHA-256 of exact bytes.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

/// Lowercase SHA-256 of a file.
///
/// # Errors
///
/// Returns [`CampaignError::Io`] when the file cannot be read.
pub fn file_sha256(path: &Path) -> Result<String, CampaignError> {
    let bytes = fs::read(path).map_err(|error| CampaignError::Io {
        message: format!("cannot read {}: {error}", path.display()),
    })?;
    Ok(sha256_hex(&bytes))
}

/// Tree digest over sorted `(path, sha256)` pairs.
#[must_use]
pub fn tree_sha256(files: &[CandidateFile]) -> String {
    let mut sorted: Vec<&CandidateFile> = files.iter().collect();
    sorted.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    let mut hasher = Sha256::new();
    for file in sorted {
        hasher.update(file.path.as_bytes());
        hasher.update([0_u8]);
        hasher.update(file.sha256.as_bytes());
        hasher.update(b"\n");
    }
    hex_lower(&hasher.finalize())
}

/// Instrument-execution identity over the environment, executable, and tools.
#[must_use]
pub fn instrument_execution_identity(instrument_id: &str, execution: &CampaignExecution) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"frf-etp.instrument-execution.v1\n");
    for value in [
        instrument_id,
        execution.environment.as_str(),
        execution.image_id.as_str(),
        execution.executable_sha256.as_str(),
    ] {
        hasher.update(value.as_bytes());
        hasher.update(b"\n");
    }
    let mut tools = execution.tool_versions.clone();
    tools.sort();
    for tool in tools {
        hasher.update(tool.as_bytes());
        hasher.update(b"\n");
    }
    hex_lower(&hasher.finalize())
}

fn derive_decision(expected: TerminalOutcome, observed: TerminalOutcome) -> CampaignDecision {
    if observed.is_not_run() {
        return CampaignDecision::NotRun;
    }
    if observed.is_failure() {
        return CampaignDecision::Fail;
    }
    if observed == expected {
        CampaignDecision::Pass
    } else {
        CampaignDecision::Fail
    }
}

fn derive_resolution(observed: TerminalOutcome) -> ObservationResolution {
    if observed == TerminalOutcome::Unresolved {
        ObservationResolution::Unresolved
    } else if observed.is_not_run() || observed.is_failure() {
        ObservationResolution::NotApplicable
    } else {
        ObservationResolution::Resolved
    }
}

fn derive_release(observed: TerminalOutcome, decision: CampaignDecision) -> ReleaseDecision {
    if decision == CampaignDecision::NotRun || observed.is_failure() {
        return ReleaseDecision::Blocked;
    }
    if decision == CampaignDecision::Fail || observed == TerminalOutcome::IllegalCase {
        return ReleaseDecision::Blocked;
    }
    if observed.is_clean() {
        ReleaseDecision::Eligible
    } else if observed.is_retained_finding() {
        ReleaseDecision::Withheld
    } else {
        ReleaseDecision::NotApplicable
    }
}

fn counts_from<'a>(labels: impl Iterator<Item = &'a str>) -> Vec<CampaignCount> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for label in labels {
        *counts.entry(label).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(label, count)| CampaignCount {
            label: label.to_owned(),
            count,
        })
        .collect()
}

fn validate_candidate(candidate: &CampaignCandidate) -> Result<(), CampaignError> {
    check_text("candidate.id", &candidate.id)?;
    check_text("candidate.version", &candidate.version)?;
    check_text(
        "candidate.tree_sha256_algorithm",
        &candidate.tree_sha256_algorithm,
    )?;
    check_text("candidate.tree_sha256", &candidate.tree_sha256)?;
    if candidate.tree_sha256_algorithm != TREE_DIGEST_ALGORITHM {
        return Err(CampaignError::Invalid {
            message: format!(
                "unsupported candidate tree digest algorithm {}",
                candidate.tree_sha256_algorithm
            ),
        });
    }
    if candidate.files.is_empty() || candidate.files.len() > MAX_FILES {
        return Err(CampaignError::Invalid {
            message: "candidate file list is empty or over limit".to_owned(),
        });
    }
    let mut seen = BTreeSet::new();
    for file in &candidate.files {
        check_text("candidate file path", &file.path)?;
        check_text("candidate file sha256", &file.sha256)?;
        if !seen.insert(&file.path) {
            return Err(CampaignError::Invalid {
                message: format!("duplicate candidate file path {}", file.path),
            });
        }
    }
    if tree_sha256(&candidate.files) != candidate.tree_sha256 {
        return Err(CampaignError::Invalid {
            message: "candidate tree digest does not match its file list".to_owned(),
        });
    }
    Ok(())
}

fn validate_instrument(instrument: &CampaignInstrument) -> Result<(), CampaignError> {
    check_text("instrument.id", &instrument.id)?;
    check_text("instrument.harness", &instrument.harness)?;
    check_text("instrument.court", &instrument.court)?;
    check_text("instrument.crate_version", &instrument.crate_version)?;
    check_text(
        "instrument.tree_sha256_algorithm",
        &instrument.tree_sha256_algorithm,
    )?;
    check_text("instrument.tree_sha256", &instrument.tree_sha256)?;
    if instrument.tree_sha256_algorithm != TREE_DIGEST_ALGORITHM {
        return Err(CampaignError::Invalid {
            message: format!(
                "unsupported instrument tree digest algorithm {}",
                instrument.tree_sha256_algorithm
            ),
        });
    }
    if instrument.files.is_empty() || instrument.files.len() > MAX_FILES {
        return Err(CampaignError::Invalid {
            message: "instrument file list is empty or over limit".to_owned(),
        });
    }
    let mut seen = BTreeSet::new();
    for file in &instrument.files {
        check_text("instrument file path", &file.path)?;
        check_text("instrument file sha256", &file.sha256)?;
        if !seen.insert(&file.path) {
            return Err(CampaignError::Invalid {
                message: format!("duplicate instrument file path {}", file.path),
            });
        }
    }
    if tree_sha256(&instrument.files) != instrument.tree_sha256 {
        return Err(CampaignError::Invalid {
            message: "instrument tree digest does not match its file list".to_owned(),
        });
    }
    Ok(())
}

/// Parse an opening inventory with strict JSON rules.
///
/// # Errors
///
/// Returns [`CampaignError`] for malformed JSON, unknown fields, duplicate
/// identifiers, an unsupported schema, an empty population, or an inconsistent
/// tree digest.
#[allow(clippy::too_many_lines)]
pub fn parse_protocol(bytes: &[u8]) -> Result<CampaignProtocol, CampaignError> {
    let value = parse_strict(bytes)?;
    let protocol: CampaignProtocol =
        serde_json::from_value(value).map_err(|error| CampaignError::Invalid {
            message: error.to_string(),
        })?;
    check_schema(
        "protocol.schema",
        &protocol.schema,
        CAMPAIGN_PROTOCOL_SCHEMA,
    )?;
    check_schema("protocol.spec", &protocol.spec, CAMPAIGN_SPEC)?;
    check_text("campaign_id", &protocol.campaign_id)?;
    check_text("frozen", &protocol.frozen)?;
    check_text("scope", &protocol.scope)?;
    check_text("threat_model", &protocol.threat_model)?;
    check_text("claim_ceiling", &protocol.claim_ceiling)?;
    validate_candidate(&protocol.candidate)?;
    validate_instrument(&protocol.instrument)?;

    if protocol.population.is_empty() || protocol.population.len() > MAX_CASES {
        return Err(CampaignError::Invalid {
            message: "population is empty or over limit".to_owned(),
        });
    }
    let mut case_ids = BTreeSet::new();
    for case in &protocol.population {
        check_text("case.id", &case.id)?;
        check_text("case.fixture", &case.fixture)?;
        check_text("case.category", &case.category)?;
        check_text("case.requirement", &case.requirement)?;
        if !case_ids.insert(&case.id) {
            return Err(CampaignError::Invalid {
                message: format!("duplicate case id {}", case.id),
            });
        }
        let mut obligations = BTreeSet::new();
        for obligation in &case.obligations {
            check_text("case obligation", obligation)?;
            if !obligations.insert(obligation) {
                return Err(CampaignError::Invalid {
                    message: format!("duplicate case obligation {obligation}"),
                });
            }
        }
    }

    let requirement_ids: BTreeSet<&String> = protocol
        .requirements
        .iter()
        .map(|requirement| &requirement.id)
        .collect();
    if requirement_ids.len() != protocol.requirements.len() {
        return Err(CampaignError::Invalid {
            message: "duplicate requirement id".to_owned(),
        });
    }
    for requirement in &protocol.requirements {
        check_text("requirement.id", &requirement.id)?;
        check_text("requirement.statement", &requirement.statement)?;
    }
    let obligation_ids: BTreeSet<&String> = protocol
        .obligations
        .iter()
        .map(|obligation| &obligation.id)
        .collect();
    if obligation_ids.len() != protocol.obligations.len() {
        return Err(CampaignError::Invalid {
            message: "duplicate obligation id".to_owned(),
        });
    }
    for obligation in &protocol.obligations {
        check_text("obligation.id", &obligation.id)?;
        check_text("obligation.statement", &obligation.statement)?;
    }
    for case in &protocol.population {
        if !requirement_ids.contains(&case.requirement) {
            return Err(CampaignError::Invalid {
                message: format!("case {} references unknown requirement", case.id),
            });
        }
        for obligation in &case.obligations {
            if !obligation_ids.contains(obligation) {
                return Err(CampaignError::Invalid {
                    message: format!("case {} references unknown obligation", case.id),
                });
            }
        }
    }

    let mut claim_ids = BTreeSet::new();
    for claim in &protocol.claims {
        check_text("claim.id", &claim.id)?;
        check_text("claim.statement", &claim.statement)?;
        if !claim_ids.insert(&claim.id) {
            return Err(CampaignError::Invalid {
                message: format!("duplicate claim id {}", claim.id),
            });
        }
    }

    for exclusion in &protocol.permitted_exclusions {
        check_text("exclusion.case_id", &exclusion.case_id)?;
        check_text("exclusion.reason", &exclusion.reason)?;
        if case_ids.contains(&exclusion.case_id) {
            return Err(CampaignError::Invalid {
                message: format!("exclusion removes declared case {}", exclusion.case_id),
            });
        }
    }

    if protocol.acceptance_policy.not_run_is_pass {
        return Err(CampaignError::Invalid {
            message: "acceptance_policy.not_run_is_pass must be false".to_owned(),
        });
    }
    if protocol.acceptance_policy.expected_case_count != protocol.population.len() {
        return Err(CampaignError::Invalid {
            message: "acceptance_policy case count disagrees with population".to_owned(),
        });
    }
    if protocol.completion_expectations.case_count != protocol.population.len() {
        return Err(CampaignError::Invalid {
            message: "completion case count disagrees with population".to_owned(),
        });
    }
    Ok(protocol)
}

/// Parse a closure manifest with strict JSON rules.
///
/// # Errors
///
/// Returns [`CampaignError`] for malformed JSON, unknown fields, or an
/// unsupported schema.
pub fn parse_closure(bytes: &[u8]) -> Result<CampaignClosure, CampaignError> {
    let value = parse_strict(bytes)?;
    let closure: CampaignClosure =
        serde_json::from_value(value).map_err(|error| CampaignError::Invalid {
            message: error.to_string(),
        })?;
    check_schema("closure.schema", &closure.schema, CAMPAIGN_CLOSURE_SCHEMA)?;
    check_schema("closure.spec", &closure.spec, CAMPAIGN_SPEC)?;
    check_text("closure.campaign_id", &closure.campaign_id)?;
    check_text(
        "closure.opening_manifest_path",
        &closure.opening_manifest_path,
    )?;
    check_text("closure.opening_sha256", &closure.opening_sha256)?;
    check_text("closure.candidate_identity", &closure.candidate_identity)?;
    check_text("closure.instrument_id", &closure.instrument_id)?;
    check_text("closure.claim_ceiling", &closure.claim_ceiling)?;
    Ok(closure)
}

/// Parse a per-case receipt with strict JSON rules.
///
/// # Errors
///
/// Returns [`CampaignError`] for malformed JSON, unknown fields, missing
/// required fields, or an unsupported schema.
pub fn parse_receipt(bytes: &[u8]) -> Result<CampaignReceipt, CampaignError> {
    let value = parse_strict(bytes)?;
    let receipt: CampaignReceipt =
        serde_json::from_value(value).map_err(|error| CampaignError::Invalid {
            message: error.to_string(),
        })?;
    check_schema("receipt.schema", &receipt.schema, CAMPAIGN_RECEIPT_SCHEMA)?;
    check_schema("receipt.spec", &receipt.spec, CAMPAIGN_SPEC)?;
    check_text("receipt.campaign_id", &receipt.campaign_id)?;
    check_text("receipt.case_id", &receipt.case_id)?;
    check_text("receipt.candidate_identity", &receipt.candidate_identity)?;
    check_text("receipt.instrument_id", &receipt.instrument_id)?;
    check_text(
        "receipt.instrument_execution_identity",
        &receipt.instrument_execution_identity,
    )?;
    check_text("receipt.requirement", &receipt.requirement)?;
    check_text("receipt.claim", &receipt.claim)?;
    check_text(
        "receipt.execution.environment",
        &receipt.execution.environment,
    )?;
    check_text(
        "receipt.execution.fixture_path",
        &receipt.execution.fixture_path,
    )?;
    check_text(
        "receipt.execution.fixture_sha256",
        &receipt.execution.fixture_sha256,
    )?;
    check_text("receipt.observation.detail", &receipt.observation.detail)?;
    for obligation in &receipt.obligations {
        check_text("receipt obligation", obligation)?;
    }
    if receipt.evidence.is_empty() {
        return Err(CampaignError::Invalid {
            message: format!("receipt {} has no raw evidence", receipt.case_id),
        });
    }
    for evidence in &receipt.evidence {
        check_text("evidence.path", &evidence.path)?;
        check_text("evidence.sha256", &evidence.sha256)?;
        check_text("evidence.kind", &evidence.kind)?;
    }
    Ok(receipt)
}

/// One in-memory campaign bundle used for lossless reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignBundle {
    /// Exact opening inventory bytes.
    pub protocol_bytes: Vec<u8>,
    /// Exact closure manifest bytes.
    pub closure_bytes: Vec<u8>,
    /// Optional frozen sidecar digest.
    pub opening_sha256: Option<String>,
    /// Receipt path relative to the campaign directory -> exact bytes.
    pub receipts: BTreeMap<String, Vec<u8>>,
    /// Raw evidence path relative to the campaign directory -> exact bytes.
    pub raw: BTreeMap<String, Vec<u8>>,
    /// Repository root used for candidate and fixture files.
    pub root: PathBuf,
}

fn find_repo_root(start: &Path) -> PathBuf {
    for ancestor in start.ancestors() {
        if ancestor.join("Cargo.toml").is_file() && ancestor.join("tests/native/fixtures").is_dir()
        {
            return ancestor.to_path_buf();
        }
    }
    start.to_path_buf()
}

fn walk_files(
    directory: &Path,
    output: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), CampaignError> {
    let entries = fs::read_dir(directory).map_err(|error| CampaignError::Io {
        message: format!("cannot read directory {}: {error}", directory.display()),
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| CampaignError::Io {
            message: format!("cannot read directory entry: {error}"),
        })?;
        let path = entry.path();
        let metadata = entry.metadata().map_err(|error| CampaignError::Io {
            message: format!("cannot stat {}: {error}", path.display()),
        })?;
        if metadata.is_dir() {
            walk_files(&path, output)?;
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        if usize::try_from(metadata.len()).unwrap_or(usize::MAX) > MAX_RAW_BYTES {
            return Err(CampaignError::Invalid {
                message: format!(
                    "raw evidence {} exceeds {MAX_RAW_BYTES} bytes",
                    path.display()
                ),
            });
        }
        let name = path
            .strip_prefix(directory)
            .map_err(|error| CampaignError::Io {
                message: error.to_string(),
            })?
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(&path).map_err(|error| CampaignError::Io {
            message: format!("cannot read {}: {error}", path.display()),
        })?;
        output.insert(name, bytes);
    }
    Ok(())
}

/// Load a campaign bundle rooted at a closure manifest path.
///
/// # Errors
///
/// Returns [`CampaignError`] when a file is missing, oversized, or malformed.
#[allow(clippy::too_many_lines)]
pub fn load_bundle(manifest_path: &Path) -> Result<CampaignBundle, CampaignError> {
    let base = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let closure_bytes = fs::read(manifest_path).map_err(|error| CampaignError::Io {
        message: format!("cannot read {}: {error}", manifest_path.display()),
    })?;
    let closure = parse_closure(&closure_bytes)?;
    let protocol_path = base.join(&closure.opening_manifest_path);
    let protocol_bytes = fs::read(&protocol_path).map_err(|error| CampaignError::Io {
        message: format!("cannot read {}: {error}", protocol_path.display()),
    })?;
    if protocol_bytes.len() > MAX_RAW_BYTES {
        return Err(CampaignError::Invalid {
            message: "opening manifest exceeds the evidence size limit".to_owned(),
        });
    }
    let opening_sha256 = fs::read_to_string(base.join("opening.sha256"))
        .ok()
        .and_then(|text| {
            text.split_whitespace()
                .next()
                .filter(|value| value.len() == 64)
                .map(ToOwned::to_owned)
        });

    let mut receipts = BTreeMap::new();
    let receipts_dir = base.join("receipts");
    if receipts_dir.is_dir() {
        let entries = fs::read_dir(&receipts_dir).map_err(|error| CampaignError::Io {
            message: format!("cannot read {}: {error}", receipts_dir.display()),
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| CampaignError::Io {
                message: format!("cannot read receipt entry: {error}"),
            })?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let metadata = entry.metadata().map_err(|error| CampaignError::Io {
                message: format!("cannot stat {}: {error}", path.display()),
            })?;
            if usize::try_from(metadata.len()).unwrap_or(usize::MAX) > MAX_RAW_BYTES {
                return Err(CampaignError::Invalid {
                    message: format!("receipt {} exceeds {MAX_RAW_BYTES} bytes", path.display()),
                });
            }
            let name = format!(
                "receipts/{}",
                path.file_name().unwrap_or_default().to_string_lossy()
            );
            let bytes = fs::read(&path).map_err(|error| CampaignError::Io {
                message: format!("cannot read {}: {error}", path.display()),
            })?;
            receipts.insert(name, bytes);
        }
    }

    let mut raw = BTreeMap::new();
    let raw_dir = receipts_dir.join("raw");
    if raw_dir.is_dir() {
        let mut relative = BTreeMap::new();
        walk_files(&raw_dir, &mut relative)?;
        for (name, bytes) in relative {
            raw.insert(format!("receipts/raw/{name}"), bytes);
        }
    }

    Ok(CampaignBundle {
        protocol_bytes,
        closure_bytes,
        opening_sha256,
        receipts,
        raw,
        root: find_repo_root(base),
    })
}

/// Parse every receipt in a bundle.
///
/// # Errors
///
/// Returns [`CampaignError`] for any malformed receipt.
pub fn parse_receipts(
    bundle: &CampaignBundle,
) -> Result<Vec<(String, CampaignReceipt)>, CampaignError> {
    let mut parsed = Vec::with_capacity(bundle.receipts.len());
    for (path, bytes) in &bundle.receipts {
        parsed.push((path.clone(), parse_receipt(bytes)?));
    }
    parsed.sort_by(|left, right| left.1.case_id.cmp(&right.1.case_id));
    Ok(parsed)
}

fn refusal(code: CampaignRefusalCode, case_id: &str, detail: impl Into<String>) -> CampaignRefusal {
    CampaignRefusal {
        code,
        case_id: case_id.to_owned(),
        detail: detail.into(),
    }
}

fn check_declared_files(
    label: &str,
    files: &[CandidateFile],
    root: &Path,
    refusals: &mut Vec<CampaignRefusal>,
) {
    for file in files {
        let path = root.join(&file.path);
        match fs::read(&path) {
            Ok(bytes) => {
                let actual = sha256_hex(&bytes);
                if actual != file.sha256 {
                    refusals.push(refusal(
                        if label == "candidate" {
                            CampaignRefusalCode::CandidateFileMismatch
                        } else {
                            CampaignRefusalCode::InstrumentFileMismatch
                        },
                        label,
                        format!("{} digest is {actual}, declared {}", file.path, file.sha256),
                    ));
                }
            }
            Err(error) => refusals.push(refusal(
                if label == "candidate" {
                    CampaignRefusalCode::CandidateFileMismatch
                } else {
                    CampaignRefusalCode::InstrumentFileMismatch
                },
                label,
                format!("cannot read {}: {error}", file.path),
            )),
        }
    }
}

fn safe_relative_path(path: &str) -> bool {
    let candidate = Path::new(path);
    !candidate.is_absolute()
        && candidate
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn finding_class_label(class: court::FindingClass) -> &'static str {
    match class {
        court::FindingClass::ObservedViolation => "observed_violation",
        court::FindingClass::Incomplete => "incomplete",
        court::FindingClass::Unresolved => "unresolved",
        court::FindingClass::Illegal => "illegal",
    }
}

fn receipt_findings(report: Option<&court::CourtReport>) -> Vec<CampaignFinding> {
    report
        .map(|report| {
            report
                .findings
                .iter()
                .map(|finding| CampaignFinding {
                    code: finding.code.clone(),
                    class: finding_class_label(finding.class).to_owned(),
                    subject: finding.subject.clone(),
                    detail: finding.detail.clone(),
                    events: finding.events.len(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn check_suppression(
    suppression: &CampaignSuppression,
    case_id: &str,
    refusals: &mut Vec<CampaignRefusal>,
) {
    if !suppression.suppressed {
        return;
    }
    for (label, value) in [
        ("justification", &suppression.justification),
        ("scope", &suppression.scope),
        ("owner", &suppression.owner),
        ("expiry", &suppression.expiry),
        ("invalidation", &suppression.invalidation),
    ] {
        if value.trim().is_empty() {
            refusals.push(refusal(
                CampaignRefusalCode::UnauthorizedSuppression,
                case_id,
                format!("suppression is missing {label}"),
            ));
        }
    }
}

fn compare_report(
    report: &court::CourtReport,
    receipt: &CampaignReceipt,
    case_id: &str,
    refusals: &mut Vec<CampaignRefusal>,
) {
    if report.outcome.as_str() != receipt.observation.court_outcome {
        refusals.push(refusal(
            CampaignRefusalCode::InconsistentAdjudication,
            case_id,
            format!(
                "court outcome {} disagrees with receipt {}",
                report.outcome.as_str(),
                receipt.observation.court_outcome
            ),
        ));
    }
    if report.event_count != receipt.observation.event_count {
        refusals.push(refusal(
            CampaignRefusalCode::InconsistentAdjudication,
            case_id,
            "court event count disagrees with receipt".to_owned(),
        ));
    }
    if report.race_witnesses.len() != receipt.observation.race_witnesses {
        refusals.push(refusal(
            CampaignRefusalCode::InconsistentAdjudication,
            case_id,
            "court race-witness count disagrees with receipt".to_owned(),
        ));
    }
    let recomputed_findings = receipt_findings(Some(report));
    if recomputed_findings != receipt.observation.findings {
        refusals.push(refusal(
            CampaignRefusalCode::InconsistentAdjudication,
            case_id,
            "court findings disagree with the receipt".to_owned(),
        ));
    }
}

#[allow(clippy::too_many_lines)]
fn check_evidence(
    receipt: &CampaignReceipt,
    case: &CampaignCase,
    bundle: &CampaignBundle,
    transcript_digest: &mut Option<String>,
    refusals: &mut Vec<CampaignRefusal>,
) {
    let mut saw_transcript = false;
    let mut saw_report = false;
    let mut saw_detail = false;
    for evidence in &receipt.evidence {
        if !safe_relative_path(&evidence.path) {
            refusals.push(refusal(
                CampaignRefusalCode::InapplicableEvidence,
                &case.id,
                format!(
                    "evidence path {} is not a safe relative path",
                    evidence.path
                ),
            ));
            continue;
        }
        let Some(bytes) = bundle.raw.get(&evidence.path) else {
            refusals.push(refusal(
                CampaignRefusalCode::MissingRawEvidence,
                &case.id,
                format!("raw evidence {} is absent", evidence.path),
            ));
            continue;
        };
        let actual = sha256_hex(bytes);
        if actual != evidence.sha256 {
            refusals.push(refusal(
                CampaignRefusalCode::DigestMismatch,
                &case.id,
                format!(
                    "raw evidence {} digest is {actual}, declared {}",
                    evidence.path, evidence.sha256
                ),
            ));
        }
        if !evidence.path.contains(&case.id) {
            refusals.push(refusal(
                CampaignRefusalCode::InapplicableEvidence,
                &case.id,
                format!("evidence {} does not name case {}", evidence.path, case.id),
            ));
        }
        match evidence.kind.as_str() {
            "transcript" => {
                saw_transcript = true;
                let transcript = match court::parse_transcript(bytes) {
                    Ok(transcript) => transcript,
                    Err(error) => {
                        refusals.push(refusal(
                            CampaignRefusalCode::InvalidRawEvidence,
                            &case.id,
                            format!("transcript {} did not parse: {error}", evidence.path),
                        ));
                        continue;
                    }
                };
                let report = match court::verify_transcript(&transcript) {
                    Ok(report) => report,
                    Err(error) => {
                        refusals.push(refusal(
                            CampaignRefusalCode::InvalidRawEvidence,
                            &case.id,
                            format!("transcript {} did not verify: {error}", evidence.path),
                        ));
                        continue;
                    }
                };
                if report.transcript_sha256 != actual {
                    refusals.push(refusal(
                        CampaignRefusalCode::DigestMismatch,
                        &case.id,
                        "court transcript digest disagrees with the raw transcript".to_owned(),
                    ));
                }
                // A replay mismatch is a harness-level condition: the first
                // transcript may still verify cleanly while the second run
                // produced different bytes. The retained report, not the raw
                // transcript re-verification, records the unresolved outcome.
                if receipt.execution.replay != "mismatch" {
                    compare_report(&report, receipt, &case.id, refusals);
                }
                if transcript.provenance.fixture_digest != receipt.execution.fixture_sha256 {
                    refusals.push(refusal(
                        CampaignRefusalCode::InapplicableEvidence,
                        &case.id,
                        "transcript fixture digest disagrees with receipt".to_owned(),
                    ));
                }
                if !receipt.execution.executable_sha256.is_empty()
                    && transcript.provenance.executable_digest
                        != receipt.execution.executable_sha256
                {
                    refusals.push(refusal(
                        CampaignRefusalCode::InapplicableEvidence,
                        &case.id,
                        "transcript executable digest disagrees with receipt".to_owned(),
                    ));
                }
                if !transcript.provenance.scope.contains(&case.id) {
                    refusals.push(refusal(
                        CampaignRefusalCode::InapplicableEvidence,
                        &case.id,
                        "transcript scope does not name the declared case".to_owned(),
                    ));
                }
                *transcript_digest = Some(actual);
            }
            "court_report" => {
                saw_report = true;
                let value = match parse_strict(bytes) {
                    Ok(value) => value,
                    Err(error) => {
                        refusals.push(refusal(
                            CampaignRefusalCode::InvalidRawEvidence,
                            &case.id,
                            format!("court report {} did not parse: {error}", evidence.path),
                        ));
                        continue;
                    }
                };
                let report: court::CourtReport = match serde_json::from_value(value) {
                    Ok(report) => report,
                    Err(error) => {
                        refusals.push(refusal(
                            CampaignRefusalCode::InvalidRawEvidence,
                            &case.id,
                            format!(
                                "court report {} is not a court report: {error}",
                                evidence.path
                            ),
                        ));
                        continue;
                    }
                };
                compare_report(&report, receipt, &case.id, refusals);
                if let Ok(canonical) = report.canonical_bytes() {
                    if sha256_hex(&canonical) != actual {
                        refusals.push(refusal(
                            CampaignRefusalCode::DigestMismatch,
                            &case.id,
                            "retained court report is not canonical".to_owned(),
                        ));
                    }
                }
            }
            "harness_detail" => {
                saw_detail = true;
                let text = String::from_utf8_lossy(bytes);
                if text != receipt.observation.detail {
                    refusals.push(refusal(
                        CampaignRefusalCode::InconsistentAdjudication,
                        &case.id,
                        "harness detail evidence disagrees with receipt".to_owned(),
                    ));
                }
            }
            other => refusals.push(refusal(
                CampaignRefusalCode::InapplicableEvidence,
                &case.id,
                format!("unknown evidence kind {other}"),
            )),
        }
    }
    if !saw_transcript && !saw_detail {
        refusals.push(refusal(
            CampaignRefusalCode::MissingRawEvidence,
            &case.id,
            "receipt has no transcript or harness-detail evidence".to_owned(),
        ));
    }
    if saw_transcript && !saw_report {
        refusals.push(refusal(
            CampaignRefusalCode::MissingRawEvidence,
            &case.id,
            "receipt has a transcript but no retained court report".to_owned(),
        ));
    }
    if saw_report && !saw_transcript {
        refusals.push(refusal(
            CampaignRefusalCode::InapplicableEvidence,
            &case.id,
            "receipt has a court report without its raw transcript".to_owned(),
        ));
    }
}

/// Reconcile a campaign bundle without trusting its closure summary.
///
/// # Errors
///
/// Returns [`CampaignError`] for malformed JSON, an unsupported schema, or an
/// unreadable declared file. Semantic integrity failures are accumulated as
/// refusals in the returned report.
#[allow(clippy::too_many_lines)]
pub fn verify_bundle(bundle: &CampaignBundle) -> Result<CampaignReport, CampaignError> {
    let protocol = parse_protocol(&bundle.protocol_bytes)?;
    let closure = parse_closure(&bundle.closure_bytes)?;
    let mut refusals = Vec::new();

    let opening_sha256 = sha256_hex(&bundle.protocol_bytes);
    if closure.opening_sha256 != opening_sha256 {
        refusals.push(refusal(
            CampaignRefusalCode::OpeningDigestMismatch,
            &protocol.campaign_id,
            format!(
                "closure names opening digest {}, computed {opening_sha256}",
                closure.opening_sha256
            ),
        ));
    }
    if let Some(sidecar) = &bundle.opening_sha256 {
        if sidecar != &opening_sha256 {
            refusals.push(refusal(
                CampaignRefusalCode::OpeningDigestMismatch,
                &protocol.campaign_id,
                format!("frozen sidecar is {sidecar}, computed {opening_sha256}"),
            ));
        }
    } else {
        refusals.push(refusal(
            CampaignRefusalCode::OpeningDigestMismatch,
            &protocol.campaign_id,
            "frozen opening digest sidecar is absent".to_owned(),
        ));
    }
    if closure.campaign_id != protocol.campaign_id {
        refusals.push(refusal(
            CampaignRefusalCode::OpeningDigestMismatch,
            &protocol.campaign_id,
            "closure campaign identifier disagrees with the opening inventory".to_owned(),
        ));
    }
    if closure.candidate_identity != protocol.candidate.tree_sha256 {
        refusals.push(refusal(
            CampaignRefusalCode::WrongCandidate,
            &protocol.campaign_id,
            "closure candidate identity disagrees with the opening inventory".to_owned(),
        ));
    }
    if closure.instrument_id != protocol.instrument.id {
        refusals.push(refusal(
            CampaignRefusalCode::WrongInstrument,
            &protocol.campaign_id,
            "closure instrument identity disagrees with the opening inventory".to_owned(),
        ));
    }
    check_declared_files(
        "candidate",
        &protocol.candidate.files,
        &bundle.root,
        &mut refusals,
    );
    check_declared_files(
        "instrument",
        &protocol.instrument.files,
        &bundle.root,
        &mut refusals,
    );

    let cases: BTreeMap<String, &CampaignCase> = protocol
        .population
        .iter()
        .map(|case| (case.id.clone(), case))
        .collect();
    let declared_claims: BTreeSet<&String> =
        protocol.claims.iter().map(|claim| &claim.id).collect();
    let exclusions: BTreeSet<&String> = protocol
        .permitted_exclusions
        .iter()
        .map(|exclusion| &exclusion.case_id)
        .collect();
    for case in &protocol.population {
        if exclusions.contains(&case.id) {
            refusals.push(refusal(
                CampaignRefusalCode::UnauthorizedExclusion,
                &case.id,
                "an exclusion removes a declared case".to_owned(),
            ));
        }
    }

    let mut by_case: BTreeMap<String, (String, Vec<u8>, CampaignReceipt)> = BTreeMap::new();
    let mut referenced_raw: BTreeSet<String> = BTreeSet::new();
    let mut retained_findings = Vec::new();
    let mut accepted_cases = Vec::new();

    for (path, bytes) in &bundle.receipts {
        let receipt = parse_receipt(bytes)?;
        let Some(case) = cases.get(&receipt.case_id) else {
            refusals.push(refusal(
                CampaignRefusalCode::UnexpectedReceipt,
                &receipt.case_id,
                format!("receipt {path} names a case outside the declared population"),
            ));
            continue;
        };
        if receipt.campaign_id != protocol.campaign_id {
            refusals.push(refusal(
                CampaignRefusalCode::UnexpectedReceipt,
                &receipt.case_id,
                "receipt campaign identifier disagrees with the opening inventory".to_owned(),
            ));
        }
        if receipt.candidate_identity != protocol.candidate.tree_sha256 {
            refusals.push(refusal(
                CampaignRefusalCode::WrongCandidate,
                &receipt.case_id,
                "receipt candidate identity disagrees with the opening inventory".to_owned(),
            ));
        }
        if receipt.instrument_id != protocol.instrument.id {
            refusals.push(refusal(
                CampaignRefusalCode::WrongInstrument,
                &receipt.case_id,
                "receipt instrument identity disagrees with the opening inventory".to_owned(),
            ));
        }
        if receipt.requirement != case.requirement {
            refusals.push(refusal(
                CampaignRefusalCode::InapplicableEvidence,
                &receipt.case_id,
                "receipt requirement disagrees with the declared case".to_owned(),
            ));
        }
        if receipt.obligations != case.obligations {
            refusals.push(refusal(
                CampaignRefusalCode::InapplicableEvidence,
                &receipt.case_id,
                "receipt obligations disagree with the declared case".to_owned(),
            ));
        }
        if receipt.adjudication.expected_outcome != case.expected_outcome {
            refusals.push(refusal(
                CampaignRefusalCode::ExpectedObservationMismatch,
                &receipt.case_id,
                "receipt expected outcome disagrees with the opening inventory".to_owned(),
            ));
        }
        if receipt.adjudication.mandatory_resolution != case.mandatory_resolution {
            refusals.push(refusal(
                CampaignRefusalCode::InconsistentAdjudication,
                &receipt.case_id,
                "receipt mandatory-resolution flag disagrees with the declared case".to_owned(),
            ));
        }
        if !declared_claims.contains(&receipt.claim) {
            refusals.push(refusal(
                CampaignRefusalCode::UnknownClaim,
                &receipt.case_id,
                format!("receipt names undeclared claim {}", receipt.claim),
            ));
        }

        let derived_decision = derive_decision(case.expected_outcome, receipt.observation.outcome);
        if receipt.adjudication.decision != derived_decision {
            refusals.push(refusal(
                CampaignRefusalCode::InconsistentAdjudication,
                &receipt.case_id,
                "receipt decision disagrees with the derived decision".to_owned(),
            ));
        }
        if receipt.adjudication.observed_outcome != receipt.observation.outcome {
            refusals.push(refusal(
                CampaignRefusalCode::InconsistentAdjudication,
                &receipt.case_id,
                "receipt adjudicated outcome disagrees with its observation".to_owned(),
            ));
        }
        let derived_resolution = derive_resolution(receipt.observation.outcome);
        if receipt.adjudication.resolution != derived_resolution {
            refusals.push(refusal(
                CampaignRefusalCode::InconsistentAdjudication,
                &receipt.case_id,
                "receipt resolution disagrees with the derived resolution".to_owned(),
            ));
        }
        let derived_release = derive_release(receipt.observation.outcome, derived_decision);
        if receipt.release_decision != derived_release {
            refusals.push(refusal(
                CampaignRefusalCode::InconsistentAdjudication,
                &receipt.case_id,
                "receipt release decision disagrees with the derived decision".to_owned(),
            ));
        }

        let recomputed_instrument =
            instrument_execution_identity(&receipt.instrument_id, &receipt.execution);
        if recomputed_instrument != receipt.instrument_execution_identity {
            refusals.push(refusal(
                CampaignRefusalCode::WrongInstrument,
                &receipt.case_id,
                "instrument-execution identity does not match its execution fields".to_owned(),
            ));
        }

        if receipt.execution.fixture_path != case.fixture {
            refusals.push(refusal(
                CampaignRefusalCode::InapplicableEvidence,
                &receipt.case_id,
                "receipt fixture path disagrees with the declared case".to_owned(),
            ));
        }
        let fixture_path = bundle.root.join(&case.fixture);
        let fixture_sha256 = file_sha256(&fixture_path)?;
        if receipt.execution.fixture_sha256 != fixture_sha256 {
            refusals.push(refusal(
                CampaignRefusalCode::InapplicableEvidence,
                &receipt.case_id,
                "receipt fixture digest disagrees with the declared fixture".to_owned(),
            ));
        }

        match receipt.observation.outcome {
            TerminalOutcome::VerifiedCompatibleWithinTranscript => {
                if !receipt.observation.findings.is_empty() {
                    refusals.push(refusal(
                        CampaignRefusalCode::StrippedResult,
                        &receipt.case_id,
                        "a clean outcome retains findings".to_owned(),
                    ));
                }
                if protocol.acceptance_policy.require_replay_identical
                    && receipt.execution.replay != "identical"
                {
                    refusals.push(refusal(
                        CampaignRefusalCode::FailureNotRetained,
                        &receipt.case_id,
                        "a clean case did not replay identically".to_owned(),
                    ));
                }
            }
            TerminalOutcome::ObservedViolation | TerminalOutcome::IncompleteTranscript => {
                if receipt.observation.findings.is_empty() {
                    refusals.push(refusal(
                        CampaignRefusalCode::StrippedResult,
                        &receipt.case_id,
                        "a retained finding has no finding record".to_owned(),
                    ));
                }
            }
            TerminalOutcome::Unresolved
            | TerminalOutcome::IllegalCase
            | TerminalOutcome::NotRun
            | TerminalOutcome::HarnessFailure => {}
        }

        let mut transcript_digest = None;
        if protocol.acceptance_policy.require_raw_evidence {
            check_evidence(
                &receipt,
                case,
                bundle,
                &mut transcript_digest,
                &mut refusals,
            );
            for evidence in &receipt.evidence {
                referenced_raw.insert(evidence.path.clone());
            }
        }
        check_suppression(&receipt.suppression, &receipt.case_id, &mut refusals);

        if receipt.suppression.suppressed {
            retained_findings.push(receipt.case_id.clone());
        }
        if receipt.observation.outcome.is_retained_finding() {
            retained_findings.push(receipt.case_id.clone());
        }
        if receipt.observation.outcome.is_clean()
            && derived_decision == CampaignDecision::Pass
            && derived_release == ReleaseDecision::Eligible
        {
            accepted_cases.push(receipt.case_id.clone());
        }

        if by_case
            .insert(
                receipt.case_id.clone(),
                (path.clone(), bytes.clone(), receipt),
            )
            .is_some()
        {
            refusals.push(refusal(
                CampaignRefusalCode::DuplicateReceipt,
                &case.id,
                "two receipts claim the same case".to_owned(),
            ));
        }
    }

    for case in &protocol.population {
        if !by_case.contains_key(&case.id) {
            refusals.push(refusal(
                CampaignRefusalCode::MissingReceipt,
                &case.id,
                "declared case has no receipt".to_owned(),
            ));
        }
    }

    for raw_path in bundle.raw.keys() {
        if !referenced_raw.contains(raw_path) {
            refusals.push(refusal(
                CampaignRefusalCode::UnexpectedRawEvidence,
                &protocol.campaign_id,
                format!("raw evidence {raw_path} is not referenced by a receipt"),
            ));
        }
    }

    let case_count = protocol.population.len();
    let receipt_count = bundle.receipts.len();
    let raw_evidence_count = bundle.raw.len();
    let outcomes = counts_from(
        by_case
            .values()
            .map(|(_, _, receipt)| receipt.observation.outcome.as_str()),
    );
    let decisions = counts_from(
        by_case
            .values()
            .map(|(_, _, receipt)| receipt.adjudication.decision.as_str()),
    );

    if closure.case_count != case_count {
        refusals.push(refusal(
            CampaignRefusalCode::InconsistentCount,
            &protocol.campaign_id,
            format!(
                "closure case_count {} differs from declared {case_count}",
                closure.case_count
            ),
        ));
    }
    if closure.receipt_count != receipt_count {
        refusals.push(refusal(
            CampaignRefusalCode::InconsistentCount,
            &protocol.campaign_id,
            format!(
                "closure receipt_count {} differs from provided {receipt_count}",
                closure.receipt_count
            ),
        ));
    }
    if closure.raw_evidence_count != raw_evidence_count {
        refusals.push(refusal(
            CampaignRefusalCode::InconsistentCount,
            &protocol.campaign_id,
            format!(
                "closure raw_evidence_count {} differs from provided {raw_evidence_count}",
                closure.raw_evidence_count
            ),
        ));
    }
    if closure.outcomes != outcomes {
        refusals.push(refusal(
            CampaignRefusalCode::InconsistentCount,
            &protocol.campaign_id,
            "closure outcome counts disagree with the receipts".to_owned(),
        ));
    }
    if closure.decisions != decisions {
        refusals.push(refusal(
            CampaignRefusalCode::InconsistentCount,
            &protocol.campaign_id,
            "closure decision counts disagree with the receipts".to_owned(),
        ));
    }
    let pass_count = decisions
        .iter()
        .find(|count| count.label == "pass")
        .map_or(0, |count| count.count);
    let retained_count = retained_findings
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .len();
    for (label, actual, expected) in [
        (
            "case_count",
            case_count,
            protocol.acceptance_policy.expected_case_count,
        ),
        (
            "receipt_count",
            receipt_count,
            protocol.acceptance_policy.expected_receipt_count,
        ),
        (
            "raw_evidence_count",
            raw_evidence_count,
            protocol.acceptance_policy.expected_raw_evidence_count,
        ),
        (
            "pass_count",
            pass_count,
            protocol.acceptance_policy.expected_pass_count,
        ),
        (
            "finding_count",
            retained_count,
            protocol.acceptance_policy.expected_finding_count,
        ),
    ] {
        if actual != expected {
            refusals.push(refusal(
                CampaignRefusalCode::InconsistentCount,
                &protocol.campaign_id,
                format!("pre-registered {label} is {expected}, derived {actual}"),
            ));
        }
    }
    if closure.case_count != protocol.completion_expectations.case_count
        || closure.receipt_count != protocol.completion_expectations.receipt_count
        || closure.raw_evidence_count != protocol.completion_expectations.raw_evidence_count
        || closure.closure_status != protocol.completion_expectations.closure_status
        || closure.acceptance != protocol.completion_expectations.acceptance
    {
        refusals.push(refusal(
            CampaignRefusalCode::InconsistentCount,
            &protocol.campaign_id,
            "closure summary disagrees with the pre-registered completion expectations".to_owned(),
        ));
    }
    if closure.exclusions != protocol.permitted_exclusions {
        refusals.push(refusal(
            CampaignRefusalCode::UnauthorizedExclusion,
            &protocol.campaign_id,
            "closure exclusions disagree with the permitted exclusions".to_owned(),
        ));
    }
    if closure.receipts.len() != receipt_count {
        refusals.push(refusal(
            CampaignRefusalCode::TruncatedPopulation,
            &protocol.campaign_id,
            "closure receipt list is truncated".to_owned(),
        ));
    }
    if closure.receipts.len() < case_count {
        refusals.push(refusal(
            CampaignRefusalCode::TruncatedPopulation,
            &protocol.campaign_id,
            format!(
                "closure lists {} receipts for {case_count} declared cases",
                closure.receipts.len()
            ),
        ));
    }
    for reference in &closure.receipts {
        let Some((path, bytes, receipt)) = by_case.get(&reference.case_id) else {
            refusals.push(refusal(
                CampaignRefusalCode::MissingReceipt,
                &reference.case_id,
                "closure references a receipt that is absent".to_owned(),
            ));
            continue;
        };
        if reference.path != *path {
            refusals.push(refusal(
                CampaignRefusalCode::InconsistentCount,
                &reference.case_id,
                "closure receipt path disagrees with the loaded receipt".to_owned(),
            ));
        }
        if reference.sha256 != sha256_hex(bytes) {
            refusals.push(refusal(
                CampaignRefusalCode::DigestMismatch,
                &reference.case_id,
                "closure receipt digest disagrees with the receipt bytes".to_owned(),
            ));
        }
        if reference.outcome != receipt.observation.outcome {
            refusals.push(refusal(
                CampaignRefusalCode::InconsistentCount,
                &reference.case_id,
                "closure receipt outcome disagrees with the receipt".to_owned(),
            ));
        }
        if reference.decision != receipt.adjudication.decision {
            refusals.push(refusal(
                CampaignRefusalCode::InconsistentCount,
                &reference.case_id,
                "closure receipt decision disagrees with the receipt".to_owned(),
            ));
        }
    }

    let structural_codes = [
        CampaignRefusalCode::MissingReceipt,
        CampaignRefusalCode::DuplicateReceipt,
        CampaignRefusalCode::UnexpectedReceipt,
        CampaignRefusalCode::TruncatedPopulation,
        CampaignRefusalCode::InvalidPopulation,
        CampaignRefusalCode::UnauthorizedExclusion,
    ];
    let closed = !refusals
        .iter()
        .any(|item| structural_codes.contains(&item.code));
    let closure_status = if closed {
        ClosureStatus::Closed
    } else {
        ClosureStatus::Blocked
    };
    if closure.closure_status != closure_status {
        refusals.push(refusal(
            CampaignRefusalCode::InconsistentClosureStatus,
            &protocol.campaign_id,
            format!(
                "closure declares {}, derived {}",
                closure.closure_status.as_str(),
                closure_status.as_str()
            ),
        ));
    }

    let mandatory_unresolved = by_case.values().any(|(_, _, receipt)| {
        receipt.adjudication.mandatory_resolution
            && receipt.observation.outcome == TerminalOutcome::Unresolved
    });
    if mandatory_unresolved {
        for (case_id, (_, _, receipt)) in &by_case {
            if receipt.adjudication.mandatory_resolution
                && receipt.observation.outcome == TerminalOutcome::Unresolved
            {
                refusals.push(refusal(
                    CampaignRefusalCode::UnresolvedMandatoryObservation,
                    case_id,
                    "a case that required a resolved observation observed unresolved".to_owned(),
                ));
            }
        }
    }
    let has_failure = by_case.values().any(|(_, _, receipt)| {
        receipt.observation.outcome.is_failure() || receipt.observation.outcome.is_not_run()
    });
    let all_pass = by_case
        .values()
        .all(|(_, _, receipt)| receipt.adjudication.decision == CampaignDecision::Pass);
    let accepted = closed && all_pass && !mandatory_unresolved && !has_failure;
    let acceptance = if accepted {
        CampaignAcceptance::Accepted
    } else {
        CampaignAcceptance::Withheld
    };
    if closure.acceptance != acceptance {
        refusals.push(refusal(
            CampaignRefusalCode::InconsistentAcceptance,
            &protocol.campaign_id,
            format!(
                "closure declares acceptance {}, derived {}",
                closure.acceptance.as_str(),
                acceptance.as_str()
            ),
        ));
    }

    accepted_cases.sort();
    retained_findings.sort();
    retained_findings.dedup();

    let status = if !closed
        || refusals.iter().any(|item| {
            matches!(
                item.code,
                CampaignRefusalCode::OpeningDigestMismatch
                    | CampaignRefusalCode::CandidateFileMismatch
                    | CampaignRefusalCode::InstrumentFileMismatch
                    | CampaignRefusalCode::InconsistentCount
                    | CampaignRefusalCode::InconsistentClosureStatus
                    | CampaignRefusalCode::InconsistentAcceptance
                    | CampaignRefusalCode::DigestMismatch
                    | CampaignRefusalCode::MissingRawEvidence
                    | CampaignRefusalCode::UnexpectedRawEvidence
                    | CampaignRefusalCode::InvalidRawEvidence
                    | CampaignRefusalCode::WrongCandidate
                    | CampaignRefusalCode::WrongInstrument
                    | CampaignRefusalCode::UnknownClaim
                    | CampaignRefusalCode::UnauthorizedSuppression
                    | CampaignRefusalCode::InconsistentAdjudication
            )
        }) {
        CampaignStatus::Refused
    } else if acceptance == CampaignAcceptance::Accepted {
        CampaignStatus::Accepted
    } else {
        CampaignStatus::Withheld
    };

    Ok(CampaignReport {
        schema: CAMPAIGN_REPORT_SCHEMA.to_owned(),
        spec: CAMPAIGN_SPEC.to_owned(),
        campaign_id: protocol.campaign_id.clone(),
        status,
        closure_status,
        acceptance,
        opening_sha256,
        candidate_identity: protocol.candidate.tree_sha256.clone(),
        instrument_id: protocol.instrument.id.clone(),
        case_count,
        receipt_count,
        raw_evidence_count,
        outcomes,
        decisions,
        accepted_cases,
        retained_findings,
        refusals,
        claim_ceiling: CAMPAIGN_CLAIM_CEILING.to_owned(),
    })
}

/// Verify a campaign from its closure manifest path.
///
/// # Errors
///
/// Returns [`CampaignError`] for malformed or unreadable artifacts.
pub fn verify_campaign_file(path: &Path) -> Result<CampaignReport, CampaignError> {
    let bundle = load_bundle(path)?;
    verify_bundle(&bundle)
}

/// Summary returned by a native campaign run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignRunSummary {
    /// Campaign identifier.
    pub campaign_id: String,
    /// Declared case count.
    pub case_count: usize,
    /// Receipt count.
    pub receipt_count: usize,
    /// Raw evidence count.
    pub raw_evidence_count: usize,
    /// Derived closure status.
    pub closure_status: ClosureStatus,
    /// Derived acceptance.
    pub acceptance: CampaignAcceptance,
    /// Closure manifest SHA-256.
    pub closure_sha256: String,
}

#[cfg(all(unix, feature = "native-harness"))]
mod live {
    use super::{
        canonical_json, counts_from, derive_decision, derive_release, derive_resolution,
        find_repo_root, instrument_execution_identity, parse_protocol, receipt_findings,
        sha256_hex, CampaignAcceptance, CampaignAdjudication, CampaignCase, CampaignClosure,
        CampaignError, CampaignEvidence, CampaignExecution, CampaignObservation, CampaignProtocol,
        CampaignReceipt, CampaignReceiptRef, CampaignRunSummary, CampaignSuppression,
        ClosureStatus, TerminalOutcome, CAMPAIGN_CLAIM_CEILING, CAMPAIGN_CLOSURE_SCHEMA,
        CAMPAIGN_RECEIPT_SCHEMA, CAMPAIGN_SPEC,
    };
    use crate::native::{self, NativeOutcome, ReplayStatus};
    use std::fs;
    use std::path::Path;

    fn map_outcome(outcome: NativeOutcome) -> TerminalOutcome {
        match outcome {
            NativeOutcome::VerifiedCompatibleWithinTranscript => {
                TerminalOutcome::VerifiedCompatibleWithinTranscript
            }
            NativeOutcome::ObservedViolation => TerminalOutcome::ObservedViolation,
            NativeOutcome::IncompleteTranscript => TerminalOutcome::IncompleteTranscript,
            NativeOutcome::Unresolved => TerminalOutcome::Unresolved,
            NativeOutcome::IllegalCase => TerminalOutcome::IllegalCase,
            NativeOutcome::NotRun => TerminalOutcome::NotRun,
            NativeOutcome::HarnessFailure => TerminalOutcome::HarnessFailure,
        }
    }

    fn replay_parts(status: &ReplayStatus) -> (String, String, String) {
        match status {
            ReplayStatus::Identical {
                first_sha256,
                second_sha256,
            } => (
                "identical".to_owned(),
                first_sha256.clone(),
                second_sha256.clone(),
            ),
            ReplayStatus::Mismatch {
                first_sha256,
                second_sha256,
            } => (
                "mismatch".to_owned(),
                first_sha256.clone(),
                second_sha256.clone(),
            ),
            ReplayStatus::NotPerformed => {
                ("not_performed".to_owned(), String::new(), String::new())
            }
        }
    }

    fn write_bytes(path: &Path, bytes: &[u8]) -> Result<(), CampaignError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| CampaignError::Io {
                message: format!("cannot create {}: {error}", parent.display()),
            })?;
        }
        fs::write(path, bytes).map_err(|error| CampaignError::Io {
            message: format!("cannot write {}: {error}", path.display()),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::type_complexity,
        clippy::too_many_lines
    )]
    fn case_receipt(
        protocol: &CampaignProtocol,
        case: &CampaignCase,
        record: &native::NativeRecord,
        command: &[String],
        environment: &str,
        image_id: &str,
        root: &Path,
        out_dir: &Path,
    ) -> Result<(CampaignReceipt, Vec<(String, Vec<u8>)>), CampaignError> {
        let fixture_sha256 = super::file_sha256(&root.join(&case.fixture))?;
        let mut evidence = Vec::new();
        let mut raw_files = Vec::new();
        if let Some(transcript) = &record.transcript {
            let bytes = canonical_json(transcript)?;
            let path = format!("receipts/raw/{}.transcript.json", case.id);
            write_bytes(&out_dir.join(&path), &bytes)?;
            raw_files.push((path.clone(), bytes.clone()));
            evidence.push(CampaignEvidence {
                kind: "transcript".to_owned(),
                path,
                sha256: sha256_hex(&bytes),
            });
        }
        if let Some(report) = &record.report {
            let bytes = report
                .canonical_bytes()
                .map_err(|error| CampaignError::Canonical {
                    message: error.to_string(),
                })?;
            let path = format!("receipts/raw/{}.court.json", case.id);
            write_bytes(&out_dir.join(&path), &bytes)?;
            raw_files.push((path.clone(), bytes.clone()));
            evidence.push(CampaignEvidence {
                kind: "court_report".to_owned(),
                path,
                sha256: sha256_hex(&bytes),
            });
        }
        if record.transcript.is_none() {
            let bytes = record.detail.as_bytes().to_vec();
            let path = format!("receipts/raw/{}.detail.txt", case.id);
            write_bytes(&out_dir.join(&path), &bytes)?;
            raw_files.push((path.clone(), bytes.clone()));
            evidence.push(CampaignEvidence {
                kind: "harness_detail".to_owned(),
                path,
                sha256: sha256_hex(&bytes),
            });
        }

        let (replay, replay_first, replay_second) = replay_parts(&record.replay);
        let tool_versions = record
            .provenance
            .as_ref()
            .map(|provenance| {
                provenance
                    .library_versions
                    .iter()
                    .map(|library| format!("{} {}", library.name, library.version))
                    .collect()
            })
            .unwrap_or_default();
        let execution = CampaignExecution {
            command: command.to_vec(),
            environment: environment.to_owned(),
            image_id: image_id.to_owned(),
            native_harness: native::native_harness_enabled(),
            replay,
            replay_first_sha256: replay_first,
            replay_second_sha256: replay_second,
            tool_versions,
            executable_sha256: record.executable_sha256.clone().unwrap_or_default(),
            fixture_path: case.fixture.clone(),
            fixture_sha256,
        };
        let outcome = map_outcome(record.outcome);
        let findings = receipt_findings(record.report.as_ref());
        let observation = CampaignObservation {
            outcome,
            court_outcome: record
                .report
                .as_ref()
                .map(|report| report.outcome.as_str().to_owned())
                .unwrap_or_default(),
            event_count: record
                .report
                .as_ref()
                .map_or(0, |report| report.event_count),
            findings,
            race_witnesses: record
                .report
                .as_ref()
                .map_or(0, |report| report.race_witnesses.len()),
            detail: record.detail.clone(),
        };
        let decision = derive_decision(case.expected_outcome, outcome);
        let adjudication = CampaignAdjudication {
            expected_outcome: case.expected_outcome,
            observed_outcome: outcome,
            decision,
            mandatory_resolution: case.mandatory_resolution,
            resolution: derive_resolution(outcome),
        };
        let release_decision = derive_release(outcome, decision);
        let instrument_execution_identity =
            instrument_execution_identity(&protocol.instrument.id, &execution);
        Ok((
            CampaignReceipt {
                schema: CAMPAIGN_RECEIPT_SCHEMA.to_owned(),
                spec: CAMPAIGN_SPEC.to_owned(),
                campaign_id: protocol.campaign_id.clone(),
                case_id: case.id.clone(),
                candidate_identity: protocol.candidate.tree_sha256.clone(),
                instrument_id: protocol.instrument.id.clone(),
                instrument_execution_identity,
                requirement: case.requirement.clone(),
                obligations: case.obligations.clone(),
                claim: protocol
                    .claims
                    .first()
                    .map_or_else(String::new, |claim| claim.id.clone()),
                execution,
                observation,
                adjudication,
                release_decision,
                evidence,
                suppression: CampaignSuppression {
                    suppressed: false,
                    justification: String::new(),
                    scope: String::new(),
                    owner: String::new(),
                    expiry: String::new(),
                    invalidation: String::new(),
                },
            },
            raw_files,
        ))
    }

    /// Run the declared native campaign and write receipts plus a closure
    /// manifest.
    ///
    /// The opening inventory is read, its candidate and instrument files are
    /// checked, and then every declared case is executed exactly once through
    /// the closed native harness. A disabled harness produces a retained typed
    /// `NOT_RUN` receipt, never a pass.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignError`] for malformed input, a changed candidate or
    /// instrument, or an I/O failure.
    #[allow(clippy::too_many_lines)]
    pub fn run_campaign(
        protocol_path: &Path,
        out_dir: &Path,
    ) -> Result<CampaignRunSummary, CampaignError> {
        let protocol_bytes = fs::read(protocol_path).map_err(|error| CampaignError::Io {
            message: format!("cannot read {}: {error}", protocol_path.display()),
        })?;
        let protocol = parse_protocol(&protocol_bytes)?;
        let root = find_repo_root(protocol_path.parent().unwrap_or_else(|| Path::new(".")));
        for file in &protocol.candidate.files {
            let actual = super::file_sha256(&root.join(&file.path))?;
            if actual != file.sha256 {
                return Err(CampaignError::Invalid {
                    message: format!("candidate file {} changed", file.path),
                });
            }
        }
        for file in &protocol.instrument.files {
            let actual = super::file_sha256(&root.join(&file.path))?;
            if actual != file.sha256 {
                return Err(CampaignError::Invalid {
                    message: format!("instrument file {} changed", file.path),
                });
            }
        }
        let command: Vec<String> = std::env::args().collect();
        let environment =
            std::env::var("FRF_ETP_ENVIRONMENT").unwrap_or_else(|_| "unknown".to_owned());
        let image_id = std::env::var("FRF_ETP_IMAGE_ID").unwrap_or_else(|_| "unknown".to_owned());

        fs::create_dir_all(out_dir.join("receipts/raw")).map_err(|error| CampaignError::Io {
            message: format!("cannot create {}: {error}", out_dir.display()),
        })?;
        write_bytes(&out_dir.join("protocol.json"), &protocol_bytes)?;
        write_bytes(
            &out_dir.join("opening.sha256"),
            format!("{}  protocol.json\n", sha256_hex(&protocol_bytes)).as_bytes(),
        )?;

        let mut references = Vec::new();
        let mut outcomes = Vec::new();
        let mut decisions = Vec::new();
        for case in &protocol.population {
            let record = native::record_case(&case.id);
            let (receipt, _raw_files) = case_receipt(
                &protocol,
                case,
                &record,
                &command,
                &environment,
                &image_id,
                &root,
                out_dir,
            )?;
            let bytes = canonical_json(&receipt)?;
            let path = format!("receipts/{}.json", case.id);
            write_bytes(&out_dir.join(&path), &bytes)?;
            references.push(CampaignReceiptRef {
                case_id: case.id.clone(),
                path,
                sha256: sha256_hex(&bytes),
                outcome: receipt.observation.outcome,
                decision: receipt.adjudication.decision,
            });
            outcomes.push(receipt.observation.outcome.as_str());
            decisions.push(receipt.adjudication.decision.as_str());
        }
        references.sort_by(|left, right| left.case_id.cmp(&right.case_id));
        let raw_evidence_count = fs::read_dir(out_dir.join("receipts/raw"))
            .map_err(|error| CampaignError::Io {
                message: format!("cannot read raw evidence directory: {error}"),
            })?
            .count();
        let outcomes = counts_from(outcomes.into_iter());
        let decisions = counts_from(decisions.into_iter());
        let all_pass = references
            .iter()
            .all(|reference| reference.decision == super::CampaignDecision::Pass);
        let has_failure = references
            .iter()
            .any(|reference| reference.outcome.is_failure() || reference.outcome.is_not_run());
        let acceptance = if all_pass && !has_failure {
            CampaignAcceptance::Accepted
        } else {
            CampaignAcceptance::Withheld
        };
        let closure = CampaignClosure {
            schema: CAMPAIGN_CLOSURE_SCHEMA.to_owned(),
            spec: CAMPAIGN_SPEC.to_owned(),
            campaign_id: protocol.campaign_id.clone(),
            opening_manifest_path: protocol_path.file_name().map_or_else(
                || "protocol.json".to_owned(),
                |name| name.to_string_lossy().into_owned(),
            ),
            opening_sha256: sha256_hex(&protocol_bytes),
            candidate_identity: protocol.candidate.tree_sha256.clone(),
            instrument_id: protocol.instrument.id.clone(),
            case_count: protocol.population.len(),
            receipt_count: references.len(),
            raw_evidence_count,
            outcomes,
            decisions,
            receipts: references,
            exclusions: protocol.permitted_exclusions.clone(),
            closure_status: ClosureStatus::Closed,
            acceptance,
            closure_reasons: if acceptance == CampaignAcceptance::Accepted {
                vec!["every declared case matched its pre-registered terminal outcome".to_owned()]
            } else {
                vec!["one or more declared cases did not match or did not resolve".to_owned()]
            },
            claim_ceiling: CAMPAIGN_CLAIM_CEILING.to_owned(),
        };
        let closure_bytes = canonical_json(&closure)?;
        write_bytes(&out_dir.join("MANIFEST.json"), &closure_bytes)?;
        Ok(CampaignRunSummary {
            campaign_id: protocol.campaign_id,
            case_count: closure.case_count,
            receipt_count: closure.receipt_count,
            raw_evidence_count: closure.raw_evidence_count,
            closure_status: closure.closure_status,
            acceptance: closure.acceptance,
            closure_sha256: sha256_hex(&closure_bytes),
        })
    }
}

#[cfg(all(unix, feature = "native-harness"))]
pub use live::run_campaign;

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, sha: &str) -> CandidateFile {
        CandidateFile {
            path: path.to_owned(),
            sha256: sha.to_owned(),
        }
    }

    #[test]
    fn tree_digest_is_order_independent_and_binds_paths_and_digests() {
        let left = vec![file("b", "2"), file("a", "1")];
        let right = vec![file("a", "1"), file("b", "2")];
        assert_eq!(tree_sha256(&left), tree_sha256(&right));
        let changed = vec![file("a", "1"), file("b", "3")];
        assert_ne!(tree_sha256(&left), tree_sha256(&changed));
    }

    #[test]
    fn not_run_is_never_a_pass() {
        assert_eq!(
            derive_decision(
                TerminalOutcome::VerifiedCompatibleWithinTranscript,
                TerminalOutcome::NotRun
            ),
            CampaignDecision::NotRun
        );
        assert_eq!(
            derive_release(TerminalOutcome::NotRun, CampaignDecision::NotRun),
            ReleaseDecision::Blocked
        );
    }

    #[test]
    fn unresolved_expected_case_is_retained_but_not_clean() {
        assert_eq!(
            derive_decision(TerminalOutcome::Unresolved, TerminalOutcome::Unresolved),
            CampaignDecision::Pass
        );
        assert_eq!(
            derive_release(TerminalOutcome::Unresolved, CampaignDecision::Pass),
            ReleaseDecision::Withheld
        );
        assert_eq!(
            derive_resolution(TerminalOutcome::Unresolved),
            ObservationResolution::Unresolved
        );
    }
}
