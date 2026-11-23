#![allow(clippy::module_name_repetitions)]

//! Phase 10.3 authenticated evidence: DSSE v1 envelopes, in-toto Statement v1
//! predicates, a versioned ETP trust policy, and separate verification
//! dimensions.
//!
//! # What this module establishes
//!
//! A successful verification establishes only that a declared signer authorized
//! by a declared trust policy signed the exact received payload bytes and that
//! the payload's predicate agrees with the referenced finite campaign closure.
//! It does **not** establish that the signed statement is true, that the signer
//! was independent, that a transparency log includes the envelope, that time is
//! trusted, or that the campaign generalizes beyond its finite population.
//!
//! # Hardening rules
//!
//! * Signed bytes are never parsed and reserialized before signature
//!   verification. The pre-authentication encoding is computed over the exact
//!   decoded payload bytes received in the envelope.
//! * Only Ed25519 is accepted in the `v1` profile. An unknown algorithm, an
//!   unknown `keyid`, or a signature that is not exactly 64 bytes is refused.
//! * `keyid` is a lookup hint only. Authorization comes from the policy role,
//!   scope, actor, and validity window of the resolved public key.
//! * Duplicate JSON keys, floating-point numbers, excessive nesting, oversized
//!   payloads, an excessive signature count, and duplicate `keyid` entries are
//!   rejected before any signature is treated as meaningful.
//! * Distinct signatures by the same actor are not independent reviewers.
//!   Duplicate credentials never satisfy an independent-role threshold.
//!
//! # Non-claims
//!
//! A signature is not truth. Authentication is not independent review.
//! Inclusion is not completeness. Trusted timestamps and transparency logs are
//! out of scope for this subphase.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::etp::ETP_SPEC;
use crate::etp_campaign::{
    load_bundle, parse_protocol, sha256_hex, verify_bundle, CampaignBundle, CampaignCase,
    CampaignReport, CampaignStatus, ClosureStatus,
};
use crate::identity::{canonical_bytes, hex_lower, parse_strict, IdentityError};

/// DSSE envelope profile identifier used by the ETP authenticated-evidence layer.
pub const DSSE_PROFILE: &str = "dsse-v1";
/// The only payload type accepted by the ETP `v1` profile.
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
/// in-toto Statement v1 type.
pub const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// Versioned trust-policy schema identifier.
pub const TRUST_POLICY_SCHEMA: &str = "frf-etp.trust-policy.v1";
/// Versioned attestation-verification report schema identifier.
pub const ATTESTATION_REPORT_SCHEMA: &str = "frf-etp.attestation-verification.v1";

/// Predicate type for a finite campaign closure.
pub const PREDICATE_TYPE_CAMPAIGN_CLOSURE: &str = "https://frf.dev/etp/campaign-closure/v1";
/// Predicate type for instrument qualification.
pub const PREDICATE_TYPE_INSTRUMENT_QUALIFICATION: &str =
    "https://frf.dev/etp/instrument-qualification/v1";
/// Predicate type for reproduction.
pub const PREDICATE_TYPE_REPRODUCTION: &str = "https://frf.dev/etp/reproduction/v1";
/// Predicate type for proof admission.
pub const PREDICATE_TYPE_PROOF_ADMISSION: &str = "https://frf.dev/etp/proof-admission/v1";
/// Predicate type for consumer closure.
pub const PREDICATE_TYPE_CONSUMER_CLOSURE: &str = "https://frf.dev/etp/consumer-closure/v1";
/// Predicate type for retained security findings.
pub const PREDICATE_TYPE_SECURITY_FINDINGS: &str = "https://frf.dev/etp/security-findings/v1";
/// Predicate type for release adjudication.
pub const PREDICATE_TYPE_RELEASE_ADJUDICATION: &str = "https://frf.dev/etp/release-adjudication/v1";

/// Predicate schema for a finite campaign closure.
pub const PREDICATE_SCHEMA_CAMPAIGN_CLOSURE: &str = "frf-etp.predicate.campaign-closure.v1";
/// Predicate schema for instrument qualification.
pub const PREDICATE_SCHEMA_INSTRUMENT_QUALIFICATION: &str =
    "frf-etp.predicate.instrument-qualification.v1";
/// Predicate schema for reproduction.
pub const PREDICATE_SCHEMA_REPRODUCTION: &str = "frf-etp.predicate.reproduction.v1";
/// Predicate schema for proof admission.
pub const PREDICATE_SCHEMA_PROOF_ADMISSION: &str = "frf-etp.predicate.proof-admission.v1";
/// Predicate schema for consumer closure.
pub const PREDICATE_SCHEMA_CONSUMER_CLOSURE: &str = "frf-etp.predicate.consumer-closure.v1";
/// Predicate schema for retained security findings.
pub const PREDICATE_SCHEMA_SECURITY_FINDINGS: &str = "frf-etp.predicate.security-findings.v1";
/// Predicate schema for release adjudication.
pub const PREDICATE_SCHEMA_RELEASE_ADJUDICATION: &str = "frf-etp.predicate.release-adjudication.v1";

/// Role identifier for the evidence producer.
pub const ROLE_EVIDENCE_PRODUCER: &str = "evidence_producer";
/// Role identifier for the instrument qualifier.
pub const ROLE_INSTRUMENT_QUALIFIER: &str = "instrument_qualifier";
/// Role identifier for an adjudicator.
pub const ROLE_ADJUDICATOR: &str = "adjudicator";
/// Role identifier for the release authority.
pub const ROLE_RELEASE_AUTHORITY: &str = "release_authority";
/// Role identifier for the correction and revocation authority.
pub const ROLE_CORRECTION_AUTHORITY: &str = "correction_authority";

/// Maximum signatures accepted in one envelope.
pub const MAX_SIGNATURES: usize = 16;
/// Maximum decoded payload bytes accepted by this profile.
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Maximum `keyid` bytes.
pub const MAX_KEYID_BYTES: usize = 256;
/// Maximum roles in one trust policy.
pub const MAX_ROLES: usize = 16;
/// Maximum keys across all roles in one trust policy.
pub const MAX_POLICY_KEYS: usize = 64;
/// Maximum subject entries in one in-toto statement.
pub const MAX_SUBJECTS: usize = 16;

/// Claim ceiling embedded in every verification report.
pub const ATTESTATION_CLAIM_CEILING: &str = "An accepted attestation establishes only that a declared signer authorized by a declared trust policy signed the exact received payload bytes and that the payload predicate agrees with the referenced finite campaign closure. A signature is not truth. Authentication is not independent review. Inclusion is not completeness. No transparency log, trusted timestamp, revocation registry, or independent reviewer is consulted.";

/// One profile predicate type and its required producing role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateKind {
    /// A finite campaign closure.
    CampaignClosure,
    /// Instrument qualification.
    InstrumentQualification,
    /// Reproduction of a finite result.
    Reproduction,
    /// Proof admission.
    ProofAdmission,
    /// Consumer closure.
    ConsumerClosure,
    /// Retained security findings.
    SecurityFindings,
    /// Release adjudication.
    ReleaseAdjudication,
}

impl PredicateKind {
    /// Every supported predicate kind.
    pub const ALL: [Self; 7] = [
        Self::CampaignClosure,
        Self::InstrumentQualification,
        Self::Reproduction,
        Self::ProofAdmission,
        Self::ConsumerClosure,
        Self::SecurityFindings,
        Self::ReleaseAdjudication,
    ];

    /// The in-toto predicate type URI.
    #[must_use]
    pub const fn predicate_type(self) -> &'static str {
        match self {
            Self::CampaignClosure => PREDICATE_TYPE_CAMPAIGN_CLOSURE,
            Self::InstrumentQualification => PREDICATE_TYPE_INSTRUMENT_QUALIFICATION,
            Self::Reproduction => PREDICATE_TYPE_REPRODUCTION,
            Self::ProofAdmission => PREDICATE_TYPE_PROOF_ADMISSION,
            Self::ConsumerClosure => PREDICATE_TYPE_CONSUMER_CLOSURE,
            Self::SecurityFindings => PREDICATE_TYPE_SECURITY_FINDINGS,
            Self::ReleaseAdjudication => PREDICATE_TYPE_RELEASE_ADJUDICATION,
        }
    }

    /// The separately versioned ETP predicate schema.
    #[must_use]
    pub const fn schema(self) -> &'static str {
        match self {
            Self::CampaignClosure => PREDICATE_SCHEMA_CAMPAIGN_CLOSURE,
            Self::InstrumentQualification => PREDICATE_SCHEMA_INSTRUMENT_QUALIFICATION,
            Self::Reproduction => PREDICATE_SCHEMA_REPRODUCTION,
            Self::ProofAdmission => PREDICATE_SCHEMA_PROOF_ADMISSION,
            Self::ConsumerClosure => PREDICATE_SCHEMA_CONSUMER_CLOSURE,
            Self::SecurityFindings => PREDICATE_SCHEMA_SECURITY_FINDINGS,
            Self::ReleaseAdjudication => PREDICATE_SCHEMA_RELEASE_ADJUDICATION,
        }
    }

    /// The role that must authorize this predicate.
    #[must_use]
    pub const fn required_role(self) -> &'static str {
        match self {
            Self::CampaignClosure | Self::ConsumerClosure | Self::SecurityFindings => {
                ROLE_EVIDENCE_PRODUCER
            }
            Self::InstrumentQualification | Self::Reproduction => ROLE_INSTRUMENT_QUALIFIER,
            Self::ProofAdmission => ROLE_ADJUDICATOR,
            Self::ReleaseAdjudication => ROLE_RELEASE_AUTHORITY,
        }
    }

    /// Resolve a predicate type URI.
    #[must_use]
    pub fn from_predicate_type(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.predicate_type() == value)
    }

    /// Resolve a predicate schema identifier.
    #[must_use]
    pub fn from_schema(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.schema() == value)
    }
}

/// A DSSE v1 signature entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseSignatureEnvelope {
    /// Lookup hint for the signing key. Not an authorization statement.
    pub keyid: String,
    /// Base64-encoded Ed25519 signature over the PAE bytes.
    pub sig: String,
}

/// A DSSE v1 envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseEnvelope {
    /// Media type of the payload.
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Base64-encoded exact payload bytes.
    pub payload: String,
    /// One or more signatures.
    pub signatures: Vec<DsseSignatureEnvelope>,
}

impl DsseEnvelope {
    /// Encode the envelope as canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns [`EtpAuthError::Canonical`] when the value cannot be encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EtpAuthError> {
        let value = serde_json::to_value(self).map_err(|error| EtpAuthError::Canonical {
            message: error.to_string(),
        })?;
        canonical_bytes(&value).map_err(|error| EtpAuthError::Canonical {
            message: error.to_string(),
        })
    }
}

/// One in-toto subject.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatementSubject {
    /// Subject name.
    pub name: String,
    /// Digest map. The `v1` profile accepts only `sha256`.
    pub digest: BTreeMap<String, String>,
}

/// An in-toto Statement v1.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InTotoStatement {
    /// Exact in-toto Statement v1 type.
    #[serde(rename = "_type")]
    pub statement_type: String,
    /// Bound subjects.
    pub subject: Vec<StatementSubject>,
    /// Predicate type URI.
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// Predicate body.
    pub predicate: Value,
}

/// One labelled count in a predicate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredicateCount {
    /// Label.
    pub label: String,
    /// Count.
    pub count: u64,
}

/// The fully bound campaign-closure predicate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignClosurePredicate {
    /// Predicate schema identifier.
    pub schema: String,
    /// ETP protocol specification.
    pub spec: String,
    /// Campaign identifier.
    pub campaign_id: String,
    /// SHA-256 of the exact closure manifest bytes.
    pub closure_sha256: String,
    /// Candidate tree identity.
    pub candidate_identity: String,
    /// SHA-256 over the sorted receipt and raw-evidence digests.
    pub raw_evidence_sha256: String,
    /// Declared case count.
    pub case_count: u64,
    /// Declared receipt count.
    pub receipt_count: u64,
    /// Declared raw-evidence count.
    pub raw_evidence_count: u64,
    /// Exact declared case identifiers.
    pub case_ids: Vec<String>,
    /// Declared terminal-outcome counts.
    pub outcomes: Vec<PredicateCount>,
    /// Declared decision counts.
    pub decisions: Vec<PredicateCount>,
    /// Declared closure status.
    pub closure_status: String,
    /// Declared acceptance.
    pub acceptance: String,
    /// Declared conclusion. Must equal the derived conclusion.
    pub conclusion: String,
    /// Independent-review claim. `established` requires distinct authorized
    /// actors meeting the policy threshold.
    pub independent_review: String,
    /// The claim ceiling carried by the statement.
    pub claim_ceiling: String,
}

/// A generic predicate for the other versioned ETP predicate types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericEtpPredicate {
    /// Predicate schema identifier.
    pub schema: String,
    /// ETP protocol specification.
    pub spec: String,
    /// SHA-256 of the bound subject evidence.
    pub subject_digest: String,
    /// Declared conclusion.
    pub conclusion: String,
    /// Independent-review claim.
    pub independent_review: String,
    /// The claim ceiling carried by the statement.
    pub claim_ceiling: String,
}

/// One authorized public key in a trust policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedKey {
    /// Lookup hint. Unique across the policy.
    pub keyid: String,
    /// Signing algorithm. Only `ed25519` is supported in `v1`.
    pub algorithm: String,
    /// Base64-encoded 32-byte Ed25519 public key.
    pub public_key_base64: String,
    /// Declared actor identity. Two keys by the same actor are not independent.
    pub actor: String,
    /// Key validity start, seconds since the Unix epoch.
    pub not_before_unix: u64,
    /// Key validity end, seconds since the Unix epoch.
    pub not_after_unix: u64,
}

/// One role in a trust policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRole {
    /// Role identifier.
    pub id: String,
    /// Distinct actors required to satisfy the role.
    pub threshold: u32,
    /// Whether the role is an independent-review role.
    pub independent: bool,
    /// Predicate types this role may authorize.
    pub scope: Vec<String>,
    /// Authorized keys for this role.
    pub keys: Vec<AuthorizedKey>,
}

/// A versioned ETP trust policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    /// Policy schema identifier.
    pub schema: String,
    /// ETP protocol specification.
    pub spec: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Monotonic policy version.
    pub version: u32,
    /// Policy validity start, seconds since the Unix epoch.
    pub issued_at_unix: u64,
    /// Policy expiry, seconds since the Unix epoch.
    pub expires_at_unix: u64,
    /// Declared roles.
    pub roles: Vec<TrustRole>,
}

impl TrustPolicy {
    /// Resolve a `keyid` to its role and key.
    #[must_use]
    pub fn resolve(&self, keyid: &str) -> Option<(&TrustRole, &AuthorizedKey)> {
        for role in &self.roles {
            if let Some(key) = role.keys.iter().find(|key| key.keyid == keyid) {
                return Some((role, key));
            }
        }
        None
    }

    /// Resolve a role by identifier.
    #[must_use]
    pub fn role(&self, id: &str) -> Option<&TrustRole> {
        self.roles.iter().find(|role| role.id == id)
    }
}

/// One separate verification dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DimensionState {
    /// The dimension was checked and holds.
    Valid,
    /// The dimension was checked and does not hold.
    Invalid,
    /// Some checked items hold and some do not.
    Partial,
    /// The dimension could not be evaluated from the supplied inputs.
    NotChecked,
    /// The dimension does not apply to this predicate.
    NotApplicable,
}

impl DimensionState {
    /// Stable text label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Partial => "partial",
            Self::NotChecked => "not_checked",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// Independent-review status. This is never inferred from signature count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndependentReviewState {
    /// The policy's independent threshold is met by distinct actors.
    Established,
    /// No independent-review role exists or its threshold is not met.
    NotEstablished,
    /// The statement claims independence but the policy threshold is not met.
    Insufficient,
    /// The dimension could not be evaluated.
    NotChecked,
}

impl IndependentReviewState {
    /// Stable text label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Established => "established",
            Self::NotEstablished => "not_established",
            Self::Insufficient => "insufficient",
            Self::NotChecked => "not_checked",
        }
    }
}

/// The seven separate verification dimensions.
#[derive(Debug, Clone, Serialize)]
pub struct AttestationDimensions {
    /// Whether at least one signature verified over the exact PAE bytes.
    pub signature_validity: DimensionState,
    /// Whether the envelope and payload decoded and parsed under the profile.
    pub payload_integrity: DimensionState,
    /// Whether an authorized, fresh, in-scope key satisfied the required role.
    pub authorization: DimensionState,
    /// Whether the predicate binds the declared campaign and subject.
    pub scope_applicability: DimensionState,
    /// Whether the policy and used keys are within their validity windows.
    pub freshness: DimensionState,
    /// Whether the predicate agrees with the recomputed finite campaign.
    pub semantic_support: DimensionState,
    /// Independent-review status. Not inferred from signature count.
    pub independent_review: IndependentReviewState,
}

/// One per-signature result.
#[derive(Debug, Clone, Serialize)]
pub struct SignatureReport {
    /// Declared `keyid`.
    pub keyid: String,
    /// Policy actor, when the `keyid` resolved.
    pub actor: Option<String>,
    /// Policy roles for the resolved key.
    pub roles: Vec<String>,
    /// Whether the Ed25519 signature verified over the exact PAE bytes.
    pub valid: bool,
    /// Explanation. Never a confidence value.
    pub detail: String,
}

/// One refusal code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationRefusalCode {
    /// A signature did not verify.
    InvalidSignature,
    /// The `keyid` is not present in the trust policy.
    UnknownKey,
    /// The resolved key names an unsupported signature algorithm.
    UnsupportedAlgorithm,
    /// The policy or a key is outside its validity window.
    ExpiredCredential,
    /// No valid signature belongs to the required role and scope.
    UnauthorizedRole,
    /// The predicate scope does not bind the supplied campaign.
    ScopeMismatch,
    /// A subject digest does not match the expected evidence.
    SubjectMismatch,
    /// The statement refers to a different campaign.
    CampaignMismatch,
    /// The candidate identity does not match the campaign closure.
    CandidateMismatch,
    /// The raw-evidence digest does not match.
    EvidenceMismatch,
    /// A declared count disagrees with the recomputed campaign.
    CountMismatch,
    /// A declared outcome or decision disagrees.
    OutcomeMismatch,
    /// A declared case identifier is missing or unexpected.
    PopulationMismatch,
    /// The declared conclusion is not the derived conclusion.
    FalseConclusion,
    /// The referenced campaign did not close.
    CampaignNotClosed,
    /// The statement claims independent review that is not established.
    InsufficientIndependentReview,
    /// A predicate schema or specification version is unsupported.
    UnsupportedSchemaVersion,
    /// The predicate type is unsupported.
    UnsupportedPredicateType,
    /// Semantic support could not be evaluated because no campaign was supplied.
    SemanticSupportNotEvaluated,
    /// The statement carries a weakened or altered claim ceiling.
    ClaimCeilingMismatch,
}

impl AttestationRefusalCode {
    /// Stable text label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidSignature => "invalid_signature",
            Self::UnknownKey => "unknown_key",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::ExpiredCredential => "expired_credential",
            Self::UnauthorizedRole => "unauthorized_role",
            Self::ScopeMismatch => "scope_mismatch",
            Self::SubjectMismatch => "subject_mismatch",
            Self::CampaignMismatch => "campaign_mismatch",
            Self::CandidateMismatch => "candidate_mismatch",
            Self::EvidenceMismatch => "evidence_mismatch",
            Self::CountMismatch => "count_mismatch",
            Self::OutcomeMismatch => "outcome_mismatch",
            Self::PopulationMismatch => "population_mismatch",
            Self::FalseConclusion => "false_conclusion",
            Self::CampaignNotClosed => "campaign_not_closed",
            Self::InsufficientIndependentReview => "insufficient_independent_review",
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::UnsupportedPredicateType => "unsupported_predicate_type",
            Self::SemanticSupportNotEvaluated => "semantic_support_not_evaluated",
            Self::ClaimCeilingMismatch => "claim_ceiling_mismatch",
        }
    }
}

/// One refusal with a detail string.
#[derive(Debug, Clone, Serialize)]
pub struct AttestationRefusal {
    /// Refusal code.
    pub code: AttestationRefusalCode,
    /// Detail.
    pub detail: String,
}

/// Overall attestation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    /// Every required dimension holds.
    Accepted,
    /// At least one required dimension does not hold.
    Refused,
}

impl AttestationStatus {
    /// Stable text label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Refused => "refused",
        }
    }
}

/// The canonical verification report.
#[derive(Debug, Clone, Serialize)]
pub struct AttestationReport {
    /// Report schema identifier.
    pub schema: String,
    /// ETP protocol specification.
    pub spec: String,
    /// Overall status.
    pub status: AttestationStatus,
    /// SHA-256 of the exact envelope bytes verified.
    pub envelope_sha256: String,
    /// SHA-256 of the exact decoded payload bytes.
    pub payload_sha256: String,
    /// Predicate type, when the payload parsed.
    pub predicate_type: String,
    /// Campaign identifier, when the predicate parsed.
    pub campaign_id: Option<String>,
    /// The seven separate dimensions.
    pub dimensions: AttestationDimensions,
    /// Per-signature results.
    pub signatures: Vec<SignatureReport>,
    /// Distinct actors that satisfied an independent-review role.
    pub independent_reviewers: usize,
    /// Refusals. Each is a named rule, never a score.
    pub refusals: Vec<AttestationRefusal>,
    /// Claim ceiling.
    pub claim_ceiling: String,
}

impl AttestationReport {
    /// Encode the report as canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns [`EtpAuthError::Canonical`] when the value cannot be encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EtpAuthError> {
        let value = serde_json::to_value(self).map_err(|error| EtpAuthError::Canonical {
            message: error.to_string(),
        })?;
        canonical_bytes(&value).map_err(|error| EtpAuthError::Canonical {
            message: error.to_string(),
        })
    }

    /// `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self.status {
            AttestationStatus::Accepted => 0,
            AttestationStatus::Refused => 4,
        }
    }
}

/// Errors produced while parsing or evaluating attestation artifacts.
#[derive(Debug, thiserror::Error)]
pub enum EtpAuthError {
    /// Strict JSON parsing failed.
    #[error("invalid attestation JSON: {0}")]
    Identity(#[from] IdentityError),
    /// A campaign artifact could not be loaded or reconciled.
    #[error(transparent)]
    Campaign(#[from] crate::etp_campaign::CampaignError),
    /// The artifact failed a structural rule.
    #[error("invalid attestation: {message}")]
    Invalid {
        /// Rule that failed.
        message: String,
    },
    /// The artifact names an unsupported profile or schema.
    #[error("unsupported attestation profile: {message}")]
    Unsupported {
        /// Detail.
        message: String,
    },
    /// A file could not be read.
    #[error("attestation I/O failure: {message}")]
    Io {
        /// Detail.
        message: String,
    },
    /// A report or policy could not be encoded canonically.
    #[error("cannot encode attestation artifact: {message}")]
    Canonical {
        /// Detail.
        message: String,
    },
}

impl EtpAuthError {
    /// Category used to choose a `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Identity(_)
            | Self::Invalid { .. }
            | Self::Unsupported { .. }
            | Self::Io { .. } => 3,
            Self::Campaign(error) => error.exit_code(),
            Self::Canonical { .. } => 7,
        }
    }
}

/// Compute the exact DSSE pre-authentication encoding.
///
/// The returned bytes are `DSSEv1 SP <len(type)> SP <type> SP <len(payload)> SP
/// <payload>`, where each length is the ASCII decimal byte length.
///
/// # Errors
///
/// Returns [`EtpAuthError::Invalid`] when the payload type is empty, contains
/// whitespace, or exceeds [`MAX_KEYID_BYTES`].
pub fn pae(payload_type: &str, payload: &[u8]) -> Result<Vec<u8>, EtpAuthError> {
    if payload_type.is_empty() {
        return Err(EtpAuthError::Invalid {
            message: "payloadType must not be empty".to_owned(),
        });
    }
    if payload_type.len() > MAX_KEYID_BYTES {
        return Err(EtpAuthError::Invalid {
            message: format!("payloadType exceeds {MAX_KEYID_BYTES} bytes"),
        });
    }
    if payload_type.chars().any(char::is_whitespace) {
        return Err(EtpAuthError::Invalid {
            message: "payloadType must not contain whitespace".to_owned(),
        });
    }
    let mut out = Vec::with_capacity(payload.len() + payload_type.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    Ok(out)
}

fn max_base64_len(decoded_len: usize) -> usize {
    decoded_len.div_ceil(3).saturating_mul(4).saturating_add(4)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_base64_canonical(label: &str, value: &str) -> Result<Vec<u8>, EtpAuthError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|error| EtpAuthError::Invalid {
            message: format!("{label} is not valid base64: {error}"),
        })?;
    if STANDARD.encode(&decoded) != value {
        return Err(EtpAuthError::Invalid {
            message: format!("{label} is not canonical padded base64"),
        });
    }
    Ok(decoded)
}

fn check_text(label: &str, value: &str, limit: usize) -> Result<(), EtpAuthError> {
    if value.trim().is_empty() {
        return Err(EtpAuthError::Invalid {
            message: format!("{label} must not be empty"),
        });
    }
    if value.len() > limit {
        return Err(EtpAuthError::Invalid {
            message: format!("{label} exceeds {limit} bytes"),
        });
    }
    Ok(())
}

/// Parse a DSSE envelope with strict JSON rules.
///
/// # Errors
///
/// Returns [`EtpAuthError`] for malformed JSON, duplicate keys, unknown fields,
/// an unsupported payload type, an excessive signature count, a duplicate
/// `keyid`, malformed base64, or an oversized payload.
pub fn parse_envelope(bytes: &[u8]) -> Result<DsseEnvelope, EtpAuthError> {
    parse_envelope_for(bytes, DSSE_PAYLOAD_TYPE)
}

/// Parse a DSSE envelope that must carry `expected_payload_type`.
///
/// This is the same strict parser as [`parse_envelope`] with an explicit
/// payload-type check. It is used by the Phase 10.4 revocation profile, which
/// signs a different payload type with the same DSSE v1 encoding.
///
/// # Errors
///
/// Returns [`EtpAuthError`] for malformed JSON, duplicate keys, unknown fields,
/// an unsupported payload type, an excessive signature count, a duplicate
/// `keyid`, malformed base64, or an oversized payload.
pub fn parse_envelope_for(
    bytes: &[u8],
    expected_payload_type: &str,
) -> Result<DsseEnvelope, EtpAuthError> {
    let value = parse_strict(bytes)?;
    let envelope: DsseEnvelope =
        serde_json::from_value(value).map_err(|error| EtpAuthError::Invalid {
            message: error.to_string(),
        })?;
    if envelope.payload_type != expected_payload_type {
        return Err(EtpAuthError::Unsupported {
            message: format!(
                "payloadType {:?} is not {expected_payload_type}",
                envelope.payload_type
            ),
        });
    }
    check_text(
        "payload",
        &envelope.payload,
        max_base64_len(MAX_PAYLOAD_BYTES),
    )?;
    if envelope.signatures.is_empty() {
        return Err(EtpAuthError::Invalid {
            message: "envelope has no signatures".to_owned(),
        });
    }
    if envelope.signatures.len() > MAX_SIGNATURES {
        return Err(EtpAuthError::Invalid {
            message: format!("envelope exceeds {MAX_SIGNATURES} signatures"),
        });
    }
    let mut keyids = BTreeSet::new();
    for signature in &envelope.signatures {
        check_text("signature keyid", &signature.keyid, MAX_KEYID_BYTES)?;
        if !keyids.insert(signature.keyid.as_str()) {
            return Err(EtpAuthError::Invalid {
                message: format!("duplicate signature keyid {:?}", signature.keyid),
            });
        }
        let decoded = decode_base64_canonical("signature", &signature.sig)?;
        if decoded.len() != 64 {
            return Err(EtpAuthError::Invalid {
                message: format!(
                    "signature for {:?} is {} bytes, expected 64",
                    signature.keyid,
                    decoded.len()
                ),
            });
        }
    }
    let payload = decode_base64_canonical("payload", &envelope.payload)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(EtpAuthError::Invalid {
            message: format!("decoded payload exceeds {MAX_PAYLOAD_BYTES} bytes"),
        });
    }
    Ok(envelope)
}

/// Parse an in-toto Statement v1 from exact payload bytes.
///
/// # Errors
///
/// Returns [`EtpAuthError`] for malformed JSON, duplicate keys, unknown fields,
/// an unsupported statement type, an empty or oversized subject list, or a
/// digest that is not a lowercase SHA-256.
pub fn parse_statement(payload: &[u8]) -> Result<InTotoStatement, EtpAuthError> {
    let value = parse_strict(payload)?;
    let statement: InTotoStatement =
        serde_json::from_value(value).map_err(|error| EtpAuthError::Invalid {
            message: error.to_string(),
        })?;
    if statement.statement_type != IN_TOTO_STATEMENT_TYPE {
        return Err(EtpAuthError::Unsupported {
            message: format!(
                "statement _type {:?} is not {IN_TOTO_STATEMENT_TYPE}",
                statement.statement_type
            ),
        });
    }
    if statement.subject.is_empty() {
        return Err(EtpAuthError::Invalid {
            message: "statement has no subject".to_owned(),
        });
    }
    if statement.subject.len() > MAX_SUBJECTS {
        return Err(EtpAuthError::Invalid {
            message: format!("statement exceeds {MAX_SUBJECTS} subjects"),
        });
    }
    for subject in &statement.subject {
        check_text("subject name", &subject.name, 4096)?;
        if subject.digest.is_empty() {
            return Err(EtpAuthError::Invalid {
                message: format!("subject {:?} has no digest", subject.name),
            });
        }
        for (algorithm, digest) in &subject.digest {
            if algorithm != "sha256" {
                return Err(EtpAuthError::Unsupported {
                    message: format!("subject digest algorithm {algorithm:?} is not sha256"),
                });
            }
            if !is_sha256_hex(digest) {
                return Err(EtpAuthError::Invalid {
                    message: format!(
                        "subject {:?} has a non-canonical sha256 digest",
                        subject.name
                    ),
                });
            }
        }
    }
    Ok(statement)
}

/// Parse a versioned ETP trust policy.
///
/// # Errors
///
/// Returns [`EtpAuthError`] for malformed JSON, duplicate keys, unknown fields,
/// an unsupported schema or specification, duplicate roles, keys, or public
/// keys, an unsupported algorithm or role, or an invalid validity window.
#[allow(clippy::too_many_lines)]
pub fn parse_policy(bytes: &[u8]) -> Result<TrustPolicy, EtpAuthError> {
    let value = parse_strict(bytes)?;
    let policy: TrustPolicy =
        serde_json::from_value(value).map_err(|error| EtpAuthError::Invalid {
            message: error.to_string(),
        })?;
    if policy.schema != TRUST_POLICY_SCHEMA {
        return Err(EtpAuthError::Unsupported {
            message: format!(
                "policy schema {:?} is not {TRUST_POLICY_SCHEMA}",
                policy.schema
            ),
        });
    }
    if policy.spec != ETP_SPEC {
        return Err(EtpAuthError::Unsupported {
            message: format!("policy spec {:?} is not {ETP_SPEC}", policy.spec),
        });
    }
    check_text("policy_id", &policy.policy_id, 4096)?;
    if policy.version == 0 {
        return Err(EtpAuthError::Invalid {
            message: "policy version must be positive".to_owned(),
        });
    }
    if policy.issued_at_unix >= policy.expires_at_unix {
        return Err(EtpAuthError::Invalid {
            message: "policy issued_at_unix must precede expires_at_unix".to_owned(),
        });
    }
    if policy.roles.is_empty() {
        return Err(EtpAuthError::Invalid {
            message: "policy has no roles".to_owned(),
        });
    }
    if policy.roles.len() > MAX_ROLES {
        return Err(EtpAuthError::Invalid {
            message: format!("policy exceeds {MAX_ROLES} roles"),
        });
    }
    let known_roles = [
        ROLE_EVIDENCE_PRODUCER,
        ROLE_INSTRUMENT_QUALIFIER,
        ROLE_ADJUDICATOR,
        ROLE_RELEASE_AUTHORITY,
        ROLE_CORRECTION_AUTHORITY,
    ];
    let mut role_ids = BTreeSet::new();
    let mut keyids = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    let mut key_count = 0_usize;
    for role in &policy.roles {
        if !known_roles.contains(&role.id.as_str()) {
            return Err(EtpAuthError::Unsupported {
                message: format!("unsupported role {:?}", role.id),
            });
        }
        if !role_ids.insert(role.id.as_str()) {
            return Err(EtpAuthError::Invalid {
                message: format!("duplicate role {:?}", role.id),
            });
        }
        if role.threshold == 0 {
            return Err(EtpAuthError::Invalid {
                message: format!("role {:?} has threshold 0", role.id),
            });
        }
        if role.scope.is_empty() {
            return Err(EtpAuthError::Invalid {
                message: format!("role {:?} has an empty scope", role.id),
            });
        }
        let mut scope = BTreeSet::new();
        for predicate_type in &role.scope {
            if PredicateKind::from_predicate_type(predicate_type).is_none() {
                return Err(EtpAuthError::Unsupported {
                    message: format!(
                        "role {:?} scope names unsupported predicate {predicate_type:?}",
                        role.id
                    ),
                });
            }
            if !scope.insert(predicate_type.as_str()) {
                return Err(EtpAuthError::Invalid {
                    message: format!("role {:?} repeats a scope entry", role.id),
                });
            }
        }
        for key in &role.keys {
            key_count += 1;
            if key_count > MAX_POLICY_KEYS {
                return Err(EtpAuthError::Invalid {
                    message: format!("policy exceeds {MAX_POLICY_KEYS} keys"),
                });
            }
            check_text("keyid", &key.keyid, MAX_KEYID_BYTES)?;
            check_text("actor", &key.actor, 4096)?;
            if key.algorithm != "ed25519" {
                return Err(EtpAuthError::Unsupported {
                    message: format!(
                        "key {:?} algorithm {:?} is not ed25519",
                        key.keyid, key.algorithm
                    ),
                });
            }
            if key.not_before_unix > key.not_after_unix {
                return Err(EtpAuthError::Invalid {
                    message: format!("key {:?} has an inverted validity window", key.keyid),
                });
            }
            if !keyids.insert(key.keyid.as_str()) {
                return Err(EtpAuthError::Invalid {
                    message: format!("duplicate keyid {:?}", key.keyid),
                });
            }
            let public_key = decode_base64_canonical("public key", &key.public_key_base64)?;
            if public_key.len() != 32 {
                return Err(EtpAuthError::Invalid {
                    message: format!(
                        "public key {:?} is {} bytes, expected 32",
                        key.keyid,
                        public_key.len()
                    ),
                });
            }
            if !public_keys.insert(public_key) {
                return Err(EtpAuthError::Invalid {
                    message: format!("duplicate public key material for {:?}", key.keyid),
                });
            }
        }
    }
    Ok(policy)
}

/// The recomputed campaign facts used to evaluate a campaign-closure predicate.
#[derive(Debug, Clone)]
pub struct CampaignExpectation {
    /// Exact closure-manifest bytes.
    pub closure_bytes: Vec<u8>,
    /// SHA-256 of the exact closure-manifest bytes.
    pub closure_sha256: String,
    /// Campaign identifier.
    pub campaign_id: String,
    /// Candidate tree identity.
    pub candidate_identity: String,
    /// SHA-256 over the sorted receipt and raw-evidence digests.
    pub evidence_root_sha256: String,
    /// Recomputed campaign report.
    pub report: CampaignReport,
    /// Declared population identifiers from the opening protocol.
    pub case_ids: Vec<String>,
}

/// SHA-256 over the sorted `(path, sha256)` pairs of every receipt and raw
/// evidence file in a bundle.
#[must_use]
pub fn campaign_evidence_root(bundle: &CampaignBundle) -> String {
    let mut entries: Vec<(&String, &Vec<u8>)> =
        bundle.receipts.iter().chain(bundle.raw.iter()).collect();
    entries.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let mut hasher = Sha256::new();
    hasher.update(b"frf-etp.campaign-evidence-root.v1\n");
    for (path, bytes) in entries {
        hasher.update(path.as_bytes());
        hasher.update([0_u8]);
        hasher.update(sha256_hex(bytes).as_bytes());
        hasher.update(b"\n");
    }
    hex_lower(&hasher.finalize())
}

/// Load and recompute the campaign facts for an attestation.
///
/// # Errors
///
/// Returns [`EtpAuthError`] when the bundle cannot be read, parsed, or
/// reconciled, or when its opening protocol cannot be parsed.
pub fn load_campaign_expectation(path: &Path) -> Result<CampaignExpectation, EtpAuthError> {
    let bundle = load_bundle(path)?;
    campaign_expectation_from_bundle(&bundle)
}

/// Recompute the campaign facts for an attestation from an in-memory bundle.
///
/// # Errors
///
/// Returns [`EtpAuthError`] when the bundle cannot be reconciled or when its
/// opening protocol cannot be parsed.
pub fn campaign_expectation_from_bundle(
    bundle: &CampaignBundle,
) -> Result<CampaignExpectation, EtpAuthError> {
    let protocol = parse_protocol(&bundle.protocol_bytes)?;
    let report = verify_bundle(bundle)?;
    let closure_sha256 = sha256_hex(&bundle.closure_bytes);
    let evidence_root_sha256 = campaign_evidence_root(bundle);
    let case_ids = protocol
        .population
        .iter()
        .map(|case: &CampaignCase| case.id.clone())
        .collect();
    Ok(CampaignExpectation {
        closure_bytes: bundle.closure_bytes.clone(),
        closure_sha256,
        campaign_id: report.campaign_id.clone(),
        candidate_identity: report.candidate_identity.clone(),
        evidence_root_sha256,
        report,
        case_ids,
    })
}

fn count_map(counts: &[crate::etp_campaign::CampaignCount]) -> BTreeMap<&str, u64> {
    counts
        .iter()
        .map(|count| {
            (
                count.label.as_str(),
                u64::try_from(count.count).unwrap_or(u64::MAX),
            )
        })
        .collect()
}

fn predicate_count_map(counts: &[PredicateCount]) -> BTreeMap<&str, u64> {
    counts
        .iter()
        .map(|count| (count.label.as_str(), count.count))
        .collect()
}

fn derived_conclusion(report: &CampaignReport) -> &'static str {
    if report.status == CampaignStatus::Accepted {
        "accepted"
    } else if report.closure_status == ClosureStatus::Blocked {
        "blocked"
    } else {
        "withheld"
    }
}

fn statement_subject_digest<'a>(statement: &'a InTotoStatement, name: &str) -> Option<&'a str> {
    statement
        .subject
        .iter()
        .find(|subject| subject.name == name)
        .and_then(|subject| subject.digest.get("sha256"))
        .map(String::as_str)
}

fn push_refusal(
    refusals: &mut Vec<AttestationRefusal>,
    code: AttestationRefusalCode,
    detail: impl Into<String>,
) {
    refusals.push(AttestationRefusal {
        code,
        detail: detail.into(),
    });
}

#[allow(clippy::too_many_lines)]
fn check_campaign_predicate(
    predicate: &CampaignClosurePredicate,
    expectation: &CampaignExpectation,
    statement: &InTotoStatement,
    refusals: &mut Vec<AttestationRefusal>,
) -> bool {
    let mut ok = true;
    let report = &expectation.report;
    if report.status != CampaignStatus::Accepted {
        push_refusal(
            refusals,
            AttestationRefusalCode::CampaignNotClosed,
            format!(
                "campaign {} recomputed as {}",
                report.campaign_id,
                report.status.as_str()
            ),
        );
        ok = false;
    }
    if predicate.campaign_id != expectation.campaign_id {
        push_refusal(
            refusals,
            AttestationRefusalCode::CampaignMismatch,
            format!(
                "predicate campaign {:?} is not {:?}",
                predicate.campaign_id, expectation.campaign_id
            ),
        );
        ok = false;
    }
    if predicate.closure_sha256 != expectation.closure_sha256 {
        push_refusal(
            refusals,
            AttestationRefusalCode::SubjectMismatch,
            "predicate closure digest does not match the closure bytes".to_owned(),
        );
        ok = false;
    }
    if predicate.candidate_identity != expectation.candidate_identity {
        push_refusal(
            refusals,
            AttestationRefusalCode::CandidateMismatch,
            "predicate candidate identity does not match the campaign".to_owned(),
        );
        ok = false;
    }
    if predicate.raw_evidence_sha256 != expectation.evidence_root_sha256 {
        push_refusal(
            refusals,
            AttestationRefusalCode::EvidenceMismatch,
            "predicate raw-evidence digest does not match the bundle".to_owned(),
        );
        ok = false;
    }
    if predicate.case_count != u64::try_from(report.case_count).unwrap_or(u64::MAX)
        || predicate.receipt_count != u64::try_from(report.receipt_count).unwrap_or(u64::MAX)
        || predicate.raw_evidence_count
            != u64::try_from(report.raw_evidence_count).unwrap_or(u64::MAX)
    {
        push_refusal(
            refusals,
            AttestationRefusalCode::CountMismatch,
            "predicate counts disagree with the recomputed campaign".to_owned(),
        );
        ok = false;
    }
    let mut expected_case_ids = expectation.case_ids.clone();
    expected_case_ids.sort();
    let mut declared_case_ids = predicate.case_ids.clone();
    declared_case_ids.sort();
    if declared_case_ids != expected_case_ids {
        push_refusal(
            refusals,
            AttestationRefusalCode::PopulationMismatch,
            "predicate case identifiers disagree with the declared population".to_owned(),
        );
        ok = false;
    }
    if predicate_count_map(&predicate.outcomes) != count_map(&report.outcomes)
        || predicate_count_map(&predicate.decisions) != count_map(&report.decisions)
    {
        push_refusal(
            refusals,
            AttestationRefusalCode::OutcomeMismatch,
            "predicate outcomes or decisions disagree with the recomputed campaign".to_owned(),
        );
        ok = false;
    }
    if predicate.closure_status != report.closure_status.as_str()
        || predicate.acceptance != report.acceptance.as_str()
    {
        push_refusal(
            refusals,
            AttestationRefusalCode::OutcomeMismatch,
            "predicate closure status or acceptance disagrees with the recomputed campaign"
                .to_owned(),
        );
        ok = false;
    }
    if predicate.conclusion != derived_conclusion(report) {
        push_refusal(
            refusals,
            AttestationRefusalCode::FalseConclusion,
            format!(
                "predicate conclusion {:?} is not the derived conclusion {:?}",
                predicate.conclusion,
                derived_conclusion(report)
            ),
        );
        ok = false;
    }
    if predicate.claim_ceiling != report.claim_ceiling {
        push_refusal(
            refusals,
            AttestationRefusalCode::ClaimCeilingMismatch,
            "predicate claim ceiling is not the campaign claim ceiling".to_owned(),
        );
        ok = false;
    }
    let subject_name = format!("campaign-closure:{}", expectation.campaign_id);
    if statement_subject_digest(statement, &subject_name) != Some(&expectation.closure_sha256) {
        push_refusal(
            refusals,
            AttestationRefusalCode::SubjectMismatch,
            format!("subject {subject_name:?} does not bind the closure digest"),
        );
        ok = false;
    }
    let candidate_name = format!("candidate:{}", expectation.candidate_identity);
    if statement_subject_digest(statement, &candidate_name) != Some(&expectation.candidate_identity)
    {
        push_refusal(
            refusals,
            AttestationRefusalCode::CandidateMismatch,
            format!("subject {candidate_name:?} does not bind the candidate identity"),
        );
        ok = false;
    }
    let evidence_name = format!("raw-evidence:{}", expectation.campaign_id);
    if statement_subject_digest(statement, &evidence_name)
        != Some(&expectation.evidence_root_sha256)
    {
        push_refusal(
            refusals,
            AttestationRefusalCode::EvidenceMismatch,
            format!("subject {evidence_name:?} does not bind the raw-evidence digest"),
        );
        ok = false;
    }
    ok
}

fn predicate_schema_matches(kind: PredicateKind, predicate: &Value) -> bool {
    predicate.get("schema").and_then(Value::as_str) == Some(kind.schema())
        && predicate.get("spec").and_then(Value::as_str) == Some(ETP_SPEC)
}

/// Return the current Unix time in seconds.
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Verify a DSSE envelope against a trust policy and, optionally, a campaign.
///
/// A valid signature is never sufficient for acceptance. Independent-review
/// status is reported separately and is never inferred from signature count.
///
/// # Errors
///
/// Returns [`EtpAuthError`] for a malformed envelope, payload, statement, or
/// policy. A well-formed artifact that fails authorization or semantics is
/// returned as a refused [`AttestationReport`] with exit status 4.
#[allow(clippy::too_many_lines, clippy::if_not_else)]
pub fn verify_envelope_bytes(
    envelope_bytes: &[u8],
    policy: &TrustPolicy,
    expectation: Option<&CampaignExpectation>,
    now_unix: u64,
) -> Result<AttestationReport, EtpAuthError> {
    let envelope = parse_envelope(envelope_bytes)?;
    let envelope_sha256 = sha256_hex(envelope_bytes);
    let payload = decode_base64_canonical("payload", &envelope.payload)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(EtpAuthError::Invalid {
            message: format!("decoded payload exceeds {MAX_PAYLOAD_BYTES} bytes"),
        });
    }
    let payload_sha256 = sha256_hex(&payload);
    let pae_bytes = pae(&envelope.payload_type, &payload)?;

    let mut refusals = Vec::new();
    let policy_fresh = now_unix >= policy.issued_at_unix && now_unix <= policy.expires_at_unix;
    if !policy_fresh {
        push_refusal(
            &mut refusals,
            AttestationRefusalCode::ExpiredCredential,
            format!("policy {} is outside its validity window", policy.policy_id),
        );
    }

    let mut signatures = Vec::with_capacity(envelope.signatures.len());
    let mut valid_signatures = 0_usize;
    let mut expired_used = false;
    for signature in &envelope.signatures {
        let sig_bytes = decode_base64_canonical("signature", &signature.sig)?;
        let sig_array: [u8; 64] =
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| EtpAuthError::Invalid {
                    message: format!("signature for {:?} is not 64 bytes", signature.keyid),
                })?;
        let signature_value = Signature::from_bytes(&sig_array);
        let resolved = policy.resolve(&signature.keyid);
        let Some((role, key)) = resolved else {
            signatures.push(SignatureReport {
                keyid: signature.keyid.clone(),
                actor: None,
                roles: Vec::new(),
                valid: false,
                detail: "keyid is not present in the trust policy".to_owned(),
            });
            push_refusal(
                &mut refusals,
                AttestationRefusalCode::UnknownKey,
                format!(
                    "keyid {:?} is not present in the trust policy",
                    signature.keyid
                ),
            );
            continue;
        };
        let public_key = decode_base64_canonical("public key", &key.public_key_base64)?;
        if key.algorithm != "ed25519" {
            signatures.push(SignatureReport {
                keyid: signature.keyid.clone(),
                actor: Some(key.actor.clone()),
                roles: vec![role.id.clone()],
                valid: false,
                detail: format!("key algorithm {:?} is not ed25519", key.algorithm),
            });
            push_refusal(
                &mut refusals,
                AttestationRefusalCode::UnsupportedAlgorithm,
                format!(
                    "key {:?} names unsupported algorithm {:?}",
                    key.keyid, key.algorithm
                ),
            );
            continue;
        }
        let public_array: [u8; 32] =
            public_key
                .as_slice()
                .try_into()
                .map_err(|_| EtpAuthError::Invalid {
                    message: format!("public key {:?} is not 32 bytes", key.keyid),
                })?;
        let verifier =
            VerifyingKey::from_bytes(&public_array).map_err(|error| EtpAuthError::Invalid {
                message: format!("public key {:?} is invalid: {error}", key.keyid),
            })?;
        let valid = verifier.verify_strict(&pae_bytes, &signature_value).is_ok();
        let key_fresh = now_unix >= key.not_before_unix && now_unix <= key.not_after_unix;
        if !valid {
            push_refusal(
                &mut refusals,
                AttestationRefusalCode::InvalidSignature,
                format!(
                    "signature for {:?} does not verify over the exact PAE bytes",
                    signature.keyid
                ),
            );
        }
        if valid && !key_fresh {
            expired_used = true;
        }
        if valid {
            valid_signatures += 1;
        }
        signatures.push(SignatureReport {
            keyid: signature.keyid.clone(),
            actor: Some(key.actor.clone()),
            roles: vec![role.id.clone()],
            valid,
            detail: if !valid {
                "Ed25519 signature does not verify over the exact PAE bytes".to_owned()
            } else if !key_fresh {
                "signature verifies but the key is outside its validity window".to_owned()
            } else {
                "signature verifies over the exact PAE bytes".to_owned()
            },
        });
    }

    let signature_state = if valid_signatures == 0 {
        DimensionState::Invalid
    } else if valid_signatures == signatures.len() {
        DimensionState::Valid
    } else {
        DimensionState::Partial
    };

    let mut payload_state = DimensionState::Valid;
    let mut scope_state = DimensionState::Invalid;
    let mut semantic_state = DimensionState::NotChecked;
    let mut authorization_state = DimensionState::Invalid;
    let mut independent_state = IndependentReviewState::NotChecked;
    let mut predicate_type = String::new();
    let mut campaign_id = None;
    let mut independent_reviewers = 0_usize;

    let statement = match parse_statement(&payload) {
        Ok(statement) => Some(statement),
        Err(error) => {
            payload_state = DimensionState::Invalid;
            push_refusal(
                &mut refusals,
                AttestationRefusalCode::UnsupportedSchemaVersion,
                format!("payload is not a valid in-toto Statement v1: {error}"),
            );
            None
        }
    };

    if let Some(statement) = &statement {
        predicate_type.clone_from(&statement.predicate_type);
        let kind = PredicateKind::from_predicate_type(&statement.predicate_type);
        if kind.is_none() {
            payload_state = DimensionState::Invalid;
            push_refusal(
                &mut refusals,
                AttestationRefusalCode::UnsupportedPredicateType,
                format!("unsupported predicate type {:?}", statement.predicate_type),
            );
        }
        if let Some(kind) = kind {
            if !predicate_schema_matches(kind, &statement.predicate) {
                payload_state = DimensionState::Invalid;
                push_refusal(
                    &mut refusals,
                    AttestationRefusalCode::UnsupportedSchemaVersion,
                    format!(
                        "predicate does not declare schema {:?} and spec {ETP_SPEC:?}",
                        kind.schema()
                    ),
                );
            } else {
                let parsed = match kind {
                    PredicateKind::CampaignClosure => {
                        serde_json::from_value::<CampaignClosurePredicate>(
                            statement.predicate.clone(),
                        )
                        .map(|predicate| {
                            campaign_id = Some(predicate.campaign_id.clone());
                            PredicateBody::CampaignClosure(Box::new(predicate))
                        })
                    }
                    _ => serde_json::from_value::<GenericEtpPredicate>(statement.predicate.clone())
                        .map(PredicateBody::Generic),
                };
                match parsed {
                    Ok(body) => {
                        let required_role = kind.required_role();
                        let role = policy.role(required_role);
                        let mut authorized_actors = BTreeSet::new();
                        for signature in &signatures {
                            if !signature.valid {
                                continue;
                            }
                            let Some((signature_role, key)) = policy.resolve(&signature.keyid)
                            else {
                                continue;
                            };
                            let key_fresh =
                                now_unix >= key.not_before_unix && now_unix <= key.not_after_unix;
                            if signature_role.id == required_role
                                && key_fresh
                                && signature_role
                                    .scope
                                    .iter()
                                    .any(|entry| entry == kind.predicate_type())
                            {
                                authorized_actors.insert(key.actor.clone());
                            }
                        }
                        let threshold = role.map_or(1, |role| role.threshold);
                        let threshold = usize::try_from(threshold).unwrap_or(usize::MAX);
                        if authorized_actors.len() >= threshold.max(1) {
                            authorization_state = DimensionState::Valid;
                        } else {
                            push_refusal(
                                &mut refusals,
                                AttestationRefusalCode::UnauthorizedRole,
                                format!(
                                    "no fresh authorized actor satisfied role {required_role:?} for {}",
                                    kind.predicate_type()
                                ),
                            );
                        }

                        if let Some(independent_role) =
                            policy.roles.iter().find(|role| role.independent)
                        {
                            let mut actors = BTreeSet::new();
                            for signature in &signatures {
                                if !signature.valid {
                                    continue;
                                }
                                let Some((signature_role, key)) = policy.resolve(&signature.keyid)
                                else {
                                    continue;
                                };
                                let key_fresh = now_unix >= key.not_before_unix
                                    && now_unix <= key.not_after_unix;
                                if signature_role.id == independent_role.id
                                    && key_fresh
                                    && signature_role
                                        .scope
                                        .iter()
                                        .any(|entry| entry == kind.predicate_type())
                                {
                                    actors.insert(key.actor.clone());
                                }
                            }
                            independent_reviewers = actors.len();
                            let threshold = usize::try_from(independent_role.threshold)
                                .unwrap_or(usize::MAX)
                                .max(1);
                            let established = actors.len() >= threshold;
                            let claimed = match &body {
                                PredicateBody::CampaignClosure(predicate) => {
                                    predicate.independent_review.as_str()
                                }
                                PredicateBody::Generic(predicate) => {
                                    predicate.independent_review.as_str()
                                }
                            };
                            independent_state = if established {
                                IndependentReviewState::Established
                            } else if claimed == "established" {
                                IndependentReviewState::Insufficient
                            } else {
                                IndependentReviewState::NotEstablished
                            };
                            if independent_state == IndependentReviewState::Insufficient {
                                push_refusal(
                                    &mut refusals,
                                    AttestationRefusalCode::InsufficientIndependentReview,
                                    format!(
                                        "statement claims independent review but {} distinct authorized actors < threshold {threshold}",
                                        actors.len()
                                    ),
                                );
                            }
                        } else {
                            independent_state = IndependentReviewState::NotEstablished;
                            if let PredicateBody::Generic(predicate) = &body {
                                if predicate.independent_review == "established" {
                                    independent_state = IndependentReviewState::Insufficient;
                                    push_refusal(
                                        &mut refusals,
                                        AttestationRefusalCode::InsufficientIndependentReview,
                                        "policy has no independent-review role".to_owned(),
                                    );
                                }
                            }
                            if let PredicateBody::CampaignClosure(predicate) = &body {
                                if predicate.independent_review == "established" {
                                    independent_state = IndependentReviewState::Insufficient;
                                    push_refusal(
                                        &mut refusals,
                                        AttestationRefusalCode::InsufficientIndependentReview,
                                        "policy has no independent-review role".to_owned(),
                                    );
                                }
                            }
                        }

                        match body {
                            PredicateBody::CampaignClosure(predicate) => {
                                if let Some(expectation) = expectation {
                                    if predicate.independent_review == "established"
                                        && independent_state != IndependentReviewState::Established
                                    {
                                        // Already refused above when the threshold is not met.
                                    }
                                    scope_state = DimensionState::Valid;
                                    if check_campaign_predicate(
                                        &predicate,
                                        expectation,
                                        statement,
                                        &mut refusals,
                                    ) {
                                        semantic_state = DimensionState::Valid;
                                    } else {
                                        semantic_state = DimensionState::Invalid;
                                    }
                                } else {
                                    scope_state = DimensionState::Valid;
                                    semantic_state = DimensionState::NotChecked;
                                    push_refusal(
                                        &mut refusals,
                                        AttestationRefusalCode::SemanticSupportNotEvaluated,
                                        "no campaign was supplied for semantic evaluation"
                                            .to_owned(),
                                    );
                                }
                            }
                            PredicateBody::Generic(predicate) => {
                                scope_state = DimensionState::Valid;
                                semantic_state = DimensionState::NotChecked;
                                if predicate.independent_review == "established"
                                    && independent_state != IndependentReviewState::Established
                                {
                                    // Already refused above when the threshold is not met.
                                }
                                push_refusal(
                                    &mut refusals,
                                    AttestationRefusalCode::SemanticSupportNotEvaluated,
                                    "semantic evaluation is implemented only for campaign-closure predicates"
                                        .to_owned(),
                                );
                            }
                        }
                    }
                    Err(error) => {
                        payload_state = DimensionState::Invalid;
                        push_refusal(
                            &mut refusals,
                            AttestationRefusalCode::UnsupportedSchemaVersion,
                            format!("predicate body does not match its schema: {error}"),
                        );
                    }
                }
            }
        }
    }

    let freshness_state = if !policy_fresh || expired_used {
        DimensionState::Invalid
    } else {
        DimensionState::Valid
    };
    if expired_used && policy_fresh {
        push_refusal(
            &mut refusals,
            AttestationRefusalCode::ExpiredCredential,
            "a verifying signature was produced by a key outside its validity window".to_owned(),
        );
    }

    let accepted = refusals.is_empty()
        && signature_state == DimensionState::Valid
        && payload_state == DimensionState::Valid
        && authorization_state == DimensionState::Valid
        && scope_state == DimensionState::Valid
        && freshness_state == DimensionState::Valid
        && semantic_state == DimensionState::Valid
        && independent_state != IndependentReviewState::Insufficient;
    let status = if accepted {
        AttestationStatus::Accepted
    } else {
        AttestationStatus::Refused
    };

    Ok(AttestationReport {
        schema: ATTESTATION_REPORT_SCHEMA.to_owned(),
        spec: ETP_SPEC.to_owned(),
        status,
        envelope_sha256,
        payload_sha256,
        predicate_type,
        campaign_id,
        dimensions: AttestationDimensions {
            signature_validity: signature_state,
            payload_integrity: payload_state,
            authorization: authorization_state,
            scope_applicability: scope_state,
            freshness: freshness_state,
            semantic_support: semantic_state,
            independent_review: independent_state,
        },
        signatures,
        independent_reviewers,
        refusals,
        claim_ceiling: ATTESTATION_CLAIM_CEILING.to_owned(),
    })
}

enum PredicateBody {
    CampaignClosure(Box<CampaignClosurePredicate>),
    Generic(GenericEtpPredicate),
}

/// Read and parse a trust policy file.
///
/// # Errors
///
/// Returns [`EtpAuthError::Io`] when the file cannot be read, or the parse
/// errors of [`parse_policy`].
pub fn load_policy(path: &Path) -> Result<TrustPolicy, EtpAuthError> {
    let bytes = fs::read(path).map_err(|error| EtpAuthError::Io {
        message: format!("cannot read {}: {error}", path.display()),
    })?;
    parse_policy(&bytes)
}

/// Read, verify, and report on an envelope file.
///
/// # Errors
///
/// Returns [`EtpAuthError::Io`] when the envelope cannot be read, the parse
/// errors of [`parse_envelope`], or the errors of [`verify_envelope_bytes`].
pub fn verify_envelope_file(
    envelope_path: &Path,
    policy: &TrustPolicy,
    expectation: Option<&CampaignExpectation>,
    now_unix: u64,
) -> Result<AttestationReport, EtpAuthError> {
    let bytes = fs::read(envelope_path).map_err(|error| EtpAuthError::Io {
        message: format!("cannot read {}: {error}", envelope_path.display()),
    })?;
    verify_envelope_bytes(&bytes, policy, expectation, now_unix)
}
