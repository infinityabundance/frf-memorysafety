#![allow(clippy::module_name_repetitions)]

//! Phase 10.4a authenticated correction and revocation registry.
//!
//! # What this module establishes
//!
//! A verified registry establishes that the declared correction authority signed
//! the exact append-only entries, that each entry is bound to the preceding
//! entry and to a registry identity, and that the declared founded-support model
//! loses the derivations named by an applied revocation unless an alternative
//! valid support path survives.
//!
//! # What this module does not establish
//!
//! A revocation is not a claim that the original evidence was false when
//! produced. Historical replay under the original policy remains valid.
//! Present authorization is a separate question under the current registry and
//! freshness rules. A registry is not a complete public revocation feed, not a
//! transparency log, and not an adjudication of truth.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::etp::ETP_SPEC;
use crate::etp_auth::{
    pae, parse_envelope_for, parse_policy, DsseEnvelope, TrustPolicy, ROLE_CORRECTION_AUTHORITY,
};
use crate::identity::{canonical_bytes, hex_lower, parse_strict};
use crate::support::{
    evaluate, HistoricVerdict, RuleSystem, SupportPolicy, SupportResult, SupportState,
};

/// Registry schema identifier.
pub const REVOCATION_REGISTRY_SCHEMA: &str = "frf-etp.revocation-registry.v1";
/// Entry payload schema identifier.
pub const REVOCATION_ENTRY_SCHEMA: &str = "frf-etp.revocation-entry.v1";
/// Entry DSSE payload type.
pub const REVOCATION_ENTRY_PAYLOAD_TYPE: &str = "application/vnd.frf-etp.revocation+json";
/// Verification report schema identifier.
pub const REVOCATION_REPORT_SCHEMA: &str = "frf-etp.revocation-verification.v1";
/// Support-model schema identifier.
pub const SUPPORT_MODEL_SCHEMA: &str = "frf-etp.support-model.v1";
/// Historical-verdict schema identifier.
pub const HISTORICAL_VERDICT_SCHEMA: &str = "frf-etp.historical-verdict.v1";
/// Maximum entries in one registry.
pub const MAX_REVOCATION_ENTRIES: usize = 1024;
/// Maximum evidence identifiers in one target.
pub const MAX_TARGET_EVIDENCE: usize = 64;
/// Claim ceiling carried by every report.
pub const REVOCATION_CLAIM_CEILING: &str = "A verified revocation registry establishes only that the declared correction authority signed the exact append-only entries under the declared policy and that the declared founded-support model loses the dependent derivations named by applied revocations unless an alternative valid support path survives. It does not establish that a revocation is correct, complete, globally visible, or that historical evidence was invalid when produced. Historical replay under the original policy is not present authorization.";

/// One revocation, correction, or dissent action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationAction {
    /// Revoke support derived from the target evidence.
    Revoke,
    /// Record a correction without erasing history.
    Correct,
    /// Retain a dissent or contradictory observation.
    Dissent,
}

impl RevocationAction {
    /// Stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Revoke => "revoke",
            Self::Correct => "correct",
            Self::Dissent => "dissent",
        }
    }
}

/// The identities a revocation is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationTarget {
    /// Claim identifier.
    pub claim_id: String,
    /// Support-policy identifier that owns the claim.
    pub policy_id: String,
    /// Evidence identifiers whose derivations are revoked. Empty means the
    /// claim itself is excluded.
    pub evidence_ids: Vec<String>,
    /// Declared subject identity.
    pub subject_identity: String,
}

/// Signed entry payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationEntry {
    /// Schema identifier.
    pub schema: String,
    /// ETP specification identifier.
    pub spec: String,
    /// Registry identifier bound into the signed bytes.
    pub registry_id: String,
    /// Registry policy identifier bound into the signed bytes.
    pub policy_id: String,
    /// Registry policy version bound into the signed bytes.
    pub policy_version: u32,
    /// Monotonic sequence, starting at 1.
    pub sequence: u64,
    /// Digest of the previous canonical envelope, or `null` for the first entry.
    pub previous_entry_sha256: Option<String>,
    /// Stable entry identifier.
    pub entry_id: String,
    /// Action.
    pub action: RevocationAction,
    /// Target identities.
    pub target: RevocationTarget,
    /// Reason.
    pub reason: String,
    /// Effective time, seconds since the Unix epoch.
    pub effective_at_unix: u64,
    /// Scope of the action.
    pub scope: String,
    /// Whether historical replay remains valid under the original policy.
    pub historical_replay: String,
    /// Statement for a correction or dissent.
    pub statement: Option<String>,
    /// Correction this entry corrects, if any.
    pub corrects_entry_id: Option<String>,
}

/// Registry document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationRegistry {
    /// Schema identifier.
    pub schema: String,
    /// ETP specification identifier.
    pub spec: String,
    /// Registry identifier.
    pub registry_id: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Policy version.
    pub policy_version: u32,
    /// Registry issue time.
    pub issued_at_unix: u64,
    /// Append-only signed entries.
    pub entries: Vec<DsseEnvelope>,
}

/// One contradictory record retained by the support model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContradictoryRecord {
    /// Identifier.
    pub id: String,
    /// Class.
    pub class: String,
    /// Statement.
    pub statement: String,
    /// Source.
    pub source: String,
    /// Must be true.
    pub retained: bool,
    /// `unresolved`, `explained`, or `resolved_by_new_evidence`.
    pub resolution: String,
}

/// One claim in the founded-support model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportClaim {
    /// Claim identifier.
    pub id: String,
    /// Evidence identifiers this claim depends on.
    pub evidence_ids: Vec<String>,
    /// Retained contradictory records.
    pub contradictory: Vec<ContradictoryRecord>,
}

/// Historical recording settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalRecording {
    /// Recording time.
    pub recorded_at_unix: u64,
    /// Revoked claims at recording time.
    pub revoked: Vec<String>,
    /// Challenged claims at recording time.
    pub challenged: Vec<String>,
}

/// Founded-support model input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportModel {
    /// Schema identifier.
    pub schema: String,
    /// ETP specification identifier.
    pub spec: String,
    /// Original support policy.
    pub policy: SupportPolicy,
    /// Present policy validity start.
    pub not_before_unix: u64,
    /// Present policy validity end.
    pub not_after_unix: u64,
    /// Historical recording settings.
    pub historical_recording: HistoricalRecording,
    /// Declared claims.
    pub claims: Vec<SupportClaim>,
}

/// Stable refusal codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationRefusalCode {
    /// A signature did not verify over the exact PAE bytes.
    InvalidSignature,
    /// A signature names a key absent from the policy.
    UnknownKey,
    /// A valid signature was made by a key outside `correction_authority`.
    UnauthorizedRole,
    /// A key was outside its declared validity window.
    ExpiredCredential,
    /// No correction authority exists or no authorized signature met its threshold.
    InsufficientAuthority,
    /// The registry policy identity or version differs from the supplied policy.
    PolicyMismatch,
    /// The policy or a key is stale at verification time.
    StalePolicy,
    /// An entry was signed for a different registry or sequence.
    ReplayedRevocation,
    /// The same target is revoked more than once.
    DuplicateRevocation,
    /// The support policy is stale at verification time.
    StaleSupportPolicy,
    /// The historical verdict does not match the original policy.
    HistoricalReplayMismatch,
    /// A contradiction was not retained.
    ContradictionNotRetained,
    /// The support model is missing while a support application was requested.
    MissingSupport,
    /// A target policy identifier does not match the support model.
    TargetPolicyMismatch,
}

impl RevocationRefusalCode {
    /// Stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidSignature => "invalid_signature",
            Self::UnknownKey => "unknown_key",
            Self::UnauthorizedRole => "unauthorized_role",
            Self::ExpiredCredential => "expired_credential",
            Self::InsufficientAuthority => "insufficient_authority",
            Self::PolicyMismatch => "policy_mismatch",
            Self::StalePolicy => "stale_policy",
            Self::ReplayedRevocation => "replayed_revocation",
            Self::DuplicateRevocation => "duplicate_revocation",
            Self::StaleSupportPolicy => "stale_support_policy",
            Self::HistoricalReplayMismatch => "historical_replay_mismatch",
            Self::ContradictionNotRetained => "contradiction_not_retained",
            Self::MissingSupport => "missing_support",
            Self::TargetPolicyMismatch => "target_policy_mismatch",
        }
    }
}

/// One refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationRefusal {
    /// Code.
    pub code: RevocationRefusalCode,
    /// Detail.
    pub detail: String,
}

/// Overall status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationStatus {
    /// The registry verified and the support application completed.
    Verified,
    /// The registry is structurally valid but a declared use was refused.
    Refused,
}

impl RevocationStatus {
    /// Stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Refused => "refused",
        }
    }
}

/// Separate verification dimensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationDimensions {
    /// Registry parse and field integrity.
    pub registry_integrity: crate::etp_auth::DimensionState,
    /// Append-only sequence and hash chain.
    pub sequence_integrity: crate::etp_auth::DimensionState,
    /// At least one signature verified over the exact PAE bytes.
    pub signature_validity: crate::etp_auth::DimensionState,
    /// A fresh correction-authority key met its threshold.
    pub authorization: crate::etp_auth::DimensionState,
    /// The policy and used keys are fresh.
    pub policy_freshness: crate::etp_auth::DimensionState,
    /// The historical verdict replays under the original policy.
    pub historical_replay: crate::etp_auth::DimensionState,
    /// Present authorization under the current registry and freshness rules.
    pub present_authorization: crate::etp_auth::DimensionState,
}

/// One signer observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationSignerReport {
    /// Entry identifier.
    pub entry_id: String,
    /// Key identifier.
    pub keyid: String,
    /// Declared actor.
    pub actor: Option<String>,
    /// Roles that contain this key.
    pub roles: Vec<String>,
    /// Whether the Ed25519 signature verified over PAE.
    pub signature_valid: bool,
    /// Whether the key is authorized for revocation.
    pub authorized: bool,
    /// Whether the key is inside its validity window.
    pub within_validity: bool,
    /// Exact detail.
    pub detail: String,
}

/// One revocation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationRecordReport {
    /// Entry identifier.
    pub entry_id: String,
    /// Claim identifier.
    pub claim_id: String,
    /// Evidence identifiers.
    pub evidence_ids: Vec<String>,
    /// Effective time.
    pub effective_at_unix: u64,
    /// Historical replay declaration.
    pub historical_replay: String,
    /// Scope.
    pub scope: String,
    /// Reason.
    pub reason: String,
    /// Whether this entry was applied to the support model.
    pub applied: bool,
}

/// One correction record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrectionRecordReport {
    /// Entry identifier.
    pub entry_id: String,
    /// Claim identifier.
    pub claim_id: String,
    /// Corrected entry identifier.
    pub corrects_entry_id: Option<String>,
    /// Statement.
    pub statement: String,
    /// Effective time.
    pub effective_at_unix: u64,
    /// Always retained.
    pub retained: bool,
}

/// One retained dissent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DissentRecordReport {
    /// Entry identifier.
    pub entry_id: String,
    /// Claim identifier.
    pub claim_id: String,
    /// Statement.
    pub statement: String,
    /// Effective time.
    pub effective_at_unix: u64,
    /// Always retained.
    pub retained: bool,
}

/// Present support state for one claim.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimSupportReport {
    /// Claim identifier.
    pub claim_id: String,
    /// Historical state under the original policy.
    pub historical_state: SupportState,
    /// Present positive state.
    pub present_state: SupportState,
    /// Present admissibility.
    pub present_admissible: bool,
    /// Whether the claim was historically positively supported.
    pub historically_supported: bool,
    /// Whether the claim is presently positively supported.
    pub presently_supported: bool,
    /// Evidence of this claim that the registry revoked.
    pub revoked_evidence: Vec<String>,
    /// Whether alternative support survived a revocation.
    pub alternative_support: bool,
    /// Retained contradictory record identifiers.
    pub contradictory_retained: Vec<String>,
}

/// Support application report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportApplicationReport {
    /// Support-policy identifier.
    pub policy_id: String,
    /// Support-policy version.
    pub policy_version: String,
    /// Support-policy digest.
    pub policy_digest: String,
    /// Historical recording time.
    pub recorded_at_unix: u64,
    /// Whether the historical verdict replayed under the original policy.
    pub historical_verdict_valid: bool,
    /// Whether present freshness is valid.
    pub present_freshness: String,
    /// Per-claim state.
    pub claims: Vec<ClaimSupportReport>,
    /// Claims historically supported and presently unsupported.
    pub invalidated: Vec<String>,
    /// Claims whose alternative support survived.
    pub alternative_survives: Vec<String>,
    /// Claims positively supported but not presently admissible.
    pub withheld: Vec<String>,
}

/// Verification report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationReport {
    /// Schema identifier.
    pub schema: String,
    /// ETP specification identifier.
    pub spec: String,
    /// Status.
    pub status: RevocationStatus,
    /// Registry identifier.
    pub registry_id: String,
    /// SHA-256 of the exact registry bytes.
    pub registry_sha256: String,
    /// Entry count.
    pub entry_count: usize,
    /// Policy identifier.
    pub policy_id: String,
    /// Policy version.
    pub policy_version: u32,
    /// Separate dimensions.
    pub dimensions: RevocationDimensions,
    /// Signer observations.
    pub signers: Vec<RevocationSignerReport>,
    /// Revocation records.
    pub revocations: Vec<RevocationRecordReport>,
    /// Correction records.
    pub corrections: Vec<CorrectionRecordReport>,
    /// Retained dissents.
    pub retained_dissent: Vec<DissentRecordReport>,
    /// Support application, when a model was supplied.
    pub support: Option<SupportApplicationReport>,
    /// Refusals.
    pub refusals: Vec<RevocationRefusal>,
    /// Unsupported features.
    pub unsupported_features: Vec<String>,
    /// Claim ceiling.
    pub claim_ceiling: String,
}

impl RevocationReport {
    /// `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self.status {
            RevocationStatus::Verified => 0,
            RevocationStatus::Refused => 4,
        }
    }
}

/// Errors from registry verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationError {
    /// I/O failure.
    Io {
        /// Diagnostic.
        message: String,
    },
    /// Structural integrity failure.
    Invalid {
        /// Diagnostic.
        message: String,
    },
    /// Canonical encoding failure.
    Canonical {
        /// Diagnostic.
        message: String,
    },
    /// Unsupported operation.
    Unsupported {
        /// Diagnostic.
        message: String,
    },
}

impl RevocationError {
    /// `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Canonical { .. } => 7,
            Self::Io { .. } | Self::Invalid { .. } => 3,
            Self::Unsupported { .. } => 6,
        }
    }
}

impl fmt::Display for RevocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { message } => write!(formatter, "revocation I/O failure: {message}"),
            Self::Invalid { message } => {
                write!(formatter, "revocation integrity failure: {message}")
            }
            Self::Canonical { message } => {
                write!(formatter, "revocation encoding failure: {message}")
            }
            Self::Unsupported { message } => {
                write!(formatter, "revocation operation unsupported: {message}")
            }
        }
    }
}

impl std::error::Error for RevocationError {}

fn check_text(label: &str, value: &str) -> Result<(), RevocationError> {
    if value.trim().is_empty() {
        return Err(RevocationError::Invalid {
            message: format!("{label} must not be empty"),
        });
    }
    if value.len() > 4096 {
        return Err(RevocationError::Invalid {
            message: format!("{label} exceeds 4096 bytes"),
        });
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn canonical_value_bytes(value: &Value) -> Result<Vec<u8>, RevocationError> {
    canonical_bytes(value).map_err(|error| RevocationError::Canonical {
        message: error.to_string(),
    })
}

fn envelope_digest(envelope: &DsseEnvelope) -> Result<String, RevocationError> {
    let value = serde_json::to_value(envelope).map_err(|error| RevocationError::Canonical {
        message: error.to_string(),
    })?;
    Ok(sha256_hex(&canonical_value_bytes(&value)?))
}

/// Parse a registry document with strict JSON and structural checks.
///
/// # Errors
///
/// Returns [`RevocationError::Invalid`] for malformed JSON, unknown fields, an
/// unsupported schema, an empty registry, or an excessive entry count.
pub fn parse_registry(bytes: &[u8]) -> Result<RevocationRegistry, RevocationError> {
    let value = parse_strict(bytes).map_err(|error| RevocationError::Invalid {
        message: error.to_string(),
    })?;
    let registry: RevocationRegistry =
        serde_json::from_value(value).map_err(|error| RevocationError::Invalid {
            message: error.to_string(),
        })?;
    if registry.schema != REVOCATION_REGISTRY_SCHEMA {
        return Err(RevocationError::Invalid {
            message: format!(
                "registry schema {:?} is not {REVOCATION_REGISTRY_SCHEMA}",
                registry.schema
            ),
        });
    }
    if registry.spec != ETP_SPEC {
        return Err(RevocationError::Invalid {
            message: format!("registry spec {:?} is not {ETP_SPEC}", registry.spec),
        });
    }
    check_text("registry_id", &registry.registry_id)?;
    check_text("policy_id", &registry.policy_id)?;
    if registry.entries.is_empty() {
        return Err(RevocationError::Invalid {
            message: "registry has no entries".to_owned(),
        });
    }
    if registry.entries.len() > MAX_REVOCATION_ENTRIES {
        return Err(RevocationError::Invalid {
            message: format!("registry exceeds {MAX_REVOCATION_ENTRIES} entries"),
        });
    }
    Ok(registry)
}

/// Parse a founded-support model with strict JSON.
///
/// # Errors
///
/// Returns [`RevocationError::Invalid`] for malformed JSON, unknown fields, an
/// unsupported schema, an empty claim list, or an invalid validity window.
pub fn parse_support_model(bytes: &[u8]) -> Result<SupportModel, RevocationError> {
    let value = parse_strict(bytes).map_err(|error| RevocationError::Invalid {
        message: error.to_string(),
    })?;
    let model: SupportModel =
        serde_json::from_value(value).map_err(|error| RevocationError::Invalid {
            message: error.to_string(),
        })?;
    if model.schema != SUPPORT_MODEL_SCHEMA {
        return Err(RevocationError::Invalid {
            message: format!(
                "support schema {:?} is not {SUPPORT_MODEL_SCHEMA}",
                model.schema
            ),
        });
    }
    if model.spec != ETP_SPEC {
        return Err(RevocationError::Invalid {
            message: format!("support spec {:?} is not {ETP_SPEC}", model.spec),
        });
    }
    if model.not_before_unix >= model.not_after_unix {
        return Err(RevocationError::Invalid {
            message: "support policy validity window is inverted".to_owned(),
        });
    }
    if model.claims.is_empty() {
        return Err(RevocationError::Invalid {
            message: "support model has no claims".to_owned(),
        });
    }
    model
        .policy
        .rules
        .validate()
        .map_err(|error| RevocationError::Invalid {
            message: error.to_string(),
        })?;
    let mut ids = BTreeSet::new();
    for claim in &model.claims {
        check_text("claim id", &claim.id)?;
        if !ids.insert(claim.id.as_str()) {
            return Err(RevocationError::Invalid {
                message: format!("duplicate claim {:?}", claim.id),
            });
        }
        if claim.evidence_ids.len() > MAX_TARGET_EVIDENCE {
            return Err(RevocationError::Invalid {
                message: format!(
                    "claim {:?} exceeds {MAX_TARGET_EVIDENCE} evidence ids",
                    claim.id
                ),
            });
        }
    }
    Ok(model)
}

/// Parse a historical verdict with strict JSON.
///
/// # Errors
///
/// Returns [`RevocationError::Invalid`] for malformed JSON or unknown fields.
pub fn parse_historical_verdict(bytes: &[u8]) -> Result<HistoricVerdict, RevocationError> {
    let value = parse_strict(bytes).map_err(|error| RevocationError::Invalid {
        message: error.to_string(),
    })?;
    serde_json::from_value(value).map_err(|error| RevocationError::Invalid {
        message: error.to_string(),
    })
}

fn decode_canonical(label: &str, value: &str) -> Result<Vec<u8>, RevocationError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|error| RevocationError::Invalid {
            message: format!("{label} is not valid base64: {error}"),
        })?;
    if STANDARD.encode(&decoded) != value {
        return Err(RevocationError::Invalid {
            message: format!("{label} is not canonical padded base64"),
        });
    }
    Ok(decoded)
}

fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(public_key) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key) else {
        return false;
    };
    let Ok(signature) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    verifying_key
        .verify_strict(message, &Signature::from_bytes(&signature))
        .is_ok()
}

fn push_refusal(
    refusals: &mut Vec<RevocationRefusal>,
    code: RevocationRefusalCode,
    detail: String,
) {
    if !refusals.iter().any(|refusal| refusal.code == code) {
        refusals.push(RevocationRefusal { code, detail });
    }
}

fn support_target_key(target: &RevocationTarget) -> (String, Vec<String>) {
    let mut evidence = target.evidence_ids.clone();
    evidence.sort();
    evidence.dedup();
    (target.claim_id.clone(), evidence)
}

/// Verify a registry against a policy, an optional support model, and an
/// optional recorded historical verdict.
///
/// # Errors
///
/// Returns [`RevocationError`] for structural integrity failures, malformed
/// inputs, or I/O failures. Semantic refusals are returned in the report.
#[allow(clippy::too_many_lines)]
pub fn verify_registry_bytes(
    registry_bytes: &[u8],
    policy: &TrustPolicy,
    support: Option<&SupportModel>,
    historical: Option<&HistoricVerdict>,
    now_unix: u64,
) -> Result<RevocationReport, RevocationError> {
    let registry = parse_registry(registry_bytes)?;
    let policy_fresh = now_unix >= policy.issued_at_unix && now_unix <= policy.expires_at_unix;
    let mut refusals = Vec::new();
    if registry.policy_id != policy.policy_id || registry.policy_version != policy.version {
        push_refusal(
            &mut refusals,
            RevocationRefusalCode::PolicyMismatch,
            format!(
                "registry policy {}/{} does not match supplied policy {}/{}",
                registry.policy_id, registry.policy_version, policy.policy_id, policy.version
            ),
        );
    }
    if !policy_fresh {
        push_refusal(
            &mut refusals,
            RevocationRefusalCode::StalePolicy,
            format!(
                "policy validity window {}..{} does not contain verification time {now_unix}",
                policy.issued_at_unix, policy.expires_at_unix
            ),
        );
    }

    let correction_role = policy.role(ROLE_CORRECTION_AUTHORITY);
    if correction_role.is_none() {
        push_refusal(
            &mut refusals,
            RevocationRefusalCode::InsufficientAuthority,
            "trust policy has no correction_authority role".to_owned(),
        );
    }

    let mut signers = Vec::new();
    let mut revocations = Vec::new();
    let mut corrections = Vec::new();
    let mut retained_dissent = Vec::new();
    let mut applied_targets: BTreeSet<(String, Vec<String>)> = BTreeSet::new();
    let mut seen_targets: BTreeMap<(String, Vec<String>), String> = BTreeMap::new();
    let mut seen_entry_ids = BTreeSet::new();
    let mut previous_digest: Option<String> = None;
    let mut any_signature_valid = false;
    let mut any_authorized = false;

    for (index, envelope) in registry.entries.iter().enumerate() {
        let envelope_value =
            serde_json::to_value(envelope).map_err(|error| RevocationError::Canonical {
                message: error.to_string(),
            })?;
        let envelope_bytes = canonical_value_bytes(&envelope_value)?;
        let parsed = parse_envelope_for(&envelope_bytes, REVOCATION_ENTRY_PAYLOAD_TYPE).map_err(
            |error| RevocationError::Invalid {
                message: format!("entry {}: {error}", index + 1),
            },
        )?;
        let payload = decode_canonical("entry payload", &parsed.payload)?;
        let entry_value = parse_strict(&payload).map_err(|error| RevocationError::Invalid {
            message: format!("entry {} payload: {error}", index + 1),
        })?;
        let entry: RevocationEntry =
            serde_json::from_value(entry_value).map_err(|error| RevocationError::Invalid {
                message: format!("entry {} payload: {error}", index + 1),
            })?;
        if entry.schema != REVOCATION_ENTRY_SCHEMA {
            return Err(RevocationError::Invalid {
                message: format!(
                    "entry {} schema {:?} is not {REVOCATION_ENTRY_SCHEMA}",
                    index + 1,
                    entry.schema
                ),
            });
        }
        if entry.spec != ETP_SPEC {
            return Err(RevocationError::Invalid {
                message: format!(
                    "entry {} spec {:?} is not {ETP_SPEC}",
                    index + 1,
                    entry.spec
                ),
            });
        }
        check_text("entry_id", &entry.entry_id)?;
        check_text("reason", &entry.reason)?;
        check_text("scope", &entry.scope)?;
        check_text("target claim_id", &entry.target.claim_id)?;
        check_text("target subject_identity", &entry.target.subject_identity)?;
        check_text("historical_replay", &entry.historical_replay)?;
        if entry.historical_replay != "valid_under_original_policy"
            && entry.historical_replay != "not_valid"
        {
            return Err(RevocationError::Invalid {
                message: format!(
                    "entry {:?} historical_replay {:?} is not a declared value",
                    entry.entry_id, entry.historical_replay
                ),
            });
        }
        if entry.target.evidence_ids.len() > MAX_TARGET_EVIDENCE {
            return Err(RevocationError::Invalid {
                message: format!(
                    "entry {} target exceeds {MAX_TARGET_EVIDENCE} evidence ids",
                    index + 1
                ),
            });
        }
        if !seen_entry_ids.insert(entry.entry_id.clone()) {
            return Err(RevocationError::Invalid {
                message: format!("duplicate entry_id {:?}", entry.entry_id),
            });
        }
        let expected_sequence = u64::try_from(index).unwrap_or(u64::MAX) + 1;
        if entry.sequence != expected_sequence {
            return Err(RevocationError::Invalid {
                message: format!(
                    "entry {:?} sequence {} is not expected {}",
                    entry.entry_id, entry.sequence, expected_sequence
                ),
            });
        }
        if entry.previous_entry_sha256 != previous_digest {
            return Err(RevocationError::Invalid {
                message: format!(
                    "entry {:?} previous digest {:?} does not match {:?}",
                    entry.entry_id, entry.previous_entry_sha256, previous_digest
                ),
            });
        }
        previous_digest = Some(envelope_digest(envelope)?);

        let mut entry_context_ok = true;
        if entry.registry_id != registry.registry_id
            || entry.policy_id != registry.policy_id
            || entry.policy_version != registry.policy_version
        {
            entry_context_ok = false;
            push_refusal(
                &mut refusals,
                RevocationRefusalCode::ReplayedRevocation,
                format!(
                    "entry {:?} is bound to registry {}/{}/{} but is presented in {}/{}/{}",
                    entry.entry_id,
                    entry.registry_id,
                    entry.policy_id,
                    entry.policy_version,
                    registry.registry_id,
                    registry.policy_id,
                    registry.policy_version
                ),
            );
        }

        let mut entry_authorized = false;
        let mut entry_valid_signer = false;
        let mut entry_distinct_actors: BTreeSet<String> = BTreeSet::new();
        for signature in &parsed.signatures {
            let Some((role, key)) = policy.resolve(&signature.keyid) else {
                signers.push(RevocationSignerReport {
                    entry_id: entry.entry_id.clone(),
                    keyid: signature.keyid.clone(),
                    actor: None,
                    roles: Vec::new(),
                    signature_valid: false,
                    authorized: false,
                    within_validity: false,
                    detail: "key is not present in the trust policy".to_owned(),
                });
                push_refusal(
                    &mut refusals,
                    RevocationRefusalCode::UnknownKey,
                    format!(
                        "entry {:?} names unknown key {:?}",
                        entry.entry_id, signature.keyid
                    ),
                );
                continue;
            };
            let signature_bytes = decode_canonical("signature", &signature.sig)?;
            let public_key = decode_canonical("public key", &key.public_key_base64)?;
            let message = pae(REVOCATION_ENTRY_PAYLOAD_TYPE, &payload).map_err(|error| {
                RevocationError::Invalid {
                    message: error.to_string(),
                }
            })?;
            let signature_valid = verify_ed25519(&public_key, &message, &signature_bytes);
            let within_validity = now_unix >= key.not_before_unix && now_unix <= key.not_after_unix;
            // The correction authority is defined by role, not by the
            // in-toto predicate scope list. A revocation entry is not an
            // in-toto predicate, so the predicate scope is not applied here.
            let role_authorized = role.id == ROLE_CORRECTION_AUTHORITY;
            if signature_valid {
                any_signature_valid = true;
                entry_valid_signer = true;
            }
            if !signature_valid {
                push_refusal(
                    &mut refusals,
                    RevocationRefusalCode::InvalidSignature,
                    format!(
                        "entry {:?} signature by {:?} did not verify",
                        entry.entry_id, signature.keyid
                    ),
                );
            }
            if !role_authorized {
                push_refusal(
                    &mut refusals,
                    RevocationRefusalCode::UnauthorizedRole,
                    format!(
                        "entry {:?} signature by {:?} is in role {:?}, not {ROLE_CORRECTION_AUTHORITY}",
                        entry.entry_id, signature.keyid, role.id
                    ),
                );
            }
            if !within_validity {
                push_refusal(
                    &mut refusals,
                    RevocationRefusalCode::ExpiredCredential,
                    format!(
                        "entry {:?} key {:?} is outside {}..{} at {now_unix}",
                        entry.entry_id, signature.keyid, key.not_before_unix, key.not_after_unix
                    ),
                );
            }
            if signature_valid && role_authorized && within_validity {
                entry_distinct_actors.insert(key.actor.clone());
            }
            signers.push(RevocationSignerReport {
                entry_id: entry.entry_id.clone(),
                keyid: signature.keyid.clone(),
                actor: Some(key.actor.clone()),
                roles: vec![role.id.clone()],
                signature_valid,
                authorized: role_authorized,
                within_validity,
                detail: format!(
                    "signature {}; role {}; validity {}",
                    if signature_valid { "valid" } else { "invalid" },
                    if role_authorized {
                        "authorized"
                    } else {
                        "unauthorized"
                    },
                    if within_validity {
                        "current"
                    } else {
                        "expired"
                    }
                ),
            });
        }
        if let Some(role) = correction_role {
            let threshold = usize::try_from(role.threshold).unwrap_or(usize::MAX);
            if entry_distinct_actors.len() >= threshold && threshold > 0 {
                entry_authorized = true;
                any_authorized = true;
            } else {
                push_refusal(
                    &mut refusals,
                    RevocationRefusalCode::InsufficientAuthority,
                    format!(
                        "entry {:?} has {} distinct authorized actors, threshold {threshold}",
                        entry.entry_id,
                        entry_distinct_actors.len()
                    ),
                );
            }
        }
        let entry_applies = entry_authorized && entry_context_ok && entry_valid_signer;

        match entry.action {
            RevocationAction::Revoke => {
                let key = support_target_key(&entry.target);
                if let Some(previous) = seen_targets.get(&key) {
                    push_refusal(
                        &mut refusals,
                        RevocationRefusalCode::DuplicateRevocation,
                        format!(
                            "target {:?} is revoked by both {:?} and {:?}",
                            entry.target.claim_id, previous, entry.entry_id
                        ),
                    );
                } else {
                    seen_targets.insert(key.clone(), entry.entry_id.clone());
                }
                if entry_applies && !applied_targets.contains(&key) {
                    applied_targets.insert(key);
                }
                revocations.push(RevocationRecordReport {
                    entry_id: entry.entry_id.clone(),
                    claim_id: entry.target.claim_id.clone(),
                    evidence_ids: entry.target.evidence_ids.clone(),
                    effective_at_unix: entry.effective_at_unix,
                    historical_replay: entry.historical_replay.clone(),
                    scope: entry.scope.clone(),
                    reason: entry.reason.clone(),
                    applied: entry_applies,
                });
            }
            RevocationAction::Correct => {
                let statement = entry.statement.clone().unwrap_or_default();
                check_text("correction statement", &statement)?;
                corrections.push(CorrectionRecordReport {
                    entry_id: entry.entry_id.clone(),
                    claim_id: entry.target.claim_id.clone(),
                    corrects_entry_id: entry.corrects_entry_id.clone(),
                    statement,
                    effective_at_unix: entry.effective_at_unix,
                    retained: true,
                });
            }
            RevocationAction::Dissent => {
                let statement = entry.statement.clone().unwrap_or_default();
                check_text("dissent statement", &statement)?;
                retained_dissent.push(DissentRecordReport {
                    entry_id: entry.entry_id.clone(),
                    claim_id: entry.target.claim_id.clone(),
                    statement,
                    effective_at_unix: entry.effective_at_unix,
                    retained: true,
                });
            }
        }
    }

    let mut dimensions = RevocationDimensions {
        registry_integrity: crate::etp_auth::DimensionState::Valid,
        sequence_integrity: crate::etp_auth::DimensionState::Valid,
        signature_validity: if any_signature_valid {
            crate::etp_auth::DimensionState::Valid
        } else {
            crate::etp_auth::DimensionState::Invalid
        },
        authorization: if any_authorized {
            crate::etp_auth::DimensionState::Valid
        } else {
            crate::etp_auth::DimensionState::Invalid
        },
        policy_freshness: if policy_fresh {
            crate::etp_auth::DimensionState::Valid
        } else {
            crate::etp_auth::DimensionState::Invalid
        },
        historical_replay: crate::etp_auth::DimensionState::NotChecked,
        present_authorization: crate::etp_auth::DimensionState::NotChecked,
    };

    let support_report = support.map(|model| {
        apply_support(
            model,
            historical,
            &applied_targets,
            now_unix,
            &mut refusals,
            &mut dimensions,
        )
    });

    if support_report.is_none() {
        dimensions.historical_replay = crate::etp_auth::DimensionState::NotChecked;
        dimensions.present_authorization = crate::etp_auth::DimensionState::NotChecked;
    }

    let status = if refusals.is_empty() {
        RevocationStatus::Verified
    } else {
        RevocationStatus::Refused
    };
    Ok(RevocationReport {
        schema: REVOCATION_REPORT_SCHEMA.to_owned(),
        spec: ETP_SPEC.to_owned(),
        status,
        registry_id: registry.registry_id,
        registry_sha256: sha256_hex(registry_bytes),
        entry_count: registry.entries.len(),
        policy_id: policy.policy_id.clone(),
        policy_version: policy.version,
        dimensions,
        signers,
        revocations,
        corrections,
        retained_dissent,
        support: support_report,
        refusals,
        unsupported_features: vec![
            "transparency_inclusion".to_owned(),
            "witness_observation".to_owned(),
            "public_revocation_feed".to_owned(),
            "global_non_equivocation".to_owned(),
        ],
        claim_ceiling: REVOCATION_CLAIM_CEILING.to_owned(),
    })
}

#[allow(clippy::if_not_else)]
#[allow(clippy::too_many_lines)]
fn apply_support(
    model: &SupportModel,
    historical: Option<&HistoricVerdict>,
    applied_targets: &BTreeSet<(String, Vec<String>)>,
    now_unix: u64,
    refusals: &mut Vec<RevocationRefusal>,
    dimensions: &mut RevocationDimensions,
) -> SupportApplicationReport {
    let policy_digest = model
        .policy
        .digest()
        .map_or_else(|_| "unavailable".to_owned(), |digest| digest.to_string());
    let mut present_revoked: BTreeSet<String> = BTreeSet::new();
    for (claim_id, evidence_ids) in applied_targets {
        if evidence_ids.is_empty() {
            present_revoked.insert(claim_id.clone());
        } else {
            present_revoked.extend(evidence_ids.iter().cloned());
        }
    }
    for (claim_id, evidence_ids) in applied_targets {
        if !model.claims.iter().any(|claim| &claim.id == claim_id) {
            push_refusal(
                refusals,
                RevocationRefusalCode::MissingSupport,
                format!("revocation target claim {claim_id:?} is absent from the support model"),
            );
        }
        if evidence_ids.iter().any(|evidence| {
            !model
                .claims
                .iter()
                .any(|claim| claim.evidence_ids.contains(evidence))
                && !model.policy.rules.nodes().contains(evidence)
        }) {
            push_refusal(
                refusals,
                RevocationRefusalCode::MissingSupport,
                format!(
                    "revocation target evidence for {claim_id:?} is absent from the support graph"
                ),
            );
        }
    }

    let mut present_challenged: BTreeSet<String> = BTreeSet::new();
    for claim in &model.claims {
        for record in &claim.contradictory {
            if !record.retained {
                push_refusal(
                    refusals,
                    RevocationRefusalCode::ContradictionNotRetained,
                    format!(
                        "claim {:?} contradictory record {:?} is not retained",
                        claim.id, record.id
                    ),
                );
            }
            if record.resolution == "unresolved" {
                present_challenged.insert(claim.id.clone());
            }
        }
    }

    let recorded_revoked: BTreeSet<String> =
        model.historical_recording.revoked.iter().cloned().collect();
    let recorded_challenged: BTreeSet<String> = model
        .historical_recording
        .challenged
        .iter()
        .cloned()
        .collect();
    let historical_eval = evaluate(&model.policy.rules, &recorded_revoked, &recorded_challenged);
    let present_eval = evaluate(&model.policy.rules, &present_revoked, &present_challenged);

    let freshness_ok = now_unix >= model.not_before_unix && now_unix <= model.not_after_unix;
    if !freshness_ok {
        push_refusal(
            refusals,
            RevocationRefusalCode::StaleSupportPolicy,
            format!(
                "support policy validity window {}..{} does not contain verification time {now_unix}",
                model.not_before_unix, model.not_after_unix
            ),
        );
    }

    let historical_valid = match historical {
        Some(verdict) => {
            let matches_recording = verdict.revoked == recorded_revoked
                && verdict.challenged == recorded_challenged
                && verdict.policy_id == model.policy.id
                && verdict.policy_version == model.policy.version;
            if !matches_recording {
                push_refusal(
                    refusals,
                    RevocationRefusalCode::HistoricalReplayMismatch,
                    "recorded historical verdict does not match the declared recording".to_owned(),
                );
                false
            } else {
                match verdict.verify(&model.policy) {
                    Ok(()) => true,
                    Err(error) => {
                        push_refusal(
                            refusals,
                            RevocationRefusalCode::HistoricalReplayMismatch,
                            error.to_string(),
                        );
                        false
                    }
                }
            }
        }
        None => false,
    };
    dimensions.historical_replay = if historical.is_some() {
        if historical_valid {
            crate::etp_auth::DimensionState::Valid
        } else {
            crate::etp_auth::DimensionState::Invalid
        }
    } else {
        crate::etp_auth::DimensionState::NotChecked
    };

    let mut claims = Vec::new();
    let mut invalidated = Vec::new();
    let mut alternative_survives = Vec::new();
    let mut withheld = Vec::new();
    for claim in &model.claims {
        let historical_state = historical_eval
            .states
            .get(&claim.id)
            .copied()
            .unwrap_or(SupportState::Unsupported);
        let present_state = present_eval
            .states
            .get(&claim.id)
            .copied()
            .unwrap_or(SupportState::Unsupported);
        let historically_supported = historical_eval.positive.contains(&claim.id);
        let presently_supported = present_eval.positive.contains(&claim.id);
        let present_admissible = present_eval.admissible.contains(&claim.id) && freshness_ok;
        let revoked_evidence: Vec<String> = claim
            .evidence_ids
            .iter()
            .filter(|evidence| present_revoked.contains(*evidence))
            .cloned()
            .collect();
        let alternative_support = presently_supported && !revoked_evidence.is_empty();
        let contradictory_retained: Vec<String> = claim
            .contradictory
            .iter()
            .filter(|record| record.retained)
            .map(|record| record.id.clone())
            .collect();
        if historically_supported && !presently_supported {
            invalidated.push(claim.id.clone());
        }
        if alternative_support {
            alternative_survives.push(claim.id.clone());
        }
        if presently_supported && !present_admissible {
            withheld.push(claim.id.clone());
        }
        claims.push(ClaimSupportReport {
            claim_id: claim.id.clone(),
            historical_state,
            present_state,
            present_admissible,
            historically_supported,
            presently_supported,
            revoked_evidence,
            alternative_support,
            contradictory_retained,
        });
    }
    if freshness_ok {
        dimensions.present_authorization = crate::etp_auth::DimensionState::Valid;
    } else {
        dimensions.present_authorization = crate::etp_auth::DimensionState::Invalid;
    }
    SupportApplicationReport {
        policy_id: model.policy.id.clone(),
        policy_version: model.policy.version.clone(),
        policy_digest,
        recorded_at_unix: model.historical_recording.recorded_at_unix,
        historical_verdict_valid: historical_valid,
        present_freshness: if freshness_ok { "current" } else { "stale" }.to_owned(),
        claims,
        invalidated,
        alternative_survives,
        withheld,
    }
}

/// Load and verify a registry file.
///
/// # Errors
///
/// Returns [`RevocationError`] for I/O or structural failures.
pub fn verify_registry_file(
    registry_path: &Path,
    policy_path: &Path,
    support_path: Option<&Path>,
    historical_path: Option<&Path>,
    now_unix: u64,
) -> Result<RevocationReport, RevocationError> {
    let registry_bytes = fs::read(registry_path).map_err(|error| RevocationError::Io {
        message: format!("cannot read {}: {error}", registry_path.display()),
    })?;
    let policy_bytes = fs::read(policy_path).map_err(|error| RevocationError::Io {
        message: format!("cannot read {}: {error}", policy_path.display()),
    })?;
    let policy = parse_policy(&policy_bytes).map_err(|error| RevocationError::Invalid {
        message: format!("{}: {error}", policy_path.display()),
    })?;
    let support = match support_path {
        Some(path) => {
            let bytes = fs::read(path).map_err(|error| RevocationError::Io {
                message: format!("cannot read {}: {error}", path.display()),
            })?;
            Some(parse_support_model(&bytes)?)
        }
        None => None,
    };
    let historical = match historical_path {
        Some(path) => {
            let bytes = fs::read(path).map_err(|error| RevocationError::Io {
                message: format!("cannot read {}: {error}", path.display()),
            })?;
            Some(parse_historical_verdict(&bytes)?)
        }
        None => None,
    };
    verify_registry_bytes(
        &registry_bytes,
        &policy,
        support.as_ref(),
        historical.as_ref(),
        now_unix,
    )
}

/// Record a historical verdict under the support model's original policy.
///
/// # Errors
///
/// Returns [`RevocationError`] when the support rules are invalid or the
/// verdict cannot be encoded.
pub fn record_historical_verdict(model: &SupportModel) -> Result<HistoricVerdict, RevocationError> {
    let revoked: BTreeSet<String> = model.historical_recording.revoked.iter().cloned().collect();
    let challenged: BTreeSet<String> = model
        .historical_recording
        .challenged
        .iter()
        .cloned()
        .collect();
    HistoricVerdict::record(&model.policy, &revoked, &challenged).map_err(|error| {
        RevocationError::Invalid {
            message: error.to_string(),
        }
    })
}

/// Build the support model for the committed Phase 10.4a evidence.
///
/// The returned model is constructed from the declared rules and claims. It is
/// used by the gate helper that records the historical verdict.
///
/// # Errors
///
/// Returns [`RevocationError`] when the rules are structurally invalid.
#[allow(clippy::too_many_lines)]
pub fn committed_support_model() -> Result<SupportModel, RevocationError> {
    let mut rules = RuleSystem::new();
    for leaf in [
        "evidence.closure",
        "evidence.mirror",
        "evidence.sarif",
        "evidence.attestation",
    ] {
        rules.admit_leaf(leaf);
    }
    rules
        .add_rule("claim.campaign-closure", ["evidence.closure".to_owned()])
        .map_err(|error| RevocationError::Invalid {
            message: error.to_string(),
        })?;
    rules
        .add_rule(
            "claim.campaign-closure-with-mirror",
            ["evidence.closure".to_owned()],
        )
        .map_err(|error| RevocationError::Invalid {
            message: error.to_string(),
        })?;
    rules
        .add_rule(
            "claim.campaign-closure-with-mirror",
            ["evidence.mirror".to_owned()],
        )
        .map_err(|error| RevocationError::Invalid {
            message: error.to_string(),
        })?;
    rules
        .add_rule(
            "claim.sarif-projection",
            [
                "claim.campaign-closure".to_owned(),
                "evidence.sarif".to_owned(),
            ],
        )
        .map_err(|error| RevocationError::Invalid {
            message: error.to_string(),
        })?;
    rules
        .add_rule(
            "claim.attested-closure",
            [
                "claim.campaign-closure".to_owned(),
                "evidence.attestation".to_owned(),
            ],
        )
        .map_err(|error| RevocationError::Invalid {
            message: error.to_string(),
        })?;
    let claims = vec![
        SupportClaim {
            id: "claim.campaign-closure".to_owned(),
            evidence_ids: vec!["evidence.closure".to_owned()],
            contradictory: vec![],
        },
        SupportClaim {
            id: "claim.campaign-closure-with-mirror".to_owned(),
            evidence_ids: vec!["evidence.closure".to_owned(), "evidence.mirror".to_owned()],
            contradictory: vec![],
        },
        SupportClaim {
            id: "claim.sarif-projection".to_owned(),
            evidence_ids: vec!["evidence.closure".to_owned(), "evidence.sarif".to_owned()],
            contradictory: vec![ContradictoryRecord {
                id: "contradiction.sarif-nondeterministic-case".to_owned(),
                class: "observation_record".to_owned(),
                statement: "the nondeterministic case has an unresolved replay observation"
                    .to_owned(),
                source: "evaluation/earned-trust/MANIFEST.json".to_owned(),
                retained: true,
                resolution: "unresolved".to_owned(),
            }],
        },
        SupportClaim {
            id: "claim.attested-closure".to_owned(),
            evidence_ids: vec![
                "evidence.closure".to_owned(),
                "evidence.attestation".to_owned(),
            ],
            contradictory: vec![],
        },
    ];
    Ok(SupportModel {
        schema: SUPPORT_MODEL_SCHEMA.to_owned(),
        spec: ETP_SPEC.to_owned(),
        policy: SupportPolicy {
            id: "frf-etp-phase10.4a-support-policy".to_owned(),
            version: "1".to_owned(),
            rules,
        },
        not_before_unix: 1_795_305_600,
        not_after_unix: 1_826_841_600,
        historical_recording: HistoricalRecording {
            recorded_at_unix: 1_795_305_600,
            revoked: vec![],
            challenged: vec![],
        },
        claims,
    })
}

/// Return the present support result for a model and a revocation set.
///
/// This is exposed for tests and independent reconstruction helpers. It is not a
/// truth operation.
#[must_use]
pub fn evaluate_support(
    model: &SupportModel,
    revoked: &BTreeSet<String>,
    challenged: &BTreeSet<String>,
) -> SupportResult {
    evaluate(&model.policy.rules, revoked, challenged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_model_has_alternative_support() {
        let model = committed_support_model().expect("model");
        let mut revoked = BTreeSet::new();
        revoked.insert("evidence.closure".to_owned());
        let result = evaluate_support(&model, &revoked, &BTreeSet::new());
        assert!(!result.positive.contains("claim.campaign-closure"));
        assert!(result
            .positive
            .contains("claim.campaign-closure-with-mirror"));
    }

    #[test]
    fn committed_model_retains_a_contradiction() {
        let model = committed_support_model().expect("model");
        let claim = model
            .claims
            .iter()
            .find(|claim| claim.id == "claim.sarif-projection")
            .expect("claim");
        assert!(claim.contradictory.iter().all(|record| record.retained));
    }

    #[test]
    fn target_key_sorts_and_deduplicates_evidence() {
        let target = RevocationTarget {
            claim_id: "c".to_owned(),
            policy_id: "p".to_owned(),
            evidence_ids: vec!["b".to_owned(), "a".to_owned(), "a".to_owned()],
            subject_identity: "s".to_owned(),
        };
        let (claim, evidence) = support_target_key(&target);
        assert_eq!(claim, "c");
        assert_eq!(evidence, vec!["a".to_owned(), "b".to_owned()]);
    }
}
