#![allow(clippy::module_name_repetitions)]
#![allow(
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::single_match_else,
    clippy::too_many_lines
)]

//! Phase 10.4b pinned local transparency profile with real proofs.
//!
//! # What this module establishes
//!
//! A verified proof establishes only that:
//!
//! * the exact entry bytes declared by the proof hash to the declared leaf;
//! * the leaf is included at the declared index in an RFC 6962 Merkle tree of
//!   the declared size;
//! * the tree root equals the root signed by the caller-pinned log key in the
//!   declared C2SP checkpoint;
//! * the checkpoint is consistent with the caller-supplied known horizon when
//!   the proof carries a consistency proof;
//! * the supplied tiles reconstruct the same root and audit path.
//!
//! It does **not** establish semantic validity, completeness, non-equivocation,
//! public transparency, witness observation, or trusted time. Inclusion is not
//! semantic validity. Inclusion is not completeness. A witness quorum is not a
//! protocol proof.
//!
//! # Trust domain
//!
//! The committed artifacts are produced by a local, test-only tlog-tiles log
//! built from `transparency-dev/tessera` v1.0.4. The log private key was
//! generated inside the hardened gate container under `target/` and discarded.
//! `external_trust` and `public_transparency` are always `false`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::etp::ETP_SPEC;
use crate::etp_auth::DimensionState;
use crate::identity::hex_lower;

/// Proof schema identifier.
pub const PROOF_SCHEMA: &str = "frf-etp.transparency-proof.v1";
/// Transparency policy schema identifier.
pub const POLICY_SCHEMA: &str = "frf-etp.transparency-policy.v1";
/// Verification report schema identifier.
pub const REPORT_SCHEMA: &str = "frf-etp.transparency-verification.v1";
/// Checkpoint-only report schema identifier.
pub const CHECKPOINT_REPORT_SCHEMA: &str = "frf-etp.checkpoint-verification.v1";
/// Pinned log API version.
pub const LOG_VERSION_TILES_V1: &str = "tlog-tiles-v1";
/// Pinned checkpoint version.
pub const CHECKPOINT_VERSION_V1: &str = "tlog-checkpoint-v1";
/// Claim ceiling carried by every report.
pub const TRANSPARENCY_CLAIM_CEILING: &str = "A verified local transparency proof establishes only that the exact entry bytes hash to the declared leaf and that the leaf is included at the declared index in an RFC 6962 Merkle tree whose signed root equals the caller-pinned local log checkpoint, consistent with the caller-supplied known horizon when a consistency proof is present. It does not establish semantic validity, completeness, non-equivocation, public transparency, witness observation, trusted time, independent review, or release authorization. Inclusion is not semantic validity and not completeness. A witness quorum is not a protocol proof.";
/// Maximum proof JSON bytes.
pub const MAX_PROOF_BYTES: u64 = 32 * 1024 * 1024;
/// Maximum proof entry bytes (tlog-tiles entry limit).
pub const MAX_ENTRY_BYTES: usize = 64 * 1024;
/// Maximum checkpoint bytes.
pub const MAX_CHECKPOINT_BYTES: usize = 64 * 1024;
/// Maximum audit-path nodes.
pub const MAX_AUDIT_PATH: usize = 64;
/// Maximum tile records.
pub const MAX_TILES: usize = 64;
/// Maximum tile bytes (256 * 32).
pub const MAX_TILE_BYTES: usize = 8 * 1024;
/// Maximum declared tree size for in-memory reconstruction.
pub const MAX_TREE_SIZE: u64 = 1_000_000;
/// Maximum extension lines in a checkpoint.
pub const MAX_CHECKPOINT_EXTENSIONS: usize = 8;
/// Maximum note signature lines.
pub const MAX_NOTE_SIGNATURES: usize = 16;

/// The local log's trust-profile label.
pub const LOCAL_TEST_LOG_TRUST_PROFILE: &str = "local-test-tlog-tiles";

/// Stable labels for the separate verification dimensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransparencyDimensions {
    /// The proof, checkpoint, and policy identify one log.
    pub log_identity: DimensionState,
    /// The pinned log API version is supported.
    pub log_version: DimensionState,
    /// The declared entry bytes hash to the declared leaf input.
    pub entry_binding: DimensionState,
    /// The declared leaf hash equals SHA-256(0x00 || entry).
    pub leaf_hash: DimensionState,
    /// The RFC 6962 inclusion path reaches the checkpoint root.
    pub inclusion: DimensionState,
    /// The checkpoint carries a valid signature from the pinned log key.
    pub checkpoint_signature: DimensionState,
    /// The checkpoint bytes equal the declared digest and persisted bytes.
    pub checkpoint_persistence: DimensionState,
    /// The checkpoint is consistent with the known horizon.
    pub consistency: DimensionState,
    /// Equal-size conflicting roots are detected.
    pub conflict_detection: DimensionState,
    /// A stale or rolled-back checkpoint is refused.
    pub anti_rollback: DimensionState,
    /// Declared tiles reconstruct the root and audit path.
    pub tiled_reconstruction: DimensionState,
    /// A proof for another log is refused.
    pub cross_log_rejection: DimensionState,
    /// Verification uses no network or provider service.
    pub offline_verification: DimensionState,
}

impl Default for TransparencyDimensions {
    fn default() -> Self {
        Self {
            log_identity: DimensionState::NotChecked,
            log_version: DimensionState::NotChecked,
            entry_binding: DimensionState::NotChecked,
            leaf_hash: DimensionState::NotChecked,
            inclusion: DimensionState::NotChecked,
            checkpoint_signature: DimensionState::NotChecked,
            checkpoint_persistence: DimensionState::NotChecked,
            consistency: DimensionState::NotChecked,
            conflict_detection: DimensionState::NotChecked,
            anti_rollback: DimensionState::NotChecked,
            tiled_reconstruction: DimensionState::NotApplicable,
            cross_log_rejection: DimensionState::NotChecked,
            offline_verification: DimensionState::Valid,
        }
    }
}

/// Overall transparency verification status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparencyStatus {
    /// Every required dimension verified.
    Verified,
    /// A dimension failed or a contradiction was detected.
    Refused,
    /// A required capability or external observation is unavailable.
    NotRun,
    /// Some declared dimensions were checked and none failed, but a required
    /// dimension (for example a consistency proof) was not available.
    Partial,
    /// The supplied bytes are malformed or digest-mismatched.
    IntegrityFailure,
}

impl TransparencyStatus {
    /// Stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Refused => "refused",
            Self::NotRun => "not_run",
            Self::Partial => "partial",
            Self::IntegrityFailure => "integrity_failure",
        }
    }

    /// `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Verified | Self::Partial => 0,
            Self::Refused => 4,
            Self::NotRun => 6,
            Self::IntegrityFailure => 3,
        }
    }
}

/// One refusal reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparencyRefusalCode {
    /// Malformed checkpoint note.
    MalformedCheckpoint,
    /// Malformed proof JSON or field.
    MalformedProof,
    /// Malformed policy JSON or field.
    MalformedPolicy,
    /// Unsupported log API version.
    UnsupportedLogVersion,
    /// Unsupported checkpoint version.
    UnsupportedCheckpointVersion,
    /// The proof, checkpoint, or policy identify different logs.
    CrossLogProof,
    /// The log identity disagrees inside one log identity.
    LogIdentityMismatch,
    /// The declared entry digest does not match the entry bytes.
    EntryDigestMismatch,
    /// The declared leaf hash does not match the entry bytes.
    LeafHashMismatch,
    /// The audit path does not reach the signed root.
    InclusionInvalid,
    /// The proof root and checkpoint root disagree.
    RootMismatch,
    /// The checkpoint signature is absent or invalid.
    InvalidCheckpointSignature,
    /// The checkpoint bytes do not match the declared digest.
    CheckpointDigestMismatch,
    /// The checkpoint digest disagrees with the persisted horizon.
    CheckpointPersistenceMismatch,
    /// A consistency proof is required but absent.
    MissingConsistencyProof,
    /// The consistency proof does not verify.
    ConsistencyInvalid,
    /// The checkpoint is older than the known horizon.
    Rollback,
    /// Two equal-size checkpoints have different roots.
    ConflictingCheckpoint,
    /// A tile record is malformed.
    MalformedTile,
    /// The tiles reconstruct a different root.
    TiledRootMismatch,
    /// The tile leaf disagrees with the declared leaf.
    TileLeafMismatch,
    /// The tiles reconstruct a different audit path.
    TiledProofMismatch,
    /// The policy has no usable horizon and rollback cannot be excluded.
    AntiRollbackUninitialized,
    /// The requested verification requires an external observation.
    ExternalObservationRequired,
    /// No pinned policy was supplied, so authenticity was not checked.
    PolicyNotSupplied,
    /// The consistency between two tree sizes was not checked.
    ConsistencyNotChecked,
}

impl TransparencyRefusalCode {
    /// Stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedCheckpoint => "malformed_checkpoint",
            Self::MalformedProof => "malformed_proof",
            Self::MalformedPolicy => "malformed_policy",
            Self::UnsupportedLogVersion => "unsupported_log_version",
            Self::UnsupportedCheckpointVersion => "unsupported_checkpoint_version",
            Self::CrossLogProof => "cross_log_proof",
            Self::LogIdentityMismatch => "log_identity_mismatch",
            Self::EntryDigestMismatch => "entry_digest_mismatch",
            Self::LeafHashMismatch => "leaf_hash_mismatch",
            Self::InclusionInvalid => "inclusion_invalid",
            Self::RootMismatch => "root_mismatch",
            Self::InvalidCheckpointSignature => "invalid_checkpoint_signature",
            Self::CheckpointDigestMismatch => "checkpoint_digest_mismatch",
            Self::CheckpointPersistenceMismatch => "checkpoint_persistence_mismatch",
            Self::MissingConsistencyProof => "missing_consistency_proof",
            Self::ConsistencyInvalid => "consistency_invalid",
            Self::Rollback => "rollback",
            Self::ConflictingCheckpoint => "conflicting_checkpoint",
            Self::MalformedTile => "malformed_tile",
            Self::TiledRootMismatch => "tiled_root_mismatch",
            Self::TileLeafMismatch => "tile_leaf_mismatch",
            Self::TiledProofMismatch => "tiled_proof_mismatch",
            Self::AntiRollbackUninitialized => "anti_rollback_uninitialized",
            Self::ExternalObservationRequired => "external_observation_required",
            Self::PolicyNotSupplied => "policy_not_supplied",
            Self::ConsistencyNotChecked => "consistency_not_checked",
        }
    }
}

/// One refusal with a detail string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransparencyRefusal {
    /// Refusal code.
    pub code: TransparencyRefusalCode,
    /// Human-readable detail.
    pub detail: String,
}

/// Log identity summary carried by a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogIdentitySummary {
    /// Checkpoint origin line.
    pub origin: String,
    /// Local log identifier, `sha256:` over the origin.
    pub log_id: String,
    /// Public note verifier key.
    pub vkey: String,
    /// SHA-256 over the raw 32-byte Ed25519 public key.
    pub public_key_sha256: String,
    /// Signature algorithm label.
    pub algorithm: String,
}

/// A known anti-rollback horizon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownHorizon {
    /// Tree size.
    pub tree_size: u64,
    /// Root hash, lowercase hexadecimal.
    pub root_hash: String,
    /// Checkpoint digest, lowercase hexadecimal.
    pub checkpoint_sha256: String,
}

/// Anti-rollback policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntiRollbackPolicy {
    /// Highest trusted horizons, unordered.
    pub known_horizons: Vec<KnownHorizon>,
    /// Persistence label, normally `caller_supplied`.
    pub persistence: String,
}

/// Pinned log identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogIdentity {
    /// Checkpoint origin line.
    pub origin: String,
    /// Local log identifier.
    pub log_id: String,
    /// Raw 32-byte Ed25519 public key, canonical base64.
    pub public_key_base64: String,
    /// Full note verifier key (`name+keyid+base64`).
    pub vkey: String,
    /// Algorithm label.
    pub algorithm: String,
    /// Supported log API versions.
    pub supported_log_versions: Vec<String>,
    /// Supported checkpoint versions.
    pub supported_checkpoint_versions: Vec<String>,
    /// Whether the pinned key is external to this repository.
    pub external_trust: bool,
}

/// Transparency policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransparencyPolicy {
    /// Schema identifier.
    pub schema: String,
    /// ETP specification identifier.
    pub spec: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Trust profile label.
    pub trust_profile: String,
    /// Pinned log identity.
    pub log: LogIdentity,
    /// Anti-rollback state.
    pub anti_rollback: AntiRollbackPolicy,
    /// Whether a witness policy is required for this profile.
    pub witness_policy_required: bool,
    /// Witness policy identifier, when one is linked.
    pub witness_policy_id: Option<String>,
    /// Claim ceiling.
    pub claim_ceiling: String,
    /// Explicit non-claims.
    pub non_claims: Vec<String>,
}

/// One consistency proof block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsistencyProof {
    /// Older tree size.
    pub old_size: u64,
    /// Older root hash, lowercase hexadecimal.
    pub old_root: String,
    /// Newer tree size.
    pub new_size: u64,
    /// Newer root hash, lowercase hexadecimal.
    pub new_root: String,
    /// RFC 6962 consistency proof nodes, canonical base64.
    pub proof: Vec<String>,
}

/// One tile snapshot record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TileRecord {
    /// Tile level.
    pub level: u64,
    /// Tile index within the level.
    pub index: u64,
    /// Number of 32-byte hashes in the tile.
    pub width: u32,
    /// SHA-256 over the tile bytes.
    pub sha256: String,
    /// Tile bytes, canonical base64.
    pub base64: String,
}

/// Transparency proof bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransparencyProof {
    /// Schema identifier.
    pub schema: String,
    /// ETP specification identifier.
    pub spec: String,
    /// Log API version.
    pub log_version: String,
    /// Checkpoint origin.
    pub log_origin: String,
    /// Local log identifier.
    pub log_id: String,
    /// Tree size.
    pub tree_size: u64,
    /// Signed tree root, lowercase hexadecimal.
    pub root_hash: String,
    /// Leaf index.
    pub leaf_index: u64,
    /// Exact entry digest, lowercase hexadecimal.
    pub entry_sha256: String,
    /// Exact entry bytes, canonical base64.
    pub entry_base64: String,
    /// Declared leaf hash, lowercase hexadecimal.
    pub leaf_hash: String,
    /// RFC 6962 audit path, canonical base64.
    pub audit_path: Vec<String>,
    /// Exact checkpoint digest, lowercase hexadecimal.
    pub checkpoint_sha256: String,
    /// Optional consistency proof from a known horizon.
    #[serde(default)]
    pub consistency: Option<ConsistencyProof>,
    /// Optional tlog-tiles snapshot.
    #[serde(default)]
    pub tiles: Vec<TileRecord>,
}

/// Transparency verification report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransparencyReport {
    /// Schema identifier.
    pub schema: String,
    /// ETP specification identifier.
    pub spec: String,
    /// Overall status.
    pub status: TransparencyStatus,
    /// Policy identifier.
    pub policy_id: String,
    /// Log identity, when it parsed.
    pub log_identity: Option<LogIdentitySummary>,
    /// Tree size, when it parsed.
    pub tree_size: Option<u64>,
    /// Root hash, when it parsed.
    pub root_hash: Option<String>,
    /// Exact checkpoint digest, when it parsed.
    pub checkpoint_sha256: Option<String>,
    /// Leaf index, when it parsed.
    pub leaf_index: Option<u64>,
    /// Trust profile.
    pub trust_profile: Option<String>,
    /// Whether the log key is external.
    pub external_trust: bool,
    /// Whether this is a public transparency log.
    pub public_transparency: bool,
    /// Witness observation state.
    pub witness_observation: String,
    /// Separate verification dimensions.
    pub dimensions: TransparencyDimensions,
    /// Known horizons.
    pub known_horizons: Vec<KnownHorizon>,
    /// Declared assumptions.
    pub assumptions: Vec<String>,
    /// Features that are not implemented.
    pub unsupported_features: Vec<String>,
    /// Refusals.
    pub refusals: Vec<TransparencyRefusal>,
    /// Claim ceiling.
    pub claim_ceiling: String,
}

impl TransparencyReport {
    /// Canonical report bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the report cannot be canonicalized.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TransparencyError> {
        let value = serde_json::to_value(self).map_err(|error| TransparencyError::Canonical {
            message: error.to_string(),
        })?;
        crate::identity::canonical_bytes(&value).map_err(|error| TransparencyError::Canonical {
            message: error.to_string(),
        })
    }

    /// `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        self.status.exit_code()
    }
}

/// Checkpoint-only report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointReport {
    /// Schema identifier.
    pub schema: String,
    /// ETP specification identifier.
    pub spec: String,
    /// Overall status.
    pub status: TransparencyStatus,
    /// Checkpoint origin.
    pub origin: String,
    /// Tree size.
    pub tree_size: u64,
    /// Root hash, lowercase hexadecimal.
    pub root_hash: String,
    /// Exact checkpoint digest, lowercase hexadecimal.
    pub checkpoint_sha256: String,
    /// Signature verification state.
    pub signature: DimensionState,
    /// Signature count.
    pub signature_count: usize,
    /// Anti-rollback state.
    pub anti_rollback: DimensionState,
    /// Conflict-detection state.
    pub conflict_detection: DimensionState,
    /// Known horizons.
    pub known_horizons: Vec<KnownHorizon>,
    /// Refusals.
    pub refusals: Vec<TransparencyRefusal>,
    /// Claim ceiling.
    pub claim_ceiling: String,
}

impl CheckpointReport {
    /// Canonical report bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the report cannot be canonicalized.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TransparencyError> {
        let value = serde_json::to_value(self).map_err(|error| TransparencyError::Canonical {
            message: error.to_string(),
        })?;
        crate::identity::canonical_bytes(&value).map_err(|error| TransparencyError::Canonical {
            message: error.to_string(),
        })
    }

    /// `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        self.status.exit_code()
    }
}

/// Transparency error category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparencyErrorCategory {
    /// Invalid input or usage.
    Usage,
    /// Evidence integrity failure.
    Integrity,
    /// Internal harness error.
    Harness,
}

/// Transparency error.
#[derive(Debug)]
pub enum TransparencyError {
    /// Usage or input problem.
    Usage {
        /// Detail.
        message: String,
    },
    /// Integrity problem.
    Integrity {
        /// Detail.
        message: String,
    },
    /// Canonicalization problem.
    Canonical {
        /// Detail.
        message: String,
    },
    /// I/O problem.
    Io {
        /// Detail.
        message: String,
    },
}

impl TransparencyError {
    /// Error category.
    #[must_use]
    pub const fn category(&self) -> TransparencyErrorCategory {
        match self {
            Self::Usage { .. } => TransparencyErrorCategory::Usage,
            Self::Integrity { .. } => TransparencyErrorCategory::Integrity,
            Self::Canonical { .. } | Self::Io { .. } => TransparencyErrorCategory::Harness,
        }
    }

    /// `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self.category() {
            TransparencyErrorCategory::Usage => 2,
            TransparencyErrorCategory::Integrity => 3,
            TransparencyErrorCategory::Harness => 7,
        }
    }

    fn usage(message: impl Into<String>) -> Self {
        Self::Usage {
            message: message.into(),
        }
    }

    fn integrity(message: impl Into<String>) -> Self {
        Self::Integrity {
            message: message.into(),
        }
    }
}

impl fmt::Display for TransparencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage { message }
            | Self::Integrity { message }
            | Self::Canonical { message }
            | Self::Io { message } => formatter.write_str(message),
        }
    }
}

impl std::error::Error for TransparencyError {}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// SHA-256 over exact bytes.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// SHA-256, lowercase hexadecimal.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&sha256(bytes))
}

/// RFC 6962 leaf hash: SHA-256(0x00 || entry).
#[must_use]
pub fn leaf_hash(entry: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(entry.len() + 1);
    buf.push(0x00);
    buf.extend_from_slice(entry);
    sha256(&buf)
}

/// RFC 6962 interior node hash: SHA-256(0x01 || left || right).
#[must_use]
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = 0x01;
    buf[1..33].copy_from_slice(left);
    buf[33..].copy_from_slice(right);
    sha256(&buf)
}

/// The RFC 6962 empty-tree root: SHA-256 of the empty string.
#[must_use]
pub fn empty_root() -> [u8; 32] {
    sha256(&[])
}

/// Decode canonical base64.
///
/// # Errors
///
/// Returns an error on non-canonical or invalid base64.
pub fn decode_base64(value: &str) -> Result<Vec<u8>, TransparencyError> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|error| TransparencyError::integrity(format!("invalid base64: {error}")))?;
    if STANDARD.encode(&bytes) != value {
        return Err(TransparencyError::integrity(
            "base64 encoding is not canonical",
        ));
    }
    Ok(bytes)
}

/// Encode canonical base64.
#[must_use]
pub fn encode_base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decode lowercase or uppercase hexadecimal.
///
/// # Errors
///
/// Returns an error on an odd length or non-hexadecimal character.
pub fn decode_hex(value: &str) -> Result<Vec<u8>, TransparencyError> {
    if value.len() % 2 != 0 {
        return Err(TransparencyError::integrity("odd-length hexadecimal"));
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let hi = hex_nibble(bytes[index])?;
        let lo = hex_nibble(bytes[index + 1])?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, TransparencyError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(TransparencyError::integrity("non-hexadecimal digit")),
    }
}

/// Decode a 32-byte hexadecimal value.
///
/// # Errors
///
/// Returns an error unless the input is exactly 64 hexadecimal characters.
pub fn decode_hex32(value: &str) -> Result<[u8; 32], TransparencyError> {
    let bytes = decode_hex(value)?;
    if bytes.len() != 32 {
        return Err(TransparencyError::integrity(
            "expected a 32-byte hexadecimal digest",
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_b64_32(value: &str) -> Result<[u8; 32], TransparencyError> {
    let bytes = decode_base64(value)?;
    if bytes.len() != 32 {
        return Err(TransparencyError::integrity(
            "expected a 32-byte base64 value",
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_json<T: DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T, TransparencyError> {
    serde_json::from_slice(bytes)
        .map_err(|error| TransparencyError::integrity(format!("malformed {what}: {error}")))
}

fn check_text(value: &str, what: &str, max: usize) -> Result<(), TransparencyError> {
    if value.is_empty() || value.len() > max {
        return Err(TransparencyError::integrity(format!(
            "{what} length is outside 1..={max}"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(TransparencyError::integrity(format!(
            "{what} contains a control character"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RFC 6962 Merkle operations
// ---------------------------------------------------------------------------

/// Largest power of two strictly less than `n` (`n > 1`).
#[must_use]
pub fn split_point(n: u64) -> u64 {
    let mut k = 1u64;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// RFC 6962 Merkle Tree Hash over an ordered leaf-hash list.
#[must_use]
pub fn merkle_tree_hash(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = usize::try_from(split_point(n as u64)).unwrap_or(0);
            node_hash(
                &merkle_tree_hash(&leaves[..k]),
                &merkle_tree_hash(&leaves[k..]),
            )
        }
    }
}

/// RFC 6962 audit path for `index` in a tree of `leaves`.
///
/// # Errors
///
/// Returns an error when `index` is outside the tree.
pub fn audit_path(leaves: &[[u8; 32]], index: u64) -> Result<Vec<[u8; 32]>, TransparencyError> {
    let index = usize::try_from(index)
        .map_err(|_| TransparencyError::usage("leaf index does not fit in memory"))?;
    if index >= leaves.len() {
        return Err(TransparencyError::usage("leaf index is outside the tree"));
    }
    Ok(audit_path_inner(leaves, index))
}

fn audit_path_inner(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    if leaves.len() == 1 {
        return Vec::new();
    }
    let k = usize::try_from(split_point(leaves.len() as u64)).unwrap_or(0);
    if index < k {
        let mut path = audit_path_inner(&leaves[..k], index);
        path.push(merkle_tree_hash(&leaves[k..]));
        path
    } else {
        let mut path = audit_path_inner(&leaves[k..], index - k);
        path.push(merkle_tree_hash(&leaves[..k]));
        path
    }
}

/// Verify an RFC 6962 inclusion proof.
#[must_use]
pub fn verify_inclusion(
    index: u64,
    tree_size: u64,
    leaf: &[u8; 32],
    path: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if tree_size == 0 || index >= tree_size {
        return false;
    }
    let mut fn_ = index;
    let mut sn = tree_size - 1;
    let mut computed = *leaf;
    for sibling in path {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            computed = node_hash(sibling, &computed);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            computed = node_hash(&computed, sibling);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && computed == *root
}

/// Verify an RFC 6962 consistency proof between two tree sizes.
#[must_use]
pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if old_size == 0 {
        return proof.is_empty() && *old_root == empty_root();
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }
    if old_size > new_size || proof.is_empty() || new_size > MAX_TREE_SIZE {
        return false;
    }
    let Some((reconstructed_old, reconstructed_new)) =
        run_tree_proof(proof, 0, new_size, old_size, old_root)
    else {
        return false;
    };
    reconstructed_old == *old_root && reconstructed_new == *new_root
}

fn run_tree_proof(
    proof: &[[u8; 32]],
    lo: u64,
    hi: u64,
    n: u64,
    old: &[u8; 32],
) -> Option<([u8; 32], [u8; 32])> {
    if !(lo < n && n <= hi) {
        return None;
    }
    if n == hi {
        if lo == 0 {
            if !proof.is_empty() {
                return None;
            }
            return Some((*old, *old));
        }
        if proof.len() != 1 {
            return None;
        }
        return Some((proof[0], proof[0]));
    }
    if proof.is_empty() {
        return None;
    }
    let k = split_point(hi - lo);
    let last = proof[proof.len() - 1];
    let rest = &proof[..proof.len() - 1];
    if n <= lo + k {
        let (left_old, left_new) = run_tree_proof(rest, lo, lo + k, n, old)?;
        Some((left_old, node_hash(&left_new, &last)))
    } else {
        let (right_old, right_new) = run_tree_proof(rest, lo + k, hi, n, old)?;
        Some((node_hash(&last, &right_old), node_hash(&last, &right_new)))
    }
}

// ---------------------------------------------------------------------------
// Checkpoint note parsing
// ---------------------------------------------------------------------------

/// One note signature line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteSignature {
    /// Key name.
    pub name: String,
    /// First four bytes of the note key hash.
    pub keyid: [u8; 4],
    /// Decoded signature bytes, including the key id prefix.
    pub raw: Vec<u8>,
}

/// Parsed C2SP checkpoint that preserves the exact original bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Exact original bytes.
    pub original: Vec<u8>,
    /// Signed note text, ending with a newline.
    pub note_text: Vec<u8>,
    /// Log origin.
    pub origin: String,
    /// Tree size.
    pub size: u64,
    /// Root hash.
    pub root: [u8; 32],
    /// Extension lines.
    pub extensions: Vec<String>,
    /// Note signature lines.
    pub signatures: Vec<NoteSignature>,
    /// SHA-256 over the exact original bytes.
    pub sha256: String,
}

impl Checkpoint {
    /// Verify an Ed25519 log signature over the note text.
    #[must_use]
    pub fn verify_log_signature(&self, origin: &str, public_key: &[u8; 32]) -> bool {
        let Some(keyid) = note_key_id(origin, public_key, 0x01) else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        self.signatures.iter().any(|signature| {
            signature.name == origin
                && signature.keyid == keyid
                && signature.raw.len() == 4 + 64
                && Signature::from_slice(&signature.raw[4..]).is_ok_and(|parsed| {
                    verifying_key
                        .verify_strict(&self.note_text, &parsed)
                        .is_ok()
                })
        })
    }
}

/// Compute a signed-note key id.
///
/// `algorithm` is `0x01` for a log note key and `0x04` for a C2SP Ed25519
/// checkpoint cosigner.
#[must_use]
pub fn note_key_id(name: &str, public_key: &[u8; 32], algorithm: u8) -> Option<[u8; 4]> {
    if name.is_empty() || name.len() > 255 {
        return None;
    }
    let mut input = Vec::with_capacity(name.len() + 1 + 1 + 32);
    input.extend_from_slice(name.as_bytes());
    input.push(b'\n');
    input.push(algorithm);
    input.extend_from_slice(public_key);
    let digest = sha256(&input);
    Some([digest[0], digest[1], digest[2], digest[3]])
}

/// Parse a C2SP checkpoint note.
///
/// # Errors
///
/// Returns an error for malformed, oversized, or non-canonical input.
pub fn parse_checkpoint(bytes: &[u8]) -> Result<Checkpoint, TransparencyError> {
    if bytes.is_empty() || bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(TransparencyError::integrity(
            "checkpoint length is outside the supported range",
        ));
    }
    if std::str::from_utf8(bytes).is_err() {
        return Err(TransparencyError::integrity("checkpoint is not UTF-8"));
    }
    let split = find_signature_split(bytes)
        .ok_or_else(|| TransparencyError::integrity("checkpoint has no signature block"))?;
    let note_text = &bytes[..=split];
    let signature_block = &bytes[split + 2..];
    if !signature_block.ends_with(b"\n") {
        return Err(TransparencyError::integrity(
            "checkpoint signature block does not end with a newline",
        ));
    }
    let text = std::str::from_utf8(note_text)
        .map_err(|_| TransparencyError::integrity("checkpoint note text is not UTF-8"))?;
    if text
        .chars()
        .any(|character| character != '\n' && character.is_control())
    {
        return Err(TransparencyError::integrity(
            "checkpoint note text contains a control character",
        ));
    }
    let mut body_lines: Vec<&str> = text.split('\n').collect();
    let _ = body_lines.pop();
    if body_lines.len() < 3 {
        return Err(TransparencyError::integrity(
            "checkpoint must have at least three body lines",
        ));
    }
    if body_lines.iter().any(|line| line.is_empty()) {
        return Err(TransparencyError::integrity(
            "checkpoint body lines must be non-empty",
        ));
    }
    let origin = body_lines[0].to_owned();
    check_text(&origin, "checkpoint origin", 255)?;
    let size: u64 = body_lines[1]
        .parse()
        .map_err(|_| TransparencyError::integrity("checkpoint size is not a decimal integer"))?;
    if size > MAX_TREE_SIZE {
        return Err(TransparencyError::integrity(
            "checkpoint tree size exceeds the supported bound",
        ));
    }
    let root = decode_b64_32(body_lines[2])?;
    let extensions: Vec<String> = body_lines[3..]
        .iter()
        .map(|line| (*line).to_owned())
        .collect();
    if extensions.len() > MAX_CHECKPOINT_EXTENSIONS {
        return Err(TransparencyError::integrity(
            "checkpoint has too many extension lines",
        ));
    }

    let signature_text = std::str::from_utf8(signature_block)
        .map_err(|_| TransparencyError::integrity("checkpoint signatures are not UTF-8"))?;
    let mut signatures = Vec::new();
    let mut seen = BTreeSet::new();
    for line in signature_text.split('\n') {
        if line.is_empty() {
            continue;
        }
        let Some(rest) = line.strip_prefix("\u{2014} ") else {
            return Err(TransparencyError::integrity(
                "checkpoint signature line has no em-dash prefix",
            ));
        };
        let (name, encoded) = rest
            .split_once(' ')
            .ok_or_else(|| TransparencyError::integrity("malformed note signature line"))?;
        check_text(name, "note signature key name", 255)?;
        let raw = decode_base64(encoded)?;
        if raw.len() < 4 {
            return Err(TransparencyError::integrity(
                "note signature is shorter than its key id",
            ));
        }
        let mut keyid = [0u8; 4];
        keyid.copy_from_slice(&raw[..4]);
        if !seen.insert(format!("{name}\u{0}{}", hex_lower(&keyid))) {
            return Err(TransparencyError::integrity(
                "duplicate note signature name and key id",
            ));
        }
        signatures.push(NoteSignature {
            name: name.to_owned(),
            keyid,
            raw,
        });
        if signatures.len() > MAX_NOTE_SIGNATURES {
            return Err(TransparencyError::integrity(
                "checkpoint has too many signature lines",
            ));
        }
    }
    if signatures.is_empty() {
        return Err(TransparencyError::integrity(
            "checkpoint has no signature lines",
        ));
    }

    Ok(Checkpoint {
        original: bytes.to_vec(),
        note_text: note_text.to_vec(),
        origin,
        size,
        root,
        extensions,
        signatures,
        sha256: sha256_hex(bytes),
    })
}

fn find_signature_split(bytes: &[u8]) -> Option<usize> {
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] == b'\n' && bytes[index + 1] == b'\n' {
            return Some(index);
        }
        index += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Proof and policy loading
// ---------------------------------------------------------------------------

/// Parse a transparency policy.
///
/// # Errors
///
/// Returns an error for malformed or unsupported policy JSON.
pub fn parse_policy(bytes: &[u8]) -> Result<TransparencyPolicy, TransparencyError> {
    let policy: TransparencyPolicy = parse_json(bytes, "transparency policy")?;
    if policy.schema != POLICY_SCHEMA {
        return Err(TransparencyError::usage(format!(
            "unsupported policy schema {}",
            policy.schema
        )));
    }
    if policy.spec != ETP_SPEC {
        return Err(TransparencyError::usage(format!(
            "unsupported policy spec {}",
            policy.spec
        )));
    }
    check_text(&policy.policy_id, "policy id", 256)?;
    check_text(&policy.log.origin, "log origin", 255)?;
    check_text(&policy.log.log_id, "log id", 256)?;
    check_text(&policy.log.vkey, "log vkey", 1024)?;
    if let Some(horizon) = policy
        .anti_rollback
        .known_horizons
        .iter()
        .max_by_key(|h| h.tree_size)
    {
        let _ = decode_hex32(&horizon.root_hash)?;
        let _ = decode_hex32(&horizon.checkpoint_sha256)?;
    }
    for horizon in &policy.anti_rollback.known_horizons {
        let _ = decode_hex32(&horizon.root_hash)?;
        let _ = decode_hex32(&horizon.checkpoint_sha256)?;
    }
    Ok(policy)
}

/// Parse a transparency proof.
///
/// # Errors
///
/// Returns an error for malformed or unsupported proof JSON.
pub fn parse_proof(bytes: &[u8]) -> Result<TransparencyProof, TransparencyError> {
    let proof: TransparencyProof = parse_json(bytes, "transparency proof")?;
    if proof.schema != PROOF_SCHEMA {
        return Err(TransparencyError::usage(format!(
            "unsupported proof schema {}",
            proof.schema
        )));
    }
    if proof.spec != ETP_SPEC {
        return Err(TransparencyError::usage(format!(
            "unsupported proof spec {}",
            proof.spec
        )));
    }
    check_text(&proof.log_origin, "proof log origin", 255)?;
    check_text(&proof.log_id, "proof log id", 256)?;
    Ok(proof)
}

/// Read and parse a policy file.
///
/// # Errors
///
/// Returns an error when the file cannot be read or parsed.
pub fn load_policy(path: &Path) -> Result<TransparencyPolicy, TransparencyError> {
    let bytes = fs::read(path).map_err(|error| TransparencyError::Io {
        message: format!("cannot read {}: {error}", path.display()),
    })?;
    parse_policy(&bytes)
}

/// Read and parse a proof file.
///
/// # Errors
///
/// Returns an error when the file cannot be read or parsed.
pub fn load_proof(path: &Path) -> Result<TransparencyProof, TransparencyError> {
    let bytes = fs::read(path).map_err(|error| TransparencyError::Io {
        message: format!("cannot read {}: {error}", path.display()),
    })?;
    parse_proof(&bytes)
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify a proof, checkpoint, and policy.
/// Verify a proof, checkpoint, and policy.
#[must_use]
pub fn verify_transparency(
    proof_bytes: &[u8],
    checkpoint_bytes: &[u8],
    policy_bytes: &[u8],
) -> TransparencyReport {
    let mut report = TransparencyReport {
        schema: REPORT_SCHEMA.to_owned(),
        spec: ETP_SPEC.to_owned(),
        status: TransparencyStatus::Verified,
        policy_id: String::new(),
        log_identity: None,
        tree_size: None,
        root_hash: None,
        checkpoint_sha256: None,
        leaf_index: None,
        trust_profile: None,
        external_trust: false,
        public_transparency: false,
        witness_observation: "not_observed".to_owned(),
        dimensions: TransparencyDimensions::default(),
        known_horizons: Vec::new(),
        assumptions: vec![
            "the caller pins the log key and origin out of band".to_owned(),
            "the caller-supplied known horizon is a trustworthy earlier view".to_owned(),
            "the local log key was generated inside a hardened container and is test-only"
                .to_owned(),
            "no external witness, public log, or transparency ecosystem is assumed".to_owned(),
        ],
        unsupported_features: vec![
            "public transparency-log submission and discovery".to_owned(),
            "external and public witnessing".to_owned(),
            "Rekor v2 submission API and entry personalities".to_owned(),
            "ML-DSA-44 cosignatures".to_owned(),
            "global gossip, monitoring, and non-equivocation".to_owned(),
            "semantic validity or completeness of a logged entry".to_owned(),
        ],
        refusals: Vec::new(),
        claim_ceiling: TRANSPARENCY_CLAIM_CEILING.to_owned(),
    };

    let policy = match parse_policy(policy_bytes) {
        Ok(policy) => policy,
        Err(error) => {
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::MalformedPolicy,
                detail: error.to_string(),
            });
            report.dimensions.log_identity = DimensionState::Invalid;
            report.status = TransparencyStatus::Refused;
            return report;
        }
    };
    report.trust_profile = Some(policy.trust_profile.clone());
    report.policy_id.clone_from(&policy.policy_id);
    report.external_trust = policy.log.external_trust;
    report
        .known_horizons
        .clone_from(&policy.anti_rollback.known_horizons);
    report.log_identity = Some(LogIdentitySummary {
        origin: policy.log.origin.clone(),
        log_id: policy.log.log_id.clone(),
        vkey: policy.log.vkey.clone(),
        public_key_sha256: public_key_digest(&policy.log.public_key_base64),
        algorithm: policy.log.algorithm.clone(),
    });

    let checkpoint = match parse_checkpoint(checkpoint_bytes) {
        Ok(checkpoint) => checkpoint,
        Err(error) => {
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::MalformedCheckpoint,
                detail: error.to_string(),
            });
            report.dimensions.checkpoint_signature = DimensionState::Invalid;
            report.status = TransparencyStatus::IntegrityFailure;
            return report;
        }
    };
    report.tree_size = Some(checkpoint.size);
    report.root_hash = Some(hex_lower(&checkpoint.root));
    report.checkpoint_sha256 = Some(checkpoint.sha256.clone());

    let proof = match parse_proof(proof_bytes) {
        Ok(proof) => proof,
        Err(error) => {
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::MalformedProof,
                detail: error.to_string(),
            });
            report.status = TransparencyStatus::IntegrityFailure;
            return report;
        }
    };
    report.leaf_index = Some(proof.leaf_index);

    // Unsupported log versions are a typed NOT_RUN, not a fabricated pass.
    if !policy
        .log
        .supported_log_versions
        .iter()
        .any(|version| version == &proof.log_version)
    {
        report.dimensions.log_version = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::UnsupportedLogVersion,
            detail: format!("unsupported log version {}", proof.log_version),
        });
        report.status = TransparencyStatus::NotRun;
        return report;
    }
    report.dimensions.log_version = DimensionState::Valid;
    if !policy
        .log
        .supported_checkpoint_versions
        .iter()
        .any(|version| version == CHECKPOINT_VERSION_V1)
    {
        report.dimensions.log_version = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::UnsupportedCheckpointVersion,
            detail: "policy does not enable tlog-checkpoint-v1".to_owned(),
        });
        report.status = TransparencyStatus::NotRun;
        return report;
    }

    // Log identity.
    let identity_ok = proof.log_origin == policy.log.origin
        && proof.log_id == policy.log.log_id
        && checkpoint.origin == policy.log.origin;
    if !identity_ok {
        report.dimensions.log_identity = DimensionState::Invalid;
        let cross_log = proof.log_origin != policy.log.origin
            || proof.log_id != policy.log.log_id
            || checkpoint.origin != policy.log.origin;
        report.refusals.push(TransparencyRefusal {
            code: if cross_log {
                TransparencyRefusalCode::CrossLogProof
            } else {
                TransparencyRefusalCode::LogIdentityMismatch
            },
            detail: format!(
                "proof origin {} / log id {} / checkpoint origin {} do not match policy origin {} / log id {}",
                proof.log_origin, proof.log_id, checkpoint.origin, policy.log.origin, policy.log.log_id
            ),
        });
    } else {
        report.dimensions.log_identity = DimensionState::Valid;
    }
    report.dimensions.cross_log_rejection = if identity_ok {
        DimensionState::Valid
    } else {
        DimensionState::Invalid
    };

    // Pinned key parse and checkpoint signature.
    let public_key = match decode_base64(&policy.log.public_key_base64) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Some(key)
        }
        _ => None,
    };
    let Some(public_key) = public_key else {
        report.dimensions.checkpoint_signature = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::InvalidCheckpointSignature,
            detail: "pinned log public key is not 32-byte canonical base64".to_owned(),
        });
        report.status = TransparencyStatus::Refused;
        return report;
    };
    let vkey_ok = vkey_matches(&policy.log.vkey, &policy.log.origin, &public_key);
    if !vkey_ok {
        report.dimensions.log_identity = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::LogIdentityMismatch,
            detail: "pinned vkey does not match the pinned origin and public key".to_owned(),
        });
    }
    let signature_ok = checkpoint.verify_log_signature(&policy.log.origin, &public_key);
    if signature_ok {
        report.dimensions.checkpoint_signature = DimensionState::Valid;
    } else {
        report.dimensions.checkpoint_signature = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::InvalidCheckpointSignature,
            detail: "checkpoint has no valid Ed25519 signature from the pinned log key".to_owned(),
        });
    }

    // Exact checkpoint bytes and persistence.
    if checkpoint.sha256 == proof.checkpoint_sha256 {
        report.dimensions.checkpoint_persistence = DimensionState::Valid;
    } else {
        report.dimensions.checkpoint_persistence = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::CheckpointDigestMismatch,
            detail: "checkpoint bytes do not match the digest declared by the proof".to_owned(),
        });
    }
    if let Some(horizon) = latest_horizon(&policy.anti_rollback.known_horizons) {
        if checkpoint.size == horizon.tree_size && checkpoint.sha256 != horizon.checkpoint_sha256 {
            report.dimensions.checkpoint_persistence = DimensionState::Invalid;
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::CheckpointPersistenceMismatch,
                detail: "checkpoint digest disagrees with the persisted horizon".to_owned(),
            });
        }
    }

    // Entry and leaf binding.
    let entry = match decode_base64(&proof.entry_base64) {
        Ok(entry) => entry,
        Err(error) => {
            report.dimensions.entry_binding = DimensionState::Invalid;
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::MalformedProof,
                detail: format!("entry base64 is invalid: {error}"),
            });
            report.status = TransparencyStatus::IntegrityFailure;
            return report;
        }
    };
    if entry.len() > MAX_ENTRY_BYTES {
        report.dimensions.entry_binding = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::MalformedProof,
            detail: "entry exceeds the tlog-tiles 64 KiB limit".to_owned(),
        });
        report.status = TransparencyStatus::IntegrityFailure;
        return report;
    }
    let entry_digest = sha256_hex(&entry);
    if entry_digest == proof.entry_sha256 {
        report.dimensions.entry_binding = DimensionState::Valid;
    } else {
        report.dimensions.entry_binding = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::EntryDigestMismatch,
            detail: "entry bytes do not match the declared entry digest".to_owned(),
        });
    }
    let computed_leaf = leaf_hash(&entry);
    let declared_leaf = decode_hex32(&proof.leaf_hash).ok();
    if declared_leaf == Some(computed_leaf) {
        report.dimensions.leaf_hash = DimensionState::Valid;
    } else {
        report.dimensions.leaf_hash = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::LeafHashMismatch,
            detail: "declared leaf hash does not equal SHA-256(0x00 || entry)".to_owned(),
        });
    }

    // Root and tree-size binding.
    let proof_root = decode_hex32(&proof.root_hash).ok();
    let roots_match = proof_root == Some(checkpoint.root);
    if !roots_match {
        report.dimensions.inclusion = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::RootMismatch,
            detail: "proof root and signed checkpoint root disagree".to_owned(),
        });
    }
    if proof.tree_size != checkpoint.size {
        report.dimensions.inclusion = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::RootMismatch,
            detail: "proof tree size and checkpoint tree size disagree".to_owned(),
        });
    }

    // Inclusion.
    let audit = match decode_hash_list(&proof.audit_path, MAX_AUDIT_PATH) {
        Ok(path) => path,
        Err(error) => {
            report.dimensions.inclusion = DimensionState::Invalid;
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::MalformedProof,
                detail: format!("audit path is invalid: {error}"),
            });
            return report;
        }
    };
    let inclusion_ok = roots_match
        && proof.tree_size == checkpoint.size
        && verify_inclusion(
            proof.leaf_index,
            checkpoint.size,
            &computed_leaf,
            &audit,
            &checkpoint.root,
        );
    if inclusion_ok {
        report.dimensions.inclusion = DimensionState::Valid;
    } else if report.dimensions.inclusion != DimensionState::Invalid {
        report.dimensions.inclusion = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::InclusionInvalid,
            detail: "audit path does not reach the signed root".to_owned(),
        });
    }

    // Anti-rollback, consistency, and conflict detection.
    verify_horizon(&policy, &checkpoint, &proof, &mut report);

    // Tiled reconstruction.
    verify_tiles(&proof, &checkpoint, &computed_leaf, &mut report);

    // Offline verification is by construction: no network call exists.
    report.dimensions.offline_verification = DimensionState::Valid;

    if !report.refusals.is_empty() && report.status == TransparencyStatus::Verified {
        report.status = transparency_status_from_dimensions(&report.dimensions);
    }
    report
}

fn public_key_digest(public_key_base64: &str) -> String {
    decode_base64(public_key_base64)
        .map_or_else(|_| "unparsed".to_owned(), |bytes| sha256_hex(&bytes))
}

fn vkey_matches(vkey: &str, origin: &str, public_key: &[u8; 32]) -> bool {
    let Some(rest) = vkey.strip_prefix(&format!("{origin}+")) else {
        return false;
    };
    let Some((keyid, encoded)) = rest.split_once('+') else {
        return false;
    };
    let Ok(raw) = decode_base64(encoded) else {
        return false;
    };
    if raw.len() != 33 || raw[0] != 0x01 || raw[1..] != public_key[..] {
        return false;
    }
    let Some(expected) = note_key_id(origin, public_key, 0x01) else {
        return false;
    };
    keyid == hex_lower(&expected)
}

fn decode_hash_list(values: &[String], max: usize) -> Result<Vec<[u8; 32]>, TransparencyError> {
    if values.len() > max {
        return Err(TransparencyError::integrity("hash list is too long"));
    }
    values.iter().map(|value| decode_b64_32(value)).collect()
}

fn latest_horizon(horizons: &[KnownHorizon]) -> Option<&KnownHorizon> {
    horizons.iter().max_by_key(|horizon| horizon.tree_size)
}

fn verify_horizon(
    policy: &TransparencyPolicy,
    checkpoint: &Checkpoint,
    proof: &TransparencyProof,
    report: &mut TransparencyReport,
) {
    let Some(horizon) = latest_horizon(&policy.anti_rollback.known_horizons) else {
        report.dimensions.anti_rollback = DimensionState::NotChecked;
        report.dimensions.consistency = DimensionState::NotApplicable;
        report.dimensions.conflict_detection = DimensionState::NotChecked;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::AntiRollbackUninitialized,
            detail: "policy declares no known horizon, so rollback cannot be excluded".to_owned(),
        });
        return;
    };
    let Ok(horizon_root) = decode_hex32(&horizon.root_hash) else {
        report.dimensions.anti_rollback = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::MalformedPolicy,
            detail: "known horizon root is not a 32-byte hexadecimal digest".to_owned(),
        });
        return;
    };

    if checkpoint.size < horizon.tree_size {
        report.dimensions.anti_rollback = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::Rollback,
            detail: format!(
                "checkpoint size {} is older than the known horizon {}",
                checkpoint.size, horizon.tree_size
            ),
        });
        return;
    }
    report.dimensions.anti_rollback = DimensionState::Valid;

    if checkpoint.size == horizon.tree_size {
        report.dimensions.consistency = DimensionState::Valid;
        if checkpoint.root == horizon_root {
            report.dimensions.conflict_detection = DimensionState::Valid;
        } else {
            report.dimensions.conflict_detection = DimensionState::Invalid;
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::ConflictingCheckpoint,
                detail: "two equal-size checkpoints have different roots".to_owned(),
            });
        }
        return;
    }

    // Newer than the horizon: a consistency proof is required.
    let Some(consistency) = &proof.consistency else {
        report.dimensions.consistency = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::MissingConsistencyProof,
            detail:
                "checkpoint is newer than the known horizon but no consistency proof is present"
                    .to_owned(),
        });
        return;
    };
    let Ok(old_root) = decode_hex32(&consistency.old_root) else {
        report.dimensions.consistency = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::MalformedProof,
            detail: "consistency old root is malformed".to_owned(),
        });
        return;
    };
    let Ok(new_root) = decode_hex32(&consistency.new_root) else {
        report.dimensions.consistency = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::MalformedProof,
            detail: "consistency new root is malformed".to_owned(),
        });
        return;
    };
    let Ok(path) = decode_hash_list(&consistency.proof, MAX_AUDIT_PATH) else {
        report.dimensions.consistency = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::MalformedProof,
            detail: "consistency proof nodes are malformed".to_owned(),
        });
        return;
    };
    let consistency_ok = consistency.old_size == horizon.tree_size
        && old_root == horizon_root
        && consistency.new_size == checkpoint.size
        && new_root == checkpoint.root
        && verify_consistency(
            consistency.old_size,
            consistency.new_size,
            &old_root,
            &new_root,
            &path,
        );
    if consistency_ok {
        report.dimensions.consistency = DimensionState::Valid;
        report.dimensions.conflict_detection = DimensionState::Valid;
    } else {
        report.dimensions.consistency = DimensionState::Invalid;
        report.dimensions.conflict_detection = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::ConsistencyInvalid,
            detail: "consistency proof does not connect the known horizon to the checkpoint"
                .to_owned(),
        });
    }
}

fn verify_tiles(
    proof: &TransparencyProof,
    checkpoint: &Checkpoint,
    leaf: &[u8; 32],
    report: &mut TransparencyReport,
) {
    if proof.tiles.is_empty() {
        report.dimensions.tiled_reconstruction = DimensionState::NotApplicable;
        return;
    }
    if proof.tiles.len() > MAX_TILES {
        report.dimensions.tiled_reconstruction = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::MalformedTile,
            detail: "proof declares too many tiles".to_owned(),
        });
        return;
    }
    let mut level_zero: BTreeMap<u64, Vec<[u8; 32]>> = BTreeMap::new();
    let mut structurally_valid = true;
    for tile in &proof.tiles {
        if tile.level > 63 || tile.width == 0 || tile.width as usize > 256 {
            structurally_valid = false;
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::MalformedTile,
                detail: format!(
                    "tile {}/{} has invalid level or width",
                    tile.level, tile.index
                ),
            });
            continue;
        }
        let Ok(bytes) = decode_base64(&tile.base64) else {
            structurally_valid = false;
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::MalformedTile,
                detail: format!("tile {}/{} base64 is invalid", tile.level, tile.index),
            });
            continue;
        };
        if bytes.len() > MAX_TILE_BYTES || bytes.len() != tile.width as usize * 32 {
            structurally_valid = false;
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::MalformedTile,
                detail: format!("tile {}/{} has a width mismatch", tile.level, tile.index),
            });
            continue;
        }
        if sha256_hex(&bytes) != tile.sha256 {
            structurally_valid = false;
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::MalformedTile,
                detail: format!("tile {}/{} digest mismatch", tile.level, tile.index),
            });
            continue;
        }
        let mut hashes = Vec::with_capacity(tile.width as usize);
        for chunk in bytes.chunks_exact(32) {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(chunk);
            hashes.push(hash);
        }
        if tile.level == 0 && level_zero.insert(tile.index, hashes).is_some() {
            structurally_valid = false;
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::MalformedTile,
                detail: format!("duplicate level-0 tile {}", tile.index),
            });
        }
    }
    if !structurally_valid {
        report.dimensions.tiled_reconstruction = DimensionState::Invalid;
        return;
    }

    // Rebuild the ordered leaf list from level-0 tiles.
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    let mut tile_index = 0u64;
    while (leaves.len() as u64) < checkpoint.size {
        let Some(hashes) = level_zero.get(&tile_index) else {
            report.dimensions.tiled_reconstruction = DimensionState::Invalid;
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::MalformedTile,
                detail: format!("missing level-0 tile {tile_index}"),
            });
            return;
        };
        let remaining = checkpoint.size - leaves.len() as u64;
        let expected = remaining.min(256) as usize;
        if hashes.len() != expected {
            report.dimensions.tiled_reconstruction = DimensionState::Invalid;
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::MalformedTile,
                detail: format!(
                    "level-0 tile {tile_index} has {} hashes; expected {expected}",
                    hashes.len()
                ),
            });
            return;
        }
        leaves.extend_from_slice(hashes);
        tile_index += 1;
    }

    if merkle_tree_hash(&leaves) != checkpoint.root {
        report.dimensions.tiled_reconstruction = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::TiledRootMismatch,
            detail: "tiles reconstruct a root different from the signed checkpoint".to_owned(),
        });
        return;
    }
    let Ok(leaf_index) = usize::try_from(proof.leaf_index) else {
        report.dimensions.tiled_reconstruction = DimensionState::Invalid;
        return;
    };
    if leaves.get(leaf_index) != Some(leaf) {
        report.dimensions.tiled_reconstruction = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::TileLeafMismatch,
            detail: "level-0 tile leaf disagrees with the declared entry leaf".to_owned(),
        });
        return;
    }
    let Some(reconstructed_path) = leaves
        .get(..)
        .and_then(|all| audit_path(all, proof.leaf_index).ok())
    else {
        report.dimensions.tiled_reconstruction = DimensionState::Invalid;
        return;
    };
    let declared_path = match decode_hash_list(&proof.audit_path, MAX_AUDIT_PATH) {
        Ok(path) => path,
        Err(_) => {
            report.dimensions.tiled_reconstruction = DimensionState::Invalid;
            return;
        }
    };
    if reconstructed_path != declared_path {
        report.dimensions.tiled_reconstruction = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::TiledProofMismatch,
            detail: "tiles reconstruct an audit path different from the declared path".to_owned(),
        });
        return;
    }

    // Check higher-level tiles against the rebuilt leaves where they cover a
    // complete subtree. Partial right-edge tiles are not hashed upward.
    for tile in &proof.tiles {
        if tile.level == 0 {
            continue;
        }
        let Ok(bytes) = decode_base64(&tile.base64) else {
            report.dimensions.tiled_reconstruction = DimensionState::Invalid;
            return;
        };
        let Some(scale) = 256u64.checked_pow(u32::try_from(tile.level).unwrap_or(u32::MAX)) else {
            continue;
        };
        let start = tile.index.saturating_mul(256).saturating_mul(scale);
        for (offset, chunk) in bytes.chunks_exact(32).enumerate() {
            let begin = start.saturating_add((offset as u64).saturating_mul(scale));
            let end = begin.saturating_add(scale);
            if end > checkpoint.size {
                continue;
            }
            let Ok(begin_usize) = usize::try_from(begin) else {
                continue;
            };
            let Ok(end_usize) = usize::try_from(end) else {
                continue;
            };
            let mut expected = [0u8; 32];
            expected.copy_from_slice(chunk);
            if merkle_tree_hash(&leaves[begin_usize..end_usize]) != expected {
                report.dimensions.tiled_reconstruction = DimensionState::Invalid;
                report.refusals.push(TransparencyRefusal {
                    code: TransparencyRefusalCode::TiledRootMismatch,
                    detail: format!(
                        "level-{} tile {} does not hash its leaf range",
                        tile.level, tile.index
                    ),
                });
                return;
            }
        }
    }

    report.dimensions.tiled_reconstruction = DimensionState::Valid;
}

fn transparency_status_from_dimensions(dimensions: &TransparencyDimensions) -> TransparencyStatus {
    let values = [
        dimensions.log_identity,
        dimensions.log_version,
        dimensions.entry_binding,
        dimensions.leaf_hash,
        dimensions.inclusion,
        dimensions.checkpoint_signature,
        dimensions.checkpoint_persistence,
        dimensions.consistency,
        dimensions.conflict_detection,
        dimensions.anti_rollback,
        dimensions.tiled_reconstruction,
        dimensions.cross_log_rejection,
        dimensions.offline_verification,
    ];
    if values.iter().any(|value| {
        matches!(
            value,
            DimensionState::Invalid | DimensionState::Partial | DimensionState::NotChecked
        )
    }) {
        TransparencyStatus::Refused
    } else {
        TransparencyStatus::Verified
    }
}

// ---------------------------------------------------------------------------
// Checkpoint-only verification
// ---------------------------------------------------------------------------

/// Verify a checkpoint, optionally against a pinned policy.
#[must_use]
pub fn verify_checkpoint(checkpoint_bytes: &[u8], policy_bytes: Option<&[u8]>) -> CheckpointReport {
    let mut report = CheckpointReport {
        schema: CHECKPOINT_REPORT_SCHEMA.to_owned(),
        spec: ETP_SPEC.to_owned(),
        status: TransparencyStatus::Verified,
        origin: String::new(),
        tree_size: 0,
        root_hash: String::new(),
        checkpoint_sha256: String::new(),
        signature: DimensionState::NotChecked,
        signature_count: 0,
        anti_rollback: DimensionState::NotChecked,
        conflict_detection: DimensionState::NotChecked,
        known_horizons: Vec::new(),
        refusals: Vec::new(),
        claim_ceiling: TRANSPARENCY_CLAIM_CEILING.to_owned(),
    };
    let checkpoint = match parse_checkpoint(checkpoint_bytes) {
        Ok(checkpoint) => checkpoint,
        Err(error) => {
            report.status = TransparencyStatus::IntegrityFailure;
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::MalformedCheckpoint,
                detail: error.to_string(),
            });
            return report;
        }
    };
    report.origin.clone_from(&checkpoint.origin);
    report.tree_size = checkpoint.size;
    report.root_hash = hex_lower(&checkpoint.root);
    report.checkpoint_sha256.clone_from(&checkpoint.sha256);
    report.signature_count = checkpoint.signatures.len();

    let Some(policy_bytes) = policy_bytes else {
        report.signature = DimensionState::NotChecked;
        report.status = TransparencyStatus::Partial;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::PolicyNotSupplied,
            detail: "no pinned policy was supplied; only structural checkpoint parsing was checked"
                .to_owned(),
        });
        return report;
    };
    let policy = match parse_policy(policy_bytes) {
        Ok(policy) => policy,
        Err(error) => {
            report.status = TransparencyStatus::Refused;
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::MalformedPolicy,
                detail: error.to_string(),
            });
            return report;
        }
    };
    report
        .known_horizons
        .clone_from(&policy.anti_rollback.known_horizons);
    if checkpoint.origin != policy.log.origin {
        report.status = TransparencyStatus::Refused;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::CrossLogProof,
            detail: "checkpoint origin does not match the pinned policy".to_owned(),
        });
        return report;
    }
    let public_key = decode_base64(&policy.log.public_key_base64)
        .ok()
        .and_then(|bytes| {
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Some(key)
            } else {
                None
            }
        });
    let Some(public_key) = public_key else {
        report.status = TransparencyStatus::Refused;
        report.signature = DimensionState::Invalid;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::InvalidCheckpointSignature,
            detail: "pinned public key is not 32-byte canonical base64".to_owned(),
        });
        return report;
    };
    if checkpoint.verify_log_signature(&policy.log.origin, &public_key) {
        report.signature = DimensionState::Valid;
    } else {
        report.signature = DimensionState::Invalid;
        report.status = TransparencyStatus::Refused;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::InvalidCheckpointSignature,
            detail: "checkpoint has no valid signature from the pinned log key".to_owned(),
        });
        return report;
    }
    if let Some(horizon) = latest_horizon(&policy.anti_rollback.known_horizons) {
        let Ok(horizon_root) = decode_hex32(&horizon.root_hash) else {
            report.status = TransparencyStatus::Refused;
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::MalformedPolicy,
                detail: "known horizon root is malformed".to_owned(),
            });
            return report;
        };
        if checkpoint.size < horizon.tree_size {
            report.anti_rollback = DimensionState::Invalid;
            report.status = TransparencyStatus::Refused;
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::Rollback,
                detail: "checkpoint is older than the known horizon".to_owned(),
            });
        } else if checkpoint.size == horizon.tree_size && checkpoint.root != horizon_root {
            report.conflict_detection = DimensionState::Invalid;
            report.status = TransparencyStatus::Refused;
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::ConflictingCheckpoint,
                detail: "equal-size checkpoint has a different root".to_owned(),
            });
        } else if checkpoint.size > horizon.tree_size {
            report.anti_rollback = DimensionState::Valid;
            report.conflict_detection = DimensionState::Partial;
            report.status = TransparencyStatus::Partial;
            report.refusals.push(TransparencyRefusal {
                code: TransparencyRefusalCode::ConsistencyNotChecked,
                detail: "a checkpoint-only check cannot verify consistency from the known horizon"
                    .to_owned(),
            });
        } else {
            report.anti_rollback = DimensionState::Valid;
            report.conflict_detection = DimensionState::Valid;
            report.status = TransparencyStatus::Verified;
        }
    } else {
        report.status = TransparencyStatus::Partial;
        report.refusals.push(TransparencyRefusal {
            code: TransparencyRefusalCode::ConsistencyNotChecked,
            detail: "policy declares no known horizon; rollback and conflict were not checked"
                .to_owned(),
        });
    }
    report
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(values: &[&[u8]]) -> Vec<[u8; 32]> {
        values.iter().map(|value| leaf_hash(value)).collect()
    }

    #[test]
    fn inclusion_paths_verify_for_non_power_of_two_sizes() {
        let values: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d", b"e", b"f", b"g"];
        let hashes = leaves(&values);
        let root = merkle_tree_hash(&hashes);
        for (index, leaf) in hashes.iter().enumerate() {
            let path = audit_path(&hashes, index as u64).expect("path");
            assert!(verify_inclusion(
                index as u64,
                hashes.len() as u64,
                leaf,
                &path,
                &root
            ));
        }
    }

    #[test]
    fn consistency_proofs_verify_for_all_prefixes() {
        let values: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h", b"i"];
        let hashes = leaves(&values);
        let new_root = merkle_tree_hash(&hashes);
        for old_size in 1..hashes.len() {
            let old_root = merkle_tree_hash(&hashes[..old_size]);
            let proof = consistency_proof_for_test(&hashes, old_size as u64);
            assert!(
                verify_consistency(
                    old_size as u64,
                    hashes.len() as u64,
                    &old_root,
                    &new_root,
                    &proof
                ),
                "old size {old_size}"
            );
        }
    }

    fn consistency_proof_for_test(leaves: &[[u8; 32]], m: u64) -> Vec<[u8; 32]> {
        fn sub(leaves: &[[u8; 32]], m: u64, b: bool) -> Vec<[u8; 32]> {
            let n = leaves.len() as u64;
            if m == n {
                if b {
                    return Vec::new();
                }
                return vec![merkle_tree_hash(leaves)];
            }
            let k = usize::try_from(split_point(n)).expect("split point fits");
            if m <= k as u64 {
                let mut proof = sub(&leaves[..k], m, b);
                proof.push(merkle_tree_hash(&leaves[k..]));
                proof
            } else {
                let mut proof = sub(&leaves[k..], m - k as u64, false);
                proof.push(merkle_tree_hash(&leaves[..k]));
                proof
            }
        }
        sub(leaves, m, true)
    }

    #[test]
    fn wrong_sibling_order_is_refused() {
        let values: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let hashes = leaves(&values);
        let root = merkle_tree_hash(&hashes);
        let path = audit_path(&hashes, 0).expect("path");
        let mut wrong = path.clone();
        wrong.reverse();
        assert!(!verify_inclusion(0, 3, &hashes[0], &wrong, &root));
    }
}
