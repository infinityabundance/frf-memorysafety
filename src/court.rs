//! Responsibility tokens, lifecycle transitions, concurrency ordering, and
//! native event-transcript verification.
//!
//! This module is the Phase 4.1 semantic core. It consumes a caller-supplied
//! finite transcript and checks the declared transitions. It does **not**
//! execute a C or Rust program, spawn a recorder, observe a callback natively,
//! or establish that the transcript corresponds to a real execution. Native
//! recording and replay belong to Phase 4.2.
//!
//! # What a verdict means
//!
//! Every verdict is one of five typed outcomes:
//!
//! * [`TranscriptOutcome::VerifiedCompatibleWithinTranscript`] — the transcript
//!   is structurally complete, every declared transition is legal under the
//!   rules in this module, no conflicting unordered access is a race, and no
//!   required event is missing. It is **not** native evidence.
//! * [`TranscriptOutcome::ObservedViolation`] — the transcript contains a
//!   definite lifecycle or concurrency contradiction.
//! * [`TranscriptOutcome::IncompleteTranscript`] — a required create, free,
//!   borrow end, generation transition, callback, or completion fact is absent,
//!   or the transcript claims completeness while retaining gaps or unknown
//!   provider edges.
//! * [`TranscriptOutcome::Unresolved`] — the transcript is not authentic native
//!   evidence, or it retains an unknown provider edge without claiming
//!   completeness. The verifier never upgrades this to a clean verdict.
//! * [`TranscriptOutcome::IllegalCase`] — the declared case legality is
//!   `illegal`, or the declared synchronizes-with graph contains a cycle.
//!
//! These outcomes are not a confidence ladder.
//!
//! # Claim ceiling
//!
//! A verified result establishes only compatibility within the supplied finite
//! transcript. It does not establish Rust borrow validity, C object lifetime or
//! effective type, native replay fidelity, absence of unrecorded events, or
//! memory safety. See [`COURT_CLAIM_CEILING`].

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::{canonical_bytes, hex_lower, parse_strict, IdentityError, MAX_BYTES};

/// Schema identifier for a native event transcript.
pub const NATIVE_EVENT_TRANSCRIPT_SCHEMA: &str = "native-event-transcript.v1";
/// Schema identifier for a court verification report.
pub const COURT_REPORT_SCHEMA: &str = "frf-memorysafety.court-verification.v1";
/// Protocol specification identifier.
pub const COURT_SPEC: &str = "frf-memorysafety-spec-v1";
/// Claim ceiling embedded in every report.
pub const COURT_CLAIM_CEILING: &str = "Verifies only a caller-supplied finite event transcript under its declared provenance. It does not execute native code, authenticate a recording, observe a real C/Rust process, prove Rust borrow validity or C object lifetime/effective type, establish replay fidelity, or establish memory safety. verified_compatible_within_transcript is not a native or universal soundness result.";

/// Maximum number of events in one transcript.
pub const MAX_TRANSCRIPT_EVENTS: usize = 4_096;
/// Maximum number of declared objects.
pub const MAX_OBJECTS: usize = 256;
/// Maximum number of declared threads.
pub const MAX_THREADS: usize = 64;
/// Maximum number of explicit synchronizes-with edges.
pub const MAX_SYNC_EDGES: usize = 8_192;
/// Maximum number of retained findings.
pub const MAX_FINDINGS: usize = 16_384;

/// Provenance origin of a transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptOrigin {
    /// Events recorded from the authentic native executable named in provenance.
    AuthenticNative,
    /// Events observed through a substituted FFI implementation or provider.
    Substitute,
    /// Events replayed from a finite model or hand-authored fixture.
    Modeled,
}

impl TranscriptOrigin {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticNative => "authentic_native",
            Self::Substitute => "substitute",
            Self::Modeled => "modeled",
        }
    }

    /// Only authentic native recording can support a clean transcript verdict.
    #[must_use]
    pub const fn is_authentic(self) -> bool {
        matches!(self, Self::AuthenticNative)
    }
}

/// Declared legality of the recorded case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseLegality {
    /// A test-only case that may exercise intentionally invalid behavior.
    TestOnly,
    /// A case that is legal for the declared production scope.
    Production,
    /// A case that violates the declared legality contract.
    Illegal,
}

/// Access performed by a use event.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    /// No memory access.
    #[default]
    #[serde(rename = "none")]
    None,
    /// Non-atomic read.
    Read,
    /// Non-atomic write.
    Write,
    /// Atomic read.
    AtomicRead,
    /// Atomic write.
    AtomicWrite,
    /// Atomic read-modify-write.
    AtomicReadWrite,
}

impl AccessMode {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Write => "write",
            Self::AtomicRead => "atomic_read",
            Self::AtomicWrite => "atomic_write",
            Self::AtomicReadWrite => "atomic_read_write",
        }
    }

    /// Whether this mode is a memory access.
    #[must_use]
    pub const fn is_access(self) -> bool {
        !matches!(self, Self::None)
    }

    /// Whether this mode writes.
    #[must_use]
    pub const fn is_write(self) -> bool {
        matches!(
            self,
            Self::Write | Self::AtomicWrite | Self::AtomicReadWrite
        )
    }

    /// Whether this mode is an atomic access.
    #[must_use]
    pub const fn is_atomic(self) -> bool {
        matches!(
            self,
            Self::AtomicRead | Self::AtomicWrite | Self::AtomicReadWrite
        )
    }
}

/// Kind of borrow token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BorrowKind {
    /// Shared borrow.
    Shared,
    /// Exclusive mutable borrow.
    Mutable,
}

impl BorrowKind {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::Mutable => "mutable",
        }
    }
}

/// Callback completion outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackOutcome {
    /// The callback returned normally.
    Ok,
    /// The callback reported failure. A bound token becomes poisoned.
    Failed,
}

/// Lifecycle transition recorded in a transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Allocate or construct an object and issue an owning token.
    Create,
    /// Transfer an owning token to another owner and issue the receiver token.
    Transfer,
    /// A transfer attempt failed; the sender retains responsibility.
    TransferFailure,
    /// Create a shared borrow token.
    BorrowShared,
    /// Create a mutable borrow token.
    BorrowMutable,
    /// Create a reborrow token from an existing borrow.
    Reborrow,
    /// End a borrow token.
    BorrowEnd,
    /// Escape a token to a foreign owner or provider.
    Escape,
    /// Reallocate storage, bump the generation, and issue a new owning token.
    Reallocate,
    /// Free the allocation through its owning token.
    Free,
    /// Access an object through a token.
    Use,
    /// Enter a callback invocation.
    CallbackEnter,
    /// Leave a callback invocation.
    CallbackExit,
    /// An allocation attempt failed and produced no object.
    AllocationFailure,
    /// Partially initialize an object.
    PartialInit,
    /// Complete initialization.
    InitComplete,
    /// Poison a token after a failed operation.
    Poison,
    /// Abort the declared lifecycle.
    Abort,
}

impl EventKind {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Transfer => "transfer",
            Self::TransferFailure => "transfer_failure",
            Self::BorrowShared => "borrow_shared",
            Self::BorrowMutable => "borrow_mutable",
            Self::Reborrow => "reborrow",
            Self::BorrowEnd => "borrow_end",
            Self::Escape => "escape",
            Self::Reallocate => "reallocate",
            Self::Free => "free",
            Self::Use => "use",
            Self::CallbackEnter => "callback_enter",
            Self::CallbackExit => "callback_exit",
            Self::AllocationFailure => "allocation_failure",
            Self::PartialInit => "partial_init",
            Self::InitComplete => "init_complete",
            Self::Poison => "poison",
            Self::Abort => "abort",
        }
    }

    /// Whether this transition is a non-atomic write to lifecycle metadata.
    #[must_use]
    pub const fn writes_lifecycle(self) -> bool {
        matches!(
            self,
            Self::Create
                | Self::Transfer
                | Self::TransferFailure
                | Self::BorrowShared
                | Self::BorrowMutable
                | Self::Reborrow
                | Self::BorrowEnd
                | Self::Escape
                | Self::Reallocate
                | Self::Free
                | Self::AllocationFailure
                | Self::PartialInit
                | Self::InitComplete
                | Self::Poison
        )
    }
}

/// Typed transcript verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptOutcome {
    /// The finite transcript is internally compatible.
    VerifiedCompatibleWithinTranscript,
    /// A definite lifecycle or concurrency contradiction was observed.
    ObservedViolation,
    /// A required event or completion fact is absent.
    IncompleteTranscript,
    /// The evidence cannot support a clean or violating verdict.
    Unresolved,
    /// The declared case is illegal or the ordering graph is cyclic.
    IllegalCase,
}

impl TranscriptOutcome {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedCompatibleWithinTranscript => "verified_compatible_within_transcript",
            Self::ObservedViolation => "observed_violation",
            Self::IncompleteTranscript => "incomplete_transcript",
            Self::Unresolved => "unresolved",
            Self::IllegalCase => "illegal_case",
        }
    }

    /// `SPEC.md` §14 exit status for this outcome.
    ///
    /// A definite violation and an illegal case block the claim (4). An
    /// incomplete transcript means the recorder missed required events, which is
    /// a detector failure (5). Unresolved evidence also blocks the claim (4).
    #[must_use]
    pub const fn exit_status(self) -> i32 {
        match self {
            Self::VerifiedCompatibleWithinTranscript => 0,
            Self::ObservedViolation | Self::Unresolved | Self::IllegalCase => 4,
            Self::IncompleteTranscript => 5,
        }
    }
}

/// Severity class of one finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingClass {
    /// A definite contradiction.
    ObservedViolation,
    /// A required event or completion fact is absent.
    Incomplete,
    /// Evidence cannot decide the question.
    Unresolved,
    /// The declared case or ordering graph is illegal.
    Illegal,
}

/// Reference to one event in one thread.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRef {
    /// Thread identifier.
    pub thread: String,
    /// Per-thread sequence number.
    pub seq: u64,
}

/// One declared object or allocation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectDecl {
    /// Stable object identifier.
    pub id: String,
    /// Whether atomic accesses are legal for this object.
    #[serde(default)]
    pub atomic: bool,
}

/// One tool or library version retained in provenance.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryVersion {
    /// Library or component name.
    pub name: String,
    /// Exact version string.
    pub version: String,
}

/// Required provenance for a native event transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptProvenance {
    /// Authentic native, substitute, or modeled origin.
    pub origin: TranscriptOrigin,
    /// Recorder or producer tool name.
    pub tool: String,
    /// Recorder or producer version.
    pub tool_version: String,
    /// Tool and library versions that affect interpretation.
    pub library_versions: Vec<LibraryVersion>,
    /// SHA-256 of the executed executable, lowercase hexadecimal.
    pub executable_digest: String,
    /// SHA-256 of the executed fixture or input, lowercase hexadecimal.
    pub fixture_digest: String,
    /// Declared legality of the case.
    pub case_legality: CaseLegality,
    /// Declared scope of the recorded case.
    pub scope: String,
    /// Whether the producer claims the transcript is complete.
    pub claimed_complete: bool,
}

/// Recording metadata used by the seeded skipped-event detector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingMetadata {
    /// Recording seed or schedule identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    /// Exact number of events the recorder claims to have emitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_event_count: Option<usize>,
    /// Human-readable schedule or replay note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
}

/// Explicit required-event obligations.
///
/// These are the seed for the skipped-event detector: a missing obligation is
/// `incomplete_transcript`, never a clean or violating verdict.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptRequirements {
    /// Objects that must have a create event.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_creates: Vec<String>,
    /// Objects that must have a free event.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_frees: Vec<String>,
    /// Borrow tokens that must have a borrow-end event.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_borrow_ends: Vec<String>,
    /// Objects that must have at least one reallocation generation bump.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_generation_transitions: Vec<String>,
    /// Callbacks that must be recorded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_callbacks: Vec<String>,
}

/// One unknown provider edge retained as unresolved evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderUnknown {
    /// Provider or substituted component.
    pub provider: String,
    /// Why the edge is unknown.
    pub detail: String,
}

/// One event in a per-thread ordered transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    /// Per-thread sequence number.
    pub seq: u64,
    /// Transition kind.
    pub kind: EventKind,
    /// Object the transition concerns.
    pub object: String,
    /// New or affected token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Consumed or source token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_token: Option<String>,
    /// Produced token for transfer events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_token: Option<String>,
    /// Current or new owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Receiver owner for transfer events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_owner: Option<String>,
    /// Claimed allocation generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    /// Access mode for use events.
    #[serde(default)]
    pub access: AccessMode,
    /// Borrow kind for reborrow events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub borrow: Option<BorrowKind>,
    /// Foreign or provider owner for escape events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Callback name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback: Option<String>,
    /// Callback completion outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<CallbackOutcome>,
    /// Number of initialized bytes for partial initialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initialized_length: Option<u64>,
    /// Free-form diagnostic detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// One thread's ordered events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadTrace {
    /// Stable thread identifier.
    pub id: String,
    /// Events in strictly increasing sequence order.
    pub events: Vec<Event>,
}

/// One explicit synchronizes-with edge.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncEdge {
    /// Event that releases or publishes.
    pub from: EventRef,
    /// Event that acquires or observes.
    pub to: EventRef,
}

/// Canonical native event transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEventTranscript {
    /// Transcript schema identifier.
    pub schema: String,
    /// Protocol specification identifier.
    pub spec: String,
    /// Required provenance.
    pub provenance: TranscriptProvenance,
    /// Declared objects.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<ObjectDecl>,
    /// Per-thread event order.
    pub threads: Vec<ThreadTrace>,
    /// Explicit synchronizes-with edges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub synchronizes_with: Vec<SyncEdge>,
    /// Required-event obligations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirements: Option<TranscriptRequirements>,
    /// Recording metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording: Option<RecordingMetadata>,
    /// Unknown provider edges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown_provider_edges: Vec<ProviderUnknown>,
}

/// One retained verification finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    /// Finding class.
    pub class: FindingClass,
    /// Stable machine code.
    pub code: String,
    /// Subject object, token, thread, or callback.
    pub subject: String,
    /// Human-readable explanation.
    pub detail: String,
    /// Events that justify the finding.
    pub events: Vec<EventRef>,
}

/// One conflicting unordered access pair.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RaceWitness {
    /// Object accessed by both events.
    pub object: String,
    /// First event in deterministic order.
    pub first: EventRef,
    /// Second event in deterministic order.
    pub second: EventRef,
    /// Access mode of the first event.
    pub first_access: AccessMode,
    /// Access mode of the second event.
    pub second_access: AccessMode,
    /// Explanation of the missing ordering.
    pub detail: String,
}

/// Deterministic court verification report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CourtReport {
    /// Report schema.
    pub schema: String,
    /// Specification identifier.
    pub spec: String,
    /// Consumed transcript schema.
    pub transcript_schema: String,
    /// SHA-256 of the canonical transcript bytes, lowercase hexadecimal.
    pub transcript_sha256: String,
    /// Typed outcome.
    pub outcome: TranscriptOutcome,
    /// Declared provenance origin.
    pub origin: TranscriptOrigin,
    /// Declared case legality.
    pub case_legality: CaseLegality,
    /// Whether the producer claimed completeness.
    pub claimed_complete: bool,
    /// Number of events in the transcript.
    pub event_count: usize,
    /// Number of threads in the transcript.
    pub thread_count: usize,
    /// Number of declared objects.
    pub object_count: usize,
    /// Retained findings, sorted deterministically.
    pub findings: Vec<Finding>,
    /// Race witnesses, sorted deterministically.
    pub race_witnesses: Vec<RaceWitness>,
    /// Claim ceiling embedded in the report.
    pub claim_ceiling: String,
}

impl CourtReport {
    /// Encode this report as strict `ms-canonical-json-v1` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CourtError::Canonical`] if the report cannot be represented as
    /// a restricted JSON value.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CourtError> {
        let value = serde_json::to_value(self).map_err(|error| CourtError::Canonical {
            message: error.to_string(),
        })?;
        canonical_bytes(&value).map_err(|error| CourtError::Canonical {
            message: error.to_string(),
        })
    }
}

/// Category used by the CLI to choose a `SPEC.md` §14 exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CourtErrorCategory {
    /// Invalid input or usage.
    Usage,
    /// Evidence/input integrity failure.
    Integrity,
    /// Internal encoding or harness failure.
    Harness,
}

/// Errors produced while parsing or verifying transcripts.
#[derive(Debug, thiserror::Error)]
pub enum CourtError {
    /// The transcript is structurally invalid.
    #[error("invalid native event transcript: {message}")]
    Invalid {
        /// Diagnostic.
        message: String,
    },
    /// A hard limit was exceeded.
    #[error("native event transcript limit exceeded: {resource} (limit {limit})")]
    LimitExceeded {
        /// Resource name.
        resource: &'static str,
        /// Configured limit.
        limit: usize,
    },
    /// The canonical encoder rejected a value.
    #[error("cannot encode court value: {message}")]
    Canonical {
        /// Encoder diagnostic.
        message: String,
    },
}

impl CourtError {
    /// Category used for exit-status selection.
    #[must_use]
    pub const fn category(&self) -> CourtErrorCategory {
        match self {
            Self::Invalid { .. } | Self::LimitExceeded { .. } => CourtErrorCategory::Integrity,
            Self::Canonical { .. } => CourtErrorCategory::Harness,
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid {
            message: message.into(),
        }
    }
}

/// Parse and structurally validate a native event transcript.
///
/// # Errors
///
/// Returns [`CourtError::Invalid`] for malformed JSON, duplicate or unknown
/// fields, missing required fields, invalid digests, duplicate identifiers, or
/// inconsistent event shapes. Returns [`CourtError::LimitExceeded`] when a hard
/// resource limit is exceeded.
pub fn parse_transcript(bytes: &[u8]) -> Result<NativeEventTranscript, CourtError> {
    if bytes.len() > MAX_BYTES {
        return Err(CourtError::LimitExceeded {
            resource: "encoded_bytes",
            limit: MAX_BYTES,
        });
    }
    let value = parse_strict(bytes).map_err(map_identity_error)?;
    let transcript: NativeEventTranscript =
        serde_json::from_value(value).map_err(|error| CourtError::invalid(error.to_string()))?;
    validate_structure(&transcript)?;
    Ok(transcript)
}

/// Parse, validate, and verify a transcript.
///
/// # Errors
///
/// Returns parse and structural errors from [`parse_transcript`], plus
/// [`CourtError::Canonical`] if the report cannot be encoded.
pub fn verify_transcript_json(bytes: &[u8]) -> Result<CourtReport, CourtError> {
    let transcript = parse_transcript(bytes)?;
    verify_transcript(&transcript)
}

/// Verify an already parsed transcript.
///
/// # Errors
///
/// Returns [`CourtError::Canonical`] if the transcript digest or report cannot
/// be encoded in restricted canonical JSON.
pub fn verify_transcript(transcript: &NativeEventTranscript) -> Result<CourtReport, CourtError> {
    let value = serde_json::to_value(transcript).map_err(|error| CourtError::Canonical {
        message: error.to_string(),
    })?;
    let bytes = canonical_bytes(&value).map_err(|error| CourtError::Canonical {
        message: error.to_string(),
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();

    let mut verifier = Verifier::new(transcript);
    let outcome = verifier.run();
    let mut findings = verifier.findings;
    findings.sort();
    findings.dedup();
    findings.truncate(MAX_FINDINGS);
    let mut race_witnesses = verifier.race_witnesses;
    race_witnesses.sort();
    race_witnesses.dedup();
    race_witnesses.truncate(MAX_FINDINGS);

    Ok(CourtReport {
        schema: COURT_REPORT_SCHEMA.to_owned(),
        spec: COURT_SPEC.to_owned(),
        transcript_schema: transcript.schema.clone(),
        transcript_sha256: hex_lower(&digest),
        outcome,
        origin: transcript.provenance.origin,
        case_legality: transcript.provenance.case_legality,
        claimed_complete: transcript.provenance.claimed_complete,
        event_count: transcript
            .threads
            .iter()
            .map(|thread| thread.events.len())
            .sum(),
        thread_count: transcript.threads.len(),
        object_count: transcript.objects.len(),
        findings,
        race_witnesses,
        claim_ceiling: COURT_CLAIM_CEILING.to_owned(),
    })
}

fn map_identity_error(error: IdentityError) -> CourtError {
    match error {
        IdentityError::TooLarge { limit, .. } => CourtError::LimitExceeded {
            resource: "encoded_bytes",
            limit,
        },
        other => CourtError::invalid(other.to_string()),
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn require_nonempty(value: &str, field: &str) -> Result<(), CourtError> {
    if value.trim().is_empty() {
        return Err(CourtError::invalid(format!("{field} must not be empty")));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_structure(transcript: &NativeEventTranscript) -> Result<(), CourtError> {
    if transcript.schema != NATIVE_EVENT_TRANSCRIPT_SCHEMA {
        return Err(CourtError::invalid(format!(
            "schema must be {NATIVE_EVENT_TRANSCRIPT_SCHEMA}, got {}",
            transcript.schema
        )));
    }
    if transcript.spec != COURT_SPEC {
        return Err(CourtError::invalid(format!(
            "spec must be {COURT_SPEC}, got {}",
            transcript.spec
        )));
    }

    let provenance = &transcript.provenance;
    require_nonempty(&provenance.tool, "provenance.tool")?;
    require_nonempty(&provenance.tool_version, "provenance.tool_version")?;
    require_nonempty(&provenance.scope, "provenance.scope")?;
    if !is_sha256_hex(&provenance.executable_digest) {
        return Err(CourtError::invalid(
            "provenance.executable_digest must be 64 lowercase hexadecimal characters",
        ));
    }
    if !is_sha256_hex(&provenance.fixture_digest) {
        return Err(CourtError::invalid(
            "provenance.fixture_digest must be 64 lowercase hexadecimal characters",
        ));
    }
    for library in &provenance.library_versions {
        require_nonempty(&library.name, "provenance.library_versions[].name")?;
        require_nonempty(&library.version, "provenance.library_versions[].version")?;
    }

    if transcript.objects.len() > MAX_OBJECTS {
        return Err(CourtError::LimitExceeded {
            resource: "objects",
            limit: MAX_OBJECTS,
        });
    }
    let mut object_ids = BTreeSet::new();
    for object in &transcript.objects {
        require_nonempty(&object.id, "object.id")?;
        if !object_ids.insert(object.id.as_str()) {
            return Err(CourtError::invalid(format!(
                "duplicate object id: {}",
                object.id
            )));
        }
    }

    if transcript.threads.len() > MAX_THREADS {
        return Err(CourtError::LimitExceeded {
            resource: "threads",
            limit: MAX_THREADS,
        });
    }
    if transcript.synchronizes_with.len() > MAX_SYNC_EDGES {
        return Err(CourtError::LimitExceeded {
            resource: "synchronizes_with",
            limit: MAX_SYNC_EDGES,
        });
    }

    let mut thread_ids = BTreeSet::new();
    let mut event_refs = BTreeSet::new();
    let mut total_events = 0usize;
    for thread in &transcript.threads {
        require_nonempty(&thread.id, "thread.id")?;
        if !thread_ids.insert(thread.id.as_str()) {
            return Err(CourtError::invalid(format!(
                "duplicate thread id: {}",
                thread.id
            )));
        }
        total_events = total_events.saturating_add(thread.events.len());
        if total_events > MAX_TRANSCRIPT_EVENTS {
            return Err(CourtError::LimitExceeded {
                resource: "events",
                limit: MAX_TRANSCRIPT_EVENTS,
            });
        }
        let mut previous = None;
        for event in &thread.events {
            if previous.is_some_and(|value| event.seq <= value) {
                return Err(CourtError::invalid(format!(
                    "thread {} event sequence numbers must be strictly increasing",
                    thread.id
                )));
            }
            previous = Some(event.seq);
            let reference = EventRef {
                thread: thread.id.clone(),
                seq: event.seq,
            };
            if !event_refs.insert(reference) {
                return Err(CourtError::invalid(format!(
                    "duplicate event reference {}:{}",
                    thread.id, event.seq
                )));
            }
            validate_event_shape(event, &object_ids)?;
        }
    }

    for edge in &transcript.synchronizes_with {
        if edge.from == edge.to {
            return Err(CourtError::invalid(
                "synchronizes_with edge must not reference the same event",
            ));
        }
        if !event_refs.contains(&edge.from) || !event_refs.contains(&edge.to) {
            return Err(CourtError::invalid(
                "synchronizes_with edge references an unknown event",
            ));
        }
    }

    if let Some(requirements) = &transcript.requirements {
        for object in requirements
            .required_creates
            .iter()
            .chain(&requirements.required_frees)
            .chain(&requirements.required_generation_transitions)
        {
            if !object_ids.contains(object.as_str()) {
                return Err(CourtError::invalid(format!(
                    "requirement references unknown object: {object}"
                )));
            }
        }
        for token in &requirements.required_borrow_ends {
            require_nonempty(token, "requirements.required_borrow_ends[]")?;
        }
        for callback in &requirements.required_callbacks {
            require_nonempty(callback, "requirements.required_callbacks[]")?;
        }
    }

    for provider in &transcript.unknown_provider_edges {
        require_nonempty(&provider.provider, "unknown_provider_edges[].provider")?;
        require_nonempty(&provider.detail, "unknown_provider_edges[].detail")?;
    }

    Ok(())
}

fn validate_event_shape(event: &Event, object_ids: &BTreeSet<&str>) -> Result<(), CourtError> {
    require_nonempty(&event.object, "event.object")?;
    if !object_ids.contains(event.object.as_str()) {
        return Err(CourtError::invalid(format!(
            "event references unknown object: {}",
            event.object
        )));
    }
    for (value, field) in [
        (event.token.as_deref(), "event.token"),
        (event.from_token.as_deref(), "event.from_token"),
        (event.to_token.as_deref(), "event.to_token"),
        (event.owner.as_deref(), "event.owner"),
        (event.to_owner.as_deref(), "event.to_owner"),
        (event.provider.as_deref(), "event.provider"),
        (event.callback.as_deref(), "event.callback"),
    ] {
        if let Some(value) = value {
            require_nonempty(value, field)?;
        }
    }

    match event.kind {
        EventKind::Create => {
            require_field(event.token.as_deref(), "create.token")?;
            require_field(event.owner.as_deref(), "create.owner")?;
            if event.generation.is_none() {
                return Err(CourtError::invalid("create.generation is required"));
            }
        }
        EventKind::Transfer => {
            require_field(event.from_token.as_deref(), "transfer.from_token")?;
            require_field(event.to_token.as_deref(), "transfer.to_token")?;
            require_field(event.to_owner.as_deref(), "transfer.to_owner")?;
        }
        EventKind::TransferFailure => {
            require_field(event.from_token.as_deref(), "transfer_failure.from_token")?;
            require_field(event.to_owner.as_deref(), "transfer_failure.to_owner")?;
        }
        EventKind::BorrowShared | EventKind::BorrowMutable => {
            require_field(event.from_token.as_deref(), "borrow.from_token")?;
            require_field(event.token.as_deref(), "borrow.token")?;
        }
        EventKind::Reborrow => {
            require_field(event.from_token.as_deref(), "reborrow.from_token")?;
            require_field(event.token.as_deref(), "reborrow.token")?;
            if event.borrow.is_none() {
                return Err(CourtError::invalid("reborrow.borrow is required"));
            }
        }
        EventKind::BorrowEnd => {
            require_field(event.token.as_deref(), "borrow_end.token")?;
        }
        EventKind::Escape => {
            require_field(event.token.as_deref(), "escape.token")?;
            require_field(event.provider.as_deref(), "escape.provider")?;
        }
        EventKind::Reallocate => {
            require_field(event.from_token.as_deref(), "reallocate.from_token")?;
            require_field(event.token.as_deref(), "reallocate.token")?;
            require_field(event.owner.as_deref(), "reallocate.owner")?;
            if event.generation.is_none() {
                return Err(CourtError::invalid("reallocate.generation is required"));
            }
        }
        EventKind::Free => {
            require_field(event.token.as_deref(), "free.token")?;
        }
        EventKind::Use => {
            require_field(event.token.as_deref(), "use.token")?;
            if !event.access.is_access() {
                return Err(CourtError::invalid(
                    "use.access must be a memory access mode",
                ));
            }
        }
        EventKind::CallbackEnter => {
            require_field(event.callback.as_deref(), "callback_enter.callback")?;
        }
        EventKind::CallbackExit => {
            require_field(event.callback.as_deref(), "callback_exit.callback")?;
            if event.outcome.is_none() {
                return Err(CourtError::invalid("callback_exit.outcome is required"));
            }
        }
        EventKind::AllocationFailure => {
            require_field(event.owner.as_deref(), "allocation_failure.owner")?;
        }
        EventKind::PartialInit => {
            require_field(event.token.as_deref(), "partial_init.token")?;
        }
        EventKind::InitComplete => {
            require_field(event.token.as_deref(), "init_complete.token")?;
        }
        EventKind::Poison => {
            require_field(event.token.as_deref(), "poison.token")?;
        }
        EventKind::Abort => {}
    }
    Ok(())
}

fn require_field(value: Option<&str>, field: &str) -> Result<(), CourtError> {
    match value {
        Some(value) if !value.trim().is_empty() => Ok(()),
        _ => Err(CourtError::invalid(format!("{field} is required"))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum InitState {
    #[default]
    Unallocated,
    Uninitialized,
    Partial,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenStatus {
    Owner,
    SharedBorrow,
    MutableBorrow,
    Escaped,
    Transferred,
    Ended,
    Stale,
}

#[derive(Debug, Clone)]
struct TokenState {
    object: String,
    owner: String,
    generation: u64,
    status: TokenStatus,
    poisoned: bool,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default)]
struct ObjectState {
    created: bool,
    generation: u64,
    owner: Option<String>,
    owner_token: Option<String>,
    init: InitState,
    freed: bool,
    failed_attempts: u64,
    borrow_stack: Vec<String>,
    saw_create: bool,
    saw_free: bool,
    saw_reallocate: bool,
}

struct Verifier<'a> {
    transcript: &'a NativeEventTranscript,
    current_thread: String,
    objects: BTreeMap<String, ObjectState>,
    tokens: BTreeMap<String, TokenState>,
    findings: Vec<Finding>,
    race_witnesses: Vec<RaceWitness>,
    callback_stacks: BTreeMap<String, Vec<String>>,
    callback_entered: BTreeSet<String>,
    callback_completed: BTreeSet<String>,
    aborted: bool,
}

impl<'a> Verifier<'a> {
    fn new(transcript: &'a NativeEventTranscript) -> Self {
        let objects = transcript
            .objects
            .iter()
            .map(|object| (object.id.clone(), ObjectState::default()))
            .collect();
        Self {
            transcript,
            current_thread: String::new(),
            objects,
            tokens: BTreeMap::new(),
            findings: Vec::new(),
            race_witnesses: Vec::new(),
            callback_stacks: BTreeMap::new(),
            callback_entered: BTreeSet::new(),
            callback_completed: BTreeSet::new(),
            aborted: false,
        }
    }

    fn run(&mut self) -> TranscriptOutcome {
        let transcript = self.transcript;
        if transcript.provenance.case_legality == CaseLegality::Illegal {
            self.push_finding(
                FindingClass::Illegal,
                "illegal_case",
                "transcript",
                "provenance declares the case illegal",
                &[],
            );
            return self.outcome();
        }

        let Ok(order) = self.topological_order() else {
            self.push_finding(
                FindingClass::Illegal,
                "synchronizes_with_cycle",
                "transcript",
                "the declared synchronizes-with graph is cyclic",
                &[],
            );
            return self.outcome();
        };

        let events: BTreeMap<EventRef, &Event> = transcript
            .threads
            .iter()
            .flat_map(|thread| {
                thread.events.iter().map(move |event| {
                    (
                        EventRef {
                            thread: thread.id.clone(),
                            seq: event.seq,
                        },
                        event,
                    )
                })
            })
            .collect();

        for reference in &order {
            if let Some(event) = events.get(reference) {
                self.current_thread.clone_from(&reference.thread);
                self.process(&reference.thread, event);
            }
        }

        self.detect_races(&order, &events);
        self.audit();

        if transcript.provenance.claimed_complete
            && self
                .findings
                .iter()
                .any(|finding| finding.class == FindingClass::Incomplete)
        {
            self.push_finding(
                FindingClass::Incomplete,
                "fictitious_completeness",
                "transcript",
                "provenance claims completeness while required events or provider edges are missing",
                &[],
            );
        }

        self.outcome()
    }

    fn outcome(&self) -> TranscriptOutcome {
        if self
            .findings
            .iter()
            .any(|finding| finding.class == FindingClass::Illegal)
        {
            TranscriptOutcome::IllegalCase
        } else if self
            .findings
            .iter()
            .any(|finding| finding.class == FindingClass::ObservedViolation)
        {
            TranscriptOutcome::ObservedViolation
        } else if self
            .findings
            .iter()
            .any(|finding| finding.class == FindingClass::Incomplete)
        {
            TranscriptOutcome::IncompleteTranscript
        } else if self
            .findings
            .iter()
            .any(|finding| finding.class == FindingClass::Unresolved)
            || !self.transcript.provenance.origin.is_authentic()
        {
            TranscriptOutcome::Unresolved
        } else {
            TranscriptOutcome::VerifiedCompatibleWithinTranscript
        }
    }

    fn topological_order(&self) -> Result<Vec<EventRef>, ()> {
        let mut successors: BTreeMap<EventRef, BTreeSet<EventRef>> = BTreeMap::new();
        let mut indegree: BTreeMap<EventRef, usize> = BTreeMap::new();

        for thread in &self.transcript.threads {
            let mut previous: Option<EventRef> = None;
            for event in &thread.events {
                let reference = EventRef {
                    thread: thread.id.clone(),
                    seq: event.seq,
                };
                indegree.entry(reference.clone()).or_insert(0);
                successors.entry(reference.clone()).or_default();
                if let Some(previous) = &previous {
                    if successors
                        .get_mut(previous)
                        .is_some_and(|set| set.insert(reference.clone()))
                    {
                        *indegree.entry(reference.clone()).or_insert(0) += 1;
                    }
                }
                previous = Some(reference);
            }
        }
        for edge in &self.transcript.synchronizes_with {
            indegree.entry(edge.from.clone()).or_insert(0);
            successors.entry(edge.from.clone()).or_default();
            indegree.entry(edge.to.clone()).or_insert(0);
            successors.entry(edge.to.clone()).or_default();
            if successors
                .get_mut(&edge.from)
                .is_some_and(|set| set.insert(edge.to.clone()))
            {
                *indegree.entry(edge.to.clone()).or_insert(0) += 1;
            }
        }

        let mut ready: BTreeSet<EventRef> = indegree
            .iter()
            .filter(|(_, count)| **count == 0)
            .map(|(reference, _)| reference.clone())
            .collect();
        let mut order = Vec::with_capacity(indegree.len());
        while let Some(reference) = ready.iter().next().cloned() {
            ready.remove(&reference);
            order.push(reference.clone());
            if let Some(next) = successors.get(&reference) {
                for successor in next {
                    if let Some(count) = indegree.get_mut(successor) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            ready.insert(successor.clone());
                        }
                    }
                }
            }
        }
        if order.len() == indegree.len() {
            Ok(order)
        } else {
            Err(())
        }
    }

    fn detect_races(&mut self, order: &[EventRef], events: &BTreeMap<EventRef, &Event>) {
        let clocks = vector_clocks(order, &self.transcript.synchronizes_with);
        let mut by_object: BTreeMap<String, Vec<(EventRef, AccessMode)>> = BTreeMap::new();
        for reference in order {
            let Some(event) = events.get(reference) else {
                continue;
            };
            if let Some(access) = event_access(event) {
                by_object
                    .entry(event.object.clone())
                    .or_default()
                    .push((reference.clone(), access));
            }
        }

        for (object, accesses) in by_object {
            for left in 0..accesses.len() {
                for right in left + 1..accesses.len() {
                    let (first, first_access) = &accesses[left];
                    let (second, second_access) = &accesses[right];
                    if first.thread == second.thread {
                        continue;
                    }
                    let ordered = happens_before(&clocks, first, second)
                        || happens_before(&clocks, second, first);
                    if ordered
                        || !(first_access.is_write() || second_access.is_write())
                        || (first_access.is_atomic() && second_access.is_atomic())
                    {
                        continue;
                    }
                    let detail = format!(
                        "unordered accesses to {object} on threads {} and {}; one writes and at least one access is non-atomic",
                        first.thread, second.thread
                    );
                    self.race_witnesses.push(RaceWitness {
                        object: object.clone(),
                        first: first.clone(),
                        second: second.clone(),
                        first_access: *first_access,
                        second_access: *second_access,
                        detail: detail.clone(),
                    });
                    self.push_finding(
                        FindingClass::ObservedViolation,
                        "data_race",
                        &object,
                        &detail,
                        &[first.clone(), second.clone()],
                    );
                }
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn audit(&mut self) {
        let object_ids: Vec<String> = self.objects.keys().cloned().collect();
        for object_id in object_ids {
            let Some(object) = self.objects.get(&object_id).cloned() else {
                continue;
            };
            if !object.created {
                if object.failed_attempts == 0 {
                    self.push_finding(
                        FindingClass::Incomplete,
                        "object_without_lifecycle",
                        &object_id,
                        "object is declared but has no create or allocation-failure event",
                        &[],
                    );
                }
                continue;
            }
            if !object.freed {
                let escaped = object
                    .owner_token
                    .as_deref()
                    .and_then(|token| self.tokens.get(token))
                    .is_some_and(|token| token.status == TokenStatus::Escaped);
                let poisoned = object
                    .owner_token
                    .as_deref()
                    .and_then(|token| self.tokens.get(token))
                    .is_some_and(|token| token.poisoned);
                if escaped {
                    // Continuing custody is a completed responsibility transfer.
                } else if poisoned {
                    self.push_finding(
                        FindingClass::Incomplete,
                        "poisoned_lifecycle",
                        &object_id,
                        "object remains allocated with a poisoned owning token",
                        &[],
                    );
                } else {
                    self.push_finding(
                        FindingClass::Incomplete,
                        "outstanding_responsibility",
                        &object_id,
                        "object remains allocated without free or continuing custody",
                        &[],
                    );
                }
                if object.init == InitState::Partial {
                    self.push_finding(
                        FindingClass::Incomplete,
                        "partial_initialization",
                        &object_id,
                        "object completes with only partial initialization",
                        &[],
                    );
                }
            }
            for token in &object.borrow_stack {
                self.push_finding(
                    FindingClass::Incomplete,
                    "borrow_not_ended",
                    token,
                    "borrow token has no matching borrow_end",
                    &[],
                );
            }
        }

        let threads: Vec<String> = self.callback_stacks.keys().cloned().collect();
        for thread in threads {
            if let Some(stack) = self.callback_stacks.get(&thread).cloned() {
                for callback in &stack {
                    self.push_finding(
                        FindingClass::Incomplete,
                        "callback_not_exited",
                        callback,
                        "callback entered but did not exit",
                        &[],
                    );
                }
            }
        }

        if self.aborted {
            self.push_finding(
                FindingClass::Incomplete,
                "aborted_lifecycle",
                "transcript",
                "the transcript declares an aborted lifecycle",
                &[],
            );
        }

        if self
            .transcript
            .threads
            .iter()
            .all(|thread| thread.events.is_empty())
        {
            self.push_finding(
                FindingClass::Incomplete,
                "empty_transcript",
                "transcript",
                "transcript contains no events",
                &[],
            );
        }

        if let Some(recording) = self.transcript.recording.clone() {
            if let Some(expected) = recording.expected_event_count {
                let actual: usize = self
                    .transcript
                    .threads
                    .iter()
                    .map(|thread| thread.events.len())
                    .sum();
                if actual != expected {
                    self.push_finding(
                        FindingClass::Incomplete,
                        "event_count_mismatch",
                        "recording",
                        &format!(
                            "recorder declared {expected} events but the transcript contains {actual}"
                        ),
                        &[],
                    );
                }
            }
        }

        let providers = self.transcript.unknown_provider_edges.clone();
        if !providers.is_empty() {
            for provider in &providers {
                if self.transcript.provenance.claimed_complete {
                    self.push_finding(
                        FindingClass::Incomplete,
                        "unknown_provider_edge",
                        &provider.provider,
                        &format!(
                            "unknown provider edge retained while completeness is claimed: {}",
                            provider.detail
                        ),
                        &[],
                    );
                } else {
                    self.push_finding(
                        FindingClass::Unresolved,
                        "unknown_provider_edge",
                        &provider.provider,
                        &format!("unknown provider edge: {}", provider.detail),
                        &[],
                    );
                }
            }
        }

        if !self.transcript.provenance.origin.is_authentic() {
            self.push_finding(
                FindingClass::Unresolved,
                "non_authentic_origin",
                self.transcript.provenance.origin.as_str(),
                "only authentic native recording can support a clean transcript verdict",
                &[],
            );
        }

        if let Some(requirements) = self.transcript.requirements.clone() {
            for object in &requirements.required_creates {
                if !self
                    .objects
                    .get(object)
                    .is_some_and(|state| state.saw_create)
                {
                    self.push_finding(
                        FindingClass::Incomplete,
                        "required_create_missing",
                        object,
                        "required create event is absent",
                        &[],
                    );
                }
            }
            for object in &requirements.required_frees {
                if !self.objects.get(object).is_some_and(|state| state.saw_free) {
                    self.push_finding(
                        FindingClass::Incomplete,
                        "required_free_missing",
                        object,
                        "required free event is absent",
                        &[],
                    );
                }
            }
            for object in &requirements.required_generation_transitions {
                if !self
                    .objects
                    .get(object)
                    .is_some_and(|state| state.saw_reallocate)
                {
                    self.push_finding(
                        FindingClass::Incomplete,
                        "required_generation_transition_missing",
                        object,
                        "required reallocation generation transition is absent",
                        &[],
                    );
                }
            }
            for token in &requirements.required_borrow_ends {
                let ended = self
                    .tokens
                    .get(token)
                    .is_some_and(|state| state.status == TokenStatus::Ended);
                if !ended {
                    self.push_finding(
                        FindingClass::Incomplete,
                        "required_borrow_end_missing",
                        token,
                        "required borrow-end event is absent",
                        &[],
                    );
                }
            }
            for callback in &requirements.required_callbacks {
                if !self.callback_completed.contains(callback) {
                    self.push_finding(
                        FindingClass::Incomplete,
                        "required_callback_missing",
                        callback,
                        "required callback was not recorded through enter and exit",
                        &[],
                    );
                }
            }
        }
    }

    fn process(&mut self, thread: &str, event: &Event) {
        if self.aborted && event.kind != EventKind::Abort {
            self.violation(
                "event_after_abort",
                &event.object,
                "an event occurs after the declared abort",
                event,
            );
            return;
        }
        match event.kind {
            EventKind::Create => self.on_create(event),
            EventKind::Transfer => self.on_transfer(event),
            EventKind::TransferFailure => self.on_transfer_failure(event),
            EventKind::BorrowShared => self.on_borrow(event, BorrowKind::Shared),
            EventKind::BorrowMutable => self.on_borrow(event, BorrowKind::Mutable),
            EventKind::Reborrow => self.on_reborrow(event),
            EventKind::BorrowEnd => self.on_borrow_end(event),
            EventKind::Escape => self.on_escape(event),
            EventKind::Reallocate => self.on_reallocate(event),
            EventKind::Free => self.on_free(event),
            EventKind::Use => self.on_use(event),
            EventKind::CallbackEnter => self.on_callback_enter(thread, event),
            EventKind::CallbackExit => self.on_callback_exit(thread, event),
            EventKind::AllocationFailure => self.on_allocation_failure(event),
            EventKind::PartialInit => self.on_partial_init(event),
            EventKind::InitComplete => self.on_init_complete(event),
            EventKind::Poison => self.on_poison(event),
            EventKind::Abort => {
                self.aborted = true;
            }
        }
    }

    fn on_create(&mut self, event: &Event) {
        let Some(token_id) = event.token.as_deref() else {
            return;
        };
        let Some(owner) = event.owner.as_deref() else {
            return;
        };
        let Some(generation) = event.generation else {
            return;
        };
        let Some(mut object) = self.objects.get(&event.object).cloned() else {
            self.unknown_object(event);
            return;
        };
        if self.tokens.contains_key(token_id) {
            self.incomplete(
                "duplicate_token",
                token_id,
                "token identifier was already issued",
                event,
            );
            return;
        }
        if object.created && !object.freed {
            self.violation(
                "double_allocation",
                &event.object,
                "create issued for an object that is already allocated",
                event,
            );
            return;
        }
        if object.created {
            if generation <= object.generation {
                self.violation(
                    "reused_generation",
                    &event.object,
                    "create after free reused a non-advancing generation",
                    event,
                );
                return;
            }
            if generation != object.generation.saturating_add(1) {
                self.incomplete(
                    "skipped_generation_transition",
                    &event.object,
                    "create after free skipped a generation transition",
                    event,
                );
            }
        } else if generation != 0 {
            self.incomplete(
                "skipped_generation_transition",
                &event.object,
                "first create did not begin at generation zero",
                event,
            );
        }
        object.created = true;
        object.freed = false;
        object.generation = generation;
        object.owner = Some(owner.to_owned());
        object.owner_token = Some(token_id.to_owned());
        object.init = InitState::Uninitialized;
        object.borrow_stack.clear();
        object.saw_create = true;
        self.tokens.insert(
            token_id.to_owned(),
            TokenState {
                object: event.object.clone(),
                owner: owner.to_owned(),
                generation,
                status: TokenStatus::Owner,
                poisoned: false,
            },
        );
        self.objects.insert(event.object.clone(), object);
    }

    #[allow(clippy::too_many_lines)]
    fn on_transfer(&mut self, event: &Event) {
        let (Some(from), Some(to), Some(to_owner)) = (
            event.from_token.as_deref(),
            event.to_token.as_deref(),
            event.to_owner.as_deref(),
        ) else {
            return;
        };
        if self.tokens.contains_key(to) {
            self.incomplete(
                "duplicate_token",
                to,
                "transfer produced an already-issued token",
                event,
            );
            return;
        }
        let Some(mut object) = self.objects.get(&event.object).cloned() else {
            self.unknown_object(event);
            return;
        };
        if !object.created {
            self.not_created(event);
            return;
        }
        let Some(mut token) = self.tokens.get(from).cloned() else {
            self.incomplete(
                "unknown_token",
                from,
                "transfer references an unknown token",
                event,
            );
            return;
        };
        if token.object != event.object {
            self.violation(
                "token_object_mismatch",
                from,
                "token belongs to a different object",
                event,
            );
            return;
        }
        match token.status {
            TokenStatus::Owner => {}
            TokenStatus::Escaped => {
                self.violation(
                    "transfer_of_escaped_token",
                    from,
                    "escaped token cannot be transferred without reacquisition",
                    event,
                );
                return;
            }
            _ => {
                self.violation(
                    "transfer_of_non_owner",
                    from,
                    "only an owning token can transfer responsibility",
                    event,
                );
                return;
            }
        }
        if token.generation != object.generation {
            self.violation(
                "stale_generation",
                from,
                "token generation does not match the object generation",
                event,
            );
            return;
        }
        if token.poisoned {
            self.violation(
                "transfer_of_poisoned_token",
                from,
                "poisoned token cannot transfer responsibility",
                event,
            );
            return;
        }
        if !object.borrow_stack.is_empty() {
            self.violation(
                "transfer_with_live_borrow",
                &event.object,
                "transfer attempted while a borrow is live",
                event,
            );
            return;
        }
        token.status = TokenStatus::Transferred;
        self.tokens.insert(from.to_owned(), token);
        self.tokens.insert(
            to.to_owned(),
            TokenState {
                object: event.object.clone(),
                owner: to_owner.to_owned(),
                generation: object.generation,
                status: TokenStatus::Owner,
                poisoned: false,
            },
        );
        object.owner = Some(to_owner.to_owned());
        object.owner_token = Some(to.to_owned());
        self.objects.insert(event.object.clone(), object);
    }

    fn on_transfer_failure(&mut self, event: &Event) {
        let Some(from) = event.from_token.as_deref() else {
            return;
        };
        let Some(object) = self.objects.get(&event.object) else {
            self.unknown_object(event);
            return;
        };
        if !object.created {
            self.not_created(event);
            return;
        }
        let Some(token) = self.tokens.get(from) else {
            self.incomplete(
                "unknown_token",
                from,
                "transfer failure references an unknown token",
                event,
            );
            return;
        };
        if token.object != event.object {
            self.violation(
                "token_object_mismatch",
                from,
                "token belongs to a different object",
                event,
            );
            return;
        }
        if token.status != TokenStatus::Owner {
            self.violation(
                "transfer_failure_of_non_owner",
                from,
                "only an owning token can retain responsibility after a failed transfer",
                event,
            );
        }
        // Failed transfer preserves the original holder and issues no token.
    }

    fn on_borrow(&mut self, event: &Event, kind: BorrowKind) {
        let (Some(from), Some(new_token)) = (event.from_token.as_deref(), event.token.as_deref())
        else {
            return;
        };
        self.create_borrow(event, from, new_token, kind, false);
    }

    fn on_reborrow(&mut self, event: &Event) {
        let (Some(from), Some(new_token), Some(kind)) = (
            event.from_token.as_deref(),
            event.token.as_deref(),
            event.borrow,
        ) else {
            return;
        };
        self.create_borrow(event, from, new_token, kind, true);
    }

    #[allow(clippy::too_many_lines)]
    fn create_borrow(
        &mut self,
        event: &Event,
        from: &str,
        new_token: &str,
        kind: BorrowKind,
        reborrow: bool,
    ) {
        if self.tokens.contains_key(new_token) {
            self.incomplete(
                "duplicate_token",
                new_token,
                "borrow produced an already-issued token",
                event,
            );
            return;
        }
        let Some(mut object) = self.objects.get(&event.object).cloned() else {
            self.unknown_object(event);
            return;
        };
        if !object.created {
            self.not_created(event);
            return;
        }
        if object.freed {
            self.violation(
                "borrow_after_free",
                &event.object,
                "borrow issued after the object was freed",
                event,
            );
            return;
        }
        let Some(source) = self.tokens.get(from).cloned() else {
            self.incomplete(
                "unknown_token",
                from,
                "borrow references an unknown source token",
                event,
            );
            return;
        };
        if source.object != event.object {
            self.violation(
                "token_object_mismatch",
                from,
                "source token belongs to a different object",
                event,
            );
            return;
        }
        if source.generation != object.generation {
            self.violation(
                "stale_generation",
                from,
                "source token generation does not match the object generation",
                event,
            );
            return;
        }
        if source.poisoned {
            self.violation(
                "borrow_of_poisoned_token",
                from,
                "source token is poisoned",
                event,
            );
            return;
        }
        if source.status == TokenStatus::Escaped {
            self.violation(
                "borrow_of_escaped_token",
                from,
                "source token escaped to a foreign owner",
                event,
            );
            return;
        }
        if !self.token_usable(&object, from, &source) {
            self.violation(
                "borrow_conflict",
                from,
                "source token is not currently usable because another borrow is active",
                event,
            );
            return;
        }
        if reborrow
            && !matches!(
                source.status,
                TokenStatus::SharedBorrow | TokenStatus::MutableBorrow
            )
        {
            self.violation(
                "reborrow_from_owner",
                from,
                "reborrow requires an existing borrow token",
                event,
            );
            return;
        }
        if kind == BorrowKind::Mutable && source.status == TokenStatus::SharedBorrow {
            self.violation(
                "mutable_borrow_through_shared",
                from,
                "mutable borrow cannot be derived from a shared borrow",
                event,
            );
            return;
        }
        let status = match kind {
            BorrowKind::Shared => TokenStatus::SharedBorrow,
            BorrowKind::Mutable => TokenStatus::MutableBorrow,
        };
        self.tokens.insert(
            new_token.to_owned(),
            TokenState {
                object: event.object.clone(),
                owner: source.owner.clone(),
                generation: object.generation,
                status,
                poisoned: false,
            },
        );
        object.borrow_stack.push(new_token.to_owned());
        self.objects.insert(event.object.clone(), object);
    }

    fn on_borrow_end(&mut self, event: &Event) {
        let Some(token_id) = event.token.as_deref() else {
            return;
        };
        let Some(mut object) = self.objects.get(&event.object).cloned() else {
            self.unknown_object(event);
            return;
        };
        if !object.created {
            self.not_created(event);
            return;
        }
        let Some(mut token) = self.tokens.get(token_id).cloned() else {
            self.incomplete(
                "unknown_token",
                token_id,
                "borrow_end references an unknown token",
                event,
            );
            return;
        };
        if token.object != event.object {
            self.violation(
                "token_object_mismatch",
                token_id,
                "token belongs to a different object",
                event,
            );
            return;
        }
        if !matches!(
            token.status,
            TokenStatus::SharedBorrow | TokenStatus::MutableBorrow
        ) {
            self.violation(
                "borrow_end_of_non_borrow",
                token_id,
                "borrow_end requires a live borrow token",
                event,
            );
            return;
        }
        if token.generation != object.generation {
            self.violation(
                "stale_generation",
                token_id,
                "borrow token generation does not match the object generation",
                event,
            );
            return;
        }
        if object.borrow_stack.last().map(String::as_str) != Some(token_id) {
            self.violation(
                "out_of_order_borrow_end",
                token_id,
                "borrow_end requires the most recent borrow to end first",
                event,
            );
            return;
        }
        object.borrow_stack.pop();
        token.status = TokenStatus::Ended;
        self.tokens.insert(token_id.to_owned(), token);
        self.objects.insert(event.object.clone(), object);
    }

    fn on_escape(&mut self, event: &Event) {
        let (Some(token_id), Some(provider)) = (event.token.as_deref(), event.provider.as_deref())
        else {
            return;
        };
        let Some(mut object) = self.objects.get(&event.object).cloned() else {
            self.unknown_object(event);
            return;
        };
        if !object.created {
            self.not_created(event);
            return;
        }
        let Some(mut token) = self.tokens.get(token_id).cloned() else {
            self.incomplete(
                "unknown_token",
                token_id,
                "escape references an unknown token",
                event,
            );
            return;
        };
        if token.object != event.object {
            self.violation(
                "token_object_mismatch",
                token_id,
                "token belongs to a different object",
                event,
            );
            return;
        }
        if token.generation != object.generation {
            self.violation(
                "stale_generation",
                token_id,
                "token generation does not match the object generation",
                event,
            );
            return;
        }
        if token.status == TokenStatus::Escaped {
            self.incomplete(
                "already_escaped",
                token_id,
                "token was already recorded as escaped",
                event,
            );
            return;
        }
        if !matches!(
            token.status,
            TokenStatus::Owner | TokenStatus::SharedBorrow | TokenStatus::MutableBorrow
        ) {
            self.violation(
                "escape_of_non_live_token",
                token_id,
                "only a live token can escape to a foreign owner",
                event,
            );
            return;
        }
        token.status = TokenStatus::Escaped;
        provider.clone_into(&mut token.owner);
        object.borrow_stack.retain(|id| id.as_str() != token_id);
        if object.owner_token.as_deref() == Some(token_id) {
            object.owner = Some(provider.to_owned());
        }
        self.tokens.insert(token_id.to_owned(), token);
        self.objects.insert(event.object.clone(), object);
    }

    #[allow(clippy::too_many_lines)]
    fn on_reallocate(&mut self, event: &Event) {
        let (Some(from), Some(new_token), Some(generation), Some(owner)) = (
            event.from_token.as_deref(),
            event.token.as_deref(),
            event.generation,
            event.owner.as_deref(),
        ) else {
            return;
        };
        if self.tokens.contains_key(new_token) {
            self.incomplete(
                "duplicate_token",
                new_token,
                "reallocation produced an already-issued token",
                event,
            );
            return;
        }
        let Some(mut object) = self.objects.get(&event.object).cloned() else {
            self.unknown_object(event);
            return;
        };
        if !object.created {
            self.not_created(event);
            return;
        }
        let Some(mut old) = self.tokens.get(from).cloned() else {
            self.incomplete(
                "unknown_token",
                from,
                "reallocation references an unknown token",
                event,
            );
            return;
        };
        if old.object != event.object {
            self.violation(
                "token_object_mismatch",
                from,
                "token belongs to a different object",
                event,
            );
            return;
        }
        if old.status != TokenStatus::Owner {
            self.violation(
                "reallocate_of_non_owner",
                from,
                "reallocation requires the owning token",
                event,
            );
            return;
        }
        if old.generation != object.generation {
            self.violation(
                "stale_generation",
                from,
                "owning token generation does not match the object generation",
                event,
            );
            return;
        }
        if old.poisoned {
            self.violation(
                "reallocate_of_poisoned_token",
                from,
                "poisoned token cannot be reallocated",
                event,
            );
            return;
        }
        if !object.borrow_stack.is_empty() {
            self.violation(
                "reallocate_with_live_borrow",
                &event.object,
                "reallocation attempted while a borrow is live",
                event,
            );
            return;
        }
        if object.owner_token.as_deref() != Some(from) {
            self.violation(
                "reallocate_of_non_owner",
                from,
                "token is not the current owning token",
                event,
            );
            return;
        }
        let Some(next) = object.generation.checked_add(1) else {
            self.violation(
                "generation_exhaustion",
                &event.object,
                "generation counter cannot advance",
                event,
            );
            return;
        };
        if generation <= object.generation {
            self.incomplete(
                "missing_generation_transition",
                &event.object,
                "reallocation did not advance the generation",
                event,
            );
            return;
        }
        if generation != next {
            self.incomplete(
                "skipped_generation_transition",
                &event.object,
                "reallocation skipped one or more generations",
                event,
            );
        }
        let old_generation = object.generation;
        let stale: Vec<String> = self
            .tokens
            .iter()
            .filter(|(_, token)| token.object == event.object && token.generation == old_generation)
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            if let Some(token) = self.tokens.get_mut(&id) {
                if !matches!(
                    token.status,
                    TokenStatus::Transferred | TokenStatus::Ended | TokenStatus::Stale
                ) {
                    token.status = TokenStatus::Stale;
                }
            }
        }
        old.status = TokenStatus::Stale;
        self.tokens.insert(from.to_owned(), old);
        self.tokens.insert(
            new_token.to_owned(),
            TokenState {
                object: event.object.clone(),
                owner: owner.to_owned(),
                generation,
                status: TokenStatus::Owner,
                poisoned: false,
            },
        );
        object.generation = generation;
        object.owner = Some(owner.to_owned());
        object.owner_token = Some(new_token.to_owned());
        object.init = InitState::Uninitialized;
        object.borrow_stack.clear();
        object.saw_reallocate = true;
        self.objects.insert(event.object.clone(), object);
    }

    fn on_free(&mut self, event: &Event) {
        let Some(token_id) = event.token.as_deref() else {
            return;
        };
        let Some(mut object) = self.objects.get(&event.object).cloned() else {
            self.unknown_object(event);
            return;
        };
        if !object.created {
            self.not_created(event);
            return;
        }
        if object.freed {
            self.violation(
                "double_free",
                &event.object,
                "object was already freed",
                event,
            );
            return;
        }
        let Some(token) = self.tokens.get(token_id).cloned() else {
            self.incomplete(
                "unknown_token",
                token_id,
                "free references an unknown token",
                event,
            );
            return;
        };
        if token.object != event.object {
            self.violation(
                "token_object_mismatch",
                token_id,
                "token belongs to a different object",
                event,
            );
            return;
        }
        if token.status == TokenStatus::Escaped {
            self.violation(
                "free_of_escaped_token",
                token_id,
                "escaped token is owned by a foreign provider and cannot be freed locally",
                event,
            );
            return;
        }
        if token.status != TokenStatus::Owner {
            self.violation(
                "free_of_non_owner",
                token_id,
                "free requires the owning token",
                event,
            );
            return;
        }
        if token.generation != object.generation {
            self.violation(
                "stale_generation",
                token_id,
                "token generation does not match the object generation",
                event,
            );
            return;
        }
        if !object.borrow_stack.is_empty() {
            self.violation(
                "free_with_live_borrow",
                &event.object,
                "free attempted while a borrow is live",
                event,
            );
            return;
        }
        let generation = object.generation;
        let stale: Vec<String> = self
            .tokens
            .iter()
            .filter(|(_, token)| token.object == event.object && token.generation == generation)
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            if let Some(token) = self.tokens.get_mut(&id) {
                if !matches!(
                    token.status,
                    TokenStatus::Transferred | TokenStatus::Ended | TokenStatus::Stale
                ) {
                    token.status = TokenStatus::Stale;
                }
            }
        }
        object.freed = true;
        object.saw_free = true;
        object.owner = None;
        object.owner_token = None;
        object.borrow_stack.clear();
        self.objects.insert(event.object.clone(), object);
    }

    #[allow(clippy::too_many_lines)]
    fn on_use(&mut self, event: &Event) {
        let Some(token_id) = event.token.as_deref() else {
            return;
        };
        let Some(object) = self.objects.get(&event.object).cloned() else {
            self.unknown_object(event);
            return;
        };
        if !object.created {
            self.not_created(event);
            return;
        }
        let Some(token) = self.tokens.get(token_id).cloned() else {
            self.incomplete(
                "unknown_token",
                token_id,
                "use references an unknown token",
                event,
            );
            return;
        };
        if token.object != event.object {
            self.violation(
                "token_object_mismatch",
                token_id,
                "token belongs to a different object",
                event,
            );
            return;
        }
        if object.freed {
            self.violation(
                "use_after_free",
                &event.object,
                "use after the object was freed",
                event,
            );
            return;
        }
        match token.status {
            TokenStatus::Stale => {
                let code = if token.generation == object.generation {
                    "stale_token"
                } else {
                    "stale_generation"
                };
                self.violation(
                    code,
                    token_id,
                    "token is stale after reallocation or free",
                    event,
                );
                return;
            }
            TokenStatus::Ended => {
                self.violation(
                    "use_of_ended_token",
                    token_id,
                    "borrow token has already ended",
                    event,
                );
                return;
            }
            TokenStatus::Transferred => {
                self.violation(
                    "use_after_transfer",
                    token_id,
                    "token responsibility was transferred to another owner",
                    event,
                );
                return;
            }
            TokenStatus::Escaped => {
                self.violation(
                    "use_of_escaped_token",
                    token_id,
                    "token escaped to a foreign owner",
                    event,
                );
                return;
            }
            TokenStatus::Owner | TokenStatus::SharedBorrow | TokenStatus::MutableBorrow => {}
        }
        if token.generation != object.generation {
            self.violation(
                "stale_generation",
                token_id,
                "token generation does not match the object generation",
                event,
            );
            return;
        }
        if token.poisoned {
            self.violation(
                "use_of_poisoned_token",
                token_id,
                "token is poisoned by a failed operation",
                event,
            );
            return;
        }
        if object.init != InitState::Complete {
            self.violation(
                "use_before_initialization",
                &event.object,
                "object is not fully initialized",
                event,
            );
            return;
        }
        if !self.token_usable(&object, token_id, &token) {
            self.violation(
                "borrow_conflict",
                token_id,
                "token is suspended by a more recent borrow",
                event,
            );
            return;
        }
        if token.status == TokenStatus::SharedBorrow
            && event.access.is_write()
            && !event.access.is_atomic()
        {
            self.violation(
                "write_through_shared_borrow",
                token_id,
                "non-atomic write through a shared borrow",
                event,
            );
            return;
        }
        let atomic_object = self
            .transcript
            .objects
            .iter()
            .any(|declaration| declaration.id == event.object && declaration.atomic);
        if event.access.is_atomic() && !atomic_object {
            self.violation(
                "atomic_access_on_non_atomic_object",
                &event.object,
                "atomic access requires an object declared atomic",
                event,
            );
        }
    }

    fn on_callback_enter(&mut self, thread: &str, event: &Event) {
        let Some(callback) = event.callback.as_deref() else {
            return;
        };
        if let Some(token_id) = event.token.as_deref() {
            if !self.tokens.contains_key(token_id) {
                self.incomplete(
                    "unknown_token",
                    token_id,
                    "callback references an unknown token",
                    event,
                );
            }
        }
        self.callback_entered.insert(callback.to_owned());
        self.callback_stacks
            .entry(thread.to_owned())
            .or_default()
            .push(callback.to_owned());
    }

    fn on_callback_exit(&mut self, thread: &str, event: &Event) {
        let Some(callback) = event.callback.as_deref() else {
            return;
        };
        let Some(outcome) = event.outcome else {
            return;
        };
        let stack = self.callback_stacks.entry(thread.to_owned()).or_default();
        if stack.is_empty() {
            self.incomplete(
                "unrecorded_callback_exit",
                callback,
                "callback exit has no recorded entry",
                event,
            );
            return;
        }
        if stack.last().map(String::as_str) != Some(callback) {
            self.incomplete(
                "callback_order_mismatch",
                callback,
                "callback exit does not match the most recent entry",
                event,
            );
            return;
        }
        stack.pop();
        self.callback_completed.insert(callback.to_owned());
        if outcome == CallbackOutcome::Failed {
            if let Some(token_id) = event.token.as_deref() {
                if let Some(token) = self.tokens.get_mut(token_id) {
                    token.poisoned = true;
                } else {
                    self.incomplete(
                        "unknown_token",
                        token_id,
                        "failed callback references an unknown token",
                        event,
                    );
                }
            }
        }
    }

    fn on_allocation_failure(&mut self, event: &Event) {
        let Some(mut object) = self.objects.get(&event.object).cloned() else {
            self.unknown_object(event);
            return;
        };
        if object.created && !object.freed {
            self.violation(
                "allocation_failure_after_create",
                &event.object,
                "allocation failure recorded while the object is live",
                event,
            );
            return;
        }
        object.failed_attempts = object.failed_attempts.saturating_add(1);
        self.objects.insert(event.object.clone(), object);
    }

    fn on_partial_init(&mut self, event: &Event) {
        let Some(token_id) = event.token.as_deref() else {
            return;
        };
        let Some(mut object) = self.objects.get(&event.object).cloned() else {
            self.unknown_object(event);
            return;
        };
        if !object.created {
            self.not_created(event);
            return;
        }
        let Some(token) = self.tokens.get(token_id).cloned() else {
            self.incomplete(
                "unknown_token",
                token_id,
                "partial_init references an unknown token",
                event,
            );
            return;
        };
        if token.object != event.object || token.generation != object.generation {
            self.violation(
                "stale_generation",
                token_id,
                "token does not match the live object generation",
                event,
            );
            return;
        }
        if token.status != TokenStatus::Owner || token.poisoned {
            self.violation(
                "partial_init_of_non_owner",
                token_id,
                "partial initialization requires a live unpoisoned owning token",
                event,
            );
            return;
        }
        if !self.token_usable(&object, token_id, &token) {
            self.violation(
                "borrow_conflict",
                token_id,
                "partial initialization attempted while a borrow is active",
                event,
            );
            return;
        }
        if object.init == InitState::Complete {
            self.violation(
                "partial_init_after_complete",
                &event.object,
                "partial initialization recorded after complete initialization",
                event,
            );
            return;
        }
        object.init = InitState::Partial;
        self.objects.insert(event.object.clone(), object);
    }

    fn on_init_complete(&mut self, event: &Event) {
        let Some(token_id) = event.token.as_deref() else {
            return;
        };
        let Some(mut object) = self.objects.get(&event.object).cloned() else {
            self.unknown_object(event);
            return;
        };
        if !object.created {
            self.not_created(event);
            return;
        }
        let Some(token) = self.tokens.get(token_id).cloned() else {
            self.incomplete(
                "unknown_token",
                token_id,
                "init_complete references an unknown token",
                event,
            );
            return;
        };
        if token.object != event.object || token.generation != object.generation {
            self.violation(
                "stale_generation",
                token_id,
                "token does not match the live object generation",
                event,
            );
            return;
        }
        if token.status != TokenStatus::Owner || token.poisoned {
            self.violation(
                "init_complete_of_non_owner",
                token_id,
                "initialization completion requires a live unpoisoned owning token",
                event,
            );
            return;
        }
        if !self.token_usable(&object, token_id, &token) {
            self.violation(
                "borrow_conflict",
                token_id,
                "initialization completion attempted while a borrow is active",
                event,
            );
            return;
        }
        if object.init == InitState::Complete {
            self.violation(
                "duplicate_init_complete",
                &event.object,
                "initialization was already complete",
                event,
            );
            return;
        }
        object.init = InitState::Complete;
        self.objects.insert(event.object.clone(), object);
    }

    fn on_poison(&mut self, event: &Event) {
        let Some(token_id) = event.token.as_deref() else {
            return;
        };
        if let Some(token) = self.tokens.get_mut(token_id) {
            token.poisoned = true;
        } else {
            self.incomplete(
                "unknown_token",
                token_id,
                "poison references an unknown token",
                event,
            );
        }
    }

    fn token_usable(&self, object: &ObjectState, token_id: &str, token: &TokenState) -> bool {
        match token.status {
            TokenStatus::Owner => {
                object.borrow_stack.is_empty() && object.owner_token.as_deref() == Some(token_id)
            }
            TokenStatus::SharedBorrow | TokenStatus::MutableBorrow => {
                let Some(position) = object.borrow_stack.iter().position(|id| id == token_id)
                else {
                    return false;
                };
                if position + 1 == object.borrow_stack.len() {
                    return true;
                }
                if token.status != TokenStatus::SharedBorrow {
                    return false;
                }
                object.borrow_stack[position + 1..].iter().all(|id| {
                    self.tokens
                        .get(id)
                        .is_some_and(|state| state.status == TokenStatus::SharedBorrow)
                })
            }
            _ => false,
        }
    }

    fn not_created(&mut self, event: &Event) {
        let failed = self
            .objects
            .get(&event.object)
            .is_some_and(|object| object.failed_attempts > 0);
        if failed {
            self.violation(
                "use_of_unallocated",
                &event.object,
                "event uses an object whose allocation failed",
                event,
            );
        } else {
            self.incomplete(
                "missing_create",
                &event.object,
                "object has no create event before this transition",
                event,
            );
        }
    }

    fn unknown_object(&mut self, event: &Event) {
        self.incomplete(
            "unknown_object",
            &event.object,
            "event references an undeclared object",
            event,
        );
    }

    fn push_finding(
        &mut self,
        class: FindingClass,
        code: &str,
        subject: &str,
        detail: &str,
        events: &[EventRef],
    ) {
        self.findings.push(Finding {
            class,
            code: code.to_owned(),
            subject: subject.to_owned(),
            detail: detail.to_owned(),
            events: events.to_vec(),
        });
    }

    fn violation(&mut self, code: &str, subject: &str, detail: &str, event: &Event) {
        let reference = EventRef {
            thread: self.current_thread.clone(),
            seq: event.seq,
        };
        self.push_finding(
            FindingClass::ObservedViolation,
            code,
            subject,
            detail,
            &[reference],
        );
    }

    fn incomplete(&mut self, code: &str, subject: &str, detail: &str, event: &Event) {
        let reference = EventRef {
            thread: self.current_thread.clone(),
            seq: event.seq,
        };
        self.push_finding(
            FindingClass::Incomplete,
            code,
            subject,
            detail,
            &[reference],
        );
    }
}

fn event_access(event: &Event) -> Option<AccessMode> {
    if event.kind == EventKind::Use {
        if event.access.is_access() {
            Some(event.access)
        } else {
            None
        }
    } else if event.kind.writes_lifecycle() {
        Some(AccessMode::Write)
    } else {
        None
    }
}

fn vector_clocks(order: &[EventRef], edges: &[SyncEdge]) -> BTreeMap<EventRef, Vec<u64>> {
    let mut indices: BTreeMap<String, usize> = BTreeMap::new();
    for reference in order {
        let next = indices.len();
        indices.entry(reference.thread.clone()).or_insert(next);
    }
    let width = indices.len();
    let mut last = vec![vec![0_u64; width]; width];
    let mut incoming: BTreeMap<EventRef, Vec<EventRef>> = BTreeMap::new();
    for edge in edges {
        incoming
            .entry(edge.to.clone())
            .or_default()
            .push(edge.from.clone());
    }
    let mut clocks: BTreeMap<EventRef, Vec<u64>> = BTreeMap::new();
    for reference in order {
        let Some(index) = indices.get(&reference.thread).copied() else {
            continue;
        };
        let mut clock: Vec<u64> = last[index].clone();
        if let Some(predecessors) = incoming.get(reference) {
            for predecessor in predecessors {
                if let Some(other) = clocks.get(predecessor) {
                    for (left, right) in clock.iter_mut().zip(other) {
                        *left = (*left).max(*right);
                    }
                }
            }
        }
        clock[index] = reference.seq.saturating_add(1);
        last[index].clone_from(&clock);
        clocks.insert(reference.clone(), clock);
    }
    clocks
}

fn happens_before(
    clocks: &BTreeMap<EventRef, Vec<u64>>,
    left: &EventRef,
    right: &EventRef,
) -> bool {
    let (Some(left), Some(right)) = (clocks.get(left), clocks.get(right)) else {
        return false;
    };
    left.iter().zip(right).all(|(a, b)| a <= b) && left.iter().zip(right).any(|(a, b)| a < b)
}
