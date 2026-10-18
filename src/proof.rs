#![allow(clippy::module_name_repetitions)]

//! Phase 6 typed proof manifest, theorem/assumption closure, admission, and
//! live checked-proof adapter.
//!
//! This module implements the manifest and classification half of Phase 6 and
//! the Phase 6.2 live Coq adapter. The manifest is a canonical JSON description
//! of a checked-proof result, its declared theorem and assumption closure, and
//! the separate Rust/FFI implementation-correspondence obligation. The live
//! adapter invokes only an installed `coqc` with explicit argv vectors, stages
//! digest-bound proof files in a private `0700` directory, and derives theorem
//! statuses from Coq's `Print Assumptions`; only `Closed under the global
//! context` is treated as proved.
//!
//! # Claim ceiling
//!
//! A manifest that passes these checks establishes only that the supplied
//! declaration is well formed, digest-bound, closed over the declared
//! assumptions, accompanied by a separately enumerated implementation
//! binding, and (with `--live`) matched by a completed authentic checker run
//! over the exact proof bytes. It does **not** establish that the theorem is
//! universally true, that the declared dependency graph is complete, or that
//! the Rust/FFI correspondence evidence is semantically sound. `proof verify`
//! reports `checker_unavailable` (exit 6) when no live checker is configured,
//! even for a well-formed manifest.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};
#[cfg(unix)]
use std::process::{Command, ExitStatus, Stdio};
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(unix)]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::{canonical_bytes, hex_lower, parse_strict, IdentityError};
use crate::profile::UNIVERSAL_SOUNDNESS;
use crate::source::{FindingKind, SourceInventory, SOURCE_INVENTORY_SCHEMA};

/// Schema identifier for a proof manifest.
pub const PROOF_MANIFEST_SCHEMA: &str = "frf-memorysafety.proof-manifest.v1";
/// Schema identifier for a proof verification report.
pub const PROOF_REPORT_SCHEMA: &str = "frf-memorysafety.proof-verification-report.v1";
/// Protocol specification identifier.
pub const PROOF_SPEC: &str = "frf-memorysafety-spec-v1";
/// Claim ceiling embedded in every proof report.
pub const PROOF_CLAIM_CEILING: &str = "Manifest validation is not proof checking. A well-formed manifest establishes only that the declared theorem, assumption closure, proof-file digests, and implementation binding are structurally consistent and mutually bound. It does not establish that a checker ran, that the proof compiles, that the theorem is true, that the dependency graph is complete, or that the implementation correspondence is semantically sound. No universal soundness or SAFE_COMPATIBLE claim is made.";

/// Maximum number of proof files in one manifest.
pub const MAX_PROOF_FILES: usize = 64;
/// Maximum number of theorems in one declared closure.
pub const MAX_CLOSURE_THEOREMS: usize = 256;
/// Maximum number of declared assumptions.
pub const MAX_ASSUMPTIONS: usize = 64;
/// Maximum number of Rust/FFI symbol bindings.
pub const MAX_SYMBOL_BINDINGS: usize = 64;
/// Maximum number of enumerated lifecycle or transition entries.
pub const MAX_TRANSITIONS: usize = 64;
/// Maximum number of separate correspondence evidence entries.
pub const MAX_CORRESPONDENCE_EVIDENCE: usize = 64;
/// Maximum bytes accepted for one proof, source, or evidence file.
pub const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
/// Wall-clock bound for one live proof-checker invocation.
#[cfg(unix)]
pub const LIVE_CHECKER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
/// Maximum captured stdout or stderr for one live checker stage.
#[cfg(unix)]
pub const MAX_LIVE_CHECKER_OUTPUT: usize = 1024 * 1024;
/// Environment flag that enables the live proof-gate seal tests.
pub const LIVE_PROOF_ENV: &str = "FRF_PROOF_GATE";

/// Lexical admission constructs that must not occur in the scanned closure.
///
/// `Admitted`, `admit`, and `sorry` are unchecked proof admissions. `Axiom`,
/// `axiom`, `Parameter`, and `Conjecture` are unproved declarations. The scan
/// is deliberately lexical and conservative; it is not a parser for any proof
/// language.
pub const FORBIDDEN_ADMISSION_TOKENS: [&str; 7] = [
    "Admitted",
    "admit",
    "sorry",
    "Axiom",
    "axiom",
    "Parameter",
    "Conjecture",
];

/// The transition kind that must always be enumerated for an FFI binding.
pub const REQUIRED_REENTRANT_TRANSITION: TransitionKind = TransitionKind::ReentrantCallback;

/// Supported proof-checker families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckerKind {
    /// Coq/Rocq.
    Coq,
    /// Lean 4.
    Lean4,
    /// Isabelle/HOL.
    Isabelle,
}

impl CheckerKind {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Coq => "coq",
            Self::Lean4 => "lean4",
            Self::Isabelle => "isabelle",
        }
    }
}

/// Role of a proof file in the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofFileRole {
    /// The file containing the requested theorem.
    Theorem,
    /// A file in the declared dependency closure.
    Dependency,
    /// A file retained for supply-chain context but outside the closure.
    Support,
}

/// Provenance of the recorded checker result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofOrigin {
    /// The recorded result claims an authentic checker run.
    AuthenticCheckerRun,
    /// The result is substituted or modeled, never an authentic run.
    SubstituteModeled,
}

impl ProofOrigin {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticCheckerRun => "authentic_checker_run",
            Self::SubstituteModeled => "substitute_modeled",
        }
    }

    /// Whether this origin claims an authentic checker run.
    #[must_use]
    pub const fn is_authentic(self) -> bool {
        matches!(self, Self::AuthenticCheckerRun)
    }
}

/// Kind of declared assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssumptionKind {
    /// A theorem-local parameter discharged by universal quantification.
    Hypothesis,
    /// A global unproved axiom.
    Axiom,
    /// A global parameter declaration.
    Parameter,
    /// A conjecture.
    Conjecture,
}

impl AssumptionKind {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hypothesis => "hypothesis",
            Self::Axiom => "axiom",
            Self::Parameter => "parameter",
            Self::Conjecture => "conjecture",
        }
    }
}

/// Checker-reported status of one theorem in the closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionStatus {
    /// The checker reports the theorem as proved.
    Proved,
    /// The theorem was admitted without a proof.
    Admitted,
    /// The theorem depends on an axiom.
    Axiom,
    /// The theorem was closed with `sorry`.
    Sorry,
    /// The checker did not check the theorem.
    Unchecked,
    /// The checker reported a failure.
    Failed,
}

impl AdmissionStatus {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proved => "proved",
            Self::Admitted => "admitted",
            Self::Axiom => "axiom",
            Self::Sorry => "sorry",
            Self::Unchecked => "unchecked",
            Self::Failed => "failed",
        }
    }

    /// Whether this status is an unchecked admission.
    #[must_use]
    pub const fn is_unproved(self) -> bool {
        matches!(self, Self::Admitted | Self::Axiom | Self::Sorry)
    }
}

/// Final admission classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofOutcome {
    /// The recorded theorem is admitted within its declared finite scope.
    AcceptedWithinScope,
    /// An admitted, `sorry`, axiom, parameter, or conjecture escapes the closure.
    RejectedAssumption,
    /// The theorem or admission is unrelated to the declared scope or closure.
    RejectedUnrelated,
    /// An FFI wrapper has no separate, checked implementation binding.
    RejectedUncheckedImplementation,
    /// A required lifecycle or reentrant-callback transition is not enumerated.
    RejectedMissingTransition,
    /// No live checker is configured, so no proof acceptance is claimed.
    CheckerUnavailable,
    /// The recorded checker run failed or was internally inconsistent.
    CheckerFailed,
}

impl ProofOutcome {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AcceptedWithinScope => "accepted_within_scope",
            Self::RejectedAssumption => "rejected_assumption",
            Self::RejectedUnrelated => "rejected_unrelated",
            Self::RejectedUncheckedImplementation => "rejected_unchecked_implementation",
            Self::RejectedMissingTransition => "rejected_missing_transition",
            Self::CheckerUnavailable => "checker_unavailable",
            Self::CheckerFailed => "checker_failed",
        }
    }

    /// Exit status for this outcome under `SPEC.md` §14.
    ///
    /// Rejections and checker failures are claim-blocking refusals (4).
    /// An unavailable checker is `NOT_RUN` (6).
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::AcceptedWithinScope => 0,
            Self::RejectedAssumption
            | Self::RejectedUnrelated
            | Self::RejectedUncheckedImplementation
            | Self::RejectedMissingTransition
            | Self::CheckerFailed => 4,
            Self::CheckerUnavailable => 6,
        }
    }
}

/// Status of one independent gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    /// Every check in this gate passed.
    Pass,
    /// At least one check in this gate failed.
    Fail,
}

/// Kind of Rust or FFI symbol binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    /// A safe or unsafe Rust function.
    RustFn,
    /// A foreign declaration in an `extern` block.
    FfiDeclaration,
    /// An exported `extern` function.
    ExternFn,
    /// A callback type or registration.
    Callback,
}

/// Enumerated lifecycle or transition kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionKind {
    /// Allocation and initialization.
    Lifecycle,
    /// Ownership transfer between Rust and foreign code.
    Transfer,
    /// Borrow or reborrow across the boundary.
    Borrow,
    /// Deallocation.
    Free,
    /// A non-reentrant callback.
    Callback,
    /// A reentrant callback that may mutate live state.
    ReentrantCallback,
    /// An error or refusal path.
    Error,
    /// Unwinding or panic across the boundary.
    Unwind,
    /// Unknown foreign interference.
    UnknownInterference,
}

impl TransitionKind {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lifecycle => "lifecycle",
            Self::Transfer => "transfer",
            Self::Borrow => "borrow",
            Self::Free => "free",
            Self::Callback => "callback",
            Self::ReentrantCallback => "reentrant_callback",
            Self::Error => "error",
            Self::Unwind => "unwind",
            Self::UnknownInterference => "unknown_interference",
        }
    }
}

/// Kind of separate implementation-correspondence evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrespondenceEvidenceKind {
    /// A refinement or simulation argument.
    Refinement,
    /// A reviewed contract or boundary argument.
    Review,
    /// A finite test or replay observation.
    Test,
    /// A digest-bound source slice.
    SourceSlice,
    /// A foreign-function contract.
    FfiContract,
    /// An enumerated transition table.
    TransitionEnumeration,
}

/// Status of one declared assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssumptionStatus {
    /// A theorem-local hypothesis discharged by a declared binder.
    AllowedHypothesis,
    /// An unproved or undeclared assumption.
    Rejected,
}

/// A lifecycle or boundary transition declared by the correspondence gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    /// Stable transition identifier.
    pub id: String,
    /// Transition kind.
    pub kind: TransitionKind,
    /// Human-readable description of the exact transition.
    pub description: String,
    /// Identifier of separate correspondence evidence for this transition.
    pub evidence: String,
}

/// One separated correspondence evidence artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrespondenceEvidence {
    /// Stable evidence identifier.
    pub id: String,
    /// Evidence kind.
    pub kind: CorrespondenceEvidenceKind,
    /// Path relative to the manifest directory.
    pub path: String,
    /// Lower-case SHA-256 of the exact evidence bytes.
    pub sha256: String,
    /// What this evidence does and does not establish.
    pub detail: String,
}

/// Foreign wrapper metadata for an FFI declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FfiBinding {
    /// Exact foreign declaration text.
    pub declaration: String,
    /// Rust symbol that wraps the declaration.
    pub wrapper_symbol: String,
    /// Whether the wrapper has been separately checked.
    pub wrapper_checked: bool,
    /// Identifier of the correspondence evidence for the wrapper.
    pub wrapper_evidence: String,
}

/// One Rust or FFI symbol bound to the proof statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolBinding {
    /// Exact symbol name.
    pub symbol: String,
    /// Symbol kind.
    pub kind: SymbolKind,
    /// Source path relative to the manifest directory.
    pub source_path: String,
    /// Lower-case SHA-256 of the exact source bytes.
    pub source_sha256: String,
    /// Foreign wrapper metadata; required exactly for [`SymbolKind::FfiDeclaration`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ffi: Option<FfiBinding>,
}

/// Explicit source-binding evidence used when no Phase 3.1 inventory is given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingEvidence {
    /// Symbol this evidence binds.
    pub symbol: String,
    /// Source path relative to the manifest directory.
    pub path: String,
    /// Lower-case SHA-256 of the exact source bytes.
    pub sha256: String,
    /// What the slice establishes.
    pub detail: String,
}

/// Reference to a Phase 3.1 source inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInventoryRef {
    /// Path relative to the manifest directory.
    pub path: String,
    /// Lower-case SHA-256 of the exact inventory bytes.
    pub sha256: String,
}

/// Separate Rust/FFI implementation binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationBinding {
    /// Exact theorem-to-code correspondence statement.
    pub statement: String,
    /// Optional Phase 3.1 source inventory binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_inventory: Option<SourceInventoryRef>,
    /// Rust and FFI symbols covered by the statement.
    pub rust_symbols: Vec<SymbolBinding>,
    /// Explicit binding evidence when no source inventory is supplied.
    #[serde(default)]
    pub binding_evidence: Vec<BindingEvidence>,
    /// Enumerated lifecycle and transition coverage.
    pub transitions: Vec<Transition>,
    /// Transition kinds the binding claims to cover.
    pub required_transitions: Vec<TransitionKind>,
    /// Separate correspondence evidence. Never part of theorem admission.
    pub correspondence_evidence: Vec<CorrespondenceEvidence>,
}

/// Exact checker identity and pinned version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckerIdentity {
    /// Checker family.
    pub kind: CheckerKind,
    /// Exact pinned version, with no wildcard or range.
    pub version: String,
    /// Exact checker executable or driver name.
    pub executable: String,
}

/// One digest-bound proof file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofFile {
    /// Stable file identifier used by dependencies.
    pub id: String,
    /// Path relative to the manifest directory.
    pub path: String,
    /// Lower-case SHA-256 of the exact file bytes.
    pub sha256: String,
    /// Proof language. Must match the checker family.
    pub language: CheckerKind,
    /// File role in the manifest.
    pub role: ProofFileRole,
    /// Theorem names declared in this file.
    pub theorems: Vec<String>,
    /// Local imports or dependencies declared by this file.
    #[serde(default)]
    pub imports: Vec<String>,
}

/// The theorem requested by the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TheoremBinding {
    /// Exact theorem name.
    pub name: String,
    /// Claim identifiers this theorem is offered for.
    pub claim_ids: Vec<String>,
}

/// Declared finite scope of the theorem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TheoremScope {
    /// Claim identifiers admitted by this scope.
    pub claim_ids: Vec<String>,
    /// Exact finite domain.
    pub finite_domain: String,
    /// What the theorem establishes.
    pub proved: String,
    /// What the theorem explicitly does not establish.
    pub not_proved: Vec<String>,
}

/// One dependency edge between theorems.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalDependency {
    /// Dependent theorem.
    pub theorem: String,
    /// Theorems it depends on.
    pub depends_on: Vec<String>,
}

/// Declared theorem and import closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureDeclaration {
    /// Every theorem in the declared closure, including the requested theorem.
    pub theorems: Vec<String>,
    /// Declared local dependency edges.
    #[serde(default)]
    pub local_dependencies: Vec<LocalDependency>,
    /// Allowed standard-library import prefixes.
    pub stdlib_allowlist: Vec<String>,
}

/// One named and justified assumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assumption {
    /// Stable assumption identifier.
    pub id: String,
    /// Assumption kind.
    pub kind: AssumptionKind,
    /// Exact assumption name.
    pub name: String,
    /// Why the assumption is claimed to be legitimate.
    pub justification: String,
    /// Where the assumption applies.
    pub scope: String,
    /// Theorem binder that discharges a hypothesis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discharged_by: Option<String>,
}

/// One proof-file digest recorded by the checker run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofDigest {
    /// Proof file identifier.
    pub file_id: String,
    /// Lower-case SHA-256 of the exact file bytes.
    pub sha256: String,
}

/// Checker-reported status for one theorem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionTheorem {
    /// Exact theorem name.
    pub name: String,
    /// Checker-reported status.
    pub status: AdmissionStatus,
}

/// Recorded admission classification and checker evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRecord {
    /// Provenance of the recorded result.
    pub origin: ProofOrigin,
    /// Checker family recorded for the run.
    pub checker_kind: CheckerKind,
    /// Exact checker version recorded for the run.
    pub checker_version: String,
    /// Checker process exit code.
    pub exit_code: i32,
    /// Digests the checker claims to have checked.
    pub proof_digests: Vec<ProofDigest>,
    /// Theorems the checker claims to have checked.
    pub theorems: Vec<AdmissionTheorem>,
    /// Classification the producer recorded. This value is untrusted; the
    /// verifier recomputes the classification.
    pub classification: ProofOutcome,
}

/// Provenance for the manifest and recorded checker result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// Authentic checker run or substitute/modeled result.
    pub origin: ProofOrigin,
    /// Stable run identifier.
    pub run_id: String,
    /// Human-readable provenance detail.
    pub detail: String,
}

/// A canonical, typed proof manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofManifest {
    /// Manifest schema.
    pub schema: String,
    /// Specification identifier.
    pub spec: String,
    /// Claim ceiling embedded in the manifest.
    pub claim_ceiling: String,
    /// Exact checker identity.
    pub checker: CheckerIdentity,
    /// Digest-bound proof files.
    pub proof_files: Vec<ProofFile>,
    /// Requested theorem.
    pub theorem: TheoremBinding,
    /// Declared finite scope.
    pub scope: TheoremScope,
    /// Declared theorem and import closure.
    pub closure: ClosureDeclaration,
    /// Named and justified assumptions.
    pub assumptions: Vec<Assumption>,
    /// Recorded admission classification.
    pub admission: AdmissionRecord,
    /// Separate implementation binding.
    pub implementation_binding: ImplementationBinding,
    /// Manifest provenance.
    pub provenance: Provenance,
}

/// Errors produced while parsing or verifying a proof manifest.
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    /// Strict JSON parsing failed.
    #[error("invalid proof manifest JSON: {0}")]
    Identity(#[from] IdentityError),
    /// The typed manifest failed a structural rule.
    #[error("invalid proof manifest: {message}")]
    Invalid {
        /// Rule that failed.
        message: String,
    },
    /// The recorded checker identity, version, or digests do not match.
    #[error("checker evidence mismatch: {detail}")]
    CheckerMismatch {
        /// Mismatched field or value.
        detail: String,
    },
    /// A proof, source, inventory, or evidence file is missing.
    #[error("missing file: {path}")]
    MissingFile {
        /// Path that could not be read.
        path: String,
    },
    /// A file digest does not match the manifest.
    #[error("digest mismatch for {path}: expected {expected}, found {actual}")]
    DigestMismatch {
        /// Path whose digest differs.
        path: String,
        /// Declared digest.
        expected: String,
        /// Observed digest.
        actual: String,
    },
    /// A manifest path escapes the manifest directory.
    #[error("path is not a safe relative path: {path}")]
    PathEscape {
        /// Rejected path.
        path: String,
    },
    /// An I/O error occurred while reading a bound file.
    #[error("cannot read {path}: {message}")]
    Io {
        /// Path that failed.
        path: String,
        /// Underlying diagnostic.
        message: String,
    },
    /// A report could not be encoded canonically.
    #[error("cannot encode proof report: {message}")]
    Canonical {
        /// Encoder diagnostic.
        message: String,
    },
}

impl ProofError {
    /// Category used for exit-status selection.
    #[must_use]
    pub const fn category(&self) -> ProofErrorCategory {
        match self {
            Self::Canonical { .. } => ProofErrorCategory::Harness,
            Self::Identity(_)
            | Self::Invalid { .. }
            | Self::CheckerMismatch { .. }
            | Self::MissingFile { .. }
            | Self::DigestMismatch { .. }
            | Self::PathEscape { .. }
            | Self::Io { .. } => ProofErrorCategory::Integrity,
        }
    }
}

/// Error category used by the CLI to choose a `SPEC.md` §14 exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofErrorCategory {
    /// Evidence integrity failure.
    Integrity,
    /// Internal harness or encoding failure.
    Harness,
}

/// One proof file retained in the admission report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScannedFile {
    /// Proof file identifier.
    pub id: String,
    /// Path relative to the manifest directory.
    pub path: String,
    /// Observed lower-case SHA-256.
    pub sha256: String,
}

/// One declared assumption and its admission status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssumptionReport {
    /// Assumption identifier.
    pub id: String,
    /// Exact assumption name.
    pub name: String,
    /// Assumption kind.
    pub kind: AssumptionKind,
    /// Admission status.
    pub status: AssumptionStatus,
    /// Why the status was assigned.
    pub detail: String,
}

/// One forbidden admission construct found during the lexical closure scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenFinding {
    /// Proof file identifier.
    pub file_id: String,
    /// Path relative to the manifest directory.
    pub path: String,
    /// One-based line number.
    pub line: usize,
    /// Forbidden token.
    pub token: String,
    /// Declared assumption name when the token introduced a declaration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_name: Option<String>,
    /// Whether a manifest assumption matched the declared name.
    pub declared_in_manifest: bool,
    /// Classification detail.
    pub detail: String,
}

/// Admission and closure report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReport {
    /// Recomputed admission outcome.
    pub outcome: ProofOutcome,
    /// Requested theorem.
    pub theorem: String,
    /// Claims admitted by the declared scope.
    pub scope_claim_ids: Vec<String>,
    /// Claims the theorem is offered for.
    pub theorem_claim_ids: Vec<String>,
    /// Theorem names reachable from the requested theorem.
    pub reachable_theorems: Vec<String>,
    /// Proof files scanned for forbidden admissions.
    pub scanned_files: Vec<ScannedFile>,
    /// Declared assumptions and their status.
    pub assumptions: Vec<AssumptionReport>,
    /// Forbidden admission constructs in the scanned closure.
    pub forbidden_findings: Vec<ForbiddenFinding>,
    /// Checker-reported theorem statuses.
    pub admission_theorems: Vec<AdmissionTheorem>,
    /// Origin recorded by the manifest.
    pub origin: ProofOrigin,
    /// Checker exit code recorded by the manifest.
    pub exit_code: i32,
    /// Classification recorded by the manifest producer. Untrusted.
    pub recorded_classification: ProofOutcome,
    /// Human-readable summary of the decisive checks.
    pub detail: String,
}

impl AdmissionReport {
    /// Encode this report as strict `ms-canonical-json-v1` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::Canonical`] if the report cannot be represented.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProofError> {
        let value = serde_json::to_value(self).map_err(|error| ProofError::Canonical {
            message: error.to_string(),
        })?;
        canonical_bytes(&value).map_err(|error| ProofError::Canonical {
            message: error.to_string(),
        })
    }
}

/// Parse and structurally validate a proof manifest.
///
/// # Errors
///
/// Returns [`ProofError`] for non-canonical JSON, duplicate or unknown fields,
/// malformed paths, bad digests, or an inconsistent manifest.
pub fn parse_manifest(bytes: &[u8]) -> Result<ProofManifest, ProofError> {
    let value = parse_strict(bytes)?;
    let manifest: ProofManifest =
        serde_json::from_value(value).map_err(|error| ProofError::Invalid {
            message: error.to_string(),
        })?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

#[allow(clippy::too_many_lines)]
fn validate_manifest(manifest: &ProofManifest) -> Result<(), ProofError> {
    require_exact("schema", &manifest.schema, PROOF_MANIFEST_SCHEMA)?;
    require_exact("spec", &manifest.spec, PROOF_SPEC)?;
    require_exact(
        "claim_ceiling",
        &manifest.claim_ceiling,
        PROOF_CLAIM_CEILING,
    )?;

    non_empty("checker.version", &manifest.checker.version)?;
    non_empty("checker.executable", &manifest.checker.executable)?;
    if manifest.checker.version.contains(['*', '^', '~', '>', '<']) {
        return Err(ProofError::Invalid {
            message: "checker.version must be an exact pinned version, not a range".to_owned(),
        });
    }

    if manifest.proof_files.is_empty() {
        return Err(ProofError::Invalid {
            message: "proof_files must not be empty".to_owned(),
        });
    }
    if manifest.proof_files.len() > MAX_PROOF_FILES {
        return Err(ProofError::Invalid {
            message: format!(
                "proof_files has {} entries; limit is {MAX_PROOF_FILES}",
                manifest.proof_files.len()
            ),
        });
    }

    let mut file_ids = BTreeSet::new();
    let mut file_paths = BTreeSet::new();
    let mut declared_theorems: BTreeMap<String, String> = BTreeMap::new();
    for file in &manifest.proof_files {
        non_empty("proof_files[].id", &file.id)?;
        validate_sha256("proof_files[].sha256", &file.sha256)?;
        validate_relative_path("proof_files[].path", &file.path)?;
        if !file_ids.insert(file.id.clone()) {
            return Err(ProofError::Invalid {
                message: format!("duplicate proof file id: {}", file.id),
            });
        }
        if !file_paths.insert(file.path.clone()) {
            return Err(ProofError::Invalid {
                message: format!("duplicate proof file path: {}", file.path),
            });
        }
        if file.language != manifest.checker.kind {
            return Err(ProofError::Invalid {
                message: format!(
                    "proof file {} language {} does not match checker kind {}",
                    file.id,
                    file.language.as_str(),
                    manifest.checker.kind.as_str()
                ),
            });
        }
        if file.theorems.is_empty() {
            return Err(ProofError::Invalid {
                message: format!("proof file {} declares no theorems", file.id),
            });
        }
        for theorem in &file.theorems {
            non_empty("proof_files[].theorems[]", theorem)?;
            if let Some(existing) = declared_theorems.insert(theorem.clone(), file.id.clone()) {
                return Err(ProofError::Invalid {
                    message: format!(
                        "theorem {theorem} is declared in both {existing} and {}",
                        file.id
                    ),
                });
            }
        }
        for import in &file.imports {
            non_empty("proof_files[].imports[]", import)?;
        }
    }

    non_empty("theorem.name", &manifest.theorem.name)?;
    require_unique_non_empty("theorem.claim_ids", &manifest.theorem.claim_ids)?;
    require_unique_non_empty("scope.claim_ids", &manifest.scope.claim_ids)?;
    non_empty("scope.finite_domain", &manifest.scope.finite_domain)?;
    non_empty("scope.proved", &manifest.scope.proved)?;
    require_unique_non_empty("scope.not_proved", &manifest.scope.not_proved)?;

    if manifest.closure.theorems.is_empty() {
        return Err(ProofError::Invalid {
            message: "closure.theorems must not be empty".to_owned(),
        });
    }
    if manifest.closure.theorems.len() > MAX_CLOSURE_THEOREMS {
        return Err(ProofError::Invalid {
            message: format!(
                "closure.theorems has {} entries; limit is {MAX_CLOSURE_THEOREMS}",
                manifest.closure.theorems.len()
            ),
        });
    }
    require_unique_non_empty("closure.theorems", &manifest.closure.theorems)?;
    if !manifest.closure.theorems.contains(&manifest.theorem.name) {
        return Err(ProofError::Invalid {
            message: "closure.theorems must contain theorem.name".to_owned(),
        });
    }
    for theorem in &manifest.closure.theorems {
        if !declared_theorems.contains_key(theorem) {
            return Err(ProofError::Invalid {
                message: format!("closure theorem {theorem} is not declared in any proof file"),
            });
        }
    }
    let closure_set: BTreeSet<String> = manifest.closure.theorems.iter().cloned().collect();
    let mut dependency_sources = BTreeSet::new();
    for edge in &manifest.closure.local_dependencies {
        non_empty("closure.local_dependencies[].theorem", &edge.theorem)?;
        if !closure_set.contains(&edge.theorem) {
            return Err(ProofError::Invalid {
                message: format!(
                    "dependency source {} is outside closure.theorems",
                    edge.theorem
                ),
            });
        }
        if !dependency_sources.insert(edge.theorem.clone()) {
            return Err(ProofError::Invalid {
                message: format!("duplicate dependency edge for {}", edge.theorem),
            });
        }
        require_unique_non_empty("closure.local_dependencies[].depends_on", &edge.depends_on)?;
        for dependency in &edge.depends_on {
            if !closure_set.contains(dependency) {
                return Err(ProofError::Invalid {
                    message: format!(
                        "dependency {dependency} of {} is outside closure.theorems",
                        edge.theorem
                    ),
                });
            }
            if dependency == &edge.theorem {
                return Err(ProofError::Invalid {
                    message: format!("theorem {} depends on itself", edge.theorem),
                });
            }
        }
    }
    require_unique_non_empty(
        "closure.stdlib_allowlist",
        &manifest.closure.stdlib_allowlist,
    )?;

    for import_owner in &manifest.proof_files {
        for import in &import_owner.imports {
            if !import_is_allowed(manifest, import) {
                return Err(ProofError::Invalid {
                    message: format!(
                        "proof file {} imports {import}, which is neither in the closure nor the stdlib allowlist",
                        import_owner.id
                    ),
                });
            }
        }
    }

    if manifest.assumptions.len() > MAX_ASSUMPTIONS {
        return Err(ProofError::Invalid {
            message: format!(
                "assumptions has {} entries; limit is {MAX_ASSUMPTIONS}",
                manifest.assumptions.len()
            ),
        });
    }
    let mut assumption_ids = BTreeSet::new();
    let mut assumption_names = BTreeSet::new();
    for assumption in &manifest.assumptions {
        non_empty("assumptions[].id", &assumption.id)?;
        non_empty("assumptions[].name", &assumption.name)?;
        non_empty("assumptions[].justification", &assumption.justification)?;
        non_empty("assumptions[].scope", &assumption.scope)?;
        if !assumption_ids.insert(assumption.id.clone()) {
            return Err(ProofError::Invalid {
                message: format!("duplicate assumption id: {}", assumption.id),
            });
        }
        if !assumption_names.insert(assumption.name.clone()) {
            return Err(ProofError::Invalid {
                message: format!("duplicate assumption name: {}", assumption.name),
            });
        }
        if assumption.kind == AssumptionKind::Hypothesis {
            let Some(discharged_by) = assumption.discharged_by.as_deref() else {
                return Err(ProofError::Invalid {
                    message: format!(
                        "hypothesis {} must name the theorem that discharges it",
                        assumption.id
                    ),
                });
            };
            if !closure_set.contains(discharged_by) {
                return Err(ProofError::Invalid {
                    message: format!(
                        "hypothesis {} is discharged by {discharged_by}, which is outside closure.theorems",
                        assumption.id
                    ),
                });
            }
        }
    }

    validate_admission_record(manifest)?;

    if manifest.provenance.origin != manifest.admission.origin {
        return Err(ProofError::Invalid {
            message: "provenance.origin must match admission.origin".to_owned(),
        });
    }
    non_empty("provenance.run_id", &manifest.provenance.run_id)?;
    non_empty("provenance.detail", &manifest.provenance.detail)?;

    validate_implementation_binding(&manifest.implementation_binding)
}

fn validate_admission_record(manifest: &ProofManifest) -> Result<(), ProofError> {
    if manifest.admission.checker_kind != manifest.checker.kind {
        return Err(ProofError::CheckerMismatch {
            detail: format!(
                "admission checker kind {} differs from manifest checker kind {}",
                manifest.admission.checker_kind.as_str(),
                manifest.checker.kind.as_str()
            ),
        });
    }
    if manifest.admission.checker_version != manifest.checker.version {
        return Err(ProofError::CheckerMismatch {
            detail: format!(
                "admission checker version {} differs from manifest checker version {}",
                manifest.admission.checker_version, manifest.checker.version
            ),
        });
    }

    let mut digests = BTreeSet::new();
    for digest in &manifest.admission.proof_digests {
        non_empty("admission.proof_digests[].file_id", &digest.file_id)?;
        validate_sha256("admission.proof_digests[].sha256", &digest.sha256)?;
        if !digests.insert(digest.file_id.clone()) {
            return Err(ProofError::Invalid {
                message: format!("duplicate admission digest for {}", digest.file_id),
            });
        }
        let Some(file) = manifest
            .proof_files
            .iter()
            .find(|file| file.id == digest.file_id)
        else {
            return Err(ProofError::CheckerMismatch {
                detail: format!(
                    "admission records a digest for unknown proof file {}",
                    digest.file_id
                ),
            });
        };
        if file.sha256 != digest.sha256 {
            return Err(ProofError::CheckerMismatch {
                detail: format!(
                    "admission digest for {} does not match the manifest digest",
                    digest.file_id
                ),
            });
        }
    }
    if digests.len() != manifest.proof_files.len() {
        return Err(ProofError::CheckerMismatch {
            detail: "admission proof digests do not cover every proof file".to_owned(),
        });
    }

    let mut theorem_names = BTreeSet::new();
    for theorem in &manifest.admission.theorems {
        non_empty("admission.theorems[].name", &theorem.name)?;
        if !theorem_names.insert(theorem.name.clone()) {
            return Err(ProofError::Invalid {
                message: format!("duplicate admission theorem: {}", theorem.name),
            });
        }
    }
    if theorem_names.is_empty() {
        return Err(ProofError::Invalid {
            message: "admission.theorems must not be empty".to_owned(),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_implementation_binding(binding: &ImplementationBinding) -> Result<(), ProofError> {
    non_empty("implementation_binding.statement", &binding.statement)?;
    if let Some(inventory) = &binding.source_inventory {
        validate_relative_path(
            "implementation_binding.source_inventory.path",
            &inventory.path,
        )?;
        validate_sha256(
            "implementation_binding.source_inventory.sha256",
            &inventory.sha256,
        )?;
    }
    if binding.rust_symbols.is_empty() {
        return Err(ProofError::Invalid {
            message: "implementation_binding.rust_symbols must not be empty".to_owned(),
        });
    }
    if binding.rust_symbols.len() > MAX_SYMBOL_BINDINGS {
        return Err(ProofError::Invalid {
            message: format!(
                "rust_symbols has {} entries; limit is {MAX_SYMBOL_BINDINGS}",
                binding.rust_symbols.len()
            ),
        });
    }
    let mut symbols = BTreeSet::new();
    for symbol in &binding.rust_symbols {
        non_empty("rust_symbols[].symbol", &symbol.symbol)?;
        validate_relative_path("rust_symbols[].source_path", &symbol.source_path)?;
        validate_sha256("rust_symbols[].source_sha256", &symbol.source_sha256)?;
        if !symbols.insert(symbol.symbol.clone()) {
            return Err(ProofError::Invalid {
                message: format!("duplicate symbol binding: {}", symbol.symbol),
            });
        }
        match (symbol.kind, symbol.ffi.as_ref()) {
            (SymbolKind::FfiDeclaration, Some(ffi)) => {
                non_empty("ffi.declaration", &ffi.declaration)?;
                non_empty("ffi.wrapper_symbol", &ffi.wrapper_symbol)?;
                non_empty("ffi.wrapper_evidence", &ffi.wrapper_evidence)?;
            }
            (SymbolKind::FfiDeclaration, None) => {
                return Err(ProofError::Invalid {
                    message: format!(
                        "FFI declaration {} must carry a wrapper binding",
                        symbol.symbol
                    ),
                });
            }
            (_, Some(_)) => {
                return Err(ProofError::Invalid {
                    message: format!(
                        "symbol {} is not an FFI declaration but carries ffi metadata",
                        symbol.symbol
                    ),
                });
            }
            (_, None) => {}
        }
    }

    if binding.binding_evidence.len() > MAX_SYMBOL_BINDINGS {
        return Err(ProofError::Invalid {
            message: format!(
                "binding_evidence has {} entries; limit is {MAX_SYMBOL_BINDINGS}",
                binding.binding_evidence.len()
            ),
        });
    }
    let mut evidence_symbols = BTreeSet::new();
    for evidence in &binding.binding_evidence {
        non_empty("binding_evidence[].symbol", &evidence.symbol)?;
        validate_relative_path("binding_evidence[].path", &evidence.path)?;
        validate_sha256("binding_evidence[].sha256", &evidence.sha256)?;
        non_empty("binding_evidence[].detail", &evidence.detail)?;
        if !evidence_symbols.insert(evidence.symbol.clone()) {
            return Err(ProofError::Invalid {
                message: format!("duplicate binding evidence for {}", evidence.symbol),
            });
        }
    }

    if binding.transitions.is_empty() {
        return Err(ProofError::Invalid {
            message: "implementation_binding.transitions must not be empty".to_owned(),
        });
    }
    if binding.transitions.len() > MAX_TRANSITIONS {
        return Err(ProofError::Invalid {
            message: format!(
                "transitions has {} entries; limit is {MAX_TRANSITIONS}",
                binding.transitions.len()
            ),
        });
    }
    let mut transition_ids = BTreeSet::new();
    for transition in &binding.transitions {
        non_empty("transitions[].id", &transition.id)?;
        non_empty("transitions[].description", &transition.description)?;
        non_empty("transitions[].evidence", &transition.evidence)?;
        if !transition_ids.insert(transition.id.clone()) {
            return Err(ProofError::Invalid {
                message: format!("duplicate transition id: {}", transition.id),
            });
        }
    }
    require_unique_non_empty(
        "implementation_binding.required_transitions",
        &binding
            .required_transitions
            .iter()
            .map(|kind| kind.as_str().to_owned())
            .collect::<Vec<_>>(),
    )?;

    if binding.correspondence_evidence.len() > MAX_CORRESPONDENCE_EVIDENCE {
        return Err(ProofError::Invalid {
            message: format!(
                "correspondence_evidence has {} entries; limit is {MAX_CORRESPONDENCE_EVIDENCE}",
                binding.correspondence_evidence.len()
            ),
        });
    }
    let mut evidence_ids = BTreeSet::new();
    for evidence in &binding.correspondence_evidence {
        non_empty("correspondence_evidence[].id", &evidence.id)?;
        validate_relative_path("correspondence_evidence[].path", &evidence.path)?;
        validate_sha256("correspondence_evidence[].sha256", &evidence.sha256)?;
        non_empty("correspondence_evidence[].detail", &evidence.detail)?;
        if !evidence_ids.insert(evidence.id.clone()) {
            return Err(ProofError::Invalid {
                message: format!("duplicate correspondence evidence id: {}", evidence.id),
            });
        }
    }
    for transition in &binding.transitions {
        if !evidence_ids.contains(&transition.evidence) {
            return Err(ProofError::Invalid {
                message: format!(
                    "transition {} references unknown evidence {}",
                    transition.id, transition.evidence
                ),
            });
        }
    }
    for symbol in &binding.rust_symbols {
        if let Some(ffi) = &symbol.ffi {
            if !evidence_ids.contains(&ffi.wrapper_evidence) {
                return Err(ProofError::Invalid {
                    message: format!(
                        "FFI wrapper for {} references unknown evidence {}",
                        symbol.symbol, ffi.wrapper_evidence
                    ),
                });
            }
        }
    }
    Ok(())
}

fn import_is_allowed(manifest: &ProofManifest, import: &str) -> bool {
    let closure_ids: BTreeSet<&str> = manifest
        .proof_files
        .iter()
        .filter(|file| {
            manifest
                .closure
                .theorems
                .iter()
                .any(|theorem| file.theorems.contains(theorem))
        })
        .map(|file| file.id.as_str())
        .collect();
    if closure_ids.contains(import) {
        return true;
    }
    if manifest
        .closure
        .theorems
        .iter()
        .any(|theorem| theorem == import)
    {
        return true;
    }
    manifest
        .closure
        .stdlib_allowlist
        .iter()
        .any(|allowed| prefix_matches(allowed, import))
}

fn prefix_matches(allowed: &str, import: &str) -> bool {
    if let Some(prefix) = allowed.strip_suffix('*') {
        import.starts_with(prefix)
    } else {
        allowed == import
    }
}

fn require_exact(field: &str, actual: &str, expected: &str) -> Result<(), ProofError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ProofError::Invalid {
            message: format!("{field} must be {expected}, got {actual}"),
        })
    }
}

fn non_empty(field: &str, value: &str) -> Result<(), ProofError> {
    if value.trim().is_empty() {
        Err(ProofError::Invalid {
            message: format!("{field} must not be empty"),
        })
    } else {
        Ok(())
    }
}

fn require_unique_non_empty(field: &str, values: &[String]) -> Result<(), ProofError> {
    if values.is_empty() {
        return Err(ProofError::Invalid {
            message: format!("{field} must not be empty"),
        });
    }
    let mut seen = BTreeSet::new();
    for value in values {
        non_empty(field, value)?;
        if !seen.insert(value) {
            return Err(ProofError::Invalid {
                message: format!("{field} contains duplicate value {value}"),
            });
        }
    }
    Ok(())
}

fn validate_sha256(field: &str, value: &str) -> Result<(), ProofError> {
    let valid = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(ProofError::Invalid {
            message: format!("{field} must be 64 lower-case hexadecimal characters"),
        })
    }
}

fn validate_relative_path(field: &str, value: &str) -> Result<(), ProofError> {
    if value.trim().is_empty() {
        return Err(ProofError::Invalid {
            message: format!("{field} must not be empty"),
        });
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return Err(ProofError::PathEscape {
            path: value.to_owned(),
        });
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(ProofError::PathEscape {
                path: value.to_owned(),
            });
        }
    }
    Ok(())
}

fn resolve_relative(base: &Path, relative: &str) -> Result<PathBuf, ProofError> {
    validate_relative_path("path", relative)?;
    Ok(base.join(relative))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, ProofError> {
    let metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ProofError::MissingFile {
                path: path.display().to_string(),
            }
        } else {
            ProofError::Io {
                path: path.display().to_string(),
                message: error.to_string(),
            }
        }
    })?;
    if !metadata.is_file() {
        return Err(ProofError::MissingFile {
            path: path.display().to_string(),
        });
    }
    let length = usize::try_from(metadata.len()).map_err(|_| ProofError::Invalid {
        message: format!("file is too large: {}", path.display()),
    })?;
    if length > MAX_FILE_BYTES {
        return Err(ProofError::Invalid {
            message: format!(
                "file {} is {length} bytes; limit is {MAX_FILE_BYTES}",
                path.display()
            ),
        });
    }
    fs::read(path).map_err(|error| ProofError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

fn read_digest_bound(base: &Path, relative: &str, expected: &str) -> Result<Vec<u8>, ProofError> {
    let path = resolve_relative(base, relative)?;
    let bytes = read_bounded(&path)?;
    let actual = sha256_hex(&bytes);
    if actual != expected {
        return Err(ProofError::DigestMismatch {
            path: path.display().to_string(),
            expected: expected.to_owned(),
            actual,
        });
    }
    Ok(bytes)
}

impl ProofManifest {
    /// Encode this manifest as strict `ms-canonical-json-v1` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::Canonical`] if the manifest cannot be represented.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProofError> {
        let value = serde_json::to_value(self).map_err(|error| ProofError::Canonical {
            message: error.to_string(),
        })?;
        canonical_bytes(&value).map_err(|error| ProofError::Canonical {
            message: error.to_string(),
        })
    }
}

/// Evaluate the recorded theorem and assumption closure.
///
/// This function verifies every listed proof-file digest and lexically scans
/// only the proof files in the reachable dependency closure. An admission in an
/// unrelated proof file is deliberately not attributed to the requested
/// theorem.
///
/// The returned [`AdmissionReport::outcome`] classifies the *recorded* checker
/// result. A live adapter still has to establish that a checker actually ran;
/// see [`verify_manifest_bytes`].
///
/// # Errors
///
/// Returns [`ProofError`] for structural invalidity, missing or tampered proof
/// files, or checker/digest mismatch.
#[allow(clippy::too_many_lines)]
pub fn evaluate_admission(
    manifest: &ProofManifest,
    base_dir: &Path,
) -> Result<AdmissionReport, ProofError> {
    validate_manifest(manifest)?;

    let mut contents = BTreeMap::new();
    let mut scanned_files = Vec::new();
    for file in &manifest.proof_files {
        let bytes = read_digest_bound(base_dir, &file.path, &file.sha256)?;
        let text = String::from_utf8(bytes).map_err(|error| ProofError::Invalid {
            message: format!("proof file {} is not UTF-8: {error}", file.path),
        })?;
        contents.insert(file.id.clone(), text);
        scanned_files.push(ScannedFile {
            id: file.id.clone(),
            path: file.path.clone(),
            sha256: file.sha256.clone(),
        });
    }

    let closure_set: BTreeSet<String> = manifest.closure.theorems.iter().cloned().collect();
    let reachable = reachable_theorems(manifest);

    let scanned_ids: BTreeSet<String> = manifest
        .proof_files
        .iter()
        .filter(|file| {
            file.theorems
                .iter()
                .any(|theorem| reachable.contains(theorem))
        })
        .map(|file| file.id.clone())
        .collect();

    let mut forbidden_findings = Vec::new();
    for file in &manifest.proof_files {
        if !scanned_ids.contains(&file.id) {
            continue;
        }
        let Some(text) = contents.get(&file.id) else {
            continue;
        };
        for (position, token) in forbidden_tokens(text) {
            let declared_name = if matches!(token, "Axiom" | "axiom" | "Parameter" | "Conjecture") {
                declaration_name_after(text, position + token.len())
            } else {
                None
            };
            let declared_in_manifest = declared_name.as_ref().is_some_and(|name| {
                manifest
                    .assumptions
                    .iter()
                    .any(|assumption| &assumption.name == name)
            });
            let detail = if declared_in_manifest {
                format!(
                    "declared assumption {token} is still an unproved admission and is not discharged"
                )
            } else {
                format!("{token} is an unchecked or undeclared admission in the theorem closure")
            };
            forbidden_findings.push(ForbiddenFinding {
                file_id: file.id.clone(),
                path: file.path.clone(),
                line: line_for(text, position),
                token: token.to_owned(),
                declared_name,
                declared_in_manifest,
                detail,
            });
        }
    }

    let mut assumptions = Vec::new();
    for assumption in &manifest.assumptions {
        let (status, detail) = match assumption.kind {
            AssumptionKind::Hypothesis => (
                AssumptionStatus::AllowedHypothesis,
                format!(
                    "discharged by theorem {}",
                    assumption.discharged_by.as_deref().unwrap_or("-")
                ),
            ),
            AssumptionKind::Axiom => (
                AssumptionStatus::Rejected,
                "declared axiom is an unproved global assumption".to_owned(),
            ),
            AssumptionKind::Parameter => (
                AssumptionStatus::Rejected,
                "declared parameter is an unproved global assumption".to_owned(),
            ),
            AssumptionKind::Conjecture => (
                AssumptionStatus::Rejected,
                "declared conjecture is not a proved theorem".to_owned(),
            ),
        };
        assumptions.push(AssumptionReport {
            id: assumption.id.clone(),
            name: assumption.name.clone(),
            kind: assumption.kind,
            status,
            detail,
        });
    }
    assumptions.sort_by(|left, right| left.id.cmp(&right.id));

    let mut admission_theorems = manifest.admission.theorems.clone();
    admission_theorems.sort_by(|left, right| left.name.cmp(&right.name));

    let mut outcome = ProofOutcome::AcceptedWithinScope;
    let mut reasons = Vec::new();

    if reachable != closure_set {
        raise(&mut outcome, ProofOutcome::RejectedUnrelated);
        reasons.push(
            "declared closure.theorems does not equal the dependency closure reachable from theorem.name"
                .to_owned(),
        );
    }
    if !manifest
        .theorem
        .claim_ids
        .iter()
        .all(|claim| manifest.scope.claim_ids.contains(claim))
    {
        raise(&mut outcome, ProofOutcome::RejectedUnrelated);
        reasons.push("theorem.claim_ids is outside scope.claim_ids".to_owned());
    }
    if !forbidden_findings.is_empty() {
        raise(&mut outcome, ProofOutcome::RejectedAssumption);
        reasons.push(format!(
            "{} forbidden admission construct(s) found in the theorem closure",
            forbidden_findings.len()
        ));
    }
    if assumptions
        .iter()
        .any(|assumption| assumption.status == AssumptionStatus::Rejected)
    {
        raise(&mut outcome, ProofOutcome::RejectedAssumption);
        reasons.push("a declared assumption is not a discharged hypothesis".to_owned());
    }

    let admitted_names: BTreeSet<&str> = admission_theorems
        .iter()
        .map(|theorem| theorem.name.as_str())
        .collect();
    if let Some(extra) = admitted_names
        .iter()
        .find(|name| !closure_set.contains(**name))
    {
        raise(&mut outcome, ProofOutcome::RejectedUnrelated);
        reasons.push(format!(
            "admission includes theorem {extra} outside the declared closure"
        ));
    }
    if !admitted_names.contains(manifest.theorem.name.as_str()) {
        raise(&mut outcome, ProofOutcome::RejectedUnrelated);
        reasons.push("admission does not include theorem.name".to_owned());
    }
    for theorem in &closure_set {
        if !admitted_names.contains(theorem.as_str()) {
            raise(&mut outcome, ProofOutcome::CheckerFailed);
            reasons.push(format!("closure theorem {theorem} has no admission status"));
        }
    }
    for theorem in &admission_theorems {
        if theorem.status.is_unproved() {
            raise(&mut outcome, ProofOutcome::RejectedAssumption);
            reasons.push(format!(
                "theorem {} has unchecked status {}",
                theorem.name,
                theorem.status.as_str()
            ));
        } else if matches!(
            theorem.status,
            AdmissionStatus::Unchecked | AdmissionStatus::Failed
        ) {
            raise(&mut outcome, ProofOutcome::CheckerFailed);
            reasons.push(format!(
                "theorem {} has status {}",
                theorem.name,
                theorem.status.as_str()
            ));
        }
    }
    if !manifest.admission.origin.is_authentic() {
        raise(&mut outcome, ProofOutcome::CheckerUnavailable);
        reasons.push(
            "recorded provenance is substituted or modeled, not an authentic checker run"
                .to_owned(),
        );
    }
    if manifest.admission.exit_code != 0 {
        raise(&mut outcome, ProofOutcome::CheckerFailed);
        reasons.push(format!(
            "recorded checker exited with status {}",
            manifest.admission.exit_code
        ));
    }

    let detail = if reasons.is_empty() {
        "recorded authentic checker run covers the declared theorem and assumption closure"
            .to_owned()
    } else {
        reasons.join("; ")
    };

    scanned_files.sort_by(|left, right| left.id.cmp(&right.id));
    let mut reachable_theorems: Vec<String> = reachable.into_iter().collect();
    reachable_theorems.sort();

    Ok(AdmissionReport {
        outcome,
        theorem: manifest.theorem.name.clone(),
        scope_claim_ids: manifest.scope.claim_ids.clone(),
        theorem_claim_ids: manifest.theorem.claim_ids.clone(),
        reachable_theorems,
        scanned_files,
        assumptions,
        forbidden_findings,
        admission_theorems,
        origin: manifest.admission.origin,
        exit_code: manifest.admission.exit_code,
        recorded_classification: manifest.admission.classification,
        detail,
    })
}

fn reachable_theorems(manifest: &ProofManifest) -> BTreeSet<String> {
    let mut graph: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in &manifest.closure.local_dependencies {
        graph
            .entry(edge.theorem.as_str())
            .or_default()
            .extend(edge.depends_on.iter().map(String::as_str));
    }
    let mut reachable = BTreeSet::new();
    let mut stack = vec![manifest.theorem.name.as_str()];
    while let Some(theorem) = stack.pop() {
        if !reachable.insert(theorem.to_owned()) {
            continue;
        }
        if let Some(dependencies) = graph.get(theorem) {
            stack.extend(dependencies.iter().copied());
        }
    }
    reachable
}

fn raise(outcome: &mut ProofOutcome, candidate: ProofOutcome) {
    if outcome_priority(candidate) > outcome_priority(*outcome) {
        *outcome = candidate;
    }
}

const fn outcome_priority(outcome: ProofOutcome) -> u8 {
    match outcome {
        ProofOutcome::AcceptedWithinScope => 0,
        ProofOutcome::CheckerUnavailable => 1,
        ProofOutcome::CheckerFailed => 2,
        ProofOutcome::RejectedUnrelated => 3,
        ProofOutcome::RejectedMissingTransition => 4,
        ProofOutcome::RejectedUncheckedImplementation => 5,
        ProofOutcome::RejectedAssumption => 6,
    }
}

fn forbidden_tokens(text: &str) -> Vec<(usize, &'static str)> {
    let mut hits = BTreeSet::new();
    for token in FORBIDDEN_ADMISSION_TOKENS {
        for (position, _) in text.match_indices(token) {
            let before = text[..position].chars().next_back();
            let after = text[position + token.len()..].chars().next();
            if before.is_some_and(is_identifier_character)
                || after.is_some_and(is_identifier_character)
            {
                continue;
            }
            hits.insert((position, token));
        }
    }
    hits.into_iter().collect()
}

fn is_identifier_character(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '\'')
}

fn declaration_name_after(text: &str, end: usize) -> Option<String> {
    let name: String = text[end..]
        .trim_start()
        .chars()
        .take_while(|character| character.is_alphanumeric() || matches!(character, '_' | '\''))
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn line_for(text: &str, position: usize) -> usize {
    text[..position]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

/// One symbol checked by the correspondence gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolReport {
    /// Exact symbol name.
    pub symbol: String,
    /// Symbol kind.
    pub kind: SymbolKind,
    /// Gate status for this symbol.
    pub status: GateStatus,
    /// Source path relative to the manifest directory.
    pub source_path: String,
    /// Lower-case SHA-256 of the exact source bytes.
    pub source_sha256: String,
    /// Binding detail.
    pub detail: String,
}

/// Separate Rust/FFI implementation-correspondence report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrespondenceReport {
    /// Gate status.
    pub status: GateStatus,
    /// Decisive rejection, or `None` when the gate passes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<ProofOutcome>,
    /// Exact theorem-to-code correspondence statement.
    pub statement: String,
    /// Optional Phase 3.1 source inventory binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_inventory: Option<ScannedFile>,
    /// Symbol bindings and their status.
    pub symbols: Vec<SymbolReport>,
    /// Transition enumeration retained from the manifest.
    pub transitions: Vec<Transition>,
    /// Required transition kinds, including the mandatory reentrant callback.
    pub required_transitions: Vec<TransitionKind>,
    /// Required transitions that were not enumerated.
    pub missing_transitions: Vec<TransitionKind>,
    /// FFI wrappers that are not separately checked.
    pub unchecked_wrappers: Vec<String>,
    /// Digest-bound correspondence evidence.
    pub evidence: Vec<ScannedFile>,
    /// Human-readable summary.
    pub detail: String,
}

impl CorrespondenceReport {
    /// Encode this report as strict `ms-canonical-json-v1` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::Canonical`] if the report cannot be represented.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProofError> {
        let value = serde_json::to_value(self).map_err(|error| ProofError::Canonical {
            message: error.to_string(),
        })?;
        canonical_bytes(&value).map_err(|error| ProofError::Canonical {
            message: error.to_string(),
        })
    }
}

/// Evidence basis for an acceptance outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceBasis {
    /// No acceptance basis is available.
    None,
    /// A recorded authentic checker run supplied by a live adapter.
    RecordedAuthenticCheckerRun,
}

/// One recorded checker run supplied by an external adapter.
///
/// The CLI constructs this only from a completed live invocation. Manifest
/// verification then re-checks the recorded digests, version, executable
/// identity, and theorem statuses independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckerRun {
    /// Checker family.
    pub kind: CheckerKind,
    /// Exact checker version.
    pub version: String,
    /// Checker process exit code.
    pub exit_code: i32,
    /// Digests the checker actually consumed.
    pub proof_digests: Vec<ProofDigest>,
    /// Theorem statuses the checker actually reported.
    pub theorems: Vec<AdmissionTheorem>,
}

/// Whether a live checker is configured for this verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckerContext {
    /// No live checker is configured. The parser cannot accept a proof.
    NotConfigured,
    /// A live adapter supplied a recorded checker run.
    Recorded(CheckerRun),
}

/// Runtime availability of a proof checker.
///
/// Availability is an installation observation, not a proof or soundness
/// claim. A checker may be available and still fail, reject the manifest, or
/// disagree with the recorded theorem statuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckerAvailability {
    /// Stable checker identifier used by the capabilities output.
    pub id: &'static str,
    /// Checker family.
    pub kind: CheckerKind,
    /// `available` or `not_run`.
    pub status: &'static str,
    /// Exact executable name declared for this checker family.
    pub executable: &'static str,
    /// Probed exact version, when available.
    pub version: Option<String>,
    /// Exact version text or the precise unavailability reason.
    pub detail: String,
}

/// Receipt for one live checker invocation.
///
/// The receipt records the exact argv vectors, executable digest, captured
/// stdout/stderr (bounded), their digests, the checker-reported theorem
/// statuses, and the proof-file digests. Digests bind these bounded bytes;
/// they are not signatures or attestations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveCheckerReceipt {
    /// Checker family that was invoked.
    pub checker_kind: CheckerKind,
    /// Exact probed checker version.
    pub checker_version: String,
    /// Resolved executable path.
    pub executable: String,
    /// Lower-case SHA-256 of the resolved executable bytes.
    pub executable_sha256: String,
    /// Every explicit argv vector executed, including assumption checks.
    pub argv: Vec<Vec<String>>,
    /// Overall process exit code (0 only for a completed run).
    pub exit_code: i32,
    /// Lower-case SHA-256 of the captured stdout text.
    pub stdout_sha256: String,
    /// Lower-case SHA-256 of the captured stderr text.
    pub stderr_sha256: String,
    /// Bounded captured stdout text.
    pub stdout: String,
    /// Bounded captured stderr text.
    pub stderr: String,
    /// Proof-file digests consumed by this run.
    pub proof_digests: Vec<ProofDigest>,
    /// Checker-reported theorem statuses from `Print Assumptions`.
    pub theorems: Vec<AdmissionTheorem>,
}

/// Outcome of one live checker attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveCheckerOutcome {
    /// The executable or its version probe could not be made available.
    Unavailable {
        /// Exact unavailability reason.
        detail: String,
    },
    /// The checker ran but the manifest, version, executable identity, or
    /// compile did not match; the receipt retains the captured evidence.
    Failed {
        /// Exact failure reason.
        detail: String,
        /// Captured run evidence.
        receipt: LiveCheckerReceipt,
    },
    /// The checker compiled every proof file and completed its assumption
    /// checks. Theorem statuses may still be unproved; the admission gate
    /// never trusts this outcome alone.
    Completed {
        /// Recorded checker run ready to bind through `CheckerContext::Recorded`.
        run: CheckerRun,
        /// Captured run evidence.
        receipt: LiveCheckerReceipt,
    },
}

/// Complete proof verification report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofReport {
    /// Report schema.
    pub schema: String,
    /// Specification identifier.
    pub spec: String,
    /// Claim ceiling embedded in the report.
    pub claim_ceiling: String,
    /// SHA-256 of the exact manifest bytes.
    pub manifest_sha256: String,
    /// Exact checker identity.
    pub checker: CheckerIdentity,
    /// Requested theorem.
    pub theorem: TheoremBinding,
    /// Declared finite scope.
    pub scope: TheoremScope,
    /// Recomputed outcome.
    pub outcome: ProofOutcome,
    /// Admission and closure report.
    pub admission: AdmissionReport,
    /// Separate implementation-correspondence report.
    pub correspondence: CorrespondenceReport,
    /// Manifest provenance.
    pub provenance: Provenance,
    /// Whether a checker run was supplied by an adapter.
    pub live_checker_configured: bool,
    /// Whether this build invoked a checker.
    pub live_checker_invoked: bool,
    /// Captured live checker evidence, when `--live` invoked one.
    pub live_run: Option<LiveCheckerReceipt>,
    /// Evidence basis for the outcome.
    pub acceptance_basis: AcceptanceBasis,
    /// Decisive outcome detail.
    pub outcome_detail: String,
    /// Universal soundness is always withheld here.
    pub universal_soundness: String,
}

impl ProofReport {
    /// Encode this report as strict `ms-canonical-json-v1` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::Canonical`] if the report cannot be represented.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProofError> {
        let value = serde_json::to_value(self).map_err(|error| ProofError::Canonical {
            message: error.to_string(),
        })?;
        canonical_bytes(&value).map_err(|error| ProofError::Canonical {
            message: error.to_string(),
        })
    }
}

/// Evaluate the separate Rust/FFI implementation-correspondence gate.
///
/// This gate does not depend on theorem acceptance. It verifies every symbol
/// binding against a Phase 3.1 source inventory or explicit digest-bound
/// binding evidence, requires a checked wrapper for every FFI declaration, and
/// requires an enumerated reentrant-callback transition in addition to the
/// declared transition set.
///
/// # Errors
///
/// Returns [`ProofError`] for structural invalidity, missing or tampered
/// source, inventory, or correspondence-evidence files.
#[allow(clippy::too_many_lines)]
pub fn evaluate_correspondence(
    manifest: &ProofManifest,
    base_dir: &Path,
) -> Result<CorrespondenceReport, ProofError> {
    validate_manifest(manifest)?;
    let binding = &manifest.implementation_binding;

    let mut inventory_report = None;
    let mut inventory_paths: BTreeMap<String, String> = BTreeMap::new();
    let mut inventory_findings: Vec<(String, FindingKind, String)> = Vec::new();
    let has_inventory = binding.source_inventory.is_some();
    if let Some(inventory_ref) = &binding.source_inventory {
        let bytes = read_digest_bound(base_dir, &inventory_ref.path, &inventory_ref.sha256)?;
        let value = parse_strict(&bytes)?;
        let inventory: SourceInventory =
            serde_json::from_value(value).map_err(|error| ProofError::Invalid {
                message: format!("invalid source inventory: {error}"),
            })?;
        if inventory.schema != SOURCE_INVENTORY_SCHEMA {
            return Err(ProofError::Invalid {
                message: format!(
                    "source inventory schema must be {SOURCE_INVENTORY_SCHEMA}, got {}",
                    inventory.schema
                ),
            });
        }
        for file in &inventory.files {
            inventory_paths.insert(file.path.clone(), file.sha256.clone());
        }
        for finding in &inventory.findings {
            inventory_findings.push((finding.path.clone(), finding.kind, finding.target.clone()));
        }
        inventory_report = Some(ScannedFile {
            id: "source-inventory".to_owned(),
            path: inventory_ref.path.clone(),
            sha256: inventory_ref.sha256.clone(),
        });
    }

    let mut evidence_reports = Vec::new();
    let mut evidence_text: BTreeMap<String, String> = BTreeMap::new();
    for evidence in &binding.correspondence_evidence {
        let bytes = read_digest_bound(base_dir, &evidence.path, &evidence.sha256)?;
        let text = String::from_utf8(bytes).map_err(|error| ProofError::Invalid {
            message: format!(
                "correspondence evidence {} is not UTF-8: {error}",
                evidence.path
            ),
        })?;
        evidence_text.insert(evidence.id.clone(), text);
        evidence_reports.push(ScannedFile {
            id: evidence.id.clone(),
            path: evidence.path.clone(),
            sha256: evidence.sha256.clone(),
        });
    }

    let mut source_cache: BTreeMap<String, String> = BTreeMap::new();
    let mut symbols = Vec::new();
    let mut unchecked_wrappers = Vec::new();

    for symbol in &binding.rust_symbols {
        if !source_cache.contains_key(&symbol.source_path) {
            let bytes = read_digest_bound(base_dir, &symbol.source_path, &symbol.source_sha256)?;
            let text = String::from_utf8(bytes).map_err(|error| ProofError::Invalid {
                message: format!("source {} is not UTF-8: {error}", symbol.source_path),
            })?;
            source_cache.insert(symbol.source_path.clone(), text);
        }
        let Some(source_text) = source_cache.get(&symbol.source_path) else {
            continue;
        };

        let mut failures = Vec::new();
        if !symbol_present(source_text, &symbol.symbol) {
            failures.push(format!(
                "symbol {} does not occur in {}",
                symbol.symbol, symbol.source_path
            ));
        }

        if has_inventory {
            match inventory_paths.get(&symbol.source_path) {
                Some(sha256) if sha256 == &symbol.source_sha256 => {}
                Some(_) => failures.push(format!(
                    "source digest for {} does not match the source inventory",
                    symbol.source_path
                )),
                None => failures.push(format!(
                    "{} is not present in the source inventory",
                    symbol.source_path
                )),
            }
            if symbol.kind == SymbolKind::FfiDeclaration {
                let found = inventory_findings.iter().any(|(path, kind, target)| {
                    path == &symbol.source_path
                        && is_ffi_finding(*kind)
                        && finding_target_matches(target, &symbol.symbol)
                });
                if !found {
                    failures.push(format!(
                        "source inventory has no FFI declaration finding for {}",
                        symbol.symbol
                    ));
                }
            }
        } else {
            let evidence = binding
                .binding_evidence
                .iter()
                .find(|evidence| evidence.symbol == symbol.symbol);
            match evidence {
                Some(evidence)
                    if evidence.path == symbol.source_path
                        && evidence.sha256 == symbol.source_sha256 =>
                {
                    let bytes = read_digest_bound(base_dir, &evidence.path, &evidence.sha256)?;
                    let text = String::from_utf8(bytes).map_err(|error| ProofError::Invalid {
                        message: format!(
                            "binding evidence {} is not UTF-8: {error}",
                            evidence.path
                        ),
                    })?;
                    if !symbol_present(&text, &symbol.symbol) {
                        failures.push(format!(
                            "binding evidence for {} does not contain the symbol",
                            symbol.symbol
                        ));
                    }
                }
                Some(_) => failures.push(format!(
                    "binding evidence for {} has the wrong path or digest",
                    symbol.symbol
                )),
                None => failures.push(format!(
                    "no explicit binding evidence for {}",
                    symbol.symbol
                )),
            }
        }

        if symbol.kind == SymbolKind::FfiDeclaration {
            if let Some(ffi) = &symbol.ffi {
                let wrapper_evidence = evidence_text.get(&ffi.wrapper_evidence);
                let wrapper_present = symbol_present(source_text, &ffi.wrapper_symbol)
                    || wrapper_evidence
                        .is_some_and(|text| symbol_present(text, &ffi.wrapper_symbol));
                if !ffi.wrapper_checked {
                    failures.push(format!(
                        "FFI wrapper {} for {} is not checked",
                        ffi.wrapper_symbol, symbol.symbol
                    ));
                    unchecked_wrappers.push(symbol.symbol.clone());
                } else if !wrapper_present {
                    failures.push(format!(
                        "FFI wrapper {} for {} is not bound by the source or wrapper evidence",
                        ffi.wrapper_symbol, symbol.symbol
                    ));
                    unchecked_wrappers.push(symbol.symbol.clone());
                }
            }
        }

        symbols.push(SymbolReport {
            symbol: symbol.symbol.clone(),
            kind: symbol.kind,
            status: if failures.is_empty() {
                GateStatus::Pass
            } else {
                GateStatus::Fail
            },
            source_path: symbol.source_path.clone(),
            source_sha256: symbol.source_sha256.clone(),
            detail: if failures.is_empty() {
                "symbol and source digest are bound; any FFI wrapper is separately checked"
                    .to_owned()
            } else {
                failures.join("; ")
            },
        });
    }

    let mut required: BTreeSet<TransitionKind> =
        binding.required_transitions.iter().copied().collect();
    required.insert(REQUIRED_REENTRANT_TRANSITION);
    let present: BTreeSet<TransitionKind> = binding
        .transitions
        .iter()
        .map(|transition| transition.kind)
        .collect();
    let missing_transitions: Vec<TransitionKind> = required.difference(&present).copied().collect();

    unchecked_wrappers.sort();
    unchecked_wrappers.dedup();
    symbols.sort_by(|left, right| left.symbol.cmp(&right.symbol));
    evidence_reports.sort_by(|left, right| left.id.cmp(&right.id));
    let mut transitions = binding.transitions.clone();
    transitions.sort_by(|left, right| left.id.cmp(&right.id));

    let symbol_failures: Vec<String> = symbols
        .iter()
        .filter(|symbol| symbol.status == GateStatus::Fail)
        .map(|symbol| symbol.symbol.clone())
        .collect();
    let outcome = if !unchecked_wrappers.is_empty() || !symbol_failures.is_empty() {
        Some(ProofOutcome::RejectedUncheckedImplementation)
    } else if !missing_transitions.is_empty() {
        Some(ProofOutcome::RejectedMissingTransition)
    } else {
        None
    };
    let detail = match outcome {
        Some(ProofOutcome::RejectedUncheckedImplementation) if !unchecked_wrappers.is_empty() => {
            format!(
                "separate implementation correspondence rejects unchecked FFI wrapper(s): {}",
                unchecked_wrappers.join(", ")
            )
        }
        Some(ProofOutcome::RejectedUncheckedImplementation) => format!(
            "separate implementation correspondence rejects unbound symbol(s): {}",
            symbol_failures.join(", ")
        ),
        Some(ProofOutcome::RejectedMissingTransition) => format!(
            "implementation binding omits required transition(s): {}",
            missing_transitions
                .iter()
                .map(|kind| kind.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        _ => "separate implementation correspondence covers every declared symbol, checked FFI wrapper, and required transition".to_owned(),
    };

    Ok(CorrespondenceReport {
        status: if outcome.is_some() {
            GateStatus::Fail
        } else {
            GateStatus::Pass
        },
        outcome,
        statement: binding.statement.clone(),
        source_inventory: inventory_report,
        symbols,
        transitions,
        required_transitions: required.into_iter().collect(),
        missing_transitions,
        unchecked_wrappers,
        evidence: evidence_reports,
        detail,
    })
}

fn is_ffi_finding(kind: FindingKind) -> bool {
    matches!(
        kind,
        FindingKind::FfiDeclaration
            | FindingKind::ExternBlock
            | FindingKind::ExternFn
            | FindingKind::NoMangle
            | FindingKind::ExportName
    )
}

fn finding_target_matches(target: &str, symbol: &str) -> bool {
    target == symbol
        || target.ends_with(&format!("::{symbol}"))
        || target.ends_with(&format!(".{symbol}"))
}

fn symbol_present(text: &str, symbol: &str) -> bool {
    text.match_indices(symbol).any(|(position, _)| {
        let before = text[..position].chars().next_back();
        let after = text[position + symbol.len()..].chars().next();
        !before.is_some_and(is_identifier_character) && !after.is_some_and(is_identifier_character)
    })
}

/// Parse, verify, and classify a proof manifest.
///
/// The admission and correspondence gates are always evaluated separately. A
/// well-formed manifest is still `checker_unavailable` unless a live adapter
/// supplies a recorded checker run through [`CheckerContext::Recorded`].
///
/// # Errors
///
/// Returns [`ProofError`] for structural invalidity, missing or tampered files,
/// or checker/digest mismatch.
pub fn verify_manifest_bytes(
    bytes: &[u8],
    base_dir: &Path,
    checker: &CheckerContext,
) -> Result<ProofReport, ProofError> {
    verify_manifest_bytes_inner(bytes, base_dir, checker, false, None)
}

fn verify_manifest_bytes_inner(
    bytes: &[u8],
    base_dir: &Path,
    checker: &CheckerContext,
    live_checker_invoked: bool,
    live_run: Option<LiveCheckerReceipt>,
) -> Result<ProofReport, ProofError> {
    let manifest = parse_manifest(bytes)?;
    let admission = evaluate_admission(&manifest, base_dir)?;
    let correspondence = evaluate_correspondence(&manifest, base_dir)?;
    let (outcome, acceptance_basis, outcome_detail) =
        combine_outcome(&manifest, &admission, &correspondence, checker);

    Ok(ProofReport {
        schema: PROOF_REPORT_SCHEMA.to_owned(),
        spec: PROOF_SPEC.to_owned(),
        claim_ceiling: PROOF_CLAIM_CEILING.to_owned(),
        manifest_sha256: sha256_hex(bytes),
        checker: manifest.checker.clone(),
        theorem: manifest.theorem.clone(),
        scope: manifest.scope.clone(),
        outcome,
        admission,
        correspondence,
        provenance: manifest.provenance.clone(),
        live_checker_configured: matches!(checker, CheckerContext::Recorded(_)),
        live_checker_invoked,
        live_run,
        acceptance_basis,
        outcome_detail,
        universal_soundness: UNIVERSAL_SOUNDNESS.to_owned(),
    })
}

/// Parse, verify, and classify a manifest while invoking a live checker.
///
/// The checker is resolved from the manifest's exact executable name on a
/// fixed search path, its version and executable identity are node-locked to
/// the manifest, and every proof file is compiled in declared order in a
/// private `0700` directory with a cleared environment. A checkout whose
/// checker is missing returns `checker_unavailable` (exit 6). A checker that
/// runs but fails, times out, exceeds the output bound, or disagrees with the
/// manifest returns `checker_failed` (exit 4). Admission and correspondence
/// rejections keep their more specific outcomes.
///
/// # Errors
///
/// Returns [`ProofError`] for structural invalidity, missing or tampered files,
/// or checker/digest mismatch.
pub fn verify_manifest_bytes_live(
    bytes: &[u8],
    base_dir: &Path,
) -> Result<ProofReport, ProofError> {
    let manifest = parse_manifest(bytes)?;
    match run_live_checker(&manifest, base_dir)? {
        LiveCheckerOutcome::Unavailable { detail } => {
            let mut report = verify_manifest_bytes_inner(
                bytes,
                base_dir,
                &CheckerContext::NotConfigured,
                false,
                None,
            )?;
            if report.outcome == ProofOutcome::CheckerUnavailable {
                report.outcome_detail = detail;
            }
            Ok(report)
        }
        LiveCheckerOutcome::Failed { detail, receipt } => {
            let mut report = verify_manifest_bytes_inner(
                bytes,
                base_dir,
                &CheckerContext::NotConfigured,
                true,
                Some(receipt),
            )?;
            if matches!(
                report.outcome,
                ProofOutcome::CheckerUnavailable | ProofOutcome::AcceptedWithinScope
            ) {
                report.outcome = ProofOutcome::CheckerFailed;
                report.acceptance_basis = AcceptanceBasis::None;
                report.outcome_detail = detail;
            }
            Ok(report)
        }
        LiveCheckerOutcome::Completed { run, receipt } => verify_manifest_bytes_inner(
            bytes,
            base_dir,
            &CheckerContext::Recorded(run),
            true,
            Some(receipt),
        ),
    }
}

fn combine_outcome(
    manifest: &ProofManifest,
    admission: &AdmissionReport,
    correspondence: &CorrespondenceReport,
    checker: &CheckerContext,
) -> (ProofOutcome, AcceptanceBasis, String) {
    match admission.outcome {
        ProofOutcome::RejectedAssumption => {
            return (
                ProofOutcome::RejectedAssumption,
                AcceptanceBasis::None,
                admission.detail.clone(),
            );
        }
        ProofOutcome::RejectedUnrelated => {
            return (
                ProofOutcome::RejectedUnrelated,
                AcceptanceBasis::None,
                admission.detail.clone(),
            );
        }
        _ => {}
    }

    if let Some(outcome) = correspondence.outcome {
        return (
            outcome,
            AcceptanceBasis::None,
            correspondence.detail.clone(),
        );
    }

    match admission.outcome {
        ProofOutcome::CheckerFailed => {
            return (
                ProofOutcome::CheckerFailed,
                AcceptanceBasis::None,
                admission.detail.clone(),
            );
        }
        ProofOutcome::CheckerUnavailable => {
            return (
                ProofOutcome::CheckerUnavailable,
                AcceptanceBasis::None,
                admission.detail.clone(),
            );
        }
        ProofOutcome::AcceptedWithinScope => {}
        other => return (other, AcceptanceBasis::None, admission.detail.clone()),
    }

    match checker {
        CheckerContext::NotConfigured => (
            ProofOutcome::CheckerUnavailable,
            AcceptanceBasis::None,
            "no live proof checker is configured; manifest parser success is not proof acceptance"
                .to_owned(),
        ),
        CheckerContext::Recorded(run) => match verify_checker_run(manifest, admission, run) {
            Ok(()) => (
                ProofOutcome::AcceptedWithinScope,
                AcceptanceBasis::RecordedAuthenticCheckerRun,
                "recorded authentic checker run matches the manifest and covers the declared closure"
                    .to_owned(),
            ),
            Err(detail) => (ProofOutcome::CheckerFailed, AcceptanceBasis::None, detail),
        },
    }
}

/// Probe the built-in proof-checker families for runtime availability.
///
/// The probe runs only the checker's bounded `--version` command with a
/// cleared environment. It never compiles a fixture and never accepts caller
/// input.
#[must_use]
pub fn checker_availability() -> Vec<CheckerAvailability> {
    vec![coq_availability()]
}

#[cfg(unix)]
fn coq_availability() -> CheckerAvailability {
    let Some(executable) = resolve_tool("coqc") else {
        return CheckerAvailability {
            id: "coq",
            kind: CheckerKind::Coq,
            status: "not_run",
            executable: "coqc",
            version: None,
            detail: "coqc is not installed on the fixed checker search path".to_owned(),
        };
    };
    let session = match PrivateCheckerDir::new("probe") {
        Ok(session) => session,
        Err(reason) => {
            return CheckerAvailability {
                id: "coq",
                kind: CheckerKind::Coq,
                status: "not_run",
                executable: "coqc",
                version: None,
                detail: reason,
            };
        }
    };
    let env = checker_env(session.path());
    match probe_checker_version(&executable, session.path(), &env) {
        Ok(version) => CheckerAvailability {
            id: "coq",
            kind: CheckerKind::Coq,
            status: "available",
            executable: "coqc",
            version: Some(version.clone()),
            detail: format!("coqc {version} at {}", executable.display()),
        },
        Err(detail) => CheckerAvailability {
            id: "coq",
            kind: CheckerKind::Coq,
            status: "not_run",
            executable: "coqc",
            version: None,
            detail,
        },
    }
}

#[cfg(not(unix))]
fn coq_availability() -> CheckerAvailability {
    CheckerAvailability {
        id: "coq",
        kind: CheckerKind::Coq,
        status: "not_run",
        executable: "coqc",
        version: None,
        detail: "live proof-checker invocation requires a unix host".to_owned(),
    }
}

#[cfg(not(unix))]
pub fn run_live_checker(
    _manifest: &ProofManifest,
    _base_dir: &Path,
) -> Result<LiveCheckerOutcome, ProofError> {
    Ok(LiveCheckerOutcome::Unavailable {
        detail: "live proof-checker invocation requires a unix host".to_owned(),
    })
}

#[cfg(unix)]
const CHECKER_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
#[cfg(unix)]
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(unix)]
static LIVE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
struct StagedProof {
    module: String,
    path: PathBuf,
}

#[cfg(unix)]
enum StageError {
    Integrity(ProofError),
    Failed(String),
}

#[cfg(unix)]
struct LiveState {
    executable: String,
    executable_sha256: String,
    version: String,
    argv: Vec<Vec<String>>,
    stdout: String,
    stderr: String,
    exit_code: i32,
}

#[cfg(unix)]
impl LiveState {
    fn receipt(
        &self,
        manifest: &ProofManifest,
        theorems: Vec<AdmissionTheorem>,
    ) -> LiveCheckerReceipt {
        LiveCheckerReceipt {
            checker_kind: manifest.checker.kind,
            checker_version: self.version.clone(),
            executable: self.executable.clone(),
            executable_sha256: self.executable_sha256.clone(),
            argv: self.argv.clone(),
            exit_code: self.exit_code,
            stdout_sha256: sha256_hex(self.stdout.as_bytes()),
            stderr_sha256: sha256_hex(self.stderr.as_bytes()),
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
            proof_digests: manifest
                .proof_files
                .iter()
                .map(|file| ProofDigest {
                    file_id: file.id.clone(),
                    sha256: file.sha256.clone(),
                })
                .collect(),
            theorems,
        }
    }
}

#[cfg(unix)]
struct PrivateCheckerDir {
    path: PathBuf,
}

#[cfg(unix)]
impl PrivateCheckerDir {
    fn new(label: &str) -> Result<Self, String> {
        let base = std::env::temp_dir();
        for _ in 0..16 {
            let sequence = LIVE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = base.join(format!(
                "frf-proof-{label}-{}-{sequence}-{nanos}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(
                        |error| format!("cannot set 0700 on {}: {error}", path.display()),
                    )?;
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(format!("cannot create {}: {error}", path.display())),
            }
        }
        Err("could not allocate a unique private proof temporary directory".to_owned())
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(unix)]
impl Drop for PrivateCheckerDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
struct CapturedProcess {
    stdout: String,
    stderr: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
    exit_code: i32,
    timed_out: bool,
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn run_bounded(
    program: &Path,
    args: &[String],
    directory: &Path,
    env: &BTreeMap<String, String>,
    timeout: Duration,
    limit: usize,
    label: &str,
) -> Result<CapturedProcess, String> {
    let sequence = LIVE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let stdout_path = directory.join(format!("{label}-{sequence}.stdout"));
    let stderr_path = directory.join(format!("{label}-{sequence}.stderr"));
    let stdout_file = open_private(&stdout_path)?;
    let stderr_file = open_private(&stderr_path)?;

    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .current_dir(directory)
        .process_group(0);
    command.env_clear();
    for (key, value) in env {
        command.env(key, value);
    }

    let started = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot execute {}: {error}", program.display()))?;
    let deadline = started + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    break child.wait().ok();
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("cannot wait for {}: {error}", program.display()));
            }
        }
    };

    let (stdout, stdout_truncated) = read_capture_bounded(&stdout_path, limit)?;
    let (stderr, stderr_truncated) = read_capture_bounded(&stderr_path, limit)?;
    let _ = fs::remove_file(&stdout_path);
    let _ = fs::remove_file(&stderr_path);
    let exit_code = exit_status(status);
    Ok(CapturedProcess {
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        exit_code,
        timed_out,
    })
}

#[cfg(unix)]
fn exit_status(status: Option<ExitStatus>) -> i32 {
    match status {
        Some(status) => status
            .code()
            .unwrap_or_else(|| status.signal().map_or(1, |signal| 128 + signal)),
        None => 1,
    }
}

#[cfg(unix)]
fn open_private(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))
}

#[cfg(unix)]
fn read_capture_bounded(path: &Path, limit: usize) -> Result<(String, bool), String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
    let size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    let mut file =
        File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let mut buffer = Vec::new();
    file.by_ref()
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut buffer)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let truncated = size > limit || buffer.len() > limit;
    if buffer.len() > limit {
        buffer.truncate(limit);
    }
    Ok((String::from_utf8_lossy(&buffer).into_owned(), truncated))
}

#[cfg(unix)]
fn resolve_tool(name: &str) -> Option<PathBuf> {
    let candidate = Path::new(name);
    if candidate.components().count() > 1 {
        return candidate.is_file().then(|| candidate.to_path_buf());
    }
    CHECKER_PATH.split(':').find_map(|directory| {
        let candidate = Path::new(directory).join(name);
        candidate.is_file().then_some(candidate)
    })
}

#[cfg(unix)]
fn executable_matches(declared: &str, resolved: &Path) -> bool {
    let declared_path = Path::new(declared);
    if declared_path.components().count() > 1 {
        return fs::canonicalize(declared_path)
            .ok()
            .zip(fs::canonicalize(resolved).ok())
            .is_some_and(|(left, right)| left == right);
    }
    resolved.file_name() == Some(OsStr::new(declared))
}

#[cfg(unix)]
fn checker_env(home: &Path) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert("PATH".to_owned(), CHECKER_PATH.to_owned());
    env.insert("HOME".to_owned(), home.to_string_lossy().into_owned());
    env.insert("LC_ALL".to_owned(), "C".to_owned());
    env.insert("LANG".to_owned(), "C".to_owned());
    env.insert("TZ".to_owned(), "UTC".to_owned());
    env
}

#[cfg(unix)]
fn parse_coq_version(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(position) = line.find("version ") {
            let version = line[position + "version ".len()..]
                .split_whitespace()
                .next()
                .unwrap_or_default();
            let version = version.trim_end_matches([',', ';', '.']);
            if version
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_digit())
            {
                return Some(version.to_owned());
            }
        }
    }
    None
}

#[cfg(unix)]
fn probe_checker_version(
    executable: &Path,
    directory: &Path,
    env: &BTreeMap<String, String>,
) -> Result<String, String> {
    let captured = run_bounded(
        executable,
        &["--version".to_owned()],
        directory,
        env,
        VERSION_PROBE_TIMEOUT,
        MAX_LIVE_CHECKER_OUTPUT,
        "version",
    )?;
    if captured.timed_out {
        return Err(format!(
            "{} --version did not answer within {} seconds",
            executable.display(),
            VERSION_PROBE_TIMEOUT.as_secs()
        ));
    }
    if captured.exit_code != 0 {
        return Err(format!(
            "{} --version exited with status {}",
            executable.display(),
            captured.exit_code
        ));
    }
    parse_coq_version(&captured.stdout)
        .or_else(|| parse_coq_version(&captured.stderr))
        .ok_or_else(|| {
            format!(
                "{} --version did not report a parseable exact version",
                executable.display()
            )
        })
}

#[cfg(unix)]
fn valid_module_name(name: &str) -> bool {
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && characters
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '\''))
}

#[cfg(unix)]
fn stage_proofs(
    manifest: &ProofManifest,
    base_dir: &Path,
    directory: &Path,
) -> Result<Vec<StagedProof>, StageError> {
    let mut staged = Vec::new();
    let mut modules = BTreeSet::new();
    for file in &manifest.proof_files {
        let bytes =
            read_digest_bound(base_dir, &file.path, &file.sha256).map_err(StageError::Integrity)?;
        let Some(module) = Path::new(&file.path)
            .file_stem()
            .and_then(OsStr::to_str)
            .map(str::to_owned)
        else {
            return Err(StageError::Failed(format!(
                "proof file {} has no UTF-8 module stem",
                file.path
            )));
        };
        if !valid_module_name(&module) {
            return Err(StageError::Failed(format!(
                "proof file {} maps to module {module}, which is not a Coq identifier",
                file.path
            )));
        }
        if !modules.insert(module.clone()) {
            return Err(StageError::Failed(format!(
                "two proof files map to the same Coq module {module}"
            )));
        }
        let path = directory.join(format!("{module}.v"));
        fs::write(&path, &bytes).map_err(|error| {
            StageError::Integrity(ProofError::Io {
                path: path.display().to_string(),
                message: error.to_string(),
            })
        })?;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        staged.push(StagedProof { module, path });
    }
    Ok(staged)
}

#[cfg(unix)]
fn cap_text(text: &mut String) {
    if text.len() > MAX_LIVE_CHECKER_OUTPUT {
        let mut end = MAX_LIVE_CHECKER_OUTPUT;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("\n[truncated]\n");
    }
}

#[cfg(unix)]
fn append_capture(
    state: &mut LiveState,
    label: &str,
    argv: Vec<String>,
    captured: &CapturedProcess,
) {
    state.argv.push(argv);
    state.stdout.push_str(&format!("[{label}]\n"));
    state.stdout.push_str(&captured.stdout);
    if !state.stdout.ends_with('\n') {
        state.stdout.push('\n');
    }
    state.stderr.push_str(&format!("[{label}]\n"));
    state.stderr.push_str(&captured.stderr);
    if !state.stderr.ends_with('\n') {
        state.stderr.push('\n');
    }
    cap_text(&mut state.stdout);
    cap_text(&mut state.stderr);
    state.exit_code = captured.exit_code;
}

#[cfg(unix)]
fn full_argv(executable: &Path, args: &[String]) -> Vec<String> {
    let mut command_line = Vec::with_capacity(args.len() + 1);
    command_line.push(executable.to_string_lossy().into_owned());
    command_line.extend_from_slice(args);
    command_line
}

#[cfg(unix)]
fn coq_compile_args(directory: &Path, file: &Path) -> Vec<String> {
    vec![
        "-q".to_owned(),
        "-Q".to_owned(),
        directory.to_string_lossy().into_owned(),
        String::new(),
        file.file_name().map_or_else(
            || file.to_string_lossy().into_owned(),
            |name| name.to_string_lossy().into_owned(),
        ),
    ]
}

#[cfg(unix)]
fn assumption_status(output: &str) -> AdmissionStatus {
    if output.contains("Closed under the global context") {
        AdmissionStatus::Proved
    } else {
        // Anything the checker does not certify as closed is retained as an
        // unproved admission. There is no optimistic fallback.
        AdmissionStatus::Admitted
    }
}

/// Invoke a live Coq checker over the manifest's digest-bound proof files.
///
/// The adapter uses explicit argv vectors only, a private `0700` session
/// directory, a cleared environment, a fixed checker search path, a 120-second
/// wall-clock bound per process, and a 1 MiB capture bound per stream. Proof
/// files are staged flat by module stem, compiled in manifest order, and then
/// each declared theorem is checked with `Print Assumptions`; only the exact
/// `Closed under the global context` result is treated as proved.
///
/// # Errors
///
/// Returns [`ProofError`] for missing or tampered proof files or an unusable
/// private temporary directory.
#[cfg(unix)]
#[allow(clippy::too_many_lines)]
pub fn run_live_checker(
    manifest: &ProofManifest,
    base_dir: &Path,
) -> Result<LiveCheckerOutcome, ProofError> {
    validate_manifest(manifest)?;
    if manifest.checker.kind != CheckerKind::Coq {
        return Ok(LiveCheckerOutcome::Unavailable {
            detail: format!(
                "no live adapter is implemented for checker kind {}",
                manifest.checker.kind.as_str()
            ),
        });
    }
    let Some(executable) = resolve_tool(&manifest.checker.executable) else {
        return Ok(LiveCheckerOutcome::Unavailable {
            detail: format!(
                "checker executable {} was not found on the fixed search path {CHECKER_PATH}",
                manifest.checker.executable
            ),
        });
    };
    let executable_sha256 = match sha256_file(&executable) {
        Ok(digest) => digest,
        Err(detail) => {
            return Ok(LiveCheckerOutcome::Unavailable { detail });
        }
    };
    let session = match PrivateCheckerDir::new("run") {
        Ok(session) => session,
        Err(reason) => {
            return Err(ProofError::Io {
                path: std::env::temp_dir().display().to_string(),
                message: reason,
            });
        }
    };
    let env = checker_env(session.path());
    let mut state = LiveState {
        executable: executable.display().to_string(),
        executable_sha256,
        version: String::new(),
        argv: Vec::new(),
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 1,
    };

    let probe_args = vec!["--version".to_owned()];
    let probe_command = full_argv(&executable, &probe_args);
    let version_captured = match run_bounded(
        &executable,
        &probe_args,
        session.path(),
        &env,
        VERSION_PROBE_TIMEOUT,
        MAX_LIVE_CHECKER_OUTPUT,
        "version",
    ) {
        Ok(captured) => captured,
        Err(detail) => return Ok(LiveCheckerOutcome::Unavailable { detail }),
    };
    append_capture(&mut state, "version", probe_command, &version_captured);
    let Some(version) = parse_coq_version(&version_captured.stdout)
        .or_else(|| parse_coq_version(&version_captured.stderr))
    else {
        state.stderr.push_str("version output was not parseable\n");
        return Ok(LiveCheckerOutcome::Unavailable {
            detail: format!(
                "{} --version did not report a parseable exact version",
                executable.display()
            ),
        });
    };
    state.version.clone_from(&version);
    if version_captured.exit_code != 0
        || version_captured.timed_out
        || version_captured.stdout_truncated
    {
        return Ok(LiveCheckerOutcome::Unavailable {
            detail: format!(
                "{} --version did not complete cleanly (exit {})",
                executable.display(),
                version_captured.exit_code
            ),
        });
    }
    if !executable_matches(&manifest.checker.executable, &executable) {
        let detail = format!(
            "resolved checker executable {} does not match manifest executable {}",
            executable.display(),
            manifest.checker.executable
        );
        state.stderr.push_str(&format!("{detail}\n"));
        state.exit_code = 1;
        return Ok(LiveCheckerOutcome::Failed {
            detail,
            receipt: state.receipt(manifest, Vec::new()),
        });
    }
    if version != manifest.checker.version {
        let detail = format!(
            "checker version {version} does not match manifest pinned version {}",
            manifest.checker.version
        );
        state.stderr.push_str(&format!("{detail}\n"));
        state.exit_code = 1;
        return Ok(LiveCheckerOutcome::Failed {
            detail,
            receipt: state.receipt(manifest, Vec::new()),
        });
    }

    let staged = match stage_proofs(manifest, base_dir, session.path()) {
        Ok(staged) => staged,
        Err(StageError::Integrity(error)) => return Err(error),
        Err(StageError::Failed(detail)) => {
            state.stderr.push_str(&format!("{detail}\n"));
            state.exit_code = 1;
            return Ok(LiveCheckerOutcome::Failed {
                detail,
                receipt: state.receipt(manifest, Vec::new()),
            });
        }
    };
    let mut theorem_module = BTreeMap::new();
    let mut module_order = BTreeMap::new();
    for (index, (file, staged_file)) in manifest.proof_files.iter().zip(&staged).enumerate() {
        module_order.insert(staged_file.module.clone(), index);
        for theorem in &file.theorems {
            theorem_module.insert(theorem.clone(), staged_file.module.clone());
        }
    }
    for (index, (file, staged_file)) in manifest.proof_files.iter().zip(&staged).enumerate() {
        for import in &file.imports {
            let local = module_order
                .contains_key(import)
                .then_some(import.as_str())
                .or_else(|| theorem_module.get(import).map(String::as_str))
                .or_else(|| {
                    manifest
                        .proof_files
                        .iter()
                        .find(|candidate| &candidate.id == import)
                        .and_then(|candidate| {
                            module_order
                                .keys()
                                .find(|module| {
                                    Path::new(&candidate.path)
                                        .file_stem()
                                        .and_then(OsStr::to_str)
                                        == Some(module.as_str())
                                })
                                .map(String::as_str)
                        })
                });
            if let Some(module) = local {
                match module_order.get(module) {
                    Some(order) if *order < index => {}
                    _ => {
                        let detail = format!(
                            "proof file {} imports local module {module}, which is not compiled earlier",
                            file.id
                        );
                        state.stderr.push_str(&format!("{detail}\n"));
                        state.exit_code = 1;
                        return Ok(LiveCheckerOutcome::Failed {
                            detail,
                            receipt: state.receipt(manifest, Vec::new()),
                        });
                    }
                }
            } else if !manifest
                .closure
                .stdlib_allowlist
                .iter()
                .any(|allowed| prefix_matches(allowed, import))
            {
                let detail = format!(
                    "proof file {} imports {import}, which is neither a staged local module nor an allowlisted stdlib prefix",
                    file.id
                );
                state.stderr.push_str(&format!("{detail}\n"));
                state.exit_code = 1;
                return Ok(LiveCheckerOutcome::Failed {
                    detail,
                    receipt: state.receipt(manifest, Vec::new()),
                });
            }
        }
        if !staged_file.path.is_file() {
            return Err(ProofError::MissingFile {
                path: staged_file.path.display().to_string(),
            });
        }
    }

    for staged_file in &staged {
        let args = coq_compile_args(session.path(), &staged_file.path);
        let command_line = full_argv(&executable, &args);
        let captured = match run_bounded(
            &executable,
            &args,
            session.path(),
            &env,
            LIVE_CHECKER_TIMEOUT,
            MAX_LIVE_CHECKER_OUTPUT,
            &format!("compile-{}", staged_file.module),
        ) {
            Ok(captured) => captured,
            Err(detail) => {
                state.stderr.push_str(&format!("{detail}\n"));
                state.exit_code = 1;
                return Ok(LiveCheckerOutcome::Failed {
                    detail,
                    receipt: state.receipt(manifest, Vec::new()),
                });
            }
        };
        append_capture(
            &mut state,
            &format!("compile {}", staged_file.module),
            command_line,
            &captured,
        );
        let detail = if captured.timed_out {
            Some(format!(
                "compiling {} exceeded {} seconds",
                staged_file.module,
                LIVE_CHECKER_TIMEOUT.as_secs()
            ))
        } else if captured.stdout_truncated || captured.stderr_truncated {
            Some(format!(
                "compiling {} exceeded the {MAX_LIVE_CHECKER_OUTPUT}-byte capture bound",
                staged_file.module
            ))
        } else if captured.exit_code != 0 {
            Some(format!(
                "compiling {} failed with exit status {}",
                staged_file.module, captured.exit_code
            ))
        } else {
            None
        };
        if let Some(detail) = detail {
            state.stderr.push_str(&format!("{detail}\n"));
            if state.exit_code == 0 {
                state.exit_code = 1;
            }
            return Ok(LiveCheckerOutcome::Failed {
                detail,
                receipt: state.receipt(manifest, Vec::new()),
            });
        }
    }

    let mut statuses = Vec::new();
    let mut theorem_modules: Vec<(&String, &String)> = theorem_module.iter().collect();
    theorem_modules.sort_by(|left, right| left.0.cmp(right.0));
    for (index, (theorem, module)) in theorem_modules.into_iter().enumerate() {
        let script_name = format!("frf_assumptions_{index}.v");
        let script_path = session.path().join(&script_name);
        let script = format!("Require Import {module}.\nPrint Assumptions {theorem}.\n");
        fs::write(&script_path, script).map_err(|error| ProofError::Io {
            path: script_path.display().to_string(),
            message: error.to_string(),
        })?;
        let _ = fs::set_permissions(&script_path, fs::Permissions::from_mode(0o600));
        let args = coq_compile_args(session.path(), &script_path);
        let command_line = full_argv(&executable, &args);
        let captured = match run_bounded(
            &executable,
            &args,
            session.path(),
            &env,
            LIVE_CHECKER_TIMEOUT,
            MAX_LIVE_CHECKER_OUTPUT,
            &format!("assumptions-{index}"),
        ) {
            Ok(captured) => captured,
            Err(detail) => {
                state.stderr.push_str(&format!("{detail}\n"));
                state.exit_code = 1;
                return Ok(LiveCheckerOutcome::Failed {
                    detail,
                    receipt: state.receipt(manifest, statuses),
                });
            }
        };
        append_capture(
            &mut state,
            &format!("assumptions {theorem}"),
            command_line,
            &captured,
        );
        let detail = if captured.timed_out {
            Some(format!(
                "Print Assumptions for {theorem} exceeded {} seconds",
                LIVE_CHECKER_TIMEOUT.as_secs()
            ))
        } else if captured.stdout_truncated || captured.stderr_truncated {
            Some(format!(
                "Print Assumptions for {theorem} exceeded the {MAX_LIVE_CHECKER_OUTPUT}-byte capture bound"
            ))
        } else if captured.exit_code != 0 {
            Some(format!(
                "Print Assumptions for {theorem} failed with exit status {}",
                captured.exit_code
            ))
        } else {
            None
        };
        if let Some(detail) = detail {
            state.stderr.push_str(&format!("{detail}\n"));
            if state.exit_code == 0 {
                state.exit_code = 1;
            }
            return Ok(LiveCheckerOutcome::Failed {
                detail,
                receipt: state.receipt(manifest, statuses),
            });
        }
        let output = format!("{}{}", captured.stdout, captured.stderr);
        statuses.push(AdmissionTheorem {
            name: theorem.clone(),
            status: assumption_status(&output),
        });
    }

    state.exit_code = 0;
    let proof_digests = manifest
        .proof_files
        .iter()
        .map(|file| ProofDigest {
            file_id: file.id.clone(),
            sha256: file.sha256.clone(),
        })
        .collect();
    let run = CheckerRun {
        kind: manifest.checker.kind,
        version: version.clone(),
        exit_code: 0,
        proof_digests,
        theorems: statuses.clone(),
    };
    Ok(LiveCheckerOutcome::Completed {
        run,
        receipt: state.receipt(manifest, statuses),
    })
}

#[cfg(unix)]
fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read checker executable {}: {error}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

fn verify_checker_run(
    manifest: &ProofManifest,
    admission: &AdmissionReport,
    run: &CheckerRun,
) -> Result<(), String> {
    if run.kind != manifest.checker.kind {
        return Err(format!(
            "recorded checker kind {} differs from manifest kind {}",
            run.kind.as_str(),
            manifest.checker.kind.as_str()
        ));
    }
    if run.version != manifest.checker.version {
        return Err(format!(
            "recorded checker version {} differs from manifest version {}",
            run.version, manifest.checker.version
        ));
    }
    if run.exit_code != 0 {
        return Err(format!(
            "recorded checker exited with status {}",
            run.exit_code
        ));
    }

    let expected_digests: BTreeMap<&str, &str> = manifest
        .proof_files
        .iter()
        .map(|file| (file.id.as_str(), file.sha256.as_str()))
        .collect();
    let mut actual_digests = BTreeMap::new();
    for digest in &run.proof_digests {
        if actual_digests
            .insert(digest.file_id.as_str(), digest.sha256.as_str())
            .is_some()
        {
            return Err(format!("duplicate recorded digest for {}", digest.file_id));
        }
    }
    if expected_digests != actual_digests {
        return Err(
            "recorded checker proof digests do not exactly match the manifest proof files"
                .to_owned(),
        );
    }

    let expected_theorems: BTreeMap<&str, AdmissionStatus> = admission
        .admission_theorems
        .iter()
        .map(|theorem| (theorem.name.as_str(), theorem.status))
        .collect();
    let mut actual_theorems = BTreeMap::new();
    for theorem in &run.theorems {
        if actual_theorems
            .insert(theorem.name.as_str(), theorem.status)
            .is_some()
        {
            return Err(format!("duplicate recorded theorem {}", theorem.name));
        }
    }
    if expected_theorems != actual_theorems {
        return Err(
            "recorded checker theorem statuses do not exactly match the admission record"
                .to_owned(),
        );
    }
    Ok(())
}
