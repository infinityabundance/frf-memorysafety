//! Optional, pinned, compiler-assisted MIR observations.
//!
//! This module invokes an **explicitly pinned nightly toolchain** through
//! `rustup run` and parses the human-readable output of
//! `rustc --edition 2021 -Zunpretty=mir` into a conservative set of typed
//! observations. It never invokes a shell.
//!
//! # Claim ceiling
//!
//! The MIR text format is not a stable interface. The output itself warns that
//! it is "intended for human consumers only" and "subject to change without
//! notice". The parser therefore recognises a small line-oriented subset and
//! records every unrecognised construct as an explicit unknown. A successful
//! scan establishes only that:
//!
//! 1. the pinned toolchain was present and the input compiled;
//! 2. MIR text was emitted within the declared bounds; and
//! 3. the listed textual constructs were observed.
//!
//! It does **not** establish symbol resolution, a whole-program caller graph,
//! alias or provenance relationships, concrete reference intervals, or any
//! memory-safety property. Every call edge remains unresolved, including calls
//! that happen to share a name with a function defined in the same MIR output.
//! Foreign, provider, trait, and indirect dispatch remain explicit uncertainty.
//!
//! # Availability
//!
//! The adapter is optional. If `rustup`, the pinned toolchain, or a bounded
//! invocation is unavailable, [`MirAdapter::scan`] returns a typed
//! [`MirScanOutcome::NotRun`] with the exact reason. It never fabricates an
//! observation.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Pinned nightly toolchain. It matches the 2025-02-20 release date of the
/// stable `1.85.0` toolchain used by the default gate.
pub const MIR_TOOLCHAIN: &str = "nightly-2025-02-20";
/// Edition passed to the pinned compiler.
pub const MIR_EDITION: &str = "2021";
/// Schema identifier for a live MIR observation.
pub const MIR_OBSERVATION_SCHEMA: &str = "frf-memorysafety.mir-observation.v1";
/// Schema identifier for a typed `NOT_RUN` response.
pub const MIR_NOT_RUN_SCHEMA: &str = "frf-memorysafety.mir-not-run.v1";
/// Protocol specification identifier this observation reports under.
pub const MIR_SPEC: &str = "frf-memorysafety-spec-v1";
/// Text embedded in every observation and `NOT_RUN` response.
pub const MIR_CLAIM_CEILING: &str = "MIR pretty-text observations only. Not a symbol-resolved caller graph, alias analysis, provenance result, reference-interval extraction, whole-program inventory, or memory-safety result. Every call edge remains unresolved; foreign, provider, trait, and indirect dispatch remain uncertain; unrecognised MIR constructs are explicit unknowns. Absence of a finding is not evidence of absence.";

/// Default wall-clock bound for each rustup/rustc invocation.
pub const DEFAULT_MIR_TIMEOUT_MS: u64 = 30_000;
/// Default maximum input source bytes.
pub const DEFAULT_MAX_MIR_SOURCE_BYTES: usize = 4 * 1024 * 1024;
/// Default maximum retained stdout bytes.
pub const DEFAULT_MAX_MIR_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
/// Default maximum retained stderr bytes.
pub const DEFAULT_MAX_MIR_STDERR_BYTES: usize = 1024 * 1024;
/// Default maximum retained function definitions.
pub const DEFAULT_MAX_MIR_FUNCTIONS: usize = 8_192;
/// Default maximum retained call edges.
pub const DEFAULT_MAX_MIR_CALLS: usize = 65_536;
/// Default maximum retained dereferences or storage markers per category.
pub const DEFAULT_MAX_MIR_OBSERVATIONS: usize = 131_072;
/// Default maximum retained explicit unknowns.
pub const DEFAULT_MAX_MIR_UNKNOWNS: usize = 8_192;

/// Hard resource limits for one MIR scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirLimits {
    /// Wall-clock bound for each child process.
    pub timeout_ms: u64,
    /// Maximum input source bytes.
    pub max_source_bytes: usize,
    /// Maximum retained stdout bytes. Exceeding it is a typed `NOT_RUN`.
    pub max_output_bytes: usize,
    /// Maximum retained stderr bytes.
    pub max_stderr_bytes: usize,
    /// Maximum retained function definitions.
    pub max_functions: usize,
    /// Maximum retained call edges.
    pub max_calls: usize,
    /// Maximum retained dereferences or storage markers per category.
    pub max_observations: usize,
    /// Maximum retained explicit unknowns.
    pub max_unknowns: usize,
}

impl Default for MirLimits {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_MIR_TIMEOUT_MS,
            max_source_bytes: DEFAULT_MAX_MIR_SOURCE_BYTES,
            max_output_bytes: DEFAULT_MAX_MIR_OUTPUT_BYTES,
            max_stderr_bytes: DEFAULT_MAX_MIR_STDERR_BYTES,
            max_functions: DEFAULT_MAX_MIR_FUNCTIONS,
            max_calls: DEFAULT_MAX_MIR_CALLS,
            max_observations: DEFAULT_MAX_MIR_OBSERVATIONS,
            max_unknowns: DEFAULT_MAX_MIR_UNKNOWNS,
        }
    }
}

/// Category used by the CLI to choose a `SPEC.md` §14 exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirErrorCategory {
    /// Invalid input or usage.
    Usage,
    /// Evidence/input integrity failure, including a limit violation.
    Integrity,
    /// Internal encoding or harness failure.
    Harness,
}

/// Errors produced while running or parsing a MIR scan.
#[derive(Debug, thiserror::Error)]
pub enum MirError {
    /// A filesystem operation failed.
    #[error("cannot access {path}: {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// The input is not a regular file.
    #[error("MIR input is not a regular file: {path}")]
    NotRegularFile {
        /// Rejected path.
        path: PathBuf,
    },
    /// The input does not have a `.rs` extension.
    #[error("not a Rust source file (.rs): {path}")]
    NotRustSource {
        /// Rejected path.
        path: PathBuf,
    },
    /// A path or compilation operand is not valid UTF-8.
    #[error("path is not valid UTF-8: {path}")]
    NonUtf8Path {
        /// Rejected path.
        path: PathBuf,
    },
    /// A declared resource limit was exceeded.
    #[error("MIR scan limit exceeded: {resource} (limit {limit})")]
    LimitExceeded {
        /// Resource name.
        resource: &'static str,
        /// Configured limit.
        limit: usize,
    },
    /// Emitted stdout was not valid UTF-8.
    #[error("MIR output is not valid UTF-8 at byte {valid_up_to}")]
    InvalidUtf8 {
        /// Byte offset of the first invalid sequence.
        valid_up_to: usize,
    },
    /// The compiler rejected the input crate.
    #[error("pinned compiler failed with status {status}: {detail}")]
    CompilerFailed {
        /// Exit status description.
        status: String,
        /// Bounded stderr diagnostic.
        detail: String,
    },
    /// Emitted text was not recognisable MIR.
    #[error("emitted text is not recognisable MIR: {message}")]
    UnrecognizedOutput {
        /// Diagnostic.
        message: String,
    },
    /// The emitted MIR was structurally malformed.
    #[error("malformed MIR at line {line}: {message}")]
    InvalidMir {
        /// One-based line number.
        line: usize,
        /// Diagnostic.
        message: String,
    },
    /// The canonical encoder rejected the observation.
    #[error("cannot encode MIR observation: {message}")]
    Canonical {
        /// Encoder diagnostic.
        message: String,
    },
}

impl MirError {
    /// Category used for exit-status selection.
    #[must_use]
    pub fn category(&self) -> MirErrorCategory {
        match self {
            Self::Io { source, .. } if source.kind() == ErrorKind::NotFound => {
                MirErrorCategory::Usage
            }
            Self::NotRegularFile { .. } | Self::NotRustSource { .. } | Self::NonUtf8Path { .. } => {
                MirErrorCategory::Usage
            }
            Self::Io { .. }
            | Self::LimitExceeded { .. }
            | Self::InvalidUtf8 { .. }
            | Self::CompilerFailed { .. }
            | Self::UnrecognizedOutput { .. }
            | Self::InvalidMir { .. } => MirErrorCategory::Integrity,
            Self::Canonical { .. } => MirErrorCategory::Harness,
        }
    }
}

/// Status discriminator for a live observation or a `NOT_RUN` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MirRunStatus {
    /// The pinned adapter produced parsed observations.
    Live,
    /// The pinned adapter or toolchain was unavailable.
    NotRun,
}

/// Exact reason a MIR scan did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirNotRunReason {
    /// The configured `rustup` executable was not found.
    RustupExecutableNotFound,
    /// The pinned toolchain is not installed or cannot be started.
    ToolchainUnavailable,
    /// The invocation exceeded the declared wall-clock bound.
    InvocationTimedOut,
    /// Retained stdout exceeded the declared bound, so parsing would be unsafe.
    OutputLimitExceeded,
    /// The adapter could not start the configured executable.
    AdapterInvocationFailed,
}

impl MirNotRunReason {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RustupExecutableNotFound => "rustup_executable_not_found",
            Self::ToolchainUnavailable => "toolchain_unavailable",
            Self::InvocationTimedOut => "invocation_timed_out",
            Self::OutputLimitExceeded => "output_limit_exceeded",
            Self::AdapterInvocationFailed => "adapter_invocation_failed",
        }
    }
}

/// A typed, honest `NOT_RUN` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirNotRun {
    /// Schema identifier.
    pub schema: String,
    /// Specification identifier.
    pub spec: String,
    /// Always [`MirRunStatus::NotRun`].
    pub status: MirRunStatus,
    /// Pinned toolchain requested.
    pub toolchain: String,
    /// `rustup` executable used.
    pub rustup_program: String,
    /// Stage that failed: `toolchain_probe` or `mir_invocation`.
    pub stage: String,
    /// Typed reason.
    pub reason: MirNotRunReason,
    /// Exact bounded diagnostic.
    pub detail: String,
    /// Claim ceiling embedded in the response.
    pub claim_ceiling: String,
    /// Limits that were requested.
    pub limits: MirLimits,
}

impl MirNotRun {
    /// Encode this response as strict `ms-canonical-json-v1` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MirError::Canonical`] if the response cannot be encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MirError> {
        let value = serde_json::to_value(self).map_err(|error| MirError::Canonical {
            message: error.to_string(),
        })?;
        canonical_value(&value)
    }
}

/// Callee form observed in the MIR text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirCalleeForm {
    /// A plain path such as `add` or `std::mem::drop::<T>`.
    Path,
    /// A qualified or trait path such as `<i32 as From<u8>>::from`.
    QualifiedPath,
    /// An indirect call through a local such as `copy _1(args)`.
    IndirectOperand,
}

/// Resolution state. This adapter never claims a resolved target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirResolution {
    /// The target is unresolved by construction.
    Unresolved,
}

/// One textual call edge. It is never a resolved call target.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirCallEdge {
    /// Enclosing function name as printed by rustc.
    pub function: String,
    /// Callee expression before the argument list, truncated for retention.
    pub callee: String,
    /// Observed callee form.
    pub callee_form: MirCalleeForm,
    /// One-based line in the emitted text.
    pub line: usize,
    /// Basic block identifier such as `bb0`.
    pub basic_block: String,
    /// Always [`MirResolution::Unresolved`].
    pub resolution: MirResolution,
    /// A same-name function definition was observed in this MIR output. This is
    /// a name coincidence, not symbol resolution.
    pub same_name_local_definition_observed: bool,
    /// Explicit uncertainty labels, sorted.
    pub uncertainty: Vec<String>,
    /// Truncated source line.
    pub text: String,
}

/// One dereference-projection observation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirDereference {
    /// Enclosing function name.
    pub function: String,
    /// One-based line.
    pub line: usize,
    /// Basic block identifier, or an empty string before `bb0`.
    pub basic_block: String,
    /// Number of `*` place projections on the line. This counts syntax, not
    /// pointer provenance or validity.
    pub occurrences: usize,
    /// Truncated source line.
    pub text: String,
}

/// Kind of storage/lifetime marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirStorageKind {
    /// A `let` local declaration.
    Declared,
    /// `StorageLive(_n)`.
    Live,
    /// `StorageDead(_n)`.
    Dead,
    /// A lexical `scope` marker.
    Scope,
    /// A `debug name => place` binding.
    DebugBinding,
}

/// One storage/lifetime marker. It is not a proof of liveness or validity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirStorageMarker {
    /// Enclosing function name.
    pub function: String,
    /// One-based line.
    pub line: usize,
    /// Basic block identifier, or an empty string.
    pub basic_block: String,
    /// Marker kind.
    pub kind: MirStorageKind,
    /// Local, scope number, or debug name.
    pub target: String,
    /// Associated place for declarations and debug bindings.
    pub place: String,
}

/// Kind of drop/free-like call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirDropKind {
    /// A call whose final name segment is `drop`.
    ExplicitDropCall,
    /// A call whose final name segment is `drop_in_place`.
    DropInPlaceCall,
    /// A call whose final name segment looks like a deallocator.
    DeallocationCall,
}

/// One textual drop/free-like call. The semantic effect is not resolved.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirDrop {
    /// Enclosing function name.
    pub function: String,
    /// One-based line.
    pub line: usize,
    /// Basic block identifier.
    pub basic_block: String,
    /// Observed kind.
    pub kind: MirDropKind,
    /// Full callee expression.
    pub callee: String,
    /// Truncated source line.
    pub text: String,
}

/// One unrecognised MIR construct preserved as explicit uncertainty.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirUnknown {
    /// Enclosing function name, if the line was inside a function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// One-based line.
    pub line: usize,
    /// Basic block identifier, or an empty string.
    pub basic_block: String,
    /// Why the construct was not interpreted.
    pub reason: String,
    /// Truncated source line.
    pub text: String,
}

/// One observed function definition.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirFunction {
    /// Function name as printed by rustc, including closure suffixes.
    pub name: String,
    /// One-based first line.
    pub line_start: usize,
    /// One-based closing-brace line.
    pub line_end: usize,
    /// Basic blocks observed.
    pub basic_blocks: usize,
    /// Call edges attributed to this function.
    pub call_edges: usize,
    /// Dereferences attributed to this function.
    pub dereferences: usize,
    /// Storage markers attributed to this function.
    pub storage_markers: usize,
    /// Drop/free-like calls attributed to this function.
    pub drops: usize,
    /// Explicit unknown constructs attributed to this function.
    pub unknown_constructs: usize,
}

/// Deterministic aggregate summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirSummary {
    /// Function definitions.
    pub functions: usize,
    /// Basic blocks.
    pub basic_blocks: usize,
    /// Textual call edges.
    pub call_edges: usize,
    /// Call edges whose target is unresolved. Always equal to `call_edges`.
    pub unresolved_call_edges: usize,
    /// Indirect call edges.
    pub indirect_call_edges: usize,
    /// Dereference observations.
    pub dereferences: usize,
    /// Storage/lifetime markers.
    pub storage_markers: usize,
    /// Drop/free-like calls.
    pub drops: usize,
    /// Explicit unknown constructs.
    pub unknown_constructs: usize,
    /// Whether rustc's human-format warning was present.
    pub format_warning_observed: bool,
}

/// Provenance of a live observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirProvenance {
    /// Canonical input path.
    pub input_path: String,
    /// SHA-256 of the exact input bytes.
    pub input_sha256: String,
    /// `rustc --version` output for the pinned toolchain.
    pub rustc_version: String,
    /// SHA-256 of the emitted stdout bytes.
    pub stdout_sha256: String,
    /// Emitted stdout bytes.
    pub stdout_bytes: usize,
    /// Emitted stderr bytes retained.
    pub stderr_bytes: usize,
    /// Whether retained stderr was truncated at the configured bound.
    pub stderr_truncated: bool,
}

/// A conservative, parsed MIR observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirObservation {
    /// Schema identifier.
    pub schema: String,
    /// Specification identifier.
    pub spec: String,
    /// Always [`MirRunStatus::Live`].
    pub status: MirRunStatus,
    /// Claim ceiling embedded in the artifact.
    pub claim_ceiling: String,
    /// Pinned toolchain requested.
    pub toolchain: String,
    /// Limits applied.
    pub limits: MirLimits,
    /// Provenance, present for a live adapter run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<MirProvenance>,
    /// Function definitions, ordered by source line and name.
    pub functions: Vec<MirFunction>,
    /// Unresolved call edges, ordered by function, line, and callee.
    pub call_edges: Vec<MirCallEdge>,
    /// Dereference observations, ordered by function, line, and text.
    pub dereferences: Vec<MirDereference>,
    /// Storage markers, ordered by function, line, kind, and target.
    pub storage_markers: Vec<MirStorageMarker>,
    /// Drop/free-like calls, ordered by function, line, and callee.
    pub drops: Vec<MirDrop>,
    /// Explicit unknowns, ordered by line and text.
    pub unknowns: Vec<MirUnknown>,
    /// Aggregate summary.
    pub summary: MirSummary,
}

impl MirObservation {
    /// Encode this observation as strict `ms-canonical-json-v1` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MirError::Canonical`] if the observation cannot be encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MirError> {
        let value = serde_json::to_value(self).map_err(|error| MirError::Canonical {
            message: error.to_string(),
        })?;
        canonical_value(&value)
    }
}

/// Outcome of an adapter attempt. `NotRun` is never a fabricated observation.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirScanOutcome {
    /// The pinned compiler ran and its MIR text was parsed.
    Live(MirObservation),
    /// The adapter or pinned toolchain was unavailable, with an exact reason.
    NotRun(MirNotRun),
}

/// Pinned, shell-free MIR adapter.
#[derive(Debug, Clone)]
pub struct MirAdapter {
    toolchain: String,
    rustup_program: PathBuf,
    limits: MirLimits,
}

impl Default for MirAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl MirAdapter {
    /// Create an adapter using [`MIR_TOOLCHAIN`] and `rustup` from `PATH`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            toolchain: MIR_TOOLCHAIN.to_owned(),
            rustup_program: PathBuf::from("rustup"),
            limits: MirLimits::default(),
        }
    }

    /// Replace the `rustup` executable used for explicit, non-shell invocation.
    #[must_use]
    pub fn with_rustup_program(mut self, program: impl Into<PathBuf>) -> Self {
        self.rustup_program = program.into();
        self
    }

    /// Replace the pinned toolchain name. The artifact records the actual name.
    #[must_use]
    pub fn with_toolchain(mut self, toolchain: impl Into<String>) -> Self {
        self.toolchain = toolchain.into();
        self
    }

    /// Replace the resource limits.
    #[must_use]
    pub fn with_limits(mut self, limits: MirLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Return the configured toolchain name.
    #[must_use]
    pub fn toolchain(&self) -> &str {
        &self.toolchain
    }

    /// Return the configured limits.
    #[must_use]
    pub fn limits(&self) -> MirLimits {
        self.limits
    }

    /// Invoke the pinned compiler and parse its MIR text.
    ///
    /// The invocation is an explicit argv vector:
    /// `rustup run <toolchain> rustc --edition 2021 -Zunpretty=mir
    /// --crate-type=lib <absolute-input>`. It never uses a shell. The child
    /// runs in a private temporary working directory, with bounded stdout,
    /// bounded stderr, a bounded wall-clock timeout, and null stdin.
    ///
    /// # Errors
    ///
    /// Returns [`MirError`] for an unusable input, a compiler rejection, a
    /// limit violation, or an encoding failure. An unavailable toolchain is
    /// **not** an error: it is returned as [`MirScanOutcome::NotRun`].
    #[allow(clippy::too_many_lines)]
    pub fn scan(&self, input: impl AsRef<Path>) -> Result<MirScanOutcome, MirError> {
        let requested = input.as_ref();
        let canonical = fs::canonicalize(requested).map_err(|source| MirError::Io {
            path: requested.to_path_buf(),
            source,
        })?;
        let metadata = fs::metadata(&canonical).map_err(|source| MirError::Io {
            path: canonical.clone(),
            source,
        })?;
        if !metadata.is_file() {
            return Err(MirError::NotRegularFile { path: canonical });
        }
        if canonical
            .extension()
            .is_none_or(|extension| extension != "rs")
        {
            return Err(MirError::NotRustSource { path: canonical });
        }
        let source_limit = u64::try_from(self.limits.max_source_bytes).unwrap_or(u64::MAX);
        if metadata.len() > source_limit {
            return Err(MirError::LimitExceeded {
                resource: "source_bytes",
                limit: self.limits.max_source_bytes,
            });
        }
        let input_text = canonical
            .to_str()
            .ok_or_else(|| MirError::NonUtf8Path {
                path: canonical.clone(),
            })?
            .to_owned();
        let input_bytes = fs::read(&canonical).map_err(|source| MirError::Io {
            path: canonical.clone(),
            source,
        })?;
        if input_bytes.len() > self.limits.max_source_bytes {
            return Err(MirError::LimitExceeded {
                resource: "source_bytes",
                limit: self.limits.max_source_bytes,
            });
        }

        let private = PrivateTempDir::create()?;
        let rustc_version = match self.probe(&private.path) {
            ProbeOutcome::Ready(version) => version,
            ProbeOutcome::NotRun(not_run) => return Ok(MirScanOutcome::NotRun(not_run)),
        };

        let output = match self.invoke(
            &[
                "run",
                &self.toolchain,
                "rustc",
                "--edition",
                MIR_EDITION,
                "-Zunpretty=mir",
                "--crate-type=lib",
                &input_text,
            ],
            &private.path,
        ) {
            Ok(output) => output,
            Err(InvocationFailure::NotFound(error)) => {
                return Ok(MirScanOutcome::NotRun(self.not_run(
                    "mir_invocation",
                    MirNotRunReason::RustupExecutableNotFound,
                    format!("cannot find rustup executable: {error}"),
                )));
            }
            Err(InvocationFailure::Other(error)) => {
                return Ok(MirScanOutcome::NotRun(self.not_run(
                    "mir_invocation",
                    MirNotRunReason::AdapterInvocationFailed,
                    format!("cannot start rustup: {error}"),
                )));
            }
        };

        if output.timed_out {
            return Ok(MirScanOutcome::NotRun(self.not_run(
                "mir_invocation",
                MirNotRunReason::InvocationTimedOut,
                format!(
                    "pinned rustc exceeded the {} ms wall-clock bound",
                    self.limits.timeout_ms
                ),
            )));
        }
        if output.stdout_truncated {
            return Ok(MirScanOutcome::NotRun(self.not_run(
                "mir_invocation",
                MirNotRunReason::OutputLimitExceeded,
                format!(
                    "retained stdout reached the {} byte bound; refusing to parse incomplete MIR",
                    self.limits.max_output_bytes
                ),
            )));
        }
        let Some(status) = output.status else {
            return Ok(MirScanOutcome::NotRun(self.not_run(
                "mir_invocation",
                MirNotRunReason::ToolchainUnavailable,
                "pinned rustc produced no exit status".to_owned(),
            )));
        };
        if !status.success() {
            return Err(MirError::CompilerFailed {
                status: describe_status(status),
                detail: bounded_text(&output.stderr, 4_096),
            });
        }
        let text = String::from_utf8(output.stdout).map_err(|error| MirError::InvalidUtf8 {
            valid_up_to: error.utf8_error().valid_up_to(),
        })?;
        let mut observation = parse_mir_text(&text, self.limits)?;
        observation.toolchain.clone_from(&self.toolchain);
        observation.provenance = Some(MirProvenance {
            input_path: input_text,
            input_sha256: sha256_hex(&input_bytes),
            rustc_version,
            stdout_sha256: sha256_hex(text.as_bytes()),
            stdout_bytes: text.len(),
            stderr_bytes: output.stderr.len(),
            stderr_truncated: output.stderr_truncated,
        });
        Ok(MirScanOutcome::Live(observation))
    }

    fn probe(&self, cwd: &Path) -> ProbeOutcome {
        let output = match self.invoke(&["run", &self.toolchain, "rustc", "--version"], cwd) {
            Ok(output) => output,
            Err(InvocationFailure::NotFound(error)) => {
                return ProbeOutcome::NotRun(self.not_run(
                    "toolchain_probe",
                    MirNotRunReason::RustupExecutableNotFound,
                    format!("cannot find rustup executable: {error}"),
                ));
            }
            Err(InvocationFailure::Other(error)) => {
                return ProbeOutcome::NotRun(self.not_run(
                    "toolchain_probe",
                    MirNotRunReason::AdapterInvocationFailed,
                    format!("cannot start rustup: {error}"),
                ));
            }
        };
        if output.timed_out {
            return ProbeOutcome::NotRun(self.not_run(
                "toolchain_probe",
                MirNotRunReason::InvocationTimedOut,
                format!(
                    "toolchain probe exceeded the {} ms wall-clock bound",
                    self.limits.timeout_ms
                ),
            ));
        }
        let Some(status) = output.status else {
            return ProbeOutcome::NotRun(self.not_run(
                "toolchain_probe",
                MirNotRunReason::ToolchainUnavailable,
                "toolchain probe produced no exit status".to_owned(),
            ));
        };
        if !status.success() {
            return ProbeOutcome::NotRun(self.not_run(
                "toolchain_probe",
                MirNotRunReason::ToolchainUnavailable,
                format!(
                    "pinned toolchain `{}` is not installed or cannot run (status {}): {}",
                    self.toolchain,
                    describe_status(status),
                    bounded_text(&output.stderr, 2_048)
                ),
            ));
        }
        ProbeOutcome::Ready(bounded_text(&output.stdout, 1_024).trim().to_owned())
    }

    fn invoke(&self, arguments: &[&str], cwd: &Path) -> Result<BoundedOutput, InvocationFailure> {
        let mut command = Command::new(&self.rustup_program);
        command
            .args(arguments)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("RUST_BACKTRACE", "0");
        run_bounded(command, self.limits).map_err(|error| {
            if error.kind() == ErrorKind::NotFound {
                InvocationFailure::NotFound(error)
            } else {
                InvocationFailure::Other(error)
            }
        })
    }

    fn not_run(&self, stage: &str, reason: MirNotRunReason, detail: String) -> MirNotRun {
        MirNotRun {
            schema: MIR_NOT_RUN_SCHEMA.to_owned(),
            spec: MIR_SPEC.to_owned(),
            status: MirRunStatus::NotRun,
            toolchain: self.toolchain.clone(),
            rustup_program: self.rustup_program.display().to_string(),
            stage: stage.to_owned(),
            reason,
            detail,
            claim_ceiling: MIR_CLAIM_CEILING.to_owned(),
            limits: self.limits,
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum ProbeOutcome {
    Ready(String),
    NotRun(MirNotRun),
}

enum InvocationFailure {
    NotFound(std::io::Error),
    Other(std::io::Error),
}

struct BoundedOutput {
    status: Option<ExitStatus>,
    timed_out: bool,
    stdout: Vec<u8>,
    stdout_truncated: bool,
    stderr: Vec<u8>,
    stderr_truncated: bool,
}

fn run_bounded(mut command: Command, limits: MirLimits) -> Result<BoundedOutput, std::io::Error> {
    let mut child = command.spawn()?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_reader = stdout.map(|reader| spawn_bounded_reader(reader, limits.max_output_bytes));
    let stderr_reader = stderr.map(|reader| spawn_bounded_reader(reader, limits.max_stderr_bytes));

    let deadline = Instant::now() + Duration::from_millis(limits.timeout_ms);
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
    };

    let (stdout, stdout_truncated) = stdout_reader
        .map(BoundedReader::receive)
        .unwrap_or_default();
    let (stderr, stderr_truncated) = stderr_reader
        .map(BoundedReader::receive)
        .unwrap_or_default();
    Ok(BoundedOutput {
        status,
        timed_out,
        stdout,
        stdout_truncated,
        stderr,
        stderr_truncated,
    })
}

struct BoundedReader {
    receiver: Receiver<(Vec<u8>, bool)>,
}

impl BoundedReader {
    fn receive(self) -> (Vec<u8>, bool) {
        self.receiver.recv().unwrap_or_default()
    }
}

fn spawn_bounded_reader<R>(mut reader: R, limit: usize) -> BoundedReader
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut retained = Vec::new();
        let mut truncated = false;
        let mut buffer = [0_u8; 8_192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    let remaining = limit.saturating_sub(retained.len());
                    if count <= remaining {
                        retained.extend_from_slice(&buffer[..count]);
                    } else {
                        retained.extend_from_slice(&buffer[..remaining]);
                        truncated = true;
                    }
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = sender.send((retained, truncated));
    });
    BoundedReader { receiver }
}

struct PrivateTempDir {
    path: PathBuf,
}

impl PrivateTempDir {
    fn create() -> Result<Self, MirError> {
        let base = std::env::temp_dir();
        let process = std::process::id();
        for attempt in 0..128_u32 {
            let path = base.join(format!("frf-mir-{process}-{attempt}"));
            match fs::create_dir(&path) {
                Ok(()) => {
                    restrict_directory(&path)?;
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(source) => return Err(MirError::Io { path, source }),
            }
        }
        Err(MirError::Io {
            path: base,
            source: std::io::Error::new(
                ErrorKind::AlreadyExists,
                "cannot create a unique private MIR working directory",
            ),
        })
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<(), MirError> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = fs::metadata(path)
        .map_err(|source| MirError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).map_err(|source| MirError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> Result<(), MirError> {
    Ok(())
}

/// Parse human-readable MIR text into conservative observations.
///
/// The parser is line-oriented and deliberately small. It recognises function
/// headers, basic blocks, `let`/`debug`/`scope` markers, `StorageLive` and
/// `StorageDead`, calls with a `-> [..]` terminator, dereference projections,
/// and drop/free-like callees. Everything else is retained as an explicit
/// unknown rather than guessed.
///
/// # Errors
///
/// Returns [`MirError::LimitExceeded`] for a hard limit violation,
/// [`MirError::UnrecognizedOutput`] when the text has no warning header and no
/// function definitions, and [`MirError::InvalidMir`] for a structurally
/// unterminated function.
#[allow(clippy::too_many_lines)]
pub fn parse_mir_text(text: &str, limits: MirLimits) -> Result<MirObservation, MirError> {
    let format_warning_observed = has_format_warning(text);
    let mut functions: Vec<MirFunction> = Vec::new();
    let mut call_edges: Vec<MirCallEdge> = Vec::new();
    let mut dereferences: Vec<MirDereference> = Vec::new();
    let mut storage_markers: Vec<MirStorageMarker> = Vec::new();
    let mut drops: Vec<MirDrop> = Vec::new();
    let mut unknowns: Vec<MirUnknown> = Vec::new();
    let mut current: Option<FunctionBuilder> = None;
    let mut current_block = String::new();

    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim_end_matches('\r');
        let trimmed = line.trim();
        if current.is_some() {
            if is_function_close(line) {
                let Some(mut finished) = current.take() else {
                    continue;
                };
                finished.line_end = line_number;
                if functions.len() >= limits.max_functions {
                    return Err(limit_error("functions", limits.max_functions));
                }
                functions.push(MirFunction {
                    name: finished.name,
                    line_start: finished.line_start,
                    line_end: finished.line_end,
                    basic_blocks: finished.basic_blocks,
                    call_edges: finished.call_edges,
                    dereferences: finished.dereferences,
                    storage_markers: finished.storage_markers,
                    drops: finished.drops,
                    unknown_constructs: finished.unknown_constructs,
                });
                current_block.clear();
                continue;
            }
            if trimmed.is_empty() {
                continue;
            }
            if trimmed == "}" {
                continue;
            }
            let Some(builder) = current.as_mut() else {
                continue;
            };
            let function = builder.name.clone();
            let block = current_block.clone();

            if let Some(identifier) = basic_block_identifier(trimmed) {
                current_block = identifier;
                builder.basic_blocks = builder.basic_blocks.saturating_add(1);
                continue;
            }

            let dereference_count = count_dereferences(trimmed);
            if dereference_count > 0 {
                if dereferences.len() >= limits.max_observations {
                    return Err(limit_error("dereferences", limits.max_observations));
                }
                builder.dereferences = builder.dereferences.saturating_add(1);
                dereferences.push(MirDereference {
                    function: function.clone(),
                    line: line_number,
                    basic_block: block.clone(),
                    occurrences: dereference_count,
                    text: truncate_text(trimmed, 240),
                });
            }

            if let Some(marker) = storage_marker(trimmed, &function, line_number, &block) {
                if storage_markers.len() >= limits.max_observations {
                    return Err(limit_error("storage_markers", limits.max_observations));
                }
                builder.storage_markers = builder.storage_markers.saturating_add(1);
                storage_markers.push(marker);
                continue;
            }

            if let Some(call) = call_edge(trimmed, &function, line_number, &block) {
                if call_edges.len() >= limits.max_calls {
                    return Err(limit_error("call_edges", limits.max_calls));
                }
                builder.call_edges = builder.call_edges.saturating_add(1);
                let drop_kind = drop_kind(&call.callee);
                if let Some(kind) = drop_kind {
                    if drops.len() >= limits.max_calls {
                        return Err(limit_error("drops", limits.max_calls));
                    }
                    builder.drops = builder.drops.saturating_add(1);
                    drops.push(MirDrop {
                        function: function.clone(),
                        line: line_number,
                        basic_block: block.clone(),
                        kind,
                        callee: call.callee.clone(),
                        text: call.text.clone(),
                    });
                }
                call_edges.push(call);
                continue;
            }

            if trimmed.contains("InlineAsm(") {
                if unknowns.len() >= limits.max_unknowns {
                    return Err(limit_error("unknowns", limits.max_unknowns));
                }
                builder.unknown_constructs = builder.unknown_constructs.saturating_add(1);
                unknowns.push(MirUnknown {
                    function: Some(function),
                    line: line_number,
                    basic_block: block,
                    reason: "inline_asm_not_interpreted".to_owned(),
                    text: truncate_text(trimmed, 240),
                });
                continue;
            }

            if is_known_control(trimmed) || is_assignment(trimmed) {
                continue;
            }

            if unknowns.len() >= limits.max_unknowns {
                return Err(limit_error("unknowns", limits.max_unknowns));
            }
            builder.unknown_constructs = builder.unknown_constructs.saturating_add(1);
            unknowns.push(MirUnknown {
                function: Some(function),
                line: line_number,
                basic_block: block,
                reason: "unrecognized_mir_statement".to_owned(),
                text: truncate_text(trimmed, 240),
            });
        } else {
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }
            if trimmed.starts_with("fn ") {
                if functions.len() >= limits.max_functions {
                    return Err(limit_error("functions", limits.max_functions));
                }
                let name = function_name(trimmed).ok_or_else(|| MirError::InvalidMir {
                    line: line_number,
                    message: "function header has no name or argument list".to_owned(),
                })?;
                if !trimmed.ends_with('{') {
                    return Err(MirError::InvalidMir {
                        line: line_number,
                        message: "function header does not end with '{'".to_owned(),
                    });
                }
                current = Some(FunctionBuilder {
                    name,
                    line_start: line_number,
                    line_end: line_number,
                    basic_blocks: 0,
                    call_edges: 0,
                    dereferences: 0,
                    storage_markers: 0,
                    drops: 0,
                    unknown_constructs: 0,
                });
                continue;
            }
            if unknowns.len() >= limits.max_unknowns {
                return Err(limit_error("unknowns", limits.max_unknowns));
            }
            unknowns.push(MirUnknown {
                function: None,
                line: line_number,
                basic_block: String::new(),
                reason: "unrecognized_top_level_construct".to_owned(),
                text: truncate_text(trimmed, 240),
            });
        }
    }

    if let Some(builder) = current {
        return Err(MirError::InvalidMir {
            line: builder.line_start,
            message: format!("function `{}` is not terminated", builder.name),
        });
    }

    if !format_warning_observed && functions.is_empty() {
        return Err(MirError::UnrecognizedOutput {
            message: "neither the rustc human-format warning nor any function definition was found"
                .to_owned(),
        });
    }
    if !format_warning_observed {
        if unknowns.len() >= limits.max_unknowns {
            return Err(limit_error("unknowns", limits.max_unknowns));
        }
        unknowns.push(MirUnknown {
            function: None,
            line: 1,
            basic_block: String::new(),
            reason: "mir_format_warning_absent".to_owned(),
            text: "the expected rustc human-format warning was not present".to_owned(),
        });
    }

    let definitions: BTreeSet<String> = functions
        .iter()
        .filter_map(|function| simple_callee(&function.name))
        .collect();
    for edge in &mut call_edges {
        let same_name = simple_callee(&edge.callee).is_some_and(|name| definitions.contains(&name));
        edge.same_name_local_definition_observed = same_name;
        if !same_name && edge.callee_form != MirCalleeForm::IndirectOperand {
            edge.uncertainty
                .push("external_foreign_or_provider_possible".to_owned());
        }
        edge.uncertainty.sort();
        edge.uncertainty.dedup();
    }

    functions.sort_by(|left, right| {
        left.line_start
            .cmp(&right.line_start)
            .then(left.name.cmp(&right.name))
    });
    call_edges.sort();
    dereferences.sort();
    storage_markers.sort();
    drops.sort();
    unknowns.sort();

    let basic_blocks = functions
        .iter()
        .map(|function| function.basic_blocks)
        .sum::<usize>();
    let indirect_call_edges = call_edges
        .iter()
        .filter(|edge| edge.callee_form == MirCalleeForm::IndirectOperand)
        .count();
    let summary = MirSummary {
        functions: functions.len(),
        basic_blocks,
        call_edges: call_edges.len(),
        unresolved_call_edges: call_edges.len(),
        indirect_call_edges,
        dereferences: dereferences.len(),
        storage_markers: storage_markers.len(),
        drops: drops.len(),
        unknown_constructs: unknowns.len(),
        format_warning_observed,
    };
    Ok(MirObservation {
        schema: MIR_OBSERVATION_SCHEMA.to_owned(),
        spec: MIR_SPEC.to_owned(),
        status: MirRunStatus::Live,
        claim_ceiling: MIR_CLAIM_CEILING.to_owned(),
        toolchain: MIR_TOOLCHAIN.to_owned(),
        limits,
        provenance: None,
        functions,
        call_edges,
        dereferences,
        storage_markers,
        drops,
        unknowns,
        summary,
    })
}

struct FunctionBuilder {
    name: String,
    line_start: usize,
    line_end: usize,
    basic_blocks: usize,
    call_edges: usize,
    dereferences: usize,
    storage_markers: usize,
    drops: usize,
    unknown_constructs: usize,
}

fn has_format_warning(text: &str) -> bool {
    let mut warning = false;
    let mut instability = false;
    for line in text.lines().take(4) {
        if line.contains("WARNING: This output format is intended for human consumers only") {
            warning = true;
        }
        if line.contains("subject to change without notice") {
            instability = true;
        }
    }
    warning && instability
}

fn is_function_close(line: &str) -> bool {
    !line.starts_with(' ') && line.trim() == "}"
}

fn function_name(header: &str) -> Option<String> {
    let rest = header.strip_prefix("fn ")?;
    let open = rest.find('(')?;
    let name = rest[..open].trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

fn basic_block_identifier(line: &str) -> Option<String> {
    let rest = line.strip_prefix("bb")?;
    let colon = rest.find(':')?;
    let digits = &rest[..colon];
    if digits.is_empty()
        || !digits.chars().all(|character| character.is_ascii_digit())
        || !line.ends_with('{')
    {
        return None;
    }
    Some(format!("bb{digits}"))
}

fn count_dereferences(line: &str) -> usize {
    let code = line.split("//").next().unwrap_or(line);
    let bytes = code.as_bytes();
    let mut count = 0;
    for index in 0..bytes.len() {
        if bytes[index] == b'*' {
            if let Some(next) = bytes.get(index + 1) {
                if *next == b'(' || *next == b'_' {
                    count += 1;
                }
            }
        }
    }
    count
}

fn storage_marker(
    line: &str,
    function: &str,
    line_number: usize,
    block: &str,
) -> Option<MirStorageMarker> {
    let (kind, target, place) = if let Some(rest) = line.strip_prefix("debug ") {
        let (name, place) = rest.split_once("=>")?;
        (
            MirStorageKind::DebugBinding,
            name.trim().to_owned(),
            place.trim().trim_end_matches(';').trim().to_owned(),
        )
    } else if let Some(rest) = line.strip_prefix("StorageLive(") {
        (
            MirStorageKind::Live,
            parenthesized_target(rest)?,
            String::new(),
        )
    } else if let Some(rest) = line.strip_prefix("StorageDead(") {
        (
            MirStorageKind::Dead,
            parenthesized_target(rest)?,
            String::new(),
        )
    } else if let Some(rest) = line.strip_prefix("scope ") {
        if !line.ends_with('{') {
            return None;
        }
        (
            MirStorageKind::Scope,
            rest.trim_end_matches('{').trim().to_owned(),
            String::new(),
        )
    } else if let Some(rest) = line.strip_prefix("let ") {
        let rest = rest.strip_prefix("mut ").unwrap_or(rest);
        let target = rest.split(':').next()?.trim();
        if target.is_empty() {
            return None;
        }
        (
            MirStorageKind::Declared,
            target.to_owned(),
            target.to_owned(),
        )
    } else {
        return None;
    };
    Some(MirStorageMarker {
        function: function.to_owned(),
        line: line_number,
        basic_block: block.to_owned(),
        kind,
        target,
        place,
    })
}

fn parenthesized_target(rest: &str) -> Option<String> {
    let close = rest.find(')')?;
    let target = rest[..close].trim();
    if target.is_empty() {
        None
    } else {
        Some(target.to_owned())
    }
}

fn call_edge(line: &str, function: &str, line_number: usize, block: &str) -> Option<MirCallEdge> {
    let arrow = line.find("-> [")?;
    let prefix = line[..arrow].trim();
    let rhs = prefix
        .split_once(" = ")
        .map_or(prefix, |(_, value)| value)
        .trim();
    if rhs.starts_with("assert(") || rhs.starts_with("switchInt(") {
        return None;
    }
    let open = rhs.find('(')?;
    let callee = rhs[..open].trim();
    if callee.is_empty()
        || callee.starts_with("const ")
        || callee == "InlineAsm"
        || callee.starts_with("InlineAsm(")
    {
        return None;
    }
    let callee_form = if callee.starts_with("copy ") || callee.starts_with("move ") {
        MirCalleeForm::IndirectOperand
    } else if callee.starts_with('<') || callee.contains(" as ") {
        MirCalleeForm::QualifiedPath
    } else {
        MirCalleeForm::Path
    };
    let mut uncertainty = BTreeSet::new();
    uncertainty.insert("mir_pretty_text_only".to_owned());
    uncertainty.insert("callee_not_symbolically_resolved".to_owned());
    match callee_form {
        MirCalleeForm::IndirectOperand => {
            uncertainty.insert("indirect_callee_operand".to_owned());
            uncertainty.insert("call_target_not_identified".to_owned());
        }
        MirCalleeForm::QualifiedPath => {
            uncertainty.insert("qualified_or_trait_path_unresolved".to_owned());
        }
        MirCalleeForm::Path => {}
    }
    if drop_kind(callee).is_some() {
        uncertainty.insert("drop_or_deallocation_semantics_not_resolved".to_owned());
    }
    Some(MirCallEdge {
        function: function.to_owned(),
        callee: truncate_text(callee, 240),
        callee_form,
        line: line_number,
        basic_block: block.to_owned(),
        resolution: MirResolution::Unresolved,
        same_name_local_definition_observed: false,
        uncertainty: uncertainty.into_iter().collect(),
        text: truncate_text(line, 240),
    })
}

fn drop_kind(callee: &str) -> Option<MirDropKind> {
    let name = simple_callee(callee)?;
    match name.as_str() {
        "drop" => Some(MirDropKind::ExplicitDropCall),
        "drop_in_place" => Some(MirDropKind::DropInPlaceCall),
        "dealloc" | "__rust_dealloc" | "free" | "raw_free" => Some(MirDropKind::DeallocationCall),
        _ => None,
    }
}

fn simple_callee(callee: &str) -> Option<String> {
    if callee.starts_with("copy ") || callee.starts_with("move ") {
        return None;
    }
    let without_generics = callee.split("::<").next().unwrap_or(callee);
    let segment = without_generics
        .rsplit("::")
        .next()
        .unwrap_or(without_generics)
        .trim();
    if segment.is_empty() {
        None
    } else {
        Some(segment.to_owned())
    }
}

fn is_known_control(line: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "assert(",
        "switchInt(",
        "goto",
        "return",
        "unreachable",
        "resume",
        "abort",
        "FalseEdge",
        "TrueEdge",
        "SetDiscriminant(",
        "Deinit(",
        "FakeRead(",
        "PlaceMention(",
        "AscribeUserType(",
        "Coverage(",
        "ConstEvalCounter",
        "Nop",
        "Retag(",
        "DropAndReplace(",
    ];
    PREFIXES.iter().any(|prefix| line.starts_with(prefix))
}

fn is_assignment(line: &str) -> bool {
    line.contains(" = ") && line.ends_with(';')
}

fn describe_status(status: ExitStatus) -> String {
    status.code().map_or_else(
        || "terminated by signal".to_owned(),
        |code| code.to_string(),
    )
}

fn limit_error(resource: &'static str, limit: usize) -> MirError {
    MirError::LimitExceeded { resource, limit }
}

fn bounded_text(bytes: &[u8], maximum: usize) -> String {
    let slice = if bytes.len() > maximum {
        &bytes[..maximum]
    } else {
        bytes
    };
    let text = String::from_utf8_lossy(slice);
    if bytes.len() > maximum {
        format!("{text}...[truncated]")
    } else {
        text.into_owned()
    }
}

fn truncate_text(value: &str, maximum_chars: usize) -> String {
    let mut characters = value.chars();
    let mut prefix: String = characters.by_ref().take(maximum_chars).collect();
    if characters.next().is_some() {
        prefix.push_str("...");
    }
    prefix
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn canonical_value(value: &serde_json::Value) -> Result<Vec<u8>, MirError> {
    crate::identity::canonical_bytes(value).map_err(|error| MirError::Canonical {
        message: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../tests/fixtures/mir/sample.mir");

    #[test]
    fn parser_observes_functions_calls_derefs_storage_and_drops() {
        let observation = parse_mir_text(SAMPLE, MirLimits::default()).expect("fixture parses");
        assert_eq!(observation.status, MirRunStatus::Live);
        assert!(observation.summary.format_warning_observed);
        assert_eq!(observation.functions.len(), 7);
        assert!(observation
            .functions
            .iter()
            .any(|function| function.name == "use_ref"));
        assert!(observation
            .call_edges
            .iter()
            .any(|edge| edge.callee == "foreign_work"
                && edge
                    .uncertainty
                    .iter()
                    .any(|item| item == "external_foreign_or_provider_possible")));
        assert!(observation
            .call_edges
            .iter()
            .any(|edge| edge.callee_form == MirCalleeForm::IndirectOperand));
        assert!(observation
            .call_edges
            .iter()
            .any(|edge| edge.callee == "add" && edge.same_name_local_definition_observed));
        assert!(observation
            .call_edges
            .iter()
            .any(|edge| edge.callee == "std::mem::drop::<Holder>"
                && !edge.same_name_local_definition_observed));
        assert!(observation
            .dereferences
            .iter()
            .any(|dereference| dereference.function == "use_ref"));
        assert!(observation
            .storage_markers
            .iter()
            .any(|marker| marker.kind == MirStorageKind::Live));
        assert!(observation
            .storage_markers
            .iter()
            .any(|marker| marker.kind == MirStorageKind::DebugBinding));
        assert!(observation
            .drops
            .iter()
            .any(|drop| drop.kind == MirDropKind::ExplicitDropCall));
        assert!(observation
            .unknowns
            .iter()
            .any(|unknown| unknown.reason == "unrecognized_mir_statement"));
        assert!(observation
            .call_edges
            .iter()
            .all(|edge| edge.resolution == MirResolution::Unresolved));
    }

    #[test]
    fn parser_is_deterministic_for_equal_text() {
        let first = parse_mir_text(SAMPLE, MirLimits::default()).unwrap();
        let second = parse_mir_text(SAMPLE, MirLimits::default()).unwrap();
        assert_eq!(
            first.canonical_bytes().unwrap(),
            second.canonical_bytes().unwrap()
        );
        crate::identity::require_canonical(&first.canonical_bytes().unwrap()).unwrap();
    }

    #[test]
    fn parser_limit_is_a_hard_error() {
        let limits = MirLimits {
            max_functions: 1,
            ..MirLimits::default()
        };
        let error = parse_mir_text(SAMPLE, limits).unwrap_err();
        assert!(matches!(
            error,
            MirError::LimitExceeded {
                resource: "functions",
                limit: 1
            }
        ));
    }

    #[test]
    fn parser_rejects_unterminated_function() {
        let text = "// WARNING: This output format is intended for human consumers only\n\
                    // and is subject to change without notice. Knock yourself out.\n\
                    fn f() -> () {\n";
        let error = parse_mir_text(text, MirLimits::default()).unwrap_err();
        assert!(matches!(error, MirError::InvalidMir { .. }));
    }

    #[test]
    fn missing_toolchain_is_a_typed_not_run() {
        let adapter = MirAdapter::new().with_rustup_program("/nonexistent/frf-rustup-probe");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mir/source.rs");
        let outcome = adapter.scan(fixture).unwrap();
        match outcome {
            MirScanOutcome::NotRun(not_run) => {
                assert_eq!(not_run.reason, MirNotRunReason::RustupExecutableNotFound);
                assert_eq!(not_run.status, MirRunStatus::NotRun);
                assert_eq!(not_run.toolchain, MIR_TOOLCHAIN);
            }
            MirScanOutcome::Live(_) => panic!("missing rustup must not produce a live result"),
        }
    }

    #[test]
    fn non_rust_input_is_a_usage_error() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md");
        let error = MirAdapter::new().scan(path).unwrap_err();
        assert!(matches!(error, MirError::NotRustSource { .. }));
        assert_eq!(error.category(), MirErrorCategory::Usage);
    }
}
