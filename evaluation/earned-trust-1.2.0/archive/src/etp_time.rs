#![allow(clippy::module_name_repetitions)]

//! Phase 10.4a RFC 3161 trusted-time adapter and verification.
//!
//! # What this module establishes
//!
//! A verified timestamp token establishes only that a timestamp authority
//! signed a token whose message imprint equals a declared digest and that the
//! signer chains to a caller-supplied pinned certificate at the token's
//! generation time. It does **not** establish when the underlying evidence was
//! created, produced, executed, reviewed, authenticated, included in a
//! transparency log, or authorized for release.
//!
//! # Trust domain
//!
//! The Phase 10.4a gate generates a local, test-only TSA under `target/`. The
//! committed token is therefore anchored in a local test trust domain, not an
//! external trusted timestamp authority. `external_trust` is always `false`.
//!
//! # Process discipline
//!
//! The adapter invokes the pinned OpenSSL executable with an explicit argument
//! vector and without a shell. It clears the environment, uses a private
//! `0700` working directory, bounds wall time and captured output, and records
//! the exact argv, executable version, digests, and return status.

use std::cmp::Ordering;
use std::fmt;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::etp::ETP_SPEC;
use crate::etp_auth::DimensionState;
use crate::identity::hex_lower;

/// Verification report schema identifier.
pub const TIME_REPORT_SCHEMA: &str = "frf-etp.time-verification.v1";
/// Token creation report schema identifier.
pub const TIME_STAMP_REPORT_SCHEMA: &str = "frf-etp.time-stamp.v1";
/// Claim ceiling carried by every time report.
pub const TIME_CLAIM_CEILING: &str = "A verified RFC 3161 token establishes only that a timestamp authority whose certificate chains to the caller-supplied pinned certificate signed a token with the declared message imprint and generation time. It does not establish source creation, experimental execution, evidence production, statement authentication, transparency inclusion, witness observation, release authorization, or correction time. A later timestamp is not proof of an earlier execution date, and a local test TSA is not external trusted time.";
/// Default trust-domain label for a caller-pinned TSA certificate.
pub const PINNED_TSA_TRUST_DOMAIN: &str = "pinned-tsa-certificate";
/// Trust-domain label used by the Phase 10.4a local test TSA.
pub const LOCAL_TEST_TSA_TRUST_DOMAIN: &str = "local-test-tsa";
/// Trust-domain label when no trust anchor was supplied.
pub const UNPINNED_TRUST_DOMAIN: &str = "unpinned";
/// Maximum captured stdout or stderr bytes per command.
pub const MAX_TIME_CAPTURE_BYTES: u64 = 256 * 1024;
/// Maximum token bytes read for digesting.
pub const MAX_TOKEN_BYTES: u64 = 4 * 1024 * 1024;
/// Default command timeout in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
/// Maximum accepted command timeout in milliseconds.
pub const MAX_TIMEOUT_MS: u64 = 120_000;
/// Clock skew allowance for a token generated slightly in the future.
pub const FUTURE_SKEW_SECONDS: u64 = 300;

/// A temporal fact is reported separately from a validity dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalFact {
    /// The token or evidence directly supports this fact.
    Observed,
    /// This run did not observe this fact.
    NotObserved,
    /// The capability is not implemented in Phase 10.4a.
    NotImplemented,
}

impl TemporalFact {
    /// Stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::NotObserved => "not_observed",
            Self::NotImplemented => "not_implemented",
        }
    }
}

/// The nine temporal facts that must stay separate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalDimensions {
    /// When the source was created.
    pub source_creation: TemporalFact,
    /// When the experiment executed.
    pub experimental_execution: TemporalFact,
    /// When the evidence was produced.
    pub evidence_production: TemporalFact,
    /// When a statement was authenticated by a signer.
    pub statement_authentication: TemporalFact,
    /// Whether a trusted timestamp was verified.
    pub trusted_timestamping: TemporalFact,
    /// Transparency-log inclusion. Not implemented in Phase 10.4a.
    pub transparency_inclusion: TemporalFact,
    /// Witness observation. Not implemented in Phase 10.4a.
    pub witness_observation: TemporalFact,
    /// Release authorization.
    pub release_authorization: TemporalFact,
    /// Correction or revocation time.
    pub correction_revocation: TemporalFact,
}

impl Default for TemporalDimensions {
    fn default() -> Self {
        Self {
            source_creation: TemporalFact::NotObserved,
            experimental_execution: TemporalFact::NotObserved,
            evidence_production: TemporalFact::NotObserved,
            statement_authentication: TemporalFact::NotObserved,
            trusted_timestamping: TemporalFact::NotObserved,
            transparency_inclusion: TemporalFact::NotImplemented,
            witness_observation: TemporalFact::NotImplemented,
            release_authorization: TemporalFact::NotObserved,
            correction_revocation: TemporalFact::NotObserved,
        }
    }
}

/// Separate verification dimensions for a timestamp token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeDimensions {
    /// The token parsed into `TSTInfo` fields.
    pub token_integrity: DimensionState,
    /// The token imprint equals the declared digest.
    pub imprint: DimensionState,
    /// The token's hash algorithm is SHA-256.
    pub hash_algorithm: DimensionState,
    /// The CMS signature chains to the pinned certificate at the token time.
    pub signature_chain: DimensionState,
    /// The policy OID equals the expected policy OID, when one was supplied.
    pub policy_oid: DimensionState,
    /// The pinned certificate digest equals the expected digest, when supplied.
    pub certificate_pin: DimensionState,
    /// The generation time parsed and is internally consistent.
    pub gen_time: DimensionState,
}

/// Classification of a caller-declared execution time relative to the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackdatingClassification {
    /// The caller did not declare an execution time.
    NotRequested,
    /// The declared time precedes the token generation time.
    DeclaredPrecedesTimestamp,
    /// The declared time equals the token generation time.
    DeclaredEqualsTimestamp,
    /// The declared time follows the token generation time.
    DeclaredFollowsTimestamp,
}

impl BackdatingClassification {
    /// Stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRequested => "not_requested",
            Self::DeclaredPrecedesTimestamp => "declared_precedes_timestamp",
            Self::DeclaredEqualsTimestamp => "declared_equals_timestamp",
            Self::DeclaredFollowsTimestamp => "declared_follows_timestamp",
        }
    }
}

/// Backdating control result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackdatingReport {
    /// The caller's declared execution time, if any.
    pub declared_execution_unix: Option<u64>,
    /// Token generation time, if parsed.
    pub gen_time_unix: Option<u64>,
    /// Classification of the declared time.
    pub classification: BackdatingClassification,
    /// Always `false`: a token never establishes the execution time.
    pub execution_time_established: bool,
    /// Exact explanation.
    pub detail: String,
}

/// Stable refusal codes for timestamp verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeRefusalCode {
    /// The token could not be parsed as a granted timestamp response.
    InvalidToken,
    /// The token imprint differs from the declared imprint.
    ImprintMismatch,
    /// The token hash algorithm is not SHA-256.
    HashAlgorithmMismatch,
    /// No pinned trust anchor was supplied.
    NoTrustAnchor,
    /// The signature chain does not verify to the pinned certificate.
    UntrustedTsa,
    /// The signer certificate was expired at the verification time.
    ExpiredTsa,
    /// The token policy OID differs from the expected policy OID.
    PolicyOidMismatch,
    /// The pinned certificate digest differs from the expected digest.
    CertificatePinMismatch,
    /// The token generation time is in the future.
    FutureTimestamp,
    /// The caller declared an execution time earlier than the token.
    BackdatedClaim,
    /// The caller's declared execution time is not established by the token.
    ExecutionTimeNotEstablished,
}

impl TimeRefusalCode {
    /// Stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidToken => "invalid_token",
            Self::ImprintMismatch => "imprint_mismatch",
            Self::HashAlgorithmMismatch => "hash_algorithm_mismatch",
            Self::NoTrustAnchor => "no_trust_anchor",
            Self::UntrustedTsa => "untrusted_tsa",
            Self::ExpiredTsa => "expired_tsa",
            Self::PolicyOidMismatch => "policy_oid_mismatch",
            Self::CertificatePinMismatch => "certificate_pin_mismatch",
            Self::FutureTimestamp => "future_timestamp",
            Self::BackdatedClaim => "backdated_claim",
            Self::ExecutionTimeNotEstablished => "execution_time_not_established",
        }
    }
}

/// One timestamp refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeRefusal {
    /// Stable code.
    pub code: TimeRefusalCode,
    /// Exact detail.
    pub detail: String,
}

/// Overall timestamp verification status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeStatus {
    /// The token verified under the declared trust anchor.
    Verified,
    /// The token is structurally valid but the declared use was refused.
    Refused,
}

impl TimeStatus {
    /// Stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Refused => "refused",
        }
    }
}

/// Exact command provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeProvenance {
    /// Exact OpenSSL executable path used for the operation.
    pub program: String,
    /// OpenSSL version string.
    pub openssl_version: String,
    /// Exact argument vector. `argv[0]` is the resolved executable path.
    pub argv: Vec<String>,
    /// Private working directory. It is removed after the operation.
    pub work_directory: String,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Return status.
    pub return_code: i32,
    /// SHA-256 of captured stdout.
    pub stdout_sha256: String,
    /// SHA-256 of captured stderr.
    pub stderr_sha256: String,
}

/// A timestamp verification report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeReport {
    /// Schema identifier.
    pub schema: String,
    /// ETP specification identifier.
    pub spec: String,
    /// Overall status.
    pub status: TimeStatus,
    /// SHA-256 of the exact token bytes.
    pub token_sha256: String,
    /// SHA-256 of the exact timestamp request, when retained.
    pub request_sha256: Option<String>,
    /// The declared evidence imprint.
    pub imprint_expected: String,
    /// The imprint parsed from the token's `TSTInfo`.
    pub imprint_in_token: Option<String>,
    /// The token hash algorithm.
    pub hash_algorithm: Option<String>,
    /// The token policy OID.
    pub policy_oid: Option<String>,
    /// The expected policy OID, when supplied.
    pub expected_policy_oid: Option<String>,
    /// The token serial number in lowercase hexadecimal without `0x`.
    pub serial: Option<String>,
    /// Token generation time as Unix seconds.
    pub gen_time_unix: Option<u64>,
    /// Token generation time as printed by OpenSSL.
    pub gen_time_text: Option<String>,
    /// `historical`, `current`, or `future` relative to the verification clock.
    pub gen_time_relation: String,
    /// Accuracy field as printed by OpenSSL.
    pub accuracy: Option<String>,
    /// Ordering field as printed by OpenSSL.
    pub ordering: Option<String>,
    /// TSA subject as printed by OpenSSL.
    pub tsa_name: Option<String>,
    /// SHA-256 of the DER-encoded pinned certificate.
    pub tsa_cert_sha256: Option<String>,
    /// Pinned certificate subject.
    pub tsa_cert_subject: Option<String>,
    /// Pinned certificate validity dates as printed by OpenSSL.
    pub tsa_cert_dates: Option<String>,
    /// Declared trust-domain label.
    pub trust_domain: String,
    /// Always `false` in Phase 10.4a: no external trusted TSA is used.
    pub external_trust: bool,
    /// Whether a caller-supplied certificate pinned the trust anchor.
    pub pinned_certificate: bool,
    /// Separate verification dimensions.
    pub dimensions: TimeDimensions,
    /// Separate temporal facts.
    pub time_dimensions: TemporalDimensions,
    /// Always `false`: a timestamp does not establish execution time.
    pub execution_time_established: bool,
    /// Exactly what the token establishes.
    pub trusted_time_establishes: String,
    /// Backdating control.
    pub backdating: BackdatingReport,
    /// Provenance of the verification command.
    pub provenance: TimeProvenance,
    /// Refusals.
    pub refusals: Vec<TimeRefusal>,
    /// Features that are not implemented.
    pub unsupported_features: Vec<String>,
    /// Explicit limitations.
    pub limitations: Vec<String>,
    /// Claim ceiling.
    pub claim_ceiling: String,
}

impl TimeReport {
    /// Whether every required dimension is valid and no use was refused.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.status == TimeStatus::Verified
    }

    /// `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self.status {
            TimeStatus::Verified => 0,
            TimeStatus::Refused => 4,
        }
    }
}

/// A timestamp creation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StampReport {
    /// Schema identifier.
    pub schema: String,
    /// ETP specification identifier.
    pub spec: String,
    /// Overall status.
    pub status: TimeStatus,
    /// Declared evidence imprint.
    pub imprint: String,
    /// SHA-256 of the exact timestamp request.
    pub request_sha256: String,
    /// SHA-256 of the exact token.
    pub token_sha256: String,
    /// Token generation time as Unix seconds.
    pub gen_time_unix: Option<u64>,
    /// Token generation time as printed by OpenSSL.
    pub gen_time_text: Option<String>,
    /// Token policy OID.
    pub policy_oid: Option<String>,
    /// Token serial number.
    pub serial: Option<String>,
    /// SHA-256 of the DER-encoded TSA certificate, when supplied.
    pub tsa_cert_sha256: Option<String>,
    /// Trust-domain label. Token creation is always a local test operation.
    pub trust_domain: String,
    /// Always `false` in Phase 10.4a.
    pub external_trust: bool,
    /// Provenance of the reply command.
    pub provenance: TimeProvenance,
    /// Refusals.
    pub refusals: Vec<TimeRefusal>,
    /// Claim ceiling.
    pub claim_ceiling: String,
}

/// Errors from the trusted-time adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeError {
    /// An I/O operation failed or a required input is missing.
    Io {
        /// Diagnostic.
        message: String,
    },
    /// An input is structurally invalid.
    Invalid {
        /// Diagnostic.
        message: String,
    },
    /// The external tool is unavailable.
    ToolUnavailable {
        /// Diagnostic.
        message: String,
    },
    /// The external tool exceeded the bounded wall time.
    Timeout {
        /// Diagnostic.
        message: String,
    },
    /// The external tool exceeded the bounded output size.
    OutputLimit {
        /// Diagnostic.
        message: String,
    },
    /// Canonical encoding failed.
    Canonical {
        /// Diagnostic.
        message: String,
    },
}

impl TimeError {
    /// `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Canonical { .. } => 7,
            Self::Io { .. } | Self::Invalid { .. } => 3,
            Self::ToolUnavailable { .. } | Self::Timeout { .. } | Self::OutputLimit { .. } => 6,
        }
    }
}

impl fmt::Display for TimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { message } => write!(formatter, "trusted-time I/O failure: {message}"),
            Self::Invalid { message } => write!(formatter, "trusted-time input failure: {message}"),
            Self::ToolUnavailable { message } => {
                write!(formatter, "trusted-time tool unavailable: {message}")
            }
            Self::Timeout { message } => write!(formatter, "trusted-time timeout: {message}"),
            Self::OutputLimit { message } => {
                write!(formatter, "trusted-time output limit: {message}")
            }
            Self::Canonical { message } => {
                write!(formatter, "trusted-time encoding failure: {message}")
            }
        }
    }
}

impl std::error::Error for TimeError {}

/// Inputs for token verification.
#[derive(Debug, Clone)]
pub struct VerifyTokenRequest<'a> {
    /// Exact token file.
    pub token_path: &'a Path,
    /// Expected SHA-256 imprint, lowercase hexadecimal.
    pub imprint_hex: &'a str,
    /// Pinned TSA certificate (PEM).
    pub tsa_cert_path: Option<&'a Path>,
    /// Optional untrusted intermediate certificate (PEM).
    pub untrusted_path: Option<&'a Path>,
    /// Optional expected policy OID.
    pub expected_policy_oid: Option<&'a str>,
    /// Optional expected pinned certificate SHA-256.
    pub expected_tsa_cert_sha256: Option<&'a str>,
    /// Optional trust-domain label.
    pub trust_domain: Option<&'a str>,
    /// Verify the chain at this Unix time instead of the token generation time.
    pub verify_at_unix: Option<u64>,
    /// Verification clock for the future check.
    pub now_unix: u64,
    /// Optional declared experimental execution time.
    pub declared_execution_unix: Option<u64>,
    /// OpenSSL executable.
    pub openssl_bin: &'a Path,
    /// Parent directory for the private working directory.
    pub work_dir: &'a Path,
    /// Bounded wall time in milliseconds.
    pub timeout_ms: u64,
}

/// Inputs for token creation.
#[derive(Debug, Clone)]
pub struct StampTokenRequest<'a> {
    /// Expected SHA-256 imprint, lowercase hexadecimal.
    pub imprint_hex: &'a str,
    /// OpenSSL TSA configuration file.
    pub tsa_config: &'a Path,
    /// Optional TSA configuration section.
    pub tsa_section: Option<&'a str>,
    /// Output token path.
    pub out_token: &'a Path,
    /// Optional output timestamp-request path.
    pub out_request: Option<&'a Path>,
    /// Optional TSA certificate (PEM) for digest recording.
    pub tsa_cert_path: Option<&'a Path>,
    /// OpenSSL executable.
    pub openssl_bin: &'a Path,
    /// Parent directory for the private working directory.
    pub work_dir: &'a Path,
    /// Bounded wall time in milliseconds.
    pub timeout_ms: u64,
}

struct CommandOutcome {
    status: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    duration_ms: u64,
    argv: Vec<String>,
    program: String,
}

#[derive(Debug, Clone, Default)]
struct TstInfo {
    policy_oid: Option<String>,
    hash_algorithm: Option<String>,
    imprint: Option<String>,
    serial: Option<String>,
    gen_time_text: Option<String>,
    gen_time_unix: Option<u64>,
    accuracy: Option<String>,
    ordering: Option<String>,
    tsa_name: Option<String>,
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn normalize_hex_64(label: &str, value: &str) -> Result<String, TimeError> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != 64
        || !normalized
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(TimeError::Invalid {
            message: format!("{label} must be exactly 64 lowercase hexadecimal characters"),
        });
    }
    Ok(normalized)
}

fn check_timeout(timeout_ms: u64) -> Result<Duration, TimeError> {
    if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
        return Err(TimeError::Invalid {
            message: format!("timeout must be between 1 and {MAX_TIMEOUT_MS} ms"),
        });
    }
    Ok(Duration::from_millis(timeout_ms))
}

fn resolve_program(name: &Path) -> Result<PathBuf, TimeError> {
    if name.is_absolute() {
        return Ok(name.to_path_buf());
    }
    if name.components().count() > 1 {
        return std::path::absolute(name).map_err(|error| TimeError::Io {
            message: format!("cannot resolve {}: {error}", name.display()),
        });
    }
    let Some(path) = std::env::var_os("PATH") else {
        return Err(TimeError::ToolUnavailable {
            message: format!("cannot resolve {}: PATH is unset", name.display()),
        });
    };
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(TimeError::ToolUnavailable {
        message: format!("cannot find {} on PATH", name.display()),
    })
}

fn absolute_path(path: &Path) -> Result<PathBuf, TimeError> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::path::absolute(path).map_err(|error| TimeError::Io {
        message: format!("cannot resolve {}: {error}", path.display()),
    })
}

fn private_directory(parent: &Path, prefix: &str) -> Result<PathBuf, TimeError> {
    fs::create_dir_all(parent).map_err(|error| TimeError::Io {
        message: format!("cannot create {}: {error}", parent.display()),
    })?;
    let parent = absolute_path(parent)?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let path = parent.join(format!("{prefix}-{}-{nanos}", std::process::id()));
    fs::create_dir(&path).map_err(|error| TimeError::Io {
        message: format!(
            "cannot create private directory {}: {error}",
            path.display()
        ),
    })?;
    secure_directory(&path)?;
    Ok(path)
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<(), TimeError> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| TimeError::Io {
        message: format!(
            "cannot set private permissions on {}: {error}",
            path.display()
        ),
    })
}

#[cfg(not(unix))]
fn secure_directory(_path: &Path) -> Result<(), TimeError> {
    Ok(())
}

#[cfg(unix)]
fn private_file(path: &Path) -> Result<fs::File, TimeError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| TimeError::Io {
            message: format!("cannot create {}: {error}", path.display()),
        })
}

#[cfg(not(unix))]
fn private_file(path: &Path) -> Result<fs::File, TimeError> {
    fs::File::create(path).map_err(|error| TimeError::Io {
        message: format!("cannot create {}: {error}", path.display()),
    })
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), TimeError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| TimeError::Io {
            message: format!("cannot create {}: {error}", parent.display()),
        })?;
    }
    let mut file = private_file(path)?;
    file.write_all(bytes).map_err(|error| TimeError::Io {
        message: format!("cannot write {}: {error}", path.display()),
    })
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, TimeError> {
    let metadata = fs::metadata(path).map_err(|error| TimeError::Io {
        message: format!("cannot stat {}: {error}", path.display()),
    })?;
    if metadata.len() > MAX_TIME_CAPTURE_BYTES {
        return Err(TimeError::OutputLimit {
            message: format!(
                "{} is {} bytes, limit {MAX_TIME_CAPTURE_BYTES}",
                path.display(),
                metadata.len()
            ),
        });
    }
    fs::read(path).map_err(|error| TimeError::Io {
        message: format!("cannot read {}: {error}", path.display()),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn run_command(
    program: &Path,
    arguments: &[String],
    cwd: &Path,
    tag: &str,
    timeout: Duration,
) -> Result<CommandOutcome, TimeError> {
    let resolved = resolve_program(program)?;
    let stdout_path = cwd.join(format!("{tag}.stdout"));
    let stderr_path = cwd.join(format!("{tag}.stderr"));
    let stdout_file = private_file(&stdout_path)?;
    let stderr_file = private_file(&stderr_path)?;

    let mut command = Command::new(&resolved);
    command
        .args(arguments)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .env_clear();

    let start = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| TimeError::ToolUnavailable {
            message: format!("cannot execute {}: {error}", resolved.display()),
        })?;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(TimeError::Timeout {
                        message: format!("{} exceeded {timeout:?}", resolved.display()),
                    });
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(TimeError::ToolUnavailable {
                    message: format!("cannot wait for {}: {error}", resolved.display()),
                });
            }
        }
    };
    let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let stdout = read_bounded(&stdout_path)?;
    let stderr = read_bounded(&stderr_path)?;
    let mut argv = vec![resolved.display().to_string()];
    argv.extend(arguments.iter().cloned());
    Ok(CommandOutcome {
        status: status.code().unwrap_or(-1),
        stdout,
        stderr,
        duration_ms,
        argv,
        program: resolved.display().to_string(),
    })
}

fn provenance(outcome: &CommandOutcome, openssl_version: &str, work: &Path) -> TimeProvenance {
    TimeProvenance {
        program: outcome.program.clone(),
        openssl_version: openssl_version.to_owned(),
        argv: outcome.argv.clone(),
        work_directory: format!("{} (removed)", work.display()),
        duration_ms: outcome.duration_ms,
        return_code: outcome.status,
        stdout_sha256: sha256_hex(&outcome.stdout),
        stderr_sha256: sha256_hex(&outcome.stderr),
    }
}

fn openssl_version(openssl: &Path, work: &Path, timeout: Duration) -> Result<String, TimeError> {
    let outcome = run_command(openssl, &["version".to_owned()], work, "version", timeout)?;
    if outcome.status != 0 {
        return Err(TimeError::ToolUnavailable {
            message: format!(
                "openssl version exited {}: {}",
                outcome.status,
                String::from_utf8_lossy(&outcome.stderr)
            ),
        });
    }
    Ok(String::from_utf8_lossy(&outcome.stdout).trim().to_owned())
}

fn text_field<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.strip_prefix(prefix).map(str::trim))
        .filter(|value| !value.is_empty())
}

fn parse_message_data(text: &str) -> Option<String> {
    let mut started = false;
    let mut hex = String::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("Message data:") {
            started = true;
            continue;
        }
        if !started {
            continue;
        }
        if trimmed.starts_with("Serial number:") || trimmed.starts_with("Time stamp:") {
            break;
        }
        if trimmed.len() < 8 || trimmed.as_bytes().get(4) != Some(&b' ') {
            continue;
        }
        let rest = &trimmed[7..];
        let chunk: String = rest.chars().take(48).collect();
        let row: String = chunk
            .chars()
            .filter(char::is_ascii_hexdigit)
            .collect::<String>()
            .to_ascii_lowercase();
        if row.len() % 2 == 0 {
            hex.push_str(&row);
        }
    }
    if hex.is_empty() {
        None
    } else {
        Some(hex)
    }
}

fn month_number(name: &str) -> Option<u32> {
    match name {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = i64::from((month + 9) % 12);
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Parse OpenSSL's `ASN1_TIME_print` format, for example
/// `Nov 22 07:09:52 2026 GMT`.
fn parse_openssl_time(text: &str) -> Option<u64> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let month = month_number(parts[0])?;
    let day = parts[1].parse::<u32>().ok()?;
    let clock: Vec<&str> = parts[2].split(':').collect();
    if clock.len() != 3 {
        return None;
    }
    let hour = clock[0].parse::<u64>().ok()?;
    let minute = clock[1].parse::<u64>().ok()?;
    let second = clock[2].parse::<u64>().ok()?;
    let year = parts[3].parse::<i64>().ok()?;
    if let Some(zone) = parts.get(4) {
        if *zone != "GMT" && *zone != "UTC" {
            return None;
        }
    }
    if hour > 23 || minute > 59 || second > 60 || day == 0 || day > 31 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    if days < 0 {
        return None;
    }
    let seconds = u64::try_from(days).ok()? * 86_400 + hour * 3_600 + minute * 60 + second;
    Some(seconds)
}

fn parse_tst_info(text: &str) -> Option<TstInfo> {
    if !text.contains("Status: Granted.") {
        return None;
    }
    let serial = text_field(text, "Serial number:").map(|value| {
        value
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .to_ascii_lowercase()
    });
    let gen_time_text = text_field(text, "Time stamp:").map(str::to_owned);
    let gen_time_unix = gen_time_text.as_deref().and_then(parse_openssl_time);
    Some(TstInfo {
        policy_oid: text_field(text, "Policy OID:").map(str::to_owned),
        hash_algorithm: text_field(text, "Hash Algorithm:").map(str::to_owned),
        imprint: parse_message_data(text),
        serial: serial.filter(|value| !value.is_empty()),
        gen_time_text,
        gen_time_unix,
        accuracy: text_field(text, "Accuracy:").map(str::to_owned),
        ordering: text_field(text, "Ordering:").map(str::to_owned),
        tsa_name: text_field(text, "TSA:").map(str::to_owned),
    })
}

fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, TimeError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let text = String::from_utf8_lossy(pem);
    let mut collected = String::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN") {
            inside = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if inside {
            collected.push_str(line);
        }
    }
    if collected.is_empty() {
        return Err(TimeError::Invalid {
            message: "pinned certificate is not PEM".to_owned(),
        });
    }
    STANDARD
        .decode(collected)
        .map_err(|error| TimeError::Invalid {
            message: format!("pinned certificate is not valid PEM base64: {error}"),
        })
}

fn certificate_sha256(path: &Path) -> Result<String, TimeError> {
    let bytes = fs::read(path).map_err(|error| TimeError::Io {
        message: format!("cannot read {}: {error}", path.display()),
    })?;
    Ok(sha256_hex(&pem_to_der(&bytes)?))
}

fn classify_verify_failure(stderr: &str) -> TimeRefusalCode {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("message imprint mismatch") {
        TimeRefusalCode::ImprintMismatch
    } else if lower.contains("certificate has expired") || lower.contains("has expired") {
        TimeRefusalCode::ExpiredTsa
    } else if lower.contains("certificate verify error") || lower.contains("unable to get") {
        TimeRefusalCode::UntrustedTsa
    } else if lower.contains("policy") && lower.contains("not acceptable") {
        TimeRefusalCode::PolicyOidMismatch
    } else {
        TimeRefusalCode::InvalidToken
    }
}

fn push_refusal(refusals: &mut Vec<TimeRefusal>, code: TimeRefusalCode, detail: String) {
    if !refusals.iter().any(|refusal| refusal.code == code) {
        refusals.push(TimeRefusal { code, detail });
    }
}

fn gen_time_relation(gen_time: Option<u64>, now: u64) -> String {
    match gen_time {
        None => "unparsed".to_owned(),
        Some(value) if value > now.saturating_add(FUTURE_SKEW_SECONDS) => "future".to_owned(),
        Some(value) if value + FUTURE_SKEW_SECONDS < now => "historical".to_owned(),
        Some(_) => "current".to_owned(),
    }
}

fn base_time_report(
    imprint_expected: String,
    trust_domain: String,
    provenance: TimeProvenance,
) -> TimeReport {
    TimeReport {
        schema: TIME_REPORT_SCHEMA.to_owned(),
        spec: ETP_SPEC.to_owned(),
        status: TimeStatus::Refused,
        token_sha256: String::new(),
        request_sha256: None,
        imprint_expected,
        imprint_in_token: None,
        hash_algorithm: None,
        policy_oid: None,
        expected_policy_oid: None,
        serial: None,
        gen_time_unix: None,
        gen_time_text: None,
        gen_time_relation: "unparsed".to_owned(),
        accuracy: None,
        ordering: None,
        tsa_name: None,
        tsa_cert_sha256: None,
        tsa_cert_subject: None,
        tsa_cert_dates: None,
        trust_domain,
        external_trust: false,
        pinned_certificate: false,
        dimensions: TimeDimensions {
            token_integrity: DimensionState::Invalid,
            imprint: DimensionState::NotChecked,
            hash_algorithm: DimensionState::NotChecked,
            signature_chain: DimensionState::NotChecked,
            policy_oid: DimensionState::NotChecked,
            certificate_pin: DimensionState::NotChecked,
            gen_time: DimensionState::NotChecked,
        },
        time_dimensions: TemporalDimensions::default(),
        execution_time_established: false,
        trusted_time_establishes: "that the declared digest was presented to the timestamp authority and that the token was signed at its generation time; not when the evidence was produced, executed, authenticated, reviewed, included, or released".to_owned(),
        backdating: BackdatingReport {
            declared_execution_unix: None,
            gen_time_unix: None,
            classification: BackdatingClassification::NotRequested,
            execution_time_established: false,
            detail: "a timestamp never establishes the experimental execution time".to_owned(),
        },
        provenance,
        refusals: Vec::new(),
        unsupported_features: vec![
            "external_trusted_tsa".to_owned(),
            "transparency_inclusion".to_owned(),
            "witness_observation".to_owned(),
            "public_revocation_feed".to_owned(),
        ],
        limitations: vec![
            "the Phase 10.4a token is anchored in a local test TSA, not an external trusted authority".to_owned(),
            "a timestamp binds a digest at generation time and is not proof of an earlier execution date".to_owned(),
            "no transparency-log inclusion or witness observation is implemented".to_owned(),
        ],
        claim_ceiling: TIME_CLAIM_CEILING.to_owned(),
    }
}

/// Verify an RFC 3161 timestamp token against a declared imprint and pinned TSA.
///
/// # Errors
///
/// Returns [`TimeError`] when an input is missing or malformed, the bounded
/// command cannot run, or captured output exceeds the limit. Semantic
/// refusals are returned in [`TimeReport::refusals`].
#[allow(clippy::too_many_lines)]
pub fn verify_token(request: &VerifyTokenRequest<'_>) -> Result<TimeReport, TimeError> {
    let imprint = normalize_hex_64("imprint", request.imprint_hex)?;
    let timeout = check_timeout(request.timeout_ms)?;

    let token_metadata = fs::metadata(request.token_path).map_err(|error| TimeError::Io {
        message: format!(
            "cannot read token {}: {error}",
            request.token_path.display()
        ),
    })?;
    if !token_metadata.is_file() {
        return Err(TimeError::Io {
            message: format!("{} is not a regular file", request.token_path.display()),
        });
    }
    if token_metadata.len() > MAX_TOKEN_BYTES {
        return Err(TimeError::OutputLimit {
            message: format!(
                "token {} exceeds {MAX_TOKEN_BYTES} bytes",
                request.token_path.display()
            ),
        });
    }
    let token_bytes = fs::read(request.token_path).map_err(|error| TimeError::Io {
        message: format!(
            "cannot read token {}: {error}",
            request.token_path.display()
        ),
    })?;
    let token_sha256 = sha256_hex(&token_bytes);

    let work = private_directory(request.work_dir, "time-verify")?;
    let result = verify_token_inner(request, &imprint, &token_sha256, &work, timeout);
    let _ = fs::remove_dir_all(&work);
    result
}

#[allow(clippy::too_many_lines)]
fn verify_token_inner(
    request: &VerifyTokenRequest<'_>,
    imprint: &str,
    token_sha256: &str,
    work: &Path,
    timeout: Duration,
) -> Result<TimeReport, TimeError> {
    let version = openssl_version(request.openssl_bin, work, timeout)?;
    let token_path = absolute_path(request.token_path)?;
    let token_arg = token_path.display().to_string();
    let tsa_cert_path = request.tsa_cert_path.map(absolute_path).transpose()?;
    let untrusted_path = request.untrusted_path.map(absolute_path).transpose()?;

    let reply = run_command(
        request.openssl_bin,
        &[
            "ts".to_owned(),
            "-reply".to_owned(),
            "-in".to_owned(),
            token_arg.clone(),
            "-text".to_owned(),
            "-token_in".to_owned(),
        ],
        work,
        "reply-text",
        timeout,
    )?;
    let reply_text = String::from_utf8_lossy(&reply.stdout).into_owned();
    let info = parse_tst_info(&reply_text).ok_or_else(|| TimeError::Invalid {
        message: format!(
            "token is not a granted RFC 3161 response: {}",
            String::from_utf8_lossy(&reply.stderr).trim()
        ),
    })?;

    let trust_domain = request
        .trust_domain
        .unwrap_or(PINNED_TSA_TRUST_DOMAIN)
        .to_owned();
    let mut report = base_time_report(
        imprint.to_owned(),
        trust_domain,
        provenance(&reply, &version, work),
    );
    token_sha256.clone_into(&mut report.token_sha256);
    report.imprint_in_token.clone_from(&info.imprint);
    report.hash_algorithm.clone_from(&info.hash_algorithm);
    report.policy_oid.clone_from(&info.policy_oid);
    report.expected_policy_oid = request.expected_policy_oid.map(str::to_owned);
    report.serial.clone_from(&info.serial);
    report.gen_time_unix = info.gen_time_unix;
    report.gen_time_text.clone_from(&info.gen_time_text);
    report.gen_time_relation = gen_time_relation(info.gen_time_unix, request.now_unix);
    report.accuracy.clone_from(&info.accuracy);
    report.ordering.clone_from(&info.ordering);
    report.tsa_name.clone_from(&info.tsa_name);
    report.dimensions.token_integrity = DimensionState::Valid;
    report.dimensions.gen_time = if info.gen_time_unix.is_some() {
        DimensionState::Valid
    } else {
        DimensionState::Invalid
    };

    if info.imprint.as_deref() == Some(imprint) {
        report.dimensions.imprint = DimensionState::Valid;
    } else {
        report.dimensions.imprint = DimensionState::Invalid;
        push_refusal(
            &mut report.refusals,
            TimeRefusalCode::ImprintMismatch,
            format!(
                "token imprint {:?} does not equal declared imprint {imprint}",
                info.imprint
            ),
        );
    }

    if info.hash_algorithm.as_deref() == Some("sha256") {
        report.dimensions.hash_algorithm = DimensionState::Valid;
    } else {
        report.dimensions.hash_algorithm = DimensionState::Invalid;
        push_refusal(
            &mut report.refusals,
            TimeRefusalCode::HashAlgorithmMismatch,
            format!(
                "token hash algorithm {:?} is not sha256",
                info.hash_algorithm
            ),
        );
    }

    if let Some(expected) = request.expected_policy_oid {
        if info.policy_oid.as_deref() == Some(expected) {
            report.dimensions.policy_oid = DimensionState::Valid;
        } else {
            report.dimensions.policy_oid = DimensionState::Invalid;
            push_refusal(
                &mut report.refusals,
                TimeRefusalCode::PolicyOidMismatch,
                format!(
                    "token policy OID {:?} does not equal expected {expected}",
                    info.policy_oid
                ),
            );
        }
    } else {
        report.dimensions.policy_oid = DimensionState::NotChecked;
    }

    if let Some(gen_time) = info.gen_time_unix {
        if gen_time > request.now_unix.saturating_add(FUTURE_SKEW_SECONDS) {
            push_refusal(
                &mut report.refusals,
                TimeRefusalCode::FutureTimestamp,
                format!("token generation time {gen_time} is in the future"),
            );
        }
    }

    let Some(tsa_cert) = tsa_cert_path else {
        report.dimensions.signature_chain = DimensionState::NotChecked;
        report.dimensions.certificate_pin = DimensionState::NotChecked;
        push_refusal(
            &mut report.refusals,
            TimeRefusalCode::NoTrustAnchor,
            "no pinned TSA certificate was supplied; the signature chain was not verified"
                .to_owned(),
        );
        apply_backdating(&mut report, request.declared_execution_unix);
        report.status = TimeStatus::Refused;
        return Ok(report);
    };

    let cert_sha256 = certificate_sha256(&tsa_cert)?;
    report.tsa_cert_sha256 = Some(cert_sha256.clone());
    report.pinned_certificate = true;
    if let Some(expected) = request.expected_tsa_cert_sha256 {
        let expected = normalize_hex_64("expected TSA certificate digest", expected)?;
        if expected == cert_sha256 {
            report.dimensions.certificate_pin = DimensionState::Valid;
        } else {
            report.dimensions.certificate_pin = DimensionState::Invalid;
            push_refusal(
                &mut report.refusals,
                TimeRefusalCode::CertificatePinMismatch,
                format!(
                    "pinned certificate digest {cert_sha256} does not equal expected {expected}"
                ),
            );
        }
    } else {
        report.dimensions.certificate_pin = DimensionState::NotChecked;
    }

    let x509 = run_command(
        request.openssl_bin,
        &[
            "x509".to_owned(),
            "-in".to_owned(),
            tsa_cert.display().to_string(),
            "-noout".to_owned(),
            "-subject".to_owned(),
            "-dates".to_owned(),
        ],
        work,
        "tsa-cert",
        timeout,
    )?;
    let x509_text = String::from_utf8_lossy(&x509.stdout).into_owned();
    report.tsa_cert_subject = text_field(&x509_text, "subject=").map(str::to_owned);
    let dates: Vec<&str> = x509_text
        .lines()
        .filter(|line| line.starts_with("notBefore=") || line.starts_with("notAfter="))
        .collect();
    if !dates.is_empty() {
        report.tsa_cert_dates = Some(dates.join("; "));
    }

    let verify_at = request
        .verify_at_unix
        .or(info.gen_time_unix)
        .unwrap_or(request.now_unix);
    let mut verify_argv = vec![
        "ts".to_owned(),
        "-verify".to_owned(),
        "-token_in".to_owned(),
        "-in".to_owned(),
        token_arg,
        "-digest".to_owned(),
        imprint.to_owned(),
        "-CAfile".to_owned(),
        tsa_cert.display().to_string(),
        "-attime".to_owned(),
        verify_at.to_string(),
    ];
    if let Some(untrusted) = untrusted_path.as_deref() {
        verify_argv.push("-untrusted".to_owned());
        verify_argv.push(untrusted.display().to_string());
    }
    if let Some(policy) = request.expected_policy_oid {
        verify_argv.push("-policy".to_owned());
        verify_argv.push(policy.to_owned());
    }
    let verify = run_command(
        request.openssl_bin,
        &verify_argv,
        work,
        "ts-verify",
        timeout,
    )?;
    let verify_ok =
        verify.status == 0 && String::from_utf8_lossy(&verify.stdout).contains("Verification: OK");
    if verify_ok {
        report.dimensions.signature_chain = DimensionState::Valid;
    } else {
        report.dimensions.signature_chain = DimensionState::Invalid;
        let code = classify_verify_failure(&String::from_utf8_lossy(&verify.stderr));
        push_refusal(
            &mut report.refusals,
            code,
            format!(
                "timestamp chain verification failed: {}",
                String::from_utf8_lossy(&verify.stderr).trim()
            ),
        );
    }

    apply_backdating(&mut report, request.declared_execution_unix);
    report.time_dimensions.trusted_timestamping = if report.refusals.is_empty() {
        TemporalFact::Observed
    } else {
        TemporalFact::NotObserved
    };
    report.status = if report.refusals.is_empty() {
        if report.dimensions.signature_chain == DimensionState::Valid
            && report.dimensions.imprint == DimensionState::Valid
        {
            TimeStatus::Verified
        } else {
            TimeStatus::Refused
        }
    } else {
        TimeStatus::Refused
    };
    Ok(report)
}

fn apply_backdating(report: &mut TimeReport, declared: Option<u64>) {
    let Some(declared) = declared else {
        report.backdating = BackdatingReport {
            declared_execution_unix: None,
            gen_time_unix: report.gen_time_unix,
            classification: BackdatingClassification::NotRequested,
            execution_time_established: false,
            detail: "no execution time was declared; a token does not establish one".to_owned(),
        };
        return;
    };
    let Some(gen_time) = report.gen_time_unix else {
        report.backdating = BackdatingReport {
            declared_execution_unix: Some(declared),
            gen_time_unix: None,
            classification: BackdatingClassification::NotRequested,
            execution_time_established: false,
            detail: "the token generation time could not be parsed".to_owned(),
        };
        return;
    };
    let (classification, detail) = match declared.cmp(&gen_time) {
        Ordering::Less => (
            BackdatingClassification::DeclaredPrecedesTimestamp,
            format!(
                "declared execution time {declared} precedes token generation time {gen_time}; the token does not prove the earlier date"
            ),
        ),
        Ordering::Equal => (
            BackdatingClassification::DeclaredEqualsTimestamp,
            "the declared time equals the token generation time; only token existence at that time is established".to_owned(),
        ),
        Ordering::Greater => (
            BackdatingClassification::DeclaredFollowsTimestamp,
            format!(
                "declared execution time {declared} follows token generation time {gen_time}; the token does not prove the later date"
            ),
        ),
    };
    report.backdating = BackdatingReport {
        declared_execution_unix: Some(declared),
        gen_time_unix: Some(gen_time),
        classification,
        execution_time_established: false,
        detail,
    };
    match classification {
        BackdatingClassification::DeclaredPrecedesTimestamp => push_refusal(
            &mut report.refusals,
            TimeRefusalCode::BackdatedClaim,
            report.backdating.detail.clone(),
        ),
        BackdatingClassification::DeclaredFollowsTimestamp => push_refusal(
            &mut report.refusals,
            TimeRefusalCode::ExecutionTimeNotEstablished,
            report.backdating.detail.clone(),
        ),
        BackdatingClassification::NotRequested
        | BackdatingClassification::DeclaredEqualsTimestamp => {}
    }
}

/// Create an RFC 3161 timestamp token for an exact digest using a local TSA.
///
/// # Errors
///
/// Returns [`TimeError`] for invalid inputs, a tool failure, a timeout, or an
/// output-limit violation.
#[allow(clippy::too_many_lines)]
pub fn stamp_token(request: &StampTokenRequest<'_>) -> Result<StampReport, TimeError> {
    let imprint = normalize_hex_64("imprint", request.imprint_hex)?;
    let timeout = check_timeout(request.timeout_ms)?;
    if !request.tsa_config.is_file() {
        return Err(TimeError::Io {
            message: format!("TSA config {} is missing", request.tsa_config.display()),
        });
    }
    let work = private_directory(request.work_dir, "time-stamp")?;
    let result = stamp_token_inner(request, &imprint, &work, timeout);
    let _ = fs::remove_dir_all(&work);
    result
}

#[allow(clippy::too_many_lines)]
fn stamp_token_inner(
    request: &StampTokenRequest<'_>,
    imprint: &str,
    work: &Path,
    timeout: Duration,
) -> Result<StampReport, TimeError> {
    let version = openssl_version(request.openssl_bin, work, timeout)?;
    let tsa_config = absolute_path(request.tsa_config)?;
    let out_token = absolute_path(request.out_token)?;
    let out_request = request.out_request.map(absolute_path).transpose()?;
    let tsa_cert = request.tsa_cert_path.map(absolute_path).transpose()?;
    let request_path = work.join("request.tsq");
    let token_path = work.join("token.tsr");

    let query = run_command(
        request.openssl_bin,
        &[
            "ts".to_owned(),
            "-query".to_owned(),
            "-digest".to_owned(),
            imprint.to_owned(),
            "-sha256".to_owned(),
            "-cert".to_owned(),
            "-out".to_owned(),
            request_path.display().to_string(),
        ],
        work,
        "ts-query",
        timeout,
    )?;
    if query.status != 0 {
        return Err(TimeError::ToolUnavailable {
            message: format!(
                "openssl ts -query exited {}: {}",
                query.status,
                String::from_utf8_lossy(&query.stderr).trim()
            ),
        });
    }

    let mut reply_argv = vec![
        "ts".to_owned(),
        "-reply".to_owned(),
        "-config".to_owned(),
        tsa_config.display().to_string(),
    ];
    if let Some(section) = request.tsa_section {
        reply_argv.push("-section".to_owned());
        reply_argv.push(section.to_owned());
    }
    reply_argv.extend([
        "-queryfile".to_owned(),
        request_path.display().to_string(),
        "-token_out".to_owned(),
        "-out".to_owned(),
        token_path.display().to_string(),
    ]);
    let reply = run_command(request.openssl_bin, &reply_argv, work, "ts-reply", timeout)?;
    if reply.status != 0 {
        return Err(TimeError::ToolUnavailable {
            message: format!(
                "openssl ts -reply exited {}: {}",
                reply.status,
                String::from_utf8_lossy(&reply.stderr).trim()
            ),
        });
    }

    let text = run_command(
        request.openssl_bin,
        &[
            "ts".to_owned(),
            "-reply".to_owned(),
            "-in".to_owned(),
            token_path.display().to_string(),
            "-text".to_owned(),
            "-token_in".to_owned(),
        ],
        work,
        "reply-text",
        timeout,
    )?;
    let info = parse_tst_info(&String::from_utf8_lossy(&text.stdout)).ok_or_else(|| {
        TimeError::Invalid {
            message: format!(
                "timestamp authority did not return a granted response: {}",
                String::from_utf8_lossy(&reply.stderr).trim()
            ),
        }
    })?;

    let request_bytes = fs::read(&request_path).map_err(|error| TimeError::Io {
        message: format!("cannot read timestamp request: {error}"),
    })?;
    let token_bytes = fs::read(&token_path).map_err(|error| TimeError::Io {
        message: format!("cannot read timestamp token: {error}"),
    })?;
    write_private(&out_token, &token_bytes)?;
    if let Some(out_request) = out_request.as_deref() {
        write_private(out_request, &request_bytes)?;
    }
    let tsa_cert_sha256 = match tsa_cert {
        Some(path) => Some(certificate_sha256(&path)?),
        None => None,
    };
    Ok(StampReport {
        schema: TIME_STAMP_REPORT_SCHEMA.to_owned(),
        spec: ETP_SPEC.to_owned(),
        status: TimeStatus::Verified,
        imprint: imprint.to_owned(),
        request_sha256: sha256_hex(&request_bytes),
        token_sha256: sha256_hex(&token_bytes),
        gen_time_unix: info.gen_time_unix,
        gen_time_text: info.gen_time_text,
        policy_oid: info.policy_oid,
        serial: info.serial,
        tsa_cert_sha256,
        trust_domain: LOCAL_TEST_TSA_TRUST_DOMAIN.to_owned(),
        external_trust: false,
        provenance: provenance(&reply, &version, work),
        refusals: Vec::new(),
        claim_ceiling: TIME_CLAIM_CEILING.to_owned(),
    })
}

/// Return the current Unix time in seconds.
#[must_use]
pub fn current_unix() -> u64 {
    now_seconds()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openssl_generalized_time() {
        assert_eq!(parse_openssl_time("Jan  1 00:00:00 1970 GMT"), Some(0));
        assert_eq!(
            parse_openssl_time("Nov 22 07:09:52 2026 GMT"),
            Some(1_795_331_392)
        );
        assert_eq!(
            parse_openssl_time("Nov 22 07:09:52 2026 UTC"),
            Some(1_795_331_392)
        );
        assert_eq!(parse_openssl_time("not a time"), None);
    }

    #[test]
    fn parses_message_data_rows() {
        let text = "\
Message data:
    0000 - 60 7b 36 e1 51 fd 79 1f-9f 8e d5 23 91 f7 e3 0f   `{6.Q.y....#....
    0010 - 2a 28 22 bf ed 0c 13 c6-39 43 06 4f 53 6a e9 12   *(\".....9C.OSj..
Serial number: 0x02
";
        assert_eq!(
            parse_message_data(text).as_deref(),
            Some("607b36e151fd791f9f8ed52391f7e30f2a2822bfed0c13c63943064f536ae912")
        );
    }

    #[test]
    fn parses_granted_tst_info() {
        let text = "\
Status info:
Status: Granted.
Status description: unspecified
Failure info: unspecified

TST info:
Version: 1
Policy OID: 1.3.6.1.4.1.99999.1
Hash Algorithm: sha256
Message data:
    0000 - 60 7b 36 e1 51 fd 79 1f-9f 8e d5 23 91 f7 e3 0f   `{6.Q.y....#....
    0010 - 2a 28 22 bf ed 0c 13 c6-39 43 06 4f 53 6a e9 12   *(\".....9C.OSj..
Serial number: 0x02
Time stamp: Nov 22 07:09:52 2026 GMT
Accuracy: 0x01 seconds, unspecified millis, unspecified micros
Ordering: yes
Nonce: 0xEC88491B8101566E
TSA: DirName:/CN=FRF Local Test TSA
Extensions:
";
        let info = parse_tst_info(text).expect("TST info");
        assert_eq!(info.hash_algorithm.as_deref(), Some("sha256"));
        assert_eq!(info.policy_oid.as_deref(), Some("1.3.6.1.4.1.99999.1"));
        assert_eq!(info.serial.as_deref(), Some("02"));
        assert_eq!(info.gen_time_unix, Some(1_795_331_392));
        assert_eq!(info.ordering.as_deref(), Some("yes"));
    }

    #[test]
    fn rejects_a_non_granted_response() {
        assert!(parse_tst_info("Status: Rejected.\n").is_none());
    }

    #[test]
    fn classifies_verify_failures() {
        assert_eq!(
            classify_verify_failure("message imprint mismatch"),
            TimeRefusalCode::ImprintMismatch
        );
        assert_eq!(
            classify_verify_failure("Verify error:certificate has expired"),
            TimeRefusalCode::ExpiredTsa
        );
        assert_eq!(
            classify_verify_failure("unable to get local issuer certificate"),
            TimeRefusalCode::UntrustedTsa
        );
        assert_eq!(
            classify_verify_failure("something else"),
            TimeRefusalCode::InvalidToken
        );
    }

    #[test]
    fn normalizes_only_canonical_imprints() {
        assert!(normalize_hex_64("imprint", &"0".repeat(64)).is_ok());
        assert!(normalize_hex_64("imprint", &"A".repeat(64)).is_ok());
        assert!(normalize_hex_64("imprint", &"0".repeat(63)).is_err());
        assert!(normalize_hex_64("imprint", &"z".repeat(64)).is_err());
    }
}
