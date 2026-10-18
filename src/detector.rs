//! Typed detector evidence and Phase 5.1 calibration adjudication.
//!
//! This module does **not** execute a detector. It defines the evidence shape
//! that a later live integration must produce, and it adjudicates a
//! caller-supplied calibration receipt. The adjudicator refuses evidence that
//! cannot distinguish a working, correctly configured detector from a dead,
//! misconfigured, substituted, or spoofed one.
//!
//! # Claim ceiling
//!
//! A `CALIBRATED` report establishes only that the supplied finite calibration
//! cases are internally consistent with the named mechanism, tool identity,
//! separate build, and provenance rules in this module. It does **not**
//! establish:
//!
//! * that any detector actually ran;
//! * that the executable digest, version, argv, environment digest, or build
//!   identifiers are authentic (there is no signature or trusted execution
//!   root);
//! * universal detector sensitivity or specificity;
//! * sensitivity for a mechanism, input class, flags combination, target, or
//!   build other than the exact ones recorded; or
//! * any memory-safety, soundness, cryptographic, or `SAFE_COMPATIBLE` result.
//!
//! Calibration is mechanism- and case-specific. A known-bad case that is
//! detected does not imply that another defect class will be detected, and a
//! clean known-good case does not imply the absence of false negatives.
//! Live instrument execution is deliberately **`NOT_RUN`** in this phase.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::court::CaseLegality;
use crate::identity::{
    canonical_bytes, digest_value, hex_lower, parse_strict, IdentityDomain, IdentityError, MsId,
};
use crate::model::DetectorKind;

/// Schema identifier for a detector calibration receipt.
pub const DETECTOR_EVIDENCE_SCHEMA: &str = "frf-memorysafety.detector-evidence.v1";
/// Schema identifier for a calibration report.
pub const CALIBRATION_REPORT_SCHEMA: &str = "frf-memorysafety.calibration-report.v1";
/// Protocol specification identifier.
pub const DETECTOR_SPEC: &str = "frf-memorysafety-spec-v1";
/// Claim ceiling embedded in every calibration report.
pub const CALIBRATION_CLAIM_CEILING: &str = "Calibration is mechanism- and case-specific. A CLEAN or CALIBRATED report establishes only that the supplied finite known-bad and known-good cases satisfy the declared structural evidence rules. It does not authenticate the tool, prove that it ran, establish universal detector sensitivity or specificity, cover another mechanism/input/flags/target/build, or establish memory safety. Live detector execution is NOT_RUN in this phase.";

/// Maximum retained UTF-8 bytes in one captured stdout or stderr stream.
pub const MAX_CAPTURE_BYTES: usize = 65_536;
/// Maximum number of calibration cases in one receipt.
pub const MAX_CALIBRATION_CASES: usize = 64;
/// Maximum number of invocation argv entries.
pub const MAX_ARGV: usize = 64;
/// Maximum number of build flags.
pub const MAX_FLAGS: usize = 64;
/// Maximum number of mechanism-enablement entries.
pub const MAX_ENABLEMENT: usize = 32;
/// Maximum bytes in one case identifier or identity string.
pub const MAX_IDENTITY_BYTES: usize = 256;
/// Maximum declared child duration (one hour).
pub const MAX_DURATION_MS: u64 = 3_600_000;

/// Calibration role of one case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationRole {
    /// A case containing a defect the named mechanism must detect.
    KnownBad,
    /// A harmless case the named mechanism must not report.
    KnownGood,
}

/// Provenance of one captured case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorOrigin {
    /// Captured from the named live detector executable.
    AuthenticLiveTool,
    /// Captured through a substituted implementation.
    Substitute,
    /// Captured through a mock provider or transport.
    MockProvider,
    /// Replayed or synthesized from a model rather than a live tool.
    Modeled,
}

impl DetectorOrigin {
    /// Whether this origin is an authentic live tool execution.
    #[must_use]
    pub const fn is_authentic(self) -> bool {
        matches!(self, Self::AuthenticLiveTool)
    }

    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticLiveTool => "authentic_live_tool",
            Self::Substitute => "substitute",
            Self::MockProvider => "mock_provider",
            Self::Modeled => "modeled",
        }
    }
}

/// Which captured stream contains the diagnostic fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// One bounded captured stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedStream {
    /// Captured UTF-8 text. The digest covers exactly these bytes.
    pub text: String,
    /// Lower-case SHA-256 of `text` encoded as UTF-8.
    pub sha256: String,
    /// Whether capture was cut short. A truncated stream is refused.
    pub truncated: bool,
}

/// Raw child-process observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawCapture {
    /// Captured standard output.
    pub stdout: CapturedStream,
    /// Captured standard error.
    pub stderr: CapturedStream,
    /// Exit code reported for the child.
    pub exit_code: i32,
    /// Terminating signal, when the child was signaled.
    pub signal: Option<i32>,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
}

/// A typed, mechanism-specific finding asserted by the evidence producer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedFinding {
    /// Mechanism named by the finding.
    pub mechanism: String,
    /// Diagnostic text that must occur in the named captured stream.
    pub diagnostic_fingerprint: String,
    /// Stream that must contain the fingerprint.
    pub source: CaptureStream,
}

/// Provenance of one calibration case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseProvenance {
    /// Authentic, substitute, mock, or modeled origin.
    pub origin: DetectorOrigin,
    /// Case identifier. It must equal the enclosing case identifier.
    pub case_id: String,
    /// SHA-256 of the test-only input fixture.
    pub fixture_digest: String,
    /// Mechanism the case targets.
    pub mechanism: String,
    /// Declared legality of the case.
    pub legality: CaseLegality,
}

/// One calibration case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationCase {
    /// Stable case identifier.
    pub case_id: String,
    /// Known-bad (sensitivity) or known-good (specificity) role.
    pub role: CalibrationRole,
    /// SHA-256 of the test-only input fixture.
    pub fixture_digest: String,
    /// Mechanism this case is expected to observe.
    pub expected_mechanism: String,
    /// Declared legality of the case.
    pub legality: CaseLegality,
    /// Raw child observation.
    pub capture: RawCapture,
    /// Provenance of this case.
    pub provenance: CaseProvenance,
    /// Typed finding, required for a known-bad case and absent for a known-good
    /// case. Capture text alone is never treated as a finding.
    pub finding: Option<ObservedFinding>,
}

/// One build identity. The detector and baseline builds must be separate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildIdentity {
    /// Exact compiler/link/runtime flags for this build.
    pub flags: Vec<String>,
    /// Target triple or target name.
    pub target: String,
    /// Cargo or tool profile.
    pub profile: String,
    /// Opaque identity of the separate build directory.
    pub build_directory: String,
    /// SHA-256 of the built artifact.
    pub artifact_sha256: String,
}

/// Detector tool identity and the two build identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorIdentity {
    /// Instrument family.
    pub kind: DetectorKind,
    /// Exact executable or driver name.
    pub tool_name: String,
    /// Exact tool version string.
    pub tool_version: String,
    /// SHA-256 of the detector executable or driver.
    pub executable_sha256: String,
    /// Exact invocation argv, beginning with the executable.
    pub invocation_argv: Vec<String>,
    /// SHA-256 over the canonical execution environment.
    pub environment_digest: String,
    /// Declared mechanism-enablement tokens.
    pub mechanism_enablement: Vec<String>,
    /// Instrumented detector build.
    pub build: BuildIdentity,
    /// Separate uninstrumented baseline build.
    pub baseline_build: BuildIdentity,
    /// Whether the producer claims the two builds were separated.
    pub build_separation_verified: bool,
}

/// A complete detector calibration receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorEvidence {
    /// Evidence schema identifier.
    pub schema: String,
    /// Protocol specification identifier.
    pub spec: String,
    /// Detector identity and build separation.
    pub detector: DetectorIdentity,
    /// Calibration cases. At least one known-bad and one known-good case are
    /// required for a calibrated verdict.
    pub cases: Vec<CalibrationCase>,
}

/// Severity of a refusal. Integrity refusals take precedence for exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RefusalSeverity {
    /// The receipt is malformed, inconsistent, or tampered with.
    Integrity,
    /// The detector failed calibration or does not deserve the evidence.
    Detector,
}

/// Stable refusal taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CalibrationRefusalCode {
    /// A known-bad case exited zero.
    DeadDetector,
    /// A known-bad case produced no typed finding.
    MissingFinding,
    /// A required mechanism build flag is absent from the detector build.
    MisconfiguredBuildFlags,
    /// The declared mechanism-enablement tokens do not enable the mechanism.
    MissingMechanismEnablement,
    /// The detector and baseline builds are not separate.
    BuildSeparationMismatch,
    /// A harmless known-good case produced a typed finding.
    HarmlessControlFinding,
    /// A harmless known-good case exited nonzero.
    HarmlessControlDirtyExit,
    /// Evidence was transported through a mock provider.
    MockProviderTransport,
    /// Evidence was produced through a substituted implementation.
    SubstituteTransport,
    /// Evidence was replayed or synthesized from a model.
    ModeledEvidence,
    /// The tool identity (name, version, executable digest, or argv) is not
    /// structurally trustworthy.
    UntrustedDetectorIdentity,
    /// A typed finding cannot be attributed to an authentic tool identity.
    FakeStdoutMarker,
    /// The diagnostic fingerprint is absent from the captured stream.
    FindingNotInCapture,
    /// The case or detector targets a different mechanism.
    MechanismMismatch,
    /// The case is declared illegal.
    IllegalCase,
    /// No known-bad sensitivity case was supplied.
    MissingSensitivityCase,
    /// No known-good specificity case was supplied.
    MissingSpecificityCase,
    /// The detector kind is not supported by this calibration profile.
    UnsupportedDetectorKind,
    /// A captured stream digest does not match its bytes.
    CaptureDigestMismatch,
    /// A captured stream exceeds [`MAX_CAPTURE_BYTES`].
    CaptureOversized,
    /// A captured stream is marked truncated.
    CaptureTruncated,
    /// Two cases share one identifier.
    DuplicateCaseId,
    /// A digest field is not 64 lower-case hexadecimal characters.
    InvalidDigestFormat,
    /// The process outcome fields contradict each other.
    InconsistentCapture,
    /// The case identifier and provenance case identifier differ.
    ProvenanceCaseMismatch,
    /// The case fixture and provenance fixture digest differ.
    ProvenanceFixtureMismatch,
    /// The schema or specification identifier is wrong.
    InvalidSchema,
    /// A case identifier is empty or oversized.
    InvalidCaseId,
}

impl CalibrationRefusalCode {
    /// Severity used for exit-status precedence.
    #[must_use]
    pub const fn severity(self) -> RefusalSeverity {
        match self {
            Self::CaptureDigestMismatch
            | Self::CaptureOversized
            | Self::CaptureTruncated
            | Self::DuplicateCaseId
            | Self::InvalidDigestFormat
            | Self::InconsistentCapture
            | Self::ProvenanceCaseMismatch
            | Self::ProvenanceFixtureMismatch
            | Self::InvalidSchema
            | Self::InvalidCaseId => RefusalSeverity::Integrity,
            Self::DeadDetector
            | Self::MissingFinding
            | Self::MisconfiguredBuildFlags
            | Self::MissingMechanismEnablement
            | Self::BuildSeparationMismatch
            | Self::HarmlessControlFinding
            | Self::HarmlessControlDirtyExit
            | Self::MockProviderTransport
            | Self::SubstituteTransport
            | Self::ModeledEvidence
            | Self::UntrustedDetectorIdentity
            | Self::FakeStdoutMarker
            | Self::FindingNotInCapture
            | Self::MechanismMismatch
            | Self::IllegalCase
            | Self::MissingSensitivityCase
            | Self::MissingSpecificityCase
            | Self::UnsupportedDetectorKind => RefusalSeverity::Detector,
        }
    }
}

/// One named calibration refusal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationRefusal {
    /// Stable refusal code.
    pub code: CalibrationRefusalCode,
    /// Integrity or detector severity.
    pub severity: RefusalSeverity,
    /// Case identifier, when the refusal is case-scoped.
    pub case_id: Option<String>,
    /// Deterministic human-readable detail.
    pub detail: String,
}

/// A finite count, not a statistical estimate.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct CalibrationScore {
    /// Cases that satisfied the role's requirement.
    pub passed: usize,
    /// Cases declared for the role.
    pub total: usize,
}

/// Result of one control dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlStatus {
    /// The control was checked and passed.
    Pass,
    /// The control was checked and failed.
    Fail,
    /// The control was not evaluated because the receipt failed integrity.
    NotEvaluated,
}

/// Calibration outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CalibrationOutcome {
    /// Every structural control and every calibration case passed.
    Calibrated,
    /// At least one named refusal applies.
    Refused,
}

/// Deterministic calibration report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationReport {
    /// Report schema identifier.
    pub schema: String,
    /// Protocol specification identifier.
    pub spec: String,
    /// Calibrated or refused.
    pub outcome: CalibrationOutcome,
    /// Instrument family named by the receipt.
    pub detector_kind: DetectorKind,
    /// Mechanisms targeted by the calibration cases, sorted and deduplicated.
    pub mechanisms: Vec<String>,
    /// Domain-separated digest of the complete typed receipt.
    pub evidence_digest: MsId,
    /// Domain-separated digest of the detector identity.
    pub identity_digest: MsId,
    /// Number of supplied cases.
    pub case_count: usize,
    /// Known-bad detection count.
    pub sensitivity: CalibrationScore,
    /// Known-good clean count.
    pub specificity: CalibrationScore,
    /// Build separation and mechanism configuration status.
    pub build_separation: ControlStatus,
    /// Provenance and tool identity status.
    pub authenticity: ControlStatus,
    /// Named refusals, sorted deterministically.
    pub refusals: Vec<CalibrationRefusal>,
    /// Claim ceiling embedded in the report.
    pub claim_ceiling: String,
}

impl CalibrationReport {
    /// Whether at least one integrity refusal is present.
    #[must_use]
    pub fn integrity_failed(&self) -> bool {
        self.refusals
            .iter()
            .any(|refusal| refusal.severity == RefusalSeverity::Integrity)
    }

    /// Encode the report in `ms-canonical-json-v1`.
    ///
    /// # Errors
    ///
    /// Returns [`DetectorError`] if the report cannot be encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DetectorError> {
        let value = serde_json::to_value(self)
            .map_err(|error| DetectorError::Encoding(error.to_string()))?;
        canonical_bytes(&value).map_err(DetectorError::from)
    }
}

/// Error category used by the CLI to choose a `SPEC.md` §14 exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorErrorCategory {
    /// Invalid or tampered evidence.
    Integrity,
    /// Internal encoding or harness failure.
    Harness,
}

/// Errors produced while parsing or encoding calibration evidence.
#[derive(Debug, thiserror::Error)]
pub enum DetectorError {
    /// Strict parsing or canonical encoding failed.
    #[error("invalid detector evidence: {0}")]
    Parse(#[from] IdentityError),
    /// The typed schema or its identifiers were rejected.
    #[error("invalid detector evidence schema: {0}")]
    Schema(String),
    /// The report could not be encoded.
    #[error("cannot encode calibration report: {0}")]
    Encoding(String),
}

impl DetectorError {
    /// Category used for exit-status selection.
    #[must_use]
    pub const fn category(&self) -> DetectorErrorCategory {
        match self {
            Self::Parse(_) | Self::Schema(_) => DetectorErrorCategory::Integrity,
            Self::Encoding(_) => DetectorErrorCategory::Harness,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct MechanismProfile {
    mechanism: Option<&'static str>,
    flag_alternatives: &'static [&'static [&'static str]],
    enablement: &'static [&'static str],
    tool_tokens: &'static [&'static str],
}

const ASAN_FLAGS: &[&[&str]] = &[&["-fsanitize=address"], &["-Zsanitizer=address"]];
const LSAN_FLAGS: &[&[&str]] = &[
    &["-fsanitize=leak"],
    &["-fsanitize=address"],
    &["-Zsanitizer=leak"],
    &["-Zsanitizer=address"],
];
const TSAN_FLAGS: &[&[&str]] = &[&["-fsanitize=thread"], &["-Zsanitizer=thread"]];
const COMPILER_TOKENS: &[&str] = &["clang", "clang++", "clang-", "gcc", "gcc-", "cc", "rustc"];
const MIRI_TOKENS: &[&str] = &["miri"];
const LOOM_TOKENS: &[&str] = &["loom", "cargo"];
const KANI_TOKENS: &[&str] = &["kani"];
const CRYPTO_TOKENS: &[&str] = &["dudect", "ctgrind", "valgrind", "cargo"];

fn profile_for(kind: &DetectorKind) -> Option<MechanismProfile> {
    match kind {
        DetectorKind::Miri => Some(MechanismProfile {
            mechanism: Some("stacked_borrows"),
            flag_alternatives: &[],
            enablement: &[
                "miri",
                "stacked-borrows",
                "stacked_borrows",
                "tree-borrows",
                "tree_borrows",
            ],
            tool_tokens: MIRI_TOKENS,
        }),
        DetectorKind::AddressSanitizer => Some(MechanismProfile {
            mechanism: Some("address"),
            flag_alternatives: ASAN_FLAGS,
            enablement: &["address"],
            tool_tokens: COMPILER_TOKENS,
        }),
        DetectorKind::LeakSanitizer => Some(MechanismProfile {
            mechanism: Some("leak"),
            flag_alternatives: LSAN_FLAGS,
            enablement: &["leak", "address"],
            tool_tokens: COMPILER_TOKENS,
        }),
        DetectorKind::ThreadSanitizer => Some(MechanismProfile {
            mechanism: Some("data_race"),
            flag_alternatives: TSAN_FLAGS,
            enablement: &["thread", "data_race"],
            tool_tokens: COMPILER_TOKENS,
        }),
        DetectorKind::Loom => Some(MechanismProfile {
            mechanism: Some("interleaving"),
            flag_alternatives: &[],
            enablement: &["loom", "interleaving"],
            tool_tokens: LOOM_TOKENS,
        }),
        DetectorKind::Kani => Some(MechanismProfile {
            mechanism: Some("bounded_model"),
            flag_alternatives: &[],
            enablement: &["kani", "bounded_model", "bounded-model"],
            tool_tokens: KANI_TOKENS,
        }),
        DetectorKind::CryptoSecretOracle | DetectorKind::Ctgrind | DetectorKind::Dudect => {
            Some(MechanismProfile {
                mechanism: Some("constant_time"),
                flag_alternatives: &[],
                enablement: &[
                    "constant-time",
                    "constant_time",
                    "ctgrind",
                    "dudect",
                    "secret_lifecycle",
                    "secret-lifecycle",
                ],
                tool_tokens: CRYPTO_TOKENS,
            })
        }
        DetectorKind::Custom(_) => Some(MechanismProfile {
            mechanism: None,
            flag_alternatives: &[],
            enablement: &[],
            tool_tokens: &[],
        }),
        DetectorKind::FrfFuzz
        | DetectorKind::FrfCourt
        | DetectorKind::CargoFuzz
        | DetectorKind::AflPlusPlus
        | DetectorKind::LibAfl => None,
    }
}

fn push_refusal(
    refusals: &mut Vec<CalibrationRefusal>,
    code: CalibrationRefusalCode,
    case_id: Option<&str>,
    detail: impl Into<String>,
) {
    refusals.push(CalibrationRefusal {
        code,
        severity: code.severity(),
        case_id: case_id.map(str::to_owned),
        detail: detail.into(),
    });
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_zero_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte == b'0')
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

fn tool_name_matches(tool_name: &str, tokens: &[&str]) -> bool {
    if tokens.is_empty() {
        return !tool_name.trim().is_empty();
    }
    tokens.iter().any(|token| tool_name.contains(token))
}

fn placeholder_version(version: &str) -> bool {
    let lowered = version.trim().to_ascii_lowercase();
    lowered.is_empty()
        || matches!(
            lowered.as_str(),
            "unknown" | "none" | "n/a" | "na" | "fake" | "mock" | "spoof"
        )
}

fn all_present(values: &[String], required: &[&str]) -> bool {
    required
        .iter()
        .all(|token| values.iter().any(|value| value == token))
}

fn any_flag_group(values: &[String], alternatives: &[&[&str]]) -> bool {
    alternatives.iter().any(|group| all_present(values, group))
}

fn contains_token(values: &[String], tokens: &[&str]) -> bool {
    values
        .iter()
        .any(|value| tokens.iter().any(|token| value == token))
}

fn check_stream(
    stream: &CapturedStream,
    name: &str,
    case_id: &str,
    refusals: &mut Vec<CalibrationRefusal>,
) -> bool {
    let mut ok = true;
    if !is_sha256_hex(&stream.sha256) {
        push_refusal(
            refusals,
            CalibrationRefusalCode::InvalidDigestFormat,
            Some(case_id),
            format!("{name} digest is not 64 lower-case hexadecimal characters"),
        );
        ok = false;
    }
    if stream.text.len() > MAX_CAPTURE_BYTES {
        push_refusal(
            refusals,
            CalibrationRefusalCode::CaptureOversized,
            Some(case_id),
            format!(
                "{name} capture is {} bytes; limit is {MAX_CAPTURE_BYTES}",
                stream.text.len()
            ),
        );
        ok = false;
    }
    if stream.truncated {
        push_refusal(
            refusals,
            CalibrationRefusalCode::CaptureTruncated,
            Some(case_id),
            format!("{name} capture is marked truncated"),
        );
        ok = false;
    }
    if is_sha256_hex(&stream.sha256) && stream.sha256 != sha256_hex(stream.text.as_bytes()) {
        push_refusal(
            refusals,
            CalibrationRefusalCode::CaptureDigestMismatch,
            Some(case_id),
            format!("{name} digest does not match the captured bytes"),
        );
        ok = false;
    }
    ok
}

#[allow(clippy::too_many_lines)]
fn check_integrity(evidence: &DetectorEvidence, refusals: &mut Vec<CalibrationRefusal>) -> bool {
    let mut ok = true;
    if evidence.schema != DETECTOR_EVIDENCE_SCHEMA {
        push_refusal(
            refusals,
            CalibrationRefusalCode::InvalidSchema,
            None,
            format!("schema must be {DETECTOR_EVIDENCE_SCHEMA}"),
        );
        ok = false;
    }
    if evidence.spec != DETECTOR_SPEC {
        push_refusal(
            refusals,
            CalibrationRefusalCode::InvalidSchema,
            None,
            format!("spec must be {DETECTOR_SPEC}"),
        );
        ok = false;
    }
    if evidence.cases.len() > MAX_CALIBRATION_CASES {
        push_refusal(
            refusals,
            CalibrationRefusalCode::InvalidSchema,
            None,
            format!(
                "{} cases supplied; limit is {MAX_CALIBRATION_CASES}",
                evidence.cases.len()
            ),
        );
        ok = false;
    }

    let identity = &evidence.detector;
    for (name, digest) in [
        ("executable", identity.executable_sha256.as_str()),
        ("environment", identity.environment_digest.as_str()),
        (
            "detector build artifact",
            identity.build.artifact_sha256.as_str(),
        ),
        (
            "baseline build artifact",
            identity.baseline_build.artifact_sha256.as_str(),
        ),
    ] {
        if !is_sha256_hex(digest) {
            push_refusal(
                refusals,
                CalibrationRefusalCode::InvalidDigestFormat,
                None,
                format!("{name} digest is not 64 lower-case hexadecimal characters"),
            );
            ok = false;
        }
    }
    if identity.invocation_argv.len() > MAX_ARGV
        || identity.build.flags.len() > MAX_FLAGS
        || identity.baseline_build.flags.len() > MAX_FLAGS
        || identity.mechanism_enablement.len() > MAX_ENABLEMENT
    {
        push_refusal(
            refusals,
            CalibrationRefusalCode::InvalidSchema,
            None,
            "detector identity exceeds an argv, flag, or enablement bound".to_owned(),
        );
        ok = false;
    }

    let mut seen = BTreeSet::new();
    for case in &evidence.cases {
        if case.case_id.is_empty() || case.case_id.len() > MAX_IDENTITY_BYTES {
            push_refusal(
                refusals,
                CalibrationRefusalCode::InvalidCaseId,
                Some(&case.case_id),
                "case identifier is empty or oversized".to_owned(),
            );
            ok = false;
        }
        if !seen.insert(case.case_id.as_str()) {
            push_refusal(
                refusals,
                CalibrationRefusalCode::DuplicateCaseId,
                Some(&case.case_id),
                "case identifier is not unique".to_owned(),
            );
            ok = false;
        }
        if !is_sha256_hex(&case.provenance.fixture_digest) {
            push_refusal(
                refusals,
                CalibrationRefusalCode::InvalidDigestFormat,
                Some(&case.case_id),
                "fixture digest is not 64 lower-case hexadecimal characters".to_owned(),
            );
            ok = false;
        }
        if case.case_id != case.provenance.case_id {
            push_refusal(
                refusals,
                CalibrationRefusalCode::ProvenanceCaseMismatch,
                Some(&case.case_id),
                "case and provenance case identifiers differ".to_owned(),
            );
            ok = false;
        }
        if case.legality != case.provenance.legality {
            push_refusal(
                refusals,
                CalibrationRefusalCode::ProvenanceCaseMismatch,
                Some(&case.case_id),
                "case and provenance legality differ".to_owned(),
            );
            ok = false;
        }
        if !is_sha256_hex(&case.fixture_digest) {
            push_refusal(
                refusals,
                CalibrationRefusalCode::InvalidDigestFormat,
                Some(&case.case_id),
                "case fixture digest is not 64 lower-case hexadecimal characters".to_owned(),
            );
            ok = false;
        }
        if case.fixture_digest != case.provenance.fixture_digest {
            push_refusal(
                refusals,
                CalibrationRefusalCode::ProvenanceFixtureMismatch,
                Some(&case.case_id),
                "case and provenance fixture digests differ".to_owned(),
            );
            ok = false;
        }
        if case.capture.exit_code < 0 || case.capture.signal.is_some_and(|signal| signal <= 0) {
            push_refusal(
                refusals,
                CalibrationRefusalCode::InconsistentCapture,
                Some(&case.case_id),
                "exit code or signal is outside the recorded domain".to_owned(),
            );
            ok = false;
        }
        if case.capture.duration_ms > MAX_DURATION_MS {
            push_refusal(
                refusals,
                CalibrationRefusalCode::InconsistentCapture,
                Some(&case.case_id),
                format!(
                    "duration {} ms exceeds {MAX_DURATION_MS} ms",
                    case.capture.duration_ms
                ),
            );
            ok = false;
        }
        ok &= check_stream(&case.capture.stdout, "stdout", &case.case_id, refusals);
        ok &= check_stream(&case.capture.stderr, "stderr", &case.case_id, refusals);
    }
    ok
}

struct Checks {
    build_separation: bool,
    authenticity: bool,
}

#[allow(clippy::too_many_lines)]
fn check_identity(identity: &DetectorIdentity, refusals: &mut Vec<CalibrationRefusal>) -> Checks {
    let mut build_separation = true;
    let mut authenticity = true;
    let Some(profile) = profile_for(&identity.kind) else {
        push_refusal(
            refusals,
            CalibrationRefusalCode::UnsupportedDetectorKind,
            None,
            "detector kind is not supported by the calibration profile".to_owned(),
        );
        return Checks {
            build_separation: false,
            authenticity: false,
        };
    };

    if identity.tool_name.trim().is_empty()
        || !tool_name_matches(&identity.tool_name, profile.tool_tokens)
    {
        push_refusal(
            refusals,
            CalibrationRefusalCode::UntrustedDetectorIdentity,
            None,
            "tool name does not identify the declared detector family".to_owned(),
        );
        authenticity = false;
    }
    if placeholder_version(&identity.tool_version) {
        push_refusal(
            refusals,
            CalibrationRefusalCode::UntrustedDetectorIdentity,
            None,
            "tool version is empty or a known placeholder".to_owned(),
        );
        authenticity = false;
    }
    if is_zero_digest(&identity.executable_sha256) || is_zero_digest(&identity.environment_digest) {
        push_refusal(
            refusals,
            CalibrationRefusalCode::UntrustedDetectorIdentity,
            None,
            "executable or environment digest is all zeroes".to_owned(),
        );
        authenticity = false;
    }
    if identity.invocation_argv.is_empty() || identity.invocation_argv[0].trim().is_empty() {
        push_refusal(
            refusals,
            CalibrationRefusalCode::UntrustedDetectorIdentity,
            None,
            "invocation argv is empty or does not name an executable".to_owned(),
        );
        authenticity = false;
    }

    if !identity.build_separation_verified {
        push_refusal(
            refusals,
            CalibrationRefusalCode::BuildSeparationMismatch,
            None,
            "producer did not verify build separation".to_owned(),
        );
        build_separation = false;
    }
    if identity.build.target.trim().is_empty()
        || identity.build.profile.trim().is_empty()
        || identity.build.build_directory.trim().is_empty()
        || identity.baseline_build.build_directory.trim().is_empty()
    {
        push_refusal(
            refusals,
            CalibrationRefusalCode::BuildSeparationMismatch,
            None,
            "build target, profile, or directory identity is empty".to_owned(),
        );
        build_separation = false;
    }
    if identity.build.target != identity.baseline_build.target
        || identity.build.profile != identity.baseline_build.profile
    {
        push_refusal(
            refusals,
            CalibrationRefusalCode::BuildSeparationMismatch,
            None,
            "detector and baseline target or profile differ".to_owned(),
        );
        build_separation = false;
    }
    if identity.build.build_directory == identity.baseline_build.build_directory {
        push_refusal(
            refusals,
            CalibrationRefusalCode::BuildSeparationMismatch,
            None,
            "detector and baseline share a build directory".to_owned(),
        );
        build_separation = false;
    }
    if identity.build.artifact_sha256 == identity.baseline_build.artifact_sha256
        || is_zero_digest(&identity.build.artifact_sha256)
        || is_zero_digest(&identity.baseline_build.artifact_sha256)
    {
        push_refusal(
            refusals,
            CalibrationRefusalCode::BuildSeparationMismatch,
            None,
            "detector and baseline artifacts are not distinct non-zero builds".to_owned(),
        );
        build_separation = false;
    }

    if !profile.flag_alternatives.is_empty()
        && !any_flag_group(&identity.build.flags, profile.flag_alternatives)
    {
        push_refusal(
            refusals,
            CalibrationRefusalCode::MisconfiguredBuildFlags,
            None,
            "detector build flags do not enable the declared mechanism".to_owned(),
        );
        build_separation = false;
    }
    if !profile.flag_alternatives.is_empty()
        && any_flag_group(&identity.baseline_build.flags, profile.flag_alternatives)
    {
        push_refusal(
            refusals,
            CalibrationRefusalCode::BuildSeparationMismatch,
            None,
            "baseline build carries the detector mechanism flag".to_owned(),
        );
        build_separation = false;
    }
    let enablement = if let Some(mechanism) = profile.mechanism {
        contains_token(&identity.mechanism_enablement, profile.enablement)
            || identity
                .mechanism_enablement
                .iter()
                .any(|token| token == mechanism)
    } else {
        !identity.mechanism_enablement.is_empty()
    };
    if !enablement {
        push_refusal(
            refusals,
            CalibrationRefusalCode::MissingMechanismEnablement,
            None,
            "mechanism-enablement tokens do not name the declared mechanism".to_owned(),
        );
        build_separation = false;
    }

    Checks {
        build_separation,
        authenticity,
    }
}

fn check_case(
    case: &CalibrationCase,
    expected: &str,
    authenticity: bool,
    refusals: &mut Vec<CalibrationRefusal>,
) -> bool {
    let mut case_ok = true;
    if !case.legality_supported() {
        push_refusal(
            refusals,
            CalibrationRefusalCode::IllegalCase,
            Some(&case.case_id),
            "case legality is illegal".to_owned(),
        );
        case_ok = false;
    }
    if case.expected_mechanism != expected || case.provenance.mechanism != case.expected_mechanism {
        push_refusal(
            refusals,
            CalibrationRefusalCode::MechanismMismatch,
            Some(&case.case_id),
            "case, provenance, and detector mechanism differ".to_owned(),
        );
        case_ok = false;
    }
    case_ok &= check_origin(case, refusals);

    match case.role {
        CalibrationRole::KnownBad => {
            case_ok &= check_known_bad(case, refusals);
        }
        CalibrationRole::KnownGood => {
            case_ok &= check_known_good(case, refusals);
        }
    }

    if case.finding.is_some() && !authenticity {
        push_refusal(
            refusals,
            CalibrationRefusalCode::FakeStdoutMarker,
            Some(&case.case_id),
            "typed finding has no structurally authentic tool identity".to_owned(),
        );
        case_ok = false;
    }
    case_ok
}

fn check_origin(case: &CalibrationCase, refusals: &mut Vec<CalibrationRefusal>) -> bool {
    match case.provenance.origin {
        DetectorOrigin::AuthenticLiveTool => true,
        DetectorOrigin::Substitute => {
            push_refusal(
                refusals,
                CalibrationRefusalCode::SubstituteTransport,
                Some(&case.case_id),
                "substituted transport is not live detector evidence".to_owned(),
            );
            false
        }
        DetectorOrigin::MockProvider => {
            push_refusal(
                refusals,
                CalibrationRefusalCode::MockProviderTransport,
                Some(&case.case_id),
                "mock-provider transport is not live detector evidence".to_owned(),
            );
            false
        }
        DetectorOrigin::Modeled => {
            push_refusal(
                refusals,
                CalibrationRefusalCode::ModeledEvidence,
                Some(&case.case_id),
                "modeled evidence is not live detector evidence".to_owned(),
            );
            false
        }
    }
}

fn finding_matches(case: &CalibrationCase) -> bool {
    let Some(finding) = &case.finding else {
        return false;
    };
    if finding.mechanism != case.expected_mechanism
        || finding.diagnostic_fingerprint.trim().is_empty()
    {
        return false;
    }
    let stream = match finding.source {
        CaptureStream::Stdout => &case.capture.stdout,
        CaptureStream::Stderr => &case.capture.stderr,
    };
    stream.text.contains(&finding.diagnostic_fingerprint)
}

fn check_known_bad(case: &CalibrationCase, refusals: &mut Vec<CalibrationRefusal>) -> bool {
    let mut ok = true;
    if case.capture.exit_code == 0 {
        push_refusal(
            refusals,
            CalibrationRefusalCode::DeadDetector,
            Some(&case.case_id),
            "known-bad case exited zero".to_owned(),
        );
        ok = false;
    }
    match &case.finding {
        None => {
            push_refusal(
                refusals,
                CalibrationRefusalCode::MissingFinding,
                Some(&case.case_id),
                "known-bad case produced no typed finding".to_owned(),
            );
            ok = false;
        }
        Some(finding) => {
            if finding.mechanism != case.expected_mechanism {
                push_refusal(
                    refusals,
                    CalibrationRefusalCode::MechanismMismatch,
                    Some(&case.case_id),
                    "finding mechanism differs from the case mechanism".to_owned(),
                );
                ok = false;
            }
            if !finding_matches(case) {
                push_refusal(
                    refusals,
                    CalibrationRefusalCode::FindingNotInCapture,
                    Some(&case.case_id),
                    "finding fingerprint is absent from the captured stream".to_owned(),
                );
                ok = false;
            }
        }
    }
    ok
}

fn check_known_good(case: &CalibrationCase, refusals: &mut Vec<CalibrationRefusal>) -> bool {
    let mut ok = true;
    if case.finding.is_some() {
        push_refusal(
            refusals,
            CalibrationRefusalCode::HarmlessControlFinding,
            Some(&case.case_id),
            "known-good case produced a typed finding".to_owned(),
        );
        ok = false;
    }
    if case.capture.exit_code != 0 {
        push_refusal(
            refusals,
            CalibrationRefusalCode::HarmlessControlDirtyExit,
            Some(&case.case_id),
            format!(
                "known-good case exited {} instead of zero",
                case.capture.exit_code
            ),
        );
        ok = false;
    }
    ok
}

/// Parse and structurally validate a calibration receipt.
///
/// Duplicate JSON keys, floats, unknown typed fields, and overall resource-limit
/// violations are rejected by strict parsing.
///
/// # Errors
///
/// Returns [`DetectorError`] for malformed JSON, unknown fields, wrong schema
/// identifiers, or invalid typed values.
pub fn parse_evidence(bytes: &[u8]) -> Result<DetectorEvidence, DetectorError> {
    let value = parse_strict(bytes)?;
    let evidence: DetectorEvidence =
        serde_json::from_value(value).map_err(|error| DetectorError::Schema(error.to_string()))?;
    if evidence.schema != DETECTOR_EVIDENCE_SCHEMA {
        return Err(DetectorError::Schema(format!(
            "schema must be {DETECTOR_EVIDENCE_SCHEMA}"
        )));
    }
    if evidence.spec != DETECTOR_SPEC {
        return Err(DetectorError::Schema(format!(
            "spec must be {DETECTOR_SPEC}"
        )));
    }
    Ok(evidence)
}

/// Adjudicate a typed calibration receipt.
///
/// # Errors
///
/// Returns [`DetectorError`] if the receipt cannot be encoded for its digest.
#[allow(clippy::too_many_lines)]
pub fn evaluate_calibration(
    evidence: &DetectorEvidence,
) -> Result<CalibrationReport, DetectorError> {
    let evidence_value = serde_json::to_value(evidence)
        .map_err(|error| DetectorError::Encoding(error.to_string()))?;
    let identity_value = serde_json::to_value(&evidence.detector)
        .map_err(|error| DetectorError::Encoding(error.to_string()))?;
    let evidence_digest =
        digest_value(IdentityDomain::Control, &evidence_value).map_err(DetectorError::from)?;
    let identity_digest =
        digest_value(IdentityDomain::Control, &identity_value).map_err(DetectorError::from)?;

    let mut refusals = Vec::new();
    let integrity_ok = check_integrity(evidence, &mut refusals);
    let mut checks = check_identity(&evidence.detector, &mut refusals);

    let mut mechanisms: BTreeSet<String> = BTreeSet::new();
    for case in &evidence.cases {
        mechanisms.insert(case.expected_mechanism.clone());
    }
    let mechanisms: Vec<String> = mechanisms.into_iter().collect();
    let single_mechanism = mechanisms.len() == 1;
    let expected = mechanisms.first().cloned().unwrap_or_default();
    let standard_mechanism =
        profile_for(&evidence.detector.kind).and_then(|profile| profile.mechanism);
    if !single_mechanism
        || expected.trim().is_empty()
        || standard_mechanism.is_some_and(|mechanism| mechanism != expected.as_str())
    {
        push_refusal(
            &mut refusals,
            CalibrationRefusalCode::MechanismMismatch,
            None,
            "calibration must target exactly one mechanism matching the detector kind".to_owned(),
        );
    }
    if standard_mechanism.is_none()
        && profile_for(&evidence.detector.kind).is_some()
        && !expected.is_empty()
        && !evidence
            .detector
            .mechanism_enablement
            .iter()
            .any(|token| token == &expected)
    {
        push_refusal(
            &mut refusals,
            CalibrationRefusalCode::MissingMechanismEnablement,
            None,
            "custom detector does not enable the declared mechanism".to_owned(),
        );
        checks.build_separation = false;
    }

    let mut sensitivity = CalibrationScore::default();
    let mut specificity = CalibrationScore::default();
    let all_origins_authentic = evidence
        .cases
        .iter()
        .all(|case| case.provenance.origin.is_authentic());
    for case in &evidence.cases {
        let authentic_case = checks.authenticity && case.provenance.origin.is_authentic();
        match case.role {
            CalibrationRole::KnownBad => {
                sensitivity.total += 1;
                if integrity_ok
                    && checks.build_separation
                    && authentic_case
                    && finding_matches(case)
                    && case.capture.exit_code != 0
                {
                    sensitivity.passed += 1;
                }
            }
            CalibrationRole::KnownGood => {
                specificity.total += 1;
                if integrity_ok
                    && checks.build_separation
                    && authentic_case
                    && case.finding.is_none()
                    && case.capture.exit_code == 0
                {
                    specificity.passed += 1;
                }
            }
        }
        check_case(case, &expected, checks.authenticity, &mut refusals);
    }
    if sensitivity.total == 0 {
        push_refusal(
            &mut refusals,
            CalibrationRefusalCode::MissingSensitivityCase,
            None,
            "no known-bad sensitivity case was supplied".to_owned(),
        );
    }
    if specificity.total == 0 {
        push_refusal(
            &mut refusals,
            CalibrationRefusalCode::MissingSpecificityCase,
            None,
            "no known-good specificity case was supplied".to_owned(),
        );
    }

    refusals.sort();
    refusals.dedup();
    let outcome = if refusals.is_empty() {
        CalibrationOutcome::Calibrated
    } else {
        CalibrationOutcome::Refused
    };
    let control = |passed: bool| {
        if integrity_ok {
            if passed {
                ControlStatus::Pass
            } else {
                ControlStatus::Fail
            }
        } else {
            ControlStatus::NotEvaluated
        }
    };
    Ok(CalibrationReport {
        schema: CALIBRATION_REPORT_SCHEMA.to_owned(),
        spec: DETECTOR_SPEC.to_owned(),
        outcome,
        detector_kind: evidence.detector.kind.clone(),
        mechanisms,
        evidence_digest,
        identity_digest,
        case_count: evidence.cases.len(),
        sensitivity,
        specificity,
        build_separation: control(checks.build_separation),
        authenticity: control(checks.authenticity && all_origins_authentic),
        refusals,
        claim_ceiling: CALIBRATION_CLAIM_CEILING.to_owned(),
    })
}

/// Parse and adjudicate calibration evidence in one step.
///
/// # Errors
///
/// Returns [`DetectorError`] for malformed evidence or an encoding failure.
pub fn evaluate_calibration_json(bytes: &[u8]) -> Result<CalibrationReport, DetectorError> {
    let evidence = parse_evidence(bytes)?;
    evaluate_calibration(&evidence)
}

impl CalibrationCase {
    fn legality_supported(&self) -> bool {
        self.legality != CaseLegality::Illegal && self.provenance.legality != CaseLegality::Illegal
    }
}
