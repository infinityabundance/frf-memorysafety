//! Phase 9.1 evaluation harness, receipt verification, and claim coverage.
//!
//! The harness runs each pre-registered `(case, arm)` in a separate child
//! process, records wall time, peak RSS, output size, digests, toolchain/image
//! identity, and the exact command, and emits canonical JSON receipts. It does
//! not execute builds or tests itself. Verification is fail-closed: a missing
//! measurement, a stale observation digest, a missing receipt, or a claim that
//! does not map to an observed field is an error.
//!
//! This module is evaluation bookkeeping over the finite controls declared in
//! `evaluation/protocol.json`. It is not a statistical estimator and makes no
//! population, universal-soundness, or `SAFE_COMPATIBLE` claim.

#![allow(clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::bridge::{
    native_provider_contracts, verify_bundle_bytes, BridgeIntegrity, BridgeNotRun, BridgeOutcome,
    BridgeRefusal, DsoBinding, EvidenceBundle, EvidenceProvenance, ExternalObservation,
    ExternalProvider, Reexecution, BRIDGE_BUNDLE_SCHEMA, BRIDGE_SPEC,
};
use crate::detector::{
    evaluate_calibration, parse_evidence, CalibrationOutcome, CalibrationRefusalCode,
    DetectorEvidence, DetectorOrigin, DETECTOR_EVIDENCE_SCHEMA, DETECTOR_SPEC,
};
use crate::identity::{canonical_bytes, IdentityError};
use crate::path_effect::{
    analyze, AccessMode, AliasDecl, AliasKind, ByteRange, CallbackBehavior, CallbackDecl,
    EventKind, Footprint, FootprintKind, ObjectDecl, PathEffectsInput, PathEvent, ProviderBehavior,
    ProviderDecl, QualifiedStatus, ReferenceIntervalDecl,
};
use crate::proof::{
    evaluate_admission, evaluate_correspondence, parse_manifest, verify_manifest_bytes_live,
    ProofOutcome,
};
use crate::support::{certificates, evaluate, exact_cut, RuleSystem};

/// Protocol schema identifier.
pub const EVALUATION_PROTOCOL_SCHEMA: &str = "frf-memorysafety.evaluation-protocol.v1";
/// Receipt schema identifier.
pub const EVALUATION_RECEIPT_SCHEMA: &str = "frf-memorysafety.evaluation-receipt.v1";
/// Verification report schema identifier.
pub const EVALUATION_REPORT_SCHEMA: &str = "frf-memorysafety.evaluation-report.v1";
/// Manifest schema for a receipt directory.
pub const EVALUATION_MANIFEST_SCHEMA: &str = "frf-memorysafety.evaluation-manifest.v1";
/// Normative specification identifier.
pub const EVALUATION_SPEC: &str = "frf-memorysafety-spec-v1";
/// Default protocol path, relative to the crate root.
pub const DEFAULT_PROTOCOL_PATH: &str = "evaluation/protocol.json";
/// Default committed receipt directory.
pub const DEFAULT_RECEIPTS_DIR: &str = "evaluation/receipts";
/// Maximum retained child stdout in bytes.
pub const MAX_OBSERVATION_BYTES: usize = 1_048_576;
/// Exact `NOT_RUN` label used by pre-registered blocked controls.
pub const NOT_RUN: &str = "NOT_RUN";

/// Typed evaluation error.
#[derive(Debug, thiserror::Error)]
pub enum EvaluationError {
    /// Filesystem failure.
    #[error("io: {0}")]
    Io(String),
    /// JSON or canonical encoding failure.
    #[error("json: {0}")]
    Json(String),
    /// Invalid protocol declaration.
    #[error("protocol: {0}")]
    Protocol(String),
    /// Invalid or fabricated receipt.
    #[error("receipt: {0}")]
    Receipt(String),
    /// A required measurement is absent.
    #[error("missing measurement: {0}")]
    MissingMeasurement(String),
    /// Child process failure.
    #[error("process: {0}")]
    Process(String),
    /// Internal canonical encoding failure.
    #[error("encoding: {0}")]
    Encoding(String),
}

impl From<IdentityError> for EvaluationError {
    fn from(error: IdentityError) -> Self {
        Self::Encoding(error.to_string())
    }
}

impl From<crate::support::SupportError> for EvaluationError {
    fn from(error: crate::support::SupportError) -> Self {
        Self::Protocol(error.to_string())
    }
}

impl From<crate::path_effect::PathError> for EvaluationError {
    fn from(error: crate::path_effect::PathError) -> Self {
        Self::Protocol(error.to_string())
    }
}

impl From<crate::proof::ProofError> for EvaluationError {
    fn from(error: crate::proof::ProofError) -> Self {
        Self::Protocol(error.to_string())
    }
}

/// One pre-registered hypothesis.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hypothesis {
    /// Stable hypothesis id.
    pub id: String,
    /// Short name.
    pub name: String,
    /// Falsifiable claim.
    pub claim: String,
    /// Decision rule.
    pub decision_rule: String,
    /// Cases that provide evidence.
    pub cases: Vec<String>,
}

/// One ablation arm.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmSpec {
    /// Stable arm id.
    pub id: String,
    /// `production`, `baseline`, or `blocked`.
    pub kind: String,
    /// Pre-registered expected observation.
    pub expected: String,
}

/// One pre-registered case.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSpec {
    /// Stable case id.
    pub id: String,
    /// Owning hypothesis.
    pub hypothesis: String,
    /// Family label.
    pub category: String,
    /// Human description.
    pub description: String,
    /// `accept`, `reject`, `unknown`, or `not_run`.
    pub truth: String,
    /// Labels that count as accepting the case's claim.
    pub accept_outcomes: Vec<String>,
    /// Arms run for this case.
    pub arms: Vec<ArmSpec>,
}

/// One claim-to-receipt requirement.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRequirement {
    /// Case id.
    pub case: String,
    /// Arm id.
    pub arm: String,
    /// Required observed label.
    pub expected: String,
}

/// One pre-registered claim.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimSpec {
    /// Stable claim id.
    pub id: String,
    /// Owning hypothesis label.
    pub hypothesis: String,
    /// Claim text.
    pub text: String,
    /// Optional derived rule.
    #[serde(default)]
    pub derived: Option<String>,
    /// Required receipts.
    #[serde(default)]
    pub requires: Vec<ClaimRequirement>,
}

/// Frozen protocol.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protocol {
    /// Schema identifier.
    pub schema: String,
    /// Spec identifier.
    pub spec: String,
    /// Protocol version.
    pub protocol_version: String,
    /// Freeze date.
    pub frozen: String,
    /// Held-out rule text.
    pub held_out_rule: String,
    /// Resource metric definitions.
    pub resource_metrics: Vec<String>,
    /// Receipt rule text.
    pub receipt_rule: String,
    /// Blocked controls.
    pub blocked_controls: Vec<String>,
    /// Hypotheses.
    pub hypotheses: Vec<Hypothesis>,
    /// Cases.
    pub cases: Vec<CaseSpec>,
    /// Claims.
    pub claims: Vec<ClaimSpec>,
}

impl Protocol {
    /// Look up a case.
    #[must_use]
    pub fn case(&self, id: &str) -> Option<&CaseSpec> {
        self.cases.iter().find(|case| case.id == id)
    }

    /// Total expected receipts.
    #[must_use]
    pub fn expected_receipts(&self) -> usize {
        self.cases.iter().map(|case| case.arms.len()).sum()
    }

    /// Held-out and development case counts.
    #[must_use]
    pub fn split_counts(&self) -> (usize, usize) {
        let held = self.cases.iter().filter(|case| held_out(&case.id)).count();
        (held, self.cases.len() - held)
    }
}

/// Parse and validate a protocol. Structural validation is fail-closed.
///
/// # Errors
///
/// Returns [`EvaluationError::Json`] for malformed JSON and
/// [`EvaluationError::Protocol`] for schema, spec, duplicate-id, or
/// cross-reference violations.
pub fn parse_protocol(bytes: &[u8]) -> Result<Protocol, EvaluationError> {
    let protocol: Protocol = serde_json::from_slice(bytes)
        .map_err(|error| EvaluationError::Json(format!("protocol: {error}")))?;
    if protocol.schema != EVALUATION_PROTOCOL_SCHEMA {
        return Err(EvaluationError::Protocol(format!(
            "schema must be {EVALUATION_PROTOCOL_SCHEMA}"
        )));
    }
    if protocol.spec != EVALUATION_SPEC {
        return Err(EvaluationError::Protocol(format!(
            "spec must be {EVALUATION_SPEC}"
        )));
    }
    let mut case_ids = BTreeSet::new();
    for case in &protocol.cases {
        if !case_ids.insert(case.id.as_str()) {
            return Err(EvaluationError::Protocol(format!(
                "duplicate case id: {}",
                case.id
            )));
        }
        if !matches!(
            case.truth.as_str(),
            "accept" | "reject" | "unknown" | "not_run"
        ) {
            return Err(EvaluationError::Protocol(format!(
                "case {} has invalid truth {}",
                case.id, case.truth
            )));
        }
        let mut arms = BTreeSet::new();
        for arm in &case.arms {
            if !arms.insert(arm.id.as_str()) {
                return Err(EvaluationError::Protocol(format!(
                    "duplicate arm {} in case {}",
                    arm.id, case.id
                )));
            }
            if !matches!(arm.kind.as_str(), "production" | "baseline" | "blocked") {
                return Err(EvaluationError::Protocol(format!(
                    "case {} arm {} has invalid kind {}",
                    case.id, arm.id, arm.kind
                )));
            }
        }
    }
    let mut hypothesis_ids = BTreeSet::new();
    for hypothesis in &protocol.hypotheses {
        if !hypothesis_ids.insert(hypothesis.id.as_str()) {
            return Err(EvaluationError::Protocol(format!(
                "duplicate hypothesis id: {}",
                hypothesis.id
            )));
        }
        for case_id in &hypothesis.cases {
            if protocol.case(case_id).is_none() {
                return Err(EvaluationError::Protocol(format!(
                    "hypothesis {} names missing case {}",
                    hypothesis.id, case_id
                )));
            }
        }
    }
    let mut claim_ids = BTreeSet::new();
    for claim in &protocol.claims {
        if !claim_ids.insert(claim.id.as_str()) {
            return Err(EvaluationError::Protocol(format!(
                "duplicate claim id: {}",
                claim.id
            )));
        }
    }
    Ok(protocol)
}

/// Read a protocol file and return its exact bytes, parsed form, and SHA-256.
///
/// # Errors
///
/// Returns [`EvaluationError::Io`] or any [`parse_protocol`] error.
pub fn read_protocol(path: &Path) -> Result<(Vec<u8>, Protocol, String), EvaluationError> {
    let bytes = fs::read(path)
        .map_err(|error| EvaluationError::Io(format!("{}: {error}", path.display())))?;
    let protocol = parse_protocol(&bytes)?;
    let digest = sha256_hex(&bytes);
    Ok((bytes, protocol, digest))
}

/// Fixed held-out rule. This must not change after measurement.
#[must_use]
pub fn held_out(case_id: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(b"frf-ms-eval-v1\0");
    hasher.update(case_id.as_bytes());
    hasher.finalize()[0] >= 0x80
}

/// Lower-case SHA-256 of arbitrary bytes.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn sha256_text(text: &str) -> String {
    sha256_hex(text.as_bytes())
}

fn canonical_value_bytes(value: &Value) -> Result<Vec<u8>, EvaluationError> {
    canonical_bytes(value).map_err(EvaluationError::from)
}

fn hash_value(value: &Value) -> Result<String, EvaluationError> {
    Ok(sha256_hex(&canonical_value_bytes(value)?))
}

/// One child observation. `vm_hwm_kb` is a fallback measurement and is excluded
/// from the observation digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// Observed label.
    pub observed: String,
    /// Digest of the exact case input used by the child.
    pub input_sha256: String,
    /// Deterministic explanation.
    pub detail: String,
    /// `/proc/self/status` `VmHWM`, when readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_hwm_kb: Option<u64>,
}

impl Observation {
    fn core(&self) -> Value {
        json!({
            "observed": self.observed,
            "input_sha256": self.input_sha256,
            "detail": self.detail,
        })
    }

    /// Digest over the deterministic observation core.
    ///
    /// # Errors
    ///
    /// Returns [`EvaluationError::Encoding`] if canonical encoding fails.
    pub fn observed_sha256(&self) -> Result<String, EvaluationError> {
        hash_value(&self.core())
    }

    /// Canonical child bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EvaluationError::Encoding`] if canonical encoding fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EvaluationError> {
        canonical_value_bytes(
            &serde_json::to_value(self)
                .map_err(|error| EvaluationError::Json(format!("observation: {error}")))?,
        )
    }
}

/// Measured child resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measurement {
    /// Parent-measured wall time.
    pub wall_time_ms: u64,
    /// Peak resident set size in KiB.
    pub peak_rss_kb: u64,
    /// Exact child stdout size.
    pub output_bytes: u64,
}

/// Receipt digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Digests {
    /// Digest of the case input.
    pub input_sha256: String,
    /// Digest of the deterministic observation core.
    pub observed_sha256: String,
    /// Digest of exact child stdout.
    pub stdout_sha256: String,
    /// Digest of exact child stderr.
    pub stderr_sha256: String,
}

/// Toolchain and image identity plus the exact command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    /// Crate version.
    pub crate_version: String,
    /// Exact `rustc --version` text.
    pub rustc_version: String,
    /// Container image name.
    pub image: String,
    /// Container image id.
    pub image_id: String,
    /// Exact argv vector.
    pub command: Vec<String>,
}

/// One canonical evaluation receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// Receipt schema.
    pub schema: String,
    /// Spec identifier.
    pub spec: String,
    /// Frozen protocol digest.
    pub protocol_sha256: String,
    /// Case id.
    pub case_id: String,
    /// Hypothesis id.
    pub hypothesis: String,
    /// Category.
    pub category: String,
    /// Arm id.
    pub arm: String,
    /// Arm kind.
    pub arm_kind: String,
    /// Pre-registered expectation.
    pub expected: String,
    /// Observed label.
    pub observed: String,
    /// `expected == observed`.
    pub pass: bool,
    /// Case truth label.
    pub truth: String,
    /// Labels that count as accepting the case claim.
    pub accept_outcomes: Vec<String>,
    /// Blocked reason, when the arm is typed `NOT_RUN`.
    pub blocked: Option<String>,
    /// Measured resources.
    pub measurements: Measurement,
    /// Digests.
    pub digests: Digests,
    /// Deterministic observation detail.
    pub detail: String,
    /// Environment and command.
    pub environment: Environment,
    /// Digest of the deterministic experiment fields (resource fields excluded).
    pub experiment_sha256: String,
}

impl Receipt {
    /// Canonical receipt bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EvaluationError::Encoding`] if canonical encoding fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EvaluationError> {
        canonical_value_bytes(
            &serde_json::to_value(self)
                .map_err(|error| EvaluationError::Json(format!("receipt: {error}")))?,
        )
    }

    /// Stable key used by claims.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}::{}", self.case_id, self.arm)
    }
}

fn experiment_core(receipt: &Receipt) -> Value {
    json!({
        "protocol_sha256": receipt.protocol_sha256,
        "case_id": receipt.case_id,
        "arm": receipt.arm,
        "expected": receipt.expected,
        "observed": receipt.observed,
        "pass": receipt.pass,
        "truth": receipt.truth,
        "input_sha256": receipt.digests.input_sha256,
        "observed_sha256": receipt.digests.observed_sha256,
    })
}

fn experiment_sha256(receipt: &Receipt) -> Result<String, EvaluationError> {
    hash_value(&experiment_core(receipt))
}

/// Build a receipt, refusing to emit one without required measurements.
///
/// # Errors
///
/// Returns [`EvaluationError::MissingMeasurement`] when wall time, peak RSS, or
/// output size is absent or zero where required, and
/// [`EvaluationError::Receipt`] when an identity or digest is malformed.
#[allow(clippy::too_many_arguments)]
pub fn build_receipt(
    protocol_sha256: &str,
    case: &CaseSpec,
    arm: &ArmSpec,
    observation: &Observation,
    measurement: Option<Measurement>,
    environment: &Environment,
    stdout_sha256: String,
    stderr_sha256: String,
) -> Result<Receipt, EvaluationError> {
    let measurement = measurement.ok_or_else(|| {
        EvaluationError::MissingMeasurement(format!(
            "{}::{} has no wall-time/peak-RSS measurement",
            case.id, arm.id
        ))
    })?;
    if measurement.peak_rss_kb == 0 {
        return Err(EvaluationError::MissingMeasurement(format!(
            "{}::{} has zero peak RSS",
            case.id, arm.id
        )));
    }
    if measurement.output_bytes == 0 {
        return Err(EvaluationError::MissingMeasurement(format!(
            "{}::{} has zero output bytes",
            case.id, arm.id
        )));
    }
    if observation.observed.is_empty() || observation.input_sha256.len() != 64 {
        return Err(EvaluationError::Receipt(format!(
            "{}::{} has an invalid observation",
            case.id, arm.id
        )));
    }
    if protocol_sha256.len() != 64 || stdout_sha256.len() != 64 || stderr_sha256.len() != 64 {
        return Err(EvaluationError::Receipt(
            "a receipt digest is not 64 hexadecimal characters".to_owned(),
        ));
    }
    if environment.rustc_version.is_empty()
        || environment.image.is_empty()
        || environment.command.is_empty()
    {
        return Err(EvaluationError::MissingMeasurement(
            "toolchain, image, or exact command is absent".to_owned(),
        ));
    }
    let observed_sha256 = observation.observed_sha256()?;
    let mut receipt = Receipt {
        schema: EVALUATION_RECEIPT_SCHEMA.to_owned(),
        spec: EVALUATION_SPEC.to_owned(),
        protocol_sha256: protocol_sha256.to_owned(),
        case_id: case.id.clone(),
        hypothesis: case.hypothesis.clone(),
        category: case.category.clone(),
        arm: arm.id.clone(),
        arm_kind: arm.kind.clone(),
        expected: arm.expected.clone(),
        observed: observation.observed.clone(),
        pass: arm.expected == observation.observed,
        truth: case.truth.clone(),
        accept_outcomes: case.accept_outcomes.clone(),
        blocked: (observation.observed == NOT_RUN).then(|| observation.detail.clone()),
        measurements: measurement,
        digests: Digests {
            input_sha256: observation.input_sha256.clone(),
            observed_sha256,
            stdout_sha256,
            stderr_sha256,
        },
        detail: observation.detail.clone(),
        environment: environment.clone(),
        experiment_sha256: String::new(),
    };
    receipt.experiment_sha256 = experiment_sha256(&receipt)?;
    Ok(receipt)
}

fn vm_hwm_kb() -> Option<u64> {
    let text = fs::read_to_string("/proc/self/status").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn observation(label: &str, input_sha256: String, detail: &str) -> Observation {
    Observation {
        observed: label.to_owned(),
        input_sha256,
        detail: detail.to_owned(),
        vm_hwm_kb: vm_hwm_kb(),
    }
}

// ---------------------------------------------------------------------------
// Support arms
// ---------------------------------------------------------------------------

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn support_case(
    case_id: &str,
) -> Result<(RuleSystem, String, BTreeSet<String>, BTreeSet<String>), EvaluationError> {
    let mut system = RuleSystem::new();
    let mut excluded = BTreeSet::new();
    let challenged = BTreeSet::new();
    let target;
    match case_id {
        "S1-grounded-cycle" => {
            system.admit_leaf("a");
            system.add_rule("p", ["q".to_owned()])?;
            system.add_rule("p", ["a".to_owned()])?;
            system.add_rule("q", ["p".to_owned()])?;
            target = "p".to_owned();
        }
        "S2-ungrounded-self-cycle" => {
            system.add_rule("q", ["q".to_owned()])?;
            target = "q".to_owned();
        }
        "S3-ungrounded-mutual-cycle" => {
            system.add_rule("p", ["q".to_owned()])?;
            system.add_rule("q", ["p".to_owned()])?;
            target = "p".to_owned();
        }
        "S4-hidden-intermediate-cut" => {
            system.admit_leaf("a");
            system.add_rule("u", ["a".to_owned()])?;
            system.add_rule("q", ["u".to_owned()])?;
            excluded = set(&["u"]);
            target = "q".to_owned();
        }
        "S5-shared-mapping-cut" => {
            system.admit_leaf("m");
            system.add_rule("a", ["m".to_owned()])?;
            system.add_rule("b", ["m".to_owned()])?;
            system.add_rule("q", ["a".to_owned()])?;
            system.add_rule("q", ["b".to_owned()])?;
            excluded = set(&["m"]);
            target = "q".to_owned();
        }
        "S6-exact-cut-unrelated-survives" | "S7-exact-cut-required-cut" => {
            system.admit_leaf("a");
            system.admit_leaf("b");
            system.add_rule("u", ["a".to_owned()])?;
            system.add_rule("q", ["u".to_owned()])?;
            system.add_rule("w", ["b".to_owned()])?;
            system.add_rule("r", ["w".to_owned()])?;
            excluded = set(&["u"]);
            target = "q".to_owned();
        }
        other => {
            return Err(EvaluationError::Protocol(format!(
                "unsupported support case {other}"
            )))
        }
    }
    Ok((system, target, excluded, challenged))
}

fn greatest_fixed_point(system: &RuleSystem) -> BTreeSet<String> {
    let mut supported: BTreeSet<String> = system.nodes();
    loop {
        let mut remove = Vec::new();
        for claim in &supported {
            if system.admitted_leaves.contains(claim) {
                continue;
            }
            let satisfied = system.rules.get(claim).is_some_and(|rules| {
                rules
                    .iter()
                    .any(|premises| premises.iter().all(|premise| supported.contains(premise)))
            });
            if !satisfied {
                remove.push(claim.clone());
            }
        }
        if remove.is_empty() {
            break;
        }
        for claim in remove {
            supported.remove(&claim);
        }
    }
    supported
}

fn support_input(
    case_id: &str,
    arm: &str,
    system: &RuleSystem,
    target: &str,
    excluded: &BTreeSet<String>,
) -> Result<String, EvaluationError> {
    hash_value(&json!({
        "case_id": case_id,
        "arm": arm,
        "system": system,
        "target": target,
        "excluded": excluded,
    }))
}

fn observe_support(case_id: &str, arm: &str) -> Result<Observation, EvaluationError> {
    let (system, target, excluded, challenged) = support_case(case_id)?;
    let input_sha256 = support_input(case_id, arm, &system, &target, &excluded)?;
    match arm {
        "lfp" => {
            let result = evaluate(&system, &excluded, &challenged);
            let label = if result.is_supported(&target) {
                "supported"
            } else {
                "unsupported"
            };
            Ok(observation(
                label,
                input_sha256,
                "least fixed point over admitted leaves",
            ))
        }
        "gfp" => {
            let supported = greatest_fixed_point(&system);
            let label = if supported.contains(&target) {
                "supported"
            } else {
                "unsupported"
            };
            Ok(observation(
                label,
                input_sha256,
                "greatest-fixed-point mutant",
            ))
        }
        "all_node_certificates" => {
            let families = certificates(&system, &target, &excluded, 64)?;
            let cut = exact_cut(&families, &excluded);
            Ok(observation(
                if cut { "cut_applies" } else { "cut_missed" },
                input_sha256,
                "all-node certificate family intersected with exclusions",
            ))
        }
        "root_only_certificates" => {
            let mut mutant = BTreeSet::new();
            mutant.insert(target.clone());
            let cut = exact_cut(&[mutant], &excluded);
            Ok(observation(
                if cut { "cut_applies" } else { "cut_missed" },
                input_sha256,
                "root-only certificate mutant",
            ))
        }
        "direct_premises" => {
            let cut_missed = system.rules.get(&target).is_some_and(|rules| {
                rules.iter().any(|premises| {
                    !premises.is_empty()
                        && premises.iter().all(|premise| !excluded.contains(premise))
                })
            });
            Ok(observation(
                if cut_missed {
                    "cut_missed"
                } else {
                    "cut_applies"
                },
                input_sha256,
                "direct-premise mutant ignores shared transitive premises",
            ))
        }
        "exact_cut" => {
            let q_certificates = certificates(&system, "q", &excluded, 64)?;
            let q_cut = exact_cut(&q_certificates, &excluded);
            let label = if case_id == "S6-exact-cut-unrelated-survives" {
                let r_certificates = certificates(&system, "r", &excluded, 64)?;
                let r_cut = exact_cut(&r_certificates, &excluded);
                match (q_cut, r_cut) {
                    (true, false) => "exact_partition",
                    (true, true) => "cut",
                    (false, false) => "survives",
                    (false, true) => "inconsistent",
                }
            } else if q_cut {
                "cut"
            } else {
                "survives"
            };
            Ok(observation(
                label,
                input_sha256,
                "exact-cut predicate over every supported node",
            ))
        }
        "over_cut" => {
            let q_certificates = certificates(&system, "q", &excluded, 64)?;
            let q_cut = exact_cut(&q_certificates, &excluded);
            let label = if case_id == "S6-exact-cut-unrelated-survives" {
                if q_cut && !excluded.is_empty() {
                    "over_cut"
                } else {
                    "cut"
                }
            } else if q_cut {
                "cut"
            } else {
                "survives"
            };
            Ok(observation(
                label,
                input_sha256,
                "over-cut mutant cuts every supported claim on any exclusion",
            ))
        }
        other => Err(EvaluationError::Protocol(format!(
            "unsupported support arm {other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Path arms
// ---------------------------------------------------------------------------

fn object(id: &str) -> ObjectDecl {
    ObjectDecl {
        id: id.to_owned(),
        interior_mutable: false,
    }
}

fn alias_exact(id: &str, object_id: &str) -> AliasDecl {
    AliasDecl {
        id: id.to_owned(),
        kind: AliasKind::ExactObject,
        object: Some(object_id.to_owned()),
        mapping: None,
        range: None,
    }
}

fn alias_descendant(id: &str, object_id: &str, offset: u64, length: u64) -> AliasDecl {
    AliasDecl {
        id: id.to_owned(),
        kind: AliasKind::Descendant,
        object: Some(object_id.to_owned()),
        mapping: None,
        range: Some(ByteRange { offset, length }),
    }
}

fn alias_shared(id: &str, mapping: &str, offset: u64, length: u64) -> AliasDecl {
    AliasDecl {
        id: id.to_owned(),
        kind: AliasKind::SharedMapping,
        object: None,
        mapping: Some(mapping.to_owned()),
        range: Some(ByteRange { offset, length }),
    }
}

fn alias_top(id: &str) -> AliasDecl {
    AliasDecl {
        id: id.to_owned(),
        kind: AliasKind::TopUnknown,
        object: None,
        mapping: None,
        range: None,
    }
}

fn interval(id: &str, alias: &str, start: u64, end: Option<u64>) -> ReferenceIntervalDecl {
    ReferenceIntervalDecl {
        id: id.to_owned(),
        alias: alias.to_owned(),
        start,
        end,
    }
}

fn footprint(kind: FootprintKind, range: Option<ByteRange>) -> Footprint {
    Footprint { kind, range }
}

fn event(
    point: u64,
    alias: &str,
    access: AccessMode,
    footprint: Footprint,
    interval: Option<&str>,
) -> PathEvent {
    PathEvent {
        point,
        kind: EventKind::Use,
        alias: alias.to_owned(),
        access,
        footprint,
        interval: interval.map(str::to_owned),
        callback: None,
    }
}

fn path_case(case_id: &str) -> Result<PathEffectsInput, EvaluationError> {
    let mut input = PathEffectsInput::empty();
    let range = |offset, length| Some(ByteRange { offset, length });
    match case_id {
        "P1-path-exact-whole-conflicts" => {
            input.objects = vec![object("a")];
            input.aliases = vec![
                alias_exact("whole", "a"),
                alias_descendant("part", "a", 8, 8),
            ];
            input.intervals = vec![
                interval("i1", "whole", 0, Some(10)),
                interval("i2", "part", 0, Some(10)),
            ];
            input.events = vec![
                event(
                    0,
                    "whole",
                    AccessMode::Write,
                    footprint(FootprintKind::Exact, None),
                    Some("i1"),
                ),
                event(
                    1,
                    "part",
                    AccessMode::Write,
                    footprint(FootprintKind::Descendant, None),
                    Some("i2"),
                ),
            ];
        }
        "P2-path-descendant-disjoint" => {
            input.objects = vec![object("a")];
            input.aliases = vec![
                alias_descendant("whole", "a", 0, 8),
                alias_descendant("part", "a", 8, 8),
            ];
            input.intervals = vec![
                interval("i1", "whole", 0, Some(10)),
                interval("i2", "part", 0, Some(10)),
            ];
            input.events = vec![
                event(
                    0,
                    "whole",
                    AccessMode::Write,
                    footprint(FootprintKind::Descendant, range(0, 8)),
                    Some("i1"),
                ),
                event(
                    1,
                    "part",
                    AccessMode::Write,
                    footprint(FootprintKind::Descendant, range(8, 8)),
                    Some("i2"),
                ),
            ];
        }
        "P3-path-shared-mapping-disjoint" => {
            input.objects = vec![object("a")];
            input.aliases = vec![alias_exact("p", "a"), alias_shared("s", "m", 8, 8)];
            input.intervals = vec![
                interval("i1", "p", 0, Some(10)),
                interval("i2", "s", 0, Some(10)),
            ];
            input.events = vec![
                event(
                    0,
                    "p",
                    AccessMode::Write,
                    footprint(FootprintKind::Exact, None),
                    Some("i1"),
                ),
                event(
                    1,
                    "s",
                    AccessMode::Write,
                    footprint(FootprintKind::Descendant, None),
                    Some("i2"),
                ),
            ];
        }
        "P4-path-descendant-vs-top" => {
            input.objects = vec![object("a")];
            input.aliases = vec![alias_descendant("p", "a", 0, 8), alias_top("u")];
            input.intervals = vec![
                interval("i1", "p", 0, Some(10)),
                interval("i2", "u", 0, Some(10)),
            ];
            input.events = vec![
                event(
                    0,
                    "p",
                    AccessMode::Write,
                    footprint(FootprintKind::Descendant, None),
                    Some("i1"),
                ),
                event(
                    1,
                    "u",
                    AccessMode::Write,
                    footprint(FootprintKind::Top, None),
                    Some("i2"),
                ),
            ];
        }
        "P5-path-omission-vs-not-falsified" => {
            input.callbacks = vec![
                CallbackDecl {
                    id: "c1".to_owned(),
                    behavior: CallbackBehavior::SynchronousLegal,
                    legally_absent: true,
                },
                CallbackDecl {
                    id: "c2".to_owned(),
                    behavior: CallbackBehavior::SynchronousLegal,
                    legally_absent: false,
                },
            ];
        }
        "P6-path-foreign-provider" => {
            input.providers = vec![ProviderDecl {
                id: "fp".to_owned(),
                behavior: ProviderBehavior::ForeignUnknown,
            }];
        }
        "P7-path-independent-allocations" => {
            input.objects = vec![object("a"), object("b")];
            input.aliases = vec![alias_exact("p", "a"), alias_exact("q", "b")];
            input.intervals = vec![
                interval("i1", "p", 0, Some(10)),
                interval("i2", "q", 0, Some(10)),
            ];
            input.events = vec![
                event(
                    0,
                    "p",
                    AccessMode::Write,
                    footprint(FootprintKind::Exact, None),
                    Some("i1"),
                ),
                event(
                    1,
                    "q",
                    AccessMode::Write,
                    footprint(FootprintKind::Exact, None),
                    Some("i2"),
                ),
            ];
        }
        other => {
            return Err(EvaluationError::Protocol(format!(
                "unsupported path case {other}"
            )))
        }
    }
    Ok(input)
}

#[derive(Clone, Copy)]
enum NaivePath {
    Boolean,
    TopAsExact,
    MappingIndependent,
    ProviderIgnored,
}

fn naive_path_label(input: &PathEffectsInput, mode: NaivePath) -> &'static str {
    if matches!(mode, NaivePath::ProviderIgnored)
        && !input.providers.is_empty()
        && input.events.is_empty()
    {
        return "compatible_within_finite_footprint";
    }
    let mut aliases = BTreeMap::new();
    for alias in &input.aliases {
        let key = match alias.kind {
            AliasKind::ExactObject | AliasKind::Descendant => {
                alias.object.clone().unwrap_or_default()
            }
            AliasKind::SharedMapping => {
                if matches!(mode, NaivePath::MappingIndependent) {
                    format!("mapping:{}", alias.mapping.clone().unwrap_or_default())
                } else {
                    alias.mapping.clone().unwrap_or_default()
                }
            }
            AliasKind::TopUnknown => "\u{0}top".to_owned(),
        };
        aliases.insert(alias.id.as_str(), key);
    }
    let windows: BTreeMap<&str, (u64, u64)> = input
        .intervals
        .iter()
        .map(|interval| {
            (
                interval.id.as_str(),
                (interval.start, interval.end.unwrap_or(u64::MAX)),
            )
        })
        .collect();
    for left in 0..input.events.len() {
        for right in (left + 1)..input.events.len() {
            let a = &input.events[left];
            let b = &input.events[right];
            if a.access == AccessMode::Read && b.access == AccessMode::Read {
                continue;
            }
            let window = |event: &PathEvent| {
                event
                    .interval
                    .as_deref()
                    .and_then(|id| windows.get(id).copied())
                    .unwrap_or((event.point, event.point.saturating_add(1)))
            };
            let (a_start, a_end) = window(a);
            let (b_start, b_end) = window(b);
            if a_start >= b_end || b_start >= a_end {
                continue;
            }
            let a_key = aliases.get(a.alias.as_str()).cloned().unwrap_or_default();
            let b_key = aliases.get(b.alias.as_str()).cloned().unwrap_or_default();
            let top = a_key == "\u{0}top" || b_key == "\u{0}top";
            let conflict = match mode {
                NaivePath::Boolean | NaivePath::TopAsExact => top || a_key == b_key,
                NaivePath::MappingIndependent | NaivePath::ProviderIgnored => a_key == b_key,
            };
            if conflict {
                return "observed_conflict";
            }
        }
    }
    "compatible_within_finite_footprint"
}

fn path_input(
    case_id: &str,
    arm: &str,
    input: &PathEffectsInput,
) -> Result<String, EvaluationError> {
    hash_value(&json!({
        "case_id": case_id,
        "arm": arm,
        "input": input,
    }))
}

fn observe_path(case_id: &str, arm: &str) -> Result<Observation, EvaluationError> {
    let input = path_case(case_id)?;
    let input_sha256 = path_input(case_id, arm, &input)?;
    match arm {
        "exact_footprint" => {
            let report = analyze(&input)?;
            let label = if case_id == "P5-path-omission-vs-not-falsified" {
                let c1 = report.outcomes.iter().any(|outcome| {
                    outcome.subject == "c1" && outcome.status == QualifiedStatus::Omission
                });
                let c2 = report.outcomes.iter().any(|outcome| {
                    outcome.subject == "c2" && outcome.status == QualifiedStatus::NotFalsified
                });
                if c1 && c2 {
                    "omission_and_not_falsified"
                } else {
                    "other"
                }
            } else {
                report.overall.as_str()
            };
            Ok(observation(
                label,
                input_sha256,
                "explicit finite path analysis",
            ))
        }
        "boolean_aliasing" => Ok(observation(
            naive_path_label(&input, NaivePath::Boolean),
            input_sha256,
            "boolean same-object aliasing ignores explicit ranges",
        )),
        "top_as_exact" => Ok(observation(
            naive_path_label(&input, NaivePath::TopAsExact),
            input_sha256,
            "top alias treated as an exact whole object",
        )),
        "mapping_as_independent" => Ok(observation(
            naive_path_label(&input, NaivePath::MappingIndependent),
            input_sha256,
            "shared mapping treated as an independent allocation",
        )),
        "provider_ignored" => Ok(observation(
            naive_path_label(&input, NaivePath::ProviderIgnored),
            input_sha256,
            "foreign provider unknowns ignored",
        )),
        "absent_is_omission" => Ok(observation(
            "omission_only",
            input_sha256,
            "every unobserved callback treated as legally absent",
        )),
        "absent_is_not_falsified" => Ok(observation(
            "not_falsified_only",
            input_sha256,
            "every unobserved callback treated as uncertain",
        )),
        other => Err(EvaluationError::Protocol(format!(
            "unsupported path arm {other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Detector arms
// ---------------------------------------------------------------------------

fn stream(text: &str) -> Value {
    json!({
        "text": text,
        "sha256": sha256_text(text),
        "truncated": false,
    })
}

fn capture(exit_code: i32, stdout: &str, stderr: &str) -> Value {
    json!({
        "stdout": stream(stdout),
        "stderr": stream(stderr),
        "exit_code": exit_code,
        "signal": null,
        "duration_ms": 1,
    })
}

fn finding(mechanism: &str, fingerprint: &str, source: &str) -> Value {
    json!({
        "mechanism": mechanism,
        "diagnostic_fingerprint": fingerprint,
        "source": source,
    })
}

#[allow(clippy::needless_pass_by_value)]
fn detector_case(
    case_id: &str,
    role: &str,
    origin: &str,
    capture: Value,
    finding: Option<Value>,
    _detector: Value,
) -> Value {
    let fixture = "e".repeat(64);
    json!({
        "case_id": case_id,
        "role": role,
        "fixture_digest": fixture,
        "expected_mechanism": "address",
        "legality": "test_only",
        "capture": capture,
        "provenance": {
            "origin": origin,
            "case_id": case_id,
            "fixture_digest": fixture,
            "mechanism": "address",
            "legality": "test_only",
        },
        "finding": finding,
    })
}

fn detector_identity(flags: &[&str], baseline_flags: &[&str]) -> Value {
    json!({
        "kind": "address_sanitizer",
        "tool_name": "gcc",
        "tool_version": "12.2.0",
        "executable_sha256": "a".repeat(64),
        "invocation_argv": ["gcc", "-fsanitize=address", "-O1", "-g", "fixture.c"],
        "environment_digest": "b".repeat(64),
        "mechanism_enablement": ["address"],
        "build": {
            "flags": flags,
            "target": "x86_64-unknown-linux-gnu",
            "profile": "release",
            "build_directory": "/build/asan",
            "artifact_sha256": "c".repeat(64),
        },
        "baseline_build": {
            "flags": baseline_flags,
            "target": "x86_64-unknown-linux-gnu",
            "profile": "release",
            "build_directory": "/build/baseline",
            "artifact_sha256": "d".repeat(64),
        },
        "build_separation_verified": true,
    })
}

fn detector_evidence(case_id: &str) -> Result<Value, EvaluationError> {
    let diagnostic = "AddressSanitizer: heap-use-after-free\n";
    let detected = finding("address", "AddressSanitizer: heap-use-after-free", "stderr");
    let clean_good = detector_case(
        "known-good",
        "known_good",
        "authentic_live_tool",
        capture(0, "", ""),
        None,
        detector_identity(&["-fsanitize=address", "-O1", "-g"], &["-O1", "-g"]),
    );
    let good_with = |detector: Value| {
        detector_case(
            "known-good",
            "known_good",
            "authentic_live_tool",
            capture(0, "", ""),
            None,
            detector,
        )
    };
    let evidence = match case_id {
        "D1-detector-authentic-calibrated" => json!({
            "schema": DETECTOR_EVIDENCE_SCHEMA,
            "spec": DETECTOR_SPEC,
            "detector": detector_identity(&["-fsanitize=address", "-O1", "-g"], &["-O1", "-g"]),
            "cases": [
                detector_case("known-bad", "known_bad", "authentic_live_tool", capture(1, "", diagnostic), Some(detected), detector_identity(&["-fsanitize=address", "-O1", "-g"], &["-O1", "-g"])),
                clean_good,
            ],
        }),
        "D2-detector-raw-stdout-no-finding" => json!({
            "schema": DETECTOR_EVIDENCE_SCHEMA,
            "spec": DETECTOR_SPEC,
            "detector": detector_identity(&["-fsanitize=address", "-O1", "-g"], &["-O1", "-g"]),
            "cases": [
                detector_case("known-bad", "known_bad", "authentic_live_tool", capture(1, diagnostic, ""), None, detector_identity(&["-fsanitize=address", "-O1", "-g"], &["-O1", "-g"])),
                clean_good,
            ],
        }),
        "D3-detector-dead" => json!({
            "schema": DETECTOR_EVIDENCE_SCHEMA,
            "spec": DETECTOR_SPEC,
            "detector": detector_identity(&["-fsanitize=address", "-O1", "-g"], &["-O1", "-g"]),
            "cases": [
                detector_case("known-bad", "known_bad", "authentic_live_tool", capture(0, "", ""), None, detector_identity(&["-fsanitize=address", "-O1", "-g"], &["-O1", "-g"])),
                clean_good,
            ],
        }),
        "D4-detector-misconfigured" => json!({
            "schema": DETECTOR_EVIDENCE_SCHEMA,
            "spec": DETECTOR_SPEC,
            "detector": detector_identity(&["-O1", "-g"], &["-O1", "-g"]),
            "cases": [
                detector_case("known-bad", "known_bad", "authentic_live_tool", capture(1, "", diagnostic), Some(detected), detector_identity(&["-O1", "-g"], &["-O1", "-g"])),
                good_with(detector_identity(&["-O1", "-g"], &["-O1", "-g"])),
            ],
        }),
        "D5-detector-mock-provider" => json!({
            "schema": DETECTOR_EVIDENCE_SCHEMA,
            "spec": DETECTOR_SPEC,
            "detector": detector_identity(&["-fsanitize=address", "-O1", "-g"], &["-O1", "-g"]),
            "cases": [
                detector_case("known-bad", "known_bad", "mock_provider", capture(1, "", diagnostic), Some(detected), detector_identity(&["-fsanitize=address", "-O1", "-g"], &["-O1", "-g"])),
                detector_case("known-good", "known_good", "mock_provider", capture(0, "", ""), None, detector_identity(&["-fsanitize=address", "-O1", "-g"], &["-O1", "-g"])),
            ],
        }),
        other => {
            return Err(EvaluationError::Protocol(format!(
                "unsupported detector case {other}"
            )))
        }
    };
    Ok(evidence)
}

fn detector_label(report: &crate::detector::CalibrationReport) -> &'static str {
    if report.outcome == CalibrationOutcome::Calibrated {
        return "calibrated";
    }
    let priority = [
        (
            CalibrationRefusalCode::DeadDetector,
            "refused_dead_detector",
        ),
        (
            CalibrationRefusalCode::MissingFinding,
            "refused_missing_finding",
        ),
        (
            CalibrationRefusalCode::MisconfiguredBuildFlags,
            "refused_misconfigured_build_flags",
        ),
        (
            CalibrationRefusalCode::MissingMechanismEnablement,
            "refused_missing_mechanism_enablement",
        ),
        (
            CalibrationRefusalCode::BuildSeparationMismatch,
            "refused_build_separation",
        ),
        (
            CalibrationRefusalCode::MockProviderTransport,
            "refused_mock_provider_transport",
        ),
        (
            CalibrationRefusalCode::SubstituteTransport,
            "refused_substitute_transport",
        ),
        (
            CalibrationRefusalCode::ModeledEvidence,
            "refused_modeled_evidence",
        ),
        (
            CalibrationRefusalCode::UntrustedDetectorIdentity,
            "refused_untrusted_identity",
        ),
        (
            CalibrationRefusalCode::FakeStdoutMarker,
            "refused_fake_stdout_marker",
        ),
        (
            CalibrationRefusalCode::FindingNotInCapture,
            "refused_finding_not_in_capture",
        ),
        (
            CalibrationRefusalCode::MechanismMismatch,
            "refused_mechanism_mismatch",
        ),
        (
            CalibrationRefusalCode::HarmlessControlFinding,
            "refused_harmless_control_finding",
        ),
        (
            CalibrationRefusalCode::HarmlessControlDirtyExit,
            "refused_harmless_control_exit",
        ),
    ];
    for (code, label) in priority {
        if report.refusals.iter().any(|refusal| refusal.code == code) {
            return label;
        }
    }
    "refused_other"
}

fn raw_stdout_label(evidence: &DetectorEvidence) -> &'static str {
    let marker = |case: &crate::detector::CalibrationCase| {
        case.capture.stdout.text.contains("Sanitizer:")
            || case.capture.stderr.text.contains("Sanitizer:")
    };
    let detected = evidence
        .cases
        .iter()
        .filter(|case| case.role == crate::detector::CalibrationRole::KnownBad)
        .any(marker);
    let clean_good = evidence
        .cases
        .iter()
        .filter(|case| case.role == crate::detector::CalibrationRole::KnownGood)
        .all(|case| !marker(case));
    if detected && clean_good {
        "calibrated"
    } else {
        "refused_missing_finding"
    }
}

fn job_success_label(evidence: &DetectorEvidence) -> &'static str {
    if evidence
        .cases
        .iter()
        .all(|case| case.capture.exit_code == 0)
    {
        "calibrated"
    } else {
        "refused_job_failure"
    }
}

fn origin_ignored_label(mut evidence: DetectorEvidence) -> &'static str {
    for case in &mut evidence.cases {
        case.provenance.origin = DetectorOrigin::AuthenticLiveTool;
    }
    match evaluate_calibration(&evidence) {
        Ok(report) => detector_label(&report),
        Err(_) => "integrity_error",
    }
}

fn observe_detector(case_id: &str, arm: &str) -> Result<Observation, EvaluationError> {
    if arm == "live_miri" {
        return Ok(observation(
            NOT_RUN,
            sha256_text(case_id),
            "live detector execution is opt-in and absent in the default image",
        ));
    }
    let value = detector_evidence(case_id)?;
    let bytes = canonical_value_bytes(&value)?;
    let input_sha256 = sha256_hex(&bytes);
    let evidence = match parse_evidence(&bytes) {
        Ok(evidence) => evidence,
        Err(error) => {
            return Ok(observation(
                "integrity_error",
                input_sha256,
                &format!("evidence parse failed: {error}"),
            ))
        }
    };
    let label = match arm {
        "calibrated" => match evaluate_calibration(&evidence) {
            Ok(report) => detector_label(&report).to_owned(),
            Err(error) => format!("integrity_error: {error}"),
        },
        "raw_stdout" => raw_stdout_label(&evidence).to_owned(),
        "job_success" => job_success_label(&evidence).to_owned(),
        "origin_ignored" => origin_ignored_label(evidence).to_owned(),
        "live_miri" => NOT_RUN.to_owned(),
        other => {
            return Err(EvaluationError::Protocol(format!(
                "unsupported detector arm {other}"
            )))
        }
    };
    Ok(observation(
        &label,
        input_sha256,
        "typed detector evidence adjudication",
    ))
}

// ---------------------------------------------------------------------------
// Proof arms
// ---------------------------------------------------------------------------

fn proof_manifest_path(case_id: &str) -> Result<&'static str, EvaluationError> {
    match case_id {
        "R1-proof-approved" | "R5-proof-live-coq" => Ok("tests/proof/coq/manifest-approved.json"),
        "R2-proof-unchecked-wrapper" => Ok("tests/proof/coq/manifest-unchecked.json"),
        "R3-proof-admitted-dependency" => Ok("tests/proof/coq/manifest-admitted.json"),
        "R4-proof-missing-transition" => Ok("tests/proof/coq/manifest-missing-transition.json"),
        other => Err(EvaluationError::Protocol(format!(
            "unsupported proof case {other}"
        ))),
    }
}

fn observe_proof(case_id: &str, arm: &str) -> Result<Observation, EvaluationError> {
    let path = proof_manifest_path(case_id)?;
    let bytes = fs::read(path).map_err(|error| EvaluationError::Io(format!("{path}: {error}")))?;
    let input_sha256 = sha256_hex(&bytes);
    let label = match arm {
        "parser_only" => match parse_manifest(&bytes) {
            Ok(_) => "accepted_within_scope".to_owned(),
            Err(error) => format!("integrity_error: {error}"),
        },
        "closure_and_correspondence" => {
            let manifest = match parse_manifest(&bytes) {
                Ok(manifest) => manifest,
                Err(error) => {
                    return Ok(observation(
                        "integrity_error",
                        input_sha256,
                        &format!("manifest parse failed: {error}"),
                    ))
                }
            };
            let base = Path::new("tests/proof/coq");
            let admission = evaluate_admission(&manifest, base)?;
            let correspondence = evaluate_correspondence(&manifest, base)?;
            match admission.outcome {
                ProofOutcome::RejectedAssumption | ProofOutcome::RejectedUnrelated => {
                    admission.outcome.as_str().to_owned()
                }
                _ => match correspondence.outcome {
                    Some(outcome) => outcome.as_str().to_owned(),
                    None => {
                        if admission.outcome == ProofOutcome::AcceptedWithinScope {
                            "accepted_admission_checker_unavailable".to_owned()
                        } else {
                            admission.outcome.as_str().to_owned()
                        }
                    }
                },
            }
        }
        "live_coq" => {
            if std::env::var("FRF_EVAL_LIVE_PROOF").as_deref() == Ok("1") {
                match verify_manifest_bytes_live(&bytes, Path::new("tests/proof/coq")) {
                    Ok(report) => report.outcome.as_str().to_owned(),
                    Err(error) => format!("integrity_error: {error}"),
                }
            } else {
                NOT_RUN.to_owned()
            }
        }
        other => {
            return Err(EvaluationError::Protocol(format!(
                "unsupported proof arm {other}"
            )))
        }
    };
    Ok(observation(
        &label,
        input_sha256,
        "digest-bound proof manifest",
    ))
}

// ---------------------------------------------------------------------------
// Discovery arms
// ---------------------------------------------------------------------------

const CANDIDATE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_CANDIDATE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const EXECUTABLE: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn push_uint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = u8::try_from(value & 0x7f).unwrap_or(0x7f);
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn frf_object(candidate: &str) -> (String, String) {
    let run = format!("run-bridge-test-{}", "1".repeat(64));
    let value = json!({
        "schema_version": "frf-receipt-v20",
        "run": run,
        "court": {"id": "bridge-test", "question": "modeled", "falsifier": "modeled",
                  "admissibility_envelope": {}, "semantic_identity": "modeled"},
        "provenance": {},
        "authority": {},
        "candidate": {"identity_hash": candidate},
        "environment": {},
        "fixtures": [],
        "observables": [],
        "residuals": [],
        "endoduction": {},
        "claims": {},
        "replay": {}
    });
    let bytes = serde_json::to_vec(&value).unwrap_or_default();
    let identity = format!("receipt-{run}-{}", sha256_hex(&bytes));
    (identity, hex_encode(&bytes))
}

fn finding_object() -> (String, String) {
    let input = b"modeled";
    let mut payload = Vec::new();
    payload.push(1);
    payload.push(1);
    payload.extend_from_slice(&[0u8; 8]);
    let mut coordinate = [0u8; 49];
    coordinate[0] = 1;
    payload.extend_from_slice(&coordinate);
    payload.push(1);
    payload.extend_from_slice(&u32::try_from(input.len()).unwrap_or(0).to_le_bytes());
    payload.extend_from_slice(input);

    let mut bytes = b"FRFZ".to_vec();
    bytes.push(0x02);
    bytes.push(0);
    bytes.push(1);
    bytes.extend_from_slice(&u64::try_from(payload.len()).unwrap_or(0).to_le_bytes());
    bytes.extend_from_slice(&payload);
    let identity = blake3::hash(&bytes).to_hex().to_string();
    (identity, hex_encode(&bytes))
}

fn gemel_object(kind: &str) -> (String, String) {
    let mut producer = [0u8; 33];
    producer[0] = 0x0E;

    let mut kind_value = Vec::new();
    push_uint(&mut kind_value, u64::try_from(kind.len()).unwrap_or(0));
    kind_value.extend_from_slice(kind.as_bytes());

    let mut body = Vec::new();
    push_uint(&mut body, 0x01);
    push_uint(&mut body, 34);
    push_uint(&mut body, 33);
    body.extend_from_slice(&producer);
    push_uint(&mut body, 0x02);
    push_uint(&mut body, u64::try_from(kind_value.len()).unwrap_or(0));
    body.extend_from_slice(&kind_value);

    let mut bytes = b"GEML".to_vec();
    bytes.push(1);
    bytes.push(0x0B);
    bytes.push(1);
    bytes.push(0);
    push_uint(&mut bytes, u64::try_from(body.len()).unwrap_or(0));
    bytes.extend_from_slice(&body);
    let identity = format!("evidence.{}", blake3::hash(&bytes).to_hex());
    (identity, hex_encode(&bytes))
}

fn bridge_observation(
    provider: ExternalProvider,
    provenance: EvidenceProvenance,
    candidate: &str,
    subject: Option<String>,
) -> ExternalObservation {
    let (identity, bytes) = match provider {
        ExternalProvider::Frf => frf_object(candidate),
        ExternalProvider::FrfFuzz => finding_object(),
        ExternalProvider::Gemel => gemel_object("court_receipt"),
    };
    let contract = native_provider_contracts()
        .into_iter()
        .find(|contract| contract.provider == provider)
        .expect("provider contract is fixed");
    ExternalObservation {
        provider,
        provenance,
        repository: contract.repository.to_owned(),
        commit: contract.commit.to_owned(),
        schema: contract.schema.to_owned(),
        identity,
        subject_identity: subject,
        canonical_bytes_hex: bytes,
        candidate_sha256: candidate.to_owned(),
        executable_sha256: EXECUTABLE.to_owned(),
        dso_binding: DsoBinding::Native,
        reexecution: Reexecution::Matched,
        capture: None,
    }
}

fn bridge_bundle(provenance: EvidenceProvenance, expected: &str) -> EvidenceBundle {
    let frf = bridge_observation(ExternalProvider::Frf, provenance, CANDIDATE, None);
    let subject = frf.identity.clone();
    let mut observations = vec![
        bridge_observation(ExternalProvider::FrfFuzz, provenance, CANDIDATE, None),
        frf,
        bridge_observation(
            ExternalProvider::Gemel,
            provenance,
            CANDIDATE,
            Some(subject),
        ),
    ];
    if provenance == EvidenceProvenance::Modeled {
        // Keep the fixture deterministic; modeled evidence is refused before capture.
        for observation in &mut observations {
            observation.capture = None;
        }
    }
    EvidenceBundle {
        schema: BRIDGE_BUNDLE_SCHEMA.to_owned(),
        spec: BRIDGE_SPEC.to_owned(),
        expected_candidate_sha256: expected.to_owned(),
        observations,
    }
}

fn tampered_finding_bundle() -> EvidenceBundle {
    let mut bundle = bridge_bundle(EvidenceProvenance::Modeled, CANDIDATE);
    if let Some(observation) = bundle
        .observations
        .iter_mut()
        .find(|observation| observation.provider == ExternalProvider::FrfFuzz)
    {
        observation.canonical_bytes_hex.push_str("00");
    }
    bundle
}

fn bridge_label(report: &crate::bridge::BridgeReport) -> &'static str {
    match &report.outcome {
        BridgeOutcome::Complete => "complete",
        BridgeOutcome::Refused { reason } => match reason {
            BridgeRefusal::ModeledEvidence { .. } => "refused_modeled_evidence",
            BridgeRefusal::ModifiedProvider { .. } => "refused_modified_provider",
            BridgeRefusal::SubstituteProvider { .. } => "refused_substitute_provider",
            BridgeRefusal::StaleCandidate { .. } => "refused_stale_candidate",
            BridgeRefusal::SubstitutedDso { .. } => "refused_substituted_dso",
            BridgeRefusal::UnboundCustody { .. } => "refused_unbound_custody",
            BridgeRefusal::MissingObservation { .. } => "refused_missing_observation",
        },
        BridgeOutcome::Integrity { reason } => match reason {
            BridgeIntegrity::DigestMismatch { .. } => "integrity_digest_mismatch",
            _ => "integrity_other",
        },
        BridgeOutcome::NotRun { reason } => match reason {
            BridgeNotRun::MissingFinding
            | BridgeNotRun::MissingFrfReceipt
            | BridgeNotRun::MissingGemelCustody
            | BridgeNotRun::ProviderUnavailable { .. }
            | BridgeNotRun::ReexecutionNotRun { .. }
            | BridgeNotRun::NativeConfirmationNotRun { .. } => NOT_RUN,
        },
    }
}

fn discovery_bundle(case_id: &str) -> Result<EvidenceBundle, EvaluationError> {
    match case_id {
        "E1-discovery-modeled-provider" => {
            Ok(bridge_bundle(EvidenceProvenance::Modeled, CANDIDATE))
        }
        "E2-discovery-substitute-provider" => {
            Ok(bridge_bundle(EvidenceProvenance::Substitute, CANDIDATE))
        }
        "E3-discovery-stale-candidate" => {
            Ok(bridge_bundle(EvidenceProvenance::Modeled, OTHER_CANDIDATE))
        }
        "E4-discovery-tampered-finding" => Ok(tampered_finding_bundle()),
        "E5-discovery-missing-finding" => Ok(EvidenceBundle {
            schema: BRIDGE_BUNDLE_SCHEMA.to_owned(),
            spec: BRIDGE_SPEC.to_owned(),
            expected_candidate_sha256: CANDIDATE.to_owned(),
            observations: Vec::new(),
        }),
        "E6-discovery-authentic-chain" => {
            let path = std::env::var("FRF_BRIDGE_LIVE_BUNDLE").ok();
            if let Some(path) = path {
                let bytes = fs::read(&path)
                    .map_err(|error| EvaluationError::Io(format!("{path}: {error}")))?;
                let bundle: EvidenceBundle = serde_json::from_slice(&bytes)
                    .map_err(|error| EvaluationError::Json(format!("{path}: {error}")))?;
                Ok(bundle)
            } else {
                Ok(EvidenceBundle {
                    schema: BRIDGE_BUNDLE_SCHEMA.to_owned(),
                    spec: BRIDGE_SPEC.to_owned(),
                    expected_candidate_sha256: CANDIDATE.to_owned(),
                    observations: Vec::new(),
                })
            }
        }
        other => Err(EvaluationError::Protocol(format!(
            "unsupported discovery case {other}"
        ))),
    }
}

fn observe_discovery(case_id: &str, arm: &str) -> Result<Observation, EvaluationError> {
    let bundle = discovery_bundle(case_id)?;
    let value = serde_json::to_value(&bundle)
        .map_err(|error| EvaluationError::Json(format!("bundle: {error}")))?;
    let bytes = canonical_value_bytes(&value)?;
    let input_sha256 = sha256_hex(&bytes);
    let label = match arm {
        "bridge_verify" => {
            if case_id == "E6-discovery-authentic-chain"
                && std::env::var("FRF_BRIDGE_LIVE_BUNDLE").is_err()
            {
                NOT_RUN.to_owned()
            } else {
                let report = verify_bundle_bytes(&bytes, None);
                bridge_label(&report).to_owned()
            }
        }
        "provenance_ignored" => {
            if bundle.observations.is_empty()
                || bundle.observations.iter().any(|observation| {
                    observation.candidate_sha256 != bundle.expected_candidate_sha256
                })
            {
                "refused_stale_candidate".to_owned()
            } else {
                "complete".to_owned()
            }
        }
        "schema_only" => {
            if bundle.observations.is_empty() {
                NOT_RUN.to_owned()
            } else {
                "complete".to_owned()
            }
        }
        other => {
            return Err(EvaluationError::Protocol(format!(
                "unsupported discovery arm {other}"
            )))
        }
    };
    Ok(observation(
        &label,
        input_sha256,
        "external evidence bundle verification",
    ))
}

// ---------------------------------------------------------------------------
// Child execution
// ---------------------------------------------------------------------------

/// Execute one pre-registered case and arm in this process and return its
/// deterministic observation. This function executes no external tool unless
/// the explicit live opt-in environment variable is set.
///
/// # Errors
///
/// Returns [`EvaluationError::Protocol`] for unknown cases or arms, and
/// propagates analysis, I/O, or encoding failures.
pub fn observe_case(case_id: &str, arm: &str) -> Result<Observation, EvaluationError> {
    if case_id.starts_with('S') {
        return observe_support(case_id, arm);
    }
    if case_id.starts_with('P') {
        return observe_path(case_id, arm);
    }
    if case_id.starts_with('D') {
        return observe_detector(case_id, arm);
    }
    if case_id.starts_with('R') {
        return observe_proof(case_id, arm);
    }
    if case_id.starts_with('E') {
        return observe_discovery(case_id, arm);
    }
    Err(EvaluationError::Protocol(format!(
        "unsupported case {case_id}"
    )))
}

fn probe_rustc() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map_or_else(|| "unknown".to_owned(), |text| text.trim().to_owned())
}

fn parse_peak_rss(path: &Path) -> Option<u64> {
    let text = fs::read_to_string(path).ok()?;
    for line in text.lines() {
        if line.contains("Maximum resident set size") {
            let value = line.split_once(':')?.1.trim();
            return value.parse().ok();
        }
    }
    None
}

fn run_environment(image: &str, image_id: &str) -> Environment {
    Environment {
        crate_version: crate::VERSION.to_owned(),
        rustc_version: probe_rustc(),
        image: image.to_owned(),
        image_id: image_id.to_owned(),
        command: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_one(
    exe: &Path,
    cwd: &Path,
    stats_dir: &Path,
    case: &CaseSpec,
    arm: &ArmSpec,
    protocol_sha256: &str,
    image: &str,
    image_id: &str,
) -> Result<Receipt, EvaluationError> {
    let stats_path = stats_dir.join(format!("{}__{}.time", case.id, arm.id));
    let time_program = Path::new("/usr/bin/time");
    let mut command = if time_program.is_file() {
        let mut command = Command::new(time_program);
        command.arg("-v").arg("-o").arg(&stats_path).arg(exe);
        command
    } else {
        Command::new(exe)
    };
    command
        .arg("child")
        .arg("--case")
        .arg(&case.id)
        .arg("--arm")
        .arg(&arm.id)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/tmp")
        .env("LC_ALL", "C")
        .env("LANG", "C");
    for variable in ["FRF_BRIDGE_LIVE_BUNDLE", "FRF_EVAL_LIVE_PROOF"] {
        if let Ok(value) = std::env::var(variable) {
            command.env(variable, value);
        }
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let argv: Vec<String> = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|value| value.to_string_lossy().into_owned())
        .collect();
    let start = Instant::now();
    let output = command
        .output()
        .map_err(|error| EvaluationError::Process(format!("{}: {error}", case.id)))?;
    let elapsed = start.elapsed();
    if !output.status.success() {
        return Err(EvaluationError::Process(format!(
            "{}::{} exited with {}",
            case.id, arm.id, output.status
        )));
    }
    if output.stdout.len() > MAX_OBSERVATION_BYTES {
        return Err(EvaluationError::Process(format!(
            "{}::{} exceeded the observation bound",
            case.id, arm.id
        )));
    }
    let observation: Observation = serde_json::from_slice(&output.stdout)
        .map_err(|error| EvaluationError::Json(format!("{}::{}: {error}", case.id, arm.id)))?;
    let canonical = observation.canonical_bytes()?;
    if canonical != output.stdout {
        return Err(EvaluationError::Receipt(format!(
            "{}::{} child observation is not canonical",
            case.id, arm.id
        )));
    }
    let peak_rss_kb = parse_peak_rss(&stats_path)
        .or(observation.vm_hwm_kb)
        .ok_or_else(|| {
            EvaluationError::MissingMeasurement(format!(
                "{}::{} has no peak RSS from /usr/bin/time or VmHWM",
                case.id, arm.id
            ))
        })?;
    let measurement = Measurement {
        wall_time_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        peak_rss_kb,
        output_bytes: u64::try_from(output.stdout.len()).unwrap_or(u64::MAX),
    };
    let mut environment = run_environment(image, image_id);
    environment.command = argv;
    build_receipt(
        protocol_sha256,
        case,
        arm,
        &observation,
        Some(measurement),
        &environment,
        sha256_hex(&output.stdout),
        sha256_hex(&output.stderr),
    )
}

/// Summary of one harness run.
#[derive(Debug, Clone, Serialize)]
pub struct RunSummary {
    /// Number of receipts written.
    pub receipts: usize,
    /// Held-out case count.
    pub held_out_cases: usize,
    /// Development case count.
    pub development_cases: usize,
    /// Total measured wall time.
    pub total_wall_time_ms: u64,
    /// Total child output bytes.
    pub total_output_bytes: u64,
}

/// Run every pre-registered case and arm in an isolated child process and write
/// canonical receipts plus a deterministic manifest.
///
/// # Errors
///
/// Fails closed on a missing protocol, a child failure, a missing measurement,
/// or an unwritable output directory. A receipt is never written for a failed
/// measurement.
#[allow(clippy::too_many_lines)]
pub fn run_protocol(
    protocol_path: &Path,
    out_dir: &Path,
    stats_dir: &Path,
    image: &str,
    image_id: &str,
) -> Result<RunSummary, EvaluationError> {
    let (_bytes, protocol, protocol_sha256) = read_protocol(protocol_path)?;
    fs::create_dir_all(out_dir)
        .map_err(|error| EvaluationError::Io(format!("{}: {error}", out_dir.display())))?;
    for entry in fs::read_dir(out_dir)
        .map_err(|error| EvaluationError::Io(format!("{}: {error}", out_dir.display())))?
    {
        let entry = entry
            .map_err(|error| EvaluationError::Io(format!("{}: {error}", out_dir.display())))?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            fs::remove_file(&path)
                .map_err(|error| EvaluationError::Io(format!("{}: {error}", path.display())))?;
        }
    }
    fs::create_dir_all(stats_dir)
        .map_err(|error| EvaluationError::Io(format!("{}: {error}", stats_dir.display())))?;
    let exe = std::env::current_exe()
        .map_err(|error| EvaluationError::Process(format!("current_exe: {error}")))?;
    let cwd = std::env::current_dir()
        .map_err(|error| EvaluationError::Io(format!("current_dir: {error}")))?;
    let mut receipts = Vec::new();
    let mut total_wall_time_ms = 0_u64;
    let mut total_output_bytes = 0_u64;
    for case in &protocol.cases {
        for arm in &case.arms {
            let receipt = run_one(
                &exe,
                &cwd,
                stats_dir,
                case,
                arm,
                &protocol_sha256,
                image,
                image_id,
            )?;
            let bytes = receipt.canonical_bytes()?;
            let path = out_dir.join(format!("{}__{}.json", case.id, arm.id));
            fs::write(&path, &bytes)
                .map_err(|error| EvaluationError::Io(format!("{}: {error}", path.display())))?;
            total_wall_time_ms =
                total_wall_time_ms.saturating_add(receipt.measurements.wall_time_ms);
            total_output_bytes =
                total_output_bytes.saturating_add(receipt.measurements.output_bytes);
            receipts.push(receipt);
        }
    }
    write_manifest(out_dir, &protocol_sha256, &receipts)?;
    let (held, development) = protocol.split_counts();
    Ok(RunSummary {
        receipts: receipts.len(),
        held_out_cases: held,
        development_cases: development,
        total_wall_time_ms,
        total_output_bytes,
    })
}

fn write_manifest(
    out_dir: &Path,
    protocol_sha256: &str,
    receipts: &[Receipt],
) -> Result<(), EvaluationError> {
    let entries: Vec<Value> = receipts
        .iter()
        .map(|receipt| {
            json!({
                "case_id": receipt.case_id,
                "arm": receipt.arm,
                "experiment_sha256": receipt.experiment_sha256,
                "pass": receipt.pass,
            })
        })
        .collect();
    let value = json!({
        "schema": EVALUATION_MANIFEST_SCHEMA,
        "spec": EVALUATION_SPEC,
        "protocol_sha256": protocol_sha256,
        "receipt_count": receipts.len(),
        "receipts": entries,
    });
    let path = out_dir.join("MANIFEST.json");
    fs::write(&path, canonical_value_bytes(&value)?)
        .map_err(|error| EvaluationError::Io(format!("{}: {error}", path.display())))
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Confusion counts for one arm.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Confusion {
    /// True accepts.
    pub true_accept: u64,
    /// True rejects.
    pub true_reject: u64,
    /// Known-bad cases mistakenly accepted.
    pub false_accept: u64,
    /// Known-good cases mistakenly rejected.
    pub false_refuse: u64,
    /// Censored `NOT_RUN` decisions.
    pub not_run: u64,
    /// Total decisions including censored cases.
    pub total: u64,
}

/// Decision-quality result split by held-out and development cases.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DecisionReport {
    /// Held-out confusion per arm.
    pub held_out: BTreeMap<String, Confusion>,
    /// Development confusion per arm.
    pub development: BTreeMap<String, Confusion>,
}

/// One hypothesis coverage result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HypothesisReport {
    /// Hypothesis id.
    pub id: String,
    /// Name.
    pub name: String,
    /// Required receipts.
    pub receipts: usize,
    /// Receipts whose observed label equals the expectation.
    pub passed: usize,
    /// Receipts whose observed label differs.
    pub failed: usize,
    /// Typed blocked receipts.
    pub blocked: usize,
}

/// One claim result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClaimReport {
    /// Claim id.
    pub id: String,
    /// Owning hypothesis label.
    pub hypothesis: String,
    /// Claim text.
    pub text: String,
    /// `supported`, `falsified`, or `not_evaluated`.
    pub status: String,
    /// Receipt keys and their observed labels.
    pub evidence: Vec<String>,
    /// Missing or mismatched requirements.
    pub problems: Vec<String>,
}

/// Full verification report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationReport {
    /// Report schema.
    pub schema: String,
    /// Spec identifier.
    pub spec: String,
    /// Frozen protocol digest.
    pub protocol_sha256: String,
    /// One if every check passed, zero otherwise.
    pub valid: u8,
    /// Observed receipt count.
    pub receipt_count: usize,
    /// Expected receipt count.
    pub expected_receipt_count: usize,
    /// Held-out case count.
    pub held_out_cases: usize,
    /// Development case count.
    pub development_cases: usize,
    /// Hypothesis coverage.
    pub hypotheses: Vec<HypothesisReport>,
    /// Claim coverage.
    pub claims: Vec<ClaimReport>,
    /// Decision-quality counts.
    pub decision: DecisionReport,
    /// Total measured wall time.
    pub total_wall_time_ms: u64,
    /// Total measured output bytes.
    pub total_output_bytes: u64,
    /// Fail-closed errors.
    pub errors: Vec<String>,
}

impl VerificationReport {
    /// Canonical report bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EvaluationError::Encoding`] if canonical encoding fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EvaluationError> {
        canonical_value_bytes(
            &serde_json::to_value(self)
                .map_err(|error| EvaluationError::Json(format!("report: {error}")))?,
        )
    }
}

fn validate_receipt(
    receipt: &Receipt,
    protocol: &Protocol,
    protocol_sha256: &str,
    bytes: &[u8],
) -> Result<(), String> {
    if receipt.schema != EVALUATION_RECEIPT_SCHEMA || receipt.spec != EVALUATION_SPEC {
        return Err(format!("{}: wrong schema/spec", receipt.key()));
    }
    if receipt.protocol_sha256 != protocol_sha256 {
        return Err(format!("{}: protocol digest mismatch", receipt.key()));
    }
    let canonical = receipt
        .canonical_bytes()
        .map_err(|error| format!("{}: {error}", receipt.key()))?;
    if canonical != bytes {
        return Err(format!("{}: receipt is not canonical", receipt.key()));
    }
    let case = protocol
        .case(&receipt.case_id)
        .ok_or_else(|| format!("{}: unknown case", receipt.key()))?;
    let arm = case
        .arms
        .iter()
        .find(|arm| arm.id == receipt.arm)
        .ok_or_else(|| format!("{}: unknown arm", receipt.key()))?;
    if receipt.hypothesis != case.hypothesis
        || receipt.category != case.category
        || receipt.truth != case.truth
        || receipt.accept_outcomes != case.accept_outcomes
        || receipt.arm_kind != arm.kind
        || receipt.expected != arm.expected
    {
        return Err(format!(
            "{}: receipt disagrees with the frozen protocol",
            receipt.key()
        ));
    }
    if receipt.pass != (receipt.expected == receipt.observed) {
        return Err(format!("{}: pass flag is inconsistent", receipt.key()));
    }
    if receipt.measurements.peak_rss_kb == 0 || receipt.measurements.output_bytes == 0 {
        return Err(format!("{}: missing required measurement", receipt.key()));
    }
    if receipt.digests.input_sha256.len() != 64
        || receipt.digests.observed_sha256.len() != 64
        || receipt.digests.stdout_sha256.len() != 64
        || receipt.digests.stderr_sha256.len() != 64
    {
        return Err(format!("{}: malformed digest", receipt.key()));
    }
    let core = json!({
        "observed": receipt.observed,
        "input_sha256": receipt.digests.input_sha256,
        "detail": receipt.detail,
    });
    let recomputed = hash_value(&core).map_err(|error| format!("{}: {error}", receipt.key()))?;
    if recomputed != receipt.digests.observed_sha256 {
        return Err(format!("{}: observation digest mismatch", receipt.key()));
    }
    if experiment_sha256(receipt).map_err(|error| format!("{}: {error}", receipt.key()))?
        != receipt.experiment_sha256
    {
        return Err(format!("{}: experiment digest mismatch", receipt.key()));
    }
    if receipt.observed == NOT_RUN && receipt.blocked.is_none() {
        return Err(format!(
            "{}: NOT_RUN without a blocked reason",
            receipt.key()
        ));
    }
    if receipt.measurements.wall_time_ms == 0 && receipt.measurements.output_bytes == 0 {
        return Err(format!("{}: absent wall time", receipt.key()));
    }
    if receipt.environment.rustc_version.is_empty()
        || receipt.environment.image.is_empty()
        || receipt.environment.command.is_empty()
    {
        return Err(format!("{}: missing environment identity", receipt.key()));
    }
    Ok(())
}

fn decision_counts(protocol: &Protocol, receipts: &BTreeMap<String, Receipt>) -> DecisionReport {
    let mut report = DecisionReport::default();
    for case in &protocol.cases {
        if !matches!(case.truth.as_str(), "accept" | "reject") {
            continue;
        }
        for arm in &case.arms {
            let key = format!("{}::{}", case.id, arm.id);
            let Some(receipt) = receipts.get(&key) else {
                continue;
            };
            let target = if held_out(&case.id) {
                report.held_out.entry(arm.id.clone()).or_default()
            } else {
                report.development.entry(arm.id.clone()).or_default()
            };
            target.total += 1;
            if receipt.observed == NOT_RUN {
                target.not_run += 1;
                continue;
            }
            let accepted = case.accept_outcomes.contains(&receipt.observed);
            match (case.truth.as_str(), accepted) {
                ("accept", true) => target.true_accept += 1,
                ("accept", false) => target.false_refuse += 1,
                ("reject", false) => target.true_reject += 1,
                ("reject", true) => target.false_accept += 1,
                _ => {}
            }
        }
    }
    report
}

fn decision_claim(report: &DecisionReport, protocol: &Protocol) -> ClaimReport {
    let mut problems = Vec::new();
    let mut evidence = Vec::new();
    let mut baseline_error = false;
    let mut arm_ids: BTreeSet<&str> = BTreeSet::new();
    arm_ids.extend(report.held_out.keys().map(String::as_str));
    arm_ids.extend(report.development.keys().map(String::as_str));
    for arm in arm_ids {
        let held = report.held_out.get(arm).cloned().unwrap_or_default();
        let development = report.development.get(arm).cloned().unwrap_or_default();
        let kind = protocol
            .cases
            .iter()
            .flat_map(|case| case.arms.iter())
            .find(|candidate| candidate.id == arm)
            .map_or("unknown", |candidate| candidate.kind.as_str());
        evidence.push(format!(
            "{arm}: held_out true_accept={} true_reject={} false_accept={} false_refuse={} not_run={} total={}; development false_accept={} false_refuse={} not_run={} total={}",
            held.true_accept,
            held.true_reject,
            held.false_accept,
            held.false_refuse,
            held.not_run,
            held.total,
            development.false_accept,
            development.false_refuse,
            development.not_run,
            development.total
        ));
        if kind == "production" && (held.false_accept > 0 || held.false_refuse > 0) {
            problems.push(format!(
                "production arm {arm} made a held-out false decision"
            ));
        }
        if kind == "baseline"
            && (held.false_accept
                + held.false_refuse
                + development.false_accept
                + development.false_refuse)
                > 0
        {
            baseline_error = true;
        }
    }
    if report.held_out.is_empty() {
        problems.push("no held-out decision cases".to_owned());
    }
    if !baseline_error {
        problems.push("no naive baseline made a false decision".to_owned());
    }
    let status = if problems.is_empty() {
        "supported"
    } else {
        "falsified"
    };
    ClaimReport {
        id: "C10".to_owned(),
        hypothesis: "H6".to_owned(),
        text: "Decision-quality confusion counts.".to_owned(),
        status: status.to_owned(),
        evidence,
        problems,
    }
}

/// Verify a receipt directory against a frozen protocol.
///
/// # Errors
///
/// Returns [`EvaluationError`] only when the protocol or directory cannot be
/// read. Receipt-level faults are fail-closed and retained in
/// [`VerificationReport::errors`] with `valid` set to zero.
#[allow(clippy::if_not_else, clippy::too_many_lines)]
pub fn verify_receipts(
    protocol_path: &Path,
    receipts_dir: &Path,
) -> Result<VerificationReport, EvaluationError> {
    let (_protocol_bytes, protocol, protocol_sha256) = read_protocol(protocol_path)?;
    let mut errors = Vec::new();
    let mut receipts = BTreeMap::new();
    let mut total_wall_time_ms = 0_u64;
    let mut total_output_bytes = 0_u64;
    if !receipts_dir.is_dir() {
        errors.push(format!("{} is not a directory", receipts_dir.display()));
    } else {
        let mut paths = Vec::new();
        for entry in fs::read_dir(receipts_dir)
            .map_err(|error| EvaluationError::Io(format!("{}: {error}", receipts_dir.display())))?
        {
            let entry = entry.map_err(|error| {
                EvaluationError::Io(format!("{}: {error}", receipts_dir.display()))
            })?;
            let path = entry.path();
            if path.file_name().and_then(|name| name.to_str()) == Some("MANIFEST.json") {
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
                paths.push(path);
            }
        }
        paths.sort();
        for path in paths {
            let bytes = fs::read(&path)
                .map_err(|error| EvaluationError::Io(format!("{}: {error}", path.display())))?;
            let receipt: Receipt = match serde_json::from_slice(&bytes) {
                Ok(receipt) => receipt,
                Err(error) => {
                    errors.push(format!("{}: {error}", path.display()));
                    continue;
                }
            };
            if let Err(error) = validate_receipt(&receipt, &protocol, &protocol_sha256, &bytes) {
                errors.push(error);
            }
            total_wall_time_ms =
                total_wall_time_ms.saturating_add(receipt.measurements.wall_time_ms);
            total_output_bytes =
                total_output_bytes.saturating_add(receipt.measurements.output_bytes);
            let key = receipt.key();
            if receipts.insert(key.clone(), receipt).is_some() {
                errors.push(format!("{key}: duplicate receipt"));
            }
        }
    }
    let expected = protocol.expected_receipts();
    if receipts.len() != expected {
        errors.push(format!(
            "receipt count {} does not equal pre-registered count {}",
            receipts.len(),
            expected
        ));
    }
    for case in &protocol.cases {
        for arm in &case.arms {
            let key = format!("{}::{}", case.id, arm.id);
            if !receipts.contains_key(&key) {
                errors.push(format!("{key}: missing receipt"));
            }
        }
    }
    let mut hypotheses = Vec::new();
    for hypothesis in &protocol.hypotheses {
        let mut required = 0_usize;
        let mut passed = 0_usize;
        let mut failed = 0_usize;
        let mut blocked = 0_usize;
        for case_id in &hypothesis.cases {
            if let Some(case) = protocol.case(case_id) {
                for arm in &case.arms {
                    required += 1;
                    let key = format!("{}::{}", case.id, arm.id);
                    match receipts.get(&key) {
                        Some(receipt) => {
                            if receipt.pass {
                                passed += 1;
                            } else {
                                failed += 1;
                            }
                            if receipt.observed == NOT_RUN {
                                blocked += 1;
                            }
                        }
                        None => failed += 1,
                    }
                }
            }
        }
        hypotheses.push(HypothesisReport {
            id: hypothesis.id.clone(),
            name: hypothesis.name.clone(),
            receipts: required,
            passed,
            failed,
            blocked,
        });
    }
    let decision = decision_counts(&protocol, &receipts);
    let mut claims = Vec::new();
    for claim in &protocol.claims {
        if claim.derived.as_deref() == Some("decision_quality") {
            let mut derived = decision_claim(&decision, &protocol);
            derived.id.clone_from(&claim.id);
            derived.hypothesis.clone_from(&claim.hypothesis);
            derived.text.clone_from(&claim.text);
            claims.push(derived);
            continue;
        }
        let mut problems = Vec::new();
        let mut evidence = Vec::new();
        for requirement in &claim.requires {
            let key = format!("{}::{}", requirement.case, requirement.arm);
            match receipts.get(&key) {
                None => problems.push(format!("{key}: missing receipt")),
                Some(receipt) => {
                    evidence.push(format!(
                        "{key}: observed={} expected={}",
                        receipt.observed, requirement.expected
                    ));
                    if receipt.observed != requirement.expected {
                        problems.push(format!(
                            "{key}: observed {} but claim requires {}",
                            receipt.observed, requirement.expected
                        ));
                    }
                }
            }
        }
        claims.push(ClaimReport {
            id: claim.id.clone(),
            hypothesis: claim.hypothesis.clone(),
            text: claim.text.clone(),
            status: if problems.is_empty() {
                "supported".to_owned()
            } else {
                "falsified".to_owned()
            },
            evidence,
            problems,
        });
    }
    let (held_out_cases, development_cases) = protocol.split_counts();
    let valid = errors.is_empty()
        && claims.iter().all(|claim| claim.status == "supported")
        && hypotheses.iter().all(|hypothesis| hypothesis.failed == 0);
    Ok(VerificationReport {
        schema: EVALUATION_REPORT_SCHEMA.to_owned(),
        spec: EVALUATION_SPEC.to_owned(),
        protocol_sha256,
        valid: u8::from(valid),
        receipt_count: receipts.len(),
        expected_receipt_count: expected,
        held_out_cases,
        development_cases,
        hypotheses,
        claims,
        decision,
        total_wall_time_ms,
        total_output_bytes,
        errors,
    })
}

/// Compare two receipt directories on their deterministic fields. Resource
/// measurements may differ; observations, expectations, and digests may not.
///
/// # Errors
///
/// Returns [`EvaluationError`] for unreadable directories, malformed receipts,
/// differing key sets, or any deterministic disagreement.
pub fn compare_receipt_dirs(generated: &Path, committed: &Path) -> Result<usize, EvaluationError> {
    let produced = read_receipts(generated)?;
    let expected = read_receipts(committed)?;
    if produced.len() != expected.len() {
        return Err(EvaluationError::Receipt(format!(
            "generated {} receipts but committed directory contains {}",
            produced.len(),
            expected.len()
        )));
    }
    for (key, receipt) in &produced {
        let Some(committed_receipt) = expected.get(key) else {
            return Err(EvaluationError::Receipt(format!(
                "{key}: generated receipt has no committed counterpart"
            )));
        };
        if receipt.experiment_sha256 != committed_receipt.experiment_sha256
            || receipt.observed != committed_receipt.observed
            || receipt.expected != committed_receipt.expected
            || receipt.pass != committed_receipt.pass
            || receipt.digests.input_sha256 != committed_receipt.digests.input_sha256
            || receipt.digests.observed_sha256 != committed_receipt.digests.observed_sha256
            || receipt.protocol_sha256 != committed_receipt.protocol_sha256
        {
            return Err(EvaluationError::Receipt(format!(
                "{key}: committed receipt disagrees with the fresh run"
            )));
        }
    }
    Ok(produced.len())
}

fn read_receipts(directory: &Path) -> Result<BTreeMap<String, Receipt>, EvaluationError> {
    let mut receipts = BTreeMap::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| EvaluationError::Io(format!("{}: {error}", directory.display())))?
    {
        let entry = entry
            .map_err(|error| EvaluationError::Io(format!("{}: {error}", directory.display())))?;
        let path = entry.path();
        if path.file_name().and_then(|name| name.to_str()) == Some("MANIFEST.json") {
            continue;
        }
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(&path)
            .map_err(|error| EvaluationError::Io(format!("{}: {error}", path.display())))?;
        let receipt: Receipt = serde_json::from_slice(&bytes)
            .map_err(|error| EvaluationError::Json(format!("{}: {error}", path.display())))?;
        let key = receipt.key();
        if receipts.insert(key.clone(), receipt).is_some() {
            return Err(EvaluationError::Receipt(format!(
                "{key}: duplicate receipt"
            )));
        }
    }
    Ok(receipts)
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn next_arg(args: &mut std::vec::IntoIter<String>, flag: &str) -> Result<String, EvaluationError> {
    args.next()
        .ok_or_else(|| EvaluationError::Protocol(format!("missing value for {flag}")))
}

fn print_usage() {
    println!(
        "usage:\n  frf-eval run [--protocol PATH] [--out DIR] [--stats DIR] [--image NAME] [--image-id ID]\n  frf-eval verify [--protocol PATH] [--receipts DIR] [--report PATH]\n  frf-eval compare [--generated DIR] [--committed DIR]\n  frf-eval child --case ID --arm ARM\n  frf-eval splits [--protocol PATH]"
    );
}

/// Harness command-line entry point.
///
/// # Errors
///
/// Returns `2` for usage errors, `3` for invalid or unreadable protocol data,
/// `4` for a failed verification, `6` for a typed `NOT_RUN`, and `7` for an
/// internal harness error.
#[allow(clippy::too_many_lines)]
pub fn cli(args: impl Iterator<Item = String>) -> i32 {
    let mut args = args.collect::<Vec<_>>().into_iter();
    let Some(command) = args.next() else {
        print_usage();
        return 2;
    };
    match command.as_str() {
        "run" => {
            let mut protocol = PathBuf::from(DEFAULT_PROTOCOL_PATH);
            let mut out = PathBuf::from("target/eval-receipts");
            let mut stats = PathBuf::from("target/eval-stats");
            let mut image =
                std::env::var("FRF_EVAL_IMAGE").unwrap_or_else(|_| "unknown".to_owned());
            let mut image_id =
                std::env::var("FRF_EVAL_IMAGE_ID").unwrap_or_else(|_| "unknown".to_owned());
            while let Some(flag) = args.next() {
                let result = match flag.as_str() {
                    "--protocol" => {
                        next_arg(&mut args, &flag).map(|value| protocol = PathBuf::from(value))
                    }
                    "--out" => next_arg(&mut args, &flag).map(|value| out = PathBuf::from(value)),
                    "--stats" => {
                        next_arg(&mut args, &flag).map(|value| stats = PathBuf::from(value))
                    }
                    "--image" => next_arg(&mut args, &flag).map(|value| image = value),
                    "--image-id" => next_arg(&mut args, &flag).map(|value| image_id = value),
                    other => Err(EvaluationError::Protocol(format!("unknown flag {other}"))),
                };
                if let Err(error) = result {
                    eprintln!("frf-eval: {error}");
                    return 2;
                }
            }
            match run_protocol(&protocol, &out, &stats, &image, &image_id) {
                Ok(summary) => {
                    println!(
                        "RAN receipts={} held_out_cases={} development_cases={} wall_ms={} output_bytes={}",
                        summary.receipts,
                        summary.held_out_cases,
                        summary.development_cases,
                        summary.total_wall_time_ms,
                        summary.total_output_bytes
                    );
                    0
                }
                Err(error) => {
                    eprintln!("frf-eval: {error}");
                    if matches!(
                        error,
                        EvaluationError::Io(_)
                            | EvaluationError::Json(_)
                            | EvaluationError::Protocol(_)
                    ) {
                        3
                    } else {
                        7
                    }
                }
            }
        }
        "verify" => {
            let mut protocol = PathBuf::from(DEFAULT_PROTOCOL_PATH);
            let mut receipts = PathBuf::from(DEFAULT_RECEIPTS_DIR);
            let mut report: Option<PathBuf> = None;
            while let Some(flag) = args.next() {
                let result = match flag.as_str() {
                    "--protocol" => {
                        next_arg(&mut args, &flag).map(|value| protocol = PathBuf::from(value))
                    }
                    "--receipts" => {
                        next_arg(&mut args, &flag).map(|value| receipts = PathBuf::from(value))
                    }
                    "--report" => {
                        next_arg(&mut args, &flag).map(|value| report = Some(PathBuf::from(value)))
                    }
                    other => Err(EvaluationError::Protocol(format!("unknown flag {other}"))),
                };
                if let Err(error) = result {
                    eprintln!("frf-eval: {error}");
                    return 2;
                }
            }
            match verify_receipts(&protocol, &receipts) {
                Ok(report_value) => {
                    if let Some(path) = report {
                        match report_value.canonical_bytes() {
                            Ok(bytes) => {
                                if let Err(error) = fs::write(&path, bytes) {
                                    eprintln!("frf-eval: {}: {error}", path.display());
                                    return 7;
                                }
                            }
                            Err(error) => {
                                eprintln!("frf-eval: {error}");
                                return 7;
                            }
                        }
                    }
                    let failing = report_value
                        .claims
                        .iter()
                        .filter(|claim| claim.status != "supported")
                        .count();
                    println!(
                        "VERIFY valid={} receipts={}/{} held_out_cases={} development_cases={} claims_supported={}/{} failing_claims={} errors={} wall_ms={} output_bytes={}",
                        report_value.valid,
                        report_value.receipt_count,
                        report_value.expected_receipt_count,
                        report_value.held_out_cases,
                        report_value.development_cases,
                        report_value.claims.len() - failing,
                        report_value.claims.len(),
                        failing,
                        report_value.errors.len(),
                        report_value.total_wall_time_ms,
                        report_value.total_output_bytes
                    );
                    for error in &report_value.errors {
                        eprintln!("FAIL {error}");
                    }
                    for claim in &report_value.claims {
                        if claim.status != "supported" {
                            for problem in &claim.problems {
                                eprintln!("FAIL claim {}: {problem}", claim.id);
                            }
                        }
                    }
                    if report_value.valid == 1 {
                        0
                    } else {
                        4
                    }
                }
                Err(error) => {
                    eprintln!("frf-eval: {error}");
                    3
                }
            }
        }
        "compare" => {
            let mut generated = PathBuf::from("target/eval-receipts");
            let mut committed = PathBuf::from(DEFAULT_RECEIPTS_DIR);
            while let Some(flag) = args.next() {
                let result = match flag.as_str() {
                    "--generated" => {
                        next_arg(&mut args, &flag).map(|value| generated = PathBuf::from(value))
                    }
                    "--committed" => {
                        next_arg(&mut args, &flag).map(|value| committed = PathBuf::from(value))
                    }
                    other => Err(EvaluationError::Protocol(format!("unknown flag {other}"))),
                };
                if let Err(error) = result {
                    eprintln!("frf-eval: {error}");
                    return 2;
                }
            }
            match compare_receipt_dirs(&generated, &committed) {
                Ok(count) => {
                    println!("COMPARE receipts={count} deterministic=identical");
                    0
                }
                Err(error) => {
                    eprintln!("frf-eval: {error}");
                    4
                }
            }
        }
        "child" => {
            let mut case_id = None;
            let mut arm = None;
            while let Some(flag) = args.next() {
                let result = match flag.as_str() {
                    "--case" => next_arg(&mut args, &flag).map(|value| case_id = Some(value)),
                    "--arm" => next_arg(&mut args, &flag).map(|value| arm = Some(value)),
                    other => Err(EvaluationError::Protocol(format!("unknown flag {other}"))),
                };
                if let Err(error) = result {
                    eprintln!("frf-eval: {error}");
                    return 2;
                }
            }
            let (Some(case_id), Some(arm)) = (case_id, arm) else {
                print_usage();
                return 2;
            };
            match observe_case(&case_id, &arm) {
                Ok(observation) => match observation.canonical_bytes() {
                    Ok(bytes) => {
                        use std::io::Write;
                        if let Err(error) = std::io::stdout().write_all(&bytes) {
                            eprintln!("frf-eval: {error}");
                            return 7;
                        }
                        0
                    }
                    Err(error) => {
                        eprintln!("frf-eval: {error}");
                        7
                    }
                },
                Err(error) => {
                    eprintln!("frf-eval: {error}");
                    if matches!(error, EvaluationError::Protocol(_)) {
                        2
                    } else {
                        7
                    }
                }
            }
        }
        "splits" => {
            let mut protocol = PathBuf::from(DEFAULT_PROTOCOL_PATH);
            while let Some(flag) = args.next() {
                if flag == "--protocol" {
                    match next_arg(&mut args, &flag) {
                        Ok(value) => protocol = PathBuf::from(value),
                        Err(error) => {
                            eprintln!("frf-eval: {error}");
                            return 2;
                        }
                    }
                } else {
                    eprintln!("frf-eval: unknown flag {flag}");
                    return 2;
                }
            }
            match read_protocol(&protocol) {
                Ok((_bytes, protocol, digest)) => {
                    let (held, development) = protocol.split_counts();
                    println!("protocol_sha256={digest} held_out_cases={held} development_cases={development} receipts={}", protocol.expected_receipts());
                    for case in &protocol.cases {
                        println!(
                            "{} {}",
                            if held_out(&case.id) {
                                "held_out"
                            } else {
                                "development"
                            },
                            case.id
                        );
                    }
                    0
                }
                Err(error) => {
                    eprintln!("frf-eval: {error}");
                    3
                }
            }
        }
        "-h" | "--help" | "help" => {
            print_usage();
            0
        }
        other => {
            eprintln!("frf-eval: unknown command {other}");
            print_usage();
            2
        }
    }
}
