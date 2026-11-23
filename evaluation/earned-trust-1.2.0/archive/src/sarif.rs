#![allow(clippy::module_name_repetitions)]

//! Versioned SARIF 2.1.0 projection for ETP campaign receipts.
//!
//! The projection is a report format, not a correctness or security proof. It
//! preserves distinct rule, hazard, logical-finding, occurrence, candidate, and
//! instrument-execution identities. Results are never silently dropped:
//! failures, incomplete transcripts, unresolved observations, and `NOT_RUN`
//! conditions are exported. A suppression remains a finding and requires
//! justification, scope, owner, expiry, and invalidation. A GitHub code-scanning
//! view is not authoritative.
//!
//! # Locations
//!
//! A location is emitted only when the receipt has a raw transcript and the
//! fixture path is declared by the campaign. No line or column region is
//! invented. Binary or harness-level findings without a transcript carry no
//! physical location.
//!
//! # Completeness
//!
//! The run records its result limit, encoded-byte limit, result count, and a
//! native manifest digest. If a limit would prevent completeness, export refuses
//! rather than truncating. The verifier accepts an explicitly sharded document
//! only when shard ranges cover every result and the native manifest is present.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::etp_campaign::{
    self, CampaignBundle, CampaignProtocol, CampaignReceipt, CampaignStatus, TerminalOutcome,
};
use crate::identity::{canonical_bytes, parse_strict, IdentityError};

/// SARIF 2.1.0 schema URI used by the projection.
pub const SARIF_SCHEMA_URI: &str = "https://json.schemastore.org/sarif-2.1.0.json";
/// SARIF version emitted by the projection.
pub const SARIF_VERSION: &str = "2.1.0";
/// Projection schema identifier recorded in `run.properties`.
pub const SARIF_PROJECTION_SCHEMA: &str = "frf-etp.sarif-projection.v1";
/// Protocol specification identifier.
pub const SARIF_SPEC: &str = "frf-etp-v1";
/// Tool driver name.
pub const SARIF_TOOL_NAME: &str = "frf-etp-sarif-projection";
/// Maximum results in one SARIF document.
pub const MAX_SARIF_RESULTS: usize = 1000;
/// Maximum canonical SARIF bytes.
pub const MAX_SARIF_BYTES: usize = 4 * 1024 * 1024;
/// Claim ceiling embedded in the run and verification report.
pub const SARIF_CLAIM_CEILING: &str = "A SARIF document is a report projection, not a correctness, memory-safety, compatibility, or security proof. The projection preserves campaign identities and exports failures and unresolved conditions. It does not establish that a finding was repaired, that a missing finding is safe, that a source location is complete, that a suppression is justified beyond its declared fields, or that a code-scanning view is authoritative. A digest is not authentication.";

/// SARIF verification status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SarifStatus {
    /// The document matches the declared campaign projection.
    Valid,
    /// The document is structurally readable but refused.
    Refused,
}

impl SarifStatus {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Refused => "refused",
        }
    }
}

/// SARIF refusal codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SarifRefusalCode {
    /// The schema URI or version is unsupported.
    UnsupportedVersion,
    /// A required profile field is missing or inconsistent.
    SchemaMismatch,
    /// The referenced campaign manifest could not be loaded.
    MissingNativeManifest,
    /// The native campaign was refused.
    CampaignInvalid,
    /// An expected result occurrence is absent.
    MissingResult,
    /// An unexpected result occurrence is present.
    UnexpectedResult,
    /// A candidate or instrument identity disagrees.
    IdentityMismatch,
    /// A result has a location that the campaign does not justify.
    FabricatedLocation,
    /// A result invents a source region.
    UnsupportedRegion,
    /// A suppression lacks a required field.
    UnauthorizedSuppression,
    /// A baseline state or absence reason is not supported.
    InvalidBaselineState,
    /// Shard ranges do not cover the results.
    IncompleteSharding,
    /// A declared limit is exceeded or misreported.
    LimitExceeded,
    /// A summary count disagrees with the document.
    InconsistentCount,
    /// A declared digest does not match the bytes.
    DigestMismatch,
    /// A rule is missing from the rule table.
    MissingRule,
}

impl SarifRefusalCode {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "unsupported_version",
            Self::SchemaMismatch => "schema_mismatch",
            Self::MissingNativeManifest => "missing_native_manifest",
            Self::CampaignInvalid => "campaign_invalid",
            Self::MissingResult => "missing_result",
            Self::UnexpectedResult => "unexpected_result",
            Self::IdentityMismatch => "identity_mismatch",
            Self::FabricatedLocation => "fabricated_location",
            Self::UnsupportedRegion => "unsupported_region",
            Self::UnauthorizedSuppression => "unauthorized_suppression",
            Self::InvalidBaselineState => "invalid_baseline_state",
            Self::IncompleteSharding => "incomplete_sharding",
            Self::LimitExceeded => "limit_exceeded",
            Self::InconsistentCount => "inconsistent_count",
            Self::DigestMismatch => "digest_mismatch",
            Self::MissingRule => "missing_rule",
        }
    }
}

/// One SARIF message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifMessage {
    /// Exact message text.
    pub text: String,
}

/// One SARIF artifact location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifArtifactLocation {
    /// Repository-relative URI.
    pub uri: String,
}

/// One SARIF physical location. Regions are deliberately unsupported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifPhysicalLocation {
    /// Artifact location.
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
}

/// One SARIF logical location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifLogicalLocation {
    /// Logical subject name.
    pub name: String,
    /// Logical subject kind.
    pub kind: String,
}

/// One SARIF location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifLocation {
    /// Physical location, when the campaign justifies one.
    #[serde(rename = "physicalLocation")]
    pub physical_location: Option<SarifPhysicalLocation>,
    /// Logical locations.
    #[serde(rename = "logicalLocations")]
    pub logical_locations: Vec<SarifLogicalLocation>,
}

/// One SARIF artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifArtifact {
    /// Location.
    pub location: SarifArtifactLocation,
    /// Roles.
    pub roles: Vec<String>,
    /// Additional properties.
    pub properties: serde_json::Value,
}

/// One SARIF rule configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifConfiguration {
    /// Default level.
    pub level: String,
}

/// One SARIF rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifRule {
    /// Stable rule identifier.
    pub id: String,
    /// Rule name.
    pub name: String,
    /// Short description.
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    /// Full description.
    #[serde(rename = "fullDescription")]
    pub full_description: SarifMessage,
    /// Default configuration.
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifConfiguration,
    /// Additional properties.
    pub properties: serde_json::Value,
}

/// One SARIF driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifDriver {
    /// Driver name.
    pub name: String,
    /// Driver version.
    pub version: String,
    /// Information URI.
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    /// Rules.
    pub rules: Vec<SarifRule>,
    /// Additional properties.
    pub properties: serde_json::Value,
}

/// One SARIF tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifTool {
    /// Driver.
    pub driver: SarifDriver,
}

/// One suppression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifSuppression {
    /// Suppression kind. This profile emits `external`.
    pub kind: String,
    /// Exact justification.
    pub justification: String,
    /// Suppression properties.
    pub properties: SarifSuppressionProperties,
}

/// Suppression properties required by the profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifSuppressionProperties {
    /// Scope.
    pub scope: String,
    /// Administrative owner.
    pub owner: String,
    /// Expiry.
    pub expiry: String,
    /// Invalidation condition.
    pub invalidation: String,
}

/// Result properties preserving campaign identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifResultProperties {
    /// Case identifier.
    pub case_id: String,
    /// Requirement identifier.
    pub requirement: String,
    /// Obligation identifiers.
    pub obligations: Vec<String>,
    /// Hazard identity (finding code or terminal outcome).
    pub hazard: String,
    /// Observed terminal outcome.
    pub observed_outcome: String,
    /// Pre-registered terminal outcome.
    pub expected_outcome: String,
    /// Derived decision.
    pub decision: String,
    /// Release decision.
    pub release_decision: String,
    /// Candidate identity.
    pub candidate_identity: String,
    /// Instrument-execution identity.
    pub instrument_execution_identity: String,
    /// Occurrence identity.
    pub occurrence_id: String,
    /// Evidence digests.
    pub evidence_sha256: Vec<String>,
    /// All finding codes retained for the case.
    pub finding_codes: Vec<String>,
    /// Absence reason when a baseline comparison is used.
    pub absence_reason: String,
    /// Evidence supporting an absence classification.
    pub absence_evidence: Vec<String>,
    /// Previous instrument-execution identity for a tool-change absence.
    pub previous_instrument_execution_identity: String,
    /// Declared scope.
    pub scope: String,
}

/// One SARIF result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifResult {
    /// Rule identifier.
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    /// Rule index.
    #[serde(rename = "ruleIndex")]
    pub rule_index: usize,
    /// Level.
    pub level: String,
    /// Message.
    pub message: SarifMessage,
    /// Locations.
    pub locations: Vec<SarifLocation>,
    /// Fingerprints.
    pub fingerprints: BTreeMap<String, String>,
    /// Partial fingerprints.
    #[serde(rename = "partialFingerprints")]
    pub partial_fingerprints: BTreeMap<String, String>,
    /// Baseline state.
    #[serde(rename = "baselineState")]
    pub baseline_state: String,
    /// Suppressions. A suppressed result remains a finding.
    pub suppressions: Vec<SarifSuppression>,
    /// Additional properties.
    pub properties: SarifResultProperties,
}

/// One shard range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifShard {
    /// Shard path.
    pub path: String,
    /// First result index.
    pub first_result: usize,
    /// Result count.
    pub result_count: usize,
    /// Shard SHA-256.
    pub sha256: String,
}

/// Completeness record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifCompleteness {
    /// Whether this document is complete.
    pub complete: bool,
    /// Receipt count of the native campaign.
    pub receipt_count: usize,
    /// Result count in this document.
    pub result_count: usize,
    /// Native closure manifest path.
    pub native_manifest: String,
    /// Native closure manifest SHA-256.
    pub native_manifest_sha256: String,
    /// Shards when the result limit prevents one complete document.
    pub shards: Vec<SarifShard>,
}

/// Limits record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifLimitsRecord {
    /// Maximum results.
    pub max_results: usize,
    /// Maximum encoded bytes.
    pub max_bytes: usize,
    /// Result count.
    pub result_count: usize,
    /// Canonical encoded bytes.
    pub encoded_bytes: usize,
    /// Whether the document is truncated or sharded.
    pub truncated: bool,
}

/// Run properties.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifRunProperties {
    /// Projection schema.
    pub frf_projection_schema: String,
    /// Campaign identifier.
    pub campaign_id: String,
    /// Opening manifest SHA-256.
    pub opening_sha256: String,
    /// Candidate identity.
    pub candidate_identity: String,
    /// Instrument identifier.
    pub instrument_id: String,
    /// Instrument tree digest.
    pub instrument_identity: String,
    /// Declared case count.
    pub case_count: usize,
    /// Receipt count.
    pub receipt_count: usize,
    /// Result count.
    pub result_count: usize,
    /// Retained finding count.
    pub retained_finding_count: usize,
    /// Suppressed result count.
    pub suppressed_result_count: usize,
    /// Declared scope.
    pub scope: String,
    /// Declared assumptions.
    pub assumptions: Vec<String>,
    /// Unsupported features.
    pub unsupported_features: Vec<String>,
    /// Completeness.
    pub completeness: SarifCompleteness,
    /// Limits.
    pub limits: SarifLimitsRecord,
    /// Claim ceiling.
    pub claim_ceiling: String,
}

/// One SARIF run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifRun {
    /// Tool.
    pub tool: SarifTool,
    /// Artifacts.
    pub artifacts: Vec<SarifArtifact>,
    /// Results.
    pub results: Vec<SarifResult>,
    /// Additional properties.
    pub properties: SarifRunProperties,
}

/// One SARIF log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifLog {
    /// Schema URI.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// SARIF version.
    pub version: String,
    /// Runs.
    pub runs: Vec<SarifRun>,
}

/// One SARIF refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifRefusal {
    /// Refusal code.
    pub code: SarifRefusalCode,
    /// Occurrence or field identifier.
    pub subject: String,
    /// Exact detail.
    pub detail: String,
}

/// SARIF verification report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SarifReport {
    /// Report schema.
    pub schema: String,
    /// Protocol specification.
    pub spec: String,
    /// Status.
    pub status: SarifStatus,
    /// SARIF version.
    pub sarif_version: String,
    /// Result count.
    pub result_count: usize,
    /// Rule count.
    pub rule_count: usize,
    /// Retained finding count.
    pub retained_finding_count: usize,
    /// Suppressed result count.
    pub suppressed_result_count: usize,
    /// Candidate identity.
    pub candidate_identity: String,
    /// Instrument identity.
    pub instrument_identity: String,
    /// Refusals.
    pub refusals: Vec<SarifRefusal>,
    /// Limits.
    pub limits: SarifLimitsRecord,
    /// Claim ceiling.
    pub claim_ceiling: String,
}

impl SarifReport {
    /// Canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SarifError::Canonical`] if the report cannot be encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SarifError> {
        canonical_json(self)
    }

    /// `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self.status {
            SarifStatus::Valid => 0,
            SarifStatus::Refused => 4,
        }
    }
}

/// SARIF parse, projection, and verification errors.
#[derive(Debug, thiserror::Error)]
pub enum SarifError {
    /// Strict JSON parsing failed.
    #[error("invalid SARIF JSON: {0}")]
    Identity(#[from] IdentityError),
    /// A structural rule failed.
    #[error("invalid SARIF projection: {message}")]
    Invalid {
        /// Diagnostic.
        message: String,
    },
    /// A schema or version is unsupported.
    #[error("SARIF schema mismatch for {field}: expected {expected}, found {actual}")]
    SchemaMismatch {
        /// Field.
        field: String,
        /// Expected.
        expected: String,
        /// Actual.
        actual: String,
    },
    /// An I/O operation failed.
    #[error("SARIF I/O failure: {message}")]
    Io {
        /// Diagnostic.
        message: String,
    },
    /// Canonical encoding failed.
    #[error("SARIF encoding failure: {message}")]
    Canonical {
        /// Diagnostic.
        message: String,
    },
    /// Campaign loading or reconciliation failed.
    #[error("campaign error: {0}")]
    Campaign(#[from] etp_campaign::CampaignError),
    /// The native campaign was refused; no projection is valid.
    #[error("campaign reconciliation refused: {message}")]
    CampaignRefused {
        /// Diagnostic.
        message: String,
    },
    /// The document would exceed a declared limit and requires explicit shards.
    #[error("SARIF projection requires explicit sharding: {message}")]
    ShardingRequired {
        /// Diagnostic.
        message: String,
    },
}

impl SarifError {
    /// `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Canonical { .. } => 7,
            Self::Campaign(error) => error.exit_code(),
            Self::CampaignRefused { .. } => 4,
            Self::ShardingRequired { .. } => 6,
            Self::Identity(_)
            | Self::Invalid { .. }
            | Self::SchemaMismatch { .. }
            | Self::Io { .. } => 3,
        }
    }
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, SarifError> {
    let value = serde_json::to_value(value).map_err(|error| SarifError::Canonical {
        message: error.to_string(),
    })?;
    canonical_bytes(&value).map_err(|error| SarifError::Canonical {
        message: error.to_string(),
    })
}

fn safe_relative(path: &str) -> bool {
    let candidate = Path::new(path);
    !candidate.is_absolute()
        && candidate
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn sanitize_hazard(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '-'
            }
        })
        .collect()
}

fn rule_id(outcome: TerminalOutcome, hazard: &str) -> String {
    let outcome_label = sanitize_hazard(outcome.as_str());
    let hazard_label = sanitize_hazard(hazard);
    if hazard_label == outcome_label {
        format!("FRF-ETP-{outcome_label}")
    } else {
        format!("FRF-ETP-{outcome_label}-{hazard_label}")
    }
}

fn level_for(outcome: TerminalOutcome) -> &'static str {
    match outcome {
        TerminalOutcome::ObservedViolation
        | TerminalOutcome::IllegalCase
        | TerminalOutcome::HarnessFailure => "error",
        TerminalOutcome::IncompleteTranscript | TerminalOutcome::Unresolved => "warning",
        TerminalOutcome::NotRun => "note",
        TerminalOutcome::VerifiedCompatibleWithinTranscript => "none",
    }
}

fn finding_codes(receipt: &CampaignReceipt) -> Vec<String> {
    receipt
        .observation
        .findings
        .iter()
        .map(|finding| finding.code.clone())
        .collect()
}

fn hazards(
    receipt: &CampaignReceipt,
) -> Vec<(String, Option<&crate::etp_campaign::CampaignFinding>)> {
    if receipt.observation.findings.is_empty() {
        vec![(receipt.observation.outcome.as_str().to_owned(), None)]
    } else {
        receipt
            .observation
            .findings
            .iter()
            .map(|finding| (finding.code.clone(), Some(finding)))
            .collect()
    }
}

fn message_for(
    receipt: &CampaignReceipt,
    hazard: &str,
    finding: Option<&crate::etp_campaign::CampaignFinding>,
) -> String {
    let detail = finding.map_or(receipt.observation.detail.as_str(), |finding| {
        finding.detail.as_str()
    });
    format!(
        "{}: {} [{}] {}",
        receipt.case_id,
        receipt.observation.outcome.as_str(),
        hazard,
        detail
    )
}

fn project_result(
    protocol: &CampaignProtocol,
    receipt: &CampaignReceipt,
    hazard: &str,
    finding: Option<&crate::etp_campaign::CampaignFinding>,
    index: usize,
) -> SarifResult {
    let occurrence_id = format!("{}::{}::{index}", receipt.case_id, hazard);
    let mut fingerprints = BTreeMap::new();
    fingerprints.insert(
        "frf/candidate".to_owned(),
        receipt.candidate_identity.clone(),
    );
    fingerprints.insert(
        "frf/instrument-execution".to_owned(),
        receipt.instrument_execution_identity.clone(),
    );
    fingerprints.insert("frf/case".to_owned(), receipt.case_id.clone());
    fingerprints.insert("frf/occurrence".to_owned(), occurrence_id.clone());

    let has_transcript = receipt
        .evidence
        .iter()
        .any(|evidence| evidence.kind == "transcript");
    let locations = if has_transcript {
        vec![SarifLocation {
            physical_location: Some(SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: receipt.execution.fixture_path.clone(),
                },
            }),
            logical_locations: finding
                .filter(|finding| !finding.subject.is_empty())
                .map(|finding| {
                    vec![SarifLogicalLocation {
                        name: finding.subject.clone(),
                        kind: "object".to_owned(),
                    }]
                })
                .unwrap_or_default(),
        }]
    } else {
        Vec::new()
    };

    let suppressions = if receipt.suppression.suppressed {
        vec![SarifSuppression {
            kind: "external".to_owned(),
            justification: receipt.suppression.justification.clone(),
            properties: SarifSuppressionProperties {
                scope: receipt.suppression.scope.clone(),
                owner: receipt.suppression.owner.clone(),
                expiry: receipt.suppression.expiry.clone(),
                invalidation: receipt.suppression.invalidation.clone(),
            },
        }]
    } else {
        Vec::new()
    };

    SarifResult {
        rule_id: rule_id(receipt.observation.outcome, hazard),
        rule_index: 0,
        level: level_for(receipt.observation.outcome).to_owned(),
        message: SarifMessage {
            text: message_for(receipt, hazard, finding),
        },
        locations,
        fingerprints: fingerprints.clone(),
        partial_fingerprints: BTreeMap::new(),
        baseline_state: "new".to_owned(),
        suppressions,
        properties: SarifResultProperties {
            case_id: receipt.case_id.clone(),
            requirement: receipt.requirement.clone(),
            obligations: receipt.obligations.clone(),
            hazard: hazard.to_owned(),
            observed_outcome: receipt.observation.outcome.as_str().to_owned(),
            expected_outcome: receipt.adjudication.expected_outcome.as_str().to_owned(),
            decision: receipt.adjudication.decision.as_str().to_owned(),
            release_decision: receipt.release_decision.as_str().to_owned(),
            candidate_identity: receipt.candidate_identity.clone(),
            instrument_execution_identity: receipt.instrument_execution_identity.clone(),
            occurrence_id,
            evidence_sha256: receipt
                .evidence
                .iter()
                .map(|evidence| evidence.sha256.clone())
                .collect(),
            finding_codes: finding_codes(receipt),
            absence_reason: "not_compared".to_owned(),
            absence_evidence: Vec::new(),
            previous_instrument_execution_identity: String::new(),
            scope: protocol.scope.clone(),
        },
    }
}

fn build_rules(results: &[SarifResult]) -> Vec<SarifRule> {
    let mut rules: BTreeMap<String, SarifRule> = BTreeMap::new();
    for result in results {
        rules.entry(result.rule_id.clone()).or_insert_with(|| SarifRule {
            id: result.rule_id.clone(),
            name: result.properties.hazard.clone(),
            short_description: SarifMessage {
                text: format!("FRF ETP hazard {}", result.properties.hazard),
            },
            full_description: SarifMessage {
                text: format!(
                    "A retained {} hazard from the declared finite ETP campaign. This is a report projection, not a proof.",
                    result.properties.hazard
                ),
            },
            default_configuration: SarifConfiguration {
                level: result.level.clone(),
            },
            properties: serde_json::json!({
                "hazard": result.properties.hazard,
                "observed_outcome": result.properties.observed_outcome,
                "category": "earned-trust-campaign",
                "report_only": true,
            }),
        });
    }
    rules.into_values().collect()
}

/// Project a verified campaign bundle into a SARIF log.
///
/// # Errors
///
/// Returns [`SarifError`] when the campaign is refused, when the projected
/// document exceeds the declared result or byte limit, or when encoding fails.
#[allow(clippy::too_many_lines)]
pub fn project_bundle(
    bundle: &CampaignBundle,
    native_manifest: &str,
    native_manifest_sha256: &str,
) -> Result<SarifLog, SarifError> {
    let report = etp_campaign::verify_bundle(bundle)?;
    if report.status == CampaignStatus::Refused {
        return Err(SarifError::CampaignRefused {
            message: report
                .refusals
                .iter()
                .map(|refusal| format!("{}:{}", refusal.code.as_str(), refusal.case_id))
                .collect::<Vec<_>>()
                .join(","),
        });
    }
    let protocol = etp_campaign::parse_protocol(&bundle.protocol_bytes)?;
    let closure = etp_campaign::parse_closure(&bundle.closure_bytes)?;
    let receipts = etp_campaign::parse_receipts(bundle)?;

    let mut results = Vec::new();
    let mut fixture_paths = BTreeSet::new();
    for (_, receipt) in &receipts {
        if receipt.observation.outcome.is_clean() {
            continue;
        }
        if receipt
            .evidence
            .iter()
            .any(|evidence| evidence.kind == "transcript")
        {
            fixture_paths.insert(receipt.execution.fixture_path.clone());
        }
        for (index, (hazard, finding)) in hazards(receipt).into_iter().enumerate() {
            results.push(project_result(&protocol, receipt, &hazard, finding, index));
        }
    }
    if results.len() > MAX_SARIF_RESULTS {
        return Err(SarifError::ShardingRequired {
            message: format!(
                "{} results exceed the {MAX_SARIF_RESULTS}-result limit",
                results.len()
            ),
        });
    }
    let rules = build_rules(&results);
    let rule_indexes: BTreeMap<String, usize> = rules
        .iter()
        .enumerate()
        .map(|(index, rule)| (rule.id.clone(), index))
        .collect();
    for result in &mut results {
        result.rule_index = *rule_indexes.get(&result.rule_id).unwrap_or(&0);
    }

    let suppressed_result_count = results
        .iter()
        .filter(|result| !result.suppressions.is_empty())
        .count();
    let artifacts = fixture_paths
        .into_iter()
        .map(|uri| SarifArtifact {
            location: SarifArtifactLocation { uri },
            roles: vec!["analysisTarget".to_owned()],
            properties: serde_json::json!({"source": "declared native fixture"}),
        })
        .collect::<Vec<_>>();

    let mut log = SarifLog {
        schema: SARIF_SCHEMA_URI.to_owned(),
        version: SARIF_VERSION.to_owned(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: SARIF_TOOL_NAME.to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                    information_uri: "https://github.com/infinityabundance/frf-memorysafety"
                        .to_owned(),
                    rules,
                    properties: serde_json::json!({
                        "projection_schema": SARIF_PROJECTION_SCHEMA,
                        "report_only": true,
                        "not_a_certificate": true,
                    }),
                },
            },
            artifacts,
            results,
            properties: SarifRunProperties {
                frf_projection_schema: SARIF_PROJECTION_SCHEMA.to_owned(),
                campaign_id: protocol.campaign_id.clone(),
                opening_sha256: report.opening_sha256.clone(),
                candidate_identity: protocol.candidate.tree_sha256.clone(),
                instrument_id: protocol.instrument.id.clone(),
                instrument_identity: protocol.instrument.tree_sha256.clone(),
                case_count: protocol.population.len(),
                receipt_count: closure.receipt_count,
                result_count: closure.receipts.len(),
                retained_finding_count: 0,
                suppressed_result_count,
                scope: protocol.scope.clone(),
                assumptions: protocol.assumptions.clone(),
                unsupported_features: protocol.unsupported_features.clone(),
                completeness: SarifCompleteness {
                    complete: true,
                    receipt_count: closure.receipt_count,
                    result_count: 0,
                    native_manifest: native_manifest.to_owned(),
                    native_manifest_sha256: native_manifest_sha256.to_owned(),
                    shards: Vec::new(),
                },
                limits: SarifLimitsRecord {
                    max_results: MAX_SARIF_RESULTS,
                    max_bytes: MAX_SARIF_BYTES,
                    result_count: 0,
                    encoded_bytes: 0,
                    truncated: false,
                },
                claim_ceiling: SARIF_CLAIM_CEILING.to_owned(),
            },
        }],
    };

    let result_count = log.runs[0].results.len();
    log.runs[0].properties.result_count = result_count;
    log.runs[0].properties.retained_finding_count = result_count;
    log.runs[0].properties.completeness.result_count = result_count;
    log.runs[0].properties.limits.result_count = result_count;

    let mut bytes = canonical_json(&log)?;
    for _ in 0..8 {
        log.runs[0].properties.limits.encoded_bytes = bytes.len();
        let next = canonical_json(&log)?;
        if next.len() == bytes.len() {
            bytes = next;
            break;
        }
        bytes = next;
    }
    if bytes.len() > MAX_SARIF_BYTES {
        return Err(SarifError::ShardingRequired {
            message: format!(
                "{} encoded bytes exceed the {MAX_SARIF_BYTES}-byte limit",
                bytes.len()
            ),
        });
    }
    Ok(log)
}

/// Export a campaign closure manifest to a SARIF log.
///
/// # Errors
///
/// Returns [`SarifError`] when the campaign cannot be loaded, is refused, or the
/// projection exceeds a limit.
pub fn export_campaign(manifest_path: &Path) -> Result<SarifLog, SarifError> {
    let bundle = etp_campaign::load_bundle(manifest_path)?;
    let manifest_name = manifest_path.file_name().map_or_else(
        || "MANIFEST.json".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    let digest = etp_campaign::sha256_hex(&bundle.closure_bytes);
    project_bundle(&bundle, &manifest_name, &digest)
}

/// Export a campaign to canonical SARIF bytes.
///
/// # Errors
///
/// Returns [`SarifError`] as for [`export_campaign`].
pub fn export_campaign_bytes(manifest_path: &Path) -> Result<Vec<u8>, SarifError> {
    let log = export_campaign(manifest_path)?;
    canonical_json(&log)
}

fn projection_refusal(
    code: SarifRefusalCode,
    subject: impl Into<String>,
    detail: impl Into<String>,
) -> SarifRefusal {
    SarifRefusal {
        code,
        subject: subject.into(),
        detail: detail.into(),
    }
}

fn check_suppression(
    suppression: &SarifSuppression,
    subject: &str,
    refusals: &mut Vec<SarifRefusal>,
) {
    if suppression.kind != "external" {
        refusals.push(projection_refusal(
            SarifRefusalCode::UnauthorizedSuppression,
            subject,
            "suppression kind must be external",
        ));
    }
    for (label, value) in [
        ("justification", &suppression.justification),
        ("scope", &suppression.properties.scope),
        ("owner", &suppression.properties.owner),
        ("expiry", &suppression.properties.expiry),
        ("invalidation", &suppression.properties.invalidation),
    ] {
        if value.trim().is_empty() {
            refusals.push(projection_refusal(
                SarifRefusalCode::UnauthorizedSuppression,
                subject,
                format!("suppression is missing {label}"),
            ));
        }
    }
}

fn check_baseline_state(result: &SarifResult, refusals: &mut Vec<SarifRefusal>) {
    let allowed = ["new", "unchanged", "updated", "absent", "renamed"];
    if !allowed.contains(&result.baseline_state.as_str()) {
        refusals.push(projection_refusal(
            SarifRefusalCode::InvalidBaselineState,
            &result.properties.occurrence_id,
            format!("unsupported baseline state {}", result.baseline_state),
        ));
        return;
    }
    if result.baseline_state != "absent" {
        if result.properties.absence_reason != "not_compared" {
            refusals.push(projection_refusal(
                SarifRefusalCode::InvalidBaselineState,
                &result.properties.occurrence_id,
                "a present result must not claim an absence reason",
            ));
        }
        return;
    }
    match result.properties.absence_reason.as_str() {
        "repaired" => {
            if result.properties.absence_evidence.is_empty() {
                refusals.push(projection_refusal(
                    SarifRefusalCode::InvalidBaselineState,
                    &result.properties.occurrence_id,
                    "a repaired absence requires repair evidence",
                ));
            }
        }
        "tool_change" => {
            if result.properties.absence_evidence.is_empty() {
                refusals.push(projection_refusal(
                    SarifRefusalCode::InvalidBaselineState,
                    &result.properties.occurrence_id,
                    "a tool-change absence requires instrument-change evidence",
                ));
            }
            if result
                .properties
                .previous_instrument_execution_identity
                .is_empty()
                || result.properties.previous_instrument_execution_identity
                    == result.properties.instrument_execution_identity
            {
                refusals.push(projection_refusal(
                    SarifRefusalCode::InvalidBaselineState,
                    &result.properties.occurrence_id,
                    "a tool-change absence requires a distinct previous instrument execution",
                ));
            }
        }
        _ => refusals.push(projection_refusal(
            SarifRefusalCode::InvalidBaselineState,
            &result.properties.occurrence_id,
            "an absent result must distinguish repaired from tool-change with evidence",
        )),
    }
}

fn compare_results(expected: &SarifResult, actual: &SarifResult, refusals: &mut Vec<SarifRefusal>) {
    let subject = &expected.properties.occurrence_id;
    if expected.rule_id != actual.rule_id {
        refusals.push(projection_refusal(
            SarifRefusalCode::IdentityMismatch,
            subject,
            format!(
                "rule id {} differs from {}",
                actual.rule_id, expected.rule_id
            ),
        ));
    }
    if expected.rule_index != actual.rule_index {
        refusals.push(projection_refusal(
            SarifRefusalCode::IdentityMismatch,
            subject,
            "rule index differs",
        ));
    }
    if expected.level != actual.level {
        refusals.push(projection_refusal(
            SarifRefusalCode::IdentityMismatch,
            subject,
            "level differs",
        ));
    }
    if expected.message != actual.message {
        refusals.push(projection_refusal(
            SarifRefusalCode::IdentityMismatch,
            subject,
            "message differs",
        ));
    }
    if expected.locations != actual.locations {
        refusals.push(projection_refusal(
            SarifRefusalCode::IdentityMismatch,
            subject,
            "locations differ",
        ));
    }
    if expected.fingerprints != actual.fingerprints {
        refusals.push(projection_refusal(
            SarifRefusalCode::IdentityMismatch,
            subject,
            "fingerprints differ",
        ));
    }
    if expected.suppressions != actual.suppressions {
        refusals.push(projection_refusal(
            SarifRefusalCode::UnauthorizedSuppression,
            subject,
            "suppressions differ from the campaign record",
        ));
    }
    if expected.properties != actual.properties {
        refusals.push(projection_refusal(
            SarifRefusalCode::IdentityMismatch,
            subject,
            "result properties differ",
        ));
    }
}

/// Parse and structurally verify a SARIF projection.
///
/// # Errors
///
/// Returns [`SarifError`] for malformed JSON, an unsupported schema or version,
/// or an unreadable native campaign manifest. Semantic disagreements are
/// accumulated as refusals in the returned report.
#[allow(clippy::too_many_lines)]
pub fn verify_sarif_file(path: &Path) -> Result<SarifReport, SarifError> {
    let bytes = fs::read(path).map_err(|error| SarifError::Io {
        message: format!("cannot read {}: {error}", path.display()),
    })?;
    let value = parse_strict(&bytes)?;
    let log: SarifLog = serde_json::from_value(value).map_err(|error| SarifError::Invalid {
        message: error.to_string(),
    })?;
    let mut refusals = Vec::new();
    if log.schema != SARIF_SCHEMA_URI {
        refusals.push(projection_refusal(
            SarifRefusalCode::UnsupportedVersion,
            "$schema",
            format!("expected {SARIF_SCHEMA_URI}, found {}", log.schema),
        ));
    }
    if log.version != SARIF_VERSION {
        refusals.push(projection_refusal(
            SarifRefusalCode::UnsupportedVersion,
            "version",
            format!("expected {SARIF_VERSION}, found {}", log.version),
        ));
    }
    if log.runs.len() != 1 {
        refusals.push(projection_refusal(
            SarifRefusalCode::SchemaMismatch,
            "runs",
            "the FRF ETP profile requires exactly one run",
        ));
        return Ok(SarifReport {
            schema: SARIF_PROJECTION_SCHEMA.to_owned(),
            spec: SARIF_SPEC.to_owned(),
            status: SarifStatus::Refused,
            sarif_version: log.version,
            result_count: 0,
            rule_count: 0,
            retained_finding_count: 0,
            suppressed_result_count: 0,
            candidate_identity: String::new(),
            instrument_identity: String::new(),
            refusals,
            limits: SarifLimitsRecord {
                max_results: MAX_SARIF_RESULTS,
                max_bytes: MAX_SARIF_BYTES,
                result_count: 0,
                encoded_bytes: bytes.len(),
                truncated: false,
            },
            claim_ceiling: SARIF_CLAIM_CEILING.to_owned(),
        });
    }
    let run = &log.runs[0];
    let properties = &run.properties;
    if properties.frf_projection_schema != SARIF_PROJECTION_SCHEMA {
        refusals.push(projection_refusal(
            SarifRefusalCode::SchemaMismatch,
            "run.properties.frf_projection_schema",
            format!(
                "expected {SARIF_PROJECTION_SCHEMA}, found {}",
                properties.frf_projection_schema
            ),
        ));
    }
    if run.tool.driver.name != SARIF_TOOL_NAME {
        refusals.push(projection_refusal(
            SarifRefusalCode::SchemaMismatch,
            "tool.driver.name",
            format!("expected {SARIF_TOOL_NAME}, found {}", run.tool.driver.name),
        ));
    }
    if !safe_relative(&properties.completeness.native_manifest) {
        refusals.push(projection_refusal(
            SarifRefusalCode::MissingNativeManifest,
            "completeness.native_manifest",
            "native manifest path must be a safe relative path",
        ));
        return Ok(SarifReport {
            schema: SARIF_PROJECTION_SCHEMA.to_owned(),
            spec: SARIF_SPEC.to_owned(),
            status: SarifStatus::Refused,
            sarif_version: log.version,
            result_count: run.results.len(),
            rule_count: run.tool.driver.rules.len(),
            retained_finding_count: run.results.len(),
            suppressed_result_count: run
                .results
                .iter()
                .filter(|result| !result.suppressions.is_empty())
                .count(),
            candidate_identity: properties.candidate_identity.clone(),
            instrument_identity: properties.instrument_identity.clone(),
            refusals,
            limits: properties.limits.clone(),
            claim_ceiling: SARIF_CLAIM_CEILING.to_owned(),
        });
    }
    let manifest_path = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(&properties.completeness.native_manifest);
    let bundle = match etp_campaign::load_bundle(&manifest_path) {
        Ok(bundle) => bundle,
        Err(error) => {
            refusals.push(projection_refusal(
                SarifRefusalCode::MissingNativeManifest,
                "completeness.native_manifest",
                format!("cannot load native campaign: {error}"),
            ));
            return Ok(SarifReport {
                schema: SARIF_PROJECTION_SCHEMA.to_owned(),
                spec: SARIF_SPEC.to_owned(),
                status: SarifStatus::Refused,
                sarif_version: log.version,
                result_count: run.results.len(),
                rule_count: run.tool.driver.rules.len(),
                retained_finding_count: run.results.len(),
                suppressed_result_count: run
                    .results
                    .iter()
                    .filter(|result| !result.suppressions.is_empty())
                    .count(),
                candidate_identity: properties.candidate_identity.clone(),
                instrument_identity: properties.instrument_identity.clone(),
                refusals,
                limits: properties.limits.clone(),
                claim_ceiling: SARIF_CLAIM_CEILING.to_owned(),
            });
        }
    };
    let campaign_report = etp_campaign::verify_bundle(&bundle)?;
    if campaign_report.status == CampaignStatus::Refused {
        refusals.push(projection_refusal(
            SarifRefusalCode::CampaignInvalid,
            &properties.campaign_id,
            "the native campaign does not reconcile",
        ));
    }
    let native_digest = etp_campaign::sha256_hex(&bundle.closure_bytes);
    if native_digest != properties.completeness.native_manifest_sha256 {
        refusals.push(projection_refusal(
            SarifRefusalCode::DigestMismatch,
            "completeness.native_manifest_sha256",
            "native manifest digest differs from the loaded closure",
        ));
    }
    let expected = project_bundle(
        &bundle,
        &properties.completeness.native_manifest,
        &native_digest,
    )?;

    let expected_run = &expected.runs[0];
    if properties.candidate_identity != expected_run.properties.candidate_identity {
        refusals.push(projection_refusal(
            SarifRefusalCode::IdentityMismatch,
            "candidate_identity",
            "candidate identity differs from the native campaign",
        ));
    }
    if properties.instrument_identity != expected_run.properties.instrument_identity {
        refusals.push(projection_refusal(
            SarifRefusalCode::IdentityMismatch,
            "instrument_identity",
            "instrument identity differs from the native campaign",
        ));
    }
    if properties.opening_sha256 != expected_run.properties.opening_sha256 {
        refusals.push(projection_refusal(
            SarifRefusalCode::IdentityMismatch,
            "opening_sha256",
            "opening manifest digest differs from the native campaign",
        ));
    }
    if properties.receipt_count != expected_run.properties.receipt_count {
        refusals.push(projection_refusal(
            SarifRefusalCode::InconsistentCount,
            "receipt_count",
            "receipt count differs from the native campaign",
        ));
    }

    let actual_by_id: BTreeMap<String, &SarifResult> = run
        .results
        .iter()
        .map(|result| (result.properties.occurrence_id.clone(), result))
        .collect();
    let expected_by_id: BTreeMap<String, &SarifResult> = expected_run
        .results
        .iter()
        .map(|result| (result.properties.occurrence_id.clone(), result))
        .collect();
    for (occurrence, expected_result) in &expected_by_id {
        match actual_by_id.get(occurrence) {
            Some(actual_result) => compare_results(expected_result, actual_result, &mut refusals),
            None => refusals.push(projection_refusal(
                SarifRefusalCode::MissingResult,
                occurrence,
                "expected result occurrence is absent",
            )),
        }
    }
    for occurrence in actual_by_id.keys() {
        if !expected_by_id.contains_key(occurrence) {
            refusals.push(projection_refusal(
                SarifRefusalCode::UnexpectedResult,
                occurrence,
                "unexpected result occurrence",
            ));
        }
    }
    if run.results.len() != actual_by_id.len() {
        refusals.push(projection_refusal(
            SarifRefusalCode::InconsistentCount,
            "results",
            "duplicate occurrence identities",
        ));
    }

    let allowed_fixtures: BTreeSet<&str> = expected_run
        .artifacts
        .iter()
        .map(|artifact| artifact.location.uri.as_str())
        .collect();
    for result in &run.results {
        for location in &result.locations {
            if let Some(physical) = &location.physical_location {
                if !allowed_fixtures.contains(physical.artifact_location.uri.as_str()) {
                    refusals.push(projection_refusal(
                        SarifRefusalCode::FabricatedLocation,
                        &result.properties.occurrence_id,
                        format!(
                            "location {} is not a declared fixture",
                            physical.artifact_location.uri
                        ),
                    ));
                }
            }
        }
        for suppression in &result.suppressions {
            check_suppression(suppression, &result.properties.occurrence_id, &mut refusals);
        }
        check_baseline_state(result, &mut refusals);
    }

    let mut expected_rules: BTreeSet<&str> = expected_run
        .tool
        .driver
        .rules
        .iter()
        .map(|rule| rule.id.as_str())
        .collect();
    for rule in &run.tool.driver.rules {
        if !expected_rules.remove(rule.id.as_str()) {
            refusals.push(projection_refusal(
                SarifRefusalCode::UnexpectedResult,
                &rule.id,
                "unexpected rule",
            ));
        }
    }
    for missing in expected_rules {
        refusals.push(projection_refusal(
            SarifRefusalCode::MissingRule,
            missing,
            "expected rule is absent",
        ));
    }
    for result in &run.results {
        if run
            .tool
            .driver
            .rules
            .iter()
            .all(|rule| rule.id != result.rule_id)
        {
            refusals.push(projection_refusal(
                SarifRefusalCode::MissingRule,
                &result.rule_id,
                "result references a rule that is absent from the rule table",
            ));
        }
        if result.rule_index >= run.tool.driver.rules.len()
            || run.tool.driver.rules[result.rule_index].id != result.rule_id
        {
            refusals.push(projection_refusal(
                SarifRefusalCode::IdentityMismatch,
                &result.properties.occurrence_id,
                "ruleIndex does not select the result rule",
            ));
        }
        for key in [
            "frf/candidate",
            "frf/instrument-execution",
            "frf/case",
            "frf/occurrence",
        ] {
            if result.fingerprints.get(key).is_none_or(String::is_empty) {
                refusals.push(projection_refusal(
                    SarifRefusalCode::IdentityMismatch,
                    &result.properties.occurrence_id,
                    format!("fingerprint {key} is missing"),
                ));
            }
        }
    }

    let actual_results = run.results.len();
    if properties.result_count != actual_results
        || properties.completeness.result_count != actual_results
        || properties.limits.result_count != actual_results
        || properties.retained_finding_count != actual_results
    {
        refusals.push(projection_refusal(
            SarifRefusalCode::InconsistentCount,
            "result_count",
            "run summary counts disagree with the result array",
        ));
    }
    let suppressed = run
        .results
        .iter()
        .filter(|result| !result.suppressions.is_empty())
        .count();
    if properties.suppressed_result_count != suppressed {
        refusals.push(projection_refusal(
            SarifRefusalCode::InconsistentCount,
            "suppressed_result_count",
            "suppressed count disagrees with the result array",
        ));
    }
    if properties.completeness.complete {
        if !properties.completeness.shards.is_empty() {
            refusals.push(projection_refusal(
                SarifRefusalCode::IncompleteSharding,
                "completeness.shards",
                "a complete document must not declare shards",
            ));
        }
        if properties.limits.truncated {
            refusals.push(projection_refusal(
                SarifRefusalCode::IncompleteSharding,
                "limits.truncated",
                "a complete document must not be truncated",
            ));
        }
    } else {
        if properties.completeness.shards.is_empty() {
            refusals.push(projection_refusal(
                SarifRefusalCode::IncompleteSharding,
                "completeness.shards",
                "an incomplete document must declare explicit shards",
            ));
        }
        let sharded: usize = properties
            .completeness
            .shards
            .iter()
            .map(|shard| shard.result_count)
            .sum();
        if sharded != actual_results {
            refusals.push(projection_refusal(
                SarifRefusalCode::IncompleteSharding,
                "completeness.shards",
                "shard result ranges do not cover the result array",
            ));
        }
        for shard in &properties.completeness.shards {
            if !safe_relative(&shard.path) || shard.sha256.len() != 64 || shard.result_count == 0 {
                refusals.push(projection_refusal(
                    SarifRefusalCode::IncompleteSharding,
                    &shard.path,
                    "shard declaration is not lossless",
                ));
            }
        }
    }
    if properties.limits.max_results < actual_results {
        refusals.push(projection_refusal(
            SarifRefusalCode::LimitExceeded,
            "limits.max_results",
            "result count exceeds the declared limit",
        ));
    }
    let canonical_len = canonical_json(&log)?.len();
    if properties.limits.encoded_bytes != canonical_len {
        refusals.push(projection_refusal(
            SarifRefusalCode::InconsistentCount,
            "limits.encoded_bytes",
            format!(
                "declared {} encoded bytes, canonical length {canonical_len}",
                properties.limits.encoded_bytes
            ),
        ));
    }
    if properties.limits.max_bytes < canonical_len {
        refusals.push(projection_refusal(
            SarifRefusalCode::LimitExceeded,
            "limits.max_bytes",
            "encoded bytes exceed the declared limit",
        ));
    }

    let status = if refusals.is_empty() {
        SarifStatus::Valid
    } else {
        SarifStatus::Refused
    };
    Ok(SarifReport {
        schema: SARIF_PROJECTION_SCHEMA.to_owned(),
        spec: SARIF_SPEC.to_owned(),
        status,
        sarif_version: log.version,
        result_count: actual_results,
        rule_count: run.tool.driver.rules.len(),
        retained_finding_count: actual_results,
        suppressed_result_count: suppressed,
        candidate_identity: properties.candidate_identity.clone(),
        instrument_identity: properties.instrument_identity.clone(),
        refusals,
        limits: properties.limits.clone(),
        claim_ceiling: SARIF_CLAIM_CEILING.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hazard_rule_identity_is_stable_and_separated() {
        assert_eq!(
            rule_id(TerminalOutcome::ObservedViolation, "use_after_free"),
            "FRF-ETP-OBSERVED-VIOLATION-USE-AFTER-FREE"
        );
        assert_ne!(
            rule_id(TerminalOutcome::ObservedViolation, "use_after_free"),
            rule_id(TerminalOutcome::ObservedViolation, "data_race")
        );
        assert_eq!(
            rule_id(TerminalOutcome::Unresolved, "unresolved"),
            "FRF-ETP-UNRESOLVED"
        );
    }

    #[test]
    fn suppression_without_fields_is_refused() {
        let suppression = SarifSuppression {
            kind: "external".to_owned(),
            justification: String::new(),
            properties: SarifSuppressionProperties {
                scope: String::new(),
                owner: String::new(),
                expiry: String::new(),
                invalidation: String::new(),
            },
        };
        let mut refusals = Vec::new();
        check_suppression(&suppression, "case", &mut refusals);
        assert!(refusals
            .iter()
            .any(|refusal| refusal.code == SarifRefusalCode::UnauthorizedSuppression));
    }
}
