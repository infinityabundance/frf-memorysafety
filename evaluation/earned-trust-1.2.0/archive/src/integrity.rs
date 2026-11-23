#![allow(clippy::module_name_repetitions)]

//! Typed reproducibility and population integrity model (Phase 11.1a).
//!
//! This module defines a small, additive data model for recording the separate,
//! non-collapsed reproducibility dimensions of an artifact, the identity of the
//! artifact and its build environment, and a frozen population manifest. It is
//! deliberately narrow: it provides **no** CLI, gate script, verifier, or
//! two-build harness. It only defines the typed model and its validation rules.
//!
//! # Separation of dimensions
//!
//! Source reconstruction, environment reconstruction, byte-identical artifact
//! reconstruction, semantically-equivalent artifact reconstruction, experiment
//! replay, statistical replication, proof replay, and independent adjudication
//! are distinct dimensions. A byte difference is never normalized into a
//! byte-reproducibility pass, and semantic equivalence never upgrades a byte
//! difference into byte identity.
//!
//! # Claim ceiling
//!
//! A successful validation establishes only that a supplied report is
//! structurally complete, versioned, internally consistent, and does not
//! promote a `NotRun` dimension to `Established`, does not claim byte identity
//! across differing digests, and does not claim semantic equivalence without a
//! recorded justification. It does **not** establish that a build is
//! reproducible, that an artifact is authentic, that a population is complete,
//! or that any dimension is independently confirmed. A digest is not
//! authentication, a recorded justification is not proof, and a passing
//! validator is not certification.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::{canonical_bytes, hex_lower, parse_strict, IdentityError};

/// Protocol specification identifier for the integrity schemas in this module.
pub const INTEGRITY_SPEC: &str = "frf-integrity-v1";
/// Report schema identifier.
pub const INTEGRITY_REPORT_SCHEMA: &str = "frf-integrity.report.v1";
/// Population-manifest schema identifier.
pub const POPULATION_MANIFEST_SCHEMA: &str = "frf-integrity.population-manifest.v1";

/// Claim ceiling embedded in every integrity report.
pub const INTEGRITY_CLAIM_CEILING: &str = "Integrity validation is bookkeeping over declared reproducibility dimensions and a frozen population manifest. It does not establish that a build is reproducible, that an artifact is authentic, that a population is complete, or that any dimension is independently confirmed. A digest is not authentication, a recorded justification is not proof, and a passing validator is not certification.";

/// Object keys that select a population by filesystem timestamp or modification
/// time. Such selection is forbidden because it is not reproducible.
const FORBIDDEN_SELECTION_KEYS: &[&str] = &[
    "mtime",
    "modified",
    "modified_time",
    "timestamp",
    "selected_at",
    "selection_time",
    "file_mtime",
    "ctime",
    "atime",
];

/// The separate, non-collapsed reproducibility dimensions of an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReproducibilityDimension {
    /// The source tree can be reconstructed from declared inputs.
    SourceReconstruction,
    /// The build environment can be reconstructed from declared inputs.
    EnvironmentReconstruction,
    /// A rebuild produces a byte-identical artifact.
    ByteIdenticalArtifact,
    /// A rebuild produces a semantically-equivalent but not byte-identical artifact.
    SemanticallyEquivalentArtifact,
    /// A declared experiment can be replayed.
    ExperimentReplay,
    /// A statistical result can be replicated.
    StatisticalReplication,
    /// A proof object can be replayed.
    ProofReplay,
    /// An independent adjudicator can reach the same decision.
    IndependentAdjudication,
}

impl ReproducibilityDimension {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceReconstruction => "source_reconstruction",
            Self::EnvironmentReconstruction => "environment_reconstruction",
            Self::ByteIdenticalArtifact => "byte_identical_artifact",
            Self::SemanticallyEquivalentArtifact => "semantically_equivalent_artifact",
            Self::ExperimentReplay => "experiment_replay",
            Self::StatisticalReplication => "statistical_replication",
            Self::ProofReplay => "proof_replay",
            Self::IndependentAdjudication => "independent_adjudication",
        }
    }
}

impl fmt::Display for ReproducibilityDimension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The status of one reproducibility dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DimensionStatus {
    /// The dimension is established by recorded evidence.
    Established,
    /// The dimension was attempted and is not established.
    NotEstablished,
    /// The dimension was not run. It is never established.
    NotRun,
    /// The dimension was refused.
    Refused,
    /// The dimension is unresolved.
    Unresolved,
}

impl DimensionStatus {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Established => "established",
            Self::NotEstablished => "not_established",
            Self::NotRun => "not_run",
            Self::Refused => "refused",
            Self::Unresolved => "unresolved",
        }
    }

    /// Whether this status counts as established. `NotRun` is never established.
    #[must_use]
    pub const fn is_established(self) -> bool {
        matches!(self, Self::Established)
    }
}

impl fmt::Display for DimensionStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The exact toolchain used for a build.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Toolchain {
    /// Exact `rustc` version string.
    pub rustc_version: String,
    /// Host triple the toolchain runs on.
    pub host: String,
}

/// The identity of an artifact and the environment that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct ArtifactIdentity {
    /// SHA-256 of the source tree.
    pub source_tree_sha256: String,
    /// SHA-256 of the lockfile.
    pub lockfile_sha256: String,
    /// SHA-256 of the build recipe.
    pub build_recipe_sha256: String,
    /// Exact toolchain identity.
    pub toolchain: Toolchain,
    /// Target triple.
    pub target: String,
    /// Enabled features.
    pub features: Vec<String>,
    /// Build profile.
    pub profile: String,
    /// Link-time optimization mode.
    pub lto: String,
    /// Panic strategy.
    pub panic: String,
    /// Whether overflow checks are enabled.
    pub overflow_checks: bool,
    /// SHA-256 of the environment whitelist.
    pub env_whitelist_sha256: String,
    /// SHA-256 of the produced binary.
    pub binary_sha256: String,
    /// Size of the produced binary in bytes.
    pub binary_size: u64,
    /// Declared scope of the artifact identity.
    pub scope: String,
}

/// One case in a frozen population.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PopulationCase {
    /// Stable case identifier. Cases are sorted by this field.
    pub id: String,
    /// Digest binding the case content.
    pub digest: String,
    /// Whether the case is required for the population to be complete.
    pub required: bool,
}

/// A frozen population manifest with a deterministic digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PopulationManifest {
    /// Manifest version identifier.
    pub version: String,
    /// Population cases, sorted strictly ascending by `id`.
    pub cases: Vec<PopulationCase>,
    /// Declared case count. Must equal `cases.len()`.
    pub count: usize,
    /// SHA-256 over the canonical JSON of `{version, cases, count}`.
    pub manifest_digest: String,
}

/// Canonical content hashed to produce a manifest digest.
#[derive(Serialize)]
struct PopulationContent<'a> {
    version: &'a str,
    cases: &'a [PopulationCase],
    count: usize,
}

impl PopulationManifest {
    /// Build a manifest from a version and cases.
    ///
    /// Cases are sorted by `id`, the count is derived, and the manifest digest
    /// is computed over the canonical content.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrityError`] if the canonical content cannot be encoded.
    pub fn new(
        version: impl Into<String>,
        mut cases: Vec<PopulationCase>,
    ) -> Result<Self, IntegrityError> {
        cases.sort_by(|left, right| left.id.cmp(&right.id));
        let count = cases.len();
        let mut manifest = Self {
            version: version.into(),
            cases,
            count,
            manifest_digest: String::new(),
        };
        manifest.manifest_digest = manifest.compute_digest()?;
        Ok(manifest)
    }

    /// Compute the deterministic manifest digest over canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrityError`] if the canonical content cannot be encoded.
    pub fn compute_digest(&self) -> Result<String, IntegrityError> {
        let content = PopulationContent {
            version: &self.version,
            cases: &self.cases,
            count: self.count,
        };
        let value = serde_json::to_value(content).map_err(|error| IntegrityError::Canonical {
            message: error.to_string(),
        })?;
        let bytes = canonical_bytes(&value)?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Ok(hex_lower(&hasher.finalize()))
    }

    /// Validate the manifest.
    ///
    /// Rejects an empty version, an empty population, a count mismatch, a
    /// duplicate case, unsorted cases, and a digest mismatch.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrityError`] for the first violated rule.
    pub fn validate(&self) -> Result<(), IntegrityError> {
        if self.version.trim().is_empty() {
            return Err(IntegrityError::Invalid {
                message: "population version must not be empty".to_owned(),
            });
        }
        if self.cases.is_empty() {
            return Err(refusal(
                IntegrityRefusalCode::EmptyPopulation,
                "population must contain at least one case; empty is not missing",
            ));
        }
        if self.count != self.cases.len() {
            return Err(refusal(
                IntegrityRefusalCode::PopulationCountMismatch,
                format!(
                    "declared count {} does not match {} cases",
                    self.count,
                    self.cases.len()
                ),
            ));
        }
        let mut seen = BTreeSet::new();
        for case in &self.cases {
            if case.id.trim().is_empty() {
                return Err(IntegrityError::Invalid {
                    message: "population case id must not be empty".to_owned(),
                });
            }
            if !seen.insert(case.id.as_str()) {
                return Err(refusal(
                    IntegrityRefusalCode::DuplicatePopulationCase,
                    format!("duplicate population case id: {}", case.id),
                ));
            }
        }
        for pair in self.cases.windows(2) {
            if pair[0].id >= pair[1].id {
                return Err(refusal(
                    IntegrityRefusalCode::UnsortedPopulation,
                    format!(
                        "population cases must be sorted by id: {} before {}",
                        pair[1].id, pair[0].id
                    ),
                ));
            }
        }
        let expected = self.compute_digest()?;
        if self.manifest_digest != expected {
            return Err(refusal(
                IntegrityRefusalCode::ManifestDigestMismatch,
                "manifest digest does not match canonical content",
            ));
        }
        Ok(())
    }
}

/// The status of one reproducibility dimension in a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DimensionAssessment {
    /// The dimension being assessed.
    pub dimension: ReproducibilityDimension,
    /// The status of the dimension.
    pub status: DimensionStatus,
    /// Recorded justification. Required for semantic equivalence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
}

/// A named refusal recorded in a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrityRefusal {
    /// Refusal code.
    pub code: IntegrityRefusalCode,
    /// Human-readable detail.
    pub detail: String,
}

/// Named refusal codes for the integrity model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityRefusalCode {
    /// Byte-identical reproducibility claimed across differing digests.
    ByteDigestMismatch,
    /// Semantic equivalence claimed without a recorded justification.
    SemanticEquivalenceWithoutJustification,
    /// Semantic equivalence used to claim byte identity.
    SemanticEquivalenceCannotUpgradeByteIdentity,
    /// A `NotRun` dimension treated as established.
    NotRunIsNotEstablished,
    /// The population manifest is missing.
    MissingPopulation,
    /// The population manifest is empty.
    EmptyPopulation,
    /// A population case is duplicated.
    DuplicatePopulationCase,
    /// Population cases are not sorted.
    UnsortedPopulation,
    /// The declared count does not match the case count.
    PopulationCountMismatch,
    /// The manifest digest does not match the canonical content.
    ManifestDigestMismatch,
    /// A timestamp or modification-time selection field is present.
    ForbiddenSelectionField,
    /// The claim ceiling is missing.
    MissingClaimCeiling,
}

impl IntegrityRefusalCode {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ByteDigestMismatch => "byte_digest_mismatch",
            Self::SemanticEquivalenceWithoutJustification => {
                "semantic_equivalence_without_justification"
            }
            Self::SemanticEquivalenceCannotUpgradeByteIdentity => {
                "semantic_equivalence_cannot_upgrade_byte_identity"
            }
            Self::NotRunIsNotEstablished => "not_run_is_not_established",
            Self::MissingPopulation => "missing_population",
            Self::EmptyPopulation => "empty_population",
            Self::DuplicatePopulationCase => "duplicate_population_case",
            Self::UnsortedPopulation => "unsorted_population",
            Self::PopulationCountMismatch => "population_count_mismatch",
            Self::ManifestDigestMismatch => "manifest_digest_mismatch",
            Self::ForbiddenSelectionField => "forbidden_selection_field",
            Self::MissingClaimCeiling => "missing_claim_ceiling",
        }
    }
}

impl fmt::Display for IntegrityRefusalCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Errors produced while parsing or validating integrity documents.
#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    /// Strict JSON parsing failed.
    #[error("invalid integrity JSON: {0}")]
    Identity(#[from] IdentityError),
    /// The typed document failed a structural rule.
    #[error("invalid integrity document: {message}")]
    Invalid {
        /// Rule that failed.
        message: String,
    },
    /// A schema or specification version is not the supported version.
    #[error("integrity schema mismatch for {field}: expected {expected}, found {actual}")]
    SchemaMismatch {
        /// Field or object name.
        field: String,
        /// Expected identifier.
        expected: String,
        /// Observed identifier.
        actual: String,
    },
    /// A document could not be encoded canonically.
    #[error("cannot encode integrity document: {message}")]
    Canonical {
        /// Encoder diagnostic.
        message: String,
    },
    /// A named integrity refusal.
    #[error("integrity refusal ({code}): {detail}")]
    Refused {
        /// Refusal code.
        code: IntegrityRefusalCode,
        /// Human-readable detail.
        detail: String,
    },
}

impl IntegrityError {
    /// Category used to choose a `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Identity(_) | Self::Invalid { .. } | Self::SchemaMismatch { .. } => 3,
            Self::Canonical { .. } => 7,
            Self::Refused { .. } => 4,
        }
    }
}

/// A typed integrity report over one artifact and one population.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrityReport {
    /// Report schema identifier.
    pub schema: String,
    /// Protocol specification identifier.
    pub spec: String,
    /// The primary artifact identity.
    pub artifact: ArtifactIdentity,
    /// The rebuild artifact identity, when a rebuild was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebuild_artifact: Option<ArtifactIdentity>,
    /// Per-dimension statuses.
    #[serde(default)]
    pub dimensions: Vec<DimensionAssessment>,
    /// The frozen population manifest. Missing is not empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub population: Option<PopulationManifest>,
    /// Named refusals recorded in this report.
    #[serde(default)]
    pub refusals: Vec<IntegrityRefusal>,
    /// Explicit claim ceiling.
    pub claim_ceiling: String,
}

impl IntegrityReport {
    /// Build a report with the supported schema, spec, and claim ceiling.
    #[must_use]
    pub fn new(artifact: ArtifactIdentity, population: PopulationManifest) -> Self {
        Self {
            schema: INTEGRITY_REPORT_SCHEMA.to_owned(),
            spec: INTEGRITY_SPEC.to_owned(),
            artifact,
            rebuild_artifact: None,
            dimensions: Vec::new(),
            population: Some(population),
            refusals: Vec::new(),
            claim_ceiling: INTEGRITY_CLAIM_CEILING.to_owned(),
        }
    }

    /// Parse and validate an integrity report from canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrityError`] for invalid JSON, schema mismatch, missing
    /// claim ceiling, missing or invalid population, duplicate dimensions,
    /// byte-identity across differing digests, semantic equivalence without
    /// justification, or a refusal without detail.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IntegrityError> {
        let value = crate::identity::parse_strict(bytes)?;
        let report: Self =
            serde_json::from_value(value).map_err(|error| IntegrityError::Invalid {
                message: error.to_string(),
            })?;
        report.validate()?;
        Ok(report)
    }

    /// Human-readable status label: "established" when at least one dimension
    /// is established and the population is complete, otherwise "refused".
    #[must_use]
    pub fn status_label(&self) -> &str {
        if self.established_dimensions().is_empty() || self.population.is_none() {
            "refused"
        } else {
            "established"
        }
    }

    /// Exit status per SPEC.md §14: 0 when established, 4 when refused.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if self.status_label() == "established" {
            0
        } else {
            4
        }
    }

    /// The dimensions currently marked `Established`.
    ///
    /// A `NotRun` dimension is never included.
    #[must_use]
    pub fn established_dimensions(&self) -> Vec<ReproducibilityDimension> {
        self.dimensions
            .iter()
            .filter(|assessment| assessment.status.is_established())
            .map(|assessment| assessment.dimension)
            .collect()
    }

    /// Validate the report.
    ///
    /// Rejects a schema or spec mismatch, a missing claim ceiling, a missing or
    /// empty population, a duplicate dimension, byte identity claimed across
    /// differing digests, semantic equivalence claimed without a recorded
    /// justification, and a recorded refusal without detail.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrityError`] for the first violated rule.
    pub fn validate(&self) -> Result<(), IntegrityError> {
        check_schema("report.schema", &self.schema, INTEGRITY_REPORT_SCHEMA)?;
        check_schema("report.spec", &self.spec, INTEGRITY_SPEC)?;
        if self.claim_ceiling.trim().is_empty() {
            return Err(refusal(
                IntegrityRefusalCode::MissingClaimCeiling,
                "an explicit claim ceiling is required",
            ));
        }
        let population = self.population.as_ref().ok_or_else(|| {
            refusal(
                IntegrityRefusalCode::MissingPopulation,
                "population manifest is required; missing is not empty",
            )
        })?;
        population.validate()?;

        let mut seen = BTreeSet::new();
        for assessment in &self.dimensions {
            if !seen.insert(assessment.dimension) {
                return Err(IntegrityError::Invalid {
                    message: format!(
                        "duplicate dimension assessment: {}",
                        assessment.dimension.as_str()
                    ),
                });
            }
        }

        for assessment in &self.dimensions {
            if !assessment.status.is_established() {
                continue;
            }
            match assessment.dimension {
                ReproducibilityDimension::ByteIdenticalArtifact => {
                    let rebuild = self.rebuild_artifact.as_ref().ok_or_else(|| {
                        refusal(
                            IntegrityRefusalCode::ByteDigestMismatch,
                            "byte-identical establishment requires a recorded rebuild artifact",
                        )
                    })?;
                    if self.artifact.binary_sha256 != rebuild.binary_sha256 {
                        return Err(refusal(
                            IntegrityRefusalCode::ByteDigestMismatch,
                            "byte-identical reproducibility cannot be established when the two digests differ",
                        ));
                    }
                }
                ReproducibilityDimension::SemanticallyEquivalentArtifact => {
                    let justified = assessment
                        .justification
                        .as_deref()
                        .is_some_and(|text| !text.trim().is_empty());
                    if !justified {
                        return Err(refusal(
                            IntegrityRefusalCode::SemanticEquivalenceWithoutJustification,
                            "semantic equivalence requires a recorded justification",
                        ));
                    }
                }
                _ => {}
            }
        }

        for entry in &self.refusals {
            if entry.detail.trim().is_empty() {
                return Err(IntegrityError::Invalid {
                    message: "recorded refusal must carry a detail".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Parse and validate a population manifest from bytes.
///
/// Rejects timestamp or modification-time selection fields anywhere in the
/// document, unknown fields, and every rule enforced by
/// [`PopulationManifest::validate`].
///
/// # Errors
///
/// Returns [`IntegrityError`] for invalid JSON, a forbidden selection field, an
/// unknown field, or a violated manifest rule.
pub fn parse_population_manifest(bytes: &[u8]) -> Result<PopulationManifest, IntegrityError> {
    let value = parse_strict(bytes)?;
    reject_selection_fields(&value)?;
    let manifest: PopulationManifest =
        serde_json::from_value(value).map_err(|error| IntegrityError::Invalid {
            message: error.to_string(),
        })?;
    manifest.validate()?;
    Ok(manifest)
}

fn reject_selection_fields(value: &serde_json::Value) -> Result<(), IntegrityError> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if FORBIDDEN_SELECTION_KEYS.contains(&key.as_str()) {
                    return Err(refusal(
                        IntegrityRefusalCode::ForbiddenSelectionField,
                        format!("population selection by {key} is forbidden"),
                    ));
                }
                reject_selection_fields(child)?;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                reject_selection_fields(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn check_schema(field: &str, actual: &str, expected: &str) -> Result<(), IntegrityError> {
    if actual == expected {
        Ok(())
    } else {
        Err(IntegrityError::SchemaMismatch {
            field: field.to_owned(),
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        })
    }
}

fn refusal(code: IntegrityRefusalCode, detail: impl Into<String>) -> IntegrityError {
    IntegrityError::Refused {
        code,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(id: &str) -> PopulationCase {
        PopulationCase {
            id: id.to_owned(),
            digest: format!("digest-{id}"),
            required: true,
        }
    }

    fn population(ids: &[&str]) -> PopulationManifest {
        let cases: Vec<PopulationCase> = ids.iter().map(|id| case(id)).collect();
        PopulationManifest::new(POPULATION_MANIFEST_SCHEMA, cases).expect("valid population")
    }

    fn artifact(binary: &str) -> ArtifactIdentity {
        ArtifactIdentity {
            binary_sha256: binary.to_owned(),
            ..ArtifactIdentity::default()
        }
    }

    fn report() -> IntegrityReport {
        IntegrityReport::new(artifact("aaa"), population(&["a", "b"]))
    }

    #[test]
    fn byte_identical_established_with_differing_digests_is_refused() {
        let mut report = report();
        report.rebuild_artifact = Some(artifact("bbb"));
        report.dimensions = vec![DimensionAssessment {
            dimension: ReproducibilityDimension::ByteIdenticalArtifact,
            status: DimensionStatus::Established,
            justification: None,
        }];
        assert!(matches!(
            report.validate(),
            Err(IntegrityError::Refused {
                code: IntegrityRefusalCode::ByteDigestMismatch,
                ..
            })
        ));
    }

    #[test]
    fn semantic_equivalence_requires_justification() {
        let mut report = report();
        report.dimensions = vec![DimensionAssessment {
            dimension: ReproducibilityDimension::SemanticallyEquivalentArtifact,
            status: DimensionStatus::Established,
            justification: None,
        }];
        assert!(matches!(
            report.validate(),
            Err(IntegrityError::Refused {
                code: IntegrityRefusalCode::SemanticEquivalenceWithoutJustification,
                ..
            })
        ));
        report.dimensions[0].justification = Some("documented ABI-compatible rebuild".to_owned());
        assert!(report.validate().is_ok());
    }

    #[test]
    fn semantic_equivalence_cannot_upgrade_byte_difference_into_byte_identity() {
        let mut report = report();
        report.rebuild_artifact = Some(artifact("bbb"));
        report.dimensions = vec![
            DimensionAssessment {
                dimension: ReproducibilityDimension::SemanticallyEquivalentArtifact,
                status: DimensionStatus::Established,
                justification: Some("documented ABI-compatible rebuild".to_owned()),
            },
            DimensionAssessment {
                dimension: ReproducibilityDimension::ByteIdenticalArtifact,
                status: DimensionStatus::Established,
                justification: None,
            },
        ];
        assert!(matches!(
            report.validate(),
            Err(IntegrityError::Refused {
                code: IntegrityRefusalCode::ByteDigestMismatch,
                ..
            })
        ));
    }

    #[test]
    fn not_run_is_never_established() {
        assert!(!DimensionStatus::NotRun.is_established());
        let mut report = report();
        report.dimensions = vec![DimensionAssessment {
            dimension: ReproducibilityDimension::ExperimentReplay,
            status: DimensionStatus::NotRun,
            justification: None,
        }];
        assert!(report.validate().is_ok());
        assert!(!report
            .established_dimensions()
            .contains(&ReproducibilityDimension::ExperimentReplay));
    }

    #[test]
    fn duplicate_population_case_is_refused() {
        let mut manifest = PopulationManifest {
            version: "v1".to_owned(),
            cases: vec![case("a"), case("a")],
            count: 2,
            manifest_digest: String::new(),
        };
        manifest.manifest_digest = manifest.compute_digest().expect("digest");
        assert!(matches!(
            manifest.validate(),
            Err(IntegrityError::Refused {
                code: IntegrityRefusalCode::DuplicatePopulationCase,
                ..
            })
        ));
    }

    #[test]
    fn unsorted_population_cases_are_refused() {
        let mut manifest = PopulationManifest {
            version: "v1".to_owned(),
            cases: vec![case("b"), case("a")],
            count: 2,
            manifest_digest: String::new(),
        };
        manifest.manifest_digest = manifest.compute_digest().expect("digest");
        assert!(matches!(
            manifest.validate(),
            Err(IntegrityError::Refused {
                code: IntegrityRefusalCode::UnsortedPopulation,
                ..
            })
        ));
    }

    #[test]
    fn population_count_mismatch_is_refused() {
        let mut manifest = PopulationManifest {
            version: "v1".to_owned(),
            cases: vec![case("a")],
            count: 2,
            manifest_digest: String::new(),
        };
        manifest.manifest_digest = manifest.compute_digest().expect("digest");
        assert!(matches!(
            manifest.validate(),
            Err(IntegrityError::Refused {
                code: IntegrityRefusalCode::PopulationCountMismatch,
                ..
            })
        ));
    }

    #[test]
    fn empty_population_is_refused() {
        let manifest = PopulationManifest {
            version: "v1".to_owned(),
            cases: Vec::new(),
            count: 0,
            manifest_digest: String::new(),
        };
        assert!(matches!(
            manifest.validate(),
            Err(IntegrityError::Refused {
                code: IntegrityRefusalCode::EmptyPopulation,
                ..
            })
        ));
    }

    #[test]
    fn missing_population_is_not_empty() {
        let mut report = report();
        report.population = None;
        assert!(matches!(
            report.validate(),
            Err(IntegrityError::Refused {
                code: IntegrityRefusalCode::MissingPopulation,
                ..
            })
        ));
        report.population = Some(PopulationManifest {
            version: "v1".to_owned(),
            cases: Vec::new(),
            count: 0,
            manifest_digest: String::new(),
        });
        assert!(matches!(
            report.validate(),
            Err(IntegrityError::Refused {
                code: IntegrityRefusalCode::EmptyPopulation,
                ..
            })
        ));
    }

    #[test]
    fn mtime_selection_field_is_rejected() {
        let json = br#"{"version":"v1","cases":[{"id":"a","digest":"d","required":true}],"count":1,"manifest_digest":"x","mtime":123}"#;
        assert!(matches!(
            parse_population_manifest(json),
            Err(IntegrityError::Refused {
                code: IntegrityRefusalCode::ForbiddenSelectionField,
                ..
            })
        ));
    }

    #[test]
    fn manifest_digest_is_deterministic() {
        let first = PopulationManifest::new("v1", vec![case("b"), case("a")]).expect("valid");
        let second = PopulationManifest::new("v1", vec![case("a"), case("b")]).expect("valid");
        assert_eq!(first.cases, second.cases);
        assert_eq!(first.manifest_digest, second.manifest_digest);
        assert!(first.validate().is_ok());
    }

    #[test]
    fn valid_report_passes() {
        let mut report = report();
        report.rebuild_artifact = Some(artifact("aaa"));
        report.dimensions = vec![DimensionAssessment {
            dimension: ReproducibilityDimension::ByteIdenticalArtifact,
            status: DimensionStatus::Established,
            justification: None,
        }];
        assert!(report.validate().is_ok());
    }
}
