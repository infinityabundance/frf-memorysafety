#![allow(clippy::module_name_repetitions)]

//! Phase 10.4a durable offline archive verification.
//!
//! The archive is a directory containing an exact object inventory, a knowledge
//! horizon, reconstruction instructions, and copies of the evidence needed to
//! reconstruct the finite Phase 9.1 and Phase 10 campaign records offline.
//!
//! Verification establishes only that every declared object is present, is not
//! a symlink, has the declared size and SHA-256, that no unlisted regular file
//! is present, that every required category is represented, and that the
//! declared reconstruction inputs are available. It does not establish that the
//! archived evidence is true, authentic, complete, or externally anchored.

#![allow(
    clippy::manual_let_else,
    clippy::single_match_else,
    clippy::too_many_lines
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::etp::ETP_SPEC;
use crate::identity::{hex_lower, parse_strict};

/// Archive manifest schema identifier.
pub const ARCHIVE_MANIFEST_SCHEMA: &str = "frf-etp.archive-manifest.v1";
/// Archive verification report schema identifier.
pub const ARCHIVE_REPORT_SCHEMA: &str = "frf-etp.archive-verification.v1";
/// Maximum declared objects.
pub const MAX_ARCHIVE_OBJECTS: usize = 8192;
/// Maximum declared object size.
pub const MAX_ARCHIVE_OBJECT_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum directory walk depth.
pub const MAX_ARCHIVE_DEPTH: usize = 32;
/// Claim ceiling carried by every report.
pub const ARCHIVE_CLAIM_CEILING: &str = "A verified archive establishes only that the declared objects are present, are regular files, have the declared sizes and SHA-256 digests, that no unlisted regular file is present, and that the declared reconstruction inputs and commands are available. It does not establish that the archived evidence is true, authentic, complete, externally anchored, or sufficient to reproduce a result without the declared container images and tools.";

/// One archived object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveObject {
    /// Path relative to the archive root.
    pub path: String,
    /// Exact SHA-256, lowercase hexadecimal.
    pub sha256: String,
    /// Exact size in bytes.
    pub size: u64,
    /// Object schema identifier or `opaque-bytes`.
    pub schema: String,
    /// Inventory category.
    pub category: String,
    /// Applicability note.
    pub applicability: String,
    /// Whether the object is required for the declared claim.
    pub required: bool,
    /// Observation time, seconds since the Unix epoch.
    pub observed_at_unix: u64,
}

/// One declared reconstruction command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconstructionCommand {
    /// Purpose.
    pub purpose: String,
    /// Working directory, relative to the repository or archive.
    pub working_directory: String,
    /// Exact argument vector.
    pub argv: Vec<String>,
    /// Object paths that must be present.
    pub requires: Vec<String>,
}

/// Reconstruction instructions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconstructionInstructions {
    /// Path to the human-readable reconstruction instructions.
    pub instructions: String,
    /// Exact commands.
    pub commands: Vec<ReconstructionCommand>,
    /// Object paths that are inputs to reconstruction.
    pub input_objects: Vec<String>,
}

/// Archive manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveManifest {
    /// Schema identifier.
    pub schema: String,
    /// ETP specification identifier.
    pub spec: String,
    /// Archive identifier.
    pub archive_id: String,
    /// Archive creation time.
    pub created_at_unix: u64,
    /// Latest observed knowledge time.
    pub knowledge_horizon_unix: u64,
    /// Exact object inventory.
    pub objects: Vec<ArchiveObject>,
    /// Categories that must be represented by a required object.
    pub required_categories: Vec<String>,
    /// Reconstruction instructions.
    pub reconstruction: ReconstructionInstructions,
    /// Features that are not implemented.
    pub unsupported_features: Vec<String>,
    /// Claim ceiling.
    pub claim_ceiling: String,
    /// Explicit non-claims.
    pub non_claims: Vec<String>,
}

/// One object problem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveObjectProblem {
    /// Declared path.
    pub path: String,
    /// `missing`, `symlink`, `not_a_file`, `size_mismatch`, `digest_mismatch`,
    /// `unlisted`, or `path_escape`.
    pub problem: String,
    /// Expected digest.
    pub expected_sha256: String,
    /// Observed digest, when available.
    pub actual_sha256: Option<String>,
    /// Expected size.
    pub expected_size: u64,
    /// Observed size, when available.
    pub actual_size: Option<u64>,
}

/// Reconstruction report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconstructionReport {
    /// Instructions path.
    pub instructions: String,
    /// Command count.
    pub command_count: usize,
    /// Input object count.
    pub input_count: usize,
    /// Whether all declared inputs and requirements are present.
    pub complete: bool,
    /// Missing inputs or requirements.
    pub missing_inputs: Vec<String>,
}

/// Overall archive status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveStatus {
    /// Every declared object and reconstruction input verified.
    Verified,
    /// The archive is structurally valid but incomplete for its declared use.
    Refused,
    /// A declared object is missing, corrupt, or unlisted.
    IntegrityFailure,
}

impl ArchiveStatus {
    /// Stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Refused => "refused",
            Self::IntegrityFailure => "integrity_failure",
        }
    }
}

/// One semantic refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveRefusal {
    /// Stable code.
    pub code: String,
    /// Detail.
    pub detail: String,
}

/// Archive verification report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveReport {
    /// Schema identifier.
    pub schema: String,
    /// ETP specification identifier.
    pub spec: String,
    /// Status.
    pub status: ArchiveStatus,
    /// Archive identifier.
    pub archive_id: String,
    /// Archive root path as supplied.
    pub archive_root: String,
    /// Declared object count.
    pub object_count: usize,
    /// Verified object count.
    pub verified_objects: usize,
    /// Knowledge horizon.
    pub knowledge_horizon_unix: u64,
    /// Required categories.
    pub required_categories: Vec<String>,
    /// Missing required categories.
    pub missing_required_categories: Vec<String>,
    /// Object problems.
    pub problems: Vec<ArchiveObjectProblem>,
    /// Unlisted regular files.
    pub unlisted_objects: Vec<String>,
    /// Reconstruction report.
    pub reconstruction: ReconstructionReport,
    /// Refusals.
    pub refusals: Vec<ArchiveRefusal>,
    /// Unsupported features.
    pub unsupported_features: Vec<String>,
    /// Non-claims.
    pub non_claims: Vec<String>,
    /// Claim ceiling.
    pub claim_ceiling: String,
}

impl ArchiveReport {
    /// `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self.status {
            ArchiveStatus::Verified => 0,
            ArchiveStatus::Refused => 4,
            ArchiveStatus::IntegrityFailure => 3,
        }
    }
}

/// Errors from archive verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveError {
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

impl ArchiveError {
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

impl fmt::Display for ArchiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { message } => write!(formatter, "archive I/O failure: {message}"),
            Self::Invalid { message } => write!(formatter, "archive integrity failure: {message}"),
            Self::Canonical { message } => write!(formatter, "archive encoding failure: {message}"),
            Self::Unsupported { message } => {
                write!(formatter, "archive operation unsupported: {message}")
            }
        }
    }
}

impl std::error::Error for ArchiveError {}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn check_text(label: &str, value: &str) -> Result<(), ArchiveError> {
    if value.trim().is_empty() {
        return Err(ArchiveError::Invalid {
            message: format!("{label} must not be empty"),
        });
    }
    Ok(())
}

fn relative_path(path: &str) -> Result<PathBuf, ArchiveError> {
    if path.is_empty() || path.contains('\\') {
        return Err(ArchiveError::Invalid {
            message: format!("archive path {path:?} is not a relative POSIX path"),
        });
    }
    let candidate = Path::new(path);
    let mut clean = PathBuf::new();
    for component in candidate.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ArchiveError::Invalid {
                    message: format!("archive path {path:?} escapes the archive root"),
                });
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(ArchiveError::Invalid {
            message: format!("archive path {path:?} is empty"),
        });
    }
    Ok(clean)
}

fn walk_files(root: &Path) -> Result<BTreeSet<String>, ArchiveError> {
    fn walk(
        root: &Path,
        directory: &Path,
        depth: usize,
        files: &mut BTreeSet<String>,
    ) -> Result<(), ArchiveError> {
        if depth > MAX_ARCHIVE_DEPTH {
            return Err(ArchiveError::Invalid {
                message: format!("archive depth exceeds {MAX_ARCHIVE_DEPTH}"),
            });
        }
        let entries = fs::read_dir(directory).map_err(|error| ArchiveError::Io {
            message: format!("cannot list {}: {error}", directory.display()),
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| ArchiveError::Io {
                message: format!("cannot read directory entry: {error}"),
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| ArchiveError::Io {
                message: format!("cannot stat {}: {error}", path.display()),
            })?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(ArchiveError::Invalid {
                    message: format!("archive contains a symlink: {}", path.display()),
                });
            }
            if file_type.is_dir() {
                walk(root, &path, depth + 1, files)?;
            } else if file_type.is_file() {
                let relative = path.strip_prefix(root).map_err(|_| ArchiveError::Invalid {
                    message: format!("cannot relativize {}", path.display()),
                })?;
                let text = relative.to_string_lossy().replace('\\', "/");
                files.insert(text);
            } else {
                return Err(ArchiveError::Invalid {
                    message: format!("archive contains a non-regular file: {}", path.display()),
                });
            }
        }
        Ok(())
    }

    let mut files = BTreeSet::new();
    walk(root, root, 0, &mut files)?;
    Ok(files)
}

/// Parse an archive manifest with strict JSON and structural checks.
///
/// # Errors
///
/// Returns [`ArchiveError::Invalid`] for malformed JSON, unknown fields, an
/// unsupported schema, an empty object list, a duplicate path, an invalid
/// digest, or a size above the declared limit.
pub fn parse_manifest(bytes: &[u8]) -> Result<ArchiveManifest, ArchiveError> {
    let value = parse_strict(bytes).map_err(|error| ArchiveError::Invalid {
        message: error.to_string(),
    })?;
    let manifest: ArchiveManifest =
        serde_json::from_value(value).map_err(|error| ArchiveError::Invalid {
            message: error.to_string(),
        })?;
    if manifest.schema != ARCHIVE_MANIFEST_SCHEMA {
        return Err(ArchiveError::Invalid {
            message: format!(
                "archive schema {:?} is not {ARCHIVE_MANIFEST_SCHEMA}",
                manifest.schema
            ),
        });
    }
    if manifest.spec != ETP_SPEC {
        return Err(ArchiveError::Invalid {
            message: format!("archive spec {:?} is not {ETP_SPEC}", manifest.spec),
        });
    }
    check_text("archive_id", &manifest.archive_id)?;
    check_text("claim_ceiling", &manifest.claim_ceiling)?;
    if manifest.objects.is_empty() {
        return Err(ArchiveError::Invalid {
            message: "archive has no objects".to_owned(),
        });
    }
    if manifest.objects.len() > MAX_ARCHIVE_OBJECTS {
        return Err(ArchiveError::Invalid {
            message: format!("archive exceeds {MAX_ARCHIVE_OBJECTS} objects"),
        });
    }
    if manifest.required_categories.is_empty() {
        return Err(ArchiveError::Invalid {
            message: "archive declares no required categories".to_owned(),
        });
    }
    let mut paths = BTreeSet::new();
    for object in &manifest.objects {
        let clean = relative_path(&object.path)?;
        let normalized = clean.to_string_lossy().replace('\\', "/");
        if normalized != object.path {
            return Err(ArchiveError::Invalid {
                message: format!("archive path {:?} is not normalized", object.path),
            });
        }
        if !paths.insert(normalized) {
            return Err(ArchiveError::Invalid {
                message: format!("duplicate archive path {:?}", object.path),
            });
        }
        if !is_sha256_hex(&object.sha256) {
            return Err(ArchiveError::Invalid {
                message: format!("object {:?} has a non-canonical SHA-256", object.path),
            });
        }
        if object.size > MAX_ARCHIVE_OBJECT_BYTES {
            return Err(ArchiveError::Invalid {
                message: format!(
                    "object {:?} exceeds {MAX_ARCHIVE_OBJECT_BYTES} bytes",
                    object.path
                ),
            });
        }
        check_text("object schema", &object.schema)?;
        check_text("object category", &object.category)?;
        check_text("object applicability", &object.applicability)?;
        if object.observed_at_unix > manifest.knowledge_horizon_unix {
            return Err(ArchiveError::Invalid {
                message: format!(
                    "object {:?} observed at {} exceeds knowledge horizon {}",
                    object.path, object.observed_at_unix, manifest.knowledge_horizon_unix
                ),
            });
        }
    }
    check_text("instructions path", &manifest.reconstruction.instructions)?;
    if manifest.reconstruction.commands.is_empty() {
        return Err(ArchiveError::Invalid {
            message: "archive declares no reconstruction commands".to_owned(),
        });
    }
    for command in &manifest.reconstruction.commands {
        check_text("reconstruction purpose", &command.purpose)?;
        check_text(
            "reconstruction working directory",
            &command.working_directory,
        )?;
        if command.argv.is_empty() {
            return Err(ArchiveError::Invalid {
                message: format!(
                    "reconstruction command {:?} has an empty argv",
                    command.purpose
                ),
            });
        }
    }
    Ok(manifest)
}

/// Verify an archive directory offline.
///
/// # Errors
///
/// Returns [`ArchiveError`] when the manifest is missing, malformed, or the
/// directory cannot be read. Missing, corrupt, or unlisted objects are reported
/// in the returned report with [`ArchiveStatus::IntegrityFailure`].
#[allow(clippy::too_many_lines)]
pub fn verify_archive(root: &Path) -> Result<ArchiveReport, ArchiveError> {
    let manifest_path = root.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path).map_err(|error| ArchiveError::Io {
        message: format!("cannot read {}: {error}", manifest_path.display()),
    })?;
    let manifest = parse_manifest(&manifest_bytes)?;
    let listed: BTreeSet<String> = manifest
        .objects
        .iter()
        .map(|object| object.path.clone())
        .collect();

    let mut problems = Vec::new();
    let mut verified_objects = 0_usize;
    let mut verified_paths = BTreeSet::new();
    for object in &manifest.objects {
        let relative = match relative_path(&object.path) {
            Ok(path) => path,
            Err(_) => {
                problems.push(ArchiveObjectProblem {
                    path: object.path.clone(),
                    problem: "path_escape".to_owned(),
                    expected_sha256: object.sha256.clone(),
                    actual_sha256: None,
                    expected_size: object.size,
                    actual_size: None,
                });
                continue;
            }
        };
        let path = root.join(&relative);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => {
                problems.push(ArchiveObjectProblem {
                    path: object.path.clone(),
                    problem: "missing".to_owned(),
                    expected_sha256: object.sha256.clone(),
                    actual_sha256: None,
                    expected_size: object.size,
                    actual_size: None,
                });
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            problems.push(ArchiveObjectProblem {
                path: object.path.clone(),
                problem: "symlink".to_owned(),
                expected_sha256: object.sha256.clone(),
                actual_sha256: None,
                expected_size: object.size,
                actual_size: None,
            });
            continue;
        }
        if !metadata.is_file() {
            problems.push(ArchiveObjectProblem {
                path: object.path.clone(),
                problem: "not_a_file".to_owned(),
                expected_sha256: object.sha256.clone(),
                actual_sha256: None,
                expected_size: object.size,
                actual_size: Some(metadata.len()),
            });
            continue;
        }
        if metadata.len() != object.size {
            problems.push(ArchiveObjectProblem {
                path: object.path.clone(),
                problem: "size_mismatch".to_owned(),
                expected_sha256: object.sha256.clone(),
                actual_sha256: None,
                expected_size: object.size,
                actual_size: Some(metadata.len()),
            });
            continue;
        }
        let bytes = fs::read(&path).map_err(|error| ArchiveError::Io {
            message: format!("cannot read {}: {error}", path.display()),
        })?;
        let digest = sha256_hex(&bytes);
        if digest != object.sha256 {
            problems.push(ArchiveObjectProblem {
                path: object.path.clone(),
                problem: "digest_mismatch".to_owned(),
                expected_sha256: object.sha256.clone(),
                actual_sha256: Some(digest),
                expected_size: object.size,
                actual_size: Some(metadata.len()),
            });
            continue;
        }
        verified_objects += 1;
        verified_paths.insert(object.path.clone());
    }

    let files = walk_files(root)?;
    let mut unlisted_objects = Vec::new();
    for file in &files {
        if file == "manifest.json" {
            continue;
        }
        if !listed.contains(file) {
            unlisted_objects.push(file.clone());
        }
    }
    for path in &listed {
        if !files.contains(path) {
            // Already recorded as a missing problem unless the path escaped.
            if !problems.iter().any(|problem| &problem.path == path) {
                problems.push(ArchiveObjectProblem {
                    path: path.clone(),
                    problem: "missing".to_owned(),
                    expected_sha256: String::new(),
                    actual_sha256: None,
                    expected_size: 0,
                    actual_size: None,
                });
            }
        }
    }
    problems.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.problem.cmp(&right.problem))
    });
    unlisted_objects.sort();

    let mut missing_required_categories = Vec::new();
    for category in &manifest.required_categories {
        let present = manifest.objects.iter().any(|object| {
            object.category == *category && object.required && verified_paths.contains(&object.path)
        });
        if !present {
            missing_required_categories.push(category.clone());
        }
    }

    let mut missing_inputs = Vec::new();
    for input in &manifest.reconstruction.input_objects {
        if !listed.contains(input) || !verified_paths.contains(input) {
            missing_inputs.push(input.clone());
        }
    }
    if !listed.contains(&manifest.reconstruction.instructions)
        || !verified_paths.contains(&manifest.reconstruction.instructions)
    {
        missing_inputs.push(manifest.reconstruction.instructions.clone());
    }
    for command in &manifest.reconstruction.commands {
        for requirement in &command.requires {
            if !listed.contains(requirement) || !verified_paths.contains(requirement) {
                missing_inputs.push(requirement.clone());
            }
        }
    }
    missing_inputs.sort();
    missing_inputs.dedup();
    let reconstruction = ReconstructionReport {
        instructions: manifest.reconstruction.instructions.clone(),
        command_count: manifest.reconstruction.commands.len(),
        input_count: manifest.reconstruction.input_objects.len(),
        complete: missing_inputs.is_empty(),
        missing_inputs,
    };

    let mut refusals = Vec::new();
    if !missing_required_categories.is_empty() {
        refusals.push(ArchiveRefusal {
            code: "missing_required_evidence".to_owned(),
            detail: format!(
                "required categories absent from verified objects: {}",
                missing_required_categories.join(", ")
            ),
        });
    }
    if !reconstruction.complete {
        refusals.push(ArchiveRefusal {
            code: "incomplete_reconstruction".to_owned(),
            detail: format!(
                "reconstruction inputs are absent: {}",
                reconstruction.missing_inputs.join(", ")
            ),
        });
    }

    let status = if !problems.is_empty() || !unlisted_objects.is_empty() {
        ArchiveStatus::IntegrityFailure
    } else if !refusals.is_empty() {
        ArchiveStatus::Refused
    } else {
        ArchiveStatus::Verified
    };

    Ok(ArchiveReport {
        schema: ARCHIVE_REPORT_SCHEMA.to_owned(),
        spec: ETP_SPEC.to_owned(),
        status,
        archive_id: manifest.archive_id,
        archive_root: root.display().to_string(),
        object_count: manifest.objects.len(),
        verified_objects,
        knowledge_horizon_unix: manifest.knowledge_horizon_unix,
        required_categories: manifest.required_categories,
        missing_required_categories,
        problems,
        unlisted_objects,
        reconstruction,
        refusals,
        unsupported_features: manifest.unsupported_features,
        non_claims: manifest.non_claims,
        claim_ceiling: manifest.claim_ceiling,
    })
}

/// Return a map of declared path to size for callers that build an archive.
///
/// This is a helper for the evidence builder. It performs no trust decision.
///
/// # Errors
///
/// Returns [`ArchiveError`] when the manifest cannot be parsed.
pub fn declared_sizes(manifest_bytes: &[u8]) -> Result<BTreeMap<String, u64>, ArchiveError> {
    let manifest = parse_manifest(manifest_bytes)?;
    Ok(manifest
        .objects
        .into_iter()
        .map(|object| (object.path, object.size))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_parent_traversal() {
        assert!(relative_path("../escape").is_err());
        assert!(relative_path("/absolute").is_err());
        assert!(relative_path("ok/path.json").is_ok());
    }

    #[test]
    fn rejects_non_canonical_digests() {
        assert!(!is_sha256_hex(&"A".repeat(64)));
        assert!(is_sha256_hex(&"a".repeat(64)));
    }
}
