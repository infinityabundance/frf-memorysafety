//! Typed conversion-court foundation for the Phase 8 OpenSSL-Rust programme.
//!
//! This module records *bookkeeping* facts about an unsafe-to-safe conversion
//! boundary: what kind of boundary it is, which C behaviour is admitted, where
//! the native witness came from, which loader closure was observed, which
//! fault/repaired revisions are identified, and which dependency versions the
//! evidence is bound to. It is deliberately fail-closed:
//!
//! * every externally supplied identity keeps its native textual form in a
//!   validated opaque newtype and is never rehashed into a local identity;
//! * a witness whose mechanism is not independently confirmed is rejected;
//! * a synthetic seeded defect can be recorded only as a synthetic fixture,
//!   never as an organic discovery;
//! * evidence is reusable only while the property, candidate, boundary,
//!   dependency closure, tool, loader closure, and revisions all remain the
//!   same.
//!
//! # Claim ceiling
//!
//! Passing these checks establishes no memory safety, no compatibility, and no
//! organic vulnerability discovery. It establishes only that a caller-supplied
//! conversion record is internally consistent under the rules in this module.
//! See [`CONVERSION_CLAIM_CEILING`].

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::{
    canonical_bytes, digest_value, hex_lower, IdentityDomain, IdentityError, MsId,
};

/// Schema identifier for a conversion-court record.
pub const CONVERSION_SPEC: &str = "frf-memorysafety.conversion-court.v1";

/// Claim ceiling embedded in documentation and reports.
pub const CONVERSION_CLAIM_CEILING: &str = "Records conversion-boundary bookkeeping only. It does not establish memory safety, functional or binary compatibility, proof acceptance, or an organic vulnerability discovery. A synthetic fixture is never an organic discovery, and a witness without an independently confirmed mechanism is rejected.";

/// Maximum length of an opaque external identity retained by this module.
pub const MAX_OPAQUE_ID_BYTES: usize = 256;

/// Environment variable naming a live conversion capture directory.
pub const CONVERSION_CAPTURE_ENV: &str = "FRF_CONVERSION_CAPTURE";

/// Environment variable that makes an unset live capture a test failure.
pub const CONVERSION_REQUIRE_LIVE_ENV: &str = "FRF_CONVERSION_REQUIRE_LIVE";

/// File name of the live capture specification inside its capture directory.
pub const CONVERSION_CAPTURE_SPEC_FILE: &str = "capture.json";

/// A validated 40-character lowercase Git commit identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct GitCommit(String);

impl GitCommit {
    /// Parse a full lowercase 40-hex Git commit.
    ///
    /// # Errors
    ///
    /// Returns [`ConversionError::InvalidGitCommit`] unless the input is exactly
    /// 40 lowercase hexadecimal characters.
    pub fn parse(value: &str) -> Result<Self, ConversionError> {
        if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ConversionError::InvalidGitCommit(value.to_owned()));
        }
        if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(ConversionError::InvalidGitCommit(value.to_owned()));
        }
        Ok(Self(value.to_owned()))
    }

    /// Borrow the original textual identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GitCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for GitCommit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// A validated lowercase SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Parse a lowercase 64-hex SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns [`ConversionError::InvalidSha256`] unless the input is exactly
    /// 64 lowercase hexadecimal characters.
    pub fn parse(value: &str) -> Result<Self, ConversionError> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ConversionError::InvalidSha256(value.to_owned()));
        }
        if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(ConversionError::InvalidSha256(value.to_owned()));
        }
        Ok(Self(value.to_owned()))
    }

    /// Compute the SHA-256 of bytes.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        Self(hex_lower(&digest))
    }

    /// Borrow the lowercase textual digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

fn validate_opaque(value: &str, field: &'static str) -> Result<(), ConversionError> {
    if value.trim().is_empty() {
        return Err(ConversionError::EmptyField(field));
    }
    if value.len() > MAX_OPAQUE_ID_BYTES {
        return Err(ConversionError::OpaqueIdTooLong(field));
    }
    Ok(())
}

/// An opaque boundary identity retained in its external textual form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct BoundaryId(String);

impl BoundaryId {
    /// Parse a non-empty opaque boundary identity.
    ///
    /// # Errors
    ///
    /// Returns [`ConversionError::EmptyField`] or
    /// [`ConversionError::OpaqueIdTooLong`] for an invalid identity.
    pub fn parse(value: &str) -> Result<Self, ConversionError> {
        validate_opaque(value, "boundary_id")?;
        Ok(Self(value.to_owned()))
    }

    /// Borrow the original textual identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BoundaryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for BoundaryId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// An opaque mechanism identity retained in its external textual form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct MechanismId(String);

impl MechanismId {
    /// Parse a non-empty opaque mechanism identity.
    ///
    /// # Errors
    ///
    /// Returns [`ConversionError::EmptyField`] or
    /// [`ConversionError::OpaqueIdTooLong`] for an invalid identity.
    pub fn parse(value: &str) -> Result<Self, ConversionError> {
        validate_opaque(value, "mechanism_id")?;
        Ok(Self(value.to_owned()))
    }

    /// Borrow the original textual identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MechanismId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for MechanismId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Kind of unsafe-to-safe conversion boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryKind {
    /// Ownership, reference count, adoption, or destructor boundary.
    Owner,
    /// Allocator hook, reallocation, or cleansed-release boundary.
    Allocator,
    /// Foreign or application callback boundary.
    Callback,
}

impl BoundaryKind {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Allocator => "allocator",
            Self::Callback => "callback",
        }
    }
}

impl fmt::Display for BoundaryKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// C behaviour that the boundary contract explicitly admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowedCBehavior {
    /// A zero-initialised object block is a valid destructor input.
    OwnerZeroValid,
    /// An over-free while storage is live is a defined no-op.
    OwnerOverFreeDefinedNoOp,
    /// `up_ref` refuses a retired or destroying object without resurrecting it.
    OwnerUpRefRefusesRetired,
    /// An allocator refusal leaves the previous owner intact.
    AllocatorRefusalContained,
    /// A failed reallocation preserves the original allocation.
    ReallocFailurePreservesOwner,
    /// A cleansed release covers the exact allocated length.
    CleansedFreeExactLength,
    /// Re-entry from an application destructor callback is a defined no-op.
    CallbackReentryDefinedNoOp,
    /// A refused callback operation leaves the object in a legal state.
    CallbackRefusalContained,
}

impl AllowedCBehavior {
    /// Boundary kind to which this behaviour belongs.
    #[must_use]
    pub const fn boundary_kind(self) -> BoundaryKind {
        match self {
            Self::OwnerZeroValid
            | Self::OwnerOverFreeDefinedNoOp
            | Self::OwnerUpRefRefusesRetired => BoundaryKind::Owner,
            Self::AllocatorRefusalContained
            | Self::ReallocFailurePreservesOwner
            | Self::CleansedFreeExactLength => BoundaryKind::Allocator,
            Self::CallbackReentryDefinedNoOp | Self::CallbackRefusalContained => {
                BoundaryKind::Callback
            }
        }
    }

    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerZeroValid => "owner_zero_valid",
            Self::OwnerOverFreeDefinedNoOp => "owner_over_free_defined_no_op",
            Self::OwnerUpRefRefusesRetired => "owner_up_ref_refuses_retired",
            Self::AllocatorRefusalContained => "allocator_refusal_contained",
            Self::ReallocFailurePreservesOwner => "realloc_failure_preserves_owner",
            Self::CleansedFreeExactLength => "cleansed_free_exact_length",
            Self::CallbackReentryDefinedNoOp => "callback_reentry_defined_no_op",
            Self::CallbackRefusalContained => "callback_refusal_contained",
        }
    }
}

impl fmt::Display for AllowedCBehavior {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The boundary and the set of C behaviours its contract admits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryScope {
    /// Opaque boundary identity supplied by the target project.
    pub boundary_id: BoundaryId,
    /// Kind of the boundary.
    pub kind: BoundaryKind,
    /// Explicitly admitted C behaviour. An empty set is rejected.
    pub allowed: BTreeSet<AllowedCBehavior>,
}

impl BoundaryScope {
    /// Validate that the allowed behaviour set is non-empty and kind-consistent.
    ///
    /// # Errors
    ///
    /// Returns [`ConversionError::EmptyAllowedBehavior`] or
    /// [`ConversionError::BoundaryKindMismatch`].
    pub fn validate(&self) -> Result<(), ConversionError> {
        if self.allowed.is_empty() {
            return Err(ConversionError::EmptyAllowedBehavior);
        }
        for behavior in &self.allowed {
            let expected = behavior.boundary_kind();
            if expected != self.kind {
                return Err(ConversionError::BoundaryKindMismatch {
                    behavior: *behavior,
                    expected,
                    actual: self.kind,
                });
            }
        }
        Ok(())
    }
}

/// Property that a conversion evidence record claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversionProperty {
    /// The owner/refcount/destructor contract holds for the boundary.
    OwnerContractEstablished,
    /// Allocator refusal or reallocation failure is contained.
    AllocatorFailureContained,
    /// Callback re-entry is rejected or contained.
    CallbackReentryRejected,
}

impl ConversionProperty {
    /// Boundary kind required by this property.
    #[must_use]
    pub const fn required_boundary_kind(self) -> BoundaryKind {
        match self {
            Self::OwnerContractEstablished => BoundaryKind::Owner,
            Self::AllocatorFailureContained => BoundaryKind::Allocator,
            Self::CallbackReentryRejected => BoundaryKind::Callback,
        }
    }

    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerContractEstablished => "owner_contract_established",
            Self::AllocatorFailureContained => "allocator_failure_contained",
            Self::CallbackReentryRejected => "callback_reentry_rejected",
        }
    }
}

impl fmt::Display for ConversionProperty {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Provenance of a native witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessOrigin {
    /// The witness was recorded from the authentic candidate executable.
    AuthenticNative,
    /// The witness was produced by a deliberately seeded synthetic defect.
    SyntheticSeeded,
    /// The witness was produced through a substituted FFI or provider.
    Substitute,
}

impl WitnessOrigin {
    /// Only an authentic native origin can support an organic discovery.
    #[must_use]
    pub const fn is_authentic(self) -> bool {
        matches!(self, Self::AuthenticNative)
    }

    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticNative => "authentic_native",
            Self::SyntheticSeeded => "synthetic_seeded",
            Self::Substitute => "substitute",
        }
    }
}

impl fmt::Display for WitnessOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Discovery claim attached to a witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryClaim {
    /// The defect was found organically in the candidate.
    OrganicDiscovery,
    /// The witness is an explicitly labelled synthetic fixture.
    SyntheticFixture,
    /// No discovery claim is made.
    NoDiscoveryClaim,
}

impl DiscoveryClaim {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OrganicDiscovery => "organic_discovery",
            Self::SyntheticFixture => "synthetic_fixture",
            Self::NoDiscoveryClaim => "no_discovery_claim",
        }
    }
}

impl fmt::Display for DiscoveryClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Exact tool identity used for a witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolIdentity {
    /// Tool name, for example `cargo test` or `readelf`.
    pub name: String,
    /// Tool version.
    pub version: String,
    /// SHA-256 of the executable bytes.
    pub executable_sha256: Sha256Digest,
}

impl ToolIdentity {
    /// Validate the name and version fields.
    ///
    /// # Errors
    ///
    /// Returns [`ConversionError::EmptyField`] for an empty name or version.
    pub fn validate(&self) -> Result<(), ConversionError> {
        if self.name.trim().is_empty() {
            return Err(ConversionError::EmptyField("tool.name"));
        }
        if self.version.trim().is_empty() {
            return Err(ConversionError::EmptyField("tool.version"));
        }
        Ok(())
    }
}

/// One loaded DSO in a loader closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsoIdentity {
    /// External SONAME or path identity, retained verbatim.
    pub soname: String,
    /// SHA-256 of the loaded bytes.
    pub sha256: Sha256Digest,
    /// Declared ELF symbol version nodes.
    pub symbol_versions: Vec<String>,
    /// Declared `DT_NEEDED` entries.
    pub dt_needed: Vec<String>,
}

impl DsoIdentity {
    /// Validate the DSO record.
    ///
    /// # Errors
    ///
    /// Returns [`ConversionError::EmptyField`] for an empty SONAME or version
    /// node, or [`ConversionError::DuplicateDso`] when a version node repeats.
    pub fn validate(&self) -> Result<(), ConversionError> {
        if self.soname.trim().is_empty() {
            return Err(ConversionError::EmptyField("dso.soname"));
        }
        let mut seen = BTreeSet::new();
        for version in &self.symbol_versions {
            if version.trim().is_empty() {
                return Err(ConversionError::EmptyField("dso.symbol_version"));
            }
            if !seen.insert(version) {
                return Err(ConversionError::DuplicateDso(version.clone()));
            }
        }
        Ok(())
    }
}

/// Observed loader closure for the candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoaderClosureEvidence {
    /// Loader inspection tool identity.
    pub loader: ToolIdentity,
    /// Loaded DSOs, including their exact bytes.
    pub loaded: Vec<DsoIdentity>,
    /// Whether every loaded DSO resolved under the candidate prefix.
    pub all_under_candidate_prefix: bool,
    /// Number of exported symbols resolved at declared versions.
    pub resolved_symbols: u64,
    /// Number of unresolved symbols.
    pub unresolved_symbols: u64,
    /// SHA-256 of the raw loader trace or map.
    pub trace_sha256: Sha256Digest,
}

impl LoaderClosureEvidence {
    /// Validate the loader closure.
    ///
    /// # Errors
    ///
    /// Returns [`ConversionError::LoaderNotClosed`] unless at least one DSO was
    /// observed, every DSO resolved under the candidate prefix, at least one
    /// symbol resolved, and no symbol remained unresolved.
    pub fn validate(&self) -> Result<(), ConversionError> {
        self.loader.validate()?;
        if self.loaded.is_empty() {
            return Err(ConversionError::LoaderNotClosed("no loaded DSO"));
        }
        if !self.all_under_candidate_prefix {
            return Err(ConversionError::LoaderNotClosed(
                "a loaded DSO is outside the candidate prefix",
            ));
        }
        if self.resolved_symbols == 0 {
            return Err(ConversionError::LoaderNotClosed("no resolved symbol"));
        }
        if self.unresolved_symbols != 0 {
            return Err(ConversionError::LoaderNotClosed("unresolved symbol"));
        }
        let mut sonames = BTreeSet::new();
        for dso in &self.loaded {
            dso.validate()?;
            if !sonames.insert(&dso.soname) {
                return Err(ConversionError::DuplicateDso(dso.soname.clone()));
            }
        }
        Ok(())
    }
}

/// Independently confirmed mechanism behind a witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MechanismEvidence {
    /// Opaque mechanism identity, for example `callback-reenter-k`.
    pub mechanism_id: MechanismId,
    /// Whether a separate process confirmed the mechanism.
    pub independently_confirmed: bool,
    /// SHA-256 of the independent confirmation artifact.
    pub confirmation_sha256: Sha256Digest,
}

impl MechanismEvidence {
    /// Validate that the mechanism was independently confirmed.
    ///
    /// # Errors
    ///
    /// Returns [`ConversionError::UnconfirmedMechanism`] when the confirmation
    /// flag is false. A witness without independent confirmation is rejected.
    pub fn validate(&self) -> Result<(), ConversionError> {
        if !self.independently_confirmed {
            return Err(ConversionError::UnconfirmedMechanism);
        }
        Ok(())
    }
}

/// Native witness provenance and mechanism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWitness {
    /// Authentic, synthetic, or substitute origin.
    pub origin: WitnessOrigin,
    /// Discovery claim attached to this witness.
    pub discovery: DiscoveryClaim,
    /// Tool identity used to produce the witness.
    pub tool: ToolIdentity,
    /// SHA-256 of the exact command line.
    pub command_sha256: Sha256Digest,
    /// SHA-256 of captured stdout/stderr.
    pub output_sha256: Sha256Digest,
    /// Independently confirmed mechanism.
    pub mechanism: MechanismEvidence,
    /// Observed loader closure.
    pub loader: LoaderClosureEvidence,
}

impl NativeWitness {
    /// Validate provenance, discovery, mechanism, and loader closure.
    ///
    /// # Errors
    ///
    /// Returns [`ConversionError::SyntheticWitnessClaimedOrganic`] or
    /// [`ConversionError::SubstituteWitnessClaimedOrganic`] when a
    /// non-authentic witness claims an organic discovery, and propagates
    /// mechanism and loader validation failures.
    pub fn validate(&self) -> Result<(), ConversionError> {
        self.tool.validate()?;
        self.mechanism.validate()?;
        self.loader.validate()?;
        if self.discovery == DiscoveryClaim::OrganicDiscovery {
            match self.origin {
                WitnessOrigin::SyntheticSeeded => {
                    return Err(ConversionError::SyntheticWitnessClaimedOrganic);
                }
                WitnessOrigin::Substitute => {
                    return Err(ConversionError::SubstituteWitnessClaimedOrganic);
                }
                WitnessOrigin::AuthenticNative => {}
            }
        }
        Ok(())
    }
}

/// Fault and repaired revision identity for one conversion repair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultRepairRevision {
    /// Revision before the repair, retained as the fault witness.
    pub fault: GitCommit,
    /// Revision carrying the repair.
    pub repaired: GitCommit,
    /// Paths changed by the repair. An empty set is rejected.
    pub changed_paths: BTreeSet<String>,
}

impl FaultRepairRevision {
    /// Validate that the pair identifies an actual change.
    ///
    /// # Errors
    ///
    /// Returns [`ConversionError::SameRevision`] when fault and repair are the
    /// same commit, or [`ConversionError::EmptyRevisionChange`] when no changed
    /// path is named.
    pub fn validate(&self) -> Result<(), ConversionError> {
        if self.fault == self.repaired {
            return Err(ConversionError::SameRevision);
        }
        if self.changed_paths.is_empty() {
            return Err(ConversionError::EmptyRevisionChange);
        }
        if self.changed_paths.iter().any(|path| path.trim().is_empty()) {
            return Err(ConversionError::EmptyField("changed_paths"));
        }
        Ok(())
    }
}

/// One dependency or tool version bound into evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyVersion {
    /// Dependency name.
    pub name: String,
    /// Dependency version or opaque revision.
    pub version: String,
    /// SHA-256 of the dependency artifact.
    pub sha256: Sha256Digest,
}

impl DependencyVersion {
    /// Validate the dependency record.
    ///
    /// # Errors
    ///
    /// Returns [`ConversionError::EmptyField`] for an empty name or version.
    pub fn validate(&self) -> Result<(), ConversionError> {
        if self.name.trim().is_empty() {
            return Err(ConversionError::EmptyField("dependency.name"));
        }
        if self.version.trim().is_empty() {
            return Err(ConversionError::EmptyField("dependency.version"));
        }
        Ok(())
    }
}

/// Dependency versions that bound one evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyClosure {
    /// Rust toolchain identity.
    pub toolchain: DependencyVersion,
    /// Dynamic loader identity.
    pub loader: DependencyVersion,
    /// External authority identity.
    pub authority: DependencyVersion,
    /// Additional libraries in the closure.
    pub libraries: Vec<DependencyVersion>,
}

impl DependencyClosure {
    fn all(&self) -> impl Iterator<Item = &DependencyVersion> {
        std::iter::once(&self.toolchain)
            .chain(std::iter::once(&self.loader))
            .chain(std::iter::once(&self.authority))
            .chain(self.libraries.iter())
    }

    /// Validate every dependency and reject duplicate names.
    ///
    /// # Errors
    ///
    /// Returns [`ConversionError::EmptyField`] for an empty field and
    /// [`ConversionError::DuplicateDependency`] for a repeated name.
    pub fn validate(&self) -> Result<(), ConversionError> {
        let mut names = BTreeSet::new();
        for dependency in self.all() {
            dependency.validate()?;
            if !names.insert(&dependency.name) {
                return Err(ConversionError::DuplicateDependency(
                    dependency.name.clone(),
                ));
            }
        }
        Ok(())
    }

    /// Domain-separated digest of the complete dependency closure.
    ///
    /// # Errors
    ///
    /// Returns [`ConversionError::Canonical`] if the closure cannot be encoded
    /// in canonical form.
    pub fn digest(&self) -> Result<Sha256Digest, ConversionError> {
        let value =
            serde_json::to_value(self).map_err(|error| ConversionError::Json(error.to_string()))?;
        let bytes = canonical_bytes(&value)?;
        let mut hasher = Sha256::new();
        hasher.update(b"frf-memorysafety/dependency-closure/v1");
        hasher.update([0u8]);
        hasher.update(&bytes);
        Ok(Sha256Digest(hex_lower(&hasher.finalize())))
    }
}

/// Candidate identity bound into evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateIdentity {
    /// Exact candidate Git commit.
    pub revision: GitCommit,
    /// SHA-256 of the candidate source snapshot.
    pub source_sha256: Sha256Digest,
    /// SHA-256 of the candidate artifact.
    pub artifact_sha256: Sha256Digest,
}

/// One conversion evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversionEvidence {
    /// Property the evidence claims.
    pub property: ConversionProperty,
    /// Candidate identity.
    pub candidate: CandidateIdentity,
    /// Boundary scope, including allowed C behaviour.
    pub boundary: BoundaryScope,
    /// Native witness provenance and mechanism.
    pub witness: NativeWitness,
    /// Fault and repaired revision identity.
    pub revisions: FaultRepairRevision,
    /// Dependency versions bound into the record.
    pub dependencies: DependencyClosure,
}

impl ConversionEvidence {
    /// Validate the entire evidence record.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ConversionError`] for a mismatched property/boundary,
    /// an unconfirmed mechanism, a synthetic organic claim, an open loader
    /// closure, an invalid revision pair, or invalid dependencies.
    pub fn validate(&self) -> Result<(), ConversionError> {
        self.boundary.validate()?;
        self.witness.validate()?;
        self.revisions.validate()?;
        self.dependencies.validate()?;
        let expected = self.property.required_boundary_kind();
        if expected != self.boundary.kind {
            return Err(ConversionError::PropertyKindMismatch {
                property: self.property,
                expected,
                actual: self.boundary.kind,
            });
        }
        Ok(())
    }

    /// Domain-separated local identity of this record.
    ///
    /// # Errors
    ///
    /// Returns [`ConversionError::Canonical`] if the record cannot be encoded.
    pub fn identity(&self) -> Result<MsId, ConversionError> {
        let value =
            serde_json::to_value(self).map_err(|error| ConversionError::Json(error.to_string()))?;
        Ok(digest_value(IdentityDomain::Court, &value)?)
    }
}

/// A request to reuse a prior evidence record for the current candidate state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRequest {
    /// Property to reuse.
    pub property: ConversionProperty,
    /// Current candidate identity.
    pub candidate: CandidateIdentity,
    /// Current boundary scope.
    pub boundary: BoundaryScope,
    /// Current witness provenance.
    pub origin: WitnessOrigin,
    /// Current discovery claim.
    pub discovery: DiscoveryClaim,
    /// SHA-256 of the current witness command line.
    pub witness_command_sha256: Sha256Digest,
    /// SHA-256 of the current witness output.
    pub witness_output_sha256: Sha256Digest,
    /// Current independently confirmed mechanism.
    pub mechanism: MechanismEvidence,
    /// Current tool identity.
    pub tool: ToolIdentity,
    /// Current loader closure.
    pub loader: LoaderClosureEvidence,
    /// Current fault/repaired revision identity.
    pub revisions: FaultRepairRevision,
    /// Current dependency closure.
    pub dependencies: DependencyClosure,
}

impl EvidenceRequest {
    /// Build a request from an existing evidence record.
    #[must_use]
    pub fn from_evidence(evidence: &ConversionEvidence) -> Self {
        Self {
            property: evidence.property,
            candidate: evidence.candidate.clone(),
            boundary: evidence.boundary.clone(),
            origin: evidence.witness.origin,
            discovery: evidence.witness.discovery,
            witness_command_sha256: evidence.witness.command_sha256.clone(),
            witness_output_sha256: evidence.witness.output_sha256.clone(),
            mechanism: evidence.witness.mechanism.clone(),
            tool: evidence.witness.tool.clone(),
            loader: evidence.witness.loader.clone(),
            revisions: evidence.revisions.clone(),
            dependencies: evidence.dependencies.clone(),
        }
    }

    /// Validate the request fields that are shared with a full evidence record.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ConversionError`] for an invalid boundary, tool,
    /// loader closure, revision pair, or dependency closure.
    pub fn validate(&self) -> Result<(), ConversionError> {
        self.boundary.validate()?;
        self.mechanism.validate()?;
        self.tool.validate()?;
        self.loader.validate()?;
        self.revisions.validate()?;
        self.dependencies.validate()?;
        let expected = self.property.required_boundary_kind();
        if expected != self.boundary.kind {
            return Err(ConversionError::PropertyKindMismatch {
                property: self.property,
                expected,
                actual: self.boundary.kind,
            });
        }
        Ok(())
    }
}

/// Reason a prior evidence record cannot be reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// The prior evidence record is itself invalid.
    PriorEvidenceInvalid,
    /// The current request is invalid.
    CurrentRequestInvalid,
    /// The claimed property changed.
    PropertyChanged,
    /// The property no longer matches the boundary kind.
    PropertyBoundaryMismatch,
    /// The candidate revision changed.
    CandidateRevisionChanged,
    /// The candidate source digest changed.
    CandidateSourceChanged,
    /// The candidate artifact digest changed.
    CandidateArtifactChanged,
    /// The boundary identity or allowed behaviour changed.
    BoundaryChanged,
    /// A dependency version changed.
    DependencyVersionChanged,
    /// The witness tool changed.
    ToolChanged,
    /// The loader closure changed.
    LoaderClosureChanged,
    /// The fault/repaired revision identity changed.
    RevisionChanged,
    /// The witness provenance or discovery claim changed.
    ProvenanceChanged,
    /// The witness command, output, or mechanism changed.
    WitnessChanged,
}

impl RevocationReason {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PriorEvidenceInvalid => "prior_evidence_invalid",
            Self::CurrentRequestInvalid => "current_request_invalid",
            Self::PropertyChanged => "property_changed",
            Self::PropertyBoundaryMismatch => "property_boundary_mismatch",
            Self::CandidateRevisionChanged => "candidate_revision_changed",
            Self::CandidateSourceChanged => "candidate_source_changed",
            Self::CandidateArtifactChanged => "candidate_artifact_changed",
            Self::BoundaryChanged => "boundary_changed",
            Self::DependencyVersionChanged => "dependency_version_changed",
            Self::ToolChanged => "tool_changed",
            Self::LoaderClosureChanged => "loader_closure_changed",
            Self::RevisionChanged => "revision_changed",
            Self::ProvenanceChanged => "provenance_changed",
            Self::WitnessChanged => "witness_changed",
        }
    }
}

impl fmt::Display for RevocationReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Outcome of a property-specific evidence-reuse request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReuseDecision {
    /// The prior evidence remains valid for the current state.
    Reusable,
    /// The prior evidence is revoked for the listed reasons.
    Revoked {
        /// Deterministically ordered revocation reasons.
        reasons: Vec<RevocationReason>,
    },
}

impl ReuseDecision {
    /// Whether the prior evidence is reusable.
    #[must_use]
    pub const fn is_reusable(&self) -> bool {
        matches!(self, Self::Reusable)
    }
}

/// Decide whether prior evidence may be reused for a current request.
///
/// Reuse is permitted only while the property, candidate, boundary, dependency
/// closure, tool identity, loader closure, and revision identity all remain the
/// same. Any change revokes the record. Invalid prior or current records fail
/// closed with an explicit revocation reason.
#[must_use]
pub fn reuse_evidence(prior: &ConversionEvidence, current: &EvidenceRequest) -> ReuseDecision {
    if prior.validate().is_err() {
        return ReuseDecision::Revoked {
            reasons: vec![RevocationReason::PriorEvidenceInvalid],
        };
    }
    if current.validate().is_err() {
        return ReuseDecision::Revoked {
            reasons: vec![RevocationReason::CurrentRequestInvalid],
        };
    }

    let mut reasons = Vec::new();
    if prior.property != current.property {
        reasons.push(RevocationReason::PropertyChanged);
    }
    if prior.candidate.revision != current.candidate.revision {
        reasons.push(RevocationReason::CandidateRevisionChanged);
    }
    if prior.candidate.source_sha256 != current.candidate.source_sha256 {
        reasons.push(RevocationReason::CandidateSourceChanged);
    }
    if prior.candidate.artifact_sha256 != current.candidate.artifact_sha256 {
        reasons.push(RevocationReason::CandidateArtifactChanged);
    }
    if prior.boundary != current.boundary {
        reasons.push(RevocationReason::BoundaryChanged);
    }
    if prior.witness.origin != current.origin || prior.witness.discovery != current.discovery {
        reasons.push(RevocationReason::ProvenanceChanged);
    }
    if prior.witness.command_sha256 != current.witness_command_sha256
        || prior.witness.output_sha256 != current.witness_output_sha256
        || prior.witness.mechanism != current.mechanism
    {
        reasons.push(RevocationReason::WitnessChanged);
    }
    if prior.dependencies != current.dependencies {
        reasons.push(RevocationReason::DependencyVersionChanged);
    }
    if prior.witness.tool != current.tool {
        reasons.push(RevocationReason::ToolChanged);
    }
    if prior.witness.loader != current.loader {
        reasons.push(RevocationReason::LoaderClosureChanged);
    }
    if prior.revisions != current.revisions {
        reasons.push(RevocationReason::RevisionChanged);
    }

    if reasons.is_empty() {
        ReuseDecision::Reusable
    } else {
        ReuseDecision::Revoked { reasons }
    }
}

/// A typed `NOT_RUN` for live conversion capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversionNotRun {
    /// Why no live capture was produced.
    pub reason: String,
}

impl ConversionNotRun {
    /// A `NOT_RUN` is never a pass or a refutation.
    #[must_use]
    pub const fn is_not_run(&self) -> bool {
        true
    }
}

/// Outcome of a live conversion capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversionCaptureOutcome {
    /// Evidence captured from the named files.
    Captured(ConversionEvidence),
    /// The capture environment was not available.
    NotRun(ConversionNotRun),
}

/// One DSO captured from a candidate prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureDso {
    /// External SONAME identity.
    pub soname: String,
    /// File holding the exact DSO bytes.
    pub path: PathBuf,
    /// Path the loader actually used. It must be under the candidate prefix.
    pub loaded_path: PathBuf,
    /// Declared ELF symbol version nodes.
    pub symbol_versions: Vec<String>,
    /// Declared `DT_NEEDED` entries.
    pub dt_needed: Vec<String>,
}

/// One dependency artifact captured for the dependency closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureDependency {
    /// Dependency name.
    pub name: String,
    /// Dependency version or opaque revision.
    pub version: String,
    /// File holding the exact dependency artifact bytes.
    pub path: PathBuf,
}

const fn default_capture_origin() -> WitnessOrigin {
    WitnessOrigin::AuthenticNative
}

const fn default_capture_discovery() -> DiscoveryClaim {
    DiscoveryClaim::NoDiscoveryClaim
}

/// A live conversion capture specification, read from `capture.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSpec {
    /// Property claimed by the captured evidence.
    pub property: ConversionProperty,
    /// Candidate Git revision.
    pub candidate_revision: GitCommit,
    /// File holding the canonical candidate source manifest.
    pub candidate_source_manifest: PathBuf,
    /// Opaque boundary identity.
    pub boundary_id: BoundaryId,
    /// Boundary kind.
    pub boundary_kind: BoundaryKind,
    /// C behaviour the boundary admits.
    pub allowed: BTreeSet<AllowedCBehavior>,
    /// Witness provenance. Live capture requires `authentic_native`.
    #[serde(default = "default_capture_origin")]
    pub origin: WitnessOrigin,
    /// Discovery claim.
    #[serde(default = "default_capture_discovery")]
    pub discovery: DiscoveryClaim,
    /// Witness tool name.
    pub tool_name: String,
    /// Witness tool version.
    pub tool_version: String,
    /// File holding the witness tool executable bytes.
    pub tool_executable: PathBuf,
    /// File holding the exact witness command line.
    pub command: PathBuf,
    /// File holding the captured witness output.
    pub output: PathBuf,
    /// Opaque mechanism identity.
    pub mechanism_id: MechanismId,
    /// Whether a separate process confirmed the mechanism.
    pub mechanism_confirmed: bool,
    /// File holding the independent mechanism confirmation.
    pub mechanism_confirmation: PathBuf,
    /// Loader tool name.
    pub loader_tool_name: String,
    /// Loader tool version.
    pub loader_tool_version: String,
    /// File holding the loader tool executable bytes.
    pub loader_executable: PathBuf,
    /// File holding the raw loader trace or map.
    pub loader_trace: PathBuf,
    /// Candidate install prefix every loaded DSO must resolve under.
    pub candidate_prefix: PathBuf,
    /// Symbols resolved at declared versions.
    pub resolved_symbols: u64,
    /// Unresolved symbols.
    pub unresolved_symbols: u64,
    /// Loaded DSO closure.
    pub dsos: Vec<CaptureDso>,
    /// Fault revision.
    pub fault: GitCommit,
    /// Repaired revision.
    pub repaired: GitCommit,
    /// Paths changed by the repair.
    pub changed_paths: BTreeSet<String>,
    /// Rust toolchain dependency.
    pub toolchain: CaptureDependency,
    /// Dynamic loader dependency.
    pub dynamic_loader: CaptureDependency,
    /// External authority dependency.
    pub authority: CaptureDependency,
    /// Additional libraries in the dependency closure.
    pub libraries: Vec<CaptureDependency>,
}

fn capture_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn read_capture(root: &Path, path: &Path, field: &'static str) -> Result<Vec<u8>, ConversionError> {
    let resolved = capture_path(root, path);
    fs::read(&resolved).map_err(|error| {
        ConversionError::CaptureIo(format!("{field} {}: {error}", resolved.display()))
    })
}

fn artifact_digest(parts: &[(String, Sha256Digest)]) -> Result<Sha256Digest, ConversionError> {
    let mut sorted = parts.to_vec();
    sorted.sort();
    let value =
        serde_json::to_value(&sorted).map_err(|error| ConversionError::Json(error.to_string()))?;
    let bytes = canonical_bytes(&value)?;
    let mut hasher = Sha256::new();
    hasher.update(b"frf-memorysafety/candidate-artifact/v1");
    hasher.update([0u8]);
    hasher.update(&bytes);
    Ok(Sha256Digest(hex_lower(&hasher.finalize())))
}

fn capture_dependency(
    root: &Path,
    dependency: &CaptureDependency,
) -> Result<DependencyVersion, ConversionError> {
    let bytes = read_capture(root, &dependency.path, "dependency")?;
    Ok(DependencyVersion {
        name: dependency.name.clone(),
        version: dependency.version.clone(),
        sha256: Sha256Digest::of_bytes(&bytes),
    })
}

impl CaptureSpec {
    /// Capture evidence from the exact files named by this specification.
    ///
    /// Digests are computed from the file bytes; no digest is accepted from the
    /// specification. The resulting record is validated before it is returned,
    /// so an open loader closure, an unconfirmed mechanism, a mismatched
    /// property, or an empty allowed-behaviour set fails closed.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ConversionError`] if a named file cannot be read, the
    /// candidate artifact closure is empty, or the assembled record is invalid.
    pub fn capture(&self, root: &Path) -> Result<ConversionEvidence, ConversionError> {
        let source = read_capture(root, &self.candidate_source_manifest, "candidate_source")?;
        let tool = read_capture(root, &self.tool_executable, "tool_executable")?;
        let command = read_capture(root, &self.command, "command")?;
        let output = read_capture(root, &self.output, "output")?;
        let confirmation =
            read_capture(root, &self.mechanism_confirmation, "mechanism_confirmation")?;
        let loader_tool = read_capture(root, &self.loader_executable, "loader_executable")?;
        let trace = read_capture(root, &self.loader_trace, "loader_trace")?;

        let mut loaded = Vec::new();
        let mut artifact_parts = Vec::new();
        let mut all_under_candidate_prefix = true;
        for dso in &self.dsos {
            let bytes = read_capture(root, &dso.path, "dso")?;
            let digest = Sha256Digest::of_bytes(&bytes);
            let resolved = capture_path(root, &dso.loaded_path);
            all_under_candidate_prefix &= resolved.starts_with(&self.candidate_prefix);
            artifact_parts.push((dso.soname.clone(), digest.clone()));
            loaded.push(DsoIdentity {
                soname: dso.soname.clone(),
                sha256: digest,
                symbol_versions: dso.symbol_versions.clone(),
                dt_needed: dso.dt_needed.clone(),
            });
        }
        if loaded.is_empty() {
            return Err(ConversionError::CaptureIo(
                "capture names no loaded DSO".to_owned(),
            ));
        }
        let artifact_sha256 = artifact_digest(&artifact_parts)?;

        let libraries = self
            .libraries
            .iter()
            .map(|dependency| capture_dependency(root, dependency))
            .collect::<Result<Vec<_>, _>>()?;

        let evidence = ConversionEvidence {
            property: self.property,
            candidate: CandidateIdentity {
                revision: self.candidate_revision.clone(),
                source_sha256: Sha256Digest::of_bytes(&source),
                artifact_sha256,
            },
            boundary: BoundaryScope {
                boundary_id: self.boundary_id.clone(),
                kind: self.boundary_kind,
                allowed: self.allowed.clone(),
            },
            witness: NativeWitness {
                origin: self.origin,
                discovery: self.discovery,
                tool: ToolIdentity {
                    name: self.tool_name.clone(),
                    version: self.tool_version.clone(),
                    executable_sha256: Sha256Digest::of_bytes(&tool),
                },
                command_sha256: Sha256Digest::of_bytes(&command),
                output_sha256: Sha256Digest::of_bytes(&output),
                mechanism: MechanismEvidence {
                    mechanism_id: self.mechanism_id.clone(),
                    independently_confirmed: self.mechanism_confirmed,
                    confirmation_sha256: Sha256Digest::of_bytes(&confirmation),
                },
                loader: LoaderClosureEvidence {
                    loader: ToolIdentity {
                        name: self.loader_tool_name.clone(),
                        version: self.loader_tool_version.clone(),
                        executable_sha256: Sha256Digest::of_bytes(&loader_tool),
                    },
                    loaded,
                    all_under_candidate_prefix,
                    resolved_symbols: self.resolved_symbols,
                    unresolved_symbols: self.unresolved_symbols,
                    trace_sha256: Sha256Digest::of_bytes(&trace),
                },
            },
            revisions: FaultRepairRevision {
                fault: self.fault.clone(),
                repaired: self.repaired.clone(),
                changed_paths: self.changed_paths.clone(),
            },
            dependencies: DependencyClosure {
                toolchain: capture_dependency(root, &self.toolchain)?,
                loader: capture_dependency(root, &self.dynamic_loader)?,
                authority: capture_dependency(root, &self.authority)?,
                libraries,
            },
        };
        evidence.validate()?;
        Ok(evidence)
    }
}

/// Capture live conversion evidence from a directory holding `capture.json`.
///
/// A missing specification is the typed [`ConversionCaptureOutcome::NotRun`]
/// path. A specification whose witness is not authentic native is refused: the
/// live path never relabels a synthetic or substitute witness.
///
/// # Errors
///
/// Returns a typed [`ConversionError`] if the specification is malformed, a
/// named file cannot be read, or the assembled record is invalid.
pub fn capture_live(root: &Path) -> Result<ConversionCaptureOutcome, ConversionError> {
    let spec_path = root.join(CONVERSION_CAPTURE_SPEC_FILE);
    if !spec_path.is_file() {
        return Ok(ConversionCaptureOutcome::NotRun(ConversionNotRun {
            reason: format!("{} is absent", spec_path.display()),
        }));
    }
    let bytes = fs::read(&spec_path)
        .map_err(|error| ConversionError::CaptureIo(format!("{}: {error}", spec_path.display())))?;
    let spec: CaptureSpec =
        serde_json::from_slice(&bytes).map_err(|error| ConversionError::Json(error.to_string()))?;
    if spec.origin != WitnessOrigin::AuthenticNative {
        return Err(ConversionError::CaptureRequiresAuthenticOrigin);
    }
    Ok(ConversionCaptureOutcome::Captured(spec.capture(root)?))
}

/// Capture live conversion evidence from [`CONVERSION_CAPTURE_ENV`].
///
/// # Errors
///
/// Returns a typed [`ConversionError`] when the configured directory or one of
/// its named files cannot be read, or when the assembled record is invalid.
pub fn capture_live_from_env() -> Result<ConversionCaptureOutcome, ConversionError> {
    match std::env::var_os(CONVERSION_CAPTURE_ENV) {
        Some(value) => {
            let root = PathBuf::from(value);
            capture_live(&root)
        }
        None => Ok(ConversionCaptureOutcome::NotRun(ConversionNotRun {
            reason: format!("{CONVERSION_CAPTURE_ENV} is not set"),
        })),
    }
}

/// Typed conversion-court error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConversionError {
    /// An opaque identity or required field was empty.
    #[error("required field is empty: {0}")]
    EmptyField(&'static str),
    /// An opaque identity exceeded the retained length bound.
    #[error("opaque identity is too long: {0}")]
    OpaqueIdTooLong(&'static str),
    /// A Git commit was not a full lowercase 40-hex identity.
    #[error("invalid Git commit identity: {0}")]
    InvalidGitCommit(String),
    /// A SHA-256 digest was not a lowercase 64-hex identity.
    #[error("invalid SHA-256 digest: {0}")]
    InvalidSha256(String),
    /// No allowed C behaviour was declared.
    #[error("a boundary must declare at least one allowed C behaviour")]
    EmptyAllowedBehavior,
    /// An allowed behaviour did not belong to the declared boundary kind.
    #[error("allowed C behaviour {behavior} belongs to {expected}, not {actual}")]
    BoundaryKindMismatch {
        /// The offending behaviour.
        behavior: AllowedCBehavior,
        /// Boundary kind required by the behaviour.
        expected: BoundaryKind,
        /// Boundary kind actually declared.
        actual: BoundaryKind,
    },
    /// The property did not belong to the declared boundary kind.
    #[error("property {property} requires {expected}, not {actual}")]
    PropertyKindMismatch {
        /// The claimed property.
        property: ConversionProperty,
        /// Boundary kind required by the property.
        expected: BoundaryKind,
        /// Boundary kind actually declared.
        actual: BoundaryKind,
    },
    /// A synthetic witness claimed an organic discovery.
    #[error("a synthetic seeded witness cannot claim an organic discovery")]
    SyntheticWitnessClaimedOrganic,
    /// A substitute witness claimed an organic discovery.
    #[error("a substitute witness cannot claim an organic discovery")]
    SubstituteWitnessClaimedOrganic,
    /// A witness had no independently confirmed mechanism.
    #[error("a witness requires an independently confirmed mechanism")]
    UnconfirmedMechanism,
    /// The loader closure was not closed.
    #[error("loader closure is not closed: {0}")]
    LoaderNotClosed(&'static str),
    /// A DSO or version node appeared twice.
    #[error("duplicate DSO or version identity: {0}")]
    DuplicateDso(String),
    /// A dependency name appeared twice.
    #[error("duplicate dependency identity: {0}")]
    DuplicateDependency(String),
    /// The fault and repaired revisions were the same commit.
    #[error("fault and repaired revisions must differ")]
    SameRevision,
    /// The revision pair named no changed path.
    #[error("a fault/repaired revision pair must name a changed path")]
    EmptyRevisionChange,
    /// A captured file could not be read.
    #[error("live capture failed: {0}")]
    CaptureIo(String),
    /// A live capture claimed a non-authentic origin.
    #[error("live capture requires an authentic native witness origin")]
    CaptureRequiresAuthenticOrigin,
    /// Canonical encoding failed.
    #[error("canonical encoding failed: {0}")]
    Canonical(#[from] IdentityError),
    /// JSON conversion failed.
    #[error("JSON conversion failed: {0}")]
    Json(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> Sha256Digest {
        Sha256Digest::parse(&std::iter::repeat(byte).take(64).collect::<String>()).unwrap()
    }

    fn commit(byte: char) -> GitCommit {
        GitCommit::parse(&std::iter::repeat(byte).take(40).collect::<String>()).unwrap()
    }

    #[test]
    fn opaque_identities_are_validated() {
        assert!(GitCommit::parse("short").is_err());
        assert!(GitCommit::parse(&"A".repeat(40)).is_err());
        assert!(Sha256Digest::parse(&"a".repeat(63)).is_err());
        assert!(BoundaryId::parse("").is_err());
        assert!(MechanismId::parse("   ").is_err());
        assert!(GitCommit::parse(&"a".repeat(40)).is_ok());
        assert!(Sha256Digest::parse(&"a".repeat(64)).is_ok());
        let _ = (digest('a'), commit('a'));
    }

    #[test]
    fn empty_allowed_behaviour_is_rejected() {
        let boundary = BoundaryScope {
            boundary_id: BoundaryId::parse("MS-SSL-SSL-0001").unwrap(),
            kind: BoundaryKind::Owner,
            allowed: BTreeSet::new(),
        };
        assert_eq!(
            boundary.validate(),
            Err(ConversionError::EmptyAllowedBehavior)
        );
    }

    #[test]
    fn mismatched_behaviour_and_property_are_rejected() {
        let boundary = BoundaryScope {
            boundary_id: BoundaryId::parse("MS-SSL-SSL-0001").unwrap(),
            kind: BoundaryKind::Owner,
            allowed: BTreeSet::from([AllowedCBehavior::CallbackReentryDefinedNoOp]),
        };
        assert!(matches!(
            boundary.validate(),
            Err(ConversionError::BoundaryKindMismatch { .. })
        ));
    }
}
