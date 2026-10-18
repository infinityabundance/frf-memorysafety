//! Phase 7.1: native-provider discovery, opaque external identities, and the
//! custody bridge.
//!
//! FRF, FRF-Fuzz, and Gemel remain the only producers of their identities.
//! This module never writes an `OpenReceipt`, a finding, a GCE object, or a GID.
//! It retains identities only after validating the exact external bytes
//! against a pinned provider contract. The identity types have private fields
//! and no public string constructor; the only producers are the crate-private
//! admission functions in this module.
//!
//! The custody pipeline is:
//!
//! ```text
//! discover -> reconstruct -> native_confirm -> frf_receipt -> gemel_custody
//! ```
//!
//! A stage that cannot execute returns a typed [`BridgeNotRun`]. A stage that
//! refuses modeled, modified, substitute, stale, or substituted-DSO evidence
//! returns a typed [`BridgeRefusal`]. Malformed or tampered evidence returns a
//! typed [`BridgeIntegrity`].
//!
//! Phase 7.2 adds [`capture_bundle`]: it executes the explicitly configured
//! provider executables, records exact bytes, executable and loader-map
//! hashes, and two independent runs, and derives identities from those bytes.
//! The record is still not authentication; digest checks bind bytes and
//! observed files, not a trusted origin.

#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema identifier for a bridge evidence bundle.
pub const BRIDGE_BUNDLE_SCHEMA: &str = "frf-memorysafety.bridge-bundle.v1";
/// Schema identifier for a bridge verification report.
pub const BRIDGE_REPORT_SCHEMA: &str = "frf-memorysafety.bridge-report.v1";
/// Schema identifier for a bridge provider-status report.
pub const BRIDGE_STATUS_SCHEMA: &str = "frf-memorysafety.bridge-status.v1";
/// Normative specification identifier.
pub const BRIDGE_SPEC: &str = "frf-memorysafety-spec-v1";
/// Maximum accepted external canonical object size.
pub const MAX_EXTERNAL_OBJECT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum accepted observation count in one bundle.
pub const MAX_OBSERVATIONS: usize = 16;
/// Maximum accepted bundle size.
pub const MAX_BUNDLE_BYTES: usize = crate::identity::MAX_BYTES;
/// Largest executable hashed for availability or live capture.
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

/// Honest ceiling for every result this module can produce.
pub const BRIDGE_CLAIM_CEILING: &str = "live capture executes configured provider executables and records exact bytes, executable digests, loader-map closures, and independent re-execution hashes; provenance remains an execution record, not a signature or trusted build root; no OpenReceipt, finding, GCE object, or GID is produced by this crate";

/// A native provider whose identity namespaces are kept separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalProvider {
    /// Forensic Residual Framework (court/OpenReceipt authority).
    Frf,
    /// FRF-Fuzz (BLAKE3 content identity authority).
    FrfFuzz,
    /// Gemel (GCE/GID authority).
    Gemel,
}

impl ExternalProvider {
    /// Stable textual name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Frf => "frf",
            Self::FrfFuzz => "frf-fuzz",
            Self::Gemel => "gemel",
        }
    }

    /// Environment variable naming a locally configured executable.
    #[must_use]
    pub const fn executable_env(self) -> &'static str {
        match self {
            Self::Frf => "FRF_BRIDGE_FRF_BIN",
            Self::FrfFuzz => "FRF_BRIDGE_FRF_FUZZ_BIN",
            Self::Gemel => "FRF_BRIDGE_GEMEL_BIN",
        }
    }

    /// Exact schema token accepted for this provider in Phase 7.1.
    #[must_use]
    pub const fn expected_schema(self) -> &'static str {
        match self {
            Self::Frf => "frf-receipt-v20",
            Self::FrfFuzz => "frf-fuzz.finding.v1",
            Self::Gemel => "gemel.gce.encver1.evidence.schemever1",
        }
    }
}

impl fmt::Display for ExternalProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Recorded build outcome for a pinned provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProviderBuild {
    /// The exact pinned source built in the hardened container.
    Built {
        /// SHA-256 of the observed executable.
        executable_sha256: &'static str,
    },
    /// The provider could not be built under the mandated limits.
    Blocked {
        /// Exact blocker.
        reason: &'static str,
    },
}

/// Exact contract for one discovered native provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderContract {
    /// Provider namespace.
    pub provider: ExternalProvider,
    /// Repository URL.
    pub repository: &'static str,
    /// Default branch at discovery time.
    pub default_branch: &'static str,
    /// License reported by the repository.
    pub license: &'static str,
    /// Exact pinned commit.
    pub commit: &'static str,
    /// Whether the repository was accessible.
    pub accessible: bool,
    /// Exact schema token retained by this bridge.
    pub schema: &'static str,
    /// Textual identity form.
    pub identity_form: &'static str,
    /// Recorded build outcome.
    pub build: ProviderBuild,
    /// Environment variable for a locally configured executable.
    pub executable_env: &'static str,
}

/// The three contracts discovered for Phase 7.1.
#[must_use]
pub fn native_provider_contracts() -> [ProviderContract; 3] {
    [
        ProviderContract {
            provider: ExternalProvider::Frf,
            repository: "https://github.com/infinityabundance/frf",
            default_branch: "main",
            license: "MIT OR Apache-2.0 (GitHub reports Apache-2.0)",
            commit: "ce461ce311bfe10fe90d2be03fba6217a6e8ba28",
            accessible: true,
            schema: ExternalProvider::Frf.expected_schema(),
            identity_form: "receipt-{run}-{64 lowercase hex}",
            build: ProviderBuild::Built {
                executable_sha256:
                    "0728aac10c4198717e04097201db55c2fbe3801e3917bc36160fc97da2a28f8b",
            },
            executable_env: ExternalProvider::Frf.executable_env(),
        },
        ProviderContract {
            provider: ExternalProvider::FrfFuzz,
            repository: "https://github.com/infinityabundance/frf-fuzz",
            default_branch: "master",
            license: "MIT OR Apache-2.0 (GitHub reports Apache-2.0)",
            commit: "054b45cda974852ccce62bc14dbeacb5fef0336b",
            accessible: true,
            schema: ExternalProvider::FrfFuzz.expected_schema(),
            identity_form: "64 lowercase hex (BLAKE3-256)",
            build: ProviderBuild::Built {
                executable_sha256:
                    "fa45c704d804146f069190e7d74b8f08e3e067a64c6253ae42c260fa2e700512",
            },
            executable_env: ExternalProvider::FrfFuzz.executable_env(),
        },
        ProviderContract {
            provider: ExternalProvider::Gemel,
            repository: "https://github.com/infinityabundance/gemel",
            default_branch: "main",
            license: "MIT OR Apache-2.0 (GitHub reports Apache-2.0)",
            commit: "54fc581bff09e67b9d4cc533d157a8c9fc575424",
            accessible: true,
            schema: ExternalProvider::Gemel.expected_schema(),
            identity_form: "{family}.{64 lowercase hex}",
            build: ProviderBuild::Built {
                executable_sha256:
                    "01b7f4cc2281a33dee3ecfe9a747845cef3a8b3c3a4c71078c3ecf8a29bf7696",
            },
            executable_env: ExternalProvider::Gemel.executable_env(),
        },
    ]
}

fn contract_for(provider: ExternalProvider) -> ProviderContract {
    native_provider_contracts()
        .into_iter()
        .find(|contract| contract.provider == provider)
        .expect("every provider has a contract")
}

/// Runtime availability of one provider (an installation observation, not a
/// capability or sensitivity claim).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderAvailability {
    /// Provider namespace.
    pub provider: ExternalProvider,
    /// Pinned repository.
    pub repository: &'static str,
    /// Pinned commit.
    pub commit: &'static str,
    /// Exact accepted schema.
    pub schema: &'static str,
    /// Whether the repository was accessible at discovery time.
    pub accessible: bool,
    /// Recorded build outcome.
    pub build: ProviderBuild,
    /// Environment variable naming an executable.
    pub executable_env: &'static str,
    /// Configured path, when the environment variable is set.
    pub configured_executable: Option<String>,
    /// Whether the configured executable matches the recorded build digest.
    pub executable_matches_recorded: bool,
    /// Whether this provider can be used for a live native confirmation.
    pub live_available: bool,
}

/// Observe provider availability without executing any provider.
#[must_use]
pub fn provider_availability() -> Vec<ProviderAvailability> {
    native_provider_contracts()
        .into_iter()
        .map(|contract| {
            let configured = std::env::var(contract.executable_env).ok();
            let recorded = match &contract.build {
                ProviderBuild::Built { executable_sha256 } => Some(*executable_sha256),
                ProviderBuild::Blocked { .. } => None,
            };
            let matches = configured.as_deref().is_some_and(|path| {
                recorded.is_some_and(|expected| {
                    sha256_file(Path::new(path)).as_deref() == Some(expected)
                })
            });
            ProviderAvailability {
                provider: contract.provider,
                repository: contract.repository,
                commit: contract.commit,
                schema: contract.schema,
                accessible: contract.accessible,
                build: contract.build,
                executable_env: contract.executable_env,
                configured_executable: configured,
                executable_matches_recorded: matches,
                live_available: contract.accessible && matches,
            }
        })
        .collect()
}

/// Status report for `bridge status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BridgeStatus {
    /// Status schema identifier.
    pub schema: &'static str,
    /// Normative specification identifier.
    pub spec: &'static str,
    /// Per-provider availability.
    pub providers: Vec<ProviderAvailability>,
    /// True only when every provider has a matching configured executable.
    pub all_live_available: bool,
    /// Claim ceiling.
    pub claim_ceiling: &'static str,
}

impl BridgeStatus {
    /// Build a status report from current process state.
    #[must_use]
    pub fn observe() -> Self {
        let providers = provider_availability();
        let all_live_available =
            !providers.is_empty() && providers.iter().all(|provider| provider.live_available);
        Self {
            schema: BRIDGE_STATUS_SCHEMA,
            spec: BRIDGE_SPEC,
            providers,
            all_live_available,
            claim_ceiling: BRIDGE_CLAIM_CEILING,
        }
    }

    /// SPEC §14 exit status: 0 only when all providers are live, else 6.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        if self.all_live_available {
            crate::cli::EXIT_OK
        } else {
            crate::cli::EXIT_NOT_RUN
        }
    }
}

// ---------------------------------------------------------------------------
// Opaque external identities
// ---------------------------------------------------------------------------

/// An FRF `OpenReceipt` identity retained verbatim.
///
/// The field is private and there is deliberately no public `parse`
/// constructor. Only [`verify_bundle_bytes`] can admit this type, and only
/// after checking the exact canonical bytes and SHA-256 suffix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrfReceiptId(String);

impl FrfReceiptId {
    /// The external textual identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn admit_shape(text: &str) -> Result<Self, String> {
        if !text.starts_with("receipt-run-") {
            return Err(format!("FRF receipt must begin 'receipt-run-': {text:?}"));
        }
        let Some((prefix, digest)) = text.rsplit_once('-') else {
            return Err(format!("FRF receipt has no digest suffix: {text:?}"));
        };
        if prefix.len() <= "receipt-".len() || !is_lower_hex(digest, 64) {
            return Err(format!(
                "FRF receipt must end in 64 lowercase hex digits: {text:?}"
            ));
        }
        Ok(Self(text.to_owned()))
    }
}

/// An FRF-Fuzz finding content identity retained verbatim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrfFuzzFindingId(String);

impl FrfFuzzFindingId {
    /// The external textual identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn admit_shape(text: &str) -> Result<Self, String> {
        if is_lower_hex(text, 64) {
            Ok(Self(text.to_owned()))
        } else {
            Err(format!(
                "FRF-Fuzz finding id must be 64 lowercase hex digits: {text:?}"
            ))
        }
    }
}

/// A Gemel GCE/GID identity retained verbatim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GemelGceId {
    text: String,
    family: String,
    kind: String,
    subject: Option<String>,
    outcome: Option<String>,
}

impl GemelGceId {
    /// The external textual identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The GCE family short name (for example `evidence`).
    #[must_use]
    pub fn family(&self) -> &str {
        &self.family
    }

    /// The evidence kind decoded from the GCE body.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The evidence subject decoded from the GCE body (field 0x03).
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// The evidence result outcome decoded from the GCE body (field 0x0D).
    #[must_use]
    pub fn outcome(&self) -> Option<&str> {
        self.outcome.as_deref()
    }

    fn admit_shape(text: &str) -> Result<(String, String), String> {
        let Some((family, digest)) = text.rsplit_once('.') else {
            return Err(format!("Gemel GID has no family separator: {text:?}"));
        };
        if !valid_family(family) || !is_lower_hex(digest, 64) {
            return Err(format!(
                "Gemel GID must be '<family>.<64 lowercase hex>': {text:?}"
            ));
        }
        Ok((family.to_owned(), digest.to_owned()))
    }
}

/// One admitted identity, kept provider-typed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AdmittedIdentity {
    Frf(FrfReceiptId),
    FrfFuzz(FrfFuzzFindingId),
    Gemel(GemelGceId),
}

impl AdmittedIdentity {
    fn text(&self) -> &str {
        match self {
            Self::Frf(id) => id.as_str(),
            Self::FrfFuzz(id) => id.as_str(),
            Self::Gemel(id) => id.as_str(),
        }
    }
}

// ---------------------------------------------------------------------------
// Bundle schema
// ---------------------------------------------------------------------------

/// Declared provenance of an external observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProvenance {
    /// Executed by the exact pinned native provider.
    AuthenticNative,
    /// A modified provider or harness produced the document.
    ModifiedProvider,
    /// A substitute provider produced the document.
    Substitute,
    /// A local model produced the document; never native execution.
    Modeled,
}

impl EvidenceProvenance {
    /// Stable textual label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticNative => "authentic_native",
            Self::ModifiedProvider => "modified_provider",
            Self::Substitute => "substitute",
            Self::Modeled => "modeled",
        }
    }
}

/// How the external executable's dynamic dependencies were bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DsoBinding {
    /// The recorded executable and its resolved dependency objects were pinned.
    Native,
    /// A dependency object was substituted.
    Substituted,
    /// No dependency closure was observed.
    Unknown,
}

/// Independent re-execution outcome for one observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reexecution {
    /// The independent run reproduced the recorded observation.
    Matched,
    /// The independent run disagreed with the recorded observation.
    Mismatch {
        /// Exact disagreement.
        detail: String,
    },
    /// No independent run was performed.
    NotRun {
        /// Exact reason.
        reason: String,
    },
}

/// One externally produced observation carried by a bridge bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalObservation {
    /// Provider namespace.
    pub provider: ExternalProvider,
    /// Declared provenance.
    pub provenance: EvidenceProvenance,
    /// Exact provider repository.
    pub repository: String,
    /// Exact provider commit.
    pub commit: String,
    /// Exact schema token.
    pub schema: String,
    /// External identity text (retained verbatim after validation).
    pub identity: String,
    /// For Gemel custody: the FRF receipt this evidence is about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_identity: Option<String>,
    /// Exact external canonical bytes, lowercase hex.
    ///
    /// FRF: canonical `OpenReceipt` JSON. FRF-Fuzz: the full `FRFZ` framed
    /// finding object. Gemel: the full `GEML` GCE envelope.
    pub canonical_bytes_hex: String,
    /// SHA-256 of the exact candidate artifact the observation binds.
    pub candidate_sha256: String,
    /// SHA-256 of the provider executable used for the observation.
    pub executable_sha256: String,
    /// Dynamic-dependency binding.
    pub dso_binding: DsoBinding,
    /// Independent re-execution outcome.
    pub reexecution: Reexecution,
    /// Live-capture record. Required for `authentic_native`; absent on
    /// modeled, modified, or substitute evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<ObservationCapture>,
}

/// One file-backed object observed in a process's loader map.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsoObject {
    /// Absolute path from `/proc/<pid>/maps`.
    pub path: String,
    /// SHA-256 recomputed from the file at capture time.
    pub sha256: String,
}

/// One captured execution's stable outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRecord {
    /// Process exit status, or `128 + signal` when terminated by a signal.
    pub exit: i32,
    /// SHA-256 of stdout.
    pub stdout_sha256: String,
    /// SHA-256 of stderr.
    pub stderr_sha256: String,
}

/// Two or more independent executions of the same executable input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReexecutionRecord {
    /// SHA-256 of the exact input bytes or argument identity.
    pub input_sha256: String,
    /// The captured runs, in execution order.
    pub runs: Vec<RunRecord>,
    /// True only when every run has identical exit, stdout, and stderr.
    pub byte_identical: bool,
}

/// Live-capture evidence for one observation: the executable file that was
/// hashed, the actual loader-map closure with recomputed hashes, and the
/// independent re-execution record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationCapture {
    /// Absolute path of the provider executable that was hashed.
    pub executable_path: String,
    /// File-backed objects from the provider's actual loader map, sorted by
    /// path. Capture-probe objects are excluded.
    pub dso_closure: Vec<DsoObject>,
    /// SHA-256 over the sorted `path\0sha256\n` closure lines.
    pub closure_sha256: String,
    /// Independent re-execution record.
    pub reexecution: ReexecutionRecord,
}

/// A bridge evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundle {
    /// Bundle schema identifier.
    pub schema: String,
    /// Normative specification identifier.
    pub spec: String,
    /// The candidate artifact every observation must bind.
    pub expected_candidate_sha256: String,
    /// External observations.
    pub observations: Vec<ExternalObservation>,
}

// ---------------------------------------------------------------------------
// Custody states and outcomes
// ---------------------------------------------------------------------------

/// Custody pipeline stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyStage {
    /// External providers and a discovery record were found.
    Discover,
    /// External bytes, identities, schemas, and candidate binding validated.
    Reconstruct,
    /// Native provenance, DSO binding, executable pin, and re-execution checked.
    NativeConfirm,
    /// An authentic FRF receipt was retained.
    FrfReceipt,
    /// Gemel custody was bound to the FRF receipt.
    GemelCustody,
}

impl CustodyStage {
    /// Stable textual label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::Reconstruct => "reconstruct",
            Self::NativeConfirm => "native_confirm",
            Self::FrfReceipt => "frf_receipt",
            Self::GemelCustody => "gemel_custody",
        }
    }
}

/// A fail-closed refusal: the evidence exists but cannot support custody.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BridgeRefusal {
    /// Modeled evidence was presented for native confirmation.
    ModeledEvidence {
        /// Provider.
        provider: ExternalProvider,
    },
    /// Modified-provider evidence was presented.
    ModifiedProvider {
        /// Provider.
        provider: ExternalProvider,
    },
    /// Substitute evidence was presented.
    SubstituteProvider {
        /// Provider.
        provider: ExternalProvider,
    },
    /// An observation binds a different candidate than the claim.
    StaleCandidate {
        /// Expected candidate digest.
        expected: String,
        /// Observed candidate digest.
        actual: String,
    },
    /// The executable's dependency object was substituted.
    SubstitutedDso {
        /// Provider.
        provider: ExternalProvider,
    },
    /// Gemel evidence is not bound to the retained FRF receipt.
    UnboundCustody {
        /// Exact mismatch.
        detail: String,
    },
    /// A required provider observation is absent.
    MissingObservation {
        /// Provider.
        provider: ExternalProvider,
    },
}

/// An evidence integrity failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BridgeIntegrity {
    /// Bundle schema mismatch.
    BundleSchema {
        /// Expected schema.
        expected: String,
        /// Observed schema.
        actual: String,
    },
    /// Bundle specification mismatch.
    BundleSpec {
        /// Expected specification.
        expected: String,
        /// Observed specification.
        actual: String,
    },
    /// Bundle cannot be parsed under the strict profile.
    MalformedBundle {
        /// Exact reason.
        detail: String,
    },
    /// Observation count is outside bounds.
    ObservationCount {
        /// Observed count.
        actual: usize,
        /// Limit.
        limit: usize,
    },
    /// An observation omits its schema token.
    MissingSchema {
        /// Provider.
        provider: ExternalProvider,
    },
    /// An observation carries the wrong schema token.
    SchemaMismatch {
        /// Provider.
        provider: ExternalProvider,
        /// Expected token.
        expected: String,
        /// Observed token.
        actual: String,
    },
    /// An observation carries the wrong repository or commit.
    ProviderPinMismatch {
        /// Provider.
        provider: ExternalProvider,
        /// Expected pin.
        expected: String,
        /// Observed pin.
        actual: String,
    },
    /// The identity text is not the provider's external form.
    IdentityShape {
        /// Provider.
        provider: ExternalProvider,
        /// Exact reason.
        detail: String,
    },
    /// The external digest does not match the canonical bytes.
    DigestMismatch {
        /// Provider.
        provider: ExternalProvider,
        /// Exact reason.
        detail: String,
    },
    /// The external object is malformed or internally inconsistent.
    TamperedObject {
        /// Provider.
        provider: ExternalProvider,
        /// Exact reason.
        detail: String,
    },
    /// The object binds a different candidate than the observation declares.
    CandidateBindingMismatch {
        /// Provider.
        provider: ExternalProvider,
        /// Declared candidate.
        expected: String,
        /// Candidate read from the external object.
        actual: String,
    },
    /// The executable is not the exact recorded build.
    UnpinnedExecutable {
        /// Provider.
        provider: ExternalProvider,
        /// Recorded digest.
        expected: String,
        /// Observed digest.
        actual: String,
    },
    /// Independent re-execution disagreed.
    ReexecutionMismatch {
        /// Provider.
        provider: ExternalProvider,
        /// Exact disagreement.
        detail: String,
    },
    /// An `authentic_native` observation carries no live-capture record.
    MissingLiveCapture {
        /// Provider.
        provider: ExternalProvider,
    },
    /// The recorded loader closure does not rederive from the files or its
    /// digest, or the declared binding disagrees with the observed closure.
    DsoClosureMismatch {
        /// Provider.
        provider: ExternalProvider,
        /// Exact mismatch.
        detail: String,
    },
    /// The FRF-Fuzz finding input is not the FRF receipt's fixture, or the
    /// Gemel evidence does not bind the retained receipt.
    ChainMismatch {
        /// Exact mismatch.
        detail: String,
    },
    /// A candidate digest is not a SHA-256 value.
    InvalidCandidateDigest {
        /// Observed value.
        actual: String,
    },
    /// Canonical bytes are not valid lowercase hex or exceed bounds.
    InvalidCanonicalBytes {
        /// Provider.
        provider: ExternalProvider,
        /// Exact reason.
        detail: String,
    },
}

/// A typed `NOT_RUN`: the capability was unavailable, not refuted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BridgeNotRun {
    /// The provider cannot be used in this environment.
    ProviderUnavailable {
        /// Provider.
        provider: ExternalProvider,
        /// Exact reason.
        reason: String,
    },
    /// No FRF-Fuzz discovery record is present.
    MissingFinding,
    /// No authentic FRF receipt is present.
    MissingFrfReceipt,
    /// No Gemel custody record is present.
    MissingGemelCustody,
    /// No independent re-execution was performed.
    ReexecutionNotRun {
        /// Provider.
        provider: ExternalProvider,
        /// Exact reason.
        reason: String,
    },
    /// No authentic native confirmation was available.
    NativeConfirmationNotRun {
        /// Exact reason.
        reason: String,
    },
}

/// Final decision for a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BridgeOutcome {
    /// Every custody stage completed.
    Complete,
    /// Evidence was refused.
    Refused {
        /// Typed reason.
        reason: BridgeRefusal,
    },
    /// Evidence integrity failed.
    Integrity {
        /// Typed reason.
        reason: BridgeIntegrity,
    },
    /// A required capability was not run.
    NotRun {
        /// Typed reason.
        reason: BridgeNotRun,
    },
}

impl BridgeOutcome {
    /// Stable textual label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Refused { .. } => "refused",
            Self::Integrity { .. } => "integrity",
            Self::NotRun { .. } => "not_run",
        }
    }

    /// SPEC §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Complete => crate::cli::EXIT_OK,
            Self::Refused { .. } => crate::cli::EXIT_REFUSED,
            Self::Integrity { .. } => crate::cli::EXIT_INTEGRITY,
            Self::NotRun { .. } => crate::cli::EXIT_NOT_RUN,
        }
    }
}

/// A verified observation summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservationSummary {
    /// Provider.
    pub provider: ExternalProvider,
    /// Declared provenance.
    pub provenance: EvidenceProvenance,
    /// Exact schema.
    pub schema: String,
    /// External identity retained verbatim.
    pub identity: String,
    /// Whether the external digest was verified.
    pub digest_verified: bool,
    /// Whether the observation is declared authentic native.
    pub authentic_native: bool,
    /// Candidate digest.
    pub candidate_sha256: String,
}

/// Verification report for one bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BridgeReport {
    /// Report schema.
    pub schema: &'static str,
    /// Normative specification.
    pub spec: &'static str,
    /// Furthest reached custody stage.
    pub stage: CustodyStage,
    /// Final decision.
    pub outcome: BridgeOutcome,
    /// Verified observations.
    pub observations: Vec<ObservationSummary>,
    /// Number of identities produced by this crate (always zero).
    pub generated_identities: usize,
    /// Number of retained identities declared authentic native. Zero unless
    /// the chain completed.
    pub authentic_native_identities: usize,
    /// Claim ceiling.
    pub claim_ceiling: &'static str,
}

impl BridgeReport {
    fn new() -> Self {
        Self {
            schema: BRIDGE_REPORT_SCHEMA,
            spec: BRIDGE_SPEC,
            stage: CustodyStage::Discover,
            outcome: BridgeOutcome::NotRun {
                reason: BridgeNotRun::MissingFinding,
            },
            observations: Vec::new(),
            generated_identities: 0,
            authentic_native_identities: 0,
            claim_ceiling: BRIDGE_CLAIM_CEILING,
        }
    }

    fn finish(mut self, stage: CustodyStage, outcome: BridgeOutcome) -> Self {
        // A failed chain issues no authentic identity: the count is diagnostic
        // only on a complete custody path.
        if !matches!(&outcome, BridgeOutcome::Complete) {
            self.authentic_native_identities = 0;
        }
        self.stage = stage;
        self.outcome = outcome;
        self
    }

    /// SPEC §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        self.outcome.exit_code()
    }
}

/// Verify a bridge evidence bundle.
///
/// `expected_candidate` optionally adds an external expectation for the
/// candidate digest. The bundle's own `expected_candidate_sha256` is always
/// checked against every observation.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn verify_bundle_bytes(bytes: &[u8], expected_candidate: Option<&str>) -> BridgeReport {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return BridgeReport::new().finish(
            CustodyStage::Discover,
            BridgeOutcome::Integrity {
                reason: BridgeIntegrity::MalformedBundle {
                    detail: format!(
                        "bundle is {} bytes; limit is {MAX_BUNDLE_BYTES}",
                        bytes.len()
                    ),
                },
            },
        );
    }
    let value = match crate::identity::parse_strict(bytes) {
        Ok(value) => value,
        Err(error) => {
            return BridgeReport::new().finish(
                CustodyStage::Discover,
                BridgeOutcome::Integrity {
                    reason: BridgeIntegrity::MalformedBundle {
                        detail: error.to_string(),
                    },
                },
            );
        }
    };
    let bundle: EvidenceBundle = match serde_json::from_value(value) {
        Ok(bundle) => bundle,
        Err(error) => {
            return BridgeReport::new().finish(
                CustodyStage::Discover,
                BridgeOutcome::Integrity {
                    reason: BridgeIntegrity::MalformedBundle {
                        detail: error.to_string(),
                    },
                },
            );
        }
    };
    verify_bundle(&bundle, expected_candidate)
}

#[allow(clippy::too_many_lines)]
fn verify_bundle(bundle: &EvidenceBundle, expected_candidate: Option<&str>) -> BridgeReport {
    let mut report = BridgeReport::new();

    // discover -------------------------------------------------------------
    if bundle.schema != BRIDGE_BUNDLE_SCHEMA {
        return report.finish(
            CustodyStage::Discover,
            BridgeOutcome::Integrity {
                reason: BridgeIntegrity::BundleSchema {
                    expected: BRIDGE_BUNDLE_SCHEMA.to_owned(),
                    actual: bundle.schema.clone(),
                },
            },
        );
    }
    if bundle.spec != BRIDGE_SPEC {
        return report.finish(
            CustodyStage::Discover,
            BridgeOutcome::Integrity {
                reason: BridgeIntegrity::BundleSpec {
                    expected: BRIDGE_SPEC.to_owned(),
                    actual: bundle.spec.clone(),
                },
            },
        );
    }
    if bundle.observations.len() > MAX_OBSERVATIONS {
        return report.finish(
            CustodyStage::Discover,
            BridgeOutcome::Integrity {
                reason: BridgeIntegrity::ObservationCount {
                    actual: bundle.observations.len(),
                    limit: MAX_OBSERVATIONS,
                },
            },
        );
    }
    if !is_sha256(&bundle.expected_candidate_sha256) {
        return report.finish(
            CustodyStage::Discover,
            BridgeOutcome::Integrity {
                reason: BridgeIntegrity::InvalidCandidateDigest {
                    actual: bundle.expected_candidate_sha256.clone(),
                },
            },
        );
    }
    if let Some(expected) = expected_candidate {
        if expected != bundle.expected_candidate_sha256 {
            return report.finish(
                CustodyStage::Discover,
                BridgeOutcome::Refused {
                    reason: BridgeRefusal::StaleCandidate {
                        expected: expected.to_owned(),
                        actual: bundle.expected_candidate_sha256.clone(),
                    },
                },
            );
        }
    }
    for contract in native_provider_contracts() {
        if !contract.accessible {
            return report.finish(
                CustodyStage::Discover,
                BridgeOutcome::NotRun {
                    reason: BridgeNotRun::ProviderUnavailable {
                        provider: contract.provider,
                        reason: format!("repository is not accessible: {}", contract.repository),
                    },
                },
            );
        }
    }
    if !bundle
        .observations
        .iter()
        .any(|observation| observation.provider == ExternalProvider::FrfFuzz)
    {
        return report.finish(
            CustodyStage::Discover,
            BridgeOutcome::NotRun {
                reason: BridgeNotRun::MissingFinding,
            },
        );
    }
    // reconstruct ----------------------------------------------------------
    let mut admitted: Vec<AdmittedObservation<'_>> = Vec::with_capacity(bundle.observations.len());
    for observation in &bundle.observations {
        match reconstruct_observation(observation, &bundle.expected_candidate_sha256) {
            Ok(admitted_observation) => {
                report.observations.push(ObservationSummary {
                    provider: observation.provider,
                    provenance: observation.provenance,
                    schema: observation.schema.clone(),
                    identity: admitted_observation.identity.text().to_owned(),
                    digest_verified: true,
                    authentic_native: observation.provenance == EvidenceProvenance::AuthenticNative,
                    candidate_sha256: observation.candidate_sha256.clone(),
                });
                admitted.push(admitted_observation);
            }
            Err(ReconstructionError::Refused(reason)) => {
                return report.finish(CustodyStage::Reconstruct, BridgeOutcome::Refused { reason });
            }
            Err(ReconstructionError::Integrity(reason)) => {
                return report.finish(
                    CustodyStage::Reconstruct,
                    BridgeOutcome::Integrity { reason },
                );
            }
        }
    }
    report.authentic_native_identities = admitted
        .iter()
        .filter(|observation| {
            observation.observation.provenance == EvidenceProvenance::AuthenticNative
        })
        .count();

    // native_confirm -------------------------------------------------------
    let mut native_confirmed = false;
    for observation in &admitted {
        match &observation.observation.reexecution {
            Reexecution::Mismatch { detail } => {
                return report.finish(
                    CustodyStage::NativeConfirm,
                    BridgeOutcome::Integrity {
                        reason: BridgeIntegrity::ReexecutionMismatch {
                            provider: observation.observation.provider,
                            detail: detail.clone(),
                        },
                    },
                );
            }
            Reexecution::NotRun { reason }
                if observation.observation.provider != ExternalProvider::Gemel =>
            {
                return report.finish(
                    CustodyStage::NativeConfirm,
                    BridgeOutcome::NotRun {
                        reason: BridgeNotRun::ReexecutionNotRun {
                            provider: observation.observation.provider,
                            reason: reason.clone(),
                        },
                    },
                );
            }
            Reexecution::Matched | Reexecution::NotRun { .. } => {}
        }
        match observation.observation.provenance {
            EvidenceProvenance::Modeled => {
                return report.finish(
                    CustodyStage::NativeConfirm,
                    BridgeOutcome::Refused {
                        reason: BridgeRefusal::ModeledEvidence {
                            provider: observation.observation.provider,
                        },
                    },
                );
            }
            EvidenceProvenance::ModifiedProvider => {
                return report.finish(
                    CustodyStage::NativeConfirm,
                    BridgeOutcome::Refused {
                        reason: BridgeRefusal::ModifiedProvider {
                            provider: observation.observation.provider,
                        },
                    },
                );
            }
            EvidenceProvenance::Substitute => {
                return report.finish(
                    CustodyStage::NativeConfirm,
                    BridgeOutcome::Refused {
                        reason: BridgeRefusal::SubstituteProvider {
                            provider: observation.observation.provider,
                        },
                    },
                );
            }
            EvidenceProvenance::AuthenticNative => {}
        }
        let contract = contract_for(observation.observation.provider);
        let ProviderBuild::Built { executable_sha256 } = &contract.build else {
            return report.finish(
                CustodyStage::NativeConfirm,
                BridgeOutcome::NotRun {
                    reason: BridgeNotRun::ProviderUnavailable {
                        provider: observation.observation.provider,
                        reason: "the pinned provider is not buildable in this environment"
                            .to_owned(),
                    },
                },
            );
        };
        if observation.observation.executable_sha256 != *executable_sha256 {
            return report.finish(
                CustodyStage::NativeConfirm,
                BridgeOutcome::Integrity {
                    reason: BridgeIntegrity::UnpinnedExecutable {
                        provider: observation.observation.provider,
                        expected: (*executable_sha256).to_owned(),
                        actual: observation.observation.executable_sha256.clone(),
                    },
                },
            );
        }
        if let Err(reason) = verify_live_capture(observation.observation, executable_sha256) {
            let outcome = match reason {
                ReconstructionError::Refused(reason) => BridgeOutcome::Refused { reason },
                ReconstructionError::Integrity(reason) => BridgeOutcome::Integrity { reason },
            };
            return report.finish(CustodyStage::NativeConfirm, outcome);
        }
        if observation.observation.reexecution == Reexecution::Matched
            && observation.observation.provider != ExternalProvider::Gemel
        {
            native_confirmed = true;
        }
    }
    if !native_confirmed {
        return report.finish(
            CustodyStage::NativeConfirm,
            BridgeOutcome::NotRun {
                reason: BridgeNotRun::NativeConfirmationNotRun {
                    reason:
                        "no authentic native observation reports a matched independent re-execution"
                            .to_owned(),
                },
            },
        );
    }
    // frf_receipt ----------------------------------------------------------
    let Some(frf_receipt) = admitted
        .iter()
        .find(|observation| observation.observation.provider == ExternalProvider::Frf)
    else {
        return report.finish(
            CustodyStage::FrfReceipt,
            BridgeOutcome::NotRun {
                reason: BridgeNotRun::MissingFrfReceipt,
            },
        );
    };
    let frf_text = frf_receipt.identity.text().to_owned();

    // The FRF receipt must bind the exact FRF-Fuzz finding input as its
    // fixture. Without this, a receipt and a finding from different runs could
    // be stitched into one "chain" even though each is individually valid.
    let finding = admitted
        .iter()
        .find(|observation| observation.observation.provider == ExternalProvider::FrfFuzz)
        .expect("a finding was required at discover");
    let finding_bytes = decode_hex(&finding.observation.canonical_bytes_hex).map_err(|detail| {
        BridgeIntegrity::InvalidCanonicalBytes {
            provider: ExternalProvider::FrfFuzz,
            detail,
        }
    });
    let finding_bytes = match finding_bytes {
        Ok(bytes) => bytes,
        Err(reason) => {
            return report.finish(
                CustodyStage::FrfReceipt,
                BridgeOutcome::Integrity { reason },
            );
        }
    };
    let Some(input) = frf_fuzz_input(&finding_bytes) else {
        return report.finish(
            CustodyStage::FrfReceipt,
            BridgeOutcome::Integrity {
                reason: BridgeIntegrity::TamperedObject {
                    provider: ExternalProvider::FrfFuzz,
                    detail: "framed finding carries no decodable input".to_owned(),
                },
            },
        );
    };
    let input_sha256 = sha256_hex(input);
    let frf_bytes = match decode_hex(&frf_receipt.observation.canonical_bytes_hex) {
        Ok(bytes) => bytes,
        Err(detail) => {
            return report.finish(
                CustodyStage::FrfReceipt,
                BridgeOutcome::Integrity {
                    reason: BridgeIntegrity::InvalidCanonicalBytes {
                        provider: ExternalProvider::Frf,
                        detail,
                    },
                },
            );
        }
    };
    let frf_value = match crate::identity::parse_strict(&frf_bytes) {
        Ok(value) => value,
        Err(error) => {
            return report.finish(
                CustodyStage::FrfReceipt,
                BridgeOutcome::Integrity {
                    reason: BridgeIntegrity::TamperedObject {
                        provider: ExternalProvider::Frf,
                        detail: error.to_string(),
                    },
                },
            );
        }
    };
    let fixture_hashes = frf_fixture_hashes(&frf_value);
    if !fixture_hashes.iter().any(|hash| hash == &input_sha256) {
        return report.finish(
            CustodyStage::FrfReceipt,
            BridgeOutcome::Integrity {
                reason: BridgeIntegrity::ChainMismatch {
                    detail: format!(
                        "FRF-Fuzz finding input SHA-256 {input_sha256} is not an FRF receipt fixture hash ({fixture_hashes:?})"
                    ),
                },
            },
        );
    }

    // gemel_custody --------------------------------------------------------
    let Some(gemel) = admitted
        .iter()
        .find(|observation| observation.observation.provider == ExternalProvider::Gemel)
    else {
        return report.finish(
            CustodyStage::GemelCustody,
            BridgeOutcome::NotRun {
                reason: BridgeNotRun::MissingGemelCustody,
            },
        );
    };
    let AdmittedIdentity::Gemel(gemel_id) = &gemel.identity else {
        unreachable!("Gemel observation admitted with another identity type");
    };
    if gemel_id.family() != "evidence" || gemel_id.kind() != "court_receipt" {
        return report.finish(
            CustodyStage::GemelCustody,
            BridgeOutcome::Refused {
                reason: BridgeRefusal::UnboundCustody {
                    detail: format!(
                        "Gemel custody must be evidence/court_receipt, got {}/{}",
                        gemel_id.family(),
                        gemel_id.kind()
                    ),
                },
            },
        );
    }
    match gemel_id.subject() {
        Some(subject) if subject == frf_text => {}
        Some(subject) => {
            return report.finish(
                CustodyStage::GemelCustody,
                BridgeOutcome::Refused {
                    reason: BridgeRefusal::UnboundCustody {
                        detail: format!(
                            "Gemel GCE subject {subject:?} is not the retained FRF receipt {frf_text:?}"
                        ),
                    },
                },
            );
        }
        None => {
            return report.finish(
                CustodyStage::GemelCustody,
                BridgeOutcome::Refused {
                    reason: BridgeRefusal::UnboundCustody {
                        detail: "Gemel GCE omits its evidence subject (field 0x03)".to_owned(),
                    },
                },
            );
        }
    }
    if gemel_id.outcome() != Some("pass") {
        return report.finish(
            CustodyStage::GemelCustody,
            BridgeOutcome::Refused {
                reason: BridgeRefusal::UnboundCustody {
                    detail: format!(
                        "Gemel evidence outcome is {:?}, expected \"pass\"",
                        gemel_id.outcome()
                    ),
                },
            },
        );
    }
    match gemel.observation.subject_identity.as_deref() {
        Some(subject) if subject == frf_text => {}
        Some(subject) => {
            return report.finish(
                CustodyStage::GemelCustody,
                BridgeOutcome::Refused {
                    reason: BridgeRefusal::UnboundCustody {
                        detail: format!(
                            "Gemel evidence subject {subject:?} is not the retained FRF receipt {frf_text:?}"
                        ),
                    },
                },
            );
        }
        None => {
            return report.finish(
                CustodyStage::GemelCustody,
                BridgeOutcome::Refused {
                    reason: BridgeRefusal::UnboundCustody {
                        detail: "Gemel evidence omits its FRF receipt subject".to_owned(),
                    },
                },
            );
        }
    }

    report.finish(CustodyStage::GemelCustody, BridgeOutcome::Complete)
}

struct AdmittedObservation<'a> {
    observation: &'a ExternalObservation,
    identity: AdmittedIdentity,
}

enum ReconstructionError {
    Refused(BridgeRefusal),
    Integrity(BridgeIntegrity),
}

fn reconstruct_observation<'a>(
    observation: &'a ExternalObservation,
    expected_candidate: &str,
) -> Result<AdmittedObservation<'a>, ReconstructionError> {
    let provider = observation.provider;
    let contract = contract_for(provider);

    if observation.schema.is_empty() {
        return Err(ReconstructionError::Integrity(
            BridgeIntegrity::MissingSchema { provider },
        ));
    }
    if observation.schema != contract.schema {
        return Err(ReconstructionError::Integrity(
            BridgeIntegrity::SchemaMismatch {
                provider,
                expected: contract.schema.to_owned(),
                actual: observation.schema.clone(),
            },
        ));
    }
    if observation.repository != contract.repository || observation.commit != contract.commit {
        return Err(ReconstructionError::Integrity(
            BridgeIntegrity::ProviderPinMismatch {
                provider,
                expected: format!("{}@{}", contract.repository, contract.commit),
                actual: format!("{}@{}", observation.repository, observation.commit),
            },
        ));
    }
    if !is_sha256(&observation.candidate_sha256) {
        return Err(ReconstructionError::Integrity(
            BridgeIntegrity::InvalidCandidateDigest {
                actual: observation.candidate_sha256.clone(),
            },
        ));
    }
    if observation.candidate_sha256 != expected_candidate {
        return Err(ReconstructionError::Refused(
            BridgeRefusal::StaleCandidate {
                expected: expected_candidate.to_owned(),
                actual: observation.candidate_sha256.clone(),
            },
        ));
    }
    if !is_sha256(&observation.executable_sha256) {
        return Err(ReconstructionError::Integrity(
            BridgeIntegrity::UnpinnedExecutable {
                provider,
                expected: "64 lowercase hex digits".to_owned(),
                actual: observation.executable_sha256.clone(),
            },
        ));
    }
    if observation.dso_binding == DsoBinding::Substituted {
        return Err(ReconstructionError::Refused(
            BridgeRefusal::SubstitutedDso { provider },
        ));
    }

    let bytes = decode_hex(&observation.canonical_bytes_hex).map_err(|detail| {
        ReconstructionError::Integrity(BridgeIntegrity::InvalidCanonicalBytes { provider, detail })
    })?;
    if bytes.len() > MAX_EXTERNAL_OBJECT_BYTES {
        return Err(ReconstructionError::Integrity(
            BridgeIntegrity::InvalidCanonicalBytes {
                provider,
                detail: format!(
                    "canonical object is {} bytes; limit is {MAX_EXTERNAL_OBJECT_BYTES}",
                    bytes.len()
                ),
            },
        ));
    }

    let identity = admit_identity(observation, &bytes)?;
    Ok(AdmittedObservation {
        observation,
        identity,
    })
}

fn admit_identity(
    observation: &ExternalObservation,
    bytes: &[u8],
) -> Result<AdmittedIdentity, ReconstructionError> {
    match observation.provider {
        ExternalProvider::Frf => admit_frf_receipt(observation, bytes),
        ExternalProvider::FrfFuzz => admit_frf_fuzz_finding(observation, bytes),
        ExternalProvider::Gemel => admit_gemel_evidence(observation, bytes),
    }
}

#[allow(clippy::too_many_lines)]
fn admit_frf_receipt(
    observation: &ExternalObservation,
    bytes: &[u8],
) -> Result<AdmittedIdentity, ReconstructionError> {
    let provider = ExternalProvider::Frf;
    let id = FrfReceiptId::admit_shape(&observation.identity).map_err(|detail| {
        ReconstructionError::Integrity(BridgeIntegrity::IdentityShape { provider, detail })
    })?;
    let value = crate::identity::parse_strict(bytes).map_err(|error| {
        ReconstructionError::Integrity(BridgeIntegrity::TamperedObject {
            provider,
            detail: error.to_string(),
        })
    })?;
    let object = value.as_object().ok_or_else(|| {
        ReconstructionError::Integrity(BridgeIntegrity::TamperedObject {
            provider,
            detail: "OpenReceipt is not a JSON object".to_owned(),
        })
    })?;
    for required in [
        "schema_version",
        "run",
        "court",
        "provenance",
        "authority",
        "candidate",
        "environment",
        "fixtures",
        "observables",
        "residuals",
        "endoduction",
        "claims",
        "replay",
    ] {
        if !object.contains_key(required) {
            return Err(ReconstructionError::Integrity(
                BridgeIntegrity::TamperedObject {
                    provider,
                    detail: format!("OpenReceipt omits required field {required:?}"),
                },
            ));
        }
    }
    let schema = object
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ReconstructionError::Integrity(BridgeIntegrity::TamperedObject {
                provider,
                detail: "OpenReceipt schema_version is not a string".to_owned(),
            })
        })?;
    if schema != observation.schema {
        return Err(ReconstructionError::Integrity(
            BridgeIntegrity::SchemaMismatch {
                provider,
                expected: observation.schema.clone(),
                actual: schema.to_owned(),
            },
        ));
    }
    let run = object
        .get("run")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ReconstructionError::Integrity(BridgeIntegrity::TamperedObject {
                provider,
                detail: "OpenReceipt run is not a string".to_owned(),
            })
        })?;
    if !run.starts_with("run-") {
        return Err(ReconstructionError::Integrity(
            BridgeIntegrity::TamperedObject {
                provider,
                detail: format!("OpenReceipt run is not a run identity: {run:?}"),
            },
        ));
    }
    let candidate = object
        .get("candidate")
        .and_then(|candidate| candidate.get("identity_hash"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ReconstructionError::Integrity(BridgeIntegrity::TamperedObject {
                provider,
                detail: "OpenReceipt candidate.identity_hash is not a string".to_owned(),
            })
        })?;
    if candidate != observation.candidate_sha256 {
        return Err(ReconstructionError::Integrity(
            BridgeIntegrity::CandidateBindingMismatch {
                provider,
                expected: observation.candidate_sha256.clone(),
                actual: candidate.to_owned(),
            },
        ));
    }
    let digest = sha256_hex(bytes);
    let expected = format!("receipt-{run}-{digest}");
    if id.as_str() != expected {
        return Err(ReconstructionError::Integrity(
            BridgeIntegrity::DigestMismatch {
                provider,
                detail: format!(
                    "receipt identity {:?} does not rederive from its bytes as {expected:?}",
                    id.as_str()
                ),
            },
        ));
    }
    Ok(AdmittedIdentity::Frf(id))
}

const FRF_FUZZ_MAGIC: [u8; 4] = *b"FRFZ";
const FRF_FUZZ_FAMILY_FINDING: u8 = 0x02;
const FRF_FUZZ_COORDINATE_LEN: usize = 49;

#[allow(clippy::too_many_lines)]
fn admit_frf_fuzz_finding(
    observation: &ExternalObservation,
    bytes: &[u8],
) -> Result<AdmittedIdentity, ReconstructionError> {
    let provider = ExternalProvider::FrfFuzz;
    let id = FrfFuzzFindingId::admit_shape(&observation.identity).map_err(|detail| {
        ReconstructionError::Integrity(BridgeIntegrity::IdentityShape { provider, detail })
    })?;
    let digest = blake3::hash(bytes).to_hex().to_string();
    if id.as_str() != digest {
        return Err(ReconstructionError::Integrity(
            BridgeIntegrity::DigestMismatch {
                provider,
                detail: format!(
                    "finding identity {:?} does not rederive from its framed bytes as {digest:?}",
                    id.as_str()
                ),
            },
        ));
    }
    let tampered = |detail: String| {
        ReconstructionError::Integrity(BridgeIntegrity::TamperedObject { provider, detail })
    };
    if bytes.len() < 15 {
        return Err(tampered(
            "framed finding is shorter than the 15-byte header".to_owned(),
        ));
    }
    if bytes[0..4] != FRF_FUZZ_MAGIC {
        return Err(tampered("framed finding has the wrong magic".to_owned()));
    }
    if bytes[4] != FRF_FUZZ_FAMILY_FINDING {
        return Err(tampered(format!(
            "framed object family is 0x{:02x}, not Finding (0x02)",
            bytes[4]
        )));
    }
    if bytes[5] != 0 || bytes[6] != 1 {
        return Err(tampered(format!(
            "framing version is {}.{}, expected 0.1",
            bytes[5], bytes[6]
        )));
    }
    let length = u64::from_le_bytes(
        bytes[7..15]
            .try_into()
            .expect("the header length slice is exactly eight bytes"),
    );
    let Ok(length) = usize::try_from(length) else {
        return Err(tampered(
            "framed payload length does not fit usize".to_owned(),
        ));
    };
    if bytes.len() != 15 + length {
        return Err(tampered(format!(
            "framed payload length {length} does not match {} trailing bytes",
            bytes.len() - 15
        )));
    }
    let payload = &bytes[15..];
    let fixed = 1 + 1 + 8 + FRF_FUZZ_COORDINATE_LEN + 1 + 4;
    if payload.len() < fixed {
        return Err(tampered(format!(
            "finding payload is {} bytes, shorter than the {fixed}-byte fixed prefix",
            payload.len()
        )));
    }
    if payload[0] != 1 {
        return Err(tampered(format!(
            "finding payload version is {}, expected 1",
            payload[0]
        )));
    }
    if !(1..=3).contains(&payload[1]) {
        return Err(tampered(format!(
            "finding kind byte {} is not crash/timeout/unattributed",
            payload[1]
        )));
    }
    if payload[1 + 1 + 8] != 1 {
        return Err(tampered(format!(
            "mutation coordinate version is {}, expected 1",
            payload[1 + 1 + 8]
        )));
    }

    let replay_offset = 1 + 1 + 8 + FRF_FUZZ_COORDINATE_LEN;
    if payload[replay_offset] > 2 {
        return Err(tampered(format!(
            "finding replay byte {} is not not-replayed/reproduced/not-reproduced",
            payload[replay_offset]
        )));
    }
    let input_len = u32::from_le_bytes(
        payload[replay_offset + 1..replay_offset + 5]
            .try_into()
            .expect("the input length slice is exactly four bytes"),
    );
    let input_len = usize::try_from(input_len)
        .map_err(|_| tampered("finding input length does not fit usize".to_owned()))?;
    if payload.len() != fixed + input_len {
        return Err(tampered(format!(
            "finding input length {input_len} does not match {} trailing bytes",
            payload.len() - fixed
        )));
    }
    Ok(AdmittedIdentity::FrfFuzz(id))
}

const GEMEL_MAGIC: [u8; 4] = *b"GEML";
const GEMEL_ENCODING_VERSION: u8 = 1;
const GEMEL_FAMILY_EVIDENCE: u8 = 0x0B;
const GEMEL_FAMILY_PRODUCER: u8 = 0x0E;
const GEMEL_EVIDENCE_SCHEMA_VERSION: u8 = 1;

#[allow(clippy::too_many_lines)]
fn admit_gemel_evidence(
    observation: &ExternalObservation,
    bytes: &[u8],
) -> Result<AdmittedIdentity, ReconstructionError> {
    let provider = ExternalProvider::Gemel;
    let (family, _digest) = GemelGceId::admit_shape(&observation.identity).map_err(|detail| {
        ReconstructionError::Integrity(BridgeIntegrity::IdentityShape { provider, detail })
    })?;
    let digest = blake3::hash(bytes).to_hex().to_string();
    let expected = format!("{family}.{digest}");
    if observation.identity != expected {
        return Err(ReconstructionError::Integrity(
            BridgeIntegrity::DigestMismatch {
                provider,
                detail: format!(
                    "Gemel identity {:?} does not rederive from its envelope bytes as {expected:?}",
                    observation.identity
                ),
            },
        ));
    }
    let tampered = |detail: String| {
        ReconstructionError::Integrity(BridgeIntegrity::TamperedObject { provider, detail })
    };
    if bytes.len() < 9 {
        return Err(tampered(
            "GCE envelope is shorter than the minimum header".to_owned(),
        ));
    }
    if bytes[0..4] != GEMEL_MAGIC {
        return Err(tampered("GCE envelope has the wrong magic".to_owned()));
    }
    if bytes[4] != GEMEL_ENCODING_VERSION {
        return Err(tampered(format!(
            "GCE encoding version is {}, expected 1",
            bytes[4]
        )));
    }
    if bytes[5] != GEMEL_FAMILY_EVIDENCE {
        return Err(tampered(format!(
            "GCE family is 0x{:02x}, not Evidence (0x0B)",
            bytes[5]
        )));
    }
    if bytes[6] != GEMEL_EVIDENCE_SCHEMA_VERSION {
        return Err(tampered(format!(
            "GCE evidence schemever is {}, expected 1",
            bytes[6]
        )));
    }
    if bytes[7] != 0 {
        return Err(tampered(format!(
            "GCE flags are 0x{:02x}, expected 0",
            bytes[7]
        )));
    }
    let mut position = 8usize;
    let body_len = read_uint(bytes, &mut position)
        .ok_or_else(|| tampered("GCE body length is not canonical LEB128".to_owned()))?;
    let body_len = usize::try_from(body_len)
        .map_err(|_| tampered("GCE body length does not fit usize".to_owned()))?;
    if bytes.len() != position + body_len {
        return Err(tampered(format!(
            "GCE body length {body_len} does not match {} trailing bytes",
            bytes.len() - position
        )));
    }
    let body_end = bytes.len();
    let mut previous_tag = 0u64;
    let mut producer: Option<&[u8]> = None;
    let mut kind: Option<String> = None;
    let mut subject: Option<String> = None;
    let mut outcome: Option<String> = None;
    while position < body_end {
        let tag = read_uint(bytes, &mut position)
            .ok_or_else(|| tampered("GCE field tag is not canonical LEB128".to_owned()))?;
        if tag == 0 || tag > 0xEF {
            return Err(tampered(format!("GCE field tag {tag} is reserved")));
        }
        if tag <= previous_tag {
            return Err(tampered(format!(
                "GCE field tags are not strictly increasing at {tag}"
            )));
        }
        previous_tag = tag;
        let value_len = read_uint(bytes, &mut position)
            .ok_or_else(|| tampered("GCE field length is not canonical LEB128".to_owned()))?;
        let value_len = usize::try_from(value_len)
            .map_err(|_| tampered("GCE field length does not fit usize".to_owned()))?;
        let end = position
            .checked_add(value_len)
            .ok_or_else(|| tampered("GCE field length overflows".to_owned()))?;
        if end > body_end {
            return Err(tampered("GCE field extends past the body".to_owned()));
        }
        let value = &bytes[position..end];
        position = end;
        match tag {
            0x01 => producer = Some(value),
            0x02 => {
                let text = parse_gce_string(value, "evidence kind")?;
                if text.is_empty() {
                    return Err(tampered("GCE evidence kind is empty".to_owned()));
                }
                kind = Some(text);
            }
            0x03 => subject = Some(parse_gce_string(value, "evidence subject")?),
            0x0D => outcome = Some(parse_gce_result_outcome(value)?),
            tag if tag >= 0x80 => {}
            tag if (0x03..=0x11).contains(&tag) => {}
            tag => {
                return Err(tampered(format!(
                    "GCE evidence uses unknown mandatory field tag {tag}"
                )));
            }
        }
    }
    let producer = producer.ok_or_else(|| tampered("GCE evidence omits producer".to_owned()))?;
    let mut producer_cursor = 0usize;
    let producer_len = read_uint(producer, &mut producer_cursor)
        .ok_or_else(|| tampered("GCE producer reference length is invalid".to_owned()))?;
    let producer_len = usize::try_from(producer_len)
        .map_err(|_| tampered("GCE producer reference length overflows".to_owned()))?;
    if producer_len != 33 || producer.len() != producer_cursor + producer_len {
        return Err(tampered(format!(
            "GCE producer reference is {} bytes (declared {producer_len}), expected 33",
            producer.len().saturating_sub(producer_cursor)
        )));
    }
    let producer = &producer[producer_cursor..];
    if producer[0] != GEMEL_FAMILY_PRODUCER {
        return Err(tampered(format!(
            "GCE producer reference family is 0x{:02x}, not Producer (0x0E)",
            producer[0]
        )));
    }
    let kind = kind.ok_or_else(|| tampered("GCE evidence omits kind".to_owned()))?;
    if family != "evidence" {
        return Err(tampered(format!(
            "Gemel custody identity family is {family:?}, expected \"evidence\""
        )));
    }
    Ok(AdmittedIdentity::Gemel(GemelGceId {
        text: observation.identity.clone(),
        family,
        kind,
        subject,
        outcome,
    }))
}

/// Decode a canonical GCE STRING value (`len` u64 + UTF-8 bytes).
fn parse_gce_string(value: &[u8], what: &str) -> Result<String, ReconstructionError> {
    let tampered = |detail: String| {
        ReconstructionError::Integrity(BridgeIntegrity::TamperedObject {
            provider: ExternalProvider::Gemel,
            detail,
        })
    };
    let mut cursor = 0usize;
    let len = read_uint(value, &mut cursor)
        .ok_or_else(|| tampered(format!("GCE {what} length is invalid")))?;
    let len = usize::try_from(len).map_err(|_| tampered(format!("GCE {what} length overflows")))?;
    if cursor + len != value.len() {
        return Err(tampered(format!(
            "GCE {what} length does not match its field"
        )));
    }
    std::str::from_utf8(&value[cursor..])
        .map(str::to_owned)
        .map_err(|_| tampered(format!("GCE {what} is not UTF-8")))
}

/// Decode the first field (outcome) of a GCE `evidence_result` record.
fn parse_gce_result_outcome(value: &[u8]) -> Result<String, ReconstructionError> {
    let tampered = |detail: String| {
        ReconstructionError::Integrity(BridgeIntegrity::TamperedObject {
            provider: ExternalProvider::Gemel,
            detail,
        })
    };
    let mut cursor = 0usize;
    // Records are self-delimiting through a leading body length.
    let body_len = read_uint(value, &mut cursor)
        .ok_or_else(|| tampered("GCE evidence result body length is invalid".to_owned()))?;
    let body_len = usize::try_from(body_len)
        .map_err(|_| tampered("GCE evidence result body length overflows".to_owned()))?;
    let body_end = cursor
        .checked_add(body_len)
        .ok_or_else(|| tampered("GCE evidence result body length overflows".to_owned()))?;
    if body_end != value.len() {
        return Err(tampered(
            "GCE evidence result body length does not match its field".to_owned(),
        ));
    }
    let tag = read_uint(value, &mut cursor)
        .ok_or_else(|| tampered("GCE evidence result tag is invalid".to_owned()))?;
    let len = read_uint(value, &mut cursor)
        .ok_or_else(|| tampered("GCE evidence result length is invalid".to_owned()))?;
    let len = usize::try_from(len)
        .map_err(|_| tampered("GCE evidence result length overflows".to_owned()))?;
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| tampered("GCE evidence result length overflows".to_owned()))?;
    if end > body_end {
        return Err(tampered(
            "GCE evidence result extends past its body".to_owned(),
        ));
    }
    if tag != 0x01 {
        return Err(tampered(format!(
            "GCE evidence result first field tag is {tag}, expected outcome (0x01)"
        )));
    }
    parse_gce_string(&value[cursor..end], "evidence result outcome")
}

// ---------------------------------------------------------------------------
// Live capture
// ---------------------------------------------------------------------------

/// Explicit inputs for a live capture. Every path is a real, already-produced
/// artifact; the capture never invents provider identities.
pub struct CaptureRequest {
    /// Candidate artifact (the subject of the chain).
    pub candidate: PathBuf,
    /// Raw FRF-Fuzz finding object (`FRFZ` family 0x02).
    pub finding: PathBuf,
    /// Canonical FRF `OpenReceipt` JSON.
    pub receipt: PathBuf,
    /// Raw Gemel GCE evidence envelope.
    pub gemel_gce: PathBuf,
    /// The `gemel.evidence.v1` document that was ingested.
    pub gemel_evidence: PathBuf,
    /// The Gemel repository that owns `gemel_gce`.
    pub gemel_repo: PathBuf,
    /// FRF store root used for exact replay.
    pub frf_root: PathBuf,
    /// The exact FRF run id to replay.
    pub frf_run: String,
    /// Pinned provider executables.
    pub frf_bin: PathBuf,
    /// Pinned FRF-Fuzz executable.
    pub frf_fuzz_bin: PathBuf,
    /// Pinned Gemel executable.
    pub gemel_bin: PathBuf,
    /// Loader maps captured from the providers (`/proc/<pid>/maps`).
    pub frf_map: PathBuf,
    /// FRF-Fuzz loader map.
    pub frf_fuzz_map: PathBuf,
    /// Gemel loader map.
    pub gemel_map: PathBuf,
    /// Capture-probe DSO excluded from the recorded closure.
    pub probe: PathBuf,
}

/// Build a bridge bundle from live provider artifacts, executable files,
/// loader maps, and independently repeated executions. The function derives
/// every identity from the exact bytes it is given; it does not construct an
/// `OpenReceipt`, finding, GCE object, or GID.
///
/// # Errors
///
/// Returns a human-readable error when an input is unreadable, a provider
/// executable does not match its recorded pin, an external schema or
/// candidate/fixture binding fails, or a loader map cannot be hashed. The
/// function does not write the bundle; the caller decides where it goes.
#[allow(clippy::too_many_lines)]
pub fn capture_bundle(request: &CaptureRequest) -> Result<Vec<u8>, String> {
    let candidate_sha256 = sha256_file(&request.candidate)
        .ok_or_else(|| format!("cannot hash candidate {}", request.candidate.display()))?;
    let finding_bytes = read_object(&request.finding)?;
    let input = frf_fuzz_input(&finding_bytes)
        .ok_or_else(|| "finding is not a valid FRFZ finding frame".to_owned())?
        .to_vec();
    let finding_identity = blake3::hash(&finding_bytes).to_hex().to_string();

    let receipt_bytes = read_object(&request.receipt)?;
    let receipt_value = crate::identity::parse_strict(&receipt_bytes)
        .map_err(|error| format!("FRF receipt is not strict JSON: {error}"))?;
    let schema = receipt_value
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "FRF receipt has no schema_version".to_owned())?;
    if schema != ExternalProvider::Frf.expected_schema() {
        return Err(format!(
            "FRF receipt schema {schema:?} is not {}",
            ExternalProvider::Frf.expected_schema()
        ));
    }
    let run = receipt_value
        .get("run")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "FRF receipt has no run".to_owned())?;
    if run != request.frf_run {
        return Err(format!(
            "FRF receipt run {run:?} is not the requested replay run {:?}",
            request.frf_run
        ));
    }
    let receipt_candidate = receipt_value
        .get("candidate")
        .and_then(|candidate| candidate.get("identity_hash"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "FRF receipt has no candidate.identity_hash".to_owned())?;
    if receipt_candidate != candidate_sha256 {
        return Err(format!(
            "FRF receipt candidate {receipt_candidate} is not the captured candidate {candidate_sha256}"
        ));
    }
    let input_sha256 = sha256_hex(&input);
    if !frf_fixture_hashes(&receipt_value)
        .iter()
        .any(|hash| hash == &input_sha256)
    {
        return Err(format!(
            "FRF receipt does not bind the finding input SHA-256 {input_sha256}"
        ));
    }
    let receipt_identity = format!("receipt-{run}-{}", sha256_hex(&receipt_bytes));

    let gemel_bytes = read_object(&request.gemel_gce)?;
    let gemel_identity = format!("evidence.{}", blake3::hash(&gemel_bytes).to_hex());

    let frf_executable = require_pinned(ExternalProvider::Frf, &request.frf_bin)?;
    let fuzz_executable = require_pinned(ExternalProvider::FrfFuzz, &request.frf_fuzz_bin)?;
    let gemel_executable = require_pinned(ExternalProvider::Gemel, &request.gemel_bin)?;

    // Independent candidate execution on the exact finding input.
    let fixture = std::env::temp_dir().join(format!(
        "frf-bridge-fixture-{}-{}",
        std::process::id(),
        input_sha256
    ));
    std::fs::write(&fixture, &input)
        .map_err(|error| format!("cannot stage candidate fixture: {error}"))?;
    let fixture_arg = fixture.to_string_lossy().into_owned();
    let (candidate_reexecution, candidate_record) = repeated_runs(
        &input,
        &request.candidate,
        &["--frf-fuzz-fixture", &fixture_arg],
        Some(std::env::temp_dir().as_path()),
    );
    let _ = std::fs::remove_file(&fixture);

    // Independent exact replays of the FRF run.
    let root_arg = request.frf_root.to_string_lossy().into_owned();
    let (frf_reexecution, frf_record) = repeated_runs(
        request.frf_run.as_bytes(),
        &request.frf_bin,
        &[
            "--root",
            &root_arg,
            "replay",
            &request.frf_run,
            "--policy",
            "exact",
        ],
        Some(request.frf_root.as_path()),
    );

    // Independent Gemel ingests of the same evidence document.
    let repo_arg = request.gemel_repo.to_string_lossy().into_owned();
    let evidence_arg = request.gemel_evidence.to_string_lossy().into_owned();
    let gemel_input = std::fs::read(&request.gemel_evidence)
        .map_err(|error| format!("cannot read Gemel evidence: {error}"))?;
    let (gemel_reexecution, gemel_record) = repeated_runs(
        &gemel_input,
        &request.gemel_bin,
        &[
            "--repo",
            &repo_arg,
            "evidence",
            "ingest",
            &evidence_arg,
            "--json",
        ],
        None,
    );

    let frf_closure = read_dso_map(&request.frf_map, &request.probe, &request.frf_bin)?;
    let fuzz_closure = read_dso_map(&request.frf_fuzz_map, &request.probe, &request.frf_fuzz_bin)?;
    let gemel_closure = read_dso_map(&request.gemel_map, &request.probe, &request.gemel_bin)?;

    let observations = vec![
        ExternalObservation {
            provider: ExternalProvider::FrfFuzz,
            provenance: EvidenceProvenance::AuthenticNative,
            repository: contract_for(ExternalProvider::FrfFuzz)
                .repository
                .to_owned(),
            commit: contract_for(ExternalProvider::FrfFuzz).commit.to_owned(),
            schema: ExternalProvider::FrfFuzz.expected_schema().to_owned(),
            identity: finding_identity,
            subject_identity: None,
            canonical_bytes_hex: hex_encode(&finding_bytes),
            candidate_sha256: candidate_sha256.clone(),
            executable_sha256: fuzz_executable,
            dso_binding: derive_dso_binding(&fuzz_closure, &request.frf_fuzz_bin),
            reexecution: candidate_reexecution,
            capture: Some(ObservationCapture {
                executable_path: request.frf_fuzz_bin.to_string_lossy().into_owned(),
                closure_sha256: closure_digest(&fuzz_closure),
                dso_closure: fuzz_closure,
                reexecution: candidate_record,
            }),
        },
        ExternalObservation {
            provider: ExternalProvider::Frf,
            provenance: EvidenceProvenance::AuthenticNative,
            repository: contract_for(ExternalProvider::Frf).repository.to_owned(),
            commit: contract_for(ExternalProvider::Frf).commit.to_owned(),
            schema: ExternalProvider::Frf.expected_schema().to_owned(),
            identity: receipt_identity.clone(),
            subject_identity: None,
            canonical_bytes_hex: hex_encode(&receipt_bytes),
            candidate_sha256: candidate_sha256.clone(),
            executable_sha256: frf_executable,
            dso_binding: derive_dso_binding(&frf_closure, &request.frf_bin),
            reexecution: frf_reexecution,
            capture: Some(ObservationCapture {
                executable_path: request.frf_bin.to_string_lossy().into_owned(),
                closure_sha256: closure_digest(&frf_closure),
                dso_closure: frf_closure,
                reexecution: frf_record,
            }),
        },
        ExternalObservation {
            provider: ExternalProvider::Gemel,
            provenance: EvidenceProvenance::AuthenticNative,
            repository: contract_for(ExternalProvider::Gemel).repository.to_owned(),
            commit: contract_for(ExternalProvider::Gemel).commit.to_owned(),
            schema: ExternalProvider::Gemel.expected_schema().to_owned(),
            identity: gemel_identity,
            subject_identity: Some(receipt_identity),
            canonical_bytes_hex: hex_encode(&gemel_bytes),
            candidate_sha256,
            executable_sha256: gemel_executable,
            dso_binding: derive_dso_binding(&gemel_closure, &request.gemel_bin),
            reexecution: gemel_reexecution,
            capture: Some(ObservationCapture {
                executable_path: request.gemel_bin.to_string_lossy().into_owned(),
                closure_sha256: closure_digest(&gemel_closure),
                dso_closure: gemel_closure,
                reexecution: gemel_record,
            }),
        },
    ];

    let bundle = EvidenceBundle {
        schema: BRIDGE_BUNDLE_SCHEMA.to_owned(),
        spec: BRIDGE_SPEC.to_owned(),
        expected_candidate_sha256: sha256_file(&request.candidate)
            .ok_or_else(|| "cannot re-hash candidate".to_owned())?,
        observations,
    };
    serde_json::to_vec(&bundle).map_err(|error| format!("cannot encode bundle: {error}"))
}

fn require_pinned(provider: ExternalProvider, path: &Path) -> Result<String, String> {
    let actual = sha256_file(path)
        .ok_or_else(|| format!("cannot hash {} executable {}", provider, path.display()))?;
    let ProviderBuild::Built { executable_sha256 } = contract_for(provider).build else {
        return Err(format!("provider {provider} has no pinned build"));
    };
    if actual != executable_sha256 {
        return Err(format!(
            "{provider} executable hashes to {actual}, pinned {executable_sha256}"
        ));
    }
    Ok(actual)
}

fn read_object(path: &Path) -> Result<Vec<u8>, String> {
    let bytes =
        std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() > MAX_EXTERNAL_OBJECT_BYTES {
        return Err(format!(
            "{} is {} bytes; limit is {MAX_EXTERNAL_OBJECT_BYTES}",
            path.display(),
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn repeated_runs(
    input: &[u8],
    program: &Path,
    args: &[&str],
    cwd: Option<&Path>,
) -> (Reexecution, ReexecutionRecord) {
    let runs: Vec<RunRecord> = (0..2)
        .map(|_| run_command(program, args, cwd))
        .collect::<Result<_, _>>()
        .unwrap_or_default();
    let byte_identical = runs.len() >= 2 && runs.windows(2).all(|pair| pair[0] == pair[1]);
    let status = if byte_identical {
        Reexecution::Matched
    } else {
        Reexecution::Mismatch {
            detail: format!(
                "{} repeated run(s) of {} were not byte-identical",
                runs.len(),
                program.display()
            ),
        }
    };
    (
        status,
        ReexecutionRecord {
            input_sha256: sha256_hex(input),
            runs,
            byte_identical,
        },
    )
}

fn run_command(program: &Path, args: &[&str], cwd: Option<&Path>) -> Result<RunRecord, String> {
    // `ulimit -c 0` keeps an aborting fixture from writing a core file; `exec`
    // preserves the target's exit status and streams.
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("ulimit -c 0 2>/dev/null; exec \"$0\" \"$@\"")
        .arg(program)
        .args(args)
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("HOME", "/tmp");
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let output = command
        .output()
        .map_err(|error| format!("cannot execute {}: {error}", program.display()))?;
    Ok(RunRecord {
        exit: exit_code(output.status),
        stdout_sha256: sha256_hex(&output.stdout),
        stderr_sha256: sha256_hex(&output.stderr),
    })
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    status.code().unwrap_or(-1)
}

fn read_dso_map(path: &Path, probe: &Path, executable: &Path) -> Result<Vec<DsoObject>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read loader map {}: {error}", path.display()))?;
    let probe_text = probe.to_string_lossy();
    let executable_text = executable.to_string_lossy();
    let mut paths = BTreeSet::new();
    for line in text.lines() {
        let Some(index) = line.find(" /") else {
            continue;
        };
        let mapped = &line[index + 1..];
        let mapped = mapped.trim_end();
        if mapped.is_empty()
            || mapped.ends_with(" (deleted)")
            || mapped == probe_text
            || mapped == executable_text
        {
            continue;
        }
        paths.insert(mapped.to_owned());
    }
    let mut closure = Vec::with_capacity(paths.len());
    for path in paths {
        let digest = sha256_file(Path::new(&path))
            .ok_or_else(|| format!("loader object {path} is not readable"))?;
        closure.push(DsoObject {
            path,
            sha256: digest,
        });
    }
    Ok(closure)
}

// ---------------------------------------------------------------------------
// Live-capture verification
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
fn verify_live_capture(
    observation: &ExternalObservation,
    pinned_executable: &str,
) -> Result<(), ReconstructionError> {
    let provider = observation.provider;
    let integrity = |reason| ReconstructionError::Integrity(reason);
    let Some(capture) = &observation.capture else {
        return Err(integrity(BridgeIntegrity::MissingLiveCapture { provider }));
    };
    let Some(recomputed) = sha256_file(Path::new(&capture.executable_path)) else {
        return Err(integrity(BridgeIntegrity::UnpinnedExecutable {
            provider,
            expected: pinned_executable.to_owned(),
            actual: format!("unreadable executable {}", capture.executable_path),
        }));
    };
    if recomputed != observation.executable_sha256 || recomputed != pinned_executable {
        return Err(integrity(BridgeIntegrity::UnpinnedExecutable {
            provider,
            expected: pinned_executable.to_owned(),
            actual: recomputed,
        }));
    }
    if capture.dso_closure.is_empty() {
        return Err(integrity(BridgeIntegrity::DsoClosureMismatch {
            provider,
            detail: "capture records an empty loader closure".to_owned(),
        }));
    }
    if !capture
        .dso_closure
        .windows(2)
        .all(|pair| pair[0].path < pair[1].path)
    {
        return Err(integrity(BridgeIntegrity::DsoClosureMismatch {
            provider,
            detail: "loader closure is not sorted by path".to_owned(),
        }));
    }
    for object in &capture.dso_closure {
        if !object.path.starts_with('/') || !is_sha256(&object.sha256) {
            return Err(integrity(BridgeIntegrity::DsoClosureMismatch {
                provider,
                detail: format!("invalid loader object entry {object:?}"),
            }));
        }
        let Some(actual) = sha256_file(Path::new(&object.path)) else {
            return Err(integrity(BridgeIntegrity::DsoClosureMismatch {
                provider,
                detail: format!("loader object {} is not readable", object.path),
            }));
        };
        if actual != object.sha256 {
            return Err(integrity(BridgeIntegrity::DsoClosureMismatch {
                provider,
                detail: format!(
                    "loader object {} hashes to {actual}, recorded {}",
                    object.path, object.sha256
                ),
            }));
        }
    }
    if closure_digest(&capture.dso_closure) != capture.closure_sha256 {
        return Err(integrity(BridgeIntegrity::DsoClosureMismatch {
            provider,
            detail: "closure digest does not rederive from its sorted entries".to_owned(),
        }));
    }
    let derived = derive_dso_binding(&capture.dso_closure, Path::new(&capture.executable_path));
    if derived == DsoBinding::Substituted {
        return Err(ReconstructionError::Refused(
            BridgeRefusal::SubstitutedDso { provider },
        ));
    }
    if observation.dso_binding != derived {
        return Err(integrity(BridgeIntegrity::DsoClosureMismatch {
            provider,
            detail: format!(
                "declared DSO binding {:?} disagrees with the observed closure ({derived:?})",
                observation.dso_binding
            ),
        }));
    }
    let reexecution = &capture.reexecution;
    if reexecution.runs.len() < 2
        || !reexecution.byte_identical
        || !reexecution.runs.windows(2).all(|pair| pair[0] == pair[1])
    {
        return Err(integrity(BridgeIntegrity::ReexecutionMismatch {
            provider,
            detail: format!(
                "capture records {} run(s), byte_identical={}",
                reexecution.runs.len(),
                reexecution.byte_identical
            ),
        }));
    }
    if observation.reexecution != Reexecution::Matched {
        return Err(integrity(BridgeIntegrity::ReexecutionMismatch {
            provider,
            detail: "capture is matched but the observation does not report matched re-execution"
                .to_owned(),
        }));
    }
    Ok(())
}

fn closure_digest(closure: &[DsoObject]) -> String {
    let mut lines = Vec::with_capacity(closure.len());
    for object in closure {
        lines.push(format!("{}\0{}\n", object.path, object.sha256));
    }
    lines.sort();
    sha256_hex(lines.concat().as_bytes())
}

fn derive_dso_binding(closure: &[DsoObject], executable: &Path) -> DsoBinding {
    if closure.is_empty() {
        return DsoBinding::Unknown;
    }
    let executable_dir = executable.parent();
    for object in closure {
        let path = Path::new(&object.path);
        let system = path.starts_with("/lib")
            || path.starts_with("/usr/lib")
            || path.starts_with("/usr/local/lib");
        let beside_executable = executable_dir.is_some_and(|dir| path.starts_with(dir));
        if !system && !beside_executable {
            return DsoBinding::Substituted;
        }
    }
    DsoBinding::Native
}

/// Decode the exact input bytes from a validated FRFZ finding frame.
fn frf_fuzz_input(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < 15 + 1 + 1 + 8 + FRF_FUZZ_COORDINATE_LEN + 1 + 4 {
        return None;
    }
    let payload = &bytes[15..];
    let fixed = 1 + 1 + 8 + FRF_FUZZ_COORDINATE_LEN + 1 + 4;
    let replay_offset = 1 + 1 + 8 + FRF_FUZZ_COORDINATE_LEN;
    let input_len = u32::from_le_bytes(
        payload[replay_offset + 1..replay_offset + 5]
            .try_into()
            .ok()?,
    ) as usize;
    if payload.len() != fixed + input_len {
        return None;
    }
    Some(&payload[fixed..])
}

/// The fixture hashes declared by an FRF `OpenReceipt`.
fn frf_fixture_hashes(receipt: &serde_json::Value) -> Vec<String> {
    receipt
        .get("fixtures")
        .and_then(serde_json::Value::as_array)
        .map(|fixtures| {
            fixtures
                .iter()
                .filter_map(|fixture| fixture.get("hash"))
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_sha256(value: &str) -> bool {
    is_lower_hex(value, 64)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_family(family: &str) -> bool {
    let mut bytes = family.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && family.len() <= 32
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("hex string has an odd length".to_owned());
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let raw = value.as_bytes();
    for pair in raw.chunks_exact(2) {
        let high =
            hex_value(pair[0]).ok_or_else(|| "hex string contains a non-hex digit".to_owned())?;
        let low =
            hex_value(pair[1]).ok_or_else(|| "hex string contains a non-hex digit".to_owned())?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn sha256_file(path: &Path) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_EXECUTABLE_BYTES {
        return None;
    }
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let count = std::io::Read::read(&mut file, &mut buffer).ok()?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Some(sha256_digest_hex(hasher.finalize()))
}

fn sha256_digest_hex(digest: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in digest.as_ref() {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// Read a canonical unsigned LEB128 value. Rejects non-minimal encodings.
fn read_uint(bytes: &[u8], position: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for index in 0..10 {
        let byte = *bytes.get(*position)?;
        *position += 1;
        if index == 9 && (byte & 0xFE) != 0 {
            return None;
        }
        value |= u64::from(byte & 0x7F) << (index * 7);
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 {
                return None;
            }
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_identity_shapes_are_strict() {
        assert!(
            FrfReceiptId::admit_shape(&format!("receipt-run-court-{}", "a".repeat(64))).is_ok()
        );
        assert!(FrfReceiptId::admit_shape("receipt-run-court-short").is_err());
        assert!(
            FrfReceiptId::admit_shape(&format!("receipt-run-court-{}", "A".repeat(64))).is_err()
        );
        assert!(FrfFuzzFindingId::admit_shape(&"b".repeat(64)).is_ok());
        assert!(FrfFuzzFindingId::admit_shape(&"B".repeat(64)).is_err());
        assert!(GemelGceId::admit_shape(&format!("evidence.{}", "c".repeat(64))).is_ok());
        assert!(GemelGceId::admit_shape(&format!("Evidence.{}", "c".repeat(64))).is_err());
    }

    #[test]
    fn canonical_leb128_rejects_non_minimal_forms() {
        let mut position = 0;
        assert_eq!(read_uint(&[0x00], &mut position), Some(0));
        let mut position = 0;
        assert_eq!(read_uint(&[0x80, 0x00], &mut position), None);
        let mut position = 0;
        assert_eq!(read_uint(&[0xAC, 0x02], &mut position), Some(300));
    }

    #[test]
    fn generated_identity_counter_is_always_zero() {
        let report = BridgeReport::new();
        assert_eq!(report.generated_identities, 0);
    }
}
