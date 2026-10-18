//! FRF-MemorySafety: candidate-bound assurance for unsafe-to-safe Rust ports.
//!
//! The crate is deliberately `#![forbid(unsafe_code)]`. It examines unsafe
//! target code without implementing unsafe behavior itself.
//!
//! The public API keeps properties, execution modes, evidence origins, and
//! quantifiers separate. See `SPEC.md` for the normative protocol.
//!
//! # What this build establishes
//!
//! This build implements strict canonical encoding, domain-separated
//! identities, the typed claim/obligation model, least-fixed-point support with
//! certificates and exact cuts, policy-versioned reconstruction, the finite
//! three-rule profile with a deterministic local buffer model, a syntax-only
//! source inventory, finite path effects, an optional pinned MIR text
//! adapter, responsibility-token lifecycle and race semantics, and a native
//! event-transcript verifier. Those results are finite-model, textual,
//! transcript, or bookkeeping results only. Phase 6 adds a typed proof
//! manifest with digest-bound proof files, a declared theorem/assumption
//! closure, an admission taxonomy, a separate Rust/FFI
//! implementation-correspondence gate, and a live pinned Coq adapter. Phase
//! 7.1 adds exact provider discovery, opaque native identities, and a
//! fail-closed custody bridge for FRF, FRF-Fuzz, and Gemel. Phase 7.2 adds an
//! opt-in live capture: it executes the explicitly configured provider
//! executables, records exact bytes, executable and loader-map hashes, and two
//! independent runs, and derives identities from those bytes. The default build
//! still does not execute a provider, and the bridge never writes an
//! `OpenReceipt`, finding, GCE object, or GID.
//!
//! # What this build does not establish
//!
//! No live FRF court, FRF-Fuzz, Gemel, or native proof-checker run is
//! performed by the default build. Phase 5.2 adds opt-in live detector adapters for a closed set of
//! checked-in fixtures: pinned Miri, gcc ASan/LSan/TSan, loom, Kani, and an
//! OpenSSL SHA-256 known-answer/signature control. Those adapters run only when
//! `FRF_DETECTOR_LIVE=1` and the instrument is installed; otherwise the typed
//! `NOT_RUN` path is reported. The optional MIR adapter observes unresolved
//! textual edges from an unstable compiler format; it does not resolve symbols,
//! aliases, types, provenance, or whole-program closure. The court verifier
//! consumes a caller-supplied transcript. A test-only harness can compile and
//! execute a closed registry of checked-in C and Rust fixtures with bounded
//! isolation, record their scripted events, and require identical replay; the CLI
//! still cannot run arbitrary native input (`court run` remains `NOT_RUN`).
//! `proof verify --live` invokes only an installed pinned `coqc`; when the
//! checker is absent the command returns `checker_unavailable` (exit 6), and
//! parser success is never proof acceptance. Lean, Isabelle, and other proof
//! checkers are not invoked. The default build performs no live FRF court,
//! FRF-Fuzz replay, or Gemel publication: it validates caller-supplied evidence
//! bundles against exact pins. The opt-in `bridge capture` command and
//! `ci/bridge-gate.sh` execute only the provider executables named on their
//! command line, record the observed execution, and still do not authenticate
//! provenance. Universal Rust soundness and `SAFE_COMPATIBLE` are outside the
//! finite profile and are always withheld.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

pub mod bridge;
pub mod cli;
pub mod closure;
pub mod conversion;
pub mod court;
pub mod detector;
pub mod identity;
pub mod mir;
pub mod model;
#[cfg(all(unix, feature = "native-harness"))]
pub mod native;
pub mod path_effect;
pub mod profile;
pub mod proof;
pub mod source;
pub mod support;

pub use bridge::{
    capture_bundle, native_provider_contracts, provider_availability, verify_bundle_bytes,
    BridgeIntegrity, BridgeNotRun, BridgeOutcome, BridgeRefusal, BridgeReport, BridgeStatus,
    CaptureRequest, CustodyStage, DsoBinding, DsoObject, EvidenceBundle, EvidenceProvenance,
    ExternalObservation, ExternalProvider, FrfFuzzFindingId as BridgeFrfFuzzFindingId,
    FrfReceiptId as BridgeFrfReceiptId, GemelGceId as BridgeGemelGceId, ObservationCapture,
    ObservationSummary, ProviderAvailability, ProviderBuild, ProviderContract, Reexecution,
    ReexecutionRecord, RunRecord, BRIDGE_BUNDLE_SCHEMA, BRIDGE_CLAIM_CEILING, BRIDGE_REPORT_SCHEMA,
    BRIDGE_SPEC, BRIDGE_STATUS_SCHEMA, MAX_BUNDLE_BYTES, MAX_EXTERNAL_OBJECT_BYTES,
    MAX_OBSERVATIONS,
};
pub use closure::{compare_inventory, CoverageOutcome, EdgeKey};
pub use conversion::{
    reuse_evidence, AllowedCBehavior, BoundaryId, BoundaryKind, BoundaryScope, CandidateIdentity,
    ConversionError, ConversionEvidence, ConversionProperty, DependencyClosure, DependencyVersion,
    DiscoveryClaim, DsoIdentity, EvidenceRequest, FaultRepairRevision, GitCommit,
    LoaderClosureEvidence, MechanismEvidence, MechanismId, NativeWitness, ReuseDecision,
    RevocationReason, Sha256Digest, ToolIdentity, WitnessOrigin, CONVERSION_CLAIM_CEILING,
    CONVERSION_SPEC, MAX_OPAQUE_ID_BYTES,
};
pub use court::{
    parse_transcript, verify_transcript, verify_transcript_json, BorrowKind, CallbackOutcome,
    CaseLegality, CourtError, CourtErrorCategory, CourtReport, Event, Finding, FindingClass,
    LibraryVersion, NativeEventTranscript, ProviderUnknown, RaceWitness, RecordingMetadata,
    SyncEdge, ThreadTrace, TranscriptOrigin, TranscriptOutcome, TranscriptProvenance,
    TranscriptRequirements, COURT_CLAIM_CEILING, COURT_REPORT_SCHEMA, COURT_SPEC, MAX_FINDINGS,
    MAX_OBJECTS, MAX_SYNC_EDGES, MAX_THREADS, MAX_TRANSCRIPT_EVENTS,
    NATIVE_EVENT_TRANSCRIPT_SCHEMA,
};
pub use detector::{
    evaluate_calibration, evaluate_calibration_json, parse_evidence, BuildIdentity,
    CalibrationCase, CalibrationOutcome, CalibrationRefusal, CalibrationRefusalCode,
    CalibrationReport, CalibrationRole, CalibrationScore, CaptureStream, CapturedStream,
    CaseProvenance, ControlStatus, DetectorError, DetectorErrorCategory, DetectorEvidence,
    DetectorIdentity, DetectorOrigin, ObservedFinding, RawCapture, RefusalSeverity,
    CALIBRATION_CLAIM_CEILING, CALIBRATION_REPORT_SCHEMA, DETECTOR_EVIDENCE_SCHEMA, DETECTOR_SPEC,
    MAX_ARGV, MAX_CALIBRATION_CASES, MAX_CAPTURE_BYTES, MAX_DURATION_MS, MAX_ENABLEMENT, MAX_FLAGS,
    MAX_IDENTITY_BYTES,
};
pub use identity::{
    canonical_bytes, digest_bytes, digest_value, parse_strict, require_canonical, IdentityDomain,
    IdentityError, MsId, CANONICAL_SCHEMA,
};
pub use mir::{
    parse_mir_text, MirAdapter, MirCallEdge, MirCalleeForm, MirDereference, MirDrop, MirDropKind,
    MirError, MirErrorCategory, MirFunction, MirLimits, MirNotRun, MirNotRunReason, MirObservation,
    MirProvenance, MirResolution, MirRunStatus, MirScanOutcome, MirStorageKind, MirStorageMarker,
    MirSummary, MirUnknown, MIR_CLAIM_CEILING, MIR_EDITION, MIR_NOT_RUN_SCHEMA,
    MIR_OBSERVATION_SCHEMA, MIR_SPEC, MIR_TOOLCHAIN,
};
pub use model::{
    ClaimAxis, ClaimKey, ClaimRecord, ClosureState, DetectorKind, DetectorOutcome, EpistemicStatus,
    EvidenceRef, ExecutionMode, FrfReceiptId, FuzzContentId, GemelGid, Hazard, Obligation,
    ObligationState, OutcomeCategory, PremiseKind, Property, Quantifier, ResidualClass,
    ReviewRecord, ScopeAnchors, TrustPremise,
};
pub use path_effect::{
    analyze, analyze_inventory, path_input_from_inventory, validate_input, AccessMode, AliasDecl,
    AliasKind, ByteRange, CallbackBehavior, CallbackDecl, EventKind, EventRef, Footprint,
    FootprintKind, ObjectDecl, PathEffectsInput, PathError, PathErrorCategory, PathEvent,
    PathReport, PathUnknown, ProviderBehavior, ProviderDecl, QualifiedOutcome, QualifiedStatus,
    ReferenceIntervalDecl, MAX_OUTCOMES, MAX_PAIR_CHECKS, MAX_PATH_EVENTS,
    PATH_EFFECT_CLAIM_CEILING, PATH_EFFECT_INPUT_SCHEMA, PATH_EFFECT_REPORT_SCHEMA,
    PATH_EFFECT_SPEC,
};
pub use profile::{
    evaluate_profile, evaluate_profile_json, local_buffer_bundle, local_buffer_claims,
    local_buffer_records, ArtifactBinding, BufferVariant, ClaimDisposition, ClaimVerdict,
    CoverageEvidence, EnumerationEvidence, EvidenceOrigin, FiniteCase, Observation, ProfileBundle,
    ProfileClaim, ProfileEvaluation, ProfilePolicy, ProfileRefusal, ProfileRefusalKind,
    ProfileRule, BUFFER_MODEL_ID, BUFFER_RECORD_COUNT, CLAIMS_PER_VARIANT, PROFILE_SCHEMA,
    PROFILE_SPEC, SCENARIOS_PER_VARIANT, UNIVERSAL_SOUNDNESS,
};
pub use proof::{
    evaluate_admission, evaluate_correspondence, parse_manifest, verify_manifest_bytes,
    AcceptanceBasis, AdmissionRecord, AdmissionReport, AdmissionStatus, AdmissionTheorem,
    Assumption, AssumptionKind, AssumptionReport, AssumptionStatus, BindingEvidence,
    CheckerContext, CheckerIdentity, CheckerKind, CheckerRun, ClosureDeclaration,
    CorrespondenceEvidence, CorrespondenceEvidenceKind, CorrespondenceReport, FfiBinding,
    ForbiddenFinding, GateStatus, ImplementationBinding, LocalDependency, ProofDigest, ProofError,
    ProofErrorCategory, ProofFile, ProofFileRole, ProofManifest, ProofOrigin, ProofOutcome,
    ProofReport, ScannedFile, SourceInventoryRef, SymbolBinding, SymbolKind, SymbolReport,
    TheoremBinding, TheoremScope, Transition, TransitionKind, FORBIDDEN_ADMISSION_TOKENS,
    MAX_ASSUMPTIONS, MAX_CLOSURE_THEOREMS, MAX_CORRESPONDENCE_EVIDENCE, MAX_FILE_BYTES,
    MAX_PROOF_FILES, MAX_SYMBOL_BINDINGS, MAX_TRANSITIONS, PROOF_CLAIM_CEILING,
    PROOF_MANIFEST_SCHEMA, PROOF_REPORT_SCHEMA, PROOF_SPEC, REQUIRED_REENTRANT_TRANSITION,
};
pub use source::{
    scan_source, scan_source_default, FindingKind, ScanLimits, SourceError, SourceErrorCategory,
    SourceFileRecord, SourceFileRole, SourceFinding, SourceInventory, SourceSummary, SourceUnknown,
    UnknownKind, SOURCE_INVENTORY_CLAIM_CEILING, SOURCE_INVENTORY_SCHEMA, SOURCE_INVENTORY_SPEC,
};
pub use support::{
    certificates, evaluate, exact_cut, explain, noninterference, reconstruct_recorded_verdict,
    reconstruct_under_policy, HistoricVerdict, NonInterferenceReport, RuleSystem, SupportPolicy,
    SupportResult, SupportState,
};

/// Crate version from Cargo metadata.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Capability declaration for this build. External integrations are reported
/// honestly; no unavailable engine is described as live.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Capabilities {
    /// Crate version.
    pub version: &'static str,
    /// Canonical encoding identifier.
    pub canonical_schema: &'static str,
    /// Stable core evaluators implemented in this crate.
    pub implemented: Vec<&'static str>,
    /// Features that require an unavailable external executable or service.
    pub not_run: Vec<&'static str>,
    /// Per-detector runtime availability. This is an installation observation,
    /// not a sensitivity or specificity claim.
    pub detectors: Vec<crate::detector::DetectorAvailability>,
    /// Per-checker runtime availability. This is an installation observation,
    /// not a proof or soundness claim.
    pub checkers: Vec<crate::proof::CheckerAvailability>,
    /// This crate never emits FRF `OpenReceipt`s or Gemel GIDs.
    pub external_authorities: Vec<&'static str>,
}

/// Return the capability matrix for this build.
#[must_use]
pub fn capabilities() -> Capabilities {
    Capabilities {
        version: VERSION,
        canonical_schema: CANONICAL_SCHEMA,
        implemented: vec![
            "strict canonical encoding and domain-separated identities",
            "typed claim, obligation, hazard, and execution-mode model",
            "least-fixed-point support, challenged premises, all-node certificates, exact cuts",
            "fixed-rule cuts, recorded historical verdicts, noninterference witnesses",
            "policy-versioned verdict reconstruction and policy-substitution detection",
            "§12.4 coverage, policy, and alternative-support acceptance cases",
            "paper-original §12.4 fixtures transcribed with recorded source digests",
            "independent finite-domain fixed-point, certificate, and exact-cut oracle",
            "CLI policy custody for evaluate and explain",
            "finite three-rule semantic profile (enumeration, restriction, conjunction)",
            "deterministic local buffer model: 24 records, 5 claims per variant",
            "named finite-profile refusal checks with deny_unknown_fields",
            "bounded syntax-only Rust source inventory with pinned syn 2.x full/visit",
            "source scan limits, explicit unknowns, symlink refusal, and canonical JSON",
            "finite explicit-input path effects: exact/descendant/top aliases and footprints",
            "typed observed-conflict, omission, not-falsified, and finite-compatible outcomes",
            "C callback retention, deferral, after-free, and foreign/provider uncertainty",
            "path analyze CLI over explicit input or a Phase 3.1 source inventory",
            "optional pinned MIR adapter (nightly-2025-02-20) with bounded, shell-free invocation",
            "conservative MIR text parser: functions, unresolved call edges, dereferences, storage/lifetime markers, drops, and unknowns",
            "mir scan CLI with typed NOT_RUN and SPEC.md §14 exit status 6",
            "footprint and reference-interval conflict classification types",
            "responsibility tokens: create, transfer, borrow, reborrow, escape, reallocate, free, use, callback, poison, and abort transitions",
            "generation bumps and stale-token detection after reallocation or free",
            "per-thread event order with explicit synchronizes-with edges and vector-clock race detection",
            "atomic-access modeling and atomic-versus-non-atomic conflict rules",
            "native event-transcript verifier with seeded skipped-event and fictitious-completeness rejection",
            "court verify CLI with typed outcomes and SPEC.md §14 exit statuses",
            "test-only isolated native harness over a closed registry of checked-in C and Rust fixtures",
            "native event capture with cleared environment, process group, rlimits, bounded output, digests, and identical-replay requirement",
            "typed detector evidence: identity, bounded capture, provenance, known-bad and known-good cases",
            "detector calibration adjudication refusing dead, misconfigured, harmless, mock-provider, and fake-marker evidence",
            "detector calibrate FILE [--json] canonical calibration reports with SPEC.md section 14 exit statuses",
            "opt-in live detector adapters over closed checked-in fixtures: Miri, ASan, LSan, TSan, loom, Kani, and OpenSSL SHA-256/signature controls",
            "live detector evidence with real stdout/stderr capture, digests, tool versions, separate build identities, and typed NOT_RUN",
            "detector calibrate --live --detector KIND [--json] with per-detector availability",
            "typed proof manifest with canonical JSON, exact checker identity, digest-bound proof files, and finite theorem scope",
            "theorem and assumption closure with local dependencies, stdlib allowlist, and named justified hypotheses",
            "lexical rejection of Admitted, admit, sorry, Axiom, Parameter, and Conjecture inside the reachable proof closure",
            "admission taxonomy: accepted_within_scope, rejected_assumption, rejected_unrelated, rejected_unchecked_implementation, rejected_missing_transition, checker_unavailable, and checker_failed",
            "separate Rust/FFI implementation-correspondence gate over a Phase 3.1 source inventory or explicit digest-bound binding evidence",
            "checked FFI wrappers and mandatory reentrant-callback transition enumeration",
            "proof verify MANIFEST [--json] with checker_unavailable (exit 6) when no live checker is configured",
            "live Coq checker adapter with explicit argv, private 0700 staging, cleared environment, bounded time/output, executable digest, and node-locked kind/version/executable",
            "proof verify MANIFEST --live [--json] compiling digest-bound proof files in order and binding a completed authentic run to CheckerContext::Recorded",
            "checker-reported theorem statuses from Coq Print Assumptions; only Closed under the global context is treated as proved",
            "exact FRF, FRF-Fuzz, and Gemel provider discovery with pinned commits and schema tokens",
            "opaque FRF receipt, FRF-Fuzz finding, and Gemel GCE/GID identities with private fields and no public string constructor",
            "custody pipeline discover -> reconstruct -> native_confirm -> frf_receipt -> gemel_custody with typed NOT_RUN and refusal reasons",
            "fail-closed bridge verification of external bytes, schemas, digests, candidate identity, provenance, DSO binding, and re-execution",
            "bridge verify FILE [--json], bridge capture OUT ... [--json], and bridge status [--json] with SPEC.md section 14 exit statuses",
            "opt-in live FRF-Fuzz -> FRF court/exact replay/OpenReceipt -> Gemel evidence/GID chain in ci/bridge-gate.sh, with actual loader-map closure and two independent runs per provider",
            "typed conversion-court bookkeeping for owner, allocator, and callback boundaries; evidence binds property, candidate, boundary, native witness provenance, loader closure, fault/repaired revisions, and dependency versions",
            "live conversion capture from exact files with authentic-native provenance, computed source/DSO/tool/loader digests, and typed NOT_RUN when the capture environment is absent",
            "conversion evidence reuse revokes on property, candidate, boundary, dependency, tool, loader, revision, provenance, witness command/output/mechanism, or DSO-byte change",
            "live OpenSSL-Rust up_ref overflow witness (28c9e34) and checked-add repair (1d9c335) with curl 8.22.0 TLS1.3 positive/negative and candidate loader closure in ci/conversion-gate.sh",
            "synthetic seeded witnesses are rejected when presented as organic discoveries, and unconfirmed mechanisms are rejected",
            "FRF/FRF-Fuzz/Gemel format-only adapters",
            "fail-closed promotion policy types and reports",
            "manual CLI with SPEC.md §14 exit statuses and explicit NOT_RUN responses",
        ],
        not_run: vec![
            "live Miri/ASan/LSan/TSan/Loom/Kani/crypto detectors are NOT_RUN unless installed and FRF_DETECTOR_LIVE=1; see detectors[] for runtime availability",
            "live detector execution over arbitrary or caller-supplied programs (closed checked-in fixtures only)",
            "live Lean/Isabelle proof-checker invocation; only the pinned Coq adapter is implemented",
            "proof acceptance from manifest parsing alone; a live checker run is required for accepted_within_scope",
            "live Coq proof checking when coqc is absent; proof verify --live reports checker_unavailable (exit 6)",
            "arbitrary native C/Rust event recording and `court run` over caller-supplied programs",
            "real-scheduler concurrency observation and native callback tracing beyond the checked-in fixtures",
            "live FRF, FRF-Fuzz, or Gemel execution in the default ci/gate.sh path; the default gate asserts typed NOT_RUN, and ci/bridge-gate.sh is the opt-in live path",
            "authenticated provenance for bridge evidence; authentic_native is a recorded, digest-checked execution label, not a signature or trust root",
            "full FRF semantic conformance and full Gemel evidence-schema conformance beyond the bridge's checked fields",
            "live OpenSSL-Rust tests and consumer replay in the default ci/gate.sh path; full Safe-33 cohort replay, all owner/allocator/callback cases, and organic vulnerability discovery; the live gate covers one up_ref boundary and the curl workload",
            "memory-safety, compatibility, or SAFE_COMPATIBLE claims beyond the typed evidence for that boundary and workflow",
            "live consumer (nginx/HAProxy/Redis/OpenSSH) replay against a newly built candidate",
            "reuse across a changed OpenSSL-Rust candidate, boundary, dependency, toolchain, loader, revision, provenance, or witness byte; those changes are typed revocations, not continued reuse",
            "live proof checking of a theorem outside the manifest's declared finite scope",
            "semantic proof of the implementation-correspondence evidence; the correspondence gate remains an independent digest-bound review",
            "MIR edges: available only when pinned nightly-2025-02-20 is present; otherwise NOT_RUN (exit 6)",
            "source- or MIR-extracted alias, footprint, and reference-interval semantics",
            "native C callback observation and retained-pointer lifecycle recording",
            "whole-program or universal alias-compatibility claims",
            "universal safe-interior or SAFE_COMPATIBLE acceptance",
        ],
        #[cfg(unix)]
        detectors: detector::live::availability(),
        #[cfg(not(unix))]
        detectors: Vec::new(),
        checkers: proof::checker_availability(),
        external_authorities: vec![
            "FRF remains the only FRF receipt producer",
            "FRF-Fuzz remains the only BLAKE3 finding producer",
            "Gemel remains the only GCE/GID producer",
            "openssl-rs remains the authority for its own source state",
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_do_not_claim_live_external_runs() {
        let capabilities = capabilities();
        assert!(capabilities
            .not_run
            .iter()
            .any(|item| item.contains("Miri")));
        assert!(!capabilities
            .implemented
            .iter()
            .any(|item| item.contains("live FRF") && !item.contains("opt-in")));
        assert!(capabilities.implemented.iter().any(
            |item| item.contains("opt-in live FRF-Fuzz") && item.contains("ci/bridge-gate.sh")
        ));
        assert!(capabilities
            .not_run
            .iter()
            .any(|item| item.contains("default ci/gate.sh")));
        assert!(capabilities
            .not_run
            .iter()
            .any(|item| item.contains("universal")));
    }

    #[test]
    fn profile_capability_is_advertised() {
        let capabilities = capabilities();
        assert!(capabilities
            .implemented
            .iter()
            .any(|item| item.contains("finite three-rule")));
    }

    #[test]
    fn proof_capability_advertises_the_live_adapter_and_availability() {
        let capabilities = capabilities();
        assert!(capabilities
            .implemented
            .iter()
            .any(|item| item.contains("proof manifest")));
        assert!(capabilities
            .implemented
            .iter()
            .any(|item| item.contains("live Coq checker adapter")));
        assert!(capabilities
            .checkers
            .iter()
            .any(|checker| checker.id == "coq"));
    }
}
