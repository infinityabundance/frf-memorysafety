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
//! certificates and exact cuts, policy-versioned reconstruction, and the finite
//! three-rule profile with a deterministic local buffer model. Those results are
//! finite-model or bookkeeping results only.
//!
//! # What this build does not establish
//!
//! No live Miri, sanitizer, Kani, Loom, FRF court, FRF-Fuzz, Gemel, or native
//! proof-checker run is performed. Universal Rust soundness and
//! `SAFE_COMPATIBLE` are outside the finite profile and are always withheld.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

pub mod cli;
pub mod closure;
pub mod identity;
pub mod mir;
pub mod model;
pub mod path_effect;
pub mod profile;
pub mod source;
pub mod support;

pub use closure::{compare_inventory, CoverageOutcome, EdgeKey};
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
            "footprint and reference-interval conflict classification types",
            "lifecycle responsibility trace types",
            "detector calibration receipt adjudication types",
            "FRF/FRF-Fuzz/Gemel format-only adapters",
            "fail-closed promotion policy types and reports",
            "manual CLI with SPEC.md §14 exit statuses and explicit NOT_RUN responses",
        ],
        not_run: vec![
            "live Miri/ASan/LSan/TSan execution",
            "live Kani/Loom execution",
            "live FRF court and OpenReceipt verification",
            "live FRF-Fuzz coordinator",
            "live Gemel publication",
            "live OpenSSL-Rust Safe-33 native courts",
            "native proof-checker adapter",
            "MIR/compiler-resolved caller graph and whole-program closure (phase 3.3+)",
            "source- or MIR-extracted alias, footprint, and reference-interval semantics",
            "native C callback observation and retained-pointer lifecycle recording",
            "whole-program or universal alias-compatibility claims",
            "universal safe-interior or SAFE_COMPATIBLE acceptance",
        ],
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
            .any(|item| item.contains("live FRF")));
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
}
