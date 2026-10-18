//! Phase 8 conversion-court evidence-model tests.
//!
//! The fixtures in the first half of this file are explicitly synthetic. They
//! exercise the bookkeeping rules, not an OpenSSL-Rust discovery. The live
//! capture tests read a caller-provided capture directory when
//! [`CONVERSION_CAPTURE_ENV`] is set and otherwise assert the typed `NOT_RUN`
//! path. No test claims an organic vulnerability.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use frf_memorysafety::conversion::{
    capture_live, capture_live_from_env, reuse_evidence, AllowedCBehavior, BoundaryId,
    BoundaryKind, BoundaryScope, CandidateIdentity, CaptureDependency, CaptureDso, CaptureSpec,
    ConversionCaptureOutcome, ConversionError, ConversionEvidence, ConversionProperty,
    DependencyClosure, DependencyVersion, DiscoveryClaim, DsoIdentity, EvidenceRequest,
    FaultRepairRevision, GitCommit, LoaderClosureEvidence, MechanismEvidence, MechanismId,
    NativeWitness, ReuseDecision, RevocationReason, Sha256Digest, ToolIdentity, WitnessOrigin,
    CONVERSION_CAPTURE_ENV, CONVERSION_CAPTURE_SPEC_FILE, CONVERSION_REQUIRE_LIVE_ENV,
};

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn digest(byte: char) -> Sha256Digest {
    Sha256Digest::parse(&std::iter::repeat(byte).take(64).collect::<String>()).unwrap()
}

fn commit(byte: char) -> GitCommit {
    GitCommit::parse(&std::iter::repeat(byte).take(40).collect::<String>()).unwrap()
}

fn tool(version: &str) -> ToolIdentity {
    ToolIdentity {
        name: "cargo test".to_owned(),
        version: version.to_owned(),
        executable_sha256: digest('e'),
    }
}

fn dso(soname: &str, byte: char) -> DsoIdentity {
    DsoIdentity {
        soname: soname.to_owned(),
        sha256: digest(byte),
        symbol_versions: vec!["OPENSSL_3.0.0".to_owned(), "OPENSSL_3.6.0".to_owned()],
        dt_needed: vec!["libc.so.6".to_owned()],
    }
}

fn loader(trace: char) -> LoaderClosureEvidence {
    LoaderClosureEvidence {
        loader: ToolIdentity {
            name: "readelf".to_owned(),
            version: "2.44".to_owned(),
            executable_sha256: digest('d'),
        },
        loaded: vec![dso("libcrypto.so.3", '1'), dso("libssl.so.3", '2')],
        all_under_candidate_prefix: true,
        resolved_symbols: 6_499,
        unresolved_symbols: 0,
        trace_sha256: digest(trace),
    }
}

fn dependency(name: &str, version: &str, byte: char) -> DependencyVersion {
    DependencyVersion {
        name: name.to_owned(),
        version: version.to_owned(),
        sha256: digest(byte),
    }
}

fn dependencies(version: &str) -> DependencyClosure {
    DependencyClosure {
        toolchain: dependency("rust", version, '3'),
        loader: dependency("ld-linux-x86-64", "2.44", '4'),
        authority: dependency("openssl", "3.6.4", '5'),
        libraries: vec![dependency("libgcc_s", "14.2.0", '6')],
    }
}

fn boundary(kind: BoundaryKind, id: &str) -> BoundaryScope {
    let allowed = match kind {
        BoundaryKind::Owner => BTreeSet::from([
            AllowedCBehavior::OwnerZeroValid,
            AllowedCBehavior::OwnerOverFreeDefinedNoOp,
        ]),
        BoundaryKind::Allocator => BTreeSet::from([
            AllowedCBehavior::AllocatorRefusalContained,
            AllowedCBehavior::ReallocFailurePreservesOwner,
        ]),
        BoundaryKind::Callback => BTreeSet::from([
            AllowedCBehavior::CallbackReentryDefinedNoOp,
            AllowedCBehavior::CallbackRefusalContained,
        ]),
    };
    BoundaryScope {
        boundary_id: BoundaryId::parse(id).unwrap(),
        kind,
        allowed,
    }
}

fn witness(origin: WitnessOrigin, discovery: DiscoveryClaim, confirmed: bool) -> NativeWitness {
    NativeWitness {
        origin,
        discovery,
        tool: tool("1.98.1"),
        command_sha256: digest('7'),
        output_sha256: digest('8'),
        mechanism: MechanismEvidence {
            mechanism_id: MechanismId::parse("callback-reenter-k").unwrap(),
            independently_confirmed: confirmed,
            confirmation_sha256: digest('9'),
        },
        loader: loader('a'),
    }
}

fn revisions() -> FaultRepairRevision {
    FaultRepairRevision {
        fault: commit('b'),
        repaired: commit('c'),
        changed_paths: BTreeSet::from(["src/runtime/refcount.rs".to_owned()]),
    }
}

fn evidence() -> ConversionEvidence {
    ConversionEvidence {
        property: ConversionProperty::OwnerContractEstablished,
        candidate: CandidateIdentity {
            revision: commit('a'),
            source_sha256: digest('b'),
            artifact_sha256: digest('c'),
        },
        boundary: boundary(BoundaryKind::Owner, "MS-SSL-SSL-0001"),
        // Explicitly synthetic: this fixture exercises the evidence model only.
        witness: witness(
            WitnessOrigin::SyntheticSeeded,
            DiscoveryClaim::SyntheticFixture,
            true,
        ),
        revisions: revisions(),
        dependencies: dependencies("1.98.1"),
    }
}

fn reasons(decision: ReuseDecision) -> Vec<RevocationReason> {
    let ReuseDecision::Revoked { reasons } = decision else {
        panic!("expected a revocation");
    };
    reasons
}

#[test]
fn reuses_while_every_bound_coordinate_is_unchanged() {
    let prior = evidence();
    let request = EvidenceRequest::from_evidence(&prior);
    assert_eq!(reuse_evidence(&prior, &request), ReuseDecision::Reusable);
}

#[test]
fn revokes_on_property_change() {
    let prior = evidence();
    let mut request = EvidenceRequest::from_evidence(&prior);
    request.property = ConversionProperty::CallbackReentryRejected;
    request.boundary = boundary(BoundaryKind::Callback, "MS-SSL-CALLBACK-0002");
    let reasons = reasons(reuse_evidence(&prior, &request));
    assert!(reasons.contains(&RevocationReason::PropertyChanged));
}

#[test]
fn revokes_on_candidate_revision_change() {
    let prior = evidence();
    let mut request = EvidenceRequest::from_evidence(&prior);
    request.candidate.revision = commit('d');
    assert_eq!(
        reasons(reuse_evidence(&prior, &request)),
        vec![RevocationReason::CandidateRevisionChanged]
    );
}

#[test]
fn revokes_on_candidate_source_and_artifact_change() {
    let prior = evidence();
    let mut request = EvidenceRequest::from_evidence(&prior);
    request.candidate.source_sha256 = digest('e');
    request.candidate.artifact_sha256 = digest('f');
    assert_eq!(
        reasons(reuse_evidence(&prior, &request)),
        vec![
            RevocationReason::CandidateSourceChanged,
            RevocationReason::CandidateArtifactChanged,
        ]
    );
}

#[test]
fn revokes_on_boundary_change() {
    let prior = evidence();
    let mut request = EvidenceRequest::from_evidence(&prior);
    request.boundary = boundary(BoundaryKind::Owner, "MS-SSL-SSL-9999");
    assert_eq!(
        reasons(reuse_evidence(&prior, &request)),
        vec![RevocationReason::BoundaryChanged]
    );
}

#[test]
fn revokes_on_dependency_version_change() {
    let prior = evidence();
    let mut request = EvidenceRequest::from_evidence(&prior);
    request.dependencies = dependencies("1.98.2");
    assert_eq!(
        reasons(reuse_evidence(&prior, &request)),
        vec![RevocationReason::DependencyVersionChanged]
    );
}

#[test]
fn revokes_on_tool_change() {
    let prior = evidence();
    let mut request = EvidenceRequest::from_evidence(&prior);
    request.tool = tool("1.98.2");
    assert_eq!(
        reasons(reuse_evidence(&prior, &request)),
        vec![RevocationReason::ToolChanged]
    );
}

#[test]
fn revokes_on_loader_closure_change() {
    let prior = evidence();
    let mut request = EvidenceRequest::from_evidence(&prior);
    request.loader = loader('b');
    assert_eq!(
        reasons(reuse_evidence(&prior, &request)),
        vec![RevocationReason::LoaderClosureChanged]
    );
}

#[test]
fn revokes_on_revision_change() {
    let prior = evidence();
    let mut request = EvidenceRequest::from_evidence(&prior);
    request.revisions.repaired = commit('d');
    assert_eq!(
        reasons(reuse_evidence(&prior, &request)),
        vec![RevocationReason::RevisionChanged]
    );
}

#[test]
fn rejects_a_synthetic_seeded_defect_presented_as_organic() {
    let mut record = evidence();
    record.witness = witness(
        WitnessOrigin::SyntheticSeeded,
        DiscoveryClaim::OrganicDiscovery,
        true,
    );
    assert_eq!(
        record.validate(),
        Err(ConversionError::SyntheticWitnessClaimedOrganic)
    );
}

#[test]
fn rejects_a_substitute_witness_presented_as_organic() {
    let mut record = evidence();
    record.witness = witness(
        WitnessOrigin::Substitute,
        DiscoveryClaim::OrganicDiscovery,
        true,
    );
    assert_eq!(
        record.validate(),
        Err(ConversionError::SubstituteWitnessClaimedOrganic)
    );
}

#[test]
fn rejects_a_witness_without_independent_mechanism() {
    let mut record = evidence();
    record.witness = witness(
        WitnessOrigin::AuthenticNative,
        DiscoveryClaim::OrganicDiscovery,
        false,
    );
    assert_eq!(
        record.validate(),
        Err(ConversionError::UnconfirmedMechanism)
    );
}

#[test]
fn accepts_an_authentic_organic_witness_with_confirmed_mechanism() {
    let mut record = evidence();
    record.witness = witness(
        WitnessOrigin::AuthenticNative,
        DiscoveryClaim::OrganicDiscovery,
        true,
    );
    assert_eq!(record.validate(), Ok(()));
}

#[test]
fn accepts_an_explicitly_labeled_synthetic_fixture() {
    let record = evidence();
    assert_eq!(record.witness.discovery, DiscoveryClaim::SyntheticFixture);
    assert_eq!(record.validate(), Ok(()));
}

#[test]
fn rejects_an_open_loader_closure() {
    let mut record = evidence();
    record.witness.loader.unresolved_symbols = 1;
    assert!(matches!(
        record.validate(),
        Err(ConversionError::LoaderNotClosed(_))
    ));
}

#[test]
fn rejects_a_loader_outside_the_candidate_prefix() {
    let mut record = evidence();
    record.witness.loader.all_under_candidate_prefix = false;
    assert!(matches!(
        record.validate(),
        Err(ConversionError::LoaderNotClosed(_))
    ));
}

#[test]
fn rejects_an_identical_fault_and_repaired_revision() {
    let mut record = evidence();
    record.revisions.repaired = record.revisions.fault.clone();
    assert_eq!(record.validate(), Err(ConversionError::SameRevision));
}

#[test]
fn rejects_a_property_boundary_mismatch() {
    let mut record = evidence();
    record.property = ConversionProperty::CallbackReentryRejected;
    assert_eq!(
        record.validate(),
        Err(ConversionError::PropertyKindMismatch {
            property: ConversionProperty::CallbackReentryRejected,
            expected: BoundaryKind::Callback,
            actual: BoundaryKind::Owner,
        })
    );
}

#[test]
fn evidence_identity_is_deterministic_and_candidate_bound() {
    let record = evidence();
    assert_eq!(record.identity().unwrap(), evidence().identity().unwrap());
    let mut changed = evidence();
    changed.candidate.revision = commit('d');
    assert_ne!(record.identity().unwrap(), changed.identity().unwrap());
}

#[test]
fn invalid_prior_or_current_records_fail_closed() {
    let prior = evidence();
    let mut request = EvidenceRequest::from_evidence(&prior);
    request.dependencies = dependencies("1.98.2");
    assert_eq!(
        reasons(reuse_evidence(&prior, &request)),
        vec![RevocationReason::DependencyVersionChanged]
    );

    let mut invalid = evidence();
    invalid.witness.mechanism.independently_confirmed = false;
    let request = EvidenceRequest::from_evidence(&invalid);
    assert_eq!(
        reasons(reuse_evidence(&invalid, &request)),
        vec![RevocationReason::PriorEvidenceInvalid]
    );
}

fn temp_capture_dir() -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "frf-p82-capture-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(base.join("lib")).unwrap();
    base
}

fn write_bytes(root: &Path, name: &str, bytes: &[u8]) {
    fs::write(root.join(name), bytes).unwrap();
}

fn live_spec(root: &Path) -> CaptureSpec {
    CaptureSpec {
        property: ConversionProperty::OwnerContractEstablished,
        candidate_revision: commit('a'),
        candidate_source_manifest: PathBuf::from("source.manifest"),
        boundary_id: BoundaryId::parse("openssl-rs:runtime::refcount::up_ref").unwrap(),
        boundary_kind: BoundaryKind::Owner,
        allowed: BTreeSet::from([
            AllowedCBehavior::OwnerUpRefRefusesRetired,
            AllowedCBehavior::OwnerOverFreeDefinedNoOp,
        ]),
        origin: WitnessOrigin::AuthenticNative,
        discovery: DiscoveryClaim::NoDiscoveryClaim,
        tool_name: "cargo test".to_owned(),
        tool_version: "1.98.1".to_owned(),
        tool_executable: PathBuf::from("tool.bin"),
        command: PathBuf::from("command.txt"),
        output: PathBuf::from("output.txt"),
        mechanism_id: MechanismId::parse("checked-add-overflow-refusal").unwrap(),
        mechanism_confirmed: true,
        mechanism_confirmation: PathBuf::from("mechanism.txt"),
        loader_tool_name: "ldd".to_owned(),
        loader_tool_version: "2.40".to_owned(),
        loader_executable: PathBuf::from("loader.bin"),
        loader_trace: PathBuf::from("loader.trace"),
        candidate_prefix: root.to_path_buf(),
        resolved_symbols: 6_499,
        unresolved_symbols: 0,
        dsos: vec![
            CaptureDso {
                soname: "libssl.so.3".to_owned(),
                path: PathBuf::from("lib/libssl.so.3"),
                loaded_path: root.join("lib/libssl.so.3"),
                symbol_versions: vec!["OPENSSL_3.0.0".to_owned(), "OPENSSL_3.6.0".to_owned()],
                dt_needed: vec!["libcrypto.so.3".to_owned(), "libc.so.6".to_owned()],
            },
            CaptureDso {
                soname: "libcrypto.so.3".to_owned(),
                path: PathBuf::from("lib/libcrypto.so.3"),
                loaded_path: root.join("lib/libcrypto.so.3"),
                symbol_versions: vec!["OPENSSL_3.0.0".to_owned(), "OPENSSL_3.6.0".to_owned()],
                dt_needed: vec!["libc.so.6".to_owned()],
            },
        ],
        fault: commit('b'),
        repaired: commit('c'),
        changed_paths: BTreeSet::from(["src/runtime/refcount.rs".to_owned()]),
        toolchain: CaptureDependency {
            name: "rust".to_owned(),
            version: "1.98.1".to_owned(),
            path: PathBuf::from("dep-rust.txt"),
        },
        dynamic_loader: CaptureDependency {
            name: "ld-linux-x86-64".to_owned(),
            version: "2.40".to_owned(),
            path: PathBuf::from("dep-ld.txt"),
        },
        authority: CaptureDependency {
            name: "openssl".to_owned(),
            version: "3.6.4".to_owned(),
            path: PathBuf::from("dep-openssl.txt"),
        },
        libraries: vec![CaptureDependency {
            name: "libgcc_s".to_owned(),
            version: "14.2.0".to_owned(),
            path: PathBuf::from("dep-libgcc.txt"),
        }],
    }
}

fn write_live_capture(root: &Path, spec: &CaptureSpec) {
    write_bytes(root, "source.manifest", b"source-tree-manifest\n");
    write_bytes(root, "tool.bin", b"tool-executable-bytes");
    write_bytes(
        root,
        "command.txt",
        b"cargo test --lib up_ref_refuses_overflow\n",
    );
    write_bytes(root, "output.txt", b"test result: ok. 1 passed\n");
    write_bytes(
        root,
        "mechanism.txt",
        b"fault panics; overflow-off wraps; repair refuses\n",
    );
    write_bytes(root, "loader.bin", b"loader-executable-bytes");
    write_bytes(
        root,
        "loader.trace",
        b"calling init: candidate/lib/libssl.so.3\n",
    );
    write_bytes(root, "lib/libssl.so.3", b"libssl-bytes");
    write_bytes(root, "lib/libcrypto.so.3", b"libcrypto-bytes");
    write_bytes(root, "dep-rust.txt", b"rustc 1.98.1");
    write_bytes(root, "dep-ld.txt", b"ldd 2.40");
    write_bytes(root, "dep-openssl.txt", b"openssl 3.6.4");
    write_bytes(root, "dep-libgcc.txt", b"libgcc 14.2.0");
    fs::write(
        root.join(CONVERSION_CAPTURE_SPEC_FILE),
        serde_json::to_vec_pretty(spec).unwrap(),
    )
    .unwrap();
}

fn captured_evidence(root: &Path) -> ConversionEvidence {
    match capture_live(root).unwrap() {
        ConversionCaptureOutcome::Captured(evidence) => evidence,
        ConversionCaptureOutcome::NotRun(not_run) => {
            panic!("expected captured evidence: {}", not_run.reason)
        }
    }
}

#[test]
fn live_capture_computes_digests_from_file_bytes() {
    let root = temp_capture_dir();
    write_live_capture(&root, &live_spec(&root));

    let evidence = captured_evidence(&root);
    evidence.validate().unwrap();
    assert_eq!(evidence.witness.origin, WitnessOrigin::AuthenticNative);
    assert_eq!(evidence.witness.discovery, DiscoveryClaim::NoDiscoveryClaim);
    assert_eq!(
        evidence.candidate.source_sha256,
        Sha256Digest::of_bytes(b"source-tree-manifest\n")
    );
    assert_eq!(
        evidence.witness.tool.executable_sha256,
        Sha256Digest::of_bytes(b"tool-executable-bytes")
    );
    assert_eq!(
        evidence.witness.command_sha256,
        Sha256Digest::of_bytes(b"cargo test --lib up_ref_refuses_overflow\n")
    );
    assert_eq!(
        evidence.witness.output_sha256,
        Sha256Digest::of_bytes(b"test result: ok. 1 passed\n")
    );
    assert_eq!(
        evidence.witness.loader.loaded[0].sha256,
        Sha256Digest::of_bytes(b"libssl-bytes")
    );
    assert!(evidence.witness.loader.all_under_candidate_prefix);
    assert_eq!(evidence.witness.loader.resolved_symbols, 6_499);
    assert_eq!(evidence.witness.loader.unresolved_symbols, 0);
}

#[test]
fn live_capture_reuse_is_property_candidate_boundary_dependency_specific() {
    let root = temp_capture_dir();
    write_live_capture(&root, &live_spec(&root));
    let prior = captured_evidence(&root);
    let request = EvidenceRequest::from_evidence(&prior);
    assert_eq!(reuse_evidence(&prior, &request), ReuseDecision::Reusable);

    let mut property = request.clone();
    property.property = ConversionProperty::CallbackReentryRejected;
    property.boundary = boundary(BoundaryKind::Callback, "MS-SSL-CALLBACK-0002");
    let property_reasons = reasons(reuse_evidence(&prior, &property));
    assert!(property_reasons.contains(&RevocationReason::PropertyChanged));

    let mut candidate = request.clone();
    candidate.candidate.revision = commit('d');
    assert_eq!(
        reasons(reuse_evidence(&prior, &candidate)),
        vec![RevocationReason::CandidateRevisionChanged]
    );

    let mut boundary_only = request.clone();
    boundary_only.boundary = boundary(BoundaryKind::Owner, "MS-SSL-SSL-9999");
    assert_eq!(
        reasons(reuse_evidence(&prior, &boundary_only)),
        vec![RevocationReason::BoundaryChanged]
    );

    let mut dependency = request.clone();
    dependency.dependencies = dependencies("1.98.2");
    assert_eq!(
        reasons(reuse_evidence(&prior, &dependency)),
        vec![RevocationReason::DependencyVersionChanged]
    );

    println!(
        "LIVE_REUSE_REPORT reusable=1 property={} candidate=1 boundary=1 dependency=1",
        usize::from(property_reasons.contains(&RevocationReason::PropertyChanged))
    );
}

#[test]
fn live_capture_revokes_on_witness_and_provenance_change() {
    let root = temp_capture_dir();
    write_live_capture(&root, &live_spec(&root));
    let prior = captured_evidence(&root);

    let mut witness = EvidenceRequest::from_evidence(&prior);
    witness.witness_output_sha256 = digest('f');
    assert_eq!(
        reasons(reuse_evidence(&prior, &witness)),
        vec![RevocationReason::WitnessChanged]
    );

    let mut provenance = EvidenceRequest::from_evidence(&prior);
    provenance.origin = WitnessOrigin::Substitute;
    assert_eq!(
        reasons(reuse_evidence(&prior, &provenance)),
        vec![RevocationReason::ProvenanceChanged]
    );
}

#[test]
fn live_capture_revokes_on_dso_byte_change() {
    let root = temp_capture_dir();
    write_live_capture(&root, &live_spec(&root));
    let prior = captured_evidence(&root);

    write_bytes(&root, "lib/libssl.so.3", b"libssl-bytes-changed");
    let current = captured_evidence(&root);
    let request = EvidenceRequest::from_evidence(&current);
    let reasons = reasons(reuse_evidence(&prior, &request));
    assert!(reasons.contains(&RevocationReason::CandidateArtifactChanged));
    assert!(reasons.contains(&RevocationReason::LoaderClosureChanged));
}

#[test]
fn live_capture_refuses_a_non_authentic_origin() {
    let root = temp_capture_dir();
    let mut spec = live_spec(&root);
    spec.origin = WitnessOrigin::SyntheticSeeded;
    spec.discovery = DiscoveryClaim::SyntheticFixture;
    write_live_capture(&root, &spec);
    assert_eq!(
        capture_live(&root),
        Err(ConversionError::CaptureRequiresAuthenticOrigin)
    );
}

#[test]
fn live_capture_without_a_specification_is_typed_not_run() {
    let root = temp_capture_dir();
    let outcome = capture_live(&root).unwrap();
    let ConversionCaptureOutcome::NotRun(not_run) = outcome else {
        panic!("expected a typed NOT_RUN");
    };
    assert!(not_run.is_not_run());
    assert!(not_run.reason.contains(CONVERSION_CAPTURE_SPEC_FILE));
}

#[test]
fn live_capture_from_env_is_typed_not_run_or_captured() {
    match capture_live_from_env().unwrap() {
        ConversionCaptureOutcome::NotRun(not_run) => {
            assert!(not_run.is_not_run());
            assert!(not_run.reason.contains(CONVERSION_CAPTURE_ENV));
            assert!(
                std::env::var_os(CONVERSION_REQUIRE_LIVE_ENV).is_none(),
                "live capture was required but did not run: {}",
                not_run.reason
            );
            println!("LIVE_CAPTURE=not_run reason={}", not_run.reason);
        }
        ConversionCaptureOutcome::Captured(evidence) => {
            evidence.validate().unwrap();
            println!(
                "LIVE_CAPTURE=captured candidate={} property={} boundary={} resolved={} unresolved={}",
                evidence.candidate.revision,
                evidence.property.as_str(),
                evidence.boundary.kind.as_str(),
                evidence.witness.loader.resolved_symbols,
                evidence.witness.loader.unresolved_symbols
            );
        }
    }
}
