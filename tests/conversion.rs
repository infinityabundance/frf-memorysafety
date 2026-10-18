//! Phase 8.1 conversion-court evidence-model tests.
//!
//! Every fixture in this file is explicitly synthetic. It exercises the
//! bookkeeping rules, not an OpenSSL-Rust discovery. No test claims an organic
//! vulnerability.

use std::collections::BTreeSet;

use frf_memorysafety::conversion::{
    reuse_evidence, AllowedCBehavior, BoundaryId, BoundaryKind, BoundaryScope, CandidateIdentity,
    ConversionError, ConversionEvidence, ConversionProperty, DependencyClosure, DependencyVersion,
    DiscoveryClaim, DsoIdentity, EvidenceRequest, FaultRepairRevision, GitCommit,
    LoaderClosureEvidence, MechanismEvidence, MechanismId, NativeWitness, ReuseDecision,
    RevocationReason, Sha256Digest, ToolIdentity, WitnessOrigin,
};

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
