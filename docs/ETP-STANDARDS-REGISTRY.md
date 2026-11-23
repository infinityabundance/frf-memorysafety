# ETP standards and research registry

**Registry identifier:** `frf-etp-standards-v1`.
**Status:** started in Phase 10.1.
**Rule:** a standard is listed because it was actually consulted for a named
mechanism. Listing is not compliance, certification, or endorsement. A standard
that informed a design decision confers no semantic proof credit.

The machine-readable schema/vector registry is `schemas/etp/registry.json`. This
document is the human-readable standards registry.

Legend:

- **Adopted** means a concrete mechanism in this repository uses the named idea.
- **Informed** means the design was shaped by the standard but no conformant
  implementation exists.
- **NOT_IMPLEMENTED** means no mechanism exists.
- **NOT_CLAIMED** means the project makes no compliance claim for that standard.

---

## 1. Registry

| ID | Standard or research | Exact version and URL | Adopted mechanism | Property | Implementation location | Assumptions and limitations |
|---|---|---|---|---|---|---|
| S01 | OASIS SARIF | 2.1.0 OASIS Standard, plus Errata 01. <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html> and <https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os.html> | Versioned SARIF 2.1.0 projection and structural verifier for the finite ETP campaign. | Interchange of static-analysis results | **IMPLEMENTED** as `frf-etp.sarif-projection.v1` in `src/sarif.rs`, `etp sarif export`, and `etp sarif verify` | A SARIF document is a report format, not a correctness or security proof. The profile is not a claim of full SARIF schema conformance. No external SARIF consumer is authoritative. |
| S02 | DSSE (Dead Simple Signing Envelope) | v1.0.0. <https://github.com/secure-systems-lab/dsse/blob/v1.0.0/protocol.md> | Versioned DSSE v1 envelope verification over the exact pre-authentication encoding, Ed25519 only. | Envelope integrity and signer identity | **IMPLEMENTED** as the `dsse-v1` profile in `src/etp_auth.rs`, `etp attest verify`, and `evaluation/earned-trust/verify_attestations.py` | A valid signature authenticates a signing key over exact bytes, not the truth of the payload. Key custody is test-only. A local test RFC 3161 token exists in Phase 10.4a and a local test tlog-tiles log exists in Phase 10.4b; neither is external trusted time, public transparency, or external witnessing. |
| S03 | in-toto | Specification v1.0.0. <https://github.com/in-toto/specification/blob/v1.0.0/in-toto-spec.md> | in-toto Statement v1 with separately versioned ETP predicate types for closure, qualification, reproduction, proof admission, consumer closure, findings, and release. | Supply-chain statement and artifact binding | **IMPLEMENTED** for the finite predicate profile in `src/etp_auth.rs` and `schemas/etp/` | The statements are not SLSA build provenance. Semantic evaluation is implemented only for campaign closure; the other predicates parse and authorize but are not semantically supported. |
| S04 | SLSA | v1.0. <https://slsa.dev/spec/v1.0/> | Informed provenance and build-identity coordinates. | Build provenance and tamper resistance levels | **NOT_IMPLEMENTED** | SLSA levels describe build provenance properties, not software correctness, memory safety, or deployment security. No level is claimed. |
| S05 | Sigstore | Sigstore/cosign documentation as consulted in Phase 10.1. <https://docs.sigstore.dev/> | Informed keyless signing and transparency concepts. | Artifact signing and public verifiability | **NOT_IMPLEMENTED** | A Sigstore signature is not a proof of correctness. Identity issuance, trust roots, and policy are external. |
| S06 | Rekor / C2SP transparency log | Rekor v2 line (`sigstore/rekor-tiles` v2.4.2, 2026-11-10); C2SP tlog-tiles v1.0.0, tlog-checkpoint v1.1.0, tlog-cosignature v1.1.0, tlog-witness v1.1.0 (2026-10-07); RFC 6962 (2013). <https://github.com/sigstore/rekor-tiles> and <https://c2sp.org/tlog-tiles> | Local tlog-tiles log, RFC 6962 inclusion and consistency, signed checkpoints, tile reconstruction, anti-rollback, and cross-log rejection. | Append-only local evidence logging with real proofs | **IMPLEMENTED** as the `local-test-tlog-tiles` profile in `src/etp_transparency.rs`, `etp transparency verify`, `etp checkpoint verify`, and `evaluation/earned-trust/verify_transparency.py` | The log is local and test-only. Inclusion is not completeness. Consistency between pinned sizes is not global non-equivocation. A signed checkpoint is not truth. No public log, Rekor v2 submission, monitoring, gossip, or external witnessing is deployed. |
| S17 | `transparency-dev/tessera` | v1.0.4, commit `6bca8e8d5e23c9941f2b8a08f512b373f7131730`, Go 1.24.0. <https://github.com/transparency-dev/tessera/releases/tag/v1.0.4> | Pinned log implementation for the local tlog-tiles profile. | tlog-tiles log sequencing, integration, checkpoint signing, POSIX tiles | **IMPLEMENTED** in `ci/transparency/frf-tlog` and `ci/etp-transparency-gate.sh` | A log implementation is not a public service, a witness, or a monitor. Build and execution are not qualification or certification. No published tessera security advisory was found on 2026-11-22; that is not a security proof. |
| S18 | C2SP tlog-witness and tlog-policy | tlog-witness v1.1.0 (2026-10-07); tlog-policy main (2026-11-17). <https://c2sp.org/tlog-witness> and <https://c2sp.org/tlog-policy> | Informed the administrative-domain, shared-trust, group, and quorum-intersection model. | Witness quorum and fault-independence modelling | **INFORMED** / model only in `src/etp_witness.rs`, `etp witnesses verify` | No witness protocol call is made and no external cosignature is observed. The local-test cosignatures are not external witnesses. `2q - n > f` is a declared assumption, not a theorem. |
| S19 | C2SP tlog-cosignature | v1.1.0 (2026-10-07). <https://c2sp.org/tlog-cosignature> | Ed25519 checkpoint cosignature message and key-id construction for local-test witness controls. | Witness cosignature integrity | **IMPLEMENTED** for local test keys in `src/etp_witness.rs` and `evaluation/earned-trust/verify_transparency.py` | The implementation is Ed25519 only. ML-DSA-44 is not implemented. A valid local-test cosignature is not an external observation. |
| S20 | Execution Witness (Phase 11.2) | Phase 11.2 execution witness protocol; hardened container, C probe compilation, execution capture, independent verification. | Canonical receipt `frf-etp.execution-witness.v1` with source-to-binary correspondence, DSO hashing, loader-closure digest, and six named refusal self-tests. | **IMPLEMENTED** in `evaluation/earned-trust/witness_execution.py`, `evaluation/earned-trust/verify_witness.py`, `ci/etp-witness-gate.sh`, `tests/fixtures/witness/probe.c` | The witness establishes an observed execution of one fixture on one host inside one hardened container. It does not establish authenticity, completeness, or deployment behaviour, and does not prove the crate binary, all DSOs, or all processes. |
| S21 | Bounded information-flow and leakage classification (Phase 12.1) | Informed by S13 (Almeida et al., *Verifying Constant-Time Implementations*, USENIX Security 2016) and the ETP leakage-model coordinate. | Adopted a bounded source/binary information-flow model with value, representation, and metadata classes, a trace model, witness-bound execution-path evidence, and named refusal rules. | Secret erasure, secret-independent branch/address, and constant-time classification under a bounded leakage model | **IMPLEMENTED** as `frf-etp.information-flow.v1` in `schemas/etp/information-flow.v1.schema.json`, `evaluation/earned-trust/information_flow.py`, `evaluation/earned-trust/information-flow/model.json`, and `ci/etp-information-flow-gate.sh` | The model is bounded only; universal quantification is refused. No live timing measurement exists yet (Phase 12.2). A source-level claim is accepted only with an explicit statement that binary behavior is not established. A binary-level claim requires a witness-bound execution path and, for secret-independent properties, a branch-trace digest. Fixed iteration count and absence of detected leakage are refused as evidence. |
| S07 | RFC 3161 Time-Stamp Protocol | RFC 3161 (2001). <https://www.rfc-editor.org/rfc/rfc3161.html> | Versioned timestamp verification over a caller-pinned TSA certificate, with separate imprint, chain, policy, serial, and generation-time dimensions. | Evidence time attestation | **IMPLEMENTED** as a local test profile in `src/etp_time.rs`, `etp time verify`, and `evaluation/earned-trust/verify_time.py` | The committed token is anchored in a local test TSA, not external trusted time. A timestamp authenticates a digest at generation time, not the experiment or its result. TSA trust and clock assumptions remain. |
| S08 | TUF (The Update Framework) | Specification v1.0.31. <https://theupdateframework.github.io/specification/v1.0.31/> | Informed the separation of role, metadata, and revocation. | Secure software update metadata | **NOT_IMPLEMENTED** | TUF protects update metadata under a threat model; it does not prove the updated software is safe or correct. No repository metadata exists. |
| S09 | RTCA DO-178C | DO-178C, Software Considerations in Airborne Systems and Equipment Certification (2011). <https://www.rtca.org/> | Informed the separation of objectives, evidence, and independence in the ETP architecture. | Airborne software assurance | **NOT_IMPLEMENTED**; **NOT_CLAIMED** | The project is not an airborne system and has not performed a DO-178C gap assessment. Objective satisfaction cannot be inferred from this registry. |
| S10 | RTCA DO-330 | DO-330, Software Tool Qualification Considerations (2011). <https://www.rtca.org/> | Informed the distinction between tool execution and tool qualification. | Tool qualification | **NOT_IMPLEMENTED**; **NOT_CLAIMED** | Running a detector or prover is not tool qualification. No tool-qualification evidence exists. |
| S11 | RTCA DO-333 | DO-333, Formal Methods Supplement to DO-178C and DO-278A (2011). <https://www.rtca.org/> | Informed the separation of formal model, proof, assumptions, and implementation correspondence. | Formal-methods assurance | **NOT_IMPLEMENTED**; **NOT_CLAIMED** | The checked Coq theorem is small and finite; it is not a DO-333 formal-methods argument. |
| S12 | seL4 verification methodology | seL4 verification pages and the SOSP 2009 paper, *seL4: Formal Verification of an OS Kernel*. <https://sel4.systems/Info/Verification/> | Informed the separation of functional correctness, security, binary correspondence, and assumptions. | Kernel-level functional correctness and security | **NOT_IMPLEMENTED** as a methodology for this crate | seL4's results depend on a specific formal model, binary verification, and explicit assumptions. No seL4-style refinement proof exists here. |
| S13 | Constant-time and relational verification | Almeida, Barbosa, Barthe, Dupressoir, Emmi, *Verifying Constant-Time Implementations*, USENIX Security 2016. <https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/almeida>; ct-verif <https://github.com/imdea-software/verifying-constant-time>; Jasmin <https://jasmin-lang.org/> | Informed the leakage-model coordinate and the refusal to treat fixed iteration count or a SHA-256 known-answer test as constant-time evidence. Phase 12.2 adds a bounded live timing profile (S22) using callgrind Ir counts as a deterministic proxy. | Secret-independent execution time under a leakage model | **NOT_IMPLEMENTED** | No timing verifier, leakage model implementation, or relational proof exists. The Phase 12.2 timing profile (S22) measures instruction counts under valgrind callgrind for one fixture; it is not a constant-time verifier and does not prove absence of leakage. The OpenSSL control is a known-answer/signature test, not a timing measurement. |
| S14 | Reproducible builds | Reproducible Builds project specification and definition. <https://reproducible-builds.org/specs/> and <https://reproducible-builds.org/docs/definition/> | Adopted a two-build byte-comparison receipt with separate reproducibility dimensions, a frozen content-addressed population, and an independent standard-library verifier. | Bit-for-bit or behaviorally identical rebuild under declared inputs | **IMPLEMENTED** for the declared CLI profile in `src/integrity.rs`, `ci/etp-integrity-gate.sh`, `evaluation/earned-trust/integrity/`, and `evaluation/earned-trust/verify_reproducibility.py` | The two builds share one host, container, toolchain, Cargo registry cache, and administrative domain. Debug information is overridden to zero for the comparison and recorded in the build-recipe digest. No syscall tracer and no independent build venue. The result covers one declared binary and does not establish correctness, authenticity, or population completeness. |
| S15 | Pre-registration | The project's own Phase 9.1 pre-registration. `evaluation/PRE-REGISTRATION.md`; `evaluation/protocol.json`; SHA-256 `02deb982c61c2a8307dbf3d34cf90f5aeb367e9ea7b1d794314aea9dd094d5ce`. | Adopted a frozen protocol, hash-defined split, pre-registered hypotheses, thresholds, and claim-to-receipt rule. | Protection against post-hoc protocol change | **IMPLEMENTED** for the Phase 9.1 finite evaluation in `ci/eval-gate.sh` and `ci/reconstruction-gate.sh` | Pre-registration does not make the result a population estimate, a third-party replication, or a proof of correctness. |
| S16 | SARIF/static-analysis result model as a reporting discipline | Same as S01 | Adopted for the ETP campaign projection, including occurrence, candidate, and instrument-execution identities, suppression retention, and completeness limits. | Auditable result reporting | **IMPLEMENTED** as the `frf-etp.sarif-projection.v1` profile in `src/sarif.rs` | The ETP validation report remains canonical JSON, not SARIF. The SARIF projection is a finite-campaign report, not an authority or a certification. |
| S22 | Bounded live timing/execution-path profile (Phase 12.2) | Valgrind callgrind instruction counting; callgrind_annotate parsing; gcc -O1 -fno-inline -fno-builtin -g compilation; hardened container execution. | Adopted a bounded live timing profile over one fixture, one input class pair, one hardened container. Uses callgrind Ir counts as a deterministic proxy (not wall-clock). Emits typed outcomes: observed_secret_dependent_divergence, observed_representation_length_divergence, no_divergence_within_bounded_trace, not_run, unresolved, wrong_dispatch, stale_binary. | Secret-dependent branch divergence, representation-length divergence, constant-time no-divergence | **IMPLEMENTED** as `frf-etp.timing-profile.v1` in `schemas/etp/timing-profile.v1.schema.json`, `evaluation/earned-trust/timing_profile.py`, `tests/fixtures/timing/timing_probe.c`, `ci/etp-timing-gate.sh`, `ci/etp-timing-gate-inner.sh` | This is a bounded live timing profile, not a constant-time proof. It measures one fixture on one host inside one container. It does not claim constant-time, absence of leakage, or deployment security. No scalar scores are used. The ten ETP status dimensions remain separate.
| S23 | Cross-property allocation/ownership repair (Phase 12.3a) | Valgrind memcheck leak/uninit detection; gcc -O1 -fno-inline -fno-builtin -g compilation; hardened container execution. | Adopted a bounded cross-property profile over one C fixture with faulty and fixed allocation/ownership repairs, forced allocation failure injection, and valgrind memcheck event/trace analysis. Emits typed outcomes: observed_erasure_violation, observed_uninitialized_read, observed_leak, no_violation_within_bounded_trace, not_run, unresolved, wrong_dispatch, stale_binary. | Secret erasure on allocation failure/relocation, failure atomicity, resource safety | **IMPLEMENTED** as `frf-etp.cross-property.v1` in `schemas/etp/cross-property.v1.schema.json`, `evaluation/earned-trust/cross_property.py`, `tests/fixtures/cross_property/secret_buffer.c`, `ci/etp-cross-property-gate.sh`, `ci/etp-cross-property-gate-inner.sh` | This is a bounded cross-property profile, not a general confidentiality, erasure, or memory-safety proof. It measures one fixture, one host, one container. It does not establish general confidentiality, erasure, or memory safety. No scalar scores are used. The ten ETP status dimensions remain separate.

## 2. Adoption status summary

| Status | Count | IDs |
|---|---:|---|
| Adopted with executable mechanism | 14 | S01, S02, S03, S06, S07, S14, S15, S16, S17, S19, S20, S21, S22, S23 |
| Informed design only | 4 | S04, S05, S08, S18 |
| Informed, explicitly not implemented | 5 | S09, S10, S11, S12, S13 |
| **Total** | **22** | |

The count is deliberately small. A longer list would not increase assurance.

## 3. Standards that are often confused with assurance

The following are **not** in the adopted set because they would be misleading if
listed as implemented:

- a signature standard does not prove the signed statement;
- a transparency-log standard does not prove completeness;
- a timestamp standard does not prove experimental authenticity;
- a provenance standard does not prove build correctness or reviewer
  independence;
- a tool-qualification standard does not qualify a detector merely because the
  detector ran;
- a formal-methods supplement does not make a small finite theorem a general
  refinement proof;
- a reproducible-build standard does not prove functional correctness;
- a security-development standard does not prove deployment security.

## 4. Consultation record

The standards above were consulted for the Phase 10.1 design and extended in
Phases 10.3-10.4b for the DSSE, RFC 3161, and C2SP tlog work. No standard
body reviewed this repository. No conformance certificate, audit opinion, or
accreditation exists. The registry is a statement of intellectual provenance, not
a claim of compliance.

## 5. Maintenance

A new standard entry must record:

- the exact version and URL;
- the adopted mechanism, if any;
- the property it is used for;
- the implementation location or `NOT_IMPLEMENTED`;
- the assumptions and limitations;
- whether any compliance claim is made (normally **none**).

Adding an entry does not change any claim ceiling. Removing an entry requires a
migration note in `docs/ETP-MIGRATION.md`.
| S24 | Interop matrix (Phase 13.1a) | Phase 13.1a implementation prompt v2 §19; this repo. | Canonical four-way interop matrix for length-prefixed TCP protocol; records per-process identity, case population reconciliation, per-cell outcomes, common failures, candidate-specific failures, and `frf-etp.interop-matrix.v1` report. | Interoperability of length-prefixed TCP protocol fixture compiled twice (reference/candidate). | **IMPLEMENTED** as `tests/fixtures/interop/interop.c`, `evaluation/earned-trust/interop_matrix.py`, `ci/etp-interop-gate.sh`, `ci/etp-interop-gate-inner.sh`, `schemas/etp/interop-matrix.v1.schema.json`, `docs/ETP-INTEROPERABILITY.md` | One local fixture on one host; does not establish TLS interoperability, deployment security, or compatibility of OpenSSL-RS. The candidate-specific failure is a labeled synthetic fixture defect, not an organically discovered vulnerability. |
