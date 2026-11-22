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
| S02 | DSSE (Dead Simple Signing Envelope) | v1.0.0. <https://github.com/secure-systems-lab/dsse/blob/v1.0.0/protocol.md> | Informed the planned authenticated-evidence layer. No envelope is emitted or verified. | Envelope integrity and signer identity | **NOT_IMPLEMENTED** | A valid signature authenticates a signing key, not the truth of the payload. Key custody, revocation, and identity are out of scope. |
| S03 | in-toto | Specification v1.0.0. <https://github.com/in-toto/specification/blob/v1.0.0/in-toto-spec.md> | Informed the separation of subject, predicate, and evidence layers. | Supply-chain step and artifact attestation | **NOT_IMPLEMENTED** | Link metadata records steps; it does not establish that a step was correctly implemented or independently reviewed. |
| S04 | SLSA | v1.0. <https://slsa.dev/spec/v1.0/> | Informed provenance and build-identity coordinates. | Build provenance and tamper resistance levels | **NOT_IMPLEMENTED** | SLSA levels describe build provenance properties, not software correctness, memory safety, or deployment security. No level is claimed. |
| S05 | Sigstore | Sigstore/cosign documentation as consulted in Phase 10.1. <https://docs.sigstore.dev/> | Informed keyless signing and transparency concepts. | Artifact signing and public verifiability | **NOT_IMPLEMENTED** | A Sigstore signature is not a proof of correctness. Identity issuance, trust roots, and policy are external. |
| S06 | Rekor / C2SP transparency log | Rekor v2 line and C2SP transparency-log specification. <https://github.com/sigstore/rekor> and <https://c2sp.org/tlog> | Informed the distinction between inclusion and completeness. | Public append-only evidence logging | **NOT_IMPLEMENTED** | Inclusion is not completeness. Consistency is not global non-equivocation. No log client or witness policy exists. |
| S07 | RFC 3161 Time-Stamp Protocol | RFC 3161 (2001). <https://www.rfc-editor.org/rfc/rfc3161.html> | Informed the trusted-timestamp coordinate. | Evidence time attestation | **NOT_IMPLEMENTED** | A trusted timestamp authenticates a time claim, not the experiment or its result. TSA trust and clock assumptions remain. |
| S08 | TUF (The Update Framework) | Specification v1.0.31. <https://theupdateframework.github.io/specification/v1.0.31/> | Informed the separation of role, metadata, and revocation. | Secure software update metadata | **NOT_IMPLEMENTED** | TUF protects update metadata under a threat model; it does not prove the updated software is safe or correct. No repository metadata exists. |
| S09 | RTCA DO-178C | DO-178C, Software Considerations in Airborne Systems and Equipment Certification (2011). <https://www.rtca.org/> | Informed the separation of objectives, evidence, and independence in the ETP architecture. | Airborne software assurance | **NOT_IMPLEMENTED**; **NOT_CLAIMED** | The project is not an airborne system and has not performed a DO-178C gap assessment. Objective satisfaction cannot be inferred from this registry. |
| S10 | RTCA DO-330 | DO-330, Software Tool Qualification Considerations (2011). <https://www.rtca.org/> | Informed the distinction between tool execution and tool qualification. | Tool qualification | **NOT_IMPLEMENTED**; **NOT_CLAIMED** | Running a detector or prover is not tool qualification. No tool-qualification evidence exists. |
| S11 | RTCA DO-333 | DO-333, Formal Methods Supplement to DO-178C and DO-278A (2011). <https://www.rtca.org/> | Informed the separation of formal model, proof, assumptions, and implementation correspondence. | Formal-methods assurance | **NOT_IMPLEMENTED**; **NOT_CLAIMED** | The checked Coq theorem is small and finite; it is not a DO-333 formal-methods argument. |
| S12 | seL4 verification methodology | seL4 verification pages and the SOSP 2009 paper, *seL4: Formal Verification of an OS Kernel*. <https://sel4.systems/Info/Verification/> | Informed the separation of functional correctness, security, binary correspondence, and assumptions. | Kernel-level functional correctness and security | **NOT_IMPLEMENTED** as a methodology for this crate | seL4's results depend on a specific formal model, binary verification, and explicit assumptions. No seL4-style refinement proof exists here. |
| S13 | Constant-time and relational verification | Almeida, Barbosa, Barthe, Dupressoir, Emmi, *Verifying Constant-Time Implementations*, USENIX Security 2016. <https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/almeida>; ct-verif <https://github.com/imdea-software/verifying-constant-time>; Jasmin <https://jasmin-lang.org/> | Informed the leakage-model coordinate and the refusal to treat fixed iteration count or a SHA-256 known-answer test as constant-time evidence. | Secret-independent execution time under a leakage model | **NOT_IMPLEMENTED** | No timing verifier, leakage model implementation, or relational proof exists. The OpenSSL control is a known-answer/signature test, not a timing measurement. |
| S14 | Reproducible builds | Reproducible Builds project specification and definition. <https://reproducible-builds.org/specs/> and <https://reproducible-builds.org/docs/definition/> | Adopted deterministic receipt observation and independent artifact reconstruction for the Phase 9.1 finite corpus. | Bit-for-bit or behaviorally identical rebuild | **IMPLEMENTED** only as deterministic receipt/artifact reconstruction in `evaluation/reconstruct.py` and `ci/reconstruction-gate.sh` | The project does not claim bit-for-bit reproducible builds. Reproduction confirms bytes and observations, not correctness. |
| S15 | Pre-registration | The project's own Phase 9.1 pre-registration. `evaluation/PRE-REGISTRATION.md`; `evaluation/protocol.json`; SHA-256 `02deb982c61c2a8307dbf3d34cf90f5aeb367e9ea7b1d794314aea9dd094d5ce`. | Adopted a frozen protocol, hash-defined split, pre-registered hypotheses, thresholds, and claim-to-receipt rule. | Protection against post-hoc protocol change | **IMPLEMENTED** for the Phase 9.1 finite evaluation in `ci/eval-gate.sh` and `ci/reconstruction-gate.sh` | Pre-registration does not make the result a population estimate, a third-party replication, or a proof of correctness. |
| S16 | SARIF/static-analysis result model as a reporting discipline | Same as S01 | Adopted for the ETP campaign projection, including occurrence, candidate, and instrument-execution identities, suppression retention, and completeness limits. | Auditable result reporting | **IMPLEMENTED** as the `frf-etp.sarif-projection.v1` profile in `src/sarif.rs` | The ETP validation report remains canonical JSON, not SARIF. The SARIF projection is a finite-campaign report, not an authority or a certification. |

## 2. Adoption status summary

| Status | Count | IDs |
|---|---:|---|
| Adopted with executable mechanism | 4 | S01 (versioned projection), S14 (limited scope), S15, S16 |
| Informed design only | 7 | S02, S03, S04, S05, S06, S07, S08 |
| Informed, explicitly not implemented | 5 | S09, S10, S11, S12, S13 |
| **Total** | **16** | |

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

The standards above were consulted for the Phase 10.1 design only. No standard
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
