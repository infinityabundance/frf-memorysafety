# ETP trust-gap inventory

**Frozen baseline:** FRF-MemorySafety 1.0.0, commit
`02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`, evidence root
`508b495b56b28cb9d674094f21dd89153b28905d61fdf9ac227ea3ff1eac6d74`.
**Inventory date:** Phase 10.1.
**Machine-readable freeze:** `schemas/etp/etp-freeze-1.0.0.json`.

This document inventories every existing 1.0.0 capability and every proposed ETP
capability. Each row is classified as exactly one of the following.

| Class | Meaning |
|---|---|
| `IMPLEMENTED` | A mechanism, artifact, or policy document exists in the repository and is exercised by a named test, gate, or review |
| `EXECUTED_MODEL` | The capability exists only as a deterministic finite model that was executed over a declared case set |
| `SPECIFIED` | The requirement is defined in ETP or 1.0.0 documentation, but no executable mechanism or deployed service exists |
| `NOT_RUN` | The capability is not implemented, or its live path is unavailable; no result is claimed |
| `BLOCKED` | The capability is in declared scope but a concrete blocker prevents completion |

`IMPLEMENTED` does not mean that a universal property is established. It means
that the declared finite or scoped mechanism exists. Every row keeps its
original claim ceiling.

References use the frozen commit. Receipt references use the Phase 9.1
identifiers in `evaluation/CLAIMS.json`; the committed receipts are the 60 files
under `evaluation/receipts/` measured at crate version 0.9.0 and verified by
`ci/eval-gate.sh`.

---

## 1. Existing 1.0.0 capabilities

| ID | Capability | Class | Evidence and references | Exact missing work |
|---|---|---|---|---|
| E01 | Strict `ms-canonical-json-v1` encoding with duplicate-key, float, trailing-byte, UTF-8, and resource-limit rejection | `IMPLEMENTED` | `src/identity.rs`; `SPEC.md` §3; canonical tests | None for the declared profile; ETP reuses the parser |
| E02 | Domain-separated `ms1-` SHA-256 identities over twelve domains | `IMPLEMENTED` | `src/identity.rs`; `tests/identity_vectors.rs`; `SPEC.md` §4 | None; ETP does not add a claim identity in v1 |
| E03 | Typed claim, scope, hazard, obligation, execution-mode, and epistemic-status model | `IMPLEMENTED` | `src/model.rs`; `SPEC.md` §2 and §5 | None; ETP adds separate coordinates without changing meanings |
| E04 | Least-fixed-point positive and admissible support, certificates, exact cuts, incremental revocation | `IMPLEMENTED` | `src/support.rs`; `tests/support.rs`; `docs/phase2-alignment.md` | None for the finite rule graph; no whole-program inference |
| E05 | Policy custody and digest-bound historical verdicts | `IMPLEMENTED` | `src/support.rs`; `tests/support.rs`; `docs/phase2-alignment.md` | None; authenticated policy provenance is not implemented |
| E06 | Finite three-rule profile (enumeration, restriction, conjunction) with nine refusal checks | `IMPLEMENTED` | `src/profile.rs`; `tests/profile.rs`; `docs/phase2-conformance.md` | None; universal soundness remains `WITHHELD_NOT_RUN` |
| E07 | Deterministic local buffer model C0/C1/C2, 24 records, 5 claims per variant | `EXECUTED_MODEL` | `src/profile.rs`; `tests/original_domain_replay.rs`; `README.md` finite-model table | None for the model; it is not native execution or universal soundness |
| E08 | Independent fixed-point, certificate, and exact-cut oracle over 110,592 configurations | `IMPLEMENTED` | `tests/support_oracle/`; `tests/phase2_conformance.rs`; `docs/phase2-conformance.md` | Same-repository oracle shares `SPEC.md` authorship; third-party oracle absent |
| E09 | Bounded, syntax-only `syn` 2.0.119 source inventory with explicit unknowns and symlink refusal | `IMPLEMENTED` | `src/source.rs`; `tests/source.rs`; `docs/phase3-source-inventory.md` | No name/type/macro resolution; no caller graph or whole-program closure |
| E10 | Finite explicit-input path effects, aliases, footprints, intervals, callbacks, and qualified outcomes | `IMPLEMENTED` | `src/path_effect.rs`; `tests/path_effects.rs`; `docs/phase3-path-effects.md` | No source/MIR alias extraction; no concurrency or native callback observation |
| E11 | Optional pinned MIR text adapter (`nightly-2025-02-20`) with bounded, shell-free invocation | `IMPLEMENTED` | `src/mir.rs`; `tests/mir.rs`; `docs/phase3-mir.md` | Text-only, unresolved edges; `NOT_RUN` when the toolchain is absent |
| E12 | Responsibility-token lifecycle, generation, failure, and race semantics over a finite transcript | `IMPLEMENTED` | `src/court.rs`; `tests/court.rs`; `docs/phase4-ownership.md` | Caller-supplied transcript only; no real scheduler or native tracing |
| E13 | Test-only isolated native event record/replay over a closed checked-in fixture registry | `IMPLEMENTED` | `src/native.rs`; `tests/native.rs`; `docs/phase4-native.md`; `ci/native-gate.sh` | No arbitrary native input; digests are not authenticated |
| E14 | Typed detector evidence and calibration refusal rules | `IMPLEMENTED` | `src/detector/`; `tests/detector.rs`; `docs/phase5-calibration.md` | Structural and mechanism-specific; no universal detector accuracy |
| E15 | Opt-in live detector adapters for Miri, ASan, LSan, TSan, loom, Kani, and OpenSSL controls | `IMPLEMENTED` | `src/detector/live.rs`; `tests/detector_live.rs`; `ci/detector-gate.sh`; `docs/phase5-live-detectors.md` | Closed fixtures only; default gate reports typed `NOT_RUN` |
| E16 | Proof manifest, theorem/assumption closure, admission taxonomy, and separate Rust/FFI correspondence | `IMPLEMENTED` | `src/proof.rs`; `tests/proof.rs`; `docs/phase6-proof-adapter.md` | Manifest parsing is not proof checking; correspondence is reviewed evidence |
| E17 | Live pinned Coq 8.16.1 adapter with six seal controls | `IMPLEMENTED` | `src/proof.rs`; `tests/proof_live.rs`; `ci/proof-gate.sh`; `docs/phase6-live-checker.md` | Small finite theorem only; no Lean or Isabelle |
| E18 | Lean/Isabelle live proof checking | `NOT_RUN` | `README.md` capability matrix; `capabilities --json` | No adapter exists; `checker_unavailable`, exit 6 |
| E19 | Exact FRF, FRF-Fuzz, and Gemel repository discovery and pinning | `IMPLEMENTED` | `src/bridge.rs`; `docs/phase7-bridge-discovery.md`; `bridge status` | Pins are exact for the recorded commits; ecosystem-wide conformance absent |
| E20 | Provider-typed opaque identities and fail-closed custody pipeline | `IMPLEMENTED` | `src/bridge.rs`; `tests/bridge.rs`; `docs/phase7-bridge-discovery.md` | No external identity is generated; full provider schemas not covered |
| E21 | Live `FRF-Fuzz -> FRF -> Gemel` chain with loader closure and six seals | `IMPLEMENTED` | `ci/bridge-gate.sh`; `tests/bridge_live.rs`; `docs/phase7-live-chain.md` | Opt-in only; recorded provenance is not authentication |
| E22 | Authenticated provenance for bridge evidence | `NOT_RUN` | `README.md` claim ceiling; `evaluation/LIMITATIONS.md` L8 | No signature, transparency log, trusted timestamp, or trusted build root |
| E23 | Full FRF semantic conformance beyond the checked subset | `BLOCKED` | `docs/phase7-bridge-discovery.md` §11; `docs/phase7-live-chain.md` §10 | External FRF semantic corpus and acceptance agreement are absent |
| E24 | Full Gemel evidence-schema conformance beyond the checked fields | `BLOCKED` | `docs/phase7-bridge-discovery.md` §11 | External full-schema validator and agreement are absent |
| E25 | Typed conversion-court model with property-specific reuse and revocation | `IMPLEMENTED` | `src/conversion.rs`; `tests/conversion.rs`; `docs/phase8-conversion-discovery.md` | Bookkeeping only; no compatibility claim |
| E26 | Live OpenSSL-Rust `up_ref` witness, repair, curl workflow, and loader closure | `IMPLEMENTED` | `ci/conversion-gate.sh`; `docs/phase8-live-conversion.md`; 27 live crate tests | One boundary, one workflow, one closure; all 33 consumers absent |
| E27 | Safe-33 cohort compatibility across all consumers | `NOT_RUN` | `docs/phase8-live-conversion.md` §11; target ledger 0/33 | No cohort replay, compatibility matrix, or independent target authority |
| E28 | `SOUND_SAFE_INTERIOR` and `SAFE_COMPATIBLE` acceptance | `NOT_RUN` | `SPEC.md` §13; `README.md` claim ceiling; `evaluation/LIMITATIONS.md` L18 | No accepting rule; universal safe-interior argument not produced |
| E29 | Pre-registered Phase 9.1 evaluation protocol with SHA-256 freeze and hash-defined split | `IMPLEMENTED` | `evaluation/PRE-REGISTRATION.md`; `evaluation/protocol.json`; `evaluation/PRE-REGISTRATION.sha256` | Protocol is frozen for this corpus; no population inference |
| E30 | Isolated `frf-eval` harness and 60 canonical receipts over 31 cases | `IMPLEMENTED` | `src/evaluation.rs`; `src/bin/frf-eval.rs`; `evaluation/receipts/`; `ci/eval-gate.sh` | Finite control family only; live arms `NOT_RUN` in the default image |
| E31 | Paper, 18-claim ledger, 18-entry limitations ledger, and methodology | `IMPLEMENTED` | `PAPER.md`; `evaluation/CLAIMS.json`; `evaluation/LIMITATIONS.md`; `evaluation/METHOD.md` | No third-party replication; no population estimates |
| E32 | Independent standard-library artifact reconstructor | `IMPLEMENTED` | `evaluation/reconstruct.py`; `ci/reconstruction-gate.sh` | Verifies artifacts, not mechanism semantics; same repository |
| E33 | Third-party replication of the evaluation | `NOT_RUN` | `evaluation/LIMITATIONS.md` L10 | No unaffiliated team or independent oracle |
| E34 | Signed receipts, transparency log, trusted timestamp, or trusted build root | `NOT_RUN` | `evaluation/LIMITATIONS.md` L5; `README.md` claim ceiling | No signature, log, timestamp, or root of trust |
| E35 | SARIF 2.1.0 export for findings and claims | `NOT_RUN` | `docs/ETP-STANDARDS-REGISTRY.md` | No SARIF emitter, schema binding, or conformance test |
| E36 | Public claim-challenge process | `NOT_RUN` | `docs/EARNED-TRUST.md` layer 7 | No intake, triage, adjudication, or publication mechanism |
| E37 | General ETP revocation registry | `NOT_RUN` | `docs/EARNED-TRUST.md` §4.6; `docs/ETP-CLAIM-INTEGRITY.md` §8.3 | Only local conversion reuse/revocation exists |
| E38 | Campaign-closure engine | `NOT_RUN` | `docs/ETP-CLAIM-INTEGRITY.md` §8.1 | No population declaration, closure record, or independent reconstruction |
| E39 | Deployment-wide security assessment | `NOT_RUN` | `README.md` claim ceiling; `evaluation/LIMITATIONS.md` L18 | No deployment-threat model, environment attestation, or security proof |
| E40 | Constant-time or relational timing verification | `NOT_RUN` | `README.md` capability matrix; `docs/ETP-STANDARDS-REGISTRY.md` | No leakage model implementation or timing verifier |
| E41 | Interoperability matrix for named consumers | `NOT_RUN` | `docs/phase8-live-conversion.md` §11 | One curl workflow only; no consumer matrix |
| E42 | Bit-for-bit reproducible builds | `NOT_RUN` | `evaluation/LIMITATIONS.md` L14; `PAPER.md` §12 | Deterministic receipts and artifacts, but no independent bit-reproducible build |
| E43 | AI-output quarantine and role-separation enforcement | `NOT_RUN` | No pre-10.1 mechanism | `AGENTS.md` now specifies the policy; no runtime enforcement |
| E44 | Standards conformance mapping | `NOT_RUN` | `schemas/etp/`; `docs/ETP-STANDARDS-REGISTRY.md` | Registry records informed-by mapping; no compliance assessment |

**Existing subtotal:** `IMPLEMENTED` 25, `EXECUTED_MODEL` 1, `SPECIFIED` 0,
`NOT_RUN` 16, `BLOCKED` 2 (44 rows).

---

## 2. Proposed ETP capabilities

| ID | Capability | Class | Evidence and references | Exact missing work |
|---|---|---|---|---|
| P01 | Generalized claim algebra with twenty required coordinates | `IMPLEMENTED` | `src/etp.rs`; `schemas/etp/etp-claim.v1.schema.json`; `tests/etp.rs` | None in v1; stronger properties need a new version |
| P02 | Versioned obligation inventory with blocking semantics | `IMPLEMENTED` | `src/etp.rs`; `schemas/etp/etp-obligation-inventory.v1.schema.json` | None; the inventory is bookkeeping, not an adjudication service |
| P03 | Ten separate status dimensions with no scalar score | `IMPLEMENTED` | `src/etp.rs`; `schemas/etp/etp-status-dimensions.v1.schema.json` | None; no aggregate is defined by design |
| P04 | SHA-256 version registry and canonical conformance vectors | `IMPLEMENTED` | `schemas/etp/registry.json`; `schemas/etp/vectors/index.json` | Registry is not authenticated; a future layer must sign or log it |
| P05 | Scalar-score and unknown-field rejection | `IMPLEMENTED` | `src/etp.rs` `deny_unknown_fields`; vector `confidence-scalar` | None |
| P06 | Contradictory-evidence retention and native-observation precedence | `IMPLEMENTED` | `src/etp.rs`; vectors `dropped-contradiction`, `native-observation-proof` | No automated discovery of unrecorded contradictions |
| P07 | Unknown-premise and blocking-obligation promotion refusal | `IMPLEMENTED` | `src/etp.rs`; vector `unknown-premise-eligible` | No mechanism to decide whether a premise was truthfully marked discharged |
| P08 | Claim-ceiling enforcement for universal, safe-interior, and safe-compatible claims | `IMPLEMENTED` | `src/etp.rs`; vector `universal-claim` | Adding an accepting rule requires new evidence and a new schema version |
| P09 | Frozen 1.0.0 baseline and immutable evidence reference | `IMPLEMENTED` | `schemas/etp/etp-freeze-1.0.0.json`; `tests/etp.rs` | Freeze covers declared evidence; it does not authenticate it |
| P10 | Schema/versioning and migration policy | `IMPLEMENTED` | `docs/ETP-MIGRATION.md` | Policy is manual; no schema-compatibility checker beyond version equality |
| P11 | Evidence-backed trust-gap inventory | `IMPLEMENTED` | This document; `schemas/etp/etp-freeze-1.0.0.json` | Must be updated by each later phase; no automatic drift detector |
| P12 | AI output is an untrusted proposal; role separation and declared administrative control | `SPECIFIED` | `AGENTS.md` | No tool-enforced quarantine, role identity, or approval workflow |
| P13 | Standards/research registry with exact versions and adoption status | `IMPLEMENTED` | `docs/ETP-STANDARDS-REGISTRY.md`; `schemas/etp/registry.json` | Registry is informed-by only; no conformance claims |
| P14 | Cryptographic ETP claim identity and canonical claim digest | `SPECIFIED` | `docs/ETP-CLAIM-INTEGRITY.md` §7 | No ETP claim digest domain; v1 uses manifest-local identifiers |
| P15 | Campaign-closure engine with population declaration and closure record | `SPECIFIED` | `docs/ETP-CLAIM-INTEGRITY.md` §8.1 | No executable closure record, population freeze, or independent reconstruction |
| P16 | Adjudication workflow with role and independence records | `SPECIFIED` | `docs/ETP-CLAIM-INTEGRITY.md` §8.2 | No adjudication schema, service, or independence verification |
| P17 | General revocation registry and revocation feed | `SPECIFIED` | `docs/ETP-CLAIM-INTEGRITY.md` §8.3 | No registry, feed, scope model, or historical-replay policy |
| P18 | Challenge and escalation protocol | `SPECIFIED` | `docs/EARNED-TRUST.md` layer 7 | No intake, triage, response deadline, or public record |
| P19 | Authenticated evidence via DSSE, in-toto/SLSA, Sigstore, Rekor/C2SP, RFC 3161, or TUF | `NOT_RUN` | `docs/ETP-STANDARDS-REGISTRY.md` | No envelope, signature, log, timestamp, or update metadata is implemented |
| P20 | Transparency-log inclusion and global non-equivocation | `NOT_RUN` | `docs/ETP-STANDARDS-REGISTRY.md`; `docs/ETP-CLAIM-INTEGRITY.md` §3 | No log client, inclusion proof, consistency proof, or witness policy |
| P21 | Trusted timestamps for evidence and experiments | `NOT_RUN` | `docs/ETP-STANDARDS-REGISTRY.md` | No RFC 3161 client or timestamp verification |
| P22 | Independent reviewer attestations and competence records | `SPECIFIED` | `docs/ETP-CLAIM-INTEGRITY.md` §3 dimension 7 | No attestation schema or independence verification |
| P23 | Public accountability surface for claims, challenges, and revocations | `SPECIFIED` | `docs/EARNED-TRUST.md` layer 7 | No public service, feed, or archival policy |
| P24 | Constant-time and relational timing verification | `SPECIFIED` | `docs/EARNED-TRUST.md` §4.3; `docs/ETP-STANDARDS-REGISTRY.md` | No leakage model, tool adapter, or timing claim |
| P25 | Interoperability matrix and multi-consumer evidence reuse | `NOT_RUN` | `docs/phase8-live-conversion.md` §11 | No consumer matrix or property-specific reuse across consumers |
| P26 | Bit-for-bit reproducible build verification | `NOT_RUN` | `evaluation/LIMITATIONS.md` L14 | No independent rebuild, normalized environment, or artifact comparison |
| P27 | Third-party replication of ETP or 1.0.0 results | `NOT_RUN` | `evaluation/LIMITATIONS.md` L10 | No unaffiliated replication |
| P28 | Evidence availability and retention guarantee | `NOT_RUN` | `docs/EARNED-TRUST.md` §4.7 | No content-addressed store, replication, or availability proof |
| P29 | Provider-authority integration into ETP claim records | `SPECIFIED` | `docs/EARNED-TRUST.md` §5 | No ETP object that references provider identities with a typed custody rule |
| P30 | Standards compliance assessment (DO-178C, DO-330, DO-333, seL4, etc.) | `NOT_RUN` | `docs/ETP-STANDARDS-REGISTRY.md` | No gap assessment, objective mapping, or independent audit |
| P31 | Enforced AI role separation and administrative control | `SPECIFIED` | `AGENTS.md` | Policy only; no runtime identity, approval, or audit trail |
| P32 | Canonical ETP validation report | `IMPLEMENTED` | `src/etp.rs` `EtpValidationReport`; `etp validate --json` | Report is bookkeeping; it is not certification |

**Proposed subtotal:** `IMPLEMENTED` 13, `EXECUTED_MODEL` 0, `SPECIFIED` 11,
`NOT_RUN` 8, `BLOCKED` 0 (32 rows).

---

## 3. Total classified inventory

| Class | Existing | Proposed | Total |
|---|---:|---:|---:|
| `IMPLEMENTED` | 25 | 13 | 38 |
| `EXECUTED_MODEL` | 1 | 0 | 1 |
| `SPECIFIED` | 0 | 11 | 11 |
| `NOT_RUN` | 16 | 8 | 24 |
| `BLOCKED` | 2 | 0 | 2 |
| **Total** | **44** | **32** | **76** |

These counts describe this inventory, not a measure of assurance quality. A
large `IMPLEMENTED` count is not a certificate. A `NOT_RUN` row is not a failure
of the software; it is an honest statement that no result exists.

## 4. The trust gap between 1.0.0 and the ETP directive

The 1.0.0 release is strong at finite evidence bookkeeping and weak at external
accountability. The directive asks for accountable, independently challengeable,
reproducible AI-assisted security engineering. The gap has five parts.

### 4.1 Claim completeness

1.0.0 has typed claims, but its claim key is narrower than the ETP coordinate
set. It does not require an interpretation, threat model, leakage model, runtime
environment, deployment scope, semantic model, TCB, supporting/contradictory
evidence, policy identity, or invalidation dependencies in one record.

**Closed in Phase 10.1 by** `frf-etp.claim.v1` and `src/etp.rs`. The closure is
structural, not semantic.

### 4.2 Claim integrity and contradiction handling

1.0.0 has support revocation and property-specific conversion revocation, but no
general rule that a positive proof cannot erase a contradictory native
observation. The Phase 9 limitations ledger states the digest-bound,
non-authenticated nature of the evidence but does not encode it as a claim
algebra rule.

**Closed in Phase 10.1 by** contradiction retention, native-observation
precedence, unknown-premise blocking, and scalar-score rejection.

### 4.3 Authenticated evidence

No 1.0.0 evidence is signed, logged, or timestamped. A coordinated rewrite that
recomputes every digest can produce a self-consistent alternative evidence set.
DSSE, in-toto/SLSA, Sigstore, Rekor/C2SP, RFC 3161, and TUF are not integrated.

**Not closed.** Phase 10.1 records the gap in
`docs/ETP-STANDARDS-REGISTRY.md` and refuses to claim authentication.

### 4.4 Independent adjudication and public accountability

There is no public challenge process, adjudication service, revocation registry,
campaign-closure engine, or independent reviewer attestation. The independent
reconstructor is same-repository and artifact-level.

**Not closed.** These are `SPECIFIED` or `NOT_RUN` in the inventory.

### 4.5 Timing, deployment, and interoperability

There is no constant-time verification, no deployment-wide security assessment,
no consumer interoperability matrix, and no third-party replication. The
OpenSSL-Rust evidence is one boundary and one curl workflow.

**Not closed.** A new mechanism and new evidence are required.

### 4.6 What Phase 10.1 deliberately does not do

- It does not add a universal accepting rule.
- It does not turn a digest into authentication.
- It does not turn a passing gate into certification.
- It does not reinterpret any 1.0.0 schema or receipt.
- It does not modify `research/`.
- It does not bump the crate version or publish a package.

## 5. What remains for the Phase 10 vertical slice

The next subphase must produce a real, end-to-end ETP slice without widening the
claim ceiling. Phase 10.2 implements items 1, 2, 6, and 7 for one finite native
campaign; items 3, 4, and 5 remain unimplemented.

1. **A concrete ETP campaign record** over an existing finite corpus, with a
   frozen population, per-case receipts or typed `NOT_RUN`, retained
   contradictions, and independent reconstruction. **Implemented for the 13-case
   native fixture campaign in `evaluation/earned-trust/`.**
2. **A campaign-closure schema and validator** that refuses a silently dropped
   case, an undeclared population, a rewritten acceptance predicate, or a
   contradiction removed after measurement. **Implemented in
   `src/etp_campaign.rs` for the declared campaign.**
3. **A signed and logged evidence envelope** (for example DSSE plus a
   transparency-log inclusion proof) with an explicit statement that
   authentication is not truth and inclusion is not completeness. **Not
   implemented.**
4. **A revocation record and replay policy** that distinguishes historical
   validity from present authorization and binds the exact changed dependency.
   **Not implemented as a general ETP registry.**
5. **A challenge and adjudication record** with declared roles and an
   independence dimension that is not inferred from multiple signatures. **Not
   implemented.**
6. **An independent reconstruction path** that re-executes the ETP validator
   and campaign closure from committed bytes, without importing the Rust crate.
   **Implemented in `evaluation/earned-trust/reconstruct.py` for the declared
   campaign.**
7. **A gate** that runs the slice in a hardened container and reports exact
   counts, with no host build and no removed memory cap. **Implemented in
   `ci/etp-gate.sh`.**

Until those exist, the ETP claim is limited to the Phase 10.1 claim-integrity
bookkeeping and the Phase 10.2 finite campaign closure described in this
document and `docs/ETP-CAMPAIGN.md`.
