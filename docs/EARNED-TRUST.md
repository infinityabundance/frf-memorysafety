# FRF Earned Trust Protocol (ETP): constitution

**Document status:** Phase 10.1 constitution. Normative for the ETP programme.
**Protocol identifier:** `frf-etp-v1`.
**Frozen baseline:** FRF-MemorySafety 1.0.0, commit
`02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`, evidence root
`508b495b56b28cb9d674094f21dd89153b28905d61fdf9ac227ea3ff1eac6d74`.

This document establishes the mission, governing principle, architecture, and
permanent distinctions of the FRF Earned Trust Protocol. It does not change the
meaning of any 1.0.0 schema, evidence record, claim, or provider identity. It
does not widen the finite profile. It does not turn the 1.0.0 evidence into a
stronger claim.

---

## 1. Mission

ETP is a general-purpose, additive assurance methodology for accountable,
independently challengeable, reproducible AI-assisted security engineering. It
exists so that a claim about software can be:

1. stated with explicit coordinates and assumptions;
2. supported by evidence that is inspectable and reproducible;
3. challenged by an independent party without renegotiating definitions;
4. adjudicated without collapsing distinct kinds of status;
5. revoked or narrowed when a dependency changes; and
6. published without manufacturing execution, independence, review, or
   consensus.

ETP is **additive**. It wraps existing evidence and provider authority. It does
not replace FRF, FRF-Fuzz, Gemel, the Rust compiler, Coq, a detector, a
transparency log, or any other authority.

## 2. Governing principle

> A claim is earned only to the extent that its exact coordinates are declared,
> its evidence is inspectable, its assumptions and trusted base are named, its
> contradictions are retained, and an independent party can reproduce or
> challenge the result within the declared scope.

The governing principle has three operational consequences.

- **No retroactive strengthening.** Evidence measured under an earlier release
  keeps its original meaning. A later document cannot relabel a finite result as
  universal, a modeled result as native, or a digest as authentication.
- **No single score.** Status is recorded as separate dimensions. There is no
  confidence scalar, assurance level, letter grade, or composite safety index.
- **No hidden premise.** An unresolved required premise blocks promotion. It is
  not discharged by renaming the state, adding a signature, or restating the
  claim.

## 3. Scope and non-claims

ETP is in scope for:

- claims about memory safety, functional correctness, interoperability, timing,
  deployment scope, reproducibility, claim integrity, and engineering process;
- finite, bounded, deployment-scoped, and universal claims, provided the
  applicable accepting rule exists;
- evidence produced by this crate, by external providers, or by a human review
  process;
- challenge, adjudication, revocation, and public accountability records.

ETP is **not**:

- a certification scheme, an accreditation body, or a regulator;
- a proof system, a static analyser, a fuzzer, or a detector;
- a substitute for FRF receipts, FRF-Fuzz findings, Gemel custody, or the
  target project's own authority;
- a guarantee that a signed record is true, that a transparency log is complete,
  or that an independent reviewer is competent;
- a mechanism that converts evidence volume, aggregate agreement, multiple
  signatures, or public inclusion into semantic proof;
- an authorization to deploy software.

A validated ETP manifest is **bookkeeping over declared evidence**. Validation
does not establish the truth of any claim. It establishes only that the claim
algebra is complete and that the declared status does not make a forbidden
promotion.

## 4. Architecture layers

ETP is layered. A lower layer does not silently confer credit on a higher layer.
Each layer has its own evidence, authority, and claim ceiling.

| Layer | Name | 1.0.0 state | What it may establish |
|---|---|---|---|
| 0 | Existing foundation | Implemented and tested | Canonical encoding, typed evidence, founded support, policy custody, finite profile |
| 1 | Memory safety | Implemented for finite, explicit, transcript-scoped and proof-scoped mechanisms | Finite model, source, path, MIR-text, transcript, detector, and checked-proof observations |
| 2 | Timing | Specified, not run | Nothing yet; no constant-time or relational result is represented as verified |
| 3 | Interoperability | Implemented for one recorded OpenSSL-Rust boundary and one consumer workflow | One boundary witness, one repair, one curl TLS 1.3 workflow, one loader closure |
| 4 | Reproducibility | Implemented for a pre-registered finite evaluation and an artifact-level reconstructor | Deterministic receipt reproduction and independent artifact reconstruction |
| 5 | ETP claim integrity, campaign closure, adjudication, revocation | Phase 10.1 starts claim integrity | Claim algebra, obligation inventory, separate dimensions, freeze, migration policy |
| 6 | Authenticated evidence | Specified, not implemented | Nothing yet; digests are not authentication |
| 7 | Public accountability | Specified, not implemented | Nothing yet; no challenge service, transparency log, or adjudication body is deployed |

### 4.1 Existing foundation

The Phase 1-9 foundation remains authoritative for its own objects:

- `ms-canonical-json-v1` strict encoding and resource limits;
- `ms1-` domain-separated identities over the twelve declared domains;
- typed claims, scopes, hazards, obligations, execution modes, and epistemic
  statuses;
- least-fixed-point support, certificates, exact cuts, policy custody, and
  historical verdict replay;
- the finite three-rule profile and its refusal rules;
- the pre-registered Phase 9.1 evaluation protocol and 60 receipts.

ETP references these objects. It does not reinterpret them.

### 4.2 Memory safety

The memory-safety layer contains separately scoped mechanisms: source inventory,
explicit path effects, optional MIR text observations, responsibility tokens,
native fixture replay, detector calibration, proof manifests, a live Coq adapter,
and a conversion court. Each mechanism has a claim ceiling in `README.md` and
`docs/phase*.md`.

ETP may record a claim about one of these mechanisms only with the mechanism's
declared property, interpretation, quantification, legal domain, and scope. A
finite observation is not a universal theorem. A clean detector run is not
detector sensitivity. Absence of `unsafe` is not soundness.

### 4.3 Timing

Timing is a separate property with its own leakage model. No 1.0.0 result is a
constant-time result. A fixed iteration count is not constant-time behaviour. A
SHA-256 known-answer test and a signature-validation control are not timing
measurements. The ETP registry records timing verification as specified and not
implemented.

### 4.4 Interoperability

Interoperability is not functional correctness and not deployment-wide security.
The 1.0.0 conversion evidence covers one `up_ref` owner/refcount boundary, one
repair, one curl 8.22.0 TLS 1.3 positive/negative workflow, and one loader
closure. It does not cover all 33 Safe-33 consumers and does not establish
binary or functional compatibility for any other workload.

### 4.5 Reproducibility

Reproducibility is not correctness. The Phase 9.1 evaluation reproduces exact
observations, digests, and experiment hashes for a pre-registered finite corpus.
The independent reconstructor validates artifacts, not mechanism semantics. No
third-party replication exists. A reproducible wrong result is still wrong.

### 4.6 ETP claim integrity, campaign closure, adjudication, revocation

Phase 10.1 implements claim integrity: the generalized claim algebra, the
obligation inventory, the ten status dimensions, schema versioning, canonical
vectors, and a frozen 1.0.0 baseline. Campaign closure, adjudication, revocation,
and challenge workflows are specified in this constitution and in
[`ETP-CLAIM-INTEGRITY.md`](ETP-CLAIM-INTEGRITY.md), but their services are not
deployed. The 1.0.0 conversion module already performs property-specific
evidence reuse and revocation for its own scope; that is not a general ETP
revocation registry.

### 4.7 Authenticated evidence

Layer 6 is where signatures, transparency logs, trusted timestamps, trusted
build roots, and update-framework metadata would live. None is implemented.
ETP distinguishes:

- a digest from authentication;
- authentication from truth;
- provenance from independent verification;
- transparency inclusion from completeness;
- consistency from global non-equivocation;
- a trusted timestamp from experimental authenticity;
- an evidence commitment from availability.

**External evidence layers do not confer semantic proof credit.** A DSSE
envelope, in-toto attestation, SLSA provenance statement, Sigstore signature,
Rekor entry, RFC 3161 timestamp, or TUF metadata may establish a fact about
who signed or logged bytes. It does not establish that the bytes describe a true
property, that the measurement was correct, that the reviewer was independent,
or that the deployed system is secure.

### 4.8 Public accountability

Layer 7 is the public surface for claims, challenges, adjudications, and
revocations. It is specified but not deployed. A public page is not an
independent review. A published claim is not an adjudicated claim. A revocation
feed is not complete merely because it is published.

## 5. Provider-authority boundaries

Existing provider authority remains binding.

| Authority | Sole producer | ETP boundary |
|---|---|---|
| FRF | FRF receipts, court records, and exact replay | ETP may reference an opaque receipt; it must not emit or rehash it as a local identity |
| FRF-Fuzz | BLAKE3 finding content objects | ETP may reference a finding; it must not synthesize one |
| Gemel | GCE objects and GIDs | ETP may reference custody evidence; it must not fabricate a GID |
| openssl-rs | Its source state, Safe-33 ledger, and revision identity | ETP may reference the pinned candidate and evidence; it must not assert compatibility for the target |
| Coq | Checked proof status | ETP may record the checker result and scope; it must not turn parser success into proof acceptance |
| Detectors (Miri, ASan, LSan, TSan, loom, Kani, crypto controls) | Their own diagnostics and exit statuses | ETP may record a mechanism-specific observation; it must not generalize it to detector accuracy |

A hash match is not an authentication statement. A provider object referenced by
ETP remains the provider's object.

## 6. Permanent distinctions

The following distinctions are permanent. They must be encoded in the claim
algebra or in a named refusal, never collapsed into a single status.

| Distinction | Required treatment |
|---|---|
| Memory safety ≠ functional correctness | Separate property and interpretation coordinates; no inference rule between them |
| Functional correctness ≠ interoperability | Separate property; an interoperability observation does not establish behaviour |
| Interoperability ≠ deployment-wide security | Deployment scope is explicit; no promotion from one workload to a deployment |
| No `unsafe` ≠ soundness | Source syntax is not a soundness proof |
| Source reasoning ≠ binary assurance | Source, build, and artifact identities are separate coordinates |
| Fixed iteration count ≠ constant-time | Timing requires a leakage model and a timing-specific result |
| No detected leakage ≠ no leakage | Absence of a detection is not absence of a leak |
| Bounded proof ≠ unrestricted theorem | Quantification and legal domain are explicit |
| Verified model ≠ verified implementation | Semantic model and implementation correspondence are separate |
| Valid proof ≠ assumptions hold | Assumptions and TCB are required coordinates |
| Instrument execution ≠ qualification | Detector evidence is mechanism- and case-specific |
| Differential success ≠ spec correctness | Agreement between implementations is not a proof of the specification |
| Reference parity ≠ security | Parity with a reference is not a security property |
| Reproducibility ≠ correctness | Reproduction confirms bytes and observations, not truth |
| Digest ≠ authentication | A digest binds bytes only |
| Authentication ≠ truth | A signature identifies a signer, not a true statement |
| Provenance ≠ independent verification | A provenance record is not an external review |
| Multiple signatures ≠ independent reviewers | Reviewer independence is a separate dimension |
| Transparency inclusion ≠ completeness | Inclusion is not global completeness |
| Consistency ≠ global non-equivocation | Local consistency is not a global view |
| Witness approval ≠ code review | Approval is not review |
| Trusted timestamp ≠ experimental authenticity | A timestamp does not authenticate the experiment |
| Evidence commitment ≠ availability | A commitment is not the evidence itself |
| Historical validity ≠ present authorization | Replay under an old policy is not current permission |
| AI explanation ≠ proof | Generated text is not a derivation |
| Agent agreement ≠ independent confirmation | Agreement among agents is not reviewer independence |
| Passing gate ≠ certification | A gate is a check, not an accreditation |
| Unresolved obligation ≠ discharged by relabeling | Only typed evidence advances state |

These distinctions are enforced where executable rules exist and are stated as
non-claims everywhere else. A future layer may add a rule that uses one of these
distinctions; it may not erase the distinction.

## 7. Promotion and non-promotion

ETP has no composite promotion ladder. A claim may be `release_eligible` only
when its declared status dimensions and obligations support that specific
claim. Eligibility is not a certificate, not a deployment authorization, and not
a statement that the claim is true.

The Phase 10.1 validator refuses:

- universal quantification;
- `sound_safe_interior` and `safe_compatible`;
- release eligibility with an unresolved assumption;
- release eligibility with an unresolved blocking obligation;
- release eligibility with non-positive, invalid, stale, or inconsistent
  status;
- a positive outcome that would erase a retained native observation or proof
  counterexample;
- a dropped contradiction;
- a scalar confidence, score, assurance level, or rating field;
- an unknown schema version or an altered frozen baseline.

These refusals are deliberate. Adding an accepting rule for a stronger property
requires a new schema version, new evidence, and a new gate record. It cannot be
done by editing a manifest.

## 8. Status of this subphase

Phase 10.1 establishes the constitution and inventory only. It does not
implement Phase 10.2. In particular:

- no new memory-safety, compatibility, timing, or deployment claim is made;
- no external evidence is authenticated;
- no transparency log or timestamp is integrated;
- no independent reviewer or adjudicator is deployed;
- no campaign-closure or revocation service is deployed;
- no existing test is deleted or weakened;
- no crate version is bumped and no package is published.

The trust-gap inventory is in [`ETP-TRUST-GAP.md`](ETP-TRUST-GAP.md). The
migration and versioning policy is in [`ETP-MIGRATION.md`](ETP-MIGRATION.md).
The claim algebra is in [`ETP-CLAIM-INTEGRITY.md`](ETP-CLAIM-INTEGRITY.md). The
standards actually consulted are in
[`ETP-STANDARDS-REGISTRY.md`](ETP-STANDARDS-REGISTRY.md).

## 9. References

1. FRF-MemorySafety, `SPEC.md`, `PAPER.md`, `CHANGELOG.md`, `README.md`.
2. FRF-MemorySafety, `evaluation/LIMITATIONS.md`, `evaluation/CLAIMS.json`,
   `evaluation/protocol.json`.
3. FRF-MemorySafety, `docs/phase2-alignment.md` through
   `docs/phase8-live-conversion.md`.
4. FRF-MemorySafety, `schemas/etp/etp-freeze-1.0.0.json` and
   `schemas/etp/registry.json`.
5. FRF-MemorySafety, `AGENTS.md`.
