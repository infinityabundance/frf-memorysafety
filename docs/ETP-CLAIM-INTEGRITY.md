# ETP claim integrity

**Protocol identifier:** `frf-etp-v1`.
**Executable implementation:** `src/etp.rs`.
**CLI:** `etp validate MANIFEST [--json]`.
**Schemas:** `schemas/etp/`.
**Conformance vectors:** `schemas/etp/vectors/`.

This document defines the generalized claim algebra and the ten separate status
dimensions. It is normative for ETP v1. It does not alter the meaning of any
FRF-MemorySafety 1.0.0 claim, schema, receipt, or provider identity.

---

## 1. Why a claim algebra

Assurance failures usually come from an underspecified claim, not from a missing
tool. A claim that omits its threat model, leakage model, build identity,
deployment scope, assumptions, trusted base, contradictions, or invalidation
dependencies cannot be independently challenged. A claim that merges epistemic
status, execution modality, quantification, verification outcome, evidence
validity, reproduction, reviewer independence, freshness, transparency, and
release eligibility into one number cannot be audited.

ETP therefore separates:

- **coordinates**: what is being claimed, about what, under which model;
- **dimensions**: distinct status facts about the evidence and process; and
- **obligations**: what remains to be done.

No coordinate or dimension is a score. There is no aggregate.

## 2. The twenty coordinates

Every `frf-etp.claim.v1` requires all twenty coordinates. A missing coordinate is
an integrity error. An empty textual coordinate is an integrity error. The
coordinates are deliberately redundant with the ten dimensions where the same
vocabulary appears; the redundancy is a consistency check, not a scalar
collapse.

| # | Coordinate | Type | Meaning | Typical invalidation |
|---:|---|---|---|---|
| 1 | `property` | closed vocabulary | The property being claimed | A changed property is a different claim |
| 2 | `interpretation` | text | The operational meaning of the property | A changed interpretation invalidates the claim |
| 3 | `quantification` | enum | Point, finite exhaustion, bounded, universal, or deployment-scoped | A wider quantifier requires new evidence |
| 4 | `legal_domain` | enum | Domain in which the claim is legally asserted | A wider domain is not a restriction |
| 5 | `threat_model` | text | Adversary, failure model, and excluded threats | A changed threat model invalidates the claim |
| 6 | `leakage_model` | text | Timing, cache, power, or other leakage model, or an explicit `not_applicable` | A timing claim without a leakage model is incomplete |
| 7 | `subject_identity` | text | The software, corpus, or process being assessed | A changed subject invalidates the claim |
| 8 | `source_identity` | text | Source revision or digest | A changed source invalidates the claim |
| 9 | `build_identity` | text | Toolchain, flags, image, and build recipe | A changed build invalidates the claim |
| 10 | `artifact_identity` | text | Binary, DSO, package, or evidence-artifact identity | A changed artifact invalidates the claim |
| 11 | `runtime_environment` | text | Runtime, kernel, container, loader, and resource envelope | A changed environment invalidates deployment-scoped claims |
| 12 | `deployment_scope` | text | Exact named deployment or declared finite scope | A wider deployment is not covered |
| 13 | `semantic_model` | text | Model, specification, or operational semantics | A changed model invalidates model claims |
| 14 | `assumptions` | typed list | Required premises with lifecycle states | An unresolved premise blocks promotion |
| 15 | `trusted_computing_base` | non-empty text list | Components whose correctness is assumed | A changed or expanded TCB invalidates the claim |
| 16 | `obligations` | identifier list | References into the obligation inventory | An unresolved blocking obligation blocks promotion |
| 17 | `supporting_evidence` | typed list | Evidence references, kinds, digests, locations | A digest mismatch or missing evidence invalidates the claim |
| 18 | `contradictory_evidence` | typed list | Retained contrary observations and their resolution state | A dropped contradiction is a refusal |
| 19 | `policy_identity` | text | Policy, rule system, or acceptance predicate | A changed policy produces a new verdict |
| 20 | `invalidation_dependencies` | text list | Everything whose change invalidates the claim | An omitted dependency is an unsound reuse |

A claim also carries `id`, `schema`, `spec`, and `status_dimensions`. These are
not substitutes for a coordinate.

## 3. The ten separate dimensions

The dimensions are recorded in `status_dimensions`. Each is a separate typed
field. None is derived from another by a numeric conversion. The validator
checks only explicit contradictions (for example, `executed_native` with a
non-native modality); it does not infer one dimension from another.

| # | Dimension | Values | What it records | What it does **not** record |
|---:|---|---|---|---|
| 1 | `epistemic_status` | specified, modeled, executed_model, executed_native, checked_proof, reviewed_argument, not_run, unsupported, unknown, challenged, invalid_evidence | Kind of statement | Truth or strength |
| 2 | `execution_modality` | authentic_native, native_instrumented, mock_provider, substituted_ffi, finite_event_model, unsupported, not_applicable | How the observation was produced | Authenticity of provenance |
| 3 | `quantification` | finite_observation, finite_model_exhaustion, bounded_model, universal_contextual, deployment_restricted | Scope of the statement | Correctness of the scope |
| 4 | `verification_outcome` | not_run, inconclusive, supported_finite, proved_within_scope, refuted, challenged, invalid_evidence | Result within the declared scope | Scope validity or assumption truth |
| 5 | `evidence_validity` | valid, stale, digest_mismatch, unverified, invalid, unknown | Integrity of the evidence bytes | Authenticity, signature, or truth |
| 6 | `reproduction_status` | not_attempted, reproduced, not_reproduced, unavailable, unknown | Whether a reproduction succeeded | That reproduction implies correctness |
| 7 | `reviewer_independence` | none, author, independent_declared, independently_verified, unknown | Independence of review | Competence or correctness |
| 8 | `freshness` | current, stale, expired, not_applicable, unknown | Temporal applicability | Authorization to deploy |
| 9 | `transparency_status` | not_included, included, consistent, inconsistent, not_applicable, unknown | Transparency-log relation | Completeness or non-equivocation |
| 10 | `release_eligibility` | eligible, withheld, blocked, not_applicable | Producer's release request | Certificate, truth, or deployment permission |

The following are **forbidden** as fields anywhere in a claim, an inventory, a
dimension object, or a validation report:

```text
confidence
score
assurance_level
rating
```

A manifest containing one is rejected as an integrity error. The validation
report contains counts and refusal codes only; it contains no aggregate.

## 4. Supporting and contradictory evidence

### 4.1 Supporting evidence

Each supporting evidence entry declares:

```text
id, kind, digest, location
```

`kind` is one of `digest_bound_artifact`, `executed_receipt`, `proof_object`,
`observation_record`, `review_record`, `external_provider_object`, or
`policy_document`.

A digest binds exact bytes. It does not authenticate the producer, establish
that the bytes were honestly produced, or prove that the described event
occurred. A provider object referenced here remains the provider's object.

### 4.2 Contradictory evidence

Each contradictory entry declares:

```text
id, class, statement, source, retained, resolution
```

`class` is one of `native_observation`, `model_observation`,
`proof_counterexample`, `review_finding`, or `external_observation`.
`resolution` is `unresolved`, `explained`, or `resolved_by_new_evidence`.

Two rules are mandatory.

1. `retained` **must** be `true`. Setting it to `false` is a refusal
   (`contradiction_not_retained`). Contradictory evidence is not deleted when a
   positive result is obtained.
2. A retained `native_observation` or `proof_counterexample` that is not
   `resolved_by_new_evidence` **cannot** coexist with
   `supported_finite` or `proved_within_scope`. The validator refuses the
   combination (`contradictory_native_observation`).

A positive proof does not erase a contradictory native observation. The claim
must be narrowed, marked `refuted` or `challenged`, or superseded by new
evidence recorded as `resolved_by_new_evidence`.

## 5. Assumptions, TCB, and obligations

### 5.1 Assumptions

An assumption has an identifier, a statement, and one of these states:

```text
discharged
declared
unknown
refuted
not_applicable_with_evidence
```

Only `discharged` and `not_applicable_with_evidence` are resolved for promotion.
`declared`, `unknown`, and `refuted` block a `release_eligibility = eligible`
claim (`unknown_premise_promotion`). A `withheld` or `blocked` claim may carry
unresolved assumptions and remain valid bookkeeping.

### 5.2 Trusted computing base

`trusted_computing_base` is a non-empty list of components whose correctness is
assumed. A claim with no TCB is rejected as an integrity error. A trivially
empty TCB is usually a false statement; if a genuinely empty TCB is needed, a
later schema version must introduce an explicit representation.

### 5.3 Obligations

The obligation inventory is versioned separately. Each obligation has:

```text
id, statement, state, blocking, evidence
```

States are:

```text
unknown
contracted
established
independently_checked
discharged
blocked
stale
inapplicable_with_evidence
reopened
```

Only `discharged` and `inapplicable_with_evidence` are resolved for promotion.
For a release-eligible claim, every referenced `blocking` obligation must be
resolved (`blocking_obligation_promotion`). `established` and
`independently_checked` are progress, not discharge. `BLOCKED` never implies
discharge. `UNKNOWN` is not an empty success.

An unresolved obligation cannot be discharged by changing its label. A new state
requires typed evidence whose scope matches the obligation.

## 6. Validation rules

`etp validate` applies these rules in order.

### 6.1 Structural integrity (exit 3)

A manifest is rejected when any of the following holds:

- the bytes are not strict JSON (duplicate keys, floats, trailing bytes,
  resource-limit violation);
- `schema` or `spec` is not the supported version;
- a required coordinate or dimension is missing;
- an unknown field is present, including any scalar score field;
- a textual coordinate or identifier is empty or over 4096 bytes;
- the TCB list is empty;
- a claim identifier, assumption identifier, evidence identifier, or
  obligation identifier is duplicated;
- a claim references an obligation not present in the inventory;
- the baseline does not exactly match the frozen 1.0.0 release, commit, and
  evidence root;
- a collection exceeds its declared limit.

### 6.2 Claim ceiling and status semantics (exit 4)

The validator reports a refusal when any of the following holds:

- `property` is `sound_safe_interior` or `safe_compatible`
  (`forbidden_strong_property`);
- `quantification` or `legal_domain` is `universal_contextual`
  (`universal_quantification`);
- the coordinate quantifier and the dimension quantifier disagree
  (`dimension_mismatch`);
- `executed_native` has a non-native modality, or `executed_model` has a
  non-model modality (`modality_mismatch`);
- a contradiction is not retained (`contradiction_not_retained`);
- a positive outcome coexists with an unresolved decisive contradiction
  (`contradictory_native_observation`);
- a positive outcome has invalid evidence (`ineligible_evidence`);
- release is requested with a non-positive outcome (`ineligible_evidence`);
- release is requested with an unresolved assumption
  (`unknown_premise_promotion`);
- release is requested with an unresolved blocking obligation
  (`blocking_obligation_promotion`);
- release is requested with stale or expired freshness (`stale_evidence`);
- release is requested with inconsistent transparency
  (`inconsistent_transparency`).

A refusal is a valid report with exit 4. It is not a parse failure. This lets a
challenger inspect every refusal in one pass.

### 6.3 What acceptance means

Exit 0 means the manifest is structurally complete and makes no refused
promotion. It does **not** mean:

- the claim is true;
- the evidence is authentic;
- the reviewer is independent;
- the transparency log is complete;
- the deployment is secure;
- the software is certified.

## 7. Claim identity and invalidation

ETP v1 does not define a new cryptographic claim identity. A claim is identified
by its manifest-local `id` and by the exact coordinates that the consumer
chooses to bind. The baseline and evidence references are digest-bound.

The following are **distinct identities** and must not be rehashed into one
another:

- policy identity;
- predicate or acceptance-rule identity;
- subject identity;
- source identity;
- build identity;
- artifact identity;
- runtime environment;
- provider object identity.

Changing any `invalidation_dependencies` entry invalidates the claim. The
dependency list is declared by the producer; the validator checks that it is
present and non-empty, not that it is complete. Completeness is an obligation.

## 8. Campaign closure, adjudication, and revocation

These are specified processes. Phase 10.1 does not deploy them.

### 8.1 Campaign closure

A campaign is closed only when:

- the case population is declared before measurement;
- every case has a receipt or a typed `NOT_RUN`;
- no case is silently dropped;
- contradictions are retained;
- the acceptance predicate is frozen;
- an independent party can reconstruct the population and outcomes.

A closed campaign is not a population inference. A finite campaign does not
establish recall, precision, sensitivity, specificity, or deployment safety.

Phase 10.2 implements these closure rules for one finite, pre-registered native
fixture campaign in `src/etp_campaign.rs` and
`evaluation/earned-trust/`. The implementation refuses missing, duplicate,
unexpected, and truncated cases; derives counts only from the complete
population; retains failures and unresolved observations; and refuses a typed
`NOT_RUN` as a pass. A general campaign-closure service, adjudication workflow,
and revocation registry are still not deployed. See
[`ETP-CAMPAIGN.md`](ETP-CAMPAIGN.md).

### 8.2 Adjudication

An adjudication record must separate:

- the claim and its coordinates;
- the challenge and its evidence;
- the adjudicator's role and independence;
- the decision and its scope;
- the assumptions and TCB;
- the contradictions retained;
- the revocation or narrowing, if any.

Adjudicator approval is not code review. A signed adjudication is not truth.
Multiple signatures are not multiple independent reviewers unless independence
is verified as a separate dimension.

### 8.3 Revocation

A revocation must name:

- the exact claim or evidence identity;
- the changed dependency;
- the reason;
- the effective time;
- the scope of the revocation;
- whether historical replay remains valid under its original policy.

Historical validity is not present authorization. A revocation feed is not
complete merely because it is published. The 1.0.0 conversion module's
property-specific reuse and revocation is a local mechanism, not the general ETP
registry.

## 9. Examples

### 9.1 Valid withheld finite claim

A finite model-clear claim may be valid with:

- `quantification = finite_model_exhaustion`;
- `verification_outcome = supported_finite`;
- `evidence_validity = valid`;
- `release_eligibility = withheld`;
- one unresolved assumption.

This is honest bookkeeping: the finite result exists, but promotion is not
requested.

### 9.2 Refused universal claim

A claim with `quantification = universal_contextual` is refused even if every
other field is populated. The 1.0.0 evidence has no accepting rule for universal
soundness. A new schema version and new evidence are required to change this.

### 9.3 Retained contradiction

A claim with a retained native observation, an unresolved resolution, and
`verification_outcome = proved_within_scope` is refused. The proof is not
deleted; the claim is blocked until the contradiction is resolved by new
evidence or the claim is narrowed.

### 9.4 Unknown premise

A claim with `release_eligibility = eligible` and an assumption in `unknown`
state is refused. Changing only the assumption label to `discharged` without
evidence would be a relabeling violation, not a discharge.

## 10. Conformance vectors

The executable vectors are in `schemas/etp/vectors/` and are indexed by
`schemas/etp/vectors/index.json`. The registry records their SHA-256 values.
They cover:

- a valid manifest and its standalone claim, inventory, and dimensions;
- a missing coordinate;
- a missing dimension;
- a scalar confidence field;
- a merged or unknown dimension field;
- a dropped contradiction;
- a native observation contradicted by a positive proof;
- an unknown premise offered for release;
- a blocked obligation offered for release;
- a universal claim;
- a wrong schema version;
- an altered frozen baseline;
- a quantifier mismatch;
- a modality mismatch.

The Rust tests in `src/etp.rs` and `tests/etp.rs` execute the same rules.

## 11. Non-claims

This document does not claim that:

- any ETP manifest is true;
- any evidence is authenticated;
- any reviewer is independent;
- any transparency log is complete;
- any deployment is secure;
- any software is certified;
- any existing 1.0.0 result is stronger than its original finite, bounded,
  transcript-scoped, proof-scoped, or recorded-execution scope.
