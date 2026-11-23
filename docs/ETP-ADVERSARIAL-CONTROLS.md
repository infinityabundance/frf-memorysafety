# ETP adversarial acceptance controls

**Subphase:** Phase 16.1b.
**Artifacts:** `evaluation/earned-trust/verify_acceptance_model.py`,
`ci/etp-formal-acceptance-gate.sh`, and the generated receipt
`evaluation/earned-trust/receipts/acceptance-controls.json`.
**Companion model:** `tests/proof/coq/etp_acceptance.v` (Phase 16.1a).
**Frozen baseline:** FRF-MemorySafety 1.0.0 at commit
`02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`. This subphase changes no frozen
artifact, no schema meaning, no case population and no claim ceiling.

This document records what the Phase 16.1b gate actually executed and what its
output does and does not establish. It is an instrument artifact. It is not
evidence that the Rust crate is sound.

---

## 1. What was built and why

Phase 16.1a mechanised a finite acceptance predicate in Coq: admission requires
a present, unchallenged, unrevoked finite derivation of the evaluated claim, and
a policy-satisfied state whose reported claim is that claim. Twelve priority
invariants were proved about that predicate.

Phase 16.1b adds a second, executable instrument: a standalone model of the same
finite predicate that is driven by seventeen control instances and reports a
deterministic JSON receipt. The purpose is to make the control behaviour
*executable* and *inspectable*, not to prove anything new. In particular it
checks that the refusals are not the behaviour of an always-reject detector:
every primary refusal is paired with a restoration that starts from the mutated
policy/state, undoes exactly the fields recorded in `mutation_fields`, verifies
that the result equals the valid base, and then requires admission.

`verify_acceptance_model.py`:

- uses the Python 3 standard library only;
- does not import, link, shell out to or read the Rust crate;
- does not read, parse or re-use `tests/proof/coq/etp_acceptance.v` at runtime;
- is a **separate authoring pass from the Coq file, by the same agent**. That
  makes it an independent *implementation*, not independent *confirmation*.

## 2. The executable model

Finite universe, matching the Phase 16.1a declarations:

- premises `pA`, `pB`, `pC`, `pD`;
- claims `c0`, `c1`, `c2`;
- four derivation rules. A derivation is a finite nested tuple:

```text
("c0", "pA")   c0 from pA
("c1", "pB")   c1 from pB
("c0", "pC")   c0 from pC
("c2", d0, d1) c2 from a c0 derivation and a c1 derivation
```

Support is enumerated per claim. The grammar is non-recursive apart from the
binary `c2` rule, so the derivation universe is finite and the receipt records
all five inhabitants (two `c0`, one `c1`, two `c2`). Well-formedness is checked
structurally: arity, leaf grammar, the child claim index of the binary rule, an
empty leaf set, an explicit `("cycle", ...)` marker, and — without building any
infinite object — a genuinely self-referential but finitely sized object graph.

The acceptance rule is:

```text
policy_satisfied(policy, state)
and state.reported_claim == claim
and SOME finite derivation of claim exists whose every leaf premise is
    present, unchallenged and unrevoked
```

Support is existential, matching `admitted` in the Coq model: one admissible
derivation is sufficient. A rejected alternative derivation is recorded in
`supports_considered` but does not veto an admissible one. Only when no
derivation is admissible are the individual support reasons promoted to the
top-level refusal record.

`policy_satisfied` covers policy version, candidate identity, campaign
implication, the independent-actor threshold, freshness implication, archive
implication and presence of every required premise. Authentication is not a
condition, and the positive control keeps `authenticated = true` so that this is
observable rather than asserted.

## 3. Control families and counts

| Family | Records | Assertion checks | Meaning |
|---|---|---|---|
| positive | 1 | 1 | The fully valid policy/state/derivation is admitted. |
| primary | 12 | 24 | One negative control per Phase 16.1a invariant, each with a restoration that undoes only its recorded mutation. |
| structural | 4 | 11 | Empty leaf set, cyclic support, claim-index typing, and existential alternative support; each with a restoration. |
| **total** | **17** | **36** | 36 checks, 0 failed. |

The primary controls, with the exact reason codes the executed model returned:

| # | Control | Invariant (Coq theorem) | Mutation | Observed |
|---|---|---|---|---|
| 1 | `p01_no_unsupported_support` | `no_unsupported_or_cyclic_admission` | support universe of `c2` set to empty | `no_support_available` |
| 2 | `p02_missing_mandatory_premise` | `missing_mandatory_evidence_blocks` | `pD` added to required premises and marked absent | `required_premise_absent:pD` |
| 3 | `p03_candidate_substitution` | `candidate_substitution_invalidates` | state bound to candidate 8, policy names 7 | `candidate_mismatch` |
| 4 | `p04_authenticated_but_unsupported` | `authentication_is_not_semantic_support` | `authenticated = true`, both `c0` leaves removed | `premise_absent:pA`, `premise_absent:pC` |
| 5 | `p05_unrelated_proof` | `unrelated_proof_does_not_satisfy` | reported claim `c0` while evaluating `c2` | `reported_claim_mismatch` |
| 6 | `p06_challenged_premise` | `challenged_premise_blocks` | `pB` challenged (occurs in every `c2` derivation) | `premise_challenged:pB` |
| 7 | `p07_revoked_premise` | `revoked_premise_invalidates` | `pB` revoked (occurs in every `c2` derivation) | `premise_revoked:pB` |
| 8 | `p08_incomplete_campaign` | `incomplete_campaign_blocks` | campaign open while required closed | `campaign_not_closed` |
| 9 | `p09_duplicate_credentials` | `duplicate_credentials_do_not_satisfy_independence` | one independent actor against threshold two | `insufficient_independent_actors` |
| 10 | `p10_stale_transparency` | `stale_transparency_blocks` | transparency stale while required fresh | `stale_transparency` |
| 11 | `p11_missing_archive` | `missing_archive_blocks_reconstruction` | archive absent while required | `archive_missing` |
| 12 | `p12_policy_version_substitution` | `policy_substitution_blocks` | policy version 2 against observed version 1 | `policy_version_mismatch` |

For controls 6 and 7 the receipt also records the side condition
`premise_occurs_in_every_derivation_of_c2: true`, computed from the enumerated
support set, so the refusal is not a coincidence of one chosen derivation.

Structural controls:

| Id | Meaning | Observed |
|---|---|---|
| `s01_empty_leaf_set` | `("c2",)` has no child derivations and therefore no leaves | `empty_support`; the grammar minimum leaf count is 1 |
| `s02_cyclic_support_marker` | explicit `("cycle", "c0")` marker, then a self-referential list inside a `c2` node | `cyclic_marker_not_finite` for both |
| `s03_claim_index_mismatch` | a `c1` derivation offered for `c2`, then a `c2` node with swapped children | `claim_index_mismatch`, `ill_typed_child` |
| `s04_alternative_support` | required premises `[pB,pC]`, `pA` absent, `pC` present: the `c0`-from-`pA` derivation is rejected but the `c0`-from-`pC` derivation is admissible, so existential acceptance must admit `c2`; removing `pC` as well must refuse | admitted `(c2, (c0, pC), (c1, pB))`; inverse refused with `no_admissible_support` |

Each structural control is followed by a restoration with the finite well-typed
`c2` derivation, which must be admitted. `s04` is the discriminating control for
existential semantics: an earlier version of this oracle rejected a claim when
any enumerated support failed, which diverges from the existential `admitted`
in Coq. That version was rejected during verification, corrected, and `s04` was
added so the two semantics cannot silently converge again. The committed
receipt records only the corrected model.

## 4. Measured evidence

Everything below was produced inside Docker on the workstation used for this
subphase. Nothing was executed on the host: the host only created directories,
hashed and compared files, copied the receipt, and ran `git status`.

| Item | Value |
|---|---|
| Gate | `./ci/etp-formal-acceptance-gate.sh` |
| Container image | `python:3.11-slim` |
| Image id | `sha256:896edfbcbf0c29ad15681617a8886cb9871b7f24c5fde4606114c8ee6bfe4c70` |
| Verifier SHA-256 | `49deb173eac685e42b86f50c6e5fdb0795db5929f54cb4fd4614c6faa66abb10` |
| Receipt SHA-256 | `6cf8b0f51a3fdd85f25f84e02e569d9fa8253573148486c8b2d1113ad2528ad9` |
| Receipt bytes | 22459 |
| Checks | 36 passed, 0 failed |
| Positive admissions | 1 |
| Primary refusals | 12 of 12 |
| Primary restorations | 12 of 12 |
| Structural refusals | 6 (across 4 controls) |
| Structural admissions | 1 (`s04`, existential alternative support) |
| Structural restorations | 4 of 4 |
| Gate result | `PASS etp-formal-acceptance-gate` (exit 0) |

The gate printed these totals line:

```text
TOTALS controls=17 checks=36 passed=36 failed=0 primary=12 primary_refused=12 primary_restorations=12 structural=4 structural_refusals=6 structural_admissions=1 structural_restorations=4
PASS etp-formal-acceptance-gate
```

Determinism: the gate was run twice after the final edit of the verifier.
Both runs printed byte-identical output, and the receipt written inside the container
(`target/gate-logs/acceptance-controls.json`) was byte-identical to the copied
host receipt. Both runs reported receipt SHA-256
`6cf8b0f5...528ad9`. The receipt contains no timestamp, hostname,
path outside the repository, duration or other volatile field.

### Container controls

The verifier ran with exactly these hardening flags:

```text
--memory=2g --memory-swap=2g --pids-limit=512 --cpus=2
--ulimit nofile=1024:1024 --oom-score-adj=500
--cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER
--security-opt no-new-privileges
```

The gate additionally sets `--network=none`, which is a further restriction on
the declared flag set, not a relaxation. The repository is mounted read-only at
`/src`; `target/` is the only writable mount, at `/src/target`. The verifier
writes the receipt to `/src/target/gate-logs/acceptance-controls.json`. The only
host action on the artifact is the copy into `evaluation/earned-trust/receipts/`.

## 5. Evidence kind

The receipt says `"evidence_kind": "EXECUTED_MODEL"`. That means an executable
model was run and its control assertions were observed. It does **not** mean:

- that the Rust crate executed — no Rust source, binary, feature or test was
  read, built or run in this subphase;
- that a Coq proof was checked — `coqc` was not invoked by this gate, and the
  `.v` file is not read by the verifier;
- that the model refines the Coq model or the Rust implementation.

## 6. Claim ceiling

For the seventeen control instances recorded in the receipt, the executable model
admits the fully valid instance, refuses each mutated instance, and reverses each
primary refusal when only the recorded mutated fields are restored. That is the
whole claim.

## 7. Explicit non-claims

- **Not a proof.** No theorem is stated, checked or certified. The Coq
  development of Phase 16.1a is the proof artifact; this receipt is not a
  machine check of it.
- **Not Rust verification.** The crate, its binaries and its gates are outside
  this subphase's execution.
- **Not memory-safety evidence.** The subject is an abstract acceptance
  predicate.
- **Not refinement.** No correspondence is established between this model, the
  Coq model, and any Rust acceptance implementation. The two models share an
  author and a stated semantics, so their agreement would be instrument parity,
  not independent confirmation.
- **Not exhaustive.** Seventeen hand-declared control instances are not an
  exhaustive analysis of the policy/state space. The finite universe is small
  enough to enumerate derivations, but the policy and state space is not
  enumerated.
- **Not independent review, adjudication or certification.** No external party
  approved this artifact. A green gate is not authorization to deploy.
- **Not a claim about the frozen 1.0.0 baseline.** No 1.0.0 artifact, schema
  meaning, case population or claim ceiling was changed, and none is
  re-blessed by this gate.

## 8. Known limits of the controls themselves

Recorded so they are not mistaken for stronger evidence than they are:

- Control `p01` mutates the support universe of the evaluated claim rather than
  a policy or state field. The refusal is therefore produced by the model's
  "no finite derivation exists" branch. The structural family exercises the same
  invariant from the well-formedness side (empty leaves, cyclic support,
  ill-typed support), so the invariant is covered from two directions, but `p01`
  alone is a universe-level mutation.
- Controls `p04`, `p06` and `p07` also report `no_admissible_support`, which is
  the consequence of every support failing, in addition to the specific cause
  (`premise_absent`, `premise_challenged`, `premise_revoked`). The receipt keeps
  both; the control assertion requires the specific cause to be present.
- The restorations prove the model is not an always-reject detector and that
  each refusal is specific to its mutated fields: the restoration starts from
  the mutated objects, undoes exactly the recorded fields, checks equality with
  the valid base, and requires admission. They do not prove the model is
  correct, minimal, or equivalent to the Coq predicate.
- Three structural controls use more than one sub-case (cyclic marker plus
  self-referential object; wrong claim index plus swapped children; alternative
  support plus its removal) and are counted as one control record each, with
  six refusal checks and one admission check across four records.
