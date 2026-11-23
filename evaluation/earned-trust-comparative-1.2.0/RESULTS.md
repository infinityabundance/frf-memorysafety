# 1.2.0 comparative replication: results and independent reconstruction

**Status:** development and the held-out partition were each executed once under
the original opening; three cases originally typed `NOT_RUN` were then replayed
under amendment `A002`; independently reconstructed with zero bookkeeping
discrepancies.
**Protocol:** `protocol.json`, `phase17.2-replication-1.2.0-amendment-002`,
SHA-256 `3f067d668a1bbdc5e7fbf4d79c0727b4c47259c9c407b134f1ec86f447dae1c4`.
**Held-out instrument:** `HELD-OUT-OPENING.sha256` (protocol + harness), re-frozen
under amendment `A002`.
**Replay record:** `REPLAY-1.2.0.md`; amendment: `AMENDMENT-002.md`.
**Reused protocol:** `evaluation/earned-trust-comparative/protocol.json`
(`phase17.2-amendment-001`).
**Frozen 1.0.0 baseline:** `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`.
**1.2.0 evidence closure:** `ece999b403e7ce05f94dbe2304a2b86b24afb1a9cd5dc5e1a5f57d22482d735a`.
**Binary:** `target/debug/frf-memorysafety`, SHA-256
`49937254ac5c35ff63f065f937b30e77674068f601a85e5111523daca0600e55`.

This is a **labeled replication** of the 1.1.0 comparative evaluation. It is not
a new held-out test, not a fresh discovery, and not external verification. The
18 case ids, the 6/12 partition, every mutation, every expected decision, the
ground truth and every metric are reused. See `REPLICATION.md`.

The held-out cases were executed once under the original opening. Their
expectations were not changed after execution and no post-hoc repair was
applied. The failures below stand.

Amendment `A002` is a **targeted replay** of the three cases that the original
run recorded as typed `NOT_RUN` (`c14`, `c15`, `c16`). Four declared artifacts
were produced by the existing 1.2.0 instrument gates, bound with their real
digests, and only those three cases were re-executed. The replay is not a new
discovery and does not turn a `NOT_RUN` into a pass. Because `c14` and `c15` are
held-out cases, they have now been executed twice: once under the original
digests (result: `NOT_RUN`, no decision) and once under the amended digests. That
deviation from single-execution is declared in `AMENDMENT-002.md` §4.

---

## 1. Population

18 cases, 6 development and 12 held-out, exactly as frozen by rule `SR1`. Every
case has one receipt. After amendment `A002` no case is typed `NOT_RUN`. The
independent reconstructor found **0** discrepancies between the protocol, the 18
receipts and the two harness analyses.

Three cases were originally `NOT_RUN` because the published 1.2.0 evidence set
did not contain their declared base artifacts. The four artifacts were then
produced by the declared 1.2.0 instrument gates and the three cases were
replayed. No 1.1.0 artifact was substituted and no mutation was replaced or
weakened.

| Case | Originally missing 1.2.0 base artifact(s) | Resolution |
|---|---|---|
| `c14-cross-property-regression` | `evaluation/earned-trust-1.2.0/cross-property/report-faulty.json`, `.../report-fixed.json` | produced by the cross-property gate; bound with real digests; case replayed |
| `c15-interop-collapsed-cell` | `evaluation/earned-trust-1.2.0/interop/report.json` | produced by the interop gate; bound with real digest; case replayed |
| `c16-tls-matrix-collapsed-cell` | `evaluation/earned-trust-1.2.0/tls-matrix/report.json` | produced by the tls-matrix gate; bound with real digest; case replayed |

The produced artifacts are marked `present_in_1.2.0_replay`. They are instrument
outputs for 1.2.0, not part of the published 1.2.0 campaign evidence. The six
other declared bindings that remain absent (`timing_branch`, `timing_ct`,
`timing_length`, `information_flow_model`, `information_flow_report`,
`witness_execution`) are not base artifacts of any case and stay
`absent_from_1.2.0_evidence`.

## 2. Development partition

| Case | Expected | Observed | Foundation | Restoration |
|---|---|---|---|---|
| `c01` positive campaign closure | accept | accept | accept | n/a |
| `c04` truncated population | refuse | refuse | accept | pass |
| `c07` signer role | refuse | refuse | accept | pass |
| `c10` time wrong imprint | refuse | refuse | accept | pass |
| `c13` SARIF suppression | refuse | refuse | accept | pass |
| `c16` TLS collapsed cell | refuse | **refuse** | accept | pass |

```text
cases=6 accept=1 refuse=5 not_run=0 unresolved=0 instrument_errors=0
decision_accuracy=6/6 wrongful_acceptance=0 wrongful_refusal=0
metric M4: direct unresolved=0, typed NOT_RUN=0, M4 unresolved total=0
wrong-code command refusals=2 (c13)
restoration: 5/5 executed negative cases passed
```

## 3. Held-out partition

| Case | Expected | Observed | Foundation | Restoration | Note |
|---|---|---|---|---|---|
| `c02` candidate substitution | refuse | refuse | accept | pass | |
| `c03` completeness deletion | refuse | refuse | accept | pass | |
| `c05` duplicate population row | refuse | refuse | accept | pass | |
| `c06` DSSE payload substitution | refuse | refuse | accept | pass | wrong-code: independent verifier exits 3 |
| `c08` transparency inclusion | refuse | refuse | accept | **unresolved** | independent verifier output is not JSON-stable on restoration |
| `c09` stale checkpoint | refuse | refuse | accept | **refuse** | restored checkpoint reports `partial` / `consistency_not_checked` at exit 0 |
| `c11` withdrawn claim | refuse | refuse | accept | **refuse** | Rust claim-level refusal; independent verifier accepts |
| `c12` missing archive object | refuse | refuse | accept | **pass** | improved: intact 1.2.0 archive reconstructs |
| `c14` cross-property regression | refuse | **refuse** | accept | **pass** | replayed under A002 |
| `c15` interop collapsed cell | refuse | **refuse** | accept | **pass** | replayed under A002 |
| `c17` proof closure removal | refuse | refuse | accept | **unresolved** | wrong-code manifest refusal; restore returns `checker_unavailable` |
| `c18` positive archive reconstruction | accept | **accept** | accept | pass | improved: 1.2.0 archive includes the declared source tree |

```text
cases=12 accept=1 refuse=11 not_run=0 unresolved=0 instrument_errors=0
decision_accuracy=12/12 wrongful_acceptance=0 wrongful_refusal=0
foundation_augmented_agreement=1/12
metric M4: direct unresolved=0, typed NOT_RUN=0, M4 unresolved total=0
wrong-code command refusals=2 (c06, c17)
restoration: 7/11 executed negative cases passed; 4 failed (c08, c09, c11, c17)
```

The frozen metric M4 defines a decision that returns a typed `NOT_RUN` as
`unresolved`. After the replay no held-out case returns `NOT_RUN`, so held-out
M4 unresolved is 0.

Across both partitions:

```text
cases=18 matched=18 not_run=0
wrongful_acceptance=0 wrongful_refusal=0
unresolved=0 instrument_errors=0
metric M4: direct unresolved=0, typed NOT_RUN=0, M4 unresolved total=0
restoration failures=4 (c08, c09, c11, c17)
wrong-code command refusals=4 commands over 3 cases (c06, c13, c17)
```

The three replayed cases remain in the 18-case denominator. A `NOT_RUN` is not a
pass; a replayed case is recorded as matching or not matching its frozen
expectation, not as a repaired or strengthened result.

## 4. Independent reconstruction

`reconstruct_analysis.py` does not import the harness. It recomputes the
partition, the per-case expected/observed matrix, the wrongful counts, the
`NOT_RUN` set and the restoration outcomes from the 18 committed receipts, then
checks both harness analyses against that recomputation.

```text
RECON development cases=6 matched=6 wrongful_acceptance=0 wrongful_refusal=0 unresolved=0 instrument_errors=0 not_run=0 restoration_failures=0
RECON held-out   cases=12 matched=12 wrongful_acceptance=0 wrongful_refusal=0 unresolved=0 instrument_errors=0 not_run=0 restoration_failures=4
PASS independent analysis reconstruction
discrepancy_count=0
```

The reconstruction establishes bookkeeping agreement only. It does not re-run a
verifier, does not establish that a refusal is correct, and is not
certification.

## 5. Negative findings

These are the substance of the replication. They are preserved, not repaired by
changing expectations.

### 5.1 `c18` now accepts because the 1.2.0 archive includes the source tree

In 1.1.0 the intact archive reported `reconstruction.complete: false` and the
independent reconstruction failed because `Cargo.toml` and the source tree were
absent. The 1.2.0 archive has 106 objects instead of 76 and preserves the
declared candidate and instrument source files. Both decisive commands now
accept:

- `etp archive verify` exits 0, status `verified`, `problems: []`,
  `missing_required_categories: []`, `reconstruction.complete: true`;
- `reconstruct.py --root . --json` exits 0 with `case_count: 13` and
  `closure_sha256: ece999b403e7ce05f94dbe2304a2b86b24afb1a9cd5dc5e1a5f57d22482d735a`.

`c12` restoration also improves: the intact archive now accepts, so the
restoration control passes. The `c12` case run still refuses on the deleted
object with `incomplete_reconstruction`, as declared.

The archive repair alone is not sufficient for the observed acceptance. The
1.1.0 accepting predicate compared the whole `ReconstructionReport` object to
`{"complete": true}`, which no report can satisfy. The predicate was
re-expressed as `reconstruction.complete: true` before execution (section 1).
Under the old encoding the archive command would have been `unresolved` even
with a complete archive. Both the archive repair and the encoding correction are
necessary, and neither changes the expected decision.

This does **not** establish that the archive is authentic, complete, externally
anchored, or independently reproducible.

### 5.2 `c11` claim-level disagreement persists

The Rust verifier exits 0 with `present_admissible: false` for
`claim.campaign-closure`, which the harness treats as a claim-level refusal. The
independent `verify_revocation.py` exits 0 and is classified as accepting
because its accepting outcome does not inspect the claim field. The case still
refuses because one decisive command refuses, but the instruments are not
equivalent. The restoration control re-runs the same `claim.campaign-closure`
selection, so it is recorded as a refusal rather than the declared
`claim.campaign-closure-with-mirror` acceptance. This is the same
command/expectation design defect as 1.1.0, retained.

### 5.3 `c13` SARIF schema disagreement persists

The Rust `SarifSuppressionProperties` denies `suppression_id`, and the
independent verifier refuses with `InconsistentCount` because the suppressed
result count is not zero. Both refuse, so the decision matches ground truth, but
neither reaches the declared suppression-review diagnostic. The case is
recorded with two wrong-code command refusals in both 1.1.0 and 1.2.0.

### 5.4 Transparency restoration instruments persist (`c08`, `c09`)

- `c08`: the independent `verify_transparency.py` is invoked without `--json`,
  so its restoration output cannot be checked against a declared
  `report_status`; the harness records `unresolved`.
- `c09`: `etp checkpoint verify` exits 0 on the restored checkpoint but reports
  `partial` with `consistency_not_checked`, which does not satisfy the declared
  accepting outcome; the harness records a refusal.

These are command/expectation design problems in the preregistration, not 1.2.0
regressions.

### 5.5 `c17` manifest-only proof verification persists

`proof verify` without `--live` exits 3 on the mutated manifest with a precise
closure error, but exits 6 (`checker_unavailable`) on the restored manifest. The
executable acceptance model accepts. The case refuses, but the diagnostic code
is undeclared and the restoration is unresolved because no checker is configured
in the harness container. Manifest validation is not proof checking.

### 5.6 `c06` independent attestation verifier persists

The Rust `etp attest verify` refuses with `invalid_signature` as declared. The
independent `verify_attestations.py` exits 3 without a declared refusal code, so
it is recorded as a wrong-code refusal. The case refuses and its restoration
passes.

### 5.7 Replayed `NOT_RUN` cases

`c14`, `c15` and `c16` were typed `NOT_RUN` in the original 1.2.0 run because
the published 1.2.0 evidence set did not contain the cross-property, interop or
tls-matrix artifacts they declare. Amendment `A002` produced those artifacts
with the declared 1.2.0 instrument gates and replayed only those three cases
(`REPLAY-1.2.0.md`). All three now refuse as declared, and all three restoration
controls pass.

This is a re-run, not a first execution and not a fresh discovery. `c14` and
`c15` are held-out cases that have now been executed twice: the first execution
returned no decision (`NOT_RUN`). The expectations were frozen before either
execution and are unchanged. The single-execution property of the held-out
partition is therefore weakened for those two cases; see `AMENDMENT-002.md` §4.

The replayed decisions include no new wrong-code refusal, no wrongful acceptance
and no wrongful refusal. The pre-existing negative findings in sections 5.2 to
5.6 are unchanged.

## 6. Acceptance criteria

| Criterion | Result |
|---|---|
| held-out wrongful acceptances = 0 | met: 0 |
| held-out unresolved = 0 | met: direct `unresolved` = 0 and metric M4 unresolved = 0 |
| every declared positive control accepted | met: `c01` and `c18` both accept |
| every negative refused with a declared code (stricter, reported separately) | **not met**: 3 cases with wrong-code command refusals (`c06`, `c13`, `c17`) |
| all 18 cases executed | met: 18 executed, 0 `NOT_RUN` after the A002 replay |

The three preregistered held-out criteria are now met. The stricter additional
control-effectiveness expectation is **not** met, and the four restoration
failures remain. Meeting the held-out criteria must not be read as a complete
18-case success or as a correct refusal for every case.

## 7. Costs

Held-out: 762 ms total verification wall clock, 489,861 bytes of declared
base-artifact input size. Development: 378 ms, 313,553 bytes. Restoration wall
clock: 802 ms held-out, 449 ms development. These are resource accounting only;
timing is environment-specific and not comparable across hosts, images, or runs.
The held-out figures include the two replayed cases, and the development figures
include the replayed `c16`. Independent reconstruction cost was not separately
preregistered, so no reconstruction-cost claim is made.

## 8. Claims

| Claim | Status | Basis |
|---|---|---|
| Q1 population | supported for the 18-case population | 18 receipts, 6/12, disjoint, zero reconstruction discrepancies, every case executed; six declared non-case artifact bindings remain absent from the published 1.2.0 evidence |
| Q2 modeled foundation | supported | 18/18 foundation accepts, as defined |
| Q3 discrimination | supported for the full population | 16/16 executed negatives refused and 2/2 positives accepted |
| Q4 acceptance criteria | partially supported | the three held-out criteria are met (wrongful acceptance 0, M4 unresolved 0, positive controls accepted); the stricter all-negatives-refused-with-a-declared-code expectation fails |
| Q5 specificity and restoration | refuted | 4 restoration failures and 4 wrong-code command refusals |
| Q6 independent corroboration | refuted | c06 wrong-code, c11 claim-level disagreement, c17 instrument mismatch, c08 not JSON-stable |
| Q7 accounting | supported | no refusal counted as a pass; `NOT_RUN` not counted as a pass |
| Q8 cost | partially supported | verification cost measured; reconstruction cost not separately measured |
| Q9 reporting | supported | all failures, wrong-code refusals and `NOT_RUN` cases retained |
| Q10 non-generalization | supported | replication is not a new held-out test and no universal or deployment claim is made |

## 9. Non-claims

This replication does not establish memory safety, functional correctness,
detector sensitivity, population-level accuracy, external independence,
administrative independence, public transparency, external trusted time,
certification, or authorization to deploy. The foundation is a modeled baseline
over committed labels, not an execution of the 1.0.0 binary. Agreement between
the 1.1.0 and 1.2.0 replications does not establish correctness. A refusal is not
a pass. A `NOT_RUN` is not a pass. A digest is not authentication.
