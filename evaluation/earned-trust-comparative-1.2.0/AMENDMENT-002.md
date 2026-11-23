# Amendment 002: targeted replay bindings for `c14`, `c15` and `c16`

**Recorded against:** `protocol.json`, version
`phase17.2-replication-1.2.0-amendment-002`.
**Predecessor:** `phase17.2-replication-1.2.0` (SHA-256
`b4488e4836253e75ee01597857e29a37a89cd23cec9b6eda7a3f8fabdd1c5b76`).
**Amended protocol:** SHA-256
`3f067d668a1bbdc5e7fbf4d79c0727b4c47259c9c407b134f1ec86f447dae1c4`.
**Kind:** targeted replay of three previously typed `NOT_RUN` cases and the
artifact bindings needed to execute them.
**Execution record:** `REPLAY-1.2.0.md`.

This amendment is an instrument and binding change. It is not a new held-out
test, not a fresh discovery, not a reclassification of a `NOT_RUN` as a pass,
and not external verification.

---

## 1. Why the amendment exists

The published 1.2.0 evidence set does not contain the cross-property, interop or
tls-matrix artifacts that the frozen cases `c14`, `c15` and `c16` declare as base
artifacts. The original 1.2.0 run therefore recorded all three as typed
`NOT_RUN`. `NOT_RUN` was, and remains, a correct record of that run.

This amendment produces those four artifacts with the already declared 1.2.0
instrument gates, binds their real SHA-256 values, and re-executes only those
three cases under the unchanged mutation, expectation, ground truth,
restoration control and decision surface.

## 2. What changed

| Item | Before | After |
|---|---|---|
| `protocol.json` SHA-256 | `b4488e4836253e75ee01597857e29a37a89cd23cec9b6eda7a3f8fabdd1c5b76` | `3f067d668a1bbdc5e7fbf4d79c0727b4c47259c9c407b134f1ec86f447dae1c4` |
| `run_comparative.py` SHA-256 | `c214ae17010031295e33084c582c1d5af9003c382b21bc78b808cacf5db37141` | `e7dfec3691fd3554a103e787d0ed3182deec6de77bdb74f8c8a3baa8e2b8fb37` |
| `artifact_bindings[cross_property_faulty]` | `sha256: null`, `absent_from_1.2.0_evidence` | `present_in_1.2.0_replay`, real digest |
| `artifact_bindings[cross_property_fixed]` | `sha256: null`, `absent_from_1.2.0_evidence` | `present_in_1.2.0_replay`, real digest |
| `artifact_bindings[interop_report]` | `sha256: null`, `absent_from_1.2.0_evidence` | `present_in_1.2.0_replay`, real digest |
| `artifact_bindings[tls_matrix_report]` | `sha256: null`, `absent_from_1.2.0_evidence` | `present_in_1.2.0_replay`, real digest |
| `replication.absent_artifacts` | contained the four ids above | the four ids removed; `replication.artifacts_produced_by_replay` added |
| `OPENING.sha256` | froze the predecessor protocol | re-frozen over the amended protocol |
| `HELD-OUT-OPENING.sha256` | froze the predecessor protocol and harness | re-frozen over the amended protocol and harness |

The harness gained one optional argument, `--cases`. Without `--cases` its
behaviour is unchanged: it selects the whole declared partition. With
`--cases` it executes only the named cases from the selected partition and
builds the analysis over the full declared partition, taking the non-replayed
cases from their committed receipts unchanged. The filter cannot add, remove or
reorder a case in the population, and it does not alter a mutation, an
expectation, a metric or a decision surface.

## 3. What did not change

Byte-for-byte unchanged in intent and in meaning:

- the 18 case ids and the 6/12 development / held-out partition (`SR1`);
- every mutation kind and operation, including the three replay cases;
- every `expected_augmented_decision`, every ground-truth decision and every
  restoration expectation;
- every metric definition, threshold, acceptance criterion, stopping rule,
  exclusion rule and claim ceiling;
- the two decision surfaces and the typed exit mapping.

No expected decision was edited. No case was moved between partitions. No case
was added or removed.

### 3.1 Byte-level check that nothing else changed

Reverse-applying exactly the edits recorded in this amendment to
`protocol.json` reproduces SHA-256
`b4488e4836253e75ee01597857e29a37a89cd23cec9b6eda7a3f8fabdd1c5b76`, the
original protocol digest. Reverse-applying exactly the edits recorded here to
`run_comparative.py` reproduces SHA-256
`c214ae17010031295e33084c582c1d5af9003c382b21bc78b808cacf5db37141`, the
original harness digest. Both reverse-applications were checked in this run.

The two digests matching means that the only byte changes are the ones recorded
above. In particular the `cases` array (mutations, expected decisions, ground
truth, restoration controls), the `partitions` object, the `metrics`,
`acceptance_criteria`, `stopping_rules`, `exclusion_rules`, both decision
surfaces and the claim ceiling are byte-for-byte identical to the predecessor
protocol. This check is a digest derivation, not authentication.

## 4. Declared deviation: the two held-out cases execute twice

`HELD-OUT-OPENING.md` rule 2 states that the 12 held-out cases execute once
under the frozen digests. `c14` and `c15` were executed once under the original
digests and returned typed `NOT_RUN` because their declared base artifacts were
absent. This amendment re-executes both under new digests.

This is a declared deviation from the single-execution rule:

- the first execution produced **no decision** and therefore no result that
  could be inferred from, fitted to, or gamed by the second;
- the expectation for both cases was frozen before the first execution and is
  unchanged;
- the new base artifacts are produced by the declared gates, not selected to
  make a decision come out in a preferred way;
- the replay is reported as a re-run of previously `NOT_RUN` cases, not as a
  first execution and not as a new held-out test.

The deviation still weakens the "executed exactly once" property for those two
held-out cases. A reader must not describe the 1.2.0 held-out partition after
this amendment as single-execution evidence.

## 5. Pre-existing instrument defect retained

The c14 mutation log records `metadata.trace_lines[2].from` incorrectly. In
`apply_mutation`, `fixed_lines` aliases the list that is then mutated, so the
`from` preview equals the `to` preview. The mutation itself is applied
correctly, and the same defect is present in the frozen 1.1.0 receipt
(`evaluation/earned-trust-comparative/receipts/c14-cross-property-regression.json`).
It is retained and reported rather than repaired, so the replay stays comparable
with the frozen 1.1.0 instrument. It affects only the human-readable mutation
preview, not a case decision.

## 6. Non-claims

This amendment does not convert a `NOT_RUN` into a pass. It does not establish
that the three cases are correctly decided, that the replay outputs are
authentic evidence, that the instrument gates are adequate, or that the
`present_in_1.2.0_replay` artifacts are part of the published 1.2.0 campaign
evidence. They are not. A digest is not authentication. A reconstruction with
zero discrepancies is a bookkeeping statement, not a review.
