# 1.2.0 replication of the Phase 17.2 comparative evaluation

**Status:** labeled replication, frozen and executed once for the held-out
partition after the development partition.
**Protocol:** `protocol.json`, version `phase17.2-replication-1.2.0`.
**Opened by:** `OPENING.sha256` and `HELD-OUT-OPENING.sha256`.
**Reused protocol:** `evaluation/earned-trust-comparative/protocol.json`
(`phase17.2-amendment-001`, SHA-256
`cdc78441ed23a8f942a1fc5f4bb59192be9120adfb6c5135047d4435a2de00df`).
**Frozen 1.0.0 baseline:** `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`.
**1.2.0 evidence:** `evaluation/earned-trust-1.2.0/`, closure
`ece999b403e7ce05f94dbe2304a2b86b24afb1a9cd5dc5e1a5f57d22482d735a`,
candidate `79e72160a6a1c169093d5e7abb39f426a9f189d07aef7ddc472b3856911bcbb7`,
opening `180e50318dc045c9ea81168c7e1e958e1d9e108b9a99c662f06081967e8b7f8a`.

This document is a migration and replication record. It is not a result, a
review, a certification, or external verification.

---

## 1. What this is

This is a **replication**, not a fresh held-out discovery. The same 18 case ids,
the same 6 development / 12 held-out partition produced by rule `SR1`, the same
deterministic mutations, the same expected augmented decisions, the same
ground-truth decisions and the same metric definitions are reused from the
frozen 1.1.0 comparative protocol. The cases were already exposed during the
1.1.0 run; the 1.2.0 held-out partition is therefore **not** a new temporal
hold-out and must not be described as one.

The purpose is narrower: determine which 1.1.0 comparative observations change
when the same declared controls are bound to the published 1.2.0 evidence and
the 1.2.0 binary.

## 2. What was reused unchanged

- the 18 case ids and their order;
- the 6/12 development/held-out partition and selection rule `SR1`;
- every mutation kind and mutation operation;
- every expected augmented decision and every ground-truth decision;
- the decision surfaces, combine rule, metrics, acceptance criteria, stopping
  rules, exclusion rules and negative-finding policy;
- the restoration-control kinds and declared restoration expectations.

No case was added, removed, reclassified, or reweighted.

## 3. What was rebound

| Item | 1.1.0 value | 1.2.0 value |
|---|---|---|
| Evidence root | `evaluation/earned-trust/` | `evaluation/earned-trust-1.2.0/` |
| Artifact SHA-256 | frozen 1.1.0 digests | recomputed from the published 1.2.0 bytes |
| Verifier copies | `evaluation/earned-trust/verify_*.py` | `evaluation/earned-trust-1.2.0/verify_*.py` where the 1.2.0 evidence set provides one |
| c10 recorded imprint | `d26e19bd...` | `ece999b403e7ce05f94dbe2304a2b86b24afb1a9cd5dc5e1a5f57d22482d735a` |
| c18 closure binding | `d26e19bd...` | `ece999b403e7ce05f94dbe2304a2b86b24afb1a9cd5dc5e1a5f57d22482d735a` |
| Verifier time bound | `1795342702` / `1795330364` | `1795417304` (the declared 1.2.0 generation-time bound) |
| c01 policy-metadata argv | no `--now` | `--now 1795417304` (required by the 1.2.0 verifier) |

The c10 mutation is still "use the all-zero imprint instead of the committed
imprint". The c18 expected decision is still `accept`. The c11 expected decision
is still `refuse`. Only the binding value changed.

`interop_matrix.py`, `tls_matrix.py` and `cross_property.py` were not migrated
into the 1.2.0 evidence set. Their instrument bindings still name the unchanged
`evaluation/earned-trust/` scripts.

## 4. Absent 1.2.0 artifacts and the A002 replay

The published 1.2.0 evidence set does not contain timing, information-flow or
witness artifacts, nor (originally) cross-property, interop or tls-matrix
artifacts. The frozen protocol declares ten such artifact bindings. Six remain
`binding_status: absent_from_1.2.0_evidence` with `sha256: null`; the harness
verifies that the declared 1.2.0 path is genuinely absent and fails closed if a
file later appears there.

Four of the ten were produced by the declared 1.2.0 instrument gates under
amendment `A002` (`REPLAY-1.2.0.md`) and are bound as
`present_in_1.2.0_replay`. Three cases declare them as base artifacts:

| Case | Base artifacts | Original handling | After A002 |
|---|---|---|---|
| `c14-cross-property-regression` | `cross_property_faulty`, `cross_property_fixed` | typed `NOT_RUN` | replayed: `refuse`, restoration `accept` |
| `c15-interop-collapsed-cell` | `interop_report` | typed `NOT_RUN` | replayed: `refuse`, restoration `accept` |
| `c16-tls-matrix-collapsed-cell` | `tls_matrix_report` | typed `NOT_RUN` | replayed: `refuse`, restoration `accept` |

`NOT_RUN` was not a pass and was not a correct refusal. The replayed cases
remain in the 18-case denominator and are recorded as matching their frozen
expectations. The remaining six absent bindings (`timing_branch`, `timing_ct`,
`timing_length`, `information_flow_model`, `information_flow_report`,
`witness_execution`) are not base artifacts of any case and are retained as
declared-absent records so the corpus is not silently erased.

## 5. Instrument corrections made before execution

Two encoding defects were identified from the frozen 1.1.0 protocol and the
committed 1.1.0 evidence, not from a 1.2.0 result:

1. **Policy-metadata verifier time bound.** The 1.2.0
   `verify_policy_metadata.py` requires an explicit `--now`. The c01 command
   supplied none. The command was rebound to the declared 1.2.0 generation-time
   bound `1795417304`.
2. **Archive accepting predicate encoding.** The 1.1.0 protocol expressed the
   archive check as `report_fields: {"reconstruction": {"complete": true}}`.
   `resolve_field` resolves that key to the whole `ReconstructionReport`
   object, which also carries `instructions`, `command_count`, `input_count`
   and `missing_inputs`; exact object equality can never hold. The predicate was
   re-expressed as `reconstruction.complete: true`. The accepting meaning is
   unchanged.

These are instrument corrections. They do not change a case population, a
mutation, an expected decision, a ground truth, or a metric. The development
first-run observations are preserved in `DEV-RUN.md`, including any defect
observed after these corrections.

## 6. Non-claims

A replication is not a new held-out test, not a fresh discovery, not independent
replication by another actor, and not external verification. Agreement between
the 1.1.0 and 1.2.0 runs does not establish correctness, completeness,
independence, generalization, or authorization to deploy. A refusal is not a
pass. A typed `NOT_RUN` is not a pass. A digest is not authentication.
