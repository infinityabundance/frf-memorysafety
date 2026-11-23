# 1.2.0 held-out opening

**Status:** originally frozen before any 1.2.0 development or held-out case was
executed, then re-frozen after the amendment `A002` targeted replay. The original digests are recorded in the re-freeze note below.
**Protocol:** `protocol.json`, version `phase17.2-replication-1.2.0-amendment-002`.
**Reused protocol:** the frozen 1.1.0 `phase17.2-amendment-001` protocol.
**Frozen 1.0.0 baseline:** `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`.
**1.2.0 evidence closure:** `ece999b403e7ce05f94dbe2304a2b86b24afb1a9cd5dc5e1a5f57d22482d735a`.

| Artifact | SHA-256 |
|---|---|
| `protocol.json` | `3f067d668a1bbdc5e7fbf4d79c0727b4c47259c9c407b134f1ec86f447dae1c4` |
| `run_comparative.py` | `e7dfec3691fd3554a103e787d0ed3182deec6de77bdb74f8c8a3baa8e2b8fb37` |
| `HELD-OUT-OPENING.sha256` | freezes both files above |

`OPENING.sha256` freezes `protocol.json` alone. `HELD-OUT-OPENING.sha256`
freezes the protocol and the harness. The gate digest is recorded in
`DEV-RUN.md` and `RESULTS.md` because the gate lives outside this directory. A
digest detects accidental or silent change; it is not authentication.

## Re-freeze under amendment A002

Amendment `A002` (`AMENDMENT-002.md`) bound four replayed artifacts and added an
optional replay filter to the harness. Both files above therefore changed, and
this sidecar was re-frozen after the replay. The original opening, which governed
the first development and held-out executions, was:

| Artifact | Original SHA-256 |
|---|---|
| `protocol.json` (`phase17.2-replication-1.2.0`) | `b4488e4836253e75ee01597857e29a37a89cd23cec9b6eda7a3f8fabdd1c5b76` |
| `run_comparative.py` | `c214ae17010031295e33084c582c1d5af9003c382b21bc78b808cacf5db37141` |

This re-freeze does not rewrite the original run. The original observations are
retained in `RESULTS.md`, `REPLAY-1.2.0.md` and the amendment record.

## Frozen rules

1. This is a **labeled replication**, not a new held-out test and not a fresh
   discovery. The same 18 cases, mutations, expectations, partitions and metrics
   are reused.
2. The 12 held-out cases execute **once** under these digests after the
   development partition. Their expected decisions and ground truth are not
   changed after execution. Amendment `A002` re-executes `c14` and `c15`, which
   the original run recorded as `NOT_RUN` with no decision; this is a declared
   deviation from the single-execution rule and is recorded in
   `AMENDMENT-002.md` §4. After the replay the held-out partition is not
   single-execution evidence for those two cases.
3. A harness defect may be corrected only if the correction does not change the
   population, a mutation, an expectation, a metric, or a decision surface. Such a
   correction is recorded in `DEV-RUN.md`, the original observations are
   preserved, and `HELD-OUT-OPENING.sha256` is re-frozen before the held-out run.
4. A refusal is not a pass. A typed `NOT_RUN` is not a pass. An instrument error
   is not a correct refusal.
5. Every result, mismatch, negative finding and failure is reported, including
   if the preregistered acceptance criteria fail.
6. The development cases are not reclassified as held-out evidence.

## Known limitations carried forward

- `c14`, `c15` and `c16` declared cross-property, interop and tls-matrix
  artifacts that the published 1.2.0 evidence set did not contain and were typed
  `NOT_RUN` in the original run. Amendment `A002` produced those artifacts with
  the declared 1.2.0 instrument gates and replayed only those three cases. They
  now decide as declared. See `REPLAY-1.2.0.md`.
- `c13` adds a SARIF suppression whose `suppression_id` is rejected by the Rust
  `SarifSuppressionProperties` (`deny_unknown_fields`) and whose suppressed
  result count is rejected by the independent verifier before the
  suppression-review path. The case is expected to refuse; its declared
  diagnostic may not be reached.
- The 1.1.0 restoration instruments for `c08`, `c09`, `c11`, `c12` and `c17`
  were not modified. They are re-executed exactly as declared and their
  observations are reported, whether or not the 1.2.0 archive repair changes
  them.

## Non-claims

This opening does not establish independence, external review, certification,
universal effectiveness, or authorization to deploy. The foundation surface is
a modeled baseline over committed decision labels, not an execution of the
1.0.0 binary. Replication is not independent verification.
