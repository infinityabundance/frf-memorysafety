# 1.2.0 replication: development run

**Status:** development partition executed once; the held-out partition was not
executed during this run.
**Protocol:** `protocol.json`, version `phase17.2-replication-1.2.0`, SHA-256
`b4488e4836253e75ee01597857e29a37a89cd23cec9b6eda7a3f8fabdd1c5b76`.
**Harness:** `run_comparative.py`, SHA-256
`c214ae17010031295e33084c582c1d5af9003c382b21bc78b808cacf5db37141`.
**Frozen 1.0.0 baseline:** `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`.
**1.2.0 evidence closure:** `ece999b403e7ce05f94dbe2304a2b86b24afb1a9cd5dc5e1a5f57d22482d735a`.

This document records what the 1.2.0 development run actually executed. It is
not a result for the held-out partition and it is not a certification.

---

## 1. Pre-execution instrument corrections

Two encoding defects were identified from the frozen 1.1.0 protocol and the
committed 1.1.0 evidence **before** any 1.2.0 case ran. They are recorded in
`REPLICATION.md` §5:

1. the c01 policy-metadata command now passes the required
   `--now 1795417304`;
2. the archive accepting predicate is encoded as `reconstruction.complete:
   true` instead of exact equality on the whole `ReconstructionReport` object.

No population, mutation, expected decision, ground truth or metric changed.

## 2. Environment

| Item | Value |
|---|---|
| Build image | `rust:1.85.0-slim` |
| Harness image | `python:3.11-slim` |
| Harness runtime | Python 3.11.18; OpenSSL 3.5.7 installed inside the container |
| Binary | `target/debug/frf-memorysafety`, SHA-256 `49937254ac5c35ff63f065f937b30e77674068f601a85e5111523daca0600e55` |
| Resource envelope | `--memory=2g --memory-swap=2g --pids-limit=512 --cpus=2 --ulimit nofile=1024:1024 --oom-score-adj=500`, `DAC_OVERRIDE/CHOWN/FOWNER` only, `no-new-privileges` |
| Rust build settings | `CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0` |
| Host execution | None. The host copied receipts from `target/` and performed read-only inspection. |

## 3. Observed results

`PASS` below means only that the observed decision equals the declared
expectation. It is not a certification.

| Case | Expected | Observed | Foundation | Restoration | Diagnostic |
|---|---|---|---|---|---|
| `c01-positive-campaign-closure` | accept | accept | accept | n/a | intact campaign, reconstruction and policy-metadata controls accepted |
| `c04-truncated-population` | refuse | refuse | accept | pass | correct refusal |
| `c07-signer-role-unauthorized` | refuse | refuse | accept | pass | correct refusal |
| `c10-time-wrong-imprint` | refuse | refuse | accept | pass | correct refusal |
| `c13-sarif-unjustified-suppression` | refuse | refuse | accept | pass | decision correct; wrong-code refusal (section 4) |
| `c16-tls-matrix-collapsed-cell` | refuse | **not_run** | accept | not_run | declared 1.2.0 tls-matrix artifact is absent |

Totals from `analysis-development.json` as originally committed (before the
`A002` replay; the current file includes the replayed `c16`):

```text
cases=6 accept=1 refuse=4 not_run=1 unresolved=0 instrument_errors=0
decision_accuracy=5/6 wrongful_acceptance=0 wrongful_refusal=0
foundation_augmented_agreement=1/6
```

The foundation decision is the modeled Phase 9 label (`pass` for every anchor),
so it accepts all six. `c16` remains in the 6-case denominator as a typed
`NOT_RUN`; it is not a pass and not a correct refusal.

## 4. Reported diagnostic mismatch

### 4.1 `c13` SARIF suppression (persists from 1.1.0)

The Rust `etp sarif verify` refused with exit 3 because
`SarifSuppressionProperties` denies the `suppression_id` field. The independent
`verify_sarif.py` refused with exit 4 (`InconsistentCount`) before the
suppression-review path. The decision is `refuse`, matching ground truth, but
neither instrument reached the declared suppression-review diagnostic. This is a
schema disagreement between the two SARIF verifiers, preserved rather than
repaired. The restoration control passes on the intact document.

## 5. Harness defects found

None. No harness or path defect appeared in the development run that changed a
population, a mutation, an expectation or a decision surface. The development
receipts were therefore promoted unchanged, and `HELD-OUT-OPENING.sha256`
remained valid for the held-out run.

## 6. Costs

Measured in-container: 357 ms total wall clock for the six development cases
(including restorations), and 215,623 bytes of declared base-artifact input
size. Timing is environment-specific and is not a stable identity. The byte
figure is the sum of the declared base artifact sizes; it is not an `rchar`
measurement.

## 7. Limits

- Development cases are not held-out evidence.
- The foundation is modeled over committed labels; it is not an execution of the
  1.0.0 binary.
- The Rust CLI and the Python verifiers share a repository and authoring
  process; their agreement is not administrative independence.
- `c16` is `NOT_RUN` in the original run; no substitute artifact was used.
- A green development run is not certification, review, or authorization to
deploy.

---

## 8. Postscript: amendment A002 replay of `c16`

This section was added after the original run. Sections 1 to 7 above are the
historical development-run record and are not rewritten.

The published 1.2.0 evidence set did not contain
`evaluation/earned-trust-1.2.0/tls-matrix/report.json`, so `c16` was typed
`NOT_RUN`. Amendment `A002` produced that report with the declared 1.2.0
tls-matrix instrument gate and replayed only `c16` in a hardened 2g/2g container.

The replayed `c16` now:

- applies the unchanged declared mutation (removes the `tls13_echo`
  candidate/candidate cell, leaving `summary.total_cells` at 8);
- refuses, because `tls-matrix-check` exits 1 with
  `Refusal: missing_cell: missing cell: tls13_echo candidate->candidate`;
- passes its restoration control.

`analysis-development.json` was regenerated over the full 6-case partition and
now reports `cases=6 refuse=5 not_run=0 decision_accuracy=6/6`. The other five
development receipts were not re-executed. The exact commands, output paths and
digests are in `REPLAY-1.2.0.md`; the amendment is `AMENDMENT-002.md`.

This is a re-run of a previously `NOT_RUN` case, not a new development result.
A green run remains not certification, review, or authorization to deploy.
