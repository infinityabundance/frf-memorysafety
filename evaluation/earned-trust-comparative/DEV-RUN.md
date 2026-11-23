# Phase 17.2 development run

**Status:** development partition only. Held-out cases have not been executed.
**Protocol:** `protocol.json`, version `phase17.2-amendment-001`, frozen by
`OPENING.sha256`.
**Gate:** `ci/etp-comparative-gate.sh`.
**Frozen 1.0.0 baseline:** `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`.

This document records what the development run actually executed. It is not a
result for the held-out partition and it is not a certification.

---

## 1. History of the development run

The first development run refused the intact positive control
`c01-positive-campaign-closure`. The diagnostic was exact: the campaign
verifier parsed the Phase 16.1b acceptance-controls receipt as a 14th campaign
receipt and refused with `unknown field 'claim_ceiling'`. The receipt placement
was a real regression introduced in Phase 16.1b; it was fixed in commit
`b641cdd` and the intact campaign gate passed again.

Amendment A001 (`AMENDMENT-001.md`) repointed the moved artifact binding and
made the `c07` mutation edit both copies of the trust policy so the role check
is reached. The population, partitions, expectations and verifier commands did
not change. The six development cases were replayed under the amended
protocol. Earlier development observations are superseded and are not used.

## 2. Environment

| Item | Value |
|---|---|
| Build image | `rust:1.85.0-slim`, `sha256:206360542a30ac87385638c1d123eae6cebcd9d8675d521bb80eac7f5820509b` |
| Harness image | `python:3.11-slim`, `sha256:896edfbcbf0c29ad15681617a8886cb9871b7f24c5fde4606114c8ee6bfe4c70` |
| Harness runtime | Python 3.11.18; OpenSSL 3.5.7 installed inside the container |
| Binary | `target/debug/frf-memorysafety`, SHA-256 `b7fd7801dde67540e395d84fe198b4e34acb7563d2a38a43d72612c7620a5843` |
| Resource envelope | `--memory=2g --memory-swap=2g --pids-limit=512 --cpus=2 --ulimit nofile=1024:1024 --oom-score-adj=500`, `DAC_OVERRIDE/CHOWN/FOWNER` only, `no-new-privileges` |
| Host execution | None. The host copied receipts from `target/` and performed read-only inspection. |

## 3. Observed results

Six development cases. `PASS` below means only that the observed decision equals
the declared expectation. It is not a certification.

| Case | Expected | Observed | Foundation | Restoration | Diagnostic |
|---|---|---|---|---|---|
| `c01-positive-campaign-closure` | accept | accept | accept | n/a | intact campaign and reconstruction accepted |
| `c04-truncated-population` | refuse | refuse | accept | pass | correct refusal |
| `c07-signer-role-unauthorized` | refuse | refuse | accept | pass | correct refusal; both verifiers exit 4 |
| `c10-time-wrong-imprint` | refuse | refuse | accept | pass | correct refusal |
| `c13-sarif-unjustified-suppression` | refuse | refuse | accept | pass | decision correct; diagnostic mismatch (section 4) |
| `c16-tls-matrix-collapsed-cell` | refuse | refuse | accept | pass | correct refusal |

Totals from `analysis-development.json`:

```text
cases=6 accept=1 refuse=5 unresolved=0 instrument_errors=0
decision_accuracy=6/6 wrongful_acceptance=0 wrongful_refusal=0
foundation_augmented_agreement=1/6
```

The foundation decision is the modeled Phase 9 label (`pass` for every anchor),
so it accepts all six. The augmented surface accepts the positive control and
refuses the five negatives. This quantifies the marginal effect of the ETP
gates over a baseline that lacks them; it is not a fair accuracy comparison
between two executed systems.

## 4. Reported diagnostic mismatches

These are preserved rather than repaired.

### 4.1 `c07` signer role

Before the harness was corrected, the independent `verify_attestations.py`
refused with exit 3 and
`integrity failure: attestations/trust-policy.json differs from the policy`,
because the harness still edited only one policy copy after Amendment A001.
The harness now applies the same reassignment to both copies and verifies
that they remain byte-identical, as the amended protocol requires. In the
final run both `etp attest verify` and `verify_attestations.py` refused with
exit 4, so the role check was reached by both instruments. No diagnostic
mismatch remains for this case.

### 4.2 `c13` SARIF suppression

The Rust `etp sarif verify` refused with exit 3:
`unknown field 'suppression_id'`. Its `SarifSuppressionProperties` uses
`deny_unknown_fields` and does not admit `suppression_id`. The independent
`verify_sarif.py` requires `suppression_id` on a suppression and also hardcodes
`EXPECTED_ENCODED_BYTES = 42988` for the pristine document, so any mutated
document is refused as `InconsistentCount` before the suppression-review path
is reached. The decision is `refuse`, matching ground truth, but the declared
diagnostic was not reached.

This is an instrument limitation and a schema disagreement between the two
SARIF verifiers. It is a negative finding, not a reason to weaken either
verifier.

## 5. Costs

Measured in-container: 405 ms total wall clock for the six development cases
(including restorations), and 312,578 bytes of declared base-artifact input
size. Repeated runs measured 398-410 ms, so the timing is environment-specific
and not a stable identity. The byte figure is the sum of the declared base
artifact sizes; it is not an `rchar` measurement.

## 6. Reproducibility

Two consecutive amended runs produced identical observations, decisions and
analysis counts. Excluding timing fields, four of six receipts were
byte-identical. `c07` and `c10` differed only in command `stdout_sha256` for the
Rust and Python verifier reports, which embed the per-process work directory.
The digests were preserved, not normalized. This is an observation about the
instrument's output, not a reproducibility pass.

## 7. Limits

- Development cases are not held-out evidence. No held-out case has executed.
- The foundation is modeled over committed labels; it is not an execution of
  the 1.0.0 binary.
- The Rust CLI and the Python verifiers share a repository and authoring
  process; their agreement is not administrative independence.
- The transparency, time, witness and correction material are local test
  artifacts, not public infrastructure.
- `c14`-`c16` use declared harness checks over committed report bytes, not
  independent verifiers.
- A green development gate is not certification, review, or authorization to
  deploy.
