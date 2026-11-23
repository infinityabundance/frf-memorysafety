# Phase 17.3 held-out results and independent reconstruction

**Status:** executed once under the frozen held-out opening; independently
reconstructed.
**Protocol:** `protocol.json`, `phase17.2-amendment-001`, SHA-256
`cdc78441ed23a8f942a1fc5f4bb59192be9120adfb6c5135047d4435a2de00df`.
**Held-out instrument:** `HELD-OUT-OPENING.sha256`.
**Frozen 1.0.0 baseline:** `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`.

The held-out cases were executed once. Their expectations were not changed
after execution. No post-hoc repair was applied to any held-out observation.
The failures below stand as results.

---

## 1. Population

18 cases, 6 development and 12 held-out, exactly as frozen. Every case has one
receipt. The independent reconstructor found zero bookkeeping discrepancies
between the protocol, the 18 receipts and the two harness analyses.

## 2. Development partition

| Case | Expected | Observed | Restoration |
|---|---|---|---|
| `c01` positive campaign closure | accept | accept | n/a |
| `c04` truncated population | refuse | refuse | accept |
| `c07` signer role | refuse | refuse | accept |
| `c10` time wrong imprint | refuse | refuse | accept |
| `c13` SARIF suppression | refuse | refuse | accept |
| `c16` TLS collapsed cell | refuse | refuse | accept |

6/6 decisions; 0 wrongful acceptance; 0 wrongful refusal; 0 unresolved;
0 restoration failures.

## 3. Held-out partition

| Case | Expected | Observed | Foundation | Restoration | Note |
|---|---|---|---|---|---|
| `c02` candidate substitution | refuse | refuse | accept | accept | |
| `c03` completeness deletion | refuse | refuse | accept | accept | |
| `c05` duplicate population row | refuse | refuse | accept | accept | |
| `c06` DSSE payload substitution | refuse | refuse | accept | accept | both verifiers refuse; independent diagnostic differs |
| `c08` transparency inclusion | refuse | refuse | accept | **unresolved** | restoration: independent verifier output is not JSON |
| `c09` stale checkpoint | refuse | refuse | accept | **refuse** | restoration: checkpoint reports `consistency_not_checked` at exit 0 |
| `c11` withdrawn claim | refuse | refuse | accept | **refuse** | Rust claim-level refusal; independent verifier accepts |
| `c12` missing archive object | refuse | refuse | accept | **refuse** | restoration: intact archive reports reconstruction incomplete |
| `c14` cross-property regression | refuse | refuse | accept | accept | declared harness check |
| `c15` interop collapsed cell | refuse | refuse | accept | accept | declared harness check |
| `c17` proof closure removal | refuse | refuse | accept | **unresolved** | manifest-only verify returns `checker_unavailable` on restore |
| `c18` positive archive reconstruction | accept | **refuse** | accept | **refuse** | wrongful refusal; archive reconstruction incomplete |

Held-out totals:

```text
cases=12 matched=11 wrongful_acceptance=0 wrongful_refusal=1
unresolved=0 instrument_errors=0 restoration_failures=6
```

Across both partitions: 18 cases, 17 decisions match, 1 wrongful refusal, 0
wrongful acceptance, 0 unresolved, 0 instrument errors, 6 restoration
failures. The foundation surface accepted all 18, as its modeled definition
predicts.

## 4. Negative findings

These are the substance of the evaluation. They are preserved, not repaired by
changing expectations.

### 4.1 The archive is not offline-reconstructible (c18, c12)

`etp archive verify` exits 0 and reports `status: verified`, but also reports
`reconstruction.complete: false` on the intact archive. The declared independent
reconstruction over the archive root fails:

```text
FAIL reconstruction: <work>/archive/Cargo.toml: cannot read:
[Errno 2] No such file or directory
```

The archived object set (76 objects) omits `Cargo.toml` and the source tree, but
the shipped `reconstruct.py` requires them. The archive verifier's
`verified` status and the reconstructor's failure are inconsistent. This is a
real archival gap. It is not repaired here because repairing the archive would
change a frozen Phase 15 artifact; it is carried into Phase 18.

### 4.2 The independent revocation verifier accepts a withheld claim (c11)

The Rust verifier exits 0 and reports `present_admissible: false` for the
withdrawn claim. The harness correctly treats that as a claim-level refusal.
The independent `verify_revocation.py` exits 0 and the harness classifies it as
accept because its accepting outcome does not inspect the claim field. The two
instruments disagree on the present decision. The case still refuses because
one decisive command refuses, but the independent verifier is not equivalent.

### 4.3 Manifest-only proof verification is not proof checking (c17)

`proof verify` without `--live` exits 3 on the mutated manifest with a precise
closure error, but exits 6 (`checker_unavailable`) on the restored manifest.
The executable acceptance model accepts. The case's refusal is correct, but the
declared diagnostic code differs, and the restoration is unresolved because no
checker is configured in the harness container. Manifest validation is not
proof checking, as the claim ceiling states.

### 4.4 Transparency restoration instruments are not JSON-stable (c08, c09)

`verify_transparency.py` is invoked without `--json`, so its restoration output
cannot be checked against a declared `report_status`; the harness records
unresolved. `etp checkpoint verify` exits 0 on the restored checkpoint but
reports `consistency_not_checked`, which does not satisfy the declared
accepting outcome and is recorded as a refusal. These are command/expectation
design problems in the preregistration, discovered on held-out execution and
not edited after the fact.

### 4.5 SARIF verifier schema disagreement (c13)

The Rust `SarifSuppressionProperties` denies `suppression_id`, while the
independent verifier requires it and hardcodes `EXPECTED_ENCODED_BYTES` for the
pristine document. The case refuses, but neither instrument reaches the
declared suppression-review diagnostic. This is a schema disagreement between
verifiers, not a reason to weaken either.

## 5. Costs

Held-out: 746 ms total wall clock, 462,412 bytes of declared base-artifact input
size. Development: 405 ms, 312,578 bytes. These are resource accounting only;
timing is environment-specific. Independent reconstruction wall-clock cost was
not separately measured or preregistered as a number, so no reconstruction-cost
claim is made.

## 6. Claims

| Claim | Status | Basis |
|---|---|---|
| Q1 population | supported | 18 cases, 6/12, disjoint, zero reconstruction discrepancies |
| Q2 modeled foundation | supported | 18/18 foundation accepts, as defined |
| Q3 discrimination | refuted | 16/16 negatives refused, but only 1/2 positives accepted |
| Q4 acceptance criteria | refuted | 1 wrongful refusal, 6 restoration failures |
| Q5 specificity and restoration | refuted | 6 restoration failures; 3 wrong-code refusals |
| Q6 independent corroboration | refuted | c11 disagreement, c17 instrument mismatch, c18 unresolved |
| Q7 accounting | supported | no refusal counted as a pass; NOT_RUN not a pass |
| Q8 cost | partially supported | verification cost measured; reconstruction cost not measured |
| Q9 reporting | supported | all failures and negative findings retained |
| Q10 non-generalization | supported | no universal or deployment claim is made |

## 7. Non-claims

This evaluation does not establish memory safety, functional correctness,
detector sensitivity, population-level accuracy, external independence,
administrative independence, public transparency, external trusted time,
certification, or authorization to deploy. The foundation is a modeled
baseline over committed labels, not an execution of the 1.0.0 binary. A refusal
is not a pass. A NOT_RUN is not a pass. A digest is not authentication.
