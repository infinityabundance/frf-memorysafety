# FRF-MemorySafety Phase 9.1 pre-registration

**Protocol version:** `phase9.1-v1`  
**Frozen:** 2026-10-18, before the committed Phase 9.1 measurement run. Harness
smoke runs used during implementation are not results and are not cited.  
**Frozen protocol manifest:** [`protocol.json`](protocol.json)  
**Frozen SHA-256:** `02deb982c61c2a8307dbf3d34cf90f5aeb367e9ea7b1d794314aea9dd094d5ce`  
**Companion freeze record:** [`PRE-REGISTRATION.sha256`](PRE-REGISTRATION.sha256)

The machine-readable protocol is authoritative for case ids, arms, expected
observations, truth labels, accept outcomes, and claim-to-receipt requirements.
This document is the human-readable rationale and analysis plan. If the two
disagree, the harness fails closed and the run is invalid.

## 1. Questions and hypotheses

The evaluation asks whether the shipped mechanisms add decision value over
competent naive baselines on a fixed, small, deterministic control family. It
does not estimate population defect-detection rates, generalize to arbitrary
software, or establish universal memory safety.

| ID | Hypothesis | Primary estimand |
|---|---|---|
| **H1** | Founded graph support: least-fixed-point support rejects ungrounded cycles; all-node certificates expose hidden intermediates and shared premises; exact cuts retain unrelated support. | Exact expected-observation match for production arms; at least one held-out discriminator failure for each naive support arm. |
| **H2** | Path/alias semantics: exact, descendant, shared-mapping, and top aliases yield distinct qualifications; omission differs from not-falsified. | Exact expected-observation match for production arms; at least one held-out divergence for each naive path arm. |
| **H3** | Calibrated detector: typed, mechanism-specific, authentic evidence is required; raw stdout, dead detectors, misconfigured builds, and mock transport are refused. | Production refuses every held-out adversarial receipt; at least one naive detector baseline accepts one. |
| **H4** | Proof: theorem/assumption closure plus the separate implementation-correspondence gate rejects an unchecked FFI wrapper and a missing reentrant transition. | Production rejects every held-out invalid manifest; parser-only accepts at least one. |
| **H5** | Empirical discovery: modeled/substitute providers, stale candidates, and tampered external objects are refused; an authentic chain is required and is not synthesized. | Production refuses/correctly not-runs every held-out bundle; at least one naive discovery baseline accepts one; authentic chain is `NOT_RUN` by default. |
| **H6** | Decision quality: production arms make no false-accept/false-refuse decision on known-bad/known-good controls; naive baselines do. | Exact confusion counts over held-out cases; `NOT_RUN` reported as censored. |

### Falsification

A hypothesis is **falsified** if any of the following holds on its held-out
cases:

* a production arm's observed label differs from its pre-registered expected
  label;
* a named naive baseline has no held-out discriminator failure where the
  hypothesis claims one;
* a required receipt is missing, non-canonical, lacks a required measurement, or
  fails its digest check;
* a claim cites an observation that does not equal the receipt's `observed`
  field.

A hypothesis that is not falsified is **supported within this control family
only**. It is not evidence of universal detector sensitivity, proof soundness,
whole-program alias completeness, or population-level defect recall.

## 2. Ablation arms

All arms run in separate child processes. Production arms call the shipped
crate. Naive arms are implemented in the evaluation harness and are labeled
`baseline`; they are competent implementations of the named simplification, not
strawmen that return a constant.

| Family | Production arm | Naive arms | What is ablated |
|---|---|---|---|
| Support | `lfp`, `all_node_certificates`, `exact_cut` | `gfp`, `root_only_certificates`, `direct_premises`, `over_cut` | Least vs greatest fixed point; all-node vs root-only certificates; exact vs over-cut. |
| Path/alias | `exact_footprint` | `boolean_aliasing`, `top_as_exact`, `absent_is_omission`, `absent_is_not_falsified`, `provider_ignored` | Exact/descendant/top footprints; shared-mapping ranges; omission vs not-falsified; foreign-provider uncertainty. |
| Detector | `calibrated` | `raw_stdout`, `job_success`, `origin_ignored` | Typed evidence vs raw stdout acceptance; detector liveness vs job success; provenance vs provenance-free acceptance. |
| Proof | `closure_and_correspondence` | `parser_only` | Closure + separate correspondence vs parse-success acceptance. |
| Discovery | `bridge_verify` | `provenance_ignored`, `schema_only` | Authentic native provenance vs provenance-free; digest/candidate binding vs schema-only. |
| Blocked | `live_miri`, `live_coq`, `bridge_verify` authentic chain | — | Typed `NOT_RUN`; never counted as a pass. |

The complete arm list, expected labels, and per-case truth labels are in
`protocol.json`. The harness does not choose expectations at run time.

## 3. Metrics

Per `(case, arm)` receipt:

* **outcome:** expected and observed label;
* **pass:** `expected == observed`;
* **wall time:** parent-measured monotonic elapsed milliseconds around the
  isolated child;
* **peak RSS:** Linux `ru_maxrss` from `/usr/bin/time -v`
  (`Maximum resident set size (kbytes)`); fallback `/proc/self/status` `VmHWM`;
* **output bytes:** exact length of the child's canonical observation;
* **digests:** case/input SHA-256, canonical observation SHA-256, stdout SHA-256,
  stderr SHA-256;
* **environment:** crate version, `rustc --version`, container image name and
  image id, and the exact argv vector;
* **blocked reason:** exact typed reason when the arm is `NOT_RUN`.

Aggregate metrics:

* per-hypothesis receipt coverage and expected-observation match count;
* per-arm held-out / development pass counts;
* false accepts and false refuses on known-bad/known-good controls, with
  `NOT_RUN` censoring reported separately;
* total wall time, total peak RSS sum, and total output bytes for the run
  (resource accounting only; not a performance comparison across algorithms).

**Primary decision metric:** exact match between the pre-registered expected
label and the observed label. This is deterministic for these finite inputs.
Wall time and RSS are reported but are not primary estimands; the corpus is too
small for performance inference.

## 4. Thresholds and decision rules

The study is a deterministic control-family evaluation, not a sampling study.
No p-values or confidence intervals are computed, because there is no random
sample and no repeated stochastic trial. Counts are exact.

* **H1/H2/H3/H4/H5 (production):** zero mismatches on all non-blocked held-out
  cases. One mismatch falsifies the corresponding production claim.
* **H1/H2/H3/H4/H5 (naive):** at least one held-out discriminator failure per
  named naive arm, where "discriminator" means the naive expected label differs
  from the production expected label on that case.
* **H6:** production `false_accept == 0` and `false_refuse == 0` on held-out
  known-bad/known-good cases. At least one named naive baseline must have
  `false_accept + false_refuse > 0` somewhere in the corpus (development or
  held-out). Baselines with zero false decisions are reported as negative
  findings. A baseline with no decision case is reported as `not_evaluated`.
* **Blocked controls:** expected and observed label must both be `NOT_RUN`.
  `NOT_RUN` is never mapped to pass/accept for a safety claim and is excluded
  from H6 denominators.
* **Negative findings:** any naive arm that agrees with production on a
  discriminator is reported as a negative finding, not hidden. A hypothesis
  may be supported while individual ablations fail to separate.

## 5. Held-out selection rule

Fixed before measurement:

```text
held_out(case_id) = (first byte of SHA-256(UTF-8("frf-ms-eval-v1" || 0x00 || case_id))) >= 0x80
```

Development and held-out counts are recomputed by the verifier and must match
the receipts. The rule is a **selection-leakage control**: a case cannot be
moved to or from held-out after seeing its result.

**Honesty about temporal holdout:** this is not a temporal holdout from prior
development. Several controls are transcribed or derived from material that was
already used to build Phases 1–8: the paper's §12.4 cases, the Phase 2 support
mutants, the Phase 5 detector seal controls, the Phase 6 proof manifests, and
the Phase 7 bridge seal controls. Those cases were authored against the
mechanisms they test. The hash split protects against post-hoc case selection
within this Phase 9.1 corpus, but it does not undo prior exposure. Cases derived
from external artifacts are marked as such in `METHOD.md`.

## 6. Blocked controls

The following are pre-registered as blocked in the default evaluation image.
They must produce typed `NOT_RUN`, with the exact reason, and must never be
reported as passes:

| Control | Why blocked | Required outcome |
|---|---|---|
| Live Miri/ASan/LSan/TSan/loom/Kani/OpenSSL detectors | Instruments are not installed in `rust:1.85.0-slim`; live runs are opt-in. | `NOT_RUN` |
| Live Coq theorem checking | `coqc` is not installed in the default image; manifest parsing is not acceptance. | `NOT_RUN` |
| Authentic native FRF/FRF-Fuzz/Gemel chain | No verified live bundle is supplied; modeled/substitute evidence is not a substitute. | `NOT_RUN` |

If a blocked control's receipt is absent or claims an observed pass, the run is
invalid. Live gates remain separate (`ci/detector-gate.sh`,
`ci/proof-gate.sh`, `ci/bridge-gate.sh`).

## 7. Receipt rule: every claim maps to an observation

* The harness emits one canonical `frf-memorysafety.evaluation-receipt.v1`
  JSON object per `(case, arm)` under `evaluation/receipts/`.
* A receipt is emitted **only** when wall time, peak RSS (>0), output bytes,
  input digest, observation digest, toolchain, image, and exact command are all
  present. A missing measurement is a hard harness error, never a default.
* `observed_sha256` is recomputed by the verifier over the canonical
  `{observed,input_sha256,detail}` object. A mutated `observed` field with a
  stale digest is rejected.
* Every claim in `protocol.json` lists required `(case, arm, expected)`
  receipts. The verifier fails if any required receipt is missing or if its
  `observed` field differs from the claimed observation.
* The derived decision-quality claim is recomputed from receipts; it may not be
  asserted in prose without the corresponding counts.
* Receipts are small (no raw logs, binaries, or target artifacts). They record
  digests and bounded observations only.

## 8. Analysis procedure

1. Freeze `protocol.json` and this document; record the SHA-256.
2. Run `ci/eval-gate.sh`, which builds and runs the harness inside the hardened
   container and writes receipts.
3. Verify canonical encoding, required measurements, digest integrity, case/arm
   coverage, held-out split, hypothesis coverage, and claim-to-receipt mapping.
4. Report exact held-out and development counts, all negative findings, all
   blocked controls, and total resource use.
5. Commit the receipts and the verification report summary. Do not hand-edit a
   receipt or a result.

Phase 9.1 does **not** write `PAPER.md`; that is Phase 9.2. No unexecuted
methodology is described in past tense as though it were measured.
