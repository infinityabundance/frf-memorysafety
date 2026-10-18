# FRF-MemorySafety: A Pre-Registered Finite Ablation Study of Evidence-Centric Memory-Safety Gates for Unsafe-to-Safe Rust Ports

**Version:** 0.9.0 (Phase 9.2 publication; no version bump)
**Evaluation protocol:** `phase9.1-v1`, frozen 2026-10-18
**Protocol SHA-256:** `02deb982c61c2a8307dbf3d34cf90f5aeb367e9ea7b1d794314aea9dd094d5ce`
**Evidence:** 60 canonical receipts in `evaluation/receipts/`, `MANIFEST.json`, `METHOD.md`, `PRE-REGISTRATION.md`
**Paper claims:** `evaluation/CLAIMS.json` (18 claims), independently reconstructed by `evaluation/reconstruct.py`
**Claim ceiling:** the measured results are exact for this finite, pre-registered control family and do not generalize to population defect detection, universal memory safety, proof soundness, alias completeness, compatibility, or `SAFE_COMPATIBLE`.

---

## Abstract

Unsafe-to-safe Rust compatibility ports need decisions about evidence, not only
instruments. A sanitizer run, a parsed proof manifest, a fuzzing finding, and a
source inventory can each be present while the claim they are supposed to
support remains unjustified. This paper reports a pre-registered, deterministic
ablation study of one evidence-centric design: a single Rust crate that records
candidate-bound finite evidence and gates claims over support graphs, path
effects, detector calibration, proof closure and implementation correspondence,
and external discovery provenance.

The study freezes a protocol before measurement, defines 31 cases and 60
`(case, arm)` receipts, uses a hash rule fixed in advance to split 20 held-out
cases from 11 development cases, and compares each shipped production arm with
competent naive baselines that implement the named simplification rather than a
constant-return stub. All 60 receipts match their pre-registered expected
observation. All 11 protocol claims are supported by their named receipts.
Production arms make no false-accept or false-refuse decision on 18 held-out
decision receipts across seven production arms. Naive baselines do make false
decisions: the greatest-fixed-point baseline accepts both held-out ungrounded
cycles; root-only and direct-premise baselines accept one held-out exact-cut
failure each; mapping-as-independent accepts one held-out shared-mapping case;
raw-stdout and job-success detector baselines each accept one held-out
adversarial receipt; parser-only accepts three held-out invalid manifests;
provenance-ignoring and schema-only discovery baselines accept two held-out
invalid bundles each.

The result is deliberately narrow. Five naive arms (`over_cut`,
`boolean_aliasing`, `top_as_exact`, `provider_ignored`, and `origin_ignored`)
have no held-out discriminator in this corpus; their separating cases are in the
development split. They are reported as negative findings or downgraded
contrasts, and the affected contrasts are not presented as held-out advantages.
H3 still satisfies its decision rule because `raw_stdout` and `job_success`
separate on held-out cases. The
corpus is synthetic or transcribed from earlier phases, the oracle is
same-repository, the held-out split is not temporal, and all provenance is
digest-bound rather than signed. The reconstructor independently recomputes
digests, coverage, tables, and claim mappings using only Python's standard
library; it does not re-execute the Rust mechanisms. No population inference,
detector accuracy, proof soundness, or memory-safety soundness claim is made.

---

## 1. Problem and non-claims

### 1.1 The decision problem

An unsafe-to-safe port replaces a native implementation with Rust while
preserving a C or C++ authority. Reviewers must decide whether a proposed claim
is supported by the evidence in front of them. The relevant questions are
conditional and local:

* does this support graph derive a claim from admitted leaves, or does it contain
  an ungrounded cycle?
* does this path analysis distinguish an exact descendant range from a shared
  mapping or a top alias?
* did the detector actually fire, under the declared build, with authentic
  transport, and with a clean known-good control?
* does the proof theorem close over its assumptions, and does a separate
  implementation-correspondence gate cover the FFI wrapper and reentrant
  transition?
* is an external finding bound to the current candidate and to exact bytes, or
  is it modeled, substituted, stale, or tampered?

A tool can report many observations without answering those questions. This
work treats the answer as a typed adjudication over evidence records, with an
explicit `NOT_RUN` for controls that were not executed.

### 1.2 Non-claims

This paper does **not** establish:

* universal memory safety, Rust borrow validity, or C object-lifetime legality;
* detector sensitivity or specificity in any population;
* proof soundness or a machine-proved semantic refinement;
* whole-program alias, provenance, or caller-graph completeness;
* compatibility of a port, all Safe-33 consumers, or `SAFE_COMPATIBLE`;
* organic vulnerability discovery;
* signed provenance, a transparency log, or a trusted build root;
* cost superiority over any other tool;
* population defect recall, time-to-defect, or engineering productivity;
* a temporal holdout from prior development.

The evaluation is a deterministic control-family study. It asks whether the
shipped mechanisms produce the pre-registered distinctions on named finite
inputs, and whether named simplifications lose those distinctions. Exact counts
are reported; no p-values or confidence intervals are computed because there is
no random sample and no repeated stochastic trial.

---

## 2. Definitions

**Receipt.** One canonical JSON object for a `(case, arm)` pair. It records the
expected and observed labels, a pass flag, the case truth label, accept
outcomes, a typed blocked reason when applicable, measured wall time, peak RSS,
output bytes, input/observation/stdout/stderr SHA-256 digests, crate and
toolchain identity, container image identity, the exact child command, a
deterministic detail string, and an experiment digest.

**`ms-canonical-json-v1`.** A restricted canonical encoding: objects are encoded
with keys sorted by UTF-16 code units; strings use the standard JSON escapes and
lowercase `\u00xx` for other control characters; numbers are integers only;
floating-point values are rejected. The digest of a value is the SHA-256 of its
canonical bytes.

**Observation digest.** `observed_sha256 = SHA-256(canonical({observed,
input_sha256, detail}))`. Mutating `observed` without recomputing this digest is
detected.

**Experiment digest.** `experiment_sha256 = SHA-256(canonical({protocol_sha256,
case_id, arm, expected, observed, pass, truth, input_sha256,
observed_sha256}))`. Resource measurements are excluded so a fresh run can be
compared with committed receipts.

**Held-out case.** A case is held out iff the first byte of
`SHA-256(UTF-8("frf-ms-eval-v1" || NUL || case_id))` is at least `0x80`. The rule
is fixed before measurement and implemented identically in the Rust harness and
the independent Python reconstructor.

**Discriminator.** For a baseline arm, a case in which the baseline's
pre-registered expected label differs from the production arm's pre-registered
expected label on the same case. A **held-out discriminator failure** is a
held-out discriminator on which the baseline produced its divergent expected
label. The phrase describes baseline behaviour, not a production advantage.

**False accept / false refuse.** For a case whose truth is `reject`, an arm
falsely accepts iff its observed label is in the case's `accept_outcomes`. For a
case whose truth is `accept`, an arm falsely refuses iff its observed label is
not in `accept_outcomes` and is not `NOT_RUN`. `NOT_RUN` is censored and
reported separately.

**Production arm.** An arm that calls the shipped crate mechanism. **Baseline
arm.** An arm implemented in the evaluation harness as the named simplification.
**Blocked control.** An arm that must return a typed `NOT_RUN` in the default
image and is never counted as a pass.

---

## 3. Architecture

FRF-MemorySafety is one Cargo crate. The relevant modules are:

| Module | Responsibility |
|---|---|
| `src/identity.rs` | Strict canonical encoding, size/nesting limits, domain-separated identities. |
| `src/model.rs` | Typed claims, scopes, obligations, hazards, external identities. |
| `src/support.rs` | Admitted leaves, rules, least fixed point, certificates, exact cuts. |
| `src/path_effect.rs` | Explicit object/alias/footprint/reference-interval analysis and qualified outcomes. |
| `src/detector/` | Typed detector evidence and calibration refusal rules. |
| `src/proof.rs` | Digest-bound proof manifest, theorem/assumption closure, admission, separate correspondence, live Coq adapter. |
| `src/bridge.rs` | FRF/FRF-Fuzz/Gemel provider contracts, candidate binding, custody, replay, loader closure. |
| `src/conversion.rs` | Property-specific evidence reuse and revocation for the declared conversion scope. |
| `src/evaluation.rs` | Phase 9.1 protocol, arms, isolated child execution, receipt construction, verification. |
| `src/bin/frf-eval.rs` | Thin CLI boundary over `src/evaluation.rs`. |

The evaluation harness `frf-eval` has three operations:

1. `run` spawns one child process per `(case, arm)` with a cleared environment,
   minimal `PATH`/`HOME`/locale, null stdin, a separate process group, and piped
   stdout/stderr. It wraps the child with `/usr/bin/time -v` when available and
   records `ru_maxrss`; otherwise it falls back to the child's
   `/proc/self/status` `VmHWM`.
2. `verify` rejects non-canonical receipts, protocol disagreement,
   missing/extra/duplicate receipts, stale observation or experiment digests,
   inconsistent pass flags, missing measurements or environment identity, and
   any protocol claim whose required observation is absent or different.
3. `compare` re-runs the harness and requires every deterministic field to match
   the committed receipt; resource values may differ.

The evaluation arms are implemented in `src/evaluation.rs`. Production arms call
the shipped mechanisms. Baseline arms implement the named simplification, for
example a greatest fixed point, root-only certificates, boolean aliasing, raw
stdout acceptance, parser-only proof acceptance, or provenance-free discovery.
They are not constant-return stubs.

The independent reconstructor `evaluation/reconstruct.py` is a separate program.
It reads only `evaluation/protocol.json`, `evaluation/receipts/MANIFEST.json`,
the receipt JSON files, and `evaluation/CLAIMS.json`; it does not import the
crate or share verifier code. It re-derives the canonical bytes and digests,
checks coverage and the held-out rule, recomputes the headline tables, and
verifies claim-to-receipt mappings. It is run by
`./ci/reconstruction-gate.sh` in a hardened `python:3.11-slim` container.

---

## 4. Prior-art comparison

The comparison below is mechanism-level, not a benchmark. No external system
was executed in Phase 9.2. The sources are the ones recorded in
`evaluation/METHOD.md` and `docs/phase2-alignment.md`; this phase adds no new
citation and invents none. The repository also names prior systems
(`cargo-geiger`, `cargo-vet`, Miri, AddressSanitizer, Kani, Coq, FRF,
FRF-Fuzz, and Gemel) in its own documentation; it does not claim a fair
quantitative comparison with them.

| Approach | What it provides | Relation to this work | Recorded source |
|---|---|---|---|
| Least-fixed-point semantics | A monotone immediate-consequence operator with a least fixed point; ungrounded cycles are not derived. | Basis for the support arm and the exact-cut experiments. | Tarski 1955, DOI `10.2140/pjm.1955.5.285`; Abiteboul, Hull, Vianu 1995. |
| Why-provenance / witness sets | Explanations as sets of contributing facts or derivations. | Basis for all-node certificates that expose hidden intermediates and shared premises. | Buneman, Khanna, Tan 2001, DOI `10.1007/3-540-44503-X_20`; Cheney, Chiticariu, Tan 2009, DOI `10.1561/1900000002`. |
| Incremental view maintenance | Insertion/deletion deltas and exact-cut reasoning. | Basis for distinguishing an exact partition from an over-cut. | Gupta, Mumick, Subrahmanian 1993, DOI `10.1145/170035.170074`. |
| Provenance semirings | Annotation-aware provenance for positive queries. | Motivates separating positive support from admissibility annotations. | Green, Karvounarakis, Tannen 2007, DOI `10.1145/1265530.1265535`. |
| Proof-carrying code | Certificate checking as a separate activity from certificate production. | Basis for the separate implementation-correspondence gate. | Necula 1997, DOI `10.1145/263699.263712`. |
| Sanitizers and dynamic detectors | Instrumented observations of specific mechanisms. | Treated as typed evidence that must be calibrated, not as proof. | Serebryany, Bruening, Potapenko, Vyukov, USENIX ATC 2012. |
| Oracle problem | Ground truth and differential consistency are themselves problems. | Motivates known-bad/known-good controls and explicit limits. | Barr, Harman, McMinn, Shahbaz, Yoo 2015, DOI `10.1109/TSE.2014.2372785`. |
| Provenance standards | Records of build and artifact provenance. | Digests bind bytes; they are not signatures or truth. | OpenSSF SLSA v1.0 provenance, <https://slsa.dev/spec/v1.0/provenance>. |
| Pre-registration / falsifiability | Confirmatory analysis fixed before measurement; corroboration is not proof. | Basis for the frozen protocol, held-out rule, and negative-finding reporting. | Simmons, Nelson, Simonsohn 2011, DOI `10.1177/0956797611417632`; Nosek et al. 2018, DOI `10.1073/pnas.1708274114`; Popper 1959. |

The specific contribution studied here is not any one of those mechanisms. It is
the combination of (a) candidate-bound evidence records with canonical digests,
(b) mechanism-specific adjudication that refuses untyped or uncalibrated
evidence, (c) a separate correspondence gate for proof manifests, and (d) a
pre-registered ablation protocol that compares each shipped mechanism with a
competent simplification on the same finite inputs.

---

## 5. Pre-registered design

### 5.1 Hypotheses

| ID | Hypothesis | Primary estimand |
|---|---|---|
| H1 | Founded graph support rejects ungrounded cycles; all-node certificates expose hidden intermediates and shared premises; exact cuts retain unrelated support. | Exact expected-observation match for production arms; at least one naive discriminator failure. |
| H2 | Exact, descendant, shared-mapping, and top aliases yield distinct qualifications; omission differs from not-falsified. | Exact production match; naive path-arm divergence. |
| H3 | Calibrated detector evidence is required; raw stdout, dead detectors, misconfigured builds, and mock transport are refused. | Production refusal of every held-out adversarial receipt; at least one naive detector baseline accepts one. |
| H4 | Theorem/assumption closure plus a separate correspondence gate rejects an unchecked wrapper and a missing transition. | Production rejects every held-out invalid manifest; parser-only accepts at least one. |
| H5 | Bridge verification refuses modeled/substitute providers, stale candidates, and tampered objects; an authentic chain is required and not synthesized. | Production refuses/correctly not-runs every held-out bundle; at least one naive discovery baseline accepts one. |
| H6 | Production arms make no false accept/refuse on known-bad/known-good controls; naive baselines do. | Exact confusion counts; `NOT_RUN` censored. |

### 5.2 Primary metric and thresholds

The primary decision metric is exact equality between the pre-registered
expected label and the observed label. The corpus is deterministic and finite.
Thresholds are:

* **Production:** zero mismatches on all non-blocked held-out cases.
* **Naive:** at least one held-out discriminator failure per named naive arm
  where the pre-registration claims one.
* **H6:** production held-out `false_accept == 0` and `false_refuse == 0`; at
  least one named naive baseline has `false_accept + false_refuse > 0` somewhere
  in the corpus.
* **Blocked controls:** expected and observed labels are both `NOT_RUN`;
  `NOT_RUN` is never mapped to a pass or accept.

A hypothesis is falsified if a production observation differs from its expected
label, a required receipt is missing or non-canonical, a digest check fails, or
a claim cites an observation that does not equal the receipt's `observed`
field. A hypothesis that is not falsified is supported **within this control
family only**.

### 5.3 Frozen protocol

The machine-readable protocol was frozen before the committed measurement run.
The harness recomputes its SHA-256 and rejects any receipt whose
`protocol_sha256` differs. The reconstructor hard-codes the frozen digest and
also requires the manifest and every receipt to agree.

| Constant | Value | Source |
|---|---|---|
| Protocol version | `phase9.1-v1` | `CLAIMS.json.constants` |
| Protocol SHA-256 | `02deb982c61c2a8307dbf3d34cf90f5aeb367e9ea7b1d794314aea9dd094d5ce` | `CLAIMS.json.constants` |
| Cases | 31 | PC2 |
| Receipts | 60 | PC1 |
| Held-out / development cases | 20 / 11 | PC2 |
| Protocol claims | 11 | PC3 |
| Paper claims | 18 | `CLAIMS.json.constants` |
| Evaluation image | `rust:1.85.0-slim` | `CLAIMS.json.constants` |
| Evaluation image id | `sha256:206360542a30ac87385638c1d123eae6cebcd9d8675d521bb80eac7f5820509b` | `CLAIMS.json.constants` |
| Evaluation image repository digest | `sha256:1829c432be4a592f3021501334d3fcca24f238432b13306a4e62669dec538e52` | `CLAIMS.json.constants` |
| Reconstruction image | `python:3.11-slim` | `CLAIMS.json.constants` |
| Reconstruction image id | `sha256:541096ae9b05d3b850341b78790e2ed31e94d5aa0ea086933c6ff0c09ffa2e63` | `CLAIMS.json.constants` |
| Reconstruction image repository digest | `sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534c5767af9ea65f6ce` | `CLAIMS.json.constants` |

---

## 6. Held-out selection and leakage control

The held-out rule is fixed before measurement:

```text
held_out(case_id) =
  first_byte(SHA-256(UTF-8("frf-ms-eval-v1" || NUL || case_id))) >= 0x80
```

The committed corpus has 20 held-out cases and 11 development cases, with 40
held-out receipts and 20 development receipts (PC2). The reconstructor
recomputes the split from the case identifiers; the rule cannot be changed after
seeing a result without invalidating the protocol digest.

This is a **selection-leakage control, not a temporal holdout**. Several
controls are transcribed or derived from material already used to build Phases
1–8: the paper's §12.4 cases, the Phase 2 support mutants, the Phase 5 detector
seal controls, the Phase 6 proof manifests, and the Phase 7 bridge seal
controls. Those controls were authored against the mechanisms they test. The
hash split prevents post-hoc movement of a case between splits within this
corpus; it does not undo prior exposure. This is also why the paper reports
development-split contrasts and negative findings instead of pretending that
every ablation separated on held-out data.

### 6.1 Corpus composition

| Family | Cases | Held-out cases | Development cases | Production arm | Naive arms |
|---|---:|---:|---:|---|---|
| Support (H1) | 7 | 5 | 2 | `lfp`, `all_node_certificates`, `exact_cut` | `gfp`, `root_only_certificates`, `direct_premises`, `over_cut` |
| Path/alias (H2) | 7 | 3 | 4 | `exact_footprint` | `boolean_aliasing`, `top_as_exact`, `mapping_as_independent`, `absent_is_omission`, `absent_is_not_falsified`, `provider_ignored` |
| Detector (H3) | 6 | 4 | 2 | `calibrated` | `raw_stdout`, `job_success`, `origin_ignored` |
| Proof (H4) | 5 | 4 | 1 | `closure_and_correspondence` | `parser_only` |
| Discovery (H5) | 6 | 4 | 2 | `bridge_verify` | `provenance_ignored`, `schema_only` |
| Decision (H6, derived) | 24 | 18 | 6 | all production arms | all baseline arms |

Source: PC18 and PC2. The H6 row counts decision cases, not a separate family of
fixtures; its receipts overlap H1–H5.

---

## 7. Ablations and baselines

The ablation design holds the cases, expected labels, harness, container, and
oracle fixed while changing one mechanism. Production and baseline arms run in
separate child processes. Baselines are competent implementations of a named
simplification, so a baseline failure is evidence about that simplification, not
about a strawman.

| Family | Ablation | Why it is a plausible simplification |
|---|---|---|
| Support | Least vs greatest fixed point | A greatest fixed point admits cycles unless an elimination step removes them. |
| Support | All-node vs root-only certificates | A root-only certificate is cheaper but hides intermediate and shared premises. |
| Support | Exact vs over-cut | An over-cut is conservative but loses unrelated support. |
| Path/alias | Exact/descendant/shared/top footprints | Byte-range precision is expensive; boolean or top-only reasoning is common. |
| Path/alias | Omission vs not-falsified | Collapsing absence into one status loses a safety-relevant distinction. |
| Path/alias | Foreign-provider uncertainty | Ignoring an unknown provider fabricates compatibility. |
| Detector | Typed evidence vs raw stdout | Text markers are easy to accept but can occur without a typed finding. |
| Detector | Detector liveness vs job success | A zero exit code does not prove that a detector fired. |
| Detector | Authentic transport vs provenance-free | A valid-looking receipt can arrive through a mock provider. |
| Proof | Closure + correspondence vs parser-only | Parse success is not proof acceptance and does not check the wrapper. |
| Discovery | Provenance/candidate/digest vs provenance-free or schema-only | Schema validity does not bind a finding to the current candidate or bytes. |

No baseline is a constant-return function. The baseline labels are computed from
the same finite inputs as the production labels; the difference is the
mechanism, not the input.

---

## 8. Measured results

All values in this section are derived from the committed receipts and are
present in `evaluation/CLAIMS.json`. The **Source** column names the paper claim
that the reconstructor verifies.

### 8.1 Coverage and exact match

| Hypothesis | Receipts | Passed | Failed | Blocked | Held-out cases | Development cases | Source |
|---|---:|---:|---:|---:|---:|---:|---|
| H1 founded support | 14 | 14 | 0 | 0 | 5 | 2 | PC18 |
| H2 path/alias | 15 | 15 | 0 | 0 | 3 | 4 | PC18 |
| H3 detector | 11 | 11 | 0 | 1 | 4 | 2 | PC18 |
| H4 proof | 9 | 9 | 0 | 1 | 4 | 1 | PC18 |
| H5 discovery | 11 | 11 | 0 | 3 | 4 | 2 | PC18 |
| H6 decision (derived) | 48 | 48 | 0 | 0 | 18 | 6 | PC18 |

Across the whole corpus, 60 of 60 receipts pass and 5 are typed `NOT_RUN`
(PC1). All 11 protocol claims are supported by their named receipts (PC3).

### 8.2 Production decision quality

| Quantity | Value | Source |
|---|---:|---|
| Production arms | 7 | PC4 |
| Held-out production decisions | 18 | PC4 |
| Held-out false accepts | 0 | PC4 |
| Held-out false refuses | 0 | PC4 |
| Held-out `NOT_RUN` | 0 | PC4 |

This is the headline decision-quality result. It is exact for the 18 held-out
decision receipts and does not estimate a population error rate.

### 8.3 Naive-baseline confusion counts

Cells are false accepts / false refuses. `—` means the baseline has no decision
case in that split.

| Baseline | Held-out FA/FR | Development FA/FR | Source |
|---|---:|---:|---|
| `gfp` (greatest fixed point) | 2 / 0 | 0 / 0 | PC5 |
| `root_only_certificates` | 1 / 0 | 0 / 0 | PC6 |
| `direct_premises` | 1 / 0 | 0 / 0 | PC6 |
| `over_cut` | 0 / 0 | 0 / 1 | PC7 |
| `boolean_aliasing` | 0 / 0 | 0 / 1 | PC8 |
| `provider_ignored` | 0 / 0 | 1 / 0 | PC8 |
| `mapping_as_independent` | 1 / 0 | 0 / 0 | PC9 |
| `top_as_exact` | 0 / 0 | 0 / 0 | PC10 |
| `raw_stdout` | 1 / 0 | 1 / 0 | PC11 |
| `job_success` | 1 / 0 | 0 / 0 | PC11 |
| `origin_ignored` | 0 / 0 | 1 / 0 | PC11 |
| `parser_only` | 3 / 0 | 0 / 0 | PC12 |
| `provenance_ignored` | 2 / 0 | 0 / 0 | PC13 |
| `schema_only` | 2 / 0 | 0 / 0 | PC13 |

`absent_is_omission` and `absent_is_not_falsified` operate on a case with truth
`unknown`, so they are not evaluated in the H6 decision denominators. Their
discrimination is reported in Section 8.4.

### 8.4 Discriminators by split

A discriminator is a case where the baseline's pre-registered expected label
differs from the production arm's expected label. The "failures" columns count
the cases where the baseline produced its divergent expected label. For
`parser_only`, four held-out discriminators arise because even the approved
manifest has a different label under parser-only; three of those are invalid
manifests and are the false accepts in Section 8.3.

| Baseline | Held-out discriminators | Development discriminators | Held-out failures | Development failures | Source |
|---|---:|---:|---:|---:|---|
| `gfp` | 2 | 0 | 2 | 0 | PC17 |
| `root_only_certificates` | 1 | 0 | 1 | 0 | PC17 |
| `direct_premises` | 1 | 0 | 1 | 0 | PC17 |
| `over_cut` | 0 | 1 | 0 | 1 | PC17 |
| `boolean_aliasing` | 0 | 1 | 0 | 1 | PC17 |
| `provider_ignored` | 0 | 1 | 0 | 1 | PC17 |
| `mapping_as_independent` | 1 | 0 | 1 | 0 | PC17 |
| `top_as_exact` | 0 | 1 | 0 | 1 | PC17 |
| `raw_stdout` | 1 | 1 | 1 | 1 | PC17 |
| `job_success` | 1 | 0 | 1 | 0 | PC17 |
| `origin_ignored` | 0 | 1 | 0 | 1 | PC17 |
| `parser_only` | 4 | 0 | 4 | 0 | PC17 |
| `provenance_ignored` | 2 | 0 | 2 | 0 | PC17 |
| `schema_only` | 2 | 0 | 2 | 0 | PC17 |
| `absent_is_omission` | 1 | 0 | 1 | 0 | PC17 |
| `absent_is_not_falsified` | 1 | 0 | 1 | 0 | PC17 |

The five baselines with zero held-out discriminators (`over_cut`,
`boolean_aliasing`, `top_as_exact`, `provider_ignored`, and `origin_ignored`)
are the downgraded cases discussed in Section 10.

### 8.5 Production outcomes by family

The labels below are the observed production labels. They are not additional
numeric claims; each is a receipt field verified through the named claim.

| Family | Cases and observed production labels | Source |
|---|---|---|
| Support | `S1` grounded cycle `supported`; `S2` self-cycle `unsupported`; `S3` mutual cycle `unsupported`; `S4` hidden intermediate `cut_applies`; `S5` shared mapping `cut_applies`; `S6` unrelated survives `exact_partition`; `S7` required cut `cut`. | PC3, PC18 |
| Path/alias | `P1` exact whole/descendant `observed_conflict`; `P2` disjoint descendants `compatible_within_finite_footprint`; `P3` shared mapping `not_falsified`; `P4` top alias `not_falsified`; `P5` omission/not-falsified `omission_and_not_falsified`; `P6` foreign provider `not_falsified`; `P7` independent allocations `compatible_within_finite_footprint`. | PC3, PC18 |
| Detector | `D1` authentic calibration `calibrated`; `D2` raw stdout no finding `refused_missing_finding`; `D3` dead detector `refused_dead_detector`; `D4` misconfigured build `refused_misconfigured_build_flags`; `D5` mock provider `refused_mock_provider_transport`; `D6` live Miri `NOT_RUN`. | PC11, PC14 |
| Proof | `R1` approved manifest `accepted_admission_checker_unavailable`; `R2` unchecked wrapper `rejected_unchecked_implementation`; `R3` admitted dependency `rejected_assumption`; `R4` missing transition `rejected_missing_transition`; `R5` live Coq `NOT_RUN`. | PC12, PC14 |
| Discovery | `E1` modeled provider `refused_modeled_evidence`; `E2` substitute provider `refused_substitute_provider`; `E3` stale candidate `refused_stale_candidate`; `E4` tampered finding `integrity_digest_mismatch`; `E5` missing finding `NOT_RUN`; `E6` authentic chain `NOT_RUN`. | PC13, PC14 |

The `R1` label is important: closure and correspondence pass, but no live checker
ran in the default image, so the aggregate is
`accepted_admission_checker_unavailable`, not proof acceptance. `E5` and `E6`
are `NOT_RUN`, not passes.

### 8.6 Blocked controls

| Control | Observed | Source |
|---|---|---|
| `D6-detector-live-miri::live_miri` | `NOT_RUN` | PC14 |
| `R5-proof-live-coq::live_coq` | `NOT_RUN` | PC14 |
| `E6-discovery-authentic-chain::bridge_verify` | `NOT_RUN` | PC14 |

There are 3 blocked controls but 5 `NOT_RUN` receipts, because the missing
discovery bundle also types both `E5-discovery-missing-finding` arms as
`NOT_RUN` (PC1). No `NOT_RUN` is counted as a pass.

---

## 9. Resource and time accounting

| Metric | Value | Source |
|---|---:|---|
| Receipts measured | 60 | PC15 |
| Sum of child wall time | 32 ms | PC15 |
| Maximum child wall time | 1 ms | PC15 |
| Sum of output bytes | 10,812 | PC15 |
| Minimum peak RSS | 5,040 KiB | PC15 |
| Maximum peak RSS | 6,016 KiB | PC15 |
| Sum of peak RSS | 329,276 KiB | PC15 |

These are single-run observations of fast child processes. `wall_time_ms = 0`
means the child completed in less than one millisecond; it is not a missing
measurement. Peak RSS is the child's `ru_maxrss` (or `VmHWM` fallback), not the
parent's or the container's. The corpus is too small for any algorithmic cost
comparison, and no cost superiority is claimed.

---

## 10. Negative findings and downgraded contrasts

Eight negative findings are pre-declared and reported (PC16):

1. **`boolean_aliasing` has no held-out discriminator.** Its separating case is
   `P2-path-descendant-disjoint`, which is in the development split. The
   baseline is still wrong on that case, but the paper does not claim a
   held-out advantage for this contrast.
2. **`over_cut` has no held-out discriminator.** Its separating case is
   `S6-exact-cut-unrelated-survives`, which is in the development split.
3. **`top_as_exact` makes no false accept or false refuse.** It reports a
   conservative conflict instead of the correct `not_falsified`. It is wrong but
   not unsafe in the decision-quality sense; its discriminator is also in the
   development split.
4. **`gfp` agrees with production on the grounded cycle `S1`.** The positive
   control is intentional: the relevant difference is ungrounded cycles, not
   all cycles.
5. **`parser_only` correctly accepts the approved manifest `R1`.** Its defect is
   that it also accepts the three invalid manifests; parse success is not proof
   acceptance.
6. **`raw_stdout` correctly accepts the authentic calibration `D1`.** Its defect
   is that it also accepts a diagnostic marker with no typed finding (`D2`) and
   a misconfigured build (`D4`).
7. **The approved proof manifest is not proof acceptance.** The production
   aggregate is `accepted_admission_checker_unavailable`: closure and
   correspondence pass, but no live checker ran.
8. **Live tools and the authentic native chain are `NOT_RUN`.** No live
   detector, Coq checker, or native FRF/FRF-Fuzz/Gemel chain is claimed in the
   default evaluation image.

**Additional development-only arm.** The discriminator table (PC17) also shows
that `origin_ignored` has no held-out discriminator: its separating case is
`D5-detector-mock-provider` in the development split. This is an additional
honest observation beyond the eight enumerated Phase 9.1 ledger entries. H3
still separates on held-out cases through `raw_stdout` (`D2`) and `job_success`
(`D3`), so the hypothesis-level decision rule is not lost.

### 10.1 Claim status and the evidence split

All 11 protocol claims are supported by their named receipts (PC3). The paper
nevertheless distinguishes claims whose contrast is supported on held-out cases
from claims whose contrast is supported only on development cases:

| Protocol claim | Held-out evidence | Development evidence | Interpretation |
|---|---|---|---|
| C1 `lfp` rejects ungrounded cycles | `S2`, `S3` | — | Held-out support. |
| C2 `gfp` accepts ungrounded cycles | `S2`, `S3` | — | Held-out baseline failure. |
| C3 all-node certificates expose hidden/shared dependencies | `S4`, `S5` | — | Held-out support. |
| C4 root-only/direct-premise miss the cut | `S4`, `S5` | — | Held-out baseline failures. |
| C5 exact cuts preserve unrelated support; over-cut loses it | `S7` production cut | `S6` exact/over-cut contrast | The over-cut contrast is development-only; the required-cut half is held-out. |
| C6 exact footprint distinguishes descendants/shared mapping | `P3` mapping contrast | `P2` boolean contrast | Boolean-aliasing contrast is development-only; mapping contrast is held-out. |
| C7 detector refuses raw/dead/misconfigured/mock | `D2`, `D3`, `D4`, `D5` | `D5` origin-ignored baseline | Production refusals and two baseline failures are held-out; `origin_ignored` is development-only. |
| C8 closure + correspondence reject invalid manifests | `R2`, `R3`, `R4` | — | Held-out support. |
| C9 bridge refuses modeled/substitute/stale/tampered | `E1`–`E4` | — | Held-out support. |
| C10 production makes no held-out false decision | 18 held-out decisions | — | Held-out support. |
| C11 live controls are `NOT_RUN` | `D6`, `R5`, `E6` | — | Typed blocked controls. |

The H1/H2 pre-registration also asked each named naive support/path arm to fail
at least one held-out discriminator. That clause is **not** met for `over_cut`,
`boolean_aliasing`, `top_as_exact`, and `provider_ignored`; their only
discriminators are in the development split. The same is true of
`origin_ignored` in the detector family, although H3 still has held-out
separators in `raw_stdout` and `job_success`. This is a downgrade of those
contrasts, not a falsification of the production observations or of the named
protocol claims. The paper reports it rather than reclassifying cases.

---

## 11. Threats to validity

1. **Finite domains.** The cases are small explicit inputs. Exact counts do not
   estimate performance on arbitrary software.
2. **Same-repository oracle.** The expected labels, baselines, and production
   mechanisms were authored by the same project. Agreement is a differential
   consistency result, not independent ground truth.
3. **Selection leakage vs temporal holdout.** The hash split prevents post-hoc
   movement, but the cases derive from earlier phases and were authored against
   the mechanisms they test.
4. **Synthetic fixtures.** The detector fixtures are typed receipts; the proof
   fixtures are checked-in manifests; the discovery fixtures are modeled or
   substitute external objects. No external provider was executed for the
   default receipts.
5. **Digest-bound, not signed, provenance.** Receipts bind exact bytes. There is
   no signature, transparency log, or trusted build root. A coordinated rewrite
   that recomputes all digests and the manifest is not detectable without an
   external anchor.
6. **Mechanism-specific detectors.** A calibrated result is specific to the
   mechanism and case in the fixture registry.
7. **Small finite Coq theorem and reviewed correspondence.** The live proof gate
   checks only the declared finite theorem. Correspondence is a reviewed
   evidence binding, not a machine-proved semantic refinement.
8. **Recorded native execution is not authenticated.** The Phase 7 chain binds
   recorded bytes and executable/closure hashes; it is not a signed attestation.
9. **Phase 8 declared scope.** The conversion results cover one boundary witness,
   one repair, one curl workload, and one loader closure, not all 33 consumers,
   full compatibility, or `SAFE_COMPATIBLE`.
10. **No third-party replication.** The reconstruction is independent code, but
    it was written in the same repository and reads the same committed receipts.
    It re-derives digests, coverage, tables, and mappings, not mechanism
    semantics.
11. **Baseline authorship.** Competent simplifications are still chosen and
    implemented by the project. A different baseline implementation could
    separate differently.
12. **Single-run resource observations.** Wall time and RSS demonstrate
    accounting and bounds, not algorithmic cost.

---

## 12. Reproducibility

All Rust builds and tests run inside the hardened `rust:1.85.0-slim` container;
the reconstructor runs inside the hardened `python:3.11-slim` container. No
`cargo`, `rustc`, or build/test command is run on the host.

```sh
# Formatting, clippy, debug tests, and release tests.
./ci/gate.sh

# Regenerate receipts, verify the fresh run, verify the committed receipts,
# and require deterministic agreement on every non-resource field.
./ci/eval-gate.sh

# Independent reconstruction from protocol.json, MANIFEST.json, receipts, and
# CLAIMS.json; fails on missing, extra, non-canonical, tampered, inconsistent,
# or unsupported artifacts.
./ci/reconstruction-gate.sh
```

The evaluation container uses `--memory=2048m --memory-swap=2048m
--pids-limit=512 --cpus=2 --ulimit nofile=1024:1024 --oom-score-adj=500`, dropped
capabilities with only `DAC_OVERRIDE`, `CHOWN`, and `FOWNER` restored, and
`--security-opt no-new-privileges`. The reconstruction container uses the same
pid, CPU, file-descriptor, capability, OOM, and no-new-privileges settings with
a 512 MiB memory cap and an equal swap cap. The repository is mounted read-only;
only `target/` and the cargo cache volume are writable.

The reconstructor can be run directly inside the pinned Python image:

```sh
docker run --rm \
  --memory=512m --memory-swap=512m \
  --pids-limit=512 --cpus=2 \
  --ulimit nofile=1024:1024 --oom-score-adj=500 \
  --cap-drop ALL --security-opt no-new-privileges \
  -v "$PWD":/src:ro -w /src python:3.11-slim \
  python3 evaluation/reconstruct.py
```

A fresh run must reproduce every deterministic field. Resource values may
differ. To change a case, arm, expectation, threshold, or the held-out rule,
edit `protocol.json` and `PRE-REGISTRATION.md`, recompute the protocol SHA-256,
regenerate receipts, and record a new protocol version. Editing a receipt or a
result directly is forbidden.

### 12.1 System verification is not an evaluated advantage

The separate live gates (`ci/mir-gate.sh`, `ci/detector-gate.sh`,
`ci/proof-gate.sh`, `ci/bridge-gate.sh`, `ci/conversion-gate.sh`) exercise live
Miri/sanitizers, live Coq, the native FRF/FRF-Fuzz/Gemel chain, and the
OpenSSL-Rust conversion witness. Their results are system-verification evidence:
they show that the corresponding mechanisms can run in their declared scope.
They are **not** part of the 60-receipt ablation, are not counted in the
headline counts above, and are not presented as evaluated advantages. The
default evaluation receipts type the live controls as `NOT_RUN` (PC14). The
README records the live-gate results and their scope.

---

## 13. Related work

The support semantics follow the least-fixed-point tradition (Tarski; Abiteboul
et al.) and the provenance literature's distinction between a derivation and its
witnesses (Buneman et al.; Cheney et al.; Green et al.). Exact-cut reasoning is
related to incremental view maintenance under deletion (Gupta et al.). The proof
side is in the proof-carrying-code tradition: checking a certificate is separate
from producing it (Necula). The detector side treats sanitizer and Miri-style
observations as instrumented evidence whose sensitivity and specificity are
mechanism- and case-specific (Serebryany et al.; the oracle-problem survey of
Barr et al.). The provenance discipline is informed by SLSA's distinction
between a provenance record and a signature or trusted root.

The project-specific comparison is with the repository's own named systems:
`cargo-geiger` and `cargo-vet` for inventory and policy, Miri and sanitizers for
dynamic observation, Kani and Coq for bounded or checked proofs, and FRF,
FRF-Fuzz, and Gemel for external court, fuzzing-finding, and custody identities.
This phase does not execute them as baselines and does not claim a fair
quantitative comparison. The contribution is the combination of evidence
typing, refusal rules, separate correspondence, and a pre-registered finite
ablation, not a claim that any one predecessor lacks value.

---

## 14. Conclusion

On a frozen finite corpus, the shipped production arms produced every
pre-registered observation (60/60), all 11 protocol claims were supported by
their named receipts, and production arms made zero false accepts and zero false
refuses across 18 held-out decisions. Several competent naive baselines made
false decisions, including the greatest-fixed-point, root-only, direct-premise,
mapping-as-independent, raw-stdout, job-success, parser-only,
provenance-ignoring, and schema-only simplifications.

The result is not a memory-safety soundness claim. Five naive contrasts had no
held-out discriminator and are downgraded to development-split observations.
The corpus is synthetic or transcribed, the oracle is same-repository, the
split is not temporal, and provenance is digest-bound rather than signed. The
appropriate conclusion is narrow and reproducible: within this declared control
family, the shipped evidence gates preserved distinctions that the named
simplifications lost, and the independent reconstructor re-derived every
headline count, digest, and claim mapping from the committed artifacts.

---

## Appendix A. Claim-to-receipt map

Every row below is a paper claim in `evaluation/CLAIMS.json`. The reconstructor
parses this table, requires every row to have a non-empty receipt mapping, and
rejects a row that does not correspond to a claim entry. The **Receipts** column
is abbreviated; the authoritative list is the `receipts` array in
`CLAIMS.json`, and `reconstruct.py` checks every named receipt.

| Claim | Prespecified hypothesis | Metric | Expected | Receipts | Observed | Status |
|---|---|---|---|---|---|---|
| PC1 | H1–H6 | exact expected-observation match | 60/60 pass | all 60 (CLAIMS.json) | 60 passed, 0 failed, 5 `NOT_RUN` | supported |
| PC2 | H1–H6 | held-out selection split | 20 held-out / 11 development | all 31 cases | 20 / 11 cases; 40 / 20 receipts | supported |
| PC3 | H1–H6 | protocol claim support | 11/11 | all 60 | 11 supported, 0 falsified | supported |
| PC4 | H6 | held-out confusion counts | 0 false accepts / 0 false refuses | production receipts | 7 arms; 18 held-out decisions; 0 / 0; 0 `NOT_RUN` | supported |
| PC5 | H1 | arm confusion counts | `gfp` held-out false accepts = 2 | `S1`–`S3` `gfp` | held-out 2 / 0; development 0 / 0 | supported |
| PC6 | H1 | arm confusion counts | root-only and direct-premise held-out false accepts = 1 each | `S4`, `S5` | each held-out 1 / 0 | supported |
| PC7 | H1 | arm confusion counts | `over_cut` development false refuses = 1 | `S6`, `S7` `over_cut` | held-out 0 / 0; development 0 / 1 | supported |
| PC8 | H2 | arm confusion counts | boolean development FR = 1; provider-ignored development FA = 1 | `P1`, `P2`, `P7`, `P6` | boolean 0 / 1 development; provider 1 / 0 development | supported |
| PC9 | H2 | arm confusion counts | mapping-as-independent held-out false accepts = 1 | `P3` | held-out 1 / 0 | supported |
| PC10 | H2 | arm confusion counts | top-as-exact false accepts/refuses = 0 | `P4` | 0 / 0; conservative conflict | supported (negative) |
| PC11 | H3 | arm confusion counts and labels | raw stdout 1 held-out + 1 development FA; job success 1 held-out FA; origin ignored 1 development FA; calibrated refuses `D2`–`D5` | `D1`–`D5` | as expected | supported |
| PC12 | H4 | arm confusion counts and labels | parser-only 3 held-out FA; closure rejects `R2`–`R4` | `R1`–`R4` | as expected; `R1` checker unavailable | supported |
| PC13 | H5 | arm confusion counts and labels | provenance-ignored 2 held-out FA; schema-only 2 held-out FA; bridge refuses `E1`–`E4`; `E5`/`E6` `NOT_RUN` | `E1`–`E6` | as expected | supported |
| PC14 | H3/H4/H5 | blocked-control statuses | 3 controls `NOT_RUN` | `D6`, `R5`, `E6` | 3 `NOT_RUN` | supported |
| PC15 | H1–H6 | resource accounting | wall 32 ms; output 10,812 B; RSS 5,040–6,016 KiB | all 60 | as expected | supported |
| PC16 | H1–H6 | negative findings ledger | 8 findings | all 60 | 8 findings | supported |
| PC17 | H1–H5 | held-out/development discriminator counts | per-arm counts | baseline receipts | as expected | supported |
| PC18 | H1–H6 | receipt coverage per hypothesis | H1=14, H2=15, H3=11, H4=9, H5=11, H6=48 | all 60 | as expected; 0 failures | supported |

## Appendix B. Artifact index

| Artifact | Purpose |
|---|---|
| `evaluation/PRE-REGISTRATION.md` | Human-readable hypotheses, thresholds, ablation design, held-out rule, and falsification criteria. |
| `evaluation/protocol.json` | Frozen machine-readable protocol: cases, arms, expectations, truth labels, accept outcomes, claims. |
| `evaluation/receipts/` | 60 canonical receipts and `MANIFEST.json`. |
| `evaluation/METHOD.md` | Phase 9.1 measurement method, results summary, negative findings, and limitations. |
| `evaluation/CLAIMS.json` | One entry per paper claim, with metric, expected value, receipt ids, observed value, and status. |
| `evaluation/reconstruct.py` | Independent standard-library reconstructor. |
| `evaluation/LIMITATIONS.md` | Numbered limitations ledger. |
| `ci/eval-gate.sh` | Hardened receipt regeneration and verification gate. |
| `ci/reconstruction-gate.sh` | Hardened independent reconstruction gate. |
| `tests/paper.rs` | Integration test that scans this claim table and fails if a claim lacks a receipt mapping. |
