# FRF-MemorySafety Phase 10.2 campaign pre-registration

**Protocol version:** `frf-etp-v1`
**Campaign identifier:** `frf-etp-native-fixtures-2026-11-22`
**Frozen:** 2026-11-22, before the committed campaign execution.
**Frozen protocol manifest:** [`protocol.json`](protocol.json)
**Frozen SHA-256:** `fc9202bc553472bb94362e4de1d4da168f51ebd5be624eefc5cf0d334d8fa7ec`
**Companion freeze record:** [`opening.sha256`](opening.sha256)
**Candidate tree SHA-256:** `7fd038b34643743ca4dc36ceb7026973a8900fb0bd9697abc2a9ba64bea02746`
**Instrument tree SHA-256:** `e0264527e0dfb79e0d30967a8605784b383c0e12c8cdd94f8764457d9370d3ec`

**Phase 10.3 amendment.** The Phase 10.2 opening digest was
`2039c3352f9edcf7d5657e341440c466a29cc6f55851b6ecb6243b46a118a236` and its
candidate and instrument trees were
`951a51ee72d1b0eaf69927ca17b6a2def73d5879e070cbd705b983321a3d6546` and
`a907e09ef3bf426a1e178eb86984f6aa5df09635c88d6252506df0b8dd53b67c`. Phase
10.3 re-froze the opening manifest as an explicitly separated instrument change
(the attestation dependency and new source) and re-executed the same 13-case
population. The population, expected terminal outcomes, requirements,
obligations, mutation controls, resource envelope, acceptance policy, and claim
ceiling are unchanged. The original bytes remain at commit `f17111d`.

**1.1.0 amendment.** The 1.1.0 crate-version bump changed `Cargo.toml`, a
declared candidate and instrument file. The opening manifest was re-frozen as an
explicitly separated instrument change and the same 13-case population was
re-executed under the 1.1.0 instrument. The current opening digest is
`aff12c6d6bf67f40b4fd25554bf76c2721293f188d5f53befe1e905a5af1c4c6`; the
candidate tree is
`28fc0a11e07e989fe5105023da09bd2dd207c1166825a409c58f43e8dcc346df`; the
instrument tree is
`833d184c4a3cf126e07c828bf6fcf2d153b8d5d4f64cdabe8e5575c47d57abda`; and the
closure digest is
`226e2e9070b99d5e0563d28245cbab926cd0549484c05ef4295dd57590493b33`. The case
population, expected outcomes, requirements, obligations, mutation controls,
resource envelope, acceptance policy, and claim ceiling are unchanged. The
Phase 10.4b values remain at commit `c150de3`.

The machine-readable protocol is authoritative for the case population,
requirements, obligations, expected terminal outcomes, mandatory-resolution
flags, mutation controls, resource limits, acceptance policy, completion
expectations, and claim ceiling. This document is the human-readable rationale.
If the two disagree, the verifier fails closed and the run is invalid.

## 1. Question

Does one real, finite execution of the closed checked-in native fixture registry
through the native harness and court verifier produce exactly the pre-registered
typed outcome for each declared case, with complete raw evidence and no silently
dropped, duplicated, unexpected, truncated, or suppressed case?

The question is about a fixed 13-case control population. It is not a question
about detector sensitivity, population recall, memory safety, functional
correctness, interoperability, timing, or deployment security.

## 2. Population

The population is fixed before measurement. It covers four positive controls,
six violation controls, one incomplete-transcript control, and two unresolved
controls.

| Category | Cases | Pre-registered outcome |
|---|---|---|
| Positive | `legal-transfer-free-c`, `legal-transfer-free-rust`, `sync-callback-c`, `atomic-control-c` | `verified_compatible_within_transcript` |
| Violation | `use-after-free-c`, `use-after-free-rust`, `mutable-alias-c`, `stale-generation-c`, `deferred-callback-c`, `data-race-c` | `observed_violation` |
| Incomplete | `skipped-free-c` | `incomplete_transcript` |
| Unresolved | `nondeterministic-c`, `oversized-output-c` | `unresolved` |

The positive cases have `mandatory_resolution = true`. The unresolved controls
have `mandatory_resolution = false`: their pre-registered observation is the
unresolved condition itself. An unresolved observation on a positive case would
block acceptance.

## 3. Requirements and obligations

* **R1:** A legal fixture must record and replay an identical canonical
  transcript and verify cleanly within the transcript scope.
* **R2:** A violation fixture must produce a definite observed violation rather
  than a clean verdict.
* **R3:** An incomplete fixture must retain a missing-required-event finding
  rather than a clean verdict.
* **R4:** An unresolved fixture must retain an unresolved observation;
  unresolved is never mapped to a pass.

Obligations:

* **O1:** Record each declared fixture through the closed harness under the
  declared resource envelope.
* **O2:** Verify each transcript with the court and retain the raw transcript and
  court report bytes.
* **O3:** Retain every finding without suppression.
* **O4:** Reconcile the complete declared population; no case may be missing,
  duplicated, unexpected, or truncated.
* **O5:** Retain unresolved and `NOT_RUN` outcomes; neither is a pass.

## 4. Acceptance policy

Closure is accepted only when:

* every declared case has exactly one receipt and one terminal outcome;
* every observed terminal outcome equals its pre-registered outcome;
* every mandatory-resolution case resolves;
* no case is missing, duplicated, unexpected, or truncated;
* every retained finding is present without unauthorized suppression;
* every receipt's raw evidence digest matches the committed raw evidence;
* the candidate and instrument file and tree digests match the opening
  manifest;
* the count of 13 cases, 13 receipts, 25 raw evidence files, 13 pass decisions,
  and 9 retained-finding cases matches the pre-registration.

Completion expectations are `closure_status = closed` and
`acceptance = accepted`. `NOT_RUN` is never counted as a pass.

## 5. Instrument, environment, and resource envelope

* Image: `rust:1.85.0-slim` (recorded image id in every receipt).
* Native harness: `frf-native-fixture-harness` with `FRF_NATIVE_HARNESS=1`.
* Court: `frf-memorysafety.court-verification.v1`.
* Required tools: `cc`, `rustc`, `prlimit`, `ld`.
* Memory and swap: 2048 MiB each.
* Pids: 512; CPUs: 2; nofile: 1024; OOM score adjustment: 500; timeout: 1800 s.
* Repository mounted read-only for verification; `target/` is the only writable
  path in the gate.

The candidate and instrument trees overlap. The overlap is declared: the
campaign executes the same harness and court whose source digests it records.
Executing the instrument is not independent verification of the instrument.

## 6. Mutation controls

The pre-registered corrupted controls are `M1` through `M9` in `protocol.json`.
They cover deleted failed evidence, truncated population, duplicate rows,
inconsistent summary counts, unauthorized suppression, stripped results,
fabricated SARIF locations, wrong candidate identity, and missing raw evidence.
Each must be refused or correctly withheld. The executable tests are in
`tests/etp_campaign.rs` and `tests/sarif.rs`.

## 7. Freeze rule

The opening manifest was written before the committed execution and its SHA-256
was recorded in `opening.sha256`. Re-running `freeze.py` after the campaign
would change the opening digest and invalidate every committed receipt. The
verifier reads the sidecar and refuses a mismatch. The freeze detects accidental
or silent change only; it is not authentication.

## 8. Non-claims

This pre-registration does not claim that the campaign is a population sample,
that the fixtures are memory-safe, that the court is complete, that the harness
detects every defect, that a SARIF consumer is authoritative, or that a passing
gate is a certification or a deployment authorization.
