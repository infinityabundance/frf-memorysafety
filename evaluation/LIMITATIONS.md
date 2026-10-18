# FRF-MemorySafety limitations ledger (Phase 9.2)

This ledger is part of the Phase 9.2 publication. It records the limits that a
reader must apply to `PAPER.md` and to the 60-receipt evaluation. It is a
numbered, evidence-linked list, not a disclaimer paragraph. Each entry states
the limitation, its impact, the evidence that establishes it, and what would
reduce it.

The claim ceiling is unchanged: the evaluation is a deterministic,
pre-registered, finite control-family study. It does not establish universal
memory safety, population defect detection, detector accuracy, proof soundness,
whole-program alias completeness, compatibility, or `SAFE_COMPATIBLE`.

---

## L1. Finite domains

**Limitation.** Every evaluation case is a small, explicit, finite input. The
support graphs, path traces, detector receipts, proof manifests, and discovery
bundles are declared controls, not samples from a software population.

**Impact.** Exact counts describe these controls only. No recall, precision,
sensitivity, specificity, time-to-defect, or cost inference follows. A production
arm that matches all 60 expected observations is not thereby correct on unseen
software.

**Evidence.** `evaluation/protocol.json` (31 cases); `PAPER.md` §5–8; PC1–PC4,
PC18.

**What would reduce it.** A pre-registered corpus of independently selected real
ports with blinded ground truth, a sampling frame, repeated trials, and
population-level estimands. The current corpus does not supply those.

---

## L2. Same-repository oracle

**Limitation.** The expected labels, the production mechanisms, and the naive
baselines were authored in the same repository by the same project. Agreement
between the harness and the receipts is not independent ground truth.

**Impact.** The evaluation is a differential consistency result between a
shipped mechanism and a named simplification. A shared specification error could
make both the production and the expected label wrong in the same direction.

**Evidence.** `evaluation/PRE-REGISTRATION.md` §1 and §5; `evaluation/METHOD.md`
§8; `PAPER.md` §11.2; PC1–PC3.

**What would reduce it.** A separately authored oracle, third-party case
authorship, or an independently implemented specification with a published
disagreement procedure. The Phase 2 conformance work already uses a separately
coded oracle for a different finite universe, but that is not the Phase 9.1
oracle.

---

## L3. Selection leakage versus temporal holdout

**Limitation.** The hash split is a selection-leakage control, not a temporal
holdout. Several controls derive from material used to build Phases 1–8: the
paper's §12.4 cases, the Phase 2 support mutants, the Phase 5 detector seals,
the Phase 6 proof manifests, and the Phase 7 bridge seals.

**Impact.** The split prevents moving a case between held-out and development
after seeing its result. It does not undo prior exposure during mechanism
development. Held-out results are therefore not a clean out-of-sample
generalization test.

**Evidence.** `evaluation/PRE-REGISTRATION.md` §5; `evaluation/METHOD.md` §2;
`PAPER.md` §6; PC2.

**What would reduce it.** A temporal holdout collected after the mechanisms were
frozen, with no author exposure, and a pre-registered leakage audit. That was
not possible for the already-developed Phase 1–8 controls.

---

## L4. Synthetic fixtures and no organic-discovery claim

**Limitation.** The detector fixtures are typed receipts, the proof fixtures are
checked-in manifests, and the discovery fixtures are modeled or substitute
external objects. The default receipts execute no external provider, no live
detector, and no live proof checker.

**Impact.** The evaluation tests the adjudication logic over declared evidence
shapes. It does not demonstrate that a real organization will encounter those
shapes, that a detector will fire on a real defect, or that an external finding
would be produced organically.

**Evidence.** `evaluation/METHOD.md` §3 and §7; `PAPER.md` §8.5, §10, and §11.4;
PC11–PC14.

**What would reduce it.** Live captured evidence from an independently operated
provider, real detector campaigns, and a separately adjudicated defect corpus.
The separate live gates exercise some of these paths, but they are not part of
the 60-receipt ablation.

---

## L5. Digest-bound, not signed, provenance

**Limitation.** Receipts and manifests bind exact bytes with SHA-256. There is
no signature, transparency log, authentication token, or trusted build root.

**Impact.** A party that can rewrite the receipts and recompute every digest and
the manifest can produce a self-consistent alternative evidence set. The
reconstructor detects missing, extra, non-canonical, and stale-digest
tampering; it cannot detect a coordinated rewrite that also recomputes the
digests.

**Evidence.** `SPEC.md` canonical-encoding rules; `PAPER.md` §2 and §11.5;
`evaluation/reconstruct.py` digest checks; PC1.

**What would reduce it.** Signed receipts, a transparency log, a trusted build
root, and an external anchor for the manifest digest. A signature alone would
still not establish semantic truth.

---

## L6. Mechanism-specific detectors

**Limitation.** Detector calibration is structural and specific to the
mechanism, build, transport, and case in the fixture registry. A `CALIBRATED`
label is not a universal detector score.

**Impact.** The result does not estimate sensitivity or specificity for Miri,
AddressSanitizer, LSan, TSan, loom, Kani, or any other mechanism outside the
named fixtures. A detector that passes one control can still miss a different
defect class.

**Evidence.** `PAPER.md` §8.5 and §11.6; PC11; README's live-detector
limitations.

**What would reduce it.** A mechanism-specific, pre-registered campaign over
independently selected defects, with known-bad/known-good controls and reported
denominators. The current detector result is one family of typed controls.

---

## L7. Small finite Coq theorem and reviewed correspondence

**Limitation.** The proof gate checks a small finite Coq theorem and its
negative controls. Implementation correspondence is a reviewed evidence binding
over a source inventory or digest-bound evidence, not a machine-proved semantic
refinement.

**Impact.** The proof result does not establish the soundness of the crate, an
arbitrary FFI implementation, or a general refinement relation between Rust and
C. A manifest that passes closure and correspondence is not thereby a proof of
memory safety.

**Evidence.** `PAPER.md` §8.5 and §11.7; PC12; README's proof claim ceiling.

**What would reduce it.** A larger machine-checked development with a proved
refinement relation and a mechanically checked correspondence proof. That is
outside the declared finite theorem.

---

## L8. Recorded native execution is not authenticated

**Limitation.** The Phase 7 live chain records exact candidate bytes, provider
executables, loader closures, and two replays. The record is digest-checked but
not authenticated by a signature or trusted execution environment.

**Impact.** `authentic_native` provenance is a recorded, digest-checked
execution record, not a signed attestation. A same-directory modified DSO can
satisfy a path-based binding rule; the substituted-DSO seal uses an out-of-tree
preload, but the general trust problem remains.

**Evidence.** README's claim ceiling and Phase 7 notes; `PAPER.md` §11.8; the
default evaluation types the authentic chain as `NOT_RUN` (PC14).

**What would reduce it.** Signed provider attestations, a trusted build root,
and an independent verifier of the execution environment. The current bridge
does not provide them.

---

## L9. Phase 8 declared scope

**Limitation.** The Phase 8 conversion results cover one OpenSSL-Rust boundary
witness (`up_ref` overflow), its repair, one unmodified curl TLS 1.3
positive/negative workflow, and one loader closure.

**Impact.** The results do not cover all 33 Safe-33 consumers, do not establish
general compatibility, and do not establish `SAFE_COMPATIBLE`. The target's own
ledger remains incomplete.

**Evidence.** README's Phase 8 claim ceiling; `PAPER.md` §11.9; the Phase 8 live
gate is system verification, not an evaluation claim (PAPER §12.1).

**What would reduce it.** A pre-registered cohort replay of all consumers, a
compatibility matrix, and a property-specific evidence-reuse study. The current
scope is explicitly declared.

---

## L10. No third-party replication

**Limitation.** The independent reconstructor was written in the same repository
and reads the same committed receipts. It is algorithmically separate from the
Rust harness—no shared verifier code and no crate execution—but it is not a
third-party replication.

**Impact.** Agreement between the harness and the reconstructor shows that the
counts, digests, split, and claim mappings are reproducible from the committed
artifacts. It does not show that an unaffiliated team would author the same
cases, labels, or baselines.

**Evidence.** `evaluation/reconstruct.py` header; `PAPER.md` §3 and §11.10;
`ci/reconstruction-gate.sh`.

**What would reduce it.** An external team reproducing the protocol and receipts
from the paper and the frozen artifacts, with its own oracle and its own
baseline implementations. No such replication exists.

---

## L11. Reconstruction verifies artifacts, not mechanism semantics

**Limitation.** `evaluation/reconstruct.py` recomputes canonical bytes, digests,
coverage, the held-out split, headline tables, decision counts, and
claim-to-receipt mappings. It does not reimplement the Rust support, path,
detector, proof, or bridge semantics, and it does not re-execute the mechanisms.

**Impact.** A receipt whose `observed` field, observation digest, experiment
digest, and manifest entry were all rewritten consistently could pass the
reconstructor even if the underlying mechanism would not produce that label.
The reconstructor's tamper detection is artifact-level, not semantic-level.

**Evidence.** `evaluation/reconstruct.py` (`validate_receipt`, `load_manifest`,
`reconstruct`); `PAPER.md` §11.5 and §11.10; PC1–PC3.

**What would reduce it.** A separately coded semantic reimplementation of each
finite mechanism, or a signed external anchor for the receipt set, or live
re-execution by an independent party. The Phase 2 conformance oracle covers a
different finite universe; it is not a Phase 9.1 semantic reconstructor.

---

## L12. Baseline authorship and competence

**Limitation.** The naive baselines are implemented by the project. They are
competent implementations of the named simplification, not constant-return
stubs, but they are still chosen by the authors.

**Impact.** A different baseline implementation could separate differently. A
baseline that is weaker than a reasonable engineering alternative would
overstate the production advantage; a stronger baseline could reduce it.

**Evidence.** `PAPER.md` §7 and §11.11; `src/evaluation.rs` baseline arms;
PC5–PC13, PC17.

**What would reduce it.** Independently authored baselines, a baseline
implementation review, and a pre-registered baseline specification. The current
baselines are named and their simplifications are explicit.

---

## L13. Five naive contrasts lack held-out discriminators

**Limitation.** `over_cut`, `boolean_aliasing`, `top_as_exact`,
`provider_ignored`, and `origin_ignored` have no held-out discriminator in this
corpus. Their separating cases are in the development split.

**Impact.** The paper cannot claim a held-out production advantage for those
contrasts. They are reported as negative findings or downgraded contrasts, and
the affected parts of C5, C6, C7, and the H2 ablation are downgraded to
development-split observations. The production observations and the named
protocol claims remain supported, but the stronger "held-out separation"
interpretation is not. H3 still has held-out separators in `raw_stdout` and
`job_success`.

**Evidence.** `PAPER.md` §8.4 and §10; PC7, PC8, PC10, PC11, PC17; PC3 for the
claim status.

**What would reduce it.** New pre-registered held-out cases that isolate the
over-cut, boolean-aliasing, top-alias, foreign-provider, and origin-ignoring
distinctions without reusing development material. Adding them requires a new
protocol version and a new measurement run.

---

## L14. Single-run resource observations

**Limitation.** Wall time and peak RSS are single-run observations of fast child
processes. The corpus is too small for algorithmic cost inference.

**Impact.** The reported 32 ms total wall time and 5,040–6,016 KiB peak RSS
demonstrate accounting and bounds, not a performance comparison. They should not
be used to rank mechanisms.

**Evidence.** `PAPER.md` §9 and §11.12; PC15.

**What would reduce it.** Repeated randomized runs, a fixed resource budget, a
performance estimand, and a reporting plan for variance and censoring. That was
not the pre-registered primary metric.

---

## L15. Finite path/alias model

**Limitation.** The path cases are explicit finite traces. The evaluation does
not extract aliases from source or MIR, resolve compiler types, observe native
callbacks, model concurrency, or establish whole-program closure.

**Impact.** A `compatible_within_finite_footprint` outcome is not universal
aliasing compatibility. The path arm tests the declared qualification logic, not
a production alias analysis.

**Evidence.** `PAPER.md` §2, §6, and §11; PC8–PC10, PC17; README's finite-model
claim ceiling.

**What would reduce it.** A source/MIR extraction pipeline with an independent
alias oracle and a coverage argument. The current model is explicit-input only.

---

## L16. Detector and proof live controls are `NOT_RUN` in the default evaluation

**Limitation.** Live Miri, live Coq, and the authentic native chain are typed
`NOT_RUN` in the default evaluation image. The separate live gates exercise
their declared scopes, but those runs are not part of the 60 receipts.

**Impact.** The ablation does not establish live detector behaviour, live proof
checking, or an authentic native chain. It establishes that the default harness
does not fabricate a pass when the tool is absent.

**Evidence.** `PAPER.md` §8.6 and §12.1; PC14; PC1 (`NOT_RUN` receipts).

**What would reduce it.** A frozen receipt set from a live environment with the
same protocol and an authenticated execution record. The live gates are the
current evidence for live behaviour, not the ablation.

---

## L17. No population or statistical inference

**Limitation.** The study is deterministic and finite. It computes exact counts
over fixed inputs, not estimates over a random sample. No p-values, confidence
intervals, or significance tests are reported.

**Impact.** The counts cannot be extrapolated to a defect population. A zero
false-accept count on 18 held-out decisions is not a zero error rate in
deployment.

**Evidence.** `evaluation/PRE-REGISTRATION.md` §4; `PAPER.md` §1.2 and §5.2;
PC4.

**What would reduce it.** A sampling frame, randomized paired campaigns,
pre-committed budgets, repeated seeds, and an analysis plan with intervals and
censoring. That is future work, not a result of this paper.

---

## L18. Compatibility and safe-interior claims remain withheld

**Limitation.** The crate does not accept `SAFE_COMPATIBLE`. Universal
safe-interior soundness is outside the finite profile. The Phase 8 conversion
module is fail-closed bookkeeping over declared evidence, not a compatibility or
memory-safety claim.

**Impact.** No result here should be read as a statement that a port is
compatible, that a safe interior is sound, or that a real conversion is
memory-safe. The README's `WITHHELD_NOT_RUN` and `SAFE_COMPATIBLE` statements
remain in force.

**Evidence.** README's claim ceiling; `PAPER.md` §1.2 and §11.9; `SPEC.md`
non-claims; the Phase 8 live gate's declared scope.

**What would reduce it.** A property-specific compatibility proof or an
independent compatibility campaign, plus a soundness argument for the safe
interior. Neither is present.

---

## Summary

| ID | Limitation | Primary impact |
|---|---|---|
| L1 | Finite domains | No population inference. |
| L2 | Same-repository oracle | Agreement is not independent ground truth. |
| L3 | Selection leakage vs temporal holdout | Held-out is not clean out-of-sample. |
| L4 | Synthetic fixtures; no organic discovery | Adjudication logic, not real discovery. |
| L5 | Digest-bound, not signed | Coordinated rewrite is not detectable. |
| L6 | Mechanism-specific detectors | No detector-wide accuracy. |
| L7 | Small finite Coq theorem; reviewed correspondence | No general proof soundness. |
| L8 | Recorded native execution not authenticated | No signed provenance. |
| L9 | Phase 8 declared scope | No all-33-consumer or compatibility claim. |
| L10 | No third-party replication | Same-repository reconstruction only. |
| L11 | Reconstruction verifies artifacts, not semantics | Coordinated semantic tamper can evade. |
| L12 | Baseline authorship | Separation depends on baseline choice. |
| L13 | Five contrasts lack held-out discriminators | Development-only downgrade. |
| L14 | Single-run resource observations | No cost ranking. |
| L15 | Finite path/alias model | No alias completeness. |
| L16 | Live controls `NOT_RUN` in default | No live behavior in the ablation. |
| L17 | No population or statistical inference | Exact counts only. |
| L18 | Compatibility and safe-interior withheld | No `SAFE_COMPATIBLE`. |
