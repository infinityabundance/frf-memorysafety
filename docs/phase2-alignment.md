# Phase 2.1 alignment: founded support, cuts, and policy custody

Snapshot: branch `staging`, base commit `eb2f4fb`, crate `frf-memorysafety 0.2.0`.
This document audits the Phase 2 paragraph and the "At every phase" paragraph of
`research/FRF-MemorySafety-Implementation-Prompt-v2.md` against `SPEC.md` §6,
`research/pdf-latest.txt` §12.3–§12.4, and the code.

Statuses are **implemented** (capability exists and has executable tests),
**partial** (some semantics exist but a stated requirement is not enforced or
not tested), or **missing**. All "after" statements are limited to finite
bookkeeping. They are not memory-safety soundness claims.

## Requirement matrix

| # | Required capability | Before | After | Primary evidence | Authority |
|---|---|---|---|---|---|
| 1 | Least-fixed-point AND/OR support; explicitly justified leaves; no implicit leaf admission; no greatest-fixed-point semantics | Partial: LFP worklist and `admitted_leaves` existed, but the certificate view disagreed with evaluation for an admitted leaf that also had non-nullary rules (`eb2f4fb:src/support.rs:342`). | Implemented: admission is a nullary justification in both views; unadmitted empty rules derive nothing; ungrounded cycles derive nothing. | `src/support.rs:59`, `:417`, `:487`; `tests/phase2_support.rs:22`; `tests/phase2_mutants.rs:101` | `SPEC.md` §6.1; Tarski [1]; Abiteboul–Hull–Vianu [2] |
| 2 | Challenge vs support are distinguished; a challenged premise cannot support | Implemented: positive and admissible fixed points were separate. | Implemented and regression-locked: challenged premises withhold admissibility while positive history survives; states are explicit. | `src/support.rs:384`; `tests/phase2_support.rs:73`; `tests/support_semantics.rs:78` | `SPEC.md` §6.1–§6.2 |
| 3 | All-node certificates cover every node in the derivation | Partial: intermediate nodes were included, but an admitted leaf with other rules lost its singleton certificate (`eb2f4fb:src/support.rs:361`). | Implemented: certificates are minimal, include every intermediate and the conclusion, and agree with evaluation. | `src/support.rs:487`; `tests/phase2_support.rs:91`; `tests/independent_conformance.rs:47` | `SPEC.md` §6.2; Buneman–Khanna–Tan [3]; Cheney et al. [4] |
| 4 | Fixed-rule cuts are exact at rule boundaries; cutting one rule does not truncate unrelated valid derivations | Partial: node-level `exact_cut` existed (`eb2f4fb:src/support.rs:458`), but there was no rule-boundary cut operation or test. | Implemented: `remove_rule` removes exactly the `conclusion <- premises` instance; tests cover alternative routes, wrong premise sets, and unrelated claims. | `src/support.rs:71`, `:604`; `tests/phase2_support.rs:130`; `tests/phase2_mutants.rs:132` | `SPEC.md` §6.2; Gupta–Mumick–Subrahmanian [5] |
| 5 | Rule and policy versioning: derivation/verdict tied to a policy version; reconstruction under a different policy is detectable | Partial: `SupportPolicy` digest existed (`eb2f4fb:src/support.rs:190`), but no constructor/verifier bound a verdict to it, and reconstruction accepted any caller-supplied "old" policy. | Implemented: `HistoricVerdict::record`/`verify` bind id, version, digest, exclusions, and result; recorded reconstruction rejects policy substitution. | `src/support.rs:220`, `:251`, `:311`, `:348`, `:679`; `tests/phase2_support.rs:216`, `:260` | `SPEC.md` §6.3; prompt §11.1; paper §12.4 |
| 6 | Noninterference arguments: unrelated valid support survives revocation, challenge, and policy changes | Partial: incremental deltas existed, but there was no structured report, retained witnesses, or explicit challenge withholding. | Implemented: `NonInterferenceReport` lists lost/gained/retained/withheld claims and a surviving certificate per retained claim. | `src/support.rs:719`, `:746`; `tests/phase2_support.rs:150`, `:176`, `:196`; `tests/phase2_mutants.rs:213` | `SPEC.md` §6.2; Gupta et al. [5]; Green et al. [6] |
| 7 | Immutable historical verdicts: past verdicts are retained; new policy versions cannot rewrite history | Partial: `HistoricVerdict` was an unconstructible public struct with a digest field and no verification. | Implemented: canonical, digest-bound records; replay verification; recorded reconstruction proves byte-identical history and rejects substitution/tampering. | `src/support.rs:251`, `:311`, `:348`, `:679`; `tests/phase2_support.rs:216`, `:260`; `tests/section_12_4.rs:93`, `:124` | `SPEC.md` §6.3; prompt §11.1 |
| 8 | The nine §12.4 coverage/policy/support cases with exact expected outcomes | Missing: neither the paper's `acceptance_cases.py` nor derivative fixtures/tests were present. | Implemented as nine derivative tests with exact outcomes: three coverage, three policy, three alternative-support. | `src/closure.rs:74`; `tests/section_12_4.rs:35`, `:50`, `:66`, `:93`, `:109`, `:124`, `:146`, `:157`, `:170` | paper §12.4; prompt §5, §11.1 |
| 9 | Mutant rejection: wrong greatest fixed point, hidden intermediate, shared mapping, changed policy; positive control | Partial: unit tests covered cycles and extraction, but no named mutant courts or positive control. | Implemented: each mutant is a test-local wrong evaluator; the shipped engine rejects its verdict, and unrelated valid support survives all changes. | `tests/phase2_mutants.rs:101`, `:132`, `:152`, `:165`, `:191`, `:213` | prompt Phase 2 seal; paper §12.3 |
| 10 | Independent evaluator for the 110,592-configuration campaign | Partial: `conformance_counts` used the same evaluator and certificate code it was checking (`eb2f4fb:src/support.rs:663`). | Implemented: a naive round-based LFP evaluator and an independent all-node certificate/minimality checker replay 110,592 configurations, 331,776 node comparisons, and 331,776 exact-cut comparisons. | `tests/independent_conformance.rs:20`, `:47`, `:84`, `:103` | paper §12.3–§12.4; Tarski [1] |

## §12.4 case registry (derivative, not the paper's originals)

The paper's `research/acceptance_cases.py` is not present in this repository.
Per the prompt, these are new derivative conformance cases with distinct local
identities, not reconstructed copies of the paper's original files.

| ID | Mechanism | Exact expected outcome | Test |
|---|---|---|---|
| A1 | Observed edge omitted from declaration | `Falsified` with the observed omission | `section_12_4.rs:35` |
| A2 | Declared edge not observed | `NotFalsified`; not conservative closure | `section_12_4.rs:50` |
| A3 | Observed declared edge | `NotFalsified`; not conservative closure | `section_12_4.rs:66` |
| B1 | Policy removes the `e -> q` inference, evidence bytes unchanged | old `q` supported; new `q` unsupported | `section_12_4.rs:93` |
| B2 | Same evidence, different policy identity | policy and verdict digests differ; verdicts differ | `section_12_4.rs:109` |
| B3 | Reconstruct old verdict under its original policy | old result byte-identical; new policy cannot rewrite it | `section_12_4.rs:124` |
| C1 | Two routes share mapping premise `m`; exclude `m` | both certificates cut; `q` unsupported | `section_12_4.rs:146` |
| C2 | Add a third route through independent premise `d` | `q` survives the `m` cut at graph level | `section_12_4.rs:157` |
| C3 | Also revoke `d` | `q` unsupported again | `section_12_4.rs:170` |

## Authoritative sources

1. A. Tarski. "A lattice-theoretical fixpoint theorem and its applications."
   *Pacific Journal of Mathematics* 5(2):285–309, 1955.
   DOI [10.2140/pjm.1955.5.285](https://doi.org/10.2140/pjm.1955.5.285).
   Establishes the least-fixed-point basis for monotone immediate-consequence
   operators used in §6.1.
2. S. Abiteboul, R. Hull, V. Vianu. *Foundations of Databases.* Addison-Wesley,
   1995. Standard least-fixed-point semantics for positive Datalog and the
   distinction between least and greatest fixed points.
3. P. Buneman, S. Khanna, W.-C. Tan. "Why and where: A characterization of data
   provenance." *ICDT 2001*, LNCS 1973, pp. 316–330.
   DOI [10.1007/3-540-44503-X_20](https://doi.org/10.1007/3-540-44503-X_20).
   Why-provenance as witness sets; basis for all-node certificates.
4. J. Cheney, L. Chiticariu, W.-C. Tan. "Provenance in databases: Why, how, and
   where." *Foundations and Trends in Databases* 1(4):379–474, 2009.
   DOI [10.1561/1900000002](https://doi.org/10.1561/1900000002).
   Provenance polynomials and witness/provenance distinctions.
5. A. Gupta, I. S. Mumick, V. S. Subrahmanian. "Maintaining views incrementally."
   *SIGMOD 1993*, pp. 157–166. DOI
   [10.1145/170035.170074](https://doi.org/10.1145/170035.170074).
   Incremental view maintenance under insertion/deletion; basis for the
   noninterference delta and exact-cut reasoning.
6. T. J. Green, G. Karvounarakis, V. Tannen. "Provenance semirings." *PODS
   2007*, pp. 31–40. DOI
   [10.1145/1265530.1265535](https://doi.org/10.1145/1265530.1265535).
   Annotation/provenance semirings; supports separating positive support from
   admissibility annotations.
7. G. C. Necula. "Proof-carrying code." *POPL 1997*, pp. 106–119. DOI
   [10.1145/263699.263712](https://doi.org/10.1145/263699.263712).
   Certificate checking as a separate, mechanically checkable activity.
8. Local normative sources: `SPEC.md` §6 and §14;
   `research/FRF-MemorySafety-Implementation-Prompt-v2.md` Phase 2, §5, §11.1,
   "At every phase"; `research/pdf-latest.txt` §12.3–§12.4.

## Mutant court mapping

| Mutant | Wrong behavior | Rejected by | Test |
|---|---|---|---|
| Greatest fixed point | Accepts an ungrounded self-cycle or mutual cycle | `evaluate`, `fixed_point`, `has_unsupported_cycle` | `phase2_mutants.rs:101` |
| Hidden intermediate | Certificate omits `u`, so excluding `u` appears harmless | all-node certificates and `exact_cut` | `phase2_mutants.rs:132` |
| Shared mapping | Treats terminal premises as independent, ignoring shared `m` | certificate intersection and `exact_cut` | `phase2_mutants.rs:152` |
| Changed policy | Replays the new policy and calls it history | `HistoricVerdict::verify`, recorded reconstruction | `phase2_mutants.rs:165` |
| Implicit leaf | Grants every empty rule a base case | explicit admission in evaluate and certificates | `phase2_mutants.rs:191` |
| Positive control | — | unrelated valid support survives revocation, challenge, and policy edit | `phase2_mutants.rs:213` |

## Gate record

`./ci/gate.sh` (container: `rust:1.85.0-slim`, 2 GiB memory/swap, 512 pids,
2 CPUs, 1024 fds, reduced capabilities, `no-new-privileges`):

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS |
| `cargo test --locked --all-targets` | PASS — 110 passed, 0 failed, 0 ignored |
| `cargo test --locked --release` | PASS — 110 passed, 0 failed, 0 ignored |

## Remaining Phase 2 gaps for the independent-evaluator subphase

- The independent evaluator and certificate checker live in this repository's
  tests and share the same `SPEC.md` and fixture generator. They are
  algorithmically independent, not externally authored.
- The nine §12.4 cases are derivative. The paper's `acceptance_cases.py`,
  original expectations, and original source digests are absent; no claim is
  made that these are the paper's original files.
- The paper's 17,712 exact-cut count is not reproduced as an identical corpus.
  This crate reports its own 331,776 exact-cut comparisons; counts are not
  interchangeable.
- Historical verdicts are digest-bound and replay-verified, not authenticated.
  There is no signature, trust root, or execution attestation.
- Noninterference is graph-level only. Undeclared common assumptions outside the
  declared rule graph are not discovered.
- The CLI `support evaluate|explain` path still consumes raw rules; policy-bound
  recording is currently a library API (`HistoricVerdict`).
- The paper's separate §6.7 nine adversarial refusal cases and 24
  candidate/scenario records are outside Phase 2.1 and were not modified.

## Phase 2.2 update

Superseded in part by `docs/phase2-conformance.md`:

- The independent oracle now lives in `tests/support_oracle/` and does not call
  the production evaluator, certificate enumerator, or exact-cut predicate. It
  is compared over all 110,592 configurations.
- The paper's `acceptance_cases.py` was located in
  `research/paper/research/` (not the prototype zip). Its nine fixtures and
  exact outcomes are transcribed in `tests/section_12_4.rs` with source
  digests.
- The 17,712 count is the paper's positively-supported-node cut denominator;
  331,776 is all nodes times configurations. Both are pinned and the
  exact-cut condition is checked on the 17,712 cases.
- The CLI `support evaluate|explain` commands now bind a policy file, expected
  digest, and expected version, and reject substitution.
