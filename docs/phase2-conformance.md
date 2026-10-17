# Phase 2.2 conformance: independent oracle and paper corpus alignment

Snapshot: branch `staging`, base commit `2a885fa`, crate `frf-memorysafety
0.2.0`. This document records exactly what Phase 2.2 checks, the finite domain
it checks, and what it does **not** establish.

## Exact tested domain

| Dimension | Value |
|---|---:|
| Claim nodes | 3 (`a`, `b`, `c`) |
| Rule patterns per node | 12 |
| Rule systems | 12³ = 1,728 |
| Revocation masks | 8 |
| Challenge masks | 8 |
| Configurations | 1,728 × 8 × 8 = 110,592 |
| All-node certificate comparisons | 110,592 × 3 = 331,776 |
| All-node exact-cut comparisons | 110,592 × 3 = 331,776 |
| Paper "exact revocation cut checks" | 17,712 |
| Single-revocation monotonicity relations | 165,888 |
| Optimistic-mutant differences | 20,878 |

The twelve patterns per node are: no derivation; the eight conjunctive subsets
of `{a,b,c}`; and the three pairs of alternative singleton derivations. An
empty premise set is an externally justified leaf, matching the paper's stated
assumption. Empty-premise leaves are assumed justified; the experiment does not
validate their truth.

## Independent evaluator and checker

`tests/support_oracle/mod.rs` is a separate implementation written from
`SPEC.md` §6.1–§6.2. It:

* computes positive and admissible least fixed points with a round-based
  immediate-consequence loop;
* computes inclusion-minimal all-node certificates as an antichain fixed point;
* checks certificate well-foundedness and inclusion-minimality independently;
* evaluates exact cuts directly from the certificate family;
* implements a separate depth-first finite-witness search;
* implements the deliberately wrong optimistic/greatest-fixed-point variant.

The module does not import or call `evaluate`, `certificates`, `exact_cut`,
`conformance_patterns`, `conformance_system`, or `conformance_counts` from
`src/support.rs`. It receives only plain data (node names, clauses, admission
flags). Production functions are called only in the integration tests, on the
other side of a comparison.

`tests/independent_conformance.rs` compares, for all 110,592 configurations:

* production positive and admissible support sets against the oracle;
* production verdict states for every node present in the production result;
* the complete production certificate family against the oracle's family;
* production and oracle exact-cut predicates at every node.

`tests/paper_corpus.rs` also pins the paper's own counting definition and the
monotonicity and optimistic-mutant counts.

### Equivalence claim ceiling

Within the enumerated finite domain only, and for this exact encoding of the
twelve patterns, the shipped evaluator, certificate enumerator, exact-cut
predicate, and verdict-state function agree with a separately coded oracle.
This is a **differential consistency result**. It is not a proof of `SPEC.md`,
because both implementations can share a false premise or a misread
specification. It says nothing about native Rust, real FFI graphs, detector
sensitivity, or universal soundness.

## Paper §12.4: original provenance and disposition

Phase 2.1 reported that `acceptance_cases.py` was absent. It was present in the
paper source bundle, not in the prototype zip:

| Original artifact | SHA-256 | Provenance |
|---|---|---|
| `research/paper/research/acceptance_cases.py` | `3a577b985868d087db9ebb655a40da64d2e8844f7e75c2d2a14263777aa6e997` | Paper companion script |
| `research/paper/research/claim_model.py` | `41eb75d88deb735313fda6c1f0c43129ee7179936340e2b12b1a416ac81ea23f` | Shared positive-rule evaluator |
| `research/paper/research/acceptance-cases-results.json` | `abc4e0c2a080d2c918ce971e91caabcd7871ed70f14ac210d678d1d17665a2d5` | Recorded nine-check output, Python 3.14.7 |

The hashes embedded in the recorded JSON for the script and evaluator match the
actual files. `tests/section_12_4.rs` transcribes the identical fixtures and
exact expected outcomes and replays them through the Rust engine. It does not
execute the Python oracle at test time, so this is not authenticated historical
execution. It is a faithful replay of the original cases, not a newly invented
derivative set.

| ID | Original check | Exact expected outcome | Rust test |
|---|---|---|---|
| A1 | `observed_omission` | `inventory_falsified`; missing `(entry, callback)` | `observed_omission_falsifies_the_inventory` |
| A2 | `unexercised_callback` | `not_falsified`; no missing edge; not closure | `unexercised_callback_is_not_falsified_and_not_closure` |
| A3 | `observed_declared_edge` | `not_falsified`; no missing edge; not closure | `observed_declared_edge_is_not_falsified_and_not_closure` |
| B1 | `old_policy_support` | supported `[e, q]` | `old_policy_supports_the_conclusion` |
| B2 | `new_policy_withholds` | supported `[e]` with identical evidence bytes | `new_policy_withholds_the_conclusion_under_identical_evidence` |
| B3 | `historical_decision_reconstructed` | same historical bytes; same evidence bytes; different policy IDs | `historical_decision_is_reconstructed_under_its_original_policy` |
| C1 | `shared_mapping_defeats_both_routes` | supported `[c]` after excluding `m` | `shared_mapping_defeats_both_routes` |
| C2 | `support_without_failed_mapping_survives` | supported `[c, q]` | `support_without_the_failed_mapping_survives` |
| C3 | `all_available_routes_blocked` | supported `[]` after excluding `m, c` | `all_available_routes_blocked` |

## The 17,712 versus 331,776 exact-cut counts

The universe is the same. The denominators differ.

* `331,776 = 110,592 × 3` is an **all-node** comparison: every node in every
  configuration is checked against the exact-cut predicate.
* `17,712 = Σ |S(revoked)|` is the paper's **exact revocation cut check**
  count: for each `(rules, revoked, challenged)`, it checks only nodes that are
  positively supported before any challenge, i.e. nodes in
  `derive(rules, revoked, ∅)`.

The paper's condition is:

```text
(node not in S(revoked union challenged))
  iff every certificate surviving revocation intersects challenged
```

`tests/paper_corpus.rs::production_exact_cuts_agree_on_the_paper_17_712_checks`
enumerates exactly those 17,712 cases and checks the production predicate. The
independent oracle independently recomputes the same count. No semantic
mismatch was found. The two counts are retained as distinct, named numbers and
are not presented as interchangeable.

Two further paper counts are cross-checks rather than claims:

* `165,888` single-revocation monotonicity relations;
* `20,878` configurations where the optimistic mutant differs from founded
  support.

Both are reproduced by the independent oracle.

## CLI policy custody

The manual parser still does not use `clap`. `support evaluate` and
`support explain` now accept:

```text
support evaluate FILE [--policy POLICY_FILE] [--expect-policy-digest MS1_ID] [--expect-policy-version VERSION]
support explain  FILE [--policy POLICY_FILE] [--expect-policy-digest MS1_ID] [--expect-policy-version VERSION]
```

A policy file is `{id, version, rules}`. A support file may also carry an
optional `policy: {id, version}` identity. Custody rules:

* a supplied policy file must have structurally valid rules and rules equal to
  the support file's rules, otherwise exit 3 (substitution rejected);
* an embedded support-file identity must match the policy file;
* `--expect-policy-digest` must be a well-formed `ms1-…` identity (otherwise
  exit 2) and must equal the computed domain-separated policy digest (otherwise
  exit 3);
* `--expect-policy-version` must equal the policy version (otherwise exit 3);
* expected digest/version without any policy identity is exit 2;
* unknown fields in policy or support files are exit 3.

This is the same digest-bound custody as `HistoricVerdict`, exposed at the CLI.
It is not authentication: there is no signature, trust root, or execution
attestation.

## Deep-research basis

Four authoritative sources were consulted through publisher/DOI metadata; the
remaining classic references are standard fixed-point and provenance texts.
The citations state the role each source plays in this methodology, not that
they endorse this crate.

1. A. Tarski, "A lattice-theoretical fixpoint theorem and its applications,"
   *Pacific Journal of Mathematics* 5(2):285–309, 1955.
   DOI [10.2140/pjm.1955.5.285](https://doi.org/10.2140/pjm.1955.5.285).
   Basis for monotone immediate-consequence least fixed points.
2. S. Abiteboul, R. Hull, V. Vianu, *Foundations of Databases*, Addison-Wesley,
   1995, ISBN 0-201-53771-0. Standard least-fixed-point semantics for positive
   rules and the least/greatest fixed-point distinction.
3. P. Buneman, S. Khanna, W.-C. Tan, "Why and Where: A Characterization of
   Data Provenance," *ICDT 2001*, LNCS 1973, pp. 316–330.
   DOI [10.1007/3-540-44503-X_20](https://doi.org/10.1007/3-540-44503-X_20).
   Why-provenance witness sets; basis for all-node certificates.
4. J. Cheney, L. Chiticariu, W.-C. Tan, "Provenance in Databases: Why, How, and
   Where," *Foundations and Trends in Databases* 1(4):379–474, 2009.
   DOI [10.1561/1900000002](https://doi.org/10.1561/1900000002).
   Separates witness/provenance families from truth.
5. G. C. Necula, "Proof-carrying code," *POPL 1997*, pp. 106–119.
   DOI [10.1145/263699.263712](https://doi.org/10.1145/263699.263712).
   Certificate checking as a separate mechanical activity; also the reason a
   checker's agreement is not an authenticity claim.
6. E. T. Barr, M. Harman, P. McMinn, M. Shahbaz, S. Yoo, "The Oracle Problem in
   Software Testing: A Survey," *IEEE Transactions on Software Engineering*
   41(5):507–525, 2015. DOI
   [10.1109/TSE.2014.2372785](https://doi.org/10.1109/TSE.2014.2372785).
   Oracles, differential testing, and the limits of agreement between two
   implementations.
7. W. M. McKeeman, "Differential Testing for Software," *Digital Technical
   Journal* 10(1):100–107, 1998. Differential testing as a consistency
   technique, not a correctness proof.

## Gate record

`./ci/gate.sh` (container `rust:1.85.0-slim`, 2 GiB memory/swap, 512 pids,
2 CPUs, 1024 fds, reduced capabilities, `no-new-privileges`):

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS |
| `cargo test --locked --all-targets` | PASS — 114 passed, 0 failed, 0 ignored |
| `cargo test --locked --release` | PASS — 114 passed, 0 failed, 0 ignored |

## Remaining honest limitations

* The oracle is separately coded but lives in the same repository and shares
  the same `SPEC.md` authorship. It can share a specification error.
* The §12.4 cases are replayed from the original paper script's recorded
  inputs/outcomes, but the Python oracle is not executed in this test suite.
* The 17,712 and 331,776 numbers are aligned by definition, not by importing
  the paper's binary corpus. They are bookkeeping counts over abstract patterns.
* Historical verdicts and CLI policy custody are digest-bound and replay-bound,
  not authenticated. There is no signature or trusted execution root.
* Noninterference remains graph-level; undeclared common assumptions outside
  the rule graph are not discovered.
* No native Rust, Miri, sanitizer, Kani, Loom, FRF court, FRF-Fuzz, or Gemel run
  is performed, and no universal soundness claim is made.
