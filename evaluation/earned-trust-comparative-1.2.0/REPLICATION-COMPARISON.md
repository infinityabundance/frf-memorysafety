# 1.1.0 → 1.2.0 comparative replication: case-by-case comparison

**Status:** comparison of the frozen 1.1.0 comparative run with the 1.2.0
replication run, after the `A002` targeted replay. This is a bookkeeping
comparison, not a new evaluation.
**1.1.0 evidence:** `evaluation/earned-trust-comparative/` (unchanged).
**1.2.0 replication:** `evaluation/earned-trust-comparative-1.2.0/`.
**Replay record:** `REPLAY-1.2.0.md`; amendment `AMENDMENT-002.md`.
**Reuse:** the same 18 case ids, 6/12 partition, mutations, expectations, ground
truth and metrics. The 1.2.0 run is not a new held-out test.

`restoration` is the observed restoration-control outcome. `not_run` meant the
declared 1.2.0 base artifact was absent; it was not a pass and not a refusal.
After `A002` no case is `not_run`.

---

## 1. Case-by-case table

| Case | Partition | Expected | 1.1.0 observed | 1.1.0 restoration | 1.2.0 observed | 1.2.0 restoration | Change |
|---|---|---|---|---|---|---|---|
| `c01` positive campaign closure | development | accept | accept | n/a | accept | n/a | none |
| `c02` candidate substitution | held-out | refuse | refuse | accept | refuse | accept | none |
| `c03` completeness deletion | held-out | refuse | refuse | accept | refuse | accept | none |
| `c04` truncated population | development | refuse | refuse | accept | refuse | accept | none |
| `c05` duplicate population row | held-out | refuse | refuse | accept | refuse | accept | none |
| `c06` DSSE payload substitution | held-out | refuse | refuse | accept | refuse | accept | none; wrong-code persists |
| `c07` signer role | development | refuse | refuse | accept | refuse | accept | none |
| `c08` transparency inclusion | held-out | refuse | refuse | unresolved | refuse | unresolved | none |
| `c09` stale checkpoint | held-out | refuse | refuse | refuse | refuse | refuse | none |
| `c10` time wrong imprint | development | refuse | refuse | accept | refuse | accept | none |
| `c11` withdrawn claim | held-out | refuse | refuse | refuse | refuse | refuse | none; disagreement persists |
| `c12` missing archive object | held-out | refuse | refuse | **refuse** | refuse | **accept** | restoration improved |
| `c13` SARIF suppression | development | refuse | refuse | accept | refuse | accept | none; wrong-code persists |
| `c14` cross-property regression | held-out | refuse | refuse | accept | **refuse** | accept | none; replayed under A002 |
| `c15` interop collapsed cell | held-out | refuse | refuse | accept | **refuse** | accept | none; replayed under A002 |
| `c16` TLS collapsed cell | development | refuse | refuse | accept | **refuse** | accept | none; replayed under A002 |
| `c17` proof closure removal | held-out | refuse | refuse | unresolved | refuse | unresolved | none; wrong-code persists |
| `c18` positive archive reconstruction | held-out | accept | **refuse** | **refuse** | **accept** | **accept** | wrongful refusal resolved |

## 2. Totals

| Metric | 1.1.0 | 1.2.0 |
|---|---|---|
| Cases | 18 | 18 |
| Executed cases | 18 | 18 |
| `NOT_RUN` cases | 0 | 0 after the A002 replay (3 before it) |
| Decision matches | 17/18 | 18/18 |
| Matches among executed cases | 17/18 | 18/18 |
| Wrongful acceptance | 0 | 0 |
| Wrongful refusal | 1 (`c18`) | 0 |
| Unresolved (direct decision type) | 0 | 0 |
| Unresolved under metric M4 (typed `NOT_RUN` included) | 0 | 0 after the A002 replay |
| Instrument errors | 0 | 0 |
| Restoration failures | 6 (`c08`, `c09`, `c11`, `c12`, `c17`, `c18`) | 4 (`c08`, `c09`, `c11`, `c17`) |
| Wrong-code command refusals | 4 commands over 3 cases (`c06`, `c13`×2, `c17`) | 4 commands over 3 cases (`c06`, `c13`×2, `c17`) |
| Independent reconstruction discrepancies | 0 | 0 |

Before `A002`, the 1.2.0 match count was 15/18 because `c14`, `c15` and `c16`
were `NOT_RUN`. The replay of those three cases raised it to 18/18; `c18`
already improved from a wrongful refusal to an acceptance in the original run.
The match count is not a quality score. A `NOT_RUN` was not a pass, and a
replayed decision is not a strengthened result. The four wrong-code refusals and
the four restoration failures are unchanged.

## 3. Specific questions

### 3.1 Does `c18` now pass because the 1.2.0 archive includes the source tree?

**Yes.** The 1.2.0 archive has 106 objects instead of 76 and preserves the
declared candidate and instrument source files (`Cargo.toml`,
`rust-toolchain.toml`, `src/*.rs`, `tests/native/fixtures/*`). On the intact
archive:

- `etp archive verify` exits 0 with status `verified`, `problems: []`,
  `missing_required_categories: []` and `reconstruction.complete: true`;
- `reconstruct.py --root . --json` exits 0 with `case_count: 13` and
  `closure_sha256: ece999b403e7ce05f94dbe2304a2b86b24afb1a9cd5dc5e1a5f57d22482d735a`.

The 1.1.0 failure was exactly the absence of `Cargo.toml` and the source tree,
which made `reconstruction.complete` false. The change is a real archive repair,
not an expectation change. The archive repair alone is not sufficient for the
observed acceptance: the frozen 1.1.0 predicate compared the whole
`ReconstructionReport` object to `{"complete": true}`, which no report can
satisfy. The predicate was re-expressed as `reconstruction.complete: true`
before execution. Under the old encoding the archive command would have been
`unresolved` even with a complete archive. Both changes are necessary; neither
changes the expected decision. They do not establish authenticity, completeness
or independent reproduction.

`c12` restoration improves for the same reason: the intact archive now accepts,
so the restoration control passes. The `c12` case run still refuses on the
deleted object.

### 3.2 Does the `c11` claim-level disagreement persist?

**Yes.** The Rust verifier exits 0 with
`support.claims[claim_id=claim.campaign-closure].present_admissible: false`,
which the harness treats as a claim-level refusal. The independent
`verify_revocation.py` exits 0 and is classified as accepting. The case refuses
because one decisive command refuses, but the instruments are not equivalent.
The restoration still selects the same `claim.campaign-closure`, so it is
recorded as a refusal rather than the declared
`claim.campaign-closure-with-mirror` acceptance. This is unchanged from 1.1.0.

### 3.3 Does the `c13` SARIF schema disagreement persist?

**Yes.** The Rust `SarifSuppressionProperties` still denies `suppression_id`,
and the independent verifier still refuses with `InconsistentCount` because the
suppressed result count is not zero. The decision is `refuse`, matching ground
truth, but neither instrument reaches the declared suppression-review
diagnostic. Both commands are wrong-code refusals in the 1.2.0 run, as in 1.1.0.
The restoration control passes because the intact SARIF is accepted by the Rust
command.

### 3.4 Do the `c08`, `c09` and `c17` restoration issues persist?

**Yes.**

- `c08`: the independent transparency verifier is still invoked without
  `--json`, so its exit-0 restoration output cannot supply a declared
  `report_status`; the harness records `unresolved`.
- `c09`: `etp checkpoint verify` still exits 0 on the restored checkpoint but
  reports `partial` with `consistency_not_checked`, so the restoration is a
  refusal, not the declared acceptance.
- `c17`: `proof verify` without `--live` still exits 6
  (`checker_unavailable`) on the restored manifest, so the restoration is
  `unresolved`. The mutated case also still refuses with an undeclared code
  (exit 3), a wrong-code refusal.

These are preregistration/command defects, not 1.2.0 regressions.

### 3.5 What is new?

The original 1.2.0 run introduced three typed `NOT_RUN` cases (`c14`, `c15`,
`c16`) because the published 1.2.0 evidence set did not contain the
cross-property, interop or tls-matrix artifacts those frozen cases declare.

Amendment `A002` produced those artifacts with the declared 1.2.0 instrument
gates and replayed only those three cases. All three now refuse as declared and
their restoration controls pass. This is a re-run of previously `NOT_RUN` cases,
not a fresh discovery and not a post-hoc expectation change. `c14` and `c15`
were held-out cases that have now been executed twice; the first execution
returned no decision. The held-out partition is therefore no longer
single-execution evidence for those two cases (`AMENDMENT-002.md` §4).

No 1.1.0 artifact was substituted. There is no new wrong-code refusal, no new
wrongful acceptance and no new wrongful refusal.

## 4. Non-claims

This comparison is not a new held-out test, not a fresh discovery, not
independent replication by another actor, and not external verification. It does
not establish that the 1.2.0 controls are correct, complete, or general. A
`NOT_RUN` is not a pass. A refusal is not a pass. A digest is not
authentication.
