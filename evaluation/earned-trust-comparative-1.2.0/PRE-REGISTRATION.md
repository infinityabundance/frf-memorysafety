# FRF-MemorySafety Phase 17.1 comparative pre-registration

> **1.2.0 replication note.** This file is copied verbatim from the frozen 1.1.0
> comparative pre-registration. It is reproduced here because the 1.2.0
> replication reuses the same question, hypotheses, population, partitions,
> decision rules, metrics, acceptance criteria, stopping rules, exclusion rules
> and negative-finding policy. In the 1.2.0 replication, every evidence path of
> the form `evaluation/earned-trust/...` is rebound to
> `evaluation/earned-trust-1.2.0/...`. As originally run, three cases (`c14`,
> `c15`, `c16`) became typed `NOT_RUN` because the published 1.2.0 evidence set
> did not contain the declared cross-property, interop and tls-matrix artifacts.
> Amendment `A002` later produced those artifacts and replayed exactly those
> three cases; see `REPLAY-1.2.0.md`. The preregistered design below is
> unchanged. No mutation, expectation, ground truth or metric changed.
>
> The preregistered text below is retained verbatim as the historical design.
> Where it says a case becomes `NOT_RUN`, read that as the original 1.2.0 run;
> the `A002` replay is an execution detail recorded separately, not a change to
> this preregistration.

**Protocol version:** `phase17.2-replication-1.2.0` (replication of the
frozen `phase17.1-v1` design)
**Frozen at commit:** `7f3b0c4210d94cb33cc390599201e2edb1d77959` on branch
`main` (the original Phase 17.1 freeze was `f5a61efe` on `staging`)
**Frozen 1.0.0 baseline:** `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`
**Frozen protocol:** [`protocol.json`](protocol.json)
**Freeze sidecar:** [`OPENING.sha256`](OPENING.sha256)
**Frozen SHA-256 of `protocol.json` only:**
`b4488e4836253e75ee01597857e29a37a89cd23cec9b6eda7a3f8fabdd1c5b76`
**Human-readable population:** [`POPULATION.md`](POPULATION.md)
**Limitations and threat model:** [`LIMITATIONS.md`](LIMITATIONS.md)
**Pending claims:** [`CLAIMS.json`](CLAIMS.json)

The machine-readable protocol is authoritative for the case population,
partitions, mutations, verifier commands, expected decisions, metrics, stopping
rules, and acceptance criteria. This document is the human-readable rationale
and analysis plan. If the two disagree, the harness fails closed and the run is
invalid.

No verifier, gate, `cargo`, `coqc`, Python verification script, or test was run
in this subphase. No result, outcome count, or measured number is produced here.
The expected decisions below are design declarations, not observations.

---

## 1. Question

Does the augmented ETP evidence chain make the declared correct decision on each
of the 18 fixed cases, while the pre-ETP foundation surface accepts all 18
because every committed Phase 9 campaign decision label is `pass`?

The question is about a finite set of synthetic, hand-authored controls. It is
not a question about population-level accuracy, detector sensitivity, defect
recall, verifier soundness, proof soundness, public transparency, external
trusted time, global revocation, deployment security, or certification.

The foundation surface is a **modeled baseline over committed evidence**. It is
not an independent execution of the 1.0.0 binary in this subphase. The
comparison is between the declared decision surfaces; it is not a comparison of
two executed binaries on the mutated copies.

---

## 2. Hypotheses

### H1: discrimination

The augmented surface refuses each of the 16 declared negative controls and
accepts both declared positive controls. The foundation surface accepts all 18
because every committed anchor records the Phase 9 campaign decision label
`pass`.

**Falsified if:** the augmented surface accepts any negative control, or refuses
any positive control.

A non-falsified H1 supports the claim that the augmented chain discriminates on
these 18 controls only. It does not support a universal-effectiveness claim.

### H2: specificity and restoration

Each negative case's refusal is attributable to its declared mutation or
withdrawal. The same command on the declared restoration returns the documented
accepting outcome, or, for the revocation case, the documented
historically-valid and present-withheld outcome. The observed refusal code is
one of the case's declared documented codes.

**Falsified if:** a restoration control fails, or a negative case is refused for
an undeclared reason, or a negative case is refused only because of a usage or
harness error.

A wrong-code refusal is a negative finding, not a correct refusal. An
instrument-error refusal is a negative finding, not a correct refusal.

### H3: held-out criteria

On the 12 held-out cases: zero wrongful acceptance, zero unresolved, every
declared negative control refused, and every declared positive control accepted.

**Falsified if:** any held-out case is wrongfully accepted, unresolved, refused
with an undeclared code, or any declared positive control is refused.

The development positive control `c01` is also reported. The held-out positive
control is `c18`. Both must be accepted for the `every declared positive control
accepted` criterion.

### H4: independent corroboration

Where an independent verifier is declared, it agrees with the Rust CLI on the
accept-or-refuse decision for the case.

**Falsified if:** a declared independent verifier disagrees with the Rust CLI on
a declared decision. A disagreement is reported as a negative finding and is not
averaged away.

"Independent verifier" here means a script that does not import or execute the
Rust crate. It does not mean administratively independent, externally reviewed,
or certified.

### R1: reporting obligation (not a hypothesis)

Every failure, every negative finding, every wrong-code refusal, every
restoration failure, every instrument error, every independent-verifier
disagreement, and every unresolved case is reported even if the held-out
criteria fail. Contradictory observations are retained and classified. This is a
requirement, not a testable hypothesis.

### Falsification and support

A hypothesis is **falsified** by the exact conditions above. A hypothesis that
is not falsified is **supported within this 18-case control family only**. It is
not evidence of universal verifier effectiveness, completeness, soundness,
population-level accuracy, or deployment security.

A negative finding does not change the ground truth. It is reported, and it may
falsify a hypothesis. A ground-truth label may not be changed after execution
without a versioned amendment.

---

## 3. Population and partitions

The population is exactly 18 cases:

- 6 in `development`;
- 12 in `held_out`;
- no case in both; and
- every case bound to real repository paths that exist at the frozen commit,
  with a SHA-256 for each base artifact.

The required families are all represented:

| Family | Cases |
|---|---|
| Positive campaign closure | `c01` |
| Candidate/identity substitution | `c02` |
| Completeness deletion and truncated population | `c03`, `c04` |
| Duplicate or conflicting population row | `c05` |
| DSSE payload substitution | `c06` |
| Signer-role/authorization failure | `c07` |
| Transparency bad inclusion/sibling/root or cross-log | `c08` |
| Stale transparency/checkpoint freshness | `c09` |
| Trusted-time wrong imprint | `c10` |
| Revocation/correction | `c11` |
| Missing archive object | `c12` |
| SARIF removed result or unjustified suppression | `c13` |
| Cross-property regression | `c14` |
| Interoperability matrix collapsed cell or wrong endpoint/executable | `c15`, `c16` |
| Formal acceptance claim removal | `c17` |
| Positive archive or independent reconstruction | `c18` |

No case was dropped. Every case is bound to artifacts that exist at the frozen
commit. The full case table, artifact bindings, mutations, commands, expected
decisions, and rationales are in `POPULATION.md` and `protocol.json`.

### Selection rule `SR1`

Sort the 18 case ids lexicographically in ascending byte order. Assign the
0-based index `i` to `development` if and only if `i mod 3 = 0`. Assign every
other index to `held_out`.

With 18 cases this yields exactly six development cases and twelve held-out
cases. The harness recomputes the rule from the frozen case list and refuses to
run if the result differs from the frozen partitions. A case may not move
between partitions after execution.

This is a deterministic index rule, not a random sample. It protects against
post-execution reassignment within this population only. It is not a temporal
holdout and does not undo prior exposure of these artifact families during
repository development.

---

## 4. Decision rules

### 4.1 Foundation surface (A)

For each case, the foundation anchor is the committed baseline artifact named by
the case: a per-case native receipt or the campaign closure. The foundation
accepts if and only if the anchor's Phase 9 campaign decision label is `pass`.
For a receipt, the label is `adjudication.decision`. For the campaign closure,
the label is the single entry in `decisions` with `label = "pass"`.

The foundation performs no candidate binding, no chain-integrity check, no
freshness check, no correction or revocation check, no authorization check, and
no archive check. It reads the committed baseline, not the mutated copy.

This is a modeled baseline over committed evidence. It is not an execution of
the 1.0.0 binary, and it does not claim that the 1.0.0 binary would accept the
mutated evidence.

### 4.2 Augmented surface (B)

For each case, the harness copies the full repository tree into `{work}` with
the repository read-only, or, for archive cases, copies the archive root into
`{work}/archive`. It applies the declared mutation only inside `{work}` and runs
every declared decisive verifier command over the mutated evidence in the
declared working directory.

The case is:

- **accept** if and only if every decisive command exits 0 and reports its
  documented accepting outcome;
- **refuse** if any decisive command exits nonzero or reports a documented
  refusal; and
- **unresolved** if a declared instrument is unavailable or returns a typed
  `NOT_RUN`.

A refusal is never counted as a pass. A `NOT_RUN` is never counted as a pass. A
claim-level refusal, such as `present_admissible = false` for a withdrawn claim,
is a refusal of the present decision even when the registry status is
`verified`.

### 4.3 Typed exit mapping

| Exit | Meaning | Accounting |
|---|---|---|
| 0 | command completed | acceptance depends on the documented accepting outcome |
| 2 | usage or instrument error | case is `refuse` at the surface; recorded as an instrument error; never a correct refusal |
| 3 | integrity failure | refusal |
| 4 | refused | refusal |
| 5 | detector failure | refusal |
| 6 | typed `NOT_RUN` | unresolved; never a pass |
| 7 | internal harness error | case is `refuse` at the surface; recorded as an instrument error; never a correct refusal |

An instrument-error refusal is not a correct refusal. It is a negative finding.
A wrong-code refusal is not a correct refusal. It is a negative finding.

### 4.4 Context-only commands

Commands marked `decisive: false` do not change the case decision and are never
counted as a pass. The witness-state command in `c08` is context only and is
expected to return a typed `NOT_RUN`. The optional live proof command in `c17`
is context only and may return a typed `NOT_RUN` when `coqc` is unavailable.
Manifest validation is not proof checking.

### 4.5 Ground truth

The ground-truth decision for each case is declared in `protocol.json` and
`POPULATION.md`. It follows from the documented semantics in `docs/` and the
committed verifier usage, not from guessing observed output. The expected
augmented decision equals the ground truth for every case. The expected
foundation decision is `accept` for every case.

---

## 5. Metrics

No metric is measured or reported in this subphase. The execution subphase
measures the following exact, non-composite quantities.

| ID | Metric | Definition |
|---|---|---|
| M1 | decision accuracy per case | observed decision equals declared ground truth |
| M2 | wrongful acceptance | decision `accept` and ground truth `refuse` |
| M3 | wrongful refusal | decision `refuse` and ground truth `accept` |
| M4 | unresolved | decision `unresolved` because an instrument is unavailable or returns a typed `NOT_RUN` |
| M5 | control effectiveness by family | per family: correct refusals with declared codes, wrong-code refusals, acceptances, unresolved cases, and restoration passes |
| M6 | verification wall-clock cost | parent-measured monotonic elapsed time per command and per case, in-container |
| M7 | verification bytes read | exact declared input sizes plus process-tree `rchar` delta when available, with the fallback labelled |
| M8 | independent reconstruction cost | wall-clock and bytes for independent reconstruction and independent verifiers, reported separately |
| M9 | restoration control pass | the restoration returns the documented accepting outcome, or the revocation's documented present-withheld state |
| M10 | instrument error | exit 2 or 7, or a harness check failure for a reason other than the declared refusal signal |
| M11 | foundation/augmented agreement | whether both surfaces make the same decision on the case |
| M12 | correct refusal | negative case refused with a declared documented code |
| M13 | wrong-code refusal | negative case refused with an undeclared code, or a failed restoration |

M2, M3, M4, M10, M12, and M13 are exact counts. They are not combined into a
confidence score, assurance level, grade, or composite index. M6, M7, and M8
are per-run resource accounting only; they are not performance claims and are
not comparable across hosts, images, or runs.

---

## 6. Held-out acceptance criteria

The held-out criteria are:

1. **zero wrongful acceptance** over the 12 held-out cases;
2. **zero unresolved** over the 12 held-out cases; and
3. **every declared positive control accepted** — `c01` (development) and `c18`
   (held-out).

The stricter control-effectiveness expectation is reported separately: every
declared negative control must be refused with a declared documented code, and
every restoration control must return its documented outcome. A refusal with an
undeclared code, an instrument error, or a restoration failure is a negative
finding and does not count as a correct refusal.

Every failure and every negative finding is reported even if the criteria fail.
Passing the criteria is not a certification, a review, an audit, a universal
effectiveness claim, or an authorization to deploy.

---

## 7. Stopping and exclusion rules

### 7.1 Stopping rules

- Stop and declare the run invalid if any bound base artifact is missing or its
  SHA-256 differs from the frozen binding.
- Stop and declare the run invalid if the case population, partition, selection
  rule result, or case id differs from the frozen table.
- Stop and declare the run invalid if the harness writes to `{repo}` or if the
  repository is not restored to its pre-run bytes.
- Stop and declare the run invalid if an expected decision is changed after
  execution without a versioned amendment.
- Do not stop on a refusal, a failure, a wrong-code refusal, an independent
  disagreement, or an unresolved case. Record it, retain it, and continue
  through the fixed 18-case population.
- If a declared instrument is unavailable, record the case as unresolved. Do not
  substitute a different instrument and do not mark the case as a pass.
- If a base artifact is unavailable at execution time, record the case as
  blocked and unresolved. Do not drop it from the population or the denominator.
- If a declared positive control is refused or a declared negative control is
  accepted, record the failure and continue. The criteria are evaluated after
  the run.

### 7.2 Exclusion rules

- No case may be excluded after its result is seen.
- No case may be moved between development and held-out after the protocol is
  frozen.
- No case may be removed from the 18-case population. A blocked case remains in
  the denominator and is reported.
- An exclusion may be recorded only for a declared missing base artifact or an
  unavailable instrument, with the exact reason. The case is classified blocked
  or unresolved, never passed.
- A case that cannot be bound to a real artifact is a blocking defect of the
  pre-registration, not a silent replacement.

---

## 8. Amendment policy

The protocol is frozen by `OPENING.sha256`, which contains the SHA-256 of
`protocol.json` only. The sidecar detects accidental or silent change. It is not
authentication.

**Changing an expectation after execution requires a versioned amendment
recorded separately.** This includes a change to a case population, a
partition, a mutation, an expected decision, a metric, a threshold, a stopping
rule, or a decision rule. The original expectation is retained, and the
amendment states the evidence and reason. An amendment must not retroactively
strengthen a 1.0.0 claim.

**Exploratory harness fixes are permitted only if they do not change the
declared case population, mutations, or expected decisions.** Each fix is an
instrument change, recorded separately, with the instrument digest before and
after. The run is repeated under the new instrument, and both runs are reported.
A fix that changes an expected decision is not an exploratory harness fix; it is
a protocol amendment.

A refusal may not be relabeled as a pass, a `NOT_RUN` may not be relabeled as a
pass, and a wrong-code refusal may not be relabeled as a correct refusal after
the fact.

---

## 9. Negative-finding policy

A **negative finding** is any of:

- a negative case where the foundation and augmented agree, so the augmented
  chain adds no discrimination;
- an augmented acceptance of a negative case;
- an augmented refusal of a positive control;
- a refusal with an undeclared code;
- a restoration-control failure;
- an independent-verifier disagreement on a declared decision;
- an instrument error;
- an unresolved case; or
- a case that could not be bound or executed as declared.

Every negative finding is reported with the case id, the command, the exit
status, the observed code or report field, the expected code, and the exact
evidence pointer. Contradictory observations are retained and classified; they
are not deleted, averaged away, or converted into support.

A negative finding does not change the ground truth. It is reported even if the
held-out criteria fail. It may falsify a hypothesis. It may not be converted
into support for a stronger claim.

---

## 10. Analysis procedure

1. Read `OPENING.sha256` and verify that it contains the SHA-256 of the exact
   `protocol.json` bytes. If it does not, fail closed; the run is invalid.
2. Recompute the 18-case population, the 6/12 partition by rule `SR1`, the
   disjointness, and every artifact binding. Fail closed on any mismatch.
3. For each case in the frozen population, copy the declared evidence into
   `{work}`, apply the declared mutation or identity copy, and run every
   declared decisive command. Record exact argv, working directory, exit status,
   stdout SHA-256, stderr SHA-256, relevant report fields, wall-clock, and bytes
   read.
4. Run the restoration control for each negative case and the identity copy for
   each positive case.
5. Run the declared independent verifiers and the independent reconstruction
   commands, and record their cost separately.
6. Generate `analysis.json` and `ANALYSIS.md` from the receipts. Recompute all
   counts from the receipts; do not hand-edit a receipt or a result.
7. Report every failure, every negative finding, every wrong-code refusal, every
   instrument error, every independent disagreement, and every unresolved case.
8. Report the held-out criteria exactly as declared, whether they pass or fail.

The execution subphase may create the receipts and analysis artifacts named in
`protocol.json`. It may not modify the frozen protocol, the case population, the
mutations, or the expected decisions.

---

## 11. Freeze statement

The protocol is frozen before execution by `OPENING.sha256`:

```
51eaac167a0868341eb425119aff23f119e556c131686ac5544544a1da05a027  protocol.json
```

The sidecar contains the SHA-256 of `protocol.json` only. Re-running a freeze
helper after execution would change the sidecar and invalidate the freeze; the
harness must treat a mismatch as an invalid run. The freeze detects accidental
or silent change only; it is not authentication.

Changing an expectation after execution requires a versioned amendment recorded
separately. Exploratory harness fixes are permitted only if they do not change
the declared case population, mutations, or expected decisions.

---

## 12. Non-claims

This pre-registration does not claim that the foundation binary was executed,
that the augmented chain is complete or sound, that any verifier is independent
in an administrative sense, that the ground truth was independently adjudicated,
that a passing control is a certification, or that a result generalizes beyond
the 18 declared cases. It does not claim public transparency, external trusted
time, external witnessing, global revocation, memory safety, functional
correctness, proof soundness, or deployment security.

A refusal is not a pass. A `NOT_RUN` is not a pass. A digest is not
authentication. A passing gate is not a certification and not an authorization
to deploy.
