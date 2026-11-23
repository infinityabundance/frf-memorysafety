# ETP formal acceptance core

**Subphase:** Phase 16.1a.
**Artifact:** `tests/proof/coq/etp_acceptance.v` and
`tests/proof/coq/manifest-acceptance.json`.
**Gate:** `ci/proof-gate.sh` (live Coq case `acceptance`).
**Frozen baseline:** FRF-MemorySafety 1.0.0 at commit
`02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`. This subphase changes no 1.0.0
artifact, schema meaning, case population or claim ceiling.

This document records a mechanically checked, finite abstract model of the
acceptance core and states exactly what it does and does not establish. It is
an instrument artifact, not evidence that the Rust crate is sound.

---

## 1. What is proved

The model is a finite universe:

- premises `pA`, `pB`, `pC`, `pD`;
- claims `c0`, `c1`, `c2`;
- four derivation constructors, including a binary rule that builds `c2` from
  derivations of `c0` and `c1`.

`derivation` is an inductive family indexed by the claim it establishes. Every
inhabitant is a finite constructor tree, so a cyclic derivation is not a
well-typed term, and a derivation of one claim cannot be used as a derivation of
another. `premises` enumerates the leaves of a derivation; `derivation_size`
counts its nodes.

A `policy` records the policy version, candidate identity, campaign, actor
threshold, freshness and archive requirements, and the required premises. A
`state` records the observed policy version, the bound candidate, the reported
claim, premise presence, challenge and revocation state, campaign closure,
independent-actor count, freshness, archive presence, and an authentication
flag.

`admitted_via p s c d` is the single acceptance rule:

```text
policy_satisfied p s
and s.reported_claim = c
and every premise of d is present, unchallenged and unrevoked
```

`admitted p s c` is the existential closure of that rule over derivations of
`c`. Authentication is deliberately not part of the rule.

## 2. Theorems

All 15 declarations compile under Debian Coq 8.16.1 and each reports
`Closed under the global context` from `Print Assumptions`. There are no
`Admitted`, `Axiom`, `Parameter` or `admit` occurrences.

| # | Theorem | Meaning |
|---|---|---|
| 1 | `no_unsupported_or_cyclic_admission` | Admission yields a finite derivation whose premises are present, unchallenged and unrevoked. |
| 2 | `missing_mandatory_evidence_blocks` | A required premise that is absent blocks admission. |
| 3 | `candidate_substitution_invalidates` | A policy/candidate identity mismatch blocks admission. |
| 4 | `authentication_is_not_semantic_support` | A valid authentication flag with no admissible derivation is refused. |
| 5 | `unrelated_proof_does_not_satisfy` | A reported claim that differs from the evaluated claim is refused. |
| 6 | `challenged_premise_blocks` | A challenged premise that every derivation of the claim requires blocks admission. |
| 7 | `revoked_premise_invalidates` | A revoked premise that every derivation of the claim requires blocks admission. |
| 8 | `incomplete_campaign_blocks` | A required campaign that is not closed blocks admission. |
| 9 | `duplicate_credentials_do_not_satisfy_independence` | Fewer independent actors than the declared threshold blocks admission. |
| 10 | `stale_transparency_blocks` | A required freshness condition that is false blocks admission. |
| 11 | `missing_archive_blocks_reconstruction` | A required archive that is absent blocks admission. |
| 12 | `policy_substitution_blocks` | A policy/state version mismatch blocks admission. |
| 13 | `every_derivation_is_finite` | Every derivation has positive finite size; a cyclic-only support object is not representable. |
| 14 | `acceptance_core_inhabited` | The acceptance rule is satisfiable on a concrete sample policy and state, so the negative theorems constrain a non-vacuous predicate. |
| 15 | `acceptance_core_sound` | The composite theorem: the conjunction of theorems 1–14, proved by invoking each theorem. This is the manifest's main theorem. |

The manifest declares a real dependency closure: `acceptance_core_sound`
depends on theorems 1–14, and the gate checks that the declared
`closure.theorems` equals the closure reachable from `theorem.name`. An earlier
draft declared a padded closure with no dependency edges and was refused with
`rejected_unrelated`; the refusal is recorded in this history, not erased.

## 3. Measured evidence

| Item | Value |
|---|---|
| Proof file SHA-256 | `b0db6791d67db799a3c73f177e6da5e3adfccda1b6879be5457b030d51dfb8ab` |
| Checker | `/usr/bin/coqc`, Coq 8.16.1, OCaml 4.13.1 |
| `coqc` SHA-256 | `aae9841a59ea5a4d04c759d8328f52b3fa84f3b0e4fc7711507325d70639a240` |
| Live seal cases | 8 passed: `approved`, `admitted`, `axiom`, `unrelated`, `unchecked`, `missing_transition`, `acceptance`, and the capability probe |
| Live proof tests | 6 passed (`tests/proof_live.rs`) |
| Base gate | 509 debug tests, 509 release tests, 0 failed, 0 ignored |

The `acceptance` case ran the real checker, compiled the model, and executed
`Print Assumptions` for all 15 theorems. The other seven cases establish that
the existing refusals are unchanged.

## 4. Resource and instrument controls

Every command ran in `rust:1.85.0-slim` with
`--memory=2g --memory-swap=2g --pids-limit=512 --cpus=2 --ulimit nofile=1024:1024 --oom-score-adj=500`,
`--cap-drop ALL` with only `DAC_OVERRIDE`, `CHOWN` and `FOWNER`, and
`--security-opt no-new-privileges`. Nothing ran on the host.

Measured peak cgroup memory for the crate build is about 1.4 GB with
incremental compilation disabled. The proof gate now exports
`CARGO_BUILD_JOBS=1` and `CARGO_INCREMENTAL=0`, matching `ci/gate.sh`. This is
a resource-scheduling change that keeps the build inside the unchanged 2 GB
cap; it weakens no test, population, assertion or claim ceiling. The change is
recorded here and in the commit message.

## 5. Limits

- This is a finite abstract model. It does not prove Rust soundness, memory
  safety, the wrapper, the FFI boundary or any native execution.
- The model is not proved to refine any Rust acceptance implementation. That
  correspondence remains a separate obligation; the manifest
  `implementation_binding` shares the Phase 6.2 symbols and transitions but
  claims no refinement.
- Completeness of the declared dependency graph is not proved.
- A green proof gate is not certification and is not authorization to deploy.
- Manifest validation is not proof checking. The live case compiles and checks
  the assumptions of the declared theorems; it does not establish that the
  model's premises hold of any real campaign.
- The composite theorem is a conjunction of separately proved invariants. It
  does not add a property beyond them, and it does not strengthen any 1.0.0
  claim.
