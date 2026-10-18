# Phase 6.2: live checked-proof adapter

Snapshot: branch `staging`, crate `frf-memorysafety 0.6.0`.

Phase 6 is complete for the declared Coq mechanism. The default gate installs
no checker and executes the typed `checker_unavailable` path. The separate
proof gate installs pinned Debian Coq, compiles the checked-in proof corpus,
and demonstrates the positive and negative Phase 6 seals against the real
checker. This is a mechanism demonstration on a small finite theorem, not a
proof of the whole crate and not a universal Rust soundness result.

## Checker installation and exact identity

`ci/proof-gate.sh` runs in the same hardened container as `ci/gate.sh`:

```text
rust:1.85.0-slim
--memory=2g --memory-swap=2g --pids-limit=512 --cpus=2
--ulimit nofile=1024:1024 --oom-score-adj=500
--cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER
--security-opt no-new-privileges
```

It installs only the Debian packages needed to check and parse the reports:

```sh
apt-get -o APT::Sandbox::User=root update
apt-get -o APT::Sandbox::User=root install -y --no-install-recommends coq jq
```

Observed in the gate run:

```text
/usr/bin/coqc
The Coq Proof Assistant, version 8.16.1
COQ_VERSION=8.16.1
aae9841a59ea5a4d04c759d8328f52b3fa84f3b0e4fc7711507325d70639a240  /usr/bin/coqc
```

The Debian package is `coq 8.16.1+dfsg-1+b2` on Debian bookworm. The manifests
pin `checker.version` to `8.16.1` and `checker.executable` to `coqc`. The
adapter resolves the executable on a fixed search path, hashes the resolved
bytes, and rejects a version, executable name, or resolved path that does not
match the manifest. The executable digest is recorded in the run receipt; it
is an observation for this run, not a signature or a trust root.

## Invocation, isolation, and bounds

The adapter uses only `std::process::Command` with explicit argv vectors. It
never invokes a shell. Each run:

* creates a private temporary directory with mode `0700` and `0600` files;
* clears the environment and sets only `PATH`, `HOME`, `LC_ALL`, `LANG`, and
  `TZ`;
* uses a fixed checker search path (`/usr/local/bin:/usr/bin:/bin`);
* uses null stdin and a separate process group;
* bounds each process to 120 seconds and each captured stream to 1 MiB;
* records the exact argv, exit status, bounded stdout/stderr, their SHA-256
  digests, the executable digest, and the proof digests.

Proof files are staged flat by Coq module stem in manifest order. A duplicate
module stem, an invalid Coq identifier, a local import that is not compiled
earlier, or an import outside the local modules and declared stdlib allowlist
is a fail-closed `checker_failed`.

Example compile invocation:

```text
coqc -q -Q <private-session> "" model.v
coqc -q -Q <private-session> "" approved.v
```

After compilation, each declared theorem is checked independently:

```coq
Require Import <module>.
Print Assumptions <theorem>.
```

Only the exact output `Closed under the global context` is mapped to
`proved`. Every other output, including `Axioms:` listings produced by
`Admitted` or an `Axiom` dependency, is retained as `admitted`. There is no
optimistic fallback.

A completed run is bound to `CheckerContext::Recorded` and reports
`live_checker_invoked: true`. The manifest's recorded admission statuses are
still untrusted: `verify_checker_run` requires the checker's theorem-status
map and proof-digest map to match the manifest and the declared closure.
A missing executable or unparseable version probe reports
`checker_unavailable` (exit 6). A checker that runs but fails, times out,
exceeds the capture bound, or disagrees with the manifest reports
`checker_failed` (exit 4). Admission and correspondence rejections keep their
more specific outcomes.

## Theorem and proved scope

The checked-in corpus is under `tests/proof/coq/`:

| File | Role |
|---|---|
| `model.v` | finite two-claim support lattice and the checked step-idempotence lemma |
| `approved.v` | requested theorem with a complete proof |
| `admitted.v` | the same statement closed with `Admitted` |
| `axiom.v` | the theorem proved from a declared `Axiom` |
| `unrelated.v` | a genuine arithmetic theorem outside the declared scope |
| `src/lib.rs` | digest-bound Rust/FFI binding source |
| `correspondence/*.txt` | digest-bound correspondence evidence |
| `manifest-*.json` | canonical manifests for the six seal cases |

The model is a four-state lattice. A `SupportState` records whether the first
claim is reachable and whether the second is derived. `support_step` is the
least-fixed-point iteration operator:

```coq
Record SupportState := { reachable : bool; derived : bool }.

Definition support_step (s : SupportState) : SupportState :=
  {| reachable := orb s.(reachable) s.(derived);
     derived := s.(derived) |}.

Lemma support_step_idempotent :
  forall s : SupportState, support_step (support_step s) = support_step s.

Theorem frf_support_fixed_point :
  forall s : SupportState,
    support_iterate 1 (support_iterate 1 s) = support_iterate 1 s.
```

The proved scope is exactly: **on the finite two-claim support lattice, one
iteration of the least-fixed-point step already reaches a fixed point.** The
manifest explicitly withholds universal Rust soundness, native execution of the
foreign implementation, and completeness of the declared dependency graph.
Nothing here proves the crate, the FFI implementation, or any Rust program.

## Closure and admission behavior

* `closure.theorems` must equal the set reachable from `theorem.name` along
  `closure.local_dependencies`.
* Only proof files whose declared theorems intersect that reachable closure are
  scanned for `Admitted`, `admit`, `sorry`, `Axiom`, `axiom`, `Parameter`, and
  `Conjecture`.
* `admission.theorems` must cover the closure exactly. Missing entries are
  `checker_failed`; extra entries are `rejected_unrelated`.
* The live adapter independently derives statuses with `Print Assumptions`.
  The manifest's recorded classification is retained only as an untrusted
  producer claim.
* A declared `Axiom` in a reachable file and a live `Print Assumptions` result
  that is not closed are both retained as rejection, not acceptance.
* An unproved theorem in an unrelated support file is not attributed to the
  requested theorem.

## Implementation-correspondence gate

The correspondence gate remains separate from proof acceptance. It always
runs, even when admission is rejected, and it does not inherit theorem
acceptance. It verifies:

* the exact correspondence statement;
* every symbol, source path, and source digest, via a Phase 3.1 inventory or
  explicit digest-bound binding evidence;
* a checked wrapper for every FFI declaration; and
* every declared transition plus the mandatory `reentrant_callback`.

The gate is digest-bound review evidence, not a semantic refinement proof. A
passing correspondence report does not prove that the Rust wrapper implements
the Coq model. Accepted theorem plus rejected correspondence still yields a
rejected Phase 6 outcome.

## Live seal results

`./ci/proof-gate.sh` reports each case PASS/FAIL and then runs
`FRF_PROOF_GATE=1 cargo test --locked --test proof_live`.

| Seal case | Theorem status | Admission | Correspondence | Overall outcome | Exit |
|---|---|---|---|---:|---:|
| approved independent theorem | 2 proved | `accepted_within_scope` | pass | `accepted_within_scope` | 0 |
| dependent `Admitted` | 1 proved, 1 admitted | `rejected_assumption` | pass | `rejected_assumption` | 4 |
| dependent `Axiom` | 1 proved, 1 admitted | `rejected_assumption` | pass | `rejected_assumption` | 4 |
| unrelated admission | 3 proved, extra theorem outside closure | `rejected_unrelated` | pass | `rejected_unrelated` | 4 |
| unchecked FFI wrapper | 2 proved | `accepted_within_scope` | fail | `rejected_unchecked_implementation` | 4 |
| missing reentrant transition | 2 proved | `accepted_within_scope` | fail | `rejected_missing_transition` | 4 |

Observed gate output:

```text
PASS approved (outcome=accepted_within_scope exit=0)
PASS admitted (outcome=rejected_assumption exit=4)
PASS axiom (outcome=rejected_assumption exit=4)
PASS unrelated (outcome=rejected_unrelated exit=4)
PASS unchecked (outcome=rejected_unchecked_implementation exit=4)
PASS missing_transition (outcome=rejected_missing_transition exit=4)
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
proof-gate: complete
```

The default gate (`./ci/gate.sh`) installs no Coq. All six `tests/proof_live.rs`
tests execute, none is ignored, and each asserts the adapter's typed
`LiveCheckerOutcome::Unavailable`. The approved manifest's
`proof verify --live` also returns `checker_unavailable` (exit 6).

## CLI and capabilities

```text
proof verify MANIFEST [--live] [--json]
```

`capabilities --json` now includes a `checkers[]` array with a bounded runtime
probe:

```json
{"id":"coq","kind":"coq","status":"available","executable":"coqc",
 "version":"8.16.1","detail":"coqc 8.16.1 at /usr/bin/coqc"}
```

When `coqc` is absent the same entry is `not_run` with the exact reason. This is
an installation observation, not a proof or sensitivity claim.

## Test counts

* `tests/proof.rs`: 22 manifest/closure/admission/correspondence tests.
* `tests/proof_live.rs`: 6 live/unavailable seal tests.
* Default gate: 290 tests passed in both debug and release (284 before Phase
  6.2; the six new tests execute the unavailable path).
* Proof gate: 6/6 live seal cases and 6/6 live tests pass with Coq 8.16.1.

## Claim ceiling

The live adapter establishes only that:

* the exact pinned checker executable ran with the recorded argv in this
  environment;
* the digest-bound proof bytes compiled;
* `Print Assumptions` reported the exact requested theorem names and the
  adapter mapped only the closed result to `proved`; and
* the recorded proof digests and theorem statuses match the manifest and its
  declared closure.

It does not establish:

* that the theorem is true outside the declared finite lattice;
* that the manifest's declared dependency graph is complete;
* that the implementation-correspondence evidence is semantically sound;
* that the FFI wrapper refines the Coq model;
* that the checker, executable, or environment is authentic beyond digests
  and process evidence;
* any universal Rust soundness, `SOUND_SAFE_INTERIOR`, or `SAFE_COMPATIBLE`
  claim; or
* anything about Lean, Isabelle, or a different Coq version.

Digests bind bytes, not origin or truth. There is no signature, transparency
log, or trusted build root.

## Citations

1. The Coq Development Team. *The Coq Reference Manual*: `Print Assumptions`,
   `Admitted`, `admit`, `Axiom`, `Parameter`, and `Conjecture`.
   <https://coq.inria.fr/refman/>
2. The Coq Development Team. *The Coq Reference Manual*: load paths and
   `-Q` / `-R` module resolution.
   <https://coq.inria.fr/refman/practical-tools/coq-commands.html>
3. Debian Project. *Debian bookworm package `coq` 8.16.1+dfsg-1+b2*.
   <https://packages.debian.org/bookworm/coq>
4. The Rust Project. *The Rust Reference: External blocks* and *The Rust
   Nomicon: FFI*.
   <https://doc.rust-lang.org/reference/items/external-blocks.html>,
   <https://doc.rust-lang.org/nomicon/ffi.html>
5. R. Jung, J.-H. Jourdan, R. Krebbers, and D. Dreyer. *RustBelt: Securing the
   Foundations of the Rust Programming Language.* POPL 2018.
   <https://plv.mpi-sws.org/rustbelt/popl18/>
6. X. Leroy. *Formal Verification of a Realistic Compiler.* Communications of
   the ACM 52(7), 2009.
   <https://doi.org/10.1145/1538788.1538814>
7. Open Source Security Foundation. *SLSA Specification v1.0: Provenance*.
   <https://slsa.dev/spec/v1.0/provenance>
8. J. Rushby. *Formal Methods and the Certification of Critical Systems.*
   Technical report, SRI International, 1993.
   <https://www.csl.sri.com/papers/csl-93-7/>
