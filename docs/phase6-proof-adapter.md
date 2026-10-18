# Phase 6: proof manifest, closure, admission, correspondence, and live checker

Snapshot: branch `staging`, crate `frf-memorysafety 0.7.0`.

Phase 6.1 implemented the **manifest and classification half** of the Phase 6
checked-proof adapter. Phase 6.2 completes the live half with a pinned Debian
Coq 8.16.1 checker, checked-in Coq fixtures, and `proof verify --live`. See
[`phase6-live-checker.md`](phase6-live-checker.md) for the install, theorem,
seal results, and claim ceiling.

The manifest implementation is in `src/proof.rs`. Tests are in
`tests/proof.rs` (manifest) and `tests/proof_live.rs` (live/unavailable). The
CLI is `proof verify MANIFEST [--live] [--json]`.

## Scope and claim ceiling

A manifest that passes these checks establishes only that:

* the JSON is strict canonical input with no duplicate or unknown fields;
* every listed proof file and implementation-evidence file exists and matches
  its declared SHA-256;
* the declared dependency edges reach exactly the declared theorem closure;
* no lexical `Admitted`, `admit`, `sorry`, `Axiom`, `Conjecture`, or
  `Parameter` construct appears in the proof files that the declared closure
  actually reaches;
* every declared assumption is either a theorem-local hypothesis discharged by
  a declared binder or is rejected;
* the separate Rust/FFI binding names source symbols, source digests, a checked
  FFI wrapper, and an enumerated reentrant-callback transition; and
* the recorded admission statuses and checker identity are internally
  consistent with the manifest.

Manifest-only verification (the default, without `--live`) does **not**
establish that:

* a proof assistant was installed, executed, or exited successfully;
* the proof files compile or the theorem is true;
* the declared dependency graph is complete or was discovered by a checker;
* the lexical scan is a semantic parser for Coq, Lean, or Isabelle;
* the implementation-correspondence evidence is semantically sound;
* the source inventory is complete or the FFI contract matches a real C
  library; or
* any universal Rust soundness, `SOUND_SAFE_INTERIOR`, or `SAFE_COMPATIBLE`
  claim.

A `--live` run does establish that the declared proof bytes compiled and that
the exact theorem names were reported by `Print Assumptions`; any status other
than `Closed under the global context` is retained as unproved. It still does
not establish theorem truth outside the declared finite scope, dependency-graph
completeness, or semantic correspondence.

`proof verify` therefore returns `checker_unavailable` and exit status 6 when
no live checker is configured, even for a well-formed manifest. `proof verify
--live` invokes the pinned Coq adapter and binds only a completed authentic run
to `CheckerContext::Recorded`; the manifest parser alone never promotes a
recorded field into acceptance.

## Canonical manifest schema

Schema identifier: `frf-memorysafety.proof-manifest.v1`.

The document is `ms-canonical-json-v1` (`SPEC.md` §3): UTF-8, sorted keys, no
insignificant whitespace, no duplicate keys, no floats, no unknown fields. The
typed schema uses `deny_unknown_fields` at every level.

```json
{
  "admission": {
    "checker_kind": "coq",
    "checker_version": "8.19.2",
    "classification": "accepted_within_scope",
    "exit_code": 0,
    "origin": "authentic_checker_run",
    "proof_digests": [
      {"file_id": "helper", "sha256": "<64 hex>"},
      {"file_id": "main", "sha256": "<64 hex>"}
    ],
    "theorems": [
      {"name": "frf_helper", "status": "proved"},
      {"name": "frf_safe_wrapper", "status": "proved"}
    ]
  },
  "assumptions": [
    {
      "discharged_by": "frf_safe_wrapper",
      "id": "h-bound",
      "justification": "bound by the theorem's universally quantified parameter",
      "kind": "hypothesis",
      "name": "bounded_input",
      "scope": "frf_safe_wrapper"
    }
  ],
  "checker": {
    "executable": "coqc",
    "kind": "coq",
    "version": "8.19.2"
  },
  "claim_ceiling": "Manifest validation is not proof checking. ...",
  "closure": {
    "local_dependencies": [
      {"depends_on": ["frf_helper"], "theorem": "frf_safe_wrapper"}
    ],
    "stdlib_allowlist": ["Coq.Init.*"],
    "theorems": ["frf_helper", "frf_safe_wrapper"]
  },
  "implementation_binding": {
    "binding_evidence": [
      {
        "detail": "exact FFI declaration and wrapper call site",
        "path": "src/lib.rs",
        "sha256": "<64 hex>",
        "symbol": "frf_foreign_create"
      }
    ],
    "correspondence_evidence": [
      {
        "detail": "checked wrapper",
        "id": "ev-wrapper",
        "kind": "refinement",
        "path": "correspondence/ev-wrapper.txt",
        "sha256": "<64 hex>"
      }
    ],
    "required_transitions": ["lifecycle", "transfer", "free", "reentrant_callback"],
    "rust_symbols": [
      {
        "ffi": {
          "declaration": "extern \"C\" { pub fn frf_foreign_create(value: c_int) -> *mut c_int; }",
          "wrapper_checked": true,
          "wrapper_evidence": "ev-wrapper",
          "wrapper_symbol": "frf_safe_create"
        },
        "kind": "ffi_declaration",
        "source_path": "src/lib.rs",
        "source_sha256": "<64 hex>",
        "symbol": "frf_foreign_create"
      }
    ],
    "source_inventory": null,
    "statement": "frf_safe_create refines frf_safe_wrapper for every enumerated transition",
    "transitions": [
      {
        "description": "reentrant callback may mutate live state",
        "evidence": "ev-callback",
        "id": "t-callback",
        "kind": "reentrant_callback"
      }
    ]
  },
  "proof_files": [
    {
      "id": "main",
      "imports": ["helper", "Coq.Init.Nat"],
      "language": "coq",
      "path": "proofs/main.v",
      "role": "theorem",
      "sha256": "<64 hex>",
      "theorems": ["frf_safe_wrapper"]
    }
  ],
  "provenance": {
    "detail": "recorded by the Phase 6.2 adapter",
    "origin": "authentic_checker_run",
    "run_id": "run-1"
  },
  "schema": "frf-memorysafety.proof-manifest.v1",
  "scope": {
    "claim_ids": ["claim-safe-wrapper"],
    "finite_domain": "the declared finite FFI wrapper state machine",
    "not_proved": ["universal Rust soundness"],
    "proved": "the wrapper preserves the finite-domain memory-safety predicate"
  },
  "spec": "frf-memorysafety-spec-v1",
  "theorem": {
    "claim_ids": ["claim-safe-wrapper"],
    "name": "frf_safe_wrapper"
  }
}
```

Fields:

| Field | Meaning |
|---|---|
| `checker` | Family, exact pinned version, and exact executable. Ranges and wildcards are rejected. |
| `proof_files` | Stable id, relative path, SHA-256, language, role, declared theorems, and declared imports. |
| `theorem` | Exact requested theorem and the claim ids it is offered for. |
| `scope` | Claim ids admitted by the scope, finite domain, what is proved, and what is explicitly not proved. |
| `closure` | Every theorem in the declared closure, local dependency edges, and stdlib import allowlist. |
| `assumptions` | Named and justified hypotheses, axioms, parameters, or conjectures. |
| `admission` | Recorded checker kind/version/exit, proof digests, theorem statuses, and classification. |
| `implementation_binding` | Exact correspondence statement, symbols, source digests, transitions, and separate evidence. |
| `provenance` | `authentic_checker_run` or `substitute_modeled`, plus run id and detail. |

Paths must be relative, must not contain `.` or `..` components, and must not
be absolute. Every bound file is capped at 4 MiB.

## Closure rules

1. `checker.version` must be an exact pinned version. `*`, `^`, `~`, `>`, and
   `<` are rejected.
2. Proof file ids, paths, theorem declarations, and assumptions must be unique.
3. `closure.theorems` must be exactly the set reachable from `theorem.name`
   along `closure.local_dependencies`. Extra or missing closure entries are
   `rejected_unrelated`.
4. Every theorem in `closure.theorems` must be declared in exactly one proof
   file. A theorem outside the declared closure is not attributed to the
   requested theorem.
5. Every import must name a closure proof-file id, a closure theorem, or a
   prefix in `stdlib_allowlist`. A `*` suffix is the only wildcard.
6. `theorem.claim_ids` must be a non-empty subset of `scope.claim_ids`.
   Otherwise the result is `rejected_unrelated`.
7. Every proof file with a theorem in the reachable closure is scanned
   lexically. The scanner matches the exact tokens `Admitted`, `admit`,
   `sorry`, `Axiom`, `axiom`, `Parameter`, and `Conjecture` at identifier
   boundaries. Any hit is `rejected_assumption`.
8. A proof file outside the reachable closure is still digest-checked but is
   **not** scanned for admissions. An unrelated `sorry` is therefore not
   attributed to the requested theorem. The declared dependency graph is the
   boundary; this build does not discover checker dependencies.
9. A `hypothesis` is allowed only when it names a theorem in the closure in
   `discharged_by` and carries a non-empty justification and scope. Declared
   `axiom`, `parameter`, and `conjecture` assumptions are always
   `rejected_assumption`, even when they also appear in the manifest.
10. The admission theorem set must equal the reachable closure set. Missing
    closure entries are `checker_failed`; extra or unrelated entries are
    `rejected_unrelated`.

The lexical scan is a conservative *name-and-digest* control, not a
language-specific parser. A comment containing `sorry` inside a scanned file
will be refused; that is intentional fail-closed behavior. A semantic parser
or checker-reported dependency graph is Phase 6.2 work.

## Admission taxonomy

The verifier recomputes the admission outcome. `admission.classification` is
retained as an untrusted producer claim; it never causes acceptance.

| Outcome | Meaning | Exit |
|---|---|---:|
| `accepted_within_scope` | The recorded theorem and every reachable dependency are reported proved, no forbidden admission or undischarged assumption was found, and the implementation-correspondence gate also passes. A live adapter must still supply a matching checker run. | 0 |
| `rejected_assumption` | `Admitted`, `admit`, `sorry`, `Axiom`, `Parameter`, or `Conjecture` occurs in the reachable closure, or a declared axiom/parameter/conjecture is present, or a hypothesis is not discharged. | 4 |
| `rejected_unrelated` | The admission or theorem is outside the declared closure or scope, the closure is not exactly reachable, or an import is not allowed. | 4 |
| `rejected_unchecked_implementation` | The separate correspondence gate rejects an unbound symbol or an unchecked FFI wrapper, independently of theorem acceptance. | 4 |
| `rejected_missing_transition` | The implementation binding omits a required transition, including the mandatory `reentrant_callback`. | 4 |
| `checker_unavailable` | No live checker is configured, or the recorded provenance is `substitute_modeled`. Parsing success is not acceptance. | 6 |
| `checker_failed` | A recorded checker status is `unchecked`/`failed`, the exit code is nonzero, the closure lacks an admission status, or a supplied checker run does not match the manifest. | 4 |

Structural failures are separate integrity errors (exit 3): malformed or
non-canonical JSON, duplicate or unknown fields, missing proof/evidence files,
digest mismatch, path escape, missing digest fields, or checker kind/version/
digest mismatch. Usage errors are exit 2; internal encoding failures are 7.

## Separate implementation-correspondence gate

The correspondence gate always runs, even when proof admission was rejected,
and its result is reported separately. It does not inherit theorem acceptance.

1. The exact `statement` must be non-empty and is retained verbatim in the
   report.
2. Every symbol binding names a `symbol`, `kind`, relative `source_path`, and
   exact `source_sha256`. The source file is read and hashed.
3. If `source_inventory` is present, the Phase 3.1 inventory file must exist,
   match its digest, have schema `frf-memorysafety.source-inventory.v1`, and
   contain the bound source path with the same digest. An
   `ffi_declaration` binding must also have a matching `FfiDeclaration`,
   `ExternBlock`, `ExternFn`, `NoMangle`, or `ExportName` finding.
4. If `source_inventory` is absent, each symbol needs an explicit
   `binding_evidence` entry with the same symbol, path, and digest. The
   evidence file is read and must contain the symbol at an identifier boundary.
5. Every `ffi_declaration` must carry `ffi.wrapper_checked: true` and a
   `wrapper_evidence` id. The wrapper symbol must occur in the source or in
   the wrapper evidence. A false flag or unbound wrapper is
   `rejected_unchecked_implementation` even if the theorem is accepted.
6. `required_transitions` is augmented with the mandatory
   `reentrant_callback`. Every required transition must appear in `transitions`
   with a description and an existing correspondence-evidence id. A missing
   transition is `rejected_missing_transition`.
7. All correspondence-evidence files are digest-bound. Evidence is never
   treated as part of theorem admission and never strengthens the theorem
   beyond its declared finite scope.

`correspondence_evidence` is separate from `proof_files`. A manifest cannot
reuse a proof digest as a substitute for the implementation statement, source
symbol binding, or transition enumeration.

## CLI

```text
proof verify MANIFEST [--live] [--json]
```

The command parses and verifies the manifest, closure, admission record, and
correspondence gate, then emits a canonical
`frf-memorysafety.proof-verification-report.v1` report (with `--json`) or a
human summary. Without `--live` it never invokes a checker. For a well-formed manifest the
outcome is `checker_unavailable` and the exit status is 6, because no live
checker is configured. With `--live`, the adapter compiles the digest-bound
proof files in declared order in a private `0700` directory and derives
theorem statuses from `Print Assumptions`. A missing checker still returns
`checker_unavailable` (6); a checker that runs but fails, times out, exceeds
the output bound, or disagrees with the manifest returns `checker_failed` (4).
A rejected assumption, unrelated theorem, unchecked wrapper, or missing
transition returns 4. Integrity failures return 3. Usage errors return 2.

The report always includes:

* the exact manifest SHA-256, checker identity, theorem, and scope;
* the recomputed outcome and the producer-recorded classification;
* every scanned proof file and forbidden finding;
* every assumption and its status;
* every symbol, transition, missing transition, unchecked wrapper, and
  correspondence-evidence digest;
* `live_checker_configured`, `live_checker_invoked`, the acceptance basis,
  and (with `--live`) the bounded captured `live_run` receipt; and
* `universal_soundness: WITHHELD_NOT_RUN` and the claim ceiling.

## Provenance and non-fabrication

The manifest distinguishes `authentic_checker_run` from
`substitute_modeled`. A substituted or modeled result is never accepted, even
if every field parses. The CLI constructs `CheckerContext::NotConfigured`, so
it cannot promote a recorded field into acceptance. The library exposes
`CheckerContext::Recorded` only for an adapter that has independently supplied
a matching checker kind, exact version, exit code, proof digest map, and
theorem-status map. Even then, `live_checker_invoked` remains `false` in this
build: the recorded run was supplied, not executed by this crate.

There is no signature, transparency log, trusted build root, or independent
re-execution. Digests bind bytes, not origin or truth.

## Tests

`tests/proof.rs` contains 22 executing tests; none is ignored. They cover:

* approved manifest shape, canonical report, and determinism;
* `Admitted`, `sorry`, lexical `Axiom`, and declared-axiom rejection;
* an unrelated admission, a theorem outside scope, and an admission in an
  unscanned support file that must not be attributed to the theorem;
* missing proof files, digest tampering, and a missing digest field;
* checker version and digest mismatch, and a recorded run that does not match;
* duplicate and unknown top-level/nested fields, duplicate ids, and path
  escape;
* unchecked FFI wrappers rejected while the theorem is still reported proved;
* a missing reentrant-callback transition;
* an independent correspondence gate when admission is rejected;
* Phase 3.1 source-inventory binding and explicit-evidence fallback;
* imports outside the closure and stdlib allowlist; and
* CLI statuses 6, 4, 3, and 2.

## Phase 6.2 completion

Phase 6.2 installs Debian Coq 8.16.1 in `ci/proof-gate.sh`, invokes it with
an explicit argv, a private `0700` session, a cleared environment, a 120-second
per-process bound, a 1 MiB capture bound, and a recorded exact version and
executable digest. It compiles the checked-in corpus in manifest order,
resolves local modules, derives each theorem status from `Print Assumptions`,
and node-locks checker kind, version, and executable to the manifest. Only a
completed run is bound to `CheckerContext::Recorded`; a missing checker keeps
`proof verify --live` fail-closed at exit 6.

The live seal passes all six cases (approved, admitted, axiom, unrelated,
unchecked wrapper, missing reentrant transition). Exact results and claim
limits are in [`phase6-live-checker.md`](phase6-live-checker.md).

## Citations

1. The Coq Development Team. *The Coq Reference Manual*: `Admitted`, `admit`,
   `Axiom`, `Parameter`, `Conjecture`, and the distinction between a closed
   proof and a declared assumption.
   <https://coq.inria.fr/refman/>
2. The Lean Project. *Theorem Proving in Lean 4* and *Lean 4 Reference
   Manual*: `sorry`, `axiom`, and the meaning of an incomplete proof.
   <https://lean-lang.org/theorem_proving_in_lean4/>,
   <https://lean-lang.org/lean4/doc/>
3. T. Nipkow, L. C. Paulson, and M. Wenzel. *Isabelle/HOL: A Proof Assistant
   for Higher-Order Logic*, and the *Isabelle/Isar Reference Manual*:
   `sorry` and `oops` as unfinished-proof markers.
   <https://isabelle.in.tum.de/doc/isar-ref.pdf>
4. The Rust Project. *The Rust Reference: External blocks* and *The Rust
   Nomicon: FFI*: `extern` declarations, ABI, and the unsafe boundary.
   <https://doc.rust-lang.org/reference/items/external-blocks.html>,
   <https://doc.rust-lang.org/nomicon/ffi.html>
5. R. Jung, J.-H. Jourdan, R. Krebbers, and D. Dreyer. *RustBelt: Securing
   the Foundations of the Rust Programming Language.* POPL 2018. The proof
   obligation for a safe abstraction over unsafe code.
   <https://plv.mpi-sws.org/rustbelt/popl18/>
6. X. Leroy. *Formal Verification of a Realistic Compiler.* Communications of
   the ACM 52(7), 2009. Compiler correctness as a refinement relation rather
   than a property of the source alone.
   <https://doi.org/10.1145/1538788.1538814>
7. Open Source Security Foundation. *SLSA Specification v1.0: Provenance*:
   provenance attestations describe how an artifact was produced but do not by
   themselves establish truth or safety.
   <https://slsa.dev/spec/v1.0/provenance>
8. J. Rushby. *Formal Methods and the Certification of Critical Systems.*
   Technical report, SRI International, 1993. The distinction between a
   checked formal artifact and the validity of its assumptions, model, and
   implementation correspondence.
   <https://www.csl.sri.com/papers/csl-93-7/>
