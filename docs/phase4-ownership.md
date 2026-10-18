# Phase 4.1: responsibility tokens, races, and transcript verification

Snapshot: branch `staging`, crate `frf-memorysafety 0.4.0` (no version bump).
This document describes the Phase 4.1 semantic core and transcript verifier.
Phase 4.2 adds a restricted, test-only native harness over a closed registry of
checked-in fixtures; see [`phase4-native.md`](phase4-native.md). The verifier
below still consumes a finite caller-supplied transcript and remains
independent of native execution.

## Claim ceiling

The verifier consumes a **caller-supplied finite transcript**. It does not
execute a C or Rust program, spawn or authenticate a recorder, observe a real
callback, control a scheduler, or replay an executable. A
`verified_compatible_within_transcript` result establishes only that the
declared events are internally consistent under this module's rules.

It does **not** establish:

* that the events occurred in a real process;
* that the executable or fixture digest names the process that produced them;
* Rust borrow validity under Stacked Borrows, Tree Borrows, or any other
  operational model;
* C object lifetime, storage duration, effective type, alignment, or
  representation legality;
* native replay determinism or the absence of unrecorded events;
* memory safety, universal Rust soundness, or `SAFE_COMPATIBLE`.

Authentic-native provenance is a **declaration**, not an authentication. Only
`authentic_native` transcripts can reach a clean verdict; `substitute` and
`modeled` transcripts are `unresolved` even when their events are internally
consistent.

## Schema

`native-event-transcript.v1` is strict JSON in the crate's
`ms-canonical-json-v1` encoding profile. Unknown fields, duplicate keys,
floating-point numbers, trailing bytes, and oversized values are rejected.
Required provenance fields are:

| Field | Meaning |
|---|---|
| `origin` | `authentic_native`, `substitute`, or `modeled` |
| `tool`, `tool_version` | Producer identity and exact version |
| `library_versions` | Tool/library versions that affect interpretation |
| `executable_digest` | 64 lowercase hex characters (SHA-256) |
| `fixture_digest` | 64 lowercase hex characters (SHA-256) |
| `case_legality` | `test_only`, `production`, or `illegal` |
| `scope` | Declared case scope |
| `claimed_complete` | Producer's completeness claim |

The verifier never treats a digest as an origin proof. It surfaces the
declared origin and rejects a clean verdict for non-authentic origins.

## Token algebra

A responsibility token is:

```text
token = (object, owner, generation, status, poisoned)
```

This is a concrete encoding of the paper's responsibility tuple
`(r, k, o, h, e)`: resource/object, responsibility kind, required disposition,
current holder, and lifecycle epoch. The transcript's event kind supplies the
responsibility kind and disposition. The lifecycle epoch is the generation
counter.

Token statuses:

```text
Owner
SharedBorrow
MutableBorrow
Escaped
Transferred
Ended
Stale
```

`poisoned` is an orthogonal flag so a failed callback can mark a live owning
token without erasing its ownership. A poisoned token may still be freed as
cleanup, but it cannot be used, transferred, reallocated, or borrowed.

## Transition legality

| Event | Required token | Legal precondition | Effect |
|---|---|---|---|
| `create` | new `token` | object not live; generation is `0` for a first create or advances after free | issue `Owner` token; storage is uninitialized |
| `allocation_failure` | none | object not live | record a failed attempt; no token |
| `partial_init` | owning `token` | live, active, matching generation, not complete | initialization state becomes partial |
| `init_complete` | owning `token` | live, active, matching generation, not already complete | initialization state becomes complete |
| `borrow_shared` | source `from_token`, new `token` | source live and usable | push a `SharedBorrow` token |
| `borrow_mutable` | source `from_token`, new `token` | source live, usable, owning or mutable | push an exclusive `MutableBorrow` token |
| `reborrow` | source borrow, new `token`, `borrow` | source is an existing borrow and usable; mutable source for a mutable reborrow | push a derived borrow token |
| `borrow_end` | borrow `token` | token is the most recent live borrow | pop it and mark it `Ended` |
| `transfer` | source `from_token`, new `to_token` | source is the active owning token | retire sender token; issue receiver `Owner` token |
| `transfer_failure` | source `from_token` | source is the active owning token | preserve the sender and issue nothing |
| `escape` | `token` | live token and non-empty provider | mark `Escaped`; provider becomes continuing custodian |
| `reallocate` | source `from_token`, new `token` | source is the active owning token; no live borrow; generation advances | mark old-generation tokens `Stale`; issue a new owning token; storage is uninitialized |
| `free` | owning `token` | active owning token, matching generation, no live borrow | mark same-generation tokens `Stale`; object becomes freed |
| `use` | `token` | live, matching generation, unpoisoned, fully initialized, currently usable | record read/write/atomic access |
| `callback_enter` | optional `token` | callback name non-empty | push a per-thread callback frame |
| `callback_exit` | optional `token` | top callback matches; outcome present | pop the frame; `failed` poisons a bound token |
| `poison` | `token` | token exists | set the poisoned flag |
| `abort` | optional `token` | none | mark the lifecycle aborted |

Multiple shared borrows may coexist. A use through any live shared borrow is
allowed while no mutable borrow is above it in the borrow stack. A use through
an owning token is allowed only while the borrow stack is empty. A mutable
borrow suspends every ancestor. Non-atomic writes through a shared borrow are
rejected.

## Failure semantics

* **Allocation failure** records an attempt and creates no object. Use of that
  object is `use_of_unallocated`; a session ending after a handled failure is
  complete.
* **Partial initialization** permits cleanup (`free`) but rejects a type-level
  use before `init_complete`. A session that ends partially initialized without
  freeing is incomplete.
* **Callback failure** (`callback_exit` with `outcome: failed`) poisons the
  bound token. Later use is `use_of_poisoned_token`; `free` remains legal.
* **Failed transfer** preserves the sender's responsibility. The sender may
  continue to use the object.
* **Poisoned lifecycle** that remains allocated at the end is incomplete.
* **Aborted lifecycle** is incomplete and any later event is a violation.

## Generation semantics

`create` starts a first lifetime at generation `0`. `reallocate` must advance
the generation by exactly one; a jump is reported as a skipped generation
transition. A create after `free` must advance beyond the previous generation.
`reallocate` and `free` mark every token of the affected generation `Stale`.
A later use of a stale token is `stale_generation` when the object generation
advanced, and `stale_token` after free. Address reuse is never inferred to be
the same allocation.

## Concurrency model

Each thread's events are ordered by a strictly increasing per-thread `seq`.
`synchronizes_with` edges are explicit event references. The verifier builds a
directed acyclic graph from program order plus these edges, rejects a cycle as
`illegal_case`, and computes vector clocks in a deterministic topological
order.

`e1` happens-before `e2` exactly when the vector clock of `e1` is componentwise
less than or equal to that of `e2` and strictly smaller in at least one
component. The race rule is:

```text
same object
and different threads
and neither event happens-before the other
and at least one event is a write
and not both events are atomic
=> data race
```

`use` events carry `read`, `write`, `atomic_read`, `atomic_write`, or
`atomic_read_write`. Lifecycle transitions (`create`, borrow changes,
transfer, reallocate, free, initialization, poison, and allocation failure)
are modeled as non-atomic metadata writes. Atomic-atomic conflicting access is
permitted by this model; atomic-versus-non-atomic conflict is a race.
`use` of an atomic access on an object not declared `atomic` is a violation.

This is a finite event-log model, not ThreadSanitizer, Loom, or a C11
operational semantics. Atomic ordering, fences, and memory orders beyond the
declared synchronizes-with edges are not inferred.

## Completeness criterion

A transcript is complete only when:

1. every declared object has a `create` or a handled allocation failure;
2. every created object is freed or escapes to continuing custody;
3. every borrow token has a `borrow_end`;
4. every reallocation advances the generation and every post-free create
   advances it;
5. every callback `enter` has a matching `exit`;
6. every explicitly required create, free, borrow end, generation transition,
   and callback is present;
7. `recording.expected_event_count`, when declared, matches the actual count;
8. no unknown provider edge remains while `claimed_complete` is true; and
9. the lifecycle is not aborted.

A missing event is `incomplete_transcript`, not a clean or violating verdict.
A definite contradiction (for example use-after-free or a data race) is
reported as `observed_violation` even if the transcript is also incomplete.

The **seeded skipped-event detector** is the combination of the explicit
`requirements` block and the lifecycle audit above. A producer cannot obtain
`verified_compatible_within_transcript` by deleting a create, free,
borrow-end, generation bump, callback, or event-count entry. If a transcript
claims completeness while any of these gaps or an unknown provider edge
remains, the verifier adds `fictitious_completeness` and returns
`incomplete_transcript`.

## Outcomes and exit statuses

| Outcome | Meaning | Exit |
|---|---|---:|
| `verified_compatible_within_transcript` | Complete, legal, internally consistent, authentic-native declaration | 0 |
| `observed_violation` | Definite lifecycle or concurrency contradiction | 4 |
| `incomplete_transcript` | Required event or completion fact absent; or fictitious completeness | 5 |
| `unresolved` | Non-authentic origin or unknown provider edge without a completeness claim | 4 |
| `illegal_case` | `case_legality: illegal` or cyclic synchronizes-with graph | 4 |

Malformed input, duplicate keys, unknown fields, invalid digests, or structural
inconsistency is an evidence-integrity failure (exit 3). Usage errors are exit
2; internal encoding failures are exit 7. `court run` over caller-supplied
programs remains `NOT_RUN` (exit 6); native recording is restricted to the
checked-in Phase 4.2 test fixtures.

## CLI

```text
court verify FILE [--json]
```

The command emits the canonical `frf-memorysafety.court-verification.v1`
report. `--json` is accepted; both spellings emit the same canonical machine
form.

## Seal controls exercised by the tests

* Positive ownership transfer, shared/mutable borrow, reborrow, generation
  bump, failed transfer, escape, and callback sequences.
* Negative use-after-transfer, use-after-free, mutable-alias, stale generation,
  use-before-initialization, use-after-escape, poisoned-token, allocation-failure
  use, and double-free controls.
* Data race, atomic-atomic compatibility, and atomic-versus-non-atomic race
  controls.
* Seeded missing create, free, borrow-end, generation transition, expected
  event count, required callback, and unknown-provider controls.
* Malformed, duplicate-key, unknown-field, and missing-required-field
  transcripts.
* Deterministic canonical report bytes and CLI exit statuses 0/2/3/4/5/6.

## Phase 4.2 status

Phase 4.2 now provides a test-only harness (`src/native.rs`) that compiles and
executes a closed registry of checked-in C and Rust fixtures under the hardened
container, records authentic native events, captures compiler/linker versions,
executable and fixture digests, case id, legality, and scope, and requires two
byte-identical canonical transcripts. Paired positive/negative cases, a seeded
skipped-event case, a fictitious-completeness case, a replay-mismatch control,
and an oversized-output control are exercised by `tests/native.rs` and
`ci/native-gate.sh`. Native execution remains separate from this finite
verifier, the verdict remains transcript-scoped, and arbitrary native input is
still `NOT_RUN`. See [`phase4-native.md`](phase4-native.md) for isolation,
provenance fields, the replay rule, exact commands, claim ceiling, and
citations.

## Citations

1. R. Jung, J.-H. Jourdan, R. Krebbers, and D. Dreyer. *RustBelt: Securing the
   Foundations of the Rust Programming Language.* POPL 2018.
   <https://plv.mpi-sws.org/rustbelt/popl18/>
2. R. Jung, H.-H. Dang, J. Kang, and D. Dreyer. *Stacked Borrows: An Aliasing
   Model for Rust.* POPL 2020.
   <https://plv.mpi-sws.org/rustbelt/stacked-borrows/>
3. N. Villani, J. Hostert, D. Dreyer, and R. Jung. *Tree Borrows.* PLDI 2025.
   <https://pldi25.sigplan.org/details/pldi-2025-papers/42/Tree-Borrows>
4. E. Ovadia. *Vale's Memory Safety Strategy: Generational References and
   Regions.* 2023. <https://verdagon.dev/blog/generational-references>
5. E. Ovadia. *Higher RAII, and the Seven Arcane Uses of Linear Types.* 2024.
   <https://verdagon.dev/blog/higher-raii-uses-linear-types>
6. M. M. Michael. *Hazard Pointers: Safe Memory Reclamation for Lock-Free
   Objects.* IEEE TPDS 15(6), 2004.
   <https://research.ibm.com/publications/hazard-pointers-safe-memory-reclamation-for-lock-free-objects>
7. R. O'Callahan et al. *Engineering Record and Replay for Deployability.*
   USENIX ATC 2017.
   <https://www.usenix.org/conference/atc17/technical-sessions/presentation/ocallahan>
8. Rust Project. *Standard Library Pointer Documentation* and *The Rustonomicon:
   FFI.* <https://doc.rust-lang.org/std/ptr/index.html>,
   <https://doc.rust-lang.org/nomicon/ffi.html>
9. ISO/IEC 9899:2018. *Programming Languages — C.* §6.2.4 (storage durations),
   §6.5 (expressions and effective type), §7.17 (atomics).
10. L. Lamport. *Time, Clocks, and the Ordering of Events in a Distributed
    System.* CACM 21(7), 1978.
11. H.-J. Boehm and S. V. Adve. *Foundations of the C++ Concurrency Memory
    Model.* PLDI 2008.
12. M. Leucker and C. Schallhart. *A Brief Account of Runtime Verification.*
    Journal of Logic and Algebraic Programming 78(5), 2009.
