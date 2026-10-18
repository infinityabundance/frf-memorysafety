# Phase 3.3: optional pinned MIR observations

Snapshot: branch `staging`, crate `frf-memorysafety 0.3.0` (no version bump).
This document describes the Phase 3.3 MIR adapter only. It does **not**
extract aliases, provenance, reference intervals, or native events, and it does
not establish a whole-program caller graph.

## Pinned toolchain

```text
nightly-2025-02-20
```

This date matches the release date of the stable `1.85.0` toolchain used by the
default gate. In the hardened container the channel resolves to:

```text
rustc 1.87.0-nightly (f280acf4c 2025-02-19)
```

The pin is a single documented constant, `MIR_TOOLCHAIN`, in `src/mir.rs`.
`mir scan --toolchain NAME` can override it explicitly; the artifact then
records the name that was actually requested. Overriding the pin is not a
reproducibility guarantee.

## Invocation

The adapter uses an explicit argv vector and **never a shell**:

```text
rustup run <toolchain> rustc --edition 2021 -Zunpretty=mir --crate-type=lib <absolute-input>
```

It first probes availability with:

```text
rustup run <toolchain> rustc --version
```

`--crate-type=lib` lets the adapter inspect a single file without requiring a
`main` function. The input is an explicit `.rs` file, not a Cargo workspace
discovery. Module resolution follows rustc's normal rules relative to that
file; external crates are not supplied with `--extern`.

Bounds and isolation:

| Control | Default |
|---|---:|
| wall clock per child process | 30,000 ms |
| input source bytes | 4 MiB |
| retained stdout | 16 MiB |
| retained stderr | 1 MiB |
| retained functions | 8,192 |
| retained call edges | 65,536 |
| retained dereferences or storage markers per category | 131,072 |
| retained unknowns | 8,192 |
| canonical output | 4 MiB (`ms-canonical-json-v1`) |

The child runs with null stdin, piped stdout/stderr, and a private `0700`
temporary directory as its working directory; the directory is removed on
drop. Reader threads drain both pipes while retaining at most the configured
bytes, so a child cannot block forever on a full pipe. The process is killed at
the timeout.

If stdout reaches its bound, the adapter returns `NOT_RUN` rather than parsing
an incomplete program. If the compiler rejects the input, the adapter returns
an integrity error (exit 3), not a fabricated observation.

## Availability and `NOT_RUN`

`mir scan` returns a typed `MIR_NOT_RUN_SCHEMA` artifact and exits `6` when:

* the `rustup` executable cannot be found;
* the pinned toolchain is not installed or cannot run;
* the probe or compiler invocation times out;
* retained stdout reaches its bound; or
* the adapter cannot start its configured executable.

The response records the toolchain, `rustup` program, stage
(`toolchain_probe` or `mir_invocation`), typed reason, bounded detail, limits,
and the claim ceiling. It never contains a fabricated function or edge list.

`ci/mir-gate.sh` attempts to install `nightly-2025-02-20` with
`--profile minimal` inside the same hardened container. If installation or
execution is unavailable it prints `NOT_RUN` and exits `6`. It is a separate
optional gate and is not invoked by `ci/gate.sh`.

## Parsed subset

The parser consumes the human-readable MIR text, line by line. It is
deliberately smaller than the compiler's internal MIR.

| Observation | Recognised form | Limit of the claim |
|---|---|---|
| Function definition | `fn name(args) -> T {` up to a column-zero `}` | The printed name, including closure suffixes. No type resolution. |
| Basic block | `bbN: {` | Count and identifier only. No CFG closure claim. |
| Call edge | a `-> [..]` terminator with a callee before `(` | Always `unresolved`. Same-name local definitions are recorded as a name coincidence, not resolution. |
| Callee form | plain path, qualified/trait path, or `copy _N(..)`/`move _N(..)` | Indirect operands are not identified with a target. |
| Dereference | `*_N` or `*(...)` place projections | Counts textual projections, not provenance, validity, or raw-pointer type. |
| Storage/lifetime | `let`, `debug name => place`, `scope N`, `StorageLive(_N)`, `StorageDead(_N)` | Markers only. `StorageLive`/`StorageDead` may be absent in the printed MIR. |
| Drop/free-like call | final callee segment `drop`, `drop_in_place`, `dealloc`, `__rust_dealloc`, `free`, `raw_free` | Textual call names. Drop paths, unwinding, and allocation identity are not resolved. |
| Unknown | any other non-empty statement or top-level line | Retained with line, basic block, truncated text, and reason. |

Every call edge carries `resolution: unresolved` and the uncertainty labels
`mir_pretty_text_only` and `callee_not_symbolically_resolved`. Additional
labels record indirect dispatch, qualified/trait paths, calls without a
same-name local definition (`external_foreign_or_provider_possible`), and
drop/deallocation calls. The labels preserve uncertainty; they are not
resolutions.

Common control terminators (`goto`, `switchInt`, `return`, `resume`, `abort`,
`unreachable`, `assert`, `FalseEdge`, `TrueEdge`, `SetDiscriminant`, `Deinit`,
`FakeRead`, `PlaceMention`, `AscribeUserType`, `Coverage`, `ConstEvalCounter`,
`Nop`, `Retag`, `DropAndReplace`) are recognised and not reported as unknowns.
Inline assembly is explicitly retained as an unknown because its memory effects
are not interpreted.

## Instability of `-Zunpretty=mir`

The emitted text begins with:

```text
// WARNING: This output format is intended for human consumers only
// and is subject to change without notice. Knock yourself out.
```

The Rust Unstable Book lists `mir` as one of the unstable `-Zunpretty`
variants and says the feature has no tracking issue, is "likely internal to the
compiler", and is "not being intended for general use". The rustc dev guide
shows the same warning and describes MIR as the compiler's internal
mid-level IR. These are **not** stable APIs:

* the pretty-printer can change between nightlies;
* the default view is not a promise about which storage statements or
  optimizations are present;
* generic and trait calls are printed in unresolved textual form;
* external crate bodies and monomorphized instances are not included;
* MIR syntax names are compiler internals, not a language specification.

The pin therefore gives one reproducible toolchain for one run. It does not
turn the text into a stable format, and a parser result must not be treated as
a portable compiler contract.

## Claim ceiling

A `LIVE` observation establishes only that the pinned compiler ran within the
declared bounds and that the listed textual constructs were observed. It does
not establish:

* a resolved call graph, whole-program closure, callback registration, or
  foreign/provider behavior;
* alias, provenance, borrow, or reference-interval facts;
* that a dereference is valid, in bounds, or correctly typed;
* that a textual `drop` or `free` call is dynamically reached;
* that all MIR constructs were understood;
* any native memory-safety property.

Absence of an observed construct is not evidence of absence. `NOT_RUN` is not
an empty successful scan.

## CLI and exit statuses

```text
frf-memorysafety mir scan FILE [--json] [--toolchain NAME]
```

Both `--json` spellings emit the same strict canonical
`ms-canonical-json-v1` bytes with no trailing newline. A live artifact uses
`frf-memorysafety.mir-observation.v1`; a typed unavailable response uses
`frf-memorysafety.mir-not-run.v1`.

| Status | Meaning for `mir scan` |
|---:|---|
| `0` | pinned compiler ran; observations are in the artifact (including explicit unknowns) |
| `2` | missing/bad flag, nonexistent input, non-regular file, non-`.rs` input, or non-UTF-8 path |
| `3` | compiler rejection, invalid UTF-8 output, malformed/unrecognised MIR, or a resource limit |
| `6` | `rustup`, the pinned toolchain, or the bounded invocation was unavailable (`NOT_RUN`) |
| `7` | internal canonical-encoding failure |

## Tests and gate result

The phase adds 13 tests: 6 unit tests in `src/mir.rs` and 7 integration tests in
`tests/mir.rs`. No test is ignored. Checked-in text fixtures
(`tests/fixtures/mir/sample.mir`) exercise the parser without a toolchain. The
adapter test accepts either a live observation or a typed `NOT_RUN`; it never
accepts a fabricated success. Limit tests cover source bytes, functions, calls,
and the canonical encoding.

`./ci/gate.sh` passes fmt, clippy `-D warnings`, debug tests, and release tests:
168 tests in each profile.

`./ci/mir-gate.sh` passes with `PASS mir-gate (LIVE observations)` in the
hardened `rust:1.85.0-slim` container. The live artifact records
`rustc 1.87.0-nightly (f280acf4c 2025-02-19)`, 7 functions, 9 unresolved call
edges, 3 dereference observations, 42 storage/lifetime markers, and 1
drop-like call for the fixture crate.

## Honest remaining limits

* The parser is a line-oriented subset of a non-stable human format.
* No symbol, type, trait, generic-instantiation, macro-expansion, or external
  crate resolution is performed.
* No alias, provenance, reference interval, or ownership identity is extracted.
* No monomorphization or whole-program closure is attempted.
* The optional toolchain is not installed by the default gate; in that
  environment the capability is honestly `NOT_RUN`.
* The capability remains unavailable on any host without the pinned nightly.

## Citations

1. The Rust Unstable Book, **`unpretty`** — lists `mir` among unstable
   `-Zunpretty` variants and states that the feature has no tracking issue, is
   likely internal, and is not intended for general use.
   <https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/unpretty.html>
2. Rust Compiler Development Guide, **The MIR (Mid-level IR)** — describes MIR
   as the compiler's internal CFG-based IR and reproduces the human-output
   warning. <https://rustc-dev-guide.rust-lang.org/mir/index.html>
3. Rust RFC 1211, **Add MIR** — introduces MIR as a radically simplified,
   explicitly typed compiler IR with explicit drops; it is not a stable
   external format. <https://rust-lang.github.io/rfcs/1211-mir.html>
4. The rustup book, **Toolchains** — documents dated toolchain names of the
   form `<channel>-<date>` and `rustup run <toolchain> rustc`.
   <https://rust-lang.github.io/rustup/concepts/toolchains.html>
5. The Rust Blog, **Announcing Rust 1.85.0** — the 2025-02-20 stable release
   that the pinned nightly date matches.
   <https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html>
6. The Rust Reference, **Behavior considered undefined** — aliasing, invalid
   values, provenance-sensitive behavior, and wrong-ABI hazards. Textual MIR
   observations cannot establish any of these properties.
   <https://doc.rust-lang.org/reference/behavior-considered-undefined.html>
7. Rust Unsafe Code Guidelines Reference, **Glossary** — allocation identity,
   aliasing, provenance, and the evolving aliasing model. None of these are
   extracted here. <https://rust-lang.github.io/unsafe-code-guidelines/glossary.html>
8. `std::process::Command` documentation — explicit program/argument
   invocation and piped standard streams used to avoid a shell.
   <https://doc.rust-lang.org/std/process/struct.Command.html>
