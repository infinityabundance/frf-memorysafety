# Phase 3.1: conservative source inventory

Snapshot: branch `staging`, crate `frf-memorysafety 0.3.0`. This document
describes the Phase 3.1 source inventory only. Phase 3.2 (MIR/compiler-assisted
edges) and Phase 3.3 (alias, footprint, and reference-interval semantics) are
not implemented.

## Claim ceiling

The inventory is **syntactic**. It parses source files into a `syn` 2.x syntax
tree and records selected constructs with file, byte, and line spans plus
SHA-256 content digests. It does not resolve names, types, traits, generic
instantiations, macro expansions, modules in other files, or dynamic foreign
dispatch.

A successful scan therefore establishes only that:

1. the named files were read and decoded as UTF-8;
2. each Rust file parsed, or its parse failure was recorded as an explicit
   unknown;
3. the listed syntax was observed inside the declared resource limits.

It does **not** establish any of the following:

* a caller graph, a resolved call target, or a whole-program call closure;
* alias relationships, provenance, reference intervals, or footprints;
* that a callback is registered, invoked, or legal under a C contract;
* that all unsafe operations, FFI edges, or allocations were found;
* any native memory-safety property or universal Rust soundness.

Absence of a finding is never evidence of absence. The canonical artifact embeds
this ceiling in `claim_ceiling`, and the module documentation repeats it.

## What is recorded

| Area | Recorded findings |
|---|---|
| Unsafety | `unsafe {}` blocks, `unsafe fn` (free, inherent, trait), `unsafe impl`, `unsafe trait` |
| FFI | `extern` blocks, foreign function/static/type declarations, ABI, `#[no_mangle]`/`#[unsafe(no_mangle)]`, `#[export_name]`, `#[link]`, `#[link_name]`, `#[repr]` |
| Pointers | raw-pointer types, dereferences, raw address-of, casts to raw pointers, `transmute`, `transmute_copy`, pointer/method operations |
| Ownership | unions, `MaybeUninit`, `UnsafeCell`, `NonNull`, allocation/deallocation calls, `into_raw`/`from_raw`/`from_raw_parts`, `drop_in_place`, `forget`, `set_len`, `leak` |
| Calls | syntactic function calls, method calls, closures, and callback-registration candidates (closure/function argument or registration-like name) |
| Configuration | `cfg`/`cfg_attr` items, feature predicates, `[features]` keys, `build = ...`, `build.rs` |
| Uncertainty | parse failures, macro invocations and `include!`, external `mod name;` bodies, `syn` verbatim nodes, symlinks, non-UTF-8 paths |

Every call edge is marked as unresolved in its `detail`. An `ffi_call` finding
means only that the callee's final path segment matches a foreign declaration
in the same file; it is not symbol resolution. A callback finding means only
that a function pointer or closure was syntactically passed, or that a callee
name looks like a registration function. It is not a proof that a callback was
registered or can be invoked legally.

The `source` scan also records `Cargo.toml` feature and build-script evidence
with a deliberately small line scanner, not a full TOML parser. Only
`[features]` keys and the `[package] build` value are interpreted.

## Resource limits

Limits are hard errors, not warnings or truncation.

| Resource | Default |
|---|---:|
| bytes per file | 1,048,576 |
| scanned files (Rust + manifests) | 2,048 |
| aggregate scanned bytes | 33,554,432 |
| syntax nodes visited | 262,144 |
| retained findings | 4,096 |
| retained unknowns | 4,096 |
| canonical output | 4 MiB (`ms-canonical-json-v1` limit) |

The finding and unknown caps are chosen to keep typical artifacts below the
canonical 4 MiB limit; the encoder enforces the byte limit as a final hard check.
Exceeding any cap exits with integrity status `3`.

Directory traversal sorts entries, skips non-Rust regular files (except
`Cargo.toml`), and **does not follow any symlink**. A symlinked entry is retained
as `symlink_not_followed` with its resolved target when available, so a link
cannot escape the scanned root. A file with invalid UTF-8 is rejected with
`invalid UTF-8` rather than lossily decoded.

Symlink refusal is not a race-free filesystem snapshot. A hostile concurrent
writer can still change a path between metadata inspection and read, as the
paper notes for the original prototype. The file digest records the bytes that
were actually read; it does not authenticate the path or prove that subsequent
builds used identical bytes.

## CLI

```text
frf-memorysafety source scan PATH [--json]
```

The command writes strict `ms-canonical-json-v1` bytes to standard output with
no trailing newline. `--json` is accepted for explicitness; both spellings emit
the same canonical machine form. The output schema is
`frf-memorysafety.source-inventory.v1`.

Exit statuses follow `SPEC.md` §14:

| Status | Meaning for `source scan` |
|---:|---|
| `0` | scan completed; findings and explicit unknowns are in the artifact |
| `2` | missing path, bad flag, nonexistent root, or non-Rust single-file root |
| `3` | invalid UTF-8, limit violation, or unreadable input |
| `7` | internal canonical-encoding failure |

A parse failure is an explicit unknown and exits `0`: the scan itself completed.
Integrity status `3` is reserved for input that cannot be retained honestly.

## The §12.4 omission / not-falsified distinction

The latest paper's §12.4 distinguishes three coverage outcomes:

1. an observed legal callback missing from the declared inventory falsifies the
   inventory;
2. a declared callback not observed in finite runs is `NOT_FALSIFIED`, not
   conservative closure;
3. an observed declared callback is also `NOT_FALSIFIED`, not proof that no
   other edge exists.

This inventory supplies a *declaration-like* source view. It is not an observed
edge set and cannot by itself falsify or close a graph. Its unresolved call and
callback findings are precisely the uncertainty that must be preserved for the
later observed/native courts. Combining a parsed inventory with incomplete
observation never yields conservative closure.

## Determinism

Files, findings, and unknowns use total orders: path first, then byte span, then
kind, target/detail, and remaining coordinates. Summary maps are `BTreeMap`s and
feature lists are sorted. Equal inputs under equal limits therefore produce
equal canonical bytes. The scan root itself is canonicalized and included in the
artifact.

## Tests

The phase adds 17 integration tests in `tests/source_inventory.rs` and 2 unit
tests in `src/source.rs`. They cover safe/unsafe/FFI/callback/cfg fixtures,
allocation and ownership sites, exact span slices, attributes, build/feature
evidence, malformed input, invalid UTF-8, every resource limit, symlink escape,
non-UTF-8 paths, deterministic canonical output, and CLI exit statuses. No test
is ignored. The full suite is 133 tests in both debug and release.

## Citations

1. The Rust Reference, **External blocks** — extern declarations, implicit
   unsafety, ABI strings, `#[link]`, and `#[link_name]`.
   <https://doc.rust-lang.org/reference/items/external-blocks.html>
2. The Rust Reference, **Behavior considered undefined** — aliasing, invalid
   values, provenance-sensitive const behavior, and wrong-ABI/unwind UB. This is
   why a syntactic call or callback finding cannot be treated as a legality
   proof. <https://doc.rust-lang.org/reference/behavior-considered-undefined.html>
3. The Rustonomicon, **Foreign Function Interface** — calling foreign functions,
   `extern`-qualified callbacks registered with C, callback targeting, and the
   hazards of asynchronous C callbacks. The inventory records registrations but
   does not validate this contract. <https://doc.rust-lang.org/nomicon/ffi.html>
4. `syn` 2.x documentation, including the `visit` module and optional features —
   parsing, spans, feature-gated syntax-tree APIs, and the absence of name/type
   resolution or macro expansion. <https://docs.rs/syn/2.0.119/syn/index.html>
   and <https://docs.rs/syn/2.0.119/syn/visit/index.html>
5. Unsafe Code Guidelines Reference, **Glossary** — allocation identity,
   aliasing, provenance, interior mutability/`UnsafeCell`, and the still-evolving
   Rust aliasing model. <https://rust-lang.github.io/unsafe-code-guidelines/glossary.html>
6. Jung, Dang, Kang, and Dreyer, **Stacked Borrows: An Aliasing Model for
   Rust** (POPL 2020) — a proposed aliasing model, not a property established by
   this inventory. Tree Borrows is a later experimental alternative; neither is
   implemented here. <https://plv.mpi-sws.org/rustbelt/stacked-borrows/paper.pdf>
