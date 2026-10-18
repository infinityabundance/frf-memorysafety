# FRF-MemorySafety

Candidate-bound memory-safety assurance for unsafe-to-safe Rust compatibility
ports. This crate records and checks finite evidence, claim scopes, obligations,
and support derivations. It deliberately separates finite-model results from
universal soundness claims.

**This build makes no memory-safety soundness claim.** Version 0.4.0 adds a
phase-3.1 syntax-only source inventory, a phase-3.2 explicit-input path-effect
model, and a phase-3.3 optional pinned MIR text adapter to the phase-2
bookkeeping core: strict encoding, typed evidence, founded support with policy
custody, a finite three-rule profile, bounded `syn`-based source discovery,
typed alias/footprint/reference-interval qualification, conservative MIR edge
observations when the pinned toolchain is present, and an honest CLI.
Universal safe-interior soundness and `SAFE_COMPATIBLE` are outside the finite
profile and are always reported as `WITHHELD_NOT_RUN`.

## Status (0.4.0, phase 3)

Verified in the pinned `rust:1.85.0-slim` container with the commands in
[Verification](#verification):

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo test --locked --all-targets` | 168 passed, 0 failed, 0 ignored |
| `cargo test --locked --release` | 168 passed, 0 failed, 0 ignored |
| `ci/mir-gate.sh` | PASS (LIVE observations with pinned nightly) |

Version 0.4.0 is the Phase 3 release, covering the Phase 3.1 source inventory,
Phase 3.2 path effects, and Phase 3.3 optional MIR adapter. Release notes for
Phase 1 (0.2.0), Phase 2 (0.3.0), and Phase 3 (0.4.0) are in
[`CHANGELOG.md`](CHANGELOG.md).

### Capability matrix

| Capability | 0.4.0 availability |
|---|---|
| Strict canonical encoding, typed evidence, founded support, policy custody | Implemented; finite model |
| `source scan` AST inventory | Implemented; syntactic, bounded, explicit unknowns |
| `path analyze` aliases, footprints, reference intervals, C callbacks | Implemented; explicit-input and finite only |
| `mir scan` MIR text observations | Available only with pinned `nightly-2025-02-20`; otherwise `NOT_RUN`, exit 6 |
| MIR-resolved caller graph, aliases, provenance, reference intervals | Not implemented; retained as explicit unknowns |
| Live Miri/sanitizers/Kani/Loom, FRF, FRF-Fuzz, Gemel, native proof checkers | `NOT_RUN`, exit 6 |
| Universal safe-interior soundness and `SAFE_COMPATIBLE` | Withheld; `WITHHELD_NOT_RUN` |

The conformance tests **execute**; they are not ignored. The shipping engine is
compared against a separately coded oracle in `tests/support_oracle/` over the
explicit 12-pattern, three-node universe: 110,592 configurations, 331,776
all-node certificate comparisons, and 331,776 all-node exact-cut comparisons.
The paper's distinct counting definition, which checks only positively
supported nodes before a challenge, is pinned at 17,712. See
`docs/phase2-conformance.md` for the exact domain, methodology, and claim
ceiling.

### Implemented

- Strict `ms-canonical-json-v1` parsing/encoding: duplicate keys, floats,
  trailing bytes, UTF-8, and all six resource limits.
- Domain-separated `ms1-` SHA-256 identities over twelve domains.
- Typed claims, scope anchors, execution modes, epistemic statuses, hazards,
  obligations, detector outcomes, and opaque external FRF/FRF-Fuzz/Gemel IDs.
- Least-fixed-point positive and admissible support with explicit leaf
  admission, challenged premises, all-node certificates, exact node and rule
  cuts, incremental revocation, and noninterference witnesses.
- Digest-bound historical verdicts that replay under their original policy and
  detect policy substitution, result tampering, or digest tampering.
- The nine §12.4 coverage/policy/support cases transcribed from the paper's
  original `acceptance_cases.py` fixtures and exact outcomes, plus
  wrong-greatest-fixed-point, hidden-intermediate, shared-mapping,
  changed-policy, and implicit-leaf mutant courts.
- An independently written fixed-point/certificate/exact-cut oracle and a
  paper-corpus test that aligns the 17,712 exact-revocation-cut definition with
  the crate's all-node 331,776 comparisons.
- CLI policy custody: `support evaluate` and `support explain` accept a policy
  file, expected policy digest, and expected policy version, and reject
  substitution with SPEC §14 exit statuses.
- The finite three-rule profile: exact enumeration, subset restriction, and
  same-domain conjunction, with nine named refusal checks.
- A deterministic local buffer model with 24 records (8 scenarios for each of
  C0/C1/C2) and 5 requested claims per variant, plus a separately written Rust
  replay of the original eight-case model in `tests/original_domain_replay.rs`.
- An evaluator that replays each local-model case against the crate's own
  reconstruction, so a fabricated case outcome and its honestly rehashed
  observation are still refused.
- A bounded, syntax-only Rust source inventory using pinned `syn` 2.0.119 with
  `full` and `visit`: unsafe items, FFI declarations/calls, exported symbols,
  raw pointers, `transmute`, unions, `MaybeUninit`/`UnsafeCell`/`NonNull`,
  allocation/ownership sites, unresolved calls/methods/closures/callback
  registrations, `cfg`/feature evidence, and `build.rs`/`Cargo.toml` evidence.
- Hard source-scan limits, deterministic ordering, canonical JSON, explicit
  parse/macro/module/symlink unknowns, and refusal to follow symlinks.
- A typed Phase 3.2 path-effect model over explicit finite objects, aliases,
  footprints, reference intervals, events, callbacks, and providers.
- Exact-object, descendant/subrange, shared-mapping, and top/unknown aliases;
  exact, descendant, and top footprints; read/write/none access modes.
- Typed `observed_conflict`, `omission`, `not_falsified`, and
  `compatible_within_finite_footprint` outcomes with evidence and explicit
  unknowns. These are never collapsed into a boolean.
- C callback qualification for legal synchronous callbacks, retained pointers,
  deferred invocation, callback-after-free, and foreign/provider dynamic
  dispatch. Foreign and provider behavior is never promoted to safe or unsafe.
- `path analyze FILE [--json]` over explicit JSON or a Phase 3.1 source
  inventory, with deterministic canonical reports and SPEC §14 exit statuses.
- An optional, pinned MIR adapter (`nightly-2025-02-20`) that invokes
  `rustup run <toolchain> rustc --edition 2021 -Zunpretty=mir` with explicit
  argv, no shell, a private temporary working directory, bounded stdout and
  stderr, and a bounded timeout.
- A conservative MIR text parser for function definitions, unresolved call
  edges, dereferences, storage/lifetime markers, drop/free-like calls, and
  explicit unknown constructs. Foreign, provider, trait, and indirect dispatch
  remain unresolved; same-name local definitions are not treated as
  resolution.
- A typed `NOT_RUN` response and exit status 6 when `rustup`, the pinned
  toolchain, or the bounded invocation is unavailable. No observation is
  fabricated.
- `mir scan FILE [--json] [--toolchain NAME]` with canonical
  `frf-memorysafety.mir-observation.v1` or
  `frf-memorysafety.mir-not-run.v1` JSON.
- A manual CLI (no `clap`, no shell execution) with SPEC §14 exit statuses and
  explicit `NOT_RUN` responses.

### Finite model

| Variant | Adjudicable | Model conflicts | Parity mismatches | Clear | Parity | Restriction | Conjunction | Universal |
|---|---:|---:|---:|---|---|---|---|---|
| C0 | 6 of 8 | 2 | 0 | not established | established | not established | not established | withheld |
| C1 | 8 of 8 | 0 | 0 | established | established | established | established | withheld |
| C2 | 8 of 8 | 0 | 4 | established | not established | established | not established | withheld |

C0 models an interval held across a successful replacement. C1 models the
interval acquired after the callback. C2 accepts all identities. These are
finite local model results, not native execution and not universal soundness.

The C0 `Parity` result is scoped to the six adjudicable cases. Over the full
eight-case domain it is not established, because two cases have modeled
conflicts and no adjudicated observation; this matches the original
`research/paper/research/worked_bundle.py` results. The replay test checks the
original counts and makes this scoping difference explicit.

### Claim ceiling

Every positive result in this README is limited to the named finite domain and
the checks that were actually executed. The claim ceiling is syntactic, finite,
and explicit-input only: no result here is whole-program or universally sound. The conformance campaign is a
differential consistency result between the shipping engine and a separately
coded oracle over the 12-pattern, three-node universe; it is not a proof of
`SPEC.md`, because both implementations can share a specification error. Policy
custody and historical verdicts are digest-bound and replay-bound, not
authenticated; there is no signature or trusted execution root. The source
inventory is syntactic and bounded: unresolved calls, callbacks, macros,
external module bodies, and foreign dispatch remain unknown, so it is not a
caller graph, an alias analysis, or a coverage proof. The path-effect model is
finite and explicit-input only: it does not extract aliases from source or MIR,
observe native callbacks, model concurrency, or establish whole-program
closure. A `compatible_within_finite_footprint` outcome is not universal
aliasing compatibility. The optional MIR adapter consumes only the
human-readable, unstable `-Zunpretty=mir` text: it does not resolve symbols,
types, traits, generics, macros, external crates, aliases, provenance, or
reference intervals, and it does not establish a caller graph or whole-program
closure. A `NOT_RUN` response is not an empty successful scan. No result here
implies native Rust soundness, detector sensitivity, real-FFI coverage, or
universal safe-interior soundness. `SAFE_COMPATIBLE` is never accepted by this
build.

### NOT_RUN in this build

- Live Miri, AddressSanitizer, LeakSanitizer, ThreadSanitizer
- Live Kani or Loom
- Live FRF court / OpenReceipt verification
- Live FRF-Fuzz coordinator
- Live Gemel publication
- Live OpenSSL-Rust Safe-33 native courts
- Native proof-checker adapters
- MIR/compiler-resolved caller graphs and whole-program closure
- Source/MIR-extracted alias, provenance, footprint, and reference-interval
  semantics
- MIR edge extraction when the pinned `nightly-2025-02-20` toolchain is absent
  (`NOT_RUN`, exit 6)
- Native C callback observation and retained-pointer lifecycle recording
- Universal safe-interior or `SAFE_COMPATIBLE` acceptance

FRF remains the only FRF receipt producer, FRF-Fuzz the only BLAKE3 finding
producer, and Gemel the only GCE/GID producer. This crate does not synthesize
their identities.

## Usage

```text
frf-memorysafety version [--json]
frf-memorysafety capabilities [--json]
frf-memorysafety profile validate FILE
frf-memorysafety profile enumerate --out DIR
frf-memorysafety support evaluate FILE [--policy POLICY_FILE] [--expect-policy-digest MS1_ID] [--expect-policy-version VERSION]
frf-memorysafety support explain FILE  [--policy POLICY_FILE] [--expect-policy-digest MS1_ID] [--expect-policy-version VERSION]
frf-memorysafety source scan PATH [--json]
frf-memorysafety path analyze FILE [--json]
frf-memorysafety mir scan FILE [--json] [--toolchain NAME]
frf-memorysafety evidence verify --root DIR
frf-memorysafety report --case FILE --format json|markdown

frf-memorysafety court run ...              # NOT_RUN, exit 6
frf-memorysafety detector calibrate --live  # NOT_RUN, exit 6
frf-memorysafety frf promote ...            # NOT_RUN, exit 6
frf-memorysafety gemel publish ...          # NOT_RUN, exit 6
```

`profile enumerate` writes canonical `bundle.json`, `policy.json`,
`claims.json`, and `cases.json`. `profile validate` accepts a
`frf-memorysafety.profile.v1` bundle (canonical or ordinary strict JSON) and
prints an evaluation. The fixture bundle intentionally requests universal
soundness, so validating it exits 4 while all finite claims are still
evaluated.

A support file has this shape:

```json
{
  "schema": "frf-memorysafety.support.v1",
  "spec": "frf-memorysafety-spec-v1",
  "rules": {
    "rules": { "q": [["a"]] },
    "admitted_leaves": ["a"]
  },
  "revoked": [],
  "challenged": [],
  "claim": "q",
  "policy": { "id": "example-policy", "version": "1" }
}
```

The optional `policy` identity binds the support file to a policy version. A
policy file has the shape `{"id": ..., "version": ..., "rules": {...}}`.
`--policy` additionally requires the policy file's rules to equal the support
file's rules. `--expect-policy-digest` accepts the canonical `ms1-...` policy
digest. Rule, digest, or version substitution exits 3; malformed expected
digest or a missing policy identity exits 2.

`evidence verify --root DIR` walks regular `*.json` files (skipping symlinks),
requires each to parse strictly and be byte-canonical, and exits 3 if any file
fails.

### Phase 3.1 source inventory

`source scan PATH [--json]` parses a Rust file or directory with pinned `syn`
2.0.119 and emits canonical `frf-memorysafety.source-inventory.v1` JSON with no
trailing newline. It records file byte/line spans, SHA-256 file and slice
digests, unsafe constructs, FFI declarations/calls, attributes, raw-pointer
operations, `transmute`, unions, `MaybeUninit`/`UnsafeCell`/`NonNull`,
allocation and ownership calls, calls/methods/closures/callback candidates,
`cfg`/feature/build-script evidence, and explicit unknowns.

This is **syntactic inventory, not a caller graph, alias analysis, or
whole-program knowledge**. Call targets, macro-generated code, external module
bodies, and foreign dispatch remain unknown. A parsed inventory cannot establish
conservative closure; the paper's §12.4 omission/not-falsified distinction is
preserved. See [`docs/phase3-source-inventory.md`](docs/phase3-source-inventory.md)
for the exact categories, limits, exit statuses, and citations.

Default hard limits are 1 MiB per file, 2,048 files, 32 MiB total, 262,144
syntax nodes, 4,096 findings, and 4,096 unknowns. Exceeding a limit exits 3.
Invalid UTF-8 exits 3. Parse failures become explicit unknowns and the scan
exits 0. Directory traversal skips non-Rust files and never follows symlinks;
a symlink is reported as `symlink_not_followed`.

### Phase 3.2 path effects

`path analyze FILE [--json]` consumes either an explicit
`frf-memorysafety.path-effects-input.v1` trace or a Phase 3.1
`frf-memorysafety.source-inventory.v1` file and emits a canonical
`frf-memorysafety.path-effects-report.v1` report. Explicit input declares
objects, aliases (`exact_object`, `descendant`, `shared_mapping`,
`top_unknown`), reference intervals, events (`creation`, `reborrow`, `escape`,
`callback`, `free`, `use`), callbacks, and foreign/provider behavior.

The report does not produce a boolean. It records typed
`observed_conflict`, `omission`, `not_falsified`, and
`compatible_within_finite_footprint` outcomes with event evidence and explicit
unknowns. A definite overlap, use-after-free, double free, or reference-interval
violation is an observed conflict; an unresolved alias, footprint, callback, or
provider is not falsified; an unobserved callback that is declared legally
absent is an omission; compatibility is limited to the declared finite
footprint. This preserves the paper's §12.4 omission/not-falsified distinction.

Inventory input has no alias or dispatch identity, so the adapter uses a
`top_unknown` alias and a foreign-dispatch provider. An inventory-derived
report is therefore never compatibility evidence. Default limits are 1,024
events, 1,048,576 pair checks, 65,536 outcomes, and the 4 MiB canonical cap;
exceeding a limit exits 3. An observed conflict is a finding, not a command
failure, so the command exits 0 with that status in the report. See
[`docs/phase3-path-effects.md`](docs/phase3-path-effects.md) for the algebra,
qualification rules, seal controls, claim ceiling, and citations.

### Phase 3.3 optional MIR edges

`mir scan FILE [--json] [--toolchain NAME]` invokes the pinned
`nightly-2025-02-20` toolchain through `rustup run <toolchain> rustc --edition
2021 -Zunpretty=mir --crate-type=lib FILE`. It uses explicit argv and never a
shell, runs in a private `0700` temporary directory with null stdin, bounds
stdout/stderr and wall time, and returns a typed
`frf-memorysafety.mir-not-run.v1` response with exit 6 when the toolchain or
invocation is unavailable.

A live `frf-memorysafety.mir-observation.v1` artifact records function
definitions, basic-block counts, unresolved call edges (including indirect,
qualified/trait, foreign/provider-possible uncertainty), textual dereferences,
storage/lifetime markers, drop/free-like calls, and every unrecognised
construct as an explicit unknown. Every call remains unresolved; a same-name
local definition is only a name coincidence. `StorageLive`/`StorageDead` may
be absent from the printed MIR.

`-Zunpretty=mir` is an unstable, human-oriented format that is explicitly
subject to change without notice. The pin makes a run reproducible for that
exact toolchain, not the format stable. The adapter does not resolve symbols,
types, traits, generics, macros, external crates, aliases, provenance, or
reference intervals, and does not establish whole-program closure. If the
pinned toolchain is absent, the capability is honestly `NOT_RUN`, not an empty
successful scan. See [`docs/phase3-mir.md`](docs/phase3-mir.md) for the parsed
subset, bounds, instability, and citations.

## Exit statuses

Following SPEC.md §14:

```text
0  command completed and its own declared checks passed
2  invalid input or usage
3  evidence integrity failure
4  promotion refused / claim blocked
5  detector failure or MISSED control
6  external tool or integration unavailable (NOT_RUN)
7  internal harness error
```

Exit 0 never means universal soundness was established.

## Verification

`./ci/gate.sh` is the canonical gate runner. Every Rust build and test runs in
the pinned `rust:1.85.0-slim` container, never on the host. A successful run
prints `PASS` for each gate and writes full logs to `target/gate-logs/`.

The four gates are:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
cargo test --locked --release
```

`./ci/mir-gate.sh` is a separate optional gate. It uses the same hardened
flags plus a `frf-rustup` volume, attempts to install the pinned minimal
`nightly-2025-02-20`, builds the binary, and runs `mir scan` against
`tests/fixtures/mir/source.rs`. It prints `PASS` for a live observation and
`NOT_RUN` (exit 6) if installation or execution is unavailable. It is not
invoked by `ci/gate.sh`.

Every container is hardened as follows:

- `--memory=2g --memory-swap=2g` caps memory and swap together, so the
  container is OOM-killed before the host is placed under memory pressure;
  `--oom-score-adj=500` makes it the preferred OOM victim.
- `--pids-limit=512 --cpus=2 --ulimit nofile=1024:1024` bound process count,
  CPU quota, and file descriptors, and each gate has a 1800-second timeout.
- `--cap-drop ALL` followed by only `DAC_OVERRIDE`, `CHOWN`, and `FOWNER`
  restoration, plus `--security-opt no-new-privileges`, permits writing the
  mounted build directory without granting broader privileges.
- The repository is mounted read-only at `/src`; only `target/` and the
  `frf-cargo` Cargo cache volume are writable.

The host `target/` directory is generated state and is not tracked. Delete it
for a clean-room run; the gate recreates it. `Cargo.lock` is committed and the
test gates use `--locked`. The `tests/lockfile.rs` guard also fails if the
lockfile or pinned toolchain is missing.

## Layout

```text
src/identity.rs   canonical encoding, limits, domain-separated identities
src/model.rs      typed claims, scopes, obligations, hazards, external IDs
src/support.rs    fixed-point support, challenges, certificates, cuts, custody
src/closure.rs    set-based declared/observed coverage comparison
docs/             phase-2 requirement alignment, conformance methodology, citations
src/profile.rs    finite three-rule profile and deterministic buffer model
src/source.rs     bounded syn-based syntactic source inventory
src/path_effect.rs finite explicit-input aliases, footprints, intervals, outcomes
src/mir.rs        optional pinned MIR adapter and conservative text parser
docs/phase3-source-inventory.md   phase 3.1 categories, limits, claim ceiling, citations
docs/phase3-path-effects.md       phase 3.2 algebra, qualification, citations
docs/phase3-mir.md                phase 3.3 pin, invocation, subset, instability, citations
src/cli.rs        manual command parser and file-only commands
src/lib.rs        public API and capability matrix
tests/            canonical vectors, support semantics, independent oracle,
                  §12.4 cases, mutant courts, paper corpus, profile model/refusals,
                  source inventory fixtures/limits/symlinks/CLI, path-effect
                  alias/UnsafeCell/callback seal controls, MIR fixtures/adapter,
                  replay, CLI
```

## Non-transfer

A finite compatibility or model result does not imply a sound safe interior. No
finite-model result in this repository is a universal soundness claim.
A sanitizer or Miri pass does not imply soundness. Absence of `unsafe` does not
imply soundness. A bounded model result does not imply a universal native
result. An authentic-looking JSON file is not proof of execution. A clean
detector run is not proof of detector sensitivity. See `SPEC.md` §1.
