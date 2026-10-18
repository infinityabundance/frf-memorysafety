# FRF-MemorySafety

Candidate-bound memory-safety assurance for unsafe-to-safe Rust compatibility
ports. This crate records and checks finite evidence, claim scopes, obligations,
and support derivations. It deliberately separates finite-model results from
universal soundness claims.

**This build makes no memory-safety soundness claim.** Version 0.5.0 is the
Phase 4 release, extended on `staging` with Phase 5.1 detector evidence and
calibration refusal rules and Phase 5.2 live detector adapters. It adds Phase
4.1 and Phase 4.2 to the phase-2/phase-3 bookkeeping core: strict encoding,
typed evidence, founded support with policy custody, a finite three-rule
profile, bounded `syn`-based source discovery, typed
alias/footprint/reference-interval qualification, conservative MIR edge
observations when the pinned toolchain is present, responsibility-token
lifecycle and race semantics, a native event-transcript verifier, a test-only
harness that records and replays checked-in native fixtures, typed detector
evidence with mechanism-specific calibration refusal rules, opt-in live
calibration over a closed fixture registry, and an honest CLI. Universal
safe-interior soundness and `SAFE_COMPATIBLE` are outside the finite profile and
are always reported as `WITHHELD_NOT_RUN`. The harness cannot run arbitrary
C/Rust input; `court run` remains `NOT_RUN`. Live detector execution is
opt-in (`FRF_DETECTOR_LIVE=1`), uses only checked-in fixtures, and reports a
typed `NOT_RUN` when an instrument is unavailable.

## Status (0.5.0 / phase 4 + phase 5)

Verified in the pinned `rust:1.85.0-slim` container with the commands in
[Verification](#verification):

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo test --locked --all-targets --features native-harness` | 261 passed, 0 failed, 0 ignored |
| `cargo test --locked --release --features native-harness` | 261 passed, 0 failed, 0 ignored |
| `./ci/native-gate.sh` | 17 live native tests passed, 0 failed, 0 ignored |
| `./ci/detector-gate.sh` | 7 live mechanisms PASS; 11 live seal tests passed; no mechanism fabricated |

The optional `ci/mir-gate.sh` was not rerun for the Phase 4/5 changes; the MIR
path is unchanged from 0.4.0. The default gates above were run in the pinned
container. The same container image is used by the native and detector gates
after installing only their declared packages; the live tests are the same
tests that assert typed `NOT_RUN` when `FRF_NATIVE_HARNESS` or
`FRF_DETECTOR_LIVE` is unset in the default gate.

Release notes for Phase 1 (0.2.0), Phase 2 (0.3.0), Phase 3 (0.4.0), and
Phase 4 (0.5.0) are in [`CHANGELOG.md`](CHANGELOG.md).

### Capability matrix

| Capability | 0.5.0 availability |
|---|---|
| Strict canonical encoding, typed evidence, founded support, policy custody | Implemented; finite model |
| `source scan` AST inventory | Implemented; syntactic, bounded, explicit unknowns |
| `path analyze` aliases, footprints, reference intervals, C callbacks | Implemented; explicit-input and finite only |
| `mir scan` MIR text observations | Available only with pinned `nightly-2025-02-20`; otherwise `NOT_RUN`, exit 6 |
| Responsibility-token lifecycle, generation, failure, and race semantics | Implemented; caller-supplied finite transcript only |
| `court verify` native event-transcript verification | Implemented; rejects incomplete/fictitious evidence |
| Native event recording and replay | Test-only checked-in C/Rust fixtures through `src/native.rs`; identical replay or `unresolved` |
| Detector evidence and calibration adjudication | Implemented; structural and finite-case only |
| `detector calibrate FILE [--json]` | Implemented; refuses dead, misconfigured, harmless, mock-provider, and fake-marker evidence |
| Live detector calibration (`detector calibrate --live --detector KIND`) | Implemented for closed checked-in fixtures when the instrument is installed and `FRF_DETECTOR_LIVE=1`; otherwise `NOT_RUN`, exit 6 |
| Arbitrary native C/Rust execution (`court run`) | Not implemented; `NOT_RUN`, exit 6 |
| MIR-resolved caller graph, aliases, provenance, reference intervals | Not implemented; retained as explicit unknowns |
| Live Miri/sanitizers/Kani/Loom over arbitrary input, FRF, FRF-Fuzz, Gemel, native proof checkers | `NOT_RUN`, exit 6 |
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
- Typed responsibility tokens bound to object, owner, and generation, with
  create, transfer, failed transfer, shared/mutable borrow, reborrow,
  borrow-end, escape, reallocate, free, use, callback, poison, and abort
  transitions.
- Failure semantics for allocation refusal, partial initialization, failed
  callbacks, poisoned tokens, and aborted lifecycles.
- Generation bumps on reallocation and post-free reuse; stale tokens are
  rejected rather than silently reused.
- Per-thread event order with explicit `synchronizes_with` edges, vector-clock
  happens-before, atomic-versus-non-atomic conflict rules, and deterministic
  race witnesses.
- Strict `native-event-transcript.v1` parsing with required origin, tool/library
  versions, executable and fixture digests, case legality, scope, and
  completeness claims.
- Typed `verified_compatible_within_transcript`, `observed_violation`,
  `incomplete_transcript`, `unresolved`, and `illegal_case` outcomes.
- A seeded skipped-event detector for missing create, free, borrow-end,
  generation transition, callback, and event-count facts; a transcript that
  claims completeness while retaining gaps or unknown provider edges is
  rejected as fictitious completeness.
- `court verify FILE [--json]` with canonical
  `frf-memorysafety.court-verification.v1` reports and SPEC §14 exit statuses.
- A test-only native harness over a closed registry of checked-in C and Rust
  fixtures: explicit `cc`/`rustc` argv with no shell, bounded compilation and
  output, a private `0700` working directory, cleared environment, null stdin,
  a new process group, and per-child `prlimit` bounds (address space, CPU,
  NPROC, FSIZE, core=0) in addition to the container caps.
- Authentic-native event recording with exact compiler/linker versions,
  fixture and executable SHA-256 digests, case id, `test_only` legality, scope,
  completeness, and recording metadata.
- Typed detector evidence (`frf-memorysafety.detector-evidence.v1`): detector
  kind, exact tool name/version/executable digest/argv/environment digest, build
  flags/target/profile, separate build-directory identity, bounded stdout and
  stderr with SHA-256, exit status, signal, duration, truncation flag, origin,
  case id, fixture digest, mechanism, legality, and a typed mechanism-specific
  finding.
- Detector calibration adjudication that refuses dead detectors, missing
  findings, wrong or missing mechanism flags/enablement, build-separation
  mismatches, harmless-control findings, substitute/mock/modeled transports,
  and fake stdout markers. Capture text alone is never accepted as a finding;
  tampered, duplicate, unknown, oversized, or truncated evidence is refused.
- `detector calibrate FILE [--json]` with the canonical
  `frf-memorysafety.calibration-report.v1`, finite sensitivity/specificity
  counts, build-separation and authenticity statuses, named refusal reasons,
  and SPEC §14 exit statuses. Live calibration is opt-in through
  `detector calibrate --live --detector KIND`.
- Phase 5.2 live adapters over a closed checked-in fixture registry: pinned
  Miri (`nightly-2025-02-20`), gcc ASan/LSan/TSan, a loom race model and atomic
  control, a bounded Kani proof pair, and an OpenSSL SHA-256 known-answer plus
  valid/corrupt signature pair. Real stdout/stderr, exit status, signal,
  duration, tool version, executable digest, argv, environment digest, bindings,
  and separate build identities are captured. An unavailable instrument, a
  refused network fetch, an unsupported runtime, a timeout, or an oversized
  capture is `NOT_RUN`, never a fabricated pass.
- Two-run replay of identical executable input with byte-identical canonical
  transcripts required; any difference is reported as `unresolved` with a
  `replay_mismatch` finding.
- Native positive/negative pairs for legal transfer/free, use-after-free,
  mutable alias, stale generation after reallocation, synchronous callback,
  deferred callback after free, data race, and an atomic control, plus
  seeded skipped-event, fictitious-completeness, output-bound, and
  nondeterminism controls.
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

### Claim ceiling (transcript-scoped for phase 4)

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
aliasing compatibility. The court verifier is transcript-scoped: even when the
Phase 4.2 harness supplies the transcript, a
`verified_compatible_within_transcript` result is not memory safety, Rust borrow
validity, C object-lifetime legality, or a universal result. The harness
establishes only that a checked-in fixture emitted the recorded finite stream
twice under the recorded isolation. It does not observe a real scheduler, trace
all events, authenticate its digests, or provide signed provenance; the
fixtures use a scripted deterministic schedule. Arbitrary native input is not
recorded. The optional
MIR adapter consumes only the
human-readable, unstable `-Zunpretty=mir` text: it does not resolve symbols,
types, traits, generics, macros, external crates, aliases, provenance, or
reference intervals, and it does not establish a caller graph or whole-program
closure. A `NOT_RUN` response is not an empty successful scan. No result here
implies native Rust soundness, detector sensitivity, real-FFI coverage, or
universal safe-interior soundness. `SAFE_COMPATIBLE` is never accepted by this
build. Detector calibration is structural and mechanism-/case-specific: a
`CALIBRATED` report does not authenticate its digests, and does not establish
universal detector sensitivity or specificity. Phase 5.2 can additionally
capture a real run of a closed checked-in fixture, but the result remains one
mechanism-and-case-specific observation. Miri does not execute native C/FFI;
ASan/LSan/TSan depend on instrumentation, runtime, optimization, and the
executed path; loom models only loom-instrumented operations; Kani is bounded
by its unwinding and modeling assumptions; and the OpenSSL SHA-256/signature
control is not a constant-time or secret-lifecycle measurement. A `NOT_RUN`
response is not an empty successful calibration.

### NOT_RUN in this build

- Live detectors over arbitrary or caller-supplied input (only the closed
  checked-in registry runs)
- Live detectors when the instrument is unavailable, the network fetch is
  refused, the runtime is unsupported, or `FRF_DETECTOR_LIVE` is unset
- Constant-time/secret-lifecycle measurement (the OpenSSL control is a
  SHA-256 known-answer and signature-verification control, not a leakage oracle)
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
- Native C callback observation and retained-pointer lifecycle recording beyond
  the checked-in scripted fixtures
- Arbitrary caller-supplied native C/Rust recording (`court run`)
- Signed provenance attestations, transparency logs, or a trusted build root
- Real-scheduler race observation, sanitizer evidence, or whole-program closure
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
frf-memorysafety court verify FILE [--json]
frf-memorysafety detector calibrate FILE [--json]
frf-memorysafety detector calibrate --live --detector miri|asan|lsan|tsan|loom|kani|crypto [--json]
frf-memorysafety evidence verify --root DIR
frf-memorysafety report --case FILE --format json|markdown

frf-memorysafety court run ...              # NOT_RUN, exit 6
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

### Phase 4.1 responsibility tokens and transcript verification

`court verify FILE [--json]` consumes a strict `native-event-transcript.v1`
file and emits a canonical `frf-memorysafety.court-verification.v1` report. The
command itself does not execute native code; the separate Phase 4.2 test-only
harness supplies authentic-native transcripts for its checked-in fixtures. The
verifier checks responsibility-token lifecycle transitions,
failure and generation semantics, per-thread order, explicit
`synchronizes_with` edges, and the race rule "same object, different threads,
unordered, at least one write, not both atomic".

The transcript must declare authentic-native/substitute/modeled origin,
tool/library versions, executable and fixture digests, case legality, and scope.
Only `authentic_native` can reach a clean verdict. Outcomes and exit statuses
are:

```text
verified_compatible_within_transcript  0
observed_violation                     4
incomplete_transcript                  5
unresolved                             4
illegal_case                           4
```

Malformed or non-conforming instances exit 3. This mapping is the
SPEC.md §14 policy used by `court verify FILE [--json]`; no outcome is
translated into a universal memory-safety result.

The seeded skipped-event detector rejects missing create, free, borrow-end,
generation transition, required callback, and event-count facts as
`incomplete_transcript`. A transcript that claims completeness while retaining
those gaps or an unknown provider edge is explicitly rejected as fictitious
completeness. See [`docs/phase4-ownership.md`](docs/phase4-ownership.md) for the
token algebra, transition legality, race rule, completeness criterion, claim
ceiling, and citations.

### Phase 4.2 isolated native recording and replay

`src/native.rs` is a **test-only harness** over a closed registry of checked-in
fixtures. It is compiled only with the non-default `native-harness` feature, is
not available through the CLI, and does not accept a caller-supplied source
file or executable. With `FRF_NATIVE_HARNESS=1` it:

* compiles `tests/native/fixtures/` with explicit `cc`/`rustc` argv and no shell;
* runs each executable in a unique `0700` temporary directory with a cleared
  environment, null stdin, its own process group, and per-child `prlimit`
  bounds for address space, CPU, NPROC, FSIZE, and core dumps;
* captures a bounded JSONL event stream and rejects oversized output;
* records authentic-native provenance, compiler and linker versions, fixture
  and executable SHA-256 digests, case id, `test_only` legality, scope, and
  recording metadata;
* executes the identical input twice and requires byte-identical canonical
  transcripts; a difference is `unresolved` with a `replay_mismatch` finding.

The registry covers legal transfer/free in C and Rust, C use-after-free,
mutable alias, stale generation after reallocation, a synchronous callback, a
deferred callback after free, a data race, an atomic control, a seeded skipped
free, a pid/clock-dependent nondeterminism control, and an oversized-output
control. The skipped-event fixture is `incomplete_transcript`; the same
transcript with an overridden completeness claim is rejected as
`fictitious_completeness`. Without `FRF_NATIVE_HARNESS`, `tests/native.rs`
executes and asserts the typed `NOT_RUN` path; no test is ignored.

This is authentic emission of a **scripted deterministic schedule**, not
real-scheduler concurrency, sanitizer evidence, or memory-safety proof.
`court run` for arbitrary input remains `NOT_RUN` (exit 6). See
[`docs/phase4-native.md`](docs/phase4-native.md) for isolation, provenance,
the replay rule, exact commands, claim ceiling, and citations.

### Phase 5.1 detector evidence and calibration

`src/detector/mod.rs` adds a typed `frf-memorysafety.detector-evidence.v1`
receipt and a deterministic adjudicator. The Phase 5.1 adjudicator does not
execute a detector; the Phase 5.2 adapters in `src/detector/live.rs` produce the
same receipt from real runs. The receipt records:

* detector kind (Miri, ASan, LSan, TSan, Loom, Kani, crypto/secret oracle, or
  custom);
* exact tool name and version, executable SHA-256, invocation argv, environment
  digest, mechanism-enablement tokens, build flags/target/profile, and separate
  detector and baseline build-directory/artifact identities;
* bounded stdout and stderr text with per-stream SHA-256, exit status, signal,
  duration, and truncation flag;
* `authentic_live_tool`, `substitute`, `mock_provider`, or `modeled` provenance
  with case id, fixture digest, mechanism, and legality; and
* known-bad (sensitivity) and known-good (specificity) cases, each with an
  optional typed mechanism-specific finding whose diagnostic fingerprint must
  occur in the declared captured stream.

Calibration refuses undeserved evidence with named reasons:

* a known-bad case that exits zero or produces no typed finding is a dead
  detector;
* missing/wrong mechanism build flags, missing mechanism enablement, or a
  shared/instrumented baseline build is a misconfigured detector;
* a typed finding on a known-good case, or a nonzero exit on that control, is a
  harmless-control failure;
* any origin other than `authentic_live_tool` is refused;
* a printed marker with missing/placeholder tool identity or executable digest
  is refused (`FAKE_STDOUT_MARKER`); capture text alone is never a finding; and
* a mismatched stdout/stderr digest, duplicate case id, unknown/duplicate JSON
  field, oversized stream, or truncated stream is an integrity refusal.

The report contains finite sensitivity and specificity counts, `PASS`/`FAIL`/
`NOT_EVALUATED` build-separation and authenticity statuses, sorted named
refusals, and an embedded claim ceiling. Calibration is mechanism- and
case-specific; it is not a universal detector sensitivity claim and it does not
authenticate the tool. See
[`docs/phase5-calibration.md`](docs/phase5-calibration.md) for the schema,
rules, refusal taxonomy, claim ceiling, test controls, and citations.

### Phase 5.2 live detector adapters

`detector calibrate --live --detector KIND [--json]` runs a closed checked-in
fixture registry when `FRF_DETECTOR_LIVE=1` and the instrument is installed.
The selectors are `miri`, `asan`, `lsan`, `tsan`, `loom`, `kani`, and `crypto`.
The detector gate's live results on this branch are:

| Mechanism | Live result |
|---|---|
| Miri (`nightly-2025-02-20`, `ub`/`clean`/`harmless`) | PASS, sensitivity 1/1, specificity 2/2 |
| AddressSanitizer (heap use-after-free, clean control) | PASS, 1/1, 1/1 |
| LeakSanitizer (leak, clean control) | PASS, 1/1, 1/1 |
| ThreadSanitizer (barrier race, atomic control) | PASS, 1/1, 1/1 |
| loom (race model, atomic control) | PASS, 1/1, 1/1 |
| Kani 0.60.0 (`known_bad`, `proof_control`) | PASS, 1/1, 1/1 |
| OpenSSL SHA-256 KAT + signature pair | PASS, 1/1, 2/2 |

Every run captures real stdout/stderr with per-stream SHA-256, exit status,
signal, duration, tool version, executable digest, explicit argv, environment
digest, fixture digest, authentic-live provenance, and separate build
identities. Missing tools, refused network fetches, unsupported runtimes,
timeouts, and oversized captures are typed `NOT_RUN` (exit 6), never a pass.
The `crypto` selector uses the custom `openssl-sha256-kat` kind because a
known-answer/signature control is not a constant-time leakage measurement. See
[`docs/phase5-live-detectors.md`](docs/phase5-live-detectors.md) for exact
install/invocation commands, versions, flags, build separation, live results,
claim ceiling, and citations.

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
cargo test --locked --all-targets --features native-harness
cargo test --locked --release --features native-harness
```

The `native-harness` feature is not enabled by default; only the gates enable
it. The default gate installs no C toolchain. The native tests therefore execute and
assert the typed `NOT_RUN` path unless `FRF_NATIVE_HARNESS=1` is set.

`./ci/native-gate.sh` is a separate live gate. It uses the same hardened Docker
flags, installs only `gcc` and `libc6-dev` inside the pinned image (apt runs as
root because the reduced capability set prevents its `_apt` sandbox user from
switching users), sets `FRF_NATIVE_HARNESS=1`, and runs the 17 live native tests.
It does not weaken the memory, swap, pid, CPU, file-descriptor, capability, or
OOM settings. `ci/native.Dockerfile` is intentionally absent because runtime
OOM and resource caps belong in the gate invocation, not in an image. Across
both gates, 250 base tests and 17 live native-gate tests execute, with none
ignored or filtered out.

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
src/court.rs      responsibility tokens, races, and transcript verification
src/native.rs     test-only isolated native fixture recording and replay
src/detector/mod.rs  typed detector evidence and calibration refusal rules
src/detector/live.rs live adapters over closed checked-in fixtures
docs/phase3-source-inventory.md   phase 3.1 categories, limits, claim ceiling, citations
docs/phase3-path-effects.md       phase 3.2 algebra, qualification, citations
docs/phase3-mir.md                phase 3.3 pin, invocation, subset, instability, citations
docs/phase4-ownership.md          phase 4.1 token algebra, races, completeness, citations
docs/phase4-native.md              phase 4.2 isolation, provenance, replay, citations
docs/phase5-calibration.md         phase 5.1 evidence schema, refusal rules, citations
docs/phase5-live-detectors.md      phase 5.2 live install, invocation, results, citations
src/detector/     Phase 5.1 evidence/adjudication and Phase 5.2 live adapters
src/cli.rs        manual command parser and file-only commands
src/lib.rs        public API and capability matrix
tests/            canonical vectors, support semantics, independent oracle,
                  §12.4 cases, mutant courts, paper corpus, profile model/refusals,
                  source inventory fixtures/limits/symlinks/CLI, path-effect
                  alias/UnsafeCell/callback seal controls, MIR fixtures/adapter,
                  court token/race/completeness/CLI controls, native fixture
                  pairs/skipped-event/replay controls, detector evidence/calibration
                  seal controls, replay, CLI
```

## Non-transfer

A finite compatibility or model result does not imply a sound safe interior. No
finite-model result in this repository is a universal soundness claim.
A sanitizer or Miri pass does not imply soundness. Absence of `unsafe` does not
imply soundness. A bounded model result does not imply a universal native
result. An authentic-looking JSON file is not proof of execution. A clean
detector run is not proof of detector sensitivity. See `SPEC.md` §1.
