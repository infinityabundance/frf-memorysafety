# FRF-MemorySafety

Candidate-bound memory-safety assurance for unsafe-to-safe Rust compatibility
ports. This crate records and checks finite evidence, claim scopes, obligations,
and support derivations. It deliberately separates finite-model results from
universal soundness claims.

**This build makes no memory-safety soundness claim.** Version 0.8.0 is the
Phase 7 release. It retains the Phase 6 proof manifest with a declared
theorem/assumption closure, admission taxonomy, separate Rust/FFI
implementation-correspondence gate, and live pinned Coq adapter, plus the Phase
5 detector evidence, calibration refusal rules, and opt-in live detector
adapters over a closed checked-in fixture registry. Phase 7 adds exact contracts
for the real FRF, FRF-Fuzz, and Gemel providers, provider-typed opaque
identities, a fail-closed custody pipeline, and a live
FRF-Fuzz -> FRF -> Gemel chain. **Phase 7 is complete for the defined chain:**
`./ci/bridge-gate.sh` produces a real candidate-bound chain with independent
re-execution and actual loader-map closure, and all six seal controls fail
closed. **Phase 6 is complete for the declared Coq mechanism:**
`./ci/proof-gate.sh` installs Debian Coq 8.16.1 and passes all six live seal
cases. Without Coq, `proof verify --live` reports `checker_unavailable`
(exit 6); parser success is never proof acceptance.

It adds Phase 4.1 and Phase 4.2 to the phase-2/phase-3 bookkeeping core: strict
encoding, typed evidence, founded support with policy custody, a finite
three-rule profile, bounded `syn`-based source discovery, typed
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
typed `NOT_RUN` when an instrument is unavailable. Proof checking is limited to
the checked-in finite Coq theorem and its negative controls; it is not a proof
of the crate and is not a universal soundness claim.

Phase 7.1 added exact discovery and pinning of the real FRF, FRF-Fuzz, and
Gemel repositories, opaque provider-typed identities, and the fail-closed
custody pipeline. Phase 7.2, released as 0.8.0, unblocks pinned FRF-Fuzz with a
dedicated `rust:1.98-slim` + `nightly-2026-07-24` image and produces a real
`FRF-Fuzz finding -> FRF court/exact replay/OpenReceipt -> Gemel evidence/GID`
chain. The live chain records the exact candidate, real provider executables,
two independent executions per provider, and the actual loader-map closure,
and it passes stale-candidate, tampered-candidate, substituted-DSO,
re-execution-mismatch, and tampered-object seals. The default
`./ci/gate.sh` remains `rust:1.85.0-slim` and asserts the typed `NOT_RUN` path;
`./ci/bridge-gate.sh` runs the live chain. The bridge never writes an
`OpenReceipt`, finding, GCE object, or GID. See
[`docs/phase7-live-chain.md`](docs/phase7-live-chain.md).

## Status (0.8.0 / phase 7 complete)

Verified in the pinned `rust:1.85.0-slim` container with the commands in
[Verification](#verification):

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo test --locked --all-targets --features native-harness` | 311 base tests passed, 0 failed, 0 ignored |
| `cargo test --locked --release --features native-harness` | 311 base tests passed, 0 failed, 0 ignored |
| `./ci/native-gate.sh` | 17 live native tests passed, 0 failed, 0 ignored |
| `./ci/detector-gate.sh` | 7 of 7 live mechanisms PASS; 11 live seal tests passed, 0 failed, 0 ignored |
| `./ci/proof-gate.sh` | Coq 8.16.1; 6 of 6 live seal cases PASS; 6 live tests passed, 0 failed, 0 ignored |
| `./ci/bridge-gate.sh` | live chain `Complete`; 6 of 6 seals PASS; `FRF_GOLDEN=PASS` (Python 3.11.2 local image) |

The default gate executes all 311 tests, including the six proof-live tests on
their typed `checker_unavailable` path, the 17 bridge seal tests, the 3 bridge
unit tests, and the 1 live/`NOT_RUN` chain test. `./ci/proof-gate.sh` re-runs
those same six tests against live Coq; the live count is a subset of the base
total, not additional to it. `./ci/bridge-gate.sh` builds and runs the three
pinned providers and executes the same chain test with
`FRF_BRIDGE_LIVE_BUNDLE` set.

The optional `ci/mir-gate.sh` was not rerun for the Phase 4/5/6 changes; the MIR
path is unchanged from 0.4.0. The default gates above were run in the pinned
container. The same container image is used by the native and detector gates
after installing only their declared packages; the live tests are the same
tests that assert typed `NOT_RUN` when `FRF_NATIVE_HARNESS` or
`FRF_DETECTOR_LIVE` is unset in the default gate.

Release notes for Phase 1 (0.2.0), Phase 2 (0.3.0), Phase 3 (0.4.0),
Phase 4 (0.5.0), Phase 5 (0.6.0), Phase 6 (0.7.0), and Phase 7 (0.8.0) are in
[`CHANGELOG.md`](CHANGELOG.md).

### Live native chain (Phase 7)

`./ci/bridge-gate.sh` builds the three pinned providers and records this chain
against one candidate artifact:

```text
candidate  b594c294f4d34d28c34b018f9bb5e07c449a3bb8dc3d4b55b4a118608d93acbf
finding    9eea34004a284cdeacf1633253ccd0ce342b53e02c9347d884a9c075e6a1fb34
receipt    receipt-run-frf-fuzz-4f775512ad38df0305be933b1238e0d6f4743ab45eff5e470852aa62d70aa2f2-debbf82bbc86f0cbc7b348525dc2f98c9ccd873147bab0ad6d901640f5e1dccb
GID        evidence.2cae082c010569b59a7bcff46a70f6cb69fec46a30d1701561f36f4a8c091ae9
```

Custody stages are `Discover -> Reconstruct -> NativeConfirm -> FrfReceipt ->
GemelCustody`. The bundle carries exact provider pins, executable and closure
SHA-256 values, two byte-identical `RunRecord`s per provider, and the actual
`/proc/self/maps` closure. The six seals are independent re-execution,
stale candidate, tampered candidate, substituted DSO, recorded re-execution
mismatch, and tampered finding object; all fail closed with zero authentic
native identities. The FRF-Fuzz finding is a real fixed-seed campaign output;
the recorded reference run performed 93,500 executions and produced 27 findings,
while rerun counts vary with scheduling. A rerun may select a different finding
and produces a new Gemel producer/GID; every admitted chain is rechecked against
the same bytes, schema, candidate, replay, closure, and re-execution rules. See
[`docs/phase7-live-chain.md`](docs/phase7-live-chain.md) for images,
toolchains, commands, closure hashes, and the claim ceiling.

### Capability matrix

| Capability | 0.8.0 availability |
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
| `proof verify MANIFEST [--live] [--json]` | Implemented; validates manifest, closure, admission, and separate correspondence; `--live` invokes pinned Coq and returns `checker_unavailable`, exit 6, when it is absent |
| `bridge verify FILE [--json] [--candidate SHA256]` | Implemented; validates a supplied evidence bundle, opaque identities, schemas, digests, candidate binding, provenance, live-capture closure, and re-execution records; does not execute a provider |
| `bridge capture OUT ... [--json]` | Implemented; executes only the pinned providers named on the command line and records exact bytes, executable/closure hashes, candidate binding, and two independent runs |
| `bridge status [--json]` | Implemented; reports exact pins, recorded builds, and executable availability; exit 6 unless every provider executable matches its recorded digest |
| Live FRF/FRF-Fuzz/Gemel custody chain | Implemented in `./ci/bridge-gate.sh`: real finding `9eea34004a28...` from a 93,500-execution campaign, receipt `receipt-run-frf-fuzz-4f7755...-debbf82b...`, GID `evidence.2cae082c01...`, candidate `b594c294f4d3...`; 6 of 6 seals PASS |
| Live Coq proof checking | Implemented for the checked-in finite theorem and seal controls with Debian Coq 8.16.1; unavailable without `coqc` |
| Live Lean/Isabelle proof checking | Not implemented; `checker_unavailable`, exit 6 |
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
- A typed Phase 6 proof manifest (`frf-memorysafety.proof-manifest.v1`)
  with exact checker identity/version, digest-bound proof files, requested
  theorem, declared finite scope, theorem/assumption closure, recorded
  admission classification, separate Rust/FFI binding, and authentic-versus-
  substituted provenance.
- Closure and admission checks that reject `Admitted`, `admit`, `sorry`,
  `Axiom`, `Parameter`, and `Conjecture` inside the reachable proof closure;
  reject undeclared or undischarged assumptions, unrelated theorems, scope
  mismatch, checker/version/digest mismatch, and missing proof files; and
  distinguish `accepted_within_scope`, `rejected_assumption`,
  `rejected_unrelated`, `rejected_unchecked_implementation`,
  `rejected_missing_transition`, `checker_unavailable`, and `checker_failed`.
- A separate Rust/FFI implementation-correspondence gate that runs
  independently of proof acceptance, binds symbols and source digests to a
  Phase 3.1 source inventory or explicit evidence, requires a checked FFI
  wrapper, and requires an enumerated reentrant-callback transition.
- Phase 6.2 live Coq adapter with explicit argv, a private `0700` session, a
  cleared environment, 120-second and 1 MiB bounds, executable digest,
  node-locked kind/version/executable, manifest-order local-module resolution,
  and `Print Assumptions` status derivation in which only
  `Closed under the global context` is `proved`.
- Checked-in Coq fixtures (`tests/proof/coq/`) for the finite support
  fixed-point theorem and the `Admitted`, `Axiom`, unrelated, unchecked-wrapper,
  and missing-reentrant-transition seals.
- `proof verify MANIFEST [--live] [--json]` with a canonical
  `frf-memorysafety.proof-verification-report.v1`; it returns
  `checker_unavailable` and exit 6 when no live checker is configured, binds a
  completed run to `CheckerContext::Recorded`, and never fabricates acceptance
  from parser success.
- Exact Phase 7.1 provider discovery and pinning for FRF, FRF-Fuzz, and Gemel,
  with repository, branch, license, commit, schema token, and recorded build
  outcome in `capabilities` and `bridge status`.
- Provider-typed opaque identities (`BridgeFrfReceiptId`,
  `BridgeFrfFuzzFindingId`, `BridgeGemelGceId`) with private fields and no
  public string constructor; admission requires exact bytes, schema, provider
  pin, identity form, and digest.
- A custody pipeline with typed `NOT_RUN` and refusal reasons for modeled,
  modified-provider, substitute, stale-candidate, substituted-DSO, schema,
  tamper, and re-execution-mismatch evidence.
- `bridge verify FILE [--json] [--candidate SHA256]`, `bridge capture OUT ...`
  [options], and `bridge status [--json]` with SPEC §14 exit statuses.
- `capabilities --json` reports bounded proof-checker availability.
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

### Claim ceiling (finite and transcript-scoped through phase 7)

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
response is not an empty successful calibration. Manifest-only validation is
not proof checking: a well-formed manifest does not by itself establish that a
checker ran, that the proof files compile, that the theorem is true, that the
declared dependency graph is complete, or that the implementation
correspondence is semantically sound. The lexical admission scan is
conservative and may reject an unrelated textual occurrence in a scanned file;
it is not a Coq, Lean, or Isabelle parser. `proof verify --live` returns
`checker_unavailable` (exit 6) without a live checker. A completed live run
establishes only that the pinned Coq checked the declared small finite
two-claim support fixed-point theorem over the exact bytes; it does not prove
universal soundness. Implementation correspondence is a reviewed evidence
binding over a source inventory or explicit digest-bound evidence, not a
machine-proved semantic refinement; no result here proves the crate or arbitrary
FFI implementations. Phase 7 bridge verification establishes only that a
supplied bundle has exact recorded bytes, external byte identities, schema
tokens, candidate binding, live-capture loader closures, two byte-identical
provider re-executions, and typed custody stages. `authentic_native`
provenance is a recorded, digest-checked execution record, not authenticated
provenance: it is not a signature, transparency log, or trusted build root. The
crate writes no `OpenReceipt`, finding, GCE object, or GID, and produces none of
those identities. A same-directory modified DSO would satisfy the path-based
binding rule; the substituted-DSO seal uses an out-of-tree preload. Full FRF
semantic conformance and full Gemel schema conformance remain outside the
bridge's checked subset, and the abort fixture is a custody-chain control, not
evidence of a real memory-safety defect.

### NOT_RUN in this build

- Live detectors over arbitrary or caller-supplied input (only the closed
  checked-in registry runs)
- Live detectors when the instrument is unavailable, the network fetch is
  refused, the runtime is unsupported, or `FRF_DETECTOR_LIVE` is unset
- Constant-time/secret-lifecycle measurement (the OpenSSL control is a
  SHA-256 known-answer and signature-verification control, not a leakage oracle)
- Live providers in the default `./ci/gate.sh` path (the live chain runs in
  `./ci/bridge-gate.sh`; the default gate asserts typed `NOT_RUN`)
- Authentication of `authentic_native` provenance (a capture record binds
  exact bytes, executable/closure hashes, and two runs, but it is not a
  signature, transparency log, or trusted build root)
- Full FRF semantic conformance and full Gemel evidence-schema conformance
  beyond the bridge's checked fields
- Live OpenSSL-Rust Safe-33 native courts
- Live Lean/Isabelle proof-checker invocation
- Live Coq proof checking when `coqc` is absent (`checker_unavailable`, exit 6)
- Proof acceptance from manifest parsing alone
- Live proof checking outside the declared finite theorem scope
- Semantic proof of the implementation-correspondence evidence
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
frf-memorysafety proof verify MANIFEST [--live] [--json]
frf-memorysafety bridge verify FILE [--json] [--candidate SHA256]
frf-memorysafety bridge capture OUT [--json] [capture options]
frf-memorysafety bridge status [--json]
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

Both `detector calibrate FILE [--json]` and
`detector calibrate --live --detector KIND [--json]` use the SPEC §14 statuses:

```text
0  CALIBRATED: the declared finite checks passed
2  usage error or unreadable input
3  evidence integrity failure
5  REFUSED: a named calibration refusal
6  NOT_RUN: live instrument unavailable or `FRF_DETECTOR_LIVE` unset
7  internal harness error
```

### Phase 5.2 live detector adapters

`detector calibrate --live --detector KIND [--json]` runs a closed checked-in
fixture registry when `FRF_DETECTOR_LIVE=1` and the instrument is installed.
The selectors are `miri`, `asan`, `lsan`, `tsan`, `loom`, `kani`, and `crypto`.
The detector gate's live availability and results, last recorded at 0.6.0 and
not rerun for 0.7.0 or 0.8.0, are:

| Mechanism | Selector | Recorded tool | Live result | Build separation |
|---|---|---|---|---|
| Miri (`nightly-2025-02-20`, `ub`/`clean`/`harmless`) | `miri` | `miri 0.1.0 (f280acf4c7 2025-02-19)` | PASS, sensitivity 1/1, specificity 2/2 | PASS |
| AddressSanitizer (heap use-after-free, clean control) | `asan` | gcc 12.2.0 | PASS, 1/1, 1/1 | PASS |
| LeakSanitizer (leak, clean control) | `lsan` | gcc 12.2.0 | PASS, 1/1, 1/1 | PASS |
| ThreadSanitizer (barrier race, atomic control) | `tsan` | gcc 12.2.0 | PASS, 1/1, 1/1 | PASS |
| loom (race model, atomic control) | `loom` | cargo 1.85.0; loom 0.7.2 | PASS, 1/1, 1/1 | PASS |
| Kani 0.60.0 (`known_bad`, `proof_control`) | `kani` | kani 0.60.0 with bundled CBMC | PASS, 1/1, 1/1 | PASS |
| OpenSSL SHA-256 KAT + signature pair | `crypto` | OpenSSL 3.0.22 | PASS, 1/1, 2/2 | PASS |

All seven mechanisms also reported `authenticity: PASS`. Availability is a
runtime installation observation from `capabilities --json`; it is not a
sensitivity claim. A mechanism that cannot be installed or run is `NOT_RUN`
with its exact reason and is never counted as PASS.

Every run captures real stdout/stderr with per-stream SHA-256, exit status,
signal, duration, tool version, executable digest, explicit argv, environment
digest, fixture digest, authentic-live provenance, and separate build
identities. Missing tools, refused network fetches, unsupported runtimes,
timeouts, and oversized captures are typed `NOT_RUN` (exit 6), never a pass.
The `crypto` selector uses the custom `openssl-sha256-kat` kind because a
known-answer/signature control is not a constant-time leakage measurement. See
[`docs/phase5-live-detectors.md`](docs/phase5-live-detectors.md) for exact
install/invocation commands, versions, flags, build separation, live results,
claim ceiling, and citations. Each PASS is one mechanism-and-case-specific
observation over checked-in fixtures; it does not establish universal detector
sensitivity or specificity, and it is not a memory-safety result.

### Phase 6 proof manifest and live checking

`proof verify MANIFEST [--live] [--json]` validates a typed
`frf-memorysafety.proof-manifest.v1` document. It checks strict canonical JSON,
exact checker kind/version, proof-file SHA-256 digests, the requested theorem
and finite scope, the declared theorem/assumption closure, the recorded
admission statuses, and a separate Rust/FFI implementation binding. The
binding is checked against a Phase 3.1 source inventory or explicit
digest-bound evidence; every FFI declaration needs a checked wrapper, and the
enumerated transitions must include a reentrant callback.

The verifier rejects `Admitted`, `admit`, `sorry`, `Axiom`, `Parameter`, and
`Conjecture` in the reachable proof closure, undeclared or undischarged
assumptions, unrelated theorems, scope mismatch, checker/version/digest
mismatch, and missing proof or evidence files. It distinguishes
`accepted_within_scope`, `rejected_assumption`, `rejected_unrelated`,
`rejected_unchecked_implementation`, `rejected_missing_transition`,
`checker_unavailable`, and `checker_failed`.

Without `--live` the command never invokes a checker. Even for a well-formed
manifest it returns `checker_unavailable` and exit 6, because no live checker is
configured. With `--live`, Debian Coq 8.16.1 compiles the digest-bound proof
files in manifest order and derives theorem statuses from `Print Assumptions`.
The positive seal is accepted within its finite two-claim support lattice, and
the dependent-`Admitted`, dependent-`Axiom`, unrelated, unchecked-wrapper, and
missing-reentrant-transition seals are all rejected. See
[`docs/phase6-live-checker.md`](docs/phase6-live-checker.md) for install,
invocation, theorem, seal results, and claim ceiling, and
[`docs/phase6-proof-adapter.md`](docs/phase6-proof-adapter.md) for the schema,
closure rules, admission taxonomy, correspondence gate, and citations.

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

Exit 0 never means universal soundness was established. For `bridge verify`
and `bridge capture`, exit 0 means `Complete`: every custody stage passed.
`bridge status` exits 0 only when every configured provider executable matches
its recorded digest and exits 6 otherwise. Bridge refusals use exit 4
(`Refused`: modeled/modified/substitute evidence, stale candidate, substituted
DSO); bridge integrity failures use exit 3 (`Integrity`: schema, digest,
candidate binding, missing live capture, or re-execution mismatch); an
unavailable provider or absent bundle is exit 6 (`NotRun`).

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
OOM and resource caps belong in the gate invocation, not in an image. The
The default gate executes 311 base tests (including the 11 detector-live tests,
the 6 proof-live tests on their typed `NOT_RUN`/`checker_unavailable` paths, the
17 bridge seal tests, the 3 bridge unit tests, and the 1 live/`NOT_RUN` chain
test) and the native gate executes 17 live native tests; none is ignored or
filtered out.

`./ci/detector-gate.sh` is a separate live gate for Phase 5.2. It uses the same
hardened Docker flags, installs only `gcc`, `libc6-dev`, `openssl`, `curl`, and
`ca-certificates`, installs the pinned `nightly-2025-02-20` miri/rust-src
components, and makes a bounded Kani 0.60.0 install attempt. It then runs each
of the seven built-in mechanisms and the 11 live seal tests. On this release all
seven mechanisms reported PASS and all 11 tests passed, 0 failed, 0 ignored. A
mechanism that is unavailable is reported as `NOT_RUN` with its reason, not as
a pass.

`./ci/proof-gate.sh` is the separate Phase 6 live proof gate. It uses the same
hardened Docker flags, installs Debian Coq 8.16.1 with `jq`, records the
`coqc --version` string and executable SHA-256, asserts that `capabilities
--json` reports `coq` as `available`, and runs the six live seal cases against
the checked-in manifests. The expected results are `accepted_within_scope`
(exit 0) for the positive seal and `rejected_assumption`, `rejected_unrelated`,
`rejected_unchecked_implementation`, and `rejected_missing_transition` (exit 4)
for the five negative seals. It then runs the six live tests. The gate does not
weaken any container limit.

`./ci/bridge-gate.sh` is the Phase 7.2 live native-chain gate. It uses the same
hardened Docker flags but a pinned `rust:1.98-slim` image for FRF-Fuzz and the
pinned `nightly-2026-07-24` toolchain, while FRF, Gemel, and this crate build in
`rust:1.85.0-slim`. It runs a fixed-seed bounded FRF-Fuzz campaign, selects a
real verified finding, replays the FRF run exactly twice, ingests real Gemel
evidence, captures the actual loader maps, and verifies the bundle. It then
exercises stale-candidate, tampered-candidate, substituted-DSO,
re-execution-mismatch, and tampered-object seals. The reported run passed 6 of
6 seals with zero authentic native identity on every failure. The default gate
still executes the same test with no external tools and asserts typed
`NOT_RUN`; no test is ignored. The Python image defaults to
`python:3.11-slim` and can be overridden with `FRF_PYTHON_IMAGE`.

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
  CPU quota, and file descriptors, and each gate has a bounded timeout
  (1800 seconds for the default gate; longer for the external build/chain
  stages).
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
src/proof.rs      Phase 6 manifest, closure, admission, correspondence, live Coq adapter
src/bridge.rs     Phase 7.1/7.2 provider pins, opaque identities, custody,
                  bundle verification, live capture, and loader closure
docs/phase6-proof-adapter.md      proof schema, closure, taxonomy, correspondence, citations
docs/phase6-live-checker.md       install, invocation, theorem, seals, claim ceiling, citations
docs/phase7-bridge-discovery.md   Phase 7.1 repos/commits/schemas, builds, identity boundary, seals
docs/phase7-live-chain.md         Phase 7.2 images/toolchains, campaign, chain IDs, seals, ceiling
ci/bridge-gate.sh                 Phase 7.2 external-tool and live-chain gate
ci/fixtures/bridge_abort_target.rs checked-in deterministic FRF-Fuzz fixture target
ci/fixtures/dso_probe.c           actual loader-map capture probe
ci/fixtures/dso_substitute.c      substituted-DSO control
tests/bridge_live.rs              live bundle Complete or default typed NOT_RUN
tests/proof/coq/                  checked-in Coq fixtures, evidence, canonical manifests
tests/proof_live.rs               live/unavailable seal tests
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
                  seal controls, proof manifest/closure/admission/correspondence
                  controls, live Coq/unavailable seals, bridge identity/custody
                  seals, replay, CLI
```

## Non-transfer

A finite compatibility or model result does not imply a sound safe interior. No
finite-model result in this repository is a universal soundness claim.
A sanitizer or Miri pass does not imply soundness. Absence of `unsafe` does not
imply soundness. A bounded model result does not imply a universal native
result. An authentic-looking JSON file is not proof of execution. A clean
detector run is not proof of detector sensitivity. A well-formed proof manifest
is not a proof: manifest validation does not establish that a checker ran, that
the theorem is true, or that the implementation correspondence is sound. The
Rust/FFI correspondence check is reviewed evidence binding, not a machine-proved
semantic refinement. A live Coq run establishes only that the checked-in small
finite two-claim support fixed-point theorem compiled and was reported closed;
it does not prove the crate, arbitrary FFI implementations, or universal
soundness. A verified bridge bundle establishes exact pins, external byte
identities, schema tokens, candidate binding, live-capture loader closures, and
recorded re-execution; it does not establish that `authentic_native` provenance
is authenticated, and a capture record is not a signature or trusted build
root. See `SPEC.md` §1,
[`docs/phase7-bridge-discovery.md`](docs/phase7-bridge-discovery.md), and
[`docs/phase7-live-chain.md`](docs/phase7-live-chain.md).
