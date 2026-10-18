# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This crate is assurance *bookkeeping*: it records, checks, and replays finite
evidence, support derivations, and policy-bound verdicts. It does not establish
universal memory-safety soundness, and no release below makes such a claim.

## [0.7.0] - 2026-10-18

Phase 6: proof manifest, theorem/assumption closure, admission taxonomy, a
separate Rust/FFI implementation-correspondence gate, and a live checked-proof
adapter. **Phase 6 is complete for the declared Coq mechanism:**
`./ci/proof-gate.sh` installs Debian Coq 8.16.1 and all six live seal cases
pass. Without Coq, `proof verify --live` remains fail-closed at exit 6.

### Added

- Phase 6.2 live Coq adapter: explicit argv only, private `0700` staging,
  cleared environment, 120-second per-process and 1 MiB per-stream bounds,
  executable digest, node-locked checker kind/version/executable,
  manifest-order local-module compilation, and `Print Assumptions` status
  derivation in which only `Closed under the global context` is `proved`.
- Checked-in Coq corpus in `tests/proof/coq/`: `model.v`, `approved.v`,
  `admitted.v`, `axiom.v`, `unrelated.v`, digest-bound source/evidence, and six
  canonical seal manifests for the finite two-claim support fixed-point
  theorem.
- `proof verify MANIFEST [--live] [--json]`, binding only a completed run to
  `CheckerContext::Recorded` and reporting `checker_unavailable` (exit 6) when
  `coqc` is absent.
- `capabilities --json` proof-checker availability (`coq`, `available` or
  `not_run`) from a bounded `coqc --version` probe.
- `ci/proof-gate.sh` with the same hardened container flags; installs Coq and
  jq, records `coqc --version` and the executable digest, runs the six live
  seal cases, and runs the live tests.
- `tests/proof_live.rs`: 6 executing tests (no `#[ignore]`) that assert each
  live seal under `FRF_PROOF_GATE=1` and the typed `checker_unavailable` path
  in the default gate.
- `docs/phase6-live-checker.md`: install/version/invocation, theorem and
  proved scope, closure behavior, correspondence limits, all seal results,
  claim ceiling, and citations.

- `src/proof.rs`: `frf-memorysafety.proof-manifest.v1` with exact checker
  identity/version, digest-bound proof files, finite theorem scope, declared
  theorem/assumption closure, recorded admission statuses, separate Rust/FFI
  implementation binding, and authentic-versus-substituted provenance.
- Canonical `frf-memorysafety.proof-verification-report.v1` with separate
  admission and correspondence reports, deterministic ordering, and an embedded
  claim ceiling.
- Closure and admission checks rejecting `Admitted`, `admit`, `sorry`,
  `Axiom`, `Parameter`, and `Conjecture` in the reachable closure; undeclared
  or undischarged assumptions; unrelated theorems; scope mismatch;
  checker/version/digest mismatch; and missing files.
- Separate correspondence gate over a Phase 3.1 source inventory or explicit
  digest-bound evidence, with checked FFI wrappers and mandatory reentrant-
  callback transition coverage.
- `proof verify MANIFEST [--json]`, returning `checker_unavailable` (exit 6)
  when no live checker is configured and never accepting parser success alone.
  Phase 6.2 extends this to `--live`.
- `tests/proof.rs`: 22 executing tests (no `#[ignore]`) covering approved
  shape, admitted/sorry/axiom, unrelated theorem, missing/tampered files,
  duplicate/unknown fields, scope mismatch, unchecked FFI wrapper, missing
  reentrant transition, independence, determinism, source-inventory binding,
  and CLI statuses.
- `docs/phase6-proof-adapter.md`: schema, closure rules, admission taxonomy,
  correspondence gate, claim ceiling, Phase 6.2 requirements, and citations.

### Verification

- `cargo fmt --all -- --check`: clean
- `cargo clippy --all-targets --all-features -- -D warnings`: clean
- `cargo test --locked --all-targets --features native-harness`: 290 base
  tests passed, 0 failed, 0 ignored
- `cargo test --locked --release --features native-harness`: 290 base tests
  passed, 0 failed, 0 ignored
- `./ci/proof-gate.sh`: Debian Coq 8.16.1 (`coqc` SHA-256
  `aae9841a59ea5a4d04c759d8328f52b3fa84f3b0e4fc7711507325d70639a240`),
  6 of 6 live seal cases PASS: `approved` -> `accepted_within_scope` (exit
  0), `admitted` and `axiom` -> `rejected_assumption` (exit 4), `unrelated` ->
  `rejected_unrelated` (exit 4), `unchecked` ->
  `rejected_unchecked_implementation` (exit 4), and `missing_transition` ->
  `rejected_missing_transition` (exit 4); 6 live tests passed, 0 failed, 0
  ignored.
- `cargo publish --dry-run --locked`: 109 files, 1.4 MiB (305.4 KiB
  compressed); no `research/`, `target/`, `.git/`, or credentials.

## [0.6.0] - 2026-10-18

Phase 5: typed detector evidence and calibration refusal rules, plus opt-in
live detector adapters over a closed checked-in fixture registry.

### Added

- `src/detector/mod.rs`: `frf-memorysafety.detector-evidence.v1` with detector kind,
  exact tool name/version/executable digest/argv/environment digest,
  mechanism-enablement tokens, build flags/target/profile, separate detector
  and baseline build identities, bounded stdout/stderr capture with SHA-256,
  exit status, signal, duration, truncation, provenance, case id, fixture
  digest, mechanism, legality, and typed mechanism-specific findings.
- Calibration adjudication with named refusals for dead detectors, missing
  findings, wrong/missing build flags or enablement, build-separation
  mismatches, harmless-control findings, substitute/mock/modeled transports,
  untrusted identities, fake stdout markers, and integrity failures (tampered
  digests, duplicate ids/keys, unknown fields, oversized or truncated capture).
- Deterministic canonical `frf-memorysafety.calibration-report.v1` with finite
  sensitivity/specificity counts, build-separation and authenticity statuses,
  sorted refusal reasons, and an embedded claim ceiling.
- `detector calibrate FILE [--json]` with SPEC §14 exit statuses 0/2/3/5/6/7.
- `tests/detector.rs`: 26 executing tests covering every Phase 5 seal control,
  positive sensitivity/specificity, build-separation pass/fail, tampered
  digests, duplicate/unknown fields, oversize/truncation, custom detectors,
  canonical determinism, and CLI statuses. None is ignored.
- `docs/phase5-calibration.md`: evidence schema, calibration rules, refusal
  taxonomy, claim ceiling, test controls, and citations.

### Phase 5.2

- `src/detector/live.rs` and `tests/detector/fixtures/`: opt-in live adapters
  for pinned Miri (`nightly-2025-02-20`), gcc ASan/LSan/TSan, loom, Kani, and an
  OpenSSL SHA-256 known-answer/signature control. Each adapter runs a closed
  checked-in fixture registry with explicit argv, no shell, private `0700`
  directories, `0600` capture files, cleared fixture environments, bounded
  time/output, null stdin, and its own process group.
- `detector calibrate --live --detector KIND [--json]` for the seven built-in
  selectors, with the canonical Phase 5.1 report on a run and a typed
  `frf-memorysafety.live-detector-not-run.v1` response (exit 6) when the tool is
  unavailable. `FRF_DETECTOR_LIVE=1` is required.
- `capabilities --json` now reports per-detector runtime availability.
- `ci/detector-gate.sh` uses the same hardened flags, installs only the needed
  detector packages, pinned nightly miri/rust-src, and a bounded Kani 0.60.0
  attempt; it reports each mechanism as PASS or NOT_RUN with the reason.
- `tests/detector_live.rs`: 11 executing seal tests (no `#[ignore]`) covering
  the typed `NOT_RUN` path, structural live evidence, sensitivity/specificity,
  build separation, digest binding, missing-finding, mock-origin, and tampered-
  capture refusals. The default gate runs them with live execution disabled.
- `docs/phase5-live-detectors.md`: exact install/invocation, versions, flags,
  live results, availability table, build separation, claim ceiling, remaining
  limits, and citations.

### Verification

- `cargo fmt --all -- --check`: clean
- `cargo clippy --all-targets --all-features -- -D warnings`: clean
- `cargo test --locked --all-targets --features native-harness`: 261 passed,
  0 failed, 0 ignored
- `cargo test --locked --release --features native-harness`: 261 passed,
  0 failed, 0 ignored
- `ci/detector-gate.sh`: Miri, ASan, LSan, TSan, loom, Kani 0.60.0, and the
  OpenSSL SHA-256/signature control all PASS with build separation PASS and
  authenticity PASS; 11 live seal tests passed, 0 failed, 0 ignored
- `cargo publish --dry-run --locked`: packaged without `research/`, `target/`,
  `.git/`, or credentials

## [0.5.0] - 2026-10-18

Phase 4: responsibility-token lifecycle, failure, borrow, generation, and race
semantics plus a native event-transcript verifier (`court verify`), and a
test-only isolated native harness that compiles, records, replays, and verifies
checked-in C and Rust fixtures. Arbitrary caller-supplied native execution
(`court run`) remains `NOT_RUN`.

### Added

- `src/court.rs`: typed responsibility tokens bound to object, owner, and
  generation; create, transfer, failed transfer, shared/mutable borrow,
  reborrow, borrow-end, escape, reallocate, free, use, callback entry/exit,
  poison, and abort transitions.
- Failure semantics for allocation refusal, partial initialization, callback
  failure, poisoned tokens, and aborted lifecycles; failed transfers preserve
  the sender.
- Generation semantics: reallocation and post-free reuse advance the
  generation; stale tokens are rejected after reallocation or free.
- Concurrency semantics: strictly increasing per-thread event order, explicit
  `synchronizes_with` edges, deterministic topological ordering, vector-clock
  happens-before, and the race rule "same object, different threads, unordered,
  at least one write, not both atomic". Atomic-atomic conflicts are permitted;
  atomic-versus-non-atomic conflicts are races.
- `native-event-transcript.v1` strict parsing with required origin,
  tool/library versions, executable and fixture digests, case legality, scope,
  and completeness claims.
- Typed outcomes `verified_compatible_within_transcript`, `observed_violation`,
  `incomplete_transcript`, `unresolved`, and `illegal_case` with SPEC §14 exit
  statuses 0/4/5/4/4.
- A seeded skipped-event detector: missing create, free, borrow-end, generation
  transition, required callback, or event-count fact yields
  `incomplete_transcript`; a completeness claim with gaps or unknown provider
  edges yields `fictitious_completeness`.
- `court verify FILE [--json]` emitting canonical
  `frf-memorysafety.court-verification.v1`; `court run` over caller-supplied
  programs remains `NOT_RUN` (exit 6).
- `tests/court.rs`: 39 tests covering positive/negative ownership transfer,
  use-after-free, mutable alias, stale generation, allocation failure, callback
  failure, partial initialization, failed transfer, reborrow, escape, abort,
  data race, atomic control, seeded skipped events, malformed/duplicate-field
  input, deterministic canonical reports, and CLI statuses. None is ignored.
- `docs/phase4-ownership.md`: token algebra, transition legality, race rule,
  completeness criterion, claim ceiling, Phase 4.2 status, and citations.
- Capability, version, and usage documentation for the court verifier.
- `src/native.rs`: test-only harness, compiled only with the non-default
  `native-harness` feature, over a closed registry of checked-in C and Rust
  fixtures. Explicit `cc`/`rustc` argv with no shell, bounded compilation
  and capture, private `0700` working directories, cleared environment, null
  stdin, a new process group, and per-child `prlimit` bounds for address space,
  CPU, NPROC, FSIZE, and core dumps in addition to the container caps.
- Authentic-native provenance with exact compiler/linker versions, fixture and
  executable SHA-256 digests, case id, `test_only` legality, scope,
  completeness, and recording metadata.
- Two-run replay of identical executable input requiring byte-identical
  canonical transcripts; a difference is `unresolved` with a `replay_mismatch`
  finding and is never reported as success.
- `tests/native/fixtures/` positive/negative pairs for legal transfer/free in C
  and Rust, use-after-free, mutable alias, stale generation after reallocation,
  synchronous callback, deferred callback after free, data race, and an atomic
  control; plus seeded skipped-free, fictitious-completeness, nondeterministic
  pid/clock, and oversized-output controls.
- `tests/native.rs`: 17 tests. Without `FRF_NATIVE_HARNESS` they execute and
  assert the typed `NOT_RUN` path; with the flag they exercise the live path.
  None is ignored.
- `ci/native-gate.sh`: the same hardened container flags as `ci/gate.sh`, an
  in-container install of only `gcc` and `libc6-dev`, and the 17 live native
  tests.
- `docs/phase4-native.md`: isolation, provenance, replay rule, fixture legality,
  exact commands, claim ceiling, and citations.
- The non-default `native-harness` feature. Default builds compile no native
  execution code; only the gates enable it.

### Verification

- `cargo fmt --all -- --check`: clean
- `cargo clippy --all-targets --all-features -- -D warnings`: clean
- `cargo test --locked --all-targets --features native-harness`: 224 passed,
  0 failed, 0 ignored
- `cargo test --locked --release --features native-harness`: 224 passed,
  0 failed, 0 ignored
- `ci/native-gate.sh`: 17 live native tests passed, 0 failed, 0 ignored
- `cargo publish --dry-run --locked`: packaged without `research/`, `target/`,
  `.git/`, or credentials

## [0.4.0] - 2026-10-18

Phase 3.1: conservative, syntax-only Rust source inventory. Phase 3.2: finite
explicit-input path effects and qualified outcomes. Phase 3.3: optional pinned
MIR text observations with honest `NOT_RUN`.

### Added

- `src/source.rs`: bounded `syn` 2.0.119 (`full`, `visit`) AST inventory for
  unsafe blocks/functions/impls/traits, `extern` blocks and FFI declarations and
  name-matched calls, export/link attributes, raw-pointer types and operations,
  `transmute`, unions, `MaybeUninit`/`UnsafeCell`/`NonNull`, allocation and
  ownership calls, unresolved calls/methods/closures/callback candidates,
  `cfg`/feature evidence, and `build.rs`/`Cargo.toml` build evidence.
- File, byte, line, and column spans plus per-file and per-finding SHA-256
  digests, deterministic ordering, and canonical
  `frf-memorysafety.source-inventory.v1` JSON.
- Hard limits for file bytes, file count, total bytes, syntax nodes, findings,
  and unknowns; explicit invalid-UTF-8 rejection; symlinks are never followed.
- `source scan PATH [--json]` with SPEC §14 exit statuses and capability/version
  updates.
- `tests/source_inventory.rs` fixtures for safe/unsafe/FFI/callback/cfg input,
  allocations, malformed input, invalid UTF-8, every resource limit, symlink
  escape, non-UTF-8 paths, deterministic canonical output, and CLI statuses.
- `docs/phase3-source-inventory.md` with the claim ceiling, §12.4 distinction,
  limits, and authoritative citations.
- `src/path_effect.rs`: typed explicit-input model for exact-object,
  descendant/subrange, shared-mapping, and top/unknown aliases; exact,
  descendant, and top footprints; reference intervals over explicit program
  points; creation, reborrow, escape, callback, free, and use events.
- Typed `observed_conflict`, `omission`, `not_falsified`, and
  `compatible_within_finite_footprint` outcomes with event evidence and
  explicit unknowns. The distinctions are never collapsed into a boolean.
- C callback qualification for legal synchronous callbacks, retained/escaped
  pointers, deferred callbacks, callback-after-free, and foreign/provider
  dynamic dispatch. Foreign behavior is never promoted to safe or unsafe.
- `path analyze FILE [--json]`, consuming either explicit
  `frf-memorysafety.path-effects-input.v1` JSON or a Phase 3.1 source inventory,
  with deterministic `frf-memorysafety.path-effects-report.v1` canonical JSON
  and SPEC §14 exit statuses.
- `tests/path_effects.rs`: exact-vs-descendant, descendant-vs-top, wrong
  shared-mapping, omitted-alias, benign `UnsafeCell`, independent-allocation,
  synchronous/retained/deferred/after-free callback, foreign/provider,
  reference-interval, §12.4 omission-vs-not-falsified, inventory-adapter, CLI,
  and canonical-determinism controls. No test is ignored.
- `docs/phase3-path-effects.md` with the model, event/footprint algebra,
  qualification rules, seal controls, claim ceiling, and authoritative
  citations.
- `src/mir.rs`: optional MIR adapter pinned to `nightly-2025-02-20` (the stable
  `1.85.0` release date). It invokes `rustup run <toolchain> rustc --edition
  2021 -Zunpretty=mir --crate-type=lib FILE` with explicit argv and no shell,
  a private `0700` temporary working directory, null stdin, bounded
  stdout/stderr, a bounded timeout, and hard source/observation limits.
- Conservative MIR text parsing for function definitions, basic blocks,
  unresolved call edges (plain, qualified/trait, and indirect), dereference
  projections, storage/lifetime markers, drop/free-like calls, and explicit
  unknown constructs. Same-name local definitions are name coincidences, not
  resolution; foreign/provider/trait/indirect uncertainty is retained.
- Typed `NOT_RUN` reasons (`rustup` missing, toolchain unavailable, timeout,
  output bound exceeded, invocation failure) and SPEC §14 exit status 6, never a
  fabricated observation.
- `mir scan FILE [--json] [--toolchain NAME]` with canonical
  `frf-memorysafety.mir-observation.v1` or
  `frf-memorysafety.mir-not-run.v1` JSON.
- `ci/mir-gate.sh`: same hardened container flags, minimal pinned nightly
  installation/use, adapter run against a fixture crate, `PASS` on a live
  observation, and `NOT_RUN` exit 6 when unavailable. It is separate from the
  default gate.
- Checked-in MIR text and source fixtures plus 13 new tests (6 unit in
  `src/mir.rs`, 7 integration in `tests/mir.rs`), including live-or-`NOT_RUN`,
  missing-`rustup`, source/call/function/unknown bound, canonical determinism,
  and CLI status controls. No test is ignored.
- `docs/phase3-mir.md` with the toolchain pin, exact invocation, parsed subset,
  known `-Zunpretty=mir` instability, claim ceiling, gate result, and
  authoritative citations.
- 13 new MIR tests, for 168 total in debug and release.

### Claim ceiling

The source inventory is syntactic only. It is not a caller graph, alias
analysis, footprint model, whole-program inventory, or memory-safety result.
Unresolved calls, callback registrations, macro-generated code, external module
bodies, and foreign dispatch remain explicit unknowns.

The path-effect model is finite and explicit-input only. It does not extract
aliases, footprints, or intervals from source or MIR; does not observe native
callback registration, invocation, retention, or after-free use; does not model
concurrency or synchronization; and does not establish whole-program closure.
`compatible_within_finite_footprint` is not universal alias compatibility, and
`not_falsified` is not a weak compatibility result.

The MIR adapter observes only the human-readable, unstable
`-Zunpretty=mir` text. It does not resolve symbols, types, traits, generics,
macros, external crates, aliases, provenance, reference intervals, or
monomorphized instances, and does not establish a caller graph or whole-program
closure. Every call edge is unresolved. The pin makes a run reproducible for
that exact toolchain, not the format stable. When the toolchain is absent the
capability is `NOT_RUN` (exit 6), not an empty successful scan. Native
observation remains unimplemented.

## [0.3.0] - 2026-10-17

Phase 2: founded support, exact cuts, policy custody, independent conformance,
paper §12.4 replay, and CLI policy checks.

### Added

- Rule-boundary exact cuts (`remove_rule`), including alternative-route,
  wrong-premise-set, and unrelated-claim regression tests.
- `HistoricVerdict::record` and `HistoricVerdict::verify`, which bind a verdict
  to its policy identity, version, digest, exclusions, and result, and reject
  policy substitution, result tampering, and digest tampering on replay.
- `NonInterferenceReport` with lost, gained, retained, and withheld claims and a
  surviving certificate for each retained claim.
- Nine §12.4 coverage/policy/support conformance cases transcribed from the
  paper's original `acceptance_cases.py` fixtures, with exact expected outcomes.
- Mutant courts for the wrong greatest fixed point, hidden intermediates, shared
  mappings, changed policies, and implicit leaves, each with a positive control.
- An independently written fixed-point, certificate, and exact-cut oracle in
  `tests/support_oracle/`, plus a differential campaign over 110,592
  configurations: 331,776 all-node certificate comparisons and 331,776 all-node
  exact-cut comparisons.
- Paper-corpus alignment for the 17,712 exact-revocation-cut definition,
  165,888 single-revocation monotonicity relations, and 20,878 optimistic-mutant
  differences.
- CLI policy custody for `support evaluate` and `support explain`:
  `--policy POLICY_FILE`, `--expect-policy-digest MS1_ID`, and
  `--expect-policy-version VERSION`, with SPEC §14 exit statuses.
- `docs/phase2-alignment.md` (requirement matrix and sources) and
  `docs/phase2-conformance.md` (tested domain, methodology, claim ceiling).
- `CHANGELOG.md`.

### Changed

- Leaf admission is now consistently a nullary justification in both evaluation
  and certificate views; an admitted leaf that also has non-nullary rules keeps
  its singleton certificate.
- All-node certificates are minimal, include every intermediate node and the
  conclusion, and agree with evaluation.
- Support verdicts are policy-versioned; reconstruction under a different policy
  is detectable rather than accepted from the caller.
- The conformance suite executes rather than being ignored, and the crate reports
  114 tests in both debug and release.

### Fixed

- Positive and admissible fixed points now distinguish challenged premises
  without discarding positive derivation history.
- Ungrounded cycles derive nothing, and unadmitted empty rules derive nothing.

### Claim ceiling

Within the enumerated finite domain only, the shipped evaluator, certificate
enumerator, exact-cut predicate, and verdict-state function agree with a
separately coded oracle. This is a differential consistency result, not a proof
of `SPEC.md`, native Rust, real FFI graphs, detector sensitivity, or universal
soundness. Historical verdicts and CLI policy custody are digest-bound and
replay-bound, not authenticated. Universal safe-interior soundness and
`SAFE_COMPATIBLE` remain withheld and are reported as `WITHHELD_NOT_RUN`.

## [0.2.0] - 2026-10-17

Phase 1: strict encoding, typed evidence, finite profile, deterministic local
model, and the manual CLI.

### Added

- Strict `ms-canonical-json-v1` parsing and encoding with duplicate-key, float,
  trailing-byte, UTF-8, and six resource-limit checks.
- Domain-separated `ms1-` SHA-256 identities over twelve identity domains.
- Typed claims, scope anchors, execution modes, epistemic statuses, hazards,
  obligations, detector outcomes, and opaque external FRF, FRF-Fuzz, and Gemel
  identifiers.
- Least-fixed-point positive and admissible support with explicit leaf
  admission, challenged premises, certificates, node cuts, incremental
  revocation, and noninterference witnesses.
- A finite three-rule profile with exact enumeration, subset restriction, and
  same-domain conjunction, plus nine named refusal checks.
- A deterministic local buffer model with 24 records (8 scenarios each for
  C0/C1/C2) and 5 requested claims per variant.
- An evaluator that replays each local-model case against the crate's own
  reconstruction, so fabricated outcomes and their honestly rehashed
  observations are refused.
- A separately written Rust replay of the original eight-case domain in
  `tests/original_domain_replay.rs`.
- A manual CLI without `clap` or shell execution, with SPEC §14 exit statuses and
  explicit `NOT_RUN` responses for unavailable external integrations.
- The OOM-capped `rust:1.85.0-slim` Docker gate (`./ci/gate.sh`) covering
  formatting, clippy, debug tests, and release tests.

### Claim ceiling

Phase 1 records and checks finite evidence and a deterministic local model. It
performs no native execution, no live Miri/sanitizer/Kani/Loom run, no live FRF
court, FRF-Fuzz, or Gemel run, and no universal safe-interior acceptance.
