# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This crate is assurance *bookkeeping*: it records, checks, and replays finite
evidence, support derivations, and policy-bound verdicts. It does not establish
universal memory-safety soundness, and no release below makes such a claim.

## [Unreleased]

No unreleased changes.

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
