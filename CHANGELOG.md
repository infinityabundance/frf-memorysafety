# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This crate is assurance *bookkeeping*: it records, checks, and replays finite
evidence, support derivations, and policy-bound verdicts. It does not establish
universal memory-safety soundness, and no release below makes such a claim.

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
