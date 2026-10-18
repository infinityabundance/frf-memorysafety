# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This crate is assurance *bookkeeping*: it records, checks, and replays finite
evidence, support derivations, and policy-bound verdicts. It does not establish
universal memory-safety soundness, and no release below makes such a claim.

## [1.0.0] - 2026-10-18

Phase 9 publication release. This is a version and documentation release: it
changes no analysis semantics, evidence rule, or measured observation. It
promotes the crate to 1.0.0, publishes the pre-registered Phase 9 evaluation,
and adds the evaluation and independent-reconstruction gates. The 60 committed
receipts remain the measured 0.9.0 artifacts; a fresh 1.0.0 evaluation run is
deterministic-identical on observation, digest, and experiment fields (resource
measurements and the crate-version environment string may differ).

### Added

- Phase 9 pre-registration in [`evaluation/PRE-REGISTRATION.md`](evaluation/PRE-REGISTRATION.md)
  and the frozen machine-readable [`evaluation/protocol.json`](evaluation/protocol.json)
  (`phase9.1-v1`, SHA-256
  `02deb982c61c2a8307dbf3d34cf90f5aeb367e9ea7b1d794314aea9dd094d5ce`),
  fixing hypotheses, metrics, thresholds, ablations, the held-out rule, blocked
  controls, resource accounting, and the claim-to-receipt rule before
  measurement.
- The isolated `frf-eval` harness (`src/evaluation.rs`, `src/bin/frf-eval.rs`):
  31 cases and 60 `(case, arm)` receipts (20 held-out, 11 development), six
  hypotheses, canonical receipts with wall time, peak RSS, output size,
  input/observation/stdout/stderr digests, crate and `rustc` versions, image
  identity, and the exact command; it refuses receipts without a required
  measurement.
- [`PAPER.md`](PAPER.md), the reproducible technical paper, and
  [`evaluation/CLAIMS.json`](evaluation/CLAIMS.json), the 18-claim ledger with
  receipt ids, expected direction/threshold, observed values, and status.
- [`evaluation/LIMITATIONS.md`](evaluation/LIMITATIONS.md), the 18-entry
  limitations ledger, and [`evaluation/METHOD.md`](evaluation/METHOD.md), the
  methodology, measured tables, negative findings, and threats to validity.
- [`evaluation/reconstruct.py`](evaluation/reconstruct.py), an independent
  Python standard-library reconstructor that does not import or execute the
  crate, plus [`ci/reconstruction-gate.sh`](ci/reconstruction-gate.sh) running
  it in hardened, network-disabled `python:3.11-slim` with a 512 MiB
  memory/swap cap.
- [`ci/eval-gate.sh`](ci/eval-gate.sh), which runs the harness, verifies all 60
  fresh receipts and the committed receipts, and compares their deterministic
  fields; and [`tests/paper.rs`](tests/paper.rs), which fails when a paper claim
  has no receipt mapping.

### Changed

- Version is 1.0.0 and `Cargo.lock` records 1.0.0; no dependency changed.
- The committed receipts continue to record the crate version under which they
  were measured (`0.9.0`); the 1.0.0 evaluation gate verifies them and compares
  a fresh 1.0.0 run on deterministic fields.
- `./ci/gate.sh` executes 351 tests (0 failed, 0 ignored) in both debug and
  release, including the Phase 9 evaluation and paper tests and the live
  mechanisms' typed `NOT_RUN` paths. The results are recorded in README.
- README status, capability matrix, verification commands, gate inventory, and
  the limitations-ledger link are updated for 1.0.0.

### Fixed

- `ci/bridge-gate.sh` now exposes the pinned Python image's interpreter at
  `/usr/bin/python3` in the golden-demo stage. FRF runs extension programs with
  its declared minimal environment (`PATH=/usr/bin:/bin`), while the official
  `python:3.11-slim` image installs the interpreter under `/usr/local/bin`;
  without the link the witness extension exited 127. No container cap or FRF
  check is changed.
- `ci/bridge-gate.sh` now fails the gate when the FRF golden demo fails. It
  previously printed `FRF_GOLDEN=FAIL` but still exited 0 because the failure
  was handled inside the container script.

### Programme 0.2.0 -> 1.0.0

- **0.2.0 (Phase 1):** strict `ms-canonical-json-v1`, domain-separated
  identities, typed evidence, least-fixed-point support, finite profile and
  local model, manual CLI, and the first hardened Docker gate.
- **0.3.0 (Phase 2):** exact cuts, policy custody and historical verdicts,
  noninterference, paper §12.4 replay, and differential conformance against a
  separately coded oracle over 110,592 configurations.
- **0.4.0 (Phase 3):** bounded `syn` source inventory, finite path effects,
  aliases/footprints/reference intervals, and the optional pinned MIR adapter.
- **0.5.0 (Phase 4):** responsibility tokens and race semantics, transcript
  verification, and the test-only isolated native record/replay harness.
- **0.6.0 (Phase 5):** typed detector evidence, calibration refusal rules, and
  opt-in live adapters over a closed checked-in fixture registry.
- **0.7.0 (Phase 6):** proof manifests, theorem/assumption closure, admission
  taxonomy, Rust/FFI correspondence evidence, and the live pinned Coq adapter
  with six seal cases.
- **0.8.0 (Phase 7):** exact FRF/FRF-Fuzz/Gemel contracts, opaque provider
  identities, a fail-closed custody pipeline, and the live
  `FRF-Fuzz -> FRF -> Gemel` chain with six seals.
- **0.9.0 (Phase 8):** pinned OpenSSL-Rust Safe-33 candidate, the real
  `up_ref` overflow witness and repair, a curl 8.22.0 TLS 1.3 workload, a
  6499/0 loader closure, and typed live capture/reuse/revocation.
- **1.0.0 (Phase 9):** pre-registered finite evaluation, paper, claim and
  limitations ledgers, independent reconstruction, and release packaging.

### Claim ceiling

Version 1.0.0 does not widen any claim. All positive results remain limited to
the named finite, explicit-input corpora and the checks actually executed. The
Phase 9 measurements are exact for this pre-registered 31-case, 60-receipt
control family and are not population inference, defect recall, detector
sensitivity/specificity, verification-cost prediction, or evidence of
whole-program behaviour. The same-repository oracle result is differential
consistency, not a proof of `SPEC.md`. Provenance and verdict custody are
digest- and replay-bound, not authenticated; there is no signature, transparency
log, or trusted build root. The live Coq result covers only the checked-in small
finite two-claim support fixed-point theorem; manifest parsing is never proof
acceptance. MIR coverage is a conservative text subset, not a caller graph or
whole-program closure. The Phase 7 chain records real provider executions and
loader maps but does not authenticate provenance. Phase 8 covers one
`up_ref` owner/refcount boundary, one compatible repair, one curl 8.22.0 TLS
1.3 workflow, and one candidate loader closure; the target ledger remains
**0/33** `SAFE_COMPATIBLE`. No memory-safety, compatibility,
`SAFE_COMPATIBLE`, universal safe-interior, or organic-vulnerability claim is
made. Live Miri/Miri-class evaluation arms, live Coq evaluation arms, and an
authentic native-chain evaluation arm remain typed `NOT_RUN` in the default
evaluation image.

## [0.9.0] - 2026-10-18

Phase 8: pinned OpenSSL-Rust Safe-33 conversion evidence, a live
refcount-overflow witness, a compatible repair, a real consumer workload, and
an ABI loader proof. The pinned `openssl-rs` candidate builds under a 4g hard
cap; `ci/conversion-gate.sh` runs the owner/allocator/callback boundary tests,
reproduces the `up_ref` overflow fault and its `checked_add` repair, builds and
runs unmodified curl 8.22.0 against the candidate prefix with TLS 1.3
positive/negative cases, captures the candidate loader closure, and feeds the
exact files through a typed live-capture model.

**Declared scope only:** one `up_ref` owner/refcount boundary, one compatible
repair, one curl 8.22.0 TLS 1.3 workflow, and one candidate loader closure. The
witness is not an organic vulnerability discovery (the target's own repair
commit records the defect), and this release makes no all-33-consumer,
compatibility, memory-safety, or `SAFE_COMPATIBLE` claim.

### Added

- Pinned `infinityabundance/openssl-rs` Safe-33 candidate
  (`integrate/safe-c33` at `56ba894594ed3df0fdf117a15747d205b4f0ecd9`, tree
  `b54cc2b96d0e12af4a534d9237aadbe089b38660`, `openssl-rs 0.0.27`) with exact
  source-manifest, owner/refcount, allocator, callback, and alias boundary
  cases recorded in `docs/phase8-conversion-discovery.md`.
- Live refcount-overflow witness: the fault revision `28c9e34` panics with
  `attempt to add with overflow` when checks are on and silently wraps a live
  `i32::MAX` count to `count=-2147483648` (`answer=1`) when checks are off; the
  independently captured mechanism pair is `mechanism.txt`.
- Compatible repair `1d9c335`: `up_ref` uses `checked_add`, passes the overflow
  test with compiler checks on and off, and preserves the positive-count answer.
- Live consumer workflow: unmodified curl 8.22.0 built against the candidate
  prefix, verified TLS 1.3 fetch (`exit=0`, `http_code=200`,
  `ssl_verify_result=0`) and unrelated-CA rejection (`exit=60`, `http_code=000`,
  `ssl_verify_result=20`), with `ldd`/`LD_DEBUG` resolution under the candidate.
- ABI loader proof: Phase-2 `ABI-LOAD` reports libcrypto `5896/5896`, libssl
  `603/603`, **6499 resolved, 0 unresolved**; `ABI-DYNAMIC`, `ABI-SUBSTITUTION`,
  and contamination courts pass, and both candidate DSO digests are recomputed
  from exact bytes.
- Live conversion capture (`capture_live`, `capture_live_from_env`) that
  computes source, DSO, tool, loader, mechanism, and dependency digests from
  exact files, requires authentic-native provenance, and returns typed
  `NOT_RUN` without `FRF_CONVERSION_CAPTURE`.
- `ci/conversion-gate.sh` and its fixtures: the real `up_ref` fault/repaired
  witness, the curl TLS 1.3 workload, the Phase-2 loader courts, and the
  live-capture/reuse test, all under a hard 4g memory/swap cap.

### Changed

- Evidence reuse now also revokes on witness provenance, command, output,
  mechanism, and DSO-byte changes, in addition to property, candidate,
  boundary, dependency, tool, loader, and revision changes.
- `./ci/gate.sh` now runs 341 tests; the 30 conversion-court tests include the
  live-capture and revocation cases and execute the typed `NOT_RUN` path
  without the external repository.

## [0.8.0] - 2026-10-18

Phase 7: pinned native provider contracts, opaque external identities, a
fail-closed custody pipeline, and a live FRF-Fuzz -> FRF -> Gemel chain.
**Phase 7 is complete for the defined chain:** the pinned `rust:1.98-slim` +
`nightly-2026-07-24` image unblocks FRF-Fuzz, and `ci/bridge-gate.sh` produces
a real candidate-bound chain with exact replay, actual loader-map closure, two
independent runs per provider, and six PASS seals. The default `ci/gate.sh`
remains on `rust:1.85.0-slim` and asserts typed `NOT_RUN` without the external
tools. No OpenReceipt, finding, GCE object, or GID is written by this crate.

### Added

- Exact pinned native contracts for `infinityabundance/frf`
  (`ce461ce311bfe10fe90d2be03fba6217a6e8ba28`, `frf-receipt-v20`),
  `infinityabundance/frf-fuzz`
  (`054b45cda974852ccce62bc14dbeacb5fef0336b`, `FRFZ` family `0x02`,
  framing `0.1`), and `infinityabundance/gemel`
  (`54fc581bff09e67b9d4cc533d157a8c9fc575424`, `gemel.evidence.v1`/GCE
  family `0x0B`), including repository, branch, license, schema token, build
  command, and executable digest.
- Provider-typed opaque identities (`BridgeFrfReceiptId`,
  `BridgeFrfFuzzFindingId`, `BridgeGemelGceId`) with private fields and no
  public string constructor. Admission requires exact bytes, provider pin,
  schema token, identity form, and digest; identity strings cannot be
  synthesized by callers.
- Custody pipeline with explicit stages `Discover`, `Reconstruct`,
  `NativeConfirm`, `FrfReceipt`, and `GemelCustody`, and typed outcomes
  `Complete`, `NotRun`, `Refused`, and `Integrity`. Refusal reasons include
  modeled/modified/substitute evidence, stale candidate, and substituted DSO;
  integrity reasons include schema, digest, candidate binding, and
  re-execution mismatch. `authentic_native_identities` is zero on every
  non-`Complete` outcome and `generated_identities` is always zero.
- Provenance and capture records: `EvidenceProvenance` distinguishes
  `AuthenticNative`, `ModifiedProvider`, `Substitute`, and `Modeled`;
  `DsoBinding` distinguishes `Native`, `Substituted`, and `Unknown`;
  `Reexecution` records `Matched`, `Mismatch`, or `NotRun`.
- `bridge capture OUT ...`: live capture of exact provider bytes, executable
  digests, repository/commit pins, candidate binding, actual
  `/proc/self/maps` closures with recomputed hashes, and two independent
  executions per provider. `bridge verify FILE [--json] [--candidate SHA256]`
  validates a supplied bundle without executing a provider; `bridge status
  [--json]` reports pins and executable availability.
- Independent re-execution: two `RunRecord`s (exit, stdout SHA-256, stderr
  SHA-256) per provider, required to be byte-identical; the FRF exact replay
  reproduces both sides with matching residual fingerprints.
- DSO closure from the provider's actual loader map, with every file-backed
  object re-hashed, sorted by path, and reduced to a closure SHA-256; the probe
  and main executable are excluded.
- Seal controls for stale candidates, tampered candidates, substituted DSOs,
  re-execution mismatches, and tampered finding objects. Every failure exits
  with its typed status (3 or 4), reports zero authentic native identities,
  and generates no external identity.
- Real live chain in `ci/bridge-gate.sh`: FRF-Fuzz finding
  `9eea34004a284cdeacf1633253ccd0ce342b53e02c9347d884a9c075e6a1fb34`,
  FRF receipt
  `receipt-run-frf-fuzz-4f775512ad38df0305be933b1238e0d6f4743ab45eff5e470852aa62d70aa2f2-debbf82bbc86f0cbc7b348525dc2f98c9ccd873147bab0ad6d901640f5e1dccb`,
  Gemel GID
  `evidence.2cae082c010569b59a7bcff46a70f6cb69fec46a30d1701561f36f4a8c091ae9`,
  and candidate
  `b594c294f4d34d28c34b018f9bb5e07c449a3bb8dc3d4b55b4a118608d93acbf`;
  6 of 6 seals PASS.
- Checked-in `ci/fixtures/bridge_abort_target.rs` deterministic FRF-Fuzz
  target, `dso_probe.c` loader-map probe, and `dso_substitute.c` control.
- `ci/bridge-gate.sh`, a hardened external-tool gate with stages A-D that
  builds the three pinned providers, runs the fixed-seed bounded campaign,
  executes the live chain, and exercises all seals. `tests/bridge_live.rs`
  requires `Complete` with `FRF_BRIDGE_LIVE_BUNDLE` or asserts typed `NOT_RUN`
  without it; no test is `#[ignore]`d.
- `docs/phase7-bridge-discovery.md` and `docs/phase7-live-chain.md` with exact
  repositories/commits, schemas, images/toolchains, commands, IDs, closure
  hashes, seal results, and the claim ceiling.

### Changed

- The FRF-Fuzz provider pin records the real build: `fa45c704d804...` in
  `rust:1.98-slim`; FRF is `0728aac10c...` and Gemel `01b7f4cc22...`.
- `authentic_native_identities` is zero on every non-`Complete` outcome.
- Gemel admission requires the GCE's own subject (field `0x03`) to match the
  retained receipt and the result outcome to be `pass`.
- The FRF-Fuzz finding input SHA-256 must be an FRF receipt fixture hash.
- Live capture without an executable digest, loader closure, or two-run record
  is `Integrity::MissingLiveCapture` for an `AuthenticNative` observation.

### Known limitations

- Provenance is a recorded, digest-checked execution record, not a signature,
  transparency log, or trusted build root; the bridge does not authenticate
  `authentic_native` provenance.
- A modified DSO placed in the provider executable's own directory would pass
  the path-based binding rule; the seal exercises an out-of-tree preload.
- Full FRF semantic and Gemel full-schema conformance remain capped at the
  bridge's checked subset.
- The abort fixture is a deterministic custody-chain fixture, not evidence of
  a real memory-safety defect.

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
