# Phase 7.2: live native chain and seals

Snapshot: `staging` after the Phase 7.1 bridge foundation, crate
`frf-memorysafety 0.7.0`, no version bump. Phase 7.2 unblocks pinned FRF-Fuzz,
runs a real fixed-seed campaign, produces a real native chain

```text
FRF-Fuzz finding -> FRF court/exact replay/OpenReceipt -> Gemel evidence/GID
```

and binds the whole chain to one candidate artifact. The default project gate
remains `rust:1.85.0-slim`; the external-tool gate is `ci/bridge-gate.sh`.
**Phase 7 is complete for this defined chain.** The claim ceiling in §10 still
applies.

## 1. Images and toolchains

All runs used the same hard limits as `ci/gate.sh`:

```text
--memory=2g --memory-swap=2g --pids-limit=512 --cpus=2
--ulimit nofile=1024:1024 --oom-score-adj=500
--cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER
--security-opt no-new-privileges
```

| Role | Image | Image ID | Repo digest |
|---|---|---|---|
| FRF-Fuzz coordinator + fixture campaign + live chain | `rust:1.98-slim` | `sha256:3807bfc7862f0e7e5f64fb10278b09a0c150fb05329afdf1b4878820eef226b8` | `rust@sha256:4cd829461bd5c4d511c32e269da9cb8929223b666519d8004e35fc8d1d771ab7` |
| FRF, Gemel, this crate (project gate image) | `rust:1.85.0-slim` | `sha256:206360542a30ac87385638c1d123eae6cebcd9d8675d521bb80eac7f5820509b` | `rust@sha256:1829c432be4a592f3021501334d3fcca24f238432b13306a4e62669dec538e52` |
| FRF golden demo with `python3` | `orfs-go-court:local` (Debian 12, Python 3.11.2) | `sha256:1879a04711dd1810b820aac99687706cca6cc9b2606827f1e35a8cbc87b848a0` | local image, no repo digest |

Toolchain identities observed inside the containers:

```text
rust:1.98-slim:   rustc 1.98.1 (48a229cea 2026-09-01), cargo 1.98.1, LLVM 22.1.8
nightly:          rustc 1.99.0-nightly (89c61a754 2026-07-23), LLVM 22.1.8
rust:1.85.0-slim: rustc 1.85.0 (4d91de4e4 2025-02-17)
```

`ci/bridge-gate.sh` defaults to `python:3.11-slim` for the golden demo and
accepts `FRF_PYTHON_IMAGE`; the reported run used the local Debian 12 image
because the Docker data root was full. This changes only the Python
interpreter image, not the chain or the project gate.

## 2. Pinned externals and build results

| Provider | Repository | Pin | Build command | Executable SHA-256 |
|---|---|---|---|---|
| FRF-Fuzz | `https://github.com/infinityabundance/frf-fuzz` | `054b45cda974852ccce62bc14dbeacb5fef0336b` | `cargo build --release --locked --bin frf-fuzz` in `rust:1.98-slim` | `fa45c704d804146f069190e7d74b8f08e3e067a64c6253ae42c260fa2e700512` |
| FRF | `https://github.com/infinityabundance/frf` | `ce461ce311bfe10fe90d2be03fba6217a6e8ba28` | `cargo build --release --locked` in `rust:1.85.0-slim` | `0728aac10c4198717e04097201db55c2fbe3801e3917bc36160fc97da2a28f8b` |
| Gemel | `https://github.com/infinityabundance/gemel` | `54fc581bff09e67b9d4cc533d157a8c9fc575424` | `cargo build --release --locked` in `rust:1.85.0-slim` | `01b7f4cc2281a33dee3ecfe9a747845cef3a8b3c3a4c71078c3ecf8a29bf7696` |

The FRF and Gemel digests reproduce the Phase 7.1 digests exactly. The pinned
clones under `target/external/` were mounted read-only and never modified.

The FRF-Fuzz campaign target is the checked-in fixture
[`ci/fixtures/bridge_abort_target.rs`](../ci/fixtures/bridge_abort_target.rs)
(SHA-256 `19189754c726d4b455166a727427469bf3edf57c436bfb8e8f7e3460a151cd53`).
`ci/bridge-gate.sh` copies it into a writable copy of the pinned examples
directory and builds it with the pinned nightly and the exact flags:

```text
-Cpasses=sancov-module
-Cllvm-args=-sanitizer-coverage-level=4
-Cllvm-args=-sanitizer-coverage-inline-8bit-counters
-Cllvm-args=-sanitizer-coverage-pc-table
-Cllvm-args=-sanitizer-coverage-trace-compares
-Copt-level=3 -Cdebug-assertions=yes -Coverflow-checks=yes -Clto=off
```

The candidate (instrumented target) SHA-256 is
`b594c294f4d34d28c34b018f9bb5e07c449a3bb8dc3d4b55b4a118608d93acbf`.
The reference authority built from the same pinned `frf-fuzz` tree
(`golden_authority`) is `4445ce8a2f802788c3c3c89322e8e05d6698d62ef6c8c61d54d5e7eb89bc974b`.

The fixture is deliberately minimal and deterministic: an eight-byte
const-comparison gate aborts with `std::process::abort()` (signal 6, empty
stdout and stderr). That makes FRF's strict raw-outcome exact replay
byte-identical; a `panic!` target embeds a dynamic thread id in stderr and
cannot satisfy exact replay.

## 3. Real campaign

Command (fixed seed, bounded time, four workers, compare guidance on, residual
guidance off):

```sh
/work/coord-build/release/frf-fuzz run bridge-abort \
  --root /work/store \
  --bin /work/frf-build/x86_64-unknown-linux-gnu/debug/examples/bridge_abort_target \
  --workers 4 --batch-size 500 --seed 0xC0FFEE \
  --seed-dir /work/store/seeds --max-time 10 \
  --nightly nightly-2026-07-24 --residual off \
  --authority /work/frf-build/debug/examples/golden_authority \
  --authority-name bridge-ref --authority-version 1.0 --gemel off
```

The non-crashing seed is `BRIDGEFX0123456789`; the campaign discovers the
abort gate through the compare-guided dictionary. Reported run:

```text
executions: 93500
findings: 27
FRF verifications: 10 verified: 10 failed: 0
first failure executions: 5000
first failure seconds: 1.401
duration: 10.7s
```

The gate selects the first `FRF VERIFIED finding=` line and binds exactly that
finding. A rerun can select a different finding if scheduling reorders
discoveries; every selection goes through the same byte, schema, candidate,
replay, closure, and re-execution checks.

## 4. The real chain

Selected finding (raw `FRFZ` family `0x02`, framing `0.1`, payload v1,
105 bytes):

```text
finding id (BLAKE3-256 of framed bytes):
9eea34004a284cdeacf1633253ccd0ce342b53e02c9347d884a9c075e6a1fb34
input (26 bytes): BRIDGEFEBRIDGEFX0123456789
input SHA-256:   1e73c476bec1fb615d80701a35899003fa9716da9179700d230e98ff80682898
replay byte:     1 (reproduced)
```

FRF court/receipt (canonical `frf-receipt-v20` JSON, 6620 bytes, SHA-256
`debbf82bbc86f0cbc7b348525dc2f98c9ccd873147bab0ad6d901640f5e1dccb`):

```text
run:       run-frf-fuzz-4f775512ad38df0305be933b1238e0d6f4743ab45eff5e470852aa62d70aa2f2
receipt:   receipt-run-frf-fuzz-4f775512ad38df0305be933b1238e0d6f4743ab45eff5e470852aa62d70aa2f2-debbf82bbc86f0cbc7b348525dc2f98c9ccd873147bab0ad6d901640f5e1dccb
candidate: b594c294f4d34d28c34b018f9bb5e07c449a3bb8dc3d4b55b4a118608d93acbf
fixture:   1e73c476bec1fb615d80701a35899003fa9716da9179700d230e98ff80682898
```

The receipt's exit observable is a residual (`reference=0`,
`candidate=signal(6)`); the stderr-first-line observable passes (both empty).
The bridge independently checks that the finding input SHA-256 is an FRF
receipt fixture hash, that the receipt's `run` is the replayed run, and that
the receipt's `candidate.identity_hash` is the captured candidate.

Gemel evidence (`gemel.evidence.v1`, ingested by the pinned `gemel 0.12.0`
executable; the GCE is 493 bytes):

```text
producer:  producer.80c4eea0cf4677bb581849efa8ccb89378daefc9bdbd694aa723f818d4953029
kind:      court_receipt
subject:   receipt-run-frf-fuzz-4f775512ad38df0305be933b1238e0d6f4743ab45eff5e470852aa62d70aa2f2-debbf82bbc86f0cbc7b348525dc2f98c9ccd873147bab0ad6d901640f5e1dccb
command:   frf --root /work/store/.frf-fuzz/frf-root replay run-frf-fuzz-4f775512ad38df0305be933b1238e0d6f4743ab45eff5e470852aa62d70aa2f2 --policy exact
tools:     frf 0.1.86 (0728aac10c...), frf-fuzz 0.8.3 (fa45c704d8...)
result:    pass, exit 0
GID:       evidence.2cae082c010569b59a7bcff46a70f6cb69fec46a30d1701561f36f4a8c091ae9
```

Ingestion was run twice and returned the same GID (`executed: false`), so the
evidence object is idempotent and provider-produced. Gemel does not execute the
recorded command.

## 5. Exact replay

`frf replay <run> --policy exact` was executed twice by the bridge capture,
with the FRF store's recorded working directory. Both runs exited 0 and their
stdout/stderr were byte-identical:

```text
replay (exact) run-frf-fuzz-4f775512ad38df0305be933b1238e0d6f4743ab45eff5e470852aa62d70aa2f2:
  reproduced — sides byte-identical, 1 residual(s) with matching fingerprints
replay_verified: yes
```

The bridge records two `RunRecord`s per provider (exit, stdout SHA-256, stderr
SHA-256) and requires equality. Reported outcomes: candidate exit 134 with
empty streams; FRF replay exit 0; Gemel ingest exit 0. All three pairs are
byte-identical.

## 6. Live capture and the actual DSO closure

`bridge capture` records:

* the exact provider executable paths and recomputed SHA-256 values;
* the provider repository/commit pins and schema tokens;
* the exact candidate SHA-256;
* two independent executions per provider;
* the file-backed objects in the provider's actual loader map, with each
  file's SHA-256 recomputed, sorted by path, and a closure SHA-256;
* the derived `native` / `substituted` binding.

The loader maps were captured by preloading
[`ci/fixtures/dso_probe.c`](../ci/fixtures/dso_probe.c) (SHA-256
`4b25adf7e07ca54b224c81f4b4c5022dbca969d038cffd15996861e691f403cb`), whose
constructor copies `/proc/self/maps`. The probe itself and the main executable
are excluded from the recorded closure.

Observed clean closures (all paths under `/usr/lib/x86_64-linux-gnu`):

| Provider | Closure entries | Closure SHA-256 |
|---|---|---|
| `frf-fuzz` | `libc`, `libgcc_s`, `libm`, `ld-linux` | `0a0391f4d86229321075170c77a263ea5c0503f828829cacf2207ac50f1a5a0d` |
| `frf` | `libc`, `libgcc_s`, `ld-linux` | `265946b5ca1b13f7b2a4dc425c8faa72eb86c8435123e3bdab7760796b62b816` |
| `gemel` | `libc`, `libgcc_s`, `libm`, `ld-linux` | `0a0391f4d86229321075170c77a263ea5c0503f828829cacf2207ac50f1a5a0d` |

The verifier re-hashes every closure path, rederives the closure digest,
rederives the binding from the paths, and refuses a mismatch. A modified
out-of-tree DSO preloaded into Gemel (`libsubstitute.so`, SHA-256
`ba75935049d0f88a28374c7280ded72b3eef8515956a2d77d924f0a005d2302b`) appears in
the actual map (44 lines versus 39 clean) and is classified `substituted`.

## 7. Gate and seal results

`ci/bridge-gate.sh` runs stages A-D under the hard limits above. Reported run:

```text
== A coordinator ==    rustc 1.98.1; frf-fuzz fa45c704d804...
== B campaign ==       nightly 1.99.0-nightly (89c61a754); 10/10 verifications
== C build ==          frf 0728aac10c..., gemel 01b7f4cc22..., bridge e899a50f02...
== C2 golden demo ==   python 3.11.2; FRF_GOLDEN=PASS
== D chain ==          verify stage=gemel_custody authentic_native=3 generated=0
                       status all_live_available=true
                       TEST PASS bridge_live
```

| Seal | Expected | Observed | Result |
|---|---|---|---|
| independent re-execution (2 runs/provider) | byte-identical | all 3 pairs identical | PASS |
| stale candidate | `Refused::StaleCandidate`, exit 4 | exit 4, authentic_native 0 | PASS |
| tampered candidate | `Integrity::CandidateBindingMismatch`, exit 3 | exit 3, authentic_native 0 | PASS |
| substituted DSO (actual loader map) | `Refused::SubstitutedDso`, exit 4 | exit 4, authentic_native 0 | PASS |
| recorded re-execution mismatch | `Integrity::ReexecutionMismatch`, exit 3 | exit 3, authentic_native 0 | PASS |
| tampered finding object | `Integrity::DigestMismatch`, exit 3 | exit 3, authentic_native 0 | PASS |

```text
SEALS pass=6 fail=0 not_run=0
```

The default `./ci/gate.sh` does not run the external tools. It executes
`tests/bridge_live.rs`, which asserts the typed
`NotRun::MissingFinding` (exit 6) and `BridgeStatus` exit 6 when
`FRF_BRIDGE_LIVE_BUNDLE` is unset. No test is `#[ignore]`d. With the variable
set, the same test requires `Complete`, `GemelCustody`, three authentic native
identities, zero generated identities, and exit 0.

Default gate counts: 311 tests passed in debug and 311 in release (0 failed,
0 ignored), including the 17 bridge seal tests, 3 bridge unit tests, and the
live/`NOT_RUN` test. `cargo fmt` and `clippy -D warnings` are clean.

## 8. Schemas accepted

| Object | Exact form |
|---|---|
| FRF receipt | `frf-receipt-v20` canonical JSON; identity `receipt-{run}-{SHA-256}`; candidate `identity_hash`; fixture `hash` |
| FRF-Fuzz finding | `FRFZ` magic, family `0x02`, framing `0.1`, payload v1, BLAKE3-256 identity over the full frame |
| Gemel evidence | `GEML` encver `1`, family `0x0B`, schemever `1`, flags `0`; identity `evidence.{BLAKE3(envelope)}`; field `0x02` kind `court_receipt`, `0x03` subject, `0x0D` result outcome `pass` |

The bridge additionally requires the Gemel GCE's own subject (field `0x03`) to
equal the retained FRF receipt, not merely the observation's declared subject.

## 9. Bridge additions

* `bridge capture OUT ...` performs the live capture described above. It
  derives identities from exact bytes and writes the bundle, then verifies it;
  it never writes an `OpenReceipt`, finding, GCE object, or GID.
* `ExternalObservation.capture` carries the executable path, actual closure,
  closure digest, and two-run re-execution record. Authentic observations
  without it are `Integrity::MissingLiveCapture`.
* `verify_live_capture` re-hashes the executable and every closure object,
  rederives the closure digest and binding, and requires two identical runs.
* The FRF-Fuzz finding input SHA-256 must appear in the FRF receipt fixtures
  (`Integrity::ChainMismatch` otherwise).
* The Gemel subject and `pass` outcome are decoded from the GCE itself.
* `authentic_native_identities` is zero on every non-Complete outcome.

## 10. Claim ceiling

Phase 7.2 establishes only:

* the three pinned repositories build in the stated images and toolchains;
* FRF-Fuzz runs a real, fixed-seed, bounded campaign and produces real
  findings and FRF court receipts;
* the selected finding, FRF receipt, and Gemel evidence are exact bytes with
  rederived identities, bound to one candidate;
* exact replay reproduces the observed sides byte-for-byte in the reported run;
* the loader closure is observed from the actual process map and re-hashed;
* the six seal controls fail closed with zero authentic identity on failure;
* the default gate still passes without the external tools and asserts typed
  `NOT_RUN`.

It does **not** establish:

* that `authentic_native` provenance is authenticated: capture is an execution
  record, not a signature, transparency log, or trusted build root;
* FRF semantic conformance beyond the bridge's checked subset;
* Gemel full-schema conformance beyond the checked evidence fields;
* detector sensitivity, memory-safety soundness, `SOUND_SAFE_INTERIOR`, or
  `SAFE_COMPATIBLE`;
* that the abort fixture represents a real memory-safety defect (it is a
  deterministic fixture for the custody chain).

A modified DSO placed beside the provider executable (same directory) would
satisfy the path-based binding rule; the seal exercises an out-of-tree preload.
This is a documented limitation of the capture policy, not a claim of
unforgeable provenance.

## 11. Blockers and environment notes

No Phase 7.2 blocker remains for the defined chain. Environment notes:

* The Docker data root on the test host was a full 26 GiB tmpfs. The gate
  reused the existing `frf-rustup` volume (which already contained
  `nightly-2026-07-24`) and the local `orfs-go-court:local` image for
  `python3`; the committed defaults are `frf-rustup` and `python:3.11-slim`.
  On a host with space, `ci/bridge-gate.sh` installs the pinned nightly and
  pulls the Python image.
* The `orfs-go-court:local` image is recorded by ID only (it has no repo
  digest). It is used only for the FRF golden demo.
* The FRF golden demo passed with Python 3.11.2 (previously `NOT_RUN` in the
  python-less 1.85 slim image).

## 12. Reproduction

```sh
./ci/gate.sh
FRF_RUSTUP_VOLUME=frf-rustup FRF_PYTHON_IMAGE=orfs-go-court:local ./ci/bridge-gate.sh
```

The live artifacts are under `target/external/bridge-gate/` (gitignored):
`bundle.json`, `report.json`, `verify.json`, `status.json`, the maps, the
Gemel repo, and the seal reports. Logs are in `target/gate-logs/`.

## 13. References

* `docs/phase7-bridge-discovery.md` — Phase 7.1 discovery, pins, identity
  boundary, and the original build blocker.
* `infinityabundance/frf` at `ce461ce...` — `src/commands/court.rs`,
  `src/commands/receipt.rs`, `src/commands/replay.rs`, `src/model.rs`.
* `infinityabundance/frf-fuzz` at `054b45c...` — `src/execute/finding.rs`,
  `src/canon.rs`, `src/frf_bridge.rs`, `src/cli.rs`, `examples/golden_demo.rs`.
* `infinityabundance/gemel` at `54fc581...` — `src/evidence.rs`,
  `src/spec.rs`, `src/store/objects.rs`, `src/hash.rs`.
* `ci/fixtures/bridge_abort_target.rs`, `ci/fixtures/dso_probe.c`,
  `ci/fixtures/dso_substitute.c`.
