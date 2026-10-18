# Phase 5.2: live detectors with real capture

Snapshot: branch `staging`, crate `frf-memorysafety 0.6.0`.
This document describes the opt-in live adapters in
`src/detector/live.rs`, the checked-in fixtures under
`tests/detector/fixtures/`, the CLI
`detector calibrate --live --detector KIND [--json]`, and the separate
`ci/detector-gate.sh`. The Phase 5.1 receipt and adjudicator in
`src/detector/mod.rs` are unchanged; live adapters produce that exact shape from
real stdout/stderr.

## Scope and claim ceiling

Live execution is opt-in through `FRF_DETECTOR_LIVE=1`. Without it every live
request returns a typed `NOT_RUN` (exit 6). The adapters accept only a built-in
detector selector and a closed registry of checked-in fixtures. There is no API
or CLI path for caller-supplied source, an arbitrary executable, an arbitrary
input file, or a shell.

A live `CALIBRATED` report establishes only that, in this run:

* the named checked-in fixture was compiled and/or executed by the recorded
  tool identity;
* stdout and stderr were captured within the declared bounds and bound by
  SHA-256;
* a known-bad case produced the declared mechanism-specific diagnostic
  fingerprint with a nonzero exit;
* a harmless control produced no typed finding and exited zero; and
* the detector and baseline build identities are separate and structurally
  consistent.

It does **not** establish memory safety, Rust soundness, C object lifetime or
effective-type legality, universal detector sensitivity or specificity, coverage
of another input/flags/target/build, real-scheduler concurrency, native FFI
behavior, cryptographic constant-time behavior, or any `SAFE_COMPATIBLE`
result. A `NOT_RUN` response is not an empty successful calibration. The claim
is mechanism- and case-specific.

## Runtime availability

`capabilities --json` now includes a `detectors` array with one entry per
built-in mechanism. Availability is an installation observation, not a
sensitivity claim. The detector gate's runtime table is:

| Mechanism | Selector | Tool recorded in the gate | Status |
|---|---|---|---|
| Miri | `miri` | `miri 0.1.0 (f280acf4c7 2025-02-19)` on `nightly-2025-02-20` (rustc `1.87.0-nightly`) | PASS |
| AddressSanitizer | `asan` | `gcc (Debian 12.2.0-14) 12.2.0` | PASS |
| LeakSanitizer | `lsan` | `gcc (Debian 12.2.0-14) 12.2.0` | PASS |
| ThreadSanitizer | `tsan` | `gcc (Debian 12.2.0-14) 12.2.0` | PASS |
| loom | `loom` | `cargo 1.85.0`; `loom 0.7.2` | PASS |
| Kani | `kani` | `kani 0.60.0` with its bundled CBMC | PASS |
| OpenSSL known-answer | `crypto` | `OpenSSL 3.0.22` in the gate | PASS |

The `crypto` selector maps to the custom detector kind
`openssl-sha256-kat`, not to `CryptoSecretOracle`. A SHA-256 known-answer test
and a signature-verification sensitivity control do not measure constant-time
leakage, so labelling them `constant_time` would be dishonest. The mechanism is
recorded as `known_answer`.

If a tool is missing, the selected fixture or toolchain cannot be installed, a
network fetch is refused, a runtime cannot map its shadow memory, a process
times out, or a capture exceeds the byte bound, the adapter returns `NOT_RUN`
with the exact reason. The detector gate reports that mechanism as `NOT_RUN`;
it never converts it to PASS.

## Isolation and bounds

Every adapter uses the following controls. The container remains the outer
bound.

| Control | Implementation |
|---|---|
| No shell | Explicit `Command` argv vectors only. |
| Private directory | Unique `0700` directory created atomically; capture files are `0600`; removed on drop. |
| Cleared fixture environment | C sanitizer fixtures run with an empty environment plus only `ASAN_OPTIONS`, `LSAN_OPTIONS`, or `TSAN_OPTIONS`. |
| Rust tool environment | Minimal `PATH`, `HOME`, `TMPDIR`, `LC_ALL`, `RUSTUP_HOME`, and `CARGO_HOME`; Miri adds `RUSTUP_TOOLCHAIN`; Kani adds `KANI_HOME` and the gate-provided `KANI_CARGO_HOME`. |
| Null stdin | `Stdio::null()`. |
| Process group | `CommandExt::process_group(0)`. |
| Wall clock | Probes 15 s; fixture runs 20 s; compilers 180 s; Miri/Loom/Kani 600 s; the gate's installs are separately `timeout`-bounded. |
| Output | At most 65,536 bytes per captured stream (the Phase 5.1 `MAX_CAPTURE_BYTES`); a truncated capture is `NOT_RUN`, never evidence. |
| Compiler output | At most 64 KiB per compiler invocation. |
| CLI allow-list | Only the seven built-in selectors; unknown selectors are usage errors (exit 2). |

The detector gate uses the same hardened Docker flags as `ci/gate.sh`:
`--memory=2g --memory-swap=2g --pids-limit=512 --cpus=2
--ulimit nofile=1024:1024 --oom-score-adj=500`, capabilities reduced to
`DAC_OVERRIDE`, `CHOWN`, and `FOWNER`, and `--security-opt no-new-privileges`.
Nothing is weakened.

## Exact install and invocation

### Miri

Fixtures: `tests/detector/fixtures/miri/` with `ub.rs`, `clean.rs`, and
`harmless.rs`.

```sh
rustup toolchain install nightly-2025-02-20 --profile minimal \
  --component miri,rust-src
cargo +nightly-2025-02-20 miri setup
cargo +nightly-2025-02-20 miri run --bin ub       # known-bad
cargo +nightly-2025-02-20 miri run --bin clean    # clean specificity
cargo +nightly-2025-02-20 miri run --bin harmless # valid-unsafe control
```

The adapter runs each command in a private copy of the fixture crate and adds
`--target-dir <private>/target-<bin>`; that exact argv is recorded in the
evidence. No `CARGO_TARGET_DIR` is passed through an unrecorded environment
variable.

`ub.rs` frees a `Vec` and then writes through a raw pointer. Miri exits nonzero
with a real `Undefined Behavior` diagnostic. `clean.rs` is entirely safe.
`harmless.rs` performs a valid raw-pointer write. Miri's default `Stacked
Borrows` model is used; the recorded enablement is `miri`/`stacked-borrows`.
Miri does not execute native C/FFI code, so these are Rust-native fixtures.

### ASan, LSan, and TSan

Fixtures: `tests/detector/fixtures/c/`.

```sh
gcc -std=c11 -fsanitize=address -fno-omit-frame-pointer -g -O1 \
  c/asan_use_after_free.c -o instrumented/bad
gcc -std=c11 -fsanitize=address -fno-omit-frame-pointer -g -O1 \
  c/asan_clean.c -o instrumented/good
gcc -std=c11 -g -O1 c/asan_use_after_free.c -o baseline/bad          # no sanitizer

gcc -std=c11 -fsanitize=leak -g -O1 c/lsan_leak.c -o instrumented/bad
gcc -std=c11 -fsanitize=leak -g -O1 c/lsan_clean.c -o instrumented/good
gcc -std=c11 -g -O1 c/lsan_leak.c -o baseline/bad

gcc -std=c11 -fsanitize=thread -pthread -g -O1 c/tsan_data_race.c -o instrumented/bad
gcc -std=c11 -fsanitize=thread -pthread -g -O1 c/tsan_atomic_control.c -o instrumented/good
gcc -std=c11 -pthread -g -O1 c/tsan_data_race.c -o baseline/bad
```

Runtime options are explicit: `ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:
abort_on_error=0`, `LSAN_OPTIONS=exitcode=23:report_objects=0`, and
`TSAN_OPTIONS=halt_on_error=1:exitcode=66`.

Detected diagnostics:

* `AddressSanitizer: heap-use-after-free` (stderr, nonzero exit);
* `LeakSanitizer: detected memory leaks` (stderr, exit 23); and
* `ThreadSanitizer: data race` (stderr, exit 66).

The TSan fixture uses a `pthread_barrier_t` so both threads are alive before
the unsynchronized increments. Without the barrier the detector was observed to
miss the race on some runs; the barrier makes the known-bad control
deterministic. The atomic control uses C11 `_Atomic` increments.

### loom

Fixture crate: `tests/detector/fixtures/loom/`, with `loom = "=0.7.2"` and two
binaries.

```sh
cargo run --release --bin race    # known-bad
cargo run --release --bin atomic  # harmless atomic control
```

The adapter runs these commands with
`--target-dir <private>/target-<bin>` and records that exact argv. The race and
atomic artifacts are built in separate target directories.

`race` uses `loom::cell::UnsafeCell`, a loom thread yield between read and
write, and two unsynchronized increments. Loom reports the real detector
diagnostic:

```text
Causality violation: Concurrent read and write accesses to `UnsafeCell`.
```

The process exits nonzero (panic). `atomic` uses `loom::sync::atomic::
AtomicUsize::fetch_add(Ordering::SeqCst)` and exits zero. Loom explores only
loom-instrumented operations; it is a bounded model, not a real scheduler.

### Kani

Fixture: `tests/detector/fixtures/kani/kani_fixture.rs`.

```sh
cargo install --locked kani-verifier --version 0.60.0
CARGO_HOME=/usr/local/cargo cargo kani setup
kani kani_fixture.rs --harness known_bad      # bounded FAILED
kani kani_fixture.rs --harness proof_control  # SUCCESSFUL
```

Kani 0.60.0 is used because the latest Kani (0.68.0) requires a Rust newer than
the crate's pinned 1.85 toolchain (`home@0.5.12` requires 1.88). Kani's setup
downloads its bundled CBMC and its own pinned nightly toolchain; `curl` and
`ca-certificates` are installed only for this bounded attempt. The known-bad
harness asserts `value < 128` for an arbitrary `u8`; Kani exits nonzero and
prints `VERIFICATION:- FAILED`. The control proves a tautology and exits zero.
Kani proofs are bounded; a successful proof is not a universal soundness claim.

### OpenSSL known-answer and signature controls

Fixtures: `tests/detector/fixtures/crypto/` (`kat_input.txt` is the three-byte
message `abc`, `message.txt`, `public.pem`, `signature.bin`, and
`signature_corrupt.bin`).

```sh
openssl dgst -sha256 -r kat_input.txt
# ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

openssl dgst -sha256 -verify public.pem -signature signature.bin message.txt
# Verified OK (stdout, exit 0)

openssl dgst -sha256 -verify public.pem -signature signature_corrupt.bin message.txt
# Verification failure (stderr, exit 1)
```

The SHA-256 vector is the NIST FIPS 180-4 known answer for `abc`. The corrupt
signature is the sensitivity control; the valid signature and the KAT are the
specificity controls. The adapter records the real stdout/stderr and the typed
`known_answer` finding. This is a primitive/verification sanity control, **not**
a constant-time or secret-lifecycle measurement.

## Build separation

Each mechanism records two build identities with the same target and profile,
different build-directory labels, and different non-zero artifact digests:

| Mechanism | Detector build | Baseline build |
|---|---|---|
| Miri | Miri interpreter driver; label `live/miri/interpreter` | native `rustc` build of `clean.rs`; label `live/miri/native` |
| ASan/LSan/TSan | sanitizer-instrumented binary; sanitizer flag present | same source at `-O1 -g` without the sanitizer flag |
| loom | `race` binary in `target-race` | `atomic` binary in `target-atomic` |
| Kani | Kani proof-checker binary; label `live/kani/proof` | native `rustc` build of `kani_baseline.rs`; label `live/kani/native` |
| OpenSSL | KAT input bundle digest; label `live/crypto/kat` | message bundle digest; label `live/crypto/signature` |

For sanitizers the baseline does not carry the mechanism flag, and the
instrumented artifact digest differs from the baseline digest. For Miri, Kani,
and OpenSSL the instrument does not emit a canonical standalone instrumented
executable in a stable path; the table records the actual driver/data identity
used and documents that this is structural separation, not a claim that the
baseline is an optimized production build. The Phase 5.1 adjudicator refuses a
shared directory, identical artifacts, a missing mechanism flag, an instrumented
baseline, or an empty target/profile.

The recorded `executable_sha256` is the process that produced the capture: for
C sanitizers it is the instrumented fixture binary, and for tool-mediated
adapters it is the `cargo` driver. The instrumented artifact identity is
recorded separately in `build.artifact_sha256` (the Miri driver, the loom race
binary, or the Kani proof checker). Compiler and tool versions are recorded in
`tool_version`; the captured argv includes an explicit `--target-dir` for Miri
and loom so no execution-affecting path is hidden in an unrecorded environment
variable.

## Live results

Run `./ci/detector-gate.sh`. The gate installs only the detector packages,
pinned nightly components, and the bounded Kani attempt; it then runs the CLI
and the structural seal tests. Verified on this branch:

| Mechanism | Sensitivity | Specificity | Build separation | Authenticity | Result |
|---|---:|---:|---|---|---|
| Miri | 1/1 | 2/2 | PASS | PASS | PASS |
| ASan | 1/1 | 1/1 | PASS | PASS | PASS |
| LSan | 1/1 | 1/1 | PASS | PASS | PASS |
| TSan | 1/1 | 1/1 | PASS | PASS | PASS |
| loom | 1/1 | 1/1 | PASS | PASS | PASS |
| Kani | 1/1 | 1/1 | PASS | PASS | PASS |
| OpenSSL KAT | 1/1 | 2/2 | PASS | PASS | PASS |

The 11 live seal tests pass with `FRF_DETECTOR_LIVE=1`. With the flag unset,
the same 11 tests execute and assert the typed `NOT_RUN` path; none is ignored.
The default `./ci/gate.sh` therefore passes in an image with none of these
tools installed.

## CLI

```text
detector calibrate FILE [--json]                       # Phase 5.1 receipt
detector calibrate --live --detector KIND [--json]     # Phase 5.2 live run
```

`KIND` is one of `miri`, `asan`, `lsan`, `tsan`, `loom`, `kani`, or `crypto`.
The live command emits the canonical `frf-memorysafety.calibration-report.v1`
on a run and a typed `frf-memorysafety.live-detector-not-run.v1` object (exit 6)
when the instrument is unavailable. Exit statuses follow SPEC.md §14: 0 for a
calibrated run, 2 for usage, 3 for an integrity failure, 5 for a refused
control, 6 for `NOT_RUN`, and 7 for an internal harness error. `capabilities
--json` reports per-detector runtime availability.

## Honest limits for Phase 6

* The live adapters run only a closed fixture registry; arbitrary candidate
  source and `court run` remain `NOT_RUN`.
* Miri is Rust-native and cannot execute the real C/FFI path.
* Sanitizer results depend on instrumentation, runtime, optimization, and the
  executed path; a clean run is not proof of absence.
* loom models only loom-instrumented operations and bounded pre-emption
  schedules; it is not a real-scheduler observation.
* Kani is bounded by its unwinding and modeling assumptions; it is not the
  Phase 6 proof manifest, theorem/assumption closure, or external checker.
* The OpenSSL controls do not measure constant-time leakage or secret
  lifecycle.
* Digests bind this run; there is no signature, transparency log, independent
  re-run, or trusted build root.
* There is no independent adversarial re-execution of a live calibration.

Phase 6 is not started here.

## Citations

1. The Rust Project. *Miri README*: installation via `rustup component add
   miri`, `cargo miri run/test`, first-run setup, `MIRIFLAGS`, and the explicit
   non-soundness/FFI limitations. <https://github.com/rust-lang/miri>
2. The Rust Project. *The Unstable Book: Sanitizer*: `-Zsanitizer=address`,
   `leak`, and `thread`; ASan default leak detection on Linux. 
   <https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/sanitizer.html>
3. Free Software Foundation. *GCC Program Instrumentation Options*:
   `-fsanitize=address`, `-fsanitize=leak`, `-fsanitize=thread`,
   `-fno-omit-frame-pointer`, and `ASAN_OPTIONS`/`LSAN_OPTIONS`/`TSAN_OPTIONS`.
   <https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html>
4. The Clang Team. *AddressSanitizer*, *LeakSanitizer*, and *ThreadSanitizer*
   documentation: report forms, runtime flags, and exit codes (TSan default 66).
   <https://clang.llvm.org/docs/AddressSanitizer.html>,
   <https://clang.llvm.org/docs/LeakSanitizer.html>,
   <https://clang.llvm.org/docs/ThreadSanitizer.html>
5. K. Serebryany, D. Bruening, A. Potapenko, and D. Vyukov.
   *AddressSanitizer: A Fast Address Sanity Checker.* USENIX ATC 2012.
   <https://www.usenix.org/conference/atc12/technical-sessions/presentation/serebryany>
6. K. Serebryany and T. Iskhodzhanov. *ThreadSanitizer: Data Race Detection in
   Practice.* Workshop on Binary Instrumentation and Applications, 2009.
   <https://doi.org/10.1145/1791194.1791203>
7. Tokio project. *loom: model checking for concurrent Rust code*:
   `loom::model`, loom synchronization types, causality violations, and bounded
   pre-emption limits. <https://docs.rs/loom/>
8. Kani Rust Verifier. *Installation* and *Kani documentation*: 
   `cargo install --locked kani-verifier`, `cargo kani setup`, `kani FILE`, and
   `VERIFICATION:- SUCCESSFUL/FAILED`.
   <https://model-checking.github.io/kani/install-guide.html>,
   <https://model-checking.github.io/kani/>
9. E. Clarke, D. Kroening, and F. Lerda. *A Tool for Checking ANSI-C Programs.*
   TACAS 2004. <https://doi.org/10.1007/978-3-540-24730-2_15>
10. OpenSSL Project. *openssl-dgst(1)*: `dgst`, `-sha256`, `-r`, `-verify`,
    `-signature`, and the `Verified OK`/`Verification failure` outputs.
    <https://docs.openssl.org/master/man1/openssl-dgst/>
11. NIST. *FIPS PUB 180-4: Secure Hash Standard (SHS)*, SHA-256 known answer for
    `abc`. <https://csrc.nist.gov/pubs/fips/180-4/upd1/final>
12. R. Jung, H.-H. Dang, J. Kang, and D. Dreyer. *Stacked Borrows: An Aliasing
    Model for Rust.* POPL 2020. <https://doi.org/10.1145/3371078>
13. Docker Inc. *Resource constraints* and *Security configuration*.
    <https://docs.docker.com/engine/containers/resource_constraints/>,
    <https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities>
14. Open Source Security Foundation. *SLSA Specification v1.0: Provenance*.
    <https://slsa.dev/spec/v1.0/provenance>
15. in-toto. *in-toto Attestation Framework*. <https://in-toto.io/>
16. D. G. Altman and J. M. Bland. *Diagnostic tests 1: sensitivity and
    specificity.* BMJ 308:1552, 1994.
    <https://doi.org/10.1136/bmj.308.6943.1552>
