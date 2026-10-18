# Phase 4.2: isolated native event recording and replay

Snapshot: branch `staging`, crate `frf-memorysafety 0.4.0` (no version bump).
This document describes the test-only native harness in `src/native.rs`, its
checked-in fixtures under `tests/native/fixtures/`, and the separate
`ci/native-gate.sh` gate. It does **not** change the Phase 4.1 verifier: that
verifier still consumes a finite caller-supplied transcript and remains
transcript-scoped.

## Scope and claim ceiling

The harness lives behind the non-default `native-harness` Cargo feature. It
compiles a **closed registry** of checked-in C and Rust fixtures. It has no
command-line entry point and no API that accepts a caller-supplied source file
or executable. `court run` remains `NOT_RUN` (exit 6).

A live record establishes that:

* the named checked-in fixture was compiled by the recorded compiler and linker
  versions;
* the resulting executable was executed twice in the recorded isolation with
  identical argv, environment, and working directory;
* both executions emitted the captured JSONL event stream; and
* the two canonical `native-event-transcript.v1` transcripts were byte-identical.

It does **not** establish:

* memory safety, Rust borrow validity, C object lifetime, effective type, or
  alignment legality;
* real-scheduler concurrency: fixtures emit a scripted deterministic event
  schedule, and logical thread identifiers are transcript metadata rather than
  operating-system thread observation;
* that any unrecorded event did or did not occur outside the captured stream;
* that a digest authenticates the executable, compiler, or execution
  environment (there is no signature, transparency log, or trusted execution
  root);
* that the verifier is sound, complete, or a native oracle;
* any universal `SAFE_COMPATIBLE` result.

The claim ceiling is the same discipline used in `docs/phase4-ownership.md`:
`verified_compatible_within_transcript` means only that the finite transcript is
internally compatible under the declared provenance.

## Isolation model

Every fixture execution uses the following controls. No shell is involved in
compilation or execution; all commands are explicit argv vectors.

| Control | Implementation |
|---|---|
| Private directory | A unique directory is created atomically with `create_dir` and then set to mode `0700`; captured files use mode `0600`. It is removed on drop. |
| Cleared environment | `Command::env_clear()`; only the native executable and the `prlimit` wrapper run with an empty environment. |
| Null stdin | `Stdio::null()` for every execution. |
| New process group | `std::os::unix::process::CommandExt::process_group(0)`, so the child is its own process-group leader. |
| Address space | `prlimit --as=536870912` (512 MiB). |
| CPU | `prlimit --cpu=5` (5 seconds). |
| Process count | `prlimit --nproc=64`. |
| File size | `prlimit --fsize=1048576` (1 MiB). |
| Core dumps | `prlimit --core=0`. |
| Wall clock | 10-second polling bound; the child is killed on timeout. |
| Output capture | stdout and stderr are redirected to files and read with a 256 KiB bound; oversized output is rejected and classified `unresolved`. |
| Compiler bounds | 120-second wall clock and 64 KiB combined output bound per compiler invocation. |
| Compiler argv | C: `cc -std=c11 -O0 -Wall -Wextra -Werror`; Rust: `rustc --edition=2021 -C opt-level=0 -C debuginfo=0`, with an explicit linker when `cc` is present. |
| Compiler environment | A minimal `PATH`, `HOME`, `TMPDIR`, `RUSTUP_HOME`, and the pinned `RUSTUP_TOOLCHAIN`; the fixture execution environment is still cleared. |

`prlimit(1)` is used instead of calling `setrlimit(2)` directly because this
crate is `#![forbid(unsafe_code)]`. The wrapper applies the limits and then
executes the fixture in the same process, so the limits cover the native
program. The container remains the outer bound. These are cumulative: the
per-child limits are additional to, and never weaken, the container limits.

The default `ci/gate.sh` uses the same container flags but installs no
toolchain. With `FRF_NATIVE_HARNESS` unset, every native test executes and
asserts the typed `NativeOutcome::NotRun` path. No test is `#[ignore]`d.

## Provenance fields

Every produced transcript carries `TranscriptProvenance` with these values:

| Field | Recorded value |
|---|---|
| `origin` | `authentic_native` for a live harness record; `substitute` and `modeled` are test-only overrides and the verifier returns `unresolved`. |
| `tool` | `frf-native-fixture-harness` |
| `tool_version` | `CARGO_PKG_VERSION` of the crate |
| `library_versions` | Exact first lines of `cc --version`, `ld --version`, and, for Rust fixtures, `rustc --version` that were available and used or relevant |
| `executable_digest` | SHA-256 of the compiled executable, lower-case hexadecimal |
| `fixture_digest` | SHA-256 of the checked-in fixture source, lower-case hexadecimal |
| `case_legality` | `test_only` for every registered case |
| `scope` | Phase 4.2 test-only fixture scope, scripted schedule, transcript-scoped, with the case id appended |
| `claimed_complete` | Default per case; overridable only through the test API |

`recording` additionally records a fixed seed (`42`), the recorder's expected
event count, and a schedule note. For the skipped-event case the expected count
is the full count, so omitting an event also triggers `event_count_mismatch`.

The digests bind the transcript text to the compiled artifact and fixture source
for this test run, but they are **not** authentication. Best practice for
production provenance is signed attestation over the build inputs and outputs,
for example SLSA provenance and in-toto attestations; this phase does not
implement either. See the citations below.

## Fixture event protocol

Each executable writes one strict JSON object per line to stdout:

```json
{"record":"event","thread":"t0","seq":0,"kind":"create","object":"obj","token":"tok0","owner":"task-a","generation":0}
{"record":"sync","from_thread":"t0","from_seq":1,"to_thread":"t1","to_seq":0}
```

The harness removes `record` and `thread`, validates the remaining object as a
Phase 4.1 `Event` with `deny_unknown_fields`, groups events by the case's
declared logical threads, and adds the case's objects, requirements, recording
metadata, and provenance. Unknown record kinds, undeclared threads, duplicate
keys, floats, malformed JSON, and structural inconsistencies are rejected.

## Registered cases

| Case | Language | Expected live outcome |
|---|---|---|
| `legal-transfer-free-c` | C | `verified_compatible_within_transcript` |
| `legal-transfer-free-rust` | Rust | `verified_compatible_within_transcript` |
| `use-after-free-c` | C | `observed_violation` (`use_after_free`) |
| `use-after-free-rust` | Rust | `observed_violation` (`use_after_free`) |
| `mutable-alias-c` | C | `observed_violation` (`borrow_conflict`) |
| `stale-generation-c` | C | `observed_violation` (`stale_generation`) |
| `sync-callback-c` | C | `verified_compatible_within_transcript` |
| `deferred-callback-c` | C | `observed_violation` (`use_after_free`) |
| `data-race-c` | C | `observed_violation` with a race witness |
| `atomic-control-c` | C | `verified_compatible_within_transcript`, no race witness |
| `skipped-free-c` | C | `incomplete_transcript` |
| `nondeterministic-c` | C | `unresolved` on replay mismatch |
| `oversized-output-c` | C | rejected as `unresolved` |

Every positive and negative case is a **test-only** case. Negative fixtures
intentionally exercise invalid lifetimes or conflicting accesses; that is legal
as a test-only control and is not evidence about production code.

## Seeded skipped-event control

`skipped_event.c` accepts the explicit argv token `skip-free`. In that mode it
omits the `free` event while the registry still requires it and the recording
metadata still claims the full event count. With an honest
`claimed_complete: false`, the verifier returns `incomplete_transcript` with
`required_free_missing` / `outstanding_responsibility` and
`event_count_mismatch`. With an overridden `claimed_complete: true`, the same
transcript also receives `fictitious_completeness`; the outcome remains
`incomplete_transcript` and is never a clean verdict.

## Replay rule

The harness compiles the fixture once, then executes the identical executable
path, argv, environment, and working directory twice. It canonicalizes each
parsed transcript with the crate's `ms-canonical-json-v1` encoder and compares
the bytes. If they differ:

* the record outcome is `unresolved`;
* the replay status is `mismatch`;
* the court report is rewritten to `unresolved` and gains a `replay_mismatch`
  finding; and
* the result is never reported as success.

`nondeterministic.c` is the control: it writes `getpid()` and a monotonic clock
value into event `detail` fields, so identical executable input produces
different canonical transcripts. The test requires a mismatch and an
`unresolved` outcome. This is the Phase 4 mechanism that turns non-reproducible
observation into a refusal rather than a pass.

## Legality and exact commands

Default gate (no C toolchain required; native tests assert `NOT_RUN`):

```sh
./ci/gate.sh
```

Live native gate (installs only `gcc` and `libc6-dev`, then runs the live
fixtures):

```sh
./ci/native-gate.sh
```

The native gate uses the same hardened Docker flags as `ci/gate.sh`:
`--memory=2g --memory-swap=2g --pids-limit=512 --cpus=2
--ulimit nofile=1024:1024 --oom-score-adj=500`, capabilities reduced to
`DAC_OVERRIDE`, `CHOWN`, and `FOWNER`, and `--security-opt no-new-privileges`.
Because the reduced capability set prevents apt's `_apt` sandbox user from
switching users, the in-container install uses
`-o APT::Sandbox::User=root`; it does not add capabilities. `ci/native.Dockerfile`
is intentionally not added because a Dockerfile can supply packages but cannot
encode the runtime OOM and resource caps, so those must remain in the gate
script.

To run the live tests directly inside the hardened container:

```sh
docker run --rm \
  --memory=2g --memory-swap=2g --pids-limit=512 --cpus=2 \
  --ulimit nofile=1024:1024 --oom-score-adj=500 \
  --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
  --security-opt no-new-privileges \
  -v "$PWD":/src:ro -v "$PWD/target":/src/target \
  -v frf-cargo:/cargo -e CARGO_HOME=/cargo -w /src \
  rust:1.85.0-slim sh -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get -o APT::Sandbox::User=root update
    apt-get -o APT::Sandbox::User=root install -y --no-install-recommends gcc libc6-dev
    FRF_NATIVE_HARNESS=1 cargo test --locked --features native-harness \
      --test native -- --nocapture
  '
```

## Tests added

`tests/native.rs` contains 17 tests. With the flag unset, each test executes the
typed `NOT_RUN` path. With the flag set, the same tests exercise the live
records, provenance, positive/negative pairs, skipped-event detector,
fictitious completeness, replay mismatch, oversized-output rejection, and
substitute/modeled origin refusal. No test is ignored.

## Remaining honest limits for Phase 5

* The transcript schedule is scripted; it is not a real thread scheduler,
  sanitizer, or dynamic race detector.
* The Phase 5.2 live detector adapters are a separate closed fixture registry;
  they do not extend this native transcript harness or accept arbitrary input.
* The harness does not sign provenance, publish attestations, or provide a
  trusted build root.
* Only the closed fixture registry can run; arbitrary native input remains
  `NOT_RUN`.
* The verifier remains a finite transcript checker, not a native or universal
  soundness oracle.

## Citations

1. IEEE and The Open Group. *POSIX.1-2017 / IEEE Std 1003.1-2017*:
   `setrlimit`, `getrlimit`, `setpgid`, `execve`, and `fork`.
   <https://pubs.opengroup.org/onlinepubs/9699919799/>
2. Linux man-pages project. *prlimit(1)*, *prlimit(2)*, *setrlimit(2)*, and
   *proc(5)*. <https://man7.org/linux/man-pages/man1/prlimit.1.html>,
   <https://man7.org/linux/man-pages/man2/prlimit.2.html>,
   <https://man7.org/linux/man-pages/man2/setrlimit.2.html>
3. Docker Inc. *Resource constraints*, *Limit a container's resources*, and
   *Security configuration*. <https://docs.docker.com/engine/containers/resource_constraints/>,
   <https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities>
4. Free Software Foundation. *GNU Compiler Collection (GCC) Manual*: overall
   options, warning options, and version reporting.
   <https://gcc.gnu.org/onlinedocs/gcc/>
5. The Rust Project. *The rustc book*: command-line arguments, `--edition`, and
   code-generation options. <https://doc.rust-lang.org/rustc/>
6. The Rust Project. *std::os::unix::process::CommandExt::process_group*.
   <https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html>
7. NIST. *FIPS PUB 180-4: Secure Hash Standard (SHS)*, SHA-256.
   <https://csrc.nist.gov/pubs/fips/180-4/upd1/final>
8. The Reproducible Builds project. *Reproducible Builds: a set of software
   development practices that create an independently verifiable path from
   source code to binary code.* <https://reproducible-builds.org/>
9. Open Source Security Foundation. *SLSA Specification v1.0*, provenance.
   <https://slsa.dev/spec/v1.0/provenance>
10. in-toto. *in-toto Attestation Framework*. <https://in-toto.io/>
11. R. O'Callahan, C. Jones, N. Froyd, K. Huey, A. Noll, and N. Partush.
    *Engineering Record and Replay for Deployability.* USENIX ATC 2017.
    <https://www.usenix.org/conference/atc17/technical-sessions/presentation/ocallahan>
12. ISO/IEC 9899:2018. *Programming Languages — C.* Storage durations,
    expressions, and the atomics library.
    <https://www.iso.org/standard/74528.html>
13. Linux man-pages project. *prctl(2)*, `PR_SET_NO_NEW_PRIVS`.
    <https://man7.org/linux/man-pages/man2/prctl.2.html>
