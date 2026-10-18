# Phase 8.2: live OpenSSL-Rust conversion witness, repair, consumer, and loader

Status: **Phase 8 is complete for the declared 8.2 scope.** One real
native-boundary witness was produced from the pinned OpenSSL-Rust candidate,
its fault and repaired revisions were built and run, the repair was confirmed
compatible, unmodified curl was built and run against the candidate prefix with
a positive TLS 1.3 fetch and an unrelated-CA rejection, the candidate loader
closure was observed, and the live capture was fed through
`src/conversion.rs` with property-specific reuse/revocation checks.

This is **not** a memory-safety, compatibility, `SAFE_COMPATIBLE`, or organic
vulnerability claim. The witness is one genuine owner/refcount defect already
identified by the target's own repair commit and reproduced here live; it is not
a new organic discovery. The target still records **0/33** consumers
`SAFE_COMPATIBLE`, and this crate adopts no such claim.

## 1. Host and hard cap

| Item | Value |
|---|---|
| Host memory | `134723346432` bytes (`125.5 GiB`) |
| Host CPUs | `16` |
| Available at the run | ~`38 GB` |
| Chosen hard cap | **`4g`** |
| Swap cap | `4g` (equal to memory; no swap headroom) |
| Other limits | `--pids-limit=512 --cpus=2 --ulimit nofile=1024:1024 --oom-score-adj=500` |
| Capabilities | `--cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER` |
| Privilege | `--security-opt no-new-privileges` |

The Phase 8.1 blocker was a 2 GiB cgroup kill while compiling the target. Phase
8.2 used the same mandatory controls with a 4g cap, which the host could
support with substantial headroom. The cap was not removed or made unbounded,
and 6g/8g were not needed. The default `./ci/gate.sh` remains on
`rust:1.85.0-slim` at its existing 2g cap.

## 2. Images and toolchain

| Role | Image | Identity |
|---|---|---|
| Target tests and fault/repair witness | `rust:1.98.1-slim` | digest `sha256:4cd829461bd5c4d511c32e269da9cb8929223b666519d8004e35fc8d1d771ab7` |
| Authority, DSOs, curl, loader proof | `openssl-rs-court:1` | image id `sha256:34abc0fac9b58f90cb97adbc2356e5b91b31e3dab50fccf3a1aef94c9759560e` (Debian 12) |
| Crate gates | `rust:1.85.0-slim` | digest `sha256:1829c432be4a592f3021501334d3fcca24f238432b13306a4e62669dec538e52` |

Observed target toolchain: `rustc 1.98.1 (48a229cea 2026-09-01)`,
`cargo 1.98.1 (797e8a9bc 2026-08-05)`, `cc (Debian 14.2.0-19) 14.2.0`,
`GNU ld 2.44`. The court image's C compiler is Debian `cc 12.2.0`; that is the
toolchain used for the authority and the Phase-2 link. The target build used
`CARGO_BUILD_JOBS=1`, `CARGO_INCREMENTAL=0`, `RUSTFLAGS="-C debuginfo=0"`, and
`CARGO_PROFILE_TEST_DEBUG=0` / `CARGO_PROFILE_RELEASE_DEBUG=0`.

## 3. Pinned candidate and build result

| Item | Value |
|---|---|
| Repository | `infinityabundance/openssl-rs` |
| Branch | `integrate/safe-c33` |
| Pinned commit | `56ba894594ed3df0fdf117a15747d205b4f0ecd9` |
| Pinned tree | `b54cc2b96d0e12af4a534d9237aadbe089b38660` |
| Crate | `openssl-rs 0.0.27` |
| Source manifest digest | `cea6ed27ee9b20b6c9409bd4845e3f1ba456dddd3192c020a20e3d0c9ecc84d0` (`git ls-tree -r --full-tree`) |

The 4g build completed. The refcount library tests built in `16.74 s` and the
release archive in `45.23 s`. A later clean gate rebuild reproduced the same
result. The 2 GiB `SIGKILL` recorded in Phase 8.1 was not reproduced at 4g.

## 4. Boundary tests at the pin

All of the following ran in `rust:1.98.1-slim` at the pinned commit:

| Filter | Result |
|---|---|
| `runtime::refcount::tests` | **9 passed**, 0 failed, 0 ignored |
| `refcount_reentrancy` (SSL `SSL_free`, `SSL_CTX_free`, `SSL_SESSION_free`) | **3 passed**, 0 failed, 0 ignored |
| `alias_ownership_tests` (SSL/SslCtx/Session alias and lifecycle closure) | **7 passed**, 0 failed, 0 ignored |
| `store_free_reentrancy_is_defined_noop` | **1 passed** |
| `store_free_from_lookup_free_hook_is_defined_noop` | **1 passed** |
| `store_refcount_is_atomic_under_concurrent_up_ref` | **1 passed** |

The four X.509/SSL callback and alias families are exercised as ordinary
library tests, not `#[ignore]`d probes.

## 5. Real native-boundary witness and independently confirmed mechanism

Selected boundary: `runtime::refcount::up_ref`, owner kind, C behaviour
`owner_up_ref_refuses_retired` and `owner_over_free_defined_no_op`.

| Item | Fault | Repair |
|---|---|---|
| Commit | `28c9e34487edf93eca314233d3c0b4a2aa061246` | `1d9c3358bd19c5434e78def3d25ead2617d3a20e` |
| Subject | `docs(safe-c33): record STOP-1 (up_ref overflow) and fix stale contract census` | `fix(refcount): refuse up_ref overflow instead of entering the sentinel` |
| `src/runtime/refcount.rs` SHA-256 | `284a349c72045aebb0e552a724c1b2aa24dd771206e8c2ade7aa0fe385ae6277` | `9b8e30005fe21dc1c3aa3af933fcb211452d991a5c8a42e295eaa137b56f5dbc` |
| Change | `compare_exchange(n, n + 1, …)` | `n.checked_add(1)` then refuse before the compare-exchange |

The fault is genuine. The repair commit's own test
`up_ref_refuses_overflow_without_changing_count` was applied unchanged to the
fault tree (test-only patch, digest
`1bf0dfa0f4e501dcec02f1ed0f309dac016afe4874af4a6b88b198ea6aabb9b9` in the
gate log; the committed patch is `ci/fixtures/phase8-overflow-test.patch`).

Observed fault output with the crate's default overflow checks:

```text
thread 'runtime::refcount::tests::up_ref_refuses_overflow_without_changing_count' panicked at src/runtime/refcount.rs:92:40:
attempt to add with overflow
test result: FAILED. 0 passed; 1 failed; 0 ignored
```

Observed fault output with compiler overflow checks disabled, using a
test-only observation (`ci/fixtures/phase8-overflow-observation.patch`):

```text
FAULT_OBSERVATION answer=1 count=-2147483648
test result: ok. 1 passed; 0 failed
```

`count=-2147483648` is `i32::MIN`, the destroying sentinel. The fault therefore
does two things: it panics when checks are on, and when they are off it wraps a
live `i32::MAX` count into `REF_DESTROYING` while reporting success (`answer=1`).
That is the silent-retire defect, not a synthetic seeded marker.

Repair observations:

| Configuration | Result |
|---|---|
| overflow checks on | `up_ref_refuses_overflow_without_changing_count` **1 passed** |
| overflow checks off | same test **1 passed** |
| positive-count compatibility (`up_ref_preserves_positive_count_answer`) | **1 passed** |

The repair's `checked_add` refusal is independent of the compiler's overflow
setting; below `i32::MAX` the positive-count answer and relaxed ordering are
unchanged. The independent mechanism confirmation is the captured pair of
compiler behaviours plus the exact fault/repair diff, stored as
`mechanism.txt` (SHA-256
`40703699a0f5263bae785a707e969cc479ca2a2394bd13b7b93e4a65c27fc932`). It is
not a claim of a newly discovered vulnerability: the target's own repair commit
already records the defect.

## 6. Consumer workflow: curl against the candidate prefix

The Phase-17 harness built unmodified curl `8.22.0` from the pinned upstream
tarball (`sha256` verified) against
`artifacts/phase2/install` built from the pinned tip. The run used the
authority's `openssl` only to generate the local PKI and serve TLS 1.3; curl
itself resolved the candidate DSOs.

| Case | Exit | HTTP | Verify | Message |
|---|---|---|---|---|
| verified TLS 1.3 fetch | `0` | `200` | `0` | — |
| unrelated CA | `60` | `000` | `20` | `unable to get local issuer certificate (20)` |

Loader resolution from the live run:

```text
libssl.so.3 => /work/artifacts/phase2/install/lib/libssl.so.3
libcrypto.so.3 => /work/artifacts/phase2/install/lib/libcrypto.so.3
```

`LD_DEBUG=libs` shows both `calling init:` lines under the candidate prefix.
The loader trace digest is
`acf78d68a968a81644c329a07651ed99ae2631c117dc2663a853d8af94667c72`.

## 7. Loader closure and DSO digests

| Item | Value |
|---|---|
| `libssl.so.3` SHA-256 | `6028297af9fadc30dff61740ef2150777e3172000735f1ea97be0712750f8af9` |
| `libcrypto.so.3` SHA-256 | `b4c57b90036d945eb0f651d9a0a21278b5941d4871e7492043c5139993f2c814` |
| Authority `libcrypto.so.3` SHA-256 | `59d9c2e4568d0e5fa4025e1d7e9000c6c07383087e6a2ebb68d525d4e5d5e17d` |
| `libssl.so.3` `DT_NEEDED` | `libcrypto.so.3`, `libgcc_s.so.1`, `libc.so.6`, `ld-linux-x86-64.so.2` |
| `libcrypto.so.3` `DT_NEEDED` | `libgcc_s.so.1`, `libc.so.6`, `ld-linux-x86-64.so.2` |
| `libssl.so.3` version nodes | `OPENSSL_3.0.0`, `3.2.0`, `3.3.0`, `3.4.0`, `3.5.0` |
| `libcrypto.so.3` version nodes | `OPENSSL_3.0.0`, `3.0.3`, `3.0.8`, `3.0.9`, `3.1.0`, `3.2.0`, `3.3.0`, `3.4.0`, `3.5.0`, `3.6.0` |
| ABI-LOAD | libcrypto `5896/5896`, libssl `603/603`, **6499 resolved, 0 unresolved** |
| ABI-DYNAMIC / ABI-SUBSTITUTION / contamination | all **pass** |

The Phase-2 courts also report `all_pass=True` for the symbol, version, layout,
link, constants, matrix, and install-layout courts.

## 8. Live capture in `src/conversion.rs`

`capture_live` reads `capture.json` from `FRF_CONVERSION_CAPTURE`, computes every
digest from the named file bytes, derives the evidence, and validates it before
returning. `capture_live_from_env` returns a typed
`ConversionCaptureOutcome::NotRun` when the variable is unset. A live capture
whose origin is not `authentic_native` is refused.

The captured record binds:

* authentic-native provenance and the discovery claim (`no_discovery_claim`
  here; a synthetic or substitute witness cannot claim organic discovery);
* the exact candidate revision, canonical source-manifest digest, and candidate
  DSO-closure digest;
* the owner boundary kind, boundary identity, and allowed C behaviour;
* the witness tool, exact command, output, and independent mechanism
  confirmation;
* the loader tool, loaded DSO bytes, version nodes, `DT_NEEDED`, under-prefix
  flag, resolved/unresolved counts, and trace digest;
* the fault and repaired revisions and the changed paths;
* the toolchain, dynamic loader, authority, and library dependency versions.

Observed capture:

```text
LIVE_CAPTURE=captured candidate=56ba894594ed3df0fdf117a15747d205b4f0ecd9 \
  property=owner_contract_established boundary=owner resolved=6499 unresolved=0
```

`src/conversion.rs` tests: **27 integration** in `tests/conversion.rs` (20
existing model tests plus 7 live-capture/reuse tests) and **3 module** tests.
The default gate runs all of them; without the external capture it executes and
asserts the typed `NOT_RUN` path (no `#[ignore]`).

## 9. Reuse and revocation

Evidence is reusable only while the property, candidate revision/source/
artifact, boundary identity/kind/allowed behaviour, dependency closure, tool,
loader closure, fault/repaired pair, witness provenance, and witness
command/output/mechanism are unchanged. Any change returns `Revoked` with typed
reasons. The live run reports:

```text
LIVE_REUSE_REPORT reusable=1 property=1 candidate=1 boundary=1 dependency=1
```

Additional tests cover `provenance_changed`, `witness_changed`,
`candidate_artifact_changed`, and `loader_closure_changed` after the DSO bytes
change. Invalid prior or current records fail closed with
`prior_evidence_invalid` or `current_request_invalid`.

## 10. Gates and exact counts

`./ci/gate.sh` (`rust:1.85.0-slim`, 2g) passes fmt, clippy `-D warnings`, debug,
and release:

| Gate | Result |
|---|---|
| fmt | PASS |
| clippy | PASS |
| debug | **341 passed**, 0 failed, 0 ignored |
| release | **341 passed**, 0 failed, 0 ignored |

`./ci/conversion-gate.sh` (`openssl-rs-court:1` / `rust:1.98.1-slim`, 4g)
passes:

| Stage | Result |
|---|---|
| boundary tests | 9 + 3 + 7 + 1 + 1 + 1 = **22 passed** |
| fault witness | **0 passed, 1 failed** with `attempt to add with overflow` |
| fault overflow-off observation | **1 passed**, `answer=1 count=-2147483648` |
| repaired default / overflow-off / positive count | **1 + 1 + 1 passed** |
| Phase-2 courts | `all_pass=True`, including ABI-LOAD |
| curl build and workload | `positive_ok=1`, `negative_rejected=1` |
| capture | 6499 resolved, 0 unresolved; both DSO digests recomputed |
| live crate capture | **27 passed**, `LIVE_REUSE_REPORT` complete |

## 11. Claim ceiling and remaining non-claims

Phase 8 is complete **for the declared 8.2 scope**: one real owner/refcount
native-boundary witness, one compatible repair, one unmodified consumer
workflow, one candidate loader closure, and typed live capture with
property-specific reuse/revocation.

It does **not** establish:

* memory safety, binary or functional compatibility, or `SAFE_COMPATIBLE`;
* a new organic vulnerability discovery (the target's repair commit already
  records this defect);
* all 33 Safe-33 consumers or all owner/allocator/callback cases;
* behavior outside the selected `up_ref` boundary, the curl 8.22.0 workload,
  and the recorded toolchain/authority/loader closure;
* that the authority is correct; the target's defined no-op/refusal behaviour
  is a deliberate safety divergence where the authority's path is undefined.

No Phase 9 work is included. `research/` was not modified, and the external
repository remains under `target/external/` (gitignored).

## 12. Reproduction

```sh
# Full live gate (builds the authority, candidate DSOs, curl, and evidence).
./ci/conversion-gate.sh

# Default crate gate; no external repository required.
./ci/gate.sh
```

The gate restores the external repository to the pinned commit at exit. The
capture record is written under
`target/external/openssl-rs/court/p82-capture/`, and the gate logs under
`target/phase8-gate/`.
