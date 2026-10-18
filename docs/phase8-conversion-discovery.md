# Phase 8.1: real OpenSSL-Rust discovery and conversion-court foundation

Status: **discovery and evidence foundation complete; the live Phase 8
witness was not produced in this environment at the 2 GiB cap.** Phase 8 is
**not complete under this 8.1 record**. This document records what was found,
pinned, inspected, and attempted. It does not claim a memory-safety result, a
compatibility result, an organic vulnerability, or a completed OpenSSL-Rust
Safe-33 court.

> **Phase 8.2 update.** The 2 GiB `SIGKILL` was an envelope limit, not a target
> defect: the pinned candidate builds and runs under a 4g hard cap on a host
> with 134.7 GB RAM. The live witness, repaired revision, curl workload, loader
> closure, and typed live capture are recorded in
> [`phase8-live-conversion.md`](phase8-live-conversion.md). This document
> remains the 8.1 discovery record and is superseded only for the live-run
> blocker.

Snapshot: `staging` at `593f0d1` (tag `v0.8.0`), crate `frf-memorysafety 0.8.0`,
no version bump. The target repository is gitignored under
`target/external/openssl-rs/`; its large `forensics/authorities/src/` tree is
gitignored by that repository and is not part of this project's commits.

## 1. Discovery and exact pin

Discovery was performed with the authenticated `infinityabundance` GitHub
account, not by guessing a repository name:

```sh
gh repo list infinityabundance --limit 200 \
  --json name,description,visibility,isFork,primaryLanguage,updatedAt
gh repo view infinityabundance/openssl-rs \
  --json name,owner,visibility,licenseInfo,defaultBranchRef,description,isEmpty,pushedAt,primaryLanguage,url
git ls-remote https://github.com/infinityabundance/openssl-rs.git \
  refs/heads/main refs/heads/integrate/safe-c33
```

Result:

| Field | Value |
|---|---|
| Repository | `infinityabundance/openssl-rs` |
| Visibility | `PUBLIC` |
| Default branch | `main` |
| Main revision | `b5bbb457ec6a3fd57ab5f9890d1bae3bbe7fe491` |
| Selected branch | `integrate/safe-c33` (the Safe-33 campaign; not protected) |
| Pinned revision | `56ba894594ed3df0fdf117a15747d205b4f0ecd9` |
| Pinned tree | `b54cc2b96d0e12af4a534d9237aadbe089b38660` |
| Commit date | `2026-10-18T07:18:43+01:00` |
| Commit subject | `docs(safe-c33): record subphase 82 and pin HEAD e3892b0c4` |
| License declared by Cargo | `Apache-2.0 OR MIT` |
| GitHub license detection | Apache License 2.0 (`LICENSE-APACHE` and `LICENSE-MIT` both present) |
| Crate / authority | `openssl-rs 0.0.27`, `rust-version = "1.98.1"`, reconstructing `openssl-3.6.4-production` |
| Rust dependencies | none (`[dependencies]` is empty; build-dependencies empty) |
| Upstream pushed-at observation | `2026-10-18T06:18:21Z` (GitHub API) |

The branch moved during discovery. An earlier `ls-remote` observed
`e3892b0c4a2d1abf2792b659d4707965300e3bea`; the re-read selected
`56ba894594ed3df0fdf117a15747d205b4f0ecd9`, which is the later tip and includes
the subphase-82 refcount repair. The link is recorded as a moving external
branch; only the SHA is treated as the candidate identity.

Clone and pin (only under `target/external/`):

```sh
git clone --quiet --depth=1 --branch main \
  https://github.com/infinityabundance/openssl-rs.git target/external/openssl-rs
git -C target/external/openssl-rs fetch --quiet --depth=1 origin integrate/safe-c33
git -C target/external/openssl-rs checkout --quiet --detach FETCH_HEAD
git -C target/external/openssl-rs rev-parse HEAD
# 56ba894594ed3df0fdf117a15747d205b4f0ecd9
git -C target/external/openssl-rs rev-parse 'HEAD^{tree}'
# b54cc2b96d0e12af4a534d9237aadbe089b38660
```

The clone was not modified except for the gitignored authority source tree and
build output described in §6. No commit was made in the target repository.

## 2. Safe-33 boundary cases that actually exist in the target

The Safe-33 campaign is recorded in
`forensics/memory-safety/campaign/safe-c33/` at the pinned revision. Its own
ledger states the current candidate-bound measurement: **628** closure files,
**314** with a recognised ownership seam, **0** fully discharged files, and
**0/33** consumers `SAFE_COMPATIBLE` (`PROGRESS.md`, `CLOSURE.md`). Those are the
target's claims, not this crate's claims.

The genuine cases selected for Phase 8 involve the three requested boundary
kinds.

### 2.1 Owner/refcount boundary with a real callback re-entry edge (RC-1)

Files:

* `src/runtime/refcount.rs` — the shared `CRYPTO_REF_COUNT` protocol.
* `src/ssl/ssl_lib.rs` — `Ssl` / `SslCtx` last-reference and destructor paths.
* `src/ssl/ssl_sess.rs` — `SSL_SESSION_free` path.
* `src/x509/x509_lu.rs` — `X509_STORE_free` path.

The mechanism is documented in `RUNTIME-ALIAS-EVIDENCE.md` §2 and
`REFCOUNT-BOUNDARY.md`. `CRYPTO_free_ex_data` invokes every registered
`free_func` after releasing the registry lock (`src/runtime/ex_data.rs:489-501`)
and zeroes the slots only afterwards (`:505-516`). A callback may call the same
`*_free` again. Before the repair, the count was zero or negative, the second
call mistook itself for the last reference, and the destructor body ran twice.
The repair reserves `REF_DESTROYING` (`i32::MIN`) in the existing `AtomicI32`:
the last releaser claims `1 -> REF_DESTROYING` with a compare-and-swap, a
re-entrant release is `DownRef::Retired`, and `up_ref` refuses zero/destroying
without resurrecting the object.

Fault and repaired revisions:

| Item | Fault revision | Repair revision |
|---|---|---|
| Commit | `cf99d913bcfc67c100793ef7b916a66e90327573` | `d4ba3b068ac347b7e7c23ca55ef200b336c68504` |
| Subject | `docs(safe-c33): pin HEAD after runtime/alias adjudication` | `fix(runtime): destroying-sentinel refcount for callback reentrancy` |
| `src/runtime/refcount.rs` SHA-256 | absent (SHA-256 of empty input `e3b0c442…`) | `284a349c72045aebb0e552a724c1b2aa24dd771206e8c2ade7aa0fe385ae6277` |
| `src/ssl/ssl_lib.rs` SHA-256 | `6c135bca1f84b955a5080d1065579598fa6db5daacee6b21fec433a33841e441` | `c6306e0254bb428ba7c0008f01f37215f78ad7aef7531a93fdb605724070d76d` |
| `src/ssl/ssl_sess.rs` SHA-256 | `9f3ef709227d9c0e4f0de3d92535e3173f15b6c59db40cc590b936f4b55ed1c4` | `6635dfe02c80665fc0a92232fc70753db251ddc41ad404fb5161c5cda817d971` |
| `src/x509/x509_lu.rs` SHA-256 | `b854cbde20e270e1edcda07789dcd01fda9a978fc53d9de25312b4e986484cbf` | `ef53c089bb431dafb643614fc04879e5dea435d6d168c7c9a9bf806826f8ade4` |
| Diff | — | 8 files, +610/−176 (`git diff --stat`) |

Tip digests at `56ba894`: `src/runtime/refcount.rs`
`3bf89ff479ebf4b1a162f0e713231bc6f225dc56e6d25434e2f3e0ce2280d57e`,
`src/x509/x509_lu.rs`
`e4a0c27dbedb10182562d330677c17922346332e6514035cf3c84b714c8ed463`,
`src/ssl/ssl_lib.rs`
`3853167544b12cc947265e3217bba298a78b2e84098d6079994ab550ac306ebc`,
`src/ssl/ssl_sess.rs`
`ba126d289c8c87a22c4754df882182ffc12abfd7575678fe344a56795bb81510`.

Tests named in the target:

* `src/runtime/refcount.rs::tests::down_ref_claims_last_reference_then_retires`
* `src/runtime/refcount.rs::tests::up_ref_refuses_zero_and_destroying`
* `src/runtime/refcount.rs::tests::up_ref_preserves_positive_count_answer`
* `src/runtime/refcount.rs::tests::ref_destroying_never_matches_a_live_count`
* `src/x509/x509_lu.rs::tests::store_free_reentrancy_is_defined_noop`
* `src/ssl/ssl_sess.rs::refcount_reentrancy_tests::session_free_reentrancy_is_defined_noop`
* `src/ssl/ssl_lib.rs::refcount_reentrancy_tests::ctx_free_reentrancy_is_defined_noop`
* `src/ssl/ssl_lib.rs::refcount_reentrancy_tests::ssl_free_reentrancy_is_defined_noop`

### 2.2 Owner boundary: `X509_STORE` atomic reference count

`RUNTIME-ALIAS-EVIDENCE.md` §1 records a real concurrent-use defect: the store
kept `CRYPTO_REF_COUNT references` as a plain `c_int` and used ordinary
read-modify-write. Two concurrent `up_ref`s could lose an increment; a last
`free` racing an `up_ref` could free a live store or leave a live count on a
freed block. The repair uses `AtomicI32` with the authority's orderings and
preserves the layout (size 160, `references` offset 144, `lock` offset 152,
align 8).

| Item | Fault | Repair |
|---|---|---|
| Commit | `9b24504cbe0826e47e2cd5ce21a2c45861bee712` | `3fc7c17105c6b1e1b95beeb84ab1459d393cc04a` |
| Subject | `docs(safe-c33): pin HEAD after destructor adjudication` | `fix(x509): make X509_STORE refcount atomic; record callback reentrancy` |
| `src/x509/x509_lu.rs` SHA-256 | `cdcb60845f4d2cabccda4d577c8d700bd82e0030fcc716296abd31ecaa6b977e` | `b854cbde20e270e1edcda07789dcd01fda9a978fc53d9de25312b4e986484cbf` |

Test: `src/x509/x509_lu.rs::tests::store_refcount_is_atomic_under_concurrent_up_ref`
(8 threads × 2,000 increments, then exact release count).

### 2.3 Owner boundary: `up_ref` overflow into the destroying sentinel (STOP-1)

`PROGRESS.md` records STOP-1: `up_ref` computed `n + 1`; at `i32::MAX` this
panicked under overflow checks and, with them disabled, wrapped to
`i32::MIN`/`REF_DESTROYING`, silently retiring a live object. The repair uses
`checked_add(1)` and refuses before any compare-exchange. Counts below
`i32::MAX` are unchanged.

| Item | Fault | Repair |
|---|---|---|
| Commit | `28c9e34487edf93eca314233d3c0b4a2aa061246` | `1d9c3358bd19c5434e78def3d25ead2617d3a20e` |
| Subject | `docs(safe-c33): record STOP-1 (up_ref overflow) and fix stale contract census` | `fix(refcount): refuse up_ref overflow instead of entering the sentinel` |
| `src/runtime/refcount.rs` SHA-256 | `284a349c72045aebb0e552a724c1b2aa24dd771206e8c2ade7aa0fe385ae6277` | `9b8e30005fe21dc1c3aa3af933fcb211452d991a5c8a42e295eaa137b56f5dbc` |
| Diff | — | 1 file, +21/−4 |

Test: `runtime::refcount::tests::up_ref_refuses_overflow_without_changing_count`.
The target records the merge as `d722f3238`; the repair commit above is the
exact file-level pair used here.

### 2.4 Owner boundary: `Ssl`/`SslCtx` alias and lifecycle closure

`RUNTIME-ALIAS-EVIDENCE.md` §4 records four real defects fixed after the
sentinel work: S1 a dangling session-cache `owner` pointer (use-after-free), S2
a missing `ENGINE_finish`, S3 a missing `dane_final`, and S4 a missing
`ssl_clear_bad_session`. The repair does not change layout, allocator
coordinates, or the C ABI.

| Item | Fault | Repair |
|---|---|---|
| Commit | `9341e0a38748d6b92110105c210866df71531a11` | `483d2afbf3f1d71c94fc7f6a14a42856c8bb10df` |
| Subject | `docs(safe-c33): pin HEAD after destroying-sentinel repair` | `fix(ssl): close Ssl/SslCtx alias obligations; clear session owner` |
| `src/ssl/ssl_lib.rs` SHA-256 | `c6306e0254bb428ba7c0008f01f37215f78ad7aef7531a93fdb605724070d76d` | `8fa495ae818307b7f69135ad947ecbd38e4c677b460c0fd2a767d9df5aa88695` |
| `src/ssl/ssl_sess.rs` SHA-256 | `6635dfe02c80665fc0a92232fc70753db251ddc41ad404fb5161c5cda817d971` | `58e402f907f50fcbda1ddae41d66b44c07ac0008a738c58e4f6b30c2a3a80b52` |
| Diff | — | 5 files, +532/−58 |

The target records seven deterministic tests for S1–S4 and promotes both rows
to `ESTABLISHED`, not `DISCHARGED` (`RUNTIME-ALIAS-EVIDENCE.md` §4.3).

### 2.5 Allocator boundary

The target's allocator surface is the `CRYPTO_*` seam in `src/runtime/mem.rs`
and `src/runtime/secure.rs`. Real converter work recorded in `PROGRESS.md`:

* subphase 73 (`stage/p25/sweep29`): `BIO_METHOD` now uses
  `CRYPTO_zalloc`/`CRYPTO_strdup`/`CRYPTO_free` instead of Box/libc, removing an
  allocator bypass.
* subphase 85 (`stage/p25/sweep43`): `BN_RECP_CTX` moved to the authority-size
  `CRYPTO_zalloc` block with exact size/align coordinates.
* subphase 86 (`stage/p25/sweep44`): `CRYPTO_RWLOCK` moved to the 56-byte
  `CRYPTO_zalloc` block, with a child-process hook test observing one allocation,
  read/write/unlock, and one release.
* The adversarial probes are `#[ignore]`d library tests run by
  `scripts/adv-probe.sh`; `PROGRESS.md` records 18/18 probes at subphase 82.
* `atlas-refresh/unsafe-census.json` records the lexical unsafe census; it is a
  measurement, not a discharge.

The relevant allowed C behaviour is `allocator_refusal_contained`,
`realloc_failure_preserves_owner`, and `cleansed_free_exact_length`, matching the
typed vocabulary in `src/conversion.rs`.

### 2.6 Callback boundary

The callback edges are real and named:

* `src/runtime/ex_data.rs:489-501` invokes `free_func` after releasing the
  registry lock; `:505-516` zeroes slots only afterwards.
* `src/runtime/bio/mod.rs:1110-1116` invokes the BIO ex-data callback.
* `src/x509/x509_lu.rs:790-801` runs `X509_LOOKUP_METHOD.free` and store ex-data
  `free_func` inside `X509_STORE_free`.

The deterministic tests use a real `CRYPTO_EX_free` callback that re-enters the
same `*_free`; they are ordinary library tests, not `#[ignore]`d
(`RUNTIME-ALIAS-EVIDENCE.md` §3). The target explicitly records that the edge
also exists in the C authority and is UB there; the candidate's defined no-op is
a deliberate §17 safety divergence, not a claim that the authority is correct.

## 3. Whole-consumer positive and negative workflows

The Safe-33 cohort is frozen in `CLOSURE.md`: **33 `DROP_IN_PASS`**, 25 at
`L4-linked` and 8 at `L7-functional`. The selected deep workflows are curl,
nginx, HAProxy, Redis, and OpenSSH (`ASSURANCE_PLAYBOOK.md` §26).

The clearest real record is curl 8.10.1 in
`forensics/downstream/p1000-run.json`, `.body.runs[344]` (authority) and
`.body.runs[345]` (candidate). Its workload is a single positive/negative pair:

```text
workload:          curl: verified TLS1.3 fetch + unrelated-CA reject
positive:          curl-verify-fetch      exit=0  http_code=200  ssl_verify_result=0
negative:          curl-unrelated-ca      exit=60 http_code=000  ssl_verify_result=20
negative message:  curl: (60) SSL certificate problem: unable to get local issuer certificate
```

Bound identities from the record:

| Item | Value |
|---|---|
| Candidate run | `run:p1000:candidate:curl` |
| Candidate source SHA-256 | `d15ebab765d793e2e96db090f0e172d127859d78ca6f6391d7eafecfd894bbc0` |
| Candidate source root hash | `34735156e3978b653ea4ea6f1b073ca3ccd5bd8c493ec708160a2dc289598d08` |
| Candidate transcript SHA-256 | `c0c495e9b9cf375da90d55099ebad85d4bc3679ba1a28454f0da56d2be55141e` |
| Authority transcript SHA-256 | `9e242ecf499bee67034fa8d0e9eb01c6dd8d5f2aefaef702aa978580501bf8c9` |
| Candidate loader trace | `/work/artifacts/phase2/install/lib/libssl.so.3`, then `libcrypto.so.3`; `ldd_exit=0`, `trace_exit=0`, all under the candidate prefix |
| Authority loader trace | `/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libssl.so.3`, then `libcrypto.so.3` |

The other selected functional records are the eight L7 families in
`CLOSURE.md` §1a: curl, haproxy, isync, monit, nginx, openssh, pure-ftpd, redis.
The sanitizer downstream record `artifacts/phase18/asan-downstream.json` lists
`clean: [curl, nginx, haproxy, git, python]` and `envelope_limited: [openssh]`
(the OpenSSH seccomp sandbox denies ASan's shadow-memory `mmap`); total findings
in that record is 0, which is a bounded observation, not a proof.

These are records made by the target repository. They were inspected, not rerun
by this crate. The live rerun is blocked as described in §6.

## 4. Actual loader proof mechanism in the target

The target does not rely on exported-symbol counts. Its loader proof is a
combination of:

1. **ELF dynamic identity**: `ABI-DYNAMIC` compares `DT_SONAME`, ELF class/type/
   machine, and every required `DT_NEEDED`. At the pinned revision the candidate
   `libssl.so.3` declares `NEEDED libcrypto.so.3`, `libgcc_s.so.1`, `libc.so.6`,
   and `ld-linux-x86-64.so.2`; `libcrypto.so.3` declares `libgcc_s.so.1`,
   `libc.so.6`, and `ld-linux-x86-64.so.2`. The court reports
   `required_verdict: pass` and `exact_verdict: residual` because the authority
   declares a strict subset (the two extra runtime dependencies are recorded).
2. **Versioned symbol resolution**: `ABI-LOAD` resolves
   `5896/5896` libcrypto and `603/603` libssl symbols via `dlvsym` at their
   declared versions, with zero unresolved.
   `readelf --version-info` on the checked-in libcrypto shows the nodes
   `OPENSSL_3.0.0` through `OPENSSL_3.6.0` (10 nodes).
3. **Production-style load path**: each consumer run records `ldd` and
   `LD_DEBUG=libs` (`dynamic_load_trace`). The trace must name the candidate
   prefix, `ldd_exit` must be 0, and `all_under_prefix` must be true; otherwise
   a system OpenSSL could be mistaken for the candidate.
4. **Substitution**: `ABI-SUBSTITUTION` runs one executable built against the
   authority against the candidate libraries through `LD_LIBRARY_PATH` without
   recompilation.
5. **Cross-DSO state**: Phase 17 isolates the fact that the crate links separate
   DSOs, where the authority shares one `libcrypto.so.3` through `DT_NEEDED`;
   the cross-DSO court raises an error through libssl and reads it through
   libcrypto.

Checked-in candidate distribution artifacts at the pinned revision (hashes
computed from the repository bytes):

| Artifact | SHA-256 |
|---|---|
| `artifacts/phase2/install/lib/libcrypto.so.3` | `ed012b13b03721a2fc36a339205fdb874318f2ae93576f4d4078999283dbec64` |
| `artifacts/phase2/install/lib/libssl.so.3` | `5e5ebc799f46c070cd139a147395ec81e2bf6789d3ffdc5cd3bfc63873674a7d` |
| `artifacts/phase2/install/lib/ossl-modules/legacy.so` | `94aae96e777b2599cd1b0496f2459ef3f5e981e87b0a359e2170a96733df2bb3` |

These artifacts are the Phase-2 distribution shell, not a rebuild of the
Safe-33 tip. They demonstrate the recorded loader mechanism and are cited as
repository evidence, not as a fresh candidate run.

## 5. Dependency invalidation across commits

The target has **no Rust dependency graph to invalidate**: `Cargo.toml` has
empty `[dependencies]` and `[build-dependencies]`. The invalidation surface is
therefore the candidate revision, the first-party source, the pinned authority,
the toolchain, the loaded DSO closure, and the repair revision.

Observed invalidation around the selected cases:

| Change | Fault → repair | What it invalidates |
|---|---|---|
| Refcount sentinel | `cf99d91` → `d4ba3b0` | Any owner/callback evidence for `Ssl`, `SslCtx`, `SslSession`, `X509Store`; `src/runtime/refcount.rs` appears in the repair |
| X.509 atomic count | `9b24504` → `3fc7c17` | Owner evidence for `X509Store`; `src/x509/x509_lu.rs` changes, layout coordinates are asserted |
| Overflow refusal | `28c9e34` → `1d9c335` | Owner evidence for `up_ref`; only `src/runtime/refcount.rs` changes (+21/−4) |
| SSL alias/lifecycle | `9341e0a` → `483d2af` | Owner/callback evidence for `Ssl`/`SslCtx`; `ssl_lib.rs` and `ssl_sess.rs` change |

The toolchain and authority are unchanged across these commits
(`rust-toolchain.toml` SHA-256
`51b89aac2174179a4470434e6666f9f54d52309005332324154cdeeb1f66dd58`,
`Cargo.toml` SHA-256
`36a32914475754059067153cb064d4a7a2fe06d6904310d171506446cc101028`).
The authority pin is `openssl-3.6.4-production`, tarball SHA-256
`9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef`,
source root hash
`27d9917bd7c63d9bb056e674cc08c809b44cde50f9e474cd30041b8b66385432`,
5,873 files / 135,093,194 bytes (`forensics/authorities/AUTHORITIES.json`).

`src/conversion.rs` turns this surface into typed revocation. Evidence is
reusable only while all of the following are identical:

* property (`owner_contract_established`, `allocator_failure_contained`,
  `callback_reentry_rejected`);
* candidate revision, source SHA-256, and artifact SHA-256;
* boundary identity, kind, and allowed C behaviour set;
* dependency closure (toolchain, loader, authority, libraries);
* witness tool identity;
* loader closure (loaded DSOs, under-prefix flag, resolved/unresolved counts,
  trace digest);
* fault/repaired revision pair and changed paths.

A change yields `Revoked { reasons }`; an invalid prior or current record yields
`PriorEvidenceInvalid` or `CurrentRequestInvalid`.

## 6. What was built and run live, and what was blocked

### 6.1 Toolchain and container

The target pins `rust-toolchain.toml` channel `1.98.1`. The image used for the
target attempt was `rust:1.98.1-slim`, with the mandated caps and no weakening:

```sh
docker run --rm --name frf-ms-p8-refcount \
  --memory=2g --memory-swap=2g --pids-limit=512 --cpus=2 \
  --ulimit nofile=1024:1024 --oom-score-adj=500 \
  --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
  --security-opt no-new-privileges \
  -v "$PWD/target/external/openssl-rs":/work -v frf-cargo:/cargo \
  -e CARGO_HOME=/cargo -w /work rust:1.98.1-slim \
  cargo test --locked --lib runtime::refcount::tests -- --test-threads=1 --nocapture
```

Observed tool versions inside that image:

```text
rustc 1.98.1 (48a229cea 2026-09-01)
cargo 1.98.1 (797e8a9bc 2026-08-05)
cc (Debian 14.2.0-19) 14.2.0
GNU ld (GNU Binutils for Debian) 2.44
```

### 6.2 First blocker: excluded authority source

The target's `forensics/authorities/src/**` is gitignored. The first build
failed with 12 `include_str!` errors for files such as
`forensics/authorities/src/openssl-3.6.4/test/recipes/30-test_evp_data/evppkey_ml_kem_512_decap.txt`
and `.../test/slh_dsa.inc`. The official upstream tarball was fetched and
verified:

```sh
curl -fsSL -o .../openssl-3.6.4.tar.gz \
  https://github.com/openssl/openssl/releases/download/openssl-3.6.4/openssl-3.6.4.tar.gz
sha256sum .../openssl-3.6.4.tar.gz
# 9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef
```

The tree was hardlinked into the gitignored expected path so the container could
see it under `/work`. This changed no tracked file.

### 6.3 Second blocker: 2 GiB rustc kill

With the authority source present, the real target test still did not run:

```text
cargo test --locked --lib runtime::refcount::tests
error: could not compile `openssl-rs` (lib test)
Caused by: process didn't exit successfully: `.../rustc ... --test ...`
(signal: 9, SIGKILL: kill)
```

A second attempt with debug info disabled and one codegen job changed only
compiler memory shape, not the mandated limits:

```sh
-e CARGO_INCREMENTAL=0 -e RUSTFLAGS=-Cdebuginfo=0 \
-e CARGO_PROFILE_TEST_DEBUG=0 ... cargo test --locked -j 1 --lib ...
```

Result: the same `SIGKILL` while compiling `src/lib.rs`. The 2 GiB cgroup is
below `rustc`'s peak for this ~800k-line, 64k-unsafe-operation crate. No test
binary was produced; no witness was fabricated. The caps were not raised.

Consequently:

* the smallest real boundary test (`runtime::refcount::tests`) was **not run**;
* no consumer workflow was rerun against a freshly built candidate;
* no fresh loader map was captured;
* the checked-in Phase-2/Phase-18/Phase-24 artifacts and records in §3–§4 were
  inspected, not re-executed.

## 7. Typed conversion-court foundation

`src/conversion.rs` adds the following public model:

* `BoundaryKind`: `owner`, `allocator`, `callback`.
* `AllowedCBehavior`: a closed vocabulary tied to its boundary kind; an empty or
  kind-mismatched set fails closed.
* `WitnessOrigin`: `authentic_native`, `synthetic_seeded`, `substitute`.
* `DiscoveryClaim`: `organic_discovery`, `synthetic_fixture`,
  `no_discovery_claim`.
* `NativeWitness` + `MechanismEvidence`: a witness is rejected unless its
  mechanism is independently confirmed; synthetic/substitute origins cannot
  claim an organic discovery.
* `LoaderClosureEvidence` + `DsoIdentity`: loaded DSOs, exact bytes, version
  nodes, `DT_NEEDED`, under-prefix flag, resolved/unresolved counts, trace
  digest. Empty, under-prefixed, unresolved, or duplicate closures fail closed.
* `FaultRepairRevision`: distinct fault/repaired commits with named changed
  paths.
* `DependencyClosure`: toolchain, loader, authority, and libraries with exact
  digests and duplicate-name refusal.
* `ConversionEvidence`: property + candidate + boundary + witness + revisions +
  dependencies, with a domain-separated local identity.
* `EvidenceRequest` + `reuse_evidence`: property-specific reuse with revocation
  on property, candidate, boundary, dependency, tool, loader, or revision
  change.

Opaque external identities (`GitCommit`, `Sha256Digest`, `BoundaryId`,
`MechanismId`) keep their native textual form in private fields and validate on
parse/deserialize. They are never rehashed into `MsId`; the local evidence
identity is a separate domain-separated `MsId` over the full record.

Tests: 20 integration tests in `tests/conversion.rs` plus 3 module tests in
`src/conversion.rs`. The fixtures are explicitly synthetic and never claim an
organic discovery. The tests cover reuse, every revocation reason, synthetic
seeded vs organic, substitute vs organic, unconfirmed mechanism, open loader
closure, identical fault/repair, property/boundary mismatch, and deterministic
candidate-bound identity.

## 8. Availability, claim ceiling, and what remains for Phase 8.2

Availability:

| Item | State |
|---|---|
| Target discovery and exact pin | Complete |
| Safe-33 boundary characterization | Complete from target files/docs/tests |
| Consumer positive/negative workflow characterization | Complete from target records |
| Loader proof characterization | Complete from target courts/artifacts |
| Fault/repaired revision identity | Complete with exact commits and file digests |
| Typed conversion-court foundation | Implemented |
| Evidence-model tests | Implemented; 23 added, 334 total |
| Live target test under mandated caps | **Blocked**: `rustc` SIGKILL at 2 GiB |
| Fresh consumer replay and loader map | **Blocked**: same build blocker |
| Authentic Phase 8 witness | **Not produced** |

Claim ceiling: this phase establishes discovery, pinning, characterization, and
typed evidence bookkeeping. It does not establish memory safety, compatibility,
`SAFE_COMPATIBLE`, or an organic vulnerability. The target itself records
`0/33` `SAFE_COMPATIBLE` and withholds `PARITY_VERIFIED`.

Phase 8 is **not completable in this environment as specified**, because the
mandated 2 GiB cgroup kills the compiler before any target test can run. Phase
8.2 needs one of the following, without weakening the caps:

1. a prebuilt, digest-pinned `openssl-rs` test binary or distribution DSO set
   produced outside this 2 GiB envelope from the pinned source; or
2. a reproducible build strategy whose `rustc` peak stays under 2 GiB (for
   example a target-owned split/incremental build that the target project
   publishes with exact digests); or
3. an explicitly authorized, separately documented build envelope, which this
   task's rules do not grant.

Once a runnable candidate exists, 8.2 must still: run the four callback/refcount
tests and the allocator probes; capture the fresh loader map/DSO closure; rerun
at least curl's positive/negative pair; produce an independently confirmed
mechanism; and record the result through `src/conversion.rs`. Until then Phase 8
stays failed/blocked, not complete.

## 9. Reproduction summary

```sh
# Target pin
git -C target/external/openssl-rs rev-parse HEAD
# 56ba894594ed3df0fdf117a15747d205b4f0ecd9

# Evidence records inspected
forensics/memory-safety/campaign/safe-c33/CLOSURE.md
forensics/memory-safety/campaign/safe-c33/PROGRESS.md
forensics/memory-safety/campaign/safe-c33/RUNTIME-ALIAS-EVIDENCE.md
forensics/memory-safety/campaign/safe-c33/REFCOUNT-BOUNDARY.md
forensics/memory-safety/campaign/safe-c33/ASSURANCE_PLAYBOOK.md
forensics/downstream/p1000-run.json             # .body.runs[344] and [345]
artifacts/phase18/asan-downstream.json
artifacts/phase2/courts/ABI-DYNAMIC.json
artifacts/phase2/courts/ABI-LOAD.json

# This crate's gate
./ci/gate.sh
# fmt PASS; clippy PASS; test 334 passed / 0 failed / 0 ignored;
# release 334 passed / 0 failed / 0 ignored
```
