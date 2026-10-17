# FRF-MemorySafety

Candidate-bound memory-safety assurance for unsafe-to-safe Rust compatibility
ports. This crate records and checks finite evidence, claim scopes, obligations,
and support derivations. It deliberately separates finite-model results from
universal soundness claims.

**This build makes no memory-safety soundness claim.** It is phase-1
infrastructure: strict encoding, typed evidence, support bookkeeping, a finite
three-rule profile, and an honest CLI. Universal safe-interior soundness and
`SAFE_COMPATIBLE` are outside the finite profile and are always reported as
`WITHHELD_NOT_RUN`.

## Status (0.2.0, phase 1)

Verified in the pinned `rust:1.85.0-slim` container with the commands in
[Verification](#verification):

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo test --locked --all-targets` | 69 passed, 0 failed, 0 ignored |
| `cargo test --locked --release` | 69 passed, 0 failed, 0 ignored |

The conformance test **executes**; it is not ignored. It checks 110,592
configurations and 331,776 node-certificate comparisons over the explicit
12-pattern, three-node universe.

### Implemented

- Strict `ms-canonical-json-v1` parsing/encoding: duplicate keys, floats,
  trailing bytes, UTF-8, and all six resource limits.
- Domain-separated `ms1-` SHA-256 identities over twelve domains.
- Typed claims, scope anchors, execution modes, epistemic statuses, hazards,
  obligations, detector outcomes, and opaque external FRF/FRF-Fuzz/Gemel IDs.
- Least-fixed-point positive and admissible support; challenges, certificates,
  exact cuts, incremental revocation, and policy-versioned reconstruction.
- The finite three-rule profile: exact enumeration, subset restriction, and
  same-domain conjunction, with nine named refusal checks.
- A deterministic local buffer model with 24 records (8 scenarios for each of
  C0/C1/C2) and 5 requested claims per variant.
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

### NOT_RUN in this build

- Live Miri, AddressSanitizer, LeakSanitizer, ThreadSanitizer
- Live Kani or Loom
- Live FRF court / OpenReceipt verification
- Live FRF-Fuzz coordinator
- Live Gemel publication
- Live OpenSSL-Rust Safe-33 native courts
- Native proof-checker adapters
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
frf-memorysafety support evaluate FILE
frf-memorysafety support explain FILE
frf-memorysafety evidence verify --root DIR
frf-memorysafety report --case FILE --format json|markdown

frf-memorysafety court run ...              # NOT_RUN, exit 6
frf-memorysafety detector calibrate --live  # NOT_RUN, exit 6
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
  "claim": "q"
}
```

`evidence verify --root DIR` walks regular `*.json` files (skipping symlinks),
requires each to parse strictly and be byte-canonical, and exits 3 if any file
fails.

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

Exit 0 never means universal soundness was established.

## Verification

All Rust builds and tests run in Docker, never on the host. The source mount is
read-only except for the writable `target` volume, and every container is
memory-, swap-, PID-, and CPU-bounded:

```sh
docker run --rm \
  --memory=2g --memory-swap=2g --pids-limit=512 --cpus=2 \
  -v "$PWD":/src:ro -v "$PWD/target":/src/target \
  -v frf-cargo:/cargo -e CARGO_HOME=/cargo -w /src \
  rust:1.85.0-slim cargo fmt --all -- --check

docker run --rm \
  --memory=2g --memory-swap=2g --pids-limit=512 --cpus=2 \
  -v "$PWD":/src:ro -v "$PWD/target":/src/target \
  -v frf-cargo:/cargo -e CARGO_HOME=/cargo -w /src \
  rust:1.85.0-slim cargo clippy --all-targets --all-features -- -D warnings

docker run --rm \
  --memory=2g --memory-swap=2g --pids-limit=512 --cpus=2 \
  -v "$PWD":/src:ro -v "$PWD/target":/src/target \
  -v frf-cargo:/cargo -e CARGO_HOME=/cargo -w /src \
  rust:1.85.0-slim cargo test --locked --all-targets

docker run --rm \
  --memory=2g --memory-swap=2g --pids-limit=512 --cpus=2 \
  -v "$PWD":/src:ro -v "$PWD/target":/src/target \
  -v frf-cargo:/cargo -e CARGO_HOME=/cargo -w /src \
  rust:1.85.0-slim cargo test --locked --release
```

`Cargo.lock` is committed and the first test run uses `--locked`. The
`tests/lockfile.rs` guard also fails if the lockfile or pinned toolchain is
missing.

## Layout

```text
src/identity.rs   canonical encoding, limits, domain-separated identities
src/model.rs      typed claims, scopes, obligations, hazards, external IDs
src/support.rs    fixed-point support, challenges, certificates, exact cuts
src/profile.rs    finite three-rule profile and deterministic buffer model
src/cli.rs        manual command parser and file-only commands
src/lib.rs        public API and capability matrix
tests/            canonical vectors, support semantics, conformance,
                  profile model/refusals, CLI, lockfile
```

## Non-transfer

A finite compatibility or model result does not imply a sound safe interior.
A sanitizer or Miri pass does not imply soundness. Absence of `unsafe` does not
imply soundness. A bounded model result does not imply a universal native
result. An authentic-looking JSON file is not proof of execution. A clean
detector run is not proof of detector sensitivity. See `SPEC.md` §1.
