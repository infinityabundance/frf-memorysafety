# FRF-MemorySafety

Candidate-bound memory-safety assurance for unsafe-to-safe Rust compatibility
ports. This crate records and checks finite evidence, claim scopes, obligations,
and support derivations. It deliberately separates finite-model results from
universal soundness claims.

**This build makes no memory-safety soundness claim.** It is phase-2
bookkeeping infrastructure: strict encoding, typed evidence, founded support
with policy custody, a finite three-rule profile, and an honest CLI. Universal
safe-interior soundness and `SAFE_COMPATIBLE` are outside the finite profile and
are always reported as `WITHHELD_NOT_RUN`.

## Status (0.2.0, phase 2.2)

Verified in the pinned `rust:1.85.0-slim` container with the commands in
[Verification](#verification):

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo test --locked --all-targets` | 114 passed, 0 failed, 0 ignored |
| `cargo test --locked --release` | 114 passed, 0 failed, 0 ignored |

The conformance tests **execute**; they are not ignored. The shipping engine is
compared against a separately coded oracle in `tests/support_oracle/` over the
explicit 12-pattern, three-node universe: 110,592 configurations, 331,776
all-node certificate comparisons, and 331,776 all-node exact-cut comparisons.
The paper's distinct counting definition, which checks only positively
supported nodes before a challenge, is pinned at 17,712. See
`docs/phase2-conformance.md` for the exact domain, methodology, and claim
ceiling.

### Implemented

- Strict `ms-canonical-json-v1` parsing/encoding: duplicate keys, floats,
  trailing bytes, UTF-8, and all six resource limits.
- Domain-separated `ms1-` SHA-256 identities over twelve domains.
- Typed claims, scope anchors, execution modes, epistemic statuses, hazards,
  obligations, detector outcomes, and opaque external FRF/FRF-Fuzz/Gemel IDs.
- Least-fixed-point positive and admissible support with explicit leaf
  admission, challenged premises, all-node certificates, exact node and rule
  cuts, incremental revocation, and noninterference witnesses.
- Digest-bound historical verdicts that replay under their original policy and
  detect policy substitution, result tampering, or digest tampering.
- The nine §12.4 coverage/policy/support cases transcribed from the paper's
  original `acceptance_cases.py` fixtures and exact outcomes, plus
  wrong-greatest-fixed-point, hidden-intermediate, shared-mapping,
  changed-policy, and implicit-leaf mutant courts.
- An independently written fixed-point/certificate/exact-cut oracle and a
  paper-corpus test that aligns the 17,712 exact-revocation-cut definition with
  the crate's all-node 331,776 comparisons.
- CLI policy custody: `support evaluate` and `support explain` accept a policy
  file, expected policy digest, and expected policy version, and reject
  substitution with SPEC §14 exit statuses.
- The finite three-rule profile: exact enumeration, subset restriction, and
  same-domain conjunction, with nine named refusal checks.
- A deterministic local buffer model with 24 records (8 scenarios for each of
  C0/C1/C2) and 5 requested claims per variant, plus a separately written Rust
  replay of the original eight-case model in `tests/original_domain_replay.rs`.
- An evaluator that replays each local-model case against the crate's own
  reconstruction, so a fabricated case outcome and its honestly rehashed
  observation are still refused.
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

The C0 `Parity` result is scoped to the six adjudicable cases. Over the full
eight-case domain it is not established, because two cases have modeled
conflicts and no adjudicated observation; this matches the original
`research/paper/research/worked_bundle.py` results. The replay test checks the
original counts and makes this scoping difference explicit.

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
frf-memorysafety support evaluate FILE [--policy POLICY_FILE] [--expect-policy-digest MS1_ID] [--expect-policy-version VERSION]
frf-memorysafety support explain FILE  [--policy POLICY_FILE] [--expect-policy-digest MS1_ID] [--expect-policy-version VERSION]
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
  "claim": "q",
  "policy": { "id": "example-policy", "version": "1" }
}
```

The optional `policy` identity binds the support file to a policy version. A
policy file has the shape `{"id": ..., "version": ..., "rules": {...}}`.
`--policy` additionally requires the policy file's rules to equal the support
file's rules. `--expect-policy-digest` accepts the canonical `ms1-...` policy
digest. Rule, digest, or version substitution exits 3; malformed expected
digest or a missing policy identity exits 2.

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

`./ci/gate.sh` is the canonical gate runner. Every Rust build and test runs in
the pinned `rust:1.85.0-slim` container, never on the host. A successful run
prints `PASS` for each gate and writes full logs to `target/gate-logs/`.

The four gates are:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
cargo test --locked --release
```

Every container is hardened as follows:

- `--memory=2g --memory-swap=2g` caps memory and swap together, so the
  container is OOM-killed before the host is placed under memory pressure;
  `--oom-score-adj=500` makes it the preferred OOM victim.
- `--pids-limit=512 --cpus=2 --ulimit nofile=1024:1024` bound process count,
  CPU quota, and file descriptors, and each gate has a 1800-second timeout.
- `--cap-drop ALL` followed by only `DAC_OVERRIDE`, `CHOWN`, and `FOWNER`
  restoration, plus `--security-opt no-new-privileges`, permits writing the
  mounted build directory without granting broader privileges.
- The repository is mounted read-only at `/src`; only `target/` and the
  `frf-cargo` Cargo cache volume are writable.

The host `target/` directory is generated state and is not tracked. Delete it
for a clean-room run; the gate recreates it. `Cargo.lock` is committed and the
test gates use `--locked`. The `tests/lockfile.rs` guard also fails if the
lockfile or pinned toolchain is missing.

## Layout

```text
src/identity.rs   canonical encoding, limits, domain-separated identities
src/model.rs      typed claims, scopes, obligations, hazards, external IDs
src/support.rs    fixed-point support, challenges, certificates, cuts, custody
src/closure.rs    set-based declared/observed coverage comparison
docs/             phase-2 requirement alignment, conformance methodology, citations
src/profile.rs    finite three-rule profile and deterministic buffer model
src/cli.rs        manual command parser and file-only commands
src/lib.rs        public API and capability matrix
tests/            canonical vectors, support semantics, independent oracle,
                  §12.4 cases, mutant courts, paper corpus, profile model/refusals,
                  replay, CLI
```

## Non-transfer

A finite compatibility or model result does not imply a sound safe interior.
A sanitizer or Miri pass does not imply soundness. Absence of `unsafe` does not
imply soundness. A bounded model result does not imply a universal native
result. An authentic-looking JSON file is not proof of execution. A clean
detector run is not proof of detector sensitivity. See `SPEC.md` §1.
