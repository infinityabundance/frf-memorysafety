# ETP reproducibility: declared artifacts and two-build receipts

**Status:** Phase 11.1 implementation, on `staging` after the 1.1.0 release.
**Baseline:** 1.0.0 at `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`; 1.1.0 at
`ddfa7be`. This phase is additive and does not change the 1.0.0 or 1.1.0
evidence, schema meanings, or claim ceilings.

## 1. What this establishes and what it does not

The Phase 11.1 receipt records eight separate reproducibility dimensions:

| Dimension | Meaning |
|---|---|
| `source_reconstruction` | the declared source inputs are digest-bound |
| `environment_reconstruction` | the declared toolchain, flags, and environment are digest-bound |
| `byte_identical_artifact` | two independent builds produced the same binary bytes |
| `semantically_equivalent_artifact` | a non-identical rebuild is justified as semantically equivalent |
| `experiment_replay` | a declared experiment can be replayed |
| `statistical_replication` | a statistical result can be replicated |
| `proof_replay` | a proof object can be replayed |
| `independent_adjudication` | an independent adjudicator reaches the same decision |

These dimensions are never collapsed into a confidence score or assurance level.
A byte difference is never normalized into a byte-identity pass, and semantic
equivalence cannot upgrade a byte difference into byte identity. `NOT_RUN` is
never established.

**Claim ceiling.** This is a bookkeeping and observation mechanism over declared
inputs. It does not establish that the build is reproducible outside the
declared host, that the artifact is authentic, that the population is complete,
or that any dimension is independently adjudicated. A digest is not
authentication, a justification is not proof, and a passing verifier is not
certification.

## 2. Artifact identity

The receipt records, for both the primary and rebuild artifact:

- source-tree SHA-256 over the declared source/instrument files;
- `Cargo.lock` SHA-256;
- build-recipe SHA-256 (the exact command and environment overrides);
- exact `rustc -Vv` version and host;
- target, features, profile, LTO, panic, and overflow-check settings;
- environment-whitelist SHA-256;
- binary SHA-256 and size;
- an explicit scope string.

The declared source set is `src/**/*.rs`, `Cargo.toml`, `Cargo.lock`,
`rust-toolchain.toml`, the two integrity-gate scripts, and
`evaluation/earned-trust/build_integrity_receipt.py`. The source tree is mounted
read-only during the gate.

## 3. Two-build gate

`ci/etp-integrity-gate.sh` runs a single hardened container:

- image `rust:1.85.0-slim`;
- `--memory=2g --memory-swap=2g --pids-limit=512 --cpus=2`;
- `--ulimit nofile=1024:1024 --oom-score-adj=500`;
- `--cap-drop ALL` with only `DAC_OVERRIDE`, `CHOWN`, `FOWNER`, `SETUID`, and
  `SETGID` restored;
- `--security-opt no-new-privileges`;
- source mounted read-only, Cargo home on a named volume, receipt directory
  writable.

Inside the container:

```sh
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_DEBUG=0
export SOURCE_DATE_EPOCH=0
export RUSTUP_AUTO_INSTALL=0
cargo build --locked --release --bin frf-memorysafety --target-dir /tmp/frf-b1
cargo build --locked --release --bin frf-memorysafety --target-dir /tmp/frf-b2
```

The release profile's `overflow-checks = true` is retained. Debug information is
overridden to zero for the reproducibility comparison and that override is
recorded in the build-recipe digest; this is a declared build configuration, not
a silent normalization.

## 4. Measured result

Running `./ci/etp-integrity-gate.sh` on 2026-11-22 produced:

| Field | Value |
|---|---|
| Source-tree SHA-256 | `6d6ac424f443ec44f7d267c9d18a622fcaa4cc1c6823403f0e26b6b2cda4addc` |
| Lockfile SHA-256 | `5f63c136103d54dff0ce9cbcecf219b8a9f802b4e334f210adfa3ca6837a1bd9` |
| Build-recipe SHA-256 | `e0e51af3dedafb47ea15c6cb2037577967ef2ff8af704100db80612f221c1f0f` |
| Environment-whitelist SHA-256 | `208e5488bdba6ab4cb91a51cccf2711546f90e222c4e5195d050963b4334e6ab` |
| Toolchain | `rustc 1.85.0 (4d91de4e4 2025-02-17)`, `x86_64-unknown-linux-gnu` |
| Primary binary SHA-256 | `1a1b90088a7cb2711bd232ab964a106fe1f294f91cab74b7cb5d2b1b3d9cddf1` |
| Rebuild binary SHA-256 | `1a1b90088a7cb2711bd232ab964a106fe1f294f91cab74b7cb5d2b1b3d9cddf1` |
| Binary size | 9,466,400 bytes |
| Byte-identical | yes |
| Population | 13 cases |
| Population manifest SHA-256 | `d29246c361d4fcc6a53724bc45e8331bf04e6e0167f4292159d0ca6b89a4761e` |

The receipt and the three CLI verification reports are under
`evaluation/earned-trust/integrity/`.

## 5. Population derivation

The population manifest is derived from the 13 committed campaign receipts in
`evaluation/earned-trust/receipts/*.json`. Cases are sorted by identifier and
each case digest is the SHA-256 of the exact receipt bytes. The manifest digest
is the SHA-256 of the canonical JSON of `{version, cases, count}`.

No directory iteration order, file modification time, build state, or inherited
environment selects the population. A missing population is not an empty
population; an empty population is refused. The verifier rejects forbidden
selection keys (`mtime`, `ctime`, `timestamp`, and related fields) anywhere in
the document.

## 6. Independent verification

`evaluation/earned-trust/verify_reproducibility.py` is a separate Python
standard-library verifier. It does not call the Rust code. It recomputes:

- the binary digests and sizes from the two builds;
- the source-tree, lockfile, build-recipe, and environment-whitelist digests;
- the toolchain identity;
- the population cases, count, and manifest digest;
- the dimension statuses, including the byte-identity honesty rule.

The verifier's `--self-test` mode refuses seven corrupted controls: tampered
binary digest, tampered population case, count mismatch, manifest-digest
mismatch, dishonest byte-identity status, forbidden `mtime` selection, and a
missing claim ceiling.

The Rust CLI also verifies the same receipt through `etp integrity verify`,
`etp reproducibility`, and `etp population`; these are bookkeeping checks, not
independent confirmation.

## 7. Limits

- The two builds share one host, one container image, one toolchain, one Cargo
  registry cache, and one administrative trust domain. Two target directories
  are not two independent build venues.
- The gate does not use a syscall tracer. It records declared inputs and a
  clean environment allowlist, but it cannot prove that the compiler read no
  undeclared host file.
- Only the declared CLI binary is compared. Other artifacts, targets, features,
  and profiles are out of scope.
- The result is a byte comparison, not a correctness, safety, or authenticity
  result. It does not establish that the binary implements the specification.
- The population is the committed 13-case campaign population; its completeness
  relative to all possible cases is not established.
- `target/` artifacts are not committed. The receipt records their historical
  digests but cannot, by itself, make the original bytes available.

## 8. Reproduction

```sh
./ci/etp-integrity-gate.sh
./ci/gate.sh
```

The gate rewrites `evaluation/earned-trust/integrity/` and exits non-zero on a
structural, digest, population, or verification failure.

## 9. References

- Reproducible Builds, *Definition* and *Specifications*:
  <https://reproducible-builds.org/docs/definition/> and
  <https://reproducible-builds.org/specs/>.
- The Cargo Book, *Profiles*:
  <https://doc.rust-lang.org/cargo/reference/profiles.html>.
- Rust compiler reproducibility environment controls (`SOURCE_DATE_EPOCH`):
  <https://doc.rust-lang.org/rustc/environment-variables.html>.
- The project's own Phase 9.1 pre-registration and independent reconstruction:
  `evaluation/PRE-REGISTRATION.md`, `evaluation/reconstruct.py`,
  `ci/reconstruction-gate.sh`.

These references informed the design. They are not a claim of conformance or
certification.
