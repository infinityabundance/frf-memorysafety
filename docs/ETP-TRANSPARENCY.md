# ETP local transparency profile: tlog-tiles, checkpoints, and witness policy

**Subphase:** Phase 10.4b (pinned local transparency profile with real proofs).
**Protocol identifier:** `frf-etp-v1`.
**Implementation:** `src/etp_transparency.rs`, `src/etp_witness.rs`,
`src/cli.rs`, `tests/etp_transparency.rs`,
`evaluation/earned-trust/verify_transparency.py`,
`evaluation/earned-trust/transparency/`, and `ci/etp-transparency-gate.sh`.
**Frozen baseline:** FRF-MemorySafety 1.0.0 at commit
`02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`. This subphase does not change any
1.0.0 evidence, schema meaning, or claim ceiling.

This document records one real, finite, local tlog-tiles log. The log was
built from `transparency-dev/tessera` v1.0.4 inside a hardened container. The
Phase 10.3 DSSE attestation envelope is leaf 0. The committed checkpoint is
signed by a test-only Ed25519 key generated inside the container; the private
key was discarded. This is **not** a public transparency log, **not** a Rekor v2
or Sigstore public-good instance, and **not** external witnessing.

---

## 1. Pinned specifications and implementations

| Item | Exact version | URL | Use |
|---|---|---|---|
| RFC 6962 | June 2013 | <https://www.rfc-editor.org/rfc/rfc6962.html> | Merkle tree hash, audit path, consistency proof |
| C2SP tlog-tiles | v1.0.0, 2026-10-07 | <https://c2sp.org/tlog-tiles> | Checkpoint and tile API, entry bundles, tile paths |
| C2SP tlog-checkpoint | v1.1.0, 2026-10-07 | <https://c2sp.org/tlog-checkpoint> | Signed checkpoint note body and Ed25519 log signature |
| C2SP tlog-cosignature | v1.1.0, 2026-10-07 | <https://c2sp.org/tlog-cosignature> | Ed25519 checkpoint cosignature message and key id |
| C2SP tlog-witness | v1.1.0, 2026-10-07 | <https://c2sp.org/tlog-witness> | Witness add-checkpoint semantics; not deployed |
| C2SP tlog-policy | `main`, 2026-11-17 | <https://c2sp.org/tlog-policy> | Informed the group/quorum surface; this profile uses a versioned ETP schema |
| signed-note | `golang.org/x/mod` v0.33.0 | <https://pkg.go.dev/golang.org/x/mod/sumdb/note> | Note text, key id, Ed25519 signature layout |

| Implementation | Pinned identity | Use |
|---|---|---|
| `transparency-dev/tessera` | v1.0.4, commit `6bca8e8d5e23c9941f2b8a08f512b373f7131730`, module hash `h1:IXjGowubcLR0T3zUQrysSMKgtTh9KGKQ0iajUiubyP4=` | Local tlog-tiles log, sequencing, integration, checkpoint signing, POSIX tiles |
| `transparency-dev/merkle` | v0.0.2 | Tessera tree hashing dependency |
| `transparency-dev/formats` | commit `404c0d5b696c6a3e4eb9cec706cfc3550cc47e52` | Tessera policy dependency |
| Go image | `golang:1.24-alpine`, image id `sha256:ebe4e0721205a049b6806724e1ccb05c99e334b1dc1f59e0729b31130bce3aed`, `go1.24.13` | Driver build and log execution |
| Rust image | `rust:1.85.0-slim`, image id `sha256:206360542a30ac87385638c1d123eae6cebcd9d8675d521bb80eac7f5820509b` | Verifier and tests |
| Python image | `python:3.11-slim`, image id `sha256:896edfbcbf0c29ad15681617a8886cb9871b7f24c5fde4606114c8ee6bfe4c70` | Independent verifier |
| Rekor v2 (`sigstore/rekor-tiles`) | v2.4.2, 2026-11-10 | Researched; not deployed (long-lived server, storage backend, entry personality) |

**Security advisories consulted on 2026-11-22.** `transparency-dev/tessera`
v1.0.4 has no published GitHub security advisories. The Rekor v1 repository
has published advisories that are recorded for the researched ecosystem:
GHSA-47q9-m4ww-924m / CVE-2026-48702 (fixed 1.5.2), GHSA-4c4x-jm2x-pf9j /
CVE-2026-24117 (fixed 1.5.0), GHSA-273p-m2cw-6833 / CVE-2026-23831 (fixed
1.5.0), GHSA-frqx-jfcm-6jjr / CVE-2023-33199 (fixed 1.2.0), and
GHSA-2h5h-59f5-c5x9 / CVE-2023-30551 (fixed 1.1.1). The profile does not run a
Rekor v1 server. A zero-advisory result is not a security proof.

## 2. Local log identity

| Field | Value |
|---|---|
| Log origin | `frf.local/etp-transparency-2026` |
| Local log id | `sha256:278f4d522bfa92ae9c73632f569f8946359c647db9fc891e337d06fa8b5f0580` (SHA-256 of the origin; not a provider GID) |
| Note key id | `6dea49ce` |
| Public vkey | `frf.local/etp-transparency-2026+6dea49ce+AchlppRYThyG2YoKurS/hzhk1Iy5QcnqzOKpGEQF4Glh` |
| Raw public key (base64) | `yGWmlFhOHIbZigq6tL+HOGTUjLlByerM4qkYRAXgaWE=` |
| Public key SHA-256 (raw Ed25519 key) | `d4c64169ce9f3e39e1ba7bfd3b5ce21fbe17ff824186661ad8697fb62ccac4f9` |
| Private key | Generated inside `golang:1.24-alpine` under `target/`, removed before the gate exits; never committed |
| Trust profile | `local-test-tlog-tiles`; `external_trust: false`; `public_transparency: false` |

The committed log is a recorded instance. A log instance is identified by its
origin and key. This profile does not claim global non-equivocation, key
continuity, or custody by an independent operator.

## 3. Committed artifacts

| Artifact | Path | SHA-256 |
|---|---|---|
| Leaf 0 entry (1.1.0 envelope) | `evaluation/earned-trust/transparency/attestation-entry.bin` | `b80888683d282e20784e7e13663cbd4a1142806fc01f2e15de195d87cf296e52` |
| Checkpoint, size 1 | `evaluation/earned-trust/transparency/checkpoint-size-1.txt` | `62baf9ab79856b039516e0487c6e0a3c1baa329e807559777e61232b502f947c` |
| Checkpoint, size 3 | `evaluation/earned-trust/transparency/checkpoint-size-3.txt` | `4d1f2fea7c87b9bdc94ab88b0a203d1301154f960ea8f129a9a35b280ca67af5` |
| Inclusion and consistency proof | `evaluation/earned-trust/transparency/proof.json` | `5059ed70025fd757317e7a9d1f2b14743c49444ef744eb89cc951143bcd904f7` |
| Public log key | `evaluation/earned-trust/transparency/log-key.pub` | `4b2f7c3f24abae23fad1d1f43af2c1e0986c58e3081cf2aa86bb5452ce4e9e9e` |
| Transparency policy | `evaluation/earned-trust/transparency/policy.json` | `26123dbe9d7945829d16c9f0143c5e20d964c6642cf1b677ed9ed65c84e5b561` |
| Witness state | `evaluation/earned-trust/transparency/witness-state.json` | `0f03b710a47bd9c0a2cbded6ef14da418ffa7098d10390b58cd3709ae3c6d783` |

The log contains three leaves: leaf 0 is the exact 1.1.0 committed DSSE
envelope; leaves 1 and 2 are deterministic local fillers. The size-3 root is
`d52e1d8ca388d69d9f048eb1172aa177ffb17e76edca47a53866da98dc3a4b84`.
The size-1 root is
`832e275b17c766f8cc7417545f45edfee4b90e7a0a0b69e1292e4205d57a2c01`.
The audit path for leaf 0 is `[pQRya6MtPKWcGxpjscVcgArloNDMrJjWADLMLdo7JTY=,
m4RWQ+MNN8A+nJnPBUX8e0cy/HZYxn+d9cvmRDrhndo=]`; the consistency proof from
size 1 to size 3 is the same two nodes, as RFC 6962 requires for these sizes.

The committed log was rebuilt for 1.1.0 because the attestation envelope
changed. The Phase 10.4b log remains at commit `c150de3`.

The live gate builds a second, fresh log from the same pinned implementation
and appends the same attestation plus 260 deterministic fillers. It verified a
size-261 inclusion proof, a size-1-to-261 consistency proof, a level-0 partial
tile, a level-1 tile, and a real checkpoint signature. The live log private
key was removed before the gate exited.

## 4. Proof and checkpoint formats

A checkpoint is a C2SP signed note:

```text
<origin>
<tree size>
<base64 RFC 6962 root>

— <origin> <base64(4-byte key id || 64-byte Ed25519 signature)>
```

The signed bytes are the note body including the final newline. The key id is
`SHA-256(origin || "\n" || 0x01 || public key)[:4]`. The verifier preserves the
exact original checkpoint bytes and reports their SHA-256; it does not
re-serialize before checking the signature.

A `frf-etp.transparency-proof.v1` proof records:

* the log origin, local log id, API version, tree size, root hash, and leaf index;
* the exact entry bytes as canonical base64 and their SHA-256;
* the declared leaf hash, the audit path, and the checkpoint digest;
* an optional RFC 6962 consistency proof from the known horizon;
* an optional tlog-tiles snapshot with each tile's level, index, width, digest,
  and canonical base64 bytes.

The entry is limited to 64 KiB (the tlog-tiles entry limit). All base64 and
hexadecimal fields are checked for canonical form.

## 5. Verification dimensions

`etp transparency verify --proof FILE --checkpoint FILE --policy FILE [--json]`
reports thirteen separate dimensions. No scalar confidence or composite score
is produced.

| Dimension | Committed result | Meaning |
|---|---|---|
| `log_identity` | `valid` | Proof, checkpoint, policy origin/log id, and pinned vkey agree |
| `log_version` | `valid` | `tlog-tiles-v1` and `tlog-checkpoint-v1` are enabled |
| `entry_binding` | `valid` | Exact entry bytes match the declared SHA-256 |
| `leaf_hash` | `valid` | Declared leaf hash equals `SHA-256(0x00 || entry)` |
| `inclusion` | `valid` | RFC 6962 audit path reaches the signed root |
| `checkpoint_signature` | `valid` | Ed25519 log signature from the pinned key over the exact note body |
| `checkpoint_persistence` | `valid` | Checkpoint bytes equal the declared digest and the persisted horizon |
| `consistency` | `valid` | Size-1-to-3 consistency proof verifies |
| `conflict_detection` | `valid` | No equal-size conflicting root was observed |
| `anti_rollback` | `valid` | Checkpoint is not older than the known horizon |
| `tiled_reconstruction` | `valid` | Tiles rebuild the root, leaf, and audit path |
| `cross_log_rejection` | `valid` | A proof for another log is refused |
| `offline_verification` | `valid` | No network or provider call is made |

`etp checkpoint verify FILE [--policy FILE]` verifies the note, signature, and
known-horizon relation. Without a policy it reports `partial` and
`policy_not_supplied`; it never calls structural parsing a verified signature.
`etp witnesses verify FILE` reports the witness model separately.

## 6. Anti-rollback state

The policy pins one known horizon: size 1, root
`5f9897a64b795ff302e6f212447e24c040c13f3e794cdcf3dbedb354b032c59c`,
checkpoint digest
`c0fe2878334596caafaeb537217e6fa3aff90caa258e005579dec74a210ffb5f`.
The verifier:

* refuses a checkpoint whose size is below the horizon (`rollback`);
* refuses an equal-size checkpoint with a different root
  (`conflicting_checkpoint`);
* requires a consistency proof from the horizon to a newer checkpoint
  (`missing_consistency_proof` or `consistency_invalid`);
* refuses a checkpoint whose digest disagrees with the persisted horizon
  (`checkpoint_persistence_mismatch`).

`--horizon-out FILE` persists the verified newer horizon with an atomic
write-and-rename. The persistence label is `caller_supplied`; the repository
does not operate a durable public horizon service.

## 7. Witness policy model

The witness model is versioned as `frf-etp.witness-state.v1` with an embedded
`frf-etp.witness-policy.v1`. It models:

* administrative domains, operators, declared independence, shared trust
  assumptions, and single-fault domains;
* witness keys, explicit correlation groups, and trust assumptions;
* ordered checkpoint observations, prior maxima, and observed roots;
* the quorum-intersection condition `2q - n > f` (equivalently
  `2q > n + f`), declared as an assumption, not proved;
* correlation detection by domain, correlation group, or a shared
  single-fault assumption; correlated witnesses are reported and the effective
  independent count collapses them;
* equal-size conflicting roots and rolled-back witness state;
* `required_domains` distinct administrative domains;
* external witnessing state. The committed state is `external_witnessing:
  false`, every witness is `not_observed`, and `require_external_witnesses:
  true`; the command returns `NOT_RUN` (exit 6) and reports `not_observed`.

The executable controls also build a **local-test-only** state with three
fresh test keys in three declared domains, two valid C2SP Ed25519
cosignatures, `q=2`, `n=3`, `f=0`, and `required_domains=2`. That state
verifies as a model (`quorum.met=true`, `basis=local_test_only`) while
continuing to report `external_witnessing=false` and
`witness_observation=not_observed`. No external witness is fabricated.

## 8. Corrupted controls executed by the tests

`tests/etp_transparency.rs` executes 25 tests. All use the committed log or
fresh local-test-only witness material; no test is `#[ignore]`.

| Control | Required result |
|---|---|
| valid committed proof | verified; all required dimensions valid |
| exact entry bytes | proof entry equals the committed envelope byte-for-byte |
| wrong leaf hash | `leaf_hash_mismatch` |
| wrong entry digest | `entry_digest_mismatch` |
| wrong index | `inclusion_invalid` |
| wrong sibling order | `inclusion_invalid` |
| wrong root | `root_mismatch` |
| wrong checkpoint signature | `invalid_checkpoint_signature` |
| cross-log proof | `cross_log_proof` |
| equal-size conflicting checkpoint | `conflicting_checkpoint` |
| rolled-back checkpoint | `rollback` |
| missing consistency proof | `missing_consistency_proof` |
| wrong consistency proof | `consistency_invalid` |
| malformed tile | `malformed_tile` |
| tile root mismatch | `tiled_root_mismatch` |
| unsupported log version | `unsupported_log_version`, status `not_run`, exit 6 |
| checkpoint verification | size-1 verified; size-3 partial; wrong signature refused |
| committed witness state | status `not_run`, `not_observed`, exit 6 |
| local-test quorum | verified, external false, `not_observed` |
| correlated witnesses | `correlated_witnesses`, quorum not met |
| quorum failure | `quorum_failed` |
| quorum assumption | `quorum_assumption_invalid` |
| rolled-back witness state | `witness_state_rollback` |
| conflicting witness roots | `conflicting_checkpoints` |
| invalid witness cosignature | `invalid_witness_signature` |

`evaluation/earned-trust/verify_transparency.py --controls` executes 20
independent controls, including the same malformed, cross-log, rollback,
conflict, tile, version, witness-correlation, quorum, and cosignature cases.
The gate requires `controls passed: 20 of 20`.

## 9. Independent verifier

`evaluation/earned-trust/verify_transparency.py` uses only the Python
standard library. It does not import or execute the Rust code. It implements
RFC 8032 Ed25519 verification (and local-test-only signing for controls), the
note key-id and signature layout, RFC 6962 inclusion and consistency
verification, tile reconstruction, and the witness model. It recomputes the
committed results and the live log results in a separate hardened
`python:3.11-slim` container with `--network=none`.

## 10. Real results and NOT_RUN

| Item | Result |
|---|---|
| Committed local log | Real log from tessera v1.0.4; size 3; inclusion and consistency verified |
| Live local log in the gate | Real log from tessera v1.0.4; size 261; inclusion, consistency, level-0 and level-1 tiles, and signature verified |
| Log checkpoint signature | Verified against the pinned local key |
| External/public transparency | `NOT_RUN` / not implemented; no public log, Rekor v2 submission, discovery, gossip, or monitoring |
| External witnessing | `not_observed`; no witness protocol call, no external cosignature |
| ML-DSA-44 cosignatures | Not implemented; Ed25519 only |
| Consistency and non-equivocation beyond the pinned horizon | Not established |
| Semantic validity or completeness of the attestation | Not established |
| Trusted time | Separate local test RFC 3161 token; not external time |

The live local log is not a `NOT_RUN`; it was built, executed, and verified in
the hardened gate. If the pinned Go module graph or image were unavailable,
the gate would record live local inclusion as `NOT_RUN` with the exact blocker
and continue to verify the committed artifacts; it would not fabricate an
entry.

## 11. Public-infrastructure non-claims

* Inclusion is not semantic validity. A logged attestation can be a well-formed
  but false statement.
* Inclusion is not completeness. A proof for one leaf does not show that the
  log contains every relevant event.
* A signed checkpoint is not truth. It authenticates the log key's view of a
  root at a size.
* A witness quorum is not a protocol proof. It is a declared assumption about
  independent administration, and the local-test cosignatures are not external
  witnesses.
* A local test log is not public transparency, not a public-good instance, not
  a transparency-log entry for the public ecosystem, and not a GID.
* Consistency between two sizes is not global non-equivocation.
* A digest is not authentication; a timestamp is not experimental authenticity;
  a passing gate is not a certification or an authorization to deploy.

## 12. Reproduction

```sh
./ci/etp-transparency-gate.sh
```

The gate runs fmt, clippy `-D warnings`, the 25 focused Rust tests, the
committed CLI checks, the 20 independent Python controls, a fresh tessera
v1.0.4 local log with 261 leaves, Rust and Python verification of the fresh
proof, and a cross-log rejection control. Every container keeps the declared
memory/swap cap, pid cap, cpu cap, nofile limit, OOM adjustment, reduced
capabilities, and no-new-privileges. The verification containers use
`--network=none`. The live log private key is written only under `target/` and
is removed before the gate exits.

## 13. Citations

1. RFC 6962, *Certificate Transparency*. <https://www.rfc-editor.org/rfc/rfc6962.html>
2. C2SP, *Tiled Transparency Logs* v1.0.0. <https://c2sp.org/tlog-tiles>
3. C2SP, *Transparency Log Checkpoints* v1.1.0. <https://c2sp.org/tlog-checkpoint>
4. C2SP, *Transparency Log Cosignatures* v1.1.0. <https://c2sp.org/tlog-cosignature>
5. C2SP, *Transparency Log Witness Protocol* v1.1.0. <https://c2sp.org/tlog-witness>
6. C2SP, *Transparency log trust policy* (main, 2026-11-17). <https://c2sp.org/tlog-policy>
7. `transparency-dev/tessera` v1.0.4. <https://github.com/transparency-dev/tessera/releases/tag/v1.0.4>
8. `sigstore/rekor-tiles` v2.4.2. <https://github.com/sigstore/rekor-tiles/releases/tag/v2.4.2>
9. Sigstore Rekor security advisories. <https://github.com/sigstore/rekor/security/advisories>
10. This repository: `docs/ETP-AUTHENTICATED-EVIDENCE.md`, `docs/ETP-TRUSTED-TIME.md`,
    `docs/ETP-CAMPAIGN.md`, `docs/ETP-ARCHIVE.md`, `AGENTS.md`, `SPEC.md`.
