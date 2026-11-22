# ETP durable offline archive

**Subphase:** Phase 10.4a (trusted time, corrections/revocation, durable archive).
**Protocol identifier:** `frf-etp-v1`.
**Implementation:** `src/etp_archive.rs`, `src/cli.rs`, `tests/etp_archive.rs`,
`evaluation/earned-trust/make_archive.py`,
`evaluation/earned-trust/archive/`, and `ci/etp-time-gate.sh`.
**Frozen baseline:** FRF-MemorySafety 1.0.0 at commit
`02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`. This subphase does not change any
1.0.0 evidence, schema meaning, or claim ceiling.

The archive is a durable, self-contained copy of the finite Phase 9.1, Phase
10.2, Phase 10.3, and Phase 10.4a records with a complete object inventory. It
is not an external anchor, not a transparency log, and not proof that the
archived evidence is true.

---

## 1. Archive location and manifest

| Field | Value |
|---|---|
| Archive root | `evaluation/earned-trust/archive/` |
| Manifest | `evaluation/earned-trust/archive/manifest.json` |
| Manifest schema | `frf-etp.archive-manifest.v1` |
| Manifest SHA-256 | `c1dbbca82be207891179e62ef5fd5b2069b587436092e33e72b3c6a3af56adb9` |
| Archive identifier | `frf-etp-phase10.4a-archive` |
| Objects | `64` |
| Knowledge horizon | `1795333079` (2026-11-22 07:37:59 GMT) |
| Required categories | 16 |

The archive preserves the repository-relative `evaluation/earned-trust`
layout so the committed reconstructor and verifiers run unchanged from the
archive root.

## 2. Object inventory

Every object has a path, SHA-256, size, schema, category, applicability note,
required flag, and observation time. The inventory includes:

| Category | Objects |
|---|---|
| `opening_manifest` | `protocol.json` |
| `opening_digest` | `opening.sha256` |
| `closure_manifest` | `MANIFEST.json` |
| `claims` | `CLAIMS.json` |
| `receipt` | 13 per-case receipts |
| `raw_evidence` | 25 retained transcripts and court reports |
| `sarif` | `campaign.sarif` |
| `attestation` | DSSE envelope, in-toto statement, and test-only public key |
| `policy` | `trust-policy.json` version 4 |
| `time_token` | `time/token.tsr` |
| `time_request` | `time/request.tsq` |
| `tsa_trust_anchor` | `time/tsa-ca.pem` |
| `tsa_signer_certificate` | `time/tsa-cert.pem` |
| `time_report` | `time/time-report.json` |
| `revocation_registry` | `revocations/registry.json` |
| `support_model` | `revocations/support-model.json` |
| `historical_verdict` | `revocations/historical-verdict.json` |
| `revocation_plan` | `revocations/plan.json` |
| `revocation_report` | `revocations/revocation-report.json` |
| `verifier` | `reconstruct.py`, `verify_attestations.py`, `verify_time.py`, `verify_revocation.py` |
| `reconstruction` | `RECONSTRUCTION.md` |

The archive's time token binds the closure digest
`8b343a22dfc7a35e947a2f85638284e37088a7128ecb4a3de787456db4d5b3ab`. The token
is anchored in the local test TSA, not external trusted time. The revocation
registry is signed by the test-only correction authority and is not a public
feed.

## 3. Verification

```sh
frf-memorysafety etp archive verify ARCHIVE [--json]
```

The verifier:

* parses `manifest.json` with strict JSON (duplicate keys and floats refused);
* rejects an absolute path, `..`, a non-normalized path, or a backslash path;
* rejects a symlink, a non-regular file, an unlisted regular file, a missing
  declared object, a size mismatch, or a digest mismatch;
* rejects an object observed after the knowledge horizon;
* requires every declared required category to be represented by a verified
  required object;
* requires every reconstruction instruction, input object, and command
  requirement to be present and verified.

Exit statuses follow `SPEC.md` §14: `0` verified, `3` integrity failure (missing,
corrupt, unlisted, size/digest/horizon/path violation), `4` refused (missing
required category or incomplete reconstruction inputs), `7` encoding failure.

The report lists the object count, verified count, knowledge horizon, required
categories, missing required categories, every object problem, unlisted objects,
the reconstruction report, refusals, unsupported features, and the claim
ceiling.

## 4. Offline reproduction

The archive's `RECONSTRUCTION.md` records the exact commands. From the archive
root, with `--network=none`:

```sh
python3 evaluation/earned-trust/reconstruct.py
python3 evaluation/earned-trust/verify_attestations.py \
  --attestations evaluation/earned-trust/attestations \
  --policy evaluation/earned-trust/trust-policy.json \
  --campaign evaluation/earned-trust/MANIFEST.json --controls
python3 evaluation/earned-trust/verify_time.py \
  --token evaluation/earned-trust/time/token.tsr \
  --imprint 8b343a22dfc7a35e947a2f85638284e37088a7128ecb4a3de787456db4d5b3ab \
  --tsa-cert evaluation/earned-trust/time/tsa-ca.pem \
  --policy-oid 1.3.6.1.4.1.99999.1 --controls
python3 evaluation/earned-trust/verify_revocation.py \
  --registry evaluation/earned-trust/revocations/registry.json \
  --policy evaluation/earned-trust/trust-policy.json \
  --support evaluation/earned-trust/revocations/support-model.json \
  --historical evaluation/earned-trust/revocations/historical-verdict.json --controls
```

The required images and tools are declared in the manifest and in
`RECONSTRUCTION.md`: `python:3.11-slim` (OpenSSL 3.5.7) and
`rust:1.85.0-slim` (OpenSSL 3.0.15). The archive verification itself needs only
the Rust binary, the archive bytes, and no network.

## 5. Corrupted controls

`tests/etp_archive.rs` executes eight tests:

| Control | Required result |
|---|---|
| valid archive | verified; 64/64 objects; reconstruction complete |
| tampered object | integrity failure, exit 3 |
| missing object | integrity failure, exit 3 |
| unlisted object | integrity failure, exit 3 |
| path escape | integrity failure, exit 3 |
| knowledge-horizon violation | integrity failure, exit 3 |
| missing required evidence | refused, exit 4 |
| incomplete reconstruction inputs | refused, exit 4 |

No test is `#[ignore]`.

## 6. Gate

```sh
./ci/etp-time-gate.sh
```

The gate verifies the committed archive with the Rust CLI, rebuilds a fresh
archive from the committed objects into `target/etp-archive-fresh`, and verifies
that fresh archive in a separate hardened container with `--network=none`. Every
container keeps the declared memory/swap cap, pid cap, cpu cap, nofile limit,
OOM adjustment, reduced capabilities, and no-new-privileges. The repository is
mounted read-only for verification; only `target/` is writable.

## 7. Non-claims and limits

* A verified archive does not establish that the archived evidence is true,
  authentic, complete, or externally anchored.
* A digest detects accidental or silent change; it is not authentication.
* An actor who can rewrite the archive, the manifest, and every referenced byte
  can produce a self-consistent alternative archive.
* The archive is not a transparency log, not a public revocation feed, and not a
  certification.
* Reproduction requires the declared images and tools; a different toolchain is
  not covered.
* The archive contains a local test TSA token, not external trusted time.
* A passing gate is not a certification and not an authorization to deploy.

## 8. Claim ceiling

A verified archive establishes only that the declared objects are present, are
regular files, have the declared sizes and SHA-256 digests, that no unlisted
regular file is present, and that the declared reconstruction inputs and
commands are available. It does not establish that the archived evidence is
true, authentic, complete, externally anchored, or sufficient to reproduce a
result without the declared container images and tools.
