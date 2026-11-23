# ETP Phase 15 Audit Matrix

**Frozen baseline:** FRF-MemorySafety 1.0.0 at commit `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`
**Phase:** 15.1a (audit matrix, durable archive extension, policy metadata, hardened gate)
**Commit:** `2e9adaa` (staging, HEAD)

| # | Requirement | Status | File / Test Reference |
|---|---|---|---|
| 1 | **Pinned local transparency profile** | IMPLEMENTED | `docs/ETP-TRANSPARENCY.md` §1-3; `evaluation/earned-trust/transparency/` (proof.json, checkpoint-size-1.txt, checkpoint-size-3.txt, attestation-entry.bin, policy.json, log-key.pub, witness-state.json); `verify_transparency.py` |
| 2 | **Trusted timestamping (RFC 3161 local test token)** | IMPLEMENTED | `docs/ETP-TRUSTED-TIME.md`; `evaluation/earned-trust/time/token.tsr`; `verify_time.py`; `ci/etp-time-gate.sh` |
| 3 | **Authenticated campaign opening and closure** | IMPLEMENTED | `docs/ETP-CAMPAIGN.md`; `evaluation/earned-trust/protocol.json`, `opening.sha256`, `MANIFEST.json`; `verify_attestations.py` |
| 4 | **Proof verification (inclusion, consistency, checkpoint)** | IMPLEMENTED | `docs/ETP-TRANSPARENCY.md` §4-5; `verify_transparency.py` 20 controls; `tests/etp_transparency.rs` 25 tests |
| 5 | **Corrections and revocation (append-only registry, founded-support, historical replay)** | IMPLEMENTED | `docs/ETP-REVOCATION.md`; `evaluation/earned-trust/revocations/`; `verify_revocation.py` 6 controls |
| 6 | **Anti-rollback (known horizon, checkpoint persistence, conflicting roots)** | IMPLEMENTED | `docs/ETP-TRANSPARENCY.md` §6; `verify_transparency.py` rollback/conflict controls; `tests/etp_transparency.rs` |
| 7 | **Offline archive (durable, self-contained, knowledge horizon, reconstruction)** | IMPLEMENTED | `docs/ETP-ARCHIVE.md`; `evaluation/earned-trust/archive/`; `make_archive.py`; `etp archive verify` |
| 8 | **Leaf/entry binding (exact entry bytes, SHA-256, RFC 6962 leaf hash)** | IMPLEMENTED | `docs/ETP-TRANSPARENCY.md` §4; `verify_transparency.py` `entry_binding`, `leaf_hash` dimensions |
| 9 | **Merkle inclusion (RFC 6962 audit path to signed root)** | IMPLEMENTED | `docs/ETP-TRANSPARENCY.md` §4; `verify_transparency.py` `inclusion` dimension; `proof.json` |
| 10 | **Signed checkpoints (C2SP tlog-checkpoint v1.1.0, Ed25519, note body)** | IMPLEMENTED | `docs/ETP-TRANSPARENCY.md` §4; `checkpoint-size-1.txt`, `checkpoint-size-3.txt`; `verify_transparency.py` |
| 11 | **Persistent checkpoint state (known horizon, atomic write-and-rename)** | IMPLEMENTED | `docs/ETP-TRANSPARENCY.md` §6; `transparency/policy.json` pins horizon; `--horizon-out` |
| 12 | **Consistency (size-1 to size-3 RFC 6962 consistency proof)** | IMPLEMENTED | `docs/ETP-TRANSPARENCY.md` §3; `proof.json` consistency proof; `verify_transparency.py` `consistency` dimension |
| 13 | **Equal-size conflicting roots (refused as `conflicting_checkpoint`)** | IMPLEMENTED | `docs/ETP-TRANSPARENCY.md` §6; `verify_transparency.py` conflict control; `tests/etp_transparency.rs` |
| 14 | **Tiled proofs (tlog-tiles v1.0.0, level-0/1 tiles, tile reconstruction)** | IMPLEMENTED | `docs/ETP-TRANSPARENCY.md` §4; `verify_transparency.py` `tiled_reconstruction` dimension; live log 261 leaves |
| 15 | **Witness policy and quorum (administrative domains, correlation, `2q-n>f`)** | IMPLEMENTED | `docs/ETP-TRANSPARENCY.md` §7; `witness-state.json`; `verify_transparency.py` witness model; local-test quorum |
| 16 | **TUF-style key rotation/delegation/expiration/rollback/freeze** | PARTIAL | `evaluation/earned-trust/policy-metadata.json` (new); `verify_policy_metadata.py` (new); trust-policy.json has roles/keys/expiry but no rotation state |
| 17 | **Historical inclusion after revocation (revoked claim remains historically valid)** | IMPLEMENTED | `docs/ETP-REVOCATION.md`; `verify_revocation.py` control "revoked but historically valid"; `historical-verdict.json` |
| 18 | **Public-good infrastructure (public transparency, external witnessing, external trusted time)** | NOT_RUN | `public_rekor_v2`: NOT_RUN — no Rekor v2 submission, long-lived server, storage backend, entry personality not deployed; `public_good_transparency`: NOT_RUN — no public log, monitoring, gossip, or discovery; `external_witnessing`: NOT_RUN — no witness protocol call, no external cosignature; `external_trusted_time`: NOT_RUN — local test TSA only, not external TSA |

## Phase 15.1a Deliverables Status

| Deliverable | Status | Notes |
|---|---|---|
| `docs/ETP-PHASE15-AUDIT.md` | IMPLEMENTED | This file |
| Extended `make_archive.py` | IMPLEMENTED | Includes transparency, suppression-review, all verifiers, attestations, time, revocations, receipts/raw, CLAIMS.json, campaign.sarif, protocol.json, opening.sha256, MANIFEST.json; excludes archive/ |
| `policy-metadata.json` | IMPLEMENTED | TUF-inspired, versioned, with roles, keys, delegations, rotation state, rollback counter, freeze state, correction authority |
| `verify_policy_metadata.py` | IMPLEMENTED | Python stdlib; checks required fields, expiry, delegated-role authorization, rollback monotonicity, freeze state; ≥6 self-test controls |
| `ci/etp-phase15-gate.sh` | IMPLEMENTED | Hardened flags; rebuilds archive to `target/etp-phase15-run/archive/`; verifies offline; runs policy-metadata verifier + self-test; runs time/revocation/transparency verifiers |
| NOT_RUN items recorded | IMPLEMENTED | `public_rekor_v2`, `public_good_transparency`, `external_witnessing`, `external_trusted_time` as NOT_RUN with exact reasons |
| README updated | IMPLEMENTED | Phase 15.1a documented honestly |
| Standards registry updated | IMPLEMENTED | TUF entry added with NOT_IMPLEMENTED status for production rotation |

## Verification Gates

| Gate | Status | Expected Counts |
|---|---|---|
| `./ci/gate.sh` | PASS | 509 tests |
| `./ci/etp-gate.sh` | PASS | Campaign + reconstruction |
| `./ci/etp-auth-gate.sh` | PASS | Attestation + controls |
| `./ci/etp-time-gate.sh` | PASS | Time + revocation + archive |
| `./ci/etp-transparency-gate.sh` | PASS | 25 Rust tests + 20 Python controls |
| `./ci/etp-phase15-gate.sh` | PASS | Archive rebuild + verify + policy-metadata + all independent verifiers |

## Non-Claims

- A passing audit matrix is not a certification.
- Local transparency is not public transparency.
- Local test TSA is not external trusted time.
- Local-test witness cosignatures are not external witnessing.
- Policy metadata is test-only; no production key rotation process exists.
- Historical inclusion after revocation is a model property, not a deployed service.
- The archive is not an external anchor.