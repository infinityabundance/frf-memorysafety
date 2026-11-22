# ETP trusted time: RFC 3161 local test token and trust-domain separation

**Subphase:** Phase 10.4a (trusted time, corrections/revocation, durable archive).
**Protocol identifier:** `frf-etp-v1`.
**Implementation:** `src/etp_time.rs`, `src/cli.rs`, `tests/etp_time.rs`,
`evaluation/earned-trust/verify_time.py`, `evaluation/earned-trust/time/`, and
`ci/etp-time-gate.sh`.
**Frozen baseline:** FRF-MemorySafety 1.0.0 at commit
`02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`. This subphase does not change any
1.0.0 evidence, schema meaning, or claim ceiling.

This document records one real RFC 3161 token created by a local, test-only TSA
inside the hardened gate. It is not external trusted time, not a public
timestamp authority, and not a transparency log. Phase 10.4b adds a separate
local tlog-tiles log; this token does not bind inclusion in it.

---

## 1. Trust domain

The gate generates a local TSA CA and a TSA signing certificate under `target/`
inside `rust:1.85.0-slim`. The private keys never leave `target/` and are removed
before the gate exits. The committed artifacts contain only public certificates,
the request, the token, and the report.

| Item | Value |
|---|---|
| TSA trust domain label | `local-test-tsa` |
| External trusted time | `false` |
| CA subject | `CN = "FRF Test TSA CA (local, test-only)"` |
| CA validity | 2026-11-22 08:34:02 GMT to 2026-11-24 08:34:02 GMT |
| CA certificate PEM SHA-256 | `5627df3672b7ab958ddccdd3d23c9c1aa73467856efd534779c5040ba0f8a4ee` |
| CA certificate DER SHA-256 (pinned digest) | `f0c0abca00067cfde4c6f472b7aba771d9423384f44c2189ed365d318ae749a2` |
| TSA signer certificate PEM SHA-256 | `0be9b4e23110623cb07f05552b2ae74b41f03e51188592fa1ed34bf40a6d64ab` |
| TSA signer subject | `CN=FRF Local Test TSA` |
| TSA extended key usage | `critical, timeStamping` |
| TSA policy OID | `1.3.6.1.4.1.99999.1` |
| OpenSSL in the Rust image | `OpenSSL 3.0.15 3 Sep 2024` |
| OpenSSL in the Python image | `OpenSSL 3.5.7 9 Jun 2026` |
| Rust image | `rust:1.85.0-slim`, image id `sha256:206360542a30...0509b` |
| Python image | `python:3.11-slim`, image id `sha256:896edfbcbf0c...e4c70` |

The token is committed at `evaluation/earned-trust/time/token.tsr`. Its
generation time is `1795336442` (2026-11-22 08:34:02 GMT). The chain is verified
at the token generation time, so the two-day test certificate validity does not
retroactively invalidate the historical token. A verifier that wants present
authorization must supply a separate freshness policy; a valid historical token
is not present authorization.

The Phase 10.4b instrument change changed the campaign closure. The local test
token was regenerated over the exact new closure digest
`20743ae9b2315a66c4529e8f14e8799bfa4fdb48a6a9849bf5d5c8524b39ac25` with a
fresh local TSA CA and TSA signer certificate. The old token, CA, and request
were not reused. The token remains local test material; it is not external
trusted time and it does not bind transparency inclusion.

The 1.1.0 crate-version change re-froze the campaign closure again. The local
test token was regenerated over
`226e2e9070b99d5e0563d28245cbab926cd0549484c05ef4295dd57590493b33` with a
fresh local TSA CA and TSA signer certificate. The Phase 10.4b token remains at
commit `c150de3`. The 1.1.0 token remains local test material; it is not
external trusted time and it does not bind transparency inclusion.

## 2. Token and request

| Field | Value |
|---|---|
| Evidence bytes | `evaluation/earned-trust/MANIFEST.json` |
| Evidence SHA-256 (imprint) | `226e2e9070b99d5e0563d28245cbab926cd0549484c05ef4295dd57590493b33` |
| Token | `evaluation/earned-trust/time/token.tsr` |
| Token SHA-256 | `ebe10c5d202b060c895c83a6eb278ba16ac886d331efda7b4ad8dbb36f48efce` |
| Request | `evaluation/earned-trust/time/request.tsq` |
| Request SHA-256 | `71b104b8d0c14c968ae587c7bbf30a455f8f16668dc88ee286050e6f3d7518ca` |
| Hash algorithm | `sha256` |
| Policy OID | `1.3.6.1.4.1.99999.1` |
| Serial | `02` |
| Generation time | `1795336442` / `Nov 22 08:34:02 2026 GMT` |
| Accuracy | `0x01 seconds, unspecified millis, unspecified micros` |
| Ordering | `yes` |
| TSA name | `DirName:/CN=FRF Local Test TSA` |

The token binds the exact closure digest. It does not bind the experimental
execution date, the source creation date, the evidence production date, the
statement authentication date, any transparency-log inclusion, any witness
observation, any release authorization, or any correction time. Those are
separate facts in the report.

## 3. Verification dimensions

`etp time verify TOKEN --imprint HEX [--tsa-cert PEM] [--json]` reports seven
separate dimensions. No scalar confidence or composite score is produced.

| Dimension | Committed result | Meaning |
|---|---|---|
| `token_integrity` | `valid` | The token parsed as a granted RFC 3161 response |
| `imprint` | `valid` | The token message imprint equals the declared digest |
| `hash_algorithm` | `valid` | The imprint algorithm is SHA-256 |
| `signature_chain` | `valid` | The CMS signature chains to the pinned CA at the token time |
| `policy_oid` | `valid` | The token policy OID equals the expected OID |
| `certificate_pin` | `valid` | The pinned certificate DER digest equals the expected digest |
| `gen_time` | `valid` | The generation time parsed and is internally consistent |

The verifier also reports the exact serial, accuracy, ordering, TSA name, token
digest, request digest, pinned certificate subject and dates, and command
provenance. The trust domain is `local-test-tsa`; `external_trust` is always
`false`.

## 4. Temporal facts

The report keeps nine separate temporal facts. A verified token sets only
`trusted_timestamping = observed`; every other fact remains separate.

| Fact | Committed result |
|---|---|
| `source_creation` | `not_observed` |
| `experimental_execution` | `not_observed` |
| `evidence_production` | `not_observed` |
| `statement_authentication` | `not_observed` |
| `trusted_timestamping` | `observed` |
| `transparency_inclusion` | `not_implemented` in this token report; separate local log in Phase 10.4b |
| `witness_observation` | `not_implemented`; Phase 10.4b reports `not_observed` |
| `release_authorization` | `not_observed` |
| `correction_revocation` | `not_observed` |

`execution_time_established` is always `false`.

## 5. Backdating control

A later token is never treated as proof of an earlier execution date. The CLI
accepts an optional `--declared-execution-unix` only to test the control:

* a declared time earlier than the token generation time is refused with
  `backdated_claim` (exit 4);
* a declared time later than the token generation time is refused with
  `execution_time_not_established` (exit 4);
* a declared time equal to the generation time still reports
  `execution_time_established: false`, because the only established fact is
  token existence at that time.

The gate runs the backdating control on a fresh token and requires exit 4. The
Rust test suite also requires `backdated_claim` for a declared earlier time.

## 6. Shell-free OpenSSL adapter

`src/etp_time.rs` invokes `openssl ts` and `openssl x509` with an explicit argv
and no shell. It:

* resolves the executable to an absolute path and clears the child environment;
* creates a private `0700` working directory under the caller's declared path;
  the directory is removed after the operation;
* writes intermediate files with `0600` permissions;
* bounds wall time (default 30 s, maximum 120 s);
* bounds captured stdout and stderr to 256 KiB per stream;
* records the executable path, OpenSSL version, exact argv, duration, return
  code, and captured-output digests in the report.

Token creation is a gate helper only:

```sh
frf-memorysafety etp time stamp --imprint HEX --tsa-config FILE --out TOKEN \
  [--request-out FILE] [--tsa-cert PEM] [--json]
```

The TSA configuration is generated inside the gate. The committed artifacts are
a recorded instance of the same helper, not a gate-time mutation of the
repository.

## 7. Independent verifier

`evaluation/earned-trust/verify_time.py` uses only the Python standard library
and the OpenSSL CLI. It does not import or execute the Rust implementation. It
re-parses the TSTInfo, recomputes the token and certificate digests, verifies
the chain with `openssl ts -verify`, and runs six executable controls:

| Control | Required result |
|---|---|
| valid token | verified |
| wrong imprint | refused `imprint_mismatch` |
| untrusted TSA | refused `untrusted_tsa` |
| expired TSA at a future verification time | refused `expired_tsa` |
| backdated claim | refused `backdated_claim` |
| missing token | integrity failure `missing_token` |

The gate requires `controls passed: 6 of 6` for both the committed token and a
freshly generated token.

## 8. Corrupted controls executed by the Rust tests

`tests/etp_time.rs` executes nine tests, all with a real local TSA and a real
OpenSSL token:

| Control | Required result |
|---|---|
| valid token | verified; seven dimensions valid; `execution_time_established: false` |
| wrong imprint | `imprint_mismatch`, exit 4 |
| untrusted TSA | `untrusted_tsa`, exit 4 |
| expired TSA (verify at generation + 10 years) | `expired_tsa`, exit 4 |
| missing token | integrity failure, exit 3 |
| backdated claim | `backdated_claim`, exit 4 |
| missing trust anchor | `no_trust_anchor`, exit 4 |
| wrong policy OID | `policy_oid_mismatch`, exit 4 |
| exact digest binding | token imprint equals the closure digest; temporal facts remain separate |

No test is `#[ignore]`.

## 9. Reproduction

```sh
./ci/etp-time-gate.sh
```

The gate runs the committed token, the independent verifier, the focused Rust
tests, a fresh local TSA and token, the backdating control, a fresh offline
archive, and the offline archive verification. Every container keeps the
declared 2g (Rust) or 512m (Python) memory and swap cap, pid cap, cpu cap,
nofile limit, OOM adjustment, reduced capabilities, and no-new-privileges. The
archive verification container has `--network=none`.

## 10. Non-claims and limits

* The token is signed by a local test TSA, not an external trusted timestamp
  authority. `external_trust` is `false`.
* A valid token does not establish that the evidence is true, complete,
  independently reviewed, or safe.
* A valid token does not establish the experimental execution date, the source
  creation date, the evidence production date, or the release date.
* The two-day test TSA certificate validity means the chain is verified at the
  token generation time; it is not a statement about present certificate
  validity.
* No public transparency-log inclusion, consistency, non-equivocation, witness
  observation, or public accountability service exists. Phase 10.4b adds a
  local test tlog-tiles log, which is not public transparency or external
  witnessing.
* A passing gate is not a certification and not an authorization to deploy.

## 11. Citations

1. RFC 3161, *Internet X.509 Public Key Infrastructure Time-Stamp Protocol*.
   <https://www.rfc-editor.org/rfc/rfc3161.html>
2. RFC 5652, *Cryptographic Message Syntax (CMS)*.
   <https://www.rfc-editor.org/rfc/rfc5652.html>
3. OpenSSL 3 documentation, `ts` and `x509`.
   <https://docs.openssl.org/3.0/man1/openssl-ts/>
4. This repository: `docs/EARNED-TRUST.md`, `docs/ETP-ARCHIVE.md`,
   `docs/ETP-AUTHENTICATED-EVIDENCE.md`, `docs/ETP-MIGRATION.md`, `AGENTS.md`.
