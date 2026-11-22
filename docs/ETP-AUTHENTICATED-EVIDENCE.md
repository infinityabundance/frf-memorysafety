# ETP authenticated evidence: DSSE, in-toto, and independent verification

**Subphase:** Phase 10.3 (authenticated attestations).
**Protocol identifier:** `frf-etp-v1`.
**Profile identifier:** `dsse-v1` with `application/vnd.in-toto+json`.
**Implementation:** `src/etp_auth.rs`, `src/cli.rs`, `tests/etp_auth.rs`,
`schemas/etp/`, `evaluation/earned-trust/trust-policy.json`,
`evaluation/earned-trust/attestations/`,
`evaluation/earned-trust/verify_attestations.py`,
`evaluation/earned-trust/make_attestation.py`, and `ci/etp-auth-gate.sh`.
**Frozen baseline:** FRF-MemorySafety 1.0.0 at commit
`02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`. This subphase does not change any
1.0.0 evidence, schema meaning, or claim ceiling.

This document records the finite authenticated-evidence profile implemented in
Phase 10.3. Phase 10.4a adds a local test RFC 3161 token, an append-only test
revocation registry, and a durable offline archive; those are documented in
[`ETP-TRUSTED-TIME.md`](ETP-TRUSTED-TIME.md),
[`ETP-REVOCATION.md`](ETP-REVOCATION.md), and
[`ETP-ARCHIVE.md`](ETP-ARCHIVE.md). This document does not implement Rekor or
any transparency log, an external trusted timestamp authority, Sigstore keyless
identity, or TUF metadata; Rekor/C2SP remains Phase 10.4b work.

---

## 1. What is implemented

Phase 10.3 adds:

1. a versioned DSSE v1 envelope parser and verifier;
2. exact pre-authentication encoding (PAE) over the exact received payload
   bytes;
3. Ed25519-only signature verification for the `v1` profile;
4. in-toto Statement v1 with separately versioned ETP predicate types;
5. a versioned trust policy with roles, actors, scope, and validity windows;
6. a verification report with seven separate dimensions;
7. an independent OpenSSL-based Python verifier that does not use the Rust
   implementation;
8. executable negative controls, including correctly signed but semantically
   incomplete or false statements;
9. a hardened `ci/etp-auth-gate.sh`;
10. versioned schemas under `schemas/etp/`.

A successful verification establishes only that a declared signer authorized by
a declared policy signed the exact received payload bytes and that the payload
predicate agrees with the referenced finite campaign closure. It does not
establish truth, independent review, transparency inclusion, trusted time, or
deployment security.

## 2. DSSE v1 envelope and PAE

The envelope is:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<canonical padded base64 of the exact payload bytes>",
  "signatures": [{"keyid": "<lookup hint>", "sig": "<base64 Ed25519 signature>"}]
}
```

The pre-authentication encoding is exactly:

```text
DSSEv1 <len(type)> <type> <len(payload)> <payload>
```

where each length is the ASCII decimal byte length and no trailing byte is
added. The verifier computes PAE over the bytes decoded from the received
payload. It never parses and reserializes the signed bytes before signature
verification. The statement is parsed only after the signature check has been
evaluated.

Hardening rules:

| Condition | Result |
|---|---|
| duplicate JSON keys | integrity failure (exit 3) |
| floating-point numbers | integrity failure |
| excessive nesting (depth limit) | integrity failure |
| oversized envelope or payload | integrity failure |
| non-canonical or malformed base64 | integrity failure |
| more than 16 signatures | integrity failure |
| duplicate `keyid` in one envelope | integrity failure |
| signature that is not 64 bytes | integrity failure |
| unsupported `payloadType` | integrity failure |
| non-Ed25519 algorithm | refusal (`unsupported_algorithm`) |

`keyid` is a lookup hint only. Authorization is decided by the resolved policy
role, scope, actor, and validity window. A `keyid` collision does not grant
authority, and a matching `keyid` with different public-key bytes fails
signature verification.

## 3. in-toto Statement v1 and ETP predicates

The statement is an in-toto Statement v1:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "<name>", "digest": {"sha256": "<lowercase hex>"}}],
  "predicateType": "https://frf.dev/etp/<predicate>/v1",
  "predicate": { "...": "..." }
}
```

The `v1` profile accepts only the `sha256` subject digest algorithm. The subject
list for a campaign-closure attestation binds three separate facts:

* `campaign-closure:<campaign_id>`: the exact closure-manifest digest;
* `candidate:<candidate_identity>`: the candidate tree identity;
* `raw-evidence:<campaign_id>`: the SHA-256 over the sorted receipt and
  raw-evidence digests.

The predicate types are separately versioned. None of them is SLSA build
provenance, and the statement is never described as SLSA provenance.

| Predicate type | Predicate schema | Required role |
|---|---|---|
| `https://frf.dev/etp/campaign-closure/v1` | `frf-etp.predicate.campaign-closure.v1` | `evidence_producer` |
| `https://frf.dev/etp/instrument-qualification/v1` | `frf-etp.predicate.instrument-qualification.v1` | `instrument_qualifier` |
| `https://frf.dev/etp/reproduction/v1` | `frf-etp.predicate.reproduction.v1` | `instrument_qualifier` |
| `https://frf.dev/etp/proof-admission/v1` | `frf-etp.predicate.proof-admission.v1` | `adjudicator` |
| `https://frf.dev/etp/consumer-closure/v1` | `frf-etp.predicate.consumer-closure.v1` | `evidence_producer` |
| `https://frf.dev/etp/security-findings/v1` | `frf-etp.predicate.security-findings.v1` | `evidence_producer` |
| `https://frf.dev/etp/release-adjudication/v1` | `frf-etp.predicate.release-adjudication.v1` | `release_authority` |

Semantic evaluation is implemented for the campaign-closure predicate only. The
other predicates parse, authorize, and report; their semantics are not
evaluated, and they are never accepted as semantically supported.

### 3.1 Campaign-closure predicate

The campaign-closure predicate records the campaign identifier, the closure
digest, the candidate identity, the raw-evidence digest, the case, receipt, and
raw-evidence counts, the exact sorted case identifiers, the outcome and decision
counts, the closure status, the acceptance value, the derived conclusion, the
independent-review claim, and the campaign claim ceiling.

Verification recomputes the finite campaign from the closure, receipts, and raw
evidence. A predicate is semantically supported only when every one of those
values agrees and the referenced campaign closes and is accepted. A missing
case, a duplicated case, a changed count, a changed outcome, a substituted
candidate, a changed raw-evidence digest, a weakened claim ceiling, or a
conclusion that is not the derived conclusion is refused even when the
signature is valid.

## 4. Trust policy and roles

The trust policy is `frf-etp.trust-policy.v1` and is stored at
`evaluation/earned-trust/trust-policy.json`. It declares a policy identifier, a
monotonic version, a validity window, and five role types:

| Role | Responsibility |
|---|---|
| `evidence_producer` | Produces closure, consumer-closure, and findings predicates |
| `instrument_qualifier` | Qualifies an instrument and records reproduction |
| `adjudicator` | Admits proofs and, when the policy declares it independent, reviews |
| `release_authority` | Records release adjudication |
| `correction_authority` | Records correction and revocation decisions |

Each role declares a predicate scope, a distinct-actor threshold, an
`independent` flag, and authorized keys. Each key declares a `keyid`, the
`ed25519` algorithm, the base64 raw public key, an actor, and a validity
window. The policy parser refuses unknown roles, unknown predicate scopes,
unknown algorithms, duplicate role identifiers, duplicate `keyid` values,
duplicate public-key material, invalid validity windows, and unknown schema or
specification versions.

Enforcement rules:

* a wrong key or an invalid signature is refused;
* a signature by a key outside the required role is `unauthorized_role`;
* a signature by a key outside its validity window is `expired_credential`;
* duplicate credentials never satisfy a threshold;
* multiple signatures by the same actor count as one actor and are not
  independent reviewers;
* a statement that claims `independent_review: established` without enough
  distinct authorized actors is `insufficient_independent_review`.

The committed policy has no adjudicator keys. The committed attestation
therefore reports `independent_review: not_established`, which is the honest
value. The test-only signer is an `evidence_producer`, not an independent
reviewer.

## 5. Verification dimensions

Verification reports seven separate dimensions. No scalar confidence, score,
assurance level, or grade is produced.

| Dimension | Values | Meaning |
|---|---|---|
| `signature_validity` | `valid`, `invalid`, `partial` | At least one signature verified over the exact PAE bytes |
| `payload_integrity` | `valid`, `invalid` | The envelope and payload decoded and parsed under the profile |
| `authorization` | `valid`, `invalid` | A fresh, in-scope key satisfied the required role threshold |
| `scope_applicability` | `valid`, `invalid` | The predicate binds the declared campaign and subjects |
| `freshness` | `valid`, `invalid` | The policy and used keys are inside their validity windows |
| `semantic_support` | `valid`, `invalid`, `not_checked` | The predicate agrees with the recomputed finite campaign |
| `independent_review` | `established`, `not_established`, `insufficient`, `not_checked` | Distinct authorized actors met an independent threshold |

Acceptance requires every required dimension to hold. A valid signature alone is
never acceptance: with no campaign supplied, `semantic_support` is
`not_checked` and the report is refused with
`semantic_support_not_evaluated`.

The CLI command is:

```sh
frf-memorysafety etp attest verify ENVELOPE \
  [--policy FILE] [--campaign FILE] [--json]
```

Exit statuses follow `SPEC.md` §14: `0` accepted, `2` usage, `3` structural or
integrity failure, `4` refused, `7` internal encoding failure. Signing is a
test/gate helper only and is not exposed by the CLI.

## 6. Committed evidence

The committed campaign closure is signed with a test-only ephemeral Ed25519 key.
The public key and policy are committed; the private key was deleted by the
signing helper before it exited. No private key is committed.

The committed envelope was recorded once by
`evaluation/earned-trust/make_attestation.py`. The gate mounts the repository
read-only and re-runs the same helper into `target/etp-attestation-run/`, so a
gate run cannot rewrite committed evidence. The gate then verifies that
generated envelope with both the Rust CLI and the independent verifier and
checks that the private key directory is absent. The committed artifacts are
therefore a recorded instance of the same gate helper, not a gate-time mutation
of the repository.

| Artifact | Path | SHA-256 |
|---|---|---|
| Envelope | `evaluation/earned-trust/attestations/campaign-closure.envelope.json` | `fafd563d816b38be8fc035f33102d0418f2e652f534b876e9057c0960d766e66` |
| Statement payload | `evaluation/earned-trust/attestations/campaign-closure.statement.json` | `71b1e22f5035a0b59eb7011977d0075eec25c5e5fa735ef113146a56d4504d4d` |
| Public key (PEM) | `evaluation/earned-trust/attestations/campaign-closure.public.pem` | present for inspection |
| Trust policy | `evaluation/earned-trust/trust-policy.json` | `a608a33624dbef00129103afba4a56998003d3e6c0a5f426eee709929af6d2cf` |

The predicate binds the closure digest
`8b343a22dfc7a35e947a2f85638284e37088a7128ecb4a3de787456db4d5b3ab`, the
candidate identity
`7fd038b34643743ca4dc36ceb7026973a8900fb0bd9697abc2a9ba64bea02746`, and the
raw-evidence digest
`58c02137266d264590aaa9a60db820392de9ab40030b98a5a63ab4cc0f2dd2f4`.

### 6.1 Phase 10.2 and Phase 10.4a campaign re-freezes

Adding the attestation dependency changed `Cargo.toml`, which is a declared
candidate and instrument file, and adding `src/etp_auth.rs` and changing
`src/cli.rs` and `src/lib.rs` changed the declared instrument. Phase 10.3
therefore re-froze the Phase 10.2 opening manifest as an explicitly recorded
instrument change and re-executed the same finite campaign with the Phase 10.3
instrument.

Phase 10.4a added `src/etp_time.rs`, `src/etp_revocation.rs`, and
`src/etp_archive.rs`, and changed `src/cli.rs`, `src/lib.rs`, and
`src/etp_auth.rs`, all declared instrument files. It re-froze the opening
manifest again and re-executed the same population. The population, expected
outcomes, receipts, accepted cases, retained findings, resource envelope, and
claim ceiling are unchanged. The candidate tree is
`7fd038b34643743ca4dc36ceb7026973a8900fb0bd9697abc2a9ba64bea02746`; the
instrument tree is
`74517c942798087e77335ffc28c4078ed85161a58c388b77d649cfac245cb338`; the
opening-manifest digest is
`08325858b5a18f6a4053f4c25f081219f0f7165c8e2c51de5ec52db09e6a942a`. The
Phase 10.3 opening digest
`fc9202bc553472bb94362e4de1d4da168f51ebd5be624eefc5cf0d334d8fa7ec` and closure
digest `607b36e151fd791f9f8ed52391f7e30f2a2822bfed0c13c63943064f536ae912` remain
available at commit `cb59ddb`. The original Phase 10.2 opening digest was
`2039c3352f9edcf7d5657e341440c466a29cc6f55851b6ecb6243b46a118a236` and its
closure digest was
`fea6c92f9840b30a63769ebd219cced2005ab32ab6b90b7eeeba1af038f01eee`; those bytes
remain available at commit `f17111d` in git history.

The re-freeze does not strengthen any claim. It is a separate instrument change
and a separate execution, and it is recorded here, in `docs/ETP-CAMPAIGN.md`,
and in `docs/ETP-MIGRATION.md`.

## 7. Key custody, administrative owner, rotation, and revocation

* **Key custody.** The committed attestation is signed by an ephemeral test key
  generated inside a hardened container. The private key is written only under
  `target/`, is used once, and is deleted by the helper. The repository contains
  only the public key and the policy.
* **Administrative owner.** The repository owner is the declared administrative
  owner for the test key and for future key custody. Administrative control is
  not technical assurance, and this document does not claim that the owner is
  independent.
* **Rotation.** There is no production rotation process. A new attestation
  requires a new policy version and a new key entry. The current policy is
  version 6; it is test-only and expires on 2027-11-22 (Unix `1826841600`).
* **Revocation.** Phase 10.4a adds an append-only, DSSE-signed test revocation
  registry for the finite Phase 10.4a support model. It is not a public feed and
  not a transparency log. Public revocation, non-equivocation, witness
  observation, and Rekor/C2SP inclusion remain Phase 10.4b or not deployed. See
  [`ETP-REVOCATION.md`](ETP-REVOCATION.md).

## 8. Independent verifier

`evaluation/earned-trust/verify_attestations.py` is independent of the Rust
implementation. It:

* parses the envelope and recomputes PAE from the exact received payload;
* verifies Ed25519 with the OpenSSL CLI in a hardened `python:3.11-slim`
  container;
* re-derives the campaign closure, receipt digests, outcomes, decisions, counts,
  candidate identity, and raw-evidence digest from the committed files;
* enforces policy roles, scope, actors, validity windows, and distinct-actor
  thresholds;
* runs thirteen executable negative controls.

The controls all refuse:

| Control | Required refusal |
|---|---|
| tampered payload | `invalid_signature` |
| wrong key | `invalid_signature` |
| malformed PAE | `invalid_signature` |
| unauthorized role | `unauthorized_role` with a valid signature retained |
| replayed envelope | `campaign_mismatch` with a valid signature retained |
| duplicate credential | integrity failure |
| duplicate actor | `insufficient_independent_review` |
| unsupported algorithm | integrity failure |
| expired key | `expired_credential` |
| substituted subject | `candidate_mismatch` with a valid signature retained |
| false conclusion | `false_conclusion` with a valid signature retained |
| incomplete closure | `population_mismatch` with a valid signature retained |
| valid attestation | accepted (positive control) |

Run it with:

```sh
./ci/etp-auth-gate.sh
```

The gate also generates a fresh ephemeral key, signs the committed closure,
verifies the generated envelope with both the Rust CLI and the independent
verifier, and checks that the private key was discarded.

## 9. Non-claims

Authenticated evidence is not truth. In particular:

* a signature authenticates a signing key over exact bytes; it does not
  establish that the bytes describe a true property;
* authentication is not independent review; the committed attestation has no
  independent reviewer;
* `independent_review: not_established` is not a negative finding, and
  `independent_review: established` would still not prove competence or
  absence of collusion;
* inclusion in any future transparency log would not be completeness;
* multiple signatures are not multiple independent reviewers;
* a trusted timestamp is not experimental authenticity; the Phase 10.4a token is
  a local test token, not external trusted time;
* an evidence commitment is not availability;
* a revocation does not make historical evidence false when produced;
* historical replay under the original policy is not present authorization;
* the finite campaign closure is not a population inference, a detector
  sensitivity estimate, a memory-safety proof, or a deployment authorization;
* a passing gate is not certification;
* no Rekor/C2SP inclusion proof, external trusted timestamp authority, Sigstore
  identity, TUF metadata, public revocation feed, witness observation, or public
  challenge service exists in Phase 10.4a. Rekor/C2SP remains Phase 10.4b.

## 10. Executed results

* Rust focused attestation tests: 21 passed, 0 failed, 0 ignored.
* Independent verifier controls: 13 passed, 0 failed.
* Phase 10.4a focused tests: 9 time tests, 13 revocation tests, and 8 archive
  tests passed, 0 failed, 0 ignored.
* Phase 10.4a independent verifiers: 6 of 6 timestamp controls and 6 of 6
  revocation controls passed.
* Full debug gate: 467 tests passed, 0 failed.
* Full release gate: 467 tests passed, 0 failed.
* The committed attestation is accepted by both the Rust CLI and the independent
  verifier with all seven dimensions reported separately.
* A correctly signed statement with a missing case, a false conclusion, a
  substituted subject, or a replay against another campaign is refused.
* `ci/etp-auth-gate.sh` passes with the declared memory, swap, pid, cpu, nofile,
  OOM, capability, and no-new-privileges controls.

## 11. Citations

1. DSSE, *Dead Simple Signing Envelope* v1.0.0.
   <https://github.com/secure-systems-lab/dsse/blob/v1.0.0/protocol.md>
2. in-toto, *Specification* v1.0.0.
   <https://github.com/in-toto/specification/blob/v1.0.0/in-toto-spec.md>
3. RFC 8032, *Edwards-Curve Digital Signature Algorithm (EdDSA)*.
   <https://www.rfc-editor.org/rfc/rfc8032.html>
4. OpenSSL 3 documentation, `pkeyutl` and Ed25519.
   <https://docs.openssl.org/3.0/man1/openssl-pkeyutl/>
5. SLSA, *Specification* v1.0. <https://slsa.dev/spec/v1.0/> (consulted for
   provenance separation; no SLSA claim is made)
6. Rekor and C2SP transparency-log materials.
   <https://github.com/sigstore/rekor> and <https://c2sp.org/tlog> (not
   implemented in Phase 10.3)
7. RFC 3161, *Time-Stamp Protocol*. <https://www.rfc-editor.org/rfc/rfc3161.html>
   (not implemented in Phase 10.3)
8. This repository: `docs/EARNED-TRUST.md`, `docs/ETP-CAMPAIGN.md`,
   `docs/ETP-CLAIM-INTEGRITY.md`, `docs/ETP-MIGRATION.md`, `AGENTS.md`.
