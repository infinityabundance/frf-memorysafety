# ETP migration and versioning policy

**Policy identifier:** `frf-etp-v1` migration policy.
**Applies to:** `schemas/etp/`, `src/etp.rs`, `docs/ETP-*.md`, and every future
ETP consumer.
**Frozen baseline:** FRF-MemorySafety 1.0.0, commit
`02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`.

---

## 1. Non-negotiable principles

1. **Existing evidence keeps its original meaning.** A 1.0.0 receipt, manifest,
   claim, verdict, report, transcript, provider identity, or schema token is
   interpreted exactly as it was at 1.0.0. No ETP document redefines it.
2. **No retroactive strengthening.** A later version cannot relabel a finite
   result as universal, a model as native, a digest as authentication, a review
   as an independent audit, or a passing gate as certification.
3. **New schemas are versioned and additive.** A new meaning is a new schema
   identifier, a new specification identifier, and new evidence.
4. **Policy, predicate, and identity domains stay explicit.** Reusing a name is
   not reusing a meaning.
5. **`research/` remains excluded.** It is gitignored and is not an ETP input,
   output, evidence source, or migration target.
6. **No silent deletion.** A deprecated schema or vector remains readable and
   documented until a declared removal version.

## 2. Version grammar

ETP uses two identifiers in every wire object.

```text
schema = frf-etp.<object>.v<N>
spec   = frf-etp-v<N>
```

For `v1`:

```text
frf-etp.manifest.v1
frf-etp.claim.v1
frf-etp.obligation-inventory.v1
frf-etp.status-dimensions.v1
frf-etp.validation-report.v1
frf-etp.freeze.v1
frf-etp.version-registry.v1
frf-etp.vector-index.v1
```

Rules:

- `<N>` is a **major** version. A reader that does not know `<N>` must reject
  the document. It must not attempt a best-effort decode.
- Adding, removing, renaming, or re-typing a required field is a major change.
- Adding an optional field with a default is still a major change in this policy,
  because every object uses `additionalProperties: false`. A new field is a new
  schema version.
- Changing an enum value is a major change.
- Changing only prose in a document is not a schema change, but it must not
  alter the meaning of an existing field.
- A patch or editorial release may update a conformance vector only when the
  vector's expected outcome is unchanged. The registry SHA-256 changes; the
  registry entry is updated in the same commit.

A consumer must reject:

- an unknown `<N>`;
- an unknown `spec`;
- a known schema with an unknown field;
- a `v1` document that omits a required field;
- a `v1` document that contains a scalar confidence, score, assurance level, or
  rating field.

## 3. Compatibility matrix

| Producer | Consumer | Rule |
|---|---|---|
| `v1` | `v1` | Accept exactly the declared schema and semantics |
| `v1` | `v2` | `v2` may read `v1` only through a named, documented migration; it must not silently reinterpret |
| `v2` | `v1` | Refuse; a `v1` reader must not guess `v2` semantics |
| unknown | any | Refuse |

A migration function, if one is ever added, must:

- be separate from the validator;
- name the source and target schemas;
- preserve every existing coordinate and dimension;
- never add a stronger property;
- never discard contradictory evidence;
- never convert an unresolved premise into a resolved one;
- be covered by vectors for both success and refusal.

## 4. Domains and identities

The following domains are distinct and are never collapsed:

| Domain | 1.0.0 identity | ETP v1 treatment |
|---|---|---|
| Policy | `MS/POLICY/v1` and policy version | `policy_identity` text; policy version explicit |
| Predicate / acceptance rule | finite-profile rule identity | `semantic_model` and `policy_identity`; no new hash domain |
| Subject | `MS/SUBJECT/v1` | `subject_identity` text; unchanged meaning |
| Source | source digest in source inventory | `source_identity` text |
| Build | toolchain, flags, image, build recipe | `build_identity` text |
| Artifact | executable, DSO, package, evidence bytes | `artifact_identity` text |
| Runtime | environment, loader, resource envelope | `runtime_environment` text |
| Provider object | FRF receipt, FRF-Fuzz finding, Gemel GID | opaque reference in `supporting_evidence`; never rehashed |
| ETP claim | none in v1 | manifest-local `id`; no cryptographic claim identity |

A hash match is not an authentication statement. An ETP `digest` field binds
bytes; it does not assert origin, truth, or independence.

## 5. 1.0.0 freeze

The 1.0.0 evidence set is frozen in
`schemas/etp/etp-freeze-1.0.0.json`. The freeze records:

- release `1.0.0`, tag `v1.0.0`, commit
  `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`;
- SHA-256 for every frozen evidence and phase document;
- the 60-receipt aggregate and the receipt manifest digest;
- an evidence-root digest of
  `508b495b56b28cb9d674094f21dd89153b28905d61fdf9ac227ea3ff1eac6d74`.

The root algorithm is recorded in the freeze file. The Rust validator requires
every `frf-etp.manifest.v1` baseline to match these exact values. A future
baseline requires a new manifest schema version.

The freeze does **not** cover mutable release documents such as `README.md`,
`CHANGELOG.md`, or future ETP phase documents. Those may change without
changing the 1.0.0 evidence meaning. The freeze does cover `SPEC.md`,
`PAPER.md`, the evaluation ledgers, the protocol, the receipt manifest, and the
fifteen phase documents.

The freeze is not authentication. It detects accidental or silent edits to the
declared bytes. A party that can rewrite the freeze, the registry, and all
referenced bytes can produce a self-consistent alternative set. Authenticating
the freeze requires a future signature, transparency log, or external anchor.

## 6. What may change in a later ETP version

A later major version may add:

- new properties, with a new accepting rule and evidence;
- new dimensions, while keeping the original ten separate;
- new contradiction classes or resolution states;
- a cryptographic claim identity;
- campaign-closure, adjudication, and revocation schemas;
- authenticated evidence envelopes and transparency proofs;
- timing, interoperability, and deployment-scope evidence;
- a new frozen baseline.

A later major version may **not**:

- reinterpret a 1.0.0 receipt or schema token;
- treat a digest as authentication;
- treat a signature as truth;
- treat transparency inclusion as completeness;
- treat consistency as global non-equivocation;
- treat multiple signatures as independent reviewers;
- treat reviewer approval as code review;
- treat a trusted timestamp as experimental authenticity;
- treat evidence commitment as availability;
- treat historical validity as present authorization;
- treat an unresolved obligation as discharged by relabeling;
- collapse the ten dimensions into one score or grade;
- remove a retained contradiction;
- add a universal accepting rule without new evidence and a new gate record.

## 7. Deprecation and removal

1. A schema is deprecated only by a named document that states the replacement
   schema identifier and the first release in which the old schema is no longer
   accepted.
2. Deprecated schemas remain in `schemas/etp/` with their original bytes and
   registry entries until removal.
3. Removal requires:
   - a major version change;
   - a migration note in this document;
   - a vector showing that the removed schema is refused;
   - an update to the registry and the freeze, if a frozen artifact is affected.
4. No deprecation may retroactively change the meaning of evidence produced under
   the deprecated schema.

## 8. Change-control procedure

Every ETP schema or validator change must include:

1. a new or updated schema file with `$id`, `$schema`, and
   `additionalProperties: false`;
2. a version bump if any required field, enum, or meaning changes;
3. new or updated conformance vectors;
4. `schemas/etp/registry.json` SHA-256 updates;
5. a freeze update only if the frozen 1.0.0 evidence is intentionally changed
   (it must not be, in a non-major migration);
6. a migration note in this document;
7. Rust unit and integration tests;
8. `./ci/gate.sh` with formatting, clippy `-D warnings`, debug tests, and release
   tests;
9. no deletion or weakening of an existing test;
10. no change to `research/`.

## 9. What Phase 10.1 adds and does not migrate

Phase 10.1 adds:

- `frf-etp.manifest.v1`;
- `frf-etp.claim.v1`;
- `frf-etp.obligation-inventory.v1`;
- `frf-etp.status-dimensions.v1`;
- the validation report;
- the freeze and registry;
- the claim-integrity, trust-gap, standards, and migration documents;
- `AGENTS.md`.

Phase 10.1 does not migrate:

- any 1.0.0 receipt or claim into an ETP claim record automatically;
- any provider object into an ETP identity;
- any finite result into a universal result;
- any digest into authentication;
- `research/` into the repository;
- the crate version.

## 9.1 What Phase 10.2 adds and does not migrate

Phase 10.2 adds, without changing any 1.0.0 meaning:

- `frf-etp.campaign-protocol.v1`;
- `frf-etp.campaign-receipt.v1`;
- `frf-etp.campaign-closure.v1`;
- `frf-etp.sarif-projection.v1`;
- the finite `frf-etp-native-fixtures-2026-11-22` campaign and its frozen opening
  manifest in `evaluation/earned-trust/`;
- `src/etp_campaign.rs`, `src/sarif.rs`, and `ci/etp-gate.sh`.

Phase 10.2 does not migrate:

- any 1.0.0 receipt or claim into a campaign receipt automatically;
- any campaign result into a universal or population-level claim;
- any digest into authentication;
- any SARIF result into a certification or deployment authorization;
- any `research/` bytes;
- the crate version.

The four new schemas are registered in `schemas/etp/registry.json`. The 1.0.0
freeze is unchanged.

## 9.2 What Phase 10.3 adds and does not migrate

Phase 10.3 adds, without changing any 1.0.0 meaning:

- `frf-etp.dsse-envelope.v1`;
- `frf-etp.in-toto-statement.v1`;
- seven separately versioned predicate schemas:
  `frf-etp.predicate.campaign-closure.v1`,
  `frf-etp.predicate.instrument-qualification.v1`,
  `frf-etp.predicate.reproduction.v1`,
  `frf-etp.predicate.proof-admission.v1`,
  `frf-etp.predicate.consumer-closure.v1`,
  `frf-etp.predicate.security-findings.v1`,
  `frf-etp.predicate.release-adjudication.v1`;
- `frf-etp.trust-policy.v1`;
- `frf-etp.attestation-verification.v1`;
- `src/etp_auth.rs`, `tests/etp_auth.rs`, and the `etp attest verify` CLI;
- `evaluation/earned-trust/trust-policy.json` and
  `evaluation/earned-trust/attestations/`;
- `evaluation/earned-trust/make_attestation.py`,
  `evaluation/earned-trust/verify_attestations.py`, and
  `ci/etp-auth-gate.sh`;
- `docs/ETP-AUTHENTICATED-EVIDENCE.md`.

Phase 10.3 records one explicitly separated instrument change. Adding the
attestation dependency changed `Cargo.toml`, which is a declared candidate and
instrument file, and adding `src/etp_auth.rs` and changing `src/cli.rs` and
`src/lib.rs` changed the declared instrument. The Phase 10.2 opening manifest
was re-frozen and the same finite campaign was re-executed under the Phase 10.3
instrument. The case population, expected terminal outcomes, receipt contents,
accepted cases, retained findings, resource envelope, and claim ceiling are
unchanged. The original Phase 10.2 opening digest
`2039c3352f9edcf7d5657e341440c466a29cc6f55851b6ecb6243b46a118a236` and closure
digest `fea6c92f9840b30a63769ebd219cced2005ab32ab6b90b7eeeba1af038f01eee`
remain available at commit `f17111d`. See
[`ETP-AUTHENTICATED-EVIDENCE.md`](ETP-AUTHENTICATED-EVIDENCE.md) for the current
values.

Phase 10.3 does not migrate:

- any 1.0.0 receipt, claim, or provider object into an attestation;
- any digest into authentication;
- any signature into truth, independent review, or certification;
- any campaign result into a population or deployment claim;
- any `research/` bytes;
- the crate version.

Phase 10.3 does not implement a transparency log (Rekor/C2SP), RFC 3161
timestamps, Sigstore keyless identity, TUF metadata, a revocation registry, or a
public challenge service. Phase 10.4a later adds a local test RFC 3161 token, an
append-only test revocation registry, and a durable archive; Rekor/C2SP
transparency inclusion and public challenge remain Phase 10.4b or not deployed.

The eleven new schemas are registered in `schemas/etp/registry.json`. The 1.0.0
freeze is unchanged.

## 9.3 What Phase 10.4a adds and does not migrate

Phase 10.4a adds, without changing any 1.0.0 meaning:

- `frf-etp.time-verification.v1`;
- `frf-etp.time-stamp.v1`;
- `frf-etp.revocation-registry.v1`;
- `frf-etp.revocation-entry.v1`;
- `frf-etp.revocation-plan.v1`;
- `frf-etp.revocation-verification.v1`;
- `frf-etp.support-model.v1`;
- `frf-etp.historical-verdict.v1`;
- `frf-etp.archive-manifest.v1`;
- `frf-etp.archive-verification.v1`;
- `src/etp_time.rs`, `src/etp_revocation.rs`, `src/etp_archive.rs`,
  `tests/etp_time.rs`, `tests/etp_revocation.rs`, `tests/etp_archive.rs`;
- `etp time verify`, `etp time stamp`, `etp revocation verify`,
  `etp revocation record`, and `etp archive verify`;
- `evaluation/earned-trust/time/`, `evaluation/earned-trust/revocations/`,
  `evaluation/earned-trust/archive/`;
- `evaluation/earned-trust/verify_time.py`,
  `evaluation/earned-trust/verify_revocation.py`,
  `evaluation/earned-trust/make_revocation.py`, and
  `evaluation/earned-trust/make_archive.py`;
- `ci/etp-time-gate.sh`;
- `docs/ETP-TRUSTED-TIME.md`, `docs/ETP-REVOCATION.md`, and
  `docs/ETP-ARCHIVE.md`.

Phase 10.4a records one explicitly separated instrument change. Adding the time,
revocation, and archive modules changed `src/lib.rs`, `src/cli.rs`, and
`src/etp_auth.rs`, all of which the Phase 10.2 opening manifest declares as
instrument files. The opening manifest was re-frozen and the same finite
campaign was re-executed under the Phase 10.4a instrument. The case population,
expected terminal outcomes, receipt contents, accepted cases, retained findings,
resource envelope, and claim ceiling are unchanged.

| Field | Phase 10.4a value |
|---|---|
| Opening SHA-256 | `08325858b5a18f6a4053f4c25f081219f0f7165c8e2c51de5ec52db09e6a942a` |
| Candidate identity | `7fd038b34643743ca4dc36ceb7026973a8900fb0bd9697abc2a9ba64bea02746` |
| Instrument identity | `74517c942798087e77335ffc28c4078ed85161a58c388b77d649cfac245cb338` |
| Closure SHA-256 | `8b343a22dfc7a35e947a2f85638284e37088a7128ecb4a3de787456db4d5b3ab` |
| Trust-policy version | `6` |
| Attestation envelope SHA-256 | `fafd563d816b38be8fc035f33102d0418f2e652f534b876e9057c0960d766e66` |
| Timestamp token SHA-256 | `8fb0de2ef49b073fca06538fbddd36154f08289b3c5ccc59ed622152369d6f78` |
| Revocation registry SHA-256 | `3ff8ec9443eb62b0cdc367b18c496b6ad2b4e89f5ef4a6617c41e99b93679bf7` |
| Archive manifest SHA-256 | `c1dbbca82be207891179e62ef5fd5b2069b587436092e33e72b3c6a3af56adb9` |

The Phase 10.3 opening digest
`fc9202bc553472bb94362e4de1d4da168f51ebd5be624eefc5cf0d334d8fa7ec` and its
closure digest
`607b36e151fd791f9f8ed52391f7e30f2a2822bfed0c13c63943064f536ae912` remain
available at commit `cb59ddb`.

Phase 10.4a does not migrate:

- any 1.0.0 receipt, claim, or provider object into a timestamp, revocation, or
  archive identity;
- any digest into authentication;
- any local test timestamp into external trusted time;
- any append-only test registry into a public revocation feed or transparency
  log;
- any historical verdict into present authorization;
- any `research/` bytes;
- the crate version.

Phase 10.4a does not implement Rekor/C2SP transparency inclusion or
consistency, an external trusted timestamp authority, Sigstore keyless identity,
TUF metadata, public revocation, global non-equivocation, witness observation,
independent adjudication, or a public challenge service. Rekor/C2SP remains
Phase 10.4b work.

The ten new schemas are registered in `schemas/etp/registry.json`. The 1.0.0
freeze is unchanged.

## 10. Rollback

A manifest, vector, registry, or freeze change can be rolled back by reverting
the commit. Rollback must restore the previous schema bytes, vector bytes,
registry digests, and validator behavior together. A partial rollback that
leaves a registry digest pointing at different bytes is an integrity failure and
must be rejected by the gate.

## 11. Non-claims

This policy does not claim that:

- ETP v1 is complete;
- the registry is authenticated;
- the freeze is externally anchored;
- a migration is semantically sound merely because it validates;
- a future version will be backward compatible in every direction;
- `research/` will ever be included.

The policy is a constraint on future changes, not evidence that the current
system is trustworthy.
