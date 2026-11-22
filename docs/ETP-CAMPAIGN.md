# ETP campaign closure and lossless reconciliation

**Subphase:** Phase 10.2 (first executable vertical slice, part 1).
**Protocol identifier:** `frf-etp-v1`.
**Campaign identifier:** `frf-etp-native-fixtures-2026-11-22`.
**Implementation:** `src/etp_campaign.rs`, `src/sarif.rs`, `ci/etp-gate.sh`,
`evaluation/earned-trust/`.
**Frozen baseline:** FRF-MemorySafety 1.0.0 at commit
`02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`. This subphase does not modify the
1.0.0 evidence or any 1.0.0 claim ceiling.

This document records one real, finite, pre-registered ETP campaign. It is
bookkeeping over typed observations. It is not a population study, a
detector-sensitivity estimate, a memory-safety proof, a certification, or an
authorization to deploy software.

---

## 1. What the campaign is

The campaign executes the closed checked-in native fixture registry described in
`src/native.rs` through the native harness and the court verifier in
`src/court.rs`. Each declared case is compiled and executed twice. The harness
records a canonical event transcript, requires identical replay unless the case
is the deliberate nondeterminism control, and verifies the transcript with the
court.

The population is declared before measurement. Every case has one
pre-registered terminal outcome. The campaign does not select cases after seeing
results, does not drop a failing case, and does not convert `NOT_RUN` or
`unresolved` into a pass.

**Declared overlap.** The candidate (the checked-in fixture and court
mechanisms) and the instrument (the same native harness and court, plus the
campaign runner) overlap. That overlap is declared in `protocol.json`. It is why
the campaign's claim is limited to the execution and bookkeeping of this finite
population. Executing the instrument is not independent verification of the
instrument.

### 1.1 Frozen opening manifest

| Field | Value |
|---|---|
| Opening manifest | `evaluation/earned-trust/protocol.json` |
| Opening SHA-256 | `08325858b5a18f6a4053f4c25f081219f0f7165c8e2c51de5ec52db09e6a942a` |
| Frozen sidecar | `evaluation/earned-trust/opening.sha256` |
| Candidate identity (tree) | `7fd038b34643743ca4dc36ceb7026973a8900fb0bd9697abc2a9ba64bea02746` |
| Instrument identity (tree) | `74517c942798087e77335ffc28c4078ed85161a58c388b77d649cfac245cb338` |
| Closure manifest | `evaluation/earned-trust/MANIFEST.json` |
| Closure SHA-256 | `8b343a22dfc7a35e947a2f85638284e37088a7128ecb4a3de787456db4d5b3ab` |
| SARIF projection | `evaluation/earned-trust/campaign.sarif` |
| SARIF SHA-256 | `1db25044943c29f5b56e53a1e5ab9ba9cc88ffb91eac058463490e09a925a9c5` |

**Phase 10.3 instrument change.** Adding the attestation dependency changed
`Cargo.toml`, and adding `src/etp_auth.rs` and changing `src/cli.rs` and
`src/lib.rs` changed the declared instrument. The opening manifest was
re-frozen and the same finite campaign was re-executed under the Phase 10.3
instrument. The population, expected outcomes, receipts, accepted cases,
retained findings, resource envelope, and claim ceiling are unchanged. The
The original Phase 10.2 opening digest was
`2039c3352f9edcf7d5657e341440c466a29cc6f55851b6ecb6243b46a118a236` and its
closure digest was
`fea6c92f9840b30a63769ebd219cced2005ab32ab6b90b7eeeba1af038f01eee`; both remain
available at commit `f17111d`. See
[`ETP-AUTHENTICATED-EVIDENCE.md`](ETP-AUTHENTICATED-EVIDENCE.md).

**Phase 10.4a instrument change.** Adding `src/etp_time.rs`,
`src/etp_revocation.rs`, `src/etp_archive.rs`, and their CLI integration changed
`src/cli.rs`, `src/lib.rs`, and `src/etp_auth.rs`, all declared instrument files.
The opening manifest was re-frozen and the same finite campaign was re-executed
under the Phase 10.4a instrument. The population, expected outcomes, receipts,
accepted cases, retained findings, resource envelope, and claim ceiling are
unchanged. The Phase 10.3 opening digest
`fc9202bc553472bb94362e4de1d4da168f51ebd5be624eefc5cf0d334d8fa7ec` and closure
digest `607b36e151fd791f9f8ed52391f7e30f2a2822bfed0c13c63943064f536ae912` remain
available at commit `cb59ddb`.

The tree digest is `sha256-sorted-path-nul-digest-lf-v1`: SHA-256 over the
concatenation of `path`, NUL, the lowercase file SHA-256, and LF, with files
sorted by path bytes. A digest binds exact bytes. It is not authentication.

The opening manifest declares:

* the candidate and instrument file lists and tree digests;
* the requirements `R1`-`R4` and obligations `O1`-`O5`;
* the threat model and declared assumptions;
* the 13-case population with expected terminal outcomes and
  mandatory-resolution flags;
* instrument identity and required tools (`cc`, `rustc`, `prlimit`, `ld`);
* the mutation controls `M1`-`M9` exercised by tests;
* permitted exclusions (none);
* the resource envelope (2048 MiB memory and equal swap, 512 pids, 2 cpus, 1024
  nofile, OOM score adjustment 500, 1800-second timeout);
* the acceptance policy and completion expectations;
* claims `C1`-`C3` and unsupported features.

## 2. Receipt schema

Each `frf-etp.campaign-receipt.v1` receipt in
`evaluation/earned-trust/receipts/` records:

| Field | Meaning |
|---|---|
| `candidate_identity` | Candidate tree digest from the opening manifest |
| `instrument_id` | Declared instrument identifier |
| `instrument_execution_identity` | SHA-256 over the instrument identifier, environment, image id, executable digest, and sorted tool versions |
| `requirement`, `obligations` | Requirement and obligation references |
| `claim` | Declared claim identifier |
| `execution.command` | Exact process argument vector of the campaign runner |
| `execution.environment`, `image_id` | Declared execution environment |
| `execution.native_harness` | Whether the native harness was enabled |
| `execution.replay` | `identical`, `mismatch`, or `not_performed` |
| `execution.tool_versions` | Exact compiler and linker versions |
| `execution.executable_sha256` | Compiled fixture executable digest when recorded |
| `execution.fixture_path`, `fixture_sha256` | Declared fixture and its exact digest |
| `observation.outcome` | One typed terminal outcome |
| `observation.court_outcome` | Court outcome from the retained report |
| `observation.findings` | Retained finding code, class, subject, detail, and event count |
| `observation.race_witnesses` | Race-witness count |
| `observation.detail` | Exact harness, court, or output-limit detail |
| `adjudication` | Expected and observed outcome, derived decision, mandatory-resolution flag, and resolution |
| `release_decision` | `eligible`, `withheld`, `blocked`, or `not_applicable` |
| `evidence` | Raw transcript, retained court report, or harness-detail path and SHA-256 |
| `suppression` | Suppression flag plus justification, scope, owner, expiry, and invalidation |

Terminal outcomes are
`verified_compatible_within_transcript`, `observed_violation`,
`incomplete_transcript`, `unresolved`, `illegal_case`, `not_run`, and
`harness_failure`. A decision is `pass` only when the observed terminal outcome
equals the pre-registered outcome. `not_run` is its own decision and is never a
pass. A harness failure is a fail.

## 3. Closure rules

A campaign closes only when all of the following hold.

1. The population is declared before measurement and is not empty.
2. Every declared case has exactly one receipt and exactly one terminal
   outcome.
3. A missing, duplicate, unexpected, or truncated case blocks closure.
4. Summary counts are recomputed from the complete identified population. A
   declared count that disagrees is refused.
5. A missing population is not treated as an empty population.
6. Failures, contradictions, and unresolved observations are retained.
7. An unresolved observation on a case whose pre-registration required a
   resolved observation withholds acceptance.
8. A typed `NOT_RUN` is never a pass.
9. A suppression without justification, scope, owner, expiry, and invalidation
   is refused; a valid suppression remains a finding.
10. The closure manifest is not trusted. The verifier recomputes the population,
    outcomes, decisions, counts, receipt digests, raw-evidence digests, candidate
    identity, and instrument identity.

Closure is not acceptance. Acceptance is granted only when closure is complete,
every case matched its pre-registered observation, no mandatory-resolution case
is unresolved, and no failure or `NOT_RUN` is present. Acceptance is still
bookkeeping over the finite campaign.

## 4. Lossless reconciliation

`etp campaign verify evaluation/earned-trust/MANIFEST.json` detects:

* a missing receipt for a declared case;
* duplicate receipt identities;
* an unexpected receipt outside the population;
* a truncated receipt list or population;
* an inconsistent summary count;
* a missing terminal outcome or a stripped observation/adjudication/evidence
  field;
* a decision, resolution, release decision, or instrument-execution identity
  that is not the derived value;
* a raw transcript or court report that is absent, non-canonical, digest
  mismatched, or inconsistent with the receipt;
* a retained court report whose outcome, event count, race-witness count, or
  findings disagree with the receipt;
* an inapplicable evidence path or cross-case substitution;
* a wrong candidate or instrument identity;
* an unauthorized suppression;
* an exclusion that removes a declared case;
* a `NOT_RUN` presented as a pass;
* an opening-manifest digest mismatch.

The verifier re-verifies every raw transcript with the court. For the deliberate
nondeterminism control, the first transcript can verify cleanly while the second
run produces different bytes; the retained court report records the unresolved
replay and is the evidence of record.

`evaluation/earned-trust/reconstruct.py` is an independent standard-library
implementation. It does not import or execute the crate. It recomputes the same
population, terminal outcomes, decisions, counts, receipt and raw-evidence
digests, candidate and instrument tree digests, and SARIF mappings. It fails on a
missing, extra, duplicate, truncated, non-canonical, or tampered receipt or raw
evidence file. It is run in `python:3.11-slim` with the hardened resource caps in
`ci/etp-gate.sh`.

## 5. Real results

The committed campaign was executed in `rust:1.85.0-slim` with
`FRF_NATIVE_HARNESS=1` and the declared caps.

| Terminal outcome | Count |
|---|---:|
| `verified_compatible_within_transcript` | 4 |
| `observed_violation` | 6 |
| `incomplete_transcript` | 1 |
| `unresolved` | 2 |
| `illegal_case` | 0 |
| `not_run` | 0 |
| `harness_failure` | 0 |

* Cases: 13; receipts: 13; raw evidence files: 25.
* Decisions: 13 `pass`; 0 `fail`; 0 `not_run`.
* Accepted clean cases: 4.
* Cases retaining findings: 9.
* Closure: `closed`; acceptance: `accepted` for the finite campaign claim.
* SARIF: 18 results, 11 rules, 8 declared fixture artifacts, 0 suppressions.

The six observed violations are the `use_after_free` C and Rust cases, the
mutable-alias case, the stale-generation case, the deferred-callback case, and
the data-race case. The incomplete transcript is the seeded skipped-free case.
The two unresolved cases are the deliberate nondeterminism control and the
oversized-output control. The four clean cases are the C and Rust legal transfer
cases, the synchronous callback, and the atomic control.

These labels are transcript- and case-scoped. They are not a claim that the
fixtures are memory-safe, that the court is complete, or that the harness detects
every defect.

## 6. Corrupted controls

The executable tests in `tests/etp_campaign.rs` and `tests/sarif.rs` mutate the
committed artifacts in memory or in a `target/` copy and require a refusal or an
unchanged finding count.

| Control | Mutation | Required result |
|---|---|---|
| M1 deleted failed evidence | Remove the `use-after-free-c` receipt | `missing_receipt`; closure blocked |
| M2 truncated population | Remove a receipt, its closure reference, and its raw files | `missing_receipt` or `truncated_population` |
| M3 duplicate rows | Add a second receipt for one case | `duplicate_receipt` |
| M4 inconsistent summary | Change `receipt_count` | `inconsistent_count` |
| M5 suppressed finding | Declare a suppression without fields | `unauthorized_suppression` |
| M6 stripped result | Remove the `observation` object | Parse refusal |
| M7 fabricated location | Point a SARIF result at an invented fixture | `fabricated_location` |
| M8 wrong candidate | Substitute a receipt candidate identity | `wrong_candidate` |
| M9 missing raw evidence | Remove a transcript named by a receipt | `missing_raw_evidence` |

Additional controls cover an unexpected receipt, an opening-digest mismatch, a
typed `NOT_RUN` receipt that is not accepted, a valid suppression that remains a
retained finding, an invented SARIF region, an absent result claiming a tool
change without instrument-change evidence, incomplete sharding, an exceeded
limit, a missing rule, an unsupported SARIF version, a missing native manifest,
and an inconsistent result count.

## 7. Reproduction

```sh
./ci/etp-gate.sh
```

The gate builds the native-harness binary, runs the 13-case campaign into
`target/etp-campaign-run`, verifies the generated and committed closure
manifests, exports and verifies SARIF, and runs the independent reconstructor in
a separate hardened container. The repository is mounted read-only; only
`target/` is writable. No OOM, memory, pid, cpu, nofile, capability, or
no-new-privileges control is removed.

## 8. Claim ceiling and non-claims

A valid closure establishes only that the declared finite campaign produced the
declared typed observations and that the counts and evidence references are
complete. It does **not** establish:

* memory safety, functional correctness, interoperability, constant-time
  behaviour, or deployment security;
* detector sensitivity, specificity, or population-level defect recall;
* proof soundness or implementation correspondence;
* reviewer independence or adjudicator independence;
* authentication, signature validity, transparency-log inclusion or
  completeness, non-equivocation, or trusted time;
* that a GitHub code-scanning view is authoritative;
* that a passing gate is a certification or an authorization to deploy.

DSSE, in-toto, and an Ed25519-only trust policy are implemented for a finite
profile in Phase 10.3; they authenticate the exact signed bytes and bind this
closure, but they do not establish truth or independent review. Phase 10.4a adds
a local test RFC 3161 token and an append-only test revocation registry; neither
is external trusted time, transparency inclusion, or a public revocation feed.
Rekor/C2SP transparency inclusion and consistency, an external trusted timestamp
authority, Sigstore keyless identity, TUF update metadata, independent
adjudication, witness observation, global non-equivocation, and public challenge
services are not implemented in this subphase. They remain `NOT_RUN` or
specified-not-deployed. The SHA-256 freeze detects accidental or silent change
only; an actor who can rewrite the opening manifest, every receipt, the
projection, and the verifier can produce a self-consistent alternative set.

## 9. Citations

1. OASIS, *SARIF 2.1.0 OASIS Standard* and Errata 01.
   <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>
2. DSSE, *Dead Simple Signing Envelope* v1.0.0.
   <https://github.com/secure-systems-lab/dsse/blob/v1.0.0/protocol.md>
3. in-toto, *Specification* v1.0.0.
   <https://github.com/in-toto/specification/blob/v1.0.0/in-toto-spec.md>
4. SLSA, *Specification* v1.0. <https://slsa.dev/spec/v1.0/>
5. Sigstore documentation. <https://docs.sigstore.dev/>
6. Rekor and C2SP transparency-log materials.
   <https://github.com/sigstore/rekor> and <https://c2sp.org/tlog>
7. RFC 3161, *Internet X.509 Public Key Infrastructure Time-Stamp Protocol*.
   <https://www.rfc-editor.org/rfc/rfc3161.html>
8. The Update Framework, *Specification* v1.0.31.
   <https://theupdateframework.github.io/specification/v1.0.31/>
9. This repository: `docs/ETP-CLAIM-INTEGRITY.md`, `docs/ETP-SARIF.md`,
   `docs/ETP-AUTHENTICATED-EVIDENCE.md`, `docs/EARNED-TRUST.md`, `SPEC.md`,
   `AGENTS.md`.
