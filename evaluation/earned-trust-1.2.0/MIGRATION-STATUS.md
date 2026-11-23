# 1.2.0 evidence migration status

**Date:** 2026-11-23
**Frozen baseline:** FRF-MemorySafety 1.0.0 at
`02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`.
**Historical 1.1.0 evidence:** `evaluation/earned-trust/` is unchanged.
**Status:** the 1.2.0 campaign, SARIF, DSSE attestation, local transparency,
local trusted time, revocation, policy metadata, durable archive, integrity
receipt, and formal-acceptance receipt are bound to the 1.2.0 candidate. The
verifiers, gates and tests named below use `evaluation/earned-trust-1.2.0/`.
A complete candidate-bound re-freeze was performed and the crate was published
as 1.2.0. External review, external trust and administrative independence are
**not** claimed.

This file is a migration record, not a verification result and not a
certification.

## 1. New campaign

| Item | Value |
|---|---|
| Candidate identity (tree) | `79e72160a6a1c169093d5e7abb39f426a9f189d07aef7ddc472b3856911bcbb7` |
| Instrument identity (tree) | `832be8cdb11fe65a9e602832569942e7e81f15a8755188752e11ee96762bdfd0` |
| Opening manifest SHA-256 | `180e50318dc045c9ea81168c7e1e958e1d9e108b9a99c662f06081967e8b7f8a` |
| Closure manifest SHA-256 | `ece999b403e7ce05f94dbe2304a2b86b24afb1a9cd5dc5e1a5f57d22482d735a` |
| Cases / receipts / raw evidence | 13 / 13 / 25 |
| Closure / acceptance | `closed` / `accepted` |
| Outcomes | 4 verified, 6 observed violations, 1 incomplete, 2 unresolved |
| Decisions | 13 pass |
| Crate version | 1.2.0 |

## 2. Regenerated artifacts

| Artifact | SHA-256 |
|---|---|
| `MANIFEST.json` | `ece999b403e7ce05f94dbe2304a2b86b24afb1a9cd5dc5e1a5f57d22482d735a` |
| `campaign.sarif` | `3d6ca4fd72bbf1ecacf336dd528eec7daac9601bdeafb1d455f38fc34f5908ad` |
| `CLAIMS.json` | `9d09efa889e87652187f695fece3db9f052be349fc850a423525d34c6cb8a375` |
| `suppression-review.json` | `dc69636fca7cc5fab443867c02e076865d33b02e311b64980781402985ceab32` |
| `attestations/campaign-closure.envelope.json` | `3eb0eb0277c463cacccdaee46a260e3580b021d64fb701b56d47c351bc8a8b07` |
| `attestations/campaign-closure.statement.json` | `c6042cbed99f48b41d5ef71e5911eaf784e3da5ddebb15386340c7906893dea6` |
| `trust-policy.json` (policy version 4) | `721b9558bb1df2bfbedc44b23298db423d44cd632fa095da673705946bca0e46` |
| `transparency/attestation-entry.bin` | `3eb0eb0277c463cacccdaee46a260e3580b021d64fb701b56d47c351bc8a8b07` |
| `transparency/proof.json` | `d0d0671961493711c9be3f18da5e5bcfd6232474232c82be03d8dcc6d18de07c` |
| `transparency/checkpoint-size-3.txt` | `777c4f4370e897cb5bf2c459a384323ef0188f6ff269b0833d59a4ba7f16807f` |
| `time/token.tsr` | `e29725174b5ba9c839e7ab0f3f573f40817fd8f19bfa205cc7eb855c0d8a2fe8` |
| `revocations/registry.json` | `feddd64a1903e011fb2476a7cda0363330b51f8ee3e71777c46b901f25c6254c` |
| `policy-metadata.json` (version 2) | `1fb9ad31326eeec1ee03ce62279652b16a2ddcccb5547b07da184e1794610ca6` |
| `integrity/integrity-receipt.json` | `709a9f0dcd77a1373613dfeb9f3b24213324b2a5fff2d0dcad3ea4c01fb8747f` |
| `acceptance-controls/receipt.json` | `6cf8b0f51a3fdd85f25f84e02e569d9fa8253573148486c8b2d1113ad2528ad9` |
| `archive/manifest.json` (106 objects) | `eb946203a1eb76f530984f8aac33f4f21232e564b6eae90581b082d1c2b7e9b4` |

The 1.2.0 archive now preserves the declared candidate and instrument source
files under their repository-relative paths and lists them in the
reconstructor's requirements. `reconstruct.py`, `verify_sarif.py`, and the other
archived verifiers therefore run from the archive root with the 1.2.0
constants. The 76-object 1.1.0 inventory is a subset of the 106-object 1.2.0
inventory (the difference is the 30 preserved declared source files). The 1.1.0
archive under `evaluation/earned-trust/archive/` is untouched.

## 3. Migrated verifiers and builders

Copies under `evaluation/earned-trust-1.2.0/`:

- `reconstruct.py`: `CAMPAIGN_DIR` and `OPENING_SHA256` bound to 1.2.0. All
  counts and checks unchanged.
- `verify_sarif.py`: candidate, opening, native-manifest digest, and an
  explicit `EXPECTED_DRIVER_VERSION = "1.2.0"`. `EXPECTED_ENCODED_BYTES` is
  `42988`, measured from the new SARIF (the byte length happens to equal the
  1.1.0 length). Schema, limit, suppression, baseline, sharding, and control
  checks unchanged.
- `verify_policy_metadata.py`: the pinned `now = 1795336442` is replaced by a
  required `--now` argument. The `issued_after_now` and `expired_before_now`
  checks are retained; `--now 1795336442` still refuses with
  `issued_after_now`, and the gates use the declared generation-time bound
  `1795417304`.
- `make_revocation.py`: default subject identity bound to the 1.2.0 candidate.
- `make_archive.py`: 1.2.0 edge and archive id, declared source preservation,
  and reconstruction commands for the SARIF verifier and policy metadata.
- `verify_attestations.py`, `verify_transparency.py`, `make_attestation.py`:
  default paths bound to 1.2.0; verification logic unchanged. The 1.2.0
  `verify_attestations.py` also creates its `target/` work directory when it is
  absent, so the archived copy runs from the archive root instead of failing
  with `FileNotFoundError`; no acceptance predicate changed.
- `build_integrity_receipt.py`, `verify_reproducibility.py`: population,
  declared-source list, and receipt path bound to 1.2.0.
- `verify_acceptance_model.py`, `verify_time.py`, `verify_revocation.py`:
  byte-identical tools; they contain no 1.1.0 path or digest constant. The
  acceptance oracle and time/revocation verification are invoked with the
  1.2.0 evidence.

The 1.1.0 copies under `evaluation/earned-trust/` are unchanged.

### Expected-value changes in tests

No assertion was deleted or loosened. The only test values that changed are in
`tests/etp_transparency.rs`: the two corruption-control markers used to locate
the checkpoint signature line changed from
`frf.local/etp-transparency-2026` to `frf.local/etp-transparency-1.2.0`,
because the committed 1.2.0 log origin legitimately changed. The tests still
parse the checkpoint and require `InvalidCheckpointSignature` after the single
byte mutation. All other migrated tests pass with their original counts and
assertions: campaign 15, auth 21, archive 8, time 9, transparency 25, SARIF 12,
CLI 15.

## 4. Gate results actually run

All runs used Docker with `--memory=2g --memory-swap=2g --pids-limit=512
--cpus=2 --ulimit nofile=1024:1024 --oom-score-adj=500 --cap-drop ALL
--cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER
--security-opt no-new-privileges`, and Rust builds used
`CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0`. No host cargo, rustc, or test ran.

| Gate | Result | Exact counts |
|---|---|---|
| `ci/gate.sh` | PASS | fmt, clippy, debug 509 passed / 0 failed / 0 ignored over 37 binaries; release 509 / 0 / 0 over 37 binaries |
| `ci/etp-gate.sh` | PASS | campaign accepted, 13/13/25; SARIF 18 results / 11 rules / 0 suppressed / 42988 bytes; reconstruction PASS; fresh run closure `ea0a23c41331383bc47597b475deb537634e0972a3f85427b4c164ce44bb11b8` (fresh-run closure is not the committed closure) |
| `ci/etp-auth-gate.sh` | PASS | `etp_auth` 21 passed / 0 failed / 0 ignored; independent controls 13; ephemeral key discarded; Rust and Python verifiers accepted the ephemeral envelope |
| `ci/etp-time-gate.sh` | PASS | `etp_time` 9, `etp_revocation` 13, `etp_archive` 8; independent time 6/6; independent revocation 6/6; fresh TSA token; archive 106/106 objects, 7 commands, 54 inputs |
| `ci/etp-transparency-gate.sh` | PASS | `etp_transparency` 25 passed; independent 20/20; live local log tree size 261, inclusion and consistency verified |
| `ci/etp-phase14-gate.sh` | PASS | SARIF 18/11/0; SARIF self-test 18 controls; attestation controls 13; Rust and Python attestation accepted |
| `ci/etp-phase15-gate.sh` | PASS | rebuilt archive 106 objects / 106 verified; reconstruct PASS; policy metadata 18/18; transparency 20/20; time 6/6; revocation 6/6; attestation 13; SARIF self-test 18 |
| `ci/etp-integrity-gate.sh` | PASS | two release builds byte-identical `8067fd797e8358fb2de7a4cb1e50c453f41c549ea2abdbcf460f414078631cd2`; population 13; reproducibility self-test 7 controls refused; receipt `709a9f0d...` |
| `ci/etp-formal-acceptance-gate.sh` | PASS | controls 17, checks 36, passed 36, failed 0; receipt `6cf8b0f5...` |
| `ci/etp-comparative-gate.sh` | PASS (historical) | development 6 cases, 5/6 decision accuracy, 0 wrongful acceptance, 1 wrongful refusal (`c01-positive-campaign-closure` observed refuse); the gate exits 0 on a completed harness run. The promoted 1.1.0-bound files were restored, see §5 |
| `ci/etp-comparative-reconstruction-gate.sh` | PASS (historical) | development 6/6, held-out 11/12, 0 wrongful acceptance, 1 wrongful refusal, 6 restoration failures |

## 5. Comparative evaluation: NOT_REBOUND

The Phase 17 comparative corpus under `evaluation/earned-trust-comparative/`
binds the 1.1.0 candidate and closure `d26e19bd...`. It was executed against the
committed 1.1.0 receipts with the 1.2.0 binary and reported the counts above.
With the 1.2.0 binary the development replay refused `c01-positive-campaign-closure`
(`FAIL c01-positive-campaign-closure expected=accept observed=refuse`), giving
5/6 decision accuracy and one wrongful refusal by the corpus's 1.1.0-bound
expectation. That refusal is the candidate-binding mismatch, not a defect newly
introduced here, and it is retained rather than erased. It is **not** rebound to
1.2.0: a rebind needs fresh mutated copies of every
comparative case, the cross-property reports, and a new opening freeze. Those
were not produced. The gate's promoted outputs were discarded and the committed
1.1.0-bound comparative bytes were restored unchanged. No result in this section
applies to the 1.2.0 candidate.

## 6. Remaining NOT_RUN

- **Complete candidate-bound 1.2.0 re-freeze:** performed, and the crate was
  published as 1.2.0. This is not external review or administrative
  independence.
- **`ci/etp-release-gate.sh`:** not run as one wrapper invocation. Its
  individual gates were run and passed in hardened containers, including the
  gates that remain candidate-independent (`information-flow`, `timing`,
  `cross-property`, `interop`, `tls-matrix`, `witness`). Running the wrapper
  would overwrite
  historical evidence that this task forbids changing.
- **Comparative evaluation for 1.2.0:** NOT_REBOUND (see §5).
- **External trusted time, public transparency, external witnessing, external
  review:** NOT_RUN. The token is from a local test TSA and the log is a local
  tessera log. No external trust is established.
- **`etp checkpoint verify`:** reports `partial` with
  `consistency_not_checked` at exit 0. This is the declared 1.1.0 limitation,
  not a pass and not a new proof.

## 7. Non-claims

A verified campaign closure is bookkeeping over a finite population. A valid
signature is not truth. A digest is not authentication. A local TSA is not
external trusted time. A local tessera log is not public transparency or
completeness. Including declared source in the archive establishes presence and
digest match, not authenticity or review. An archive inventory plus a successful
`reconstruct.py` is not independent reproduction or certification. No result
here establishes memory safety, functional correctness, detector sensitivity,
independent review, certification, or authorization to deploy. A refusal is
not a pass. `NOT_RUN` is not a pass.
