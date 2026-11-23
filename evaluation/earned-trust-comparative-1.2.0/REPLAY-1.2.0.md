# 1.2.0 targeted replay of `c14`, `c15` and `c16`

**Status:** targeted replay of three cases that the original 1.2.0 replication
recorded as typed `NOT_RUN`. This is **not** a new discovery, **not** a new
held-out test, **not** external verification, and **not** a reclassification of a
`NOT_RUN` into a pass.
**Amended protocol:** `protocol.json`,
`phase17.2-replication-1.2.0-amendment-002`, SHA-256
`3f067d668a1bbdc5e7fbf4d79c0727b4c47259c9c407b134f1ec86f447dae1c4`.
**Harness:** `run_comparative.py`, SHA-256
`e7dfec3691fd3554a103e787d0ed3182deec6de77bdb74f8c8a3baa8e2b8fb37`.
**Amendment record:** `AMENDMENT-002.md`.
**Frozen 1.0.0 baseline:** `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`.
**1.2.0 evidence closure:** `ece999b403e7ce05f94dbe2304a2b86b24afb1a9cd5dc5e1a5f57d22482d735a`.
**Instrument binary:** `target/debug/frf-memorysafety`, SHA-256
`49937254ac5c35ff63f065f937b30e77674068f601a85e5111523daca0600e55`
(unchanged; no rebuild was required for these three cases).

---

## 1. What was produced and where

Three existing 1.2.0 instrument gates were re-run in hardened containers. Their
fresh outputs were captured in a temporary directory and the fresh report bytes
were copied into the 1.2.0 evidence tree. The 1.1.0 evidence under
`evaluation/earned-trust/` was never written to.

| Artifact binding | Source (fresh instrument output) | Destination (1.2.0 evidence) | SHA-256 |
|---|---|---|---|
| `cross_property_faulty` | `target/replay-1.2.0/cross-property/report-faulty.json` | `evaluation/earned-trust-1.2.0/cross-property/report-faulty.json` | `9c0c0a79e8dbf869a0b973124a40d277db2ead11195ea628268026273935d423` |
| `cross_property_fixed` | `target/replay-1.2.0/cross-property/report-fixed.json` | `evaluation/earned-trust-1.2.0/cross-property/report-fixed.json` | `d09494571515ed9ea0adb55282fd24b7f958107e55fde880cd7e196fc37ec5ac` |
| `interop_report` | `target/replay-1.2.0/interop/report.json` | `evaluation/earned-trust-1.2.0/interop/report.json` | `bfdca661fa83d7c0fd7ee7b0574c31fbf2634018cc01073226cded73f3ff546d` |
| `tls_matrix_report` | `target/replay-1.2.0/tls-matrix/report.json` | `evaluation/earned-trust-1.2.0/tls-matrix/report.json` | `425aab2b6fe6d19863bca042af1180b1964d543760b670b70746c4631dd088a3` |

`target/` is not committed evidence. The temporary captures are retained only as
the copy source for this record.

These are **1.2.0 instrument runs**. They are not the published 1.2.0 campaign
evidence, not a copy of the 1.1.0 reports and not a rebinding of 1.1.0 bytes.
They are bound in `protocol.json` with `binding_status:
present_in_1.2.0_replay`.

## 2. Exact producing commands

All commands ran from `/mnt/1tb_kingston/FRF-MemorySafety`. No `cargo`, `rustc`,
test or verifier was executed on the host. The envelope is the declared
2g/2g OOM-capped envelope: `--memory=2g --memory-swap=2g --pids-limit=512
--cpus=2 --ulimit nofile=1024:1024 --oom-score-adj=500`, `--cap-drop ALL` with
only `DAC_OVERRIDE`, `CHOWN`, `FOWNER`, `SETUID`, `SETGID` added,
`--security-opt no-new-privileges`, and `CARGO_BUILD_JOBS=1
CARGO_INCREMENTAL=0`.

The outer `ci/etp-*-gate.sh` wrappers were **not** executed, because they
hardcode a 1g envelope. Their inner scripts, which are the instruments that
produce the reports, were executed directly with the same mounts, capabilities
and limits except the required 2g/2g memory cap. The wrappers' stable-field
comparison was reproduced read-only afterwards (section 4).

### 2.1 Interop matrix gate (produces `interop_report`)

```sh
mkdir -p target/replay-1.2.0/interop
timeout 1800 docker run --rm --name frf-replay-interop \
    --memory=2g --memory-swap=2g --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 --oom-score-adj=500 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --cap-add SETUID --cap-add SETGID \
    --security-opt no-new-privileges \
    -e CARGO_BUILD_JOBS=1 -e CARGO_INCREMENTAL=0 \
    -v /mnt/1tb_kingston/FRF-MemorySafety:/src:ro \
    -v /mnt/1tb_kingston/FRF-MemorySafety/target/replay-1.2.0/interop:/out \
    -w /src python:3.11-slim /src/ci/etp-interop-gate-inner.sh
```

Observed: `gcc 14.2.0`, `ld 2.44`, `accepted=True`,
report digest `bfdca661fa83d7c0fd7ee7b0574c31fbf2634018cc01073226cded73f3ff546d`,
`SELF_TEST PASS`, `interop-matrix inner: PASS`. All nine harness controls
reported their declared refusals.

### 2.2 Cross-property gate (produces `cross_property_faulty`, `cross_property_fixed`)

```sh
mkdir -p target/replay-1.2.0/cross-property
timeout 1800 docker run --rm --name frf-replay-cross-property \
    --memory=2g --memory-swap=2g --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 --oom-score-adj=500 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --cap-add SETUID --cap-add SETGID \
    --security-opt no-new-privileges \
    -e CARGO_BUILD_JOBS=1 -e CARGO_INCREMENTAL=0 \
    -v /mnt/1tb_kingston/FRF-MemorySafety:/src:ro \
    -v /mnt/1tb_kingston/FRF-MemorySafety/target/replay-1.2.0/cross-property:/out \
    -w /src python:3.11-slim /src/ci/etp-cross-property-gate-inner.sh
```

Observed: `gcc 14.2.0`, `ld 2.44`, `valgrind-3.24.0`. The faulty report is
`outcome=observed_erasure_violation`; the fixed report is
`outcome=no_violation_within_bounded_trace`. `self-test: 10/10 controls passed`,
`cross-property gate inner: PASS`.

### 2.3 TLS matrix gate (produces `tls_matrix_report`)

```sh
mkdir -p target/replay-1.2.0/tls-matrix
timeout 1800 docker run --rm --name frf-replay-tls-matrix \
    --memory=2g --memory-swap=2g --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 --oom-score-adj=500 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --cap-add SETUID --cap-add SETGID \
    --security-opt no-new-privileges \
    -e CARGO_BUILD_JOBS=1 -e CARGO_INCREMENTAL=0 \
    -v /mnt/1tb_kingston/FRF-MemorySafety:/src:ro \
    -v /mnt/1tb_kingston/FRF-MemorySafety/target/replay-1.2.0/tls-matrix:/out \
    -w /src python:3.11-slim /src/ci/etp-tls-matrix-gate-inner.sh
```

Observed: `gcc 14.2.0`, `ld 2.44`, `Python 3.11.18`, `accepted=True`,
report digest `425aab2b6fe6d19863bca042af1180b1964d543760b670b70746c4631dd088a3`,
`SELF_TEST PASS`, `tls-matrix inner: PASS`. All nine harness controls reported
their declared refusals.

### 2.4 Comparative harness: held-out replay of `c14` and `c15`

```sh
mkdir -p target/replay-1.2.0/comparative-held-out
timeout 1800 docker run --rm --name frf-replay-comparative-heldout \
    --memory=2g --memory-swap=2g --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 --oom-score-adj=500 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges \
    -e CARGO_BUILD_JOBS=1 -e CARGO_INCREMENTAL=0 \
    -v /mnt/1tb_kingston/FRF-MemorySafety:/src:ro \
    -v /mnt/1tb_kingston/FRF-MemorySafety/target/replay-1.2.0/comparative-held-out:/out \
    -w /src python:3.11-slim sh -c '
set -eu
if ! command -v openssl >/dev/null 2>&1; then
    apt-get update >/dev/null 2>&1
    apt-get install -y --no-install-recommends openssl >/dev/null 2>&1
fi
echo "openssl: $(openssl version)"
echo "python: $(python3 -V 2>&1)"
set +e
python3 /src/evaluation/earned-trust-comparative-1.2.0/run_comparative.py \
    --partition held-out \
    --cases c14-cross-property-regression,c15-interop-collapsed-cell \
    --out /out
status=$?
set -e
chmod -R a+rwX /out 2>/dev/null || true
exit $status
'
```

Observed (`OpenSSL 3.5.7`, `Python 3.11.18`):

```text
REPLAY partition=held-out cases=c14-cross-property-regression,c15-interop-collapsed-cell
PASS c14-cross-property-regression expected=refuse observed=refuse foundation=accept
  restoration: PASS
PASS c15-interop-collapsed-cell expected=refuse observed=refuse foundation=accept
  restoration: PASS
ANALYSIS partition=held-out cases=12 accept=1 refuse=11 unresolved=0 instrument_errors=0 not_run=0 decision_accuracy=12/12
ANALYSIS wrongful_acceptance=0 wrongful_refusal=0 foundation_augmented_agreement=1/12
```

### 2.5 Comparative harness: development replay of `c16`

```sh
mkdir -p target/replay-1.2.0/comparative-development
timeout 1800 docker run --rm --name frf-replay-comparative-dev \
    --memory=2g --memory-swap=2g --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 --oom-score-adj=500 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges \
    -e CARGO_BUILD_JOBS=1 -e CARGO_INCREMENTAL=0 \
    -v /mnt/1tb_kingston/FRF-MemorySafety:/src:ro \
    -v /mnt/1tb_kingston/FRF-MemorySafety/target/replay-1.2.0/comparative-development:/out \
    -w /src python:3.11-slim sh -c '
set -eu
if ! command -v openssl >/dev/null 2>&1; then
    apt-get update >/dev/null 2>&1
    apt-get install -y --no-install-recommends openssl >/dev/null 2>&1
fi
echo "openssl: $(openssl version)"
echo "python: $(python3 -V 2>&1)"
set +e
python3 /src/evaluation/earned-trust-comparative-1.2.0/run_comparative.py \
    --partition development \
    --cases c16-tls-matrix-collapsed-cell \
    --out /out
status=$?
set -e
chmod -R a+rwX /out 2>/dev/null || true
exit $status
'
```

Observed:

```text
REPLAY partition=development cases=c16-tls-matrix-collapsed-cell
PASS c16-tls-matrix-collapsed-cell expected=refuse observed=refuse foundation=accept
  restoration: PASS
ANALYSIS partition=development cases=6 accept=1 refuse=5 unresolved=0 instrument_errors=0 not_run=0 decision_accuracy=6/6
ANALYSIS wrongful_acceptance=0 wrongful_refusal=0 foundation_augmented_agreement=1/6
```

Only these three cases were executed by the comparative harness. The other 15
receipts were not re-executed and their bytes were not touched. The analysis
documents are built over the full 6- and 12-case partitions, with the 15
unchanged committed receipts supplying the non-replayed cases.

### 2.6 Independent reconstruction gate

```sh
timeout 900 docker run --rm --name frf-replay-recon \
    --memory=2g --memory-swap=2g --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 --oom-score-adj=500 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges --network=none \
    -v /mnt/1tb_kingston/FRF-MemorySafety:/src:ro \
    -v /mnt/1tb_kingston/FRF-MemorySafety/target:/src/target \
    -w /src python:3.11-slim \
    python3 evaluation/earned-trust-comparative-1.2.0/reconstruct_analysis.py \
        --out /src/target/analysis-reconstruction-1.2.0.json
```

Observed:

```text
RECON development cases=6 matched=6 wrongful_acceptance=0 wrongful_refusal=0 unresolved=0 instrument_errors=0 not_run=0 restoration_failures=0
RECON held-out cases=12 matched=12 wrongful_acceptance=0 wrongful_refusal=0 unresolved=0 instrument_errors=0 not_run=0 restoration_failures=4
PASS independent analysis reconstruction
discrepancy_count=0
```

The output was copied to `analysis-reconstruction.json`. The four held-out
restoration failures are `c08`, `c09`, `c11` and `c17`; they are unchanged from
the original 1.2.0 run and are not caused by this replay.

## 3. Per-case old versus new

| Case | Partition | Expected | Old observed | Old restoration | New observed | New decision basis | New restoration |
|---|---|---|---|---|---|---|---|
| `c14-cross-property-regression` | held-out | refuse | `not_run` | none | **refuse** | `cross-property-check` exits 1 with `AssertionError`; the mutated fixed report records a FREE without a preceding CLEANSE | **accept** |
| `c15-interop-collapsed-cell` | held-out | refuse | `not_run` | none | **refuse** | `interop-matrix-check` exits 1 with `Refusal: missing_cell: missing cell: max_4096 reference->candidate` | **accept** |
| `c16-tls-matrix-collapsed-cell` | development | refuse | `not_run` | none | **refuse** | `tls-matrix-check` exits 1 with `Refusal: missing_cell: missing cell: tls13_echo candidate->candidate` | **accept** |

All three new observed decisions equal their frozen expected decisions, and all
three restoration controls now accept. They are recorded as matches, not as
passes, certifications or correct refusals in any stronger sense.

Receipt digests:

| Case | Previous receipt SHA-256 | New receipt SHA-256 |
|---|---|---|
| `c14-cross-property-regression` | `24650bdd573cefe5cc99e5eb0ff06fb7888878e227e78953627737b1d373eee4` | `e09af221dc412d18f869595fcfab005fb98fcb1643217c3122f35ce032a2a29b` |
| `c15-interop-collapsed-cell` | `9657d10a84fcd43079f97af5140cd6adfb80f1a94903bf7ecc163a61ba72a705` | `44293bdd91f04f9cb62101d177d33eeafb66d6230f3293812e2cc51bb78f4d53` |
| `c16-tls-matrix-collapsed-cell` | `2136b9fc8b7ecde958e90d63a4d8a9427f149eb81e5e7a45f43794c00f51f9c8` | `bd27253962f6b2ddfc7315ad39b7a4b16e23311a113d30fcf116add878852078` |

The previous receipt bytes are retained outside the committed tree at
`target/replay-1.2.0/original/receipts/`, together with the previous analysis
documents at `target/replay-1.2.0/original/`. `target/` is not committed
evidence. The original decision (`not_run`) and its reason are preserved in this
record and in `AMENDMENT-002.md` §4.

## 4. Instrument stability check (read-only)

The outer gate wrappers compare stable report fields against the 1.1.0 committed
reports. That comparison was reproduced read-only on the fresh 1.2.0 bytes:

```text
cross-property faulty: MATCH
cross-property fixed:  MATCH
interop:               MATCH
tls-matrix:            MATCH
```

The fields compared are the ones the wrappers declare: `schema`, `spec`,
`accepted`/`outcome`, `claim_ceiling`, fixture source digests, variant binary
digests and the summary fields (`common_failures`,
`candidate_specific_failures`, `unresolved_cells`). Matching stable fields show
that the gates are deterministic across these runs; it does not make the 1.2.0
bytes a copy of the 1.1.0 bytes, and the two report files are not
byte-identical.

## 5. Analysis documents

`analysis-development.json` and `analysis-held-out.json` were regenerated by the
harness over the full declared partitions. Structural comparison with the
previous documents shows that:

- the only changed case entries are `c14`, `c15` and `c16`;
- every other case entry is byte-identical in content;
- wrong-code refusals are unchanged: `c06`, `c13` (two commands) and `c17`;
- restoration failures are unchanged: `c08`, `c09`, `c11`, `c17`;
- `instrument.binary_sha256` is unchanged
  (`49937254ac5c35ff63f065f937b30e77674068f601a85e5111523daca0600e55`);
- `instrument.python_version` remains `3.11.18`;
- the recorded `protocol_version` and `protocol_sha256` are those of the
  amended protocol.

The 15 receipts that were not replayed retain the predecessor protocol digest
`b4488e4836253e75ee01597857e29a37a89cd23cec9b6eda7a3f8fabdd1c5b76` in their
`protocol_sha256` field. That is an accurate record of the protocol under which
each was produced. They were not rewritten to claim the amended protocol. The
three replayed receipts record
`3f067d668a1bbdc5e7fbf4d79c0727b4c47259c9c407b134f1ec86f447dae1c4`.
`reconstruct_analysis.py` does not require every receipt to carry the current
protocol digest; it checks the receipt population, typed decisions, expectation
matches, foundation decisions and restoration outcomes, and it found 0
discrepancies.

## 6. Remaining `NOT_RUN` cases

None. After the replay, all 18 cases have a decided receipt, and reconstruction
reports `not_run=0` for both partitions.

This does **not** mean every case passed, and it does not remove the existing
negative findings (sections 5.2 to 5.6 of `RESULTS.md`).

## 7. Environment

| Item | Value |
|---|---|
| Instrument gates image | `python:3.11-slim` |
| Comparative harness image | `python:3.11-slim` |
| Harness runtime | Python 3.11.18; OpenSSL 3.5.7 |
| Gate toolchain | gcc 14.2.0, GNU ld 2.44, valgrind 3.24.0 |
| Resource envelope | `--memory=2g --memory-swap=2g --pids-limit=512 --cpus=2 --ulimit nofile=1024:1024 --oom-score-adj=500` |
| Capabilities | `ALL` dropped, plus `DAC_OVERRIDE`, `CHOWN`, `FOWNER` (and `SETUID`, `SETGID` for the fixture gates) |
| Isolation | `no-new-privileges`; reconstruction additionally `--network=none` |
| Build settings | `CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0` |
| Host execution | None for `cargo`, `rustc`, the comparative harness or any verifier. The host copied report bytes and performed read-only JSON inspection and comparison. |

## 8. Non-claims

This replay is not a new held-out test, not a fresh discovery, not a new
evaluation and not external verification. It does not establish that the three
reports are authentic evidence, that the gates are adequate, that the three
refusals are correct beyond the declared document semantics, that the
restoration acceptance is independent corroboration, or that any claim in
`CLAIMS.json` is strengthened. `c14` and `c15` have now been executed twice
under two different digests; the held-out partition is no longer
single-execution evidence for those two cases. A refusal is not a pass. A
`NOT_RUN` was not a pass, and converting it to a decided result does not make it
one. A digest is not authentication.
