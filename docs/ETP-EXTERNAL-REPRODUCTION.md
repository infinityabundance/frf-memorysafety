# External reproduction instructions

**Release:** FRF-MemorySafety 1.2.0 candidate in the working tree (not
published), historical evidence tag `etp-evidence-v1`.
**Frozen 1.0.0 baseline:** `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`.

> The 1.2.0 candidate is bound to `Cargo.toml` version `1.2.0`. The campaign
> closure is `ece999b403e7ce05f94dbe2304a2b86b24afb1a9cd5dc5e1a5f57d22482d735a`,
> the candidate identity is
> `79e72160a6a1c169093d5e7abb39f426a9f189d07aef7ddc472b3856911bcbb7`, and the
> evidence lives under `evaluation/earned-trust-1.2.0/`. No crates.io publish
> was made. The 1.1.0 evidence under `evaluation/earned-trust/` remains
> historical and unchanged.
**Scope:** reproduce the declared evidence and gate results from a clean export.
This document does not certify the software and does not claim that reproduction
is correctness.

## 1. Prerequisites

- Git, Docker, and enough disk for the Rust and Coq containers.
- No host compiler or test execution is permitted. Every build and verifier
  runs in a container with:

```text
--memory=2g --memory-swap=2g --pids-limit=512 --cpus=2
--ulimit nofile=1024:1024 --oom-score-adj=500
--cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER
--security-opt no-new-privileges
```

- Network access is needed only to pull images and to install Coq, jq,
  OpenSSL or the OpenSSL CLI inside the containers.
- The transparency, time, witness, revocation and attestation material are
  local test artifacts. They are not public infrastructure.

## 2. Clean export

```sh
git clone https://github.com/infinityabundance/frf-memorysafety.git
cd frf-memorysafety
# Historical 1.1.0 evidence tag
git checkout etp-evidence-v1
git status --porcelain   # must be empty
```

A `git archive` export of the tag is also acceptable. Do not use a working
tree containing `target/`, `research/` or uncommitted files. The 1.2.0 migration
candidate is a working-tree change set, not a tag; reproduce it from the exact
working tree that produced `evaluation/earned-trust-1.2.0/` and verify its
digests before running the gates.

## 3. Release gate

```sh
./ci/etp-release-gate.sh
```

The script runs the declared gate inventory in sequence, writes one log per
gate under `target/release-gate/`, and prints a `GATE <name> PASS|FAIL` line
for each. It exits nonzero if any gate fails. The expected inventory is:

```text
fmt clippy test test-release
native mir detector proof bridge conversion eval reconstruction
etp eth-auth eth-time eth-transparency eth-integrity eth-witness
eth-information-flow eth-timing eth-cross-property eth-interop eth-tls-matrix
eth-phase14 eth-phase15 eth-formal-acceptance eth-comparative-development
eth-comparative-reconstruction
```

Gate names in the script are the actual `ci/*.sh` names; the list above is
descriptive. A `NOT_RUN` gate is reported as `NOT_RUN`, never as a pass.

## 4. Evidence checks that do not depend on the release gate

From the repository root, in a container if the tool is not available on the
host:

```sh
# 1.2.0 frozen opening and campaign closure
sha256sum evaluation/earned-trust-1.2.0/opening.sha256
sha256sum evaluation/earned-trust-1.2.0/MANIFEST.json   # ece999b4...
./ci/etp-gate.sh

# 1.1.0 historical comparative opening (NOT_REBOUND to 1.2.0)
sha256sum -c evaluation/earned-trust-comparative/OPENING.sha256
sha256sum -c evaluation/earned-trust-comparative/HELD-OUT-OPENING.sha256

# Independent reconstruction of the comparative analysis
docker run --rm --memory=1g --memory-swap=1g --pids-limit=128 --cpus=1 \
  --ulimit nofile=512:512 --oom-score-adj=500 --cap-drop ALL \
  --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
  --security-opt no-new-privileges --network=none \
  -v "$PWD":/src:ro -v "$PWD/target":/src/target -w /src \
  python:3.11-slim python3 \
  evaluation/earned-trust-comparative/reconstruct_analysis.py \
  --out /src/target/analysis-reconstruction.json
```

Expected results (1.2.0 items were rerun in hardened containers; items marked
historical are 1.1.0 records that were not rerun for 1.2.0):

- `etp-campaign`: 13 cases, 13 receipts, 25 raw evidence files; SARIF valid
  with 18 results and 11 rules, 0 suppressed, 42988 bytes; independent
  reconstruction reports opening `180e5031...` and closure `ece999b4...`.
- Comparative reconstruction: `development` 6/6, `held-out` 11/12,
  0 wrongful acceptance, 1 wrongful refusal (`c18`), 6 restoration failures,
  0 bookkeeping discrepancies. This corpus binds 1.1.0 and is NOT_REBOUND.
  Replaying it with the 1.2.0 binary refuses `c01-positive-campaign-closure`
  (5/6 development decisions), which is the candidate-binding mismatch and is
  retained, not relabelled as a pass.
- Proof gate: 8 live seal cases and 6 live proof tests; 15 Coq theorems report
  `Closed under the global context`. These are 1.1.0 records and were not rerun
  for 1.2.0.
- Formal acceptance gate: 17 controls, 36 checks, 36 passed; 1.2.0 receipt
  `6cf8b0f5...`.
- Integrity gate: two byte-identical 1.2.0 release builds
  `8067fd79...`; population 13; receipt `709a9f0d...`.
- Archive: 106/106 objects, 7 reconstruction commands, 54 inputs;
  `reconstruct.py` and `verify_sarif.py` run from the archive root.

## 5. Known reproduction limits

These are expected, not environmental accidents:

- The 1.2.0 archive includes the declared candidate and instrument source
  files under their repository-relative paths, so `reconstruct.py` and the
  archived verifiers run from the archive root. It still excludes undeclared
  source, container images, and toolchain network state; it is not a complete
  independent re-execution package and not a certification.
- The Phase 17 comparative corpus (`evaluation/earned-trust-comparative/`)
  binds the 1.1.0 candidate and closure `d26e19bd...`. It was replayed with the
  1.2.0 binary but is NOT_REBOUND; no comparative result applies to 1.2.0.
- The Rust SARIF verifier denies `suppression_id` while the independent SARIF
  verifier requires it. The `c13` control refuses, but not with the declared
  diagnostic.
- The independent revocation verifier accepts a claim that the Rust verifier
  withholds for `present_admissible: false`.
- `proof verify` without `--live` returns `checker_unavailable` when Coq is not
  configured. Only the live proof gate checks the proofs.
- External witnessing, public Rekor v2 inclusion, public trusted time and
  external review are `NOT_RUN`. No local artifact substitutes for them.

## 6. What reproduction does not establish

Reproduction is not correctness, not external review, not independence, not
certification, and not authorization to deploy. The foundation surface in the
comparative evaluation is modeled over committed labels, not an execution of
the 1.0.0 binary. A refusal is not a pass. A `NOT_RUN` is not a pass. A digest
is not authentication.
