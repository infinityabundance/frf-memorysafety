#!/usr/bin/env sh
# Phase 14 ETP gate.
#
# Runs both independent verifiers (Rust CLI + Python stdlib) and their self-tests
# against the committed evidence. Fresh runs land in target/etp-phase14-run/.
# Committed evidence is never rewritten.
#
# Hardened container flags:
#   --memory=512m --memory-swap=512m --pids-limit=512 --cpus=2
#   --ulimit nofile=1024:1024 --oom-score-adj=500
#   --cap-drop ALL --security-opt no-new-privileges --network=none
set -eu

RUST_IMAGE="${FRF_RUST_IMAGE:-rust:1.85.0-slim}"
PYTHON_IMAGE="${FRF_PYTHON_IMAGE:-python:3.11-slim}"
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
LOGS="$ROOT/target/gate-logs"
mkdir -p "$LOGS"

rust_run() {
    name=$1
    shift
    echo "== $name =="
    if timeout 1800 docker run --rm \
        --name "frf-ms-$name-$$" \
        --memory=2g --memory-swap=2g \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 \
        --oom-score-adj=500 \
        --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
        --security-opt no-new-privileges \
        -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
        -v frf-cargo:/cargo -e CARGO_HOME=/cargo \
        -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" -e CARGO_INCREMENTAL=0 \
        -w /src "$RUST_IMAGE" "$@" >"$LOGS/$name.log" 2>&1
    then
        cat "$LOGS/$name.log"
        echo "PASS $name"
    else
        status=$?
        tail -n 120 "$LOGS/$name.log" || true
        echo "FAIL $name (exit $status)"
        exit "$status"
    fi
}

python_run() {
    name=$1
    shift
    echo "== $name =="
    if timeout 900 docker run --rm \
        --name "frf-ms-$name-$$" \
        --memory=512m --memory-swap=512m \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 \
        --oom-score-adj=500 \
        --cap-drop ALL --cap-add DAC_OVERRIDE \
        --security-opt no-new-privileges \
        --network=none \
        -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
        -w /src "$PYTHON_IMAGE" "$@" >"$LOGS/$name.log" 2>&1
    then
        cat "$LOGS/$name.log"
        echo "PASS $name"
    else
        status=$?
        tail -n 120 "$LOGS/$name.log" || true
        echo "FAIL $name (exit $status)"
        exit "$status"
    fi
}

mkdir -p target/etp-phase14-run

# 1. Build the crate and run Rust SARIF verifier on committed evidence
rust_run etp-phase14-rust-sarif sh -c '
    set -eu
    cargo build --locked --features native-harness --bin frf-memorysafety
    ./target/debug/frf-memorysafety etp sarif verify \
        evaluation/earned-trust/campaign.sarif --json \
        > target/etp-phase14-run/rust-sarif-report.json
    ./target/debug/frf-memorysafety etp sarif verify \
        evaluation/earned-trust/campaign.sarif
'

# 2. Run Python SARIF verifier on committed evidence
python_run etp-phase14-py-sarif \
    python3 evaluation/earned-trust/verify_sarif.py \
    --campaign evaluation/earned-trust/MANIFEST.json \
    --sarf evaluation/earned-trust/campaign.sarif \
    --review evaluation/earned-trust/suppression-review.json \
    --statement evaluation/earned-trust/attestations/campaign-closure.statement.json \
    --json

# 3. Run Python SARIF verifier self-test
python_run etp-phase14-py-sarif-selftest \
    python3 evaluation/earned-trust/verify_sarif.py \
    --campaign evaluation/earned-trust/MANIFEST.json \
    --sarf evaluation/earned-trust/campaign.sarif \
    --review evaluation/earned-trust/suppression-review.json \
    --statement evaluation/earned-trust/attestations/campaign-closure.statement.json \
    --self-test

# 4. Run Python attestation verifier on committed evidence
python_run etp-phase14-py-attestation \
    python3 evaluation/earned-trust/verify_attestations.py \
    --attestations evaluation/earned-trust/attestations \
    --policy evaluation/earned-trust/trust-policy.json \
    --campaign evaluation/earned-trust/MANIFEST.json

# 5. Run Python attestation verifier negative controls
python_run etp-phase14-py-attestation-controls \
    python3 evaluation/earned-trust/verify_attestations.py \
    --attestations evaluation/earned-trust/attestations \
    --policy evaluation/earned-trust/trust-policy.json \
    --campaign evaluation/earned-trust/MANIFEST.json \
    --controls

# 6. Run Rust attestation verifier on committed evidence
rust_run etp-phase14-rust-attestation sh -c '
    set -eu
    ./target/debug/frf-memorysafety etp attest verify \
        evaluation/earned-trust/attestations/campaign-closure.envelope.json \
        --policy evaluation/earned-trust/trust-policy.json \
        --campaign evaluation/earned-trust/MANIFEST.json \
        --json > target/etp-phase14-run/rust-attestation-report.json
    ./target/debug/frf-memorysafety etp attest verify \
        evaluation/earned-trust/attestations/campaign-closure.envelope.json \
        --policy evaluation/earned-trust/trust-policy.json \
        --campaign evaluation/earned-trust/MANIFEST.json
'

echo "PASS etp-phase14-gate"
echo "rust image: $RUST_IMAGE"
echo "python image: $PYTHON_IMAGE"
