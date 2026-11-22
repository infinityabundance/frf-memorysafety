#!/bin/sh
# Phase 10.2 ETP campaign and independent reconstruction gate.
#
# This gate runs the real closed native fixture campaign in a hardened
# rust:1.85.0-slim container, verifies the generated and committed closure
# manifests, projects and verifies SARIF 2.1.0, and then runs the independent
# standard-library reconstructor in a separate hardened python:3.11-slim
# container. Every container keeps the declared memory/swap cap, pid cap, cpu
# cap, nofile limit, OOM adjustment, reduced capabilities, and
# no-new-privileges. The repository is mounted read-only except for target/.
set -eu

RUST_IMAGE="${FRF_RUST_IMAGE:-rust:1.85.0-slim}"
PYTHON_IMAGE="${FRF_PYTHON_IMAGE:-python:3.11-slim}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOGS="$ROOT/target/gate-logs"
mkdir -p "$LOGS"
RUST_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$RUST_IMAGE" 2>/dev/null || true)
PYTHON_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$PYTHON_IMAGE" 2>/dev/null || true)
if [ -z "$RUST_IMAGE_ID" ]; then RUST_IMAGE_ID=unknown; fi
if [ -z "$PYTHON_IMAGE_ID" ]; then PYTHON_IMAGE_ID=unknown; fi

echo "== etp-campaign =="
if timeout 1800 docker run --rm \
    --name "frf-ms-etp-campaign-$$" \
    --memory=2g --memory-swap=2g \
    --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 \
    --oom-score-adj=500 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges \
    -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
    -v frf-cargo:/cargo -e CARGO_HOME=/cargo \
    -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" -e CARGO_INCREMENTAL=0 \
    -e FRF_NATIVE_HARNESS=1 \
    -e FRF_ETP_ENVIRONMENT="$RUST_IMAGE" \
    -e FRF_ETP_IMAGE_ID="$RUST_IMAGE_ID" \
    -w /src "$RUST_IMAGE" sh -c '
        set -eu
        cargo build --locked --features native-harness --bin frf-memorysafety
        rm -rf target/etp-campaign-run
        mkdir -p target/etp-campaign-run
        ./target/debug/frf-memorysafety etp campaign run \
            --protocol evaluation/earned-trust/protocol.json \
            --out target/etp-campaign-run
        ./target/debug/frf-memorysafety etp campaign verify \
            target/etp-campaign-run/MANIFEST.json --json \
            > target/etp-campaign-run/report.json
        ./target/debug/frf-memorysafety etp campaign verify \
            evaluation/earned-trust/MANIFEST.json --json \
            > target/etp-committed-report.json
        ./target/debug/frf-memorysafety etp sarif export \
            target/etp-campaign-run/MANIFEST.json \
            --out target/etp-campaign-run/campaign.sarif
        ./target/debug/frf-memorysafety etp sarif verify \
            target/etp-campaign-run/campaign.sarif --json \
            > target/etp-campaign-run/sarif-report.json
        ./target/debug/frf-memorysafety etp sarif verify \
            evaluation/earned-trust/campaign.sarif --json \
            > target/etp-committed-sarif-report.json
        ./target/debug/frf-memorysafety etp campaign verify \
            evaluation/earned-trust/MANIFEST.json
        ./target/debug/frf-memorysafety etp sarif verify \
            evaluation/earned-trust/campaign.sarif
    ' >"$LOGS/etp-campaign.log" 2>&1
then
    cat "$LOGS/etp-campaign.log"
    echo "PASS etp-campaign"
else
    status=$?
    tail -n 120 "$LOGS/etp-campaign.log" || true
    echo "FAIL etp-campaign (exit $status)"
    exit "$status"
fi

echo "== etp-reconstruction =="
if timeout 600 docker run --rm \
    --name "frf-ms-etp-reconstruction-$$" \
    --memory=512m --memory-swap=512m \
    --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 \
    --oom-score-adj=500 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --network=none \
    -v "$ROOT":/src:ro -w /src "$PYTHON_IMAGE" \
    python3 evaluation/earned-trust/reconstruct.py >"$LOGS/etp-reconstruction.log" 2>&1
then
    cat "$LOGS/etp-reconstruction.log"
    echo "PASS etp-reconstruction"
else
    status=$?
    tail -n 120 "$LOGS/etp-reconstruction.log" || true
    echo "FAIL etp-reconstruction (exit $status)"
    exit "$status"
fi
