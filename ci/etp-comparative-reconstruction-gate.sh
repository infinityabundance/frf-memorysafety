#!/bin/sh
# Independent reconstruction gate for the Phase 17 comparative analysis.
#
# Recomputes the 18-case matrix from the committed receipts and the frozen
# protocol without importing the harness, then checks that both harness
# analyses agree. Runs in a hardened python:3.11-slim container with no network.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON_IMAGE="${FRF_PYTHON_IMAGE:-python:3.11-slim}"
LOGS="$ROOT/target/release-gate"
mkdir -p "$LOGS"

echo "== etp-comparative-reconstruction =="
if timeout 900 docker run --rm \
    --name "frf-ms-comparative-recon-$$" \
    --memory=1g --memory-swap=1g \
    --pids-limit=128 --cpus=1 \
    --ulimit nofile=512:512 \
    --oom-score-adj=500 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges \
    --network=none \
    -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
    -w /src "$PYTHON_IMAGE" \
    python3 evaluation/earned-trust-comparative/reconstruct_analysis.py \
        --out /src/target/analysis-reconstruction.json \
    >"$LOGS/etp-comparative-reconstruction.log" 2>&1
then
    cat "$LOGS/etp-comparative-reconstruction.log"
    cp "$ROOT/target/analysis-reconstruction.json" \
       "$ROOT/evaluation/earned-trust-comparative/analysis-reconstruction.json"
    echo "PASS etp-comparative-reconstruction"
else
    status=$?
    tail -n 120 "$LOGS/etp-comparative-reconstruction.log" || true
    echo "FAIL etp-comparative-reconstruction (exit $status)"
    exit "$status"
fi
