#!/bin/sh
# Independent reconstruction gate for the 1.2.0 comparative replication.
#
# Recomputes the 18-case matrix from the committed receipts and the frozen
# 1.2.0 replication protocol without importing the harness, then checks that
# both harness analyses agree. Runs in a hardened python:3.11-slim container
# with no network and the exact declared resource caps.
#
# This checks bookkeeping only. It does not re-run a verifier, does not
# establish that a refusal is correct, and is not certification. A NOT_RUN is
# not a pass.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON_IMAGE="${FRF_PYTHON_IMAGE:-python:3.11-slim}"
OUT="$ROOT/evaluation/earned-trust-comparative-1.2.0"
LOGS="$ROOT/target/release-gate"
TMP_OUT="$ROOT/target/analysis-reconstruction-1.2.0.json"
mkdir -p "$LOGS" "$ROOT/target"

echo "== etp-comparative-1.2.0-reconstruction =="
if timeout 900 docker run --rm \
    --name "frf-ms-comparative-1.2.0-recon-$$" \
    --memory=2g --memory-swap=2g \
    --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 \
    --oom-score-adj=500 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges \
    --network=none \
    -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
    -w /src "$PYTHON_IMAGE" \
    python3 evaluation/earned-trust-comparative-1.2.0/reconstruct_analysis.py \
        --out /src/target/analysis-reconstruction-1.2.0.json \
    >"$LOGS/recon-1.2.0.log" 2>&1
then
    cat "$LOGS/recon-1.2.0.log"
    cp -f "$TMP_OUT" "$OUT/analysis-reconstruction.json"
    echo "PASS etp-comparative-1.2.0-reconstruction"
    echo "NOTE reconstruction checks bookkeeping only; it is not certification."
else
    status=$?
    tail -n 120 "$LOGS/recon-1.2.0.log" || true
    echo "FAIL etp-comparative-1.2.0-reconstruction (exit $status)"
    exit "$status"
fi
