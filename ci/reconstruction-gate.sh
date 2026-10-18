#!/bin/sh
# Phase 9.2 independent reconstruction gate.
#
# Recomputes the evaluation from evaluation/protocol.json, MANIFEST.json, every
# receipt, and evaluation/CLAIMS.json with evaluation/reconstruct.py. The
# reconstructor is standard-library Python and does not import or execute the
# Rust crate. The same hardened container limits as ./ci/gate.sh are used; the
# repository is mounted read-only and the container has no network.
set -eu

IMAGE="${FRF_PYTHON_IMAGE:-python:3.11-slim}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOGS="$ROOT/target/gate-logs"
mkdir -p "$LOGS"
IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null || true)
if [ -z "$IMAGE_ID" ]; then
    IMAGE_ID=unknown
fi

echo "== independent-reconstruction =="
if timeout 600 docker run --rm \
    --name "frf-ms-reconstruction-$$" \
    --memory=512m --memory-swap=512m \
    --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 \
    --oom-score-adj=500 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --network=none \
    -e FRF_EVAL_IMAGE="$IMAGE" -e FRF_EVAL_IMAGE_ID="$IMAGE_ID" \
    -v "$ROOT":/src:ro -w /src "$IMAGE" \
    python3 evaluation/reconstruct.py >"$LOGS/reconstruction-gate.log" 2>&1
then
    cat "$LOGS/reconstruction-gate.log"
    echo "PASS independent-reconstruction"
else
    status=$?
    tail -n 80 "$LOGS/reconstruction-gate.log" || true
    echo "FAIL independent-reconstruction (exit $status)"
    exit "$status"
fi
