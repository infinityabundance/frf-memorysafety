#!/bin/sh
# Phase 9.1 evaluation gate.
#
# Runs the harness and verifies every pre-registered hypothesis and claim against
# measured receipts. The same hardened container limits as ./ci/gate.sh are used;
# nothing is weakened. `time` is installed only to obtain ru_maxrss.
set -eu

IMAGE="${IMAGE:-rust:1.85.0-slim}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOGS="$ROOT/target/gate-logs"
mkdir -p "$LOGS"
IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null || true)
if [ -z "$IMAGE_ID" ]; then
    IMAGE_ID=unknown
fi

echo "== eval-harness =="
if [ "${FRF_EVAL_BOOTSTRAP:-0}" = "1" ]; then
    SCRIPT='
        set -eu
        export DEBIAN_FRONTEND=noninteractive
        apt-get -o APT::Sandbox::User=root update >/dev/null
        apt-get -o APT::Sandbox::User=root install -y --no-install-recommends time >/dev/null
        cargo build --locked --bin frf-eval
        ./target/debug/frf-eval run \
            --protocol evaluation/protocol.json \
            --out target/eval-receipts \
            --stats target/eval-stats
        ./target/debug/frf-eval verify \
            --protocol evaluation/protocol.json \
            --receipts target/eval-receipts \
            --report target/eval-report.json
    '
else
    SCRIPT='
        set -eu
        export DEBIAN_FRONTEND=noninteractive
        apt-get -o APT::Sandbox::User=root update >/dev/null
        apt-get -o APT::Sandbox::User=root install -y --no-install-recommends time >/dev/null
        cargo build --locked --bin frf-eval
        ./target/debug/frf-eval run \
            --protocol evaluation/protocol.json \
            --out target/eval-receipts \
            --stats target/eval-stats
        ./target/debug/frf-eval verify \
            --protocol evaluation/protocol.json \
            --receipts target/eval-receipts \
            --report target/eval-report.json
        ./target/debug/frf-eval verify \
            --protocol evaluation/protocol.json \
            --receipts evaluation/receipts \
            --report target/eval-committed-report.json
        ./target/debug/frf-eval compare \
            --generated target/eval-receipts \
            --committed evaluation/receipts
    '
fi

if timeout 1800 docker run --rm \
    --name "frf-ms-eval-$$" \
    --memory=2g --memory-swap=2g \
    --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 \
    --oom-score-adj=500 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges \
    -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
    -v frf-cargo:/cargo -e CARGO_HOME=/cargo \
    -e FRF_EVAL_IMAGE="$IMAGE" -e FRF_EVAL_IMAGE_ID="$IMAGE_ID" \
    -w /src "$IMAGE" sh -c "$SCRIPT" >"$LOGS/eval-gate.log" 2>&1
then
    if [ "${FRF_EVAL_BOOTSTRAP:-0}" = "1" ]; then
        echo "PASS eval-harness (bootstrap; committed receipts not yet verified)"
    else
        echo "PASS eval-harness"
    fi
else
    status=$?
    tail -n 80 "$LOGS/eval-gate.log" || true
    echo "FAIL eval-harness (exit $status)"
    exit "$status"
fi
