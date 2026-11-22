#!/bin/sh
# Phase 12.1 bounded information-flow and leakage classification gate.
#
# Runs the Python validator inside python:3.11-slim with a hard memory cap,
# equal swap cap, pid/cpu/nofile limits, reduced capabilities, and
# no-new-privileges. Network is disabled (--network=none) because this is a
# pure validation gate. DAC_OVERRIDE/CHOWN/FOWNER are added only so the
# container can write the committed report into the bind-mounted output
# directory; no other capability is granted.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="${IMAGE:-python:3.11-slim}"
OUT="$ROOT/evaluation/earned-trust/information-flow"
mkdir -p "$OUT"

timeout 1800 docker run --rm \
    --name "frf-etp-information-flow-$$" \
    --memory=512m --memory-swap=512m \
    --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 \
    --oom-score-adj=500 \
    --cap-drop ALL \
    --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges \
    --network=none \
    -v "$ROOT":/src:ro \
    -v "$OUT":/out \
    -w /src \
    "$IMAGE" python3 /src/evaluation/earned-trust/information_flow.py \
        --model /src/evaluation/earned-trust/information-flow/model.json \
        --report /out/report.json \
        --self-test

echo "information-flow gate: PASS"
