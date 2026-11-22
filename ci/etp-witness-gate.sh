#!/bin/sh
# Phase 11.2 external execution witness gate.
#
# Compiles the C witness probe inside rust:1.85.0-slim with a hard OOM cap,
# equal swap cap, pid/cpu/nofile limits, reduced capabilities, and
# no-new-privileges. Runs the witness script and its self-test, then runs the
# independent verifier if present; absent verifier is a typed NOT_RUN, not a
# pass.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="${IMAGE:-rust:1.85.0-slim}"
OUT="$ROOT/evaluation/earned-trust/witness"
mkdir -p "$OUT"

timeout 1800 docker run --rm \
    --name "frf-etp-witness-$$" \
    --memory=2g --memory-swap=2g \
    --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 \
    --oom-score-adj=500 \
    --cap-drop ALL \
    --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --cap-add SETUID --cap-add SETGID \
    --security-opt no-new-privileges \
    -v "$ROOT":/src:ro \
    -v "$OUT":/out \
    -w /src \
    "$IMAGE" /src/ci/etp-witness-gate-inner.sh
