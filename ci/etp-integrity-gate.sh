#!/bin/sh
# Phase 11.1b: two-build reproducibility receipt under a hardened container.
#
# Every build and verification runs inside rust:1.85.0-slim with a hard OOM
# cap, equal swap cap, pid/cpu/nofile limits, reduced capabilities, and
# no-new-privileges. The source is mounted read-only; only the receipt
# directory and the Cargo home volume are writable.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="${IMAGE:-rust:1.85.0-slim}"
OUT="$ROOT/evaluation/earned-trust/integrity"
mkdir -p "$OUT"

timeout 1800 docker run --rm \
    --name "frf-etp-integrity-$$" \
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
    -v frf-cargo:/cargo \
    -e CARGO_HOME=/cargo \
    -w /src \
    "$IMAGE" /src/ci/etp-integrity-gate-inner.sh
