#!/bin/sh
# Phase 12.2a bounded live timing/execution-path profile gate.
#
# Compiles the C timing probe inside python:3.11-slim with a hard OOM cap,
# equal swap cap, pid/cpu/nofile limits, reduced capabilities, and
# no-new-privileges. Installs gcc, binutils, and valgrind inside the container.
# Runs the timing profile script and its self-test, then compares stable fields
# to the committed report.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="${IMAGE:-python:3.11-slim}"
OUT="$ROOT/evaluation/earned-trust/timing"
RUN_DIR="$ROOT/target/etp-timing-run"
mkdir -p "$OUT" "$RUN_DIR"

# Clean up any previous run artifacts in the run directory.
rm -rf "$RUN_DIR"/*

timeout 1800 docker run --rm \
    --name "frf-etp-timing-$$" \
    --memory=1g --memory-swap=1g \
    --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 \
    --oom-score-adj=500 \
    --cap-drop ALL \
    --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --cap-add SETUID --cap-add SETGID \
    --security-opt no-new-privileges \
    -v "$ROOT":/src:ro \
    -v "$RUN_DIR":/out \
    -w /src \
    "$IMAGE" /src/ci/etp-timing-gate-inner.sh

# Compare the fresh run reports to the committed reports per mode.
# Stable fields include the typed outcome and the real per-function Ir counts.
for mode in branch ct length; do
    committed="$OUT/report-$mode.json"
    fresh="$RUN_DIR/report-$mode.json"
    if [ ! -f "$committed" ] || [ ! -f "$fresh" ]; then
        echo "MISSING report for $mode: committed=$committed fresh=$fresh"
        exit 1
    fi
    python3 - "$committed" "$fresh" "$mode" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    committed = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    fresh = json.load(handle)
mode = sys.argv[3]

for field in ("schema", "spec", "claim_ceiling", "outcome"):
    if committed.get(field) != fresh.get(field):
        print(f"MISMATCH {mode}.{field}: committed={committed.get(field)!r} fresh={fresh.get(field)!r}")
        sys.exit(1)

for field in ("source_sha256", "binary_sha256"):
    left = committed.get("metadata", {}).get(field)
    right = fresh.get("metadata", {}).get(field)
    if left != right:
        print(f"MISMATCH {mode}.metadata.{field}: committed={left!r} fresh={right!r}")
        sys.exit(1)

for field in ("results", "trace_lines"):
    left = committed.get("metadata", {}).get(field)
    right = fresh.get("metadata", {}).get(field)
    if left != right:
        print(f"MISMATCH {mode}.metadata.{field}: committed={left!r} fresh={right!r}")
        sys.exit(1)

print(f"Stable fields match for {mode}.")
PY
done

echo "etp-timing gate: PASS"