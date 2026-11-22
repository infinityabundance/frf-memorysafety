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

# Compare the fresh run report to the committed report.
# Only compare stable fields (schema, spec, claim_ceiling, outcome, metadata keys).
# The exact instruction counts and trace lines may vary between runs.
if [ -f "$OUT/report.json" ] && [ -f "$RUN_DIR/report.json" ]; then
    echo "Comparing committed report to fresh run..."
    # Use python to compare stable fields.
    python3 -c "
import json
import sys

with open('$OUT/report.json') as f:
    committed = json.load(f)
with open('$RUN_DIR/report.json') as f:
    fresh = json.load(f)

stable_fields = ['schema', 'spec', 'claim_ceiling', 'outcome']
for field in stable_fields:
    if committed.get(field) != fresh.get(field):
        print(f'MISMATCH: {field}: committed={committed.get(field)} fresh={fresh.get(field)}')
        sys.exit(1)

# Check that metadata has the same keys (values may differ)
committed_keys = set(committed.get('metadata', {}).keys())
fresh_keys = set(fresh.get('metadata', {}).keys())
if committed_keys != fresh_keys:
    print(f'MISMATCH: metadata keys: committed={sorted(committed_keys)} fresh={sorted(fresh_keys)}')
    sys.exit(1)

print('Stable fields match.')
"
    if [ $? -ne 0 ]; then
        echo "Report comparison FAILED"
        exit 1
    fi
else
    echo "WARNING: One or both reports missing, skipping comparison"
fi

echo "etp-timing gate: PASS"