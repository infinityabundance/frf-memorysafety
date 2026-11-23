#!/bin/sh
# Phase 12.3a cross-property allocation/ownership repair gate.
#
# Compiles the fixture with gcc -O1 -g -fno-inline -fno-builtin;
# runs faulty and fixed variants with and without forced allocation failure;
# checks a property vector (memory validity, secret erasure, failure atomicity,
# resource safety) against the event trace and, where available, a valgrind
# memcheck run (--error-exitcode=99) for uninitialized reads/leaks;
# emits a canonical report (frf-etp.cross-property.v1) under
# evaluation/earned-trust/cross-property/ with named violations, evidence,
# limitations, and claim ceiling; refuses a clean result when any required
# property is unobserved or when the instrument is dead/empty (typed not_run).
# Fresh runs go to target/etp-cross-property-run/; committed evidence under
# evaluation/earned-trust/cross-property/; repeated gate runs must not dirty the tree.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="${IMAGE:-python:3.11-slim}"
OUT="$ROOT/evaluation/earned-trust/cross-property"
RUN_DIR="$ROOT/target/etp-cross-property-run"
mkdir -p "$OUT" "$RUN_DIR"

# Clean up any previous run artifacts in the run directory.
rm -rf "$RUN_DIR"/*

timeout 1800 docker run --rm \
    --name "frf-etp-cross-property-$$" \
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
    "$IMAGE" /src/ci/etp-cross-property-gate-inner.sh

# Compare the fresh run reports to the committed reports per mode.
for mode in faulty fixed; do
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

for field in ("metadata.source_sha256", "metadata.binary_sha256"):
    left = committed.get("metadata", {}).get(field)
    right = fresh.get("metadata", {}).get(field)
    if left != right:
        print(f"MISMATCH {mode}.metadata.{field}: committed={left!r} fresh={right!r}")
        sys.exit(1)

for field in ("metadata.results", "metadata.trace_lines"):
    left = committed.get("metadata", {}).get(field)
    right = fresh.get("metadata", {}).get(field)
    if left != right:
        print(f"MISMATCH {mode}.metadata.{field}: committed={left!r} fresh={right!r}")
        sys.exit(1)

print(f"Stable fields match for {mode}.")
PY
done

echo "etp-cross-property gate: PASS"