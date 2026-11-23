#!/bin/sh
# Phase 13.1a interop matrix gate.
#
# Compiles tests/fixtures/interop/interop.c twice (reference/candidate) with
# gcc -O1 -fno-inline -fno-builtin -g, runs the genuine four-way matrix for
# every pre-registered case, records per-process identity, case population,
# per-cell results, common failures, candidate-specific failures, environment,
# and fixture identity, and emits a canonical frf-etp.interop-matrix.v1 report
# under evaluation/earned-trust/interop/.
#
# Fresh runs go to target/etp-interop-run/; committed evidence under
# evaluation/earned-trust/interop/; repeated gate runs must not dirty the tree.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="${IMAGE:-python:3.11-slim}"
OUT="$ROOT/evaluation/earned-trust/interop"
RUN_DIR="$ROOT/target/etp-interop-run"
mkdir -p "$OUT" "$RUN_DIR"

# Clean up any previous run artifacts in the run directory.
rm -rf "$RUN_DIR"/*

timeout 1800 docker run --rm \
    --name "frf-etp-interop-$$" \
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
    "$IMAGE" /src/ci/etp-interop-gate-inner.sh

# Compare the fresh run report to the committed report.
committed="$OUT/report.json"
fresh="$RUN_DIR/report.json"
if [ ! -f "$committed" ] || [ ! -f "$fresh" ]; then
    echo "MISSING report: committed=$committed fresh=$fresh"
    exit 1
fi

python3 - "$committed" "$fresh" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    committed = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    fresh = json.load(handle)

for field in ("schema", "spec", "accepted", "claim_ceiling"):
    if committed.get(field) != fresh.get(field):
        print(f"MISMATCH {field}: committed={committed.get(field)!r} fresh={fresh.get(field)!r}")
        sys.exit(1)

# Compare fixture source digest.
if committed.get("fixture", {}).get("source_sha256") != fresh.get("fixture", {}).get("source_sha256"):
    print(f"MISMATCH fixture.source_sha256")
    sys.exit(1)

# Compare binary digests.
for variant in ("reference", "candidate"):
    left = committed.get("binaries", {}).get(variant, {}).get("binary_sha256")
    right = fresh.get("binaries", {}).get(variant, {}).get("binary_sha256")
    if left != right:
        print(f"MISMATCH binaries.{variant}.binary_sha256")
        sys.exit(1)

# Compare summary fields.
for field in ("common_failures", "candidate_specific_failures"):
    left = committed.get("summary", {}).get(field)
    right = fresh.get("summary", {}).get(field)
    if left != right:
        print(f"MISMATCH summary.{field}")
        sys.exit(1)

print("Stable fields match.")
PY

echo "etp-interop gate: PASS"