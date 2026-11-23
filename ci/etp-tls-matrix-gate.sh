#!/bin/sh
# Phase 13.2 TLS matrix gate.
#
# Compiles tests/fixtures/tls/tls_echo_server.c and tls_echo_client.c against
# reference and candidate OpenSSL prefixes, runs the genuine four-way matrix
# for cases tls13_echo and wrong_ca, records per-process identity, case
# population, per-cell outcomes, common failures, candidate-specific failures,
# and explicit unresolved cells, and emits a canonical frf-etp.tls-matrix.v1
# report under evaluation/earned-trust/tls-matrix/.
#
# Fresh runs go to target/etp-tls-matrix-run/; committed evidence under
# evaluation/earned-trust/tls-matrix/; repeated gate runs must not dirty the tree.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="${IMAGE:-python:3.11-slim}"
OUT="$ROOT/evaluation/earned-trust/tls-matrix"
RUN_DIR="$ROOT/target/etp-tls-matrix-run"
mkdir -p "$OUT" "$RUN_DIR"

# Clean up any previous run artifacts in the run directory.
rm -rf "$RUN_DIR"/*

timeout 1800 docker run --rm \
    --name "frf-etp-tls-matrix-$$" \
    --memory=1g --memory-swap=1g \
    --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 \
    --oom-score-adj=500 \
    --cap-drop ALL \
    --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --cap-add SETUID --cap-add SETGID \
    --security-opt no-new-privileges \
    -v "$ROOT":/src:ro -v "$RUN_DIR":/out \
    -w /src \
    "$IMAGE" /src/ci/etp-tls-matrix-gate-inner.sh

# Compare the fresh run report to the committed report.
committed="$OUT/report.json"
fresh="$RUN_DIR/report.json"
if [ ! -f "$fresh" ]; then
    echo "MISSING fresh report: $fresh"
    exit 1
fi
if [ ! -f "$committed" ]; then
    # First run: promote fresh to committed.
    cp "$fresh" "$committed"
    echo "First run: committed report created at $committed"
    echo "etp-tls-matrix gate: PASS"
    exit 0
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

# Compare fixture source digests.
for src_field in ("server_source_sha256", "client_source_sha256"):
    if committed.get("fixture", {}).get(src_field) != fresh.get("fixture", {}).get(src_field):
        print(f"MISMATCH fixture.{src_field}")
        sys.exit(1)

# Compare binary digests.
for variant in ("reference", "candidate"):
    for bin_field in ("server_binary_sha256", "client_binary_sha256"):
        left = committed.get("binaries", {}).get(variant, {}).get(bin_field)
        right = fresh.get("binaries", {}).get(variant, {}).get(bin_field)
        if left != right:
            print(f"MISMATCH binaries.{variant}.{bin_field}")
            sys.exit(1)

# Compare summary fields.
for field in ("common_failures", "candidate_specific_failures", "unresolved_cells"):
    left = committed.get("summary", {}).get(field)
    right = fresh.get("summary", {}).get(field)
    if left != right:
        print(f"MISMATCH summary.{field}")
        sys.exit(1)

print("Stable fields match.")
PY

echo "etp-tls-matrix gate: PASS"