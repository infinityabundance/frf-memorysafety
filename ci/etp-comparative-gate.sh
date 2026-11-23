#!/bin/sh
# Phase 17.2 comparative evaluation gate (development partition only).
#
# Builds the frf-memorysafety CLI in a hardened rust:1.85.0-slim container and
# runs evaluation/earned-trust-comparative/run_comparative.py for
# --partition development in a hardened python:3.11-slim container. Host
# builds and host verifier execution are forbidden.
#
# Fresh runs go to target/comparative-run/. Committed evidence under
# evaluation/earned-trust-comparative/ is replaced only when the harness exits
# 0. Re-runs overwrite the same receipt names; they never append or duplicate.
#
# A PASS line means the observed decision equals the declared expectation. It is
# not a certification, a review, or an authorization to deploy. A refusal is
# not a pass. A NOT_RUN is not a pass.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RUST_IMAGE="${RUST_IMAGE:-rust:1.85.0-slim}"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.11-slim}"
RUN_DIR="$ROOT/target/comparative-run"
OUT="$ROOT/evaluation/earned-trust-comparative"
BUILD_LOG="$ROOT/target/comparative-build.log"
HARNESS_LOG="$ROOT/target/comparative-harness.log"

mkdir -p "$RUN_DIR" "$OUT/receipts" "$ROOT/target"
rm -rf "$RUN_DIR"/*
: >"$BUILD_LOG"
: >"$HARNESS_LOG"

echo "== etp-comparative build ($RUST_IMAGE) =="
if timeout 1800 docker run --rm \
    --name "frf-etp-comparative-build-$$" \
    --memory=2g --memory-swap=2g \
    --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 \
    --oom-score-adj=500 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges \
    -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
    -v frf-cargo:/cargo -e CARGO_HOME=/cargo \
    -e CARGO_BUILD_JOBS=1 -e CARGO_INCREMENTAL=0 \
    -w /src \
    "$RUST_IMAGE" cargo build --locked --bin frf-memorysafety \
    >"$BUILD_LOG" 2>&1
then
    echo "build: PASS"
else
    status=$?
    tail -n 80 "$BUILD_LOG" || true
    echo "FAIL etp-comparative-dev (build exit $status)"
    exit "$status"
fi

if [ ! -f "$ROOT/target/debug/frf-memorysafety" ]; then
    echo "MISSING binary after build"
    tail -n 40 "$BUILD_LOG" || true
    echo "FAIL etp-comparative-dev"
    exit 1
fi
echo "binary sha256: $(sha256sum "$ROOT/target/debug/frf-memorysafety" | cut -d ' ' -f 1)"

echo "== etp-comparative harness ($PYTHON_IMAGE) =="
if timeout 1800 docker run --rm \
    --name "frf-etp-comparative-run-$$" \
    --memory=2g --memory-swap=2g \
    --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 \
    --oom-score-adj=500 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges \
    -v "$ROOT":/src:ro -v "$RUN_DIR":/out \
    -w /src \
    "$PYTHON_IMAGE" sh -c '
set -eu
if ! command -v openssl >/dev/null 2>&1; then
    apt-get update >/dev/null 2>&1
    apt-get install -y --no-install-recommends openssl >/dev/null 2>&1
fi
echo "openssl: $(openssl version)"
echo "python: $(python3 -V 2>&1)"
set +e
python3 /src/evaluation/earned-trust-comparative/run_comparative.py \
    --partition development --out /out
status=$?
set -e
# The container runs as root. Make its outputs removable and replaceable by
# the host user so a re-run cannot accumulate or corrupt stale receipts.
chmod -R a+rwX /out 2>/dev/null || true
exit $status
' >"$HARNESS_LOG" 2>&1
then
    harness_status=0
else
    harness_status=$?
fi

# Always print the harness transcript: it contains the exact per-case
# PASS/FAIL/UNRESOLVED lines and the analysis totals.
cat "$HARNESS_LOG"

if [ "$harness_status" -ne 0 ]; then
    echo "FAIL etp-comparative-dev (harness exit $harness_status)"
    exit "$harness_status"
fi

if [ ! -f "$RUN_DIR/analysis-development.json" ]; then
    echo "MISSING analysis-development.json from the harness"
    echo "FAIL etp-comparative-dev"
    exit 1
fi

# Promote receipts and analysis only after a successful harness run. The file
# names are case ids, so re-running overwrites in place and never duplicates.
for receipt in "$RUN_DIR"/receipts/*.json; do
    if [ ! -f "$receipt" ]; then
        echo "MISSING case receipt in harness output"
        echo "FAIL etp-comparative-dev"
        exit 1
    fi
    cp -f "$receipt" "$OUT/receipts/"
done
cp -f "$RUN_DIR/analysis-development.json" "$OUT/analysis-development.json"

echo "receipts: $(ls -1 "$OUT"/receipts/*.json | wc -l) committed"
echo "PASS etp-comparative-dev"
