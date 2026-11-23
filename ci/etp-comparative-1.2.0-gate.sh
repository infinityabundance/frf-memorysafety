#!/bin/sh
# 1.2.0 comparative replication gate.
#
# Builds the frf-memorysafety CLI in a hardened rust:1.85.0-slim container and
# runs evaluation/earned-trust-comparative-1.2.0/run_comparative.py for the
# selected partition in a hardened python:3.11-slim container. Host builds and
# host verifier execution are forbidden.
#
# This is a labeled replication of the frozen 1.1.0 comparative evaluation. It is
# not a new held-out test and not external verification. The default partition is
# development so that a routine gate run does not re-execute the held-out
# partition; the committed held-out evidence is reconstructed by
# ci/etp-comparative-1.2.0-reconstruction-gate.sh. Set
# FRF_COMPARATIVE_1_2_0_PARTITION to held-out or all only for a deliberate
# re-execution, which must be reported as a re-run rather than a first run.
#
# Fresh runs go to target/comparative-1.2.0-run/. Committed evidence under
# evaluation/earned-trust-comparative-1.2.0/ is replaced only when
# FRF_COMPARATIVE_1_2_0_PROMOTE=1 (the default) and the harness exits 0.
#
# A PASS line means the observed decision equals the declared expectation. It is
# not a certification, a review, or an authorization to deploy. A refusal is not
# a pass. A NOT_RUN is not a pass.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RUST_IMAGE="${RUST_IMAGE:-rust:1.85.0-slim}"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.11-slim}"
PARTITION="${FRF_COMPARATIVE_1_2_0_PARTITION:-development}"
PROMOTE="${FRF_COMPARATIVE_1_2_0_PROMOTE:-1}"
RUN_DIR="$ROOT/target/comparative-1.2.0-run"
OUT="${FRF_COMPARATIVE_1_2_0_OUT:-$ROOT/evaluation/earned-trust-comparative-1.2.0}"
BUILD_LOG="$ROOT/target/comparative-1.2.0-build.log"
HARNESS_LOG="$ROOT/target/comparative-1.2.0-harness.log"

mkdir -p "$RUN_DIR" "$ROOT/target"
rm -rf "$RUN_DIR"/*
: >"$BUILD_LOG"
: >"$HARNESS_LOG"

echo "== etp-comparative-1.2.0 build ($RUST_IMAGE) =="
if timeout 1800 docker run --rm \
    --name "frf-etp-comparative-1.2.0-build-$$" \
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
    echo "FAIL etp-comparative-1.2.0-$PARTITION (build exit $status)"
    exit "$status"
fi

if [ ! -f "$ROOT/target/debug/frf-memorysafety" ]; then
    echo "MISSING binary after build"
    tail -n 40 "$BUILD_LOG" || true
    echo "FAIL etp-comparative-1.2.0-$PARTITION"
    exit 1
fi
echo "binary sha256: $(sha256sum "$ROOT/target/debug/frf-memorysafety" | cut -d ' ' -f 1)"

echo "== etp-comparative-1.2.0 harness ($PYTHON_IMAGE) =="
if timeout 1800 docker run --rm \
    --name "frf-etp-comparative-1.2.0-run-$$" \
    --memory=2g --memory-swap=2g \
    --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 \
    --oom-score-adj=500 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges \
    -v "$ROOT":/src:ro -v "$RUN_DIR":/out \
    -e FRF_COMPARATIVE_PARTITION="$PARTITION" \
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
python3 /src/evaluation/earned-trust-comparative-1.2.0/run_comparative.py \
    --partition "${FRF_COMPARATIVE_PARTITION:-development}" --out /out
status=$?
set -e
chmod -R a+rwX /out 2>/dev/null || true
exit $status
' >"$HARNESS_LOG" 2>&1
then
    harness_status=0
else
    harness_status=$?
fi

cat "$HARNESS_LOG"

if [ "$harness_status" -ne 0 ]; then
    echo "FAIL etp-comparative-1.2.0-$PARTITION (harness exit $harness_status)"
    exit "$harness_status"
fi

if [ ! -f "$RUN_DIR/analysis-$PARTITION.json" ]; then
    echo "MISSING analysis-$PARTITION.json from the harness"
    echo "FAIL etp-comparative-1.2.0-$PARTITION"
    exit 1
fi

if [ "$PROMOTE" = "1" ]; then
    mkdir -p "$OUT/receipts"
    for receipt in "$RUN_DIR"/receipts/*.json; do
        if [ ! -f "$receipt" ]; then
            echo "MISSING case receipt in harness output"
            echo "FAIL etp-comparative-1.2.0-$PARTITION"
            exit 1
        fi
        cp -f "$receipt" "$OUT/receipts/"
    done
    cp -f "$RUN_DIR/analysis-$PARTITION.json" "$OUT/analysis-$PARTITION.json"
    echo "receipts: $(ls -1 "$OUT"/receipts/*.json | wc -l) committed"
else
    echo "promotion: skipped (FRF_COMPARATIVE_1_2_0_PROMOTE=$PROMOTE)"
fi

echo "PASS etp-comparative-1.2.0-$PARTITION"
echo "NOTE PASS is not certification. A refusal is not a pass. A NOT_RUN is not a pass."
