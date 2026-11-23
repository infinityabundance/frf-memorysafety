#!/bin/sh
# Phase 16.1b independent executable adversarial-control oracle gate.
#
# This gate runs the standalone standard-library acceptance oracle in a
# hardened python:3.11-slim container. The oracle re-implements the finite
# acceptance predicate of tests/proof/coq/etp_acceptance.v as an executable
# model and asserts one positive control, twelve primary negative controls with
# per-control restoration, and three structural controls.
#
# The container keeps the declared memory/swap cap, pid cap, cpu cap, nofile
# limit, OOM adjustment, reduced capabilities, and no-new-privileges. It has
# no network. The repository is mounted read-only at /src; only target/ is
# writable. The oracle writes the receipt into target/gate-logs, and the host
# copies those bytes into evaluation/earned-trust-1.2.0/receipts. That copy is the
# only host action on the artifact.
#
# This gate is not a proof check, not Rust verification, and not
# certification.
set -eu

PYTHON_IMAGE="${FRF_PYTHON_IMAGE:-python:3.11-slim}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOGS="$ROOT/target/gate-logs"
VERIFIER_REL="evaluation/earned-trust-1.2.0/verify_acceptance_model.py"
VERIFIER="$ROOT/$VERIFIER_REL"
RECEIPT_SRC="$LOGS/acceptance-controls.json"
RECEIPT_DST="$ROOT/evaluation/earned-trust-1.2.0/acceptance-controls/receipt.json"
LOG="$LOGS/acceptance-controls.log"
STDOUT_LOG="$LOGS/acceptance-controls.stdout.json"

mkdir -p "$LOGS" "$ROOT/evaluation/earned-trust-1.2.0/receipts" "$ROOT/evaluation/earned-trust-1.2.0/acceptance-controls"

if [ ! -f "$VERIFIER" ]; then
    echo "FAIL etp-formal-acceptance-gate (missing $VERIFIER_REL)"
    exit 1
fi

IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$PYTHON_IMAGE" 2>/dev/null || true)
if [ -z "$IMAGE_ID" ]; then IMAGE_ID=unknown; fi
VERIFIER_SHA=$(sha256sum "$VERIFIER" | cut -d' ' -f1)

# A stale temporary receipt must not survive a failing run. The committed
# receipt is left in place: a failed run is reported loudly and must not delete
# the last successful evidence.
rm -f "$RECEIPT_SRC"

echo "== etp-formal-acceptance =="
echo "python image: $PYTHON_IMAGE ($IMAGE_ID)"
echo "verifier: $VERIFIER_REL sha256=$VERIFIER_SHA"

if timeout 600 docker run --rm \
    --name "frf-ms-etp-formal-acceptance-$$" \
    --memory=2g --memory-swap=2g \
    --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 \
    --oom-score-adj=500 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges \
    --network=none \
    -e FRF_ETP_PYTHON_IMAGE="$PYTHON_IMAGE" \
    -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
    -w /src "$PYTHON_IMAGE" \
    python3 "$VERIFIER_REL" \
        --out /src/target/gate-logs/acceptance-controls.json \
    >"$STDOUT_LOG" 2>"$LOG"
then
    cat "$LOG"
    if grep -q '"failed": 0' "$RECEIPT_SRC" \
        && grep -q '"evidence_kind": "EXECUTED_MODEL"' "$RECEIPT_SRC"; then
        cp "$RECEIPT_SRC" "$RECEIPT_DST"
        RECEIPT_SHA=$(sha256sum "$RECEIPT_DST" | cut -d' ' -f1)
        echo "receipt: evaluation/earned-trust-1.2.0/acceptance-controls/receipt.json sha256=$RECEIPT_SHA"
        echo "PASS etp-formal-acceptance-gate"
    else
        echo "FAIL etp-formal-acceptance-gate (receipt missing or reports failures)"
        exit 1
    fi
else
    status=$?
    tail -n 120 "$LOG" || true
    echo "FAIL etp-formal-acceptance-gate (exit $status)"
    exit "$status"
fi
