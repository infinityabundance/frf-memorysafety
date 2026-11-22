#!/bin/sh
# Phase 10.3 authenticated-evidence gate.
#
# This gate runs the real DSSE/in-toto verification path in hardened containers.
# It builds the crate and executes the focused attestation tests, verifies the
# committed attestation with the Rust CLI, runs the independent OpenSSL-based
# Python verifier and its negative controls, and finally generates a fresh
# ephemeral test key inside the gate, signs the committed campaign closure,
# verifies the generated envelope with both implementations, and discards the
# private key.
#
# Every container keeps the declared memory/swap cap, pid cap, cpu cap, nofile
# limit, OOM adjustment, reduced capabilities, and no-new-privileges. The
# repository is mounted read-only except for target/, where the ephemeral key and
# generated artifacts live. No private key is committed.
set -eu

RUST_IMAGE="${FRF_RUST_IMAGE:-rust:1.85.0-slim}"
PYTHON_IMAGE="${FRF_PYTHON_IMAGE:-python:3.11-slim}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOGS="$ROOT/target/gate-logs"
mkdir -p "$LOGS"
RUST_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$RUST_IMAGE" 2>/dev/null || true)
if [ -z "$RUST_IMAGE_ID" ]; then RUST_IMAGE_ID=unknown; fi

rust_run() {
    name=$1
    shift
    echo "== $name =="
    if timeout 1800 docker run --rm \
        --name "frf-ms-$name-$$" \
        --memory=2g --memory-swap=2g \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 \
        --oom-score-adj=500 \
        --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
        --security-opt no-new-privileges \
        -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
        -v frf-cargo:/cargo -e CARGO_HOME=/cargo \
        -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" -e CARGO_INCREMENTAL=0 \
        -w /src "$RUST_IMAGE" "$@" >"$LOGS/$name.log" 2>&1
    then
        cat "$LOGS/$name.log"
        echo "PASS $name"
    else
        status=$?
        tail -n 120 "$LOGS/$name.log" || true
        echo "FAIL $name (exit $status)"
        exit "$status"
    fi
}

python_run() {
    name=$1
    shift
    echo "== $name =="
    if timeout 900 docker run --rm \
        --name "frf-ms-$name-$$" \
        --memory=512m --memory-swap=512m \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 \
        --oom-score-adj=500 \
        --cap-drop ALL --cap-add DAC_OVERRIDE \
        --security-opt no-new-privileges \
        --network=none \
        -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
        -w /src "$PYTHON_IMAGE" "$@" >"$LOGS/$name.log" 2>&1
    then
        cat "$LOGS/$name.log"
        echo "PASS $name"
    else
        status=$?
        tail -n 120 "$LOGS/$name.log" || true
        echo "FAIL $name (exit $status)"
        exit "$status"
    fi
}

rust_run etp-auth-tests sh -c '
    set -eu
    cargo build --locked --features native-harness --bin frf-memorysafety
    cargo test --locked --features native-harness --test etp_auth
    ./target/debug/frf-memorysafety etp campaign verify \
        evaluation/earned-trust/MANIFEST.json
    ./target/debug/frf-memorysafety etp sarif verify \
        evaluation/earned-trust/campaign.sarif
    ./target/debug/frf-memorysafety etp attest verify \
        evaluation/earned-trust/attestations/campaign-closure.envelope.json \
        --policy evaluation/earned-trust/trust-policy.json \
        --campaign evaluation/earned-trust/MANIFEST.json \
        --json > target/etp-attestation-committed-report.json
    ./target/debug/frf-memorysafety etp attest verify \
        evaluation/earned-trust/attestations/campaign-closure.envelope.json \
        --policy evaluation/earned-trust/trust-policy.json \
        --campaign evaluation/earned-trust/MANIFEST.json
'
if ! grep -Eq '^test result: ok\. 21 passed; 0 failed; 0 ignored' "$LOGS/etp-auth-tests.log"; then
    echo "FAIL etp-auth-tests (unexpected focused-test counts)"
    tail -n 40 "$LOGS/etp-auth-tests.log" || true
    exit 1
fi

python_run etp-auth-independent \
    python3 evaluation/earned-trust/verify_attestations.py \
    --attestations evaluation/earned-trust/attestations \
    --policy evaluation/earned-trust/trust-policy.json \
    --campaign evaluation/earned-trust/MANIFEST.json \
    --controls
if ! grep -q 'controls passed: 13' "$LOGS/etp-auth-independent.log"; then
    echo "FAIL etp-auth-independent (unexpected control count)"
    exit 1
fi

# Generate a fresh ephemeral key and attestation inside the gate. The private key
# is written only under target/ and is removed by the helper before it exits.
python_run etp-auth-ephemeral-generate \
    python3 evaluation/earned-trust/make_attestation.py \
    --campaign evaluation/earned-trust/MANIFEST.json \
    --out target/etp-attestation-run \
    --policy-out target/etp-attestation-run/trust-policy.json \
    --key-dir target/etp-attestation-key
if [ -e "$ROOT/target/etp-attestation-key" ]; then
    echo "FAIL etp-auth-ephemeral-generate (private key was not discarded)"
    exit 1
fi

rust_run etp-auth-ephemeral-verify-rust sh -c '
    set -eu
    ./target/debug/frf-memorysafety etp attest verify \
        target/etp-attestation-run/campaign-closure.envelope.json \
        --policy target/etp-attestation-run/trust-policy.json \
        --campaign evaluation/earned-trust/MANIFEST.json \
        --json > target/etp-attestation-ephemeral-report.json
    ./target/debug/frf-memorysafety etp attest verify \
        target/etp-attestation-run/campaign-closure.envelope.json \
        --policy target/etp-attestation-run/trust-policy.json \
        --campaign evaluation/earned-trust/MANIFEST.json
'

python_run etp-auth-ephemeral-verify-python \
    python3 evaluation/earned-trust/verify_attestations.py \
    --attestations target/etp-attestation-run \
    --policy target/etp-attestation-run/trust-policy.json \
    --campaign evaluation/earned-trust/MANIFEST.json \
    --envelope target/etp-attestation-run/campaign-closure.envelope.json \
    --statement target/etp-attestation-run/campaign-closure.statement.json

rm -rf "$ROOT/target/etp-attestation-key"
echo "PASS etp-auth-gate"
echo "rust image: $RUST_IMAGE ($RUST_IMAGE_ID)"
echo "python image: $PYTHON_IMAGE"
