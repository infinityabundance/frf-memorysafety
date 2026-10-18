#!/bin/sh
# Run the optional pinned MIR adapter against a checked-in fixture crate.
#
# This gate is intentionally separate from ci/gate.sh. It uses the same
# hardened container and reports NOT_RUN (exit 6) when the pinned nightly
# toolchain cannot be installed or executed. A missing optional tool is not a
# failure of the default source/test gate.
set -eu

IMAGE="${IMAGE:-rust:1.85.0-slim}"
TOOLCHAIN="${MIR_TOOLCHAIN:-nightly-2025-02-20}"
RUSTUP_VOLUME="${RUSTUP_VOLUME:-frf-rustup}"
CARGO_VOLUME="${CARGO_VOLUME:-frf-cargo}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOGS="$ROOT/target/gate-logs"
mkdir -p "$LOGS"

run_gate() {
    name=$1
    shift
    timeout 1800 docker run --rm \
        --name "frf-mir-$name-$$" \
        --memory=2g --memory-swap=2g \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 \
        --oom-score-adj=500 \
        --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
        --security-opt no-new-privileges \
        -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
        -v "$CARGO_VOLUME":/cargo -e CARGO_HOME=/cargo \
        -v "$RUSTUP_VOLUME":/usr/local/rustup -e RUSTUP_HOME=/usr/local/rustup \
        -w /src \
        "$IMAGE" "$@"
}

if ! run_gate probe rustup run "$TOOLCHAIN" rustc --version \
    >"$LOGS/mir-probe.log" 2>&1
then
    echo "pinned toolchain $TOOLCHAIN is not installed; attempting minimal install"
    if ! run_gate install rustup toolchain install "$TOOLCHAIN" --profile minimal \
        >"$LOGS/mir-install.log" 2>&1
    then
        echo "NOT_RUN: cannot install $TOOLCHAIN inside the hardened container"
        tail -n 20 "$LOGS/mir-install.log" || true
        exit 6
    fi
    if ! run_gate probe rustup run "$TOOLCHAIN" rustc --version \
        >"$LOGS/mir-probe.log" 2>&1
    then
        echo "NOT_RUN: installed toolchain $TOOLCHAIN still cannot run"
        tail -n 20 "$LOGS/mir-probe.log" || true
        exit 6
    fi
fi

if ! run_gate build cargo build --locked --bin frf-memorysafety \
    >"$LOGS/mir-build.log" 2>&1
then
    echo "FAIL mir-gate: cargo build failed"
    tail -n 40 "$LOGS/mir-build.log" || true
    exit 1
fi

set +e
run_gate scan ./target/debug/frf-memorysafety \
    mir scan tests/fixtures/mir/source.rs --json \
    >"$LOGS/mir-scan.log" 2>"$LOGS/mir-scan.err"
scan_status=$?
set -e

if [ "$scan_status" -eq 0 ]; then
    if grep -q '"status":"LIVE"' "$LOGS/mir-scan.log"; then
        echo "PASS mir-gate (LIVE observations)"
        exit 0
    fi
    echo "FAIL mir-gate: adapter exited 0 without a LIVE observation"
    tail -n 20 "$LOGS/mir-scan.log" || true
    exit 1
fi

if [ "$scan_status" -eq 6 ]; then
    echo "NOT_RUN: pinned MIR adapter reported exit 6"
    cat "$LOGS/mir-scan.err" || true
    exit 6
fi

echo "FAIL mir-gate: adapter exited $scan_status"
tail -n 20 "$LOGS/mir-scan.err" || true
exit "$scan_status"
