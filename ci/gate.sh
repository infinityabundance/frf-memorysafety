#!/bin/sh
# Run every verification gate in a minimal, memory-capped Docker container.
#
# Host builds are forbidden. Each gate runs in rust:1.85.0-slim with a hard
# memory cap, a matching swap cap, a pid cap, a cpu cap, dropped capabilities,
# no-new-privileges, and a raised OOM score so the container is killed before
# the host is placed under memory pressure.
set -eu

IMAGE="${IMAGE:-rust:1.85.0-slim}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOGS="$ROOT/target/gate-logs"
mkdir -p "$LOGS"

run() {
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
        -v frf-cargo:/cargo -e CARGO_HOME=/cargo -w /src \
        "$IMAGE" "$@" >"$LOGS/$name.log" 2>&1
    then
        echo "PASS $name"
    else
        status=$?
        tail -n 40 "$LOGS/$name.log" || true
        echo "FAIL $name (exit $status)"
        exit "$status"
    fi
}

run fmt cargo fmt --all -- --check
run clippy cargo clippy --all-targets --all-features -- -D warnings
run test cargo test --locked --all-targets --features native-harness
run test-release cargo test --locked --release --features native-harness
