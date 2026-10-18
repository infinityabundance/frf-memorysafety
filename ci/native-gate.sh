#!/bin/sh
# Run the live Phase 4.2 native fixture tests inside the pinned, hardened
# container. This gate is deliberately separate from ci/gate.sh: the default
# gate must pass in an image without a C toolchain, where the same tests assert
# the typed NOT_RUN path.
#
# The install requests only gcc and libc6-dev (their unavoidable package
# dependencies are resolved by apt). Network access is allowed for apt. The
# runtime limits are identical to ci/gate.sh and are not weakened.
set -eu

IMAGE="${IMAGE:-rust:1.85.0-slim}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOGS="$ROOT/target/gate-logs"
mkdir -p "$LOGS"

echo "== native =="
if timeout 2400 docker run --rm \
    --name "frf-ms-native-$$" \
    --memory=2g --memory-swap=2g \
    --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 \
    --oom-score-adj=500 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges \
    -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
    -v frf-cargo:/cargo -e CARGO_HOME=/cargo -w /src \
    "$IMAGE" sh -c '
        set -eu
        export DEBIAN_FRONTEND=noninteractive
        apt-get -o APT::Sandbox::User=root update
        apt-get -o APT::Sandbox::User=root install -y --no-install-recommends gcc libc6-dev
        FRF_NATIVE_HARNESS=1 cargo test --locked --features native-harness --test native -- --nocapture
    ' >"$LOGS/native.log" 2>&1
then
    echo "PASS native"
    grep -E '^test result:' "$LOGS/native.log" || true
else
    status=$?
    tail -n 60 "$LOGS/native.log" || true
    echo "FAIL native (exit $status)"
    exit "$status"
fi
