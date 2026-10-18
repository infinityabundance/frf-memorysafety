#!/bin/sh
# Live Phase 5.2 detector gate.
#
# This gate is deliberately separate from ci/gate.sh. The default gate installs
# no detector tooling and executes every live test's typed NOT_RUN path. This
# gate uses the same hardened container flags, installs only gcc, libc6-dev, and
# openssl, installs the pinned nightly miri/rust-src components, attempts a
# bounded Kani install, and then runs every built-in live mechanism. An
# unavailable mechanism is reported as NOT_RUN with its exact reason; a
# mechanism that runs but fails a control is a failure.
set -eu

IMAGE="${IMAGE:-rust:1.85.0-slim}"
TOOLCHAIN="${DETECTOR_TOOLCHAIN:-nightly-2025-02-20}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOGS="$ROOT/target/gate-logs"
mkdir -p "$LOGS"

echo "== detector =="
if timeout 5400 docker run --rm \
    --name "frf-ms-detector-$$" \
    --memory=2g --memory-swap=2g \
    --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 \
    --oom-score-adj=500 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges \
    -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
    -v frf-cargo:/cargo -e CARGO_HOME=/cargo \
    -v frf-rustup:/usr/local/rustup -e RUSTUP_HOME=/usr/local/rustup \
    -e KANI_HOME=/cargo/kani \
    -e KANI_CARGO_HOME=/usr/local/cargo \
    -e DETECTOR_TOOLCHAIN="$TOOLCHAIN" \
    -e PATH=/cargo/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin \
    -w /src \
    "$IMAGE" sh -c '
        set -eu
        export DEBIAN_FRONTEND=noninteractive
        echo "== install gcc libc6-dev openssl (curl only for the Kani attempt) =="
        apt-get -o APT::Sandbox::User=root update >/dev/null
        apt-get -o APT::Sandbox::User=root install -y --no-install-recommends \
            gcc libc6-dev openssl curl ca-certificates

        echo "== install stable and pinned nightly components =="
        env CARGO_HOME=/usr/local/cargo rustup toolchain install 1.85.0 \
            --profile minimal >/dev/null 2>&1 || true
        env CARGO_HOME=/usr/local/cargo rustup default 1.85.0 >/dev/null 2>&1 || true
        if timeout 1200 env CARGO_HOME=/usr/local/cargo rustup toolchain install \
            "$DETECTOR_TOOLCHAIN" --profile minimal --component miri,rust-src
        then
            :
        else
            echo "MIRI_INSTALL=warning rustup returned nonzero; probing the toolchain"
        fi
        if env CARGO_HOME=/usr/local/cargo rustup run "$DETECTOR_TOOLCHAIN" \
            rustc --version >/dev/null 2>&1
        then
            echo "MIRI_INSTALL=PASS"
        else
            echo "MIRI_INSTALL=NOT_RUN pinned toolchain did not pass its probe"
        fi

        echo "== attempt bounded Kani install (0.60.0 supports Rust 1.85) =="
        if timeout 900 cargo install --locked kani-verifier --version 0.60.0
        then
            if timeout 1200 env CARGO_HOME=/usr/local/cargo cargo kani setup
            then
                echo "KANI_INSTALL=PASS"
            else
                echo "KANI_INSTALL=NOT_RUN cargo kani setup failed or timed out"
            fi
        else
            echo "KANI_INSTALL=NOT_RUN cargo install kani-verifier failed or timed out"
        fi

        echo "== build =="
        cargo build --locked --bin frf-memorysafety

        echo "== live mechanisms =="
        failed=0
        for kind in miri asan lsan tsan loom kani crypto; do
            out="/src/target/gate-logs/live-$kind.json"
            err="/src/target/gate-logs/live-$kind.err"
            set +e
            FRF_DETECTOR_LIVE=1 ./target/debug/frf-memorysafety \
                detector calibrate --live --detector "$kind" --json \
                >"$out" 2>"$err"
            status=$?
            set -e
            case "$status" in
                0)
                    echo "PASS $kind"
                    grep -o "\"sensitivity\":{[^}]*}" "$out" || true
                    grep -o "\"specificity\":{[^}]*}" "$out" || true
                    grep -o "\"build_separation\":\"[A-Z]*\"" "$out" || true
                    grep -o "\"authenticity\":\"[A-Z]*\"" "$out" || true
                    ;;
                6)
                    reason=$(sed -n "s/.*\"reason\": *\"\([^\"]*\)\".*/\1/p" "$out")
                    if [ -n "$reason" ]; then
                        echo "NOT_RUN $kind: $reason"
                    else
                        echo "NOT_RUN $kind: $(cat "$err")"
                    fi
                    ;;
                *)
                    echo "FAIL $kind (exit $status)"
                    cat "$err" || true
                    cat "$out" || true
                    failed=1
                    ;;
            esac
        done
        if [ "$failed" -ne 0 ]; then
            echo "detector-gate: at least one available mechanism failed its control"
            exit 1
        fi

        echo "== live structural seal tests =="
        FRF_DETECTOR_LIVE=1 cargo test --locked --test detector_live -- --nocapture
        echo "detector-gate: complete"
    ' >"$LOGS/detector.log" 2>&1
then
    echo "PASS detector-gate"
    grep -E '^(PASS|NOT_RUN|MIRI_INSTALL|KANI_INSTALL|test result:|detector-gate:)' \
        "$LOGS/detector.log" || true
else
    status=$?
    tail -n 160 "$LOGS/detector.log" || true
    echo "FAIL detector-gate (exit $status)"
    exit "$status"
fi
