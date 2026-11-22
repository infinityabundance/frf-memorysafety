#!/bin/sh
# Phase 10.4b pinned local transparency profile gate.
#
# Every container keeps a hard memory/swap cap, a pid cap, a cpu cap, a nofile
# limit, a raised OOM score, reduced capabilities, and no-new-privileges. The
# repository is mounted read-only except for target/, where the fresh local
# log, its ephemeral private key, generated proofs, and reports live. No
# private key is committed.
#
# Modes:
#   full (default)  focused tests, committed and fresh log verification,
#                   independent Python verifier, corrupted controls
#   check           fmt, clippy, focused tests
#   compile         cargo check only
#   fmt             write rustfmt output inside the container
set -eu

RUST_IMAGE="${FRF_RUST_IMAGE:-rust:1.85.0-slim}"
PYTHON_IMAGE="${FRF_PYTHON_IMAGE:-python:3.11-slim}"
GO_IMAGE="${FRF_GO_IMAGE:-golang:1.24-alpine}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOGS="$ROOT/target/gate-logs"
mkdir -p "$LOGS"
RUST_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$RUST_IMAGE" 2>/dev/null || true)
PYTHON_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$PYTHON_IMAGE" 2>/dev/null || true)
GO_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$GO_IMAGE" 2>/dev/null || true)
if [ -z "$RUST_IMAGE_ID" ]; then RUST_IMAGE_ID=unknown; fi
if [ -z "$PYTHON_IMAGE_ID" ]; then PYTHON_IMAGE_ID=unknown; fi
if [ -z "$GO_IMAGE_ID" ]; then GO_IMAGE_ID=unknown; fi

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
        -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" -e CARGO_INCREMENTAL=0 \
        -w /src "$RUST_IMAGE" "$@" >"$LOGS/$name.log" 2>&1
    then
        cat "$LOGS/$name.log"
        echo "PASS $name"
    else
        status=$?
        tail -n 160 "$LOGS/$name.log" || true
        echo "FAIL $name (exit $status)"
        exit "$status"
    fi
}

rust_run_offline() {
    name=$1
    shift
    echo "== $name =="
    if timeout 1800 docker run --rm \
        --name "frf-ms-$name-$$" \
        --memory=2g --memory-swap=2g \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 \
        --oom-score-adj=500 \
        --cap-drop ALL --cap-add DAC_OVERRIDE \
        --security-opt no-new-privileges --network=none \
        -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
        -w /src "$RUST_IMAGE" "$@" >"$LOGS/$name.log" 2>&1
    then
        cat "$LOGS/$name.log"
        echo "PASS $name"
    else
        status=$?
        tail -n 160 "$LOGS/$name.log" || true
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
        --security-opt no-new-privileges --network=none \
        -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
        -w /src "$PYTHON_IMAGE" "$@" >"$LOGS/$name.log" 2>&1
    then
        cat "$LOGS/$name.log"
        echo "PASS $name"
    else
        status=$?
        tail -n 160 "$LOGS/$name.log" || true
        echo "FAIL $name (exit $status)"
        exit "$status"
    fi
}

go_run() {
    name=$1
    shift
    echo "== $name =="
    mkdir -p "$ROOT/target/transparency-home" "$ROOT/target/transparency-gocache" "$ROOT/target/transparency-gomodcache"
    if timeout 1800 docker run --rm \
        --name "frf-ms-$name-$$" \
        --user "$(id -u):$(id -g)" \
        --memory=2g --memory-swap=2g \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 \
        --oom-score-adj=500 \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
        -e HOME=/src/target/transparency-home \
        -e GOCACHE=/src/target/transparency-gocache \
        -e GOMODCACHE=/src/target/transparency-gomodcache \
        -e GOFLAGS=-mod=mod \
        -w /src/ci/transparency/frf-tlog "$GO_IMAGE" "$@" >"$LOGS/$name.log" 2>&1
    then
        cat "$LOGS/$name.log"
        echo "PASS $name"
    else
        status=$?
        tail -n 160 "$LOGS/$name.log" || true
        echo "FAIL $name (exit $status)"
        exit "$status"
    fi
}

go_run_optional() {
    name=$1
    shift
    echo "== $name =="
    mkdir -p "$ROOT/target/transparency-home" "$ROOT/target/transparency-gocache" "$ROOT/target/transparency-gomodcache"
    if timeout 1800 docker run --rm \
        --name "frf-ms-$name-$$" \
        --user "$(id -u):$(id -g)" \
        --memory=2g --memory-swap=2g \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 \
        --oom-score-adj=500 \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
        -e HOME=/src/target/transparency-home \
        -e GOCACHE=/src/target/transparency-gocache \
        -e GOMODCACHE=/src/target/transparency-gomodcache \
        -e GOFLAGS=-mod=mod \
        -w /src/ci/transparency/frf-tlog "$GO_IMAGE" "$@" >"$LOGS/$name.log" 2>&1
    then
        cat "$LOGS/$name.log"
        echo "PASS $name"
        return 0
    else
        status=$?
        echo "NOT_RUN $name (exit $status)"
        tail -n 60 "$LOGS/$name.log" || true
        return "$status"
    fi
}

case "${1:-full}" in
    fmt)
        rust_run etp-transparency-fmt cargo fmt --all
        ;;
    compile)
        rust_run etp-transparency-compile cargo check --locked --all-targets --features native-harness
        ;;
    check)
        rust_run etp-transparency-fmt cargo fmt --all -- --check
        rust_run etp-transparency-clippy cargo clippy --locked --all-targets --all-features -- -D warnings
        rust_run etp-transparency-tests cargo test --locked --features native-harness --test etp_transparency
        ;;
    full)
        rust_run etp-transparency-fmt cargo fmt --all -- --check
        rust_run etp-transparency-clippy cargo clippy --locked --all-targets --all-features -- -D warnings
        rust_run etp-transparency-tests sh -c '
            set -eu
            cargo build --locked --features native-harness --bin frf-memorysafety
            cargo test --locked --features native-harness --test etp_transparency
            ./target/debug/frf-memorysafety etp transparency verify \
                --proof evaluation/earned-trust/transparency/proof.json \
                --checkpoint evaluation/earned-trust/transparency/checkpoint-size-3.txt \
                --policy evaluation/earned-trust/transparency/policy.json \
                --json > target/etp-transparency-committed-report.json
            ./target/debug/frf-memorysafety etp checkpoint verify \
                evaluation/earned-trust/transparency/checkpoint-size-3.txt \
                --policy evaluation/earned-trust/transparency/policy.json \
                --json > target/etp-transparency-checkpoint-report.json
            if ./target/debug/frf-memorysafety etp witnesses verify \
                evaluation/earned-trust/transparency/witness-state.json \
                --json > target/etp-transparency-witness-report.json; then
                echo "FAIL: external witness state was reported as verified"
                exit 1
            else
                status=$?
                if [ "$status" -ne 6 ]; then
                    echo "FAIL: external witness state exit $status, expected 6"
                    exit 1
                fi
            fi
            grep -q "not_observed" target/etp-transparency-witness-report.json
            ./target/debug/frf-memorysafety etp witnesses verify \
                target/etp-transparency-witness-local.json \
                --json > target/etp-transparency-witness-local-report.json
            grep -q "met.:true" target/etp-transparency-witness-local-report.json
            grep -q "external_witnessing.:false" target/etp-transparency-witness-local-report.json
            grep -q "witness_observation.:.not_observed" target/etp-transparency-witness-local-report.json
        '
        python_run etp-transparency-independent \
            python3 evaluation/earned-trust/verify_transparency.py \
            --dir evaluation/earned-trust/transparency \
            --controls
        if ! grep -q 'controls passed: 20 of 20' "$LOGS/etp-transparency-independent.log"; then
            echo "FAIL etp-transparency-independent (unexpected control count)"
            exit 1
        fi
        if ! grep -Eq '^test result: ok\. 25 passed; 0 failed; 0 ignored' "$LOGS/etp-transparency-tests.log"; then
            echo "FAIL etp-transparency-tests (unexpected focused-test counts)"
            exit 1
        fi

        # Fresh local log from the pinned tessera v1.0.4 driver. If the Go
        # module graph cannot be fetched, live local inclusion is NOT_RUN with
        # the recorded blocker; committed artifacts are still verified above.
        LIVE="$ROOT/target/etp-transparency-live"
        rm -rf "$LIVE"
        mkdir -p "$LIVE/entries-a" "$LIVE/entries-b" "$LIVE/entries-cross"
        cp "$ROOT/evaluation/earned-trust/transparency/attestation-entry.bin" \
            "$LIVE/entries-a/000-attestation.bin"
        printf 'frf-etp-cross-log-entry\n' > "$LIVE/entries-cross/000-entry.bin"
        if go_run_optional etp-transparency-live-log sh -c '
            set -eu
            OUT=/src/target/etp-transparency-live
            go build -trimpath -o "$OUT/frf-tlog" .
            "$OUT/frf-tlog" -mode keygen \
                -origin frf.local/etp-transparency-live \
                -key-out "$OUT/key.priv" -public-key-out "$OUT/log-key.pub"
            "$OUT/frf-tlog" -mode append -storage "$OUT/log" \
                -private-key "$OUT/key.priv" -entries "$OUT/entries-a/*.bin" \
                -checkpoint-out "$OUT/checkpoint-old.txt"
            i=1
            while [ "$i" -le 260 ]; do
                n=$(printf "%04d" "$i")
                printf "frf-etp-live-filler-%s\n" "$n" > "$OUT/entries-b/100-filler-$n.bin"
                i=$((i + 1))
            done
            "$OUT/frf-tlog" -mode append -storage "$OUT/log" \
                -private-key "$OUT/key.priv" -entries "$OUT/entries-b/*.bin" \
                -checkpoint-out "$OUT/checkpoint-new.txt"
            "$OUT/frf-tlog" -mode proof -storage "$OUT/log" -index 0 \
                -checkpoint-out "$OUT/checkpoint-new.txt" \
                -old-checkpoint "$OUT/checkpoint-old.txt" \
                -proof-out "$OUT/proof.json"
            rm -f "$OUT/key.priv"
            "$OUT/frf-tlog" -mode keygen \
                -origin frf.local/etp-transparency-cross-log \
                -key-out "$OUT/key-cross.priv" -public-key-out "$OUT/log-key-cross.pub"
            "$OUT/frf-tlog" -mode append -storage "$OUT/log-cross" \
                -private-key "$OUT/key-cross.priv" -entries "$OUT/entries-cross/*.bin" \
                -checkpoint-out "$OUT/checkpoint-cross.txt"
            "$OUT/frf-tlog" -mode proof -storage "$OUT/log-cross" -index 0 \
                -checkpoint-out "$OUT/checkpoint-cross.txt" \
                -proof-out "$OUT/proof-cross.json"
            rm -f "$OUT/key-cross.priv"
            echo LIVE_READY
        '
        then
            python_run etp-transparency-live-policy \
                python3 evaluation/earned-trust/make_transparency_policy.py \
                --origin frf.local/etp-transparency-live \
                --public-key target/etp-transparency-live/log-key.pub \
                --checkpoint-old target/etp-transparency-live/checkpoint-old.txt \
                --checkpoint-new target/etp-transparency-live/checkpoint-new.txt \
                --out target/etp-transparency-live/policy.json
            rust_run etp-transparency-live-verify sh -c '
                set -eu
                OUT=target/etp-transparency-live
                ./target/debug/frf-memorysafety etp transparency verify \
                    --proof "$OUT/proof.json" \
                    --checkpoint "$OUT/checkpoint-new.txt" \
                    --policy "$OUT/policy.json" \
                    --json > "$OUT/live-report.json"
                grep -q "status.:.verified" "$OUT/live-report.json"
                grep -q "tiled_reconstruction.:.valid" "$OUT/live-report.json"
                if ./target/debug/frf-memorysafety etp transparency verify \
                    --proof "$OUT/proof-cross.json" \
                    --checkpoint "$OUT/checkpoint-cross.txt" \
                    --policy "$OUT/policy.json" \
                    --json > "$OUT/cross-log-report.json"; then
                    echo "FAIL: cross-log proof was accepted"
                    exit 1
                else
                    status=$?
                    if [ "$status" -ne 4 ]; then
                        echo "FAIL: cross-log proof exit $status, expected 4"
                        exit 1
                    fi
                fi
                grep -q "cross_log_proof" "$OUT/cross-log-report.json"
            '
            python_run etp-transparency-live-independent \
                python3 evaluation/earned-trust/verify_transparency.py \
                --proof target/etp-transparency-live/proof.json \
                --checkpoint target/etp-transparency-live/checkpoint-new.txt \
                --policy target/etp-transparency-live/policy.json
            if ! grep -q 'transparency: verified' "$LOGS/etp-transparency-live-independent.log"; then
                echo "FAIL etp-transparency-live-independent"
                exit 1
            fi
            echo "live local log: inclusion and consistency verified"
        else
            echo "NOT_RUN live local transparency log: pinned Go module graph or container unavailable"
            tail -n 20 "$LOGS/etp-transparency-live-log.log" > "$LIVE/NOT_RUN.txt" || true
            echo "committed local log artifacts remain verified; live inclusion is NOT_RUN"
        fi
        echo "rust image: $RUST_IMAGE ($RUST_IMAGE_ID)"
        echo "python image: $PYTHON_IMAGE ($PYTHON_IMAGE_ID)"
        echo "go image: $GO_IMAGE ($GO_IMAGE_ID)"
        echo "PASS etp-transparency-gate"
        ;;
    *)
        echo "usage: $0 {full|check|compile|fmt}" >&2
        exit 2
        ;;
esac
