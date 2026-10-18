#!/bin/sh
# Phase 8.2 conversion gate: the real OpenSSL-Rust Safe-33 witness, repair,
# consumer workload, loader closure, and live evidence capture.
#
# Everything runs inside a minimal, hard-capped container. Nothing is built or
# executed on the host. The default cap is 4g, which was the first cap that
# completed the pinned candidate on the recorded host (134.7 GB RAM / 16 CPUs).
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOGS="$ROOT/target/phase8-gate"
EXTERNAL="$ROOT/target/external/openssl-rs"
IMAGE="${IMAGE:-openssl-rs-court:1}"
CRATE_IMAGE="${CRATE_IMAGE:-rust:1.85.0-slim}"
CAP="${CAP:-4g}"

PIN=56ba894594ed3df0fdf117a15747d205b4f0ecd9
FAULT=28c9e34487edf93eca314233d3c0b4a2aa061246
REPAIRED=1d9c3358bd19c5434e78def3d25ead2617d3a20e
AUTHORITY=openssl-3.6.4-production
CANDIDATE=/work/artifacts/phase2/install
AUTH_PREFIX="/work/forensics/authorities/prefix/$AUTHORITY"
CURL=/work/court/p82-curl/curl-8.22.0/src/curl
CAPTURE=/work/court/p82-capture

mkdir -p "$LOGS"

echo "== host =="
free -b | sed -n '1,2p'
echo "nproc=$(nproc)"
echo "cap=$CAP image=$IMAGE crate_image=$CRATE_IMAGE"

cleanup() {
    if [ -d "$EXTERNAL/.git" ]; then
        # The build containers run as root. Restore through a container so the
        # host user does not need permission to unlink root-owned outputs.
        docker run --rm \
            --memory="$CAP" --memory-swap="$CAP" \
            --pids-limit=512 --cpus=2 \
            --ulimit nofile=1024:1024 --oom-score-adj=500 \
            --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
            --security-opt no-new-privileges \
            -v "$EXTERNAL":/work -w /work "$IMAGE" \
            git checkout -- artifacts/phase2 forensics/atlas >/dev/null 2>&1 || true
        docker run --rm \
            --memory="$CAP" --memory-swap="$CAP" \
            --pids-limit=512 --cpus=2 \
            --ulimit nofile=1024:1024 --oom-score-adj=500 \
            --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
            --security-opt no-new-privileges \
            -v "$EXTERNAL":/work -w /work "$IMAGE" \
            git checkout --detach "$PIN" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

if [ ! -d "$EXTERNAL/.git" ]; then
    echo "NOT_RUN: $EXTERNAL is absent; clone the pinned candidate first."
    exit 6
fi
actual=$(git -C "$EXTERNAL" rev-parse HEAD)
if [ "$actual" != "$PIN" ]; then
    echo "FAIL: candidate pin is $actual, expected $PIN"
    exit 1
fi

target_run() {
    name=$1
    shift
    echo "== $name =="
    timeout 2400 docker run --rm \
        --name "frf-ms-p82-$name-$$" \
        --memory="$CAP" --memory-swap="$CAP" \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 --oom-score-adj=500 \
        --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
        --security-opt no-new-privileges \
        -v "$EXTERNAL":/work -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
        -v frf-cargo:/cargo -e CARGO_HOME=/cargo \
        -e CARGO_BUILD_JOBS=1 -e CARGO_INCREMENTAL=0 \
        -e RUSTFLAGS=-Cdebuginfo=0 \
        -e CARGO_PROFILE_TEST_DEBUG=0 -e CARGO_PROFILE_RELEASE_DEBUG=0 \
        -w /work "$IMAGE" "$@" >"$LOGS/$name.log" 2>&1
}

target_run_off() {
    name=$1
    shift
    echo "== $name =="
    timeout 2400 docker run --rm \
        --name "frf-ms-p82-$name-$$" \
        --memory="$CAP" --memory-swap="$CAP" \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 --oom-score-adj=500 \
        --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
        --security-opt no-new-privileges \
        -v "$EXTERNAL":/work -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
        -v frf-cargo:/cargo -e CARGO_HOME=/cargo \
        -e CARGO_BUILD_JOBS=1 -e CARGO_INCREMENTAL=0 \
        -e RUSTFLAGS='-Cdebuginfo=0 -Coverflow-checks=off' \
        -e CARGO_PROFILE_TEST_DEBUG=0 -e CARGO_PROFILE_RELEASE_DEBUG=0 \
        -w /work "$IMAGE" "$@" >"$LOGS/$name.log" 2>&1
}

crate_run() {
    name=$1
    shift
    echo "== $name =="
    timeout 2400 docker run --rm \
        --name "frf-ms-p82-$name-$$" \
        --memory="$CAP" --memory-swap="$CAP" \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 --oom-score-adj=500 \
        --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
        --security-opt no-new-privileges \
        -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
        -v "$EXTERNAL":/work:ro \
        -v frf-cargo:/cargo -e CARGO_HOME=/cargo \
        -w /src "$CRATE_IMAGE" "$@" >"$LOGS/$name.log" 2>&1
}

require_line() {
    file=$1
    pattern=$2
    if ! grep -q "$pattern" "$LOGS/$file.log"; then
        echo "FAIL: '$pattern' missing from $file"
        tail -n 50 "$LOGS/$file.log"
        exit 1
    fi
}

require_count() {
    file=$1
    pattern=$2
    expected=$3
    actual=$(grep -c "$pattern" "$LOGS/$file.log" || true)
    if [ "$actual" -ne "$expected" ]; then
        echo "FAIL: $file has $actual matches for '$pattern', expected $expected"
        tail -n 50 "$LOGS/$file.log"
        exit 1
    fi
}

# 1. Boundary tests at the pin.
target_run boundary-tests sh -c '
    cargo test --locked --lib runtime::refcount::tests -- --test-threads=1 --nocapture
    echo MARK_REENTRANCY
    cargo test --locked --lib refcount_reentrancy -- --test-threads=1 --nocapture
    echo MARK_ALIAS
    cargo test --locked --lib alias_ownership_tests -- --test-threads=1 --nocapture
    echo MARK_X509
    cargo test --locked --lib store_free_reentrancy_is_defined_noop -- --test-threads=1 --nocapture
    cargo test --locked --lib store_free_from_lookup_free_hook_is_defined_noop -- --test-threads=1 --nocapture
    cargo test --locked --lib store_refcount_is_atomic_under_concurrent_up_ref -- --test-threads=1 --nocapture
' || { tail -n 50 "$LOGS/boundary-tests.log"; exit 1; }
require_line boundary-tests "test result: ok. 9 passed; 0 failed; 0 ignored"
require_line boundary-tests "test result: ok. 3 passed; 0 failed; 0 ignored"
require_line boundary-tests "test result: ok. 7 passed; 0 failed; 0 ignored"
require_count boundary-tests "test result: ok. 1 passed; 0 failed; 0 ignored" 3

# 2. Fault and repaired witness for the counter-overflow boundary.
git -C "$EXTERNAL" checkout --quiet --detach "$FAULT"
git -C "$EXTERNAL" apply "$ROOT/ci/fixtures/phase8-overflow-test.patch"
if target_run fault-default cargo test --locked --lib up_ref_refuses_overflow_without_changing_count -- --test-threads=1 --nocapture; then
    echo "FAIL: the fault revision unexpectedly passed the overflow test"
    exit 1
fi
require_line fault-default "attempt to add with overflow"
require_line fault-default "0 passed; 1 failed"

git -C "$EXTERNAL" apply "$ROOT/ci/fixtures/phase8-overflow-observation.patch"
target_run_off fault-wrap cargo test --locked --lib up_ref_overflow_observation -- --test-threads=1 --nocapture \
    || { tail -n 50 "$LOGS/fault-wrap.log"; exit 1; }
require_line fault-wrap "FAULT_OBSERVATION answer=1 count=-2147483648"
require_line fault-wrap "test result: ok. 1 passed; 0 failed"

git -C "$EXTERNAL" checkout --quiet -- src/runtime/refcount.rs
git -C "$EXTERNAL" checkout --quiet --detach "$REPAIRED"
target_run repair-default cargo test --locked --lib up_ref_refuses_overflow_without_changing_count -- --test-threads=1 --nocapture \
    || { tail -n 50 "$LOGS/repair-default.log"; exit 1; }
require_line repair-default "test result: ok. 1 passed; 0 failed"
target_run_off repair-off cargo test --locked --lib up_ref_refuses_overflow_without_changing_count -- --test-threads=1 --nocapture \
    || { tail -n 50 "$LOGS/repair-off.log"; exit 1; }
require_line repair-off "test result: ok. 1 passed; 0 failed"
target_run repair-positive cargo test --locked --lib up_ref_preserves_positive_count_answer -- --test-threads=1 --nocapture \
    || { tail -n 50 "$LOGS/repair-positive.log"; exit 1; }
require_line repair-positive "test result: ok. 1 passed; 0 failed"
git -C "$EXTERNAL" checkout --quiet --detach "$PIN"

# 3. Authority prefix, candidate distribution DSOs, and the Phase 2 courts.
if [ ! -f "$EXTERNAL/forensics/authorities/prefix/$AUTHORITY/lib/libssl.so.3" ]; then
    target_run authority-build python3 forensics/tools/authority_build.py \
        --authority "$AUTHORITY" --jobs 2 \
        || { tail -n 50 "$LOGS/authority-build.log"; exit 1; }
fi
target_run phase2 bash forensics/tools/build_phase2.sh \
    || { tail -n 50 "$LOGS/phase2.log"; exit 1; }
require_line phase2 "all_pass=True"
require_line phase2 "ABI-LOAD.*pass"

# 4. Build unmodified curl against the candidate prefix.
target_run curl-build env CANDIDATE="$CANDIDATE" WORK=/work/court/p82-curl \
    INSTALL=/work/court/p82-curl/install \
    sh courts/phase17/downstream/curl/build.sh \
    || { tail -n 50 "$LOGS/curl-build.log"; exit 1; }
require_line curl-build "sha256 ok for curl-8.22.0.tar.gz"
require_line curl-build "libssl.so.3 => $CANDIDATE/lib/libssl.so.3"
require_line curl-build "libcrypto.so.3 => $CANDIDATE/lib/libcrypto.so.3"

# 5. Live positive/negative TLS 1.3 workload against the candidate prefix.
target_run curl-live env CANDIDATE="$CANDIDATE" AUTH="$AUTH_PREFIX" CURL="$CURL" \
    WORKDIR=/work/court/p82-curl-run PORT=4433 \
    sh /src/ci/fixtures/phase8-curl-workload.sh \
    || { tail -n 50 "$LOGS/curl-live.log"; exit 1; }
require_line curl-live "positive_ok=1"
require_line curl-live "negative_rejected=1"
require_line curl-live "http_code=200"
require_line curl-live "ssl_verify_result=0"
require_line curl-live "exit=60"
require_line curl-live "ssl_verify_result=20"
require_line curl-live "calling init: $CANDIDATE/lib/libssl.so.3"
require_line curl-live "calling init: $CANDIDATE/lib/libcrypto.so.3"

# 6. Capture the live evidence from exact files.
target_run capture python3 /src/ci/fixtures/phase8-capture.py \
    --external /work --candidate "$CANDIDATE" --authority "$AUTH_PREFIX" \
    --capture "$CAPTURE" \
    --fault-log /src/target/phase8-gate/fault-default.log \
    --wrap-log /src/target/phase8-gate/fault-wrap.log \
    --repair-log /src/target/phase8-gate/repair-default.log \
    --curl-log /src/target/phase8-gate/curl-live.log \
    --pin "$PIN" --fault "$FAULT" --repaired "$REPAIRED" \
    || { tail -n 50 "$LOGS/capture.log"; exit 1; }
require_line capture "CAPTURE_WRITTEN=1"
require_line capture "CAPTURE_RESOLVED=6499"
require_line capture "CAPTURE_UNRESOLVED=0"

# 7. Recompute and assert the DSO digests the capture recorded.
ssl_digest=$(sha256sum "$EXTERNAL/artifacts/phase2/install/lib/libssl.so.3" | cut -d' ' -f1)
crypto_digest=$(sha256sum "$EXTERNAL/artifacts/phase2/install/lib/libcrypto.so.3" | cut -d' ' -f1)
require_line capture "CAPTURE_DSO_libssl_so_3=$ssl_digest"
require_line capture "CAPTURE_DSO_libcrypto_so_3=$crypto_digest"

# 8. Capture through the crate's typed live model and report reuse/revocation.
crate_run live-capture env FRF_CONVERSION_CAPTURE="$CAPTURE" FRF_CONVERSION_REQUIRE_LIVE=1 \
    cargo test --locked --test conversion -- --nocapture \
    || { tail -n 80 "$LOGS/live-capture.log"; exit 1; }
require_line live-capture "LIVE_CAPTURE=captured"
require_line live-capture "LIVE_REUSE_REPORT reusable=1 property=1 candidate=1 boundary=1 dependency=1"
require_line live-capture "test result: ok. 27 passed; 0 failed; 0 ignored"

echo "== conversion gate summary =="
grep -E --exclude='run*.log' "9 passed; 0 failed; 0 ignored|3 passed; 0 failed; 0 ignored|7 passed; 0 failed; 0 ignored|1 passed; 0 failed; 0 ignored|attempt to add with overflow|FAULT_OBSERVATION|positive_ok=1|negative_rejected=1|CAPTURE_RESOLVED|CAPTURE_UNRESOLVED|CAPTURE_DSO_|LIVE_CAPTURE=captured|LIVE_REUSE_REPORT" "$LOGS"/*.log || true
echo "PASS conversion"
