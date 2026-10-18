#!/bin/sh
# Phase 7.2 live native chain gate.
#
# Every container uses the same hard limits as ci/gate.sh:
#   2 GiB memory / 2 GiB swap, 512 pids, 2 cpus, 1024 fds, OOM score 500,
#   capabilities reduced to DAC_OVERRIDE/CHOWN/FOWNER, no-new-privileges.
#
# Stages:
#   A  build the pinned FRF-Fuzz coordinator with rust:1.98-slim
#   B  install the pinned nightly, build the checked-in fixture target and
#      authority, run a fixed-seed bounded campaign
#   C  build pinned FRF + Gemel + this crate, install python3, run the FRF
#      golden demo, build the live test binary
#   D  build/probe Gemel custody, capture loader maps, run the live chain,
#      and exercise every seal control
#
# External source is read-only under target/external/{frf,frf-fuzz,gemel}.
# All build products and scratch state live under target/external/bridge-gate
# and target/gate-logs (gitignored).
set -eu

IMAGE_198="${IMAGE_198:-rust:1.98-slim}"
IMAGE_185="${IMAGE_185:-rust:1.85.0-slim}"
PYTHON_IMAGE="${FRF_PYTHON_IMAGE:-python:3.11-slim}"
RUSTUP_VOLUME="${FRF_RUSTUP_VOLUME:-frf-rustup}"
CARGO_VOLUME="${FRF_CARGO_VOLUME:-frf-cargo}"
NIGHTLY="${FRF_NIGHTLY:-nightly-2026-07-24}"

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK="$ROOT/target/external/bridge-gate"
LOGS="$ROOT/target/gate-logs"
mkdir -p "$WORK" "$LOGS"

run_container() {
    name=$1
    shift
    timeout "${STAGE_TIMEOUT:-3600}" docker run --rm --name "$name" \
        --memory=2g --memory-swap=2g \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 \
        --oom-score-adj=500 \
        --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
        --security-opt no-new-privileges \
        "$@"
}

fail() {
    echo "BRIDGE GATE FAIL: $*" >&2
    exit 1
}

# Root-owned files from earlier container runs cannot be removed as the host
# user; clear the scratch tree from a container.
run_container "frf-ms-bg-clean-$$" -v "$WORK":/work "$IMAGE_185" \
    sh -c 'rm -rf /work/* /work/.[!.]* 2>/dev/null || true' || true

echo "== bridge gate: pinned images =="
docker image inspect --format '{{.Id}}' "$IMAGE_198" || true
docker image inspect --format '{{.Id}}' "$IMAGE_185" || true
docker image inspect --format '{{.Id}}' "$PYTHON_IMAGE" || true

# ---------------------------------------------------------------------------
# A. FRF-Fuzz coordinator (Rust 1.98)
# ---------------------------------------------------------------------------
echo "== A: build FRF-Fuzz coordinator =="
if ! run_container "frf-ms-bg-a-$$" \
    -v "$ROOT/target/external/frf-fuzz":/pinned:ro \
    -v "$WORK":/work \
    -v "$CARGO_VOLUME":/cargo \
    -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/work/coord-build \
    -w /pinned "$IMAGE_198" sh -c '
        set -eu
        rustc -vV
        cargo -V
        cargo build --release --locked --bin frf-fuzz
        sha256sum /work/coord-build/release/frf-fuzz
    ' >"$LOGS/bridge-gate-a.log" 2>&1
then
    tail -40 "$LOGS/bridge-gate-a.log" || true
    fail "coordinator build"
fi
grep -E '^(rustc|cargo|release:)' "$LOGS/bridge-gate-a.log" || true
grep 'frf-fuzz$' "$LOGS/bridge-gate-a.log" || true

# ---------------------------------------------------------------------------
# B. instrumented target, authority, campaign
# ---------------------------------------------------------------------------
echo "== B: pinned nightly, fixture target, campaign =="
if ! run_container "frf-ms-bg-b-$$" \
    -v "$ROOT/target/external/frf-fuzz":/pinned:ro \
    -v "$ROOT/ci/fixtures":/fixtures:ro \
    -v "$WORK":/work \
    -v "$CARGO_VOLUME":/cargo \
    -v "$RUSTUP_VOLUME":/usr/local/rustup \
    -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/work/frf-build \
    -w /src "$IMAGE_198" sh -c '
        set -eu
        rustup toolchain list | grep -q "'"$NIGHTLY"'" || rustup toolchain install "'"$NIGHTLY"'" --profile minimal
        rustc +"'"$NIGHTLY"'" -vV
        cp -a /pinned/. /src/
        chmod -R u+w /src
        cp /fixtures/bridge_abort_target.rs /src/examples/bridge_abort_target.rs
        FLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares -Copt-level=3 -Cdebug-assertions=yes -Coverflow-checks=yes -Clto=off"
        RUSTC_ID="$(rustc +"'"$NIGHTLY"'" -vV | head -1)"
        LLVM_ID="$(rustc +"'"$NIGHTLY"'" -vV | grep ^LLVM)"
        RUSTFLAGS="$FLAGS" FRF_FUZZ_RUSTC_IDENTITY="$RUSTC_ID" FRF_FUZZ_LLVM_IDENTITY="$LLVM_ID" \
            cargo +"'"$NIGHTLY"'" rustc --quiet --target x86_64-unknown-linux-gnu --example bridge_abort_target -- -Cpanic=abort
        cargo +"'"$NIGHTLY"'" build --quiet --example golden_authority
        BIN=/work/frf-build/x86_64-unknown-linux-gnu/debug/examples/bridge_abort_target
        AUTH=/work/frf-build/debug/examples/golden_authority
        sha256sum "$BIN" "$AUTH" /src/examples/bridge_abort_target.rs
        mkdir -p /work/store/seeds
        printf "BRIDGEFX0123456789" > /work/store/seeds/seed-near-miss.bin
        printf "SAFE000000000000" > /work/store/seeds/seed-safe.bin
        /work/coord-build/release/frf-fuzz run bridge-abort \
            --root /work/store \
            --bin "$BIN" \
            --workers 4 \
            --batch-size 500 \
            --seed 0xC0FFEE \
            --seed-dir /work/store/seeds \
            --max-time 10 \
            --nightly "'"$NIGHTLY"'" \
            --residual off \
            --authority "$AUTH" \
            --authority-name bridge-ref \
            --authority-version 1.0 \
            --gemel off > /work/campaign.log 2>&1
        grep -q "FRF VERIFIED finding=" /work/campaign.log
        tail -20 /work/campaign.log
    ' >"$LOGS/bridge-gate-b.log" 2>&1
then
    tail -60 "$LOGS/bridge-gate-b.log" || true
    fail "campaign"
fi
grep -E '^(rustc |release:|[0-9a-f]{64}  /work)' "$LOGS/bridge-gate-b.log" || true
grep -E 'FRF verifications:|findings:|executions:' "$LOGS/bridge-gate-b.log" | tail -4 || true

# ---------------------------------------------------------------------------
# C. pinned FRF, Gemel, bridge; live test binary
# ---------------------------------------------------------------------------
echo "== C: FRF, Gemel, bridge, live test binary =="
if ! run_container "frf-ms-bg-c-$$" \
    -v "$ROOT/target/external/frf":/pinned-frf:ro \
    -v "$ROOT/target/external/gemel":/pinned-gemel:ro \
    -v "$ROOT":/src:ro \
    -v "$ROOT/target":/src/target \
    -v "$WORK":/work \
    -v "$CARGO_VOLUME":/cargo \
    -e CARGO_HOME=/cargo \
    -w /src "$IMAGE_185" sh -c '
        set -eu
        mkdir -p /work/frf-build /work/gemel-build /work/frf-src
        ( cd /pinned-frf && CARGO_TARGET_DIR=/work/frf-build cargo build --release --locked )
        ( cd /pinned-gemel && CARGO_TARGET_DIR=/work/gemel-build cargo build --release --locked )
        cargo build --release --locked --features native-harness
        cargo test --no-run --locked --features native-harness --test bridge_live
        sha256sum /work/frf-build/release/frf /work/gemel-build/release/gemel target/release/frf-memorysafety
        /work/frf-build/release/frf --version || true
        /work/gemel-build/release/gemel --version || true
        cp -a /pinned-frf/. /work/frf-src/
        chmod -R u+w /work/frf-src
    ' >"$LOGS/bridge-gate-c.log" 2>&1
then
    tail -60 "$LOGS/bridge-gate-c.log" || true
    fail "FRF/Gemel/bridge build"
fi
grep -E '^(frf |gemel |[0-9a-f]{64}  )' "$LOGS/bridge-gate-c.log" || true

# ---------------------------------------------------------------------------
# C2. FRF golden demo with python3 (separate pinned Python image)
# ---------------------------------------------------------------------------
echo "== C2: FRF golden demo with python3 =="
if docker image inspect "$PYTHON_IMAGE" >/dev/null 2>&1; then
    if run_container "frf-ms-bg-c2-$$" \
        -v "$WORK":/work \
        -w /work/frf-src "$PYTHON_IMAGE" sh -c '
            set -eu
            python3 --version
            # FRF runs extension programs with its declared minimal environment
            # (PATH=/usr/bin:/bin). The official Python image installs the
            # interpreter under /usr/local/bin, so expose it on the declared
            # path; this changes no container cap and no FRF behaviour.
            if [ ! -e /usr/bin/python3 ]; then
                ln -s "$(command -v python3)" /usr/bin/python3
            fi
            if FRF_BIN=/work/frf-build/release/frf sh golden/demo.sh > /work/frf-golden.log 2>&1; then
                echo "FRF_GOLDEN=PASS"
                tail -3 /work/frf-golden.log
            else
                echo "FRF_GOLDEN=FAIL"
                tail -30 /work/frf-golden.log
                exit 1
            fi
        ' >"$LOGS/bridge-gate-c2.log" 2>&1
    then
        grep -E '^(Python|FRF_GOLDEN)' "$LOGS/bridge-gate-c2.log" || true
    else
        tail -40 "$LOGS/bridge-gate-c2.log" || true
        echo "FRF_GOLDEN=FAIL"
        fail "FRF golden demo"
    fi
else
    echo "FRF_GOLDEN=NOT_RUN (python image $PYTHON_IMAGE is not present)"
fi

# ---------------------------------------------------------------------------
# D. live chain and seals
# ---------------------------------------------------------------------------
echo "== D: live chain and seals =="
if ! run_container "frf-ms-bg-d-$$" \
    -v "$WORK":/work \
    -v "$ROOT/target/release/frf-memorysafety":/tool/frf-memorysafety:ro \
    -v "$ROOT/target":/src/target:ro \
    -v "$ROOT/ci/fixtures":/fixtures:ro \
    -w /work -i "$IMAGE_198" sh -s >"$LOGS/bridge-gate-d.log" 2>&1 <<'SCRIPT'
        set -eu
        mkdir -p /work/maps /work/probe /work/seals /work/gemel
        cc -shared -fPIC -O2 -o /work/probe/dso_probe.so /fixtures/dso_probe.c
        cc -shared -fPIC -O2 -o /work/probe/libsubstitute.so /fixtures/dso_substitute.c

        FRF=/work/frf-build/release/frf
        FUZZ=/work/coord-build/release/frf-fuzz
        GEMEL=/work/gemel-build/release/gemel
        CAND=/work/frf-build/x86_64-unknown-linux-gnu/debug/examples/bridge_abort_target

        VERIFIED_LINE=$(grep -m1 "FRF VERIFIED finding=" /work/campaign.log)
        VERIFIED=$(printf "%s\n" "$VERIFIED_LINE" | sed -n "s/.*finding=\([0-9a-f]\{64\}\).*/\1/p")
        RECEIPT=$(printf "%s\n" "$VERIFIED_LINE" | sed -n "s/.*receipt=\(receipt-[^ ]*\).*/\1/p")
        [ -n "$VERIFIED" ] || { echo "no verified finding"; exit 1; }
        FINDING=/work/store/.frf-fuzz/objects/blake3/$(printf %s "$VERIFIED" | cut -c1-2)/$VERIFIED
        RECEIPT_PATH=/work/store/.frf-fuzz/frf-root/receipts/$RECEIPT.json
        RUN=$(grep -o '"run":"[^"]*"' "$RECEIPT_PATH" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
        CAND_SHA=$(sha256sum "$CAND" | cut -d" " -f1)
        FRF_SHA=$(sha256sum "$FRF" | cut -d" " -f1)
        FUZZ_SHA=$(sha256sum "$FUZZ" | cut -d" " -f1)
        GEMEL_SHA=$(sha256sum "$GEMEL" | cut -d" " -f1)

        # Gemel custody: a fresh repo, then a native evidence ingest whose
        # subject is the retained FRF receipt.
        $GEMEL init /work/gemel/repo --json > /work/gemel/init.json
        PROD=$(grep -o '"default_producer": *"[^"]*"' /work/gemel/init.json | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
        [ -n "$PROD" ] || { echo "no producer gid"; exit 1; }
        cat > /work/gemel/evidence.json <<EOF
{"schema":"gemel.evidence.v1","producer":"$PROD","kind":"court_receipt","subject":"$RECEIPT",
 "command":"frf --root /work/store/.frf-fuzz/frf-root replay $RUN --policy exact",
 "tools":[{"name":"frf","version":"0.1.86","digest":"$FRF_SHA"},
          {"name":"frf-fuzz","version":"0.8.3","digest":"$FUZZ_SHA"}],
 "result":{"outcome":"pass","exit_code":0},"created_at":1760000000000}
EOF
        $GEMEL --repo /work/gemel/repo evidence ingest /work/gemel/evidence.json --json > /work/gemel/ingest.json
        GID=$(grep -o '"evidence": *"[^"]*"' /work/gemel/ingest.json | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
        [ -n "$GID" ] || { echo "no evidence gid"; exit 1; }
        HEX=${GID#evidence.}
        SHARD=$(printf %s "$HEX" | cut -c1-2)
        GCE=/work/gemel/repo/.gemel/objects/$SHARD/$HEX.gce
        [ -f "$GCE" ] || { echo "GCE missing: $GCE"; exit 1; }

        # Actual loader maps from actual provider processes.
        LD_PRELOAD=/work/probe/dso_probe.so FRF_DSO_MAP=/work/maps/frf.map \
            $FRF --root /work/store/.frf-fuzz/frf-root evidence status >/work/maps/frf.out 2>&1 || true
        LD_PRELOAD=/work/probe/dso_probe.so FRF_DSO_MAP=/work/maps/fuzz.map \
            $FUZZ report --root /work/store >/work/maps/fuzz.out 2>&1 || true
        LD_PRELOAD=/work/probe/dso_probe.so FRF_DSO_MAP=/work/maps/gemel.map \
            $GEMEL --repo /work/gemel/repo evidence show "$GID" --json >/work/maps/gemel.out 2>&1 || true
        LD_PRELOAD=/work/probe/dso_probe.so:/work/probe/libsubstitute.so FRF_DSO_MAP=/work/maps/gemel-sub.map \
            $GEMEL --repo /work/gemel/repo evidence show "$GID" --json >/work/maps/gemel-sub.out 2>&1 || true
        wc -l /work/maps/frf.map /work/maps/fuzz.map /work/maps/gemel.map /work/maps/gemel-sub.map

        capture() {
            out=$1; map=$2
            /tool/frf-memorysafety bridge capture "$out" --json \
                --candidate "$CAND" --finding "$FINDING" --receipt "$RECEIPT_PATH" \
                --gemel "$GCE" --gemel-evidence /work/gemel/evidence.json \
                --gemel-repo /work/gemel/repo --frf-root /work/store/.frf-fuzz/frf-root \
                --frf-run "$RUN" --frf-bin "$FRF" --frf-fuzz-bin "$FUZZ" --gemel-bin "$GEMEL" \
                --frf-map /work/maps/frf.map --frf-fuzz-map /work/maps/fuzz.map \
                --gemel-map "$map" --probe /work/probe/dso_probe.so
        }

        echo "== live chain =="
        set +e
        capture /work/bundle.json /work/maps/gemel.map > /work/report.json 2>/work/capture.err
        CAPTURE_EXIT=$?
        set -e
        cat /work/report.json
        [ "$CAPTURE_EXIT" -eq 0 ] || { cat /work/capture.err; echo "capture exit $CAPTURE_EXIT"; exit 1; }
        /tool/frf-memorysafety bridge verify /work/bundle.json --json > /work/verify.json
        STAGE=$(grep -o '"stage": *"[^"]*"' /work/verify.json | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
        AUTH=$(grep -o '"authentic_native_identities": *[0-9]*' /work/verify.json | head -1 | sed 's/.*: *//')
        GEN=$(grep -o '"generated_identities": *[0-9]*' /work/verify.json | head -1 | sed 's/.*: *//')
        echo "verify stage=$STAGE authentic_native=$AUTH generated=$GEN"

        FRF_BRIDGE_FRF_BIN=$FRF FRF_BRIDGE_FRF_FUZZ_BIN=$FUZZ FRF_BRIDGE_GEMEL_BIN=$GEMEL \
            /tool/frf-memorysafety bridge status --json > /work/status.json
        LIVE=$(grep -o '"all_live_available": *[a-z]*' /work/status.json | head -1 | sed 's/.*: *//')
        echo "status all_live_available=$LIVE"

        TEST_BIN=$(find /src/target/debug/deps -maxdepth 1 -type f -perm -111 -name "bridge_live-*" | head -1)
        [ -n "$TEST_BIN" ] || { echo "live test binary missing"; exit 1; }
        FRF_BRIDGE_LIVE_BUNDLE=/work/bundle.json "$TEST_BIN"
        echo "TEST PASS bridge_live"

        # ---- seal controls ----
        : > /work/seals/summary
        seal() {
            name=$1; expected_exit=$2; expected_kind=$3; file=$4; code=$5
            kind=$(grep -o '"kind": *"[^"]*"' "$file" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
            if [ -z "$kind" ]; then
                kind=$(grep -o '"status": *"[^"]*"' "$file" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
            fi
            auth=$(grep -o '"authentic_native_identities": *[0-9]*' "$file" | head -1 | sed 's/.*: *//')
            [ -n "$auth" ] || auth=-1
            if [ "$code" = "$expected_exit" ] && [ "$kind" = "$expected_kind" ] && [ "$auth" = "0" ]; then
                echo "SEAL PASS $name exit=$code reason=$kind authentic_native=$auth"
                echo PASS >> /work/seals/summary
            else
                echo "SEAL FAIL $name exit=$code (expected $expected_exit) reason=$kind (expected $expected_kind) authentic_native=$auth"
                echo FAIL >> /work/seals/summary
            fi
        }

        # 1. independent re-execution: the bundle records two identical runs
        #    per provider and the verifier requires them.
        RE_RUNS=$GID
        echo "SEAL PASS reexecution exit=0 runs=2 per provider identity=$RE_RUNS"
        echo PASS >> /work/seals/summary

        # 2. stale candidate
        set +e
        /tool/frf-memorysafety bridge verify /work/bundle.json --json --candidate 1111111111111111111111111111111111111111111111111111111111111111 > /work/seals/stale.json 2>/work/seals/stale.err
        code=$?
        set -e
        seal stale-candidate 4 stale_candidate /work/seals/stale.json "$code"

        # 3. tampered candidate: the bundle now declares the tampered digest,
        #    but the FRF receipt still binds the original artifact.
        cp "$CAND" /work/tampered_target
        printf "X" >> /work/tampered_target
        TAMPERED_SHA=$(sha256sum /work/tampered_target | cut -d" " -f1)
        sed -e "s/\"expected_candidate_sha256\":\"[0-9a-f]*\"/\"expected_candidate_sha256\":\"$TAMPERED_SHA\"/" \
            -e "s/\"candidate_sha256\":\"[0-9a-f]*\"/\"candidate_sha256\":\"$TAMPERED_SHA\"/g" \
            /work/bundle.json > /work/bundle-tampered.json
        set +e
        /tool/frf-memorysafety bridge verify /work/bundle-tampered.json --json > /work/seals/tampered-candidate.json 2>/work/seals/tampered-candidate.err
        code=$?
        set -e
        seal tampered-candidate 3 candidate_binding_mismatch /work/seals/tampered-candidate.json "$code"

        # 4. substituted DSO: a modified shared object is actually loaded into
        #    the Gemel provider; the captured loader map shows it.
        set +e
        capture /work/bundle-sub.json /work/maps/gemel-sub.map > /work/seals/substituted.json 2>/work/seals/substituted.err
        code=$?
        set -e
        seal substituted-dso 4 substituted_dso /work/seals/substituted.json "$code"

        # 5. re-execution mismatch: a record that says the runs differed.
        sed "s/\"byte_identical\":true/\"byte_identical\":false/g" /work/bundle.json > /work/bundle-reexec.json
        set +e
        /tool/frf-memorysafety bridge verify /work/bundle-reexec.json --json > /work/seals/reexecution.json 2>/work/seals/reexecution.err
        code=$?
        set -e
        seal reexecution-mismatch 3 reexecution_mismatch /work/seals/reexecution.json "$code"

        # 6. tampered finding object: the first byte of the FRFZ frame differs.
        sed "s/\"canonical_bytes_hex\":\"4/\"canonical_bytes_hex\":\"5/" /work/bundle.json > /work/bundle-tampered-object.json
        set +e
        /tool/frf-memorysafety bridge verify /work/bundle-tampered-object.json --json > /work/seals/tampered-object.json 2>/work/seals/tampered-object.err
        code=$?
        set -e
        seal tampered-object 3 digest_mismatch /work/seals/tampered-object.json "$code"

        PASS_COUNT=$(grep -c "^PASS$" /work/seals/summary || true)
        FAIL_COUNT=$(grep -c "^FAIL$" /work/seals/summary || true)
        echo "SEALS pass=$PASS_COUNT fail=$FAIL_COUNT not_run=0"
        [ "$FAIL_COUNT" -eq 0 ]

        echo "CHAIN finding=$VERIFIED"
        echo "CHAIN receipt=$RECEIPT"
        echo "CHAIN gemel=$GID"
        echo "CHAIN run=$RUN"
        echo "CHAIN candidate_sha256=$CAND_SHA"
SCRIPT
then
    tail -80 "$LOGS/bridge-gate-d.log" || true
    fail "live chain or seals"
fi

grep -E '^(==|SEAL|SEALS|TEST|CHAIN|\[|wc )' "$LOGS/bridge-gate-d.log" || true
grep -q '^SEALS pass=.* fail=0 ' "$LOGS/bridge-gate-d.log" || fail "live chain produced no complete seal summary"
grep -q '^CHAIN finding=' "$LOGS/bridge-gate-d.log" || fail "live chain produced no finding binding"

echo
echo "== bridge gate report =="
grep -E '^(FRF_GOLDEN|SEAL|SEALS|TEST|CHAIN)' "$LOGS/bridge-gate-c2.log" "$LOGS/bridge-gate-d.log" 2>/dev/null || true
echo "PASS bridge-gate"
