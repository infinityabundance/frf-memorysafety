#!/bin/sh
# Live Phase 6.2 proof gate.
#
# This gate is deliberately separate from ci/gate.sh. The default gate installs
# no proof checker and executes every live test's typed `checker_unavailable`
# path. This gate uses the same hardened container flags, installs Debian Coq
# (plus jq for report parsing), records the exact coqc version, and runs every
# live seal case against the checked-in Coq fixtures.
set -eu

IMAGE="${IMAGE:-rust:1.85.0-slim}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOGS="$ROOT/target/gate-logs"
mkdir -p "$LOGS"

echo "== proof =="
if timeout 5400 docker run --rm \
    --name "frf-ms-proof-$$" \
    --memory=2g --memory-swap=2g \
    --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 \
    --oom-score-adj=500 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges \
    -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
    -v frf-cargo:/cargo -e CARGO_HOME=/cargo \
    -w /src \
    "$IMAGE" sh -c '
        set -eu
        export DEBIAN_FRONTEND=noninteractive
        echo "== install pinned Debian coq and jq =="
        apt-get -o APT::Sandbox::User=root update >/dev/null
        apt-get -o APT::Sandbox::User=root install -y --no-install-recommends \
            coq jq

        echo "== checker identity =="
        command -v coqc
        coqc --version
        coqc --version | sed -n "s/.*version \([^ ]*\).*/COQ_VERSION=\1/p"
        sha256sum "$(command -v coqc)"

        echo "== build =="
        cargo build --locked --bin frf-memorysafety

        echo "== capabilities =="
        ./target/debug/frf-memorysafety capabilities --json \
            >/src/target/gate-logs/proof-capabilities.json
        jq -c .checkers /src/target/gate-logs/proof-capabilities.json
        jq -e ".checkers | any(.id == \"coq\" and .status == \"available\")" \
            /src/target/gate-logs/proof-capabilities.json >/dev/null

        echo "== live seal cases =="
        failed=0
        check_case() {
            name=$1
            manifest=$2
            expected_exit=$3
            expected_outcome=$4
            out="/src/target/gate-logs/proof-$name.json"
            err="/src/target/gate-logs/proof-$name.err"
            set +e
            ./target/debug/frf-memorysafety proof verify "$manifest" --live --json \
                >"$out" 2>"$err"
            status=$?
            set -e
            actual=$(jq -r ".outcome" "$out" 2>/dev/null || true)
            if [ "$status" -eq "$expected_exit" ] && [ "$actual" = "$expected_outcome" ]; then
                echo "PASS $name (outcome=$actual exit=$status)"
            else
                echo "FAIL $name (expected outcome=$expected_outcome exit=$expected_exit; got outcome=${actual:-?} exit=$status)"
                cat "$err" || true
                cat "$out" || true
                failed=1
            fi
        }

        check_case approved /src/tests/proof/coq/manifest-approved.json 0 accepted_within_scope
        check_case admitted /src/tests/proof/coq/manifest-admitted.json 4 rejected_assumption
        check_case axiom /src/tests/proof/coq/manifest-axiom.json 4 rejected_assumption
        check_case unrelated /src/tests/proof/coq/manifest-unrelated.json 4 rejected_unrelated
        check_case unchecked /src/tests/proof/coq/manifest-unchecked.json 4 rejected_unchecked_implementation
        check_case missing_transition /src/tests/proof/coq/manifest-missing-transition.json 4 rejected_missing_transition

        if [ "$failed" -ne 0 ]; then
            echo "proof-gate: at least one live seal case failed"
            exit 1
        fi

        echo "== live seal tests =="
        FRF_PROOF_GATE=1 cargo test --locked --test proof_live -- --nocapture
        echo "proof-gate: complete"
    ' >"$LOGS/proof.log" 2>&1
then
    echo "PASS proof-gate"
    grep -E '^(PASS|FAIL|COQ_VERSION|test result:|proof-gate:|/usr/bin/coqc|\[|[0-9a-f]{64}  )' \
        "$LOGS/proof.log" || true
else
    status=$?
    tail -n 200 "$LOGS/proof.log" || true
    echo "FAIL proof-gate (exit $status)"
    exit "$status"
fi
