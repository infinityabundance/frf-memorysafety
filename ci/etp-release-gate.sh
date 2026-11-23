#!/bin/sh
# Release gate: run the declared gate inventory in sequence.
#
# Every gate is a hardened container gate. This script never builds or tests on
# the host. It continues after a failure so the full matrix is recorded, prints
# one GATE line per entry, and exits nonzero if any gate failed.
#
# A gate result is not certification. A NOT_RUN is not a pass.
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOGS="$ROOT/target/release-gate"
mkdir -p "$LOGS"
SUMMARY="$LOGS/summary.txt"
: >"$SUMMARY"
fail=0

run() {
    name=$1
    script=$2
    echo "== release gate: $name =="
    if [ ! -f "$ROOT/$script" ]; then
        echo "GATE $name NOT_RUN (missing $script)" | tee -a "$SUMMARY"
        fail=1
        return
    fi
    timeout 5400 sh "$ROOT/$script" >"$LOGS/$name.log" 2>&1
    status=$?
    if [ "$status" -eq 0 ]; then
        echo "GATE $name PASS" | tee -a "$SUMMARY"
    elif [ "$status" -eq 124 ]; then
        echo "GATE $name FAIL (timeout)" | tee -a "$SUMMARY"
        tail -n 40 "$LOGS/$name.log" || true
        fail=1
    else
        echo "GATE $name FAIL (exit $status)" | tee -a "$SUMMARY"
        tail -n 40 "$LOGS/$name.log" || true
        fail=1
    fi
}

run base ci/gate.sh
run native ci/native-gate.sh
run mir ci/mir-gate.sh
run detector ci/detector-gate.sh
run proof ci/proof-gate.sh
run bridge ci/bridge-gate.sh
run conversion ci/conversion-gate.sh
run evaluation ci/eval-gate.sh
run reconstruction ci/reconstruction-gate.sh
run etp-campaign ci/etp-gate.sh
run etp-auth ci/etp-auth-gate.sh
run etp-time ci/etp-time-gate.sh
run etp-transparency ci/etp-transparency-gate.sh
run etp-integrity ci/etp-integrity-gate.sh
run etp-witness ci/etp-witness-gate.sh
run etp-information-flow ci/etp-information-flow-gate.sh
run etp-timing ci/etp-timing-gate.sh
run etp-cross-property ci/etp-cross-property-gate.sh
run etp-interop ci/etp-interop-gate.sh
run etp-tls-matrix ci/etp-tls-matrix-gate.sh
run etp-phase14 ci/etp-phase14-gate.sh
run etp-phase15 ci/etp-phase15-gate.sh
run etp-formal-acceptance ci/etp-formal-acceptance-gate.sh
run etp-comparative-development ci/etp-comparative-gate.sh
run etp-comparative-reconstruction ci/etp-comparative-reconstruction-gate.sh

echo
echo "== release gate summary =="
cat "$SUMMARY"
if [ "$fail" -ne 0 ]; then
    echo "FAIL etp-release-gate (at least one gate failed or was not run)"
    exit 1
fi
echo "PASS etp-release-gate"
