#!/bin/sh
# Inner Phase 11.1b gate. Runs inside the hardened container started by
# ci/etp-integrity-gate.sh. Never executed on the host.
set -eu

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_DEBUG=0
export SOURCE_DATE_EPOCH=0
export RUSTUP_AUTO_INSTALL=0

rm -rf /tmp/frf-b1 /tmp/frf-b2
cargo build --locked --release --bin frf-memorysafety --target-dir /tmp/frf-b1
cargo build --locked --release --bin frf-memorysafety --target-dir /tmp/frf-b2

rustc -vV > /out/toolchain.txt
printf '%s\n' \
    'cargo build --locked --release --bin frf-memorysafety' \
    'CARGO_INCREMENTAL=0' \
    'CARGO_PROFILE_RELEASE_DEBUG=0' \
    'SOURCE_DATE_EPOCH=0' \
    'RUSTUP_AUTO_INSTALL=0' \
    > /out/build-recipe.txt

if ! command -v python3 >/dev/null 2>&1; then
    apt-get update >/dev/null
    apt-get install -y --no-install-recommends python3 >/dev/null
fi

python3 /src/evaluation/earned-trust-1.2.0/build_integrity_receipt.py \
    --root /src \
    --build1 /tmp/frf-b1/release/frf-memorysafety \
    --build2 /tmp/frf-b2/release/frf-memorysafety \
    --toolchain /out/toolchain.txt \
    --build-recipe /out/build-recipe.txt \
    --out /out/integrity-receipt.json

BIN=/tmp/frf-b1/release/frf-memorysafety
"$BIN" etp population /out/integrity-receipt.json --json > /out/population-report.json
"$BIN" etp reproducibility /out/integrity-receipt.json --json > /out/reproducibility-report.json
"$BIN" etp integrity verify /out/integrity-receipt.json --json > /out/integrity-report.json

python3 /src/evaluation/earned-trust-1.2.0/verify_reproducibility.py \
    --receipt /out/integrity-receipt.json \
    --root /src \
    --build1 /tmp/frf-b1/release/frf-memorysafety \
    --build2 /tmp/frf-b2/release/frf-memorysafety \
    --toolchain /out/toolchain.txt \
    --build-recipe /out/build-recipe.txt \
    --self-test

echo "integrity gate: PASS"
