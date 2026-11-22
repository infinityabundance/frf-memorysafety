#!/bin/sh
# Inner Phase 11.2 execution witness. Runs inside the hardened container started
# by ci/etp-witness-gate.sh. Never executed on the host.
set -eu

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_DEBUG=0
export SOURCE_DATE_EPOCH=0
export RUSTUP_AUTO_INSTALL=0

# Install python3 if not present.
if ! command -v python3 >/dev/null 2>&1; then
    apt-get update >/dev/null
    apt-get install -y --no-install-recommends python3 >/dev/null
fi


rm -rf /tmp/witness_probe /tmp/toolchain.txt /tmp/build-recipe.txt

# Compile the probe with gcc -O0 -g -fno-inline.
gcc -O0 -g -fno-inline tests/fixtures/witness/probe.c -o /tmp/witness_probe

# Record toolchain identity and build recipe.
rustc -vV > /tmp/toolchain.txt
printf '%s\n' \
    'gcc -O0 -g -fno-inline tests/fixtures/witness/probe.c -o /tmp/witness_probe' \
    'CARGO_INCREMENTAL=0' \
    'CARGO_PROFILE_RELEASE_DEBUG=0' \
    'SOURCE_DATE_EPOCH=0' \
    'RUSTUP_AUTO_INSTALL=0' \
    > /tmp/build-recipe.txt

# Run the witness script and its self-test.
python3 /src/evaluation/earned-trust/witness_execution.py \
    --receipt /out/frf-etp.execution-witness.v1 \
    --root /src \
    --toolchain /tmp/toolchain.txt \
    --build-recipe /tmp/build-recipe.txt \
    --binary-out /tmp/witness_probe \
    --self-test

# Run the independent verifier if present; absent verifier is typed NOT_RUN.
if [ -f /src/evaluation/earned-trust/verify_witness.py ]; then
    python3 /src/evaluation/earned-trust/verify_witness.py \
        --receipt /out/frf-etp.execution-witness.v1 \
        --binary /tmp/witness_probe \
        --self-test
else
    echo "NOT_RUN: independent verifier absent"
fi

echo "witness gate: PASS"
