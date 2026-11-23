#!/bin/sh
# Inner Phase 13.1a interop matrix gate. Runs inside the hardened container started
# by ci/etp-interop-gate.sh. Never executed on the host.
set -eu

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_DEBUG=0
export SOURCE_DATE_EPOCH=0
export RUSTUP_AUTO_INSTALL=0

if ! command -v gcc >/dev/null 2>&1; then
    apt-get update >/dev/null 2>&1
    apt-get install -y --no-install-recommends gcc binutils libc6-dev >/dev/null 2>&1
fi

echo "gcc: $(gcc --version | head -1)"
echo "ld:  $(ld --version | head -1)"

# Run the interop matrix (four-way matrix for all pre-registered cases).
python3 /src/evaluation/earned-trust/interop_matrix.py \
    --root /src \
    --workdir /tmp/etp-interop-work \
    --report /out/report.json

# Run the controls (harness self-test).
python3 /src/evaluation/earned-trust/interop_matrix.py \
    --root /src \
    --workdir /tmp/etp-interop-self-test \
    --self-test

echo "interop-matrix inner: PASS"