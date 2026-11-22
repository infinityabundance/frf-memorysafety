#!/bin/sh
# Inner Phase 12.2a timing profile. Runs inside the hardened container started
# by ci/etp-timing-gate.sh. Never executed on the host.
set -eu

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_DEBUG=0
export SOURCE_DATE_EPOCH=0
export RUSTUP_AUTO_INSTALL=0

# Install gcc, binutils, valgrind, and libc6-dev if not present.
if ! command -v gcc >/dev/null 2>&1; then
    apt-get update >/dev/null 2>&1
    apt-get install -y --no-install-recommends gcc binutils valgrind libc6-dev >/dev/null 2>&1
fi

# Verify tools are available.
echo "gcc: $(gcc --version | head -1)"
echo "ld: $(ld --version | head -1)"
echo "valgrind: $(valgrind --version)"
echo "callgrind_annotate: $(callgrind_annotate --version 2>&1 | head -1)"

# Run the timing profile script and its self-test.
python3 /src/evaluation/earned-trust/timing_profile.py \
    --root /src \
    --workdir /tmp/etp-timing-work \
    --report /out/report.json \
    --self-test

echo "timing gate inner: PASS"