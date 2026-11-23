#!/bin/sh
# Inner Phase 12.3a cross-property gate. Runs inside the hardened container started
# by ci/etp-cross-property-gate.sh. Never executed on the host.
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

# Run each mode explicitly so the committed evidence covers faulty and fixed.
for mode in faulty fixed; do
    python3 /src/evaluation/earned-trust/cross_property.py \
        --root /src \
        --workdir "/tmp/etp-cross-property-work" \
        --mode "$mode" \
        --report "/out/report-$mode.json"
done

# Run the controls (the self-test also exercises faulty, fixed, leak, and uninit modes internally).
python3 /src/evaluation/earned-trust/cross_property.py \
    --root /src \
    --workdir /tmp/etp-cross-property-self-test \
    --self-test

echo "cross-property gate inner: PASS"