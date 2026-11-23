#!/bin/sh
# Inner Phase 13.2 TLS matrix gate. Runs inside the hardened container started
# by ci/etp-tls-matrix-gate.sh. Never executed on the host.
set -eu

export SOURCE_DATE_EPOCH=0

if ! command -v gcc >/dev/null 2>&1; then
    apt-get update >/dev/null 2>&1
    apt-get install -y --no-install-recommends gcc binutils libc6-dev openssl >/dev/null 2>&1
fi

echo "gcc: $(gcc --version | head -1)"
echo "ld:  $(ld --version | head -1)"
echo "python: $(python3 --version)"

# Run the TLS matrix (four-way matrix for tls13_echo and wrong_ca).
python3 /src/evaluation/earned-trust/tls_matrix.py \
    --root /src \
    --workdir /tmp/etp-tls-matrix-work \
    --report /out/report.json

# Run the controls (harness self-test).
python3 /src/evaluation/earned-trust/tls_matrix.py \
    --root /src \
    --workdir /tmp/etp-tls-matrix-self-test \
    --self-test

echo "tls-matrix inner: PASS"