#!/bin/sh
# Phase 10.4a trusted-time, revocation, and durable-archive gate.
#
# Every container keeps a hard memory/swap cap, a pid cap, a cpu cap, a nofile
# limit, a raised OOM score, reduced capabilities, and no-new-privileges. The
# repository is mounted read-only except for target/, where test-only TSA
# material, token requests, timestamp tokens, revocation registries, and the
# regenerated archive live. No private key is committed.
#
# Modes:
#   full (default)  generate, verify, run controls, and build a fresh archive
#   check           compile, clippy, and focused tests only
#   fmt             write rustfmt output inside the container
set -eu

RUST_IMAGE="${FRF_RUST_IMAGE:-rust:1.85.0-slim}"
PYTHON_IMAGE="${FRF_PYTHON_IMAGE:-python:3.11-slim}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOGS="$ROOT/target/gate-logs"
mkdir -p "$LOGS"
RUST_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$RUST_IMAGE" 2>/dev/null || true)
PYTHON_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$PYTHON_IMAGE" 2>/dev/null || true)
if [ -z "$RUST_IMAGE_ID" ]; then RUST_IMAGE_ID=unknown; fi
if [ -z "$PYTHON_IMAGE_ID" ]; then PYTHON_IMAGE_ID=unknown; fi

rust_run() {
    name=$1
    shift
    echo "== $name =="
    if timeout 1800 docker run --rm \
        --name "frf-ms-$name-$$" \
        --memory=2g --memory-swap=2g \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 \
        --oom-score-adj=500 \
        --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
        --security-opt no-new-privileges \
        -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
        -v frf-cargo:/cargo -e CARGO_HOME=/cargo \
        -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" -e CARGO_INCREMENTAL=0 \
        -w /src "$RUST_IMAGE" "$@" >"$LOGS/$name.log" 2>&1
    then
        cat "$LOGS/$name.log"
        echo "PASS $name"
    else
        status=$?
        tail -n 160 "$LOGS/$name.log" || true
        echo "FAIL $name (exit $status)"
        exit "$status"
    fi
}

rust_run_rw() {
    name=$1
    shift
    echo "== $name =="
    if timeout 1800 docker run --rm \
        --name "frf-ms-$name-$$" \
        --memory=2g --memory-swap=2g \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 \
        --oom-score-adj=500 \
        --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
        --security-opt no-new-privileges \
        -v "$ROOT":/src -v "$ROOT/target":/src/target \
        -v frf-cargo:/cargo -e CARGO_HOME=/cargo \
        -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" -e CARGO_INCREMENTAL=0 \
        -w /src "$RUST_IMAGE" "$@" >"$LOGS/$name.log" 2>&1
    then
        cat "$LOGS/$name.log"
        echo "PASS $name"
    else
        status=$?
        tail -n 160 "$LOGS/$name.log" || true
        echo "FAIL $name (exit $status)"
        exit "$status"
    fi
}

rust_run_offline() {
    name=$1
    shift
    echo "== $name =="
    if timeout 600 docker run --rm \
        --name "frf-ms-$name-$$" \
        --memory=512m --memory-swap=512m \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 \
        --oom-score-adj=500 \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --network=none \
        -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
        -w /src "$RUST_IMAGE" "$@" >"$LOGS/$name.log" 2>&1
    then
        cat "$LOGS/$name.log"
        echo "PASS $name"
    else
        status=$?
        tail -n 160 "$LOGS/$name.log" || true
        echo "FAIL $name (exit $status)"
        exit "$status"
    fi
}

python_run() {
    name=$1
    shift
    echo "== $name =="
    if timeout 900 docker run --rm \
        --name "frf-ms-$name-$$" \
        --memory=512m --memory-swap=512m \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 \
        --oom-score-adj=500 \
        --cap-drop ALL --cap-add DAC_OVERRIDE \
        --security-opt no-new-privileges \
        --network=none \
        -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
        -w /src "$PYTHON_IMAGE" "$@" >"$LOGS/$name.log" 2>&1
    then
        cat "$LOGS/$name.log"
        echo "PASS $name"
    else
        status=$?
        tail -n 160 "$LOGS/$name.log" || true
        echo "FAIL $name (exit $status)"
        exit "$status"
    fi
}

python_run_rw() {
    name=$1
    shift
    echo "== $name =="
    if timeout 900 docker run --rm \
        --name "frf-ms-$name-$$" \
        --memory=512m --memory-swap=512m \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 \
        --oom-score-adj=500 \
        --cap-drop ALL --cap-add DAC_OVERRIDE \
        --security-opt no-new-privileges \
        --network=none \
        -v "$ROOT":/src \
        -w /src "$PYTHON_IMAGE" "$@" >"$LOGS/$name.log" 2>&1
    then
        cat "$LOGS/$name.log"
        echo "PASS $name"
    else
        status=$?
        tail -n 160 "$LOGS/$name.log" || true
        echo "FAIL $name (exit $status)"
        exit "$status"
    fi
}

MODE="${FRF_ETP_TIME_MODE:-full}"

if [ "$MODE" = "fmt" ]; then
    # Development-only formatting mode. It mounts the source read-write but
    # keeps the same memory, swap, pid, cpu, nofile, OOM, capability, and
    # no-new-privileges controls. The evidence modes stay read-only.
    rust_run_rw etp-time-fmt cargo fmt --all
    exit 0
fi

if [ "$MODE" = "check" ]; then
    rust_run etp-time-check sh -c '
        set -eu
        cargo fmt --all -- --check
        cargo clippy --locked --all-targets --all-features -- -D warnings
        cargo build --locked --features native-harness --bin frf-memorysafety
        cargo test --locked --features native-harness --test etp_time
        cargo test --locked --features native-harness --test etp_revocation
        cargo test --locked --features native-harness --test etp_archive
    '
    exit 0
fi

if [ "$MODE" = "populate" ]; then
    rust_run etp-time-populate-rust sh -c '
        set -eu
        cargo build --locked --features native-harness --bin frf-memorysafety
        rm -rf target/etp-populate
        mkdir -p target/etp-populate/time target/etp-populate/revocations target/etp-populate/tsa
        TSA=$(pwd)/target/etp-populate/tsa
        printf "01\n" > "$TSA/tsaserial"
        cat > "$TSA/ext.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
extendedKeyUsage=critical,timeStamping
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
        cat > "$TSA/tsa.cnf" <<EOF
[ tsa ]
default_tsa = tsa_config1

[ tsa_config1 ]
dir = $TSA
serial = $TSA/tsaserial
crypto_device = builtin
signer_cert = $TSA/tsa.crt
certs = $TSA/tsa.crt
signer_key = $TSA/tsa.key
signer_digest = sha256
default_policy = 1.3.6.1.4.1.99999.1
other_policies = 1.3.6.1.4.1.99999.1
digests = sha256, sha384, sha512
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
EOF
        openssl ecparam -name prime256v1 -genkey -noout -out "$TSA/ca.key"
        openssl req -new -x509 -key "$TSA/ca.key" -out "$TSA/ca.crt" -days 2 -sha256 \
            -subj "/CN=FRF Test TSA CA (local, test-only)" \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign"
        openssl ecparam -name prime256v1 -genkey -noout -out "$TSA/tsa.key"
        openssl req -new -key "$TSA/tsa.key" -out "$TSA/tsa.csr" -sha256 -subj "/CN=FRF Local Test TSA"
        openssl x509 -req -in "$TSA/tsa.csr" -CA "$TSA/ca.crt" -CAkey "$TSA/ca.key" \
            -CAcreateserial -out "$TSA/tsa.crt" -days 2 -sha256 -extfile "$TSA/ext.cnf"
        IMPRINT=$(sha256sum evaluation/earned-trust/MANIFEST.json | cut -d" " -f1)
        printf "%s\n" "$IMPRINT" > target/etp-populate/time/evidence-imprint.txt
        ./target/debug/frf-memorysafety etp time stamp \
            --imprint "$IMPRINT" \
            --tsa-config "$TSA/tsa.cnf" \
            --tsa-cert "$TSA/tsa.crt" \
            --out target/etp-populate/time/token.tsr \
            --request-out target/etp-populate/time/request.tsq \
            --json > target/etp-populate/time/stamp-report.json
        cp "$TSA/ca.crt" target/etp-populate/time/tsa-ca.pem
        cp "$TSA/tsa.crt" target/etp-populate/time/tsa-cert.pem
        openssl version > target/etp-populate/time/openssl-version.txt
        CA_DIGEST=$(openssl x509 -in "$TSA/ca.crt" -outform DER | sha256sum | cut -d" " -f1)
        ./target/debug/frf-memorysafety etp time verify target/etp-populate/time/token.tsr \
            --imprint "$IMPRINT" \
            --tsa-cert "$TSA/ca.crt" \
            --tsa-cert-sha256 "$CA_DIGEST" \
            --policy-oid 1.3.6.1.4.1.99999.1 \
            --trust-domain local-test-tsa \
            --json > target/etp-populate/time/time-report.json
        ./target/debug/frf-memorysafety etp revocation model \
            --out target/etp-populate/revocations/support-model.json
        ./target/debug/frf-memorysafety etp revocation record \
            target/etp-populate/revocations/support-model.json \
            --out target/etp-populate/revocations/historical-verdict.json
        cp evaluation/earned-trust/revocations/plan.json target/etp-populate/revocations/plan.json
        rm -f "$TSA"/*.key "$TSA"/*.csr "$TSA"/*.srl
        find target/etp-populate -type f -exec chmod 0644 {} +
        find target/etp-populate -type d -exec chmod 0755 {} +
    '

    python_run etp-time-populate-revocation \
        python3 evaluation/earned-trust/make_revocation.py \
        --policy-in evaluation/earned-trust/trust-policy.json \
        --support target/etp-populate/revocations/support-model.json \
        --plan evaluation/earned-trust/revocations/plan.json \
        --out-policy target/etp-populate/trust-policy.json \
        --out-registry target/etp-populate/revocations/registry.json \
        --out-public target/etp-populate/revocations/correction.pem \
        --key-dir target/etp-populate/revocation-key

    rust_run etp-time-populate-verify sh -c '
        set -eu
        CA_DIGEST=$(openssl x509 -in target/etp-populate/time/tsa-ca.pem -outform DER | sha256sum | cut -d" " -f1)
        ./target/debug/frf-memorysafety etp time verify target/etp-populate/time/token.tsr \
            --imprint "$(cat target/etp-populate/time/evidence-imprint.txt)" \
            --tsa-cert target/etp-populate/time/tsa-ca.pem \
            --tsa-cert-sha256 "$CA_DIGEST" \
            --policy-oid 1.3.6.1.4.1.99999.1 \
            --trust-domain local-test-tsa \
            --json > target/etp-populate/time/time-report.json
        ./target/debug/frf-memorysafety etp revocation verify \
            target/etp-populate/revocations/registry.json \
            --policy target/etp-populate/trust-policy.json \
            --support target/etp-populate/revocations/support-model.json \
            --historical target/etp-populate/revocations/historical-verdict.json \
            --json > target/etp-populate/revocations/revocation-report.json
    '

    mkdir -p "$ROOT/evaluation/earned-trust/time" "$ROOT/evaluation/earned-trust/revocations"
    cp -f "$ROOT/target/etp-populate/time/"* "$ROOT/evaluation/earned-trust/time/"
    cp -f "$ROOT/target/etp-populate/revocations/"* "$ROOT/evaluation/earned-trust/revocations/"
    cp -f "$ROOT/target/etp-populate/trust-policy.json" "$ROOT/evaluation/earned-trust/trust-policy.json"
    rm -rf "$ROOT/target/etp-populate/tsa" || true
    HORIZON=$(grep -o "\"gen_time_unix\": [0-9]*" "$ROOT/evaluation/earned-trust/time/time-report.json" | head -n 1 | tr -dc "0-9")
    python_run_rw etp-time-populate-archive \
        python3 evaluation/earned-trust/make_archive.py \
        --out-dir evaluation/earned-trust/archive \
        --time-dir evaluation/earned-trust/time \
        --revocation-dir evaluation/earned-trust/revocations \
        --horizon-unix "$HORIZON"
    echo "PASS etp-time-populate"
    exit 0
fi

if [ "$MODE" = "archive" ]; then
    HORIZON=$(grep -o "\"gen_time_unix\": [0-9]*" "$ROOT/evaluation/earned-trust/time/time-report.json" | head -n 1 | tr -dc "0-9")
    python_run_rw etp-time-archive-build \
        python3 evaluation/earned-trust/make_archive.py \
        --out-dir evaluation/earned-trust/archive \
        --time-dir evaluation/earned-trust/time \
        --revocation-dir evaluation/earned-trust/revocations \
        --horizon-unix "$HORIZON"
    exit 0
fi

if [ "$MODE" = "attest" ]; then
    python_run etp-attest-refreeze \
        python3 evaluation/earned-trust/make_attestation.py \
        --campaign evaluation/earned-trust/MANIFEST.json \
        --out target/etp-attestation-refreeze \
        --base-policy evaluation/earned-trust/trust-policy.json \
        --policy-out target/etp-attestation-refreeze/trust-policy.json \
        --key-dir target/etp-attestation-refreeze/key
    cp -f "$ROOT/target/etp-attestation-refreeze/campaign-closure.envelope.json" \
        "$ROOT/evaluation/earned-trust/attestations/campaign-closure.envelope.json"
    cp -f "$ROOT/target/etp-attestation-refreeze/campaign-closure.statement.json" \
        "$ROOT/evaluation/earned-trust/attestations/campaign-closure.statement.json"
    cp -f "$ROOT/target/etp-attestation-refreeze/campaign-closure.public.pem" \
        "$ROOT/evaluation/earned-trust/attestations/campaign-closure.public.pem"
    cp -f "$ROOT/target/etp-attestation-refreeze/trust-policy.json" \
        "$ROOT/evaluation/earned-trust/trust-policy.json"
    echo "PASS etp-attest-refreeze-copy"
    exit 0
fi

if [ "$MODE" = "campaign" ]; then
    echo "== etp-campaign-refreeze =="
    if timeout 1800 docker run --rm \
        --name "frf-ms-etp-campaign-refreeze-$$" \
        --memory=2g --memory-swap=2g \
        --pids-limit=512 --cpus=2 \
        --ulimit nofile=1024:1024 \
        --oom-score-adj=500 \
        --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
        --security-opt no-new-privileges \
        -v "$ROOT":/src:ro -v "$ROOT/target":/src/target \
        -v frf-cargo:/cargo -e CARGO_HOME=/cargo \
        -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" -e CARGO_INCREMENTAL=0 \
        -e FRF_NATIVE_HARNESS=1 \
        -e FRF_ETP_ENVIRONMENT="$RUST_IMAGE" \
        -e FRF_ETP_IMAGE_ID="$RUST_IMAGE_ID" \
        -w /src "$RUST_IMAGE" sh -c '
            set -eu
            cargo build --locked --features native-harness --bin frf-memorysafety
            rm -rf target/etp-campaign-refreeze
            mkdir -p target/etp-campaign-refreeze
            ./target/debug/frf-memorysafety etp campaign run \
                --protocol evaluation/earned-trust/protocol.json \
                --out target/etp-campaign-refreeze
            ./target/debug/frf-memorysafety etp campaign verify \
                target/etp-campaign-refreeze/MANIFEST.json
            ./target/debug/frf-memorysafety etp sarif export \
                target/etp-campaign-refreeze/MANIFEST.json \
                --out target/etp-campaign-refreeze/campaign.sarif
            ./target/debug/frf-memorysafety etp sarif verify \
                target/etp-campaign-refreeze/campaign.sarif
        ' >"$LOGS/etp-campaign-refreeze.log" 2>&1
    then
        cat "$LOGS/etp-campaign-refreeze.log"
        echo "PASS etp-campaign-refreeze"
    else
        status=$?
        tail -n 160 "$LOGS/etp-campaign-refreeze.log" || true
        echo "FAIL etp-campaign-refreeze (exit $status)"
        exit "$status"
    fi
    cp -f "$ROOT/target/etp-campaign-refreeze/protocol.json" "$ROOT/evaluation/earned-trust/protocol.json"
    cp -f "$ROOT/target/etp-campaign-refreeze/opening.sha256" "$ROOT/evaluation/earned-trust/opening.sha256"
    cp -f "$ROOT/target/etp-campaign-refreeze/MANIFEST.json" "$ROOT/evaluation/earned-trust/MANIFEST.json"
    cp -f "$ROOT/target/etp-campaign-refreeze/campaign.sarif" "$ROOT/evaluation/earned-trust/campaign.sarif"
    rm -rf "$ROOT/evaluation/earned-trust/receipts"
    cp -r "$ROOT/target/etp-campaign-refreeze/receipts" "$ROOT/evaluation/earned-trust/receipts"
    echo "PASS etp-campaign-refreeze-copy"
    exit 0
fi

if [ "$MODE" = "verify" ]; then
    IMPRINT=$(cat "$ROOT/evaluation/earned-trust/time/evidence-imprint.txt")
    NOW=1795333200
    rust_run etp-time-committed sh -c '
        set -eu
        IMPRINT=$(cat evaluation/earned-trust/time/evidence-imprint.txt)
        CA_DIGEST=$(openssl x509 -in evaluation/earned-trust/time/tsa-ca.pem -outform DER | sha256sum | cut -d" " -f1)
        ./target/debug/frf-memorysafety etp time verify evaluation/earned-trust/time/token.tsr \
            --imprint "$IMPRINT" \
            --tsa-cert evaluation/earned-trust/time/tsa-ca.pem \
            --tsa-cert-sha256 "$CA_DIGEST" \
            --policy-oid 1.3.6.1.4.1.99999.1 \
            --trust-domain local-test-tsa \
            --now-unix 1795333200 \
            --json > target/etp-time-committed-report.json
        ./target/debug/frf-memorysafety etp time verify evaluation/earned-trust/time/token.tsr \
            --imprint "$IMPRINT" \
            --tsa-cert evaluation/earned-trust/time/tsa-ca.pem \
            --tsa-cert-sha256 "$CA_DIGEST" \
            --policy-oid 1.3.6.1.4.1.99999.1 \
            --trust-domain local-test-tsa \
            --now-unix 1795333200
        ./target/debug/frf-memorysafety etp revocation verify \
            evaluation/earned-trust/revocations/registry.json \
            --policy evaluation/earned-trust/trust-policy.json \
            --support evaluation/earned-trust/revocations/support-model.json \
            --historical evaluation/earned-trust/revocations/historical-verdict.json \
            --now-unix 1795333200 --json > target/etp-revocation-committed-report.json
        ./target/debug/frf-memorysafety etp revocation verify \
            evaluation/earned-trust/revocations/registry.json \
            --policy evaluation/earned-trust/trust-policy.json \
            --support evaluation/earned-trust/revocations/support-model.json \
            --historical evaluation/earned-trust/revocations/historical-verdict.json \
            --now-unix 1795333200
        ./target/debug/frf-memorysafety etp archive verify \
            evaluation/earned-trust/archive --json > target/etp-archive-committed-report.json
        ./target/debug/frf-memorysafety etp archive verify evaluation/earned-trust/archive
    '
    python_run etp-time-independent \
        python3 evaluation/earned-trust/verify_time.py \
        --token evaluation/earned-trust/time/token.tsr \
        --imprint "$IMPRINT" \
        --tsa-cert evaluation/earned-trust/time/tsa-ca.pem \
        --policy-oid 1.3.6.1.4.1.99999.1 \
        --now "$NOW" --controls
    if ! grep -q 'controls passed: 6 of 6' "$LOGS/etp-time-independent.log"; then
        echo "FAIL etp-time-independent (unexpected control count)"
        exit 1
    fi
    python_run etp-revocation-independent \
        python3 evaluation/earned-trust/verify_revocation.py \
        --registry evaluation/earned-trust/revocations/registry.json \
        --policy evaluation/earned-trust/trust-policy.json \
        --support evaluation/earned-trust/revocations/support-model.json \
        --historical evaluation/earned-trust/revocations/historical-verdict.json \
        --now "$NOW" --controls
    if ! grep -q 'controls passed: 6 of 6' "$LOGS/etp-revocation-independent.log"; then
        echo "FAIL etp-revocation-independent (unexpected control count)"
        exit 1
    fi
    rust_run_offline etp-archive-offline \
        ./target/debug/frf-memorysafety etp archive verify \
        evaluation/earned-trust/archive
    echo "PASS etp-time-verify"
    exit 0
fi

if [ "$MODE" = "full" ]; then
    # Committed evidence and the independent verifiers.
    FRF_ETP_TIME_MODE=verify "$0"

    rust_run etp-time-tests sh -c '
        set -eu
        cargo fmt --all -- --check
        cargo clippy --locked --all-targets --all-features -- -D warnings
        cargo build --locked --features native-harness --bin frf-memorysafety
        cargo test --locked --features native-harness \
            --test etp_time --test etp_revocation --test etp_archive
    '
    if ! grep -q "test result: ok. 9 passed; 0 failed; 0 ignored" "$LOGS/etp-time-tests.log"; then
        echo "FAIL etp-time-tests (unexpected etp_time counts)"
        exit 1
    fi
    if ! grep -q "test result: ok. 13 passed; 0 failed; 0 ignored" "$LOGS/etp-time-tests.log"; then
        echo "FAIL etp-time-tests (unexpected etp_revocation counts)"
        exit 1
    fi
    if ! grep -q "test result: ok. 8 passed; 0 failed; 0 ignored" "$LOGS/etp-time-tests.log"; then
        echo "FAIL etp-time-tests (unexpected etp_archive counts)"
        exit 1
    fi

    # Fresh local TSA, token, and backdating control.
    rust_run etp-time-fresh sh -c '
        set -eu
        rm -rf target/etp-time-run
        mkdir -p target/etp-time-run/tsa
        TSA=$(pwd)/target/etp-time-run/tsa
        printf "01\n" > "$TSA/tsaserial"
        cat > "$TSA/ext.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
extendedKeyUsage=critical,timeStamping
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
        cat > "$TSA/tsa.cnf" <<EOF
[ tsa ]
default_tsa = tsa_config1

[ tsa_config1 ]
dir = $TSA
serial = $TSA/tsaserial
crypto_device = builtin
signer_cert = $TSA/tsa.crt
certs = $TSA/tsa.crt
signer_key = $TSA/tsa.key
signer_digest = sha256
default_policy = 1.3.6.1.4.1.99999.1
other_policies = 1.3.6.1.4.1.99999.1
digests = sha256, sha384, sha512
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
EOF
        openssl ecparam -name prime256v1 -genkey -noout -out "$TSA/ca.key"
        openssl req -new -x509 -key "$TSA/ca.key" -out "$TSA/ca.crt" -days 2 -sha256 \
            -subj "/CN=FRF Test TSA CA (local, test-only)" \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign"
        openssl ecparam -name prime256v1 -genkey -noout -out "$TSA/tsa.key"
        openssl req -new -key "$TSA/tsa.key" -out "$TSA/tsa.csr" -sha256 -subj "/CN=FRF Local Test TSA"
        openssl x509 -req -in "$TSA/tsa.csr" -CA "$TSA/ca.crt" -CAkey "$TSA/ca.key" \
            -CAcreateserial -out "$TSA/tsa.crt" -days 2 -sha256 -extfile "$TSA/ext.cnf"
        IMPRINT=$(sha256sum evaluation/earned-trust/MANIFEST.json | cut -d" " -f1)
        printf "%s\n" "$IMPRINT" > target/etp-time-run/evidence-imprint.txt
        ./target/debug/frf-memorysafety etp time stamp \
            --imprint "$IMPRINT" --tsa-config "$TSA/tsa.cnf" --tsa-cert "$TSA/tsa.crt" \
            --out target/etp-time-run/token.tsr --request-out target/etp-time-run/request.tsq \
            --json > target/etp-time-run/stamp-report.json
        cp "$TSA/ca.crt" target/etp-time-run/tsa-ca.pem
        cp "$TSA/tsa.crt" target/etp-time-run/tsa-cert.pem
        openssl version > target/etp-time-run/openssl-version.txt
        CA_DIGEST=$(openssl x509 -in "$TSA/ca.crt" -outform DER | sha256sum | cut -d" " -f1)
        ./target/debug/frf-memorysafety etp time verify target/etp-time-run/token.tsr \
            --imprint "$IMPRINT" --tsa-cert "$TSA/ca.crt" --tsa-cert-sha256 "$CA_DIGEST" \
            --policy-oid 1.3.6.1.4.1.99999.1 --trust-domain local-test-tsa \
            --json > target/etp-time-run/time-report.json
        ./target/debug/frf-memorysafety etp time verify target/etp-time-run/token.tsr \
            --imprint "$IMPRINT" --tsa-cert "$TSA/ca.crt" --tsa-cert-sha256 "$CA_DIGEST" \
            --policy-oid 1.3.6.1.4.1.99999.1 --trust-domain local-test-tsa
        if ./target/debug/frf-memorysafety etp time verify target/etp-time-run/token.tsr \
            --imprint "$IMPRINT" --tsa-cert "$TSA/ca.crt" --tsa-cert-sha256 "$CA_DIGEST" \
            --policy-oid 1.3.6.1.4.1.99999.1 --trust-domain local-test-tsa \
            --declared-execution-unix 1795305600; then
            echo "backdating control was unexpectedly accepted"
            exit 1
        fi
        rm -f "$TSA"/*.key "$TSA"/*.csr "$TSA"/*.srl
        find target/etp-time-run -type f -exec chmod 0644 {} +
    '

    FRESH_IMPRINT=$(cat "$ROOT/target/etp-time-run/evidence-imprint.txt")
    python_run etp-time-independent-fresh \
        python3 evaluation/earned-trust/verify_time.py \
        --token target/etp-time-run/token.tsr \
        --imprint "$FRESH_IMPRINT" \
        --tsa-cert target/etp-time-run/tsa-ca.pem \
        --policy-oid 1.3.6.1.4.1.99999.1 --controls
    if ! grep -q "controls passed: 6 of 6" "$LOGS/etp-time-independent-fresh.log"; then
        echo "FAIL etp-time-independent-fresh (unexpected control count)"
        exit 1
    fi

    # Fresh archive built from the committed objects and verified offline.
    HORIZON=$(grep -o "\"gen_time_unix\": [0-9]*" "$ROOT/evaluation/earned-trust/time/time-report.json" | head -n 1 | tr -dc "0-9")
    python_run etp-archive-fresh \
        python3 evaluation/earned-trust/make_archive.py \
        --out-dir target/etp-archive-fresh \
        --time-dir evaluation/earned-trust/time \
        --revocation-dir evaluation/earned-trust/revocations \
        --horizon-unix "$HORIZON"
    rust_run_offline etp-archive-fresh-verify \
        ./target/debug/frf-memorysafety etp archive verify target/etp-archive-fresh

    echo "PASS etp-time-gate"
    echo "rust image: $RUST_IMAGE ($RUST_IMAGE_ID)"
    echo "python image: $PYTHON_IMAGE ($PYTHON_IMAGE_ID)"
    exit 0
fi

echo "full mode not yet implemented"
exit 1
