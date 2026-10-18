#!/bin/sh
# Phase 8.2 live consumer workload: a candidate-linked curl against a local
# TLS 1.3 server, with a positive verified fetch and an unrelated-CA rejection.
#
# Runs inside the court container. The authority CLI generates the PKI and
# serves; curl was built by the Phase-17 harness against the candidate prefix.
set -eu

: "${CANDIDATE:?CANDIDATE must point at the candidate install prefix}"
: "${AUTH:?AUTH must point at the authority install prefix}"
: "${CURL:?CURL must point at the candidate-linked curl binary}"
: "${WORKDIR:?WORKDIR must be a writable scratch directory}"
PORT="${PORT:-4433}"

OPENSSL="$AUTH/bin/openssl"
AUTH_ENV="LD_LIBRARY_PATH=$AUTH/lib OPENSSL_CONF=/dev/null"
CANDIDATE_ENV="LD_LIBRARY_PATH=$CANDIDATE/lib"

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/pki"
cd "$WORKDIR/pki"

env $AUTH_ENV "$OPENSSL" req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 7 \
    -subj "/CN=phase8 runtime test CA" -addext "basicConstraints=critical,CA:TRUE" \
    >"$WORKDIR/ca.log" 2>&1
env $AUTH_ENV "$OPENSSL" req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
    -subj "/CN=127.0.0.1" >"$WORKDIR/csr.log" 2>&1
env $AUTH_ENV "$OPENSSL" req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other-ca.crt -days 7 \
    -subj "/CN=phase8 unrelated CA" -addext "basicConstraints=critical,CA:TRUE" \
    >"$WORKDIR/other.log" 2>&1
printf '%s\n' \
    "subjectAltName=IP:127.0.0.1" \
    "basicConstraints=CA:FALSE" \
    "keyUsage=digitalSignature,keyEncipherment" \
    "extendedKeyUsage=serverAuth" > server.ext
env $AUTH_ENV "$OPENSSL" x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 7 -extfile server.ext >"$WORKDIR/sign.log" 2>&1

# Keep s_server's stdin open; -www serves a page for each request.
FIFO="$WORKDIR/srv.fifo"
mkfifo "$FIFO"
env $AUTH_ENV "$OPENSSL" s_server -accept "$PORT" -cert "$WORKDIR/pki/server.crt" \
    -key "$WORKDIR/pki/server.key" -tls1_3 -www <"$FIFO" \
    >"$WORKDIR/srv.out" 2>"$WORKDIR/srv.err" &
SRV=$!
exec 3>"$FIFO"
cleanup() {
    exec 3>&- || true
    kill "$SRV" 2>/dev/null || true
    wait "$SRV" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Wait for the listener (python3 is present in the court image).
i=0
while [ "$i" -lt 100 ]; do
    if python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.2); sys.exit(0 if s.connect_ex(('127.0.0.1', $PORT)) == 0 else 1)" 2>/dev/null; then
        break
    fi
    i=$((i + 1))
    sleep 0.1
done

COMMON="-sS --max-time 15 --tlsv1.3 --tls-max 1.3 -o /dev/null -w http_code=%{http_code}\nssl_verify_result=%{ssl_verify_result}\n"

set +e
env $CANDIDATE_ENV LD_DEBUG=libs "$CURL" $COMMON --cacert "$WORKDIR/pki/ca.crt" \
    "https://127.0.0.1:$PORT/" >"$WORKDIR/pos.out" 2>"$WORKDIR/pos.err"
POS=$?
env $CANDIDATE_ENV "$CURL" $COMMON --cacert "$WORKDIR/pki/other-ca.crt" \
    "https://127.0.0.1:$PORT/" >"$WORKDIR/neg.out" 2>"$WORKDIR/neg.err"
NEG=$?
set -e

echo "== curl-verify-fetch =="
echo "exit=$POS"
cat "$WORKDIR/pos.out"
echo "== curl-unrelated-ca (must fail) =="
echo "exit=$NEG"
cat "$WORKDIR/neg.out"
cat "$WORKDIR/neg.err"
echo "== ldd =="
env $CANDIDATE_ENV ldd "$CURL"
echo "== LD_DEBUG (candidate DSOs) =="
grep -E "libssl|libcrypto" "$WORKDIR/pos.err" | grep -F "$CANDIDATE" | head -20 || true
echo "== DSO digests =="
sha256sum "$CANDIDATE/lib/libssl.so.3" "$CANDIDATE/lib/libcrypto.so.3"
echo "== DSO metadata =="
readelf -d "$CANDIDATE/lib/libssl.so.3" | sed -n 's/.*Shared library: \[\(.*\)\]/NEEDED \1/p'
readelf -d "$CANDIDATE/lib/libcrypto.so.3" | sed -n 's/.*Shared library: \[\(.*\)\]/NEEDED \1/p'
echo "== result =="
[ "$POS" -eq 0 ] && grep -q "http_code=200" "$WORKDIR/pos.out" &&
    grep -q "ssl_verify_result=0" "$WORKDIR/pos.out"
[ "$NEG" -eq 60 ] && grep -q "http_code=000" "$WORKDIR/neg.out" &&
    grep -q "ssl_verify_result=20" "$WORKDIR/neg.out"
echo "positive_ok=1"
echo "negative_rejected=1"
