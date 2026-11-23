#!/bin/sh
# Phase 15.1a durable archive, policy metadata, and offline evidence gate.
#
# Rebuilds the archive from the committed evidence inside a hardened, offline
# python:3.11-slim container, verifies every archived object, and runs the
# independent time, revocation, transparency, attestation, SARIF, and policy
# metadata verifiers from the archive root.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="${IMAGE:-python:3.11-slim}"
RUN="$ROOT/target/etp-phase15-run-$$"
HORIZON=1795417198
rm -rf "$RUN" 2>/dev/null || true
mkdir -p "$RUN"

timeout 1800 docker run --rm \
    --name "frf-etp-phase15-$$" \
    --memory=512m --memory-swap=512m \
    --pids-limit=512 --cpus=2 \
    --ulimit nofile=1024:1024 \
    --oom-score-adj=500 \
    --cap-drop ALL \
    --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges \
    --network=none \
    -v "$ROOT":/src:ro \
    -v "$RUN":/out \
    -w /src \
    "$IMAGE" sh -c '
        set -eu
        python3 evaluation/earned-trust-1.2.0/make_archive.py \
            --root /src \
            --out-dir /out/archive \
            --time-dir /src/evaluation/earned-trust-1.2.0/time \
            --revocation-dir /src/evaluation/earned-trust-1.2.0/revocations \
            --horizon-unix '"$HORIZON"'

        python3 - <<"PY"
import hashlib
import json
import pathlib
import sys

root = pathlib.Path("/out/archive")
manifest_path = root / "manifest.json"
if not manifest_path.is_file():
    sys.exit("archive manifest missing")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
objects = manifest.get("objects")
if not isinstance(objects, list) or not objects:
    sys.exit("archive manifest has no objects")
for entry in objects:
    relative = entry.get("path", "")
    if relative.startswith("evaluation/earned-trust-1.2.0/archive/"):
        sys.exit(f"archive recursion detected: {relative}")
    path = root / relative
    if not path.is_file():
        sys.exit(f"missing archive object: {relative}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != entry.get("sha256"):
        sys.exit(f"archive digest mismatch: {relative}")
print(f"archive objects verified: {len(objects)}")
PY

        cd /out/archive

        python3 evaluation/earned-trust-1.2.0/reconstruct.py

        python3 evaluation/earned-trust-1.2.0/verify_policy_metadata.py \
            --policy evaluation/earned-trust-1.2.0/policy-metadata.json \
            --now 1795417304 --controls

        python3 evaluation/earned-trust-1.2.0/verify_transparency.py \
            --dir evaluation/earned-trust-1.2.0/transparency --controls

        closure="$(sha256sum evaluation/earned-trust-1.2.0/MANIFEST.json | cut -d" " -f1)"
        python3 evaluation/earned-trust-1.2.0/verify_time.py \
            --token evaluation/earned-trust-1.2.0/time/token.tsr \
            --imprint "$closure" \
            --tsa-cert evaluation/earned-trust-1.2.0/time/tsa-ca.pem \
            --policy-oid 1.3.6.1.4.1.99999.1 --controls

        python3 evaluation/earned-trust-1.2.0/verify_revocation.py \
            --registry evaluation/earned-trust-1.2.0/revocations/registry.json \
            --policy evaluation/earned-trust-1.2.0/trust-policy.json \
            --support evaluation/earned-trust-1.2.0/revocations/support-model.json \
            --historical evaluation/earned-trust-1.2.0/revocations/historical-verdict.json --controls

        mkdir -p target
        python3 evaluation/earned-trust-1.2.0/verify_attestations.py \
            --attestations evaluation/earned-trust-1.2.0/attestations \
            --policy evaluation/earned-trust-1.2.0/trust-policy.json \
            --campaign evaluation/earned-trust-1.2.0/MANIFEST.json --controls

        python3 evaluation/earned-trust-1.2.0/verify_sarif.py \
            --campaign evaluation/earned-trust-1.2.0/MANIFEST.json \
            --sarf evaluation/earned-trust-1.2.0/campaign.sarif \
            --review evaluation/earned-trust-1.2.0/suppression-review.json \
            --statement evaluation/earned-trust-1.2.0/attestations/campaign-closure.statement.json

        python3 evaluation/earned-trust-1.2.0/verify_sarif.py \
            --campaign evaluation/earned-trust-1.2.0/MANIFEST.json \
            --sarf evaluation/earned-trust-1.2.0/campaign.sarif \
            --review evaluation/earned-trust-1.2.0/suppression-review.json \
            --statement evaluation/earned-trust-1.2.0/attestations/campaign-closure.statement.json \
            --self-test
    '

echo "etp-phase15 gate: PASS"
