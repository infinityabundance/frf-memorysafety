#!/usr/bin/env python3
"""Create a test-only DSSE/in-toto attestation for the finite ETP campaign.

This helper is a gate and test utility, not a production signer. It generates an
ephemeral Ed25519 key with the OpenSSL CLI, derives the raw public key, signs the
exact in-toto Statement bytes, writes the envelope, statement, public key, and
trust policy, and then deletes the private key. The private key is written only
under the caller-supplied ``--key-dir`` (normally ``target/``) and is never
committed.

It refuses to sign unless the committed closure is internally complete: every
declared receipt exists, every receipt digest matches, every receipt outcome and
decision matches the closure reference, and the recomputed counts and population
match the declared closure. A missing, duplicate, or altered case is a hard
failure, not a signed statement.

Standard library plus the OpenSSL CLI only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import NoReturn

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://frf.dev/etp/campaign-closure/v1"
PREDICATE_SCHEMA = "frf-etp.predicate.campaign-closure.v1"
POLICY_SCHEMA = "frf-etp.trust-policy.v1"
SPEC = "frf-etp-v1"

ISSUED_AT_UNIX = 1795305600  # 2026-11-22T00:00:00Z
EXPIRES_AT_UNIX = 1826841600  # 2027-11-22T00:00:00Z

SCOPE_CLOSURE = "https://frf.dev/etp/campaign-closure/v1"
SCOPE_INSTRUMENT = "https://frf.dev/etp/instrument-qualification/v1"
SCOPE_REPRODUCTION = "https://frf.dev/etp/reproduction/v1"
SCOPE_PROOF = "https://frf.dev/etp/proof-admission/v1"
SCOPE_CONSUMER = "https://frf.dev/etp/consumer-closure/v1"
SCOPE_FINDINGS = "https://frf.dev/etp/security-findings/v1"
SCOPE_RELEASE = "https://frf.dev/etp/release-adjudication/v1"

ED25519_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")


def fail(message: str) -> NoReturn:
    print(f"make_attestation: {message}", file=sys.stderr)
    raise SystemExit(1)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(type_bytes)).encode("ascii")
        + b" "
        + type_bytes
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def run_openssl(args: list[str]) -> None:
    try:
        subprocess.run(args, check=True, capture_output=True)
    except FileNotFoundError as error:
        fail(f"openssl is unavailable: {error}")
    except subprocess.CalledProcessError as error:
        fail(f"openssl failed: {error.stderr.decode('utf-8', 'replace')}")


def derive_conclusion(closure_status: str, acceptance: str) -> str:
    if closure_status == "closed" and acceptance == "accepted":
        return "accepted"
    if closure_status == "blocked":
        return "blocked"
    return "withheld"


def recompute_campaign(campaign_path: Path) -> dict[str, object]:
    base = campaign_path.parent
    closure_bytes = campaign_path.read_bytes()
    closure = json.loads(closure_bytes)
    opening_path = base / closure["opening_manifest_path"]
    opening_bytes = opening_path.read_bytes()
    if sha256_bytes(opening_bytes) != closure["opening_sha256"]:
        fail("opening manifest digest does not match the closure")
    protocol = json.loads(opening_bytes)

    receipt_files: dict[str, bytes] = {}
    receipts_dir = base / "receipts"
    for path in sorted(receipts_dir.glob("*.json")):
        receipt_files[f"receipts/{path.name}"] = path.read_bytes()

    raw_files: dict[str, bytes] = {}
    raw_dir = receipts_dir / "raw"
    if raw_dir.is_dir():
        for path in sorted(raw_dir.rglob("*")):
            if path.is_file():
                raw_files[f"receipts/raw/{path.relative_to(raw_dir).as_posix()}"] = path.read_bytes()

    outcomes: Counter[str] = Counter()
    decisions: Counter[str] = Counter()
    case_ids: list[str] = []
    referenced_paths = set()
    for reference in closure["receipts"]:
        relative = reference["path"]
        if relative in referenced_paths:
            fail(f"duplicate closure receipt reference {relative}")
        referenced_paths.add(relative)
        if relative not in receipt_files:
            fail(f"closure references a missing receipt {relative}")
        receipt_bytes = receipt_files[relative]
        if sha256_bytes(receipt_bytes) != reference["sha256"]:
            fail(f"receipt digest mismatch for {relative}")
        receipt = json.loads(receipt_bytes)
        if receipt["case_id"] != reference["case_id"]:
            fail(f"receipt case identifier mismatch for {relative}")
        if receipt["observation"]["outcome"] != reference["outcome"]:
            fail(f"receipt outcome mismatch for {relative}")
        if receipt["adjudication"]["decision"] != reference["decision"]:
            fail(f"receipt decision mismatch for {relative}")
        if receipt["candidate_identity"] != closure["candidate_identity"]:
            fail(f"receipt candidate identity mismatch for {relative}")
        case_ids.append(receipt["case_id"])
        outcomes[receipt["observation"]["outcome"]] += 1
        decisions[receipt["adjudication"]["decision"]] += 1

    population = [case["id"] for case in protocol["population"]]
    if sorted(population) != sorted(case_ids):
        fail("closure receipts do not cover exactly the declared population")
    if len(receipt_files) != len(referenced_paths):
        fail("receipt directory contains an unreferenced receipt")

    hasher = hashlib.sha256()
    hasher.update(b"frf-etp.campaign-evidence-root.v1\n")
    for path in sorted(list(receipt_files) + list(raw_files), key=lambda value: value.encode("utf-8")):
        data = receipt_files.get(path, raw_files.get(path))
        assert data is not None
        hasher.update(path.encode("utf-8"))
        hasher.update(b"\x00")
        hasher.update(sha256_bytes(data).encode("ascii"))
        hasher.update(b"\n")
    evidence_root = hasher.hexdigest()

    declared_outcomes = {item["label"]: item["count"] for item in closure["outcomes"]}
    declared_decisions = {item["label"]: item["count"] for item in closure["decisions"]}
    if declared_outcomes != dict(outcomes):
        fail("closure outcome counts disagree with the receipts")
    if declared_decisions != dict(decisions):
        fail("closure decision counts disagree with the receipts")
    if closure["case_count"] != len(case_ids):
        fail("closure case_count disagrees with the receipts")
    if closure["receipt_count"] != len(receipt_files):
        fail("closure receipt_count disagrees with the receipt directory")
    if closure["raw_evidence_count"] != len(raw_files):
        fail("closure raw_evidence_count disagrees with the raw evidence directory")
    if closure["candidate_identity"] != protocol["candidate"]["tree_sha256"]:
        fail("closure candidate identity disagrees with the opening protocol")
    if closure["instrument_id"] != protocol["instrument"]["id"]:
        fail("closure instrument identity disagrees with the opening protocol")

    return {
        "closure_bytes": closure_bytes,
        "closure_sha256": sha256_bytes(closure_bytes),
        "campaign_id": closure["campaign_id"],
        "candidate_identity": closure["candidate_identity"],
        "evidence_root_sha256": evidence_root,
        "case_ids": sorted(case_ids),
        "case_count": len(case_ids),
        "receipt_count": len(receipt_files),
        "raw_evidence_count": len(raw_files),
        "outcomes": [
            {"label": label, "count": count} for label, count in sorted(outcomes.items())
        ],
        "decisions": [
            {"label": label, "count": count} for label, count in sorted(decisions.items())
        ],
        "closure_status": closure["closure_status"],
        "acceptance": closure["acceptance"],
        "conclusion": derive_conclusion(closure["closure_status"], closure["acceptance"]),
        "claim_ceiling": closure["claim_ceiling"],
    }


def build_statement(campaign: dict[str, object]) -> dict[str, object]:
    campaign_id = campaign["campaign_id"]
    predicate = {
        "schema": PREDICATE_SCHEMA,
        "spec": SPEC,
        "campaign_id": campaign_id,
        "closure_sha256": campaign["closure_sha256"],
        "candidate_identity": campaign["candidate_identity"],
        "raw_evidence_sha256": campaign["evidence_root_sha256"],
        "case_count": campaign["case_count"],
        "receipt_count": campaign["receipt_count"],
        "raw_evidence_count": campaign["raw_evidence_count"],
        "case_ids": campaign["case_ids"],
        "outcomes": campaign["outcomes"],
        "decisions": campaign["decisions"],
        "closure_status": campaign["closure_status"],
        "acceptance": campaign["acceptance"],
        "conclusion": campaign["conclusion"],
        "independent_review": "not_established",
        "claim_ceiling": campaign["claim_ceiling"],
    }
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": f"campaign-closure:{campaign_id}",
                "digest": {"sha256": campaign["closure_sha256"]},
            },
            {
                "name": f"candidate:{campaign['candidate_identity']}",
                "digest": {"sha256": campaign["candidate_identity"]},
            },
            {
                "name": f"raw-evidence:{campaign_id}",
                "digest": {"sha256": campaign["evidence_root_sha256"]},
            },
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def generate_key(key_dir: Path) -> tuple[Path, bytes]:
    key_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(key_dir, 0o700)
    private_key = key_dir / "ed25519-private.pem"
    public_der = key_dir / "ed25519-public.der"
    run_openssl(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)])
    run_openssl(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-outform",
            "DER",
            "-out",
            str(public_der),
        ]
    )
    der = public_der.read_bytes()
    if len(der) != 44 or not der.startswith(ED25519_DER_PREFIX):
        fail("unexpected Ed25519 SubjectPublicKeyInfo encoding")
    return private_key, der[len(ED25519_DER_PREFIX) :]


def sign(private_key: Path, message: bytes, key_dir: Path) -> bytes:
    message_path = key_dir / "pae.bin"
    signature_path = key_dir / "signature.bin"
    message_path.write_bytes(message)
    run_openssl(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-inkey",
            str(private_key),
            "-rawin",
            "-in",
            str(message_path),
            "-out",
            str(signature_path),
        ]
    )
    signature = signature_path.read_bytes()
    if len(signature) != 64:
        fail("unexpected Ed25519 signature length")
    return signature


def public_pem(private_key: Path, key_dir: Path) -> bytes:
    pem_path = key_dir / "ed25519-public.pem"
    run_openssl(
        ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(pem_path)]
    )
    return pem_path.read_bytes()


def build_policy(public_key_base64: str, keyid: str, actor: str) -> dict[str, object]:
    test_key = {
        "keyid": keyid,
        "algorithm": "ed25519",
        "public_key_base64": public_key_base64,
        "actor": actor,
        "not_before_unix": ISSUED_AT_UNIX,
        "not_after_unix": EXPIRES_AT_UNIX,
    }
    return {
        "schema": POLICY_SCHEMA,
        "spec": SPEC,
        "policy_id": "frf-etp-test-trust-policy-2026-11-22",
        "version": 1,
        "issued_at_unix": ISSUED_AT_UNIX,
        "expires_at_unix": EXPIRES_AT_UNIX,
        "roles": [
            {
                "id": "evidence_producer",
                "threshold": 1,
                "independent": False,
                "scope": [SCOPE_CLOSURE, SCOPE_CONSUMER, SCOPE_FINDINGS],
                "keys": [test_key],
            },
            {
                "id": "instrument_qualifier",
                "threshold": 1,
                "independent": False,
                "scope": [SCOPE_INSTRUMENT, SCOPE_REPRODUCTION],
                "keys": [],
            },
            {
                "id": "adjudicator",
                "threshold": 2,
                "independent": True,
                "scope": [SCOPE_PROOF, SCOPE_CLOSURE],
                "keys": [],
            },
            {
                "id": "release_authority",
                "threshold": 1,
                "independent": False,
                "scope": [SCOPE_RELEASE],
                "keys": [],
            },
            {
                "id": "correction_authority",
                "threshold": 1,
                "independent": False,
                "scope": [SCOPE_CLOSURE],
                "keys": [],
            },
        ],
    }


def build_policy_from_base(
    base: dict[str, object], public_key_base64: str, keyid: str, actor: str
) -> dict[str, object]:
    """Replace only the evidence-producer key and preserve every other role.

    Adding or replacing a test key is a substantive policy change, so the
    version is incremented. Other role keys, scopes, thresholds, and validity
    windows are preserved byte-for-byte after JSON normalization.
    """
    if base.get("schema") != POLICY_SCHEMA:
        fail("base policy schema is not frf-etp.trust-policy.v1")
    if base.get("spec") != SPEC:
        fail("base policy spec is not frf-etp-v1")
    roles = base.get("roles")
    if not isinstance(roles, list):
        fail("base policy has no roles list")
    policy = json.loads(json.dumps(base))
    test_key = {
        "keyid": keyid,
        "algorithm": "ed25519",
        "public_key_base64": public_key_base64,
        "actor": actor,
        "not_before_unix": base.get("issued_at_unix"),
        "not_after_unix": base.get("expires_at_unix"),
    }
    for role in policy["roles"]:
        if isinstance(role, dict) and role.get("id") == "evidence_producer":
            role["keys"] = [test_key]
            break
    else:
        fail("base policy has no evidence_producer role")
    policy["version"] = int(policy.get("version", 1)) + 1
    return policy


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--campaign",
        default="evaluation/earned-trust-1.2.0/MANIFEST.json",
        help="committed campaign closure manifest",
    )
    parser.add_argument(
        "--out",
        default="evaluation/earned-trust-1.2.0/attestations",
        help="directory for the envelope, statement, public key, and policy copy",
    )
    parser.add_argument(
        "--policy-out",
        default=None,
        help="optional additional path for the trust policy",
    )
    parser.add_argument(
        "--key-dir",
        default="target/attestation-key",
        help="directory for the ephemeral private key; deleted before exit",
    )
    parser.add_argument("--keyid", default="frf-etp-test-ephemeral-2026-11-22")
    parser.add_argument("--actor", default="test-only-ephemeral-evidence-producer")
    parser.add_argument(
        "--base-policy",
        default=None,
        help="preserve every role except the replaced evidence-producer key",
    )
    args = parser.parse_args()

    campaign_path = Path(args.campaign)
    out = Path(args.out)
    key_dir = Path(args.key_dir)
    campaign = recompute_campaign(campaign_path)
    statement = build_statement(campaign)
    payload = canonical_json(statement)
    message = pae(PAYLOAD_TYPE, payload)

    key_dir.mkdir(parents=True, exist_ok=True)
    private_key, raw_public_key = generate_key(key_dir)
    try:
        signature = sign(private_key, message, key_dir)
        pem = public_pem(private_key, key_dir)
        public_key_base64 = base64.b64encode(raw_public_key).decode("ascii")
        if args.base_policy:
            base = json.loads(Path(args.base_policy).read_text())
            if not isinstance(base, dict):
                fail("base policy must be a JSON object")
            policy = build_policy_from_base(
                base, public_key_base64, args.keyid, args.actor
            )
        else:
            policy = build_policy(public_key_base64, args.keyid, args.actor)
        envelope = {
            "payloadType": PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [
                {"keyid": args.keyid, "sig": base64.b64encode(signature).decode("ascii")}
            ],
        }

        out.mkdir(parents=True, exist_ok=True)
        (out / "campaign-closure.envelope.json").write_bytes(canonical_json(envelope))
        (out / "campaign-closure.statement.json").write_bytes(payload)
        (out / "campaign-closure.public.pem").write_bytes(pem)
        (out / "trust-policy.json").write_bytes(canonical_json(policy))
        if args.policy_out:
            policy_out = Path(args.policy_out)
            policy_out.parent.mkdir(parents=True, exist_ok=True)
            policy_out.write_bytes(canonical_json(policy))
    finally:
        shutil.rmtree(key_dir, ignore_errors=True)

    print(f"campaign: {campaign['campaign_id']}")
    print(f"closure sha256: {campaign['closure_sha256']}")
    print(f"raw evidence sha256: {campaign['evidence_root_sha256']}")
    print(f"payload sha256: {sha256_bytes(payload)}")
    print(f"public key base64: {public_key_base64}")
    print("private key discarded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
