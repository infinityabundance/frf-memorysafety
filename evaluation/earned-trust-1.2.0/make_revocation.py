#!/usr/bin/env python3
"""Generate a test-only correction-authority key, an updated trust policy, and
an append-only DSSE-signed revocation registry.

The private key is written only under the supplied key directory, used once, and
removed by this helper before it exits. The repository receives only the public
key in the trust policy.

Exit statuses: 0 generated, 3 invalid input or integrity failure, 5 signing
failure, 6 OpenSSL unavailable.
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
from pathlib import Path
from typing import NoReturn

SPEC = "frf-etp-v1"
ENTRY_SCHEMA = "frf-etp.revocation-entry.v1"
REGISTRY_SCHEMA = "frf-etp.revocation-registry.v1"
PAYLOAD_TYPE = "application/vnd.frf-etp.revocation+json"
CORRECTION_ROLE = "correction_authority"
SCOPE_CLOSURE = "https://frf.dev/etp/campaign-closure/v1"
ED25519_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
KEYID = "frf-etp-test-correction-2026-11-22"
ACTOR = "test-only-correction-authority"


def fail(message: str, status: int = 3) -> NoReturn:
    print(f"make_revocation: {message}", file=sys.stderr)
    raise SystemExit(status)


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(), object_pairs_hook=strict_object)
    except FileNotFoundError:
        fail(f"missing input {path}")
    except json.JSONDecodeError as error:
        fail(f"invalid JSON in {path}: {error}")


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def run_openssl(args: list[str], status: int = 5) -> None:
    try:
        subprocess.run(args, check=True, capture_output=True)
    except FileNotFoundError as error:
        fail(f"openssl is unavailable: {error}", 6)
    except subprocess.CalledProcessError as error:
        fail(
            f"openssl failed: {error.stderr.decode('utf-8', 'replace')}",
            status,
        )


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


def write_public_pem(private_key: Path, key_dir: Path, out: Path) -> None:
    pem_path = key_dir / "ed25519-public.pem"
    run_openssl(
        ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(pem_path)]
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(pem_path, out)


def update_policy(
    base: dict[str, object], public_key_base64: str
) -> dict[str, object]:
    policy = json.loads(json.dumps(base))
    roles = policy.get("roles")
    if not isinstance(roles, list):
        fail("trust policy has no roles list")
    if policy.get("schema") != "frf-etp.trust-policy.v1":
        fail("trust policy schema is not frf-etp.trust-policy.v1")
    if policy.get("spec") != SPEC:
        fail("trust policy spec is not frf-etp-v1")
    issued = policy.get("issued_at_unix")
    expires = policy.get("expires_at_unix")
    if not isinstance(issued, int) or not isinstance(expires, int):
        fail("trust policy has an invalid validity window")
    key = {
        "keyid": KEYID,
        "algorithm": "ed25519",
        "public_key_base64": public_key_base64,
        "actor": ACTOR,
        "not_before_unix": issued,
        "not_after_unix": expires,
    }
    for role in roles:
        if not isinstance(role, dict):
            fail("trust policy role is not an object")
        if role.get("id") == CORRECTION_ROLE:
            role["keys"] = [key]
            if not role.get("scope"):
                role["scope"] = [SCOPE_CLOSURE]
            break
    else:
        roles.append(
            {
                "id": CORRECTION_ROLE,
                "threshold": 1,
                "independent": False,
                "scope": [SCOPE_CLOSURE],
                "keys": [key],
            }
        )
    # Adding an authorized correction key is a substantive policy change. The
    # policy version is monotonic; the remaining roles and keys are unchanged.
    policy["version"] = int(policy.get("version", 1)) + 1
    return policy


def build_registry(
    plan: dict[str, object],
    policy: dict[str, object],
    support: dict[str, object],
    private_key: Path,
    key_dir: Path,
) -> dict[str, object]:
    if plan.get("schema") != "frf-etp.revocation-plan.v1":
        fail("plan schema is not frf-etp.revocation-plan.v1")
    if plan.get("spec") != SPEC:
        fail("plan spec is not frf-etp-v1")
    entries_in = plan.get("entries")
    if not isinstance(entries_in, list) or not entries_in:
        fail("plan has no entries")
    support_policy = support.get("policy")
    if not isinstance(support_policy, dict):
        fail("support model has no policy object")
    support_policy_id = support_policy.get("id")
    if not isinstance(support_policy_id, str):
        fail("support model policy has no id")
    registry_id = plan.get("registry_id")
    if not isinstance(registry_id, str) or not registry_id:
        fail("plan registry_id is missing")
    issued = plan.get("issued_at_unix")
    if not isinstance(issued, int):
        fail("plan issued_at_unix is missing")
    registry_policy_id = policy.get("policy_id")
    registry_policy_version = policy.get("version")
    if not isinstance(registry_policy_id, str) or not isinstance(
        registry_policy_version, int
    ):
        fail("trust policy identity is missing")
    entries: list[dict[str, object]] = []
    previous: str | None = None
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for index, item in enumerate(entries_in, start=1):
        if not isinstance(item, dict):
            fail("plan entry is not an object")
        action = item.get("action")
        if action not in {"revoke", "correct", "dissent"}:
            fail(f"unsupported action {action!r}")
        claim_id = item.get("claim_id")
        if not isinstance(claim_id, str) or not claim_id:
            fail("plan entry has no claim_id")
        evidence_ids = item.get("evidence_ids", [])
        if not isinstance(evidence_ids, list) or not all(
            isinstance(value, str) for value in evidence_ids
        ):
            fail("plan entry evidence_ids is invalid")
        if action == "revoke":
            key = (claim_id, tuple(sorted(evidence_ids)))
            if key in seen:
                fail(f"duplicate revocation target {claim_id}")
            seen.add(key)
        entry = {
            "schema": ENTRY_SCHEMA,
            "spec": SPEC,
            "registry_id": registry_id,
            "policy_id": registry_policy_id,
            "policy_version": registry_policy_version,
            "sequence": index,
            "previous_entry_sha256": previous,
            "entry_id": item.get("entry_id"),
            "action": action,
            "target": {
                "claim_id": claim_id,
                "policy_id": support_policy_id,
                "evidence_ids": evidence_ids,
                "subject_identity": item.get("subject_identity")
                or "candidate:79e72160a6a1c169093d5e7abb39f426a9f189d07aef7ddc472b3856911bcbb7",
            },
            "reason": item.get("reason"),
            "effective_at_unix": item.get("effective_at_unix", issued),
            "scope": item.get("scope"),
            "historical_replay": item.get(
                "historical_replay", "valid_under_original_policy"
            ),
            "statement": item.get("statement"),
            "corrects_entry_id": item.get("corrects_entry_id"),
        }
        payload = canonical_json(entry)
        signature = sign(private_key, pae(PAYLOAD_TYPE, payload), key_dir)
        envelope = {
            "payloadType": PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [
                {
                    "keyid": KEYID,
                    "sig": base64.b64encode(signature).decode("ascii"),
                }
            ],
        }
        previous = sha256_bytes(canonical_json(envelope))
        entries.append(envelope)
    return {
        "schema": REGISTRY_SCHEMA,
        "spec": SPEC,
        "registry_id": registry_id,
        "policy_id": registry_policy_id,
        "policy_version": registry_policy_version,
        "issued_at_unix": issued,
        "entries": entries,
    }


def write_public(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy-in", type=Path, required=True)
    parser.add_argument("--support", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--out-policy", type=Path, required=True)
    parser.add_argument("--out-registry", type=Path, required=True)
    parser.add_argument("--out-public", type=Path, required=True)
    parser.add_argument("--key-dir", type=Path, required=True)
    args = parser.parse_args()

    base = load_json(args.policy_in)
    support = load_json(args.support)
    plan = load_json(args.plan)
    if not isinstance(base, dict) or not isinstance(support, dict) or not isinstance(
        plan, dict
    ):
        fail("inputs must be JSON objects")

    if args.key_dir.exists():
        shutil.rmtree(args.key_dir)
    private_key, public_key = generate_key(args.key_dir)
    public_key_base64 = base64.b64encode(public_key).decode("ascii")
    policy = update_policy(base, public_key_base64)
    registry = build_registry(plan, policy, support, private_key, args.key_dir)
    write_public(args.out_policy, policy)
    write_public(args.out_registry, registry)
    write_public_pem(private_key, args.key_dir, args.out_public)
    shutil.rmtree(args.key_dir)
    if args.key_dir.exists():
        fail("private key directory was not removed")
    print(f"policy version: {policy['version']}")
    print(f"registry entries: {len(registry['entries'])}")
    print(f"registry sha256: {sha256_bytes(canonical_json(registry))}")
    print("private key discarded: true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
