#!/usr/bin/env python3
"""Independent correction/revocation registry verifier and controls.

This verifier uses the OpenSSL CLI and the Python standard library only. It
does not import or execute the Rust implementation. It checks the append-only
sequence and hash chain, the DSSE Ed25519 signatures over the exact PAE bytes,
the correction-authority role, signature and policy freshness, duplicate
targets, the recorded historical verdict, and the present founded-support
states.

Exit statuses: 0 verified and all controls passed, 3 integrity failure, 4 refused.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

SPEC = "frf-etp-v1"
ENTRY_SCHEMA = "frf-etp.revocation-entry.v1"
REGISTRY_SCHEMA = "frf-etp.revocation-registry.v1"
PAYLOAD_TYPE = "application/vnd.frf-etp.revocation+json"
CORRECTION_ROLE = "correction_authority"
ED25519_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")


class VerifierError(Exception):
    pass


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise VerifierError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load(path: Path) -> object:
    try:
        return json.loads(path.read_text(), object_pairs_hook=strict_object)
    except FileNotFoundError as error:
        raise VerifierError(f"missing input {path}") from error
    except json.JSONDecodeError as error:
        raise VerifierError(f"invalid JSON in {path}: {error}") from error


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


def run_openssl(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(args, check=False, capture_output=True)
    except FileNotFoundError as error:
        raise VerifierError(f"openssl is unavailable: {error}") from error


def openssl_verify(public_key: bytes, message: bytes, signature: bytes, work: Path) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    der = work / "public.der"
    msg = work / "message.bin"
    sig = work / "signature.bin"
    der.write_bytes(ED25519_DER_PREFIX + public_key)
    msg.write_bytes(message)
    sig.write_bytes(signature)
    result = run_openssl(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(der),
            "-keyform",
            "DER",
            "-rawin",
            "-in",
            str(msg),
            "-sigfile",
            str(sig),
        ]
    )
    return result.returncode == 0


def resolve(policy: dict[str, object], keyid: str) -> tuple[dict[str, object], dict[str, object]] | None:
    roles = policy.get("roles")
    if not isinstance(roles, list):
        return None
    for role in roles:
        if not isinstance(role, dict):
            continue
        keys = role.get("keys")
        if not isinstance(keys, list):
            continue
        for key in keys:
            if isinstance(key, dict) and key.get("keyid") == keyid:
                return role, key
    return None


def fixed_point(rules: dict[str, list[list[str]]], admitted: set[str], excluded: set[str]) -> set[str]:
    supported: set[str] = {claim for claim in admitted if claim not in excluded}
    changed = True
    while changed:
        changed = False
        for claim, alternatives in rules.items():
            if claim in supported or claim in excluded:
                continue
            for premises in alternatives:
                if all(premise in supported for premise in premises):
                    supported.add(claim)
                    changed = True
                    break
    return supported


def evaluate(
    support: dict[str, object], revoked: set[str], challenged: set[str]
) -> tuple[set[str], set[str]]:
    policy = support.get("policy")
    if not isinstance(policy, dict):
        raise VerifierError("support model has no policy object")
    rules_obj = policy.get("rules")
    if not isinstance(rules_obj, dict):
        raise VerifierError("support policy has no rules object")
    rules = rules_obj.get("rules")
    admitted = rules_obj.get("admitted_leaves")
    if not isinstance(rules, dict) or not isinstance(admitted, list):
        raise VerifierError("support policy rules are malformed")
    normalized: dict[str, list[list[str]]] = {}
    for claim, alternatives in rules.items():
        if not isinstance(claim, str) or not isinstance(alternatives, list):
            raise VerifierError("support policy rule is malformed")
        normalized[claim] = [
            [str(premise) for premise in premises] for premises in alternatives
        ]
    positive = fixed_point(normalized, {str(value) for value in admitted}, revoked)
    admissible = fixed_point(
        normalized, {str(value) for value in admitted}, revoked | challenged
    )
    return positive, admissible


def verify_registry(
    registry: dict[str, object],
    policy: dict[str, object],
    support: dict[str, object],
    historical: dict[str, object],
    now: int,
    work: Path,
    override_policy: dict[str, object] | None = None,
) -> dict[str, object]:
    errors: list[str] = []
    if registry.get("schema") != REGISTRY_SCHEMA:
        return {"status": "integrity_failure", "errors": ["registry_schema"]}
    if registry.get("spec") != SPEC:
        return {"status": "integrity_failure", "errors": ["registry_spec"]}
    active_policy = override_policy or policy
    policy_id = active_policy.get("policy_id")
    policy_version = active_policy.get("version")
    if registry.get("policy_id") != policy_id or registry.get("policy_version") != policy_version:
        errors.append("policy_mismatch")
    expires = active_policy.get("expires_at_unix")
    if not isinstance(expires, int) or now > expires:
        errors.append("stale_policy")
    entries = registry.get("entries")
    if not isinstance(entries, list) or not entries:
        return {"status": "integrity_failure", "errors": ["missing_entries"]}
    previous: str | None = None
    applied: list[dict[str, object]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    correction_role = None
    roles = active_policy.get("roles")
    if isinstance(roles, list):
        for role in roles:
            if isinstance(role, dict) and role.get("id") == CORRECTION_ROLE:
                correction_role = role
                break
    for index, envelope in enumerate(entries, start=1):
        if not isinstance(envelope, dict):
            return {"status": "integrity_failure", "errors": ["entry_not_object"]}
        if envelope.get("payloadType") != PAYLOAD_TYPE:
            return {"status": "integrity_failure", "errors": ["entry_payload_type"]}
        payload_b64 = envelope.get("payload")
        signatures = envelope.get("signatures")
        if not isinstance(payload_b64, str) or not isinstance(signatures, list):
            return {"status": "integrity_failure", "errors": ["entry_shape"]}
        try:
            payload = base64.b64decode(payload_b64, validate=True)
        except ValueError as error:
            return {"status": "integrity_failure", "errors": [f"entry_base64: {error}"]}
        if base64.b64encode(payload).decode("ascii") != payload_b64:
            return {"status": "integrity_failure", "errors": ["entry_base64_noncanonical"]}
        try:
            entry = json.loads(payload, object_pairs_hook=strict_object)
        except json.JSONDecodeError as error:
            return {"status": "integrity_failure", "errors": [f"entry_json: {error}"]}
        if not isinstance(entry, dict):
            return {"status": "integrity_failure", "errors": ["entry_not_dict"]}
        if entry.get("schema") != ENTRY_SCHEMA or entry.get("spec") != SPEC:
            return {"status": "integrity_failure", "errors": ["entry_schema"]}
        if entry.get("sequence") != index:
            return {"status": "integrity_failure", "errors": ["sequence_mismatch"]}
        if entry.get("previous_entry_sha256") != previous:
            return {"status": "integrity_failure", "errors": ["chain_mismatch"]}
        previous = sha256_bytes(canonical_json(envelope))
        if entry.get("registry_id") != registry.get("registry_id"):
            errors.append("replayed_revocation")
        if (
            entry.get("policy_id") != registry.get("policy_id")
            or entry.get("policy_version") != registry.get("policy_version")
        ):
            errors.append("replayed_revocation")
        authorized_actors: set[str] = set()
        for signature in signatures:
            if not isinstance(signature, dict):
                errors.append("invalid_signature")
                continue
            keyid = signature.get("keyid")
            sig_b64 = signature.get("sig")
            resolved = resolve(active_policy, str(keyid))
            if resolved is None or not isinstance(sig_b64, str):
                errors.append("unknown_key")
                continue
            role, key = resolved
            if role.get("id") != CORRECTION_ROLE:
                errors.append("unauthorized_role")
                continue
            try:
                public_key = base64.b64decode(str(key.get("public_key_base64")), validate=True)
                signature_bytes = base64.b64decode(sig_b64, validate=True)
            except ValueError:
                errors.append("invalid_signature")
                continue
            if not openssl_verify(
                public_key, pae(PAYLOAD_TYPE, payload), signature_bytes, work
            ):
                errors.append("invalid_signature")
                continue
            not_before = key.get("not_before_unix")
            not_after = key.get("not_after_unix")
            if not isinstance(not_before, int) or not isinstance(not_after, int) or not (
                not_before <= now <= not_after
            ):
                errors.append("expired_credential")
                continue
            authorized_actors.add(str(key.get("actor")))
        if correction_role is None or len(authorized_actors) < int(
            correction_role.get("threshold", 1)
        ):
            errors.append("insufficient_authority")
            continue
        target = entry.get("target")
        if not isinstance(target, dict):
            errors.append("missing_target")
            continue
        action = entry.get("action")
        if action == "revoke":
            key = (
                str(target.get("claim_id")),
                tuple(sorted(str(value) for value in target.get("evidence_ids", []))),
            )
            if key in seen:
                errors.append("duplicate_revocation")
            seen.add(key)
            applied.append(entry)
        elif action == "correct":
            pass
        elif action == "dissent":
            pass
        else:
            errors.append("unsupported_action")

    if errors:
        return {"status": "refused", "errors": sorted(set(errors))}

    recorded_revoked = {str(value) for value in historical.get("revoked", [])}
    recorded_challenged = {str(value) for value in historical.get("challenged", [])}
    historical_positive, historical_admissible = evaluate(
        support, recorded_revoked, recorded_challenged
    )
    result = historical.get("result")
    if not isinstance(result, dict):
        return {"status": "refused", "errors": ["historical_missing_result"]}
    if sorted(result.get("positive", [])) != sorted(historical_positive):
        return {"status": "refused", "errors": ["historical_replay_mismatch"]}
    if sorted(result.get("admissible", [])) != sorted(historical_admissible):
        return {"status": "refused", "errors": ["historical_replay_mismatch"]}

    present_revoked: set[str] = set()
    for entry in applied:
        target = entry["target"]
        evidence = [str(value) for value in target.get("evidence_ids", [])]
        if not evidence:
            present_revoked.add(str(target.get("claim_id")))
        else:
            present_revoked.update(evidence)
    claims = support.get("claims")
    present_challenged: set[str] = set()
    if isinstance(claims, list):
        for claim in claims:
            if not isinstance(claim, dict):
                continue
            for record in claim.get("contradictory", []):
                if isinstance(record, dict) and record.get("resolution") == "unresolved":
                    present_challenged.add(str(claim.get("id")))
    present_positive, present_admissible = evaluate(
        support, present_revoked, present_challenged
    )
    target_claim = "claim.campaign-closure"
    stale_support = False
    not_after = support.get("not_after_unix")
    if not isinstance(not_after, int) or now > not_after:
        stale_support = True
    return {
        "status": "verified",
        "errors": [],
        "entry_count": len(entries),
        "applied_revocations": len(applied),
        "historical_positive": sorted(historical_positive),
        "present_positive": sorted(present_positive),
        "present_admissible": sorted(present_admissible),
        "target_claim": target_claim,
        "target_historically_supported": target_claim in historical_positive,
        "target_present_supported": target_claim in present_positive,
        "alternative_present_supported": "claim.campaign-closure-with-mirror"
        in present_positive,
        "stale_support_policy": stale_support,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--support", type=Path, required=True)
    parser.add_argument("--historical", type=Path, required=True)
    parser.add_argument("--now", type=int, default=1795330364)
    parser.add_argument("--controls", action="store_true")
    args = parser.parse_args()

    registry = load(args.registry)
    policy = load(args.policy)
    support = load(args.support)
    historical = load(args.historical)
    if not all(
        isinstance(value, dict)
        for value in [registry, policy, support, historical]
    ):
        raise VerifierError("inputs must be JSON objects")

    with tempfile.TemporaryDirectory(prefix="etp-revocation-verify-") as temporary:
        work = Path(temporary)
        result = verify_registry(
            registry, policy, support, historical, args.now, work
        )
        print(
            f"revocation: {result['status']}; entries={result.get('entry_count')}; "
            f"errors={result.get('errors')}"
        )
        if not args.controls:
            if result["status"] == "integrity_failure":
                return 3
            return 0 if result["status"] == "verified" else 4

        passed = 0
        total = 0
        total += 1
        ok = result["status"] == "verified"
        print(f"{'PASS' if ok else 'FAIL'} control valid registry")
        passed += 1 if ok else 0

        total += 1
        stale = verify_registry(
            registry, policy, support, historical, args.now + 10 * 365 * 24 * 60 * 60, work
        )
        ok = stale["status"] == "refused" and "stale_policy" in stale["errors"]
        print(f"{'PASS' if ok else 'FAIL'} control stale policy")
        passed += 1 if ok else 0

        total += 1
        empty_policy = json.loads(json.dumps(policy))
        for role in empty_policy.get("roles", []):
            if isinstance(role, dict) and role.get("id") == CORRECTION_ROLE:
                role["keys"] = []
        unauthorized = verify_registry(
            registry,
            policy,
            support,
            historical,
            args.now,
            work,
            override_policy=empty_policy,
        )
        ok = unauthorized["status"] == "refused" and "insufficient_authority" in unauthorized[
            "errors"
        ]
        print(f"{'PASS' if ok else 'FAIL'} control unauthorized revocation signer")
        passed += 1 if ok else 0

        total += 1
        tampered = json.loads(json.dumps(registry))
        entries = tampered.get("entries", [])
        if entries:
            payload = base64.b64decode(entries[-1]["payload"])
            parsed = json.loads(payload)
            parsed["target"]["claim_id"] = "claim.tampered"
            entries[-1]["payload"] = base64.b64encode(
                canonical_json(parsed)
            ).decode("ascii")
        tampered_result = verify_registry(
            tampered, policy, support, historical, args.now, work
        )
        ok = tampered_result["status"] == "refused" and "invalid_signature" in tampered_result[
            "errors"
        ]
        print(f"{'PASS' if ok else 'FAIL'} control tampered entry")
        passed += 1 if ok else 0

        total += 1
        replay = json.loads(json.dumps(registry))
        replay["registry_id"] = "another-registry"
        replay_result = verify_registry(
            replay, policy, support, historical, args.now, work
        )
        ok = replay_result["status"] == "refused" and "replayed_revocation" in replay_result[
            "errors"
        ]
        print(f"{'PASS' if ok else 'FAIL'} control replayed revocation")
        passed += 1 if ok else 0

        total += 1
        ok = (
            result["status"] == "verified"
            and result.get("target_historically_supported") is True
            and result.get("target_present_supported") is False
            and result.get("alternative_present_supported") is True
        )
        print(f"{'PASS' if ok else 'FAIL'} control revoked but historically valid")
        passed += 1 if ok else 0

        print(f"controls passed: {passed} of {total}")
        return 0 if passed == total else 4


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerifierError as error:
        print(f"verify_revocation: {error}", file=sys.stderr)
        raise SystemExit(3) from error
