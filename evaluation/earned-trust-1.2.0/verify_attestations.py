#!/usr/bin/env python3
"""Independent ETP attestation verifier.

This verifier is deliberately separate from the Rust implementation. It parses
the DSSE envelope, recomputes the pre-authentication encoding from the exact
received payload bytes, verifies Ed25519 signatures with the OpenSSL CLI,
re-derives the finite campaign facts from the committed closure and receipts, and
enforces the trust-policy roles, actors, scope, expiry, and independence
thresholds.

It does not import or execute the crate. It uses only the Python standard
library and the OpenSSL CLI available in ``python:3.11-slim``.

Exit statuses: 0 accepted and all controls passed, 3 integrity failure,
4 refused.

Non-claims: a valid signature is not truth; authentication is not independent
review; inclusion is not completeness. No transparency log or trusted timestamp
is consulted.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
TRUST_POLICY_SCHEMA = "frf-etp.trust-policy.v1"
SPEC = "frf-etp-v1"
MAX_SIGNATURES = 16
MAX_PAYLOAD_BYTES = 1024 * 1024
MAX_KEYID_BYTES = 256
ED25519_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")

PREDICATE_TYPES = {
    "https://frf.dev/etp/campaign-closure/v1": (
        "frf-etp.predicate.campaign-closure.v1",
        "evidence_producer",
        "closure",
    ),
    "https://frf.dev/etp/instrument-qualification/v1": (
        "frf-etp.predicate.instrument-qualification.v1",
        "instrument_qualifier",
        "generic",
    ),
    "https://frf.dev/etp/reproduction/v1": (
        "frf-etp.predicate.reproduction.v1",
        "instrument_qualifier",
        "generic",
    ),
    "https://frf.dev/etp/proof-admission/v1": (
        "frf-etp.predicate.proof-admission.v1",
        "adjudicator",
        "generic",
    ),
    "https://frf.dev/etp/consumer-closure/v1": (
        "frf-etp.predicate.consumer-closure.v1",
        "evidence_producer",
        "generic",
    ),
    "https://frf.dev/etp/security-findings/v1": (
        "frf-etp.predicate.security-findings.v1",
        "evidence_producer",
        "generic",
    ),
    "https://frf.dev/etp/release-adjudication/v1": (
        "frf-etp.predicate.release-adjudication.v1",
        "release_authority",
        "generic",
    ),
}

SCOPE_CLOSURE = "https://frf.dev/etp/campaign-closure/v1"
SCOPE_RELEASE = "https://frf.dev/etp/release-adjudication/v1"


class IntegrityError(Exception):
    """Structural integrity failure (exit 3)."""


class Refused(Exception):
    """Semantic or authorization refusal with named codes."""

    def __init__(self, codes: list[tuple[str, str]]) -> None:
        super().__init__(", ".join(code for code, _ in codes))
        self.codes = codes


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_sha256_hex(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    if not payload_type or any(character.isspace() for character in payload_type):
        raise IntegrityError("payloadType is empty or contains whitespace")
    if len(type_bytes) > MAX_KEYID_BYTES:
        raise IntegrityError("payloadType is too long")
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


def decode_base64_canonical(label: str, value: object) -> bytes:
    if not isinstance(value, str):
        raise IntegrityError(f"{label} is not a string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as error:  # noqa: BLE001 - convert every decode failure
        raise IntegrityError(f"{label} is not valid base64: {error}") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise IntegrityError(f"{label} is not canonical padded base64")
    return decoded


def check_text(label: str, value: object, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IntegrityError(f"{label} must be a non-empty string")
    if len(value.encode("utf-8")) > limit:
        raise IntegrityError(f"{label} exceeds {limit} bytes")
    return value


def run_openssl(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(args, check=False, capture_output=True)
    except FileNotFoundError as error:
        raise IntegrityError(f"openssl is unavailable: {error}") from error


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


def generate_key(work: Path) -> tuple[Path, bytes]:
    key_dir = Path(tempfile.mkdtemp(prefix="key-", dir=work))
    private_key = key_dir / "ed25519-private.pem"
    public_der = key_dir / "ed25519-public.der"
    result = run_openssl(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)]
    )
    if result.returncode != 0:
        raise IntegrityError("cannot generate an ephemeral Ed25519 key")
    result = run_openssl(
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
    if result.returncode != 0:
        raise IntegrityError("cannot derive an Ed25519 public key")
    der = public_der.read_bytes()
    if len(der) != 44 or not der.startswith(ED25519_DER_PREFIX):
        raise IntegrityError("unexpected Ed25519 SubjectPublicKeyInfo encoding")
    return private_key, der[len(ED25519_DER_PREFIX) :]


def sign_message(private_key: Path, message: bytes, work: Path) -> bytes:
    msg = work / "to-sign.bin"
    sig = work / "to-sign.sig"
    msg.write_bytes(message)
    result = run_openssl(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-inkey",
            str(private_key),
            "-rawin",
            "-in",
            str(msg),
            "-out",
            str(sig),
        ]
    )
    if result.returncode != 0:
        raise IntegrityError("cannot sign the test message")
    signature = sig.read_bytes()
    if len(signature) != 64:
        raise IntegrityError("unexpected Ed25519 signature length")
    return signature


def parse_policy(policy: object) -> dict[str, object]:
    if not isinstance(policy, dict):
        raise IntegrityError("policy is not an object")
    if policy.get("schema") != TRUST_POLICY_SCHEMA:
        raise IntegrityError("unsupported trust-policy schema")
    if policy.get("spec") != SPEC:
        raise IntegrityError("unsupported trust-policy spec")
    check_text("policy_id", policy.get("policy_id"), 4096)
    version = policy.get("version")
    if not isinstance(version, int) or version <= 0:
        raise IntegrityError("policy version must be a positive integer")
    issued = policy.get("issued_at_unix")
    expires = policy.get("expires_at_unix")
    if not isinstance(issued, int) or not isinstance(expires, int) or issued >= expires:
        raise IntegrityError("policy validity window is invalid")
    roles = policy.get("roles")
    if not isinstance(roles, list) or not roles:
        raise IntegrityError("policy has no roles")
    known_roles = {
        "evidence_producer",
        "instrument_qualifier",
        "adjudicator",
        "release_authority",
        "correction_authority",
    }
    role_ids: set[str] = set()
    keyids: set[str] = set()
    public_keys: set[bytes] = set()
    for role in roles:
        if not isinstance(role, dict):
            raise IntegrityError("role is not an object")
        role_id = role.get("id")
        if role_id not in known_roles:
            raise IntegrityError(f"unsupported role {role_id!r}")
        if role_id in role_ids:
            raise IntegrityError(f"duplicate role {role_id!r}")
        role_ids.add(role_id)
        threshold = role.get("threshold")
        if not isinstance(threshold, int) or threshold <= 0:
            raise IntegrityError(f"role {role_id!r} has an invalid threshold")
        if not isinstance(role.get("independent"), bool):
            raise IntegrityError(f"role {role_id!r} has no independent flag")
        scope = role.get("scope")
        if not isinstance(scope, list) or not scope:
            raise IntegrityError(f"role {role_id!r} has an empty scope")
        for predicate_type in scope:
            if predicate_type not in PREDICATE_TYPES:
                raise IntegrityError(f"role {role_id!r} names an unsupported predicate")
        keys = role.get("keys")
        if not isinstance(keys, list):
            raise IntegrityError(f"role {role_id!r} keys is not a list")
        for key in keys:
            if not isinstance(key, dict):
                raise IntegrityError("key is not an object")
            keyid = check_text("keyid", key.get("keyid"), MAX_KEYID_BYTES)
            if keyid in keyids:
                raise IntegrityError(f"duplicate keyid {keyid!r}")
            keyids.add(keyid)
            if key.get("algorithm") != "ed25519":
                raise IntegrityError(f"key {keyid!r} does not use ed25519")
            actor = check_text("actor", key.get("actor"), 4096)
            del actor
            public_key = decode_base64_canonical("public key", key.get("public_key_base64"))
            if len(public_key) != 32:
                raise IntegrityError(f"public key {keyid!r} is not 32 bytes")
            if public_key in public_keys:
                raise IntegrityError(f"duplicate public key material for {keyid!r}")
            public_keys.add(public_key)
            not_before = key.get("not_before_unix")
            not_after = key.get("not_after_unix")
            if (
                not isinstance(not_before, int)
                or not isinstance(not_after, int)
                or not_before > not_after
            ):
                raise IntegrityError(f"key {keyid!r} has an invalid validity window")
    return policy


def resolve_key(policy: dict[str, object], keyid: str) -> tuple[dict[str, object], dict[str, object]] | None:
    for role in policy["roles"]:
        for key in role["keys"]:
            if key["keyid"] == keyid:
                return role, key
    return None


def parse_envelope(envelope: object) -> dict[str, object]:
    if not isinstance(envelope, dict):
        raise IntegrityError("envelope is not an object")
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        raise IntegrityError("unsupported payloadType")
    payload = decode_base64_canonical("payload", envelope.get("payload"))
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise IntegrityError("decoded payload is too large")
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise IntegrityError("envelope has no signatures")
    if len(signatures) > MAX_SIGNATURES:
        raise IntegrityError("envelope has too many signatures")
    keyids: set[str] = set()
    for signature in signatures:
        if not isinstance(signature, dict):
            raise IntegrityError("signature is not an object")
        keyid = check_text("signature keyid", signature.get("keyid"), MAX_KEYID_BYTES)
        if keyid in keyids:
            raise IntegrityError(f"duplicate signature keyid {keyid!r}")
        keyids.add(keyid)
        raw = decode_base64_canonical("signature", signature.get("sig"))
        if len(raw) != 64:
            raise IntegrityError(f"signature for {keyid!r} is not 64 bytes")
    return envelope


def parse_statement(payload: bytes) -> dict[str, object]:
    try:
        statement = json.loads(payload)
    except Exception as error:  # noqa: BLE001 - any parse failure is integrity
        raise IntegrityError(f"payload is not JSON: {error}") from error
    if not isinstance(statement, dict):
        raise IntegrityError("statement is not an object")
    if statement.get("_type") != STATEMENT_TYPE:
        raise IntegrityError("unsupported statement _type")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise IntegrityError("statement has no subject")
    for subject in subjects:
        if not isinstance(subject, dict):
            raise IntegrityError("subject is not an object")
        check_text("subject name", subject.get("name"), 4096)
        digest = subject.get("digest")
        if not isinstance(digest, dict) or not digest:
            raise IntegrityError("subject has no digest")
        for algorithm, value in digest.items():
            if algorithm != "sha256" or not is_sha256_hex(value):
                raise IntegrityError("subject digest is not a lowercase sha256")
    predicate_type = statement.get("predicateType")
    if predicate_type not in PREDICATE_TYPES:
        raise IntegrityError(f"unsupported predicateType {predicate_type!r}")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise IntegrityError("predicate is not an object")
    schema = PREDICATE_TYPES[predicate_type][0]
    if predicate.get("schema") != schema or predicate.get("spec") != SPEC:
        raise IntegrityError("predicate schema or spec is unsupported")
    return statement


def recompute_campaign(campaign_path: Path) -> dict[str, object]:
    base = campaign_path.parent
    closure_bytes = campaign_path.read_bytes()
    closure = json.loads(closure_bytes)
    opening_path = base / closure["opening_manifest_path"]
    opening_bytes = opening_path.read_bytes()
    if sha256_bytes(opening_bytes) != closure["opening_sha256"]:
        raise IntegrityError("opening manifest digest does not match the closure")
    protocol = json.loads(opening_bytes)

    receipt_files: dict[str, bytes] = {}
    for path in sorted((base / "receipts").glob("*.json")):
        receipt_files[f"receipts/{path.name}"] = path.read_bytes()
    raw_files: dict[str, bytes] = {}
    raw_dir = base / "receipts" / "raw"
    if raw_dir.is_dir():
        for path in sorted(raw_dir.rglob("*")):
            if path.is_file():
                raw_files[f"receipts/raw/{path.relative_to(raw_dir).as_posix()}"] = path.read_bytes()

    outcomes: Counter[str] = Counter()
    decisions: Counter[str] = Counter()
    case_ids: list[str] = []
    referenced: set[str] = set()
    for reference in closure["receipts"]:
        relative = reference["path"]
        if relative in referenced:
            raise IntegrityError(f"duplicate closure reference {relative}")
        referenced.add(relative)
        if relative not in receipt_files:
            raise IntegrityError(f"missing receipt {relative}")
        receipt_bytes = receipt_files[relative]
        if sha256_bytes(receipt_bytes) != reference["sha256"]:
            raise IntegrityError(f"receipt digest mismatch for {relative}")
        receipt = json.loads(receipt_bytes)
        if receipt["case_id"] != reference["case_id"]:
            raise IntegrityError(f"receipt case mismatch for {relative}")
        if receipt["observation"]["outcome"] != reference["outcome"]:
            raise IntegrityError(f"receipt outcome mismatch for {relative}")
        if receipt["adjudication"]["decision"] != reference["decision"]:
            raise IntegrityError(f"receipt decision mismatch for {relative}")
        if receipt["candidate_identity"] != closure["candidate_identity"]:
            raise IntegrityError(f"receipt candidate mismatch for {relative}")
        case_ids.append(receipt["case_id"])
        outcomes[receipt["observation"]["outcome"]] += 1
        decisions[receipt["adjudication"]["decision"]] += 1

    population = [case["id"] for case in protocol["population"]]
    if sorted(population) != sorted(case_ids):
        raise IntegrityError("receipts do not cover the declared population")
    if len(receipt_files) != len(referenced):
        raise IntegrityError("unreferenced receipt present")

    hasher = hashlib.sha256()
    hasher.update(b"frf-etp.campaign-evidence-root.v1\n")
    for path in sorted(list(receipt_files) + list(raw_files), key=lambda value: value.encode("utf-8")):
        data = receipt_files.get(path, raw_files.get(path))
        assert data is not None
        hasher.update(path.encode("utf-8"))
        hasher.update(b"\x00")
        hasher.update(sha256_bytes(data).encode("ascii"))
        hasher.update(b"\n")

    if {item["label"]: item["count"] for item in closure["outcomes"]} != dict(outcomes):
        raise IntegrityError("closure outcomes disagree with receipts")
    if {item["label"]: item["count"] for item in closure["decisions"]} != dict(decisions):
        raise IntegrityError("closure decisions disagree with receipts")
    if closure["case_count"] != len(case_ids) or closure["receipt_count"] != len(receipt_files):
        raise IntegrityError("closure counts disagree with receipts")
    if closure["raw_evidence_count"] != len(raw_files):
        raise IntegrityError("closure raw-evidence count disagrees with the directory")

    return {
        "campaign_id": closure["campaign_id"],
        "closure_sha256": sha256_bytes(closure_bytes),
        "candidate_identity": closure["candidate_identity"],
        "evidence_root_sha256": hasher.hexdigest(),
        "case_ids": sorted(case_ids),
        "case_count": len(case_ids),
        "receipt_count": len(receipt_files),
        "raw_evidence_count": len(raw_files),
        "outcomes": [{"label": label, "count": count} for label, count in sorted(outcomes.items())],
        "decisions": [
            {"label": label, "count": count} for label, count in sorted(decisions.items())
        ],
        "closure_status": closure["closure_status"],
        "acceptance": closure["acceptance"],
        "conclusion": derive_conclusion(closure["closure_status"], closure["acceptance"]),
        "claim_ceiling": closure["claim_ceiling"],
    }


def derive_conclusion(closure_status: str, acceptance: str) -> str:
    if closure_status == "closed" and acceptance == "accepted":
        return "accepted"
    if closure_status == "blocked":
        return "blocked"
    return "withheld"


def subject_digest(statement: dict[str, object], name: str) -> str | None:
    for subject in statement["subject"]:
        if subject["name"] == name:
            return subject["digest"].get("sha256")
    return None


def counts_map(items: object) -> dict[str, int]:
    if not isinstance(items, list):
        raise IntegrityError("predicate counts are not a list")
    result: dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("label"), str):
            raise IntegrityError("predicate count entry is malformed")
        count = item.get("count")
        if not isinstance(count, int) or count < 0:
            raise IntegrityError("predicate count is malformed")
        result[item["label"]] = count
    return result


def evaluate(
    envelope: object,
    policy: dict[str, object],
    campaign: dict[str, object] | None,
    now_unix: int,
    work: Path,
    *,
    skip_signature_check: bool = False,
) -> dict[str, object]:
    policy = parse_policy(policy)
    envelope = parse_envelope(envelope)
    payload = decode_base64_canonical("payload", envelope["payload"])
    message = pae(envelope["payloadType"], payload)
    refusals: list[tuple[str, str]] = []
    signatures_report: list[dict[str, object]] = []

    policy_fresh = policy["issued_at_unix"] <= now_unix <= policy["expires_at_unix"]
    valid_count = 0
    expired_used = False
    for signature in envelope["signatures"]:
        keyid = signature["keyid"]
        raw_signature = decode_base64_canonical("signature", signature["sig"])
        resolved = resolve_key(policy, keyid)
        if resolved is None:
            signatures_report.append({"keyid": keyid, "valid": False, "actor": None, "roles": []})
            refusals.append(("unknown_key", f"keyid {keyid!r} is not in the policy"))
            continue
        role, key = resolved
        if key["algorithm"] != "ed25519":
            signatures_report.append(
                {"keyid": keyid, "valid": False, "actor": key["actor"], "roles": [role["id"]]}
            )
            refusals.append(("unsupported_algorithm", f"key {keyid!r} is not ed25519"))
            continue
        public_key = decode_base64_canonical("public key", key["public_key_base64"])
        valid = (
            True
            if skip_signature_check
            else openssl_verify(public_key, message, raw_signature, work)
        )
        key_fresh = key["not_before_unix"] <= now_unix <= key["not_after_unix"]
        if valid and not key_fresh:
            expired_used = True
        if valid:
            valid_count += 1
        signatures_report.append(
            {
                "keyid": keyid,
                "valid": valid,
                "actor": key["actor"],
                "roles": [role["id"]],
            }
        )
        if not valid:
            refusals.append(("invalid_signature", f"signature for {keyid!r} does not verify"))

    signature_state = (
        "invalid" if valid_count == 0 else "valid" if valid_count == len(envelope["signatures"]) else "partial"
    )
    statement = parse_statement(payload)
    predicate_type = statement["predicateType"]
    predicate = statement["predicate"]
    _, required_role, kind = PREDICATE_TYPES[predicate_type]

    if not policy_fresh:
        refusals.append(("expired_credential", "policy is outside its validity window"))
    if expired_used:
        refusals.append(("expired_credential", "a verifying key is outside its validity window"))

    def authorized_actors(role_id: str, predicate: str) -> set[str]:
        actors: set[str] = set()
        for report in signatures_report:
            if not report["valid"]:
                continue
            resolved = resolve_key(policy, report["keyid"])
            assert resolved is not None
            role, key = resolved
            if role["id"] != role_id or predicate not in role["scope"]:
                continue
            if not (key["not_before_unix"] <= now_unix <= key["not_after_unix"]):
                continue
            actors.add(key["actor"])
        return actors

    role = next((item for item in policy["roles"] if item["id"] == required_role), None)
    threshold = role["threshold"] if role is not None else 1
    if len(authorized_actors(required_role, predicate_type)) < max(threshold, 1):
        refusals.append(
            ("unauthorized_role", f"no fresh authorized actor satisfied role {required_role!r}")
        )

    independent_role = next((item for item in policy["roles"] if item["independent"]), None)
    independent_reviewers = 0
    independent_ok = predicate.get("independent_review") != "established"
    if independent_role is not None:
        independent_reviewers = len(authorized_actors(independent_role["id"], predicate_type))
        established = independent_reviewers >= max(independent_role["threshold"], 1)
        independent_ok = established or predicate.get("independent_review") != "established"
        if predicate.get("independent_review") == "established" and not established:
            refusals.append(
                (
                    "insufficient_independent_review",
                    f"{independent_reviewers} distinct authorized actors < {independent_role['threshold']}",
                )
            )
    elif predicate.get("independent_review") == "established":
        refusals.append(("insufficient_independent_review", "policy has no independent-review role"))

    semantic_state = "not_checked"
    scope_state = "invalid"
    if campaign is not None and kind == "closure":
        scope_state = "valid"
        semantic_ok = True
        if predicate.get("campaign_id") != campaign["campaign_id"]:
            refusals.append(("campaign_mismatch", "predicate campaign does not match"))
            semantic_ok = False
        if predicate.get("closure_sha256") != campaign["closure_sha256"]:
            refusals.append(("subject_mismatch", "predicate closure digest does not match"))
            semantic_ok = False
        if predicate.get("candidate_identity") != campaign["candidate_identity"]:
            refusals.append(("candidate_mismatch", "predicate candidate does not match"))
            semantic_ok = False
        if predicate.get("raw_evidence_sha256") != campaign["evidence_root_sha256"]:
            refusals.append(("evidence_mismatch", "predicate evidence digest does not match"))
            semantic_ok = False
        if (
            predicate.get("case_count") != campaign["case_count"]
            or predicate.get("receipt_count") != campaign["receipt_count"]
            or predicate.get("raw_evidence_count") != campaign["raw_evidence_count"]
        ):
            refusals.append(("count_mismatch", "predicate counts do not match"))
            semantic_ok = False
        if sorted(predicate.get("case_ids") or []) != campaign["case_ids"]:
            refusals.append(("population_mismatch", "predicate population does not match"))
            semantic_ok = False
        if counts_map(predicate.get("outcomes")) != counts_map(campaign["outcomes"]):
            refusals.append(("outcome_mismatch", "predicate outcomes do not match"))
            semantic_ok = False
        if counts_map(predicate.get("decisions")) != counts_map(campaign["decisions"]):
            refusals.append(("outcome_mismatch", "predicate decisions do not match"))
            semantic_ok = False
        if (
            predicate.get("closure_status") != campaign["closure_status"]
            or predicate.get("acceptance") != campaign["acceptance"]
        ):
            refusals.append(("outcome_mismatch", "predicate closure status or acceptance does not match"))
            semantic_ok = False
        if predicate.get("conclusion") != campaign["conclusion"]:
            refusals.append(("false_conclusion", "predicate conclusion is not derived"))
            semantic_ok = False
        if predicate.get("claim_ceiling") != campaign["claim_ceiling"]:
            refusals.append(("claim_ceiling_mismatch", "predicate claim ceiling does not match"))
            semantic_ok = False
        if subject_digest(statement, f"campaign-closure:{campaign['campaign_id']}") != campaign[
            "closure_sha256"
        ]:
            refusals.append(("subject_mismatch", "campaign-closure subject does not match"))
            semantic_ok = False
        if subject_digest(statement, f"candidate:{campaign['candidate_identity']}") != campaign[
            "candidate_identity"
        ]:
            refusals.append(("candidate_mismatch", "candidate subject does not match"))
            semantic_ok = False
        if subject_digest(statement, f"raw-evidence:{campaign['campaign_id']}") != campaign[
            "evidence_root_sha256"
        ]:
            refusals.append(("evidence_mismatch", "raw-evidence subject does not match"))
            semantic_ok = False
        semantic_state = "valid" if semantic_ok else "invalid"
    elif campaign is None:
        refusals.append(("semantic_support_not_evaluated", "no campaign supplied"))
    else:
        refusals.append(
            (
                "semantic_support_not_evaluated",
                "semantic evaluation is implemented only for campaign-closure predicates",
            )
        )

    accepted = (
        not refusals
        and signature_state == "valid"
        and semantic_state == "valid"
        and scope_state == "valid"
        and independent_ok
    )
    return {
        "status": "accepted" if accepted else "refused",
        "dimensions": {
            "signature_validity": signature_state,
            "payload_integrity": "valid",
            "authorization": "invalid"
            if any(code == "unauthorized_role" for code, _ in refusals)
            else "valid",
            "scope_applicability": scope_state,
            "freshness": "invalid"
            if any(code == "expired_credential" for code, _ in refusals)
            else "valid",
            "semantic_support": semantic_state,
            "independent_review": "established"
            if independent_role is not None
            and independent_reviewers >= max(independent_role["threshold"], 1)
            else "not_established",
        },
        "independent_reviewers": independent_reviewers,
        "signatures": signatures_report,
        "refusals": [{"code": code, "detail": detail} for code, detail in refusals],
    }


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_bytes())
    except Exception as error:  # noqa: BLE001 - report a single integrity error
        raise IntegrityError(f"cannot parse {path}: {error}") from error


def base_policy(
    keyid: str,
    public_key: bytes,
    actor: str,
    *,
    role_id: str = "evidence_producer",
    independent: bool = False,
    threshold: int = 1,
    not_before: int = 1795305600,
    not_after: int = 1826841600,
    extra_keys: list[tuple[str, bytes, str]] | None = None,
) -> dict[str, object]:
    roles = [
        {"id": "evidence_producer", "threshold": 1, "independent": False, "scope": [SCOPE_CLOSURE, "https://frf.dev/etp/consumer-closure/v1", "https://frf.dev/etp/security-findings/v1"], "keys": []},
        {"id": "instrument_qualifier", "threshold": 1, "independent": False, "scope": ["https://frf.dev/etp/instrument-qualification/v1", "https://frf.dev/etp/reproduction/v1"], "keys": []},
        {"id": "adjudicator", "threshold": 2, "independent": True, "scope": ["https://frf.dev/etp/proof-admission/v1", SCOPE_CLOSURE], "keys": []},
        {"id": "release_authority", "threshold": 1, "independent": False, "scope": [SCOPE_RELEASE], "keys": []},
        {"id": "correction_authority", "threshold": 1, "independent": False, "scope": [SCOPE_CLOSURE], "keys": []},
    ]
    key = {
        "keyid": keyid,
        "algorithm": "ed25519",
        "public_key_base64": base64.b64encode(public_key).decode("ascii"),
        "actor": actor,
        "not_before_unix": not_before,
        "not_after_unix": not_after,
    }
    for entry in roles:
        if entry["id"] == role_id:
            entry["keys"].append(key)
            entry["threshold"] = threshold
            entry["independent"] = independent
    for extra_keyid, extra_public, extra_actor in extra_keys or []:
        for entry in roles:
            if entry["id"] == role_id:
                entry["keys"].append(
                    {
                        "keyid": extra_keyid,
                        "algorithm": "ed25519",
                        "public_key_base64": base64.b64encode(extra_public).decode("ascii"),
                        "actor": extra_actor,
                        "not_before_unix": not_before,
                        "not_after_unix": not_after,
                    }
                )
    return {
        "schema": TRUST_POLICY_SCHEMA,
        "spec": SPEC,
        "policy_id": "frf-etp-control-policy",
        "version": 1,
        "issued_at_unix": 1795305600,
        "expires_at_unix": 1826841600,
        "roles": roles,
    }


def make_envelope(
    payload: bytes,
    keyid: str,
    private_key: Path,
    work: Path,
    *,
    payload_type: str = PAYLOAD_TYPE,
    malformed_pae: bool = False,
) -> dict[str, object]:
    message = (
        b"DSSEv1 29 " + payload_type.encode("utf-8") + b" 999 " + payload
        if malformed_pae
        else pae(payload_type, payload)
    )
    signature = sign_message(private_key, message, work)
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": keyid, "sig": base64.b64encode(signature).decode("ascii")}],
    }


def expect_refused(name: str, result: dict[str, object], required: str, controls: list[str]) -> None:
    codes = {entry["code"] for entry in result["refusals"]}
    if result["status"] != "refused" or required not in codes:
        raise IntegrityError(
            f"control {name!r} did not refuse with {required!r}: status={result['status']} codes={sorted(codes)}"
        )
    controls.append(name)


def run_controls(committed: dict[str, object], campaign: dict[str, object], work: Path) -> int:
    controls: list[str] = []
    base_envelope = committed["envelope"]
    payload = decode_base64_canonical("payload", base_envelope["payload"])
    now = 1795330364

    private_key, public_key = generate_key(work)
    policy = base_policy("control-key", public_key, "control-actor")
    envelope = make_envelope(payload, "control-key", private_key, work)
    accepted = evaluate(envelope, policy, campaign, now, work)
    if accepted["status"] != "accepted":
        raise IntegrityError(f"control valid attestation was not accepted: {accepted['refusals']}")
    controls.append("valid_attestation_accepted")

    tampered_statement = json.loads(payload)
    tampered_statement["predicate"]["case_count"] += 1
    tampered_payload = canonical_json(tampered_statement)
    tampered_envelope = {
        "payloadType": base_envelope["payloadType"],
        "payload": base64.b64encode(tampered_payload).decode("ascii"),
        "signatures": envelope["signatures"],
    }
    result = evaluate(tampered_envelope, policy, campaign, now, work)
    expect_refused("tampered_payload", result, "invalid_signature", controls)

    _, wrong_public = generate_key(work)
    wrong_policy = base_policy("control-key", wrong_public, "control-actor")
    result = evaluate(envelope, wrong_policy, campaign, now, work)
    expect_refused("wrong_key", result, "invalid_signature", controls)

    malformed = make_envelope(payload, "control-key", private_key, work, malformed_pae=True)
    result = evaluate(malformed, policy, campaign, now, work)
    expect_refused("malformed_pae", result, "invalid_signature", controls)

    release_private, release_public = generate_key(work)
    release_policy = base_policy(
        "release-key", release_public, "release-actor", role_id="release_authority"
    )
    release_envelope = make_envelope(payload, "release-key", release_private, work)
    result = evaluate(release_envelope, release_policy, campaign, now, work)
    expect_refused("unauthorized_role", result, "unauthorized_role", controls)
    if result["dimensions"]["signature_validity"] != "valid":
        raise IntegrityError("unauthorized-role control did not retain a valid signature")

    replayed_campaign = dict(campaign)
    replayed_campaign["campaign_id"] = "frf-etp-replayed-campaign"
    replayed_campaign["closure_sha256"] = "0" * 64
    replayed_campaign["case_ids"] = ["invented-case"]
    result = evaluate(envelope, policy, replayed_campaign, now, work)
    expect_refused("replayed_envelope", result, "campaign_mismatch", controls)
    if result["dimensions"]["signature_validity"] != "valid":
        raise IntegrityError("replay control did not retain a valid signature")

    duplicate_envelope = {
        "payloadType": envelope["payloadType"],
        "payload": envelope["payload"],
        "signatures": [envelope["signatures"][0], envelope["signatures"][0]],
    }
    try:
        evaluate(duplicate_envelope, policy, campaign, now, work)
    except IntegrityError:
        controls.append("duplicate_credential")
    else:
        raise IntegrityError("duplicate keyid was not rejected")

    second_private, second_public = generate_key(work)
    producer_private, producer_public = generate_key(work)
    independent_policy = base_policy(
        "adjudicator-key-1",
        public_key,
        "same-actor",
        role_id="adjudicator",
        independent=True,
        threshold=2,
        extra_keys=[("adjudicator-key-2", second_public, "same-actor")],
    )
    for role in independent_policy["roles"]:
        if role["id"] == "evidence_producer":
            role["keys"].append(
                {
                    "keyid": "producer-key",
                    "algorithm": "ed25519",
                    "public_key_base64": base64.b64encode(producer_public).decode("ascii"),
                    "actor": "producer-actor",
                    "not_before_unix": 1795305600,
                    "not_after_unix": 1826841600,
                }
            )
    independent_statement = json.loads(payload)
    independent_statement["predicate"]["independent_review"] = "established"
    independent_payload = canonical_json(independent_statement)
    independent_message = pae(PAYLOAD_TYPE, independent_payload)
    signatures = []
    for keyid, signing_key in [
        ("producer-key", producer_private),
        ("adjudicator-key-1", private_key),
        ("adjudicator-key-2", second_private),
    ]:
        signature = sign_message(signing_key, independent_message, work)
        signatures.append({"keyid": keyid, "sig": base64.b64encode(signature).decode("ascii")})
    independent_envelope = {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(independent_payload).decode("ascii"),
        "signatures": signatures,
    }
    result = evaluate(independent_envelope, independent_policy, campaign, now, work)
    expect_refused(
        "duplicate_actor_not_independent",
        result,
        "insufficient_independent_review",
        controls,
    )

    rsa_policy = base_policy("control-key", public_key, "control-actor")
    rsa_policy["roles"][0]["keys"][0]["algorithm"] = "rsa"
    try:
        evaluate(envelope, rsa_policy, campaign, now, work)
    except IntegrityError:
        controls.append("unsupported_algorithm")
    else:
        raise IntegrityError("unsupported algorithm was not rejected")

    expired_policy = base_policy(
        "control-key", public_key, "control-actor", not_after=now - 1
    )
    result = evaluate(envelope, expired_policy, campaign, now, work)
    expect_refused("expired_key", result, "expired_credential", controls)

    substituted = json.loads(payload)
    substituted["subject"][1]["digest"]["sha256"] = "1" * 64
    substituted_payload = canonical_json(substituted)
    substituted_envelope = make_envelope(
        substituted_payload, "control-key", private_key, work
    )
    result = evaluate(substituted_envelope, policy, campaign, now, work)
    expect_refused("substituted_subject", result, "candidate_mismatch", controls)
    if result["dimensions"]["signature_validity"] != "valid":
        raise IntegrityError("substituted-subject control did not retain a valid signature")

    false_statement = json.loads(payload)
    false_statement["predicate"]["conclusion"] = "withheld"
    false_payload = canonical_json(false_statement)
    false_envelope = make_envelope(false_payload, "control-key", private_key, work)
    result = evaluate(false_envelope, policy, campaign, now, work)
    expect_refused("false_conclusion", result, "false_conclusion", controls)
    if result["dimensions"]["signature_validity"] != "valid":
        raise IntegrityError("false-conclusion control did not retain a valid signature")

    incomplete_campaign = dict(campaign)
    incomplete_campaign["case_ids"] = campaign["case_ids"][:-1]
    incomplete_campaign["case_count"] = campaign["case_count"] - 1
    result = evaluate(envelope, policy, incomplete_campaign, now, work)
    expect_refused("incomplete_closure", result, "population_mismatch", controls)
    if result["dimensions"]["signature_validity"] != "valid":
        raise IntegrityError("incomplete-closure control did not retain a valid signature")

    for name in controls:
        print(f"PASS control {name}")
    print(f"controls passed: {len(controls)}")
    return len(controls)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--attestations",
        default="evaluation/earned-trust-1.2.0/attestations",
        help="directory holding the envelope and statement",
    )
    parser.add_argument(
        "--policy",
        default="evaluation/earned-trust-1.2.0/trust-policy.json",
        help="trust policy path",
    )
    parser.add_argument(
        "--campaign",
        default="evaluation/earned-trust-1.2.0/MANIFEST.json",
        help="campaign closure manifest",
    )
    parser.add_argument(
        "--envelope",
        default=None,
        help="envelope path; defaults to campaign-closure.envelope.json",
    )
    parser.add_argument(
        "--statement",
        default=None,
        help="optional statement path for exact payload comparison",
    )
    parser.add_argument("--controls", action="store_true", help="run the negative controls")
    parser.add_argument("--now", type=int, default=None, help="verification time in Unix seconds")
    args = parser.parse_args()

    work_root = Path("target")
    work_root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="etp-attest-verify-", dir=work_root))
    try:
        attestations = Path(args.attestations)
        envelope_path = (
            Path(args.envelope)
            if args.envelope
            else attestations / "campaign-closure.envelope.json"
        )
        statement_path = (
            Path(args.statement)
            if args.statement
            else attestations / "campaign-closure.statement.json"
        )
        policy = parse_policy(load_json(Path(args.policy)))
        committed_policy_path = attestations / "trust-policy.json"
        if committed_policy_path.is_file():
            if committed_policy_path.read_bytes() != Path(args.policy).read_bytes():
                raise IntegrityError("attestations/trust-policy.json differs from the policy")
        campaign = recompute_campaign(Path(args.campaign))
        envelope = load_json(envelope_path)
        payload = decode_base64_canonical("payload", envelope.get("payload"))
        if statement_path.is_file() and statement_path.read_bytes() != payload:
            raise IntegrityError("decoded payload differs from the committed statement")
        now = args.now if args.now is not None else int(time.time())
        result = evaluate(envelope, policy, campaign, now, work)
        print(f"committed attestation: {result['status']}")
        print(f"envelope: {envelope_path}")
        print(f"campaign: {campaign['campaign_id']}")
        for name, value in result["dimensions"].items():
            print(f"dimension {name}: {value}")
        print(f"independent reviewers: {result['independent_reviewers']}")
        for refusal in result["refusals"]:
            print(f"refused {refusal['code']}: {refusal['detail']}")
        if result["status"] != "accepted":
            return 4
        if args.controls:
            run_controls(
                {"envelope": envelope},
                campaign,
                work,
            )
        return 0
    except IntegrityError as error:
        print(f"integrity failure: {error}", file=sys.stderr)
        return 3
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
