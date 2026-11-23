#!/usr/bin/env python3
"""Independent Phase 10.4b transparency verifier.

This script uses only the Python standard library. It does not import or
execute the Rust implementation. It re-parses the C2SP checkpoint note,
verifies the Ed25519 log signature with a pure-Python RFC 8032 verifier,
recomputes RFC 6962 inclusion and consistency proofs, checks the tiled
reconstruction, and models the witness quorum.

It establishes only what the repository claim ceiling allows. Inclusion is
not semantic validity. Inclusion is not completeness. A witness quorum is
not a protocol proof.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from typing import Any

# ---------------------------------------------------------------------------
# Pure-Python Ed25519 (RFC 8032), verification and local-test signing
# ---------------------------------------------------------------------------

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)


def _xrecover(y: int) -> int | None:
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if (x * x - xx) % P != 0:
        return None
    if x % 2 != 0:
        x = P - x
    return x


By = (4 * pow(5, P - 2, P)) % P
Bx = _xrecover(By)
B = (Bx % P, By % P)
IDENTITY = (0, 1)


def _edwards(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + product, P - 2, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - product, P - 2, P) % P
    return (x3 % P, y3 % P)


def _scalarmult(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _edwards(result, addend)
        addend = _edwards(addend, addend)
        scalar >>= 1
    return result


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode_point(encoded: bytes) -> tuple[int, int] | None:
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if x is None:
        return None
    if (x & 1) != (encoded[31] >> 7):
        x = P - x
    point = (x, y)
    if (-x * x + y * y - 1 - D * x * x * y * y) % P != 0:
        return None
    return point


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    public_point = _decode_point(public_key)
    r_point = _decode_point(signature[:32])
    if public_point is None or r_point is None:
        return False
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= L:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % L
    return _scalarmult(B, scalar) == _edwards(r_point, _scalarmult(public_point, challenge))


def _expand_seed(seed: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def ed25519_public_key(seed: bytes) -> bytes:
    scalar, _ = _expand_seed(seed)
    return _encode_point(_scalarmult(B, scalar))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    scalar, prefix = _expand_seed(seed)
    public_key = _encode_point(_scalarmult(B, scalar))
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    r_point = _encode_point(_scalarmult(B, nonce))
    challenge = int.from_bytes(
        hashlib.sha512(r_point + public_key + message).digest(), "little"
    ) % L
    return r_point + ((nonce + challenge * scalar) % L).to_bytes(32, "little")


# ---------------------------------------------------------------------------
# Encoding and Merkle helpers
# ---------------------------------------------------------------------------


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def b64d(value: str) -> bytes:
    raw = base64.b64decode(value, validate=True)
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("base64 is not canonical")
    return raw


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def hexd(value: str) -> bytes:
    if len(value) % 2 != 0:
        raise ValueError("odd-length hex")
    raw = bytes.fromhex(value)
    return raw


def hex32(value: str) -> bytes:
    raw = hexd(value)
    if len(raw) != 32:
        raise ValueError("expected 32-byte hex")
    return raw


def mutate_base64(value: str) -> str:
    """Change one base64 alphabet character without touching padding."""
    characters = list(value)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    for index in range(len(characters) - 1, -1, -1):
        if characters[index] in alphabet:
            characters[index] = "B" if characters[index] == "A" else "A"
            return "".join(characters)
    return value


def leaf_hash(entry: bytes) -> bytes:
    return sha256(b"\x00" + entry)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


def split_point(n: int) -> int:
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def mth(leaves: list[bytes]) -> bytes:
    if not leaves:
        return sha256(b"")
    if len(leaves) == 1:
        return leaves[0]
    k = split_point(len(leaves))
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def audit_path(leaves: list[bytes], index: int) -> list[bytes]:
    if index < 0 or index >= len(leaves):
        raise ValueError("index outside tree")
    if len(leaves) == 1:
        return []
    k = split_point(len(leaves))
    if index < k:
        return audit_path(leaves[:k], index) + [mth(leaves[k:])]
    return audit_path(leaves[k:], index - k) + [mth(leaves[:k])]


def verify_inclusion(
    index: int, size: int, leaf: bytes, path: list[bytes], root: bytes
) -> bool:
    if size == 0 or index >= size:
        return False
    fn = index
    sn = size - 1
    computed = leaf
    for sibling in path:
        if sn == 0:
            return False
        if (fn & 1) == 1 or fn == sn:
            computed = node_hash(sibling, computed)
            if (fn & 1) == 0:
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            computed = node_hash(computed, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and computed == root


def _run_tree_proof(
    proof: list[bytes], lo: int, hi: int, n: int, old: bytes
) -> tuple[bytes, bytes] | None:
    if not (lo < n <= hi):
        return None
    if n == hi:
        if lo == 0:
            if proof:
                return None
            return old, old
        if len(proof) != 1:
            return None
        return proof[0], proof[0]
    if not proof:
        return None
    k = split_point(hi - lo)
    last = proof[-1]
    rest = proof[:-1]
    if n <= lo + k:
        result = _run_tree_proof(rest, lo, lo + k, n, old)
        if result is None:
            return None
        return result[0], node_hash(result[1], last)
    result = _run_tree_proof(rest, lo + k, hi, n, old)
    if result is None:
        return None
    return node_hash(last, result[0]), node_hash(last, result[1])


def verify_consistency(
    old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]
) -> bool:
    if old_size == 0:
        return not proof and old_root == sha256(b"")
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size > new_size or not proof:
        return False
    result = _run_tree_proof(proof, 0, new_size, old_size, old_root)
    if result is None:
        return False
    return result[0] == old_root and result[1] == new_root


# ---------------------------------------------------------------------------
# Checkpoint parsing and signature verification
# ---------------------------------------------------------------------------


def parse_checkpoint(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > 64 * 1024:
        raise ValueError("checkpoint length is outside the supported range")
    split = raw.find(b"\n\n")
    if split < 0:
        raise ValueError("checkpoint has no signature block")
    text = raw[: split + 1]
    signature_block = raw[split + 2 :]
    if not signature_block.endswith(b"\n"):
        raise ValueError("checkpoint signature block does not end with a newline")
    body = text.decode("utf-8").split("\n")[:-1]
    if len(body) < 3 or any(not line for line in body):
        raise ValueError("checkpoint body is malformed")
    origin = body[0]
    size = int(body[1])
    if size < 0 or size > 1_000_000:
        raise ValueError("checkpoint size is outside the supported bound")
    root = b64d(body[2])
    if len(root) != 32:
        raise ValueError("checkpoint root is not 32 bytes")
    signatures = []
    seen = set()
    for line in signature_block.decode("utf-8").split("\n"):
        if not line:
            continue
        if not line.startswith("\u2014 "):
            raise ValueError("signature line has no em-dash prefix")
        name, encoded = line[2:].split(" ", 1)
        signature = b64d(encoded)
        if len(signature) < 4:
            raise ValueError("signature is shorter than its key id")
        identity = (name, signature[:4])
        if identity in seen:
            raise ValueError("duplicate signature name and key id")
        seen.add(identity)
        signatures.append((name, signature))
    if not signatures:
        raise ValueError("checkpoint has no signatures")
    return {
        "original": raw,
        "text": text,
        "origin": origin,
        "size": size,
        "root": root,
        "extensions": body[3:],
        "signatures": signatures,
        "sha256": sha256(raw).hex(),
    }


def note_key_id(name: str, public_key: bytes, algorithm: int) -> bytes:
    return sha256(name.encode("utf-8") + b"\n" + bytes([algorithm]) + public_key)[:4]


def verify_log_signature(checkpoint: dict[str, Any], origin: str, public_key: bytes) -> bool:
    key_id = note_key_id(origin, public_key, 0x01)
    for name, signature in checkpoint["signatures"]:
        if (
            name == origin
            and signature[:4] == key_id
            and len(signature) == 68
            and ed25519_verify(public_key, signature[4:], checkpoint["text"])
        ):
            return True
    return False


def cosignature_message(checkpoint: dict[str, Any], timestamp: int) -> bytes:
    message = b"cosignature/v1\n"
    message += f"time {timestamp}\n".encode("ascii")
    message += checkpoint["origin"].encode("utf-8") + b"\n"
    message += str(checkpoint["size"]).encode("ascii") + b"\n"
    message += b64e(checkpoint["root"]).encode("ascii") + b"\n"
    for extension in checkpoint["extensions"]:
        message += extension.encode("utf-8") + b"\n"
    return message


def verify_cosignature(
    line: str, name: str, public_key: bytes, checkpoint: dict[str, Any]
) -> bool:
    if not line.startswith("\u2014 "):
        return False
    parsed_name, encoded = line[2:].split(" ", 1)
    if parsed_name != name:
        return False
    raw = b64d(encoded)
    if len(raw) != 4 + 8 + 64:
        return False
    if raw[:4] != note_key_id(name, public_key, 0x04):
        return False
    timestamp = int.from_bytes(raw[4:12], "big")
    return ed25519_verify(public_key, raw[12:], cosignature_message(checkpoint, timestamp))


# ---------------------------------------------------------------------------
# Proof and policy verification
# ---------------------------------------------------------------------------


def _policy_public_key(policy: dict[str, Any]) -> bytes:
    raw = b64d(policy["log"]["public_key_base64"])
    if len(raw) != 32:
        raise ValueError("pinned public key is not 32 bytes")
    return raw


def _vkey_matches(vkey: str, origin: str, public_key: bytes) -> bool:
    prefix = origin + "+"
    if not vkey.startswith(prefix):
        return False
    key_id, encoded = vkey[len(prefix) :].split("+", 1)
    raw = b64d(encoded)
    if raw[:1] != b"\x01" or raw[1:] != public_key:
        return False
    return key_id == note_key_id(origin, public_key, 0x01).hex()


def _latest_horizon(policy: dict[str, Any]) -> dict[str, Any] | None:
    horizons = policy.get("anti_rollback", {}).get("known_horizons", [])
    if not horizons:
        return None
    return max(horizons, key=lambda horizon: int(horizon["tree_size"]))


def verify_transparency(
    proof: dict[str, Any], checkpoint_raw: bytes, policy: dict[str, Any]
) -> dict[str, Any]:
    refusals: list[str] = []
    result: dict[str, Any] = {
        "status": "verified",
        "refusals": refusals,
        "external_trust": False,
        "public_transparency": False,
        "witness_observation": "not_observed",
        "tree_size": None,
        "leaf_index": None,
    }

    def refuse(code: str) -> None:
        refusals.append(code)

    try:
        if proof.get("schema") != "frf-etp.transparency-proof.v1":
            refuse("malformed_proof")
            result["status"] = "refused"
            return result
        if proof.get("spec") != "frf-etp-v1":
            refuse("malformed_proof")
        if policy.get("schema") != "frf-etp.transparency-policy.v1":
            refuse("malformed_policy")
        if policy.get("spec") != "frf-etp-v1":
            refuse("malformed_policy")
        checkpoint = parse_checkpoint(checkpoint_raw)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        result["status"] = "integrity_failure"
        refuse(f"malformed_checkpoint_or_policy: {error}")
        return result

    result["tree_size"] = checkpoint["size"]
    result["leaf_index"] = proof.get("leaf_index")

    if proof.get("log_version") not in policy["log"].get("supported_log_versions", []):
        refuse("unsupported_log_version")
        result["status"] = "not_run"
        return result
    if "tlog-checkpoint-v1" not in policy["log"].get("supported_checkpoint_versions", []):
        refuse("unsupported_checkpoint_version")
        result["status"] = "not_run"
        return result

    identity_ok = (
        proof.get("log_origin") == policy["log"]["origin"]
        and proof.get("log_id") == policy["log"]["log_id"]
        and checkpoint["origin"] == policy["log"]["origin"]
    )
    if not identity_ok:
        refuse("cross_log_proof")

    try:
        public_key = _policy_public_key(policy)
    except (ValueError, KeyError) as error:
        refuse(f"invalid_pinned_key: {error}")
        result["status"] = "refused"
        return result

    if not _vkey_matches(policy["log"]["vkey"], policy["log"]["origin"], public_key):
        refuse("log_identity_mismatch")
    if not verify_log_signature(checkpoint, policy["log"]["origin"], public_key):
        refuse("invalid_checkpoint_signature")
    if checkpoint["sha256"] != proof.get("checkpoint_sha256"):
        refuse("checkpoint_digest_mismatch")

    horizon = _latest_horizon(policy)
    if horizon is not None:
        if checkpoint["size"] == int(horizon["tree_size"]) and checkpoint[
            "sha256"
        ] != horizon["checkpoint_sha256"]:
            refuse("checkpoint_persistence_mismatch")

    try:
        entry = b64d(proof["entry_base64"])
    except (ValueError, KeyError) as error:
        refuse(f"malformed_proof: {error}")
        result["status"] = "integrity_failure"
        return result
    if len(entry) > 64 * 1024:
        refuse("malformed_proof")
    if sha256(entry).hex() != proof.get("entry_sha256"):
        refuse("entry_digest_mismatch")
    computed_leaf = leaf_hash(entry)
    try:
        declared_leaf = hex32(proof["leaf_hash"])
    except (ValueError, KeyError):
        declared_leaf = b""
        refuse("leaf_hash_mismatch")
    if declared_leaf != computed_leaf:
        refuse("leaf_hash_mismatch")
    try:
        proof_root = hex32(proof["root_hash"])
    except (ValueError, KeyError):
        proof_root = b""
        refuse("root_mismatch")
    if proof_root != checkpoint["root"]:
        refuse("root_mismatch")
    if int(proof.get("tree_size", -1)) != checkpoint["size"]:
        refuse("root_mismatch")

    try:
        declared_path = [b64d(node) for node in proof.get("audit_path", [])]
    except (ValueError, TypeError):
        declared_path = []
        refuse("malformed_proof")
    if not verify_inclusion(
        int(proof.get("leaf_index", 0)),
        checkpoint["size"],
        computed_leaf,
        declared_path,
        checkpoint["root"],
    ):
        refuse("inclusion_invalid")

    if horizon is None:
        refuse("anti_rollback_uninitialized")
    else:
        horizon_size = int(horizon["tree_size"])
        horizon_root = hex32(horizon["root_hash"])
        if checkpoint["size"] < horizon_size:
            refuse("rollback")
        elif checkpoint["size"] == horizon_size:
            if checkpoint["root"] != horizon_root:
                refuse("conflicting_checkpoint")
        else:
            consistency = proof.get("consistency")
            if not consistency:
                refuse("missing_consistency_proof")
            else:
                try:
                    old_root = hex32(consistency["old_root"])
                    new_root = hex32(consistency["new_root"])
                    path = [b64d(node) for node in consistency["proof"]]
                except (ValueError, KeyError, TypeError):
                    refuse("malformed_proof")
                else:
                    if not (
                        int(consistency["old_size"]) == horizon_size
                        and old_root == horizon_root
                        and int(consistency["new_size"]) == checkpoint["size"]
                        and new_root == checkpoint["root"]
                        and verify_consistency(
                            int(consistency["old_size"]),
                            int(consistency["new_size"]),
                            old_root,
                            new_root,
                            path,
                        )
                    ):
                        refuse("consistency_invalid")

    _verify_tiles(proof, checkpoint, computed_leaf, declared_path, refuse)

    if refusals:
        result["status"] = "refused"
    return result


def _verify_tiles(
    proof: dict[str, Any],
    checkpoint: dict[str, Any],
    leaf: bytes,
    declared_path: list[bytes],
    refuse,
) -> None:
    tiles = proof.get("tiles", [])
    if not tiles:
        return
    if len(tiles) > 64:
        refuse("malformed_tile")
        return
    level_zero: dict[int, list[bytes]] = {}
    for tile in tiles:
        try:
            level = int(tile["level"])
            index = int(tile["index"])
            width = int(tile["width"])
            raw = b64d(tile["base64"])
        except (ValueError, KeyError, TypeError):
            refuse("malformed_tile")
            return
        if level > 63 or width < 1 or width > 256:
            refuse("malformed_tile")
            return
        if len(raw) > 8192 or len(raw) != width * 32:
            refuse("malformed_tile")
            return
        if sha256(raw).hex() != tile.get("sha256"):
            refuse("malformed_tile")
            return
        hashes = [raw[offset : offset + 32] for offset in range(0, len(raw), 32)]
        if level == 0:
            if index in level_zero:
                refuse("malformed_tile")
                return
            level_zero[index] = hashes

    leaves: list[bytes] = []
    tile_index = 0
    while len(leaves) < checkpoint["size"]:
        hashes = level_zero.get(tile_index)
        if hashes is None:
            refuse("malformed_tile")
            return
        expected = min(256, checkpoint["size"] - len(leaves))
        if len(hashes) != expected:
            refuse("malformed_tile")
            return
        leaves.extend(hashes)
        tile_index += 1
    if mth(leaves) != checkpoint["root"]:
        refuse("tiled_root_mismatch")
        return
    index = int(proof.get("leaf_index", 0))
    if index >= len(leaves) or leaves[index] != leaf:
        refuse("tile_leaf_mismatch")
        return
    if audit_path(leaves, index) != declared_path:
        refuse("tiled_proof_mismatch")
        return
    for tile in tiles:
        level = int(tile["level"])
        if level == 0:
            continue
        raw = b64d(tile["base64"])
        scale = 256**level
        start = int(tile["index"]) * 256 * scale
        for offset in range(0, len(raw), 32):
            begin = start + (offset // 32) * scale
            end = begin + scale
            if end > checkpoint["size"]:
                continue
            if mth(leaves[begin:end]) != raw[offset : offset + 32]:
                refuse("tiled_root_mismatch")
                return


# ---------------------------------------------------------------------------
# Witness model
# ---------------------------------------------------------------------------


def verify_witness_state(state: dict[str, Any]) -> dict[str, Any]:
    refusals: list[str] = []
    report: dict[str, Any] = {
        "status": "verified",
        "refusals": refusals,
        "quorum": {},
        "external_witnessing": False,
        "local_test_only": False,
        "witness_observation": "not_observed",
    }

    def refuse(code: str) -> None:
        refusals.append(code)

    try:
        if state.get("schema") != "frf-etp.witness-state.v1" or state.get(
            "spec"
        ) != "frf-etp-v1":
            raise ValueError("unsupported witness state schema")
        policy = state["policy"]
        if policy.get("schema") != "frf-etp.witness-policy.v1" or policy.get(
            "spec"
        ) != "frf-etp-v1":
            raise ValueError("unsupported witness policy schema")
        checkpoint_bytes = b64d(state["checkpoint_base64"])
        checkpoint = parse_checkpoint(checkpoint_bytes)
    except (ValueError, KeyError, TypeError) as error:
        report["status"] = "integrity_failure"
        refuse(f"malformed_state: {error}")
        return report

    if checkpoint["sha256"] != state.get("checkpoint_sha256"):
        report["status"] = "integrity_failure"
        refuse("checkpoint_mismatch")
        return report
    if checkpoint["origin"] != policy.get("log_origin"):
        report["status"] = "integrity_failure"
        refuse("checkpoint_mismatch")
        return report

    report["external_witnessing"] = bool(state.get("external_witnessing"))
    report["local_test_only"] = bool(state.get("local_test_only"))

    domains = {domain["id"]: domain for domain in policy.get("administrative_domains", [])}
    keys = {witness["id"]: witness for witness in policy.get("witnesses", [])}
    observations = {observation["id"]: observation for observation in state.get("observations", [])}
    if len(keys) != len(policy.get("witnesses", [])) or set(observations) != set(keys):
        report["status"] = "integrity_failure"
        refuse("witness_identity_mismatch")
        return report

    counted: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    entries = []
    for witness_id, witness in keys.items():
        observation = observations[witness_id]
        domain = domains.get(witness.get("domain"))
        if domain is None:
            refuse("witness_identity_mismatch")
            continue
        try:
            public_key = b64d(witness["public_key_base64"])
            if len(public_key) != 32:
                raise ValueError
        except (ValueError, KeyError):
            refuse("witness_identity_mismatch")
            continue
        status = observation.get("status")
        signature_valid = False
        if observation.get("cosignature"):
            signature_valid = verify_cosignature(
                observation["cosignature"], witness["name"], public_key, checkpoint
            )
            if not signature_valid:
                refuse("invalid_witness_signature")
        rollback = False
        prior = observation.get("prior_max_tree_size")
        if prior is not None and int(prior) > int(observation.get("last_observed_tree_size", 0)):
            rollback = True
            refuse("witness_state_rollback")
        if int(observation.get("last_observed_tree_size", 0)) > checkpoint["size"]:
            rollback = True
            refuse("witness_state_rollback")
        roots: dict[int, set[str]] = {}
        for observed in observation.get("observed_roots", []):
            roots.setdefault(int(observed["tree_size"]), set()).add(
                observed["root_hash"].lower()
            )
        for size, values in roots.items():
            if len(values) > 1:
                refuse("conflicting_checkpoints")
                report.setdefault("conflicting_checkpoints", []).append(size)
        if signature_valid and status in ("observed", "local_test_only"):
            counted.append((witness, observation, domain))
        entries.append(
            {
                "id": witness_id,
                "domain": domain["id"],
                "signature_verified": signature_valid,
                "observation": status,
                "rollback": rollback,
            }
        )
    report["witnesses"] = entries

    quorum = policy["quorum"]
    n, q, f = int(quorum["n"]), int(quorum["q"]), int(quorum["f"])
    required_domains = int(quorum["required_domains"])
    intersection_holds = 2 * q > n + f
    if q < 1 or q > n or f >= max(n, 1):
        refuse("quorum_assumption_invalid")
    if n != len(keys):
        refuse("quorum_assumption_invalid")
    if not intersection_holds:
        refuse("quorum_assumption_invalid")
    if required_domains > len(domains):
        refuse("quorum_assumption_invalid")

    correlated = []
    units = set()
    distinct_domains = set()
    for left_index, (left, _, left_domain) in enumerate(counted):
        for right, _, right_domain in counted[left_index + 1 :]:
            if left_domain["id"] == right_domain["id"]:
                correlated.append((left["id"], right["id"], "same-domain"))
            elif left.get("correlation_group") and left.get("correlation_group") == right.get(
                "correlation_group"
            ):
                correlated.append((left["id"], right["id"], "same-correlation-group"))
            else:
                for assumption in left_domain.get("shared_trust", []):
                    if left_domain.get("single_fault_domain") and assumption in right_domain.get(
                        "shared_trust", []
                    ):
                        correlated.append((left["id"], right["id"], f"shared:{assumption}"))
                        break
        distinct_domains.add(left_domain["id"])
        units.add(left.get("correlation_group") or left_domain["id"])
    if correlated:
        refuse("correlated_witnesses")
    effective = len(units)
    met = not correlated and effective >= q and len(distinct_domains) >= required_domains
    report["quorum"] = {
        "n": n,
        "q": q,
        "f": f,
        "required_domains": required_domains,
        "intersection_condition": "2q - n > f",
        "intersection_holds": intersection_holds,
        "observed": len(counted),
        "effective_independent": effective,
        "distinct_domains": len(distinct_domains),
        "met": met,
        "basis": (
            "local_test_only"
            if state.get("local_test_only")
            else ("declared_external" if state.get("external_witnessing") else "none")
        ),
    }
    if not met:
        refuse("quorum_failed")

    any_observed = any(
        observation.get("status") == "observed" for observation in observations.values()
    )
    if state.get("external_witnessing") and any_observed:
        report["witness_observation"] = "declared_observed_not_independently_confirmed"
    else:
        report["witness_observation"] = "not_observed"

    if policy.get("require_external_witnesses") and not state.get("external_witnessing"):
        report["status"] = "not_run"
        refuse("external_observation_required")
        return report

    report["status"] = "verified" if met and not refusals else "refused"
    return report


# ---------------------------------------------------------------------------
# Local-test witness fixture generator (controls only)
# ---------------------------------------------------------------------------


def make_local_test_witness_state(checkpoint: dict[str, Any], counted: int = 2) -> dict[str, Any]:
    seeds = [bytes([index]) * 32 for index in (1, 2, 3)]
    names = [
        "frf.local/etp/witness-a",
        "frf.local/etp/witness-b",
        "frf.local/etp/witness-c",
    ]
    ids = ["witness-a", "witness-b", "witness-c"]
    domains = ["a", "b", "c"]
    timestamp = 1_795_300_000
    witnesses = []
    observations = []
    for index in range(3):
        public_key = ed25519_public_key(seeds[index])
        is_counted = index < counted
        cosignature = None
        if is_counted:
            key_id = note_key_id(names[index], public_key, 0x04)
            message = cosignature_message(checkpoint, timestamp)
            signature = ed25519_sign(seeds[index], message)
            raw = key_id + timestamp.to_bytes(8, "big") + signature
            cosignature = f"\u2014 {names[index]} {b64e(raw)}"
        witnesses.append(
            {
                "id": ids[index],
                "name": names[index],
                "domain": domains[index],
                "public_key_base64": b64e(public_key),
                "correlation_group": None,
                "trust_assumptions": ["local-test-key"],
            }
        )
        observations.append(
            {
                "id": ids[index],
                "status": "local_test_only" if is_counted else "not_observed",
                "last_observed_tree_size": checkpoint["size"],
                "prior_max_tree_size": None,
                "checkpoint_sha256": checkpoint["sha256"],
                "cosignature": cosignature,
                "observed_roots": [],
            }
        )
    return {
        "schema": "frf-etp.witness-state.v1",
        "spec": "frf-etp-v1",
        "checkpoint_base64": b64e(checkpoint["original"]),
        "checkpoint_sha256": checkpoint["sha256"],
        "external_witnessing": False,
        "local_test_only": True,
        "policy": {
            "schema": "frf-etp.witness-policy.v1",
            "spec": "frf-etp-v1",
            "policy_id": "python-control-witness-policy",
            "log_origin": checkpoint["origin"],
            "log_id": "sha256:" + sha256(checkpoint["origin"].encode()).hex(),
            "require_external_witnesses": False,
            "administrative_domains": [
                {
                    "id": "a",
                    "operator": "test-a",
                    "independent": True,
                    "shared_trust": ["test-kernel-a"],
                    "single_fault_domain": True,
                },
                {
                    "id": "b",
                    "operator": "test-b",
                    "independent": True,
                    "shared_trust": ["test-kernel-b"],
                    "single_fault_domain": True,
                },
                {
                    "id": "c",
                    "operator": "test-c",
                    "independent": True,
                    "shared_trust": ["test-kernel-c"],
                    "single_fault_domain": True,
                },
            ],
            "witnesses": witnesses,
            "quorum": {"n": 3, "q": 2, "f": 0, "required_domains": 2},
        },
        "observations": observations,
    }


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


def _expect(code: str, result: dict[str, Any]) -> None:
    if code not in result["refusals"]:
        raise AssertionError(f"expected refusal {code}, got {result['refusals']}")


def run_controls(base: str) -> int:
    with open(f"{base}/proof.json", encoding="utf-8") as handle:
        proof = json.load(handle)
    with open(f"{base}/policy.json", encoding="utf-8") as handle:
        policy = json.load(handle)
    with open(f"{base}/checkpoint-size-3.txt", "rb") as handle:
        checkpoint = handle.read()
    with open(f"{base}/witness-state.json", encoding="utf-8") as handle:
        committed_witness = json.load(handle)

    passed = 0
    total = 0

    def check(label: str, condition: bool) -> None:
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f"control ok: {label}")
        else:
            print(f"control FAILED: {label}")
            raise SystemExit(1)

    valid = verify_transparency(proof, checkpoint, policy)
    check("valid proof verifies", valid["status"] == "verified" and not valid["refusals"])

    mutated = json.loads(json.dumps(proof))
    mutated["leaf_hash"] = "00" * 32
    check("wrong leaf", "leaf_hash_mismatch" in verify_transparency(mutated, checkpoint, policy)["refusals"])

    mutated = json.loads(json.dumps(proof))
    mutated["leaf_index"] = 1
    check("wrong index", "inclusion_invalid" in verify_transparency(mutated, checkpoint, policy)["refusals"])

    mutated = json.loads(json.dumps(proof))
    mutated["audit_path"] = list(reversed(mutated["audit_path"]))
    check("wrong sibling order", "inclusion_invalid" in verify_transparency(mutated, checkpoint, policy)["refusals"])

    mutated = json.loads(json.dumps(proof))
    mutated["root_hash"] = "11" * 32
    check("wrong root", "root_mismatch" in verify_transparency(mutated, checkpoint, policy)["refusals"])

    wrong_checkpoint = bytearray(checkpoint)
    marker = "\u2014 frf.local/etp-transparency-2026 ".encode()
    position = wrong_checkpoint.find(marker) + len(marker)
    wrong_checkpoint[position] = ord("B") if wrong_checkpoint[position] == ord("A") else ord("A")
    check(
        "wrong signature",
        "invalid_checkpoint_signature"
        in verify_transparency(proof, bytes(wrong_checkpoint), policy)["refusals"],
    )

    mutated = json.loads(json.dumps(proof))
    mutated["log_origin"] = "frf.local/other-transparency-log"
    mutated["log_id"] = "sha256:" + sha256(b"frf.local/other-transparency-log").hex()
    check("cross-log proof", "cross_log_proof" in verify_transparency(mutated, checkpoint, policy)["refusals"])

    rolled = json.loads(json.dumps(policy))
    rolled["anti_rollback"]["known_horizons"] = [
        {"tree_size": 7, "root_hash": "33" * 32, "checkpoint_sha256": "44" * 32}
    ]
    check("rollback", "rollback" in verify_transparency(proof, checkpoint, rolled)["refusals"])

    conflicting = json.loads(json.dumps(policy))
    conflicting["anti_rollback"]["known_horizons"] = [
        {
            "tree_size": 3,
            "root_hash": "22" * 32,
            "checkpoint_sha256": sha256(checkpoint).hex(),
        }
    ]
    check(
        "conflicting checkpoint",
        "conflicting_checkpoint"
        in verify_transparency(proof, checkpoint, conflicting)["refusals"],
    )

    mutated = json.loads(json.dumps(proof))
    mutated.pop("consistency")
    check(
        "missing consistency",
        "missing_consistency_proof" in verify_transparency(mutated, checkpoint, policy)["refusals"],
    )

    mutated = json.loads(json.dumps(proof))
    mutated["tiles"][0]["width"] = 2
    check("malformed tile", "malformed_tile" in verify_transparency(mutated, checkpoint, policy)["refusals"])

    mutated = json.loads(json.dumps(proof))
    mutated["log_version"] = "tlog-tiles-v2"
    check(
        "unsupported log version",
        "unsupported_log_version"
        in verify_transparency(mutated, checkpoint, policy)["refusals"],
    )

    witness = verify_witness_state(committed_witness)
    check(
        "committed witness not observed",
        witness["status"] == "not_run"
        and witness["witness_observation"] == "not_observed"
        and "external_observation_required" in witness["refusals"],
    )

    checkpoint_parsed = parse_checkpoint(checkpoint)
    local = make_local_test_witness_state(checkpoint_parsed)
    local_result = verify_witness_state(local)
    check(
        "local-test quorum verified",
        local_result["status"] == "verified"
        and local_result["quorum"]["met"]
        and not local_result["external_witnessing"]
        and local_result["witness_observation"] == "not_observed",
    )

    correlated = json.loads(json.dumps(local))
    correlated["policy"]["witnesses"][1]["domain"] = "a"
    check(
        "correlated witnesses",
        "correlated_witnesses" in verify_witness_state(correlated)["refusals"],
    )

    quorum_failure = json.loads(json.dumps(local))
    quorum_failure["observations"][1]["cosignature"] = None
    quorum_failure["observations"][1]["status"] = "not_observed"
    check(
        "quorum failure",
        "quorum_failed" in verify_witness_state(quorum_failure)["refusals"],
    )

    rollback = json.loads(json.dumps(local))
    rollback["observations"][0]["prior_max_tree_size"] = 5
    check(
        "witness state rollback",
        "witness_state_rollback" in verify_witness_state(rollback)["refusals"],
    )

    conflicts = json.loads(json.dumps(local))
    conflicts["observations"][0]["observed_roots"] = [
        {"tree_size": 3, "root_hash": "55" * 32},
        {"tree_size": 3, "root_hash": "66" * 32},
    ]
    check(
        "conflicting witness roots",
        "conflicting_checkpoints" in verify_witness_state(conflicts)["refusals"],
    )

    invalid_signature = json.loads(json.dumps(local))
    line = invalid_signature["observations"][0]["cosignature"]
    prefix, encoded = line.rsplit(" ", 1)
    invalid_signature["observations"][0]["cosignature"] = prefix + " " + mutate_base64(encoded)
    check(
        "invalid witness cosignature",
        "invalid_witness_signature" in verify_witness_state(invalid_signature)["refusals"],
    )

    assumption = json.loads(json.dumps(local))
    assumption["policy"]["quorum"] = {"n": 3, "q": 1, "f": 2, "required_domains": 1}
    check(
        "quorum assumption",
        "quorum_assumption_invalid" in verify_witness_state(assumption)["refusals"],
    )

    print(f"controls passed: {passed} of {total}")
    return 0 if passed == total else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dir", default="evaluation/earned-trust-1.2.0/transparency", help="artifact directory"
    )
    parser.add_argument("--proof", help="override proof path")
    parser.add_argument("--checkpoint", help="override checkpoint path")
    parser.add_argument("--policy", help="override policy path")
    parser.add_argument("--witness-state", help="override witness state path")
    parser.add_argument("--controls", action="store_true", help="run corrupted controls")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    if args.controls:
        return run_controls(args.dir)

    proof_path = args.proof or f"{args.dir}/proof.json"
    checkpoint_path = args.checkpoint or f"{args.dir}/checkpoint-size-3.txt"
    policy_path = args.policy or f"{args.dir}/policy.json"
    with open(proof_path, encoding="utf-8") as handle:
        proof = json.load(handle)
    with open(checkpoint_path, "rb") as handle:
        checkpoint = handle.read()
    with open(policy_path, encoding="utf-8") as handle:
        policy = json.load(handle)

    result = verify_transparency(proof, checkpoint, policy)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"transparency: {result['status']}")
        print(f"tree size: {result['tree_size']}")
        print(f"leaf index: {result['leaf_index']}")
        print(f"external trust: {result['external_trust']}")
        print(f"witness observation: {result['witness_observation']}")
        for refusal in result["refusals"]:
            print(f"refused {refusal}")
        print(
            "claim ceiling: a local inclusion proof is not semantic validity, "
            "not completeness, and not public transparency."
        )
    exit_codes = {"verified": 0, "refused": 4, "not_run": 6, "integrity_failure": 3}
    return exit_codes.get(result["status"], 7)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
