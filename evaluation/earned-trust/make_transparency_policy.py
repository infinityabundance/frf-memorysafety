#!/usr/bin/env python3
"""Fixture helper: write a transparency policy for a fresh local log.

This is fixture generation, not verification. It reads the public note vkey and
two checkpoints produced by the pinned tessera driver and writes a policy JSON
that pins the log identity and the smaller checkpoint as the known horizon.
The private key is never read.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json


def parse_checkpoint(raw: bytes) -> tuple[str, int, bytes, str]:
    split = raw.find(b"\n\n")
    if split < 0:
        raise SystemExit("checkpoint has no signature block")
    body = raw[: split + 1].decode("utf-8").split("\n")[:-1]
    if len(body) < 3:
        raise SystemExit("checkpoint body is too short")
    root = base64.b64decode(body[2])
    if len(root) != 32:
        raise SystemExit("checkpoint root is not 32 bytes")
    return body[0], int(body[1]), root, hashlib.sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--checkpoint-old", required=True)
    parser.add_argument("--checkpoint-new", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    with open(args.public_key, encoding="ascii") as handle:
        vkey = handle.read().strip()
    prefix = args.origin + "+"
    if not vkey.startswith(prefix):
        raise SystemExit("vkey origin does not match --origin")
    key_id, encoded = vkey[len(prefix) :].split("+", 1)
    public = base64.b64decode(encoded)
    if public[:1] != b"\x01" or len(public) != 33:
        raise SystemExit("vkey is not an Ed25519 note key")
    public_raw = public[1:]
    computed_key_id = hashlib.sha256(
        args.origin.encode() + b"\n" + public
    ).hexdigest()[:8]
    if computed_key_id != key_id:
        raise SystemExit("vkey key id does not match the public key")

    with open(args.checkpoint_old, "rb") as handle:
        old_raw = handle.read()
    with open(args.checkpoint_new, "rb") as handle:
        new_raw = handle.read()
    old_origin, old_size, old_root, old_digest = parse_checkpoint(old_raw)
    new_origin, new_size, _, _ = parse_checkpoint(new_raw)
    if old_origin != args.origin or new_origin != args.origin:
        raise SystemExit("checkpoint origin mismatch")
    if old_size >= new_size:
        raise SystemExit("old checkpoint is not smaller than the new checkpoint")

    policy = {
        "schema": "frf-etp.transparency-policy.v1",
        "spec": "frf-etp-v1",
        "policy_id": "frf-local-transparency-live-policy",
        "trust_profile": "local-test-tlog-tiles",
        "log": {
            "origin": args.origin,
            "log_id": "sha256:" + hashlib.sha256(args.origin.encode()).hexdigest(),
            "public_key_base64": base64.b64encode(public_raw).decode("ascii"),
            "vkey": vkey,
            "algorithm": "ed25519-note-v1",
            "supported_log_versions": ["tlog-tiles-v1"],
            "supported_checkpoint_versions": ["tlog-checkpoint-v1"],
            "external_trust": False,
        },
        "anti_rollback": {
            "known_horizons": [
                {
                    "tree_size": old_size,
                    "root_hash": old_root.hex(),
                    "checkpoint_sha256": old_digest,
                }
            ],
            "persistence": "caller_supplied",
        },
        "witness_policy_required": False,
        "witness_policy_id": "frf-local-witness-model-2026-11-22",
        "claim_ceiling": (
            "A verified local transparency proof establishes only that the exact "
            "entry bytes hash to the declared leaf and that the leaf is included at "
            "the declared index in an RFC 6962 Merkle tree whose signed root equals "
            "the caller-pinned local log checkpoint, consistent with the caller-"
            "supplied known horizon when a consistency proof is present. It does not "
            "establish semantic validity, completeness, non-equivocation, public "
            "transparency, witness observation, trusted time, independent review, or "
            "release authorization. Inclusion is not semantic validity and not "
            "completeness. A witness quorum is not a protocol proof."
        ),
        "non_claims": [
            "not a public transparency log",
            "not Rekor v2 or a Sigstore public good instance",
            "not external trusted time",
            "not external witnessing",
            "not global non-equivocation",
            "not completeness of the log",
            "not semantic validity of the logged attestation",
            "not independent review or certification",
        ],
    }
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(policy, handle, indent=2)
        handle.write("\n")
    print(f"wrote policy for {args.origin} horizon {old_size}..{new_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
