#!/usr/bin/env python3
"""Independent reconstruction of the FRF-MemorySafety Phase 9.1 evaluation.

This program is deliberately algorithmically separate from the Rust harness in
``src/evaluation.rs``.  It reads only the frozen protocol, the committed
manifest, the committed receipts, and ``evaluation/CLAIMS.json``.  It does not
import or execute the crate, and it does not share the harness's verifier.

It recomputes:

* the protocol SHA-256 and every ``observed_sha256`` / ``experiment_sha256``;
* canonical ``ms-canonical-json-v1`` encoding of every receipt and the manifest;
* exact receipt coverage against the protocol (missing and extra receipts);
* the held-out selection split and per-hypothesis / per-arm tables;
* decision-quality confusion counts and false accept/refuse counts;
* claim-to-receipt mappings for the protocol claims and the paper claims;
* resource totals, blocked controls, and negative findings.

Any missing, extra, non-canonical, tampered, inconsistent, or unsupported
artifact is a hard failure (exit 1).  The script is standard-library only.

Usage:
    python3 evaluation/reconstruct.py [--root DIR] [--json] [--report FILE]

The gate invocation is ``./ci/reconstruction-gate.sh``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

NOT_RUN = "NOT_RUN"
PROTOCOL_SCHEMA = "frf-memorysafety.evaluation-protocol.v1"
MANIFEST_SCHEMA = "frf-memorysafety.evaluation-manifest.v1"
RECEIPT_SCHEMA = "frf-memorysafety.evaluation-receipt.v1"
SPEC = "frf-memorysafety-spec-v1"
CLAIMS_SCHEMA = "frf-memorysafety.paper-claims.v1"

PROTOCOL_DIGEST = "02deb982c61c2a8307dbf3d34cf90f5aeb367e9ea7b1d794314aea9dd094d5ce"
RUST_IMAGE = "rust:1.85.0-slim"
RUST_IMAGE_ID = "sha256:206360542a30ac87385638c1d123eae6cebcd9d8675d521bb80eac7f5820509b"
RUST_IMAGE_DIGEST = "sha256:1829c432be4a592f3021501334d3fcca24f238432b13306a4e62669dec538e52"
PYTHON_IMAGE = "python:3.11-slim"
PYTHON_IMAGE_ID = "sha256:541096ae9b05d3b850341b78790e2ed31e94d5aa0ea086933c6ff0c09ffa2e63"
PYTHON_IMAGE_DIGEST = "sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534c5767af9ea65f6ce"

EXPECTED_RECEIPTS = 60
EXPECTED_CASES = 31
EXPECTED_HELD_OUT = 20
EXPECTED_DEVELOPMENT = 11
EXPECTED_CLAIMS = 11
EXPECTED_PAPER_CLAIMS = 18
CRATE_VERSION = "0.9.0"
MEMORY_LIMIT_MB = 2048
MEMORY_SWAP_LIMIT_MB = 2048
RECONSTRUCTION_MEMORY_LIMIT_MB = 512
PIDS_LIMIT = 512
CPUS = 2
NOFILE_LIMIT = 1024
OOM_SCORE_ADJ = 500
TIMEOUT_SECONDS = 1800


class ReconstructionError(Exception):
    """A hard reconstruction failure."""


def fail(message: str) -> None:
    raise ReconstructionError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# ms-canonical-json-v1
# ---------------------------------------------------------------------------

def _encode_string(value: str) -> bytes:
    out = bytearray(b'"')
    for char in value:
        code = ord(char)
        if char == '"':
            out += b'\\"'
        elif char == "\\":
            out += b"\\\\"
        elif char == "\b":
            out += b"\\b"
        elif char == "\f":
            out += b"\\f"
        elif char == "\n":
            out += b"\\n"
        elif char == "\r":
            out += b"\\r"
        elif char == "\t":
            out += b"\\t"
        elif code < 0x20:
            out += ("\\u%04x" % code).encode("ascii")
        else:
            out += char.encode("utf-8")
    out += b'"'
    return bytes(out)


def _utf16_key(value: str) -> bytes:
    return value.encode("utf-16-be")


def canonical_json(value: object) -> bytes:
    """Encode a value in the restricted ``ms-canonical-json-v1`` grammar."""
    if value is None:
        return b"null"
    if isinstance(value, bool):
        return b"true" if value else b"false"
    if isinstance(value, int):
        return str(value).encode("ascii")
    if isinstance(value, float):
        fail("floating-point numbers are forbidden by ms-canonical-json-v1")
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, list):
        return b"[" + b",".join(canonical_json(item) for item in value) + b"]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                fail("object keys must be strings")
        entries = []
        for key in sorted(value, key=_utf16_key):
            entries.append(_encode_string(key) + b":" + canonical_json(value[key]))
        return b"{" + b",".join(entries) + b"}"
    fail("unsupported value in canonical encoding: %r" % (value,))


def _reject_float(_text: str) -> None:
    fail("floating-point numbers are forbidden by ms-canonical-json-v1")


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate JSON object key %r" % key)
        result[key] = value
    return result


def parse_json(raw: bytes, label: str) -> object:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        fail("%s: invalid UTF-8: %s" % (label, error))
    try:
        return json.loads(
            text,
            object_pairs_hook=_no_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except ReconstructionError:
        raise
    except json.JSONDecodeError as error:
        fail("%s: invalid JSON: %s" % (label, error))


def require_canonical(raw: bytes, label: str) -> object:
    value = parse_json(raw, label)
    encoded = canonical_json(value)
    if encoded != raw:
        fail("%s: bytes are not canonical ms-canonical-json-v1" % label)
    return value


def is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


# ---------------------------------------------------------------------------
# Frozen rule
# ---------------------------------------------------------------------------

def held_out(case_id: str) -> bool:
    digest = hashlib.sha256(b"frf-ms-eval-v1\0" + case_id.encode("utf-8")).digest()
    return digest[0] >= 0x80


def receipt_key(case_id: str, arm: str) -> str:
    return "%s::%s" % (case_id, arm)


def read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        fail("%s: cannot read: %s" % (path, error))


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------

def validate_protocol(protocol: object) -> None:
    require(isinstance(protocol, dict), "protocol: expected an object")
    require(protocol.get("schema") == PROTOCOL_SCHEMA, "protocol: schema mismatch")
    require(protocol.get("spec") == SPEC, "protocol: spec mismatch")
    require(
        isinstance(protocol.get("protocol_version"), str)
        and protocol["protocol_version"],
        "protocol: missing protocol_version",
    )
    hypotheses = protocol.get("hypotheses")
    cases = protocol.get("cases")
    claims = protocol.get("claims")
    require(isinstance(hypotheses, list) and hypotheses, "protocol: hypotheses")
    require(isinstance(cases, list) and cases, "protocol: cases")
    require(isinstance(claims, list) and claims, "protocol: claims")

    hypothesis_ids: set[str] = set()
    for hypothesis in hypotheses:
        require(isinstance(hypothesis, dict), "protocol: hypothesis object")
        for field in ("id", "name", "claim", "decision_rule"):
            require(
                isinstance(hypothesis.get(field), str) and hypothesis[field],
                "protocol: hypothesis field %s" % field,
            )
        require(hypothesis["id"] not in hypothesis_ids, "duplicate hypothesis")
        hypothesis_ids.add(hypothesis["id"])

    case_ids: set[str] = set()
    arm_keys: set[str] = set()
    for case in cases:
        require(isinstance(case, dict), "protocol: case object")
        for field in ("id", "hypothesis", "category", "description", "truth"):
            require(
                isinstance(case.get(field), str) and case[field],
                "protocol: case field %s" % field,
            )
        require(case["id"] not in case_ids, "duplicate case id %r" % case["id"])
        case_ids.add(case["id"])
        require(
            case["hypothesis"] in hypothesis_ids,
            "case %s: unknown hypothesis" % case["id"],
        )
        require(
            case["truth"] in ("accept", "reject", "unknown", "not_run"),
            "case %s: invalid truth" % case["id"],
        )
        accept_outcomes = case.get("accept_outcomes")
        require(
            isinstance(accept_outcomes, list)
            and all(isinstance(item, str) for item in accept_outcomes),
            "case %s: accept_outcomes" % case["id"],
        )
        arms = case.get("arms")
        require(isinstance(arms, list) and arms, "case %s: arms" % case["id"])
        seen_arms: set[str] = set()
        for arm in arms:
            require(isinstance(arm, dict), "case %s: arm object" % case["id"])
            for field in ("id", "kind", "expected"):
                require(
                    isinstance(arm.get(field), str) and arm[field],
                    "case %s: arm field %s" % (case["id"], field),
                )
            require(
                arm["kind"] in ("production", "baseline", "blocked"),
                "case %s arm %s: invalid kind" % (case["id"], arm["id"]),
            )
            require(
                arm["id"] not in seen_arms,
                "case %s: duplicate arm %s" % (case["id"], arm["id"]),
            )
            seen_arms.add(arm["id"])
            key = receipt_key(case["id"], arm["id"])
            require(key not in arm_keys, "duplicate case/arm %s" % key)
            arm_keys.add(key)

    claim_ids: set[str] = set()
    for claim in claims:
        require(isinstance(claim, dict), "protocol: claim object")
        for field in ("id", "hypothesis", "text"):
            require(
                isinstance(claim.get(field), str) and claim[field],
                "protocol: claim field %s" % field,
            )
        require(claim["id"] not in claim_ids, "duplicate claim id")
        claim_ids.add(claim["id"])
        requires = claim.get("requires")
        require(isinstance(requires, list), "claim %s: requires" % claim["id"])
        if claim.get("derived") is not None:
            require(
                claim["derived"] == "decision_quality",
                "claim %s: unknown derived metric" % claim["id"],
            )
            require(not requires, "claim %s: derived claim has requires" % claim["id"])
            continue
        for item in requires:
            require(isinstance(item, dict), "claim %s: require object" % claim["id"])
            for field in ("case", "arm", "expected"):
                require(
                    isinstance(item.get(field), str) and item[field],
                    "claim %s: require field %s" % (claim["id"], field),
                )
            key = receipt_key(item["case"], item["arm"])
            require(key in arm_keys, "claim %s: unknown receipt %s" % (claim["id"], key))
            protocol_arm = find_arm(protocol, item["case"], item["arm"])
            require(
                protocol_arm["expected"] == item["expected"],
                "claim %s: expected %r is not the pre-registered expectation for %s"
                % (claim["id"], item["expected"], key),
            )


def find_case(protocol: dict, case_id: str) -> dict:
    for case in protocol["cases"]:
        if case["id"] == case_id:
            return case
    fail("unknown case %r" % case_id)


def find_arm(protocol: dict, case_id: str, arm_id: str) -> dict:
    case = find_case(protocol, case_id)
    for arm in case["arms"]:
        if arm["id"] == arm_id:
            return arm
    fail("unknown arm %r in case %r" % (arm_id, case_id))


def expected_keys(protocol: dict) -> dict[str, dict]:
    keys: dict[str, dict] = {}
    for case in protocol["cases"]:
        for arm in case["arms"]:
            keys[receipt_key(case["id"], arm["id"])] = {
                "case": case,
                "arm": arm,
            }
    return keys


# ---------------------------------------------------------------------------
# Receipts and manifest
# ---------------------------------------------------------------------------

RECEIPT_FIELDS = {
    "schema",
    "spec",
    "protocol_sha256",
    "case_id",
    "hypothesis",
    "category",
    "arm",
    "arm_kind",
    "expected",
    "observed",
    "pass",
    "truth",
    "accept_outcomes",
    "blocked",
    "measurements",
    "digests",
    "detail",
    "environment",
    "experiment_sha256",
}


def validate_receipt(
    value: object,
    label: str,
    protocol: dict,
    protocol_sha256: str,
) -> dict:
    require(isinstance(value, dict), "%s: expected an object" % label)
    require(
        set(value) == RECEIPT_FIELDS,
        "%s: unexpected or missing fields: %s"
        % (label, sorted(set(value) ^ RECEIPT_FIELDS)),
    )
    require(value["schema"] == RECEIPT_SCHEMA, "%s: schema mismatch" % label)
    require(value["spec"] == SPEC, "%s: spec mismatch" % label)
    require(
        value["protocol_sha256"] == protocol_sha256,
        "%s: protocol digest mismatch" % label,
    )
    case = find_case(protocol, value["case_id"])
    arm = find_arm(protocol, value["case_id"], value["arm"])
    require(value["hypothesis"] == case["hypothesis"], "%s: hypothesis" % label)
    require(value["category"] == case["category"], "%s: category" % label)
    require(value["arm_kind"] == arm["kind"], "%s: arm kind" % label)
    require(value["expected"] == arm["expected"], "%s: expected label" % label)
    require(value["truth"] == case["truth"], "%s: truth label" % label)
    require(
        value["accept_outcomes"] == case["accept_outcomes"],
        "%s: accept_outcomes" % label,
    )
    require(
        isinstance(value["observed"], str) and value["observed"],
        "%s: observed label" % label,
    )
    require(
        isinstance(value["pass"], bool),
        "%s: pass must be boolean" % label,
    )
    require(
        value["pass"] == (value["expected"] == value["observed"]),
        "%s: inconsistent pass flag" % label,
    )
    if value["observed"] == NOT_RUN:
        require(
            isinstance(value["blocked"], str) and value["blocked"],
            "%s: NOT_RUN without a blocked reason" % label,
        )
    else:
        require(value["blocked"] is None, "%s: blocked reason without NOT_RUN" % label)

    measurements = value["measurements"]
    require(isinstance(measurements, dict), "%s: measurements" % label)
    require(
        set(measurements) == {"wall_time_ms", "peak_rss_kb", "output_bytes"},
        "%s: measurement fields" % label,
    )
    for field in ("wall_time_ms", "peak_rss_kb", "output_bytes"):
        require(
            isinstance(measurements[field], int)
            and not isinstance(measurements[field], bool),
            "%s: measurement %s must be an integer" % (label, field),
        )
    require(measurements["wall_time_ms"] >= 0, "%s: negative wall time" % label)
    require(measurements["peak_rss_kb"] > 0, "%s: missing peak RSS" % label)
    require(measurements["output_bytes"] > 0, "%s: missing output bytes" % label)

    digests = value["digests"]
    require(isinstance(digests, dict), "%s: digests" % label)
    require(
        set(digests)
        == {"input_sha256", "observed_sha256", "stdout_sha256", "stderr_sha256"},
        "%s: digest fields" % label,
    )
    for field, digest in digests.items():
        require(is_digest(digest), "%s: %s is not a SHA-256" % (label, field))

    observed_core = {
        "observed": value["observed"],
        "input_sha256": digests["input_sha256"],
        "detail": value["detail"],
    }
    recomputed_observed = sha256_hex(canonical_json(observed_core))
    require(
        recomputed_observed == digests["observed_sha256"],
        "%s: observation digest mismatch (recomputed %s)"
        % (label, recomputed_observed),
    )

    environment = value["environment"]
    require(isinstance(environment, dict), "%s: environment" % label)
    require(
        set(environment)
        == {"crate_version", "rustc_version", "image", "image_id", "command"},
        "%s: environment fields" % label,
    )
    for field in ("crate_version", "rustc_version", "image", "image_id"):
        require(
            isinstance(environment[field], str) and environment[field],
            "%s: environment %s" % (label, field),
        )
    require(
        environment["crate_version"] == CRATE_VERSION,
        "%s: crate version %r != %r"
        % (label, environment["crate_version"], CRATE_VERSION),
    )
    require(
        environment["image"] == RUST_IMAGE,
        "%s: image %r != %r" % (label, environment["image"], RUST_IMAGE),
    )
    require(
        environment["image_id"] == RUST_IMAGE_ID,
        "%s: image id %r != %r"
        % (label, environment["image_id"], RUST_IMAGE_ID),
    )
    require(
        isinstance(environment["command"], list)
        and environment["command"]
        and all(isinstance(item, str) and item for item in environment["command"]),
        "%s: exact command" % label,
    )

    experiment_core = {
        "protocol_sha256": value["protocol_sha256"],
        "case_id": value["case_id"],
        "arm": value["arm"],
        "expected": value["expected"],
        "observed": value["observed"],
        "pass": value["pass"],
        "truth": value["truth"],
        "input_sha256": digests["input_sha256"],
        "observed_sha256": digests["observed_sha256"],
    }
    recomputed_experiment = sha256_hex(canonical_json(experiment_core))
    require(
        recomputed_experiment == value["experiment_sha256"],
        "%s: experiment digest mismatch (recomputed %s)"
        % (label, recomputed_experiment),
    )
    return value


def load_receipts(
    receipts_dir: Path,
    protocol: dict,
    protocol_sha256: str,
) -> dict[str, dict]:
    expected = expected_keys(protocol)
    receipts: dict[str, dict] = {}
    for path in sorted(receipts_dir.glob("*.json")):
        if path.name == "MANIFEST.json":
            continue
        raw = read_bytes(path)
        label = "receipt %s" % path.name
        value = require_canonical(raw, label)
        receipt = validate_receipt(value, label, protocol, protocol_sha256)
        key = receipt_key(receipt["case_id"], receipt["arm"])
        expected_name = "%s__%s.json" % (receipt["case_id"], receipt["arm"])
        require(
            path.name == expected_name,
            "%s: filename does not match case/arm" % label,
        )
        require(key not in receipts, "duplicate receipt %s" % key)
        receipts[key] = receipt

    missing = sorted(set(expected) - set(receipts))
    extra = sorted(set(receipts) - set(expected))
    require(not missing, "missing receipts: %s" % ", ".join(missing))
    require(not extra, "extra receipts: %s" % ", ".join(extra))
    require(
        len(receipts) == EXPECTED_RECEIPTS,
        "receipt count %d != %d" % (len(receipts), EXPECTED_RECEIPTS),
    )
    return receipts


def load_manifest(
    path: Path,
    receipts: dict[str, dict],
    protocol_sha256: str,
) -> dict:
    raw = read_bytes(path)
    value = require_canonical(raw, "receipts/MANIFEST.json")
    require(isinstance(value, dict), "manifest: expected an object")
    require(value.get("schema") == MANIFEST_SCHEMA, "manifest: schema mismatch")
    require(value.get("spec") == SPEC, "manifest: spec mismatch")
    require(
        value.get("protocol_sha256") == protocol_sha256,
        "manifest: protocol digest mismatch",
    )
    require(
        value.get("receipt_count") == len(receipts),
        "manifest: receipt_count mismatch",
    )
    entries = value.get("receipts")
    require(isinstance(entries, list), "manifest: receipts must be a list")
    require(
        len(entries) == len(receipts),
        "manifest: receipt entry count mismatch",
    )
    seen: set[str] = set()
    for entry in entries:
        require(isinstance(entry, dict), "manifest: entry object")
        require(
            set(entry) == {"case_id", "arm", "experiment_sha256", "pass"},
            "manifest: entry fields",
        )
        key = receipt_key(entry["case_id"], entry["arm"])
        require(key not in seen, "manifest: duplicate entry %s" % key)
        seen.add(key)
        require(key in receipts, "manifest: unknown receipt %s" % key)
        require(
            entry["experiment_sha256"] == receipts[key]["experiment_sha256"],
            "manifest: experiment digest mismatch for %s" % key,
        )
        require(
            entry["pass"] == receipts[key]["pass"],
            "manifest: pass flag mismatch for %s" % key,
        )
    require(seen == set(receipts), "manifest: receipt set mismatch")
    return value


# ---------------------------------------------------------------------------
# Reconstruction tables
# ---------------------------------------------------------------------------

def hypothesis_coverage(protocol: dict, receipts: dict[str, dict]) -> dict:
    table: dict[str, dict] = {}
    for hypothesis in protocol["hypotheses"]:
        hypothesis_id = hypothesis["id"]
        declared = hypothesis.get("cases", [])
        if declared:
            cases = [find_case(protocol, case_id) for case_id in declared]
        else:
            cases = [
                case
                for case in protocol["cases"]
                if case["hypothesis"] == hypothesis_id
            ]
        keys = [
            receipt_key(case["id"], arm["id"])
            for case in cases
            for arm in case["arms"]
        ]
        values = [receipts[key] for key in keys]
        table[hypothesis_id] = {
            "cases": len(cases),
            "receipts": len(values),
            "passed": sum(1 for receipt in values if receipt["pass"]),
            "failed": sum(1 for receipt in values if not receipt["pass"]),
            "blocked": sum(1 for receipt in values if receipt["observed"] == NOT_RUN),
            "held_out_cases": sum(1 for case in cases if held_out(case["id"])),
            "development_cases": sum(1 for case in cases if not held_out(case["id"])),
        }
    return table


def arm_table(protocol: dict, receipts: dict[str, dict]) -> dict[str, dict]:
    table: dict[str, dict] = {}
    for case in protocol["cases"]:
        for arm in case["arms"]:
            entry = table.setdefault(
                arm["id"],
                {
                    "kind": arm["kind"],
                    "receipts": 0,
                    "held_out": 0,
                    "held_out_passed": 0,
                    "development": 0,
                    "development_passed": 0,
                    "blocked": 0,
                },
            )
            receipt = receipts[receipt_key(case["id"], arm["id"])]
            entry["receipts"] += 1
            if held_out(case["id"]):
                entry["held_out"] += 1
                entry["held_out_passed"] += 1 if receipt["pass"] else 0
            else:
                entry["development"] += 1
                entry["development_passed"] += 1 if receipt["pass"] else 0
            entry["blocked"] += 1 if receipt["observed"] == NOT_RUN else 0
    return dict(sorted(table.items()))


def decision_table(protocol: dict, receipts: dict[str, dict]) -> dict:
    table: dict[str, dict] = {}
    for case in protocol["cases"]:
        if case["truth"] not in ("accept", "reject"):
            continue
        for arm in case["arms"]:
            key = receipt_key(case["id"], arm["id"])
            receipt = receipts[key]
            split = "held_out" if held_out(case["id"]) else "development"
            entry = table.setdefault(
                arm["id"],
                {
                    "kind": arm["kind"],
                    "held_out": {
                        "true_accept": 0,
                        "true_reject": 0,
                        "false_accept": 0,
                        "false_refuse": 0,
                        "not_run": 0,
                        "total": 0,
                    },
                    "development": {
                        "true_accept": 0,
                        "true_reject": 0,
                        "false_accept": 0,
                        "false_refuse": 0,
                        "not_run": 0,
                        "total": 0,
                    },
                },
            )
            target = entry[split]
            target["total"] += 1
            if receipt["observed"] == NOT_RUN:
                target["not_run"] += 1
                continue
            accepted = receipt["observed"] in case["accept_outcomes"]
            if case["truth"] == "accept" and accepted:
                target["true_accept"] += 1
            elif case["truth"] == "accept":
                target["false_refuse"] += 1
            elif accepted:
                target["false_accept"] += 1
            else:
                target["true_reject"] += 1
    return dict(sorted(table.items()))


def discriminator_table(protocol: dict, receipts: dict[str, dict]) -> dict[str, dict]:
    """For each baseline arm, cases where its expected label differs from the
    production arm's expected label on the same case, split held-out/dev."""
    table: dict[str, dict] = {}
    for case in protocol["cases"]:
        productions = [arm for arm in case["arms"] if arm["kind"] == "production"]
        if len(productions) != 1:
            continue
        production = productions[0]
        for arm in case["arms"]:
            if arm["kind"] != "baseline":
                continue
            if arm["expected"] == production["expected"]:
                continue
            receipt = receipts[receipt_key(case["id"], arm["id"])]
            entry = table.setdefault(
                arm["id"],
                {
                    "held_out": [],
                    "development": [],
                    "held_out_failures": [],
                    "development_failures": [],
                },
            )
            split = "held_out" if held_out(case["id"]) else "development"
            entry[split].append(case["id"])
            if receipt["observed"] == arm["expected"]:
                entry[split + "_failures"].append(case["id"])
    return dict(sorted(table.items()))


def claim_reports(protocol: dict, receipts: dict[str, dict], decision: dict) -> dict:
    reports: dict[str, dict] = {}
    for claim in protocol["claims"]:
        problems: list[str] = []
        evidence: list[str] = []
        if claim.get("derived") == "decision_quality":
            production_false = 0
            baseline_false = 0
            for arm, entry in decision.items():
                held = entry["held_out"]
                development = entry["development"]
                if entry["kind"] == "production":
                    production_false += held["false_accept"] + held["false_refuse"]
                if entry["kind"] == "baseline":
                    baseline_false += (
                        held["false_accept"]
                        + held["false_refuse"]
                        + development["false_accept"]
                        + development["false_refuse"]
                    )
            if production_false != 0:
                problems.append("production held-out false decision")
            if baseline_false == 0:
                problems.append("no baseline made a false decision")
            if not any(entry["held_out"]["total"] for entry in decision.values()):
                problems.append("no held-out decision cases")
            reports[claim["id"]] = {
                "status": "supported" if not problems else "falsified",
                "problems": problems,
                "evidence": [
                    "production held-out false decisions=%d; baseline false decisions=%d"
                    % (production_false, baseline_false)
                ],
            }
            continue
        for item in claim["requires"]:
            key = receipt_key(item["case"], item["arm"])
            receipt = receipts.get(key)
            if receipt is None:
                problems.append("claim requires missing receipt %s" % key)
                continue
            evidence.append("%s=%s" % (key, receipt["observed"]))
            if receipt["observed"] != item["expected"]:
                problems.append(
                    "claim requires %s=%s, observed %s"
                    % (key, item["expected"], receipt["observed"])
                )
        reports[claim["id"]] = {
            "status": "supported" if not problems else "falsified",
            "problems": problems,
            "evidence": evidence,
        }
    return reports


def resources(receipts: dict[str, dict]) -> dict:
    wall = [receipt["measurements"]["wall_time_ms"] for receipt in receipts.values()]
    rss = [receipt["measurements"]["peak_rss_kb"] for receipt in receipts.values()]
    output = [receipt["measurements"]["output_bytes"] for receipt in receipts.values()]
    return {
        "receipts": len(receipts),
        "wall_time_ms_sum": sum(wall),
        "output_bytes_sum": sum(output),
        "peak_rss_kb_min": min(rss),
        "peak_rss_kb_max": max(rss),
        "peak_rss_kb_sum": sum(rss),
        "wall_time_ms_max": max(wall),
    }


def negative_findings(
    protocol: dict,
    receipts: dict[str, dict],
    decision: dict,
    discriminators: dict,
) -> list[str]:
    findings: list[str] = []

    def has_no_held_out_discriminator(arm: str) -> bool:
        entry = discriminators.get(arm)
        return (
            entry is not None
            and not entry["held_out"]
            and bool(entry["development"])
        )

    if has_no_held_out_discriminator("boolean_aliasing"):
        findings.append("N1:boolean_aliasing_no_held_out_discriminator")
    if has_no_held_out_discriminator("over_cut"):
        findings.append("N2:over_cut_no_held_out_discriminator")
    top = decision.get("top_as_exact")
    if top is not None:
        total_false = sum(
            top[split]["false_accept"] + top[split]["false_refuse"]
            for split in ("held_out", "development")
        )
        if total_false == 0:
            findings.append("N3:top_as_exact_zero_false_decisions")
    s1_lfp = receipts[receipt_key("S1-grounded-cycle", "lfp")]["observed"]
    s1_gfp = receipts[receipt_key("S1-grounded-cycle", "gfp")]["observed"]
    if s1_lfp == s1_gfp == "supported":
        findings.append("N4:gfp_agrees_on_grounded_cycle")
    if (
        receipts[receipt_key("R1-proof-approved", "parser_only")]["observed"]
        == "accepted_within_scope"
    ):
        findings.append("N5:parser_only_accepts_approved_manifest")
    if (
        receipts[receipt_key("D1-detector-authentic-calibrated", "raw_stdout")][
            "observed"
        ]
        == "calibrated"
    ):
        findings.append("N6:raw_stdout_accepts_authentic_calibration")
    if (
        receipts[
            receipt_key("R1-proof-approved", "closure_and_correspondence")
        ]["observed"]
        == "accepted_admission_checker_unavailable"
    ):
        findings.append("N7:no_live_proof_checker_ran")
    blocked = [
        receipt_key("D6-detector-live-miri", "live_miri"),
        receipt_key("R5-proof-live-coq", "live_coq"),
        receipt_key("E6-discovery-authentic-chain", "bridge_verify"),
    ]
    if all(receipts[key]["observed"] == NOT_RUN for key in blocked):
        findings.append("N8:live_controls_not_run")
    return findings


def blocked_controls(protocol: dict, receipts: dict[str, dict]) -> dict:
    controls: dict[str, str] = {}
    for case in protocol["cases"]:
        for arm in case["arms"]:
            if arm["kind"] != "blocked":
                continue
            key = receipt_key(case["id"], arm["id"])
            controls[key] = receipts[key]["observed"]
    return {"count": len(controls), "controls": dict(sorted(controls.items()))}


# ---------------------------------------------------------------------------
# Paper claims
# ---------------------------------------------------------------------------

def load_claims(path: Path, protocol: dict, protocol_sha256: str) -> dict:
    raw = read_bytes(path)
    value = parse_json(raw, "evaluation/CLAIMS.json")
    require(isinstance(value, dict), "CLAIMS.json: expected an object")
    require(value.get("schema") == CLAIMS_SCHEMA, "CLAIMS.json: schema mismatch")
    require(
        value.get("protocol_sha256") == protocol_sha256,
        "CLAIMS.json: protocol digest mismatch",
    )
    constants = value.get("constants")
    require(isinstance(constants, dict), "CLAIMS.json: constants")
    expected_constants = {
        "protocol_version": protocol["protocol_version"],
        "protocol_sha256": protocol_sha256,
        "receipts": EXPECTED_RECEIPTS,
        "cases": EXPECTED_CASES,
        "held_out_cases": EXPECTED_HELD_OUT,
        "development_cases": EXPECTED_DEVELOPMENT,
        "protocol_claims": EXPECTED_CLAIMS,
        "paper_claims": EXPECTED_PAPER_CLAIMS,
        "rust_image": RUST_IMAGE,
        "rust_image_id": RUST_IMAGE_ID,
        "rust_image_digest": RUST_IMAGE_DIGEST,
        "python_image": PYTHON_IMAGE,
        "python_image_id": PYTHON_IMAGE_ID,
        "python_image_digest": PYTHON_IMAGE_DIGEST,
        "memory_limit_mb": MEMORY_LIMIT_MB,
        "memory_swap_limit_mb": MEMORY_SWAP_LIMIT_MB,
        "reconstruction_memory_limit_mb": RECONSTRUCTION_MEMORY_LIMIT_MB,
        "pids_limit": PIDS_LIMIT,
        "cpus": CPUS,
        "nofile_limit": NOFILE_LIMIT,
        "oom_score_adj": OOM_SCORE_ADJ,
        "timeout_seconds": TIMEOUT_SECONDS,
    }
    expected_constants["crate_version"] = CRATE_VERSION
    require(
        constants == expected_constants,
        "CLAIMS.json: constants do not match the frozen reconstruction constants",
    )
    claims = value.get("claims")
    require(isinstance(claims, list) and claims, "CLAIMS.json: claims")
    require(
        len(claims) == EXPECTED_PAPER_CLAIMS,
        "CLAIMS.json: expected %d paper claims, found %d"
        % (EXPECTED_PAPER_CLAIMS, len(claims)),
    )
    ids: set[str] = set()
    protocol_claim_ids = {claim["id"] for claim in protocol["claims"]}
    for claim in claims:
        require(isinstance(claim, dict), "CLAIMS.json: claim object")
        required = {
            "id",
            "protocol_claims",
            "hypothesis",
            "statement",
            "metric",
            "expected",
            "receipts",
            "observed",
            "status",
            "kind",
            "in_paper",
            "check",
        }
        require(
            set(claim) == required,
            "CLAIMS.json: claim %r fields %s"
            % (claim.get("id"), sorted(set(claim) ^ required)),
        )
        require(
            isinstance(claim["id"], str) and claim["id"].startswith("PC"),
            "CLAIMS.json: claim id %r" % claim.get("id"),
        )
        require(claim["id"] not in ids, "CLAIMS.json: duplicate claim %r" % claim["id"])
        ids.add(claim["id"])
        require(
            isinstance(claim["protocol_claims"], list)
            and all(
                item in protocol_claim_ids or item == "derived"
                for item in claim["protocol_claims"]
            ),
            "CLAIMS.json: claim %s protocol_claims" % claim["id"],
        )
        require(
            claim["status"] in ("supported", "unsupported"),
            "CLAIMS.json: claim %s status" % claim["id"],
        )
        require(
            claim["kind"] in ("measured", "negative_finding"),
            "CLAIMS.json: claim %s kind" % claim["id"],
        )
        require(
            isinstance(claim["receipts"], list),
            "CLAIMS.json: claim %s receipts" % claim["id"],
        )
        require(
            isinstance(claim["observed"], dict),
            "CLAIMS.json: claim %s observed" % claim["id"],
        )
        require(
            isinstance(claim["check"], dict)
            and isinstance(claim["check"].get("type"), str),
            "CLAIMS.json: claim %s check" % claim["id"],
        )
        require(
            isinstance(claim["in_paper"], bool),
            "CLAIMS.json: claim %s in_paper" % claim["id"],
        )
    return value


def verify_paper_claim_table(paper_path: Path, claims: dict) -> set[str]:
    text = read_bytes(paper_path).decode("utf-8", errors="strict")
    rows: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("| PC"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        rows.append(cells[0])
    require(rows, "PAPER.md: no claim table rows starting with '| PC'")
    table_ids = set(rows)
    require(
        len(table_ids) == len(rows),
        "PAPER.md: duplicate claim ids in the claim table",
    )
    claimed_ids = {claim["id"] for claim in claims["claims"]}
    require(
        table_ids == claimed_ids,
        "PAPER.md: claim table ids %s do not match CLAIMS.json ids %s"
        % (sorted(table_ids), sorted(claimed_ids)),
    )
    for claim in claims["claims"]:
        if claim["in_paper"]:
            require(
                claim["id"] in table_ids,
                "PAPER.md: claim %s is missing from the claim table" % claim["id"],
            )
        require(
            claim["receipts"],
            "CLAIMS.json: claim %s has no receipt mapping" % claim["id"],
        )
    return table_ids


def compute_claim_observed(
    claim: dict,
    protocol: dict,
    receipts: dict[str, dict],
    decision: dict,
    discriminators: dict,
    hypotheses: dict,
    resources_table: dict,
    findings: list[str],
    blocked: dict,
    protocol_claims: dict,
) -> dict:
    check = claim["check"]
    kind = check["type"]
    if kind == "all_receipts":
        return {
            "receipts": len(receipts),
            "passed": sum(1 for receipt in receipts.values() if receipt["pass"]),
            "failed": sum(1 for receipt in receipts.values() if not receipt["pass"]),
            "blocked": sum(
                1 for receipt in receipts.values() if receipt["observed"] == NOT_RUN
            ),
        }
    if kind == "split":
        held_cases = [case["id"] for case in protocol["cases"] if held_out(case["id"])]
        development_cases = [
            case["id"] for case in protocol["cases"] if not held_out(case["id"])
        ]
        held_receipts = sum(
            1
            for case in protocol["cases"]
            if held_out(case["id"])
            for _ in case["arms"]
        )
        development_receipts = sum(
            1
            for case in protocol["cases"]
            if not held_out(case["id"])
            for _ in case["arms"]
        )
        return {
            "cases": len(protocol["cases"]),
            "held_out_cases": len(held_cases),
            "development_cases": len(development_cases),
            "held_out_receipts": held_receipts,
            "development_receipts": development_receipts,
        }
    if kind == "protocol_claims":
        return {
            "claims": len(protocol_claims),
            "supported": sum(
                1
                for report in protocol_claims.values()
                if report["status"] == "supported"
            ),
            "falsified": sum(
                1
                for report in protocol_claims.values()
                if report["status"] != "supported"
            ),
            "statuses": {
                claim_id: report["status"]
                for claim_id, report in sorted(protocol_claims.items())
            },
        }
    if kind == "production_decision_quality":
        production = {
            arm: entry
            for arm, entry in decision.items()
            if entry["kind"] == "production"
        }
        return {
            "arms": len(production),
            "held_out_decisions": sum(
                entry["held_out"]["total"] for entry in production.values()
            ),
            "held_out_false_accept": sum(
                entry["held_out"]["false_accept"] for entry in production.values()
            ),
            "held_out_false_refuse": sum(
                entry["held_out"]["false_refuse"] for entry in production.values()
            ),
            "held_out_not_run": sum(
                entry["held_out"]["not_run"] for entry in production.values()
            ),
        }
    if kind == "arm_decisions":
        arms = check["arms"]
        return {
            arm: {
                "kind": decision[arm]["kind"],
                "held_out": decision[arm]["held_out"],
                "development": decision[arm]["development"],
            }
            for arm in arms
        }
    if kind == "arm_decisions_with_outcomes":
        arms = check["arms"]
        return {
            "decisions": {
                arm: {
                    "kind": decision[arm]["kind"],
                    "held_out": decision[arm]["held_out"],
                    "development": decision[arm]["development"],
                }
                for arm in arms
            },
            "outcomes": {key: receipts[key]["observed"] for key in check["receipts"]},
        }
    if kind == "receipt_outcomes":
        return {
            key: receipts[key]["observed"]
            for key in check["receipts"]
        }
    if kind == "discrimination":
        arms = {
            arm: discriminators.get(
                arm,
                {
                    "held_out": [],
                    "development": [],
                    "held_out_failures": [],
                    "development_failures": [],
                },
            )
            for arm in check["arms"]
        }
        held_out_zero = sorted(
            arm
            for arm, entry in arms.items()
            if not entry["held_out"] and entry["development"]
        )
        development_zero = sorted(
            arm
            for arm, entry in arms.items()
            if not entry["development"] and entry["held_out"]
        )
        return {
            "arms": arms,
            "held_out_zero": held_out_zero,
            "held_out_zero_count": len(held_out_zero),
            "development_zero": development_zero,
            "development_zero_count": len(development_zero),
        }
    if kind == "resources":
        return resources_table
    if kind == "negative_findings":
        return {"count": len(findings), "findings": findings}
    if kind == "blocked_controls":
        return blocked
    if kind == "hypothesis_coverage":
        return hypotheses
    fail("CLAIMS.json: claim %s has unknown check type %r" % (claim["id"], kind))


# ---------------------------------------------------------------------------
# Main reconstruction
# ---------------------------------------------------------------------------

def reconstruct(root: Path) -> dict:
    protocol_path = root / "evaluation" / "protocol.json"
    receipts_dir = root / "evaluation" / "receipts"
    manifest_path = receipts_dir / "MANIFEST.json"

    protocol_raw = read_bytes(protocol_path)
    protocol_sha256 = sha256_hex(protocol_raw)
    require(
        protocol_sha256 == PROTOCOL_DIGEST,
        "protocol digest %s does not match the frozen digest %s"
        % (protocol_sha256, PROTOCOL_DIGEST),
    )
    protocol = parse_json(protocol_raw, "evaluation/protocol.json")
    validate_protocol(protocol)
    require(
        len(list(receipts_dir.glob("*.json"))) - 1 == EXPECTED_RECEIPTS,
        "receipt file count mismatch",
    )

    receipts = load_receipts(receipts_dir, protocol, protocol_sha256)
    manifest = load_manifest(manifest_path, receipts, protocol_sha256)

    cases = protocol["cases"]
    held_cases = [case for case in cases if held_out(case["id"])]
    development_cases = [case for case in cases if not held_out(case["id"])]
    require(len(cases) == EXPECTED_CASES, "case count mismatch")
    require(len(held_cases) == EXPECTED_HELD_OUT, "held-out case count mismatch")
    require(
        len(development_cases) == EXPECTED_DEVELOPMENT,
        "development case count mismatch",
    )

    failed = [key for key, receipt in receipts.items() if not receipt["pass"]]
    require(not failed, "receipts do not match their pre-registered expectation: %s"
            % ", ".join(sorted(failed)))

    hypotheses = hypothesis_coverage(protocol, receipts)
    arms = arm_table(protocol, receipts)
    decision = decision_table(protocol, receipts)
    discriminators = discriminator_table(protocol, receipts)
    protocol_claims = claim_reports(protocol, receipts, decision)
    resources_table = resources(receipts)
    findings = negative_findings(protocol, receipts, decision, discriminators)
    blocked = blocked_controls(protocol, receipts)

    unsupported_claims = [
        claim_id
        for claim_id, report in protocol_claims.items()
        if report["status"] != "supported"
    ]
    require(
        not unsupported_claims,
        "unsupported protocol claims: %s" % ", ".join(sorted(unsupported_claims)),
    )
    require(
        len(protocol_claims) == EXPECTED_CLAIMS,
        "protocol claim count mismatch",
    )

    claims_value = load_claims(
        root / "evaluation" / "CLAIMS.json", protocol, protocol_sha256
    )
    paper_ids = verify_paper_claim_table(root / "PAPER.md", claims_value)
    for claim in claims_value["claims"]:
        observed = compute_claim_observed(
            claim,
            protocol,
            receipts,
            decision,
            discriminators,
            hypotheses,
            resources_table,
            findings,
            blocked,
            protocol_claims,
        )
        require(
            observed == claim["observed"],
            "CLAIMS.json: claim %s observed value mismatch\n  expected: %s\n  computed: %s"
            % (claim["id"], json.dumps(claim["observed"], sort_keys=True),
               json.dumps(observed, sort_keys=True)),
        )
        if claim["check"]["type"] in (
            "all_receipts",
            "split",
            "protocol_claims",
            "production_decision_quality",
            "arm_decisions",
            "arm_decisions_with_outcomes",
            "receipt_outcomes",
            "discrimination",
            "resources",
            "negative_findings",
            "blocked_controls",
            "hypothesis_coverage",
        ):
            require(
                claim["status"] == "supported",
                "CLAIMS.json: measured claim %s is not supported" % claim["id"],
            )
        for key in claim["receipts"]:
            require(
                key in receipts,
                "CLAIMS.json: claim %s names missing receipt %s"
                % (claim["id"], key),
            )

    return {
        "protocol_sha256": protocol_sha256,
        "protocol_version": protocol["protocol_version"],
        "receipts_total": len(receipts),
        "receipts_passed": sum(1 for receipt in receipts.values() if receipt["pass"]),
        "receipts_failed": sum(1 for receipt in receipts.values() if not receipt["pass"]),
        "cases_total": len(cases),
        "held_out_cases": len(held_cases),
        "development_cases": len(development_cases),
        "manifest_receipts": manifest["receipt_count"],
        "hypotheses": hypotheses,
        "arms": arms,
        "decision": decision,
        "discriminators": discriminators,
        "protocol_claims": protocol_claims,
        "resources": resources_table,
        "blocked": blocked,
        "negative_findings": findings,
        "paper_claims": {
            claim["id"]: {
                "status": claim["status"],
                "metric": claim["metric"],
                "observed": claim["observed"],
            }
            for claim in claims_value["claims"]
        },
        "paper_claim_ids": sorted(paper_ids),
        "claim_count": len(claims_value["claims"]),
    }


def print_report(report: dict) -> None:
    print("FRF-MemorySafety Phase 9.2 independent reconstruction")
    print("  protocol: %s (%s)" % (report["protocol_version"], report["protocol_sha256"]))
    print(
        "  receipts: %d/%d pass; cases %d (%d held-out, %d development)"
        % (
            report["receipts_passed"],
            report["receipts_total"],
            report["cases_total"],
            report["held_out_cases"],
            report["development_cases"],
        )
    )
    print("  manifest entries: %d" % report["manifest_receipts"])
    print("  protocol claims: %d/%d supported" % (
        sum(
            1
            for status in report["protocol_claims"].values()
            if status["status"] == "supported"
        ),
        len(report["protocol_claims"]),
    ))
    print("  paper claims: %d (%s)" % (
        report["claim_count"],
        ", ".join(report["paper_claim_ids"]),
    ))
    print("  hypotheses:")
    for hypothesis_id, entry in report["hypotheses"].items():
        print(
            "    %s receipts=%d passed=%d failed=%d blocked=%d "
            "held_out_cases=%d development_cases=%d"
            % (
                hypothesis_id,
                entry["receipts"],
                entry["passed"],
                entry["failed"],
                entry["blocked"],
                entry["held_out_cases"],
                entry["development_cases"],
            )
        )
    print("  decision quality (false accepts / false refuses):")
    for arm, entry in report["decision"].items():
        held = entry["held_out"]
        development = entry["development"]
        print(
            "    %-28s held-out %d/%d  development %d/%d  not_run %d/%d"
            % (
                arm,
                held["false_accept"],
                held["false_refuse"],
                development["false_accept"],
                development["false_refuse"],
                held["not_run"],
                development["not_run"],
            )
        )
    print("  negative findings: %d" % len(report["negative_findings"]))
    for finding in report["negative_findings"]:
        print("    %s" % finding)
    print("  resources: wall=%d ms output=%d bytes rss=%d..%d KiB sum=%d KiB"
          % (
              report["resources"]["wall_time_ms_sum"],
              report["resources"]["output_bytes_sum"],
              report["resources"]["peak_rss_kb_min"],
              report["resources"]["peak_rss_kb_max"],
              report["resources"]["peak_rss_kb_sum"],
          ))
    print("PASS independent reconstruction")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (default: parent of evaluation/)",
    )
    parser.add_argument("--json", action="store_true", help="emit the full report as JSON")
    parser.add_argument("--report", type=Path, help="write the full report as JSON")
    args = parser.parse_args(argv)
    try:
        report = reconstruct(args.root)
    except ReconstructionError as error:
        print("FAIL independent reconstruction: %s" % error, file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_report(report)
    if args.report:
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
