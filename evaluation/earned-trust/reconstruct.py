#!/usr/bin/env python3
"""Independent reconstruction of the FRF-MemorySafety ETP Phase 10.2 campaign.

This program is deliberately algorithmically separate from the Rust campaign
verifier. It reads only the frozen opening inventory, the committed closure
manifest, the committed per-case receipts, the committed raw evidence, and the
committed SARIF projection. It does not import or execute the crate.

It recomputes:

* the opening freeze digest and the candidate/instrument file and tree digests;
* exact population coverage (missing, duplicate, unexpected, truncated cases);
* every terminal outcome, derived decision, resolution, and release decision;
* every receipt, raw-evidence, and closure digest;
* outcome/decision counts and retained-finding counts;
* the SARIF rule, occurrence, candidate, instrument-execution, location, and
  suppression mappings from the raw receipts;
* the SARIF completeness and limit records.

Any missing, extra, duplicate, truncated, non-canonical, tampered, or
inconsistent artifact is a hard failure (exit 1). The script is
standard-library only.

Usage:
    python3 evaluation/earned-trust/reconstruct.py [--root DIR] [--json]

The gate invocation is ``./ci/etp-gate.sh``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

CAMPAIGN_DIR = "evaluation/earned-trust"
CAMPAIGN_ID = "frf-etp-native-fixtures-2026-11-22"
OPENING_SHA256 = "fc9202bc553472bb94362e4de1d4da168f51ebd5be624eefc5cf0d334d8fa7ec"
EXPECTED_CASES = 13
EXPECTED_RECEIPTS = 13
EXPECTED_RAW_EVIDENCE = 25
EXPECTED_PASS = 13
EXPECTED_FINDING_CASES = 9
EXPECTED_ACCEPTED_CASES = 4
EXPECTED_RESULTS = 18
EXPECTED_RULES = 11
EXPECTED_OUTCOMES = {
    "verified_compatible_within_transcript": 4,
    "observed_violation": 6,
    "incomplete_transcript": 1,
    "unresolved": 2,
}
EXPECTED_DECISIONS = {"pass": 13}
TREE_ALGORITHM = "sha256-sorted-path-nul-digest-lf-v1"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
SARIF_PROJECTION_SCHEMA = "frf-etp.sarif-projection.v1"
SARIF_TOOL_NAME = "frf-etp-sarif-projection"
MAX_SARIF_RESULTS = 1000
MAX_SARIF_BYTES = 4 * 1024 * 1024
SARIF_CLAIM_CEILING = (
    "A SARIF document is a report projection, not a correctness, memory-safety, "
    "compatibility, or security proof. The projection preserves campaign identities "
    "and exports failures and unresolved conditions. It does not establish that a "
    "finding was repaired, that a missing finding is safe, that a source location is "
    "complete, that a suppression is justified beyond its declared fields, or that a "
    "code-scanning view is authoritative. A digest is not authentication."
)


class ReconstructionError(Exception):
    """A hard reconstruction failure."""


def fail(message: str) -> None:
    raise ReconstructionError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        fail("%s: cannot read: %s" % (path, error))


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        fail("%s: cannot read: %s" % (path, error))


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
# File and tree digests
# ---------------------------------------------------------------------------


def digest_file(root: Path, relative: str) -> str:
    require(isinstance(relative, str) and relative and not relative.startswith("/"), "unsafe path %r" % (relative,))
    require(".." not in Path(relative).parts, "unsafe path %r" % (relative,))
    return sha256_hex(read_bytes(root / relative))


def tree_digest(files: list[dict[str, object]]) -> str:
    hasher = hashlib.sha256()
    for item in sorted(files, key=lambda value: str(value["path"]).encode("utf-8")):
        hasher.update(str(item["path"]).encode("utf-8"))
        hasher.update(b"\x00")
        hasher.update(str(item["sha256"]).encode("ascii"))
        hasher.update(b"\n")
    return hasher.hexdigest()


def verify_declared_files(
    root: Path, label: str, files: list[dict[str, object]], expected_tree: str
) -> None:
    require(isinstance(files, list) and files, "%s file list is empty" % label)
    seen = set()
    for item in files:
        path = item.get("path")
        digest = item.get("sha256")
        require(isinstance(path, str) and path, "%s file path is missing" % label)
        require(is_digest(digest), "%s file digest is invalid for %s" % (label, path))
        require(path not in seen, "duplicate %s file path %s" % (label, path))
        seen.add(path)
        actual = digest_file(root, path)
        require(actual == digest, "%s file %s changed: %s != %s" % (label, path, actual, digest))
    actual_tree = tree_digest(files)
    require(actual_tree == expected_tree, "%s tree digest is %s, declared %s" % (label, actual_tree, expected_tree))


# ---------------------------------------------------------------------------
# Campaign model helpers
# ---------------------------------------------------------------------------

CLEAN = "verified_compatible_within_transcript"


def derive_decision(expected: str, observed: str) -> str:
    if observed == "not_run":
        return "not_run"
    if observed == "harness_failure":
        return "fail"
    return "pass" if observed == expected else "fail"


def derive_resolution(observed: str) -> str:
    if observed == "unresolved":
        return "unresolved"
    if observed in ("not_run", "harness_failure"):
        return "not_applicable"
    return "resolved"


def derive_release(observed: str, decision: str) -> str:
    if decision in ("not_run", "fail") or observed in ("harness_failure", "illegal_case"):
        return "blocked"
    if observed == CLEAN:
        return "eligible"
    if observed in ("observed_violation", "incomplete_transcript", "unresolved"):
        return "withheld"
    return "not_applicable"


def instrument_execution_identity(instrument_id: str, execution: dict[str, object]) -> str:
    hasher = hashlib.sha256()
    hasher.update(b"frf-etp.instrument-execution.v1\n")
    for value in [
        instrument_id,
        execution.get("environment", ""),
        execution.get("image_id", ""),
        execution.get("executable_sha256", ""),
    ]:
        hasher.update(str(value).encode("utf-8"))
        hasher.update(b"\n")
    for tool in sorted(execution.get("tool_versions", [])):
        hasher.update(str(tool).encode("utf-8"))
        hasher.update(b"\n")
    return hasher.hexdigest()


def counts(values: list[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values:
        result[value] = result.get(value, 0) + 1
    return result


# ---------------------------------------------------------------------------
# SARIF projection helpers
# ---------------------------------------------------------------------------


def sanitize_hazard(value: str) -> str:
    return "".join(char.upper() if char.isascii() and char.isalnum() else "-" for char in value)


def rule_id(outcome: str, hazard: str) -> str:
    outcome_label = sanitize_hazard(outcome)
    hazard_label = sanitize_hazard(hazard)
    if hazard_label == outcome_label:
        return "FRF-ETP-%s" % outcome_label
    return "FRF-ETP-%s-%s" % (outcome_label, hazard_label)


def level_for(outcome: str) -> str:
    if outcome in ("observed_violation", "illegal_case", "harness_failure"):
        return "error"
    if outcome in ("incomplete_transcript", "unresolved"):
        return "warning"
    if outcome == "not_run":
        return "note"
    return "none"


def finding_codes(receipt: dict[str, object]) -> list[str]:
    return [finding["code"] for finding in receipt["observation"]["findings"]]


def hazards(receipt: dict[str, object]) -> list[tuple[str, dict[str, object] | None]]:
    findings = receipt["observation"]["findings"]
    if not findings:
        return [(receipt["observation"]["outcome"], None)]
    return [(finding["code"], finding) for finding in findings]


def message_for(receipt: dict[str, object], hazard: str, finding: dict[str, object] | None) -> str:
    detail = finding["detail"] if finding is not None else receipt["observation"]["detail"]
    return "%s: %s [%s] %s" % (receipt["case_id"], receipt["observation"]["outcome"], hazard, detail)


def project_results(protocol: dict[str, object], receipts: list[dict[str, object]]) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for receipt in sorted(receipts, key=lambda value: value["case_id"]):
        if receipt["observation"]["outcome"] == CLEAN:
            continue
        has_transcript = any(item["kind"] == "transcript" for item in receipt["evidence"])
        for index, (hazard, finding) in enumerate(hazards(receipt)):
            occurrence_id = "%s::%s::%d" % (receipt["case_id"], hazard, index)
            locations: list[dict[str, object]] = []
            if has_transcript:
                logical = []
                if finding is not None and finding["subject"]:
                    logical.append({"kind": "object", "name": finding["subject"]})
                locations.append(
                    {
                        "logicalLocations": logical,
                        "physicalLocation": {
                            "artifactLocation": {"uri": receipt["execution"]["fixture_path"]}
                        },
                    }
                )
            suppressions = []
            suppression = receipt["suppression"]
            if suppression["suppressed"]:
                suppressions.append(
                    {
                        "justification": suppression["justification"],
                        "kind": "external",
                        "properties": {
                            "expiry": suppression["expiry"],
                            "invalidation": suppression["invalidation"],
                            "owner": suppression["owner"],
                            "scope": suppression["scope"],
                        },
                    }
                )
            fingerprints = {
                "frf/candidate": receipt["candidate_identity"],
                "frf/case": receipt["case_id"],
                "frf/instrument-execution": receipt["instrument_execution_identity"],
                "frf/occurrence": occurrence_id,
            }
            results.append(
                {
                    "baselineState": "new",
                    "fingerprints": fingerprints,
                    "level": level_for(receipt["observation"]["outcome"]),
                    "locations": locations,
                    "message": {"text": message_for(receipt, hazard, finding)},
                    "partialFingerprints": {},
                    "properties": {
                        "absence_evidence": [],
                        "absence_reason": "not_compared",
                        "candidate_identity": receipt["candidate_identity"],
                        "case_id": receipt["case_id"],
                        "decision": receipt["adjudication"]["decision"],
                        "evidence_sha256": [item["sha256"] for item in receipt["evidence"]],
                        "expected_outcome": receipt["adjudication"]["expected_outcome"],
                        "finding_codes": finding_codes(receipt),
                        "hazard": hazard,
                        "instrument_execution_identity": receipt["instrument_execution_identity"],
                        "obligations": receipt["obligations"],
                        "observed_outcome": receipt["observation"]["outcome"],
                        "occurrence_id": occurrence_id,
                        "previous_instrument_execution_identity": "",
                        "release_decision": receipt["release_decision"],
                        "requirement": receipt["requirement"],
                        "scope": protocol["scope"],
                    },
                    "ruleId": rule_id(receipt["observation"]["outcome"], hazard),
                    "ruleIndex": 0,
                    "suppressions": suppressions,
                }
            )
    rules: dict[str, dict[str, object]] = {}
    for result in results:
        rules.setdefault(
            result["ruleId"],
            {"level": result["level"], "name": result["properties"]["hazard"]},
        )
    indexes = {rule: index for index, rule in enumerate(sorted(rules))}
    for result in results:
        result["ruleIndex"] = indexes[result["ruleId"]]
    return results


def expected_rule_table(results: list[dict[str, object]]) -> list[dict[str, object]]:
    rules: dict[str, dict[str, object]] = {}
    for result in results:
        rules.setdefault(
            result["ruleId"],
            {
                "id": result["ruleId"],
                "level": result["level"],
                "name": result["properties"]["hazard"],
            },
        )
    return [rules[key] for key in sorted(rules)]


# ---------------------------------------------------------------------------
# Reconstruction
# ---------------------------------------------------------------------------


def reconstruct(root: Path) -> dict[str, object]:
    campaign = root / CAMPAIGN_DIR
    protocol_path = campaign / "protocol.json"
    closure_path = campaign / "MANIFEST.json"
    sarif_path = campaign / "campaign.sarif"
    receipts_dir = campaign / "receipts"
    raw_dir = receipts_dir / "raw"

    protocol_bytes = read_bytes(protocol_path)
    opening = sha256_hex(protocol_bytes)
    require(opening == OPENING_SHA256, "opening digest is %s, expected %s" % (opening, OPENING_SHA256))
    sidecar = read_text(campaign / "opening.sha256").split()
    require(sidecar and sidecar[0] == OPENING_SHA256, "opening.sha256 does not name the frozen digest")

    protocol = parse_json(protocol_bytes, "protocol.json")
    require(protocol["schema"] == "frf-etp.campaign-protocol.v1", "protocol schema")
    require(protocol["spec"] == "frf-etp-v1", "protocol spec")
    require(protocol["campaign_id"] == CAMPAIGN_ID, "campaign id")
    require(protocol["candidate"]["tree_sha256_algorithm"] == TREE_ALGORITHM, "candidate tree algorithm")
    require(protocol["instrument"]["tree_sha256_algorithm"] == TREE_ALGORITHM, "instrument tree algorithm")
    verify_declared_files(
        root,
        "candidate",
        protocol["candidate"]["files"],
        protocol["candidate"]["tree_sha256"],
    )
    verify_declared_files(
        root,
        "instrument",
        protocol["instrument"]["files"],
        protocol["instrument"]["tree_sha256"],
    )
    require(protocol["acceptance_policy"]["not_run_is_pass"] is False, "NOT_RUN must not be a pass")

    population = protocol["population"]
    require(isinstance(population, list) and len(population) == EXPECTED_CASES, "population size")
    population_by_id: dict[str, dict[str, object]] = {}
    for case in population:
        case_id = case["id"]
        require(case_id not in population_by_id, "duplicate population case %s" % case_id)
        population_by_id[case_id] = case
    require(len(population_by_id) == EXPECTED_CASES, "population identity count")

    closure_bytes = read_bytes(closure_path)
    closure = require_canonical(closure_bytes, "MANIFEST.json")
    require(closure["schema"] == "frf-etp.campaign-closure.v1", "closure schema")
    require(closure["spec"] == "frf-etp-v1", "closure spec")
    require(closure["campaign_id"] == CAMPAIGN_ID, "closure campaign id")
    require(closure["opening_sha256"] == OPENING_SHA256, "closure opening digest")
    require(closure["candidate_identity"] == protocol["candidate"]["tree_sha256"], "closure candidate identity")
    require(closure["instrument_id"] == protocol["instrument"]["id"], "closure instrument id")
    require(closure["case_count"] == EXPECTED_CASES, "closure case count")
    require(closure["receipt_count"] == EXPECTED_RECEIPTS, "closure receipt count")
    require(closure["raw_evidence_count"] == EXPECTED_RAW_EVIDENCE, "closure raw evidence count")

    receipt_files = sorted(path for path in receipts_dir.glob("*.json") if path.is_file())
    require(len(receipt_files) == EXPECTED_RECEIPTS, "receipt file count is %d" % len(receipt_files))
    receipts: list[dict[str, object]] = []
    receipt_by_case: dict[str, dict[str, object]] = {}
    receipt_digest_by_case: dict[str, str] = {}
    for path in receipt_files:
        raw = read_bytes(path)
        receipt = require_canonical(raw, str(path.relative_to(root)))
        require(receipt["schema"] == "frf-etp.campaign-receipt.v1", "receipt schema")
        require(receipt["spec"] == "frf-etp-v1", "receipt spec")
        require(receipt["campaign_id"] == CAMPAIGN_ID, "receipt campaign id")
        case_id = receipt["case_id"]
        require(case_id in population_by_id, "unexpected receipt case %s" % case_id)
        require(case_id not in receipt_by_case, "duplicate receipt case %s" % case_id)
        case = population_by_id[case_id]
        require(receipt["candidate_identity"] == protocol["candidate"]["tree_sha256"], "wrong candidate %s" % case_id)
        require(receipt["instrument_id"] == protocol["instrument"]["id"], "wrong instrument %s" % case_id)
        require(receipt["requirement"] == case["requirement"], "requirement mismatch %s" % case_id)
        require(receipt["obligations"] == case["obligations"], "obligation mismatch %s" % case_id)
        require(receipt["adjudication"]["expected_outcome"] == case["expected_outcome"], "expected outcome %s" % case_id)
        require(receipt["adjudication"]["mandatory_resolution"] == case["mandatory_resolution"], "mandatory flag %s" % case_id)
        require(receipt["claim"] in {claim["id"] for claim in protocol["claims"]}, "unknown claim %s" % case_id)
        observed = receipt["observation"]["outcome"]
        require(receipt["adjudication"]["observed_outcome"] == observed, "observed outcome %s" % case_id)
        decision = derive_decision(case["expected_outcome"], observed)
        require(receipt["adjudication"]["decision"] == decision, "decision mismatch %s" % case_id)
        require(receipt["adjudication"]["resolution"] == derive_resolution(observed), "resolution mismatch %s" % case_id)
        require(receipt["release_decision"] == derive_release(observed, decision), "release mismatch %s" % case_id)
        require(
            receipt["instrument_execution_identity"]
            == instrument_execution_identity(receipt["instrument_id"], receipt["execution"]),
            "instrument execution identity %s" % case_id,
        )
        require(receipt["execution"]["fixture_path"] == case["fixture"], "fixture path %s" % case_id)
        declared_fixture = next(
            (item["sha256"] for item in protocol["candidate"]["files"] if item["path"] == case["fixture"]),
            None,
        )
        require(declared_fixture is not None, "fixture not declared %s" % case_id)
        require(receipt["execution"]["fixture_sha256"] == declared_fixture, "fixture digest %s" % case_id)
        require(receipt["execution"]["native_harness"] is True, "native harness disabled %s" % case_id)
        require(receipt["execution"]["replay"] in ("identical", "mismatch", "not_performed"), "replay label %s" % case_id)
        suppression = receipt["suppression"]
        if suppression["suppressed"]:
            for field in ("justification", "scope", "owner", "expiry", "invalidation"):
                require(bool(suppression[field].strip()), "suppression missing %s for %s" % (field, case_id))
        receipt_by_case[case_id] = receipt
        receipt_digest_by_case[case_id] = sha256_hex(raw)
        receipts.append(receipt)

    missing = sorted(set(population_by_id) - set(receipt_by_case))
    require(not missing, "missing receipts: %s" % ", ".join(missing))
    require(len(receipt_by_case) == EXPECTED_RECEIPTS, "unique receipt count")

    raw_files = sorted(path for path in raw_dir.rglob("*") if path.is_file())
    require(len(raw_files) == EXPECTED_RAW_EVIDENCE, "raw evidence file count is %d" % len(raw_files))
    raw_by_relative: dict[str, bytes] = {}
    for path in raw_files:
        relative = str(path.relative_to(campaign)).replace("\\", "/")
        raw_by_relative[relative] = read_bytes(path)

    referenced: set[str] = set()
    for receipt in receipts:
        case_id = receipt["case_id"]
        require(receipt["evidence"], "receipt has no evidence %s" % case_id)
        transcript_digest = None
        saw_transcript = False
        saw_report = False
        saw_detail = False
        for evidence in receipt["evidence"]:
            relative = evidence["path"]
            require(relative.startswith("receipts/raw/") and ".." not in Path(relative).parts, "unsafe evidence path %s" % relative)
            require(relative not in referenced, "duplicate evidence reference %s" % relative)
            referenced.add(relative)
            require(relative in raw_by_relative, "missing raw evidence %s" % relative)
            actual = sha256_hex(raw_by_relative[relative])
            require(actual == evidence["sha256"], "raw evidence digest %s" % relative)
            require(case_id in relative, "evidence does not name case %s" % relative)
            kind = evidence["kind"]
            if kind == "transcript":
                saw_transcript = True
                transcript = require_canonical(raw_by_relative[relative], relative)
                require(transcript["schema"] == "native-event-transcript.v1", "transcript schema %s" % relative)
                provenance = transcript["provenance"]
                require(provenance["origin"] == "authentic_native", "transcript origin %s" % relative)
                require(provenance["fixture_digest"] == receipt["execution"]["fixture_sha256"], "transcript fixture digest %s" % relative)
                require(case_id in provenance["scope"], "transcript scope %s" % relative)
                if receipt["execution"]["executable_sha256"]:
                    require(
                        provenance["executable_digest"] == receipt["execution"]["executable_sha256"],
                        "transcript executable digest %s" % relative,
                    )
                transcript_digest = actual
            elif kind == "court_report":
                saw_report = True
                report = require_canonical(raw_by_relative[relative], relative)
                require(report["schema"] == "frf-memorysafety.court-verification.v1", "court schema %s" % relative)
                require(report["outcome"] == receipt["observation"]["court_outcome"], "court outcome %s" % relative)
                require(report["event_count"] == receipt["observation"]["event_count"], "court event count %s" % relative)
                require(len(report["race_witnesses"]) == receipt["observation"]["race_witnesses"], "court race witnesses %s" % relative)
                expected_findings = [
                    {
                        "class": finding["class"],
                        "code": finding["code"],
                        "detail": finding["detail"],
                        "events": len(finding["events"]),
                        "subject": finding["subject"],
                    }
                    for finding in report["findings"]
                ]
                require(expected_findings == receipt["observation"]["findings"], "court findings %s" % relative)
                if transcript_digest is not None:
                    require(report["transcript_sha256"] == transcript_digest, "court transcript digest %s" % relative)
            elif kind == "harness_detail":
                saw_detail = True
                text = raw_by_relative[relative].decode("utf-8")
                require(text == receipt["observation"]["detail"], "harness detail %s" % relative)
            else:
                fail("unknown evidence kind %s" % kind)
        if saw_transcript and not saw_report:
            fail("transcript without retained court report %s" % case_id)
        if saw_report and not saw_transcript:
            fail("court report without transcript %s" % case_id)
        if not saw_transcript and not saw_detail:
            fail("receipt without raw evidence %s" % case_id)
        if receipt["observation"]["outcome"] == CLEAN:
            require(not receipt["observation"]["findings"], "clean case retains findings %s" % case_id)
            require(receipt["execution"]["replay"] == "identical", "clean case did not replay identically %s" % case_id)
        elif receipt["observation"]["outcome"] in ("observed_violation", "incomplete_transcript"):
            require(receipt["observation"]["findings"], "retained finding is stripped %s" % case_id)

    unreferenced = sorted(set(raw_by_relative) - referenced)
    require(not unreferenced, "unexpected raw evidence: %s" % ", ".join(unreferenced))

    outcomes = counts([receipt["observation"]["outcome"] for receipt in receipts])
    decisions = counts([receipt["adjudication"]["decision"] for receipt in receipts])
    require(outcomes == EXPECTED_OUTCOMES, "outcome counts %r" % outcomes)
    require(decisions == EXPECTED_DECISIONS, "decision counts %r" % decisions)
    require(closure["outcomes"] == [{"label": key, "count": value} for key, value in sorted(outcomes.items())], "closure outcomes")
    require(closure["decisions"] == [{"label": key, "count": value} for key, value in sorted(decisions.items())], "closure decisions")

    retained = sorted(
        receipt["case_id"]
        for receipt in receipts
        if receipt["observation"]["outcome"] in ("observed_violation", "incomplete_transcript", "unresolved", "illegal_case")
        or receipt["suppression"]["suppressed"]
    )
    require(len(retained) == EXPECTED_FINDING_CASES, "retained finding count %d" % len(retained))
    accepted = sorted(
        receipt["case_id"]
        for receipt in receipts
        if receipt["observation"]["outcome"] == CLEAN
        and receipt["adjudication"]["decision"] == "pass"
        and receipt["release_decision"] == "eligible"
    )
    require(len(accepted) == EXPECTED_ACCEPTED_CASES, "accepted case count %d" % len(accepted))
    mandatory_unresolved = [
        receipt["case_id"]
        for receipt in receipts
        if receipt["adjudication"]["mandatory_resolution"] and receipt["observation"]["outcome"] == "unresolved"
    ]
    require(not mandatory_unresolved, "mandatory unresolved: %s" % ", ".join(mandatory_unresolved))
    require(closure["closure_status"] == "closed", "closure status")
    require(closure["acceptance"] == "accepted", "acceptance")

    closure_refs = closure["receipts"]
    require(len(closure_refs) == EXPECTED_RECEIPTS, "closure receipt references")
    seen_refs = set()
    for reference in closure_refs:
        case_id = reference["case_id"]
        require(case_id not in seen_refs, "duplicate closure receipt reference %s" % case_id)
        seen_refs.add(case_id)
        require(case_id in receipt_by_case, "closure references missing receipt %s" % case_id)
        receipt = receipt_by_case[case_id]
        require(reference["path"] == "receipts/%s.json" % case_id, "closure receipt path %s" % case_id)
        require(reference["sha256"] == receipt_digest_by_case[case_id], "closure receipt digest %s" % case_id)
        require(reference["outcome"] == receipt["observation"]["outcome"], "closure receipt outcome %s" % case_id)
        require(reference["decision"] == receipt["adjudication"]["decision"], "closure receipt decision %s" % case_id)
    require(seen_refs == set(receipt_by_case), "closure receipt reference population")

    receipts_with_transcript = sum(
        1
        for receipt in receipts
        if any(item["kind"] == "transcript" for item in receipt["evidence"])
    )
    claims_doc = parse_json(read_bytes(campaign / "CLAIMS.json"), "CLAIMS.json")
    require(claims_doc["schema"] == "frf-etp.campaign-claims.v1", "claims schema")
    require(claims_doc["spec"] == "frf-etp-v1", "claims spec")
    require(claims_doc["campaign_id"] == CAMPAIGN_ID, "claims campaign id")
    require(claims_doc["opening_sha256"] == OPENING_SHA256, "claims opening digest")
    require(claims_doc["claim_ceiling"] == protocol["claim_ceiling"], "claims claim ceiling")
    require(claims_doc["non_claims"], "claims non-claims")
    claims_by_id = {claim["id"]: claim for claim in claims_doc["claims"]}
    require(set(claims_by_id) == {"C1", "C2", "C3"}, "claims table")
    case_ids = set(receipt_by_case)
    for claim in claims_by_id.values():
        require(set(claim["receipts"]) == case_ids, "claim receipt population %s" % claim["id"])
    observed_c1 = claims_by_id["C1"]["observed"]
    require(observed_c1["cases"] == len(population), "C1 cases")
    require(observed_c1["receipts"] == len(receipts), "C1 receipts")
    require(observed_c1["pass"] == decisions.get("pass", 0), "C1 pass")
    require(observed_c1["fail"] == decisions.get("fail", 0), "C1 fail")
    require(observed_c1["not_run"] == decisions.get("not_run", 0), "C1 not_run")
    require(observed_c1["mandatory_unresolved"] == len(mandatory_unresolved), "C1 mandatory unresolved")
    require(observed_c1["accepted_clean_cases"] == len(accepted), "C1 accepted cases")
    for key in (
        "verified_compatible_within_transcript",
        "observed_violation",
        "incomplete_transcript",
        "unresolved",
    ):
        require(observed_c1[key] == outcomes[key], "C1 outcome %s" % key)
    observed_c2 = claims_by_id["C2"]["observed"]
    require(observed_c2["receipts"] == len(receipts), "C2 receipts")
    require(observed_c2["raw_evidence"] == len(raw_files), "C2 raw evidence")
    require(observed_c2["digest_mismatches"] == 0, "C2 digest mismatches")
    require(observed_c2["missing_raw_evidence"] == 0, "C2 missing raw evidence")
    require(observed_c2["receipts_with_transcript"] == receipts_with_transcript, "C2 transcripts")
    require(
        observed_c2["receipts_without_transcript"] == len(receipts) - receipts_with_transcript,
        "C2 transcript count",
    )
    observed_c3 = claims_by_id["C3"]["observed"]
    require(observed_c3["cases"] == len(population), "C3 cases")
    require(observed_c3["receipts"] == len(receipts), "C3 receipts")
    require(observed_c3["missing"] == 0, "C3 missing")
    require(observed_c3["duplicate"] == 0, "C3 duplicate")
    require(observed_c3["unexpected"] == 0, "C3 unexpected")
    require(observed_c3["truncated"] == 0, "C3 truncated")
    require(observed_c3["suppressed"] == 0, "C3 suppressed")

    sarif_bytes = read_bytes(sarif_path)
    sarif = require_canonical(sarif_bytes, "campaign.sarif")
    require(sarif["$schema"] == SARIF_SCHEMA, "SARIF schema")
    require(sarif["version"] == SARIF_VERSION, "SARIF version")
    require(isinstance(sarif["runs"], list) and len(sarif["runs"]) == 1, "SARIF run count")
    run = sarif["runs"][0]
    require(run["tool"]["driver"]["name"] == SARIF_TOOL_NAME, "SARIF tool name")
    props = run["properties"]
    require(props["frf_projection_schema"] == SARIF_PROJECTION_SCHEMA, "SARIF projection schema")
    require(props["campaign_id"] == CAMPAIGN_ID, "SARIF campaign id")
    require(props["opening_sha256"] == OPENING_SHA256, "SARIF opening digest")
    require(props["candidate_identity"] == protocol["candidate"]["tree_sha256"], "SARIF candidate identity")
    require(props["instrument_id"] == protocol["instrument"]["id"], "SARIF instrument id")
    require(props["instrument_identity"] == protocol["instrument"]["tree_sha256"], "SARIF instrument identity")
    require(props["case_count"] == EXPECTED_CASES, "SARIF case count")
    require(props["receipt_count"] == EXPECTED_RECEIPTS, "SARIF receipt count")
    require(props["scope"] == protocol["scope"], "SARIF scope")
    require(props["assumptions"] == protocol["assumptions"], "SARIF assumptions")
    require(props["unsupported_features"] == protocol["unsupported_features"], "SARIF unsupported features")
    require(props["claim_ceiling"] == SARIF_CLAIM_CEILING, "SARIF claim ceiling")

    expected_results = project_results(protocol, receipts)
    expected_rules = expected_rule_table(expected_results)
    require(len(expected_results) == EXPECTED_RESULTS, "expected result count %d" % len(expected_results))
    require(len(expected_rules) == EXPECTED_RULES, "expected rule count %d" % len(expected_rules))
    actual_results = run["results"]
    require(len(actual_results) == EXPECTED_RESULTS, "SARIF result count %d" % len(actual_results))
    actual_by_id = {}
    for result in actual_results:
        occurrence = result["properties"]["occurrence_id"]
        require(occurrence not in actual_by_id, "duplicate SARIF occurrence %s" % occurrence)
        actual_by_id[occurrence] = result
    expected_by_id = {result["properties"]["occurrence_id"]: result for result in expected_results}
    require(set(actual_by_id) == set(expected_by_id), "SARIF occurrence population")
    for occurrence, expected in expected_by_id.items():
        actual = actual_by_id[occurrence]
        for field in (
            "ruleId",
            "ruleIndex",
            "level",
            "message",
            "locations",
            "fingerprints",
            "partialFingerprints",
            "baselineState",
            "suppressions",
            "properties",
        ):
            require(actual[field] == expected[field], "SARIF %s differs for %s" % (field, occurrence))

    actual_rules = run["tool"]["driver"]["rules"]
    require(len(actual_rules) == EXPECTED_RULES, "SARIF rule count")
    actual_rule_ids = {rule["id"]: rule["defaultConfiguration"]["level"] for rule in actual_rules}
    expected_rule_ids = {rule["id"]: rule["level"] for rule in expected_rules}
    require(actual_rule_ids == expected_rule_ids, "SARIF rule table")

    expected_artifacts = sorted(
        {
            receipt["execution"]["fixture_path"]
            for receipt in receipts
            if receipt["observation"]["outcome"] != CLEAN
            and any(item["kind"] == "transcript" for item in receipt["evidence"])
        }
    )
    actual_artifacts = sorted(artifact["location"]["uri"] for artifact in run["artifacts"])
    require(actual_artifacts == expected_artifacts, "SARIF artifacts")

    suppressed = sum(1 for result in actual_results if result["suppressions"])
    require(props["result_count"] == EXPECTED_RESULTS, "SARIF result_count")
    require(props["retained_finding_count"] == EXPECTED_RESULTS, "SARIF retained_finding_count")
    require(props["suppressed_result_count"] == suppressed, "SARIF suppressed count")
    completeness = props["completeness"]
    require(completeness["complete"] is True, "SARIF completeness")
    require(completeness["receipt_count"] == EXPECTED_RECEIPTS, "SARIF completeness receipts")
    require(completeness["result_count"] == EXPECTED_RESULTS, "SARIF completeness results")
    require(completeness["native_manifest"] == "MANIFEST.json", "SARIF native manifest name")
    require(completeness["native_manifest_sha256"] == sha256_hex(closure_bytes), "SARIF native manifest digest")
    require(completeness["shards"] == [], "SARIF shards")
    limits = props["limits"]
    require(limits["max_results"] == MAX_SARIF_RESULTS, "SARIF max results")
    require(limits["max_bytes"] == MAX_SARIF_BYTES, "SARIF max bytes")
    require(limits["result_count"] == EXPECTED_RESULTS, "SARIF limit result count")
    require(limits["encoded_bytes"] == len(canonical_json(sarif)), "SARIF encoded bytes")
    require(limits["truncated"] is False, "SARIF truncated flag")

    return {
        "campaign_id": CAMPAIGN_ID,
        "opening_sha256": opening,
        "candidate_identity": protocol["candidate"]["tree_sha256"],
        "instrument_identity": protocol["instrument"]["tree_sha256"],
        "case_count": len(population),
        "receipt_count": len(receipts),
        "raw_evidence_count": len(raw_files),
        "outcomes": outcomes,
        "decisions": decisions,
        "retained_findings": len(retained),
        "accepted_cases": len(accepted),
        "characters": {
            "receipts": len(receipts),
            "raw_evidence": len(raw_files),
            "sarif_results": len(actual_results),
            "sarif_rules": len(actual_rules),
            "suppressed_results": suppressed,
        },
        "closure_sha256": sha256_hex(closure_bytes),
        "sarif_sha256": sha256_hex(sarif_bytes),
    }


def print_report(report: dict[str, object]) -> None:
    print("ETP campaign reconstruction")
    print("campaign: %s" % report["campaign_id"])
    print("opening sha256: %s" % report["opening_sha256"])
    print("candidate identity: %s" % report["candidate_identity"])
    print("instrument identity: %s" % report["instrument_identity"])
    print(
        "cases: %d; receipts: %d; raw evidence: %d"
        % (report["case_count"], report["receipt_count"], report["raw_evidence_count"])
    )
    for key in sorted(report["outcomes"]):
        print("outcome %s: %d" % (key, report["outcomes"][key]))
    for key in sorted(report["decisions"]):
        print("decision %s: %d" % (key, report["decisions"][key]))
    print("retained finding cases: %d" % report["retained_findings"])
    print("accepted cases: %d" % report["accepted_cases"])
    print(
        "SARIF results: %d; rules: %d; suppressed: %d"
        % (
            report["characters"]["sarif_results"],
            report["characters"]["sarif_rules"],
            report["characters"]["suppressed_results"],
        )
    )
    print("closure sha256: %s" % report["closure_sha256"])
    print("SARIF sha256: %s" % report["sarif_sha256"])
    print("PASS reconstruction")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root",
    )
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)
    try:
        report = reconstruct(args.root.resolve())
    except ReconstructionError as error:
        print("FAIL reconstruction: %s" % error, file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
