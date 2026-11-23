#!/usr/bin/env python3
"""Phase 17.2 comparative evaluation harness.

Executes the frozen Phase 17.1 comparative protocol
(``evaluation/earned-trust-comparative/protocol.json``) in-container.

This harness is an *instrument*. It is not proof, review, certification, or
authorization. It does not emit an FRF receipt, finding, GCE object, or GID.

What it does
------------
1. Reads ``OPENING.sha256`` and fails closed unless it names the exact SHA-256
   of the protocol bytes.
2. Recomputes the 18-case population and the 6/12 partition by rule ``SR1``
   and fails closed on any disagreement with the frozen table.
3. Verifies every bound artifact and instrument digest against the frozen
   binding and fails closed on any mismatch.
4. For each selected case: copies the repository tree (or the archive root for
   archive cases) into a fresh work directory, applies the declared
   deterministic mutation only inside the work directory, substitutes
   ``{bin}``, ``{repo}``, and ``{work}``, and runs every declared command with
   a bounded timeout.
5. Classifies the augmented surface from the *observed* command outcomes only.
   The declared expectation is consulted afterwards, solely to compute
   ``expected_match``. It never influences the observed decision.
6. Reads the foundation anchor from the committed baseline (never the mutated
   copy).
7. Runs the declared restoration control for negative cases.
8. Writes one canonical, sorted-key JSON receipt per case and one analysis
   document for the selected partition.

Exit statuses
-------------
0  the selected partition ran and every selected case has a receipt; the run is
   internally consistent. Declared expectations are *not* required to match.
1  a selected case produced no receipt (harness defect).
3  the run is invalid: opening digest, population, partition, or bound artifact
   mismatch, or the repository was written to.
7  internal harness error.

No hostname, no absolute host path, and no timestamp is recorded. Wall-clock
durations are per-run resource accounting only and are not comparable across
hosts, images, or runs.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCHEMA_RECEIPT = "frf-etp.comparative-case-receipt.v1"
SCHEMA_ANALYSIS = "frf-etp.comparative-analysis.v1"
SPEC = "frf-etp-comparative-v1"
PROTOCOL_REL = "evaluation/earned-trust-comparative/protocol.json"
OPENING_REL = "evaluation/earned-trust-comparative/OPENING.sha256"
COMPARATIVE_DIR = "evaluation/earned-trust-comparative"
EXCLUDED_DIR_NAMES = {".git", "target", "research"}
COMMAND_TIMEOUT_SECONDS = 300
STDERR_TAIL_CHARS = 900
VALUE_PREVIEW_CHARS = 120
ZERO64 = "0" * 64

EXIT_INVALID = 3
EXIT_MISSING_RECEIPT = 1
EXIT_HARNESS = 7

DECISIONS = ("accept", "refuse", "unresolved", "instrument_error")


class HarnessError(Exception):
    """A condition that invalidates the whole run."""


class CaseBlocked(Exception):
    """A declared case cannot be executed exactly as declared."""


# ---------------------------------------------------------------------------
# canonical JSON and digests
# ---------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def write_canonical(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))


def load_json_bytes(data: bytes) -> object:
    return json.loads(data.decode("utf-8"))


def load_document(path: Path) -> tuple[object, str]:
    """Load JSON and record the exact serialization style of the source.

    Only the declared field may change. The harness therefore refuses to rewrite
    a document unless the untouched document round-trips byte-for-byte in one of
    the two serializations used by this repository.
    """

    raw = path.read_bytes()
    value = load_json_bytes(raw)
    compact = canonical_bytes(value)
    if raw == compact:
        return value, "compact"
    pretty = json.dumps(
        value, sort_keys=False, indent=2, ensure_ascii=True
    ).encode("utf-8") + b"\n"
    if raw == pretty:
        return value, "pretty"
    raise CaseBlocked(f"refusing to rewrite unrecognized JSON formatting: {path.name}")


def dump_document(value: object, style: str) -> bytes:
    if style == "compact":
        return canonical_bytes(value)
    if style == "pretty":
        return json.dumps(
            value, sort_keys=False, indent=2, ensure_ascii=True
        ).encode("utf-8") + b"\n"
    raise CaseBlocked(f"unknown document style: {style!r}")


def write_document(path: Path, value: object, style: str) -> None:
    path.write_bytes(dump_document(value, style))


# ---------------------------------------------------------------------------
# protocol, opening digest, population, bindings
# ---------------------------------------------------------------------------


def load_frozen_protocol(repo: Path) -> tuple[dict, str]:
    opening_path = repo / OPENING_REL
    if not opening_path.is_file():
        raise HarnessError(f"missing opening digest: {OPENING_REL}")
    entries: list[tuple[str, str]] = []
    for line in opening_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) != 2:
            raise HarnessError("malformed OPENING.sha256 entry")
        entries.append((parts[0].lower(), parts[1]))
    named = [digest for digest, name in entries if name == "protocol.json"]
    if len(named) != 1:
        raise HarnessError("OPENING.sha256 must name protocol.json exactly once")
    protocol_path = repo / PROTOCOL_REL
    if not protocol_path.is_file():
        raise HarnessError(f"missing protocol: {PROTOCOL_REL}")
    raw = protocol_path.read_bytes()
    actual = sha256_bytes(raw)
    if actual != named[0]:
        raise HarnessError(
            "protocol sha256 does not match OPENING.sha256; failing closed"
        )
    protocol = json.loads(raw.decode("utf-8"))
    if not protocol.get("frozen"):
        raise HarnessError("protocol is not marked frozen")
    return protocol, actual


def recompute_partition(protocol: dict) -> dict[str, str]:
    cases = protocol["cases"]
    ids = sorted(case["id"] for case in cases)
    derived = {case_id: ("development" if index % 3 == 0 else "held_out")
               for index, case_id in enumerate(ids)}
    frozen: dict[str, str] = {}
    for partition, members in protocol["partitions"].items():
        if partition in ("counts", "disjoint", "selection_rule_id"):
            continue
        for case_id in members:
            frozen[case_id] = partition
    if set(derived) != set(frozen):
        raise HarnessError("case population differs from the frozen table")
    for case_id, partition in derived.items():
        if frozen[case_id] != partition:
            raise HarnessError(
                f"SR1 recomputation disagrees for {case_id}; failing closed"
            )
    if protocol["selection_rule"]["id"] != "SR1":
        raise HarnessError("unexpected selection rule id")
    return frozen


def verify_bindings(repo: Path, protocol: dict) -> list[str]:
    problems: list[str] = []
    for binding in protocol["instrument_bindings"] + protocol["artifact_bindings"]:
        path = repo / binding["path"]
        if not path.is_file():
            problems.append(f"missing binding: {binding['path']}")
            continue
        if sha256_bytes(path.read_bytes()) != binding["sha256"]:
            problems.append(f"binding sha256 mismatch: {binding['path']}")
    return problems


def artifact_index(protocol: dict) -> dict[str, dict]:
    return {item["id"]: item for item in protocol["artifact_bindings"]}


# ---------------------------------------------------------------------------
# foundation surface (A)
# ---------------------------------------------------------------------------


def resolve_field(value: object, expr: str) -> object:
    """Resolve a dotted field path with optional ``[key=value]`` selectors."""

    pos = 0
    current = value
    length = len(expr)
    while pos < length:
        if expr[pos] == ".":
            pos += 1
            continue
        match = re.match(r"[A-Za-z0-9_\-]+", expr[pos:])
        if not match:
            raise KeyError(expr)
        name = match.group(0)
        pos += len(name)
        if not isinstance(current, dict):
            raise KeyError(expr)
        current = current[name]
        if pos < length and expr[pos] == "[":
            end = expr.find("]", pos)
            if end < 0:
                raise KeyError(expr)
            inner = expr[pos + 1:end]
            key, separator, wanted = inner.partition("=")
            if not separator or not isinstance(current, list):
                raise KeyError(expr)
            matches = [
                item
                for item in current
                if isinstance(item, dict) and str(item.get(key)) == wanted
            ]
            if len(matches) != 1:
                raise KeyError(expr)
            current = matches[0]
            pos = end + 1
    return current


def foundation_decision(repo: Path, case: dict, index: dict[str, dict]) -> dict:
    foundation = case["foundation"]
    kind = foundation["anchor_kind"]
    rel = foundation["anchor_path"]
    field = foundation["anchor_field"]
    record = {
        "anchor_kind": kind,
        "anchor_artifact_id": foundation["anchor_artifact_id"],
        "anchor_path": rel,
        "anchor_field": field,
        "source": "committed_baseline",
        "observed_label": None,
        "decision": "unavailable",
        "sha256_matches_binding": None,
    }
    binding = index.get(foundation["anchor_artifact_id"])
    path = repo / rel
    if not path.is_file():
        return record
    raw = path.read_bytes()
    if binding is not None:
        record["sha256_matches_binding"] = sha256_bytes(raw) == binding["sha256"]
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return record
    if kind == "native_receipt":
        try:
            label = resolve_field(document, field)
        except KeyError:
            return record
        record["observed_label"] = label
        record["decision"] = "accept" if label == "pass" else "refuse"
    elif kind == "campaign_decision":
        decisions = document.get("decisions")
        if not isinstance(decisions, list):
            return record
        passing = [
            entry
            for entry in decisions
            if isinstance(entry, dict) and entry.get("label") == "pass"
        ]
        record["observed_label"] = {
            "decision_count": len(decisions),
            "pass_count": len(passing),
        }
        record["decision"] = "accept" if len(passing) == 1 else "refuse"
    else:
        raise HarnessError(f"unknown foundation anchor kind: {kind}")
    return record


# ---------------------------------------------------------------------------
# work-tree construction
# ---------------------------------------------------------------------------


def _ignore_repository(path: str, names: list[str]) -> set[str]:
    ignored = {name for name in names if name in EXCLUDED_DIR_NAMES}
    current = Path(path)
    # Exclude only the comparative receipts directory, never the protocol docs.
    if current.name == Path(COMPARATIVE_DIR).name:
        ignored.add("receipts")
    return ignored


def copy_repository(repo: Path, destination: Path) -> None:
    shutil.copytree(
        repo,
        destination,
        symlinks=False,
        ignore=_ignore_repository,
        copy_function=shutil.copyfile,
    )
    # ```{work}/target`` is a declared writable path. The tree copy excludes the
    # repository ``target/``, so create an empty scratch directory for the
    # declared instruments that create their private work directories there.
    (destination / "target").mkdir(parents=True, exist_ok=True)


def copy_archive(repo: Path, destination: Path) -> None:
    archive = repo / "evaluation/earned-trust/archive"
    if not archive.is_dir():
        raise CaseBlocked("archive root is missing")
    shutil.copytree(
        archive,
        destination / "archive",
        symlinks=False,
        copy_function=shutil.copyfile,
    )


def prepare_work(repo: Path, case: dict, root: Path) -> Path:
    root.parent.mkdir(parents=True, exist_ok=True)
    mutation = case["mutation"]
    archive_case = mutation["kind"] == "required_object_deletion" or (
        mutation["kind"] == "identity_copy"
        and mutation.get("target") == "the intact archive tree"
    )
    if archive_case:
        copy_archive(repo, root)
    else:
        copy_repository(repo, root)
    return root



# ---------------------------------------------------------------------------
# declared deterministic mutations
# ---------------------------------------------------------------------------


def _rel(work: Path, path: Path) -> str:
    return str(path.relative_to(work))


def _preview(value: object) -> object:
    if isinstance(value, str) and len(value) > VALUE_PREVIEW_CHARS:
        return value[:VALUE_PREVIEW_CHARS] + "..."
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return f"list[{len(value)}]"
    if isinstance(value, dict):
        return f"object[{len(value)}]"
    return str(value)[:VALUE_PREVIEW_CHARS]


def _set_field(work: Path, path: Path, field: str, new_value: object,
               changes: list) -> None:
    document, style = load_document(path)
    old = resolve_field(document, field)
    if old == new_value:
        raise CaseBlocked(f"declared field already has the mutated value: {field}")
    container = document
    parts = field.split(".")
    for part in parts[:-1]:
        container = container[part]
    container[parts[-1]] = new_value
    write_document(path, document, style)
    changes.append(
        {
            "action": "set",
            "path": _rel(work, path),
            "field": field,
            "from": _preview(old),
            "to": _preview(new_value),
        }
    )


def apply_mutation(case: dict, work: Path, repo: Path) -> list[dict]:
    kind = case["mutation"]["kind"]
    changes: list[dict] = []

    if kind == "identity_copy":
        changes.append(
            {
                "action": "none",
                "detail": "identity copy: the declared evidence tree is copied "
                          "byte-for-byte and no declared byte changes",
            }
        )
        return changes

    if kind == "verifier_input_substitution":
        changes.append(
            {
                "action": "none",
                "detail": "argument substitution: the mutated value is declared "
                          "in the case argv; no artifact byte changes",
            }
        )
        return changes

    if kind == "claim_selection":
        changes.append(
            {
                "action": "none",
                "detail": "claim selection: the declared claim is selected by the "
                          "case argv; no artifact byte changes",
            }
        )
        return changes

    if kind == "field_substitution":
        path = work / "evaluation/earned-trust/receipts/use-after-free-c.json"
        _set_field(work, path, "candidate_identity", ZERO64, changes)
        receipt = path.read_bytes()
        manifest_path = work / "evaluation/earned-trust/MANIFEST.json"
        manifest, style = load_document(manifest_path)
        matched = False
        for entry in manifest.get("receipts", []):
            if entry.get("case_id") == "use-after-free-c":
                entry["sha256"] = sha256_bytes(receipt)
                matched = True
        if not matched:
            raise CaseBlocked("no receipts[] entry for use-after-free-c")
        write_document(manifest_path, manifest, style)
        changes.append(
            {
                "action": "set",
                "path": _rel(work, manifest_path),
                "field": "receipts[case_id=use-after-free-c].sha256",
                "to": sha256_bytes(receipt),
            }
        )
        return changes

    if kind == "required_record_deletion":
        manifest_path = work / "evaluation/earned-trust/MANIFEST.json"
        manifest, style = load_document(manifest_path)
        before = len(manifest.get("receipts", []))
        manifest["receipts"] = [
            entry
            for entry in manifest.get("receipts", [])
            if entry.get("case_id") != "use-after-free-c"
        ]
        if len(manifest["receipts"]) != before - 1:
            raise CaseBlocked("expected one receipts[] entry for use-after-free-c")
        write_document(manifest_path, manifest, style)
        changes.append(
            {
                "action": "remove",
                "path": _rel(work, manifest_path),
                "field": "receipts[case_id=use-after-free-c]",
            }
        )
        for rel in (
            "evaluation/earned-trust/receipts/use-after-free-c.json",
            "evaluation/earned-trust/receipts/raw/use-after-free-c.transcript.json",
            "evaluation/earned-trust/receipts/raw/use-after-free-c.court.json",
        ):
            target = work / rel
            if not target.is_file():
                raise CaseBlocked(f"declared deletion target missing: {rel}")
            target.unlink()
            changes.append({"action": "delete_file", "path": rel})
        return changes

    if kind == "population_truncation":
        manifest_path = work / "evaluation/earned-trust/MANIFEST.json"
        manifest, style = load_document(manifest_path)
        before = len(manifest.get("receipts", []))
        manifest["receipts"] = [
            entry
            for entry in manifest.get("receipts", [])
            if entry.get("case_id") != "nondeterministic-c"
        ]
        if len(manifest["receipts"]) != before - 1:
            raise CaseBlocked("expected one receipts[] entry for nondeterministic-c")
        manifest["case_count"] = 12
        manifest["receipt_count"] = 12
        manifest["raw_evidence_count"] = 23
        for entry in manifest.get("decisions", []):
            entry["count"] = 12
        unresolved = [
            entry for entry in manifest.get("outcomes", [])
            if entry.get("label") == "unresolved"
        ]
        if len(unresolved) != 1 or unresolved[0]["count"] < 1:
            raise CaseBlocked("cannot decrement the unresolved outcome count")
        unresolved[0]["count"] -= 1
        write_document(manifest_path, manifest, style)
        changes.append(
            {
                "action": "remove",
                "path": _rel(work, manifest_path),
                "field": "receipts[case_id=nondeterministic-c]",
            }
        )
        for field, value in (
            ("case_count", 12),
            ("receipt_count", 12),
            ("raw_evidence_count", 23),
            ("decisions[*].count", 12),
            ("outcomes[label=unresolved].count", unresolved[0]["count"]),
        ):
            changes.append(
                {
                    "action": "set",
                    "path": _rel(work, manifest_path),
                    "field": field,
                    "to": value,
                }
            )
        for rel in (
            "evaluation/earned-trust/receipts/nondeterministic-c.json",
            "evaluation/earned-trust/receipts/raw/nondeterministic-c.transcript.json",
            "evaluation/earned-trust/receipts/raw/nondeterministic-c.court.json",
        ):
            target = work / rel
            if not target.is_file():
                raise CaseBlocked(f"declared deletion target missing: {rel}")
            target.unlink()
            changes.append({"action": "delete_file", "path": rel})
        return changes

    if kind == "duplicate_row":
        manifest_path = work / "evaluation/earned-trust/MANIFEST.json"
        manifest, style = load_document(manifest_path)
        entries = [
            entry for entry in manifest.get("receipts", [])
            if entry.get("case_id") == "use-after-free-c"
        ]
        if len(entries) != 1:
            raise CaseBlocked("expected one use-after-free-c receipts[] entry")
        manifest["receipts"].append(copy.deepcopy(entries[0]))
        manifest["receipt_count"] = 14
        write_document(manifest_path, manifest, style)
        changes.append(
            {
                "action": "append_duplicate",
                "path": _rel(work, manifest_path),
                "field": "receipts[case_id=use-after-free-c]",
            }
        )
        changes.append(
            {
                "action": "set",
                "path": _rel(work, manifest_path),
                "field": "receipt_count",
                "to": 14,
            }
        )
        return changes

    if kind == "payload_substitution":
        path = work / "evaluation/earned-trust/attestations/campaign-closure.envelope.json"
        envelope, style = load_document(path)
        payload = base64.b64decode(envelope["payload"], validate=True)
        marker = payload.find(b'"case_count"')
        if marker < 0:
            raise CaseBlocked("payload has no case_count field")
        digit = payload.find(b"13", marker)
        if digit < 0:
            raise CaseBlocked("payload has no case_count 13 to substitute")
        mutated = payload[:digit] + b"12" + payload[digit + 2:]
        if len(mutated) != len(payload):
            raise CaseBlocked("payload substitution changed the payload length")
        envelope["payload"] = base64.b64encode(mutated).decode("ascii")
        write_document(path, envelope, style)
        changes.append(
            {
                "action": "set",
                "path": _rel(work, path),
                "field": "payload",
                "from": "base64(case_count=13)",
                "to": "base64(case_count=12)",
            }
        )
        return changes

    if kind == "role_reassignment":
        rels = (
            "evaluation/earned-trust/trust-policy.json",
            "evaluation/earned-trust/attestations/trust-policy.json",
        )
        keyid = "frf-etp-test-ephemeral-2026-11-22"
        mutated_paths = []
        for rel in rels:
            path = work / rel
            policy, style = load_document(path)
            roles = {role["id"]: role for role in policy.get("roles", [])}
            producer = roles.get("evidence_producer")
            correction = roles.get("correction_authority")
            if producer is None or correction is None:
                raise CaseBlocked("declared policy roles are missing in " + rel)
            moved = [
                key
                for key in producer.get("keys", [])
                if key.get("keyid") == keyid
            ]
            if len(moved) != 1:
                raise CaseBlocked(
                    "expected exactly one evidence_producer key in " + rel
                )
            producer["keys"] = [
                key
                for key in producer.get("keys", [])
                if key.get("keyid") != keyid
            ]
            correction.setdefault("keys", []).append(moved[0])
            write_document(path, policy, style)
            mutated_paths.append(path)
            changes.append(
                {
                    "action": "move",
                    "path": rel,
                    "field": "roles[evidence_producer].keys[keyid=%s]" % keyid,
                    "to": "roles[correction_authority].keys",
                }
            )
        if mutated_paths[0].read_bytes() != mutated_paths[1].read_bytes():
            raise CaseBlocked(
                "policy copies are not byte-identical after the role reassignment"
            )
        return changes

    if kind == "proof_sibling_reorder":
        path = work / "evaluation/earned-trust/transparency/proof.json"
        proof, style = load_document(path)
        siblings = proof.get("audit_path")
        if not isinstance(siblings, list) or len(siblings) != 2:
            raise CaseBlocked("audit_path does not have exactly two entries")
        proof["audit_path"] = [siblings[1], siblings[0]]
        write_document(path, proof, style)
        changes.append(
            {
                "action": "swap",
                "path": _rel(work, path),
                "field": "audit_path[0]",
                "to": "audit_path[1]",
            }
        )
        return changes

    if kind == "known_horizon_advance":
        path = work / "evaluation/earned-trust/transparency/policy.json"
        policy, style = load_document(path)
        horizons = policy.get("anti_rollback", {}).get("known_horizons")
        if not isinstance(horizons, list) or not horizons:
            raise CaseBlocked("known_horizons is missing")
        horizons[0]["tree_size"] = 4
        horizons[0]["root_hash"] = ZERO64
        horizons[0]["checkpoint_sha256"] = ZERO64
        write_document(path, policy, style)
        for field, value in (
            ("anti_rollback.known_horizons[0].tree_size", 4),
            ("anti_rollback.known_horizons[0].root_hash", ZERO64),
            ("anti_rollback.known_horizons[0].checkpoint_sha256", ZERO64),
        ):
            changes.append(
                {"action": "set", "path": _rel(work, path), "field": field, "to": value}
            )
        return changes

    if kind == "required_object_deletion":
        rel = "archive/evaluation/earned-trust/attestations/campaign-closure.envelope.json"
        target = work / rel
        if not target.is_file():
            raise CaseBlocked("archived envelope object is missing")
        target.unlink()
        changes.append({"action": "delete_file", "path": rel})
        return changes

    if kind == "unjustified_suppression":
        path = work / "evaluation/earned-trust/campaign.sarif"
        sarif, style = load_document(path)
        runs = sarif.get("runs")
        if not isinstance(runs, list) or len(runs) != 1:
            raise CaseBlocked("expected exactly one SARIF run")
        run = runs[0]
        target = None
        for result in run.get("results", []):
            props = result.get("properties", {})
            if (
                props.get("case_id") == "data-race-c"
                and props.get("occurrence_id") == "data-race-c::data_race::0"
            ):
                target = result
                break
        if target is None:
            raise CaseBlocked("declared SARIF occurrence is missing")
        target["suppressions"] = [
            {
                "kind": "external",
                "justification": "Suppression asserted by the Phase 17.2 comparative "
                                 "harness; no independent review record exists.",
                "properties": {
                    "scope": "case:data-race-c",
                    "owner": "comparative-harness",
                    "expiry": "2026-12-31",
                    "invalidation": "any change to the receipt or raw evidence",
                    "suppression_id": "sup-0001",
                },
            }
        ]
        run["properties"]["suppressed_result_count"] = 1
        write_document(path, sarif, style)
        changes.append(
            {
                "action": "set",
                "path": _rel(work, path),
                "field": "runs[0].results[occurrence_id=data-race-c::data_race::0]"
                         ".suppressions",
                "to": "1 external suppression, suppression_id sup-0001",
            }
        )
        changes.append(
            {
                "action": "set",
                "path": _rel(work, path),
                "field": "runs[0].properties.suppressed_result_count",
                "to": 1,
            }
        )
        return changes

    if kind == "cross_property_report_substitution":
        faulty_path = work / "evaluation/earned-trust/cross-property/report-faulty.json"
        fixed_path = work / "evaluation/earned-trust/cross-property/report-fixed.json"
        faulty, _ = load_document(faulty_path)
        fixed, fixed_style = load_document(fixed_path)
        faulty_lines = faulty.get("metadata", {}).get("trace_lines", [])
        fixed_lines = fixed.get("metadata", {}).get("trace_lines", [])
        if len(faulty_lines) < 3 or len(fixed_lines) < 3:
            raise CaseBlocked("trace_lines has fewer than three entries")
        previous_outcome = fixed.get("outcome")
        fixed["outcome"] = "observed_erasure_violation"
        fixed["metadata"]["trace_lines"][2] = faulty_lines[2]
        write_document(fixed_path, fixed, fixed_style)
        changes.append(
            {
                "action": "set",
                "path": _rel(work, fixed_path),
                "field": "outcome",
                "from": _preview(previous_outcome),
                "to": "observed_erasure_violation",
            }
        )
        changes.append(
            {
                "action": "set",
                "path": _rel(work, fixed_path),
                "field": "metadata.trace_lines[2]",
                "from": _preview(fixed_lines[2]),
                "to": _preview(faulty_lines[2]),
            }
        )
        return changes

    if kind == "matrix_cell_deletion":
        rel_target = case["mutation"]["target"].replace("{work}/", "")
        path = work / rel_target
        report, style = load_document(path)
        cells = report.get("cells")
        if not isinstance(cells, list):
            raise CaseBlocked("report has no cells array")
        wanted_match = re.search(
            r"case is ([A-Za-z0-9_]+), client_variant is ([A-Za-z0-9_]+), "
            r"and server_variant is ([A-Za-z0-9_]+)",
            case["mutation"]["operation"],
        )
        if wanted_match is None:
            raise CaseBlocked("declared matrix cell identity is not stated")
        wanted = wanted_match.groups()
        keep = [
            cell for cell in cells
            if not (
                cell.get("case") == wanted[0]
                and cell.get("client_variant") == wanted[1]
                and cell.get("server_variant") == wanted[2]
            )
        ]
        if len(keep) != len(cells) - 1:
            raise CaseBlocked("declared matrix cell is not present exactly once")
        report["cells"] = keep
        write_document(path, report, style)
        changes.append(
            {
                "action": "remove",
                "path": _rel(work, path),
                "field": "cells[case=%s,client_variant=%s,server_variant=%s]"
                         % wanted,
            }
        )
        return changes

    if kind == "required_theorem_removal":
        path = work / "tests/proof/coq/manifest-acceptance.json"
        manifest, style = load_document(path)
        name = "stale_transparency_blocks"
        removed = 0
        closure_theorems = manifest.get("closure", {}).get("theorems")
        if isinstance(closure_theorems, list) and name in closure_theorems:
            closure_theorems.remove(name)
            removed += 1
        admission_theorems = manifest.get("admission", {}).get("theorems")
        if isinstance(admission_theorems, list):
            kept = [
                entry
                for entry in admission_theorems
                if not (isinstance(entry, dict) and entry.get("name") == name)
            ]
            if len(kept) != len(admission_theorems):
                manifest["admission"]["theorems"] = kept
                removed += 1
        if removed != 2:
            raise CaseBlocked("declared theorem is not present in both lists")
        write_document(path, manifest, style)
        changes.append(
            {
                "action": "remove",
                "path": _rel(work, path),
                "field": "closure.theorems and admission.theorems",
                "value": name,
            }
        )
        return changes

    raise CaseBlocked(f"no generic handler for mutation kind {kind!r}")


# ---------------------------------------------------------------------------
# command execution and classification
# ---------------------------------------------------------------------------


def substitute_argv(argv: list[str], repo: Path, work: Path) -> list[str]:
    mapping = {
        "{repo}": str(repo),
        "{work}": str(work),
        "{bin}": str(repo / "target/debug/frf-memorysafety"),
        "{mutated}": str(work),
    }
    resolved: list[str] = []
    for argument in argv:
        value = argument
        for token, replacement in mapping.items():
            value = value.replace(token, replacement)
        resolved.append(value)
    return resolved


def display_argv(argv: list[str], repo: Path, work: Path) -> list[str]:
    repo_s = str(repo)
    work_s = str(work)
    bin_s = str(repo / "target/debug/frf-memorysafety")
    shown: list[str] = []
    for argument in argv:
        value = argument.replace(bin_s, "<bin>").replace(repo_s, "<repo>")
        value = value.replace(work_s, "<work>")
        shown.append(value)
    return shown


def display_cwd(path: Path, repo: Path, work: Path) -> str:
    text = str(path)
    text = text.replace(str(repo), "<repo>").replace(str(work), "<work>")
    return text


def sanitize_tail(text: str, repo: Path, work: Path) -> str:
    text = text.replace(str(work), "<work>").replace(str(repo), "<repo>")
    text = text.replace("\r\n", "\n").strip()
    if len(text) > STDERR_TAIL_CHARS:
        text = "..." + text[-STDERR_TAIL_CHARS:]
    return text


def run_command(argv: list[str], cwd: Path) -> dict:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONHASHSEED"] = "0"
    env["SOURCE_DATE_EPOCH"] = "0"
    env["TZ"] = "UTC"
    started = time.monotonic()
    timed_out = False
    exit_code: int | None = None
    stdout = b""
    stderr = b""
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
            env=env,
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as error:
        timed_out = True
        stdout = error.stdout or b""
        stderr = error.stderr or b""
    except OSError as error:
        stderr = f"cannot execute declared command: {error}".encode("utf-8")
    duration_ms = int(round((time.monotonic() - started) * 1000.0))
    return {
        "exit_code": exit_code,
        "timed_out": timed_out,
        "stdout": stdout,
        "stderr": stderr,
        "duration_ms": duration_ms,
    }


def parse_stdout_json(stdout: bytes) -> object | None:
    if not stdout.strip():
        return None
    try:
        return json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def normalize_code(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def is_literal_code(value: object) -> bool:
    return (
        isinstance(value, str)
        and " " not in value
        and re.fullmatch(r"[A-Za-z0-9_.:\-]+", value) is not None
    )


def extract_status(document: object, stdout_text: str) -> str | None:
    if isinstance(document, dict):
        for key in ("status", "report_status", "acceptance"):
            value = document.get(key)
            if isinstance(value, str):
                return value
    for line in stdout_text.splitlines():
        match = re.match(
            r"^\s*(timestamp|status|report|committed attestation)\s*:\s*([^\s;]+)",
            line,
            re.IGNORECASE,
        )
        if match:
            return match.group(2)
    return None


def extract_codes(document: object) -> list[str]:
    codes: list[str] = []
    if isinstance(document, dict):
        for key in ("refusals", "codes"):
            value = document.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        codes.append(item)
                    elif isinstance(item, dict) and isinstance(item.get("code"), str):
                        codes.append(item["code"])
    return codes


def report_snapshot(document: object, stdout_text: str) -> dict:
    snapshot: dict[str, object] = {}
    if isinstance(document, dict):
        for key in (
            "status",
            "closure_status",
            "acceptance",
            "case_count",
            "receipt_count",
            "raw_evidence_count",
            "closure_sha256",
            "result_count",
            "suppressed_result_count",
            "outcome",
            "claim_ceiling",
        ):
            if key in document and not isinstance(document[key], (dict, list)):
                value = document[key]
                snapshot[key] = _preview(value)
        codes = extract_codes(document)
        if codes:
            snapshot["refusal_codes"] = codes
    status = extract_status(document, stdout_text)
    if status is not None:
        snapshot["reported_status"] = status
    return snapshot


def evaluate_accepting(cmd: dict, record: dict, document: object,
                       stdout_text: str, stderr_text: str) -> dict | None:
    accepting = cmd.get("accepting_outcome")
    if accepting is None:
        return None
    checks: dict[str, bool] = {}
    checks["exit_code"] = (
        record["exit_code"] is not None
        and record["exit_code"] == accepting.get("exit_code")
    )
    if "report_status" in accepting:
        checks["report_status"] = (
            extract_status(document, stdout_text) == accepting["report_status"]
        )
    if "report_fields" in accepting:
        for field, wanted in accepting["report_fields"].items():
            try:
                observed = resolve_field(document, field)
            except (KeyError, TypeError):
                observed = None
            checks["report_fields.%s" % field] = observed == wanted
    if "stdout_contains" in accepting:
        checks["stdout_contains"] = accepting["stdout_contains"] in stdout_text
    if "report_outcome" in accepting:
        observed = None
        if isinstance(document, dict):
            observed = document.get("outcome")
        checks["report_outcome"] = observed == accepting["report_outcome"]
    if "claim_field" in accepting:
        try:
            observed = resolve_field(document, accepting["claim_field"])
        except (KeyError, TypeError):
            observed = None
        checks["claim_field"] = observed == accepting.get("claim_value")
    return {"checks": checks, "all_ok": all(checks.values())}


def evaluate_refusal(cmd: dict, record: dict, document: object,
                     stdout_text: str, stderr_text: str) -> dict:
    refusal = cmd.get("refusal_outcomes") or {}
    codes = extract_codes(document)
    combined = normalize_code(stdout_text + "\n" + stderr_text)
    observed_norm = {normalize_code(code) for code in codes}

    checks: dict[str, bool] = {}
    if "exit_codes" in refusal:
        checks["exit_in_declared_band"] = (
            record["exit_code"] is not None
            and record["exit_code"] in refusal["exit_codes"]
        )

    matched_declared: list[str] = []
    declared = refusal.get("codes_any_of") or []
    literal = [code for code in declared if is_literal_code(code)]
    if literal:
        for code in literal:
            normalized = normalize_code(code)
            if normalized in observed_norm or normalized in combined:
                matched_declared.append(code)
        checks["codes_any_of"] = bool(matched_declared)

    if refusal.get("stdout_contains_any_of"):
        hits = [
            token for token in refusal["stdout_contains_any_of"]
            if token in stdout_text
        ]
        checks["stdout_contains_any_of"] = bool(hits)
        matched_declared.extend(hits)

    if refusal.get("stderr_contains_any_of"):
        hits = [
            token for token in refusal["stderr_contains_any_of"]
            if token in stderr_text
        ]
        checks["stderr_contains_any_of"] = bool(hits)
        matched_declared.extend(hits)

    if refusal.get("outcomes_any_of"):
        observed_outcome = None
        if isinstance(document, dict):
            observed_outcome = document.get("outcome")
        checks["outcomes_any_of"] = observed_outcome in refusal["outcomes_any_of"]

    if refusal.get("claim_field") is not None:
        try:
            observed_claim = resolve_field(document, refusal["claim_field"])
        except (KeyError, TypeError):
            observed_claim = None
        checks["claim_field"] = observed_claim == refusal.get("claim_value")
        if isinstance(refusal.get("claim_signal"), str):
            matched_declared.append(refusal["claim_signal"])

    code_predicates = {
        key: value
        for key, value in checks.items()
        if key != "exit_in_declared_band"
    }
    declared_matched = any(code_predicates.values()) if code_predicates else False
    return {
        "checks": checks,
        "declared_code_matched": declared_matched,
        "matched_declared": matched_declared,
        "observed_codes": codes,
    }


def classify_command(cmd: dict, record: dict, repo: Path, work: Path) -> dict:
    stdout_text = record["stdout"].decode("utf-8", "replace")
    stderr_text = record["stderr"].decode("utf-8", "replace")
    document = parse_stdout_json(record["stdout"])
    accepting = evaluate_accepting(cmd, record, document, stdout_text, stderr_text)
    refusal = evaluate_refusal(cmd, record, document, stdout_text, stderr_text)

    outcome = "unresolved"
    reason = ""
    if record["timed_out"]:
        outcome = "instrument_error"
        reason = "declared command exceeded the bounded timeout"
    elif record["exit_code"] is None:
        outcome = "instrument_error"
        reason = "declared command could not be executed"
    elif record["exit_code"] == 6:
        outcome = "not_run"
        reason = "declared command returned typed NOT_RUN (exit 6)"
    elif record["exit_code"] in (2, 7):
        outcome = "instrument_error"
        reason = f"declared command returned exit {record['exit_code']}"
    elif accepting is not None and accepting["all_ok"]:
        outcome = "accept"
        reason = "documented accepting outcome observed"
    elif record["exit_code"] != 0:
        outcome = "refuse"
        reason = "declared command exited nonzero"
    elif refusal["declared_code_matched"]:
        outcome = "refuse"
        reason = "documented claim-level refusal observed at exit 0"
    else:
        outcome = "unresolved"
        reason = "exit 0 but the documented accepting outcome was not observed"

    return {
        "id": cmd["id"],
        "kind": cmd["kind"],
        "decisive": bool(cmd.get("decisive", False)),
        "argv": display_argv(
            substitute_argv(cmd["argv"], repo, work), repo, work
        ),
        "working_directory": display_cwd(
            work / cmd.get("working_directory", ".").replace("{work}/", "").replace("{work}", ""),
            repo,
            work,
        ),
        "exit_code": record["exit_code"],
        "timed_out": record["timed_out"],
        "duration_ms": record["duration_ms"],
        "stdout_sha256": sha256_bytes(record["stdout"]),
        "stderr_sha256": sha256_bytes(record["stderr"]),
        "stderr_tail": sanitize_tail(stderr_text, repo, work),
        "reported": report_snapshot(document, stdout_text),
        "accepting_checks": accepting["checks"] if accepting else {},
        "refusal_checks": refusal["checks"],
        "observed_codes": refusal["observed_codes"],
        "matched_declared": refusal["matched_declared"],
        "declared_code_matched": refusal["declared_code_matched"],
        "outcome": outcome,
        "outcome_reason": reason,
        "context_only_expected_outcome": cmd.get("expected_outcome")
        if not cmd.get("decisive", False) else None,
    }


def combine_case(records: list[dict], decisive_only: bool = True) -> tuple[str, str]:
    relevant = [r for r in records if r["decisive"]] if decisive_only else records
    if not relevant:
        return "unresolved", "no decisive command was declared"
    if any(r["outcome"] == "instrument_error" for r in relevant):
        return "instrument_error", "a decisive command was an instrument error"
    if any(r["outcome"] == "not_run" for r in relevant):
        return "unresolved", "a decisive command returned typed NOT_RUN"
    if any(r["outcome"] == "refuse" for r in relevant):
        return "refuse", "a decisive command reported a documented refusal"
    if any(r["outcome"] == "unresolved" for r in relevant):
        return "unresolved", "a decisive command did not report a documented outcome"
    return "accept", "every decisive command reported its documented accepting outcome"


# ---------------------------------------------------------------------------
# restoration control
# ---------------------------------------------------------------------------


def _operation_component(operation: str, pattern: str) -> str | None:
    match = re.search(pattern, operation)
    return match.group(0) if match else None


def run_restoration(case: dict, repo: Path, work_root: Path,
                    case_root: Path, protocol: dict,
                    case_observed: str) -> dict:
    control = case["restoration_control"]
    kind = control["kind"]
    record = {
        "kind": kind,
        "declared_expected": control["expected"],
        "observed": "not_run",
        "basis": "",
        "commands": [],
        "duration_ms": 0,
    }
    if kind == "identity_copy":
        # For a positive case the identity copy *is* the case run. Its observed
        # outcome is therefore the case outcome, not an assumed acceptance.
        record["observed"] = case_observed
        record["basis"] = (
            "identity copy: the case run is the restoration; the recorded "
            "outcome is the observed case outcome"
        )
        return record

    try:
        if kind == "argument_restoration":
            restored_root = prepare_work(repo, case, work_root / "restoration")
            committed = _operation_component(
                control["operation"], r"\b[0-9a-f]{64}\b"
            )
            if committed is None:
                raise CaseBlocked("restoration operation does not name a committed value")
            mutated_imprint = None
            for cmd in case["verifier_commands"]:
                for argument in cmd["argv"]:
                    if argument == ZERO64:
                        mutated_imprint = ZERO64
                        break
                if mutated_imprint:
                    break
            if mutated_imprint is None:
                raise CaseBlocked("case argv does not declare the mutated imprint")
        elif kind in ("full_restoration", "field_restoration", "claim_selection_restoration"):
            restored_root = prepare_work(repo, case, work_root / "restoration")
            committed = None
        else:
            raise CaseBlocked(f"no generic handler for restoration kind {kind!r}")
    except CaseBlocked as error:
        record["observed"] = "unresolved"
        record["basis"] = str(error)
        return record

    for cmd in case["verifier_commands"]:
        if not cmd.get("decisive", False):
            continue
        argv = substitute_argv(cmd["argv"], repo, restored_root)
        if kind == "argument_restoration" and committed is not None:
            argv = [
                committed if argument == ZERO64 else argument for argument in argv
            ]
            commands_for_classify = dict(cmd)
            accepting = copy.deepcopy(cmd.get("accepting_outcome") or {})
            commands_for_classify["accepting_outcome"] = accepting
        else:
            commands_for_classify = cmd
        cwd = restored_root / cmd.get("working_directory", "{work}").replace(
            "{work}/", ""
        ).replace("{work}", "")
        raw = run_command(argv, cwd)
        classified = classify_command(commands_for_classify, raw, repo, restored_root)
        classified["argv"] = display_argv(argv, repo, restored_root)
        record["commands"].append(classified)
        record["duration_ms"] += raw["duration_ms"]

    observed, basis = combine_case(record["commands"])
    record["observed"] = observed
    record["basis"] = basis
    return record


# ---------------------------------------------------------------------------
# per-case execution
# ---------------------------------------------------------------------------


def execute_case(case: dict, repo: Path, work_root: Path, index: dict[str, dict],
                 protocol: dict) -> dict:
    case_root = work_root / "case"
    receipt: dict = {
        "schema": SCHEMA_RECEIPT,
        "spec": SPEC,
        "case_id": case["id"],
        "partition": case["partition"],
        "family": case["family"],
        "description": case["description"],
        "protocol_sha256": protocol["_sha256"],
        "expected_decision": case["expected_augmented_decision"],
        "observed_decision": "unresolved",
        "expected_match": False,
        "decision_basis": "",
        "foundation": foundation_decision(repo, case, index),
        "mutation": {
            "kind": case["mutation"]["kind"],
            "target": case["mutation"]["target"],
            "applied": False,
            "blocked_reason": None,
            "fields_changed": [],
        },
        "commands": [],
        "restoration": None,
        "cost": {
            "wall_clock_ms": 0,
            "bytes_read": 0,
            "bytes_read_basis": "sum of declared base artifact sizes",
        },
        "non_claims": [
            "A refusal is not a pass. A NOT_RUN is not a pass.",
            "This receipt is a harness output, not a review or certification.",
            "Durations are per-run resource accounting only.",
        ],
    }

    base_bytes = 0
    for artifact_id in case.get("base_artifacts", []):
        binding = index.get(artifact_id)
        if binding is not None:
            path = repo / binding["path"]
            if path.is_file():
                base_bytes += path.stat().st_size
    receipt["cost"]["bytes_read"] = base_bytes

    try:
        prepare_work(repo, case, case_root)
        changes = apply_mutation(case, case_root, repo)
        receipt["mutation"]["applied"] = True
        receipt["mutation"]["fields_changed"] = changes
    except CaseBlocked as error:
        receipt["mutation"]["blocked_reason"] = str(error)
        receipt["observed_decision"] = "unresolved"
        receipt["decision_basis"] = f"case blocked: {error}"
        receipt["expected_match"] = (
            receipt["observed_decision"] == receipt["expected_decision"]
        )
        return receipt
    except Exception as error:  # noqa: BLE001 - a case that cannot be applied
        receipt["mutation"]["blocked_reason"] = (
            f"{type(error).__name__}: {error}"
        )
        receipt["observed_decision"] = "unresolved"
        receipt["decision_basis"] = (
            "case could not be implemented exactly as declared: "
            f"{type(error).__name__}: {error}"
        )
        receipt["expected_match"] = (
            receipt["observed_decision"] == receipt["expected_decision"]
        )
        return receipt

    for cmd in case["verifier_commands"]:
        argv = substitute_argv(cmd["argv"], repo, case_root)
        cwd = case_root / cmd.get("working_directory", "{work}").replace(
            "{work}/", ""
        ).replace("{work}", "")
        raw = run_command(argv, cwd)
        classified = classify_command(cmd, raw, repo, case_root)
        receipt["commands"].append(classified)
        receipt["cost"]["wall_clock_ms"] += raw["duration_ms"]

    observed, basis = combine_case(receipt["commands"])
    receipt["observed_decision"] = observed
    receipt["decision_basis"] = basis

    receipt["restoration"] = run_restoration(
        case, repo, work_root, case_root, protocol, observed
    )

    # The declared expectation is consulted only now, after classification.
    receipt["expected_match"] = observed == receipt["expected_decision"]
    return receipt


# ---------------------------------------------------------------------------
# analysis
# ---------------------------------------------------------------------------


def family_control_summary(receipts: list[dict]) -> dict:
    families: dict[str, dict] = {}
    for receipt in receipts:
        family = receipt["family"]
        entry = families.setdefault(
            family,
            {
                "cases": [],
                "negative_cases": 0,
                "positive_cases": 0,
                "correct_refusals": 0,
                "wrong_code_refusals": 0,
                "acceptances_of_negative": 0,
                "unresolved": 0,
                "instrument_errors": 0,
                "restoration_passed": 0,
                "restoration_expected": 0,
                "restoration_failed": 0,
            },
        )
        expected = receipt["expected_decision"]
        observed = receipt["observed_decision"]
        entry["cases"].append(receipt["case_id"])
        if expected == "accept":
            entry["positive_cases"] += 1
        else:
            entry["negative_cases"] += 1
        if observed == "accept" and expected == "refuse":
            entry["acceptances_of_negative"] += 1
        elif observed == "refuse" and expected == "refuse":
            refusing = [
                command
                for command in receipt["commands"]
                if command["decisive"] and command["outcome"] == "refuse"
            ]
            wrong = any(
                not command["declared_code_matched"] for command in refusing
            )
            if wrong:
                entry["wrong_code_refusals"] += 1
            else:
                entry["correct_refusals"] += 1
        elif observed == "unresolved":
            entry["unresolved"] += 1
        elif observed == "instrument_error":
            entry["instrument_errors"] += 1
        restoration = receipt.get("restoration") or {}
        if receipt["expected_decision"] == "refuse":
            entry["restoration_expected"] += 1
            if restoration.get("observed") == "accept":
                entry["restoration_passed"] += 1
            else:
                entry["restoration_failed"] += 1
    for entry in families.values():
        entry["cases"].sort()
    return families


def negative_findings(receipts: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for receipt in receipts:
        expected = receipt["expected_decision"]
        observed = receipt["observed_decision"]
        case_id = receipt["case_id"]
        if expected == "accept" and observed == "refuse":
            findings.append(
                {
                    "case_id": case_id,
                    "kind": "wrongful_refusal_of_positive_control",
                    "detail": receipt["decision_basis"],
                }
            )
        if expected == "refuse" and observed == "accept":
            findings.append(
                {
                    "case_id": case_id,
                    "kind": "wrongful_acceptance_of_negative_control",
                    "detail": receipt["decision_basis"],
                }
            )
        if observed == "unresolved":
            findings.append(
                {
                    "case_id": case_id,
                    "kind": "unresolved_case",
                    "detail": receipt["decision_basis"],
                }
            )
        if observed == "instrument_error":
            findings.append(
                {
                    "case_id": case_id,
                    "kind": "instrument_error",
                    "detail": receipt["decision_basis"],
                }
            )
        for command in receipt["commands"]:
            if command["decisive"] and command["outcome"] == "refuse":
                if not command["declared_code_matched"]:
                    findings.append(
                        {
                            "case_id": case_id,
                            "kind": "wrong_code_refusal",
                            "command": command["id"],
                            "exit_code": command["exit_code"],
                            "observed_codes": command["observed_codes"],
                            "matched_declared": command["matched_declared"],
                            "refusal_checks": command["refusal_checks"],
                        }
                    )
        restoration = receipt.get("restoration") or {}
        if expected == "refuse" and restoration.get("observed") not in ("accept",):
            findings.append(
                {
                    "case_id": case_id,
                    "kind": "restoration_control_failure",
                    "observed": restoration.get("observed"),
                    "expected": restoration.get("declared_expected"),
                    "detail": restoration.get("basis"),
                }
            )
        if (
            expected == "accept"
            and restoration.get("observed") != "accept"
        ):
            findings.append(
                {
                    "case_id": case_id,
                    "kind": "restoration_control_failure",
                    "observed": restoration.get("observed"),
                    "expected": restoration.get("declared_expected"),
                    "detail": restoration.get("basis"),
                }
            )
        if receipt["foundation"]["decision"] != "accept":
            findings.append(
                {
                    "case_id": case_id,
                    "kind": "foundation_anchor_not_accepting",
                    "detail": receipt["foundation"],
                }
            )
        if (
            receipt["foundation"]["sha256_matches_binding"] is False
        ):
            findings.append(
                {
                    "case_id": case_id,
                    "kind": "foundation_anchor_digest_mismatch",
                    "detail": receipt["foundation"],
                }
            )
    return findings


def build_analysis(protocol: dict, partition: str, receipts: list[dict],
                   repo: Path) -> dict:
    ordered = sorted(receipts, key=lambda item: item["case_id"])
    counts = {
        "cases_total": len(ordered),
        "expected_accept": sum(
            1 for item in ordered if item["expected_decision"] == "accept"
        ),
        "expected_refuse": sum(
            1 for item in ordered if item["expected_decision"] == "refuse"
        ),
        "observed_accept": sum(
            1 for item in ordered if item["observed_decision"] == "accept"
        ),
        "observed_refuse": sum(
            1 for item in ordered if item["observed_decision"] == "refuse"
        ),
        "observed_unresolved": sum(
            1 for item in ordered if item["observed_decision"] == "unresolved"
        ),
        "observed_instrument_error": sum(
            1 for item in ordered if item["observed_decision"] == "instrument_error"
        ),
        "expected_match": sum(1 for item in ordered if item["expected_match"]),
    }
    matrix: dict[str, dict[str, int]] = {
        "expected_accept": {key: 0 for key in DECISIONS},
        "expected_refuse": {key: 0 for key in DECISIONS},
    }
    for item in ordered:
        row = (
            "expected_accept"
            if item["expected_decision"] == "accept"
            else "expected_refuse"
        )
        matrix[row][item["observed_decision"]] += 1

    per_case_accuracy = {
        item["case_id"]: item["expected_match"] for item in ordered
    }
    wrongful_acceptance = [
        item["case_id"]
        for item in ordered
        if item["expected_decision"] == "refuse"
        and item["observed_decision"] == "accept"
    ]
    wrongful_refusal = [
        item["case_id"]
        for item in ordered
        if item["expected_decision"] == "accept"
        and item["observed_decision"] == "refuse"
    ]
    unresolved = [
        item["case_id"]
        for item in ordered
        if item["observed_decision"] == "unresolved"
    ]
    instrument_errors = [
        item["case_id"]
        for item in ordered
        if item["observed_decision"] == "instrument_error"
    ]

    wall_clock = {
        item["case_id"]: item["cost"]["wall_clock_ms"] for item in ordered
    }
    bytes_read = {
        item["case_id"]: item["cost"]["bytes_read"] for item in ordered
    }
    restoration_clock = {
        item["case_id"]: (item["restoration"] or {}).get("duration_ms", 0)
        for item in ordered
    }
    binary = repo / "target/debug/frf-memorysafety"
    binary_sha = sha256_bytes(binary.read_bytes()) if binary.is_file() else None

    analysis = {
        "schema": SCHEMA_ANALYSIS,
        "spec": SPEC,
        "protocol_version": protocol["protocol_version"],
        "protocol_sha256": protocol["_sha256"],
        "partition": partition,
        "held_out_executed": partition in ("held-out", "all"),
        "instrument": {
            "binary_relative_path": "target/debug/frf-memorysafety",
            "binary_sha256": binary_sha,
            "python_version": sys.version.split()[0],
            "openssl_present": shutil.which("openssl") is not None,
        },
        "cases": [
            {
                "case_id": item["case_id"],
                "family": item["family"],
                "expected_decision": item["expected_decision"],
                "observed_decision": item["observed_decision"],
                "expected_match": item["expected_match"],
                "foundation_decision": item["foundation"]["decision"],
                "foundation_augmented_agreement": (
                    item["foundation"]["decision"] == item["observed_decision"]
                ),
                "restoration_observed": (item["restoration"] or {}).get("observed"),
                "mutation_applied": item["mutation"]["applied"],
            }
            for item in ordered
        ],
        "counts": counts,
        "outcome_matrix": matrix,
        "decision_accuracy": {
            "matched": counts["expected_match"],
            "total": counts["cases_total"],
            "per_case": per_case_accuracy,
        },
        "wrongful_acceptance": wrongful_acceptance,
        "wrongful_refusal": wrongful_refusal,
        "unresolved": unresolved,
        "instrument_errors": instrument_errors,
        "control_effectiveness_by_family": family_control_summary(ordered),
        "foundation_augmented_agreement": {
            "agree": sum(
                1
                for item in ordered
                if item["foundation"]["decision"] == item["observed_decision"]
            ),
            "total": len(ordered),
            "per_case": {
                item["case_id"]: (
                    item["foundation"]["decision"] == item["observed_decision"]
                )
                for item in ordered
            },
        },
        "costs": {
            "wall_clock_ms_by_case": wall_clock,
            "wall_clock_ms_total": sum(wall_clock.values()),
            "restoration_wall_clock_ms_by_case": restoration_clock,
            "restoration_wall_clock_ms_total": sum(restoration_clock.values()),
            "bytes_read_by_case": bytes_read,
            "bytes_read_total": sum(bytes_read.values()),
            "bytes_read_basis": "sum of declared base artifact sizes; rchar delta "
                                 "not captured",
            "note": "Per-run resource accounting only; not comparable across "
                    "hosts, images, or runs.",
        },
        "negative_findings": negative_findings(ordered),
        "mismatches": [
            {
                "case_id": item["case_id"],
                "expected_decision": item["expected_decision"],
                "observed_decision": item["observed_decision"],
                "basis": item["decision_basis"],
            }
            for item in ordered
            if not item["expected_match"]
        ],
        "internal_consistency": {
            "every_selected_case_has_a_receipt": True,
            "every_selected_case_mutation_applied": all(
                item["mutation"]["applied"] for item in ordered
            ),
            "protocol_sha256": protocol["_sha256"],
        },
        "non_claims": protocol["non_claims"],
        "claim_ceiling": protocol["claim_ceiling"],
    }
    return analysis


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def selected_cases(protocol: dict, partition: str) -> list[dict]:
    members = {
        "development": set(protocol["partitions"]["development"]),
        "held-out": set(protocol["partitions"]["held_out"]),
    }
    if partition == "all":
        wanted = members["development"] | members["held-out"]
    else:
        wanted = members[partition]
    cases = [case for case in protocol["cases"] if case["id"] in wanted]
    if len(cases) != len(wanted):
        raise HarnessError("selected case population does not match the protocol")
    return sorted(cases, key=lambda case: case["id"])


def print_case_line(receipt: dict) -> None:
    observed = receipt["observed_decision"]
    if observed == "unresolved":
        status = "UNRESOLVED"
    elif observed == "instrument_error":
        status = "UNRESOLVED"
    elif receipt["expected_match"]:
        status = "PASS"
    else:
        status = "FAIL"
    print(
        "%s %s expected=%s observed=%s foundation=%s"
        % (
            status,
            receipt["case_id"],
            receipt["expected_decision"],
            observed,
            receipt["foundation"]["decision"],
        )
    )
    if observed in ("unresolved", "instrument_error"):
        print("  reason: %s" % receipt["decision_basis"])
    for command in receipt["commands"]:
        if command["decisive"] and command["outcome"] == "refuse":
            if not command["declared_code_matched"]:
                print(
                    "  wrong-code: command=%s exit=%s observed=%s"
                    % (
                        command["id"],
                        command["exit_code"],
                        command["observed_codes"] or command["matched_declared"],
                    )
                )
    restoration = receipt.get("restoration") or {}
    if receipt["expected_decision"] == "refuse":
        if restoration.get("observed") == "accept":
            print("  restoration: PASS")
        else:
            print(
                "  restoration: FAIL observed=%s expected=%s"
                % (restoration.get("observed"), restoration.get("declared_expected"))
            )


def print_totals(analysis: dict) -> None:
    counts = analysis["counts"]
    costs = analysis["costs"]
    print(
        "ANALYSIS partition=%s cases=%d accept=%d refuse=%d unresolved=%d "
        "instrument_errors=%d decision_accuracy=%d/%d"
        % (
            analysis["partition"],
            counts["cases_total"],
            counts["observed_accept"],
            counts["observed_refuse"],
            counts["observed_unresolved"],
            counts["observed_instrument_error"],
            analysis["decision_accuracy"]["matched"],
            analysis["decision_accuracy"]["total"],
        )
    )
    print(
        "ANALYSIS wrongful_acceptance=%d wrongful_refusal=%d "
        "foundation_augmented_agreement=%d/%d"
        % (
            len(analysis["wrongful_acceptance"]),
            len(analysis["wrongful_refusal"]),
            analysis["foundation_augmented_agreement"]["agree"],
            analysis["foundation_augmented_agreement"]["total"],
        )
    )
    print(
        "ANALYSIS wall_clock_ms_total=%d bytes_read_total=%d basis=%s"
        % (
            costs["wall_clock_ms_total"],
            costs["bytes_read_total"],
            costs["bytes_read_basis"],
        )
    )
    for family in sorted(analysis["control_effectiveness_by_family"]):
        entry = analysis["control_effectiveness_by_family"][family]
        print(
            "FAMILY %s cases=%d negative=%d correct_refusals=%d "
            "wrong_code_refusals=%d acceptances_of_negative=%d unresolved=%d "
            "instrument_errors=%d restoration_passed=%d/%d"
            % (
                family,
                len(entry["cases"]),
                entry["negative_cases"],
                entry["correct_refusals"],
                entry["wrong_code_refusals"],
                entry["acceptances_of_negative"],
                entry["unresolved"],
                entry["instrument_errors"],
                entry["restoration_passed"],
                entry["restoration_expected"],
            )
        )
    print(
        "NOTE PASS means the observed decision equals the declared expectation. "
        "It is not a certification. A refusal is not a pass. A NOT_RUN is not a pass."
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--partition",
        choices=("development", "held-out", "all"),
        required=True,
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    repo = Path(__file__).resolve().parents[2]
    try:
        protocol, protocol_sha = load_frozen_protocol(repo)
        protocol["_sha256"] = protocol_sha
        recompute_partition(protocol)
        problems = verify_bindings(repo, protocol)
        if problems:
            for problem in problems:
                print(f"INVALID {problem}", file=sys.stderr)
            return EXIT_INVALID
        index = artifact_index(protocol)
        cases = selected_cases(protocol, args.partition)
    except HarnessError as error:
        print(f"INVALID {error}", file=sys.stderr)
        return EXIT_INVALID

    out = args.out
    receipts_dir = out / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)

    work_parent = Path(tempfile.mkdtemp(prefix="frf-comparative-"))
    receipts: list[dict] = []
    try:
        for case in cases:
            work_root = work_parent / case["id"]
            receipt = execute_case(case, repo, work_root, index, protocol)
            write_canonical(receipts_dir / ("%s.json" % case["id"]), receipt)
            receipts.append(receipt)
            print_case_line(receipt)
            shutil.rmtree(work_root, ignore_errors=True)
    finally:
        shutil.rmtree(work_parent, ignore_errors=True)

    if len(receipts) != len(cases):
        print("INVALID missing case receipts", file=sys.stderr)
        return EXIT_MISSING_RECEIPT

    analysis = build_analysis(protocol, args.partition, receipts, repo)
    analysis_name = "analysis-%s.json" % args.partition
    write_canonical(out / analysis_name, analysis)
    print_totals(analysis)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001 - typed harness failure
        print(f"HARNESS ERROR {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(EXIT_HARNESS)
