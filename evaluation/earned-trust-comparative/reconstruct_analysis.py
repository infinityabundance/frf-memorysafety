#!/usr/bin/env python3
"""Independent reconstruction of the Phase 17 comparative analysis.

This program does not import the comparative harness. It reads the frozen
protocol, the opening sidecars and the 18 committed case receipts, and
recomputes the decision matrix, the failure counts and the restoration
outcomes. It then checks that the harness analyses agree with that
recomputation. It does not re-run any verifier and does not decide whether an
expectation was correct; it checks bookkeeping only.

Exit 0 when the receipt set is complete, partitioned as declared, and agrees
with both analysis files. Exit 1 on any discrepancy. A mismatch between an
expectation and an observation is a recorded result, not a reconstruction
error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

SCHEMA = "frf-etp.comparative-reconstruction.v1"
DECISIONS = ("accept", "refuse", "unresolved", "instrument_error")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument(
        "--out",
        default="evaluation/earned-trust-comparative/analysis-reconstruction.json",
    )
    args = parser.parse_args(argv)
    repo = Path(args.repo).resolve()
    comp = repo / "evaluation/earned-trust-comparative"
    problems: list[str] = []
    report: dict = {
        "schema": SCHEMA,
        "evidence_kind": "INDEPENDENT_RECONSTRUCTION",
        "claim_ceiling": (
            "This reconstruction checks that the committed receipts, the frozen "
            "protocol and the two harness analyses agree on a finite bookkeeping "
            "population. It does not re-run a verifier, does not establish that a "
            "refusal is correct, does not repair a failed expectation, and is not "
            "certification, review, independence or authorization to deploy."
        ),
        "openings": {},
        "partitions": {},
        "discrepancies": problems,
    }

    protocol_path = comp / "protocol.json"
    protocol_sha = sha256(protocol_path)
    opening = comp / "OPENING.sha256"
    opening_lines = opening.read_text(encoding="utf-8").splitlines()
    opening_ok = any(
        line.split() == [protocol_sha, "protocol.json"] for line in opening_lines
    )
    report["openings"]["protocol_sha256"] = protocol_sha
    report["openings"]["opening_sha256_matches"] = opening_ok
    if not opening_ok:
        problems.append("protocol.json does not match OPENING.sha256")

    held = comp / "HELD-OUT-OPENING.sha256"
    held_map = {}
    for line in held.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) == 2:
            held_map[parts[1]] = parts[0]
    harness_sha = sha256(comp / "run_comparative.py")
    report["openings"]["harness_sha256"] = harness_sha
    report["openings"]["held_out_opening_harness_matches"] = (
        held_map.get("run_comparative.py") == harness_sha
    )
    if held_map.get("protocol.json") != protocol_sha:
        problems.append("protocol.json does not match HELD-OUT-OPENING.sha256")
    if held_map.get("run_comparative.py") != harness_sha:
        problems.append("run_comparative.py does not match HELD-OUT-OPENING.sha256")

    protocol = load(protocol_path)
    cases = {case["id"]: case for case in protocol["cases"]}
    development = set(protocol["partitions"]["development"])
    held_out = set(protocol["partitions"]["held_out"])
    if len(cases) != 18:
        problems.append("protocol case count is not 18")
    if len(development) != 6 or len(held_out) != 12:
        problems.append("partition counts are not 6/12")
    if development & held_out:
        problems.append("partitions overlap")
    if development | held_out != set(cases):
        problems.append("partition union is not the declared population")

    receipts_dir = comp / "receipts"
    receipt_paths = sorted(receipts_dir.glob("*.json"))
    receipts = {}
    receipt_digests = {}
    for path in receipt_paths:
        document = load(path)
        case_id = document.get("case_id")
        if case_id in receipts:
            problems.append("duplicate receipt for " + str(case_id))
            continue
        receipts[case_id] = document
        receipt_digests[path.name] = sha256(path)
    report["receipt_digests"] = receipt_digests
    if set(receipts) != set(cases):
        missing = sorted(set(cases) - set(receipts))
        extra = sorted(set(receipts) - set(cases))
        problems.append("receipt population mismatch missing=%r extra=%r" % (missing, extra))

    for label, partition_key, members in (
        ("development", "development", development),
        ("held-out", "held_out", held_out),
    ):
        rows = []
        for case_id in sorted(members):
            case = cases[case_id]
            receipt = receipts.get(case_id)
            if receipt is None:
                rows.append({"case_id": case_id, "missing": True})
                continue
            expected = case["expected_augmented_decision"]
            observed = receipt.get("observed_decision")
            if receipt.get("partition") != partition_key:
                problems.append(case_id + " receipt partition mismatch")
            if receipt.get("expected_decision") != expected:
                problems.append(case_id + " receipt expected decision mismatch")
            if observed not in DECISIONS:
                problems.append(case_id + " observed decision is not typed")
            recomputed_match = observed == expected
            if receipt.get("expected_match") is not recomputed_match:
                problems.append(case_id + " expected_match disagrees with recomputation")
            foundation = (receipt.get("foundation") or {}).get("decision")
            if foundation not in ("accept", "refuse", "unavailable"):
                problems.append(case_id + " foundation decision is not typed")
            restoration = receipt.get("restoration") or {}
            declared = (case.get("restoration_control") or {}).get("expected")
            rows.append(
                {
                    "case_id": case_id,
                    "expected": expected,
                    "observed": observed,
                    "match": recomputed_match,
                    "foundation": foundation,
                    "restoration_declared": declared,
                    "restoration_observed": restoration.get("observed"),
                    "restoration_match": restoration.get("observed") == declared
                    if declared
                    else None,
                    "wrongful_acceptance": expected == "refuse" and observed == "accept",
                    "wrongful_refusal": expected == "accept" and observed == "refuse",
                    "unresolved": observed == "unresolved",
                    "instrument_error": observed == "instrument_error",
                }
            )

        recomputed = {
            "cases": len(rows),
            "matched": sum(1 for row in rows if row.get("match")),
            "wrongful_acceptance": [
                row["case_id"] for row in rows if row.get("wrongful_acceptance")
            ],
            "wrongful_refusal": [
                row["case_id"] for row in rows if row.get("wrongful_refusal")
            ],
            "unresolved": [row["case_id"] for row in rows if row.get("unresolved")],
            "instrument_errors": [
                row["case_id"] for row in rows if row.get("instrument_error")
            ],
            "restoration_failures": [
                row["case_id"]
                for row in rows
                if row.get("restoration_match") is False
            ],
        }
        analysis_path = comp / ("analysis-%s.json" % label)
        if not analysis_path.is_file():
            problems.append("missing " + analysis_path.name)
            analysis = {}
        else:
            analysis = load(analysis_path)
        if analysis:
            declared_cases = {item["case_id"]: item for item in analysis.get("cases", [])}
            for row in rows:
                item = declared_cases.get(row["case_id"])
                if item is None:
                    problems.append(label + ": analysis is missing " + row["case_id"])
                    continue
                if item.get("observed_decision") != row["observed"]:
                    problems.append(
                        label + ": analysis observed mismatch for " + row["case_id"]
                    )
            accuracy = analysis.get("decision_accuracy") or {}
            if accuracy.get("total") != recomputed["cases"]:
                problems.append(label + ": analysis accuracy total mismatch")
            if accuracy.get("matched") != recomputed["matched"]:
                problems.append(label + ": analysis accuracy matched mismatch")
            for key in ("wrongful_acceptance", "wrongful_refusal", "unresolved", "instrument_errors"):
                declared_list = analysis.get(key)
                if declared_list is None:
                    continue
                declared_ids = [
                    item.get("case_id") if isinstance(item, dict) else item
                    for item in declared_list
                ]
                if sorted(declared_ids) != sorted(recomputed[key]):
                    problems.append(label + ": analysis " + key + " mismatch")

        report["partitions"][label] = {
            "rows": rows,
            "recomputed": recomputed,
        }

    report["discrepancy_count"] = len(problems)
    out = Path(args.out)
    if not out.is_absolute():
        out = repo / out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for partition, data in report["partitions"].items():
        recomputed = data["recomputed"]
        print(
            "RECON %s cases=%d matched=%d wrongful_acceptance=%d "
            "wrongful_refusal=%d unresolved=%d instrument_errors=%d "
            "restoration_failures=%d"
            % (
                partition,
                recomputed["cases"],
                recomputed["matched"],
                len(recomputed["wrongful_acceptance"]),
                len(recomputed["wrongful_refusal"]),
                len(recomputed["unresolved"]),
                len(recomputed["instrument_errors"]),
                len(recomputed["restoration_failures"]),
            )
        )
    if problems:
        for problem in problems:
            print("FAIL reconstruction: " + problem)
        return 1
    print("PASS independent analysis reconstruction")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
