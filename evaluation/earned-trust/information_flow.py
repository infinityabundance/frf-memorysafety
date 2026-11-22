#!/usr/bin/env python3
"""ETP information-flow model validator (Phase 12.1).

Validates a bounded information-flow / leakage classification model and emits a
canonical report (frf-etp.information-flow-report.v1) with named refusals and
the claim ceiling. Python standard library only.

Refusal codes:
  unknown_is_not_public            unknown value/metadata class in a positive claim
  missing_metadata_classification  metadata lacks a classification
  missing_leakage_model            threat/leakage model absent
  source_claim_as_binary           source-level claim presented as binary assurance
  fixed_iteration_is_not_constant_time fixed iteration count as constant-time evidence
  absence_of_detection_is_not_absence no leakage detected as proof of no leakage
  scalar_score_forbidden           any scalar confidence/assurance score
  binary_claim_without_execution_path binary claim without witness-bound execution path
  witness_digest_mismatch          witness digest mismatch
  execution_path_mismatch          exe/loader-closure digest mismatch
  binary_claim_without_branch_trace binary constant-time/secret-independent claim without branch trace
  universal_quantification_refused universal quantification
  missing_claim_ceiling            missing claim ceiling
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPORT_SCHEMA = "frf-etp.information-flow-report.v1"

VALUE_CLASSES = {"public", "secret", "declassified", "derived_public", "derived_secret", "unknown"}
METADATA_CLASSES = {"fixed_width", "variable_length", "normalized", "serialized", "spare_capacity", "uninitialized"}
OBSERVABLE_FLAGS = {
    "lengths",
    "capacity",
    "allocation_sizes",
    "object_shape",
    "pointer_derived_access",
    "control_flow",
    "algorithm_selection",
    "failure_behaviour",
}
TRACE_OBSERVABLES = {
    "branch",
    "memory_address",
    "access_count",
    "allocation/release",
    "instruction_latency_class",
    "execution_time",
    "cache",
    "branch_prediction",
    "scheduler",
    "syscall",
    "error/retry",
    "output_length",
}
PROPERTIES = {
    "secret_erasure",
    "no_secret_dependent_branch",
    "constant_time",
    "no_secret_dependent_address",
    "functional_correctness",
    "other",
}
LEVELS = {"source", "binary"}
QUANTIFICATIONS = {"finite_observation", "finite_model_exhaustion", "bounded_model", "universal_contextual"}
BOUNDED_QUANTIFICATIONS = {"finite_observation", "finite_model_exhaustion", "bounded_model"}
BINARY_SECRET_PROPERTIES = {"constant_time", "no_secret_dependent_branch", "no_secret_dependent_address"}


class Refusal(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def is_scalar_score(value: object) -> bool:
    """Any scalar confidence/assurance score is forbidden."""
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        return False
    return False


def contains_scalar_score(obj: object) -> bool:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str) and any(
                term in key.lower() for term in ("score", "confidence", "assurance")
            ):
                if is_scalar_score(value):
                    return True
            if contains_scalar_score(value):
                return True
        return False
    if isinstance(obj, list):
        return any(contains_scalar_score(item) for item in obj)
    return False


def validate_model(model: object) -> list[Refusal]:
    """Validate the model and return a list of refusals (empty means accepted)."""
    refusals: list[Refusal] = []

    if not isinstance(model, dict):
        refusals.append(Refusal("structural", "model must be a JSON object"))
        return refusals

    # Universal quantification is refused before anything else.
    claim = model.get("claim")
    if isinstance(claim, dict):
        quantification = claim.get("quantification")
        if quantification == "universal_contextual":
            refusals.append(Refusal("universal_quantification_refused", "universal quantification is refused"))

    # Missing claim ceiling.
    if isinstance(claim, dict):
        ceiling = claim.get("claim_ceiling")
        if not isinstance(ceiling, str) or not ceiling.strip():
            refusals.append(Refusal("missing_claim_ceiling", "claim_ceiling is required and non-empty"))

    # Missing threat/leakage model.
    if isinstance(claim, dict):
        threat_model = claim.get("threat_model")
        leakage_model = claim.get("leakage_model")
        if not isinstance(threat_model, str) or not threat_model.strip():
            refusals.append(Refusal("missing_leakage_model", "threat_model is required"))
        if not isinstance(leakage_model, str) or not leakage_model.strip():
            refusals.append(Refusal("missing_leakage_model", "leakage_model is required"))

    # Scalar confidence/assurance score anywhere in the model.
    if contains_scalar_score(model):
        refusals.append(Refusal("scalar_score_forbidden", "scalar confidence/assurance score present"))

    # Unknown value/metadata class used in a positive claim.
    values = model.get("values")
    if isinstance(values, list):
        for value in values:
            if isinstance(value, dict):
                value_class = value.get("class")
                if value_class == "unknown":
                    refusals.append(
                        Refusal(
                            "unknown_is_not_public",
                            f"value {value.get('name')!r} uses unknown class in a positive claim",
                        )
                    )

    metadata = model.get("metadata")
    if isinstance(metadata, list):
        for entry in metadata:
            if isinstance(entry, dict):
                meta_class = entry.get("class")
                if meta_class == "unknown":
                    refusals.append(
                        Refusal(
                            "unknown_is_not_public",
                            f"metadata {entry.get('name')!r} uses unknown class in a positive claim",
                        )
                    )
                if meta_class not in METADATA_CLASSES:
                    refusals.append(
                        Refusal(
                            "missing_metadata_classification",
                            f"metadata {entry.get('name')!r} lacks a valid classification",
                        )
                    )

    # Source-level claim presented as binary assurance.
    if isinstance(claim, dict):
        level = claim.get("level")
        if level == "binary":
            refusals.append(
                Refusal(
                    "source_claim_as_binary",
                    "source-level claim presented as binary assurance",
                )
            )

    # Fixed iteration count as constant-time evidence.
    evidence = model.get("evidence")
    if isinstance(evidence, dict):
        fixed_iteration = evidence.get("fixed_iteration_count")
        if fixed_iteration is True:
            refusals.append(
                Refusal(
                    "fixed_iteration_is_not_constant_time",
                    "fixed iteration count is not constant-time evidence",
                )
            )

    # Absence of detected leakage as proof of no leakage.
    if isinstance(evidence, dict):
        no_leakage = evidence.get("no_leakage_detected")
        if no_leakage is True:
            refusals.append(
                Refusal(
                    "absence_of_detection_is_not_absence",
                    "absence of detected leakage is not proof of absence",
                )
            )

    # Binary-level claim requires witness-bound execution path.
    if isinstance(claim, dict):
        level = claim.get("level")
        if level == "binary":
            exec_path = evidence.get("authenticated_execution_path") if isinstance(evidence, dict) else None
            if not isinstance(exec_path, dict):
                refusals.append(
                    Refusal(
                        "binary_claim_without_execution_path",
                        "binary-level claim requires an authenticated execution path binding",
                    )
                )
            else:
                witness_schema = exec_path.get("witness_schema")
                witness_sha256 = exec_path.get("witness_sha256")
                exe_sha256 = exec_path.get("exe_sha256")
                loader_closure_sha256 = exec_path.get("loader_closure_sha256")
                executed_function = exec_path.get("executed_function")
                branch_trace_digest = exec_path.get("branch_trace_digest")

                if not isinstance(witness_schema, str) or not witness_schema.strip():
                    refusals.append(
                        Refusal("binary_claim_without_execution_path", "witness_schema is required")
                    )
                if not isinstance(witness_sha256, str) or not witness_sha256.strip():
                    refusals.append(
                        Refusal("binary_claim_without_execution_path", "witness_sha256 is required")
                    )
                if not isinstance(exe_sha256, str) or not exe_sha256.strip():
                    refusals.append(
                        Refusal("binary_claim_without_execution_path", "exe_sha256 is required")
                    )
                if not isinstance(loader_closure_sha256, str) or not loader_closure_sha256.strip():
                    refusals.append(
                        Refusal("binary_claim_without_execution_path", "loader_closure_sha256 is required")
                    )
                if not isinstance(executed_function, str) or not executed_function.strip():
                    refusals.append(
                        Refusal("binary_claim_without_execution_path", "executed_function is required")
                    )

                # Witness digest / exe / loader-closure mismatch checks.
                if isinstance(witness_sha256, str) and isinstance(exe_sha256, str):
                    if witness_sha256 != exe_sha256:
                        refusals.append(
                            Refusal(
                                "witness_digest_mismatch",
                                "witness SHA-256 does not match exe SHA-256",
                            )
                        )
                if isinstance(exe_sha256, str) and isinstance(loader_closure_sha256, str):
                    if exe_sha256 == loader_closure_sha256:
                        refusals.append(
                            Refusal(
                                "execution_path_mismatch",
                                "exe SHA-256 equals loader-closure SHA-256 (expected distinct digests)",
                            )
                        )

                # Binary-level constant-time/secret-independent claim requires branch trace.
                property_name = claim.get("property")
                if property_name in BINARY_SECRET_PROPERTIES:
                    if not isinstance(branch_trace_digest, str) or not branch_trace_digest.strip():
                        refusals.append(
                            Refusal(
                                "binary_claim_without_branch_trace",
                                f"binary-level {property_name} claim requires a branch-trace digest",
                            )
                        )

    return refusals


def build_report(model: object, refusals: list[Refusal], claim_ceiling: str) -> dict:
    accepted = len(refusals) == 0
    binary_behavior_not_established = accepted and isinstance(model, dict) and isinstance(model.get("claim"), dict) and model["claim"].get("level") == "source"

    report = {
        "schema": REPORT_SCHEMA,
        "spec": "frf-etp-information-flow-v1",
        "accepted": accepted,
        "claim_ceiling": claim_ceiling,
        "binary_behavior_not_established": binary_behavior_not_established,
        "refusals": [
            {"code": r.code, "detail": r.detail} for r in refusals
        ],
        "refusal_count": len(refusals),
    }
    return report


def write_report(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical(report).decode("utf-8") + "\n", encoding="utf-8")


def run_self_test(report_path: Path | None = None) -> dict:
    """Build the valid model plus mutated controls and assert refusal.
    Returns the canonical report for the valid model."""
    valid_model = {
        "claim": {
            "id": "frf-etp.information-flow.source.secret_erasure.v1",
            "property": "secret_erasure",
            "level": "source",
            "threat_model": "local adversary observing source-level control flow and memory accesses",
            "leakage_model": "bounded source-level leakage model over one fixture",
            "quantification": "bounded_model",
            "assumptions": [
                {
                    "id": "assumption-1",
                    "statement": "the source model covers the declared function only",
                    "state": "declared",
                }
            ],
            "claim_ceiling": "This source-level model does not establish binary behavior, timing behavior, or deployment security.",
        },
        "values": [
            {
                "name": "secret_input",
                "class": "secret",
                "representation_class": "fixed_width",
                "length_class": "fixed",
            }
        ],
        "metadata": [
            {
                "name": "secret_input",
                "class": "fixed_width",
                "observable_flag": "control_flow",
            }
        ],
        "trace_model": {
            "observables_in_scope": ["branch", "memory_address", "access_count"],
            "explicit_exclusions": ["execution_time", "cache"],
            "limitations": "no live timing measurement yet (Phase 12.2)",
        },
        "evidence": {
            "fixed_iteration_count": False,
            "no_leakage_detected": False,
        },
    }

    controls: list[tuple[str, dict, str]] = [
        (
            "unknown_as_public",
            {
                "claim": {
                    "id": "frf-etp.information-flow.source.secret_erasure.v1",
                    "property": "secret_erasure",
                    "level": "source",
                    "threat_model": "local adversary",
                    "leakage_model": "bounded source-level leakage model",
                    "quantification": "bounded_model",
                    "assumptions": [],
                    "claim_ceiling": "This source-level model does not establish binary behavior.",
                },
                "values": [
                    {
                        "name": "secret_input",
                        "class": "unknown",
                        "representation_class": "fixed_width",
                        "length_class": "fixed",
                    }
                ],
                "metadata": [
                    {
                        "name": "secret_input",
                        "class": "fixed_width",
                        "observable_flag": "control_flow",
                    }
                ],
                "trace_model": {
                    "observables_in_scope": ["branch"],
                    "explicit_exclusions": [],
                    "limitations": "no live timing measurement yet (Phase 12.2)",
                },
                "evidence": {
                    "fixed_iteration_count": False,
                    "no_leakage_detected": False,
                },
            },
            "unknown_is_not_public",
        ),
        (
            "missing_metadata",
            {
                "claim": {
                    "id": "frf-etp.information-flow.source.secret_erasure.v1",
                    "property": "secret_erasure",
                    "level": "source",
                    "threat_model": "local adversary",
                    "leakage_model": "bounded source-level leakage model",
                    "quantification": "bounded_model",
                    "assumptions": [],
                    "claim_ceiling": "This source-level model does not establish binary behavior.",
                },
                "values": [
                    {
                        "name": "secret_input",
                        "class": "secret",
                        "representation_class": "fixed_width",
                        "length_class": "fixed",
                    }
                ],
                "metadata": [
                    {
                        "name": "secret_input",
                        "class": "unknown",
                        "observable_flag": "control_flow",
                    }
                ],
                "trace_model": {
                    "observables_in_scope": ["branch"],
                    "explicit_exclusions": [],
                    "limitations": "no live timing measurement yet (Phase 12.2)",
                },
                "evidence": {
                    "fixed_iteration_count": False,
                    "no_leakage_detected": False,
                },
            },
            "missing_metadata_classification",
        ),
        (
            "missing_leakage_model",
            {
                "claim": {
                    "id": "frf-etp.information-flow.source.secret_erasure.v1",
                    "property": "secret_erasure",
                    "level": "source",
                    "threat_model": "",
                    "leakage_model": "",
                    "quantification": "bounded_model",
                    "assumptions": [],
                    "claim_ceiling": "This source-level model does not establish binary behavior.",
                },
                "values": [
                    {
                        "name": "secret_input",
                        "class": "secret",
                        "representation_class": "fixed_width",
                        "length_class": "fixed",
                    }
                ],
                "metadata": [
                    {
                        "name": "secret_input",
                        "class": "fixed_width",
                        "observable_flag": "control_flow",
                    }
                ],
                "trace_model": {
                    "observables_in_scope": ["branch"],
                    "explicit_exclusions": [],
                    "limitations": "no live timing measurement yet (Phase 12.2)",
                },
                "evidence": {
                    "fixed_iteration_count": False,
                    "no_leakage_detected": False,
                },
            },
            "missing_leakage_model",
        ),
        (
            "source_as_binary",
            {
                "claim": {
                    "id": "frf-etp.information-flow.source.secret_erasure.v1",
                    "property": "secret_erasure",
                    "level": "binary",
                    "threat_model": "local adversary",
                    "leakage_model": "bounded source-level leakage model",
                    "quantification": "bounded_model",
                    "assumptions": [],
                    "claim_ceiling": "This source-level model does not establish binary behavior.",
                },
                "values": [
                    {
                        "name": "secret_input",
                        "class": "secret",
                        "representation_class": "fixed_width",
                        "length_class": "fixed",
                    }
                ],
                "metadata": [
                    {
                        "name": "secret_input",
                        "class": "fixed_width",
                        "observable_flag": "control_flow",
                    }
                ],
                "trace_model": {
                    "observables_in_scope": ["branch"],
                    "explicit_exclusions": [],
                    "limitations": "no live timing measurement yet (Phase 12.2)",
                },
                "evidence": {
                    "fixed_iteration_count": False,
                    "no_leakage_detected": False,
                },
            },
            "source_claim_as_binary",
        ),
        (
            "fixed_iteration",
            {
                "claim": {
                    "id": "frf-etp.information-flow.source.constant_time.v1",
                    "property": "constant_time",
                    "level": "source",
                    "threat_model": "local adversary",
                    "leakage_model": "bounded source-level leakage model",
                    "quantification": "bounded_model",
                    "assumptions": [],
                    "claim_ceiling": "This source-level model does not establish binary behavior.",
                },
                "values": [
                    {
                        "name": "secret_input",
                        "class": "secret",
                        "representation_class": "fixed_width",
                        "length_class": "fixed",
                    }
                ],
                "metadata": [
                    {
                        "name": "secret_input",
                        "class": "fixed_width",
                        "observable_flag": "control_flow",
                    }
                ],
                "trace_model": {
                    "observables_in_scope": ["branch"],
                    "explicit_exclusions": [],
                    "limitations": "no live timing measurement yet (Phase 12.2)",
                },
                "evidence": {
                    "fixed_iteration_count": True,
                    "no_leakage_detected": False,
                },
            },
            "fixed_iteration_is_not_constant_time",
        ),
        (
            "absence_of_detection",
            {
                "claim": {
                    "id": "frf-etp.information-flow.source.secret_erasure.v1",
                    "property": "secret_erasure",
                    "level": "source",
                    "threat_model": "local adversary",
                    "leakage_model": "bounded source-level leakage model",
                    "quantification": "bounded_model",
                    "assumptions": [],
                    "claim_ceiling": "This source-level model does not establish binary behavior.",
                },
                "values": [
                    {
                        "name": "secret_input",
                        "class": "secret",
                        "representation_class": "fixed_width",
                        "length_class": "fixed",
                    }
                ],
                "metadata": [
                    {
                        "name": "secret_input",
                        "class": "fixed_width",
                        "observable_flag": "control_flow",
                    }
                ],
                "trace_model": {
                    "observables_in_scope": ["branch"],
                    "explicit_exclusions": [],
                    "limitations": "no live timing measurement yet (Phase 12.2)",
                },
                "evidence": {
                    "fixed_iteration_count": False,
                    "no_leakage_detected": True,
                },
            },
            "absence_of_detection_is_not_absence",
        ),
        (
            "scalar_score",
            {
                "claim": {
                    "id": "frf-etp.information-flow.source.secret_erasure.v1",
                    "property": "secret_erasure",
                    "level": "source",
                    "threat_model": "local adversary",
                    "leakage_model": "bounded source-level leakage model",
                    "quantification": "bounded_model",
                    "assumptions": [],
                    "claim_ceiling": "This source-level model does not establish binary behavior.",
                    "confidence_score": 0.95,
                },
                "values": [
                    {
                        "name": "secret_input",
                        "class": "secret",
                        "representation_class": "fixed_width",
                        "length_class": "fixed",
                    }
                ],
                "metadata": [
                    {
                        "name": "secret_input",
                        "class": "fixed_width",
                        "observable_flag": "control_flow",
                    }
                ],
                "trace_model": {
                    "observables_in_scope": ["branch"],
                    "explicit_exclusions": [],
                    "limitations": "no live timing measurement yet (Phase 12.2)",
                },
                "evidence": {
                    "fixed_iteration_count": False,
                    "no_leakage_detected": False,
                },
            },
            "scalar_score_forbidden",
        ),
        (
            "binary_without_witness",
            {
                "claim": {
                    "id": "frf-etp.information-flow.binary.constant_time.v1",
                    "property": "constant_time",
                    "level": "binary",
                    "threat_model": "local adversary",
                    "leakage_model": "bounded binary leakage model",
                    "quantification": "bounded_model",
                    "assumptions": [],
                    "claim_ceiling": "This binary-level claim is bound to the Phase 11.2 execution witness.",
                },
                "values": [
                    {
                        "name": "secret_input",
                        "class": "secret",
                        "representation_class": "fixed_width",
                        "length_class": "fixed",
                    }
                ],
                "metadata": [
                    {
                        "name": "secret_input",
                        "class": "fixed_width",
                        "observable_flag": "control_flow",
                    }
                ],
                "trace_model": {
                    "observables_in_scope": ["branch"],
                    "explicit_exclusions": [],
                    "limitations": "no live timing measurement yet (Phase 12.2)",
                },
                "evidence": {
                    "fixed_iteration_count": False,
                    "no_leakage_detected": False,
                },
            },
            "binary_claim_without_execution_path",
        ),
        (
            "witness_digest_mismatch",
            {
                "claim": {
                    "id": "frf-etp.information-flow.binary.constant_time.v1",
                    "property": "constant_time",
                    "level": "binary",
                    "threat_model": "local adversary",
                    "leakage_model": "bounded binary leakage model",
                    "quantification": "bounded_model",
                    "assumptions": [],
                    "claim_ceiling": "This binary-level claim is bound to the Phase 11.2 execution witness.",
                },
                "values": [
                    {
                        "name": "secret_input",
                        "class": "secret",
                        "representation_class": "fixed_width",
                        "length_class": "fixed",
                    }
                ],
                "metadata": [
                    {
                        "name": "secret_input",
                        "class": "fixed_width",
                        "observable_flag": "control_flow",
                    }
                ],
                "trace_model": {
                    "observables_in_scope": ["branch"],
                    "explicit_exclusions": [],
                    "limitations": "no live timing measurement yet (Phase 12.2)",
                },
                "evidence": {
                    "fixed_iteration_count": False,
                    "no_leakage_detected": False,
                    "authenticated_execution_path": {
                        "witness_schema": "frf-etp.execution-witness.v1",
                        "witness_sha256": "0" * 64,
                        "exe_sha256": "347b2d3a1ecd25c2087e71cd539c7f369c3fdb5ebf1ca1d5904465c42e140dd9",
                        "loader_closure_sha256": "a6608cde70139cb870874bd163a4d31a68595f5cab2dc982021321859431f926",
                        "executed_function": "witness_probe",
                        "branch_trace_digest": "a" * 64,
                    },
                },
            },
            "witness_digest_mismatch",
        ),
        (
            "universal_quantification",
            {
                "claim": {
                    "id": "frf-etp.information-flow.source.secret_erasure.v1",
                    "property": "secret_erasure",
                    "level": "source",
                    "threat_model": "local adversary",
                    "leakage_model": "bounded source-level leakage model",
                    "quantification": "universal_contextual",
                    "assumptions": [],
                    "claim_ceiling": "This source-level model does not establish binary behavior.",
                },
                "values": [
                    {
                        "name": "secret_input",
                        "class": "secret",
                        "representation_class": "fixed_width",
                        "length_class": "fixed",
                    }
                ],
                "metadata": [
                    {
                        "name": "secret_input",
                        "class": "fixed_width",
                        "observable_flag": "control_flow",
                    }
                ],
                "trace_model": {
                    "observables_in_scope": ["branch"],
                    "explicit_exclusions": [],
                    "limitations": "no live timing measurement yet (Phase 12.2)",
                },
                "evidence": {
                    "fixed_iteration_count": False,
                    "no_leakage_detected": False,
                },
            },
            "universal_quantification_refused",
        ),
    ]

    # Validate the valid model first.
    refusals = validate_model(valid_model)
    if refusals:
        codes = [r.code for r in refusals]
        raise SystemExit(f"self-test failed: valid model was refused: {codes}")

    # Validate each control and assert the expected refusal.
    for name, mutated, expected_code in controls:
        refusals = validate_model(mutated)
        codes = [r.code for r in refusals]
        if expected_code not in codes:
            raise SystemExit(
                f"self-test failed: control {name!r} expected {expected_code}, got {codes}"
            )

    # Write the accepted report for the valid model.
    claim_ceiling = valid_model["claim"]["claim_ceiling"]
    report = build_report(valid_model, [], claim_ceiling)
    print("self-test: PASS (valid model accepted, 9 mutated controls refused)")
    print(f"report schema: {report['schema']}")
    print(f"accepted: {report['accepted']}")
    print(f"refusal_count: {report['refusal_count']}")
    print(f"binary_behavior_not_established: {report['binary_behavior_not_established']}")
    print(f"claim_ceiling: {claim_ceiling}")

    if report_path:
        write_report(report, report_path)

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="ETP information-flow model validator")
    parser.add_argument("--model", help="Path to model JSON")
    parser.add_argument("--report", help="Path to write canonical report JSON")
    parser.add_argument("--self-test", action="store_true", help="Run self-test suite")
    args = parser.parse_args()

    try:
        if args.self_test:
            # Self-test: run the built-in valid model plus mutated controls.
            report = run_self_test(Path(args.report) if args.report else None)
            if args.report:
                print(f"report written: {args.report}")
            return 0

        if not args.model:
            print("ERROR: --model is required (unless --self-test)", file=sys.stderr)
            return 1

        model_path = Path(args.model)
        model = load_json(model_path)

        refusals = validate_model(model)

        claim_ceiling = ""
        if isinstance(model, dict) and isinstance(model.get("claim"), dict):
            ceiling = model["claim"].get("claim_ceiling")
            if isinstance(ceiling, str):
                claim_ceiling = ceiling

        report = build_report(model, refusals, claim_ceiling)

        if args.report:
            write_report(report, Path(args.report))

        if refusals:
            for r in refusals:
                print(f"REFUSED: {r.code}: {r.detail}", file=sys.stderr)
            print(f"report: {len(refusals)} refusal(s)", file=sys.stderr)
            return 1

        print(f"accepted: {report['schema']}")
        print(f"claim_ceiling: {claim_ceiling}")
        print(f"binary_behavior_not_established: {report['binary_behavior_not_established']}")
        return 0
    except Refusal as refusal:
        print(f"REFUSED: {refusal.code}: {refusal.detail}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
