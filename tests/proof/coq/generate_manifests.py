#!/usr/bin/env python3
"""Generate the canonical Phase 6.2 proof-manifest fixtures.

The manifests are strict ``ms-canonical-json-v1`` documents: sorted keys, no
insignificant whitespace, no trailing newline.  Every digest is recomputed from
the checked-in fixture bytes.  The Coq version must match the checker installed
by ``ci/proof-gate.sh``; pass it as the first argument when Debian's pin
changes.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[2]
SCHEMA = "frf-memorysafety.proof-manifest.v1"
SPEC = "frf-memorysafety-spec-v1"
DEFAULT_COQ_VERSION = "8.16.1"


def claim_ceiling() -> str:
    source = (REPO / "src" / "proof.rs").read_text(encoding="utf-8")
    match = re.search(
        r'pub const PROOF_CLAIM_CEILING: &str = "([^"]+)";', source
    )
    if match is None:
        raise SystemExit("cannot locate PROOF_CLAIM_CEILING")
    return match.group(1)


CEILING = claim_ceiling()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def proof_file(
    file_id: str,
    path: str,
    role: str,
    theorems: list[str],
    imports: list[str],
) -> dict:
    return {
        "id": file_id,
        "imports": imports,
        "language": "coq",
        "path": path,
        "role": role,
        "sha256": sha(ROOT / path),
        "theorems": theorems,
    }


def evidence(identifier: str, filename: str, kind: str, detail: str) -> dict:
    return {
        "detail": detail,
        "id": identifier,
        "kind": kind,
        "path": f"correspondence/{filename}",
        "sha256": sha(ROOT / "correspondence" / filename),
    }


def binding(
    *,
    wrapper_checked: bool = True,
    include_callback_transition: bool = True,
) -> dict:
    source_digest = sha(ROOT / "src" / "lib.rs")
    transitions = [
        {
            "description": "allocate and initialize",
            "evidence": "ev-lifecycle",
            "id": "t-create",
            "kind": "lifecycle",
        },
        {
            "description": "transfer ownership",
            "evidence": "ev-transfer",
            "id": "t-transfer",
            "kind": "transfer",
        },
        {
            "description": "release the transferred pointer",
            "evidence": "ev-free",
            "id": "t-free",
            "kind": "free",
        },
    ]
    evidence_entries = [
        evidence("ev-wrapper", "ev-wrapper.txt", "refinement", "checked wrapper"),
        evidence(
            "ev-lifecycle",
            "ev-lifecycle.txt",
            "transition_enumeration",
            "lifecycle",
        ),
        evidence(
            "ev-transfer", "ev-transfer.txt", "transition_enumeration", "transfer"
        ),
        evidence("ev-free", "ev-free.txt", "transition_enumeration", "free"),
    ]
    required = ["lifecycle", "transfer", "free"]
    if include_callback_transition:
        transitions.append(
            {
                "description": "reentrant callback may mutate live state",
                "evidence": "ev-callback",
                "id": "t-callback",
                "kind": "reentrant_callback",
            }
        )
        evidence_entries.append(
            evidence(
                "ev-callback",
                "ev-callback.txt",
                "transition_enumeration",
                "reentrant callback",
            )
        )
        required.append("reentrant_callback")
    return {
        "binding_evidence": [
            {
                "detail": "exact FFI declaration and wrapper call site",
                "path": "src/lib.rs",
                "sha256": source_digest,
                "symbol": "frf_foreign_create",
            },
            {
                "detail": "exact callback definition",
                "path": "src/lib.rs",
                "sha256": source_digest,
                "symbol": "frf_wrapper_callback",
            },
        ],
        "correspondence_evidence": evidence_entries,
        "required_transitions": required,
        "rust_symbols": [
            {
                "ffi": {
                    "declaration": 'extern "C" { pub fn frf_foreign_create(value: c_int) -> *mut c_int; }',
                    "wrapper_checked": wrapper_checked,
                    "wrapper_evidence": "ev-wrapper",
                    "wrapper_symbol": "frf_safe_create",
                },
                "kind": "ffi_declaration",
                "source_path": "src/lib.rs",
                "source_sha256": source_digest,
                "symbol": "frf_foreign_create",
            },
            {
                "kind": "callback",
                "source_path": "src/lib.rs",
                "source_sha256": source_digest,
                "symbol": "frf_wrapper_callback",
            },
        ],
        "source_inventory": None,
        "statement": "frf_safe_create refines the finite-domain support fixed-point theorem for every enumerated transition",
        "transitions": transitions,
    }


def manifest(
    *,
    version: str,
    run_id: str,
    proof_files: list[dict],
    closure_theorems: list[str],
    local_dependencies: list[dict],
    admission_theorems: list[dict],
    binding_entry: dict | None = None,
) -> dict:
    return {
        "admission": {
            "checker_kind": "coq",
            "checker_version": version,
            "classification": "accepted_within_scope",
            "exit_code": 0,
            "origin": "authentic_checker_run",
            "proof_digests": [
                {"file_id": item["id"], "sha256": item["sha256"]}
                for item in proof_files
            ],
            "theorems": admission_theorems,
        },
        "assumptions": [],
        "checker": {"executable": "coqc", "kind": "coq", "version": version},
        "claim_ceiling": CEILING,
        "closure": {
            "local_dependencies": local_dependencies,
            "stdlib_allowlist": ["Coq.Bool.*", "Coq.Init.*"],
            "theorems": closure_theorems,
        },
        "implementation_binding": binding_entry or binding(),
        "proof_files": proof_files,
        "provenance": {
            "detail": "live Coq run recorded by the Phase 6.2 proof adapter",
            "origin": "authentic_checker_run",
            "run_id": run_id,
        },
        "schema": SCHEMA,
        "scope": {
            "claim_ids": ["claim-support-fixed-point"],
            "finite_domain": "the four-state two-claim support lattice",
            "not_proved": [
                "universal Rust soundness",
                "native execution of the foreign implementation",
                "completeness of the declared dependency graph",
            ],
            "proved": "support_iterate reaches a fixed point after one step on the finite two-claim support lattice",
        },
        "spec": SPEC,
        "theorem": {
            "claim_ids": ["claim-support-fixed-point"],
            "name": "frf_support_fixed_point",
        },
    }


def write(name: str, value: dict) -> None:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    (ROOT / name).write_bytes(encoded.encode("utf-8"))


def main() -> None:
    version = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_COQ_VERSION
    model = proof_file(
        "model",
        "model.v",
        "dependency",
        ["support_step_idempotent"],
        ["Coq.Bool.Bool", "Coq.Init.Nat"],
    )
    approved = proof_file(
        "approved", "approved.v", "theorem", ["frf_support_fixed_point"], ["model"]
    )
    admitted = proof_file(
        "admitted", "admitted.v", "theorem", ["frf_support_fixed_point"], ["model"]
    )
    axiom = proof_file(
        "axiom", "axiom.v", "theorem", ["frf_support_fixed_point"], ["model"]
    )
    unrelated = proof_file(
        "unrelated",
        "unrelated.v",
        "support",
        ["frf_unrelated_arithmetic"],
        ["Coq.Init.Nat"],
    )
    closure = ["frf_support_fixed_point", "support_step_idempotent"]
    dependency = [
        {
            "depends_on": ["support_step_idempotent"],
            "theorem": "frf_support_fixed_point",
        }
    ]
    proved = [
        {"name": "frf_support_fixed_point", "status": "proved"},
        {"name": "support_step_idempotent", "status": "proved"},
    ]

    write(
        "manifest-approved.json",
        manifest(
            version=version,
            run_id="phase6.2-approved",
            proof_files=[model, approved],
            closure_theorems=closure,
            local_dependencies=dependency,
            admission_theorems=proved,
        ),
    )
    write(
        "manifest-admitted.json",
        manifest(
            version=version,
            run_id="phase6.2-admitted",
            proof_files=[model, admitted],
            closure_theorems=closure,
            local_dependencies=dependency,
            admission_theorems=proved,
        ),
    )
    write(
        "manifest-axiom.json",
        manifest(
            version=version,
            run_id="phase6.2-axiom",
            proof_files=[model, axiom],
            closure_theorems=closure,
            local_dependencies=dependency,
            admission_theorems=proved,
        ),
    )
    write(
        "manifest-unrelated.json",
        manifest(
            version=version,
            run_id="phase6.2-unrelated",
            proof_files=[model, approved, unrelated],
            closure_theorems=closure,
            local_dependencies=dependency,
            admission_theorems=[
                {"name": "frf_support_fixed_point", "status": "proved"},
                {"name": "frf_unrelated_arithmetic", "status": "proved"},
                {"name": "support_step_idempotent", "status": "proved"},
            ],
        ),
    )
    write(
        "manifest-unchecked.json",
        manifest(
            version=version,
            run_id="phase6.2-unchecked",
            proof_files=[model, approved],
            closure_theorems=closure,
            local_dependencies=dependency,
            admission_theorems=proved,
            binding_entry=binding(wrapper_checked=False),
        ),
    )
    write(
        "manifest-missing-transition.json",
        manifest(
            version=version,
            run_id="phase6.2-missing-transition",
            proof_files=[model, approved],
            closure_theorems=closure,
            local_dependencies=dependency,
            admission_theorems=proved,
            binding_entry=binding(include_callback_transition=False),
        ),
    )


if __name__ == "__main__":
    main()
