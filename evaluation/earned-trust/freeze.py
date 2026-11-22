#!/usr/bin/env python3
"""Generate the frozen ETP campaign opening inventory.

This helper was run once, before the committed campaign execution. It computes
the candidate and instrument file digests and the sorted tree digests, writes
``protocol.json``, and writes ``opening.sha256``. Re-running it after the
campaign would re-freeze a different protocol and would invalidate every
receipt recorded against the committed opening manifest.

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "evaluation/earned-trust"

FIXTURES = [
    "legal_transfer_free.c",
    "legal_transfer_free.rs",
    "use_after_free.c",
    "use_after_free.rs",
    "mutable_alias.c",
    "stale_generation.c",
    "sync_callback.c",
    "deferred_callback.c",
    "data_race.c",
    "atomic_control.c",
    "skipped_event.c",
    "nondeterministic.c",
    "oversized_output.c",
]

CANDIDATE_PATHS = [
    "Cargo.toml",
    "rust-toolchain.toml",
    "src/court.rs",
    "src/native.rs",
    "src/identity.rs",
] + [f"tests/native/fixtures/{name}" for name in FIXTURES]

INSTRUMENT_PATHS = [
    "Cargo.toml",
    "rust-toolchain.toml",
    "src/cli.rs",
    "src/court.rs",
    "src/etp_archive.rs",
    "src/etp_auth.rs",
    "src/etp_campaign.rs",
    "src/etp_revocation.rs",
    "src/etp_time.rs",
    "src/etp_transparency.rs",
    "src/etp_witness.rs",
    "src/identity.rs",
    "src/integrity.rs",
    "src/lib.rs",
    "src/main.rs",
    "src/native.rs",
    "src/sarif.rs",
]


def sha256_bytes(data: bytes) -> str:
    """Lowercase SHA-256 of exact bytes."""
    return hashlib.sha256(data).hexdigest()


def digest_file(relative: str) -> str:
    """Lowercase SHA-256 of one repository-relative file."""
    return sha256_bytes((ROOT / relative).read_bytes())


def tree_digest(files: list[dict[str, str]]) -> str:
    """Sorted path/NUL/digest/LF tree digest."""
    hasher = hashlib.sha256()
    for item in sorted(files, key=lambda value: value["path"].encode("utf-8")):
        hasher.update(item["path"].encode("utf-8"))
        hasher.update(b"\x00")
        hasher.update(item["sha256"].encode("ascii"))
        hasher.update(b"\n")
    return hasher.hexdigest()


def file_list(paths: list[str]) -> list[dict[str, str]]:
    """Declared file list with exact digests."""
    return [{"path": path, "sha256": digest_file(path)} for path in paths]


def build_cases() -> list[dict[str, object]]:
    """Build the closed 13-case population."""
    cases: list[dict[str, object]] = []
    fixtures = {
        "legal-transfer-free-c": "legal_transfer_free.c",
        "legal-transfer-free-rust": "legal_transfer_free.rs",
        "use-after-free-c": "use_after_free.c",
        "use-after-free-rust": "use_after_free.rs",
        "mutable-alias-c": "mutable_alias.c",
        "stale-generation-c": "stale_generation.c",
        "sync-callback-c": "sync_callback.c",
        "deferred-callback-c": "deferred_callback.c",
        "data-race-c": "data_race.c",
        "atomic-control-c": "atomic_control.c",
        "skipped-free-c": "skipped_event.c",
        "nondeterministic-c": "nondeterministic.c",
        "oversized-output-c": "oversized_output.c",
    }
    positive = [
        "legal-transfer-free-c",
        "legal-transfer-free-rust",
        "sync-callback-c",
        "atomic-control-c",
    ]
    violations = [
        "use-after-free-c",
        "use-after-free-rust",
        "mutable-alias-c",
        "stale-generation-c",
        "deferred-callback-c",
        "data-race-c",
    ]
    for case_id in positive:
        cases.append(
            {
                "id": case_id,
                "fixture": f"tests/native/fixtures/{fixtures[case_id]}",
                "category": "positive_control",
                "expected_outcome": "verified_compatible_within_transcript",
                "requirement": "R1",
                "obligations": ["O1", "O2", "O4"],
                "mandatory_resolution": True,
            }
        )
    for case_id in violations:
        cases.append(
            {
                "id": case_id,
                "fixture": f"tests/native/fixtures/{fixtures[case_id]}",
                "category": "violation_control",
                "expected_outcome": "observed_violation",
                "requirement": "R2",
                "obligations": ["O1", "O2", "O3", "O4"],
                "mandatory_resolution": False,
            }
        )
    cases.append(
        {
            "id": "skipped-free-c",
            "fixture": "tests/native/fixtures/skipped_event.c",
            "category": "incomplete_control",
            "expected_outcome": "incomplete_transcript",
            "requirement": "R3",
            "obligations": ["O1", "O2", "O3", "O4"],
            "mandatory_resolution": False,
        }
    )
    for case_id in ["nondeterministic-c", "oversized-output-c"]:
        cases.append(
            {
                "id": case_id,
                "fixture": f"tests/native/fixtures/{fixtures[case_id]}",
                "category": "unresolved_control",
                "expected_outcome": "unresolved",
                "requirement": "R4",
                "obligations": ["O1", "O2", "O4", "O5"],
                "mandatory_resolution": False,
            }
        )
    return cases


def main() -> int:
    """Write the frozen protocol and its digest sidecar."""
    candidate_files = file_list(CANDIDATE_PATHS)
    instrument_files = file_list(INSTRUMENT_PATHS)
    protocol = {
        "schema": "frf-etp.campaign-protocol.v1",
        "spec": "frf-etp-v1",
        "campaign_id": "frf-etp-native-fixtures-2026-11-22",
        "frozen": "2026-11-22",
        "scope": "One finite, pre-registered native campaign over the closed checked-in FRF-MemorySafety native fixture registry and the court verifier. The campaign is a single execution of 13 declared cases. It is not a population sample, a detector-sensitivity estimate, a memory-safety proof, or a deployment authorization.",
        "candidate": {
            "id": "frf-memorysafety-native-fixtures",
            "version": "1.1.0",
            "tree_sha256_algorithm": "sha256-sorted-path-nul-digest-lf-v1",
            "tree_sha256": tree_digest(candidate_files),
            "files": candidate_files,
        },
        "requirements": [
            {
                "id": "R1",
                "statement": "A legal fixture must record and replay an identical canonical transcript and verify cleanly within the transcript scope.",
            },
            {
                "id": "R2",
                "statement": "A violation fixture must produce a definite observed violation rather than a clean verdict.",
            },
            {
                "id": "R3",
                "statement": "An incomplete fixture must retain a missing-required-event finding rather than a clean verdict.",
            },
            {
                "id": "R4",
                "statement": "An unresolved fixture must retain an unresolved observation; unresolved is never mapped to a pass.",
            },
        ],
        "threat_model": "Accidental or silent modification of receipts, raw evidence, closure counts, candidate identity, instrument identity, source locations, suppression fields, or terminal outcomes. Excluded: an adversary who can rewrite the opening manifest, the protocol, every receipt, and the verifier together; signature forgery; transparency-log equivocation; toolchain compromise; and any inference from this finite campaign to a population.",
        "assumptions": [
            "The checked-in fixture registry, native harness, and court verifier are the instrument; the candidate and instrument trees overlap and that overlap is declared.",
            "The harness executes in the declared container environment with the declared compilers and resource caps.",
            "Candidate and instrument file digests bind the exact bytes used for the run.",
            "A digest is not authentication; the opening manifest is frozen only against accidental or silent change.",
            "Replay equality is a transcript-byte condition within the declared environment, not a proof of determinism beyond it.",
        ],
        "obligations": [
            {
                "id": "O1",
                "statement": "Record each declared native fixture through the closed harness under the declared resource envelope.",
                "blocking": True,
            },
            {
                "id": "O2",
                "statement": "Verify each recorded transcript with the court and retain the raw transcript and court report bytes.",
                "blocking": True,
            },
            {
                "id": "O3",
                "statement": "Retain every court finding without suppression, including observed violations and incomplete transcripts.",
                "blocking": True,
            },
            {
                "id": "O4",
                "statement": "Declare and reconcile the complete case population; no case may be missing, duplicated, unexpected, or truncated.",
                "blocking": True,
            },
            {
                "id": "O5",
                "statement": "Retain unresolved and NOT_RUN outcomes; neither is a pass and neither is silently converted into a clean result.",
                "blocking": True,
            },
        ],
        "population": build_cases(),
        "instrument": {
            "id": "frf-native-court-instrument-v1",
            "harness": "frf-native-fixture-harness",
            "court": "frf-memorysafety.court-verification.v1",
            "crate_version": "1.1.0",
            "required_tools": ["cc", "rustc", "prlimit", "ld"],
            "tree_sha256_algorithm": "sha256-sorted-path-nul-digest-lf-v1",
            "tree_sha256": tree_digest(instrument_files),
            "files": instrument_files,
        },
        "mutation_controls": [
            {
                "id": "M1",
                "description": "Delete a receipt for a case whose expected observation is a retained violation.",
                "expected": "refused as missing_receipt and closure blocked",
            },
            {
                "id": "M2",
                "description": "Remove a receipt and its closure reference while leaving the declared population intact.",
                "expected": "refused as truncated_population or missing_receipt",
            },
            {
                "id": "M3",
                "description": "Duplicate a receipt identity.",
                "expected": "refused as duplicate_receipt",
            },
            {
                "id": "M4",
                "description": "Change a closure summary count.",
                "expected": "refused as inconsistent_count",
            },
            {
                "id": "M5",
                "description": "Declare a suppression without justification, scope, owner, expiry, or invalidation.",
                "expected": "refused as unauthorized_suppression; a valid suppression remains a finding",
            },
            {
                "id": "M6",
                "description": "Strip a required observation, adjudication, or evidence field from a receipt.",
                "expected": "refused at parse time",
            },
            {
                "id": "M7",
                "description": "Replace a SARIF artifact location with an invented fixture path.",
                "expected": "refused as fabricated_location",
            },
            {
                "id": "M8",
                "description": "Substitute a different candidate identity in a receipt.",
                "expected": "refused as wrong_candidate",
            },
            {
                "id": "M9",
                "description": "Delete a raw transcript or court report named by a receipt.",
                "expected": "refused as missing_raw_evidence",
            },
        ],
        "permitted_exclusions": [],
        "resource_limits": {
            "memory_mb": 2048,
            "swap_mb": 2048,
            "pids_limit": 512,
            "cpus": 2,
            "nofile": 1024,
            "oom_score_adj": 500,
            "timeout_seconds": 1800,
        },
        "acceptance_policy": {
            "rule": "Closure is accepted only when every declared case has exactly one receipt, every observed terminal outcome equals its pre-registered outcome, every mandatory-resolution case resolves, no case is missing, duplicated, unexpected, or truncated, every retained finding is present without unauthorized suppression, and every receipt's raw evidence digest matches.",
            "expected_case_count": 13,
            "expected_receipt_count": 13,
            "expected_raw_evidence_count": 25,
            "expected_pass_count": 13,
            "expected_finding_count": 9,
            "require_raw_evidence": True,
            "require_replay_identical": True,
            "not_run_is_pass": False,
        },
        "completion_expectations": {
            "case_count": 13,
            "receipt_count": 13,
            "raw_evidence_count": 25,
            "closure_status": "closed",
            "acceptance": "accepted",
        },
        "claims": [
            {
                "id": "C1",
                "statement": "Every one of the 13 declared cases produced its pre-registered terminal outcome; all 13 receipts pass; no mandatory-resolution case is unresolved.",
            },
            {
                "id": "C2",
                "statement": "Every receipt is backed by its raw transcript and retained court report, and every raw evidence digest matches the receipt and closure manifest.",
            },
            {
                "id": "C3",
                "statement": "Closure counts are derived from the complete declared population; no case is missing, duplicated, unexpected, truncated, or suppressed.",
            },
        ],
        "unsupported_features": [
            "DSSE authenticated envelopes",
            "in-toto and SLSA attestations",
            "Sigstore signatures",
            "Rekor or C2SP transparency inclusion and consistency",
            "RFC 3161 trusted timestamps",
            "TUF update metadata",
            "authority of a GitHub code-scanning view",
            "population-level detector sensitivity, specificity, or defect recall",
            "memory-safety, functional-correctness, interoperability, constant-time, or deployment-security conclusions",
        ],
        "claim_ceiling": "Campaign closure is bookkeeping over a finite, pre-registered case population. It establishes that every declared case has one retained typed observation and that the declared counts were derived from the complete population. It does not establish memory safety, functional correctness, detector sensitivity, proof soundness, population-level recall, reviewer independence, authentication, transparency completeness, or deployment security. A typed NOT_RUN is not a pass. A digest is not authentication. A SARIF projection is not a certification and a code-scanning view is not authoritative.",
    }
    encoded = json.dumps(protocol, indent=2, sort_keys=True) + "\n"
    (OUT / "protocol.json").write_text(encoded, encoding="utf-8")
    digest = sha256_bytes(encoded.encode("utf-8"))
    (OUT / "opening.sha256").write_text(f"{digest}  protocol.json\n", encoding="utf-8")
    print(f"opening sha256: {digest}")
    print(f"candidate tree: {tree_digest(candidate_files)}")
    print(f"instrument tree: {tree_digest(instrument_files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
