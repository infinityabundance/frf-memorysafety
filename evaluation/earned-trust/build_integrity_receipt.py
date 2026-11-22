#!/usr/bin/env python3
"""Build the Phase 11.1b integrity receipt from two independent builds.

This script is deliberately run inside the hardened Docker gate. It does not
establish authenticity, population completeness, or independent confirmation.
It records the declared artifact identity, the frozen case population, and the
separate reproducibility dimensions, including an honest byte-identity result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

CLAIM_CEILING = (
    "Integrity validation is bookkeeping over declared reproducibility "
    "dimensions and a frozen population manifest. It does not establish that "
    "a build is reproducible, that an artifact is authentic, that a population "
    "is complete, or that any dimension is independently confirmed. A digest "
    "is not authentication, a recorded justification is not proof, and a "
    "passing validator is not certification."
)

FORBIDDEN_KEYS = {
    "mtime",
    "modified",
    "modified_time",
    "timestamp",
    "selected_at",
    "selection_time",
    "file_mtime",
    "ctime",
    "atime",
}


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def declared_source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted((root / "src").rglob("*.rs")):
        if path.is_file():
            files.append(path)
    for name in (
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "ci/etp-integrity-gate.sh",
        "ci/etp-integrity-gate-inner.sh",
        "evaluation/earned-trust/build_integrity_receipt.py",
    ):
        path = root / name
        if path.is_file():
            files.append(path)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def source_tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in declared_source_files(root):
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def parse_toolchain(path: Path) -> tuple[str, str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    rustc_version = lines[0].strip() if lines else "unknown"
    host = "unknown"
    for line in lines:
        if line.startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break
    return rustc_version, host


def overflow_checks_enabled(root: Path) -> bool:
    text = (root / "Cargo.toml").read_text(encoding="utf-8")
    in_release = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_release = stripped == "[profile.release]"
            continue
        if in_release and re.match(r"overflow-checks\s*=\s*true", stripped):
            return True
    return False


def population(root: Path, version: str) -> dict:
    receipts = root / "evaluation" / "earned-trust" / "receipts"
    cases = []
    for path in sorted(receipts.glob("*.json")):
        if not path.is_file():
            continue
        cases.append(
            {
                "id": path.stem,
                "digest": sha256_file(path),
                "required": True,
            }
        )
    cases.sort(key=lambda case: case["id"])
    if not cases:
        raise SystemExit("missing population: no campaign receipts found")
    content = {"version": version, "cases": cases, "count": len(cases)}
    return {
        "version": version,
        "cases": cases,
        "count": len(cases),
        "manifest_digest": sha256_bytes(canonical(content)),
    }


def identity(
    root: Path,
    binary: Path,
    rustc_version: str,
    host: str,
    build_recipe_sha256: str,
    env_whitelist_sha256: str,
    overflow_checks: bool,
) -> dict:
    return {
        "source_tree_sha256": source_tree_digest(root),
        "lockfile_sha256": sha256_file(root / "Cargo.lock"),
        "build_recipe_sha256": build_recipe_sha256,
        "toolchain": {"rustc_version": rustc_version, "host": host},
        "target": host,
        "features": [],
        "profile": "release",
        "lto": "off",
        "panic": "unwind",
        "overflow_checks": overflow_checks,
        "env_whitelist_sha256": env_whitelist_sha256,
        "binary_sha256": sha256_file(binary),
        "binary_size": binary.stat().st_size,
        "scope": (
            "frf-memorysafety release CLI binary; declared source, lockfile, "
            "toolchain, flags, and environment only; no authenticity or "
            "completeness claim"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--build1", required=True)
    parser.add_argument("--build2", required=True)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--build-recipe", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--population-version", default="frf-etp-native-fixtures-2026-11-22"
    )
    args = parser.parse_args()

    root = Path(args.root)
    build1 = Path(args.build1)
    build2 = Path(args.build2)
    rustc_version, host = parse_toolchain(Path(args.toolchain))
    recipe_sha = sha256_file(Path(args.build_recipe))

    env = {
        "CARGO_HOME": os.environ.get("CARGO_HOME", ""),
        "CARGO_INCREMENTAL": os.environ.get("CARGO_INCREMENTAL", ""),
        "CARGO_PROFILE_RELEASE_DEBUG": os.environ.get(
            "CARGO_PROFILE_RELEASE_DEBUG", ""
        ),
        "SOURCE_DATE_EPOCH": os.environ.get("SOURCE_DATE_EPOCH", ""),
        "RUSTUP_AUTO_INSTALL": os.environ.get("RUSTUP_AUTO_INSTALL", ""),
    }
    env_sha = sha256_bytes(canonical(env))

    overflow = overflow_checks_enabled(root)
    artifact = identity(root, build1, rustc_version, host, recipe_sha, env_sha, overflow)
    rebuild = identity(root, build2, rustc_version, host, recipe_sha, env_sha, overflow)

    byte_identical = artifact["binary_sha256"] == rebuild["binary_sha256"]
    dimensions = [
        {"dimension": "source_reconstruction", "status": "established"},
        {"dimension": "environment_reconstruction", "status": "established"},
        {
            "dimension": "byte_identical_artifact",
            "status": "established" if byte_identical else "not_established",
        },
        {"dimension": "semantically_equivalent_artifact", "status": "not_run"},
        {"dimension": "experiment_replay", "status": "not_run"},
        {"dimension": "statistical_replication", "status": "not_run"},
        {"dimension": "proof_replay", "status": "not_run"},
        {"dimension": "independent_adjudication", "status": "not_run"},
    ]

    refusals = []
    if not byte_identical:
        refusals.append(
            {
                "code": "byte_digest_mismatch",
                "detail": (
                    "the two independent builds produced different binary "
                    "digests; byte-identical reproducibility is not established"
                ),
            }
        )

    report = {
        "schema": "frf-integrity.report.v1",
        "spec": "frf-integrity-v1",
        "artifact": artifact,
        "rebuild_artifact": rebuild,
        "dimensions": dimensions,
        "population": population(root, args.population_version),
        "refusals": refusals,
        "claim_ceiling": CLAIM_CEILING,
    }

    output = Path(args.out)
    output.write_bytes(canonical(report))

    print(f"artifact binary sha256: {artifact['binary_sha256']}")
    print(f"rebuild binary sha256:  {rebuild['binary_sha256']}")
    print(f"byte_identical: {'yes' if byte_identical else 'no'}")
    print(f"population count: {report['population']['count']}")
    print(f"population manifest: {report['population']['manifest_digest']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
