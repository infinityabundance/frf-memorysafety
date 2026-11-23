#!/usr/bin/env python3
"""Independent verifier for the Phase 11.1b integrity receipt.

This verifier is deliberately separate from the Rust implementation. It reads
the receipt, recomputes every digest that the receipt declares, checks the
frozen population against the committed campaign receipts, and rejects
tampering, dishonest dimension statuses, and forbidden timestamp selection.

It establishes only that the receipt is internally consistent with the supplied
bytes. It is not authentication, not an independent build venue, and not a
proof of reproducibility beyond the exact inputs supplied.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

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

DECLARED_SOURCE = [
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "ci/etp-integrity-gate.sh",
    "ci/etp-integrity-gate-inner.sh",
    "evaluation/earned-trust-1.2.0/build_integrity_receipt.py",
]


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


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> object:
    return json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates
    )


def check_forbidden(value: object, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_KEYS:
                raise ValueError(f"forbidden selection field at {path}.{key}")
            check_forbidden(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            check_forbidden(child, f"{path}[{index}]")


def declared_source_files(root: Path) -> list[Path]:
    files = sorted((root / "src").rglob("*.rs"))
    files = [path for path in files if path.is_file()]
    for name in DECLARED_SOURCE:
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


def expected_population(root: Path, version: str) -> dict:
    receipts = root / "evaluation" / "earned-trust-1.2.0" / "receipts"
    cases = [
        {"id": path.stem, "digest": sha256_file(path), "required": True}
        for path in sorted(receipts.glob("*.json"))
        if path.is_file()
    ]
    cases.sort(key=lambda case: case["id"])
    content = {"version": version, "cases": cases, "count": len(cases)}
    return {
        "version": version,
        "cases": cases,
        "count": len(cases),
        "manifest_digest": sha256_bytes(canonical(content)),
    }


class Refusal(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def verify(receipt_path: Path, root: Path, build1: Path, build2: Path,
           toolchain_path: Path, build_recipe: Path) -> None:
    receipt = load_json(receipt_path)
    require(isinstance(receipt, dict), "receipt must be a JSON object")
    check_forbidden(receipt)

    require(receipt.get("schema") == "frf-integrity.report.v1", "unsupported schema")
    require(receipt.get("spec") == "frf-integrity-v1", "unsupported spec")
    require(
        isinstance(receipt.get("claim_ceiling"), str)
        and receipt["claim_ceiling"].strip(),
        "missing claim ceiling",
    )

    artifact = receipt.get("artifact")
    rebuild = receipt.get("rebuild_artifact")
    require(isinstance(artifact, dict), "missing artifact identity")
    require(isinstance(rebuild, dict), "missing rebuild identity")

    require(sha256_file(build1) == artifact.get("binary_sha256"), "artifact binary digest mismatch")
    require(build1.stat().st_size == artifact.get("binary_size"), "artifact binary size mismatch")
    require(sha256_file(build2) == rebuild.get("binary_sha256"), "rebuild binary digest mismatch")
    require(build2.stat().st_size == rebuild.get("binary_size"), "rebuild binary size mismatch")

    require(source_tree_digest(root) == artifact.get("source_tree_sha256"), "source tree digest mismatch")
    require(sha256_file(root / "Cargo.lock") == artifact.get("lockfile_sha256"), "lockfile digest mismatch")
    require(sha256_file(build_recipe) == artifact.get("build_recipe_sha256"), "build recipe digest mismatch")

    rustc_version, host = parse_toolchain(toolchain_path)
    toolchain = artifact.get("toolchain", {})
    require(toolchain.get("rustc_version") == rustc_version, "toolchain version mismatch")
    require(toolchain.get("host") == host, "toolchain host mismatch")
    require(artifact.get("target") == host, "target mismatch")

    population = receipt.get("population")
    require(isinstance(population, dict), "missing population")
    expected = expected_population(root, population.get("version", ""))
    require(population == expected, "population manifest mismatch")

    dimensions = receipt.get("dimensions")
    require(isinstance(dimensions, list), "missing dimensions")
    seen = set()
    byte_status = None
    for assessment in dimensions:
        require(isinstance(assessment, dict), "invalid dimension assessment")
        dimension = assessment.get("dimension")
        status = assessment.get("status")
        require(dimension not in seen, f"duplicate dimension: {dimension}")
        seen.add(dimension)
        if dimension == "byte_identical_artifact":
            byte_status = status
        if dimension == "semantically_equivalent_artifact" and status == "established":
            justification = assessment.get("justification")
            require(
                isinstance(justification, str) and justification.strip(),
                "semantic equivalence requires a justification",
            )

    identical = artifact["binary_sha256"] == rebuild["binary_sha256"]
    if identical:
        require(
            byte_status == "established",
            "identical binaries must record byte_identical_artifact as established",
        )
    else:
        require(
            byte_status == "not_established",
            "differing binaries must record byte_identical_artifact as not_established",
        )

    require(
        all(assessment.get("status") != "not_run" or assessment.get("dimension") != "byte_identical_artifact"
            for assessment in dimensions),
        "byte identity cannot be not_run here",
    )


def self_test(root: Path, build1: Path, build2: Path, toolchain: Path,
              recipe: Path, receipt_path: Path) -> None:
    original = load_json(receipt_path)
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)

        def check_mutation(name: str, mutate) -> None:
            data = json.loads(json.dumps(original))
            mutate(data)
            candidate = work / f"{name}.json"
            candidate.write_bytes(canonical(data))
            try:
                verify(candidate, root, build1, build2, toolchain, recipe)
            except (Refusal, ValueError, KeyError, TypeError, AssertionError):
                return
            raise SystemExit(f"self-test failed: {name} was accepted")

        check_mutation(
            "binary_digest",
            lambda data: data["artifact"].__setitem__("binary_sha256", "0" * 64),
        )
        check_mutation(
            "population_case",
            lambda data: data["population"]["cases"][0].__setitem__("digest", "0" * 64),
        )
        check_mutation(
            "population_count",
            lambda data: data["population"].__setitem__("count", data["population"]["count"] + 1),
        )
        check_mutation(
            "manifest_digest",
            lambda data: data["population"].__setitem__("manifest_digest", "0" * 64),
        )
        current = next(
            item for item in original["dimensions"]
            if item["dimension"] == "byte_identical_artifact"
        )["status"]
        check_mutation(
            "byte_status",
            lambda data: next(
                item for item in data["dimensions"]
                if item["dimension"] == "byte_identical_artifact"
            ).__setitem__(
                "status",
                "not_established" if current == "established" else "established",
            ),
        )
        check_mutation(
            "forbidden_key",
            lambda data: data["population"].__setitem__("mtime", 1),
        )
        check_mutation(
            "missing_ceiling",
            lambda data: data.__setitem__("claim_ceiling", ""),
        )

        valid = work / "valid.json"
        valid.write_bytes(canonical(original))
        verify(valid, root, build1, build2, toolchain, recipe)
    print("self-test: PASS (7 corrupted controls refused)")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--build1", required=True)
    parser.add_argument("--build2", required=True)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--build-recipe", required=True)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    root = Path(args.root)
    receipt = Path(args.receipt)
    build1 = Path(args.build1)
    build2 = Path(args.build2)
    toolchain = Path(args.toolchain)
    recipe = Path(args.build_recipe)

    try:
        verify(receipt, root, build1, build2, toolchain, recipe)
    except (Refusal, ValueError, KeyError, TypeError) as error:
        print(f"REFUSED: {error}")
        return 1

    if args.self_test:
        try:
            self_test(root, build1, build2, toolchain, recipe, receipt)
        except (Refusal, ValueError, KeyError, TypeError) as error:
            print(f"REFUSED during self-test: {error}")
            return 1

    print("verified: receipt, artifact bytes, source tree, population, dimensions")
    print(f"binary sha256: {sha256_file(build1)}")
    print(f"population cases: {len(expected_population(root, 'frf-etp-native-fixtures-2026-11-22')['cases'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
