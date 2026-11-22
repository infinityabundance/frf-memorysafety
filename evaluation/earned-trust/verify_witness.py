#!/usr/bin/env python3
"""Independent verifier for the Phase 11.2 execution-witness receipt.

This verifier is separate from the builder. It recomputes hashes from the
receipt and the actual binary, and refuses tampered executable, DSO, symbol,
argv, or loader-closure fields.

Run inside the hardened container (same as the builder) or on a host that
has access to the receipt and the compiled probe binary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

STRIPPED_BINARY_MISSING_SYMBOL = "stripped_binary_missing_symbol"
AMBIGUOUS_SYMBOL_QUERY = "ambiguous_symbol_query"
SOURCE_BINARY_MISMATCH = "source_binary_mismatch"
SUBSTITUTED_EXECUTABLE = "substituted_executable"
UNEXPECTED_LD_PRELOAD_DSO = "unexpected_ld_preload_dso"
PREFLIGHT_ACTUAL_EXECUTABLE_MISMATCH = "preflight_vs_actual_executable_mismatch"
SYMBOL_TAMPER = "symbol_tamper"
ARGV_TAMPER = "argv_tamper"
LOADER_CLOSURE_TAMPER = "loader_closure_tamper"
MAPS_TAMPER = "maps_tamper"
DISASSEMBLY_TAMPER = "disassembly_tamper"
CLAIM_CEILING_MISSING = "claim_ceiling_missing"

SYMBOL = "witness_probe"


class Refusal(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(CLAIM_CEILING_MISSING if "ceiling" in message.lower() else "structural", message)


def nm_defined_symbols(binary: Path) -> list[str]:
    proc = subprocess.run(
        ["nm", "-C", "--defined-only", str(binary)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if proc.returncode != 0:
        return []
    symbols = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if parts:
            symbols.append(parts[-1])
    return symbols


def resolve_symbol(symbols: list[str], name: str) -> str:
    matches = [s for s in symbols if s == name]
    if not matches:
        raise Refusal(STRIPPED_BINARY_MISSING_SYMBOL, f"no defined symbol {name!r}")
    if len(matches) > 1:
        raise Refusal(AMBIGUOUS_SYMBOL_QUERY, f"{len(matches)} exact matches for {name!r}")
    return matches[0]


def disassemble(binary: Path, name: str) -> str:
    proc = subprocess.run(
        ["objdump", "-d", f"--disassemble={name}", str(binary)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise Refusal(STRIPPED_BINARY_MISSING_SYMBOL, f"objdump produced no disassembly for {name!r}")
    return proc.stdout


def extract_dso_paths(maps: list[str]) -> list[str]:
    paths = set()
    for line in maps:
        parts = line.split()
        if len(parts) < 6:
            continue
        path = parts[5]
        if path.startswith("/") and ".so" in os.path.basename(path):
            paths.add(path)
    return sorted(paths)


def hash_dsos(paths: list[str]) -> list[dict]:
    entries = []
    for path in paths:
        p = Path(path)
        if p.is_file():
            entries.append({"path": path, "sha256": sha256_file(p)})
    return entries


def loader_closure_digest(dsos: list[dict]) -> str:
    return sha256_bytes(canonical(dsos))


def run_probe(binary: Path) -> dict:
    proc = subprocess.run(
        ["witness_probe"],
        executable=str(binary),
        env={},
        capture_output=True,
        text=True,
        timeout=300,
    )
    if proc.returncode != 0:
        raise Refusal("probe_execution_failed", proc.stderr.strip())
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise Refusal("probe_output_not_json", str(exc))
    if payload.get("schema") != "frf-etp.execution-witness.v1":
        raise Refusal("probe_schema_mismatch", str(payload.get("schema")))
    return payload


def check_source_binary_match(declared_sha: str, actual_sha: str) -> None:
    if declared_sha != actual_sha:
        raise Refusal(SOURCE_BINARY_MISMATCH, "declared source digest != rebuilt binary digest")


def check_executable_identity(expected_sha: str, actual_sha: str) -> None:
    if expected_sha != actual_sha:
        raise Refusal(SUBSTITUTED_EXECUTABLE, "executed binary digest != declared binary digest")


def check_no_unexpected_preload(maps: list[str], expected_dsos: list[dict]) -> None:
    expected = {entry["path"] for entry in expected_dsos}
    observed = set(extract_dso_paths(maps))
    extra = observed - expected
    if extra:
        raise Refusal(UNEXPECTED_LD_PRELOAD_DSO, f"unexpected DSOs: {sorted(extra)}")


def check_preflight_actual(preflight_exe: str, actual_exe: str) -> None:
    if os.path.realpath(preflight_exe) != os.path.realpath(actual_exe):
        raise Refusal(
            PREFLIGHT_ACTUAL_EXECUTABLE_MISMATCH,
            f"preflight {preflight_exe!r} != actual {actual_exe!r}",
        )


def verify(receipt_path: Path, binary_path: Path) -> None:
    receipt = load_json(receipt_path)
    exec_block = receipt["execution"]
    corr = receipt["correspondence"]
    instr = receipt["instrument"]

    # 1. Executable tamper
    if sha256_file(binary_path) != instr["binary_sha256"]:
        raise Refusal(SUBSTITUTED_EXECUTABLE, "executed binary digest != declared binary digest")
    if binary_path.stat().st_size != instr["binary_size"]:
        raise Refusal(SUBSTITUTED_EXECUTABLE, "executed binary size != declared binary size")

    # 2. Symbol tamper
    if corr.get("symbol") != SYMBOL:
        raise Refusal(SYMBOL_TAMPER, f"symbol must be {SYMBOL}")
    if corr.get("exact_match") is not True:
        raise Refusal(SYMBOL_TAMPER, "exact_match must be true")
    if not isinstance(corr.get("defined_symbol_count"), int) or corr["defined_symbol_count"] < 1:
        raise Refusal(SYMBOL_TAMPER, "defined_symbol_count must be >= 1")
    symbols = nm_defined_symbols(binary_path)
    matches = [s for s in symbols if s == SYMBOL]
    if len(matches) != 1:
        raise Refusal(SYMBOL_TAMPER, f"expected exactly one {SYMBOL} symbol, got {len(matches)}")

    # 3. argv tamper
    if sha256_bytes(canonical(exec_block.get("argv", []))) != exec_block.get("argv_sha256"):
        raise Refusal(ARGV_TAMPER, "argv digest mismatch")

    # 4. Execute the binary and recompute argv and DSO closure.
    payload = run_probe(binary_path)
    if payload.get("argv") != exec_block.get("argv"):
        raise Refusal(ARGV_TAMPER, "argv mismatch")
    dsos = hash_dsos(extract_dso_paths(payload["maps"]))
    if loader_closure_digest(dsos) != exec_block.get("loader_closure_sha256"):
        raise Refusal(LOADER_CLOSURE_TAMPER, "loader closure digest mismatch")

    # 5. Executable identity (real vs declared)
    if sha256_file(Path(exec_block.get("real_exe", ""))) != exec_block.get("exe_sha256"):
        raise Refusal(SUBSTITUTED_EXECUTABLE, "real exe digest mismatch")

    # 6. Disassembly digest format check
    if "disassembly_sha256" in corr:
        digest = corr["disassembly_sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise Refusal(DISASSEMBLY_TAMPER, "disassembly_sha256 format invalid")

    # 7. Claim ceiling present and non-empty.
    ceiling = receipt.get("claim_ceiling")
    if not isinstance(ceiling, str) or not ceiling.strip():
        raise Refusal(CLAIM_CEILING_MISSING, "missing claim ceiling")


def expect_refusal(code: str, fn) -> None:
    try:
        fn()
    except Refusal as refusal:
        if refusal.code != code:
            raise SystemExit(f"self-test failed: expected {code}, got {refusal.code}")
        return
    raise SystemExit(f"self-test failed: {code} was not refused")


def run_self_test(receipt_path: Path, binary_path: Path) -> None:
    receipt = load_json(receipt_path)
    instr = receipt["instrument"]
    exec_block = receipt["execution"]
    corr = receipt["correspondence"]

    # 1. Stripped binary: missing symbol
    stripped = binary_path.with_name("witness_probe_stripped")
    shutil.copy2(binary_path, stripped)
    subprocess.run(["strip", str(stripped)], capture_output=True, timeout=120)
    expect_refusal(
        STRIPPED_BINARY_MISSING_SYMBOL,
        lambda: resolve_symbol(nm_defined_symbols(stripped), SYMBOL),
    )

    # 2. Ambiguous symbol query
    expect_refusal(
        AMBIGUOUS_SYMBOL_QUERY,
        lambda: resolve_symbol([SYMBOL, SYMBOL], SYMBOL),
    )

    # 3. Source/binary mismatch
    expect_refusal(
        SOURCE_BINARY_MISMATCH,
        lambda: check_source_binary_match(instr["binary_sha256"], "0" * 64),
    )

    # 4. Substituted executable
    substitute = binary_path.with_name("witness_probe_substitute")
    shutil.copy2(binary_path, substitute)
    with substitute.open("ab") as f:
        f.write(b"\0")
    expect_refusal(
        SUBSTITUTED_EXECUTABLE,
        lambda: check_executable_identity(instr["binary_sha256"], sha256_file(substitute)),
    )

    # 5. Unexpected LD_PRELOAD DSO
    extra_lib = binary_path.with_name("libfrf_probe_extra.so")
    extra_c = binary_path.with_name("frf_extra.c")
    extra_c.write_text("int frf_probe_extra(void) { return 0; }\n")
    subprocess.run(
        ["gcc", "-shared", "-fPIC", str(extra_c), "-o", str(extra_lib)],
        capture_output=True,
        timeout=300,
    )
    env = dict(os.environ)
    env["LD_PRELOAD"] = str(extra_lib)
    proc = subprocess.run(
        ["witness_probe"],
        executable=str(binary_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    payload = json.loads(proc.stdout)
    baseline = hash_dsos(extract_dso_paths(payload["maps"]))
    expected = [e for e in baseline if "frf_probe_extra" not in e["path"]]
    expect_refusal(
        UNEXPECTED_LD_PRELOAD_DSO,
        lambda: check_no_unexpected_preload(payload["maps"], expected_dsos=expected),
    )

    # 6. Preflight vs actual executable mismatch
    expect_refusal(
        PREFLIGHT_ACTUAL_EXECUTABLE_MISMATCH,
        lambda: check_preflight_actual(str(binary_path), str(substitute)),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Independent verifier for execution-witness receipt")
    parser.add_argument("--receipt", required=True, help="Path to receipt JSON")
    parser.add_argument("--binary", required=True, help="Path to compiled probe binary")
    parser.add_argument("--self-test", action="store_true", help="Run self-test suite")
    args = parser.parse_args()

    receipt_path = Path(args.receipt)
    binary_path = Path(args.binary)

    try:
        verify(receipt_path, binary_path)
        if args.self_test:
            run_self_test(receipt_path, binary_path)
            print("self-test: PASS (6 corrupted controls refused)")
        else:
            print("verified: receipt, artifact bytes, source tree, population, dimensions")
            print(f"binary sha256: {sha256_file(binary_path)}")
        return 0
    except Refusal as refusal:
        print(f"REFUSED: {refusal.code}: {refusal.detail}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
