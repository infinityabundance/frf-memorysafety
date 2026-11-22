#!/usr/bin/env python3
"""Phase 11.2 external execution witness (Python stdlib only).

This script is an external ETP instrument. It does not change any Rust source
and does not invalidate the frozen 13-case campaign.

It:

1. compiles ``tests/fixtures/witness/probe.c`` with ``gcc -O0 -g -fno-inline``
   into a private 0700 temporary directory, and records gcc/ld/rustc versions
   and the source/binary SHA-256;
2. performs source-to-binary correspondence with ``nm -C --defined-only`` for
   an exact ``witness_probe`` match and ``objdump -d --disassemble=witness_probe``,
   recording the exact-match status and the disassembly digest. Ambiguous or
   missing symbols are refused, never guessed;
3. executes the probe with a cleared environment and a fixed argv, captures the
   real ``/proc/self/exe``, argv, and ``/proc/self/maps``, hashes every loaded
   regular-file DSO, and records the loader-closure digest and
   ``authentic_native`` provenance;
4. writes a canonical JSON receipt ``frf-etp.execution-witness.v1`` with a
   claim ceiling and limitations;
5. with ``--self-test``, refuses six named refusal codes.

Run inside the hardened container started by ``ci/etp-witness-gate.sh``.
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

# ---------------------------------------------------------------------------
# Named refusal codes (stable identifiers, never free-form guesses).
# ---------------------------------------------------------------------------
STRIPPED_BINARY_MISSING_SYMBOL = "stripped_binary_missing_symbol"
AMBIGUOUS_SYMBOL_QUERY = "ambiguous_symbol_query"
SOURCE_BINARY_MISMATCH = "source_binary_mismatch"
SUBSTITUTED_EXECUTABLE = "substituted_executable"
UNEXPECTED_LD_PRELOAD_DSO = "unexpected_ld_preload_dso"
PREFLIGHT_ACTUAL_EXECUTABLE_MISMATCH = "preflight_vs_actual_executable_mismatch"

SYMBOL = "witness_probe"

DECLARED_WITNESS_FILES = [
    "tests/fixtures/witness/probe.c",
    "evaluation/earned-trust/witness_execution.py",
    "ci/etp-witness-gate.sh",
]


class Refusal(Exception):
    """A typed refusal with a stable code."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Hashing and canonical JSON helpers.
# ---------------------------------------------------------------------------
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Source-tree digest over declared witness inputs plus the crate source.
# ---------------------------------------------------------------------------
def declared_source_files(root: Path) -> list[Path]:
    files = sorted(p for p in (root / "src").rglob("*.rs") if p.is_file())
    for name in (
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        *DECLARED_WITNESS_FILES,
    ):
        path = root / name
        if path.is_file():
            files.append(path)
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def source_tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in declared_source_files(root):
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Toolchain parsing.
# ---------------------------------------------------------------------------
def parse_toolchain(path: Path) -> tuple[str, str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    rustc_version = lines[0].strip() if lines else "unknown"
    host = "unknown"
    for line in lines:
        if line.startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break
    return rustc_version, host


def first_line(command: list[str]) -> str:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    if proc.returncode != 0:
        return "unavailable"
    return proc.stdout.splitlines()[0].strip() if proc.stdout else "unavailable"


# ---------------------------------------------------------------------------
# Compilation.
# ---------------------------------------------------------------------------
def compile_probe(source: Path, out_dir: Path) -> tuple[Path, list[str]]:
    binary = out_dir / "witness_probe"
    command = ["gcc", "-O0", "-g", "-fno-inline", str(source), "-o", str(binary)]
    proc = subprocess.run(command, capture_output=True, text=True, timeout=1800)
    if proc.returncode != 0:
        raise Refusal("probe_compilation_failed", proc.stderr.strip())
    return binary, command


# ---------------------------------------------------------------------------
# Symbol resolution. Refuses on missing or ambiguous exact matches.
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Execution and DSO hashing.
# ---------------------------------------------------------------------------
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


def normalized_maps_digest(maps: list[str]) -> str:
    """Hash the stable shape of the maps: permissions and pathname only.

    Raw maps contain ASLR-dependent addresses, offsets, and inode numbers.
    Those are observation-specific and must not be treated as a reproducible
    identity. The normalized digest is stable for a fixed executable and
    loader closure.
    """
    normalized = []
    for line in maps:
        parts = line.split()
        permissions = parts[1] if len(parts) > 1 else ""
        pathname = parts[5] if len(parts) >= 6 else ""
        normalized.append({"permissions": permissions, "pathname": pathname})
    return sha256_bytes(canonical(normalized))


def loader_closure_digest(dsos: list[dict]) -> str:
    return sha256_bytes(canonical(dsos))


def run_probe(binary: Path) -> dict:
    # Cleared environment, fixed argv[0] independent of the on-disk path.
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


# ---------------------------------------------------------------------------
# Refusal predicates used by both the main path and the self-test.
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Receipt construction.
# ---------------------------------------------------------------------------
def build_receipt(root: Path, work: Path, toolchain: Path, recipe: Path, binary_out: Path | None = None) -> dict:
    probe_src = root / "tests/fixtures/witness/probe.c"
    binary, compile_command = compile_probe(probe_src, work)

    # Use binary_out for execution if provided, otherwise use the compiled binary.
    exec_binary = binary_out if binary_out else binary
    if binary_out:
        shutil.copy2(binary, binary_out)
        exec_binary = binary_out

    gcc_version = first_line(["gcc", "--version"])
    ld_version = first_line(["ld", "--version"])
    rustc_version, host = parse_toolchain(toolchain)

    symbols = nm_defined_symbols(binary)
    resolve_symbol(symbols, SYMBOL)  # refuses missing/ambiguous
    disasm = disassemble(binary, SYMBOL)

    payload = run_probe(exec_binary)
    real_exe = payload["exe"]
    argv = payload["argv"]
    maps = payload["maps"]

    dsos = hash_dsos(extract_dso_paths(maps))
    closure = loader_closure_digest(dsos)

    # Preflight vs actual executable: the preflight path is the compiled binary;
    # the actual path is what the kernel reports through /proc/self/exe.
    check_preflight_actual(str(exec_binary), real_exe)
    # The executed bytes must equal the declared bytes.
    check_executable_identity(sha256_file(binary), sha256_file(Path(real_exe)))

    return {
        "schema": "frf-etp.execution-witness.v1",
        "spec": "frf-etp-execution-witness-v1",
        "claim_ceiling": (
            "This receipt records an observed execution of one fixture on one "
            "host inside one hardened container. It does not establish "
            "authenticity, completeness, correctness, or deployment behaviour, "
            "and it does not prove the crate binary, all DSOs, or all processes."
        ),
        "limitations": [
            "authentic_native is declared provenance, not authentication",
            "a digest binds exact bytes; it is not a signature or trusted timestamp",
            "the loader closure covers only the DSOs mapped by this one probe",
            "same-host, same-container, same-toolchain observation only",
            "no external witness, transparency log, or independent build venue",
        ],
        "instrument": {
            "probe_source": "tests/fixtures/witness/probe.c",
            "probe_source_sha256": sha256_file(probe_src),
            "compile_command": compile_command,
            "gcc_version": gcc_version,
            "ld_version": ld_version,
            "rustc_version": rustc_version,
            "host": host,
            "binary_sha256": sha256_file(binary),
            "binary_size": binary.stat().st_size,
            "source_tree_sha256": source_tree_digest(root),
            "lockfile_sha256": sha256_file(root / "Cargo.lock"),
            "build_recipe_sha256": sha256_file(recipe),
        },
        "correspondence": {
            "symbol": SYMBOL,
            "nm_command": ["nm", "-C", "--defined-only", str(binary)],
            "defined_symbol_count": len(symbols),
            "exact_match": True,
            "objdump_command": ["objdump", "-d", f"--disassemble={SYMBOL}", str(binary)],
            "disassembly_sha256": sha256_bytes(disasm.encode("utf-8")),
            "disassembly_size": len(disasm.encode("utf-8")),
        },
        "execution": {
            "argv": argv,
            "argv_sha256": sha256_bytes(canonical(argv)),
            "cleared_environment": True,
            "real_exe": real_exe,
            "exe_sha256": sha256_file(Path(real_exe)),
            "maps_sha256": normalized_maps_digest(maps),
            "maps_line_count": len(maps),
            "loaded_dsos": dsos,
            "loader_closure_sha256": closure,
            "authentic_native": True,
            "authentic_native_note": "declared native execution; not authentication",
            "exit_code": 0,
        },
        "toolchain": {"rustc_version": rustc_version, "host": host},
        "dimensions": [
            {"dimension": "source_reconstruction", "status": "established"},
            {"dimension": "environment_reconstruction", "status": "established"},
            {"dimension": "byte_identical_artifact", "status": "not_run"},
            {"dimension": "semantically_equivalent_artifact", "status": "not_established"},
            {"dimension": "experiment_replay", "status": "not_run"},
            {"dimension": "statistical_replication", "status": "not_run"},
            {"dimension": "proof_replay", "status": "not_run"},
            {"dimension": "independent_adjudication", "status": "not_run"},
        ],
    }


# ---------------------------------------------------------------------------
# Self-test: six named refusal controls.
# ---------------------------------------------------------------------------
def expect_refusal(code: str, fn) -> None:
    try:
        fn()
    except Refusal as refusal:
        if refusal.code != code:
            raise SystemExit(
                f"self-test failed: expected {code}, got {refusal.code}"
            )
        return
    raise SystemExit(f"self-test failed: {code} was not refused")


def run_self_test(root: Path, work: Path) -> None:
    probe_src = root / "tests/fixtures/witness/probe.c"
    binary, _ = compile_probe(probe_src, work)
    declared_sha = sha256_file(binary)

    # 1. Stripped binary: missing symbol.
    stripped = work / "witness_probe_stripped"
    shutil.copy2(binary, stripped)
    subprocess.run(["strip", str(stripped)], capture_output=True, timeout=120)
    expect_refusal(
        STRIPPED_BINARY_MISSING_SYMBOL,
        lambda: resolve_symbol(nm_defined_symbols(stripped), SYMBOL),
    )

    # 2. Ambiguous symbol query: two exact matches in a crafted symbol list.
    expect_refusal(
        AMBIGUOUS_SYMBOL_QUERY,
        lambda: resolve_symbol([SYMBOL, SYMBOL], SYMBOL),
    )

    # 3. Source/binary mismatch: a different source digest.
    expect_refusal(
        SOURCE_BINARY_MISMATCH,
        lambda: check_source_binary_match(declared_sha, "0" * 64),
    )

    # 4. Substituted executable: a different binary digest.
    substitute = work / "witness_probe_substitute"
    shutil.copy2(binary, substitute)
    with substitute.open("ab") as handle:
        handle.write(b"\0")
    expect_refusal(
        SUBSTITUTED_EXECUTABLE,
        lambda: check_executable_identity(declared_sha, sha256_file(substitute)),
    )

    # 5. Unexpected LD_PRELOAD DSO: run with LD_PRELOAD of a synthetic library
    #    that is not part of the baseline closure, and detect the extra DSO.
    extra_lib = work / "libfrf_probe_extra.so"
    extra_c = work / "frf_extra.c"
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
        executable=str(binary),
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

    # 6. Preflight-vs-actual executable mismatch.
    expect_refusal(
        PREFLIGHT_ACTUAL_EXECUTABLE_MISMATCH,
        lambda: check_preflight_actual(str(binary), str(substitute)),
    )

    print("self-test: PASS (6 corrupted controls refused)")


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 11.2 execution witness")
    parser.add_argument("--receipt", required=True, help="Receipt output path")
    parser.add_argument("--root", required=True, help="Project root (mounted read-only)")
    parser.add_argument("--toolchain", required=True, help="rustc -vV output file")
    parser.add_argument("--build-recipe", required=True, help="Build recipe file")
    parser.add_argument("--binary-out", default=None, help="Optional path to persist the compiled probe")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    receipt_path = Path(args.receipt)
    toolchain = Path(args.toolchain)
    recipe = Path(args.build_recipe)

    work = Path("/tmp/frf-witness")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    os.chmod(work, 0o700)
    try:
        print("DEBUG: before build_receipt", file=sys.stderr)
        receipt = build_receipt(root, work, toolchain, recipe, args.binary_out)
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_bytes(canonical(receipt) + b"\n")

        if args.binary_out:
            shutil.copy2(work / "witness_probe", args.binary_out)

        exec_block = receipt["execution"]
        print(f"receipt: {receipt_path}")
        print(f"binary sha256: {receipt['instrument']['binary_sha256']}")
        print(f"disassembly sha256: {receipt['correspondence']['disassembly_sha256']}")
        print(f"loader closure sha256: {exec_block['loader_closure_sha256']}")
        print(f"loaded DSOs: {len(exec_block['loaded_dsos'])}")
        print(f"real exe: {exec_block['real_exe']}")
        return 0
    except Refusal as refusal:
        print(f"REFUSED: {refusal.code}: {refusal.detail}", file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())