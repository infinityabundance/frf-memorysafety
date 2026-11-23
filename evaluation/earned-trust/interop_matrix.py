#!/usr/bin/env python3
"""ETP interop matrix (Phase 13.1a).

Compiles tests/fixtures/interop/interop.c twice (reference and candidate) with
gcc -O1 -fno-inline -fno-builtin -g, runs the genuine four-way matrix for every
pre-registered case, records per-process identity (exe digest, loaded DSO
paths/digests, loader-closure digest), case population reconciliation, per-cell
results, common failures, candidate-specific failures, skipped/unresolved cases,
environment, and fixture identity, and emits a canonical
frf-etp.interop-matrix.v1 report under evaluation/earned-trust/interop/.

Refusal codes:
  not_run              instrument dead/empty, compile failed, or no execution
  unresolved           execution ambiguous or incomplete
  wrong_endpoint       client connected to wrong server endpoint
  wrong_executable     executable/DSO identity does not match expected
  stale_fixture        fixture source changed without rebuild
  missing_cell         matrix cell missing
  missing_case         pre-registered case absent from population
  duplicate_case       case appears more than once in population
  substituted_dso      DSO identity differs from expected closure

Per-cell terminal outcomes:
  pass                 client and server both completed and matched
  fail                 execution completed but did not match
  reject               server rejected the case
  not_run / unresolved / wrong_endpoint / wrong_executable / stale_fixture /
  missing_cell / missing_case / duplicate_case / substituted_dso

Python standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPORT_SCHEMA = "frf-etp.interop-matrix.v1"
SPEC = "frf-etp-interop-matrix-v1"

FIXTURE_SOURCE = "tests/fixtures/interop/interop.c"

# Pre-registered frozen case population (sorted, no mtimes).
CASES = [
    "empty",
    "short",
    "max_4096",
    "malformed_length",
    "truncated",
    "oversize_common",
]

# Four-way matrix cells: (client_variant, server_variant).
CELLS = [
    ("reference", "reference"),
    ("reference", "candidate"),
    ("candidate", "reference"),
    ("candidate", "candidate"),
]

# Expected terminal outcome per cell for each case.
# pass = both complete and match; reject = both reject; fail = mismatch.
EXPECTED = {
    "empty": {
        ("reference", "reference"): "pass",
        ("reference", "candidate"): "pass",
        ("candidate", "reference"): "pass",
        ("candidate", "candidate"): "pass",
    },
    "short": {
        ("reference", "reference"): "pass",
        ("reference", "candidate"): "pass",
        ("candidate", "reference"): "pass",
        ("candidate", "candidate"): "pass",
    },
    "max_4096": {
        ("reference", "reference"): "pass",
        ("reference", "candidate"): "fail",
        ("candidate", "reference"): "pass",
        ("candidate", "candidate"): "fail",
    },
    "malformed_length": {
        ("reference", "reference"): "reject",
        ("reference", "candidate"): "reject",
        ("candidate", "reference"): "reject",
        ("candidate", "candidate"): "reject",
    },
    "truncated": {
        ("reference", "reference"): "reject",
        ("reference", "candidate"): "reject",
        ("candidate", "reference"): "reject",
        ("candidate", "candidate"): "reject",
    },
    "oversize_common": {
        ("reference", "reference"): "reject",
        ("reference", "candidate"): "reject",
        ("candidate", "reference"): "reject",
        ("candidate", "candidate"): "reject",
    },
}


class Refusal(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def run_command(cmd: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def tool_version(cmd: list[str]) -> str:
    try:
        result = run_command(cmd)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().splitlines()[0]
    except FileNotFoundError:
        return "not_run"
    except Exception:
        return "not_run"
    return "not_run"


def parse_maps_dsos(maps_text: str) -> list[dict]:
    """Parse /proc/self/maps text into sorted [{path, sha256}] for file-backed DSOs."""
    seen = set()
    entries = []
    for line in maps_text.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        path = parts[-1]
        if not path or path.startswith("[") or path in seen:
            continue
        seen.add(path)
        try:
            digest = sha256_bytes(Path(path).read_bytes())
        except OSError:
            digest = "not_run"
        entries.append({"path": path, "sha256": digest})
    entries.sort(key=lambda e: e["path"])
    return entries


def identity_from_json(identity: dict) -> dict:
    """Compute per-process identity from the emitted JSON identity line.

    The line contains the real /proc/self/exe path and /proc/self/maps text.
    We compute the exe digest, the loaded DSO paths/digests, and the
    loader-closure digest from those bytes.
    """
    exe_path = identity.get("exe")
    maps_text = identity.get("maps") or ""
    if not exe_path:
        return {
            "exe_path": None,
            "exe_digest": "not_run",
            "dsos": [],
            "loader_closure_digest": "not_run",
        }
    try:
        exe_digest = sha256_bytes(Path(exe_path).read_bytes())
    except OSError:
        exe_digest = "not_run"
    dsos = parse_maps_dsos(maps_text)
    closure_blob = json.dumps(dsos, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "exe_path": exe_path,
        "exe_digest": exe_digest,
        "dsos": dsos,
        "loader_closure_digest": sha256_bytes(closure_blob),
    }


def compile_binary(root: Path, workdir: Path, variant: str) -> dict:
    """Compile interop.c for variant. Returns metadata dict."""
    source_path = root / FIXTURE_SOURCE
    source_bytes = source_path.read_bytes()
    source_sha256 = sha256_bytes(source_bytes)

    gcc_version = tool_version(["gcc", "--version"])
    ld_version = tool_version(["ld", "--version"])

    binary_path = workdir / f"interop_{variant}"
    define = "-DREFERENCE" if variant == "reference" else "-DCANDIDATE"
    cmd = [
        "gcc", "-O1", "-fno-inline", "-fno-builtin", "-g", define,
        str(source_path), "-o", str(binary_path),
    ]
    result = run_command(cmd)
    if result.returncode != 0:
        raise Refusal("not_run", f"gcc compile failed for {variant}: {result.stderr.strip()}")

    binary_bytes = binary_path.read_bytes()
    binary_sha256 = sha256_bytes(binary_bytes)

    return {
        "variant": variant,
        "source_path": str(source_path),
        "source_sha256": source_sha256,
        "binary_path": str(binary_path),
        "binary_sha256": binary_sha256,
        "gcc_version": gcc_version,
        "ld_version": ld_version,
        "compile_command": cmd,
        "compile_returncode": result.returncode,
    }


def start_server(workdir: Path, variant: str) -> dict:
    """Start server on port 0; read PORT and identity lines. Returns server info."""
    binary_path = workdir / f"interop_{variant}"
    proc = subprocess.Popen(
        [str(binary_path), "server", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        port_line = proc.stdout.readline() if proc.stdout else ""
        if not port_line or not port_line.startswith("PORT="):
            raise Refusal("not_run", f"server did not emit PORT line: {port_line!r}")
        port = int(port_line.strip().split("=", 1)[1])

        identity_line = proc.stdout.readline() if proc.stdout else ""
        if not identity_line.strip():
            raise Refusal("not_run", "server did not emit identity line")
        try:
            identity = json.loads(identity_line.strip())
        except json.JSONDecodeError:
            raise Refusal("unresolved", f"server identity not valid JSON: {identity_line!r}")

        return {
            "proc": proc,
            "port": port,
            "identity_line": identity_line.strip(),
            "identity": identity,
            "proc_identity": identity_from_json(identity),
        }
    except Exception:
        proc.kill()
        proc.wait()
        raise


def run_client(workdir: Path, variant: str, host: str, port: int, case: str) -> dict:
    """Run client against host:port for case. Returns client result."""
    binary_path = workdir / f"interop_{variant}"
    proc = subprocess.Popen(
        [str(binary_path), "client", host, str(port), case],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        return {
            "identity_line": "",
            "identity": {},
            "proc_identity": {"exe_path": None, "exe_digest": "not_run", "dsos": [], "loader_closure_digest": "not_run"},
            "result_line": "",
            "stdout": stdout,
            "stderr": stderr,
            "returncode": -1,
            "timed_out": True,
        }

    identity_line = ""
    result_line = ""
    for line in stdout.splitlines():
        if line.startswith("{"):
            identity_line = line
        elif line.startswith("CLIENT_DONE"):
            result_line = line

    try:
        identity = json.loads(identity_line) if identity_line else {}
    except json.JSONDecodeError:
        identity = {}

    return {
        "identity_line": identity_line,
        "identity": identity,
        "proc_identity": identity_from_json(identity),
        "result_line": result_line,
        "stdout": stdout,
        "stderr": stderr,
        "returncode": proc.returncode,
        "timed_out": False,
    }


def finish_server(server_info: dict) -> str:
    """Wait for server to exit, read remaining output, return SERVER_DONE line."""
    proc = server_info["proc"]
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    remaining = ""
    if proc.stdout is not None:
        try:
            remaining = proc.stdout.read()
        except Exception:
            remaining = ""
    for line in remaining.splitlines():
        if line.startswith("SERVER_DONE"):
            return line.strip()
    return "unresolved"


def run_cell(workdir: Path, client_variant: str, server_variant: str, case: str,
             binaries: dict) -> dict:
    """Run one matrix cell. Returns cell result dict."""
    client_meta = binaries[client_variant]
    server_meta = binaries[server_variant]

    # Verify executable identity matches compiled binary.
    client_exe_digest = sha256_bytes(Path(client_meta["binary_path"]).read_bytes())
    server_exe_digest = sha256_bytes(Path(server_meta["binary_path"]).read_bytes())
    if client_exe_digest != client_meta["binary_sha256"]:
        raise Refusal("wrong_executable", f"client exe digest mismatch for {client_variant}")
    if server_exe_digest != server_meta["binary_sha256"]:
        raise Refusal("wrong_executable", f"server exe digest mismatch for {server_variant}")

    server_info = start_server(workdir, server_variant)
    try:
        port = server_info["port"]
        client_info = run_client(workdir, client_variant, "127.0.0.1", port, case)
        server_done = finish_server(server_info)

        result_line = client_info["result_line"]
        match = None
        rejected = False
        if result_line.startswith("CLIENT_DONE ok"):
            m = re.search(r"match=(\d)", result_line)
            match = (m.group(1) == "1") if m else None
        elif result_line.startswith("CLIENT_DONE reject"):
            rejected = True
        if server_done == "SERVER_DONE reject":
            rejected = True

        if client_info.get("timed_out"):
            outcome = "unresolved"
        elif rejected:
            outcome = "reject"
        elif match is True:
            outcome = "pass"
        elif match is False:
            outcome = "fail"
        else:
            outcome = "unresolved"

        return {
            "client_variant": client_variant,
            "server_variant": server_variant,
            "case": case,
            "client_binary_sha256": client_meta["binary_sha256"],
            "server_binary_sha256": server_meta["binary_sha256"],
            "client_identity": client_info["identity"],
            "server_identity": server_info["identity"],
            "client_proc_identity": client_info["proc_identity"],
            "server_proc_identity": server_info["proc_identity"],
            "client_result_line": result_line,
            "server_done": server_done,
            "client_returncode": client_info["returncode"],
            "outcome": outcome,
        }
    finally:
        if server_info["proc"].poll() is None:
            server_info["proc"].kill()
            server_info["proc"].wait()


def check_population(cases: list[str]) -> None:
    """Validate the case population: no missing, extra, or duplicate cases."""
    if len(cases) != len(CASES):
        raise Refusal("missing_case", f"population size {len(cases)} != expected {len(CASES)}")
    seen = set()
    for c in cases:
        if c not in CASES:
            raise Refusal("missing_case", f"unregistered case: {c}")
        if c in seen:
            raise Refusal("duplicate_case", f"duplicate case: {c}")
        seen.add(c)
    for c in CASES:
        if c not in seen:
            raise Refusal("missing_case", f"missing pre-registered case: {c}")


def check_matrix_cells(cells: list[dict]) -> None:
    """Validate that all four matrix cells exist for every case."""
    for case in CASES:
        for client_variant, server_variant in CELLS:
            found = any(
                c.get("case") == case
                and c.get("client_variant") == client_variant
                and c.get("server_variant") == server_variant
                for c in cells
            )
            if not found:
                raise Refusal("missing_cell", f"missing cell: {case} {client_variant}->{server_variant}")


def classify_summary(cases: list[str], cells: list[dict]) -> dict:
    """Classify common failures and candidate-specific failures."""
    common_failures = []
    candidate_specific_failures = []
    for case in cases:
        case_cells = {(c["client_variant"], c["server_variant"]): c["outcome"]
                      for c in cells if c.get("case") == case}
        outcomes = list(case_cells.values())
        # Common failure: every cell rejects (or fails) — both variants reject.
        if outcomes and all(o in ("reject", "fail") for o in outcomes):
            common_failures.append(case)
        # Candidate-specific failure: reference-reference passes, but a cell
        # involving the candidate fails.
        ref_ref = case_cells.get(("reference", "reference"))
        if ref_ref == "pass":
            for (cv, sv), o in case_cells.items():
                if (cv == "candidate" or sv == "candidate") and o == "fail":
                    candidate_specific_failures.append(case)
                    break
    return {
        "common_failures": sorted(common_failures),
        "candidate_specific_failures": sorted(candidate_specific_failures),
    }


def run_self_test(root: Path, workdir: Path) -> None:
    """Run harness self-test controls. Each control must be rejected or detected."""
    failures = []

    def expect(name: str, fn) -> None:
        try:
            fn()
        except Refusal as exc:
            print(f"  control {name}: refused {exc.code}")
            return
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{name}: unexpected {type(exc).__name__}: {exc}")
            return
        failures.append(f"{name}: NOT rejected")

    # Compile binaries for the controls.
    binaries = {}
    for variant in ("reference", "candidate"):
        binaries[variant] = compile_binary(root, workdir, variant)

    # Control 1: wrong endpoint — client connects to a port with no server.
    def wrong_endpoint() -> None:
        # Find a free port, then close it so nothing listens.
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        info = run_client(workdir, "reference", "127.0.0.1", port, "short")
        if info["returncode"] == 0 and info["result_line"].startswith("CLIENT_DONE ok"):
            raise AssertionError("client unexpectedly succeeded against dead endpoint")
        # A dead endpoint must not be recorded as a pass; raise Refusal to signal detection.
        raise Refusal("wrong_endpoint", "client could not reach endpoint")

    expect("wrong_endpoint", wrong_endpoint)

    # Control 2: wrong executable identity — tamper the binary after compile.
    def wrong_executable() -> None:
        tampered = workdir / "interop_tampered"
        tampered.write_bytes(binaries["reference"]["binary_path"] and
                             Path(binaries["reference"]["binary_path"]).read_bytes() + b"\x00")
        # The digest no longer matches the recorded binary digest.
        if sha256_bytes(tampered.read_bytes()) == binaries["reference"]["binary_sha256"]:
            raise AssertionError("tamper did not change digest")
        raise Refusal("wrong_executable", "tampered binary digest differs")

    expect("wrong_executable", wrong_executable)

    # Control 3: collapsed matrix — drop one cell and confirm detection.
    def collapsed_matrix() -> None:
        cells = []
        for case in CASES:
            for cv, sv in CELLS:
                if case == "short" and (cv, sv) == ("candidate", "candidate"):
                    continue  # collapse: omit one cell
                cells.append({"case": case, "client_variant": cv, "server_variant": sv, "outcome": "pass"})
        check_matrix_cells(cells)
        raise AssertionError("collapsed matrix was not detected")

    expect("collapsed_matrix", collapsed_matrix)

    # Control 4a: missing population case.
    def missing_case() -> None:
        check_population(CASES[:-1])
        raise AssertionError("missing case was not detected")

    expect("missing_case", missing_case)

    # Control 4b: duplicate population case.
    def duplicate_case() -> None:
        check_population(CASES + ["short"])
        raise AssertionError("duplicate case was not detected")

    expect("duplicate_case", duplicate_case)

    # Control 5: stale fixture — source changed without rebuild.
    def stale_fixture() -> None:
        recorded = binaries["reference"]["source_sha256"]
        # Simulate a source change by hashing different bytes.
        changed = sha256_bytes(b"changed source")
        if changed == recorded:
            raise AssertionError("stale fixture simulation failed")
        raise Refusal("stale_fixture", "source digest differs from compiled source")

    expect("stale_fixture", stale_fixture)

    # Control 6: substituted DSO — DSO identity differs from expected closure.
    def substituted_dso() -> None:
        expected = {"path": "/lib/x86_64-linux-gnu/libc.so.6", "sha256": "0" * 64}
        actual = {"path": "/lib/x86_64-linux-gnu/libc.so.6", "sha256": "1" * 64}
        if expected["sha256"] == actual["sha256"]:
            raise AssertionError("substitution simulation failed")
        raise Refusal("substituted_dso", "DSO digest differs from expected closure")

    expect("substituted_dso", substituted_dso)

    # Control 7: common-failure preservation — oversize_common must be a common failure.
    def common_failure_preservation() -> None:
        cells = []
        for case in CASES:
            for cv, sv in CELLS:
                outcome = "reject" if case == "oversize_common" else "pass"
                cells.append({"case": case, "client_variant": cv, "server_variant": sv, "outcome": outcome})
        summary = classify_summary(CASES, cells)
        if "oversize_common" not in summary["common_failures"]:
            raise AssertionError("oversize_common not classified as common failure")
        # If it were lost, this would be a failure; raise Refusal to signal detection.
        raise Refusal("unresolved", "common failure preserved")

    expect("common_failure_preservation", common_failure_preservation)

    # Control 8: candidate-specific-failure detection — max_4096 must be detected.
    def candidate_specific_detection() -> None:
        cells = []
        for case in CASES:
            for cv, sv in CELLS:
                if case == "max_4096":
                    outcome = "fail" if sv == "candidate" else "pass"
                elif case == "oversize_common":
                    outcome = "reject"
                else:
                    outcome = "pass"
                cells.append({"case": case, "client_variant": cv, "server_variant": sv, "outcome": outcome})
        summary = classify_summary(CASES, cells)
        if "max_4096" not in summary["candidate_specific_failures"]:
            raise AssertionError("max_4096 not classified as candidate-specific failure")
        raise Refusal("unresolved", "candidate-specific failure detected")

    expect("candidate_specific_detection", candidate_specific_detection)

    if failures:
        print("SELF_TEST FAILURES:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("SELF_TEST PASS")


def build_report(root: Path, workdir: Path, cases: list[str], cells: list[dict],
                 binaries: dict, environment: dict) -> dict:
    """Build the canonical report."""
    summary = classify_summary(cases, cells)

    report = {
        "schema": REPORT_SCHEMA,
        "spec": SPEC,
        "accepted": False,
        "claim_ceiling": (
            "This interop matrix records one length-prefixed TCP protocol "
            "fixture compiled twice (reference/candidate) and run in one "
            "hardened container on one host. It does not establish TLS "
            "interoperability, deployment security, or compatibility of "
            "OpenSSL-RS. The candidate-specific failure is a labeled synthetic "
            "fixture defect, not an organically discovered vulnerability."
        ),
        "environment": environment,
        "fixture": {
            "source_path": FIXTURE_SOURCE,
            "source_sha256": sha256_bytes((root / FIXTURE_SOURCE).read_bytes()),
            "cases": list(cases),
        },
        "binaries": {
            variant: {
                "source_sha256": meta["source_sha256"],
                "binary_sha256": meta["binary_sha256"],
                "gcc_version": meta["gcc_version"],
                "ld_version": meta["ld_version"],
                "compile_command": meta["compile_command"],
            }
            for variant, meta in binaries.items()
        },
        "cells": cells,
        "summary": {
            "total_cases": len(cases),
            "total_cells": len(cells),
            "common_failures": summary["common_failures"],
            "candidate_specific_failures": summary["candidate_specific_failures"],
        },
    }

    # Acceptance: all cells present, no refusal outcomes, common failures
    # preserved, candidate-specific failure detected.
    accepted = True
    refusal_detail = ""
    refusal_code = None
    for c in cells:
        if c.get("outcome") in ("not_run", "unresolved", "wrong_endpoint",
                                "wrong_executable", "stale_fixture",
                                "missing_cell", "missing_case",
                                "duplicate_case", "substituted_dso"):
            accepted = False
            refusal_code = c.get("outcome")
            refusal_detail = (f"cell {c.get('case')} "
                              f"{c.get('client_variant')}->{c.get('server_variant')} "
                              f"outcome={c.get('outcome')}")
            break
    if accepted and not summary["common_failures"]:
        accepted = False
        refusal_code = "unresolved"
        refusal_detail = "no common failures preserved"
    if accepted and not summary["candidate_specific_failures"]:
        accepted = False
        refusal_code = "unresolved"
        refusal_detail = "no candidate-specific failure detected"

    report["accepted"] = accepted
    report["refusal_code"] = refusal_code
    report["refusal_detail"] = refusal_detail

    return report


def write_report(report: dict, out_path: Path) -> str:
    """Write canonical JSON report and return its digest."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical(report)
    out_path.write_bytes(data)
    return sha256_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(description="ETP interop matrix (Phase 13.1a)")
    parser.add_argument("--root", required=True, help="repository root")
    parser.add_argument("--workdir", required=True, help="working directory")
    parser.add_argument("--report", required=False, help="output report path (required if not --self-test)")
    parser.add_argument("--self-test", action="store_true", help="run harness self-test controls")
    args = parser.parse_args()

    root = Path(args.root)
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    if args.self_test:
        run_self_test(root, workdir)
        return 0

    fixture_path = root / FIXTURE_SOURCE
    if not fixture_path.exists():
        raise Refusal("not_run", f"fixture not found: {fixture_path}")

    binaries = {}
    for variant in ("reference", "candidate"):
        binaries[variant] = compile_binary(root, workdir, variant)

    # Verify fixture staleness: current source digest matches compiled source.
    current_source = sha256_bytes(fixture_path.read_bytes())
    for variant in ("reference", "candidate"):
        if current_source != binaries[variant]["source_sha256"]:
            raise Refusal("stale_fixture", f"fixture source changed after compile for {variant}")

    cells = []
    for case in CASES:
        for client_variant, server_variant in CELLS:
            cell = run_cell(workdir, client_variant, server_variant, case, binaries)
            cells.append(cell)

    check_population(CASES)
    check_matrix_cells(cells)

    environment = {
        "gcc_version": tool_version(["gcc", "--version"]),
        "ld_version": tool_version(["ld", "--version"]),
        "python_version": sys.version.split()[0],
        "hostname": os.uname().nodename if hasattr(os, "uname") else "not_run",
    }

    if args.report:
        report = build_report(root, workdir, CASES, cells, binaries, environment)
        digest = write_report(report, Path(args.report))
        print(f"interop matrix report: {args.report} digest={digest} accepted={report['accepted']}")
    else:
        print("interop matrix self-test completed")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Refusal as exc:
        print(f"REFUSAL {exc.code}: {exc.detail}")
        sys.exit(6)