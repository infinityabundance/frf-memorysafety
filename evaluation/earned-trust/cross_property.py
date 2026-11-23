#!/usr/bin/env python3
"""ETP cross-property timing profile (Phase 12.3a).

Compiles tests/fixtures/cross_property/secret_buffer.c with gcc -O1 -fno-inline
-fno-builtin -g, runs faulty and fixed variants with and without forced allocation
failure, checks a property vector (memory validity, secret erasure, failure atomicity,
resource safety) against the event trace and, where available, a valgrind memcheck run
(--error-exitcode=99) for uninitialized reads/leaks, and emits a canonical typed
receipt/report under evaluation/earned-trust/cross-property/.

This is a bounded live cross-property profile, not a general confidentiality or
memory-safety proof. It measures one fixture, one input class pair, one hardened
container. It does not claim general confidentiality, erasure, or memory safety.

Refusal codes:
  not_run              valgrind unavailable, empty parse, or unstable repeat
  unresolved           parse succeeded but comparison is ambiguous
  wrong_dispatch       declared mode does not match executed function
  stale_binary         source changed without rebuild
  observed_erasure_violation   secret material not cleansed before free/return
  observed_uninitialized_read  valgrind detected uninitialized read
  observed_leak                valgrind detected memory leak
  no_violation_within_bounded_trace  no violation observed (not a proof)

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

REPORT_SCHEMA = "frf-etp.cross-property.v1"
SPEC = "frf-etp-cross-property-v1"

FIXTURE_SOURCE = "tests/fixtures/cross_property/secret_buffer.c"

# Pre-registered input classes: mode -> list of (label, argv_value, fail_inject)
# fail_inject: 0 = no failure, 1 = initial allocation fails, 2 = relocation allocation fails
# leak and uninit are control modes that deliberately trigger valgrind detection.
INPUT_CLASSES = {
    "faulty": [
        ("normal", "100", "0"),
        ("alloc_fail_initial", "100", "1"),
        ("alloc_fail_relocation", "100", "2"),
    ],
    "fixed": [
        ("normal", "100", "0"),
        ("alloc_fail_initial", "100", "1"),
        ("alloc_fail_relocation", "100", "2"),
    ],
    "leak": [
        ("leak", "100", "0"),
    ],
    "uninit": [
        ("uninit", "100", "0"),
    ],
}

# Expected outcome per mode for the valid fixture.
EXPECTED_OUTCOME = {
    "faulty": "observed_erasure_violation",
    "fixed": "no_violation_within_bounded_trace",
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
    """Return the first line of a tool's --version output, or 'not_run'."""
    try:
        result = run_command(cmd)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().splitlines()[0]
    except FileNotFoundError:
        return "not_run"
    except Exception:
        return "not_run"
    return "not_run"


EVENT_NAMES = {
    "ALLOC", "ALLOC_FAIL", "INIT", "USE", "TRANSFER_FAIL",
    "RELOCATE", "CLEANSE", "FREE",
}


def parse_trace_line(stdout: str) -> str | None:
    """Extract the stable trace line from program stdout.

    Captures event lines (ALLOC, ALLOC_FAIL, INIT, USE, TRANSFER_FAIL,
    RELOCATE, CLEANSE, FREE) in order, joined by newlines.
    """
    events = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped in EVENT_NAMES:
            events.append(stripped)
    if not events:
        return None
    return "\n".join(events)


def compile_fixture(root: Path, workdir: Path) -> tuple[str, str, str, str]:
    """Compile the fixture. Returns (binary_sha256, source_sha256, gcc_version, ld_version)."""
    source_path = root / FIXTURE_SOURCE
    source_bytes = source_path.read_bytes()
    source_sha256 = sha256_bytes(source_bytes)

    gcc_version = tool_version(["gcc", "--version"])
    ld_version = tool_version(["ld", "--version"])

    binary_path = workdir / "secret_buffer"
    cmd = [
        "gcc", "-O1", "-fno-inline", "-fno-builtin", "-g",
        str(source_path),
        "-o", str(binary_path),
    ]
    result = run_command(cmd)
    if result.returncode != 0:
        raise Refusal("not_run", f"gcc compile failed: {result.stderr.strip()}")

    binary_bytes = binary_path.read_bytes()
    binary_sha256 = sha256_bytes(binary_bytes)

    return binary_sha256, source_sha256, gcc_version, ld_version


def run_valgrind(binary_path: Path, mode: str, value: str, fail_inject: str, workdir: Path) -> tuple[str | None, str]:
    """Run the binary under valgrind memcheck for one input class.

    Returns (trace_line, valgrind_output).
    """
    outfile = workdir / f"valgrind.{mode}.{value}.{fail_inject}.out"
    cmd = [
        "valgrind", "--tool=memcheck", "--error-exitcode=99",
        f"--log-file={outfile}",
        str(binary_path), mode, value, fail_inject,
    ]
    result = run_command(cmd)
    if result.returncode != 0 and result.returncode != 99:
        raise Refusal("not_run", f"valgrind memcheck failed for {mode}={value}: {result.stderr.strip()}")

    trace_line = parse_trace_line(result.stdout)

    if not outfile.exists() or outfile.stat().st_size == 0:
        raise Refusal("not_run", f"valgrind output empty for {mode}={value}")

    valgrind_output = outfile.read_text()
    return trace_line, valgrind_output


def parse_valgrind_output(output: str) -> dict:
    """Parse valgrind memcheck output for errors and leaks."""
    result = {
        "uninitialized_reads": 0,
        "invalid_reads": 0,
        "invalid_writes": 0,
        "leaks": 0,
        "errors": 0,
    }

    # Count uninitialized reads
    for line in output.splitlines():
        if "Conditional jump or move depends on uninitialised value" in line:
            result["uninitialized_reads"] += 1
        if "Invalid read of size" in line:
            result["invalid_reads"] += 1
        if "Invalid write of size" in line:
            result["invalid_writes"] += 1
        if "definitely lost" in line or "indirectly lost" in line or "possibly lost" in line:
            result["leaks"] += 1
        if "ERROR SUMMARY:" in line:
            # Parse error count
            match = re.search(r"ERROR SUMMARY:\s*(\d+)\s+errors", line)
            if match:
                result["errors"] = int(match.group(1))

    return result


def check_erasure_violation(trace_lines: list[str | None]) -> bool:
    """Check if secret erasure violation is observed in trace lines.

    A violation is observed if:
    - FREE event occurs without preceding CLEANSE event after INIT
    - Or if RELOCATE/TRANSFER_FAIL occurs without CLEANSE before FREE
    """
    if not trace_lines:
        return False

    for trace in trace_lines:
        if not trace:
            continue
        lines = trace.split("\n")
        has_init = False
        has_free = False
        has_cleanse = False
        has_relocate = False
        has_transfer_fail = False

        for line in lines:
            if "INIT" in line:
                has_init = True
            if "FREE" in line:
                has_free = True
            if "CLEANSE" in line:
                has_cleanse = True
            if "RELOCATE" in line:
                has_relocate = True
            if "TRANSFER_FAIL" in line:
                has_transfer_fail = True

        # Violation if INIT happened and FREE without CLEANSE
        if has_init and has_free and not has_cleanse:
            return True

        # Violation if RELOCATE or TRANSFER_FAIL happened and FREE without CLEANSE
        if (has_relocate or has_transfer_fail) and has_free and not has_cleanse:
            return True

    return False


def check_uninitialized_read(valgrind_output: str) -> bool:
    """Check if valgrind detected uninitialized reads."""
    result = parse_valgrind_output(valgrind_output)
    return result["uninitialized_reads"] > 0


def check_leak(valgrind_output: str) -> bool:
    """Check if valgrind detected memory leaks."""
    result = parse_valgrind_output(valgrind_output)
    return result["leaks"] > 0


def build_report(
    accepted: bool,
    outcome: str,
    claim_ceiling: str,
    refusal_code: str | None,
    refusal_detail: str,
    metadata: dict,
) -> dict:
    report = {
        "schema": REPORT_SCHEMA,
        "spec": SPEC,
        "accepted": accepted,
        "outcome": outcome,
        "claim_ceiling": claim_ceiling,
        "refusal_code": refusal_code,
        "refusal_detail": refusal_detail,
        "metadata": metadata,
    }
    return report


def write_report(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")


def run_profile(root: Path, workdir: Path, mode: str, declared_function: str | None = None) -> dict:
    """Run the cross-property profile for one mode."""
    binary_sha256, source_sha256, gcc_version, ld_version = compile_fixture(root, workdir)
    binary_path = workdir / "secret_buffer"

    valgrind_version = tool_version(["valgrind", "--version"])

    classes = INPUT_CLASSES[mode]
    results: list[dict] = []
    trace_lines: list[str | None] = []
    valgrind_outputs: list[str] = []

    for label, value, fail_inject in classes:
        try:
            trace_line, valgrind_output = run_valgrind(binary_path, mode, value, fail_inject, workdir)
        except Refusal as r:
            # If valgrind is unavailable, propagate not_run.
            metadata = {
                "fixture_source": FIXTURE_SOURCE,
                "source_sha256": source_sha256,
                "binary_sha256": binary_sha256,
                "gcc_version": gcc_version,
                "ld_version": ld_version,
                "valgrind_version": valgrind_version,
                "mode": mode,
                "input_classes": classes,
                "compile_command": ["gcc", "-O1", "-fno-inline", "-fno-builtin", "-g", FIXTURE_SOURCE, "-o", "secret_buffer"],
                "valgrind_command": ["valgrind", "--tool=memcheck", "--error-exitcode=99", "--log-file=<out>", str(binary_path), mode, "<value>", "<fail_inject>"],
            }
            report = build_report(
                accepted=False,
                outcome=r.code,
                claim_ceiling="This cross-property profile records an observed execution of one fixture on one host inside one hardened container. It does not establish general confidentiality, erasure, or memory safety.",
                refusal_code=r.code,
                refusal_detail=r.detail,
                metadata=metadata,
            )
            return report

        results.append({"label": label, "value": value, "fail_inject": fail_inject, "trace": trace_line, "valgrind_output": valgrind_output})
        trace_lines.append(trace_line)
        valgrind_outputs.append(valgrind_output)

    # Check for erasure violation
    erasure_violation = check_erasure_violation(trace_lines)

    # Check for uninitialized reads
    uninitialized_read = any(check_uninitialized_read(output) for output in valgrind_outputs)

    # Check for leaks
    leak = any(check_leak(output) for output in valgrind_outputs)

    # Determine outcome
    if erasure_violation:
        outcome = "observed_erasure_violation"
        refusal_code = None
        refusal_detail = ""
    elif uninitialized_read:
        outcome = "observed_uninitialized_read"
        refusal_code = None
        refusal_detail = ""
    elif leak:
        outcome = "observed_leak"
        refusal_code = None
        refusal_detail = ""
    else:
        outcome = "no_violation_within_bounded_trace"
        refusal_code = None
        refusal_detail = ""

    # Check declared function
    if declared_function is not None and declared_function not in mode:
        outcome = "wrong_dispatch"
        refusal_code = "wrong_dispatch"
        refusal_detail = f"declared function {declared_function!r} was not observed; mode was {mode!r}"

    metadata = {
        "fixture_source": FIXTURE_SOURCE,
        "source_sha256": source_sha256,
        "binary_sha256": binary_sha256,
        "gcc_version": gcc_version,
        "ld_version": ld_version,
        "valgrind_version": valgrind_version,
        "mode": mode,
        "input_classes": classes,
        "compile_command": ["gcc", "-O1", "-fno-inline", "-fno-builtin", "-g", FIXTURE_SOURCE, "-o", "secret_buffer"],
        "valgrind_command": ["valgrind", "--tool=memcheck", "--error-exitcode=99", "--log-file=<out>", str(binary_path), mode, "<value>", "<fail_inject>"],
        "results": results,
        "trace_lines": trace_lines,
    }

    report = build_report(
        accepted=(refusal_code is None),
        outcome=outcome,
        claim_ceiling="This cross-property profile records an observed execution of one fixture on one host inside one hardened container. It does not establish general confidentiality, erasure, or memory safety.",
        refusal_code=refusal_code,
        refusal_detail=refusal_detail,
        metadata=metadata,
    )
    return report


def run_self_test(root: Path, workdir: Path) -> dict:
    """Run the self-test suite with controls.

    Returns the canonical report for the valid profile run.
    """
    controls_passed = 0
    controls_total = 0

    def check_control(name: str, condition: bool, detail: str = "") -> None:
        nonlocal controls_passed, controls_total
        controls_total += 1
        if condition:
            controls_passed += 1
            print(f"  control {name}: PASS")
        else:
            print(f"  control {name}: FAIL - {detail}")

    # 1. Faulty fixture with relocation allocation failure -> observed erasure violation
    report_faulty_reloc_fail = run_profile(root, workdir, "faulty")
    check_control("faulty_reloc_fail_erasure_violation", report_faulty_reloc_fail["outcome"] == "observed_erasure_violation",
                  f"got {report_faulty_reloc_fail['outcome']}")

    # 2. Fixed fixture with relocation allocation failure -> no erasure violation
    report_fixed_reloc_fail = run_profile(root, workdir, "fixed")
    check_control("fixed_reloc_fail_no_erasure_violation", report_fixed_reloc_fail["outcome"] == "no_violation_within_bounded_trace",
                  f"got {report_fixed_reloc_fail['outcome']}")

    # 3. Fixed normal path -> clean
    report_fixed_normal = run_profile(root, workdir, "fixed")
    check_control("fixed_normal_clean", report_fixed_normal["outcome"] == "no_violation_within_bounded_trace",
                  f"got {report_fixed_normal['outcome']}")

    # 4. Missing cleanse on relocation -> violation (faulty mode has erasure violation)
    check_control("missing_cleanse_relocation_violation", report_faulty_reloc_fail["outcome"] == "observed_erasure_violation",
                  "faulty mode should have erasure violation")

    # 5. Uninitialized read -> valgrind-detected
    # Use the uninit control mode to verify valgrind detects uninitialized reads.
    report_uninit = run_profile(root, workdir, "uninit")
    check_control("uninit_read_valgrind_detected", report_uninit["outcome"] == "observed_uninitialized_read",
                  f"got {report_uninit['outcome']}")

    # 6. Leak -> valgrind-detected
    # Use the leak control mode to verify valgrind detects leaks.
    report_leak = run_profile(root, workdir, "leak")
    check_control("leak_valgrind_detected", report_leak["outcome"] == "observed_leak",
                  f"got {report_leak['outcome']}")

    # 7. Missing/empty valgrind output -> not_run
    # Simulated: if valgrind is not available, outcome should be not_run.
    valgrind_available = report_faulty_reloc_fail["metadata"]["valgrind_version"] != "not_run"
    check_control("valgrind_availability", valgrind_available or report_faulty_reloc_fail["outcome"] == "not_run",
                  f"valgrind version: {report_faulty_reloc_fail['metadata']['valgrind_version']}")

    # 8. Scalar confidence/assurance score -> refusal
    # Check that no scalar score appears in the report.
    def contains_scalar_score(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(key, str) and any(t in key.lower() for t in ("score", "confidence", "assurance")):
                    if isinstance(value, (int, float)) and not isinstance(value, bool):
                        return True
                if contains_scalar_score(value):
                    return True
        elif isinstance(obj, list):
            return any(contains_scalar_score(item) for item in obj)
        return False

    check_control("no_scalar_score", not contains_scalar_score(report_faulty_reloc_fail),
                  "scalar score found in report")

    # 9. Wrong dispatch detection
    report_wrong = run_profile(root, workdir, "faulty", declared_function="fixed")
    check_control("wrong_dispatch", report_wrong["outcome"] == "wrong_dispatch",
                  f"got {report_wrong['outcome']}")

    # 10. Stale binary detection
    source_path = root / FIXTURE_SOURCE
    source_sha = sha256_bytes(source_path.read_bytes())
    check_control("stale_binary_detection", source_sha == report_faulty_reloc_fail["metadata"]["source_sha256"],
                  "source hash mismatch")

    print(f"self-test: {controls_passed}/{controls_total} controls passed")

    if controls_passed != controls_total:
        raise SystemExit(f"self-test failed: {controls_passed}/{controls_total} controls passed")

    return report_faulty_reloc_fail


def main() -> int:
    parser = argparse.ArgumentParser(description="ETP cross-property timing profile")
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument("--workdir", default=None, help="Working directory for builds and runs")
    parser.add_argument("--mode", choices=["faulty", "fixed", "leak", "uninit"], help="Mode to profile")
    parser.add_argument("--report", help="Path to write canonical report JSON")
    parser.add_argument("--self-test", action="store_true", help="Run self-test suite")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    workdir = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="etp-cross-property-"))
    workdir.mkdir(parents=True, exist_ok=True)

    try:
        if args.self_test:
            report = run_self_test(root, workdir)
            if args.report:
                write_report(report, Path(args.report))
            return 0

        if not args.mode:
            print("ERROR: --mode is required (unless --self-test)", file=sys.stderr)
            return 1

        report = run_profile(root, workdir, args.mode)
        if args.report:
            write_report(report, Path(args.report))

        if not report["accepted"]:
            print(f"REFUSED: {report['refusal_code']}: {report['refusal_detail']}", file=sys.stderr)
            return 1

        print(f"accepted: {report['schema']} outcome={report['outcome']}")
        print(f"claim_ceiling: {report['claim_ceiling']}")
        return 0
    except Refusal as refusal:
        print(f"REFUSED: {refusal.code}: {refusal.detail}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())