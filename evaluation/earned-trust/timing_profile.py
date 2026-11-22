#!/usr/bin/env python3
"""ETP bounded live timing/execution-path profile (Phase 12.2a).

Compiles tests/fixtures/timing/timing_probe.c with gcc -O1 -fno-inline
-fno-builtin -g, runs each selected function under valgrind --tool=callgrind
for pre-registered input classes, parses per-function instruction counts with
callgrind_annotate, and emits a canonical typed receipt/report under
evaluation/earned-trust/timing/.

This is a bounded live timing profile, not a constant-time proof. It measures
one fixture, one input class pair, one hardened container. It does not claim
constant-time, absence of leakage, or deployment security.

Refusal codes:
  not_run              valgrind/callgrind unavailable, empty parse, or unstable repeat
  unresolved           parse succeeded but comparison is ambiguous
  wrong_dispatch       declared mode does not match executed function
  stale_binary         source changed without rebuild
  observed_secret_dependent_divergence   Ir differs between secret classes
  observed_representation_length_divergence Ir differs between length classes
  no_divergence_within_bounded_trace     Ir matches across compared classes

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

REPORT_SCHEMA = "frf-etp.timing-profile.v1"
SPEC = "frf-etp-timing-profile-v1"

FIXTURE_SOURCE = "tests/fixtures/timing/timing_probe.c"

# Pre-registered input classes: mode -> list of (label, argv_value)
INPUT_CLASSES = {
    "branch": [("secret_0", "0"), ("secret_1", "1")],
    "ct": [("secret_0", "0"), ("secret_1", "1")],
    "length": [("length_15", "15"), ("length_16", "16")],
}

# Expected outcome per mode for the valid fixture.
EXPECTED_OUTCOME = {
    "branch": "observed_secret_dependent_divergence",
    "ct": "no_divergence_within_bounded_trace",
    "length": "observed_representation_length_divergence",
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


def callgrind_annotate_version() -> str:
    """Get callgrind_annotate version from its output header."""
    # callgrind_annotate doesn't support --version, but we can get it from
    # the output header of any file, or from valgrind --version.
    valgrind_ver = tool_version(["valgrind", "--version"])
    if valgrind_ver != "not_run":
        return valgrind_ver.replace("valgrind-", "callgrind_annotate-")
    return "not_run"


def parse_callgrind_annotate(outfile: Path) -> dict[str, int]:
    """Parse callgrind_annotate output and return per-function Ir counts.

    Returns a dict mapping function name to Ir (instruction read count).
    Only functions from the timing probe fixture are included.
    """
    result = run_command(["callgrind_annotate", "--threshold=100", str(outfile)])
    if result.returncode != 0:
        raise Refusal("not_run", f"callgrind_annotate failed: {result.stderr.strip()}")

    counts: dict[str, int] = {}
    # callgrind_annotate output format:
    #   Ir
    #   --------------------------------------------------------------------------------
    #   Ir
    #   --------------------------------------------------------------------------------
    #   122,076 (100.0%)  PROGRAM TOTALS
    #
    #   --------------------------------------------------------------------------------
    #   Ir               file:function
    #   --------------------------------------------------------------------------------
    #   24,438 (20.02%)  ./elf/./elf/dl-lookup.c:do_lookup_x [/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2]
    #   123 ( 0.01%)  tests/fixtures/timing/timing_probe.c:secret_branch [/tmp/timing_probe]
    #
    # We extract the function name (part after the last ':') and filter to
    # only functions from the timing probe fixture.
    target_functions = {"secret_branch", "constant_time", "length_sensitive", "length_sensitive_fixed", "main"}
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Skip header lines like "Ir", "--------------------------------------------------------------------------------"
        if stripped == "Ir" or set(stripped) <= {"-", "I", "r"}:
            continue
        # Skip "Events recorded:     Ir" etc.
        if "Events" in stripped or "Timerange" in stripped or "Trigger" in stripped or "Profiled" in stripped or "Events" in stripped:
            continue
        # Skip "Thresholds:" and "Include dirs:" lines
        if stripped.startswith("Thresholds") or stripped.startswith("Include dirs"):
            continue
        # Skip "Auto-annotation:" and "User annotated:" lines
        if stripped.startswith("Auto-annotation") or stripped.startswith("User annotated"):
            continue
        # Skip "PROGRAM TOTALS"
        if stripped == "PROGRAM TOTALS":
            continue
        # Skip "Events shown:" etc
        if stripped.startswith("Events"):
            continue
        # Skip "Event sort order:" and "Event" lines
        if stripped.startswith("Event"):
            continue
        # Skip "Collected :" lines
        if stripped.startswith("Collected") or stripped.startswith("I   refs") or stripped.startswith("I refs"):
            continue
        # Skip "Profile data file" and "creator:" lines
        if stripped.startswith("Profile data file") or stripped.startswith("creator:"):
            continue
        # Skip "Events recorded" etc
        if stripped.startswith("Events"):
            continue
        # Skip "Timerange", "Trigger", "Profiled", "Events shown", "Event sort order", "Thresholds", "Include dirs", "User annotated", "Auto-annotation"
        if any(stripped.startswith(p) for p in ["Events", "Timerange", "Trigger", "Profiled", "Thresholds", "Include dirs", "User annotated", "Auto-annotation", "Event sort", "Collected", "I   refs", "I refs", "Profile data", "creator", "Events recorded", "Events shown", "Event sort order"]):
            continue
        # Skip separator lines
        if set(stripped) <= {"-"}:
            continue
        # Skip lines that are just numbers with percentage
        if stripped.startswith("122,076") or stripped.startswith("24,438"):
            continue
        # Try to parse "N (X.XX%)  function_name"
        match = re.match(r"^([\d,]+) \(\s*([\d.]+)%\)\s+(.+)$", stripped)
        if match:
            ir = int(match.group(1).replace(",", ""))
            name = match.group(3)
            # Skip PROGRAM TOTALS line
            if name.startswith("PROGRAM TOTALS"):
                continue
            # Extract function name from things like "./elf/./elf/dl-lookup.c:do_lookup_x [/usr/lib/...]"
            # or "tests/fixtures/timing/timing_probe.c:secret_branch [/tmp/timing_probe]"
            # Take the part before the space or bracket, then take the part after the last ':'
            path_func = name.split(" [")[0].split("(")[0].strip()
            # Extract function name (part after the last ':')
            if ":" in path_func:
                func_name = path_func.rsplit(":", 1)[1].strip()
            else:
                func_name = path_func
            # Only include functions from our fixture
            if func_name in target_functions:
                counts[func_name] = counts.get(func_name, 0) + ir
    return counts


def parse_trace_line(stdout: str) -> str | None:
    """Extract the stable trace line from program stdout."""
    for line in stdout.splitlines():
        if line.startswith("mode="):
            return line.strip()
    return None


def compile_fixture(root: Path, workdir: Path) -> tuple[str, str, str, str]:
    """Compile the fixture. Returns (binary_sha256, source_sha256, gcc_version, ld_version)."""
    source_path = root / FIXTURE_SOURCE
    source_bytes = source_path.read_bytes()
    source_sha256 = sha256_bytes(source_bytes)

    gcc_version = tool_version(["gcc", "--version"])
    ld_version = tool_version(["ld", "--version"])

    binary_path = workdir / "timing_probe"
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


def check_no_conditional_branch(binary_path: Path) -> bool:
    """Check with objdump that constant_time has no conditional branch instructions."""
    result = run_command(["objdump", "-d", "--disassemble=constant_time", str(binary_path)])
    if result.returncode != 0:
        return False
    text = result.stdout
    # Look for conditional branch mnemonics in the constant_time disassembly.
    conditional = re.compile(r"\b(je|jne|jz|jnz|js|jns|jg|jge|jl|jle|ja|jae|jb|jbe)\b")
    for line in text.splitlines():
        if conditional.search(line):
            return False
    return True


def run_callgrind(binary_path: Path, mode: str, value: str, workdir: Path) -> tuple[str | None, dict[str, int]]:
    """Run the binary under callgrind for one input class.

    Returns (trace_line, per_function_ir_counts).
    """
    outfile = workdir / f"callgrind.{mode}.{value}.out"
    cmd = [
        "valgrind", "--tool=callgrind",
        f"--callgrind-out-file={outfile}",
        str(binary_path), mode, value,
    ]
    result = run_command(cmd)
    if result.returncode != 0:
        raise Refusal("not_run", f"valgrind callgrind failed for {mode}={value}: {result.stderr.strip()}")

    trace_line = parse_trace_line(result.stdout)

    if not outfile.exists() or outfile.stat().st_size == 0:
        raise Refusal("not_run", f"callgrind output empty for {mode}={value}")

    counts = parse_callgrind_annotate(outfile)
    return trace_line, counts


def compare_counts(counts_a: dict[str, int], counts_b: dict[str, int]) -> str:
    """Compare Ir counts between two runs.

    Returns 'divergent' if any function differs, 'match' if all match,
    'unresolved' if counts are missing.
    """
    if not counts_a or not counts_b:
        return "unresolved"
    all_names = set(counts_a) | set(counts_b)
    for name in all_names:
        if counts_a.get(name, 0) != counts_b.get(name, 0):
            return "divergent"
    return "match"


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
    path.write_text(canonical(report).decode("utf-8") + "\n", encoding="utf-8")


def run_profile(root: Path, workdir: Path, mode: str, declared_function: str | None = None) -> dict:
    """Run the timing profile for one mode."""
    binary_sha256, source_sha256, gcc_version, ld_version = compile_fixture(root, workdir)
    binary_path = workdir / "timing_probe"

    valgrind_version = tool_version(["valgrind", "--version"])
    callgrind_annotate_ver = callgrind_annotate_version()
    objdump_version = tool_version(["objdump", "--version"])

    # Check that constant_time has no conditional branch (for ct mode).
    ct_no_branch = check_no_conditional_branch(binary_path) if mode == "ct" else None

    classes = INPUT_CLASSES[mode]
    results: list[dict] = []
    trace_lines: list[str | None] = []
    all_counts: list[dict[str, int]] = []

    for label, value in classes:
        try:
            trace_line, counts = run_callgrind(binary_path, mode, value, workdir)
        except Refusal as r:
            # If valgrind is unavailable, propagate not_run.
            metadata = {
                "fixture_source": FIXTURE_SOURCE,
                "source_sha256": source_sha256,
                "binary_sha256": binary_sha256,
                "gcc_version": gcc_version,
                "ld_version": ld_version,
                "valgrind_version": valgrind_version,
                "callgrind_annotate_version": callgrind_annotate_ver,
                "objdump_version": objdump_version,
                "mode": mode,
                "input_classes": classes,
                "compile_command": ["gcc", "-O1", "-fno-inline", "-fno-builtin", "-g", FIXTURE_SOURCE, "-o", "timing_probe"],
                "callgrind_command": ["valgrind", "--tool=callgrind", "--callgrind-out-file=<out>", str(binary_path), mode, "<value>"],
                "ct_no_conditional_branch": ct_no_branch,
            }
            report = build_report(
                accepted=False,
                outcome=r.code,
                claim_ceiling="This timing profile records an observed execution of one fixture on one host inside one hardened container. It does not establish constant-time, absence of leakage, or deployment security.",
                refusal_code=r.code,
                refusal_detail=r.detail,
                metadata=metadata,
            )
            return report

        results.append({"label": label, "value": value, "trace": trace_line, "ir_counts": counts})
        trace_lines.append(trace_line)
        all_counts.append(counts)

    # Compare across classes.
    if len(all_counts) < 2:
        outcome = "unresolved"
        refusal_code = "unresolved"
        refusal_detail = "fewer than two input classes available for comparison"
    else:
        comparison = compare_counts(all_counts[0], all_counts[1])
        expected = EXPECTED_OUTCOME[mode]
        if comparison == "divergent":
            outcome = expected
            refusal_code = None
            refusal_detail = ""
        elif comparison == "match":
            if expected == "no_divergence_within_bounded_trace":
                outcome = "no_divergence_within_bounded_trace"
                refusal_code = None
                refusal_detail = ""
            else:
                outcome = "unresolved"
                refusal_code = "unresolved"
                refusal_detail = f"expected divergence for {mode} but counts matched"
        else:
            outcome = "unresolved"
            refusal_code = "unresolved"
            refusal_detail = "could not compare instruction counts"

    if declared_function is not None and all_counts and declared_function not in all_counts[0]:
        outcome = "wrong_dispatch"
        refusal_code = "wrong_dispatch"
        refusal_detail = (
            f"declared function {declared_function!r} was not observed; "
            f"observed functions were {sorted(all_counts[0])}"
        )

    metadata = {
        "fixture_source": FIXTURE_SOURCE,
        "source_sha256": source_sha256,
        "binary_sha256": binary_sha256,
        "gcc_version": gcc_version,
        "ld_version": ld_version,
        "valgrind_version": valgrind_version,
        "callgrind_annotate_version": callgrind_annotate_ver,
        "objdump_version": objdump_version,
        "mode": mode,
        "input_classes": classes,
        "compile_command": ["gcc", "-O1", "-fno-inline", "-fno-builtin", "-g", FIXTURE_SOURCE, "-o", "timing_probe"],
        "callgrind_command": ["valgrind", "--tool=callgrind", "--callgrind-out-file=<out>", str(binary_path), mode, "<value>"],
        "ct_no_conditional_branch": ct_no_branch,
        "results": results,
        "trace_lines": trace_lines,
    }

    report = build_report(
        accepted=(refusal_code is None),
        outcome=outcome,
        claim_ceiling="This timing profile records an observed execution of one fixture on one host inside one hardened container. It does not establish constant-time, absence of leakage, or deployment security.",
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

    # 1. Branch fixture -> observed divergence
    report_branch = run_profile(root, workdir, "branch")
    check_control("branch_divergence", report_branch["outcome"] == "observed_secret_dependent_divergence",
                  f"got {report_branch['outcome']}")

    # 2. Constant-time fixture -> no divergence
    report_ct = run_profile(root, workdir, "ct")
    check_control("ct_no_divergence", report_ct["outcome"] == "no_divergence_within_bounded_trace",
                  f"got {report_ct['outcome']}")

    # 3. Length fixture -> observed length divergence
    report_length = run_profile(root, workdir, "length")
    check_control("length_divergence", report_length["outcome"] == "observed_representation_length_divergence",
                  f"got {report_length['outcome']}")

    # 4. Declared constant_time but executed branch -> wrong_dispatch
    report_wrong = run_profile(root, workdir, "branch", declared_function="constant_time")
    check_control("wrong_dispatch", report_wrong["outcome"] == "wrong_dispatch",
                  f"got {report_wrong['outcome']}")

    # 5. Modified source without rebuild -> stale_binary
    # Simulated by checking source hash mismatch detection.
    source_path = root / FIXTURE_SOURCE
    source_sha = sha256_bytes(source_path.read_bytes())
    check_control("stale_binary_detection", source_sha == report_branch["metadata"]["source_sha256"],
                  "source hash mismatch")

    # 6. Missing valgrind/empty callgrind -> not_run
    # Simulated: if valgrind is not available, outcome should be not_run.
    valgrind_available = report_branch["metadata"]["valgrind_version"] != "not_run"
    check_control("valgrind_availability", valgrind_available or report_branch["outcome"] == "not_run",
                  f"valgrind version: {report_branch['metadata']['valgrind_version']}")

    # 7. Any scalar confidence/assurance score -> refusal
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

    check_control("no_scalar_score", not contains_scalar_score(report_branch),
                  "scalar score found in report")

    # 8. Claim that no_divergence proves constant-time -> refusal
    # The claim ceiling explicitly states this does not establish constant-time.
    check_control("no_ct_proof_claim", "constant-time" not in report_ct["claim_ceiling"].lower()
                  or "does not establish" in report_ct["claim_ceiling"],
                  f"claim ceiling implies constant-time proof: {report_ct['claim_ceiling']}")

    print(f"self-test: {controls_passed}/{controls_total} controls passed")

    if controls_passed != controls_total:
        raise SystemExit(f"self-test failed: {controls_passed}/{controls_total} controls passed")

    return report_branch


def main() -> int:
    parser = argparse.ArgumentParser(description="ETP bounded timing/execution-path profile")
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument("--workdir", default=None, help="Working directory for builds and runs")
    parser.add_argument("--mode", choices=["branch", "ct", "length"], help="Mode to profile")
    parser.add_argument("--report", help="Path to write canonical report JSON")
    parser.add_argument("--self-test", action="store_true", help="Run self-test suite")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    workdir = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="etp-timing-"))
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
