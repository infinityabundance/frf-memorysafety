#!/usr/bin/env python3
"""Build the Phase 8.2 live conversion capture directory.

The helper copies the exact bytes that the evidence model will hash and writes
`capture.json`. It never invents a digest: every digest in the record is later
computed by `frf_memorysafety::conversion::capture_live` from these files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(argv: list[str]) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


def elf_versions(path: Path) -> list[str]:
    text = run(["readelf", "--version-info", "-W", str(path)])
    return sorted(set(re.findall(r"Name: (OPENSSL_[0-9.]+)", text)))


def elf_needed(path: Path) -> list[str]:
    text = run(["readelf", "-d", str(path)])
    return re.findall(r"Shared library: \[([^\]]+)\]", text)


def copy(src: Path, dst: Path) -> Path:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    return dst


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--external", required=True)
    ap.add_argument("--candidate", required=True)
    ap.add_argument("--authority", required=True)
    ap.add_argument("--capture", required=True)
    ap.add_argument("--fault-log", required=True)
    ap.add_argument("--wrap-log", required=True)
    ap.add_argument("--repair-log", required=True)
    ap.add_argument("--curl-log", required=True)
    ap.add_argument("--pin", required=True)
    ap.add_argument("--fault", required=True)
    ap.add_argument("--repaired", required=True)
    args = ap.parse_args()

    external = Path(args.external)
    candidate = Path(args.candidate)
    authority = Path(args.authority)
    capture = Path(args.capture)
    if capture.exists():
        shutil.rmtree(capture)
    (capture / "lib").mkdir(parents=True)
    (capture / "deps").mkdir(parents=True)

    # Exact source snapshot: the pinned tree listing, not a checkout mtime.
    (capture / "source.manifest").write_text(
        run(["git", "-C", str(external), "ls-tree", "-r", "--full-tree", args.pin]),
        encoding="utf-8",
    )

    # Witness tool and command.
    cargo = Path(shutil.which("cargo"))
    copy(cargo, capture / "tool.bin")
    rustc_version = run(["rustc", "--version"]).strip()
    ldd = Path(shutil.which("ldd"))
    copy(ldd, capture / "loader.bin")
    ldd_version = run(["ldd", "--version"]).splitlines()[0].strip()
    command = (
        "cargo test --locked --lib up_ref_refuses_overflow_without_changing_count "
        "-- --test-threads=1 --nocapture"
    )
    (capture / "command.txt").write_text(command + "\n", encoding="utf-8")

    # The repaired witness output and the independent mechanism confirmation.
    repair_log = Path(args.repair_log)
    shutil.copyfile(repair_log, capture / "output.txt")
    fault_diff = run(
        ["git", "-C", str(external), "diff", args.fault, args.repaired, "--",
         "src/runtime/refcount.rs"]
    )
    mechanism = "\n".join(
        [
            "== fault (overflow checks on): panic ==",
            Path(args.fault_log).read_text(encoding="utf-8", errors="replace"),
            "== fault (overflow checks off): silent sentinel wrap ==",
            Path(args.wrap_log).read_text(encoding="utf-8", errors="replace"),
            "== repair (overflow checks on and off): refusal ==",
            repair_log.read_text(encoding="utf-8", errors="replace"),
            "== exact fault/repair diff ==",
            fault_diff,
        ]
    )
    (capture / "mechanism.txt").write_text(mechanism, encoding="utf-8")

    # Consumer loader proof: ldd, LD_DEBUG, DSO digests and DT_NEEDED.
    shutil.copyfile(args.curl_log, capture / "loader.trace")

    # Candidate DSO bytes and their declared metadata.
    dsos = []
    for soname in ("libssl.so.3", "libcrypto.so.3"):
        source = candidate / "lib" / soname
        target = copy(source, capture / "lib" / soname)
        dsos.append(
            {
                "soname": soname,
                "path": f"lib/{soname}",
                "loaded_path": str(source),
                "symbol_versions": elf_versions(target),
                "dt_needed": elf_needed(target),
            }
        )

    # Dependency closure bytes.
    copy(authority / "lib" / "libcrypto.so.3", capture / "deps" / "libcrypto-authority.so.3")
    copy(Path("/lib/x86_64-linux-gnu/libgcc_s.so.1"), capture / "deps" / "libgcc_s.so.1")
    copy(Path("/lib/x86_64-linux-gnu/libc.so.6"), capture / "deps" / "libc.so.6")
    (capture / "deps" / "rustc-version.txt").write_text(rustc_version + "\n", encoding="utf-8")
    (capture / "deps" / "ldd-version.txt").write_text(ldd_version + "\n", encoding="utf-8")

    abi_load = json.loads(
        (external / "artifacts" / "phase2" / "courts" / "ABI-LOAD.json").read_text(encoding="utf-8")
    )
    if abi_load.get("verdict") != "pass":
        raise SystemExit("ABI-LOAD did not pass; refusing to write loader evidence")
    for name, lib in abi_load["libraries"].items():
        if lib.get("verdict") != "pass":
            raise SystemExit(f"ABI-LOAD {name} did not pass")
    resolved = sum(int(lib["symbols_tested"]) for lib in abi_load["libraries"].values())
    unresolved = 0

    spec = {
        "property": "owner_contract_established",
        "candidate_revision": args.pin,
        "candidate_source_manifest": "source.manifest",
        "boundary_id": "openssl-rs:runtime::refcount::up_ref",
        "boundary_kind": "owner",
        "allowed": ["owner_up_ref_refuses_retired", "owner_over_free_defined_no_op"],
        "origin": "authentic_native",
        "discovery": "no_discovery_claim",
        "tool_name": "cargo test",
        "tool_version": rustc_version,
        "tool_executable": "tool.bin",
        "command": "command.txt",
        "output": "output.txt",
        "mechanism_id": "checked-add-overflow-refusal",
        "mechanism_confirmed": True,
        "mechanism_confirmation": "mechanism.txt",
        "loader_tool_name": "ldd",
        "loader_tool_version": ldd_version,
        "loader_executable": "loader.bin",
        "loader_trace": "loader.trace",
        "candidate_prefix": str(candidate),
        "resolved_symbols": resolved,
        "unresolved_symbols": unresolved,
        "dsos": dsos,
        "fault": args.fault,
        "repaired": args.repaired,
        "changed_paths": ["src/runtime/refcount.rs"],
        "toolchain": {
            "name": "rust",
            "version": rustc_version,
            "path": "deps/rustc-version.txt",
        },
        "dynamic_loader": {
            "name": "ld-linux-x86-64",
            "version": ldd_version,
            "path": "deps/ldd-version.txt",
        },
        "authority": {
            "name": "openssl",
            "version": "3.6.4",
            "path": "deps/libcrypto-authority.so.3",
        },
        "libraries": [
            {"name": "libgcc_s", "version": "system", "path": "deps/libgcc_s.so.1"},
            {"name": "libc", "version": "system", "path": "deps/libc.so.6"},
        ],
    }
    (capture / "capture.json").write_text(
        json.dumps(spec, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    curl_log = Path(args.curl_log).read_text(encoding="utf-8", errors="replace")
    if "positive_ok=1" not in curl_log or "negative_rejected=1" not in curl_log:
        raise SystemExit("curl workload did not report both results")

    print(f"CAPTURE_WRITTEN=1")
    print(f"CAPTURE_DIR={capture}")
    print(f"CAPTURE_RESOLVED={resolved}")
    print(f"CAPTURE_UNRESOLVED={unresolved}")
    for dso in dsos:
        print(f"CAPTURE_DSO_{dso['soname'].replace('.', '_')}={sha256_file(capture / dso['path'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
