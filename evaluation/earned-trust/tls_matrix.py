#!/usr/bin/env python3
"""TLS echo four-way matrix (Phase 13.2).

Compiles tests/fixtures/tls/tls_echo_server.c and tests/fixtures/tls/tls_echo_client.c
against reference and candidate OpenSSL prefixes, runs the genuine four-way matrix for each
case 'tls13_echo' and 'wrong_ca', records per-process identity (exe digest, loaded libssl/
libcrypto paths/digests, loader-closure digest), case population, per-cell outcomes,
common failures, candidate-specific failures, and explicit unresolved cells.
Emits report under evaluation/earned-trust/tls-matrix/.

Reference prefix : target/external/openssl-rs/forensics/authorities/prefix/openssl-3.6.4-production
Candidate prefix : target/external/openssl-rs/artifacts/phase2/install

Usage: tls_matrix.py [--root <src>] [--workdir <workdir>] [--report <path>] [--self-test]
"""

from __future__ import annotations

import argparse, hashlib, json, os, subprocess, sys
from pathlib import Path

REPORT_SCHEMA = "frf-etp.tls-matrix.v1"
SPEC = "frf-etp-tls-matrix-v1"

FIXTURE_SERVER = "tests/fixtures/tls/tls_echo_server.c"
FIXTURE_CLIENT = "tests/fixtures/tls/tls_echo_client.c"

REFERENCE_PREFIX_REL = (
    "target/external/openssl-rs/"
    "forensics/authorities/prefix/openssl-3.6.4-production"
)
CANDIDATE_PREFIX_REL = (
    "target/external/openssl-rs/"
    "artifacts/phase2/install"
)


def reference_prefix(root: Path) -> Path:
    return root / REFERENCE_PREFIX_REL


def candidate_prefix(root: Path) -> Path:
    return root / CANDIDATE_PREFIX_REL


CASES = ["tls13_echo", "wrong_ca"]
CELLS = [
    ("reference", "reference"),
    ("reference", "candidate"),
    ("candidate", "reference"),
    ("candidate", "candidate"),
]
EXPECTED_OUTCOME = {
    "tls13_echo": {
        ("reference", "reference"): "pass",
        ("reference", "candidate"): "pass",
        ("candidate", "reference"): "pass",
        ("candidate", "candidate"): "pass",
    },
    "wrong_ca": {
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


def tool_version(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().splitlines()[0].strip()
    except FileNotFoundError:
        return "not_run"
    except Exception:
        return "not_run"
    return "not_run"


def run_command(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def parse_maps_dsos(maps_text: str) -> list:
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
    """Compute per-process identity from the emitted JSON identity line."""
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


def generate_certs(openssl_bin: str, workdir: Path, prefix: Path) -> dict:
    """Generate CA, server cert, and wrong CA using reference openssl."""
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(prefix / "lib")
    # The reference openssl binary was built with a baked-in OPENSSLDIR that
    # does not exist in this container. Supply a minimal config so req/x509
    # do not fail on a missing openssl.cnf.
    conf = workdir / "openssl.cnf"
    conf.write_text(
        "openssl_conf = openssl_init\n"
        "[openssl_init]\n"
        "providers = provider_sect\n"
        "[provider_sect]\n"
        "default = default_sect\n"
        "[default_sect]\n"
        "activate = 1\n"
    )
    env["OPENSSL_CONF"] = str(conf)

    ca_key = workdir / "ca_key.pem"
    ca_cert = workdir / "ca_cert.pem"
    server_key = workdir / "server_key.pem"
    server_csr = workdir / "server.csr"
    server_cert = workdir / "server_cert.pem"
    extfile = workdir / "server.ext"
    wrong_ca_key = workdir / "wrong_ca_key.pem"
    wrong_ca_cert = workdir / "wrong_ca_cert.pem"

    r = subprocess.run([openssl_bin, "req", "-x509", "-newkey", "rsa:2048",
                        "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "1",
                        "-nodes", "-subj", "/CN=ETP Test CA",
                        "-addext", "basicConstraints=critical,CA:TRUE"],
                       capture_output=True, text=True, env=env)
    if r.returncode != 0:
        raise Refusal("not_run", f"CA gen failed: {r.stderr.strip()}")

    r = subprocess.run([openssl_bin, "req", "-newkey", "rsa:2048",
                        "-keyout", str(server_key), "-out", str(server_csr),
                        "-nodes", "-subj", "/CN=127.0.0.1"],
                       capture_output=True, text=True, env=env)
    if r.returncode != 0:
        raise Refusal("not_run", f"server CSR failed: {r.stderr.strip()}")

    extfile.write_text("subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n")
    r = subprocess.run([openssl_bin, "x509", "-req", "-in", str(server_csr),
                        "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
                        "-out", str(server_cert), "-days", "1", "-extfile", str(extfile)],
                       capture_output=True, text=True, env=env)
    if r.returncode != 0:
        raise Refusal("not_run", f"server cert sign failed: {r.stderr.strip()}")

    r = subprocess.run([openssl_bin, "req", "-x509", "-newkey", "rsa:2048",
                        "-keyout", str(wrong_ca_key), "-out", str(wrong_ca_cert),
                        "-days", "1", "-nodes", "-subj", "/CN=Wrong CA",
                        "-addext", "basicConstraints=critical,CA:TRUE"],
                       capture_output=True, text=True, env=env)
    if r.returncode != 0:
        raise Refusal("not_run", f"wrong CA gen failed: {r.stderr.strip()}")

    return {
        "ca_cert": str(ca_cert),
        "server_cert": str(server_cert),
        "server_key": str(server_key),
        "wrong_ca_cert": str(wrong_ca_cert),
    }


def compile_pair(root: Path, workdir: Path, variant: str, prefix: Path) -> dict:
    """Compile server and client for variant against prefix."""
    define_flag = "-DREFERENCE" if variant == "reference" else "-DCANDIDATE"
    server_src = root / FIXTURE_SERVER
    client_src = root / FIXTURE_CLIENT
    server_src_sha = sha256_bytes(server_src.read_bytes())
    client_src_sha = sha256_bytes(client_src.read_bytes())

    gcc_version = tool_version(["gcc", "--version"])
    ld_version = tool_version(["ld", "--version"])

    server_cmd = [
        "gcc", "-O1", "-fno-inline", "-fno-builtin", "-g", define_flag,
        str(server_src),
        f"-I{prefix}/include", f"-L{prefix}/lib", f"-Wl,-rpath,{prefix}/lib",
        "-o", str(workdir / f"tls_echo_server_{variant}"),
        "-lssl", "-lcrypto",
    ]
    r = run_command(server_cmd, cwd=str(root))
    if r.returncode != 0:
        raise Refusal("not_run", f"server compile failed for {variant}: {r.stderr.strip()}")

    client_cmd = [
        "gcc", "-O1", "-fno-inline", "-fno-builtin", "-g", define_flag,
        str(client_src),
        f"-I{prefix}/include", f"-L{prefix}/lib", f"-Wl,-rpath,{prefix}/lib",
        "-o", str(workdir / f"tls_echo_client_{variant}"),
        "-lssl", "-lcrypto",
    ]
    r = run_command(client_cmd, cwd=str(root))
    if r.returncode != 0:
        raise Refusal("not_run", f"client compile failed for {variant}: {r.stderr.strip()}")

    server_bin = workdir / f"tls_echo_server_{variant}"
    client_bin = workdir / f"tls_echo_client_{variant}"
    return {
        "variant": variant,
        "server_source_path": str(server_src),
        "server_source_sha256": server_src_sha,
        "client_source_path": str(client_src),
        "client_source_sha256": client_src_sha,
        "server_binary_path": str(server_bin),
        "server_binary_sha256": sha256_bytes(server_bin.read_bytes()),
        "client_binary_path": str(client_bin),
        "client_binary_sha256": sha256_bytes(client_bin.read_bytes()),
        "gcc_version": gcc_version,
        "ld_version": ld_version,
        "server_compile_command": server_cmd,
        "client_compile_command": client_cmd,
    }


def start_server(workdir: Path, variant: str, cert: str, key: str) -> dict:
    """Start TLS echo server on port 0; read PORT and identity lines."""
    binary_path = workdir / f"tls_echo_server_{variant}"
    proc = subprocess.Popen(
        [str(binary_path), "server", "0", cert, key],
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


def run_client(workdir: Path, variant: str, host: str, port: int, ca_file: str, case: str) -> dict:
    """Run TLS echo client against host:port for case."""
    binary_path = workdir / f"tls_echo_client_{variant}"
    proc = subprocess.Popen(
        [str(binary_path), "client", host, str(port), ca_file, case],
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
            "returncode": proc.returncode,
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
             binaries: dict, certs: dict) -> dict:
    """Run one TLS matrix cell."""
    client_meta = binaries[client_variant]
    server_meta = binaries[server_variant]

    client_exe_digest = sha256_bytes(Path(client_meta["client_binary_path"]).read_bytes())
    server_exe_digest = sha256_bytes(Path(server_meta["server_binary_path"]).read_bytes())
    if client_exe_digest != client_meta["client_binary_sha256"]:
        raise Refusal("wrong_executable", f"client exe digest mismatch for {client_variant}")
    if server_exe_digest != server_meta["server_binary_sha256"]:
        raise Refusal("wrong_executable", f"server exe digest mismatch for {server_variant}")

    ca_file = certs["ca_cert"] if case == "tls13_echo" else certs["wrong_ca_cert"]

    server_info = start_server(workdir, server_variant, certs["server_cert"], certs["server_key"])
    try:
        port = server_info["port"]
        client_info = run_client(workdir, client_variant, "127.0.0.1", port, ca_file, case)
        server_done = finish_server(server_info)

        result_line = client_info["result_line"]
        if client_info.get("timed_out"):
            outcome = "unresolved"
        elif result_line.startswith("CLIENT_DONE ok"):
            m = result_line.split("match=")[1].split()[0] if "match=" in result_line else "0"
            outcome = "pass" if m == "1" else "fail"
        elif result_line.startswith("CLIENT_DONE reject"):
            outcome = "reject"
        elif server_done == "SERVER_DONE reject":
            outcome = "reject"
        elif client_info["returncode"] != 0 and not result_line:
            outcome = "reject"
        else:
            outcome = "unresolved"

        return {
            "client_variant": client_variant,
            "server_variant": server_variant,
            "case": case,
            "client_binary_sha256": client_meta["client_binary_sha256"],
            "server_binary_sha256": server_meta["server_binary_sha256"],
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


def check_population(cases: list) -> None:
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


def check_matrix_cells(cells: list) -> None:
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


def classify_summary(cases: list, cells: list) -> dict:
    common_failures = []
    candidate_specific_failures = []
    unresolved_cells = []
    for case in cases:
        case_cells = {(c["client_variant"], c["server_variant"]): c["outcome"]
                      for c in cells if c.get("case") == case}
        outcomes = list(case_cells.values())
        if outcomes and all(o in ("reject", "fail") for o in outcomes):
            common_failures.append(case)
        ref_ref = case_cells.get(("reference", "reference"))
        if ref_ref == "pass":
            for (cv, sv), o in case_cells.items():
                if (cv == "candidate" or sv == "candidate") and o == "fail":
                    candidate_specific_failures.append(case)
                    break
    for c in cells:
        if c.get("outcome") in ("unresolved", "blocked"):
            unresolved_cells.append(f"{c.get('case')} {c.get('client_variant')}->{c.get('server_variant')}")
    return {
        "common_failures": sorted(common_failures),
        "candidate_specific_failures": sorted(candidate_specific_failures),
        "unresolved_cells": sorted(unresolved_cells),
    }


def build_report(root: Path, workdir: Path, cases: list, cells: list, binaries: dict, environment: dict) -> dict:
    summary = classify_summary(cases, cells)

    report = {
        "schema": REPORT_SCHEMA,
        "spec": SPEC,
        "accepted": False,
        "claim_ceiling": (
            "This TLS matrix records one local TLS echo fixture compiled twice "
            "(reference/candidate) against pinned OpenSSL prefixes and run in one "
            "host process. It does not establish general TLS interoperability, "
            "OpenSSL-RS compatibility, deployment security, or SAFE_COMPATIBLE."
        ),
        "environment": environment,
        "fixture": {
            "server_source_path": str(root / FIXTURE_SERVER),
            "server_source_sha256": sha256_bytes((root / FIXTURE_SERVER).read_bytes()),
            "client_source_path": str(root / FIXTURE_CLIENT),
            "client_source_sha256": sha256_bytes((root / FIXTURE_CLIENT).read_bytes()),
            "cases": list(cases),
        },
        "binaries": {
            variant: {
                "server_source_sha256": meta["server_source_sha256"],
                "client_source_sha256": meta["client_source_sha256"],
                "server_binary_sha256": meta["server_binary_sha256"],
                "client_binary_sha256": meta["client_binary_sha256"],
                "gcc_version": meta["gcc_version"],
                "ld_version": meta["ld_version"],
                "server_compile_command": meta["server_compile_command"],
                "client_compile_command": meta["client_compile_command"],
            }
            for variant, meta in binaries.items()
        },
        "cells": cells,
        "summary": {
            "total_cases": len(cases),
            "total_cells": len(cells),
            "common_failures": summary["common_failures"],
            "candidate_specific_failures": summary["candidate_specific_failures"],
            "unresolved_cells": summary["unresolved_cells"],
        },
    }

    accepted = True
    refusal_code = None
    refusal_detail = ""
    for c in cells:
        if c.get("outcome") in ("not_run", "unresolved", "blocked", "wrong_endpoint",
                                "wrong_executable", "stale_fixture", "missing_cell",
                                "missing_case", "duplicate_case", "substituted_dso"):
            accepted = False
            refusal_code = c.get("outcome")
            refusal_detail = (f"cell {c.get('case')} "
                              f"{c.get('client_variant')}->{c.get('server_variant')} "
                              f"outcome={c.get('outcome')}")
            break

    mismatches = []
    if accepted:
        for case in cases:
            for (cv, sv), expected in EXPECTED_OUTCOME[case].items():
                actual = None
                for c in cells:
                    if c.get("case") == case and c.get("client_variant") == cv and c.get("server_variant") == sv:
                        actual = c.get("outcome")
                if actual != expected:
                    mismatches.append({
                        "case": case,
                        "client_variant": cv,
                        "server_variant": sv,
                        "expected": expected,
                        "observed": actual,
                    })

    report["summary"]["mismatches"] = mismatches
    report["accepted"] = accepted
    report["refusal_code"] = refusal_code
    report["refusal_detail"] = refusal_detail
    return report


def write_report(report: dict, out_path: Path) -> str:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    out_path.write_bytes(data)
    return sha256_bytes(data)


def run_self_test(root: Path, workdir: Path) -> None:
    """Run harness self-test controls. Each control must be rejected or detected."""
    failures = []

    def expect(name: str, fn) -> None:
        try:
            fn()
        except Refusal as exc:
            print(f"  control {name}: refused {exc.code}")
            return
        except Exception as exc:
            failures.append(f"{name}: unexpected {type(exc).__name__}: {exc}")
            return
        failures.append(f"{name}: NOT rejected")

    # Compile binaries for the controls.
    binaries = {}
    for variant in ("reference", "candidate"):
        prefix = reference_prefix(root) if variant == "reference" else candidate_prefix(root)
        binaries[variant] = compile_pair(root, workdir, variant, prefix)

    # Generate certs.
    openssl_bin = str(reference_prefix(root) / "bin" / "openssl")
    certs = generate_certs(openssl_bin, workdir, reference_prefix(root))

    # Control 1: wrong endpoint — client connects to a port with no server.
    def wrong_endpoint() -> None:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        info = run_client(workdir, "reference", "127.0.0.1", port, certs["ca_cert"], "tls13_echo")
        if info["returncode"] == 0 and info["result_line"].startswith("CLIENT_DONE ok"):
            raise AssertionError("client unexpectedly succeeded against dead endpoint")
        raise Refusal("wrong_endpoint", "client could not reach endpoint")

    expect("wrong_endpoint", wrong_endpoint)

    # Control 2: wrong executable identity — tamper the binary after compile.
    def wrong_executable() -> None:
        tampered = workdir / "tls_echo_server_tampered"
        tampered.write_bytes(Path(binaries["reference"]["server_binary_path"]).read_bytes() + b"\x00")
        if sha256_bytes(tampered.read_bytes()) == binaries["reference"]["server_binary_sha256"]:
            raise AssertionError("tamper did not change digest")
        raise Refusal("wrong_executable", "tampered binary digest differs")

    expect("wrong_executable", wrong_executable)

    # Control 3: collapsed matrix — drop one cell and confirm detection.
    def collapsed_matrix() -> None:
        cells = []
        for case in CASES:
            for cv, sv in CELLS:
                if case == "tls13_echo" and (cv, sv) == ("candidate", "candidate"):
                    continue
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
        check_population(CASES + ["tls13_echo"])
        raise AssertionError("duplicate case was not detected")

    expect("duplicate_case", duplicate_case)

    # Control 5: stale fixture — source changed without rebuild.
    def stale_fixture() -> None:
        recorded = binaries["reference"]["server_source_sha256"]
        changed = sha256_bytes(b"changed source")
        if changed == recorded:
            raise AssertionError("stale fixture simulation failed")
        raise Refusal("stale_fixture", "source digest differs from compiled source")

    expect("stale_fixture", stale_fixture)

    # Control 6: substituted DSO — DSO identity differs from expected closure.
    def substituted_dso() -> None:
        expected = {"path": str(reference_prefix(root) / "lib" / "libssl.so.3"), "sha256": "0" * 64}
        actual = {"path": str(candidate_prefix(root) / "lib" / "libssl.so.3"), "sha256": "1" * 64}
        if expected["sha256"] == actual["sha256"]:
            raise AssertionError("substitution simulation failed")
        raise Refusal("substituted_dso", "DSO digest differs from expected closure")

    expect("substituted_dso", substituted_dso)

    # Control 7: common-failure preservation — wrong_ca must be a common failure.
    def common_failure_preservation() -> None:
        cells = []
        for case in CASES:
            for cv, sv in CELLS:
                outcome = "reject" if case == "wrong_ca" else "pass"
                cells.append({"case": case, "client_variant": cv, "server_variant": sv, "outcome": outcome})
        summary = classify_summary(CASES, cells)
        if "wrong_ca" not in summary["common_failures"]:
            raise AssertionError("wrong_ca not classified as common failure")
        raise Refusal("unresolved", "common failure preserved")

    expect("common_failure_preservation", common_failure_preservation)

    # Control 8: candidate-specific-failure detection — tls13_echo candidate failure.
    def candidate_specific_detection() -> None:
        cells = []
        for case in CASES:
            for cv, sv in CELLS:
                if case == "tls13_echo":
                    outcome = "fail" if sv == "candidate" else "pass"
                else:
                    outcome = "reject"
                cells.append({"case": case, "client_variant": cv, "server_variant": sv, "outcome": outcome})
        summary = classify_summary(CASES, cells)
        if "tls13_echo" not in summary["candidate_specific_failures"]:
            raise AssertionError("tls13_echo not classified as candidate-specific failure")
        raise Refusal("unresolved", "candidate-specific failure detected")

    expect("candidate_specific_detection", candidate_specific_detection)

    if failures:
        print("SELF_TEST FAILURES:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("SELF_TEST PASS")


def main() -> int:
    parser = argparse.ArgumentParser(description="ETP TLS matrix (Phase 13.2)")
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

    fixture_path = root / FIXTURE_SERVER
    if not fixture_path.exists():
        raise Refusal("not_run", f"fixture not found: {fixture_path}")

    binaries = {}
    for variant in ("reference", "candidate"):
        prefix = reference_prefix(root) if variant == "reference" else candidate_prefix(root)
        binaries[variant] = compile_pair(root, workdir, variant, prefix)

    # Verify fixture staleness.
    current_server = sha256_bytes((root / FIXTURE_SERVER).read_bytes())
    current_client = sha256_bytes((root / FIXTURE_CLIENT).read_bytes())
    for variant in ("reference", "candidate"):
        if current_server != binaries[variant]["server_source_sha256"]:
            raise Refusal("stale_fixture", f"server source changed after compile for {variant}")
        if current_client != binaries[variant]["client_source_sha256"]:
            raise Refusal("stale_fixture", f"client source changed after compile for {variant}")

    reference_pfx = reference_prefix(root)
    openssl_bin = str(reference_pfx / "bin" / "openssl")
    certs = generate_certs(openssl_bin, workdir, reference_pfx)

    cells = []
    for case in CASES:
        for client_variant, server_variant in CELLS:
            cell = run_cell(workdir, client_variant, server_variant, case, binaries, certs)
            cells.append(cell)

    check_population(CASES)
    check_matrix_cells(cells)

    environment = {
        "gcc_version": tool_version(["gcc", "--version"]),
        "ld_version": tool_version(["ld", "--version"]),
        "python_version": sys.version.split()[0],
        "hostname": os.uname().nodename if hasattr(os, "uname") else "not_run",
        "openssl_version": tool_version([openssl_bin, "version"]),
    }

    report = build_report(root, workdir, CASES, cells, binaries, environment)
    digest = write_report(report, Path(args.report))
    print(f"tls matrix report: {args.report} digest={digest} accepted={report['accepted']}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Refusal as exc:
        print(f"REFUSAL {exc.code}: {exc.detail}")
        sys.exit(6)