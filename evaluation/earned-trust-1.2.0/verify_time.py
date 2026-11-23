#!/usr/bin/env python3
"""Independent RFC 3161 timestamp verifier and negative controls.

This verifier uses the OpenSSL CLI and the Python standard library only. It
does not import or execute the Rust implementation. A verified token establishes
only that the pinned TSA signed a token whose message imprint equals the declared
digest at the token generation time. It does not establish source creation,
experimental execution, evidence production, transparency inclusion, witness
observation, release authorization, or correction time.

Exit statuses: 0 verified and all controls passed, 3 integrity failure, 4 refused.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

POLICY_OID = "1.3.6.1.4.1.99999.1"
FUTURE_SKEW = 300


class VerifierError(Exception):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(args, check=False, capture_output=True, cwd=cwd)
    except FileNotFoundError as error:
        raise VerifierError(f"cannot execute {args[0]}: {error}") from error


def pem_to_der(pem: bytes) -> bytes:
    lines = pem.decode("ascii", "replace").splitlines()
    inside = False
    collected: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("-----BEGIN"):
            inside = True
            continue
        if stripped.startswith("-----END"):
            break
        if inside:
            collected.append(stripped)
    if not collected:
        raise VerifierError("pinned certificate is not PEM")
    return base64.b64decode("".join(collected))


def certificate_sha256(path: Path) -> str:
    return sha256_bytes(pem_to_der(path.read_bytes()))


def parse_message_data(text: str) -> str | None:
    started = False
    hex_digits: list[str] = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("Message data:"):
            started = True
            continue
        if not started:
            continue
        if stripped.startswith("Serial number:") or stripped.startswith("Time stamp:"):
            break
        if len(stripped) < 8 or stripped[4] != " ":
            continue
        chunk = stripped[7:][:48]
        row = "".join(ch for ch in chunk if ch in "0123456789abcdefABCDEF").lower()
        if len(row) % 2 == 0:
            hex_digits.append(row)
    value = "".join(hex_digits)
    return value or None


MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def days_from_civil(year: int, month: int, day: int) -> int:
    year = year - 1 if month <= 2 else year
    era = (year if year >= 0 else year - 399) // 400
    year_of_era = year - era * 400
    shifted = (month + 9) % 12
    day_of_year = (153 * shifted + 2) // 5 + day - 1
    day_of_era = year_of_era * 365 + year_of_era // 4 - year_of_era // 100 + day_of_year
    return era * 146097 + day_of_era - 719468


def parse_openssl_time(text: str) -> int | None:
    match = re.fullmatch(
        r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\s+(GMT|UTC)",
        text.strip(),
    )
    if not match:
        return None
    month = MONTHS.get(match.group(1))
    if month is None:
        return None
    day = int(match.group(2))
    hour = int(match.group(3))
    minute = int(match.group(4))
    second = int(match.group(5))
    year = int(match.group(6))
    if not (1 <= day <= 31 and hour <= 23 and minute <= 59 and second <= 60):
        return None
    days = days_from_civil(year, month, day)
    if days < 0:
        return None
    return days * 86400 + hour * 3600 + minute * 60 + second


def field(text: str, prefix: str) -> str | None:
    for line in text.splitlines():
        if line.startswith(prefix):
            value = line[len(prefix) :].strip()
            return value or None
    return None


def parse_reply(text: str) -> dict[str, object] | None:
    if "Status: Granted." not in text:
        return None
    gen_text = field(text, "Time stamp:")
    gen = parse_openssl_time(gen_text) if gen_text else None
    if gen is None:
        return None
    return {
        "policy_oid": field(text, "Policy OID:"),
        "hash_algorithm": field(text, "Hash Algorithm:"),
        "imprint": parse_message_data(text),
        "serial": (field(text, "Serial number:") or "").removeprefix("0x").lower()
        or None,
        "gen_time_unix": gen,
        "gen_time_text": gen_text,
        "accuracy": field(text, "Accuracy:"),
        "ordering": field(text, "Ordering:"),
        "tsa_name": field(text, "TSA:"),
    }


def classify(stderr: str) -> str:
    lower = stderr.lower()
    if "message imprint mismatch" in lower:
        return "imprint_mismatch"
    if "expired" in lower:
        return "expired_tsa"
    if "certificate verify error" in lower or "unable to get" in lower:
        return "untrusted_tsa"
    if "policy" in lower and "not acceptable" in lower:
        return "policy_oid_mismatch"
    return "invalid_token"


def verify(
    token: Path,
    imprint: str,
    tsa_cert: Path | None,
    policy_oid: str | None,
    now: int,
    declared: int | None,
    verify_at: int | None,
    work: Path,
) -> dict[str, object]:
    if not token.is_file():
        return {
            "status": "integrity_failure",
            "refusals": ["missing_token"],
            "detail": f"missing token {token}",
        }
    token_bytes = token.read_bytes()
    reply = run(["openssl", "ts", "-reply", "-in", str(token), "-text", "-token_in"])
    info = parse_reply(reply.stdout.decode("utf-8", "replace"))
    if info is None:
        return {
            "status": "integrity_failure",
            "refusals": ["invalid_token"],
            "detail": reply.stderr.decode("utf-8", "replace").strip(),
        }
    gen = int(info["gen_time_unix"])
    refusals: list[str] = []
    if info["imprint"] != imprint:
        refusals.append("imprint_mismatch")
    if info["hash_algorithm"] != "sha256":
        refusals.append("hash_algorithm_mismatch")
    if policy_oid is not None and info["policy_oid"] != policy_oid:
        refusals.append("policy_oid_mismatch")
    if gen > now + FUTURE_SKEW:
        refusals.append("future_timestamp")
    if tsa_cert is None:
        refusals.append("no_trust_anchor")
        chain = "not_checked"
    else:
        attime = verify_at if verify_at is not None else gen
        args = [
            "openssl",
            "ts",
            "-verify",
            "-token_in",
            "-in",
            str(token),
            "-digest",
            imprint,
            "-CAfile",
            str(tsa_cert),
            "-attime",
            str(attime),
        ]
        if policy_oid is not None:
            args.extend(["-policy", policy_oid])
        checked = run(args)
        output = (checked.stdout + checked.stderr).decode("utf-8", "replace")
        if checked.returncode == 0 and "Verification: OK" in checked.stdout.decode(
            "utf-8", "replace"
        ):
            chain = "valid"
        else:
            chain = "invalid"
            refusals.append(classify(output))
    classification = "not_requested"
    if declared is not None:
        if declared < gen:
            classification = "declared_precedes_timestamp"
            refusals.append("backdated_claim")
        elif declared == gen:
            classification = "declared_equals_timestamp"
        else:
            classification = "declared_follows_timestamp"
            refusals.append("execution_time_not_established")
    unique = sorted(set(refusals))
    return {
        "status": "verified" if not unique and chain == "valid" else "refused",
        "refusals": unique,
        "token_sha256": sha256_bytes(token_bytes),
        "imprint_expected": imprint,
        "imprint_in_token": info["imprint"],
        "hash_algorithm": info["hash_algorithm"],
        "policy_oid": info["policy_oid"],
        "serial": info["serial"],
        "gen_time_unix": gen,
        "gen_time_text": info["gen_time_text"],
        "tsa_cert_sha256": certificate_sha256(tsa_cert) if tsa_cert else None,
        "signature_chain": chain,
        "trust_domain": "local-test-tsa",
        "external_trust": False,
        "execution_time_established": False,
        "backdating": classification,
        "declared_execution_unix": declared,
        "work_dir": str(work),
    }


def generate_unrelated_ca(work: Path) -> Path:
    key = work / "other.key"
    cert = work / "other.crt"
    run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)])
    run(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-key",
            str(key),
            "-out",
            str(cert),
            "-days",
            "2",
            "-sha256",
            "-subj",
            "/CN=Unrelated Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ]
    )
    return cert


def expect(name: str, result: dict[str, object], required: str | None) -> bool:
    refusals = result.get("refusals", [])
    if required is None:
        ok = result.get("status") == "verified" and not refusals
    else:
        ok = result.get("status") in {"refused", "integrity_failure"} and required in refusals
    print(f"{'PASS' if ok else 'FAIL'} control {name}: {result.get('status')} {refusals}")
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token", type=Path, required=True)
    parser.add_argument("--imprint", required=True)
    parser.add_argument("--tsa-cert", type=Path)
    parser.add_argument("--policy-oid", default=POLICY_OID)
    parser.add_argument("--now", type=int, default=None)
    parser.add_argument("--declared-execution-unix", type=int, default=None)
    parser.add_argument("--verify-at-unix", type=int, default=None)
    parser.add_argument("--controls", action="store_true")
    args = parser.parse_args()

    now = args.now if args.now is not None else int(time.time())
    with tempfile.TemporaryDirectory(prefix="etp-time-verify-") as temporary:
        work = Path(temporary)
        result = verify(
            args.token,
            args.imprint,
            args.tsa_cert,
            args.policy_oid,
            now,
            args.declared_execution_unix,
            args.verify_at_unix,
            work,
        )
        print(
            f"timestamp: {result['status']}; chain={result.get('signature_chain')}; "
            f"trust_domain={result.get('trust_domain')}; "
            f"gen_time={result.get('gen_time_unix')}"
        )
        if result.get("refusals"):
            print(f"refusals: {', '.join(result['refusals'])}")
        if not args.controls:
            return 0 if result["status"] == "verified" else (
                3 if result["status"] == "integrity_failure" else 4
            )

        passed = 0
        total = 0
        total += 1
        passed += expect("valid token", result, None)
        total += 1
        passed += expect(
            "wrong imprint",
            verify(
                args.token,
                "0" * 64,
                args.tsa_cert,
                args.policy_oid,
                now,
                None,
                None,
                work,
            ),
            "imprint_mismatch",
        )
        total += 1
        passed += expect(
            "untrusted TSA",
            verify(
                args.token,
                args.imprint,
                generate_unrelated_ca(work),
                args.policy_oid,
                now,
                None,
                None,
                work,
            ),
            "untrusted_tsa",
        )
        gen = result.get("gen_time_unix")
        if isinstance(gen, int):
            total += 1
            passed += expect(
                "expired TSA",
                verify(
                    args.token,
                    args.imprint,
                    args.tsa_cert,
                    args.policy_oid,
                    now,
                    None,
                    gen + 10 * 365 * 24 * 60 * 60,
                    work,
                ),
                "expired_tsa",
            )
            total += 1
            passed += expect(
                "backdated claim",
                verify(
                    args.token,
                    args.imprint,
                    args.tsa_cert,
                    args.policy_oid,
                    now,
                    gen - 86400,
                    None,
                    work,
                ),
                "backdated_claim",
            )
        total += 1
        passed += expect(
            "missing token",
            verify(
                work / "missing.tsr",
                args.imprint,
                args.tsa_cert,
                args.policy_oid,
                now,
                None,
                None,
                work,
            ),
            "missing_token",
        )
        print(f"controls passed: {passed} of {total}")
        return 0 if passed == total else 4


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerifierError as error:
        print(f"verify_time: {error}", file=sys.stderr)
        raise SystemExit(3) from error
