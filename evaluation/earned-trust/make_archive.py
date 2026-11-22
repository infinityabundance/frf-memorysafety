#!/usr/bin/env python3
"""Build the Phase 10.4a durable offline archive.

The archive preserves the repository-relative `evaluation/earned-trust` layout so
the committed reconstructor and verifiers run unchanged from the archive root.
Every copied file is listed in `manifest.json` with its SHA-256, size, schema,
category, applicability, and observation time. The archive itself is verified by
`etp archive verify` and by the hardened gate.

Exit statuses: 0 built, 3 invalid input or integrity failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

SPEC = "frf-etp-v1"
MANIFEST_SCHEMA = "frf-etp.archive-manifest.v1"
EDGE = "evaluation/earned-trust"


def fail(message: str) -> None:
    print(f"make_archive: {message}", file=sys.stderr)
    raise SystemExit(3)


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(), object_pairs_hook=strict_object)
    except FileNotFoundError:
        fail(f"missing input {path}")
    except json.JSONDecodeError as error:
        fail(f"invalid JSON in {path}: {error}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def copy_object(
    root: Path,
    out: Path,
    objects: list[dict[str, object]],
    source: Path,
    destination: str,
    category: str,
    schema: str,
    required: bool,
    observed: int,
    applicability: str,
) -> None:
    if not source.is_file():
        fail(f"missing archive source {source}")
    target = out / destination
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    data = target.read_bytes()
    objects.append(
        {
            "path": destination,
            "sha256": sha256_bytes(data),
            "size": len(data),
            "schema": schema,
            "category": category,
            "applicability": applicability,
            "required": required,
            "observed_at_unix": observed,
        }
    )
    _ = root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--time-dir", type=Path, required=True)
    parser.add_argument("--revocation-dir", type=Path, required=True)
    parser.add_argument("--horizon-unix", type=int, required=True)
    args = parser.parse_args()

    root = args.root.resolve()
    out = args.out_dir.resolve()
    if out == root or root in out.parents and out.name == "evaluation":
        fail("refusing to replace the repository root")
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    objects: list[dict[str, object]] = []
    observed = args.horizon_unix

    def copy(
        source: Path,
        destination: str,
        category: str,
        schema: str,
        required: bool,
        applicability: str,
    ) -> None:
        copy_object(
            root,
            out,
            objects,
            source,
            destination,
            category,
            schema,
            required,
            observed,
            applicability,
        )

    base = root / EDGE
    copy(
        base / "protocol.json",
        f"{EDGE}/protocol.json",
        "opening_manifest",
        "frf-etp.campaign-protocol.v1",
        True,
        "frozen Phase 10.2 opening manifest",
    )
    copy(
        base / "opening.sha256",
        f"{EDGE}/opening.sha256",
        "opening_digest",
        "opaque-bytes",
        True,
        "frozen opening manifest digest sidecar",
    )
    copy(
        base / "MANIFEST.json",
        f"{EDGE}/MANIFEST.json",
        "closure_manifest",
        "frf-etp.campaign-closure.v1",
        True,
        "finite campaign closure",
    )
    copy(
        base / "CLAIMS.json",
        f"{EDGE}/CLAIMS.json",
        "claims",
        "frf-etp.campaign-claims.v1",
        True,
        "finite campaign claims",
    )
    copy(
        base / "campaign.sarif",
        f"{EDGE}/campaign.sarif",
        "sarif",
        "sarif-2.1.0",
        True,
        "SARIF 2.1.0 projection",
    )
    for path in sorted((base / "receipts").glob("*.json")):
        copy(
            path,
            f"{EDGE}/receipts/{path.name}",
            "receipt",
            "frf-etp.campaign-receipt.v1",
            True,
            "per-case typed receipt",
        )
    raw_dir = base / "receipts/raw"
    if not raw_dir.is_dir():
        fail("missing raw evidence directory")
    for path in sorted(raw_dir.rglob("*")):
        if path.is_file():
            relative = path.relative_to(raw_dir).as_posix()
            copy(
                path,
                f"{EDGE}/receipts/raw/{relative}",
                "raw_evidence",
                "opaque-bytes",
                True,
                "retained transcript or court report",
            )
    for name in [
        "campaign-closure.envelope.json",
        "campaign-closure.statement.json",
        "campaign-closure.public.pem",
    ]:
        schema = {
            "campaign-closure.envelope.json": "frf-etp.dsse-envelope.v1",
            "campaign-closure.statement.json": "frf-etp.in-toto-statement.v1",
            "campaign-closure.public.pem": "opaque-bytes",
        }[name]
        copy(
            base / "attestations" / name,
            f"{EDGE}/attestations/{name}",
            "attestation",
            schema,
            True,
            "committed test-only campaign closure attestation",
        )
    copy(
        base / "trust-policy.json",
        f"{EDGE}/trust-policy.json",
        "policy",
        "frf-etp.trust-policy.v1",
        True,
        "trust policy with the test-only correction authority",
    )

    time_dir = args.time_dir.resolve()
    for name, category, schema, applicability in [
        ("token.tsr", "time_token", "rfc3161-timestamp-token", "local test TSA token"),
        ("request.tsq", "time_request", "rfc3161-timestamp-request", "timestamp request"),
        ("tsa-ca.pem", "tsa_trust_anchor", "x509-certificate", "local test TSA CA"),
        ("tsa-cert.pem", "tsa_signer_certificate", "x509-certificate", "local test TSA signer"),
        (
            "time-report.json",
            "time_report",
            "frf-etp.time-verification.v1",
            "time verification dimensions and trust domain",
        ),
        (
            "openssl-version.txt",
            "time_tool_provenance",
            "opaque-bytes",
            "pinned OpenSSL version",
        ),
        (
            "evidence-imprint.txt",
            "time_imprint",
            "opaque-bytes",
            "SHA-256 imprint bound by the token",
        ),
    ]:
        copy(
            time_dir / name,
            f"{EDGE}/time/{name}",
            category,
            schema,
            True,
            applicability,
        )

    revocation_dir = args.revocation_dir.resolve()
    for name, category, schema, applicability in [
        (
            "registry.json",
            "revocation_registry",
            "frf-etp.revocation-registry.v1",
            "append-only correction and revocation registry",
        ),
        (
            "support-model.json",
            "support_model",
            "frf-etp.support-model.v1",
            "founded-support model",
        ),
        (
            "historical-verdict.json",
            "historical_verdict",
            "frf-etp.historical-verdict.v1",
            "historical verdict under the original policy",
        ),
        (
            "plan.json",
            "revocation_plan",
            "frf-etp.revocation-plan.v1",
            "declared revocation and correction plan",
        ),
        (
            "revocation-report.json",
            "revocation_report",
            "frf-etp.revocation-verification.v1",
            "revocation verification dimensions",
        ),
    ]:
        copy(
            revocation_dir / name,
            f"{EDGE}/revocations/{name}",
            category,
            schema,
            True,
            applicability,
        )

    for name in [
        "reconstruct.py",
        "verify_attestations.py",
        "verify_time.py",
        "verify_revocation.py",
        "verify_transparency.py",
    ]:
        copy(
            base / name,
            f"{EDGE}/{name}",
            "verifier",
            "python-source",
            True,
            "independent offline verifier",
        )

    transparency_dir = base / "transparency"
    for name, category, schema, applicability in [
        (
            "proof.json",
            "transparency_proof",
            "frf-etp.transparency-proof.v1",
            "local inclusion and consistency proof",
        ),
        (
            "checkpoint-size-1.txt",
            "transparency_checkpoint",
            "tlog-checkpoint-v1",
            "signed size-1 known horizon",
        ),
        (
            "checkpoint-size-3.txt",
            "transparency_checkpoint",
            "tlog-checkpoint-v1",
            "signed size-3 checkpoint",
        ),
        (
            "attestation-entry.bin",
            "transparency_entry",
            "frf-etp.dsse-envelope.v1",
            "exact leaf-0 entry bytes",
        ),
        (
            "policy.json",
            "transparency_policy",
            "frf-etp.transparency-policy.v1",
            "pinned local log identity and horizon",
        ),
        (
            "log-key.pub",
            "transparency_log_key",
            "opaque-bytes",
            "pinned local log public vkey",
        ),
        (
            "witness-state.json",
            "witness_state",
            "frf-etp.witness-state.v1",
            "committed not-observed witness state",
        ),
    ]:
        copy(
            transparency_dir / name,
            f"{EDGE}/transparency/{name}",
            category,
            schema,
            True,
            applicability,
        )

    imprint = sha256_bytes((base / "MANIFEST.json").read_bytes())
    reconstruction = f"""# Offline reconstruction

Images: `python:3.11-slim` (OpenSSL 3.5.7) and `rust:1.85.0-slim`
(OpenSSL 3.0.15). Run from the archive root with `--network=none`.

1. Campaign bookkeeping and artifact reconstruction:

```sh
python3 evaluation/earned-trust/reconstruct.py
```

2. Attestation verification and its executable controls:

```sh
python3 evaluation/earned-trust/verify_attestations.py \\
  --attestations evaluation/earned-trust/attestations \\
  --policy evaluation/earned-trust/trust-policy.json \\
  --campaign evaluation/earned-trust/MANIFEST.json --controls
```

3. Timestamp verification over the exact closure digest `{imprint}`:

```sh
python3 evaluation/earned-trust/verify_time.py \\
  --token evaluation/earned-trust/time/token.tsr \\
  --imprint {imprint} \\
  --tsa-cert evaluation/earned-trust/time/tsa-ca.pem \\
  --policy-oid 1.3.6.1.4.1.99999.1 --controls
```

4. Revocation and founded-support verification:

```sh
python3 evaluation/earned-trust/verify_revocation.py \\
  --registry evaluation/earned-trust/revocations/registry.json \\
  --policy evaluation/earned-trust/trust-policy.json \\
  --support evaluation/earned-trust/revocations/support-model.json \\
  --historical evaluation/earned-trust/revocations/historical-verdict.json --controls
```

5. Rust CLI verification:

```sh
./ci/etp-time-gate.sh
```

6. Local transparency proof and witness-model verification:

```sh
python3 evaluation/earned-trust/verify_transparency.py \\
  --dir evaluation/earned-trust/transparency --controls
```

Knowledge horizon: Unix `{observed}`. This archive is not an external anchor,
not a public transparency log, and not proof that the evidence is true.
"""
    reconstruction_path = out / EDGE / "RECONSTRUCTION.md"
    reconstruction_path.parent.mkdir(parents=True, exist_ok=True)
    reconstruction_path.write_text(reconstruction)
    objects.append(
        {
            "path": f"{EDGE}/RECONSTRUCTION.md",
            "sha256": sha256_bytes(reconstruction.encode("utf-8")),
            "size": len(reconstruction.encode("utf-8")),
            "schema": "markdown",
            "category": "reconstruction",
            "applicability": "exact offline reconstruction instructions",
            "required": True,
            "observed_at_unix": observed,
        }
    )

    commands = [
        {
            "purpose": "reconstruct the finite campaign bookkeeping",
            "working_directory": ".",
            "argv": ["python3", f"{EDGE}/reconstruct.py"],
            "requires": [f"{EDGE}/MANIFEST.json", f"{EDGE}/protocol.json", f"{EDGE}/reconstruct.py"],
        },
        {
            "purpose": "verify the committed attestation and run its controls",
            "working_directory": ".",
            "argv": [
                "python3",
                f"{EDGE}/verify_attestations.py",
                "--attestations",
                f"{EDGE}/attestations",
                "--policy",
                f"{EDGE}/trust-policy.json",
                "--campaign",
                f"{EDGE}/MANIFEST.json",
                "--controls",
            ],
            "requires": [
                f"{EDGE}/attestations/campaign-closure.envelope.json",
                f"{EDGE}/trust-policy.json",
                f"{EDGE}/MANIFEST.json",
                f"{EDGE}/verify_attestations.py",
            ],
        },
        {
            "purpose": "verify the RFC 3161 token and run its controls",
            "working_directory": ".",
            "argv": [
                "python3",
                f"{EDGE}/verify_time.py",
                "--token",
                f"{EDGE}/time/token.tsr",
                "--imprint",
                imprint,
                "--tsa-cert",
                f"{EDGE}/time/tsa-ca.pem",
                "--policy-oid",
                "1.3.6.1.4.1.99999.1",
                "--controls",
            ],
            "requires": [
                f"{EDGE}/time/token.tsr",
                f"{EDGE}/time/tsa-ca.pem",
                f"{EDGE}/verify_time.py",
            ],
        },
        {
            "purpose": "verify revocation, historical replay, and present authorization",
            "working_directory": ".",
            "argv": [
                "python3",
                f"{EDGE}/verify_revocation.py",
                "--registry",
                f"{EDGE}/revocations/registry.json",
                "--policy",
                f"{EDGE}/trust-policy.json",
                "--support",
                f"{EDGE}/revocations/support-model.json",
                "--historical",
                f"{EDGE}/revocations/historical-verdict.json",
                "--controls",
            ],
            "requires": [
                f"{EDGE}/revocations/registry.json",
                f"{EDGE}/trust-policy.json",
                f"{EDGE}/revocations/support-model.json",
                f"{EDGE}/revocations/historical-verdict.json",
                f"{EDGE}/verify_revocation.py",
            ],
        },
        {
            "purpose": "verify the local transparency proof and run its controls",
            "working_directory": ".",
            "argv": [
                "python3",
                f"{EDGE}/verify_transparency.py",
                "--dir",
                f"{EDGE}/transparency",
                "--controls",
            ],
            "requires": [
                f"{EDGE}/transparency/proof.json",
                f"{EDGE}/transparency/checkpoint-size-3.txt",
                f"{EDGE}/transparency/policy.json",
                f"{EDGE}/transparency/witness-state.json",
                f"{EDGE}/verify_transparency.py",
            ],
        },
    ]
    required_categories = [
        "opening_manifest",
        "closure_manifest",
        "receipt",
        "raw_evidence",
        "sarif",
        "attestation",
        "policy",
        "time_token",
        "time_request",
        "tsa_trust_anchor",
        "time_report",
        "revocation_registry",
        "support_model",
        "historical_verdict",
        "transparency_proof",
        "transparency_checkpoint",
        "transparency_policy",
        "witness_state",
        "reconstruction",
        "verifier",
    ]
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "spec": SPEC,
        "archive_id": "frf-etp-phase10.4b-archive",
        "created_at_unix": observed,
        "knowledge_horizon_unix": observed,
        "objects": sorted(objects, key=lambda item: item["path"]),
        "required_categories": required_categories,
        "reconstruction": {
            "instructions": f"{EDGE}/RECONSTRUCTION.md",
            "commands": commands,
            "input_objects": sorted(
                {
                    requirement
                    for command in commands
                    for requirement in command["requires"]
                }
            ),
        },
        "unsupported_features": [
            "public_transparency",
            "external_witness_observation",
            "external_trusted_time",
            "public_revocation_feed",
            "global_non_equivocation",
            "semantic_validity_of_a_logged_entry",
            "completeness_of_the_log",
        ],
        "claim_ceiling": (
            "A verified archive establishes only that the declared objects are "
            "present, regular, and digest-matched, that no unlisted regular file "
            "is present, and that the declared reconstruction inputs are available. "
            "It does not establish truth, authenticity, completeness, external "
            "anchoring, or reproduction without the declared images and tools."
        ),
        "non_claims": [
            "Local transparency inclusion is not public transparency and not completeness.",
            "No external witness observation is established.",
            "The timestamp is anchored in a local test TSA, not external trusted time.",
            "The revocation registry is not a public feed and is not complete.",
            "A verified archive is not a certification or a deployment authorization.",
        ],
    }
    (out / "manifest.json").write_bytes(canonical_json(manifest))
    print(f"archive objects: {len(manifest['objects'])}")
    print(f"archive horizon: {observed}")
    print(f"archive path: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
