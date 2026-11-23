# ETP Interoperability Matrix (Phase 13.1a)

Status: **Phase 13.1a is complete for the declared scope.** One local length-prefixed TCP protocol fixture compiled twice (reference/candidate) and run in a genuine four-way matrix inside one hardened container on one host. The matrix shows a candidate-specific failure (labeled synthetic defect) and preserves common failures.

This is **not** a TLS interoperability, deployment security, or OpenSSL-RS compatibility claim. It does not establish `SAFE_COMPATIBLE`, memory safety, or organic vulnerability discovery.

## 1. Protocol

The fixture `tests/fixtures/interop/interop.c` implements a minimal length-prefixed TCP protocol:

- **Frame**: 4-byte big-endian length + payload bytes.
- **Echo**: the receiver sends back the same length-prefixed message.
- **Identity**: both server and client emit a JSON identity line containing the real `/proc/self/exe` path and `/proc/self/maps` content (escaped as `\xHH` for non-printable bytes).

Modes:
- `server <port>` — listen, accept one connection, echo, exit.
- `client <host> <port> <case>` — connect, send case payload, receive echo, compare.

## 2. Matrix

For every pre-registered case, the harness runs the genuine four-way matrix:

| Cell | Client | Server |
|---|---|---|
| 1 | reference | reference |
| 2 | reference | candidate |
| 3 | candidate | reference |
| 4 | candidate | candidate |

For each cell, the harness:
1. Starts the server on port 0.
2. Reads its port and identity.
3. Runs the client with the case.
4. Captures both identities and the result.
5. Stops the server.
6. Records exactly one terminal outcome.

## 3. Cases (frozen list)

| Case | Description | Expected outcome |
|---|---|---|
| `empty` | zero-length payload | pass (all four cells) |
| `short` | 5-byte payload "hello" | pass (all four cells) |
| `max_4096` | 4096-byte payload | reference passes; candidate fails (synthetic truncation defect) |
| `malformed_length` | send length 0xFFFFFFFF | reject (all four cells) |
| `truncated` | send length 10 with 5 bytes | reject (all four cells) |
| `oversize_common` | send length 4097 with 4096 bytes | reject (all four cells) |

## 4. Per-process identity

For each process, the harness records:
- **exe digest**: SHA-256 of the executable file.
- **loaded DSO paths/digests**: parsed from `/proc/self/maps`, each file-backed DSO hashed.
- **loader-closure digest**: SHA-256 of the sorted DSO digest list.

The fixture reads `/proc/self/maps` in chunks because procfs reports `st_size = 0`;
reading only the reported size would silently produce an empty map. In the
committed run, each process records the executable, `ld-linux-x86-64.so.2`, and
`libc.so.6`; the reference client/server closure digest is
`ccee6c1e57de562d2b38adb19a4ef0aacee018ab862ac8872d0d868b7f94b8f7`.

## 5. Population reconciliation

The case population is:
- **sorted**: cases are processed in sorted order.
- **frozen**: the list is hard-coded in `interop_matrix.py` (`CASES`).
- **no mtimes**: the population is validated by name only, not by file modification time.

The harness refuses a missing, extra, or duplicate case.

## 6. Controls (harness self-test)

The self-test (`--self-test`) exercises these controls:

| Control | Description |
|---|---|
| wrong endpoint | client connects to a port with no server |
| wrong executable identity | tampered binary digest differs from recorded |
| collapsed matrix | one cell omitted; `missing_cell` refusal |
| missing population case | one case removed; `missing_case` refusal |
| duplicate population case | one case duplicated; `duplicate_case` refusal |
| stale fixture | source digest differs from compiled source |
| substituted DSO | DSO digest differs from expected closure |
| common-failure preservation | `oversize_common` must be classified as common failure |
| candidate-specific-failure detection | `max_4096` must be classified as candidate-specific failure |

## 7. Real results

The committed report `evaluation/earned-trust/interop/report.json` records:

- **accepted**: `true`
- **total_cases**: 6
- **total_cells**: 24
- **common_failures**: `malformed_length`, `oversize_common`, `truncated`
- **candidate_specific_failures**: `max_4096`

The candidate-specific failure is the labeled synthetic defect (truncating a 4096-byte payload at 2048). It is **not** an organically discovered vulnerability.

## 8. Claim ceiling

This is one local fixture on one host. It does not establish:
- TLS interoperability.
- Deployment security.
- Compatibility of OpenSSL-RS.
- Memory safety or functional compatibility.
- Organic vulnerability discovery.

## 9. Limits

- One fixture, one host, one hardened container.
- The candidate defect is synthetic and labeled.
- The matrix does not cover TLS, cryptography, or production workloads.
- Repeated runs must not dirty the tree; fresh runs go to `target/etp-interop-run/`.

## 10. Reproduction

```sh
# Full interop matrix gate (builds reference/candidate, runs matrix, runs controls).
./ci/etp-interop-gate.sh

# Default crate gate (no Rust change).
./ci/gate.sh
```

The gate restores the run directory to a clean state at exit. The committed evidence is under `evaluation/earned-trust/interop/report.json`.
