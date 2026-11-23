# ETP TLS Matrix (Phase 13.2)

## Overview

The ETP TLS Matrix is a four-way interoperability test for a local TLS 1.3 echo
fixture. It compiles the same C TLS client and server source against two pinned
OpenSSL prefixes — a reference authority (OpenSSL 3.6.4 production build) and a
candidate (OpenSSL-RS Safe-33 phase 2 build) — and runs the genuine four-way
matrix for two cases:

| Case | Description | Expected Outcome |
|------|-------------|------------------|
| `tls13_echo` | Client verifies server with correct CA, sends message, checks echo | `pass` in all 4 cells |
| `wrong_ca` | Client verifies server with wrong CA, handshake must fail | `reject` in all 4 cells |

This yields 8 cells total (2 cases × 4 client/server variant combinations).

## Protocol

### Fixture

- **Server** (`tests/fixtures/tls/tls_echo_server.c`): Listens on port 0 (OS-assigned),
  prints `PORT=<n>`, accepts one TLS 1.3 connection, reads a length-prefixed
  message, echoes it back, prints `SERVER_DONE ok` or `SERVER_DONE reject`,
  and exits.
- **Client** (`tests/fixtures/tls/tls_echo_client.c`): Connects to 127.0.0.1,
  verifies the server certificate against a supplied CA file, sends a
  length-prefixed message, reads the echo, compares, prints `CLIENT_DONE ok
  match=1` or `CLIENT_DONE reject`, and exits.
- **Identity emission**: Both binaries emit a single JSON line to stdout
  containing the real `/proc/self/exe` path (via `readlink`) and the full
  `/proc/self/maps` content (read in chunks because procfs reports `st_size = 0`).

### Compilation

Each variant (reference/candidate) is compiled against its prefix:

```bash
gcc -O1 -fno-inline -fno-builtin -g -D<VARIANT> \
    -I<prefix>/include -L<prefix>/lib -Wl,-rpath,<prefix>/lib \
    tls_echo_server.c -o tls_echo_server_<variant> -lssl -lcrypto
gcc -O1 -fno-inline -fno-builtin -g -D<VARIANT> \
    -I<prefix>/include -L<prefix>/lib -Wl,-rpath,<prefix>/lib \
    tls_echo_client.c -o tls_echo_client_<variant> -lssl -lcrypto
```

- Reference prefix: `target/external/openssl-rs/forensics/authorities/prefix/openssl-3.6.4-production`
- Candidate prefix: `target/external/openssl-rs/artifacts/phase2/install`

The `-Wl,-rpath` ensures each binary loads its own prefix's `libssl.so.3` and
`libcrypto.so.3` at runtime.

### Certificate Generation

A local self-signed CA and server certificate are generated using the reference
`openssl` binary (with `LD_LIBRARY_PATH` set to the reference prefix's `lib`):

1. CA key + self-signed CA cert (`basicConstraints=critical,CA:TRUE`)
2. Server key + CSR (CN=127.0.0.1)
3. Server cert signed by CA (with `subjectAltName=IP:127.0.0.1`)
4. Wrong CA key + self-signed wrong CA cert (`basicConstraints=critical,CA:TRUE`)

For `tls13_echo`, the client uses the correct CA cert. For `wrong_ca`, the
client uses the wrong CA cert.

## Per-Process Identity

For each process (client and server in every cell), the harness records:

- **exe_digest**: SHA-256 of the executable file (`/proc/self/exe` target).
- **dsos**: Sorted array of `{path, sha256}` for all file-backed DSOs from
  `/proc/self/maps` (excluding pseudo-paths like `[stack]`, `[vdso]`, etc.).
- **loader_closure_digest**: SHA-256 of the canonical JSON encoding of the
  `dsos` array.

The `libssl` and `libcrypto` entries in `dsos` are the primary evidence of
which OpenSSL prefix was actually loaded.

## Case Population

The frozen case population is exactly two cases, sorted, no mtimes:

```json
["tls13_echo", "wrong_ca"]
```

The harness validates that the population matches exactly (no missing, extra,
or duplicate cases).

## Matrix Cells

The four-way matrix cells are:

| Cell | Client Variant | Server Variant |
|------|----------------|----------------|
| 1 | reference | reference |
| 2 | reference | candidate |
| 3 | candidate | reference |
| 4 | candidate | candidate |

Each case runs all four cells (8 cells total). The harness validates that all
cells are present.

## Outcome Classification

Per-cell terminal outcomes:

| Outcome | Meaning |
|---------|---------|
| `pass` | Client `CLIENT_DONE ok match=1` and server `SERVER_DONE ok` |
| `fail` | Client `CLIENT_DONE ok match=0` (echo mismatch) |
| `reject` | TLS handshake/verification failed (no `CLIENT_DONE ok`), or server rejected |
| `unresolved` | Timeout, ambiguous output, or execution incomplete |
| `blocked` | Candidate binary could not be compiled/run (recorded as `unresolved` in report) |

Expected outcomes:
- `tls13_echo`: `pass` in all 4 cells.
- `wrong_ca`: `reject` in all 4 cells (common failure).

## Common Failures

A case is a **common failure** if all four cells have outcome `reject` or
`fail`. `wrong_ca` is expected to be a common failure (both variants correctly
reject the wrong CA). The harness records common failures; it does not require
that at least one exists.

## Candidate-Specific Failures

A case is a **candidate-specific failure** if the reference→reference cell
passes but any cell involving the candidate fails. The harness records
candidate-specific failures; it does not require that at least one exists. A
clean interoperability run is a valid result, not a failed harness. In the
committed run, `tls13_echo` passed in all four cells, so no candidate-specific
failure was observed.

## Unresolved/Blocked Cells

If the candidate client or server cannot be compiled or run, the exact
compiler/linker/loader error is recorded and the affected cells are marked
`unresolved`/`blocked`. They are **never** recorded as `pass`. The report's
`accepted` field will be `false` with `refusal_code = "unresolved"`.

## Controls (Harness Self-Test)

The harness includes 9 self-test controls that must be refused/detected:

1. **wrong_endpoint**: Client connects to a port with no server → must not pass.
2. **wrong_executable**: Tampered binary digest differs from recorded → detected.
3. **collapsed_matrix**: One cell omitted from matrix → `check_matrix_cells` refuses.
4. **missing_case**: Population missing a pre-registered case → `check_population` refuses.
5. **duplicate_case**: Population contains duplicate case → `check_population` refuses.
6. **stale_fixture**: Source digest differs from compiled source → detected.
7. **substituted_dso**: Reference vs candidate `libssl.so.3` digest differs → detected.
8. **common_failure_preservation**: synthetic cells classify `wrong_ca` as a common failure → detected.
9. **candidate_specific_detection**: synthetic cells classify a candidate-only failure → detected.

These two controls exercise the classification functions with synthetic cells;
they are not claims that the real candidate failed.

All controls raise `Refusal` with the appropriate code when the defect is
detected. If any control fails to detect its defect, the self-test fails.

## Real Results (Committed Run)

| Case | ref→ref | ref→cand | cand→ref | cand→cand |
|---|---|---|---|---|
| `tls13_echo` | pass | pass | pass | pass |
| `wrong_ca` | reject | reject | reject | reject |

- `accepted`: `true`
- common failures: `wrong_ca`
- candidate-specific failures: none
- unresolved cells: none
- expected-vs-observed mismatches: none

Per-process runtime identity distinguishes the two stacks:

| Stack | `libcrypto.so.3` | `libssl.so.3` |
|---|---|---|
| Reference authority 3.6.4 | `59d9c2e4568d0e5fa4025e1d7e9000c6c07383087e6a2ebb68d525d4e5d5e17d` | `c25b910e51116973f1e0f2c4a834d39f07c818e6e22727a5eb8bd0fa3f4f3d9b` |
| OpenSSL-RS candidate | `ed012b13b03721a2fc36a339205fdb874318f2ae93576f4d4078999283dbec64` | `5e5ebc799f46c070cd139a147395ec81e2bf6789d3ffdc5cd3bfc63873674a7d` |

The candidate binaries also load `libgcc_s.so.1`; the reference binaries do not.

## Report Schema

The canonical report conforms to `schemas/etp/tls-matrix.v1.schema.json` and
contains:

- `schema`: `"frf-etp.tls-matrix.v1"`
- `spec`: `"frf-etp-tls-matrix-v1"`
- `accepted`: boolean (true if every cell has a terminal outcome and no
  unresolved/integrity refusal; `pass`/`fail`/`reject` findings do not by
  themselves make the matrix invalid)
- `claim_ceiling`: human-readable claim ceiling statement
- `environment`: gcc, ld, python, hostname, openssl versions
- `fixture`: server/client source paths, SHA-256 digests, case population
- `binaries`: per-variant source/binary digests, compiler versions, compile commands
- `cells`: 8 cell objects with per-process identity, outcomes, result lines
- `summary`: total cases/cells, common failures, candidate-specific failures, unresolved cells, expected-vs-observed mismatches
- `refusal_code` / `refusal_detail`: structural or unresolved failure (if applicable)

## Claim Ceiling

> This TLS matrix records one local TLS echo fixture compiled twice
> (reference/candidate) against pinned OpenSSL prefixes and run in one
> host process. It does not establish general TLS interoperability,
> OpenSSL-RS compatibility, deployment security, or SAFE_COMPATIBLE.

The evidence is **local** (one host, one fixture, two pinned prefixes),
**finite** (2 cases, 8 cells), and **non-transferable**. It does not imply
any universal property of the candidate, OpenSSL-RS, or TLS implementations.

## Limits

1. **Single fixture**: One TLS echo protocol; does not cover renegotiation,
   session resumption, client cert auth, ALPN, etc.
2. **Single host**: Linux x86-64 only; no cross-platform evidence.
3. **Pinned prefixes**: Reference is OpenSSL 3.6.4 production; candidate is
   OpenSSL-RS Safe-33 phase 2. Results do not generalize to other versions.
4. **No deployment security**: No network adversary model, no PKI validation
   beyond self-signed CA, no side-channel analysis.
5. **No SAFE_COMPATIBLE**: The real candidate passed the two declared cells;
   this is not evidence of general compatibility. No organically discovered
   vulnerability is claimed. `SAFE_COMPATIBLE` remains `WITHHELD_NOT_RUN`.
6. **No external trust**: The reference authority is a local build artifact,
   not an independently audited OpenSSL release.

## Gate Execution

```bash
./ci/etp-tls-matrix-gate.sh
```

Runs in a hardened `python:3.11-slim` container with:
- `--memory=1g --memory-swap=1g`
- `--pids-limit=512 --cpus=2`
- `--ulimit nofile=1024:1024`
- `--oom-score-adj=500`
- `--cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER --cap-add SETUID --cap-add SETGID`
- `--security-opt no-new-privileges`
- Repo mounted read-only at `/src`; fresh run dir at `/out`

The gate:
1. Cleans `target/etp-tls-matrix-run/`.
2. Runs inner script (compiles, runs matrix, runs self-test, writes report).
3. Compares fresh report to committed report in `evaluation/earned-trust/tls-matrix/`.
4. Fails if stable fields (schema, spec, accepted, claim_ceiling, fixture digests,
   binary digests, summary) differ.

## Evidence Locations

- **Committed report**: `evaluation/earned-trust/tls-matrix/report.json`
- **Fresh run**: `target/etp-tls-matrix-run/report.json`
- **Schema**: `schemas/etp/tls-matrix.v1.schema.json`
- **Gate scripts**: `ci/etp-tls-matrix-gate.sh`, `ci/etp-tls-matrix-gate-inner.sh`
- **Harness**: `evaluation/earned-trust/tls_matrix.py`
- **Fixtures**: `tests/fixtures/tls/tls_echo_server.c`, `tests/fixtures/tls/tls_echo_client.c`