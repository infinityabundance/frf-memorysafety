# ETP Cross-Property Allocation/Ownership Repair Profile (Phase 12.3a)

This document describes the Phase 12.3a bounded cross-property allocation/ownership repair profile for the FRF-MemorySafety ETP.

## 1. Purpose

Phase 12.3a demonstrates that an allocation/ownership repair preserves confidentiality and failure semantics. It measures a single C fixture (`tests/fixtures/cross_property/secret_buffer.c`) with two non-inlined variants:

- **faulty_repair(size_t n, int fail_inject)**: Adds fallible allocation but has one failure/relocation path that does not cleanse secret material before returning or freeing.
- **fixed_repair(size_t n, int fail_inject)**: Cleanses secret material on every path, including allocation failure, partial initialization, failed ownership transfer, relocation, and normal free; uses a volatile/explicit wipe helper.

The program takes a mode (`faulty`/`fixed`) and an allocation-failure injection count, and emits a stable event trace (`ALLOC`, `ALLOC_FAIL`, `INIT`, `USE`, `TRANSFER_FAIL`, `RELOCATE`, `CLEANSE`, `FREE`) plus a result.

## 2. Property Vector

The profile checks four properties against the event trace and valgrind memcheck output:

| Property | Description | Detection Method |
|----------|-------------|------------------|
| **Memory validity** | No uninitialized reads, no invalid memory access | Valgrind memcheck (`--error-exitcode=99`) |
| **Secret erasure** | Secret material cleansed before free/return on all paths | Event trace analysis (CLEANSE before FREE) |
| **Failure atomicity** | Allocation failure returns error without partial state | Event trace analysis (ALLOC_FAIL without INIT) |
| **Resource safety** | No memory leaks | Valgrind memcheck leak summary |

## 3. Controls

The self-test validates the following controls:

| # | Control | Expected Outcome |
|---|---------|------------------|
| 1 | faulty + allocation-failure (relocation) | `observed_erasure_violation` |
| 2 | fixed + allocation-failure (relocation) | `no_violation_within_bounded_trace` |
| 3 | fixed normal path | `no_violation_within_bounded_trace` |
| 4 | missing cleanse on relocation | `observed_erasure_violation` (faulty mode) |
| 5 | uninitialized read | `observed_uninitialized_read` (valgrind-detected) |
| 6 | leak | `observed_leak` (valgrind-detected) |
| 7 | missing/empty valgrind output | `not_run` |
| 7 | scalar confidence/assurance score | Refusal |
| 7 | wrong dispatch detection | `wrong_dispatch` |
| 7 | stale binary detection | Source hash mismatch detection |

All 10 controls pass.

## 4. Execution Environment

- **Container**: `python:3.11-slim`
- **Memory cap**: 1 GiB (`--memory=1g --memory-swap=1g`)
- **PID limit**: 512 (`--pids-limit=512`)
- **CPU limit**: 2 (`--cpus=2`)
- **File descriptor limit**: 1024 (`--ulimit nofile=1024:1024`)
- **OOM score adjustment**: 500 (`--oom-score-adj=500`)
- **Capabilities**: `--cap-drop ALL` + `DAC_OVERRIDE`, `CHOWN`, `FOWNER`, `SETUID`, `SETGID`
- **Security**: `--security-opt no-new-privileges`
- **Tools installed**: `gcc`, `binutils`, `valgrind`, `libc6-dev`

## 5. Tool Versions

- **gcc**: gcc (Debian 14.2.0-19) 14.2.0
- **ld**: GNU ld (GNU Binutils for Debian) 2.44
- **valgrind**: valgrind-3.24.0

## 6. Committed Reports

The canonical reports are stored under `evaluation/earned-trust/cross-property/`:

- `report-faulty.json` — faulty variant with allocation failure injection
- `report-fixed.json` — fixed variant with allocation failure injection

Fresh runs are written to `target/etp-cross-property-run/` and compared against the committed reports for stable fields (schema, spec, claim_ceiling, outcome, source_sha256, binary_sha256, results, trace_lines).

## 7. Claim Ceiling

> "This cross-property profile records an observed execution of one fixture on one host inside one hardened container. It does not establish general confidentiality, erasure, or memory safety."

This claim ceiling is included in every report and cannot be omitted.

## 8. Limitations

- **One fixture, one host, one container**: The profile measures a single C fixture (`secret_buffer.c`) compiled with `gcc -O1 -fno-inline -fno-builtin -g` on a single host inside a single hardened container. It does not generalize to other fixtures, compilers, optimization levels, or deployment environments.
- **Not a proof**: A missing violation (`no_violation_within_bounded_trace`) is **not** a proof of correctness. It only means no violation was observed in this bounded execution.
- **Bounded quantification only**: Universal claims are refused. The profile only covers the declared input classes and execution paths.
- **No scalar scores**: The ten ETP status dimensions remain separate; no confidence score, assurance level, grade, or composite index is used.
- **Valgrind scope**: Valgrind memcheck detects certain classes of memory errors (uninitialized reads, leaks, invalid accesses) but is not exhaustive. Absence of detected errors does not prove absence of all errors.
- **Event trace scope**: The event trace captures only the explicitly emitted events (ALLOC, ALLOC_FAIL, INIT, USE, TRANSFER_FAIL, RELOCATE, CLEANSE, FREE). It does not capture all possible execution paths or side channels.
- **No external review**: The profile is self-validated; independent review is a separate role.

## 11. Files

| File | Purpose |
|------|---------|
| `schemas/etp/cross-property.v1.schema.json` | JSON Schema for the canonical report |
| `evaluation/earned-trust/cross_property.py` | Validator (Python stdlib only) |
| `evaluation/earned-trust/cross-property/report-faulty.json` | Committed canonical report for faulty variant |
| `evaluation/earned-trust/cross-property/report-fixed.json` | Committed canonical report for fixed variant |
| `ci/etp-cross-property-gate.sh` | Hardened outer gate script |
| `ci/etp-cross-property-gate-inner.sh` | Hardened inner gate script |
| `tests/fixtures/cross_property/secret_buffer.c` | C fixture with faulty/fixed variants |
| `docs/ETP-CROSS-PROPERTY.md` | This document |

## 12. References

- Phase 12.1: `docs/ETP-TIMING-AND-INFORMATION-FLOW.md`
- Phase 12.2: `docs/ETP-TIMING-PROFILE.md`
- ETP Standards Registry: `docs/ETP-STANDARDS-REGISTRY.md` (S23)
- ETP Claim Algebra: `schemas/etp/etp-claim.v1.schema.json`