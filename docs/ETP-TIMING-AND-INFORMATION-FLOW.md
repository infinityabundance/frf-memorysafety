# ETP Timing and Information Flow

This document describes the Phase 12.1 bounded information-flow and leakage
classification model for the FRF-MemorySafety ETP. Phase 12.2 will add live
timing measurement.

## 1. Classifications

The model classifies values and metadata into the following classes:

### Value Classes
| Class | Meaning |
|-------|---------|
| `public` | Publicly observable; no secrecy requirement |
| `secret` | Secret input; must not influence observable behavior |
| `declassified` | Formerly secret, intentionally released |
| `derived_public` | Derived from public values only |
| `derived_secret` | Derived from secret values |
| `unknown` | Classification not determined; **refused in positive claims** |

### Representation Classes
| Class | Meaning |
|-------|---------|
| `fixed_width` | Fixed-size representation (e.g., `u64`, `[u8; 32]`) |
| `variable_length` | Variable-length representation (e.g., `Vec<u8>`, `String`) |
| `normalized` | Canonicalized form (e.g., constant-time encoding) |
| `serialized` | Wire/serialization format |
| `spare_capacity` | Uninitialized or excess capacity in containers |
| `uninitialized` | Memory not yet initialized |

### Metadata Observable Flags
Each metadata entry declares which observable properties it exposes:
| Flag | Meaning |
|------|---------|
| `lengths` | Length of variable-length values |
| `capacity` | Allocated capacity of containers |
| `allocation_sizes` | Sizes of heap allocations |
| `object_shape` | Structural shape (e.g., enum discriminant) |
| `pointer_derived_access` | Memory access pattern derived from pointers |
| `control_flow` | Branch decisions |
| `algorithm_selection` | Choice of algorithm variant |
| `failure_behaviour` | Error/retry behavior |

## 2. Trace Model

The trace model declares which observables are in scope for the claim.

### Observables in Scope (choose subset)
- `branch` — conditional branch decisions
- `memory_address` — memory addresses accessed
- `access_count` — number of memory accesses
- `allocation/release` — allocation and deallocation events
- `instruction_latency_class` — instruction latency categories
- `execution_time` — wall-clock or cycle-accurate time
- `cache` — cache state / access patterns
- `branch_prediction` — branch predictor state
- `scheduler` — thread/process scheduling
- `syscall` — system call entry/exit
- `error/retry` — error handling and retry loops
- `output_length` — length of produced output

### Explicit Exclusions
Observables explicitly declared out of scope.

### Limitations
Free-text description of model limitations (e.g., "no live timing measurement yet").

## 3. Source vs. Binary Distinction

| Aspect | Source Level | Binary Level |
|--------|--------------|--------------|
| **Claim** | About source code model | About compiled binary behavior |
| **Evidence** | Static analysis, model checking | Execution witness + branch trace |
| **Assurance** | Binary behavior **not established** | Bound to authenticated execution path |
| **Quantification** | Bounded model only | Bounded model only |

A source-level claim **must not** be presented as binary assurance. The validator
refuses `source_claim_as_binary` when `level: "binary"` is used without a
witness-bound execution path.

## 4. Witness Binding (Phase 11.2)

Binary-level claims require an `authenticated_execution_path` binding to the
Phase 11.2 execution witness:

```json
"authenticated_execution_path": {
  "witness_schema": "frf-etp.execution-witness.v1",
  "witness_sha256": "<sha256 of witness receipt>",
  "exe_sha256": "<sha256 of executed binary>",
  "loader_closure_sha256": "<sha256 of loader closure>",
  "executed_function": "witness_probe",
  "branch_trace_digest": "<optional branch-trace digest>"
}
```

The validator checks:
- `witness_digest_mismatch` — witness SHA-256 ≠ exe SHA-256
- `execution_path_mismatch` — exe SHA-256 = loader-closure SHA-256 (expected distinct)
- `binary_claim_without_branch_trace` — binary `constant_time` / `no_secret_dependent_branch` / `no_secret_dependent_address` claims require a branch-trace digest

## 5. Refusal Rules

The validator emits a canonical report (`frf-etp.information-flow-report.v1`)
with named refusals. The following are **always refused**:

| Code | Condition |
|------|-----------|
| `unknown_is_not_public` | Any `unknown` value/metadata class in a positive claim |
| `missing_metadata_classification` | Metadata lacks a valid classification |
| `missing_leakage_model` | Threat model or leakage model absent/empty |
| `source_claim_as_binary` | Source-level claim presented as binary assurance |
| `fixed_iteration_is_not_constant_time` | `fixed_iteration_count: true` used as constant-time evidence |
| `absence_of_detection_is_not_absence` | `no_leakage_detected: true` presented as proof of no leakage |
| `scalar_score_forbidden` | Any scalar confidence/assurance score anywhere in the model |
| `binary_claim_without_execution_path` | Binary-level claim without witness-bound execution path |
| `witness_digest_mismatch` | Witness SHA-256 ≠ exe SHA-256 |
| `execution_path_mismatch` | Exe SHA-256 = loader-closure SHA-256 |
| `binary_claim_without_branch_trace` | Binary secret-independent claim without branch trace |
| `universal_quantification_refused` | Quantification = `universal_contextual` |
| `missing_claim_ceiling` | Claim ceiling absent or empty |

## 6. Real Result (Phase 12.1)

The self-test validates:
1. A **valid source-level model** is accepted with `binary_behavior_not_established: true`
2. **9 mutated controls** are refused with the expected codes:
   - `unknown_as_public` → `unknown_is_not_public`
   - `missing_metadata` → `missing_metadata_classification`
   - `missing_leakage_model` → `missing_leakage_model`
   - `source_as_binary` → `source_claim_as_binary`
   - `fixed_iteration` → `fixed_iteration_is_not_constant_time`
   - `absence_of_detection` → `absence_of_detection_is_not_absence`
   - `scalar_score` → `scalar_score_forbidden`
   - `binary_without_witness` → `binary_claim_without_execution_path`
   - `witness_digest_mismatch` → `witness_digest_mismatch`
   - `universal_quantification` → `universal_quantification_refused`

The committed report is written to `evaluation/earned-trust/information-flow/report.json`
by `ci/etp-information-flow-gate.sh`.

## 7. Claim Ceiling

Every model must include a `claim_ceiling` string that honestly describes the
limitations of the claim. For the valid source-level model:

> "This source-level model does not establish binary behavior, timing behavior, or deployment security."

The claim ceiling is included in the report and cannot be omitted.

## 8. Limits

- **No live timing measurement** — Phase 12.2 will add timing profiles.
- **Bounded quantification only** — Universal claims are refused.
- **No scalar scores** — The ten ETP status dimensions remain separate.
- **Source ≠ Binary** — Source-level acceptance explicitly states binary behavior is not established.
- **Witness scope** — The Phase 11.2 witness covers one fixture, one host, one container.
- **No external review** — The model is self-validated; independent review is a separate role.

## 9. Files

| File | Purpose |
|------|---------|
| `schemas/etp/information-flow.v1.schema.json` | JSON Schema for the model |
| `evaluation/earned-trust/information_flow.py` | Validator (stdlib only) |
| `evaluation/earned-trust/information-flow/model.json` | Valid source-level model |
| `evaluation/earned-trust/information-flow/report.json` | Committed canonical report |
| `ci/etp-information-flow-gate.sh` | Hardened gate script |
| `docs/ETP-TIMING-AND-INFORMATION-FLOW.md` | This document |

## 10. References

- S13: Almeida et al., *Verifying Constant-Time Implementations*, USENIX Security 2016
- Phase 11.2: `docs/ETP-EXECUTION-WITNESS.md`
- ETP Claim Algebra: `schemas/etp/etp-claim.v1.schema.json`
- ETP Standards Registry: `docs/ETP-STANDARDS-REGISTRY.md`