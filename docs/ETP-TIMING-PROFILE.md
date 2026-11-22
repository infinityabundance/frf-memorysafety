# ETP Timing and Information Flow Profile (Phase 12.2)

This document describes the Phase 12.2 bounded live timing and execution-path profile model for the FRF-MemorySafety ETP.

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
Free-text description of model limitations (e.g., "no live timing measurement yet", "no external witnessing").

## 3. Source vs. Binary Distinction

| Aspect | Source Level | Binary Level |
|--------|--------------|--------------|
| **Claim** | About source code model | About compiled binary behavior |
| **Evidence** | Static analysis, model checking | Execution witness + branch trace |
| **Assurance** | Binary behavior **not established** | Bound to authenticated execution path |
| **Quantification** | Bounded model only | Bounded model only |

A source-level claim **must not** be presented as binary assurance. The validator refuses `source_claim_as_binary` when `level: "binary"` is used without a witness-bound execution path.

## 4. Witness Binding (Phase 11.2)

Binary-level claims require an `authenticated_execution_path` binding to the Phase 11.2 execution witness:

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

The validator emits a canonical report (`frf-etp.timing-profile-report.v1`) with named refusals. The following are **always refused**:

| Code | Condition |
|------|-----------|
| `not_run` | valgrind/callgrind unavailable, empty parse, or unstable repeat |
| `unresolved` | parse succeeded but comparison is ambiguous |
| `wrong_dispatch` | declared mode does not match executed function |
| `stale_binary` | modified source without rebuild |
| `observed_secret_dependent_divergence` | Ir differs between secret classes |
| `observed_representation_length_divergence` | Ir differs between length classes |
| `no_divergence_within_bounded_trace` | Ir matches across compared classes |

## 6. Real Result (Phase 12.2)

The self-test validates 8 controls:
1. **branch_divergence** — `branch` mode produces `observed_secret_dependent_divergence`
2. **ct_no_divergence** — `ct` mode produces `no_divergence_within_bounded_trace`
3. **length_divergence** — `length` mode produces `observed_representation_length_divergence`
4. **wrong_dispatch** — declared `constant_time` but the branch run executed `secret_branch`; the profile checks the declared function against the observed per-function Ir map and refuses with `wrong_dispatch`
5. **stale_binary_detection** — modified source without rebuild detected via source hash mismatch
6. **valgrind_availability** — missing valgrind/empty callgrind produces `not_run`
7. **no_scalar_score** — any scalar confidence/assurance score in report is refused
8. **no_ct_proof_claim** — claim that `no_divergence` proves constant-time is refused (claim ceiling explicitly states this does not establish constant-time)

The committed per-mode reports are `evaluation/earned-trust/timing/report-branch.json`,
`report-ct.json`, and `report-length.json`. The observed per-function Ir counts are:

| Mode | Input classes | Function | Ir counts | Outcome |
|---|---|---|---|---|
| `branch` | secret 0 / 1 | `secret_branch` | 8 / 14 | `observed_secret_dependent_divergence` |
| `ct` | secret 0 / 1 | `constant_time` | 24 / 24 | `no_divergence_within_bounded_trace` (not a proof) |
| `length` | length 15 / 16 | `length_sensitive_fixed` | 222 / 236 | `observed_representation_length_divergence` |

The `ct` result values differ (0 and -2725307) but the per-function instruction
counts match; the declared observable for this bounded profile is the
per-function Ir count, not the output value. `ci/etp-timing-gate.sh` writes
fresh runs to `target/etp-timing-run/`, compares the typed outcome, function
counts, and traces against the committed reports, and does not dirty the tree.