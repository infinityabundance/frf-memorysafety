# ETP Execution Witness

This document describes the Phase 11.2 external execution witness for the FRF-MemorySafety ETP.

## Overview

The execution witness is a self-contained, reproducible record of a single execution of the C probe `witness_probe` within a hardened container. It establishes that:

1. The probe was compiled with `gcc -O0 -g -fno-inline` into a fixed private 0700 build directory (`/tmp/frf-witness`).
2. The binary was executed with a cleared environment and a fixed argv.
3. The real executable path, argv, and `/proc/self/maps` were captured; the maps digest is normalized over permissions and pathnames, not ASLR-dependent addresses.
4. Every loaded regular-file DSO was hashed and the loader-closure digest recorded.
5. The receipt includes source-to-binary correspondence via `nm` and `objdump`.
6. The receipt is committed as evidence. It is not signed, and this gate does not authenticate it.

## Artifacts

- **Probe source**: `tests/fixtures/witness/probe.c`
- **Witness script**: `evaluation/earned-trust/witness_execution.py`
- **Receipt**: `evaluation/earned-trust/witness/frf-etp.execution-witness.v1`
- **Independent verifier**: `evaluation/earned-trust/verify_witness.py`
- **Hardened gate**: `ci/etp-witness-gate.sh`

## Process

1. **Compilation**: The probe is compiled with `gcc -O0 -g -fno-inline` into a fixed private 0700 build directory (`/tmp/frf-witness`). The toolchain (gcc, ld, rustc) and build recipe are recorded. The fixed path keeps the compile command and disassembly text stable across runs.
2. **Execution**: The probe is executed with a cleared environment and fixed argv. Its stdout is parsed as canonical JSON containing:
   - `exe`: the real path to the executable (`/proc/self/exe`)
   - `argv`: the actual argv array (captured from `/proc/self/cmdline`)
   - `maps`: the `/proc/self/maps` lines
3. **Receipt generation**: The gate writes a fresh receipt to `target/etp-witness-run/`. The committed receipt under `evaluation/earned-trust/witness/` is the historical record. `maps_sha256` is computed over normalized permissions and pathnames, not addresses, offsets, or inode numbers, so repeated runs are stable.

## Schema

The receipt conforms to `schemas/etp/execution-witness.v1.schema.json`, which defines the exact structure and required fields.

## Self-Test

The witness script includes a `--self-test` mode that refuses six named refusal codes:
- stripped binary (missing symbol)
- ambiguous symbol query
- source/binary mismatch
- substituted executable
- unexpected LD_PRELOAD DSO
- preflight-vs-actual executable mismatch

## Independent Verifier

The verifier `verify_witness.py` is separate from the builder. It recomputes hashes from the receipt and the actual binary, and refuses tampering with executable, DSO, symbol, argv, or loader-closure fields.

## Limits

- This is one probe, one host, one container, and one toolchain. It does not establish authenticity, completeness, correctness, or deployment behaviour.
- `/proc/self/maps` is self-reported by the process; it is not a hypervisor or kernel attestation.
- Symbol correspondence is a `nm`/`objdump` observation, not a refinement proof between source and binary.
- Child processes, other binaries, other DSOs, and other processes are out of scope.
- No branch trace, timing measurement, or information-flow claim is established here.

## References

- `docs/ETP-REPRODUCIBILITY.md`
- `docs/ETP-STANDARDS-REGISTRY.md`
- `schemas/etp/execution-witness.v1.schema.json`
- `evaluation/earned-trust/verify_reproducibility.py`