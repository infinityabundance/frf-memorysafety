# Phase 5.1: detector evidence and calibration refusal rules

Snapshot: branch `staging`, crate `frf-memorysafety 0.5.0` (no version bump).
This document describes `src/detector/mod.rs`, the typed detector-evidence
receipt, the calibration adjudicator, the refusal taxonomy, and the
`detector calibrate FILE [--json]` command. It is the **Phase 5.1** adjudication
layer; the Phase 5.2 live adapters are documented separately in
[`phase5-live-detectors.md`](phase5-live-detectors.md).

The Phase 5.1 adjudicator executes no detector process. It adjudicates a
caller-supplied receipt. Phase 5.2 adds opt-in live adapters that produce this
same shape from real runs of a closed checked-in fixture registry; an
unavailable instrument remains a typed `NOT_RUN` (exit 6).

## Scope and claim ceiling

A `CALIBRATED` report establishes only that the supplied finite receipt is
internally consistent with the declared mechanism, tool identity, separate
build, capture, provenance, and known-bad/known-good rules in this document.
It does **not** establish:

* that a detector process actually ran when only a Phase 5.1 receipt is
  supplied (the Phase 5.2 live adapters capture real output, but a live run is
  still one mechanism-and-case-specific observation);
* that the executable, version, argv, environment digest, or build identities
  are authentic (there is no signature, transparency log, or trusted execution
  root);
* universal detector sensitivity or specificity;
* sensitivity or specificity for another mechanism, defect class, input,
  flags combination, target, profile, or build;
* absence of detector false negatives;
* memory safety, Rust borrow validity, C object lifetime, or any
  `SAFE_COMPATIBLE` result.

Calibration is **mechanism- and case-specific**. A known-bad case that is
detected does not imply that a different defect mechanism will be detected. A
clean known-good case does not imply the absence of false negatives. The report
embeds this ceiling in `claim_ceiling`.

## Evidence schema

Schema identifier: `frf-memorysafety.detector-evidence.v1`.
Specification identifier: `frf-memorysafety-spec-v1`.
Input is parsed with `ms-canonical-json-v1` strict parsing (duplicate keys,
floats, unknown typed fields, trailing bytes, and resource limits are
rejected). Non-canonical whitespace is accepted on input; the report is emitted
canonically.

```json
{
  "cases": [
    {
      "capture": {
        "duration_ms": 12,
        "exit_code": 1,
        "signal": null,
        "stderr": {
          "sha256": "<64 lowercase hex>",
          "text": "AddressSanitizer: heap-use-after-free\n",
          "truncated": false
        },
        "stdout": {
          "sha256": "<64 lowercase hex>",
          "text": "",
          "truncated": false
        }
      },
      "case_id": "asan-use-after-free",
      "expected_mechanism": "address",
      "finding": {
        "diagnostic_fingerprint": "AddressSanitizer: heap-use-after-free",
        "mechanism": "address",
        "source": "stderr"
      },
      "fixture_digest": "<64 lowercase hex>",
      "legality": "test_only",
      "provenance": {
        "case_id": "asan-use-after-free",
        "fixture_digest": "<64 lowercase hex>",
        "legality": "test_only",
        "mechanism": "address",
        "origin": "authentic_live_tool"
      },
      "role": "known_bad"
    }
  ],
  "detector": {
    "baseline_build": {
      "artifact_sha256": "<64 lowercase hex>",
      "build_directory": "/build/baseline",
      "flags": ["-O2"],
      "profile": "release",
      "target": "x86_64-unknown-linux-gnu"
    },
    "build": {
      "artifact_sha256": "<64 lowercase hex>",
      "build_directory": "/build/asan",
      "flags": ["-fsanitize=address", "-O1", "-g"],
      "profile": "release",
      "target": "x86_64-unknown-linux-gnu"
    },
    "build_separation_verified": true,
    "environment_digest": "<64 lowercase hex>",
    "executable_sha256": "<64 lowercase hex>",
    "invocation_argv": ["clang", "-fsanitize=address", "canary.c"],
    "kind": "address_sanitizer",
    "mechanism_enablement": ["address"],
    "tool_name": "clang",
    "tool_version": "18.1.8"
  },
  "schema": "frf-memorysafety.detector-evidence.v1",
  "spec": "frf-memorysafety-spec-v1"
}
```

### Detector kinds

`DetectorKind` reuses the crate vocabulary and adds
`crypto_secret_oracle`. The calibratable names are:

| Kind | Wire value | Mechanism flag requirement | Enablement tokens |
|---|---|---|---|
| Miri | `miri` | none | `miri`, `stacked-borrows`, `stacked_borrows`, `tree-borrows`, `tree_borrows` |
| ASan | `address_sanitizer` | `-fsanitize=address` or `-Zsanitizer=address` | `address` |
| LSan | `leak_sanitizer` | `-fsanitize=leak`, `-fsanitize=address`, or the `-Zsanitizer=` equivalents | `leak`, `address` |
| TSan | `thread_sanitizer` | `-fsanitize=thread` or `-Zsanitizer=thread` | `thread`, `data_race` |
| Loom | `loom` | none | `loom`, `interleaving` |
| Kani | `kani` | none | `kani`, `bounded_model`, `bounded-model` |
| Crypto/secret oracle | `crypto_secret_oracle` | none | `constant-time`, `constant_time`, `ctgrind`, `dudect`, `secret_lifecycle`, `secret-lifecycle` |
| Custom | `{"custom":"name"}` | none | the case's declared mechanism must appear |

`ctgrind` and `dudect` are also accepted as detector kinds under the
constant-time profile. Fuzzing/court kinds are rejected as
`UNSUPPORTED_DETECTOR_KIND`; they are not calibrated by this profile.

Why the distinction matters: ASan requires compiler *and* runtime support, and
an instrumented harness that is not linked or not loaded can exit successfully
without detecting anything. Miri is an interpreter with its own aliasing model
and its own enablement/disablement flags; it does not observe native FFI the way
a sanitizer does. TSan observes a different mechanism. A single "detector
passed" bit cannot represent these differences.

### Identity fields

| Field | Meaning |
|---|---|
| `tool_name` | Exact executable or driver name. Must identify the declared family. |
| `tool_version` | Exact version. Empty and obvious placeholders are refused. |
| `executable_sha256` | SHA-256 of the executable or driver. All-zero digests are refused. |
| `invocation_argv` | Exact argv, beginning with the executable. Bounded to 64 entries. |
| `environment_digest` | SHA-256 over the canonical execution environment. |
| `mechanism_enablement` | Declared mechanism tokens that must include the kind's mechanism. |
| `build` | Instrumented build: flags, target, profile, separate directory identity, artifact digest. |
| `baseline_build` | Uninstrumented build with the same target/profile and a separate directory/artifact. |
| `build_separation_verified` | Producer claim that the two builds were kept separate. |

The digest of the complete typed receipt and the digest of the detector identity
are both recorded in the report under the `MS/CONTROL/v1` domain. These are
integrity identifiers, not authentication.

### Raw capture

Each case records:

* bounded UTF-8 `stdout` and `stderr` text;
* a lower-case SHA-256 for each stream's exact bytes;
* `exit_code`, optional `signal`, and `duration_ms`;
* a per-stream `truncated` flag.

Limits: 65,536 bytes per stream, 64 cases, 64 argv entries, 64 flags per build,
32 enablement tokens, 256 bytes per identifier, and one hour per child. The
whole receipt is also subject to the 4 MiB canonical-parser bound. Exceeding a
capture limit, marking a stream truncated, or presenting a digest that does not
match the text is an **integrity** refusal. The receipt is rejected; the
adjudicator does not silently truncate, repair, or hash a truncated stream.

### Provenance

| Origin | Meaning | Admissible? |
|---|---|---|
| `authentic_live_tool` | Captured from the named live executable | Yes |
| `substitute` | Substituted implementation/transport | No |
| `mock_provider` | Mock provider or transport | No |
| `modeled` | Modeled or synthesized evidence | No |

Each case's provenance repeats the case id, fixture digest, mechanism, and
legality. The adjudicator checks these against the enclosing case. A mismatch is
an **integrity** refusal; a non-authentic origin is a **detector** refusal.

## Calibration cases and verdict rules

Each receipt must contain at least one `known_bad` (sensitivity) and one
`known_good` (specificity) case, all targeting exactly one mechanism that
matches the detector kind (or the declared custom mechanism).

### Known-bad sensitivity

A known-bad case is counted as detected only when **all** of the following hold:

1. `capture.exit_code` is nonzero.
2. A typed `finding` is present.
3. `finding.mechanism` equals the case and detector mechanism.
4. `finding.diagnostic_fingerprint` is non-empty and occurs in the capture
   stream named by `finding.source`.
5. The provenance origin is `authentic_live_tool`.
6. The tool identity is structurally trustworthy and the build separation and
   mechanism configuration checks pass.
7. The receipt passed integrity checks.

A zero exit on a known-bad case is `DEAD_DETECTOR`. No typed finding is
`MISSING_FINDING`. A finding whose fingerprint is absent is
`FINDING_NOT_IN_CAPTURE`. **Capture text alone is never a finding**: a marker
printed by a program without a typed finding is still `MISSING_FINDING`.

### Known-good specificity

A known-good case passes only when it has no typed finding, exits zero, has an
authentic origin, and the receipt passes the same integrity/build/identity
checks. A typed finding on the control is `HARMLESS_CONTROL_FINDING`; a nonzero
exit is `HARMLESS_CONTROL_DIRTY_EXIT`.

### Build separation and configuration

The detector and baseline builds must have:

* the same target and profile;
* different `build_directory` identities;
* different, non-zero artifact digests;
* `build_separation_verified = true`;
* the detector build carrying a required mechanism flag (where the kind defines
  one);
* the baseline build not carrying that mechanism flag;
* mechanism-enablement tokens naming the declared mechanism.

Any failure is `BUILD_SEPARATION_MISMATCH`, `MISCONFIGURED_BUILD_FLAGS`, or
`MISSING_MECHANISM_ENABLEMENT`. The point is to refuse a run where the
instrument was not built into the tested artifact, where the "baseline" was
actually instrumented, or where instrumented and uninstrumented objects were
mixed in one build directory.

### Authenticity

Authenticity requires every case to use `authentic_live_tool`, and the detector
identity to have a family-matching tool name, a non-placeholder exact version, a
non-zero executable digest, and non-empty argv. A typed finding that cannot be
attributed to such an identity is `FAKE_STDOUT_MARKER` in addition to
`UNTRUSTED_DETECTOR_IDENTITY`. This rule prevents a program that merely prints
the expected diagnostic text or the expected JSON marker from being accepted.
It is structural provenance, not cryptographic authentication.

## Refusal taxonomy

Integrity refusals take precedence for the process exit status. Detector
refusals map to SPEC §14 exit 5.

| Code | Severity | Trigger |
|---|---|---|
| `INVALID_SCHEMA` | integrity | Wrong schema/spec, oversized case list, oversized identity vectors |
| `INVALID_CASE_ID` | integrity | Empty or oversized case id |
| `INVALID_DIGEST_FORMAT` | integrity | A digest is not 64 lower-case hex characters |
| `DUPLICATE_CASE_ID` | integrity | Two cases share an id |
| `PROVENANCE_CASE_MISMATCH` | integrity | Case and provenance id/legality differ |
| `PROVENANCE_FIXTURE_MISMATCH` | integrity | Case and provenance fixture digests differ |
| `CAPTURE_DIGEST_MISMATCH` | integrity | stdout/stderr digest does not match its text |
| `CAPTURE_OVERSIZED` | integrity | A stream exceeds 65,536 bytes |
| `CAPTURE_TRUNCATED` | integrity | A stream is marked truncated |
| `INCONSISTENT_CAPTURE` | integrity | Negative exit/signal or absurd duration |
| `DEAD_DETECTOR` | detector | Known-bad case exited zero |
| `MISSING_FINDING` | detector | Known-bad case produced no typed finding |
| `FINDING_NOT_IN_CAPTURE` | detector | Finding fingerprint absent from its declared stream |
| `MECHANISM_MISMATCH` | detector | Case/provenance/finding/kind mechanisms disagree |
| `MISSING_SENSITIVITY_CASE` | detector | No known-bad case |
| `MISSING_SPECIFICITY_CASE` | detector | No known-good case |
| `MISCONFIGURED_BUILD_FLAGS` | detector | Required mechanism flag absent |
| `MISSING_MECHANISM_ENABLEMENT` | detector | Enablement does not name the mechanism |
| `BUILD_SEPARATION_MISMATCH` | detector | Builds are not separate/instrumentation leaked into baseline |
| `HARMLESS_CONTROL_FINDING` | detector | Known-good case produced a finding |
| `HARMLESS_CONTROL_DIRTY_EXIT` | detector | Known-good case exited nonzero |
| `SUBSTITUTE_TRANSPORT` | detector | Provenance origin is `substitute` |
| `MOCK_PROVIDER_TRANSPORT` | detector | Provenance origin is `mock_provider` |
| `MODELED_EVIDENCE` | detector | Provenance origin is `modeled` |
| `UNTRUSTED_DETECTOR_IDENTITY` | detector | Tool name/version/executable/argv is not structurally trustworthy |
| `FAKE_STDOUT_MARKER` | detector | Typed finding has no authentic identity |
| `ILLEGAL_CASE` | detector | Case legality is `illegal` |
| `UNSUPPORTED_DETECTOR_KIND` | detector | Kind is outside the calibration profile |

## Deterministic report and CLI

`detector calibrate FILE [--json]` reads one file, never executes a process, and
emits either a short text summary or (with `--json`) the canonical
`frf-memorysafety.calibration-report.v1` report. The report contains:

* `outcome` = `CALIBRATED` or `REFUSED`;
* `detector_kind`;
* the sorted, deduplicated `mechanisms`;
* `evidence_digest` and `identity_digest`;
* `case_count`;
* `sensitivity` and `specificity` as `{passed,total}` finite counts;
* `build_separation` and `authenticity` as `PASS`, `FAIL`, or `NOT_EVALUATED`;
* the sorted, deduplicated `refusals` with code, severity, case id, and detail;
* the embedded `claim_ceiling`.

Sorting and deduplication make equal inputs produce byte-identical reports.
Integrity failures set both control dimensions to `NOT_EVALUATED`; they are not
reported as passing.

Exit statuses follow SPEC §14:

```text
0  calibrated (all declared checks passed)
2  usage, missing file, or unreadable input
3  integrity refusal (malformed, tampered, duplicate, unknown field, oversize)
5  detector refusal (dead, misconfigured, harmless control, non-authentic)
6  live detector or calibration instrument unavailable (NOT_RUN)
7  internal encoding/harness failure
```

## Seal controls and tests

`tests/detector.rs` contains 26 tests, all executing and none ignored. Each
Phase 5 seal control has its own fixture:

| Control | Expected result |
|---|---|
| Positive known-bad + known-good | `CALIBRATED`, sensitivity 1/1, specificity 1/1 |
| Dead detector exits zero | `REFUSED`, `DEAD_DETECTOR` |
| Dead detector produces no finding | `REFUSED`, `MISSING_FINDING` |
| stdout marker without typed finding | `REFUSED`, `MISSING_FINDING` |
| Wrong/missing build flags | `REFUSED`, `MISCONFIGURED_BUILD_FLAGS` |
| Missing mechanism enablement | `REFUSED`, `MISSING_MECHANISM_ENABLEMENT` |
| Build separation pass/fail | `PASS` for distinct builds; `FAIL` for shared directory, instrumented baseline, or unverified separation |
| Harmless control finding | `REFUSED`, `HARMLESS_CONTROL_FINDING` |
| Harmless control nonzero exit | `REFUSED`, `HARMLESS_CONTROL_DIRTY_EXIT` |
| Mock-provider transport | `REFUSED`, `MOCK_PROVIDER_TRANSPORT` |
| Substitute/modeled transport | `REFUSED`, `SUBSTITUTE_TRANSPORT` / `MODELED_EVIDENCE` |
| Fake stdout marker without identity | `REFUSED`, `UNTRUSTED_DETECTOR_IDENTITY` + `FAKE_STDOUT_MARKER` |
| Fingerprint absent from capture | `REFUSED`, `FINDING_NOT_IN_CAPTURE` |
| Mechanism mismatch | `REFUSED`, `MECHANISM_MISMATCH` |
| Missing known-bad or known-good | `REFUSED`, `MISSING_SENSITIVITY_CASE` / `MISSING_SPECIFICITY_CASE` |
| Illegal case | `REFUSED`, `ILLEGAL_CASE` |
| Tampered stdout/stderr digest | integrity refusal, exit 3 |
| Duplicate case id | integrity refusal, exit 3 |
| Provenance case/fixture mismatch | integrity refusal, exit 3 |
| Oversized/truncated capture | integrity refusal, exit 3 |
| Unknown field / duplicate JSON key | integrity error, exit 3 |
| Custom detector | `CALIBRATED` for its declared mechanism |
| Determinism | identical canonical bytes and digests |
| CLI statuses and canonical output | 0/2/3/5/6 as specified |

## Phase 5.2 delivery

Phase 5.2 is implemented in `src/detector/live.rs`, the checked-in fixtures
under `tests/detector/fixtures/`, `detector calibrate --live --detector KIND`,
and `ci/detector-gate.sh`. The live adapters run pinned Miri, gcc
ASan/LSan/TSan, loom, Kani 0.60.0, and an OpenSSL SHA-256 known-answer plus
signature pair, and produce this receipt shape from real stdout/stderr. They
still cover only a closed checked-in fixture registry, and an unavailable
tool is an honest typed `NOT_RUN` (exit 6), never a fabricated pass.

Miri applicability and FFI/skipped-code reporting, the Rust `-Zsanitizer`
path, loom/Kani model-to-concrete caveats, secret/crypto leakage-model
specificity, and signed/attested provenance with an independent re-run remain
outside this phase. See [`phase5-live-detectors.md`](phase5-live-detectors.md)
for exact install/invocation, versions, flags, live results, availability,
build separation, claim ceiling, and citations.

## Citations

1. NIST. *FIPS PUB 180-4: Secure Hash Standard (SHS)*, SHA-256.
   <https://csrc.nist.gov/pubs/fips/180-4/upd1/final>
2. The Clang Team. *AddressSanitizer* (compiler instrumentation plus runtime;
   `-fsanitize=address`; stderr diagnostic and nonzero exit).
   <https://clang.llvm.org/docs/AddressSanitizer.html>
3. The Clang Team. *ThreadSanitizer* and *LeakSanitizer*.
   <https://clang.llvm.org/docs/ThreadSanitizer.html>,
   <https://clang.llvm.org/docs/LeakSanitizer.html>
4. K. Serebryany, D. Bruening, A. Potapenko, and D. Vyukov.
   *AddressSanitizer: A Fast Address Sanity Checker.* USENIX ATC 2012.
   <https://www.usenix.org/conference/atc12/technical-sessions/presentation/serebryany>
5. K. Serebryany and T. Iskhodzhanov. *ThreadSanitizer: Data Race Detection in
   Practice.* Proceedings of the Workshop on Binary Instrumentation and
   Applications, 2009. <https://doi.org/10.1145/1791194.1791203>
6. The Rust Project. *Miri: an interpreter for Rust's mid-level intermediate
   representation*.
   <https://github.com/rust-lang/miri>
7. R. Jung, H.-H. Dang, J. Kang, and D. Dreyer. *Stacked Borrows: An Aliasing
   Model for Rust.* POPL 2020. <https://doi.org/10.1145/3371078>
8. The Rust Project. *The Unstable Book: Sanitizer*.
   <https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/sanitizer.html>
9. Kani Rust Verifier. *Kani documentation* (bounded model checking backed by
   CBMC).
   <https://model-checking.github.io/kani/>
10. E. Clarke, D. Kroening, and F. Lerda. *A Tool for Checking ANSI-C Programs.*
    TACAS 2004. <https://doi.org/10.1007/978-3-540-24730-2_15>
11. Tokio project. *loom: model checking for concurrent Rust code*.
    <https://docs.rs/loom/>
12. O. Reparaz, J. Balasch, and I. Verbauwhede. *Dude, is my code constant
    time?* DATE 2017. <https://doi.org/10.23919/DATE.2017.7927267>
13. NIST. *SAMATE: Software Assurance Metrics And Tool Evaluation*.
    <https://samate.nist.gov/>
14. D. G. Altman and J. M. Bland. *Diagnostic tests 1: sensitivity and
    specificity.* BMJ 308:1552, 1994.
    <https://doi.org/10.1136/bmj.308.6943.1552>
15. Open Source Security Foundation. *SLSA Specification v1.0: Provenance*.
    <https://slsa.dev/spec/v1.0/provenance>
16. in-toto. *in-toto Attestation Framework*. <https://in-toto.io/>
17. The Reproducible Builds project.
    <https://reproducible-builds.org/>
18. The Rust Project. *The Cargo Book: Build cache / target directory*.
    <https://doc.rust-lang.org/cargo/reference/build-cache.html>
