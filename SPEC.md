# FRF-MemorySafety normative protocol specification

**Specification identifier:** `frf-memorysafety-spec-v1`  
**Reference implementation:** `frf-memorysafety 0.2.x`  
**Status:** normative for this crate only. It is **not** an FRF OpenReceipt, an FRF
claim, an FRF-Fuzz content object, or a Gemel GCE object.

This document is written so that an independent implementation can be built
from it. Where the implementation is narrower than this specification, the
narrower supported profile is stated explicitly. Normative keywords are
MUST, MUST NOT, SHOULD, and MAY.

---

## 1. Purpose and non-transfer

This protocol records candidate-bound memory-safety assurance facts for an
unsafe-to-safe Rust compatibility conversion. It preserves separate axes for:

1. finite compatibility observations;
2. public safe-Rust contextual soundness;
3. deployment-scoped safety;
4. model-to-implementation correspondence;
5. cryptographic and security properties;
6. provenance and dependency closure.

A successful record MUST NOT be promoted from one axis to another. In
particular, none of the following inferences is admissible:

```text
compatibility              => sound safe interior
sanitizer pass             => sound safe interior
Miri pass                  => sound safe interior
absence of `unsafe`        => sound safe interior
source review              => cryptographic security
bounded model result       => universal native result
authentic-looking JSON     => authentic execution
clean detector run         => detector sensitivity
```

The finite profile in §8 has **no accepting rule** for universal Rust
soundness, native proof acceptance, or `SAFE_COMPATIBLE`.

---

## 2. Epistemic statuses

Statuses are kinds of statement, not points on a single ladder.

```text
SPECIFIED
MODELED
EXECUTED_MODEL
EXECUTED_NATIVE
CHECKED_PROOF
REVIEWED_ARGUMENT
NOT_RUN
UNSUPPORTED
UNKNOWN
CHALLENGED
INVALID_EVIDENCE
```

Each record carrying a status MUST also carry the property, legal domain,
candidate, environment, semantic model, and policy to which it applies.
Changing a status label MUST NOT strengthen its quantifier, execution mode,
origin, or property.

`PASS` is not a status. The implementation uses explicit outcome names such as
`DETECTED`, `MISSED`, `NOT_FALSIFIED`, or `COMPLETE_WITHIN_BOUNDED_SCOPE`.

---

## 3. Character encoding and canonical bytes

### 3.1 Encoding profile

FRF-MemorySafety defines a new, separately versioned restricted encoding:

**`ms-canonical-json-v1`**

It is intentionally narrower than RFC 8785/JCS. It MUST NOT be described as
JCS and MUST NOT be used as the canonical form of an external protocol.

* Input MUST be valid UTF-8.
* Top-level input MUST be a JSON value.
* Objects MUST have string keys.
* Duplicate keys at any object level MUST be rejected.
* Numbers MUST be integers fitting in `i64` or `u64`; floating-point numbers
  MUST be rejected.
* `true`, `false`, and `null` are permitted.
* Strings MUST be valid Unicode scalar values after JSON unescaping.
* Object keys are sorted by Unicode **UTF-16 code units**, ascending.
* No insignificant whitespace is emitted.
* `"` and `\` are escaped. `\b`, `\f`, `\n`, `\r`, and `\t` use their short
  escapes. Other code points below U+0020 use lowercase `\u00xx`.
* Non-ASCII scalar values are emitted as UTF-8.
* Unknown top-level or nested fields are rejected by the typed schema.
* Trailing bytes after the JSON value are rejected.

### 3.2 Resource limits

The reference implementation enforces these limits before or during parsing:

| resource | limit |
|---|---:|
| encoded bytes | 4 MiB |
| nesting depth | 64 |
| object members | 16,384 |
| array elements | 65,536 |
| string bytes | 1 MiB |
| total nodes | 262,144 |

Exceeding a limit is `INVALID_EVIDENCE`, never a warning.

### 3.3 Canonical check

A file claiming `ms-canonical-json-v1` is valid only if:

```text
canonical_encode(parse_strict(file_bytes)) == file_bytes
```

The parse and the typed decode MUST be performed separately. A typed decode
success does not establish canonicality. A digest does not establish origin.

---

## 4. Domain-separated identities

Identities are full SHA-256 values:

```text
ID = "ms1-" || lowercase_hex(SHA-256(domain_utf8 || 0x00 || canonical_bytes))
```

The domain separator is mandatory and typed in the API. The following domains
are defined:

```text
MS/SUBJECT/v1
MS/BOUNDARY/v1
MS/OBLIGATION/v1
MS/COURT/v1
MS/EXECUTION/v1
MS/FINDING/v1
MS/ASSESSMENT/v1
MS/HANDOFF/v1
MS/GRAPH/v1
MS/TRACE/v1
MS/CONTROL/v1
MS/POLICY/v1
```

External identities MUST retain their native type and textual form:

* FRF receipt/run IDs are opaque strings beginning `receipt-` or `run-`,
  validated only by their external producer.
* FRF-Fuzz content IDs are opaque 64-hex strings with BLAKE3 semantics.
* Gemel GIDs are opaque strings of the form `<family>.<64 lowercase hex>`.

They MUST NOT be parsed as `MsId`, rehashed as `MsId`, or replaced by a local
identifier. A hash match is not an authentication statement.

---

## 5. Core object model

All wire objects carry `schema` and `spec`. This profile uses:

```text
frf-memorysafety.manifest.v1
frf-memorysafety.claim.v1
frf-memorysafety.evidence.v1
frf-memorysafety.graph.v1
frf-memorysafety.footprint.v1
frf-memorysafety.trace.v1
frf-memorysafety.control.v1
frf-memorysafety.residual.v1
frf-memorysafety.handoff.v1
frf-memorysafety.report.v1
```

### 5.1 Claim coordinates

```text
ClaimKey = (property, legal_domain, candidate, environment, semantic_model)
```

`legal_domain` distinguishes:

```text
finite_observation
finite_model_exhaustion
bounded_model
universal_contextual
deployment_restricted
```

A claim record additionally names the policy/rule identity and evaluation
time as metadata. Time is never part of claim identity unless the question
itself is temporal.

### 5.2 Obligation lifecycle

```text
UNKNOWN -> CONTRACTED -> ESTABLISHED -> INDEPENDENTLY_CHECKED -> DISCHARGED
```

The additional states are:

```text
BLOCKED
STALE
INAPPLICABLE_WITH_EVIDENCE
REOPENED
```

`BLOCKED` never implies discharge. State advancement requires typed evidence
whose scope matches the obligation. A naked boolean, an author's own approval,
or an unverified log MUST NOT advance state.

### 5.3 Detector outcomes

```text
DETECTED
MISSED
NOT_RUN
UNSUPPORTED
INDETERMINATE
INVALID_EVIDENCE
```

`MISSED` is a `STOP` for every claim depending on that detector. A crash with
no independently established canary relevance is not `DETECTED`.

### 5.4 Execution modes

```text
AUTHENTIC_NATIVE
NATIVE_INSTRUMENTED
MOCK_PROVIDER
SUBSTITUTED_FFI
FINITE_EVENT_MODEL
UNSUPPORTED
```

Promotion from a weaker mode to `AUTHENTIC_NATIVE` requires a new authentic
observation. It cannot be performed by relabeling or metadata merge.

---

## 6. Founded support

### 6.1 Rule system

For a finite active claim set `Q`:

* `Rules(q)` is a finite set of conjunctive premise sets.
* An empty premise set is admissible only when `q` is listed as an externally
  justified leaf with an independent admission record, scope, and owner.
* Rules are identified by policy version.

For exclusions `X`:

```text
S_0(X) = {}
S_(k+1)(X) = S_k(X) union
             { q not in X | exists U in Rules(q): U subseteq S_k(X) }
S(X) = least fixed point
```

Positive support is `S(revoked)`. Admissible support is
`S(revoked union challenged)`. A challenge withholds the challenged claim and
all derivations requiring it while preserving positive-support history.

A self-cycle with no justified entry derives nothing. Mutually recursive
program components require an independently justified shared invariant; the
bookkeeping engine does not create one.

### 6.2 Certificates

A support certificate is every claim node in a finite derivation tree,
including intermediate nodes and the conclusion. `C(q)` is the family of
inclusion-minimal certificates.

* `q in S(X)` iff some certificate `C` satisfies `C intersect X = {}`.
* For fixed rules, newly excluded `Y` removes support iff `Y` intersects every
  previously surviving certificate.

The reference implementation provides:

* deterministic least-fixed-point evaluation;
* explanation/certificate enumeration with an explicit cap;
* exact-cut checking;
* positive versus admissible support;
* policy-versioned historical verdict reconstruction.

### 6.3 Policy changes

Changing an inference rule is not a leaf revocation. A verdict MUST record its
policy identity. Recomputing under a new policy produces a new verdict. The
historical verdict is reconstructed under its original policy and MUST remain
byte-identical.

---

## 7. Finite semantic profile

The profile admits exactly three rules.

### 7.1 Enumeration

The claim MUST have quantifier `finite_model_exhaustion`. The evidence MUST
name the exact case set, source/model/environment/policy anchors, artifact
bytes, and replayed observations. Coverage MUST be exact. Enumeration
concludes one property:

```text
model_clear   = no modeled violation in every case
model_parity  = every case agrees with the stipulated observation oracle
```

### 7.2 Restriction

The premise MUST be supported and have the same property, model, policy,
candidate, and environment. The target case set MUST be a subset of the
premise case set. A restriction MUST NOT expand a domain.

### 7.3 Conjunction

Two supported claims may be conjoined only when they describe the same finite
domain and scope and their properties are the permitted finite model
properties. Conjunction does not transport a property across domains.

### 7.4 Refusals

The profile MUST refuse:

* stronger quantifiers;
* native or universal Rust soundness claims;
* stale source/model/environment/policy anchors;
* artifact digest mismatch;
* a rehashed observation that disagrees with local model replay;
* wider domains through restriction;
* substituted properties;
* self-dependent derivation;
* duplicate claim identifiers;
* unknown fields;
* absent evidence bytes.

---

## 8. Dependency closure

Graph edges have one of these certainties:

```text
observed_dynamic
proven_static
conservative_possible
declared
unknown
```

The implementation exposes four views:

```text
declared_graph
statically_possible_graph
observed_graph
unresolved_summary
```

Only a closure whose edges are justified for the supported interaction family
is `JUSTIFIED_CONSERVATIVE_CLOSURE`. An observed omission falsifies the
declared inventory. A declared but unobserved edge yields `NOT_FALSIFIED`,
not conservative closure. An observed declared edge also yields
`NOT_FALSIFIED`.

An `unknown` edge is retained and blocks claims requiring its contract.
No "absent by default" rule is permitted.

---

## 9. Footprints and reference intervals

A footprint is one of:

```text
Exact(resource)
Indexed(resource, index)
Descendant(resource)
Escape(resource)
Top
```

Effects are:

```text
read, write, relocate, release, escape, callback, unwind,
reallocate, unknown_interference
```

Only soundly demonstrated abstract disjointness excludes a spatial conflict.
Abstract overlap is `POTENTIAL_CONFLICT`; it is not `CONFIRMED_INVALID`.
`UnsafeCell` may permit shared mutation, but it does not permit conflicting
live references under the chosen Rust model. An uninstrumented foreign
callback contributes `Top` until a justified contract narrows it.

---

## 10. Lifecycle traces

### 10.1 Storage

```text
Unallocated -> AllocatedUninit -> PrefixInitialized(n) -> Initialized
 -> Owned | BorrowedShared(n) | BorrowedExclusive
 -> Transferred | Freed | Poisoned
```

### 10.2 Responsibilities

```text
(resource_id, kind, required_disposition, holder, epoch)
```

Acquisition creates a pending responsibility. Discharge consumes it.
Successful transfer consumes the sender's responsibility and issues one for
the receiver. Failed transfer preserves the original holder unless the
contract states another completed disposition. Duplicate discharge and
unmatched transfer are protocol faults.

### 10.3 Trace outcomes

```text
VALID_COMPLETED_SESSION
MEMORY_INVALIDITY
RESOURCE_LEAK
VALID_TRANSFER_TO_CONTINUING_CUSTODY
OUTSTANDING_AT_COMPLETION
NOT_FINISHED
AVAILABILITY_FAILURE
UNRESOLVED_TRACE
```

An incomplete trace is `UNRESOLVED_TRACE`, not a pass. A manually typed trace
is a model test. It must be labeled `FINITE_EVENT_MODEL`; it is not evidence
that target events occurred.

---

## 11. Detector calibration

A calibration receipt MUST bind at least:

```text
control_id, hazard_id, source_digest, mutant_build_digest,
expected_mechanism, diagnostic_fingerprint,
instrument_digest, executed_child_digest,
assertion_or_exit_predicate, observed_stdout_digest, observed_stderr_digest,
process_outcome, tool_version, flags, seed_or_schedule,
containment_identity, specificity_control, adjudication
```

The following are not sufficient:

* `"detected": true`;
* a marker printed by the harness;
* a nonzero exit with no detector-specific diagnostic;
* a substring in an unverified user-supplied log;
* a detector run in which the instrument was not loaded.

A control that exits intentionally without triggering the detector is
`MISSED`.

---

## 12. External bridges

### 12.1 FRF

FRF remains the only producer of FRF receipts. This crate may parse and
structurally validate a receipt, retain its opaque ID, and refuse a mismatched
candidate. It MUST NOT emit an OpenReceipt. The current external writer is
`frf-receipt-v20`; this specification does not freeze future versions.

### 12.2 FRF-Fuzz

The external fixture interface is:

```text
target --frf-fuzz-fixture <path>
```

The fixture is arbitrary bytes. Finding and verification records are framed
binary values with external BLAKE3 identities. This crate may parse those
formats and retain their IDs; it MUST NOT synthesize a finding or a verification
record.

### 12.3 Gemel

This crate may produce a transcription proposal for `gemel.evidence.v1` only
after validating the external schema. Publication requires the actual Gemel
engine. A failed publication retains the local finding and reports
`GEMEL_PUBLICATION_FAILED`; it MUST NOT fabricate a GID.

---

## 13. Promotion

A promotion request names one of:

```text
BINARY_COMPATIBLE
FUNCTIONALLY_COMPATIBLE
SOUND_SAFE_INTERIOR
SAFE_COMPATIBLE
```

`SOUND_SAFE_INTERIOR` requires a recorded independent semantic argument over
arbitrary legal safe clients, including retained unsafe preconditions. The
software validates presence, scope, contradiction status, and reviewer
separation; it does not mechanically prove the argument.

`SAFE_COMPATIBLE` additionally requires:

* current-candidate FRF compatibility evidence;
* verified loaded-runtime closure;
* the named consumer's conservative dependency closure;
* all applicable obligations discharged;
* detector controls that actually detected their mechanisms.

The promotion engine MUST be fail-closed on unknown required premises.
`UNSUPPORTED` does not mean "proved unsafe".

---

## 14. Exit statuses

CLI exit codes:

```text
0  command completed and its own declared checks passed
2  invalid input or usage
3  evidence integrity failure
4  promotion refused / claim blocked
5  detector failure or MISSED control
6  external tool or integration unavailable (NOT_RUN)
7  internal harness error
```

Exit code `0` means the command executed. It does not mean a universal
soundness claim was established.
