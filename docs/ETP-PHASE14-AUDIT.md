# ETP Phase 14 Audit Matrix

**Frozen baseline:** FRF-MemorySafety 1.0.0 at commit `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`
**Phase:** 14.1 (external gaps only; no Rust changes)
**Commit:** `3206735` (staging, HEAD)

| # | Requirement | Status | File / Test Reference |
|---|---|---|---|
| 1 | **lossless SARIF projection** | IMPLEMENTED | `src/sarif.rs`, `tests/sarif.rs`, `evaluation/earned-trust/campaign.sarif`; `ETP-CAMPAIGN.md` §1-9 |
| 2 | **native reconciliation** | IMPLEMENTED | `ci/etp-gate.sh` runs native campaign; `evaluation/earned-trust/MANIFEST.json`; `src/sarif.rs` completeness |
| 3 | **seven in-toto predicate types** | IMPLEMENTED | `src/etp_auth.rs` `PredicateKind` (7 types); `verify_attestations.py` `PREDICATE_TYPES`; schemas in `schemas/etp/` |
| 4 | **DSSE exact-byte PAE** | IMPLEMENTED | `verify_attestations.py` `pae()` function (lines 117-132); `ETP-AUTHENTICATED-EVIDENCE.md` §2 |
| 5 | **role authorization** | IMPLEMENTED | `src/etp_auth.rs` role resolution (lines 349-362); `verify_attestations.py` `parse_policy` (lines 247-323); `ROLE_*` constants |
| 6 | **independent verifier** | IMPLEMENTED | `evaluation/earned-trust/verify_attestations.py` (OpenSSL-based, no Rust import) |
| 7 | **correctly signed incomplete/incorrect refusal** | PARTIAL | `verify_attestations.py` has `InsufficientIndependentReview`, `SemanticSupportNotEvaluated`, `FalseConclusion`; missing explicit refusal for weakly signed incomplete statements in Rust (`src/etp_auth.rs` §7) |
| 8 | **SARIF errata/consumer restrictions** | PARTIAL | `src/sarif.rs` has version/schema checks, suppression checks, baseline state; errata 01 not explicitly checked in verifier |
| 9 | **rule/hazard/finding/occurrence/candidate/instrument identities** | IMPLEMENTED | `src/sarif.rs` identity model (lines 44-58): `ruleId`, `properties.hazard`, `properties.case_id`, `properties.candidate_identity`, `properties.instrument_execution_identity`; `tests/sarif.rs` identity tests |
| 10 | **location precision (source/generated/MIR/machine/runtime)** | PARTIAL | `ETP-CAMPAIGN.md` §4: no invented regions, no physical location without transcript; `src/sarif.rs` `FabricatedLocation` refusal; missing explicit MIR/machine/runtime location categories |
| 11 | **export of failures/unresolved** | IMPLEMENTED | `src/sarif.rs` exports all results including failures/unresolved; `tests/sarif.rs` `limit_exceeded`, `inconsistent_result_count`, `missing_native_manifest` tests |
| 12 | **sharding/native manifests** | IMPLEMENTED | `src/sarif.rs` completeness with `native_manifest` and `native_manifest_sha256`; `limits` with `max_results`, `max_bytes`, `truncated`; `tests/sarif.rs` `incomplete_sharding` |
| 13 | **suppression justification/scope/owner/review/expiry/invalidation** | PARTIAL | `src/sarif.rs` `SarifSuppressionProperties` has `scope`, `owner`, `expiry`, `invalidation` (lines 267-276); `ETP-CAMPAIGN.md` §5 requires all 5 fields; verifier checks them but Rust-side enforcement needs audit |
| 14 | **suppressed finding remains a finding** | MISSING | No test or struct ensuring suppressed results stay in `results` count and are not dropped; `tests/sarif.rs` `suppression_does_not_remove_a_finding` verifies count but structural guarantee needs documentation |
| 15 | **repaired-vs-disappeared distinction** | PARTIAL | `src/sarif.rs` `check_baseline_state` (lines 1038-1096) refuses `absent` without `absence_evidence`; `absent` with `repaired` or `tool_change` distinguished; committed campaign emits no absent result |
| 16 | **parser hardening** | PARTIAL | `verify_attestations.py` has duplicate-key, oversized-payload, excessive-nesting, signature-count >16, duplicate-keyid, unsupported-algorithm, exact-byte PAE, keyid-as-hint-not-authorization checks (see §17); Rust-side parser gaps noted in audit |
| 17 | **authentication separate from semantic support/authorization/scope/freshness** | IMPLEMENTED | `verify_attestations.py` seven dimensions: `signature_validity`, `payload_integrity`, `authorization`, `scope_applicability`, `freshness`, `semantic_support`, `independent_review` (lines 478-492); each tracked independently in `AttestationDimensions` |
| 18 | **keyid as hint** | IMPLEMENTED | `ETP-AUTHENTICATED-EVIDENCE.md` §2: `keyid` is a lookup hint only; `verify_attestations.py` `parse_envelope` validates duplicate keyid; `parse_policy` does not grant authority from keyid match; `src/etp_auth.rs` `AuthorizedKey` has `keyid` as hint |

## Phase 14.1b external-closure status (linked native evidence)

Phase 14.1b closed the external-closure gaps without any Rust source change and
without a campaign re-freeze. The independent Python SARIF verifier
(`evaluation/earned-trust/verify_sarif.py`) now enforces the linked native
suppression-review record and the attested campaign-closure predicate.

| # | Requirement | Status | Linked native evidence / Control |
|---|---|---|---|
| R1 | Missing explicit independent-review field in SARIF suppression struct | **CLOSED via linked native evidence** | `schemas/etp/suppression-review.v1.schema.json` + `evaluation/earned-trust/suppression-review.json`; verifier requires a matching review entry with `independent_of_producer = true`; producer self-review refused; self-test control `pass:SelfReview` |
| R2 | Unsupported non-source locations (MIR/machine/runtime) | **DECLARED SOURCE-ONLY LIMITATION** | Source-only support is declared; non-source locations require an explicit justified native reference; no native/MIR/machine/runtime location is invented; self-test control `pass:NonSourceLocation` refuses a non-source location without native reference |
| R3 | No `previous_instrument_execution_identity` in SARIF result properties for tool-change tracking | **CLOSED via linked native evidence** | Absent results require `absence_reason` in {`repaired`, `tool_change`, `population_change`, `instrument_change`}, non-empty `absence_evidence`, and (for tool/instrument change) a distinct `previous_instrument_execution_identity`; self-test controls `pass:InvalidBaselineState` |
| R4 | In-toto predicate schema/spec not validated on SARIF import | **CLOSED via linked native evidence** | Verifier cross-checks the SARIF native-manifest digest against the committed `MANIFEST.json` SHA-256 and the attested campaign-closure predicate (`frf-etp.predicate.campaign-closure.v1`, `frf-etp-v1`, subject digest); self-test control `pass:PredicateMismatch` |

**Honest Rust-level partial.** The Rust SARIF struct (`src/sarif.rs`)
`SarifSuppressionProperties` does not carry an `independent_review` field and
`SarifResultProperties` does not carry the full absence-evidence vocabulary.
The linked suppression-review manifest is therefore the authoritative
independent-review requirement; the Rust projection remains unchanged and no
campaign re-freeze was performed.