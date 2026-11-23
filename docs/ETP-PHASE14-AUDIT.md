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

## Rust-level gaps (for 14.1b re-freeze)

| # | Gap | Struct / Test that would need instrument change |
|---|---|---|
| R1 | Missing explicit independent-review field in SARIF suppression struct | `src/sarif.rs` `SarifSuppressionProperties` lacks `independent_review` field; would need re-frozen instrument change |
| R2 | Unsupported non-source locations (MIR/machine/runtime) | `src/sarif.rs` `SarifPhysicalLocation` only handles `artifactLocation`; non-source locations not categorized; would need re-frozen instrument change |
| R3 | No `previous_instrument_execution_identity` in SARIF result properties for tool-change tracking | `SarifResultProperties` has the field (line 313) but exporter/importer may not persist it across rebuilds; audit gate would flag |
| R4 | In-toto predicate schema/spec not validated on SARIF import | `src/sarif.rs` verifies campaign closure but does not cross-check predicate schema against committed `trust-policy.json`; would need instrument change |