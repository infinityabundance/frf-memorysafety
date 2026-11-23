# ETP SARIF 2.1.0 projection

**Subphase:** Phase 10.2 (first executable vertical slice, part 1).
**Projection schema:** `frf-etp.sarif-projection.v1`.
**SARIF version:** 2.1.0 OASIS Standard.
**Implementation:** `src/sarif.rs`, `etp sarif verify`, `etp sarif export`.
**Committed projection:**
`evaluation/earned-trust/campaign.sarif` (SHA-256
`336edb23e8ee3c4c9a31c2a83ec645a0993421bfd0cf775a17990ca40e9b8f8b`).

Phase 10.3 re-projected the SARIF document after the explicitly recorded
instrument change and campaign re-execution described in
[`ETP-AUTHENTICATED-EVIDENCE.md`](ETP-AUTHENTICATED-EVIDENCE.md). The 18 results,
11 rules, and 0 suppressions are unchanged; the candidate and instrument
identities are the Phase 10.3 values.

A SARIF document is a report format. It is not a correctness, memory-safety,
compatibility, or security proof. A GitHub code-scanning view is not
authoritative. The projection exists so that the campaign's retained failures
and unresolved conditions can be inspected with standard tooling without
collapsing their identities.

---

## 1. What is projected

The projection reads the committed closure manifest, the 13 per-case receipts,
and their raw evidence. It emits one SARIF run with:

* one result per retained court finding;
* one outcome result when a non-clean case has no finding (for example, the
  oversized-output control);
* no result for a clean `verified_compatible_within_transcript` case;
* a rule table keyed by the pair (terminal outcome, hazard);
* a declared artifact for every fixture that produced a transcript-backed
  non-clean result;
* no suppression in the committed campaign.

The committed projection has 18 results, 11 rules, 8 declared artifacts, and 0
suppressions.

## 2. Identity model

The projection deliberately preserves distinct identities.

| Identity | Representation |
|---|---|
| Rule | `ruleId` = `FRF-ETP-<OUTCOME>-<HAZARD>` (or `FRF-ETP-<OUTCOME>` when they coincide); `ruleIndex` selects the rule |
| Hazard | `properties.hazard` = the court finding code, or the terminal outcome when no finding exists |
| Logical finding | `locations[].logicalLocations[]` = finding subject and kind; `properties.finding_codes` lists every code retained for the case |
| Occurrence | `properties.occurrence_id` = `<case>::<hazard>::<index>`; `fingerprints["frf/occurrence"]` |
| Case | `properties.case_id`; `fingerprints["frf/case"]` |
| Candidate | `properties.candidate_identity`; `fingerprints["frf/candidate"]`; `run.properties.candidate_identity` |
| Instrument execution | `properties.instrument_execution_identity`; `fingerprints["frf/instrument-execution"]`; the run-level `instrument_identity` binds the instrument tree |
| Campaign | `run.properties.campaign_id` |
| Opening manifest | `run.properties.opening_sha256` |
| Native closure | `run.properties.completeness.native_manifest` and `native_manifest_sha256` |

The occurrence identity is not the rule identity. Several occurrences can share
one rule (for example, multiple `data_race` findings). Several hazards can share
one case. The projection does not merge them.

## 3. Projection rules

For each receipt, sorted by case identifier:

1. If the terminal outcome is `verified_compatible_within_transcript`, emit no
   result and require the receipt to retain no findings.
2. If the receipt has findings, emit one result per finding in receipt order.
3. Otherwise emit one result whose hazard is the terminal outcome.
4. The result level is `error` for `observed_violation`, `illegal_case`, and
   `harness_failure`; `warning` for `incomplete_transcript` and `unresolved`;
   and `note` for `not_run`.
5. The message names the case, terminal outcome, hazard, and the exact retained
   finding or observation detail.
6. `baselineState` is `new` for a present result. A present result records
   `properties.absence_reason = "not_compared"`.

No result is dropped because it is a failure, an incomplete transcript, an
unresolved observation, an illegal case, or `NOT_RUN`.

## 4. Locations

A physical location is emitted only when the receipt has a raw transcript and the
fixture path is declared by the campaign. The location contains exactly one
`artifactLocation.uri` naming that fixture. The profile does not emit a `region`
and does not invent a line, column, snippet, or function. A harness-level or
binary finding without a transcript carries no physical location.

A logical location is emitted only from a retained finding subject. It names the
subject and kind; it is not a source coordinate.

The verifier refuses a physical location whose URI is not a declared fixture and
rejects an invented region structurally.

## 5. Suppression

A suppression is not a deletion. A suppressed result remains in `results` and
remains counted in `result_count`, `retained_finding_count`, and
`suppressed_result_count`.

The profile requires every suppression to carry:

* `kind = "external"`;
* a non-empty `justification`;
* `properties.scope`;
* `properties.owner`;
* `properties.expiry`;
* `properties.invalidation`;
* `properties.suppression_id` (a stable identifier used to link the suppression
  to its review record).

A missing field is refused as `unauthorized_suppression`. A valid suppression
still differs from the native campaign record unless the corresponding receipt
also records it; the verifier compares the projected suppression to the receipt
and refuses an unauthorized projection. The committed campaign has no
suppression.

### 5.1 Suppression review manifest

Every suppression must have a matching review entry in the linked native
record `evaluation/earned-trust/suppression-review.json`, validated against
`schemas/etp/suppression-review.v1.schema.json`. A review entry must include:

* `suppression_id` (matches the SARIF suppression `properties.suppression_id`);
* `result_id` (the occurrence identity of the suppressed result);
* `justification`, `scope`, `owner`;
* `reviewer_identity`, `reviewer_role`;
* `independent_of_producer` (must be `true`; a producer self-review is refused);
* `expiry`, `invalidation`;
* `evidence_digest` (SHA-256 of the review evidence).

The verifier refuses a suppression without a matching review entry as
`missing_suppression_review` and refuses a producer self-review as
`self_review`. The committed campaign has an empty `reviews` array because it
has no suppressions.

## 6. Repaired versus disappeared due to a tool change

A result that is present cannot claim an absence reason. If a future projection
uses `baselineState = "absent"`, the profile requires
`properties.absence_reason` to distinguish:

* `repaired`, with non-empty `properties.absence_evidence`; or
* `tool_change` or `instrument_change`, with non-empty
  `properties.absence_evidence` and a `previous_instrument_execution_identity`
  distinct from the current instrument-execution identity; or
* `population_change`, with non-empty `properties.absence_evidence`.

An absent result without that evidence is refused as `invalid_baseline_state`.
This prevents a disappeared finding from being silently relabeled as repaired
when only the instrument changed, and prevents a repair claim without evidence.
The committed projection emits no absent result.

## 7. Predicate cross-check

The verifier cross-checks the SARIF native manifest's campaign identity and
digest against the committed campaign closure (`evaluation/earned-trust/MANIFEST.json`)
and the attested campaign-closure statement
(`evaluation/earned-trust/attestations/campaign-closure.statement.json`). It
requires:

* the predicate `schema` to be `frf-etp.predicate.campaign-closure.v1`;
* the predicate `spec` to be `frf-etp-v1`;
* the predicate `closure_sha256` to equal the SHA-256 of the committed
  `MANIFEST.json`;
* the predicate `campaign_id` to equal the SARIF `campaign_id`;
* the campaign-closure subject digest to equal the SHA-256 of the committed
  `MANIFEST.json`.

A mismatch is refused as `predicate_mismatch`. This prevents a SARIF projection
from being presented against a different campaign closure or predicate.

## 8. Source-only location support

The profile supports source locations only. A physical location is emitted only
when the receipt has a raw transcript and the fixture path is declared by the
campaign. The location contains exactly one `artifactLocation.uri` naming that
fixture. The profile does not emit a `region` and does not invent a line,
column, snippet, or function. A harness-level or binary finding without a
transcript carries no physical location.

A logical location is emitted only from a retained finding subject. It names the
subject and kind; it is not a source coordinate.

The verifier refuses a physical location whose URI is not a declared fixture and
rejects an invented region structurally. A location that explicitly declares a
non-source kind (for example, `properties.location_kind = "mir"`,
`"machine"`, or `"runtime"`) must carry an explicit justified native reference
(`properties.native_reference` with a non-empty `uri` and `justification`);
otherwise it is refused as `non_source_location`. The profile does not invent
MIR, machine, or runtime locations; source-only support is a declared
limitation, not a completeness claim.
