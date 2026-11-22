# ETP SARIF 2.1.0 projection

**Subphase:** Phase 10.2 (first executable vertical slice, part 1).
**Projection schema:** `frf-etp.sarif-projection.v1`.
**SARIF version:** 2.1.0 OASIS Standard.
**Implementation:** `src/sarif.rs`, `etp sarif verify`, `etp sarif export`.
**Committed projection:**
`evaluation/earned-trust/campaign.sarif` (SHA-256
`7920605d09808dae8b9fd8c6fce63ddd5b8656b09012e0242c6427d49f7382e1`).

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
* `properties.invalidation`.

A missing field is refused as `unauthorized_suppression`. A valid suppression
still differs from the native campaign record unless the corresponding receipt
also records it; the verifier compares the projected suppression to the receipt
and refuses an unauthorized projection. The committed campaign has no
suppression.

## 6. Repaired versus disappeared due to a tool change

A result that is present cannot claim an absence reason. If a future projection
uses `baselineState = "absent"`, the profile requires
`properties.absence_reason` to distinguish:

* `repaired`, with non-empty `properties.absence_evidence`; or
* `tool_change`, with non-empty `properties.absence_evidence` and a
  `previous_instrument_execution_identity` distinct from the current
  instrument-execution identity.

An absent result without that evidence is refused as `invalid_baseline_state`.
This prevents a disappeared finding from being silently relabeled as repaired
when only the instrument changed, and prevents a repair claim without evidence.
The committed projection emits no absent result.

## 7. Completeness, sharding, and limits

Every run records:

* `properties.limits.max_results` (1000);
* `properties.limits.max_bytes` (4 MiB);
* `properties.limits.result_count`;
* `properties.limits.encoded_bytes` (the canonical encoded length);
* `properties.limits.truncated`.

It also records `properties.completeness`:

* `complete`;
* `receipt_count`;
* `result_count`;
* `native_manifest` and `native_manifest_sha256`;
* `shards`.

The projection never truncates silently. If the result or byte limit would be
exceeded, `etp sarif export` returns a typed sharding-required refusal (exit 6)
rather than emitting an incomplete document. A sharded document must set
`complete = false`, declare explicit shard ranges, and retain the native closure
manifest. The verifier refuses a complete document that declares shards, an
incomplete document without shards, shard ranges that do not cover the results,
or a shard without a safe path, a SHA-256, or a positive result count.

The committed campaign is complete: 18 results, 42,988 canonical bytes.

## 8. Structural verification

`etp sarif verify evaluation/earned-trust/campaign.sarif` checks:

* the SARIF schema URI and `version = "2.1.0"`;
* exactly one run and the declared tool driver;
* the projection schema;
* the native closure manifest path, digest, and campaign reconciliation;
* the candidate, instrument, opening, and campaign identities;
* the result occurrence population against a fresh projection from the
  receipts;
* rule identifiers, rule indexes, levels, messages, locations, fingerprints,
  suppressions, and result properties;
* the rule table;
* the declared artifacts;
* `result_count`, `retained_finding_count`, `suppressed_result_count`, and the
  completeness/limit counts;
* the canonical encoded length;
* suppression justification, scope, owner, expiry, and invalidation;
* absent-result repair versus tool-change evidence;
* sharding coverage and limits.

A structurally readable but disagreeing document returns exit 4. A malformed or
unsupported document returns exit 3. A sharding-required export returns exit 6.

## 9. Limits and non-claims

The projection does not:

* establish that a finding is true outside its finite transcript scope;
* establish that a clean case is safe, memory-safe, or defect-free;
* establish that a missing finding is safe;
* establish detector sensitivity, specificity, or population recall;
* authenticate the campaign, the candidate, the instrument, or the findings;
* establish reviewer or adjudicator independence;
* establish transparency-log inclusion, consistency, or non-equivocation;
* establish a trusted time;
* make a GitHub code-scanning view, a SARIF consumer, or a dashboard
  authoritative;
* certify the software or authorize deployment.

DSSE, in-toto/SLSA, Sigstore, Rekor/C2SP, RFC 3161 timestamps, and TUF metadata
are not implemented. The native closure manifest is a SHA-256-bound bookkeeping
document, not an authenticated attestation.

## 10. References

1. OASIS, *SARIF 2.1.0 OASIS Standard*.
   <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>
2. OASIS, *SARIF 2.1.0 Errata 01*.
   <https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os.html>
3. This repository: `docs/ETP-CAMPAIGN.md`, `docs/ETP-CLAIM-INTEGRITY.md`,
   `docs/ETP-STANDARDS-REGISTRY.md`, `SPEC.md`.
