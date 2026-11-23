# Amendment A001 to the Phase 17 comparative protocol

**Status:** applied before any held-out execution.
**Trigger:** Phase 17.2 development run.
**Frozen 1.0.0 baseline:** `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`.
**Previous protocol digest:**
`51eaac167a0868341eb425119aff23f119e556c131686ac5544544a1da05a027`.
**Amended protocol digest:** see `OPENING.sha256`.

## 1. What the development run found

The development run executed only the six development cases. It recorded the
intact positive control `c01-positive-campaign-closure` as a refusal. The
diagnostic was exact:

```text
etp campaign verify: exit 3, invalid campaign: unknown field 'claim_ceiling'
reconstruct.py: exit 1, receipt file count is 14
```

The cause was not the campaign. The Phase 16.1b acceptance-controls receipt had
been written into `evaluation/earned-trust/receipts/`, and the campaign
verifier and reconstructor scan every JSON file in that directory as a
campaign receipt. The Phase 16.1b artifact was therefore a 14th receipt. The
placement was fixed in commit `b641cdd`; the receipt bytes and digest are
unchanged.

The development run also recorded three refusals whose decision matched the
expectation but whose diagnostic code differed. Two causes were identified:

- `c07` edited only `evaluation/earned-trust/trust-policy.json`, while
  `verify_attestations.py` also reads the copy under
  `evaluation/earned-trust/attestations/`. The copy mismatch was detected
  before the role check. The mutation must edit both copies identically to
  exercise the intended role-authorization control.
- `c13` adds a suppression whose `suppression_id` field is accepted by the
  independent verifier but rejected by the Rust `SarifSuppressionProperties`
  (`deny_unknown_fields`). The independent verifier also refuses earlier with
  `InconsistentCount` because it hardcodes `EXPECTED_ENCODED_BYTES` for the
  pristine document. This is an instrument limitation, recorded as a negative
  finding. The case's expected decision remains `refuse`; the protocol does not
  claim its expected diagnostic code was reached.

## 2. What changed

1. The `acceptance_controls` artifact binding now points at
   `evaluation/earned-trust/acceptance-controls/receipt.json`, the location
   created by commit `b641cdd`.
2. A new `attestation_policy` binding records the SHA-256 of
   `evaluation/earned-trust/attestations/trust-policy.json`.
3. The `c07` mutation now applies the same role reassignment to both policy
   copies and requires them to remain byte-identical.

The change is recorded in `protocol.json.amendments` and in
`protocol.json.protocol_version` (`phase17.2-amendment-001`).

## 3. What did not change

- The 18-case population, the 6/12 partition, the case ids, and the
  development/held-out split.
- Every expected augmented decision and every ground-truth decision.
- Every verifier command.
- The decision surfaces, metrics, acceptance criteria, exclusion rules,
  stopping rules and negative-finding policy.
- No held-out case was executed before or during this amendment.

## 4. Replay

The six development cases are re-executed under the amended protocol. Their
earlier receipts are retained as superseded development observations and are
not used in the final analysis. Held-out cases remain unexecuted.

## 5. Limits

This amendment is a protocol correction made before held-out execution. It is
not independent review, does not retroactively validate the earlier
development observations, and does not change the claim ceiling. The
instrument limitation in `c13` remains visible and must be reported in the
final results rather than repaired by weakening the verifier.
