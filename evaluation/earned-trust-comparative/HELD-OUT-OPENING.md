# Phase 17 held-out opening

**Status:** frozen before any held-out case was executed.
**Protocol:** `protocol.json`, version `phase17.2-amendment-001`.
**Frozen 1.0.0 baseline:** `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`.

| Artifact | SHA-256 |
|---|---|
| `protocol.json` | `cdc78441ed23a8f942a1fc5f4bb59192be9120adfb6c5135047d4435a2de00df` |
| `run_comparative.py` | `ab98ff9c35dab885d835a34964cac0c999a3bc7be549c15e9110e5c14516e69e` |
| `ci/etp-comparative-gate.sh` | `00c5c53c7f20746ce5a30df101d7861790d58c2fde9299a377a8fa1f54c4adb4` |

`HELD-OUT-OPENING.sha256` covers the protocol and the harness. The gate digest
is recorded here because the gate lives outside this directory.

## Frozen rules

1. The 12 held-out cases execute once under these digests. Their expected
   decisions and ground truth are not changed after execution.
2. A harness defect may be corrected only if the correction does not change
   the population, a mutation, an expectation or the decision surfaces. Such a
   correction is recorded in an amendment and the affected cases are replayed;
   the original observations are preserved.
3. A refusal is not a pass. A typed `NOT_RUN` is not a pass. An instrument
   error is not a correct refusal.
4. Every result, mismatch, negative finding and failure is reported, including
   if the preregistered acceptance criteria fail.
5. The development cases are not reclassified as held-out evidence.

## Known limitation carried forward

`c13` (`c13-sarif-unjustified-suppression`) is expected to refuse, but the
independent SARIF verifier hardcodes the pristine document's encoded byte count
and rejects `suppression_id` at the Rust layer, so its declared diagnostic may
not be reached. This is an instrument finding, not a reason to weaken either
verifier. It remains in the held-out population as declared.

## Non-claims

This opening does not establish independence, external review, certification,
universal effectiveness, or authorization to deploy. The foundation surface is
a modeled baseline over committed decision labels, not an execution of the
1.0.0 binary.
