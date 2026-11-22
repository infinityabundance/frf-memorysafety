# ETP authenticated corrections and revocation

**Subphase:** Phase 10.4a (corrections/revocation and durable archive).
**Protocol identifier:** `frf-etp-v1`.
**Implementation:** `src/etp_revocation.rs`, `src/cli.rs`,
`tests/etp_revocation.rs`, `evaluation/earned-trust/make_revocation.py`,
`evaluation/earned-trust/verify_revocation.py`,
`evaluation/earned-trust/revocations/`, and `ci/etp-time-gate.sh`.
**Frozen baseline:** FRF-MemorySafety 1.0.0 at commit
`02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`. This subphase does not change any
1.0.0 evidence, schema meaning, or claim ceiling.

This registry is append-only bookkeeping over declared evidence. It is not a
public revocation feed, not an adjudication of truth, and not a transparency
log. Public challenge and transparency inclusion remain Phase 10.4b or not
deployed.

---

## 1. Registry and entries

The registry is `evaluation/earned-trust/revocations/registry.json`:

| Field | Value |
|---|---|
| Schema | `frf-etp.revocation-registry.v1` |
| Registry identifier | `frf-etp-phase10.4a-revocation-registry` |
| Registry SHA-256 | `3ff8ec9443eb62b0cdc367b18c496b6ad2b4e89f5ef4a6617c41e99b93679bf7` |
| Policy identifier | `frf-etp-test-trust-policy-2026-11-22` |
| Policy version | `6` |
| Entries | `3` |
| Entry 1 | `rev-0001` revokes `evidence.closure` for `claim.campaign-closure` |
| Entry 2 | `cor-0002` records a correction without erasing history |
| Entry 3 | `dis-0003` retains a dissent for `claim.sarif-projection` |

Each entry is a DSSE envelope with payload type
`application/vnd.frf-etp.revocation+json`. The signed payload binds:

* the registry identifier, policy identifier, and policy version;
* the monotonic sequence, starting at 1;
* the SHA-256 of the previous canonical envelope, or `null` for the first;
* the entry identifier, action, target claim, target policy, target evidence,
  subject identity, reason, effective time, scope, historical-replay
  declaration, optional statement, and optional corrected entry.

The verifier recomputes the chain, the PAE bytes, the Ed25519 signature, the
role authorization, the key validity window, the policy freshness, and the
duplicate-target set. A signature by a key outside `correction_authority` is
refused even when the signature is valid. An entry presented under a different
registry identity is refused as a replay. A duplicate target revocation is
refused. A sequence gap, duplicate entry identifier, or wrong previous digest is
an integrity failure (exit 3).

## 2. Correction authority

The trust policy is `evaluation/earned-trust/trust-policy.json` (version 6). The
`correction_authority` role contains one test-only Ed25519 public key:

```text
keyid: frf-etp-test-correction-2026-11-22
actor: test-only-correction-authority
algorithm: ed25519
```

The private key is generated inside the hardened container, used once, and
removed by `make_revocation.py`. No private key is committed. The committed
`correction.pem` is the public key for inspection.

Adding this key and replacing the evidence-producer key were separate policy
changes. The policy version is monotonic; the historical attestation key and
scope remain unchanged where the evidence-producer role is concerned.

## 3. Founded-support application

`evaluation/earned-trust/revocations/support-model.json` declares one finite
support graph. Its support policy is
`frf-etp-phase10.4a-support-policy` version `1`. The historical verdict is
`evaluation/earned-trust/revocations/historical-verdict.json`, recorded under
the original policy with no revocations:

| Field | Value |
|---|---|
| Historical verdict digest | `ms1-0fccbeaabafb2c2c88931408f7649783f7d2129902e6561ace106984bbfd0db1` |
| Support-policy digest | `ms1-2d4f593acfe665fab69e2a36ebd0318a670a0641a854e5a5a9882ea4884e49f3` |

Applying `rev-0001` to `evidence.closure` produces:

| Claim | Historical | Present | Present admissible | Alternative support |
|---|---|---|---|---|
| `claim.campaign-closure` | supported | unsupported | no | no |
| `claim.campaign-closure-with-mirror` | supported | supported | yes | yes (`evidence.mirror`) |
| `claim.sarif-projection` | supported | challenged | no | no |
| `claim.attested-closure` | supported | unsupported | no | no |

The revoked claim remains historically valid because the recorded verdict
replays under its original policy and original revocation set. It is
inadmissible now because present authorization is a separate question under the
current registry and freshness rules. A later correction does not delete the
historical verdict; the `cor-0002` correction is retained. The `dis-0003`
dissent is retained and is not converted into a pass.

## 4. CLI

```sh
frf-memorysafety etp revocation verify REGISTRY \
  [--policy FILE] [--support FILE] [--historical FILE] [--now-unix N] [--json]
```

Exit statuses follow `SPEC.md` §14: `0` verified, `3` structural or integrity
failure, `4` refused, `7` encoding failure. The report keeps these dimensions
separate:

| Dimension | Meaning |
|---|---|
| `registry_integrity` | The registry parsed and its fields are structurally valid |
| `sequence_integrity` | The append-only sequence and hash chain match |
| `signature_validity` | At least one Ed25519 signature verified over PAE |
| `authorization` | A fresh `correction_authority` actor met the role threshold |
| `policy_freshness` | The policy and used keys are current |
| `historical_replay` | The recorded verdict replays under the original policy |
| `present_authorization` | Present support is admissible under the current registry and freshness rules |

The report also lists every signer, revocation, correction, retained dissent,
invalidated claim, surviving alternative support, withheld claim, and refusal.
It does not produce a confidence score or a composite.

## 5. Executed controls

`tests/etp_revocation.rs` executes thirteen tests:

| Control | Required result |
|---|---|
| valid registry | verified; revocation applied; historical replay valid |
| revoked but historically valid | historical supported; present inadmissible |
| duplicate revocation | `duplicate_revocation` |
| unauthorized signer | `unauthorized_role`; valid signature retained |
| replayed entry | `replayed_revocation` |
| stale policy | `stale_policy` |
| expired key | `expired_credential` |
| tampered entry | `invalid_signature` |
| chain mismatch | integrity failure, exit 3 |
| duplicate entry identifier | integrity failure, exit 3 |
| retained dissent and correction | both retained; status verified |
| stale support policy | `stale_support_policy`; present authorization withheld |
| missing support target | `missing_support` |

The independent `verify_revocation.py` runs six controls on the committed
registry: valid, stale policy, unauthorized signer, tampered entry, replayed
registry, and revoked-but-historically-valid. The gate requires
`controls passed: 6 of 6`.

## 6. Reproduction

```sh
./ci/etp-time-gate.sh
```

The gate verifies the committed registry with the Rust CLI and the independent
verifier, and re-generates a fresh correction key and registry under `target/`
for the focused tests. It does not mutate committed evidence.

## 7. Non-claims and limits

* A verified registry does not establish that a revocation is correct, complete,
  or globally visible.
* A revocation does not make the historical evidence false when produced.
* Historical replay under the original policy is not present authorization.
* The registry is not a public feed and is not a transparency log.
* The dissent and correction records are retained, but retention is not
  adjudication.
* There is no independent adjudicator, no public challenge service, and no
  non-equivocation guarantee in Phase 10.4a.
* A passing gate is not a certification and not an authorization to deploy.

## 8. Claim ceiling

A verified registry establishes only that the declared correction authority
signed the exact append-only entries under the declared policy and that the
declared founded-support model loses the dependent derivations named by applied
revocations unless an alternative valid support path survives. It does not
establish that a revocation is correct, complete, globally visible, or that
historical evidence was invalid when produced. Historical replay under the
original policy is not present authorization.
