# ETP implementation status matrix

**Release target:** FRF-MemorySafety 1.2.0 candidate-bound evidence (crate
version `1.2.0` in the working tree; not published).
**Evidence release:** `etp-evidence-v1` (1.1.0 historical) plus the
`evaluation/earned-trust-1.2.0/` migration candidate.
**Frozen 1.0.0 baseline:** `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`.

> **1.2.0 is not published and not an independent re-freeze.** The 1.2.0
> campaign is bound to candidate
> `79e72160a6a1c169093d5e7abb39f426a9f189d07aef7ddc472b3856911bcbb7`, instrument
> `832be8cdb11fe65a9e602832569942e7e81f15a8755188752e11ee96762bdfd0`, opening
> `180e50318dc045c9ea81168c7e1e958e1d9e108b9a99c662f06081967e8b7f8a` and
> closure `ece999b403e7ce05f94dbe2304a2b86b24afb1a9cd5dc5e1a5f57d22482d735a`.
> The gates and tests named in `evaluation/earned-trust-1.2.0/MIGRATION-STATUS.md`
> ran against it in hardened containers. No commit, tag, push, or publish was
> made, and no external review or external trust exists. The 1.1.0 evidence
> under `evaluation/earned-trust/` remains historical and unchanged.

**Purpose:** state, per capability, what exists, what actually ran, and what is
not established. A capability is not complete because it is documented.

Status vocabulary:

- **IMPLEMENTED**: code exists and a declared gate exercises it.
- **EXECUTED**: the exact evidence was produced by a real execution and is
  preserved.
- **MODELED**: an abstract or executable model was exercised, not the native
  implementation.
- **SPECIFIED**: a specification exists without an executed implementation.
- **NOT_RUN**: no qualifying execution exists.
- **KNOWN_GAP**: a declared capability failed its own control and remains
  incomplete.

No row in this matrix authorizes deployment, certifies a system, or establishes
external independence.

## 1. Core and ETP capabilities

| Capability | Status | Evidence | Limits |
|---|---|---|---|
| Domain-separated identities, typed statuses, founded support, revocation cuts | IMPLEMENTED | 1.0.0 suite; 509 debug and 509 release tests | Finite-profile ceiling retained |
| Native detector campaign | EXECUTED | 1.2.0: 13 cases, 25 raw evidence objects, 13 receipts; 1.1.0 set retained | Case population, not recall |
| Preregistered evaluation closure | EXECUTED | `evaluation/earned-trust-1.2.0/MANIFEST.json`, `protocol.json`, opening digest `180e5031…`, closure `ece999b4…` | Bookkeeping, not safety |
| SARIF projection and reconciliation | EXECUTED | 1.2.0: 18 results, 11 rules, 0 suppressed, 42988 bytes; independent verifier 18/18 controls | Report projection, not proof |
| DSSE attestations and signer roles | EXECUTED | 1.2.0 envelope `3eb0eb02…`, local test key, policy version 4, 13/13 controls | Local test signer; not external review |
| Local transparency log and checkpoints | EXECUTED | 1.2.0 local tlog profile, 20/20 controls; live tree size 261 | Not public Rekor v2; external witness NOT_RUN |
| Trusted time | EXECUTED | 1.2.0 local RFC 3161 token `e2972517…`, gen time 1795417198; 6/6 controls | Local TSA; not external trusted time |
| Revocation and historical verdict replay | EXECUTED | 1.2.0 registry `feddd64a…`, 3 entries, 6/6 controls | Local registry; c11 disagreement below |
| Local archive | EXECUTED | 1.2.0: 106 objects, 7 commands, 54 inputs; reconstruct and SARIF verifier run from archive root | Declared source included; still not external anchoring |
| Interoperability matrix | EXECUTED | 1.1.0 four-way matrix, deterministic population | Declared cases only; not re-run for 1.2.0 |
| Timing and information-flow profile | EXECUTED | 1.1.0 bounded profile, controls, explicit leakage-model limits | Not a constant-time proof; not re-run for 1.2.0 |
| Cross-property transformation | EXECUTED | 1.1.0 faulty/fixed traces, bounded analysis | Declared properties only; not re-run for 1.2.0 |
| Formal acceptance core | MODELED | Coq 8.16.1, 15 closed theorems, 8/8 seal cases | Finite abstract model; no Rust refinement |
| Adversarial acceptance controls | MODELED | 17 controls, 36/36 checks; 1.2.0 receipt `6cf8b0f5…` | Same-author executable oracle |
| Comparative evaluation | HISTORICAL / NOT_REBOUND | 1.1.0-bound 18 cases; independent reconstruction 6/6 and 11/12 | Does not apply to the 1.2.0 candidate |

## 2. Comparative evaluation results (historical 1.1.0, NOT_REBOUND)

> These results bind the 1.1.0 candidate and closure `d26e19bd…`. The 1.2.0
> binary replays the committed 1.1.0 corpus, but the corpus was **not rebound**
> to the 1.2.0 candidate. No row in this table applies to 1.2.0.

| Partition | Cases | Matched | Wrongful acceptance | Wrongful refusal | Unresolved | Restoration failures |
|---|---:|---:|---:|---:|---:|---:|
| Development | 6 | 6 | 0 | 0 | 0 | 0 |
| Held-out | 12 | 11 | 0 | 1 (`c18`) | 0 | 6 |
| Total | 18 | 17 | 0 | 1 | 0 | 6 |

The foundation surface is a modeled baseline over committed Phase 9 labels; it
accepted 18/18 by definition and is not an execution of the 1.0.0 binary. The
comparison measures the marginal effect of the ETP gates, not relative accuracy
of two executed systems.

## 3. Known instrument and evidence gaps

| Gap | Observed | Consequence |
|---|---|---|
| Archive self-containment | 1.2.0 archive includes the declared candidate/instrument source and runs `reconstruct.py` from the archive root | The 106-object archive is still not a certification and excludes undeclared source |
| Independent revocation verifier | Rust withholds `present_admissible`; independent verifier accepts | Independent verifier is not equivalent for claim-level refusal |
| SARIF suppression schema | Rust denies `suppression_id`; independent verifier requires it and hardcodes pristine encoded bytes | Declared suppression-review diagnostic not reached; both refuse |
| Proof manifest-only verification | Exit 6 `checker_unavailable` without `--live` | Manifest validation is not proof checking; live Coq is the proof gate |
| Transparency restoration commands | Independent verifier output not JSON; checkpoint reports `consistency_not_checked` at exit 0 | Restoration classification unresolved/refused; commands need revision |
| Claim-level restoration | `c11` has no artifact mutation and the intact claim remains withheld | Restoration expectation is not achievable; recorded failure |
| Comparative evaluation is 1.1.0-bound | The 1.2.0 binary replays the committed 1.1.0 comparative corpus | The 18-case comparative result does not apply to the 1.2.0 candidate until rebound |

These are recorded so that no reader mistakes a green end-to-end run for
complete instrument agreement.

## 4. What is not established

- Universal memory safety, functional correctness, or specification
  correctness.
- Detector sensitivity, population-level recall, or absence of defects.
- Complete dependency or dynamic reachability closure.
- Constant-time behaviour outside the declared leakage model.
- External review, external witnessing, public transparency, or public trusted
  time.
- Administrator independence of the Rust CLI, Python verifiers and Coq
  development.
- Certification, regulatory compliance, or authorization to deploy.
- Re-execution of the native fixtures and provider instruments from the archive
  alone; the archive carries declared source, not the container images or
  toolchain network state.

## 5. Release gates

The release gate runs the declared gate inventory in sequence and records each
result. A gate result is not certification. A typed NOT_RUN is not a pass. See
`docs/ETP-EXTERNAL-REPRODUCTION.md` for exact commands. The 1.2.0 migration gate
results are recorded exactly in
`evaluation/earned-trust-1.2.0/MIGRATION-STATUS.md`; the full
`ci/etp-release-gate.sh` inventory was not run for 1.2.0 because its remaining
evidence gates still write 1.1.0 artifacts under `evaluation/earned-trust/`.
