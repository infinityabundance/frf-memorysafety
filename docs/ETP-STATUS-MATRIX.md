# ETP implementation status matrix

**Release target:** FRF-MemorySafety 1.2.0.
**Frozen 1.0.0 baseline:** `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`.
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
| Native detector campaign | EXECUTED | 13 cases, 25 raw evidence objects, 13 receipts, 60 canonical receipt set | Case population, not recall |
| Preregistered evaluation closure | EXECUTED | `evaluation/earned-trust/MANIFEST.json`, `protocol.json`, opening digest | Bookkeeping, not safety |
| SARIF projection and reconciliation | EXECUTED | 18 results, 11 rules, independent verifier and controls | Report projection, not proof |
| DSSE attestations and signer roles | EXECUTED | Live envelope, local test key, trust policy, controls | Local test signer; not external review |
| Local transparency log and checkpoints | EXECUTED | Local tlog profile, inclusion, consistency, witness state | Not public Rekor v2; external witness NOT_RUN |
| Trusted time | EXECUTED | Local RFC 3161 token and verification | Local TSA; not external trusted time |
| Revocation and historical verdict replay | EXECUTED | Registry, support model, historical verdict | Local registry; c11 disagreement below |
| Local archive | KNOWN_GAP | 76 objects verify; `reconstruction.complete` false; offline reconstruct fails on missing `Cargo.toml` | Not self-contained; source overlay required |
| Interoperability matrix | EXECUTED | Four-way matrix, deterministic population | Declared cases only |
| Timing and information-flow profile | EXECUTED | Bounded profile, controls, explicit leakage-model limits | Not a constant-time proof |
| Cross-property transformation | EXECUTED | Faulty/fixed traces, bounded analysis | Declared properties only |
| Formal acceptance core | MODELED | Coq 8.16.1, 15 closed theorems, 8/8 seal cases | Finite abstract model; no Rust refinement |
| Adversarial acceptance controls | MODELED | 17 controls, 36/36 checks | Same-author executable oracle |
| Comparative evaluation | EXECUTED | 18 cases, 18 receipts, independent reconstruction | 11/12 held-out; 4 claims refuted |

## 2. Comparative evaluation results

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
| Archive self-containment | `etp archive verify` reports `verified` while `reconstruction.complete` is false; offline `reconstruct.py` needs `Cargo.toml`, `rust-toolchain.toml`, source and fixtures | The 76-object archive is evidence-only; the release package must overlay the source tree |
| Independent revocation verifier | Rust withholds `present_admissible`; independent verifier accepts | Independent verifier is not equivalent for claim-level refusal |
| SARIF suppression schema | Rust denies `suppression_id`; independent verifier requires it and hardcodes pristine encoded bytes | Declared suppression-review diagnostic not reached; both refuse |
| Proof manifest-only verification | Exit 6 `checker_unavailable` without `--live` | Manifest validation is not proof checking; live Coq is the proof gate |
| Transparency restoration commands | Independent verifier output not JSON; checkpoint reports `consistency_not_checked` at exit 0 | Restoration classification unresolved/refused; commands need revision |
| Claim-level restoration | `c11` has no artifact mutation and the intact claim remains withheld | Restoration expectation is not achievable; recorded failure |

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
- Byte-identical reconstruction of the archive from the 76 objects alone.

## 5. Release gates

The release gate runs the declared gate inventory in sequence and records each
result. A gate result is not certification. A typed NOT_RUN is not a pass. See
`docs/ETP-EXTERNAL-REPRODUCTION.md` for exact commands.
