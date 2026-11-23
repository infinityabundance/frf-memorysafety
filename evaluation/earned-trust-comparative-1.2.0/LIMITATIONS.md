# FRF-MemorySafety Phase 17.1 comparative limitations

> **1.2.0 replication note.** This file is copied verbatim from the frozen 1.1.0
> comparative limitations. It remains normative for the 1.2.0 replication. Read
> every 1.1.0-specific statement together with `REPLICATION.md`, which records
> the evidence rebinding. As originally run, three cases (`c14`, `c15`, `c16`)
> were typed `NOT_RUN` because their declared base artifacts were absent;
> amendment `A002` produced those artifacts and replayed exactly those three
> cases (`REPLAY-1.2.0.md`). The limitation that a `NOT_RUN` is not a pass still
> applies to the original run, and the replay does not broaden any claim.

**Protocol:** `phase17.1-v1`
**Frozen protocol:** [`protocol.json`](protocol.json)
**Freeze sidecar:** [`OPENING.sha256`](OPENING.sha256)

This document states the threat model, the known confounders, and what the
comparative evaluation cannot establish. It is normative for interpretation. A
result from this evaluation may not be reported with a stronger claim than this
document allows.

No verifier, gate, `cargo`, `coqc`, Python verification script, or test was run
in this subphase. Nothing here is a measured result.

---

## 1. Evidence kind

The evaluation compares two **decision surfaces** over a fixed, finite, 18-case
control population:

- **(A) the pre-ETP foundation surface**, modeled over the committed Phase 9
  campaign decision labels; and
- **(B) the augmented ETP evidence chain**, the declared Rust CLI commands and
  independent verifiers run over a mutated copy of the committed evidence.

The unit of evidence is a per-case receipt from the harness. The harness copies
the declared base artifacts into a temporary work directory, applies one
declared mutation, runs the declared commands, and records exact argv, exit
status, stdout and stderr digests, report fields, wall-clock cost, and bytes
read. The foundation receipt is computed from the committed baseline anchor, not
from the mutated copy.

This is an **instrumented control-family comparison**, not an observational
study, a random sample, a population estimate, or a deployment test.

---

## 2. Threat model

### 2.1 Adversary capabilities in scope

The declared mutations model an adversary who can present committed-looking
evidence that differs from the frozen baseline in one of the following ways:

- substitute the candidate identity or the artifact binding in a native receipt;
- delete a required receipt, raw-evidence record, or archived object;
- truncate the population and make the summary counts internally consistent;
- duplicate or conflict with a population row;
- substitute DSSE payload bytes while retaining the signature;
- present a valid signature from a key that is outside the required role or
  authorized only for a different role;
- reorder or replace transparency audit-path siblings, or present a stale
  checkpoint below the declared known horizon;
- present an RFC 3161 token against a different evidence imprint;
- rely on a claim whose supporting evidence has been withdrawn by a committed
  revocation or correction;
- add a SARIF suppression without an independent review record;
- label a repair fixed while its failure/relocation path omits the cleanse;
- omit a required client/server cell from an interoperability or TLS matrix; or
- remove a required theorem from a declared formal-closure or admission record.

The adversary may copy, delete, reorder, or substitute bytes in the presented
evidence. The adversary does not need to modify the repository, and the harness
does not modify the repository.

### 2.2 Adversary capabilities out of scope

The evaluation does **not** model or test:

- a forger who can produce a valid Ed25519 signature under a committed key
  without the private key;
- a collision or preimage attack on SHA-256;
- a compromise of the build toolchain, container runtime, kernel, or hypervisor;
- a repository owner who rewrites history or changes the frozen baseline;
- a compromised TSA, transparency-log key, witness key, or correction key;
- a malicious or backdoored verifier script, harness, or analysis step;
- a side-channel, fault-injection, or physical attack;
- a real deployment, a public transparency log, an external trusted timestamp
  authority, an external witness, or a public revocation feed;
- an independent human reviewer, adjudicator, or certification body.

These are outside the declared legal domain and threat model. A result from this
evaluation says nothing about them.

---

## 3. Confounders

### 3.1 The foundation is modeled, not executed

The foundation surface is a modeled baseline over the committed Phase 9 campaign
decision labels. It is **not** an independent execution of the 1.0.0 binary in
this subphase, and the evaluation does not claim that the 1.0.0 binary would
accept the mutated evidence. The comparison is between the declared decision
surface, not between two executed binaries. The foundation's expected
acceptance of all 18 cases follows from its definition and from the committed
`pass` labels; it is not an observation about the binary. The foundation is
therefore a lower bound with the compared gates removed by construction. The
evaluation quantifies the marginal effect of the ETP gates over a baseline that
lacks them; it is not a fair accuracy comparison between two executed systems
and must not be reported as one.

### 3.2 Same-repository independence

The Rust CLI and the Python verifiers are algorithmically separate but share the
same repository and the same authoring process. They are not administratively
independent, and a passing agreement between them is not external review,
certification, or independent confirmation. The term "independent verifier" in
this protocol means "does not import or execute the Rust crate", not
"administratively independent".

### 3.3 Local-test-only trust anchors

The committed transparency log, TSA, witness state, and correction authority are
local test material:

- the transparency log is a local test log, not a public transparency log;
- the TSA is a local test TSA, not external trusted time;
- the witness state is `not_observed` and external witnessing is not
  established;
- the revocation registry is not a public feed and is not complete;
- the attestation signer is a test-only evidence producer, not an independent
  reviewer.

The augmented chain's acceptance of the transparency, time, and attestation
cases is acceptance within these local trust domains only.

### 3.4 Harness checks versus verifiers

The cross-property, interop, and TLS cases use declared harness checks over the
committed report bytes. These checks reuse the committed harness's population
and matrix functions or a declared trace invariant. They are not independent
verifiers and do not execute a separate implementation. They test the report's
declared shape and completeness, not the truth of the underlying execution.

The formal case uses a manifest-only proof check as its deciding command. Manifest
validation is not proof checking. The optional `proof verify --live` command is
not decisive; it may return `NOT_RUN` when `coqc` is unavailable, and it is never
counted as a pass.

### 3.5 Environment-sensitive profiles

The cross-property, interop, and TLS artifacts were produced by instrumented
harnesses under declared container caps and toolchains. Their committed reports
contain environment-specific paths, binary digests, and process maps. The
evaluation does not treat those fields as portable evidence, and it does not
compare them across hosts or images. The TLS matrix additionally depends on
pinned reference and candidate OpenSSL prefixes that may be unavailable in a
clean checkout; if a declared instrument is unavailable, the case is
`unresolved` and reported, never passed.

### 3.6 Documentation and artifact version lag

The repository documentation contains version-specific counts, digests, and
status values for earlier phases. The frozen bytes committed at the evaluation
commit are authoritative for this protocol: every base artifact is bound by its
SHA-256 in `protocol.json` and `POPULATION.md`. The protocol does not rely on any
documentation count or historical digest. A disagreement between a documented
count and the current artifact is a documentation finding, not a license to
change a ground-truth label or an expected decision.

### 3.7 Verifier-clock parameters

The time and revocation commands use artifact-derived integer times so the
verifier clocks are deterministic and inside the committed validity windows.
Those values are not a record of when the evaluation runs. If the execution
environment's wall clock is outside the trust-policy validity window for a
command that has no explicit time argument, the affected case may be refused as
a freshness failure. That is a run-time finding, reported as such; it is not a
ground-truth change and it does not authorize a pass.

### 3.8 Cost measurement

Wall-clock and bytes-read are per-run resource accounting. Build time, container
startup, and filesystem cache effects can dominate the measurement. The values
are not comparable across hosts, images, or runs, and they are not a performance
or efficiency claim about the algorithms.

### 3.9 Ground truth authorship

The ground-truth labels and the mutations were authored during the design of
this protocol, before any execution. They are not the product of an independent
adjudicator. The expected refusals follow from the documented semantics and the
committed verifier usage, not from guessing observed output. An observed
disagreement is a finding; it is not a reason to relabel the ground truth after
the fact.

### 3.10 Selection rule

The development/held-out split is a deterministic index rule over the frozen
case ids. It protects against post-execution reassignment within this population.
It is not a random sample and does not undo prior exposure of these artifact
families during repository development. It is not a temporal holdout.

---

## 4. What the evaluation cannot establish

The evaluation cannot establish any of the following:

- that the augmented chain is **complete**: it may fail to refuse a mutation
  outside the 18 declared cases;
- that the augmented chain is **sound in general**: a verifier may accept or
  refuse for reasons unrelated to the declared semantic property;
- that a declared verifier's implementation matches its documentation beyond the
  declared cases;
- that the foundation binary behaves as modeled;
- that the 1.0.0 baseline is unaffected: the evaluation adds a new population
  and changes no 1.0.0 artifact or claim;
- that the 18 cases are representative of real attacks, real defects, real
  deployments, or a population;
- that a control's success generalizes to another fixture, host, compiler,
  optimization level, container, or trust domain;
- that the transparency log is public, complete, non-equivocating, or externally
  witnessed;
- that the timestamp is external trusted time or that it establishes execution
  time;
- that the revocation registry is a complete public feed;
- that the attestation signer is independent or that independent review exists;
- that the proof model refines the Rust implementation or that the Coq
  development is sound beyond the checked finite model;
- that a passing gate is a certification, a review, an audit, or an
  authorization to deploy;
- that a digest is authentication, a signature is truth, a log entry is
  completeness, or a timestamp is experimental authenticity;
- that reproducibility is correctness, reference parity is security, or a
  historical verdict is present authorization; or
- that the evaluation's wall-clock or bytes-read values are a performance claim.

---

## 5. What a refusal does not mean

A refusal in this evaluation means only that a declared command did not report
its documented accepting outcome under the declared mutation and the declared
inputs. It does **not** establish:

- that the underlying artifact is false, malicious, or unsafe;
- that the mutation corresponds to a real attack;
- that the verifier's refusal reason is the only possible reason;
- that the evidence is unauthentic or that a signature was forged;
- that a different verifier, consumer, or deployment would make the same
  decision; or
- that the refused party is at fault.

A refusal with an undeclared code, a refusal caused by a usage or harness error,
and a refusal whose restoration control also fails are **negative findings**, not
correct refusals. They are reported as such.

## 6. What an acceptance does not mean

An acceptance in this evaluation means only that every declared decisive command
exited 0 and reported its documented accepting outcome under the declared
mutation and inputs. It does **not** establish:

- that the evidence is true, complete, or externally anchored;
- that the candidate is memory-safe, functionally correct, or deployment-ready;
- that the instrument is qualified or the verifier is independent;
- that the acceptance generalizes to another case, host, image, or trust
  domain; or
- that a gate result is an authorization to deploy.

## 7. Non-claims

This document does not claim external independence, review, adjudication,
certification, or universal effectiveness. It does not claim that the foundation
binary ran, that the augmented chain is complete, or that any result is a
certification or a deployment authorization. Following this document does not
make an agent independent, a review authoritative, a gate a certification, or a
repository secure.
