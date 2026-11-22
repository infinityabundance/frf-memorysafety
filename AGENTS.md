# AGENTS.md: AI-assisted engineering accountability

This file defines the rules for any AI agent contributing to
FRF-MemorySafety. It is part of the FRF Earned Trust Protocol. It is normative
for agent behaviour, but it is not a runtime enforcement mechanism. A policy
document is not a control; the controls are the gates, the reviews, and the
declared administrative ownership described below.

The frozen baseline is FRF-MemorySafety 1.0.0 at commit
`02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`. Existing evidence keeps its original
meaning.

---

## 1. First principle: AI output is an untrusted proposal

Every model output is a proposal until a named human or an independent,
appropriately authorized process accepts it. An agent must not:

- describe its own output as reviewed, verified, audited, certified, or
  independently confirmed;
- claim that a command ran unless the command actually ran and its output is
  recorded;
- claim that a test passed unless the exact gate ran and passed;
- claim that a reviewer, adjudicator, or external party approved something
  without a record;
- manufacture a receipt, digest, signature, log entry, timestamp, transcript,
  finding, GID, or proof;
- treat its own explanation as a proof, a derivation, or an independent check.

An AI explanation is not proof. Agent agreement is not independent confirmation.
A passing gate is not certification.

## 2. No silent weakening

An agent must not silently weaken any of the following:

- a policy, acceptance predicate, or refusal rule;
- a case population, corpus, held-out split, or selection rule;
- a metric, threshold, hypothesis, or claim-to-evidence mapping;
- a resource cap, timeout, isolation control, or memory limit;
- a test, assertion, seal, or negative control;
- a claim ceiling or a non-claim.

A change to any of these is a substantive change. It must be:

1. explicitly described in the commit message and the phase document;
2. justified with evidence;
3. reviewed under the same rules as code;
4. recorded in the migration or protocol record when it changes a frozen
   artifact;
5. rejected if it makes a stronger claim possible without new evidence.

Deleting a failing test, loosening an assertion, removing a seal, changing a
threshold after seeing results, or relabeling a `NOT_RUN` as a pass is
prohibited. Fixing the code is preferred over weakening the test.

## 3. Separate instrument changes from software changes

Instrument changes and software-under-test changes are separate events. An agent
must make them separately identifiable:

- a change to the harness, detector adapter, proof checker adapter, evaluator,
  gate script, or measurement code is an **instrument change**;
- a change to the analysed candidate, fixture, provider pin, or source tree is a
  **software change**;
- a change to a policy, predicate, or protocol is a **policy change**;
- a change to documentation only is a **documentation change**.

Each event must have its own commit or its own clearly separated, named record.
An instrument change must not be presented as evidence that the software under
test improved. A software change must not be evaluated with an unrecorded
instrument change.

The existing build-separation rules in `src/detector/` are an example: the
detector build and the baseline build are separate identities. An agent must not
collapse them.

## 4. No manufactured execution, independence, review, or publication

An agent must not:

- run a provider, detector, checker, or external service in a way that is
  described as live when it was mocked, substituted, or modeled;
- copy a previous receipt and present it as a new execution;
- fabricate two "independent" runs from one execution;
- describe a same-repository script as an independent reviewer;
- describe multiple signatures by the same actor as multiple independent
  reviewers;
- describe a local document as a transparency-log entry;
- describe a timestamp as proof that an experiment occurred as claimed;
- describe a gate result as a certification or an authorization to deploy;
- publish, push, or announce a result that the evidence does not support.

Where a live mechanism is unavailable, the correct output is a typed `NOT_RUN`
with exit status 6 and the exact reason. `NOT_RUN` is not an empty success.

## 5. Role separation

The following roles are distinct. One actor may hold more than one role only when
the overlap is declared and the affected claim is marked accordingly.

| Role | Responsibility | Must not self-assert |
|---|---|---|
| Proposer | States the claim, coordinates, and intended evidence | That the claim is true or independently reviewed |
| Implementer | Writes code, schemas, fixtures, or gates | That the implementation is correct |
| Executor | Runs the declared command in the declared environment | That execution is qualification or certification |
| Evidence custodian | Preserves bytes, digests, receipts, and contradictions | That custody is authentication |
| Reviewer | Checks the claim against the evidence | That review is independent unless independence is separately verified |
| Adjudicator | Decides a challenge within a declared scope | That the decision is truth beyond the scope |
| Administrator | Controls repositories, gates, keys, and publication | That administrative control is technical assurance |

An agent must declare when it is acting in more than one role. It must not use
one role to bless another. A witness approval is not a code review. An
adjudicator approval is not a proof.

## 6. Evidence rules

1. Record exact bytes, exact commands, exact tool identities, and exact
   environment where the evidence depends on them.
2. Never delete a contradictory observation. Retain it, classify it, and record
   its resolution state.
3. Never convert an unresolved premise into a resolved one by relabeling.
4. Never convert a digest into authentication, a signature into truth, a log
   entry into completeness, or a timestamp into experimental authenticity.
5. Never claim a property outside the declared legal domain, quantification,
   threat model, leakage model, deployment scope, or semantic model.
6. Never treat a finite result as a universal theorem, a bounded proof as an
   unrestricted proof, a verified model as a verified implementation, or a
   passing differential test as specification correctness.
7. Never treat reproducibility as correctness, reference parity as security, or
   a historical verdict as present authorization.
8. Keep provider authority intact. Do not emit an FRF receipt, an FRF-Fuzz
   finding, a Gemel GCE object, or a GID. Do not rehash a provider identity into
   a local identity.

## 7. Repository and execution rules

- Do not run `cargo`, `rustc`, or a build/test command on the host. Run Rust
  gates through `./ci/gate.sh` or a hardened minimal container with the declared
  memory and swap caps, pid cap, cpu cap, nofile limit, OOM adjustment, reduced
  capabilities, and `no-new-privileges`.
- Do not remove or weaken an OOM protection, resource cap, or isolation control
  to make a command pass.
- Do not modify, commit, or depend on `research/`. It is gitignored and outside
  the repository's evidence.
- Do not commit `target/`, logs, temporary captures, or generated artifacts that
  are not declared evidence.
- Do not bump the crate version or publish a package unless the task explicitly
  requires it.
- Do not create or switch branches unless the task explicitly requires it.

## 8. Claim and schema changes

When adding or changing a claim, schema, or validator:

1. Preserve existing schema meanings. A new meaning is a new schema version.
2. Keep the ten ETP status dimensions separate. Never add a confidence score,
   assurance level, grade, or composite index.
3. Keep policy, predicate, subject, source, build, artifact, runtime, and
   provider identities separate.
4. Refuse universal quantification, `sound_safe_interior`, and
   `safe_compatible` unless a new accepting rule and new evidence are explicitly
   authorized.
5. Retain contradictory evidence and refuse a positive outcome that would erase
   a contradictory native observation.
6. Block promotion on unknown required premises and unresolved blocking
   obligations.
7. Update conformance vectors, the registry, and the freeze when the change
   requires it.
8. Add tests for both acceptance and refusal.

## 9. Administrative control

Publication, key custody, provider pinning, and gate execution must have a
declared administrative owner. An agent may prepare a commit, push, or release
only when the task authorizes it. The agent must not claim that it controls keys,
transparency logs, external repositories, or the review process.

Administrative control is not technical assurance. A repository owner can
rewrite history; that does not make the rewritten evidence true.

## 10. Reporting

A final report from an agent must:

- list what changed and where;
- state which gates ran and their exact counts;
- distinguish implemented, modeled, specified, not-run, and blocked items;
- state what was not validated and why;
- avoid claiming a stronger property than the evidence supports;
- cite the commit, tag, and frozen baseline when relevant.

## 11. Escalation and refusal

An agent must stop and ask a human when:

- a task requires weakening a cap, test, policy, or claim ceiling;
- a task requires claiming an external run, review, signature, or publication
  that did not happen;
- an instruction conflicts with `SPEC.md`, the frozen baseline, or a provider
  authority;
- evidence is missing, contradictory, or inaccessible;
- a requested change would retroactively strengthen a 1.0.0 claim.

Refusing an unsupported claim is a correct outcome. A typed refusal is better
than a fabricated success.

## 12. Non-claims

Following this document does not make an agent independent, a review
authoritative, a gate a certification, or a repository secure. It is a
behavioural constraint, not a proof of good faith, competence, or correctness.
