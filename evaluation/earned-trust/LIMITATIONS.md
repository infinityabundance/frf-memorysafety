# ETP campaign limitations

**Campaign:** `frf-etp-native-fixtures-2026-11-22`
**Opening SHA-256:**
`aff12c6d6bf67f40b4fd25554bf76c2721293f188d5f53befe1e905a5af1c4c6`
**Closure SHA-256:**
`226e2e9070b99d5e0563d28245cbab926cd0549484c05ef4295dd57590493b33`

**Phase 10.3 amendment.** The Phase 10.2 opening digest was
`2039c3352f9edcf7d5657e341440c466a29cc6f55851b6ecb6243b46a118a236` and its
closure digest was
`fea6c92f9840b30a63769ebd219cced2005ab32ab6b90b7eeeba1af038f01eee`. Phase
10.3 re-froze the opening manifest as an explicitly separated instrument change
(the attestation dependency and new source) and re-executed the same 13-case
population. The case population, expected outcomes, acceptance policy, receipt
contents, accepted cases, retained findings, resource envelope, and claim
ceiling are unchanged. The original bytes remain at commit `f17111d`.

**Phase 10.4b amendment.** Phase 10.4b added `src/etp_transparency.rs` and
`src/etp_witness.rs`, and changed `src/cli.rs` and `src/lib.rs`, all declared
instrument files. It re-froze the opening manifest and re-executed the same
13-case population. The case population, expected outcomes, acceptance policy,
receipt contents, accepted cases, retained findings, resource envelope, and
claim ceiling are unchanged. The Phase 10.4a opening digest
`08325858b5a18f6a4053f4c25f081219f0f7165c8e2c51de5ec52db09e6a942a` and closure
digest `8b343a22dfc7a35e947a2f85638284e37088a7128ecb4a3de787456db4d5b3ab`
remain available at commit `eeb5c80`.

**1.1.0 amendment.** The 1.1.0 crate-version bump changed `Cargo.toml`, a
declared candidate and instrument file. The opening manifest was re-frozen as an
explicitly separated instrument change and the same 13-case population was
re-executed under the 1.1.0 instrument. The case population, expected outcomes,
acceptance policy, receipt contents, accepted cases, retained findings, resource
envelope, and claim ceiling are unchanged. The Phase 10.4b opening digest
`df6cd0e8a6e62011cc6acb32359a00bccac7c5e078bc87420926f5399f78a6ff` and closure
digest `20743ae9b2315a66c4529e8f14e8799bfa4fdb48a6a9849bf5d5c8524b39ac25`
remain available at commit `c150de3`.

This ledger states what the campaign does not establish. It is part of the
evidence, not a caveat added after the result.

## 1. Scope limits

- The campaign covers exactly 13 checked-in native fixtures. It is not a sample
  of arbitrary C, Rust, or FFI software.
- The results are transcript- and case-scoped. `verified_compatible_within_
  transcript` is not a memory-safety result, a Rust borrow-validity result, a C
  object-lifetime result, or a proof of replay fidelity beyond the recorded
  execution.
- The observed violations are fixture-scoped observations. They do not estimate
  detector recall, precision, sensitivity, specificity, or population defect
  rates.
- The incomplete and unresolved cases are retained controls. They are not
  converted into passes and do not establish that the instrument is complete.
- The campaign does not cover timing, constant-time behaviour, interoperability,
  deployment scope, or functional correctness.

## 2. Instrument and environment limits

- The candidate (native fixtures and court) and the instrument (native harness,
  court, and campaign runner) overlap. The overlap is declared. Executing the
  instrument is not independent verification of the instrument.
- The native harness compiles and executes only a closed registry. It cannot run
  arbitrary caller-supplied code.
- Replay equality is a byte condition on the canonical transcripts in the
  declared environment. It is not a proof of determinism outside that
  environment.
- The C fixtures are compiled with `cc` from the declared image. The Rust fixture
  is compiled with the pinned `rustc`. A different compiler, linker, libc, or
  loader is a different instrument execution and invalidates this campaign's
  reuse.
- The campaign uses `rust:1.85.0-slim` with the declared memory, swap, pid, cpu,
  nofile, OOM, capability, and no-new-privileges limits. It does not establish
  that the same result holds under a different resource envelope.

## 3. Evidence and authentication limits

- The opening manifest is frozen only by SHA-256. That detects accidental or
  silent change. It is not a signature, a transparency-log entry, a trusted
  timestamp, or an authenticated build root.
- A receipt or raw-evidence digest binds exact bytes. It does not authenticate
  the producer, establish that the execution occurred as claimed, or prove that
  the bytes describe a true property.
- The instrument-execution identity binds the declared environment, executable
  digest, and sorted tool versions. It is not a signature and not a provider
  identity.
- An actor who can rewrite the opening manifest, every receipt, the raw evidence,
  the SARIF projection, and the verifier can produce a self-consistent
  alternative set. The committed digests do not prevent that.
- No Sigstore signature, public Rekor/C2SP inclusion, RFC 3161 external trusted
  timestamp, or TUF metadata exists. Phase 10.3 adds a separate test-only
  DSSE/in-toto attestation of the closure; Phase 10.4a adds a local test RFC
  3161 token; Phase 10.4b adds a local test tlog-tiles proof. None confers
  independent review, public transparency, completeness, external witnessing,
  or authentication of the campaign's receipts or raw evidence. These remain
  `NOT_RUN` or specified-not-deployed.
- The SARIF projection is a report. A GitHub code-scanning view or any external
  SARIF consumer is not authoritative.

## 4. Reconciliation limits

- The Rust verifier re-verifies every raw transcript with the court and checks
  the retained court report against the receipt. The Python reconstructor
  independently checks the bookkeeping, digests, counts, and SARIF mappings, but
  it does not reimplement the court's semantic rules.
- A valid closure means the declared counts and evidence references are complete.
  It does not mean the declared acceptance predicate is semantically correct or
  that the threat model is complete.
- A finite closed campaign is not a population inference. A missing case is not
  an empty population; a clean finite result does not imply that unknown cases
  are clean.
- Suppression is not deletion. A valid suppression remains a finding and is
  counted. The committed campaign has no suppression.
- A result marked `absent` in a future SARIF projection must distinguish a
  repair from an instrument change with evidence. The committed projection emits
  no absent result.

## 5. Claim ceiling

The campaign establishes only that:

1. each declared case has exactly one retained terminal receipt;
2. each observed terminal outcome equals its pre-registered outcome;
3. each mandatory-resolution case resolved;
4. every raw transcript, retained court report, and harness detail is present and
   digest-bound to its receipt;
5. the closure counts are derived from the complete declared population;
6. the SARIF projection preserves the campaign identities and exports every
   retained finding and unresolved condition.

It does **not** establish memory safety, functional correctness, interoperability,
timing behaviour, deployment security, detector sensitivity, proof soundness,
reviewer independence, authentication, transparency completeness, or
certification. A passing gate is not an authorization to deploy.

## 6. Reproduction and ownership

`./ci/etp-gate.sh` reproduces the campaign, closure verification, SARIF
export/verification, and independent reconstruction in hardened containers.
`./ci/gate.sh` runs formatting, clippy with `-D warnings`, debug tests, and
release tests. Neither gate runs `cargo`, `rustc`, or a test on the host.

The repository's administrative owner controls the gate, the keys, and
publication. Phase 10.3 uses a discarded test-only ephemeral key; no production
key exists. Administrative control is not technical assurance. AI agreement is
not independent confirmation. A passing validator is not a certification.
