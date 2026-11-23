# FRF-MemorySafety Phase 17.1 comparative population

**Protocol:** `phase17.1-v1`
**Machine-readable protocol:** [`protocol.json`](protocol.json)
**Freeze sidecar:** [`OPENING.sha256`](OPENING.sha256)
**Frozen at commit:** `f5a61efe0a3b0cdafa2e9e2e4f5a01f0967163f7` on branch `staging`
**Frozen 1.0.0 baseline:** `02c6f2d9d99323a3bd79f97eb70b46f3bfc38aab`

This document is the human-readable rationale and case table. The
machine-readable protocol is authoritative for the case population, partitions,
mutations, commands, expected decisions, metrics, and acceptance criteria. If the
two disagree, the run is invalid and fails closed.

No verifier, gate, `cargo`, `coqc`, Python verification script, or test was run
in this subphase. No result, outcome count, or measured number is produced here.
The only numbers in this document are the design counts of the frozen
population, the artifact digests that bind the bytes, and the artifact-derived
verifier parameters described in section 7.

---

## 1. Question and scope

The evaluation compares two decision surfaces over the same 18 fixed cases:

- **(A) the pre-ETP foundation decision surface**, a modeled baseline over the
  committed Phase 9 campaign decision labels; and
- **(B) the augmented ETP evidence chain**, the declared Rust CLI commands and
  independent verifiers run over a mutated copy of the committed evidence.

The question is whether the augmented chain refuses the 16 declared negative
controls and accepts the 2 declared positive controls, while the foundation
accepts all 18 because every committed anchor is `pass`. The question is about
these 18 controls only. It is not a population sample, a detector-sensitivity
estimate, a memory-safety proof, a proof of verifier soundness, or a deployment
authorization.

The foundation is a **modeled baseline over committed evidence**. It is not an
independent execution of the 1.0.0 binary in this subphase, and the evaluation
does not claim that the 1.0.0 binary would behave the same way on the mutated
copies.

---

## 2. The two decision surfaces

### 2.1 Foundation surface (A)

For each case, the foundation anchor is the committed baseline artifact named by
the case:

- a per-case native receipt
  `evaluation/earned-trust/receipts/<case>.json`, whose Phase 9 campaign
  decision label is the value of `adjudication.decision`; or
- the campaign closure `evaluation/earned-trust/MANIFEST.json`, whose Phase 9
  campaign decision label is the single entry in `decisions` with
  `label = "pass"`.

The foundation **accepts** the case if and only if the anchor's label is
`pass`. It performs:

- no candidate binding;
- no chain-integrity check;
- no freshness check;
- no correction or revocation check;
- no authorization check; and
- no archive check.

The foundation reads the committed baseline, not the mutated copy in `{work}`.
This is deliberate: the pre-ETP surface has no gate that would notice the
mutation. The surface is a modeled baseline, not an execution of the 1.0.0
binary.

The committed anchors are:

| Anchor kind | Path | Field | Committed value | Foundation decision |
|---|---|---|---|---|
| Campaign decision | `evaluation/earned-trust/MANIFEST.json` | `decisions[0].label` | `pass` | `accept` |
| Native receipt | `evaluation/earned-trust/receipts/use-after-free-c.json` | `adjudication.decision` | `pass` | `accept` |
| Native receipt | `evaluation/earned-trust/receipts/nondeterministic-c.json` | `adjudication.decision` | `pass` | `accept` |

Every case anchors to one of these committed values. The expected foundation
decision is therefore `accept` for all 18 cases. The per-case anchor is in the
case table and in `protocol.json`.

### 2.2 Augmented surface (B)

For each case, the harness:

1. copies the full repository tree from `{repo}` into `{work}` with the
   repository read-only, or, for archive cases, copies the archive root into
   `{work}/archive`;
2. applies the declared mutation only inside `{work}`; and
3. runs every declared decisive verifier command over the mutated evidence in
   the declared working directory.

The case is:

- **accept** if and only if every decisive command exits 0 **and** reports its
  documented accepting outcome;
- **refuse** if any decisive command exits nonzero **or** reports a documented
  refusal; and
- **unresolved** if a declared instrument is unavailable or returns a typed
  `NOT_RUN`.

A refusal is never counted as a pass. A `NOT_RUN` is never counted as a pass. A
claim-level refusal, such as `present_admissible = false` for a withdrawn claim,
is a refusal of the present decision even when the registry status is
`verified`.

Typed exit mapping:

| Exit | Meaning | Accounting |
|---|---|---|
| 0 | command completed | acceptance depends on the documented accepting outcome |
| 2 | usage or instrument error | case is `refuse` at the surface; recorded as an instrument error; never a correct refusal |
| 3 | integrity failure | refusal |
| 4 | refused | refusal |
| 5 | detector failure | refusal |
| 6 | typed `NOT_RUN` | unresolved; never a pass |
| 7 | internal harness error | case is `refuse` at the surface; recorded as an instrument error; never a correct refusal |

Commands marked `decisive: false` are context only. They do not change the case
decision and are never counted as a pass. The witness-state command in `c08` and
the optional live proof command in `c17` are context only.

---

## 3. Population summary

Exactly 18 cases. Six are in `development`; twelve are in `held_out`. No case
appears in both. The partition is fixed by the deterministic rule in section 4
before any execution.

| Family | Cases | Partition(s) |
|---|---|---|
| Positive campaign closure | `c01` | development |
| Candidate/identity substitution | `c02` | held_out |
| Completeness deletion and truncated population | `c03`, `c04` | held_out, development |
| Duplicate or conflicting population row | `c05` | held_out |
| DSSE payload substitution | `c06` | held_out |
| Signer-role/authorization failure | `c07` | development |
| Transparency bad inclusion/sibling/root or cross-log | `c08` | held_out |
| Stale transparency/checkpoint freshness | `c09` | held_out |
| Trusted-time wrong imprint | `c10` | development |
| Revocation/correction | `c11` | held_out |
| Missing archive object | `c12` | held_out |
| SARIF removed result or unjustified suppression | `c13` | development |
| Cross-property regression | `c14` | held_out |
| Interoperability matrix collapsed cell or wrong endpoint/executable | `c15`, `c16` | held_out, development |
| Formal acceptance claim removal | `c17` | held_out |
| Positive archive or independent reconstruction | `c18` | held_out |

Expected decisions are design declarations, not observed results:

| Case | Augmented expectation | Foundation expectation | Ground truth |
|---|---|---|---|
| `c01` | `accept` | `accept` | `accept` |
| `c02` | `refuse` | `accept` | `refuse` |
| `c03` | `refuse` | `accept` | `refuse` |
| `c04` | `refuse` | `accept` | `refuse` |
| `c05` | `refuse` | `accept` | `refuse` |
| `c06` | `refuse` | `accept` | `refuse` |
| `c07` | `refuse` | `accept` | `refuse` |
| `c08` | `refuse` | `accept` | `refuse` |
| `c09` | `refuse` | `accept` | `refuse` |
| `c10` | `refuse` | `accept` | `refuse` |
| `c11` | `refuse` | `accept` | `refuse` |
| `c12` | `refuse` | `accept` | `refuse` |
| `c13` | `refuse` | `accept` | `refuse` |
| `c14` | `refuse` | `accept` | `refuse` |
| `c15` | `refuse` | `accept` | `refuse` |
| `c16` | `refuse` | `accept` | `refuse` |
| `c17` | `refuse` | `accept` | `refuse` |
| `c18` | `accept` | `accept` | `accept` |

---

## 4. Partitions and selection rule

The selection rule is `SR1`:

> Sort the 18 case ids lexicographically in ascending byte order. Assign the
> 0-based index `i` to `development` if and only if `i mod 3 = 0`. Assign every
> other index to `held_out`.

With 18 cases this yields exactly six development cases and twelve held-out
cases. The harness recomputes the rule from the frozen case list and refuses to
run if the result differs from the frozen partition table. A case may not move
between partitions after execution.

This is a deterministic index rule, not a random sample. It protects against
post-execution reassignment within this population only. It does not undo prior
exposure of these artifact families during repository development.

| Partition | Cases |
|---|---|
| `development` (6) | `c01`, `c04`, `c07`, `c10`, `c13`, `c16` |
| `held_out` (12) | `c02`, `c03`, `c05`, `c06`, `c08`, `c09`, `c11`, `c12`, `c14`, `c15`, `c17`, `c18` |

Positive controls: `c01` is in development and `c18` is in held_out.

---

## 5. Artifact bindings

Every base artifact is bound by its exact SHA-256. The paths are
repository-relative and exist at the frozen commit. The archive manifest is the
binding root for the archived tree: its `objects[]` array binds every archived
path and digest. The `timing/`, `integrity/`, `information-flow/`, and
`witness/` artifacts are bound for context but are not case-bound; see section
9.

### 5.1 Campaign and attestation artifacts

| ID | Path | SHA-256 |
|---|---|---|
| `manifest` | `evaluation/earned-trust/MANIFEST.json` | `d26e19bdf4515d1302ad724119eb2f4ff8f4f6d7a2544d949be0a6470613ee59` |
| `opening_manifest` | `evaluation/earned-trust/protocol.json` | `1380703f34d88bcbcbba5dde694e616274ff427557aa6e596db0953efcd1304c` |
| `opening_digest` | `evaluation/earned-trust/opening.sha256` | `730257a9e78d60bb3dcd07c266afd21246208127de21fbc6b1c97d23ac2d6d67` |
| `claims` | `evaluation/earned-trust/CLAIMS.json` | `5e22edb7695c366bcff01c083c1af04521db01a267aa36d0cb24dce0383f90fc` |
| `policy_metadata` | `evaluation/earned-trust/policy-metadata.json` | `2af9781ada243323c562c5d93c372d8fbd3ed40d8afa24c64d464220c8a6a089` |
| `suppression_review` | `evaluation/earned-trust/suppression-review.json` | `b2477a834be749ac1fa39fcdb0a8128f15054bef3b37ce526f571365d6675c1e` |
| `sarif` | `evaluation/earned-trust/campaign.sarif` | `e64168e1fb16a154dccad6646d4dc17d129f9d513aee582078200d58d345551e` |
| `attestation_envelope` | `evaluation/earned-trust/attestations/campaign-closure.envelope.json` | `a68a35cdacc3e43c405e85cc8ee24dc2edf855054952246b33e225659156ca26` |
| `attestation_statement` | `evaluation/earned-trust/attestations/campaign-closure.statement.json` | `c3170ebdc2989fc597ec51f6a376c4732afc6ffb727b9ad6a0ae34990ed27f9e` |
| `attestation_pubkey` | `evaluation/earned-trust/attestations/campaign-closure.public.pem` | `fcf26cc67e61f08b59117dfdb5fcf4fc3b8189ed660bd6c76db58a62f3777db8` |
| `trust_policy` | `evaluation/earned-trust/trust-policy.json` | `7f1ae23d198474dc3f77a6af4183141a8ead3b26477bf753062690f66d165ac4` |

### 5.2 Transparency, time, revocation, archive

| ID | Path | SHA-256 |
|---|---|---|
| `transparency_proof` | `evaluation/earned-trust/transparency/proof.json` | `5059ed70025fd757317e7a9d1f2b14743c49444ef744eb89cc951143bcd904f7` |
| `transparency_checkpoint_3` | `evaluation/earned-trust/transparency/checkpoint-size-3.txt` | `4d1f2fea7c87b9bdc94ab88b0a203d1301154f960ea8f129a9a35b280ca67af5` |
| `transparency_checkpoint_1` | `evaluation/earned-trust/transparency/checkpoint-size-1.txt` | `62baf9ab79856b039516e0487c6e0a3c1baa329e807559777e61232b502f947c` |
| `transparency_policy` | `evaluation/earned-trust/transparency/policy.json` | `26123dbe9d7945829d16c9f0143c5e20d964c6642cf1b677ed9ed65c84e5b561` |
| `transparency_log_key` | `evaluation/earned-trust/transparency/log-key.pub` | `4b2f7c3f24abae23fad1d1f43af2c1e0986c58e3081cf2aa86bb5452ce4e9e9e` |
| `transparency_entry` | `evaluation/earned-trust/transparency/attestation-entry.bin` | `b80888683d282e20784e7e13663cbd4a1142806fc01f2e15de195d87cf296e52` |
| `witness_state` | `evaluation/earned-trust/transparency/witness-state.json` | `0f03b710a47bd9c0a2cbded6ef14da418ffa7098d10390b58cd3709ae3c6d783` |
| `time_token` | `evaluation/earned-trust/time/token.tsr` | `a2676c8f1ca82ce892cc632585e8e614f6e305c9174b86d586409ca4b48555e0` |
| `time_request` | `evaluation/earned-trust/time/request.tsq` | `a47473588bd724a4721ca51cb1c514d6bffe61f325945d1090834a8b6b0de50a` |
| `time_imprint` | `evaluation/earned-trust/time/evidence-imprint.txt` | `a1ddcea1ec43773da6c271a332d38b57543c442d781e19391fbd25cee470375a` |
| `tsa_cert` | `evaluation/earned-trust/time/tsa-cert.pem` | `e3278bbad4ff9fb0b6b48febd5443d4f6d3a90dad6482c54053a188166ca4c6b` |
| `tsa_ca` | `evaluation/earned-trust/time/tsa-ca.pem` | `2d392a20e76385c769ccdf9447bb55be7c49e22d0520748cdae7dbc3b33e2332` |
| `time_report` | `evaluation/earned-trust/time/time-report.json` | `e229407ebb07acd554280de3971c5dcea8ae864632701f38ca5cf52b90d5dcc4` |
| `stamp_report` | `evaluation/earned-trust/time/stamp-report.json` | `71c88235514cbbecfa0e85d7f444b32476a93031b34c01faf4cc8281bc72f338` |
| `revocation_registry` | `evaluation/earned-trust/revocations/registry.json` | `31283759e874954910dca6d6f9ed277d4c667f3652b842b18bea9070d6bdc31d` |
| `revocation_support` | `evaluation/earned-trust/revocations/support-model.json` | `b5a14ad46f12e45bb7d55aa660a3e535a4886356e5d6041adea9910c163a28fd` |
| `revocation_history` | `evaluation/earned-trust/revocations/historical-verdict.json` | `7942d2da9d7c7e13caef9c59e864c856046d788e7f1f5c2a15811f5afe5ec1ce` |
| `revocation_report` | `evaluation/earned-trust/revocations/revocation-report.json` | `99425be7893ae24502b88d82558db42ca4007ef99eb68d0912a2b49c305dafc5` |
| `revocation_plan` | `evaluation/earned-trust/revocations/plan.json` | `b98776606b240adfda9943944166e92916d403d152f622978d73efdad9ac8e65` |
| `revocation_correction_pub` | `evaluation/earned-trust/revocations/correction.pem` | `a0c78e2827f4ea019460bfda64774f7c8631d8dd793dc5e8a5c096c207d3e561` |
| `archive_manifest` | `evaluation/earned-trust/archive/manifest.json` | `01359a2ce3d2368f03e50b44e02cfbeceeeabc68ce3c03d9988e7ac909f2f7f1` |
| `archive_envelope` | `evaluation/earned-trust/archive/evaluation/earned-trust/attestations/campaign-closure.envelope.json` | `a68a35cdacc3e43c405e85cc8ee24dc2edf855054952246b33e225659156ca26` |
| `archive_reconstruct` | `evaluation/earned-trust/archive/evaluation/earned-trust/reconstruct.py` | `45912e75b259dac0b4f5aa4abbbe5781a167426a6c0e2f4ca11c72a195a2ea29` |
| `archive_reconstruction_md` | `evaluation/earned-trust/archive/evaluation/earned-trust/RECONSTRUCTION.md` | `8cacfe2d2d870896a3813ba69b78aab610db9db58a6d1787d958ae9b1b6af7d9` |

### 5.3 Cross-property, interop, TLS, formal, context

| ID | Path | SHA-256 |
|---|---|---|
| `cross_property_faulty` | `evaluation/earned-trust/cross-property/report-faulty.json` | `9c0c0a79e8dbf869a0b973124a40d277db2ead11195ea628268026273935d423` |
| `cross_property_fixed` | `evaluation/earned-trust/cross-property/report-fixed.json` | `d09494571515ed9ea0adb55282fd24b7f958107e55fde880cd7e196fc37ec5ac` |
| `interop_report` | `evaluation/earned-trust/interop/report.json` | `92a9ce7a015b55201ef143cf8b4e857a738b467bb0690805058f4e569f67320c` |
| `tls_matrix_report` | `evaluation/earned-trust/tls-matrix/report.json` | `4061be5522d2d82bb48200bc935031b5da8cfbed6a7e5027b4004e20be668f6a` |
| `proof_manifest` | `tests/proof/coq/manifest-acceptance.json` | `1faf8997e193fa93b6c6ea87651fd7a19c1a6bab272863a9025a72f283e0d861` |
| `proof_file` | `tests/proof/coq/etp_acceptance.v` | `b0db6791d67db799a3c73f177e6da5e3adfccda1b6879be5457b030d51dfb8ab` |
| `acceptance_controls` | `evaluation/earned-trust/acceptance-controls/receipt.json` | `6cf8b0f51a3fdd85f25f84e02e569d9fa8253573148486c8b2d1113ad2528ad9` |
| `integrity_receipt` | `evaluation/earned-trust/integrity/integrity-receipt.json` | `bd31bcf7a27cb58a26ee3eeef0fc022f6289bfa56467315e6a7dd5ae7f6d2e66` |
| `integrity_report` | `evaluation/earned-trust/integrity/integrity-report.json` | `068a4a1d9e5276ae7b7a7a0c9cd8db845a16900ebcd71e1ed76372a3de66bc57` |
| `timing_branch` | `evaluation/earned-trust/timing/report-branch.json` | `1fd3e5adab60e7efc1f577acc78b0379411fa30e8b4058dc32b0551d2731a7fa` |
| `timing_ct` | `evaluation/earned-trust/timing/report-ct.json` | `f998ddbc6135ab76261ed26142a782dfc42e795ea7f1caa86d8a54474546affc` |
| `timing_length` | `evaluation/earned-trust/timing/report-length.json` | `0f149072a7409e1ac575608ea235ab61ec1f07fd83ab2376c5ed698be423ee44` |
| `information_flow_model` | `evaluation/earned-trust/information-flow/model.json` | `537dbafc5ad6cccd239906766edd2bf62721ace9edccd13f149a95cce35df39e` |
| `information_flow_report` | `evaluation/earned-trust/information-flow/report.json` | `0e1ce08b285178b6cb12abcd609209aad3ea2e5c1d52acd144699d5e7d72e71e` |
| `witness_execution` | `evaluation/earned-trust/witness/frf-etp.execution-witness.v1` | `4c96ee9fe8281dac14bebfd0bca43d80b535351a216b3bed54d202395f6cce46` |

### 5.4 Native receipts and raw evidence

| ID | Path | SHA-256 |
|---|---|---|
| `receipt_atomic` | `evaluation/earned-trust/receipts/atomic-control-c.json` | `4e070129e849c0ab67d78d699cfa24809711b30bd928b66fdb0abd36ceaf00d1` |
| `receipt_data_race` | `evaluation/earned-trust/receipts/data-race-c.json` | `791bb512844647f4116f05035848390ce7a044e1939c884b330a68b6c597362c` |
| `receipt_deferred` | `evaluation/earned-trust/receipts/deferred-callback-c.json` | `9d64d5c6b2a642b54714f5ef1e3cc23cea7ac2f2d3489f7b836760144ebf7add` |
| `receipt_legal_c` | `evaluation/earned-trust/receipts/legal-transfer-free-c.json` | `70d17bf361503fc703d89c8fc7ca0d8c8f6941309826ec0711bdcc5fc6f5db26` |
| `receipt_legal_rust` | `evaluation/earned-trust/receipts/legal-transfer-free-rust.json` | `42db18e64c21ef225fa4112cfe153ad1d10cca64eb28178911a80dca23471b97` |
| `receipt_mutable` | `evaluation/earned-trust/receipts/mutable-alias-c.json` | `0a8f01d08bb28a0d880ca31cb560e6d907c5fecc751868d0f11e73b54b7c436a` |
| `receipt_nondet` | `evaluation/earned-trust/receipts/nondeterministic-c.json` | `d02283d999c6db2927567b10628bdddef588314a9b1bb6665e1a52ab2172ebb4` |
| `receipt_oversized` | `evaluation/earned-trust/receipts/oversized-output-c.json` | `34fa54bf3486afd56567df90f439e2e95189c78321994f717eb81c252c43c540` |
| `receipt_skipped` | `evaluation/earned-trust/receipts/skipped-free-c.json` | `51399dc1a1cb831b7cdd6376dc04d67bcf78f93d24fe72ee2e4547f6c38e0af6` |
| `receipt_stale` | `evaluation/earned-trust/receipts/stale-generation-c.json` | `25659ce0306cd63c8c9cc0bcd7d23b056c99acd5cc51f7152f9075ce10a0d436` |
| `receipt_sync` | `evaluation/earned-trust/receipts/sync-callback-c.json` | `91fd127d91b825fc786fc896888d7a9f8a8a08701d911019532cf57a91b977ea` |
| `receipt_uaf_c` | `evaluation/earned-trust/receipts/use-after-free-c.json` | `596bdb3c5e6fc7c3dd5f5266642905d6b1384ddf19e2cedd89677150dff06a0d` |
| `receipt_uaf_rust` | `evaluation/earned-trust/receipts/use-after-free-rust.json` | `d5a91ee73140378db69903263dc6a80c664081fd321021a04af8c582c00be0b6` |
| `raw_uaf_transcript` | `evaluation/earned-trust/receipts/raw/use-after-free-c.transcript.json` | `776f892d2d56c096a11970a06f63092fb61eab540bd694cce01693befdd4314a` |
| `raw_uaf_court` | `evaluation/earned-trust/receipts/raw/use-after-free-c.court.json` | `f07978ad84991b7e517415da13c872447abf7a78e665b25f1cac958fcc8bd4cd` |
| `raw_nondet_transcript` | `evaluation/earned-trust/receipts/raw/nondeterministic-c.transcript.json` | `600f49c1976b37f1134ff9ccd6e8eeca12ab3ce8093debb5630fe6c3a15d917a` |
| `raw_nondet_court` | `evaluation/earned-trust/receipts/raw/nondeterministic-c.court.json` | `ef2be4bedeae102777ba53f544eca47be80414f7d2282ef988b55a8be5b72824` |
| `raw_data_race_transcript` | `evaluation/earned-trust/receipts/raw/data-race-c.transcript.json` | `2f84c932e1ae49d71f66e3e055e8e75da7f9c229512c6afb60cfc222e7fbb70a` |
| `raw_data_race_court` | `evaluation/earned-trust/receipts/raw/data-race-c.court.json` | `6cd5ebfa99561fcc855b2f167c0ea4a6047b06e69d6fedd1c00abcb5e6189817` |

The campaign's other raw-evidence files are bound transitively by each
receipt's `evidence[].sha256` and by the closure manifest. The six raw files used
by the mutation cases are listed explicitly.

### 5.5 Instrument bindings

| ID | Path | SHA-256 |
|---|---|---|
| `verify_attestations` | `evaluation/earned-trust/verify_attestations.py` | `2f0cbdd9c85bce0ae641723ca997a931481382733c979f9b90de059632edbc16` |
| `verify_sarif` | `evaluation/earned-trust/verify_sarif.py` | `bf9d69f51719c66da9138c62245b966b7b5603bb73148a3555180fab74719319` |
| `verify_policy_metadata` | `evaluation/earned-trust/verify_policy_metadata.py` | `191fdc310080e148da8cc06e85f7b5f746a2a7e634241e0950b5dd6085ed8f94` |
| `verify_transparency` | `evaluation/earned-trust/verify_transparency.py` | `376ee1ac39dfb4a5fd3b38d34b9127d76a37d6dbdc1f4705ac0ee6f50355879e` |
| `verify_time` | `evaluation/earned-trust/verify_time.py` | `36b4685ab34d03c679a48f189659008478ccb060d7a6aaaf5ae7281d003dd8b8` |
| `verify_revocation` | `evaluation/earned-trust/verify_revocation.py` | `55a3d3e9faa69a18ea327ad34585e4d0579d3e291a84337c22f04911077f7dcf` |
| `reconstruct` | `evaluation/earned-trust/reconstruct.py` | `45912e75b259dac0b4f5aa4abbbe5781a167426a6c0e2f4ca11c72a195a2ea29` |
| `verify_acceptance_model` | `evaluation/earned-trust/verify_acceptance_model.py` | `49deb173eac685e42b86f50c6e5fdb0795db5929f54cb4fd4614c6faa66abb10` |
| `interop_matrix` | `evaluation/earned-trust/interop_matrix.py` | `76eb7957eb93b7beb55bfa7721beb04c67be5266733af44547f0360669829e6d` |
| `tls_matrix` | `evaluation/earned-trust/tls_matrix.py` | `881f20179515663c0ce344b9067657bc6740bf689de537419c8f8bf6f9746b1c` |
| `cross_property` | `evaluation/earned-trust/cross_property.py` | `f17f0acabb37eaf2c90b21f81e9476f0f4c16fc17c71d5720fdf2c257b438bd4` |
| `gate` | `ci/gate.sh` | `b171ae90a19d1d595d8780c482d1a5852df2ec8afcf605f36caea4c57dbab818` |

The Rust binary is built from commit
`f5a61efe0a3b0cdafa2e9e2e4f5a01f0967163f7` under the declared container
envelope. It is an instrument, not a base artifact. No binary digest is declared
here because no binary is built in this subphase.

---

## 6. Case table

The table gives the case id, partition, family, base artifacts, mutation,
deciding commands, expected decisions, and ground truth. The base-artifact
column uses the IDs defined in section 5; each ID resolves to the exact
repository-relative path and SHA-256 in that section. The detailed subsections
give the rationale and the exact command lines. `{bin}` is
`{repo}/target/debug/frf-memorysafety`. `{work}` is the harness copy root.

| Case | Part. | Family | Base artifacts | Mutation | Deciding commands | Aug. | Found. | Truth |
|---|---|---|---|---|---|---|---|---|
| `c01` | dev | positive campaign closure | `manifest`, `opening_manifest`, `opening_digest`, `claims`, `policy_metadata`, `sarif`, all 13 receipts | identity copy | `etp campaign verify`; `reconstruct.py`; `verify_policy_metadata.py --controls` | accept | accept | accept |
| `c02` | held | candidate substitution | `manifest`, `opening_manifest`, `opening_digest`, `receipt_uaf_c`, `raw_uaf_*` | receipt `candidate_identity` to 64 zeroes; refresh closure receipt digest | `etp campaign verify`; `reconstruct.py` | refuse | accept | refuse |
| `c03` | held | completeness deletion | `manifest`, `opening_manifest`, `opening_digest`, `receipt_uaf_c`, `raw_uaf_*` | delete receipt and raw files; leave counts at 13 | `etp campaign verify`; `reconstruct.py` | refuse | accept | refuse |
| `c04` | dev | truncated population | `manifest`, `opening_manifest`, `opening_digest`, `receipt_nondet`, `raw_nondet_*` | remove case and raw files; make counts consistent at 12 | `etp campaign verify`; `reconstruct.py` | refuse | accept | refuse |
| `c05` | held | duplicate row | `manifest`, `opening_manifest`, `opening_digest`, `receipt_uaf_c`, `raw_uaf_*` | duplicate the use-after-free-c closure row; receipt_count 14 | `etp campaign verify`; `reconstruct.py` | refuse | accept | refuse |
| `c06` | held | DSSE payload substitution | `attestation_envelope`, `attestation_statement`, `trust_policy`, `manifest`, `attestation_pubkey` | change one payload digit; keep signature | `etp attest verify`; `verify_attestations.py --controls` | refuse | accept | refuse |
| `c07` | dev | signer role | `attestation_envelope`, `attestation_statement`, `trust_policy`, `manifest` | move producer key to correction_authority in both policy copies | `etp attest verify`; `verify_attestations.py --controls` | refuse | accept | refuse |
| `c08` | held | transparency inclusion | `transparency_proof`, `transparency_checkpoint_3`, `transparency_policy`, `transparency_log_key`, `transparency_entry`, `witness_state` | swap the audit-path siblings | `etp transparency verify`; `verify_transparency.py` | refuse | accept | refuse |
| `c09` | held | stale checkpoint | `transparency_proof`, `transparency_checkpoint_3`, `transparency_checkpoint_1`, `transparency_policy` | advance known horizon to size 4 | `etp checkpoint verify`; `etp transparency verify`; `verify_transparency.py` | refuse | accept | refuse |
| `c10` | dev | wrong imprint | `time_token`, `time_request`, `time_imprint`, `tsa_cert`, `tsa_ca`, `time_report`, `stamp_report`, `manifest` | use `--imprint` of 64 zeroes | `etp time verify`; `verify_time.py` | refuse | accept | refuse |
| `c11` | held | revocation | `revocation_registry`, `revocation_support`, `revocation_history`, `revocation_report`, `revocation_plan`, `revocation_correction_pub`, `trust_policy`, `manifest` | select the withdrawn claim as the present target | `etp revocation verify`; `verify_revocation.py` | refuse | accept | refuse |
| `c12` | held | missing archive object | `archive_manifest`, `archive_envelope` | delete the archived envelope object | `etp archive verify` | refuse | accept | refuse |
| `c13` | dev | SARIF suppression | `sarif`, `manifest`, `suppression_review`, `attestation_statement`, `receipt_data_race`, `raw_data_race_*` | add an unreviewed suppression to the data-race result | `etp sarif verify`; `verify_sarif.py` | refuse | accept | refuse |
| `c14` | held | cross-property regression | `cross_property_faulty`, `cross_property_fixed` | fixed report carries the faulty relocation trace | harness check on the report | refuse | accept | refuse |
| `c15` | held | interop collapsed cell | `interop_report` | delete one max_4096 cell | harness check using `interop_matrix` | refuse | accept | refuse |
| `c16` | dev | TLS collapsed cell | `tls_matrix_report` | delete one tls13_echo cell | harness check using `tls_matrix` | refuse | accept | refuse |
| `c17` | held | formal claim removal | `proof_manifest`, `proof_file`, `acceptance_controls` | remove a required theorem from closure and admission | `proof verify`; `verify_acceptance_model.py` | refuse | accept | refuse |
| `c18` | held | positive archive | `archive_manifest`, `archive_reconstruct`, `archive_reconstruction_md`, `archive_envelope` | identity copy | `etp archive verify`; `reconstruct.py` in the archive root | accept | accept | accept |

---

## 7. Case details

### c01 positive campaign closure (development)

**Base artifacts.** The closure manifest, opening manifest, opening digest,
claims, policy metadata, SARIF projection, and all 13 native receipts listed in
sections 5.1 and 5.4. The 25 raw-evidence files are bound transitively by the
receipts and the closure.

**Mutation.** Identity copy of the full repository tree. No byte changes.

**Commands.**

```sh
{bin} etp campaign verify {work}/evaluation/earned-trust/MANIFEST.json --json
python3 {repo}/evaluation/earned-trust/reconstruct.py --root {work} --json
python3 {repo}/evaluation/earned-trust/verify_policy_metadata.py \
  --policy {work}/evaluation/earned-trust/policy-metadata.json --controls
```

**Accepting outcome.** Exit 0; campaign status `accepted`, closure status
`closed`, acceptance `accepted`, no refusals; reconstruction
`closure_sha256 = d26e...e59` and `case_count = 13`; policy-metadata controls
`PASS`.

**Expected augmented decision.** `accept`.
**Expected foundation decision.** `accept` (campaign decision label `pass`).
**Ground truth.** `accept`. Rationale: `docs/ETP-CAMPAIGN.md` sections 3 and 5;
an intact closed campaign with every case matching its pre-registered observation
and no failure or `NOT_RUN` is accepted. The independent reconstructor
recomputes the same finite bookkeeping.

**Restoration control.** The case is the intact base; the identity copy is the
restoration.

### c02 candidate substitution (held_out)

**Base artifacts.** `manifest`, `opening_manifest`, `opening_digest`,
`receipt_uaf_c`, `raw_uaf_transcript`, `raw_uaf_court`.

**Mutation.** In the copied receipt, set `candidate_identity` to 64 lowercase
hexadecimal zeroes. Recompute the receipt SHA-256 and update the matching
`receipts[].sha256` in the copied `MANIFEST.json`. Change no other field.

**Commands.**

```sh
{bin} etp campaign verify {work}/evaluation/earned-trust/MANIFEST.json --json
python3 {repo}/evaluation/earned-trust/reconstruct.py --root {work} --json
```

**Refusal outcome.** Exit nonzero; a documented campaign refusal such as
`wrong_candidate`, `candidate_file_mismatch`, or `inconsistent_count`; the
reconstructor prints `FAIL reconstruction` with a candidate-related reason.

**Expected augmented decision.** `refuse`.
**Expected foundation decision.** `accept` (the committed receipt's
`adjudication.decision` is `pass`).
**Ground truth.** `refuse`. Rationale: `docs/ETP-CAMPAIGN.md` section 3 rule 10;
the verifier recomputes candidate identity and does not trust the closure
manifest. `tests/etp_campaign.rs::wrong_candidate_is_refused` requires refusal.

**Restoration control.** Restore the committed `candidate_identity` and receipt
digest; the same commands accept.

### c03 completeness deletion (held_out)

**Base artifacts.** `manifest`, `opening_manifest`, `opening_digest`,
`receipt_uaf_c`, `raw_uaf_transcript`, `raw_uaf_court`.

**Mutation.** Remove the `use-after-free-c` row from `receipts[]` and delete the
receipt and its two raw files. Leave `case_count = 13`, `receipt_count = 13`,
`raw_evidence_count = 25`, the decisions count `13`, and the outcome counts at
their full-population values.

**Commands.** The same campaign and reconstruction commands as c02.

**Refusal outcome.** `missing_receipt`, `missing_raw_evidence`,
`inconsistent_count`, or `truncated_population`; the reconstructor fails.

**Expected augmented decision.** `refuse`.
**Expected foundation decision.** `accept` (the committed receipt is `pass`).
**Ground truth.** `refuse`. Rationale: `docs/ETP-CAMPAIGN.md` section 3 rules 2,
4, and 5; a missing declared receipt blocks closure, a missing population is not
an empty population, and a declared count that disagrees is refused.
`tests/etp_campaign.rs::deleted_failed_evidence_is_refused` and
`truncated_population_is_refused` require refusal.

**Restoration control.** Restore the receipt, raw files, closure row, and
counts; the same commands accept.

### c04 truncated population (development)

**Base artifacts.** `manifest`, `opening_manifest`, `opening_digest`,
`receipt_nondet`, `raw_nondet_transcript`, `raw_nondet_court`.

**Mutation.** Remove the `nondeterministic-c` row, receipt, and raw files. Set
`case_count = 12`, `receipt_count = 12`, `raw_evidence_count = 23`, decisions
`12`, and decrement the unresolved outcome count by one, so the summary is
internally consistent with the 12-row population.

**Commands.** The same campaign and reconstruction commands as c02.

**Refusal outcome.** `truncated_population`, `missing_receipt`, or
`invalid_population`; the reconstructor fails because the frozen opening
manifest declares 13 cases.

**Expected augmented decision.** `refuse`.
**Expected foundation decision.** `accept` (the committed `nondeterministic-c`
receipt records `adjudication.decision = pass`, even though its outcome is
`unresolved`).
**Ground truth.** `refuse`. Rationale: `docs/ETP-CAMPAIGN.md` section 3 rules 1,
3, and 4; the population is declared before measurement and a truncated case
blocks closure. `tests/etp_campaign.rs::truncated_population_is_refused` requires
refusal.

**Restoration control.** Restore the removed case and full-population counts;
the same commands accept.

### c05 duplicate population row (held_out)

**Base artifacts.** `manifest`, `opening_manifest`, `opening_digest`,
`receipt_uaf_c`, `raw_uaf_transcript`, `raw_uaf_court`.

**Mutation.** Append a second `receipts[]` row with the same `case_id`, `path`,
and `sha256` as the `use-after-free-c` row. Set `receipt_count = 14`. Leave
`case_count = 13` and the decisions and outcomes counts at 13.

**Commands.** The same campaign and reconstruction commands as c02.

**Refusal outcome.** `duplicate_receipt` or `inconsistent_count`; the
reconstructor fails.

**Expected augmented decision.** `refuse`.
**Expected foundation decision.** `accept` (the committed receipt is `pass`).
**Ground truth.** `refuse`. Rationale: `docs/ETP-CAMPAIGN.md` section 3 rule 2;
every declared case has exactly one receipt and one terminal outcome.
`tests/etp_campaign.rs::duplicate_receipt_rows_are_refused` requires refusal.

**Restoration control.** Remove the duplicate row and restore
`receipt_count = 13`; the same commands accept.

### c06 DSSE payload substitution (held_out)

**Base artifacts.** `attestation_envelope`, `attestation_statement`,
`trust_policy`, `manifest`, `attestation_pubkey`.

**Mutation.** Canonically base64-decode the envelope payload, change one ASCII
digit in the decoded payload without changing its length (for example
`case_count` 13 to 12), canonically re-encode it, and keep every signature byte.
The signature no longer verifies over the PAE of the modified payload.

**Commands.**

```sh
{bin} etp attest verify \
  {work}/evaluation/earned-trust/attestations/campaign-closure.envelope.json \
  --policy {work}/evaluation/earned-trust/trust-policy.json \
  --campaign {work}/evaluation/earned-trust/MANIFEST.json --json
python3 {repo}/evaluation/earned-trust/verify_attestations.py \
  --attestations {work}/evaluation/earned-trust/attestations \
  --policy {work}/evaluation/earned-trust/trust-policy.json \
  --campaign {work}/evaluation/earned-trust/MANIFEST.json --controls
```

**Refusal outcome.** Exit 4; `invalid_signature`; the independent verifier's
valid control fails.

**Expected augmented decision.** `refuse`.
**Expected foundation decision.** `accept` (campaign decision label `pass`).
**Ground truth.** `refuse`. Rationale: `docs/ETP-AUTHENTICATED-EVIDENCE.md`
sections 2 and 5; PAE is computed over the exact received payload bytes and a
signature that does not verify is refused.
`tests/etp_auth.rs::tampered_payload_is_refused` requires `invalid_signature`.

**Restoration control.** Restore the exact committed envelope; the same commands
accept.

### c07 signer-role authorization (development)

**Base artifacts.** `attestation_envelope`, `attestation_statement`,
`trust_policy`, `manifest`.

**Mutation.** In the copied trust policy, remove the key with `keyid =
frf-etp-test-ephemeral-2026-11-22` from `evidence_producer.keys` and append it to
`correction_authority.keys`. Leave the envelope, statement, and every other
policy field unchanged. The signature remains valid under the same key, but no
key in the required `evidence_producer` role satisfies the campaign-closure
predicate.

**Commands.** The same attestation commands as c06, with the mutated policy.

**Refusal outcome.** Exit 4; `unauthorized_role`; the independent verifier's
valid control fails.

**Expected augmented decision.** `refuse`.
**Expected foundation decision.** `accept` (campaign decision label `pass`).
**Ground truth.** `refuse`. Rationale: `docs/ETP-AUTHENTICATED-EVIDENCE.md`
section 4; a signature by a key outside the required role is
`unauthorized_role`, and authorization is decided by the resolved policy role
and scope. `tests/etp_auth.rs::unauthorized_role_is_refused` requires refusal.

**Restoration control.** Restore the committed policy; the same commands accept.

### c08 transparency inclusion/sibling (held_out)

**Base artifacts.** `transparency_proof`, `transparency_checkpoint_3`,
`transparency_policy`, `transparency_log_key`, `transparency_entry`,
`witness_state`.

**Mutation.** Swap the two entries of `audit_path` in the copied proof. Leave
the entry bytes, leaf hash, leaf index, root hash, checkpoint digest, tree size,
and consistency object unchanged.

**Commands.**

```sh
{bin} etp transparency verify \
  --proof {work}/evaluation/earned-trust/transparency/proof.json \
  --checkpoint {work}/evaluation/earned-trust/transparency/checkpoint-size-3.txt \
  --policy {work}/evaluation/earned-trust/transparency/policy.json --json
python3 {repo}/evaluation/earned-trust/verify_transparency.py \
  --proof {work}/evaluation/earned-trust/transparency/proof.json \
  --checkpoint {work}/evaluation/earned-trust/transparency/checkpoint-size-3.txt \
  --policy {work}/evaluation/earned-trust/transparency/policy.json
```

The context-only witness command is
`{bin} etp witnesses verify {work}/evaluation/earned-trust/transparency/witness-state.json --json`.
It is expected to return a typed `NOT_RUN` because the committed witness state is
`not_observed` and external witnesses are required. It is never counted as a
pass or as a deciding refusal.

**Refusal outcome.** Exit 4; `inclusion_invalid` (or a documented root
mismatch).

**Expected augmented decision.** `refuse`.
**Expected foundation decision.** `accept` (campaign decision label `pass`).
**Ground truth.** `refuse`. Rationale: `docs/ETP-TRANSPARENCY.md` section 5;
inclusion requires the RFC 6962 audit path to reach the signed root.
`tests/etp_transparency.rs::wrong_sibling_order_invalidates_inclusion` requires
`inclusion_invalid`.

**Restoration control.** Restore the committed audit-path order; the same
commands accept.

### c09 stale transparency checkpoint (held_out)

**Base artifacts.** `transparency_proof`, `transparency_checkpoint_3`,
`transparency_checkpoint_1`, `transparency_policy`.

**Mutation.** In the copied transparency policy, set
`anti_rollback.known_horizons[0].tree_size = 4`, its `root_hash` to 64 lowercase
hexadecimal zeroes, and its `checkpoint_sha256` to 64 lowercase hexadecimal
zeroes. Leave the log identity and keys unchanged. The committed proof and
checkpoint remain size 3.

**Commands.**

```sh
{bin} etp checkpoint verify \
  {work}/evaluation/earned-trust/transparency/checkpoint-size-3.txt \
  --policy {work}/evaluation/earned-trust/transparency/policy.json --json
{bin} etp transparency verify \
  --proof {work}/evaluation/earned-trust/transparency/proof.json \
  --checkpoint {work}/evaluation/earned-trust/transparency/checkpoint-size-3.txt \
  --policy {work}/evaluation/earned-trust/transparency/policy.json --json
python3 {repo}/evaluation/earned-trust/verify_transparency.py \
  --proof {work}/evaluation/earned-trust/transparency/proof.json \
  --checkpoint {work}/evaluation/earned-trust/transparency/checkpoint-size-3.txt \
  --policy {work}/evaluation/earned-trust/transparency/policy.json
```

**Refusal outcome.** Exit 4; `rollback` (or a documented
`checkpoint_persistence_mismatch` or `conflicting_checkpoint`).

**Expected augmented decision.** `refuse`.
**Expected foundation decision.** `accept` (campaign decision label `pass`).
**Ground truth.** `refuse`. Rationale: `docs/ETP-TRANSPARENCY.md` section 6; the
verifier refuses a checkpoint whose size is below the known horizon as
`rollback`. `tests/etp_transparency.rs::rolled_back_checkpoint_is_refused`
requires `rollback`.

**Restoration control.** Restore the committed known horizon at size 1 with its
committed root and checkpoint digest; the same commands accept.

### c10 trusted-time wrong imprint (development)

**Base artifacts.** `time_token`, `time_request`, `time_imprint`, `tsa_cert`,
`tsa_ca`, `time_report`, `stamp_report`, `manifest`.

**Mutation.** Run the time verifier with
`--imprint 0000000000000000000000000000000000000000000000000000000000000000`
instead of the committed imprint
`d26e19bdf4515d1302ad724119eb2f4ff8f4f6d7a2544d949be0a6470613ee59`. Do not
change the token, certificate, or any other artifact.

**Commands.**

```sh
{bin} etp time verify {work}/evaluation/earned-trust/time/token.tsr \
  --imprint 0000000000000000000000000000000000000000000000000000000000000000 \
  --tsa-cert {work}/evaluation/earned-trust/time/tsa-ca.pem \
  --now-unix 1795342702 --json
python3 {repo}/evaluation/earned-trust/verify_time.py \
  --token {work}/evaluation/earned-trust/time/token.tsr \
  --imprint 0000000000000000000000000000000000000000000000000000000000000000 \
  --tsa-cert {work}/evaluation/earned-trust/time/tsa-ca.pem \
  --now 1795342702
```

`1795342702` is one second after the token generation time recorded inside the
committed evidence, chosen to avoid an inclusive-boundary ambiguity. It is inside
the pinned TSA certificate validity window. It is not a record of when the
evaluation runs.

**Refusal outcome.** Exit 4; `imprint_mismatch`.

**Expected augmented decision.** `refuse`.
**Expected foundation decision.** `accept` (campaign decision label `pass`).
**Ground truth.** `refuse`. Rationale: `docs/ETP-TRUSTED-TIME.md` sections 3 and
8; the token binds a declared message imprint and a wrong imprint is refused.
`tests/etp_time.rs::wrong_imprint_is_refused` requires refusal.

**Restoration control.** Run the same command with the committed imprint; it
accepts.

### c11 revocation withdrawn claim (held_out)

**Base artifacts.** `revocation_registry`, `revocation_support`,
`revocation_history`, `revocation_report`, `revocation_plan`,
`revocation_correction_pub`, `trust_policy`, `manifest`.

**Mutation.** No artifact byte changes. The harness selects
`claim.campaign-closure` as the present decision target from the verified
revocation report. This is the claim whose `evidence.closure` is withdrawn by
`rev-0001`.

**Commands.**

```sh
{bin} etp revocation verify \
  {work}/evaluation/earned-trust/revocations/registry.json \
  --policy {work}/evaluation/earned-trust/trust-policy.json \
  --support {work}/evaluation/earned-trust/revocations/support-model.json \
  --historical {work}/evaluation/earned-trust/revocations/historical-verdict.json \
  --now-unix 1795330364 --json
python3 {repo}/evaluation/earned-trust/verify_revocation.py \
  --registry {work}/evaluation/earned-trust/revocations/registry.json \
  --policy {work}/evaluation/earned-trust/trust-policy.json \
  --support {work}/evaluation/earned-trust/revocations/support-model.json \
  --historical {work}/evaluation/earned-trust/revocations/historical-verdict.json \
  --now 1795330364
```

`1795330364` is the verifier's declared default verification time, after the
entries' effective time and inside the policy validity window. It is not a
record of when the evaluation runs.

**Claim-level refusal outcome.** The Rust report's
`support.claims[claim_id = claim.campaign-closure].present_admissible` is
`false`, while the historical replay remains `valid`. The independent verifier
corroborates registry integrity, chain, signature, authorization, freshness, and
historical replay.

**Expected augmented decision.** `refuse` (the withdrawn claim does not
authorize the present decision).
**Expected foundation decision.** `accept` (campaign decision label `pass`).
**Ground truth.** `refuse`. Rationale: `docs/ETP-REVOCATION.md` section 3;
applying `rev-0001` leaves `claim.campaign-closure` historically supported but
presently unsupported, with `present_admissible = false`.
`tests/etp_revocation.rs::revoked_but_historically_valid_claim_is_inadmissible_now`
requires this separation.

**Restoration control.** Select `claim.campaign-closure-with-mirror`, whose
alternative support `evidence.mirror` survives, and require
`present_admissible = true`. This shows the verifier is not always-refuse.

### c12 missing archive object (held_out)

**Base artifacts.** `archive_manifest`, `archive_envelope`. The archive manifest
is the binding root for the archived tree.

**Mutation.** Copy the archive root to `{work}/archive` and delete
`{work}/archive/evaluation/earned-trust/attestations/campaign-closure.envelope.json`.
Leave `manifest.json` and every other object unchanged.

**Command.**

```sh
{bin} etp archive verify {work}/archive --json
```

**Refusal outcome.** Exit 3 (integrity failure) or 4; a documented
missing-object, missing-required-category, or incomplete-reconstruction refusal.

**Expected augmented decision.** `refuse`.
**Expected foundation decision.** `accept` (campaign decision label `pass`).
**Ground truth.** `refuse`. Rationale: `docs/ETP-ARCHIVE.md` sections 3 and 5; a
missing declared object is an integrity failure and an incomplete archive cannot
support offline reconstruction.
`tests/etp_archive.rs::missing_archive_object_is_an_integrity_failure` requires
refusal.

**Restoration control.** Restore the archived envelope object; the archive
verifies.

### c13 SARIF unjustified suppression (development)

**Base artifacts.** `sarif`, `manifest`, `suppression_review`,
`attestation_statement`, `receipt_data_race`, `raw_data_race_transcript`,
`raw_data_race_court`.

**Mutation.** In the result whose `properties.case_id = data-race-c` and
`properties.occurrence_id = data-race-c::data_race::0`, add one external
suppression with a non-empty justification, scope, owner, expiry, invalidation,
and `suppression_id = sup-0001`. Increment
`properties.suppressed_result_count` to 1. Keep the result in `results` and keep
`result_count = 18`. Do not add a matching review entry to
`suppression-review.json`.

**Commands.**

```sh
{bin} etp sarif verify {work}/evaluation/earned-trust/campaign.sarif --json
python3 {repo}/evaluation/earned-trust/verify_sarif.py \
  --campaign {work}/evaluation/earned-trust/MANIFEST.json \
  --sarf {work}/evaluation/earned-trust/campaign.sarif \
  --review {work}/evaluation/earned-trust/suppression-review.json \
  --statement {work}/evaluation/earned-trust/attestations/campaign-closure.statement.json
```

**Refusal outcome.** Exit 4; `unauthorized_suppression` from the Rust verifier
and `missing_suppression_review` or `unauthorized_suppression` from the
independent verifier. The suppressed result remains a finding.

**Expected augmented decision.** `refuse`.
**Expected foundation decision.** `accept` (campaign decision label `pass`).
**Ground truth.** `refuse`. Rationale: `docs/ETP-SARIF.md` sections 5 and 5.1; a
suppression requires every declared field and a matching independent review
entry, and a suppression does not remove the result.
`tests/sarif.rs::suppression_without_fields_is_refused` and
`suppression_does_not_remove_a_finding` require refusal.

**Restoration control.** Remove the added suppression and restore
`suppressed_result_count = 0`; both verifiers accept.

### c14 cross-property regression (held_out)

**Base artifacts.** `cross_property_faulty`, `cross_property_fixed`.

**Mutation.** In the copied `report-fixed.json`, set `outcome` to
`observed_erasure_violation` and replace `metadata.trace_lines[2]` with the
exact third trace line from `report-faulty.json`, which frees without a
preceding `CLEANSE`. Leave `metadata.mode = "fixed"` and every other field
unchanged.

**Command.**

```sh
python3 -c "import json,sys; r=json.load(open(sys.argv[1])); \
assert r['schema']=='frf-etp.cross-property.v1'; \
assert r['metadata']['mode']=='fixed'; \
assert r['outcome']=='no_violation_within_bounded_trace'; \
lines=r['metadata']['trace_lines']; \
assert all(('CLEANSE' in line) for line in lines if 'FREE' in line)" \
  {work}/evaluation/earned-trust/cross-property/report-fixed.json
```

The command is a harness check over the report bytes. It exits nonzero on the
mutated report. It is not an independent verifier and is declared as a harness
check, not as an external review.

**Refusal outcome.** Exit 1 with an `AssertionError`.

**Expected augmented decision.** `refuse`.
**Expected foundation decision.** `accept` (campaign decision label `pass`).
**Ground truth.** `refuse`. Rationale: `docs/ETP-CROSS-PROPERTY.md` sections 1,
2, and 3; secret erasure requires `CLEANSE` before `FREE` on every path. A
relocation-failure path without the cleanse is an observed erasure violation and
is not an improvement. The fixed report's documented outcome is
`no_violation_within_bounded_trace`.

**Restoration control.** Restore the committed fixed report; the same check
exits 0.

### c15 interop collapsed cell (held_out)

**Base artifacts.** `interop_report`.

**Mutation.** In the copied report, remove the cell whose `case = max_4096`,
`client_variant = reference`, and `server_variant = candidate`. Leave
`summary.total_cells = 24` and every other cell unchanged.

**Command.**

```sh
python3 -c "import json,sys; sys.path.insert(0,'{repo}/evaluation/earned-trust'); \
import interop_matrix as m; r=json.load(open(sys.argv[1])); \
m.check_population(r['fixture']['cases']); m.check_matrix_cells(r['cells']); \
s=m.classify_summary(r['fixture']['cases'],r['cells']); \
assert r['summary']['total_cases']==len(r['fixture']['cases']); \
assert r['summary']['total_cells']==len(r['cells']); \
assert r['summary']['common_failures']==s['common_failures']; \
assert r['summary']['candidate_specific_failures']==s['candidate_specific_failures']" \
  {work}/evaluation/earned-trust/interop/report.json
```

The command reuses the committed harness's population and matrix checks. It is
declared as a harness check, not as an independent verifier.

**Refusal outcome.** Exit 1; stderr contains `missing_cell` from the harness
`Refusal`.

**Expected augmented decision.** `refuse`.
**Expected foundation decision.** `accept` (campaign decision label `pass`).
**Ground truth.** `refuse`. Rationale: `docs/ETP-INTEROPERABILITY.md` sections
2, 5, and 6; every pre-registered case runs all four cells, and the
collapsed-matrix control requires a `missing_cell` refusal.

**Restoration control.** Restore the removed cell; the same check exits 0.

### c16 TLS collapsed cell (development)

**Base artifacts.** `tls_matrix_report`.

**Mutation.** In the copied report, remove the cell whose `case = tls13_echo`,
`client_variant = candidate`, and `server_variant = candidate`. Leave
`summary.total_cells = 8` and every other cell unchanged.

**Command.**

```sh
python3 -c "import json,sys; sys.path.insert(0,'{repo}/evaluation/earned-trust'); \
import tls_matrix as m; r=json.load(open(sys.argv[1])); \
m.check_population(r['fixture']['cases']); m.check_matrix_cells(r['cells']); \
s=m.classify_summary(r['fixture']['cases'],r['cells']); \
assert r['summary']['total_cases']==len(r['fixture']['cases']); \
assert r['summary']['total_cells']==len(r['cells']); \
assert r['summary']['common_failures']==s['common_failures']; \
assert r['summary']['candidate_specific_failures']==s['candidate_specific_failures']" \
  {work}/evaluation/earned-trust/tls-matrix/report.json
```

The command reuses the committed harness's population and matrix checks. It is
declared as a harness check, not as an independent verifier.

**Refusal outcome.** Exit 1; stderr contains `missing_cell`.

**Expected augmented decision.** `refuse`.
**Expected foundation decision.** `accept` (campaign decision label `pass`).
**Ground truth.** `refuse`. Rationale: `docs/ETP-TLS-MATRIX.md` sections Matrix
Cells and Case Population; each of the two cases runs all four cells and the
harness validates that all cells are present.

**Restoration control.** Restore the removed TLS cell; the same check exits 0.

### c17 formal claim removal (held_out)

**Base artifacts.** `proof_manifest`, `proof_file`, `acceptance_controls`.

**Mutation.** Remove `stale_transparency_blocks` from `closure.theorems` and
from `admission.theorems`. Leave the main theorem `acceptance_core_sound`, the
`closure.local_dependencies` entry that names `stale_transparency_blocks`, and
the proof file unchanged. The declared closure is then smaller than the
dependency closure reachable from the main theorem.

**Commands.**

```sh
{bin} proof verify {work}/tests/proof/coq/manifest-acceptance.json --json
python3 {repo}/evaluation/earned-trust/verify_acceptance_model.py \
  --out {work}/acceptance-controls.receipt.json
```

The optional live corroboration is

```sh
{bin} proof verify {work}/tests/proof/coq/manifest-acceptance.json --live --json
```

It is not decisive. If `coqc` is unavailable it returns a typed `NOT_RUN` with
exit 6. It is never counted as a pass and does not change the manifest-only
decision. Manifest validation is not proof checking.

**Refusal outcome.** Exit 4; `rejected_unrelated` (or another documented
`rejected_*` outcome). The executable acceptance model check exits 0 with zero
failed controls; it does not verify the Coq manifest and does not substitute for
the closure check.

**Expected augmented decision.** `refuse`.
**Expected foundation decision.** `accept` (campaign decision label `pass`).
**Ground truth.** `refuse`. Rationale: `docs/ETP-FORMAL-ACCEPTANCE.md` section
2; the manifest declares a real dependency closure and the gate checks that
`closure.theorems` equals the closure reachable from `theorem.name`. Removing a
required theorem must be rejected, as the earlier padded-closure draft was.

**Restoration control.** Run the same manifest-only command on the intact
`manifest-acceptance.json` and require `accepted_within_scope`.

### c18 positive archive reconstruction (held_out)

**Base artifacts.** `archive_manifest`, `archive_reconstruct`,
`archive_reconstruction_md`, `archive_envelope`. The archive manifest is the
binding root for the archived tree.

**Mutation.** Identity copy of the archive root into `{work}/archive`. No byte
changes.

**Commands.**

```sh
{bin} etp archive verify {work}/archive --json
cd {work}/archive && python3 evaluation/earned-trust/reconstruct.py --root . --json
```

**Accepting outcome.** Archive status `verified`; no problems, no missing
required categories, reconstruction `complete = true`; reconstruction exit 0
with `closure_sha256 = d26e...e59` and `case_count = 13`.

**Expected augmented decision.** `accept`.
**Expected foundation decision.** `accept` (campaign decision label `pass`).
**Ground truth.** `accept`. Rationale: `docs/ETP-ARCHIVE.md` sections 3 and 4;
an archive whose declared objects are present, regular, digest-matched, within
the knowledge horizon, and whose reconstruction inputs are complete verifies and
reconstructs offline.

**Restoration control.** The case is the intact archive; the identity copy is
the restoration.

---

## 8. Command conventions

- `{repo}` is the read-only evaluation checkout root.
- `{work}` is a fresh working directory outside `{repo}`. For non-archive
  cases, the harness copies the full repository tree into `{work}` before
  applying the mutation. For archive cases, the archive root is copied to
  `{work}/archive`.
- `{bin}` is `{repo}/target/debug/frf-memorysafety`, built from the frozen
  commit under the declared container envelope.
- Commands that resolve relative paths, including the SARIF verifier, run from
  the declared working directory inside the copied tree.
- The harness records the exact argv, working directory, exit status, stdout
  SHA-256, stderr SHA-256, and the relevant report fields for every command.
- The harness never writes to `{repo}`. The repository is mounted read-only for
  verification; `target/` and `{work}` are the only declared writable paths.

The **only integer time values** in the case commands are deterministic verifier
clocks derived from the committed evidence and its declared validity windows:
`1795342702` is one second after the RFC 3161 token generation time, and
`1795330364` is the revocation verifier's declared default verification time.
Both are inside the declared certificate and policy validity windows. They are
not a record of when this protocol was written or when the evaluation runs. No
hostname or wall-clock timestamp is recorded in this document or in
`protocol.json`. The `2026-11-22` substring in a committed key id or registry
identifier is an artifact identifier, not a timestamp of this protocol.

---

## 9. Context-only artifacts and exclusions

The following real artifact families are bound by SHA-256 but are not case-bound:

- `evaluation/earned-trust/timing/report-branch.json`,
  `report-ct.json`, and `report-length.json`;
- `evaluation/earned-trust/integrity/integrity-receipt.json` and
  `integrity-report.json`;
- `evaluation/earned-trust/information-flow/model.json` and `report.json`;
- `evaluation/earned-trust/witness/frf-etp.execution-witness.v1`.

They are not case-bound because the required 16 families already cover the
declared decision question, and because these profiles answer different bounded
questions. Binding them prevents silent instrument or evidence change, but the
evaluation makes no timing, constant-time, information-flow, integrity, or
witness-observation claim from them.

No case was dropped. Every required family is represented, and every case is
bound to artifacts that exist at the frozen commit.

---

## 10. Non-claims

This population document does not claim that the foundation binary was executed,
that the augmented chain is complete or sound, that any verifier is independent
in an administrative sense, that the ground truth was independently adjudicated,
that a passing control is a certification, or that a result generalizes beyond
the 18 declared cases. A refusal is not a pass. A `NOT_RUN` is not a pass. A
digest is not authentication.
