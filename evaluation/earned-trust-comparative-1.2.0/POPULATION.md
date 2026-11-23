# Population and bindings: 1.2.0 comparative replication

**Protocol:** `protocol.json`, version `phase17.2-replication-1.2.0`.
**Source:** generated from `protocol.json`; the machine-readable protocol is authoritative.
**Reused population:** the same 18 case ids, the same 6/12 partition and the same mutations as the frozen 1.1.0 protocol (`phase17.2-amendment-001`).

This file is a derived catalog, not a result. A `NOT_RUN` is not a pass.

## Selection rule `SR1`

Sort the 18 case ids lexicographically in ascending byte order. Assign the 0-based index i to development if and only if i mod 3 equals 0. Assign every other index to held_out. With 18 cases this yields exactly 6 development and 12 held_out cases.

## Case population

| # | Case | Family | Partition | Expected | Mutation | Base artifacts | Restoration |
|---|---|---|---|---|---|---|---|
| 1 | `c01-positive-campaign-closure` | `positive_campaign_closure` | development | **accept** | `identity_copy` | `manifest`, `opening_manifest`, `opening_digest`, `claims`, `policy_metadata`, `sarif`, `receipt_atomic`, `receipt_data_race`, `receipt_deferred`, `receipt_legal_c`, `receipt_legal_rust`, `receipt_mutable`, `receipt_nondet`, `receipt_oversized`, `receipt_skipped`, `receipt_stale`, `receipt_sync`, `receipt_uaf_c`, `receipt_uaf_rust` | `identity_copy` → accept |
| 2 | `c02-candidate-substitution` | `candidate_identity_substitution` | held_out | **refuse** | `field_substitution` | `manifest`, `opening_manifest`, `opening_digest`, `receipt_uaf_c`, `raw_uaf_transcript`, `raw_uaf_court` | `field_restoration` → accept |
| 3 | `c03-completeness-deletion` | `completeness_deletion_and_truncated_population` | held_out | **refuse** | `required_record_deletion` | `manifest`, `opening_manifest`, `opening_digest`, `receipt_uaf_c`, `raw_uaf_transcript`, `raw_uaf_court` | `full_restoration` → accept |
| 4 | `c04-truncated-population` | `completeness_deletion_and_truncated_population` | development | **refuse** | `population_truncation` | `manifest`, `opening_manifest`, `opening_digest`, `receipt_nondet`, `raw_nondet_transcript`, `raw_nondet_court` | `full_restoration` → accept |
| 5 | `c05-duplicate-population-row` | `duplicate_or_conflicting_population_row` | held_out | **refuse** | `duplicate_row` | `manifest`, `opening_manifest`, `opening_digest`, `receipt_uaf_c`, `raw_uaf_transcript`, `raw_uaf_court` | `full_restoration` → accept |
| 6 | `c06-dsse-payload-substitution` | `dsse_payload_substitution` | held_out | **refuse** | `payload_substitution` | `attestation_envelope`, `attestation_statement`, `trust_policy`, `manifest`, `attestation_pubkey` | `full_restoration` → accept |
| 7 | `c07-signer-role-unauthorized` | `signer_role_authorization_failure` | development | **refuse** | `role_reassignment` | `attestation_envelope`, `attestation_statement`, `trust_policy`, `manifest` | `full_restoration` → accept |
| 8 | `c08-transparency-inclusion-sibling` | `transparency_bad_inclusion_or_cross_log` | held_out | **refuse** | `proof_sibling_reorder` | `transparency_proof`, `transparency_checkpoint_3`, `transparency_policy`, `transparency_log_key`, `transparency_entry`, `witness_state` | `full_restoration` → accept |
| 9 | `c09-transparency-stale-checkpoint` | `stale_transparency_or_checkpoint_freshness` | held_out | **refuse** | `known_horizon_advance` | `transparency_proof`, `transparency_checkpoint_3`, `transparency_checkpoint_1`, `transparency_policy` | `field_restoration` → accept |
| 10 | `c10-time-wrong-imprint` | `trusted_time_wrong_imprint` | development | **refuse** | `verifier_input_substitution` | `time_token`, `time_request`, `time_imprint`, `tsa_cert`, `tsa_ca`, `time_report`, `stamp_report`, `manifest` | `argument_restoration` → accept |
| 11 | `c11-revocation-withdrawn-claim` | `revocation_or_correction` | held_out | **refuse** | `claim_selection` | `revocation_registry`, `revocation_support`, `revocation_history`, `revocation_report`, `revocation_plan`, `revocation_correction_pub`, `trust_policy`, `manifest` | `claim_selection_restoration` → accept |
| 12 | `c12-archive-missing-object` | `missing_archive_object` | held_out | **refuse** | `required_object_deletion` | `archive_manifest`, `archive_envelope` | `full_restoration` → accept |
| 13 | `c13-sarif-unjustified-suppression` | `sarif_removed_result_or_unjustified_suppression` | development | **refuse** | `unjustified_suppression` | `sarif`, `manifest`, `suppression_review`, `attestation_statement`, `receipt_data_race`, `raw_data_race_transcript`, `raw_data_race_court` | `full_restoration` → accept |
| 14 | `c14-cross-property-regression` | `cross_property_regression` | held_out | **refuse** | `cross_property_report_substitution` | `cross_property_faulty`, `cross_property_fixed` | `full_restoration` → accept |
| 15 | `c15-interop-collapsed-cell` | `interoperability_matrix_collapsed_cell` | held_out | **refuse** | `matrix_cell_deletion` | `interop_report` | `full_restoration` → accept |
| 16 | `c16-tls-matrix-collapsed-cell` | `interoperability_matrix_collapsed_cell` | development | **refuse** | `matrix_cell_deletion` | `tls_matrix_report` | `full_restoration` → accept |
| 17 | `c17-proof-closure-removal` | `formal_acceptance_claim_removal` | held_out | **refuse** | `required_theorem_removal` | `proof_manifest`, `proof_file`, `acceptance_controls` | `full_restoration` → accept |
| 18 | `c18-positive-archive-reconstruction` | `positive_archive_or_independent_reconstruction` | held_out | **accept** | `identity_copy` | `archive_manifest`, `archive_reconstruct`, `archive_reconstruction_md`, `archive_envelope` | `identity_copy` → accept |

Partition totals: development 6, held_out 12, total 18.

## Instrument bindings

| Instrument | Path | SHA-256 |
|---|---|---|
| `verify_attestations` | `evaluation/earned-trust-1.2.0/verify_attestations.py` | `b6b51db8fb594374679a26af47f36c0783f9e71ea9afea03cfdf2842e25ac965` |
| `verify_sarif` | `evaluation/earned-trust-1.2.0/verify_sarif.py` | `510506c93bf631c0335b88d172933c0d2ca6599d252c30e0b9ef0f0d79957eae` |
| `verify_policy_metadata` | `evaluation/earned-trust-1.2.0/verify_policy_metadata.py` | `112c5b057c6e7beac9f4dc350ba85f66880151683e0a50cc5f76ab2debbe1499` |
| `verify_transparency` | `evaluation/earned-trust-1.2.0/verify_transparency.py` | `e41364cdcaf18a51861d7a8528864e0563e171be4500faacaf0a2a2eb6d4c9b0` |
| `verify_time` | `evaluation/earned-trust-1.2.0/verify_time.py` | `36b4685ab34d03c679a48f189659008478ccb060d7a6aaaf5ae7281d003dd8b8` |
| `verify_revocation` | `evaluation/earned-trust-1.2.0/verify_revocation.py` | `55a3d3e9faa69a18ea327ad34585e4d0579d3e291a84337c22f04911077f7dcf` |
| `reconstruct` | `evaluation/earned-trust-1.2.0/reconstruct.py` | `8e14f0c5eae4ae6b42375badbe400687a32a2339c1894b85f40e9fd038689eb0` |
| `verify_acceptance_model` | `evaluation/earned-trust-1.2.0/verify_acceptance_model.py` | `49deb173eac685e42b86f50c6e5fdb0795db5929f54cb4fd4614c6faa66abb10` |
| `interop_matrix` | `evaluation/earned-trust/interop_matrix.py` | `76eb7957eb93b7beb55bfa7721beb04c67be5266733af44547f0360669829e6d` |
| `tls_matrix` | `evaluation/earned-trust/tls_matrix.py` | `881f20179515663c0ce344b9067657bc6740bf689de537419c8f8bf6f9746b1c` |
| `cross_property` | `evaluation/earned-trust/cross_property.py` | `f17f0acabb37eaf2c90b21f81e9476f0f4c16fc17c71d5720fdf2c257b438bd4` |
| `gate` | `ci/gate.sh` | `b171ae90a19d1d595d8780c482d1a5852df2ec8afcf605f36caea4c57dbab818` |

## Artifact bindings

| Artifact | Path | SHA-256 / status |
|---|---|---|
| `manifest` | `evaluation/earned-trust-1.2.0/MANIFEST.json` | `ece999b403e7ce05f94dbe2304a2b86b24afb1a9cd5dc5e1a5f57d22482d735a` |
| `opening_manifest` | `evaluation/earned-trust-1.2.0/protocol.json` | `180e50318dc045c9ea81168c7e1e958e1d9e108b9a99c662f06081967e8b7f8a` |
| `opening_digest` | `evaluation/earned-trust-1.2.0/opening.sha256` | `82df05fc868ec3092cd1f36e1ddd0ebb1fc6213da53f238358572427bd8d0d2a` |
| `claims` | `evaluation/earned-trust-1.2.0/CLAIMS.json` | `9d09efa889e87652187f695fece3db9f052be349fc850a423525d34c6cb8a375` |
| `policy_metadata` | `evaluation/earned-trust-1.2.0/policy-metadata.json` | `1fb9ad31326eeec1ee03ce62279652b16a2ddcccb5547b07da184e1794610ca6` |
| `suppression_review` | `evaluation/earned-trust-1.2.0/suppression-review.json` | `dc69636fca7cc5fab443867c02e076865d33b02e311b64980781402985ceab32` |
| `sarif` | `evaluation/earned-trust-1.2.0/campaign.sarif` | `3d6ca4fd72bbf1ecacf336dd528eec7daac9601bdeafb1d455f38fc34f5908ad` |
| `attestation_envelope` | `evaluation/earned-trust-1.2.0/attestations/campaign-closure.envelope.json` | `3eb0eb0277c463cacccdaee46a260e3580b021d64fb701b56d47c351bc8a8b07` |
| `attestation_statement` | `evaluation/earned-trust-1.2.0/attestations/campaign-closure.statement.json` | `c6042cbed99f48b41d5ef71e5911eaf784e3da5ddebb15386340c7906893dea6` |
| `attestation_pubkey` | `evaluation/earned-trust-1.2.0/attestations/campaign-closure.public.pem` | `0e85521b12f58fd33ca9f83bea9b51726ffa2908e79970b42aa774a33e4c6974` |
| `trust_policy` | `evaluation/earned-trust-1.2.0/trust-policy.json` | `721b9558bb1df2bfbedc44b23298db423d44cd632fa095da673705946bca0e46` |
| `transparency_proof` | `evaluation/earned-trust-1.2.0/transparency/proof.json` | `d0d0671961493711c9be3f18da5e5bcfd6232474232c82be03d8dcc6d18de07c` |
| `transparency_checkpoint_3` | `evaluation/earned-trust-1.2.0/transparency/checkpoint-size-3.txt` | `777c4f4370e897cb5bf2c459a384323ef0188f6ff269b0833d59a4ba7f16807f` |
| `transparency_checkpoint_1` | `evaluation/earned-trust-1.2.0/transparency/checkpoint-size-1.txt` | `afd2b86af350ab9e521425c85acd530cdca43236951b3b251fabda3deef562ce` |
| `transparency_policy` | `evaluation/earned-trust-1.2.0/transparency/policy.json` | `c1513c1276c82ed521c9615376882e971045807f789ca708d8090634dbbaa993` |
| `transparency_log_key` | `evaluation/earned-trust-1.2.0/transparency/log-key.pub` | `7ffe82693deed0ea1652eefea0ee268dc40858e500bc70c62f45e81320466571` |
| `transparency_entry` | `evaluation/earned-trust-1.2.0/transparency/attestation-entry.bin` | `3eb0eb0277c463cacccdaee46a260e3580b021d64fb701b56d47c351bc8a8b07` |
| `witness_state` | `evaluation/earned-trust-1.2.0/transparency/witness-state.json` | `2f934951ab2a4fd00518a129c2b9f3ed7cf6c5edda57a4c1813c27de502e7223` |
| `time_token` | `evaluation/earned-trust-1.2.0/time/token.tsr` | `e29725174b5ba9c839e7ab0f3f573f40817fd8f19bfa205cc7eb855c0d8a2fe8` |
| `time_request` | `evaluation/earned-trust-1.2.0/time/request.tsq` | `6bb0cab02f13fef2ff1c6311baede1494798d5b131e73c24aa8dd1c659c9b1ad` |
| `time_imprint` | `evaluation/earned-trust-1.2.0/time/evidence-imprint.txt` | `8f2b7b04bb046b43f24174f71103a23e6bb6a6a17836f7600d7aaf5db5fb18de` |
| `tsa_cert` | `evaluation/earned-trust-1.2.0/time/tsa-cert.pem` | `0474c61a3903cbedd2cc00962d531b7b2e05cee411d1b66052513f293399ee24` |
| `tsa_ca` | `evaluation/earned-trust-1.2.0/time/tsa-ca.pem` | `0308859528e423129ac3fa3e3623105122f786a6547488b4be3ff78daf223be5` |
| `time_report` | `evaluation/earned-trust-1.2.0/time/time-report.json` | `ad02e8f7afc59235eac2a3554cb6949001a51d08a41306a9a4e5d9cb81358757` |
| `stamp_report` | `evaluation/earned-trust-1.2.0/time/stamp-report.json` | `c974fbaa7c0656ffd67492d3c9b2a9a7e9af4ce0c0336b24f17302e10df1319e` |
| `revocation_registry` | `evaluation/earned-trust-1.2.0/revocations/registry.json` | `feddd64a1903e011fb2476a7cda0363330b51f8ee3e71777c46b901f25c6254c` |
| `revocation_support` | `evaluation/earned-trust-1.2.0/revocations/support-model.json` | `b5a14ad46f12e45bb7d55aa660a3e535a4886356e5d6041adea9910c163a28fd` |
| `revocation_history` | `evaluation/earned-trust-1.2.0/revocations/historical-verdict.json` | `7942d2da9d7c7e13caef9c59e864c856046d788e7f1f5c2a15811f5afe5ec1ce` |
| `revocation_report` | `evaluation/earned-trust-1.2.0/revocations/revocation-report.json` | `0c4cf3e3914fe45287546721f91723609ddaa7f0aa0ee46b3b68027b11b42c8e` |
| `revocation_plan` | `evaluation/earned-trust-1.2.0/revocations/plan.json` | `934b8b497d61715b4804f8a840a532282b10e02d09ed1e08692bfc1fbb421c78` |
| `revocation_correction_pub` | `evaluation/earned-trust-1.2.0/revocations/correction.pem` | `5248d85e803e1f70c76297d0414507ad9539004d8465f1d3d178385e14b1625a` |
| `archive_manifest` | `evaluation/earned-trust-1.2.0/archive/manifest.json` | `eb946203a1eb76f530984f8aac33f4f21232e564b6eae90581b082d1c2b7e9b4` |
| `archive_envelope` | `evaluation/earned-trust-1.2.0/archive/evaluation/earned-trust-1.2.0/attestations/campaign-closure.envelope.json` | `3eb0eb0277c463cacccdaee46a260e3580b021d64fb701b56d47c351bc8a8b07` |
| `archive_reconstruct` | `evaluation/earned-trust-1.2.0/archive/evaluation/earned-trust-1.2.0/reconstruct.py` | `8e14f0c5eae4ae6b42375badbe400687a32a2339c1894b85f40e9fd038689eb0` |
| `archive_reconstruction_md` | `evaluation/earned-trust-1.2.0/archive/evaluation/earned-trust-1.2.0/RECONSTRUCTION.md` | `9d60e85878fcfe237292e7105139b258f68212bb764ff65748880d2a0c2be0fa` |
| `cross_property_faulty` | `evaluation/earned-trust-1.2.0/cross-property/report-faulty.json` | `9c0c0a79e8dbf869a0b973124a40d277db2ead11195ea628268026273935d423` (1.2.0 instrument replay) |
| `cross_property_fixed` | `evaluation/earned-trust-1.2.0/cross-property/report-fixed.json` | `d09494571515ed9ea0adb55282fd24b7f958107e55fde880cd7e196fc37ec5ac` (1.2.0 instrument replay) |
| `interop_report` | `evaluation/earned-trust-1.2.0/interop/report.json` | `bfdca661fa83d7c0fd7ee7b0574c31fbf2634018cc01073226cded73f3ff546d` (1.2.0 instrument replay) |
| `tls_matrix_report` | `evaluation/earned-trust-1.2.0/tls-matrix/report.json` | `425aab2b6fe6d19863bca042af1180b1964d543760b670b70746c4631dd088a3` (1.2.0 instrument replay) |
| `integrity_receipt` | `evaluation/earned-trust-1.2.0/integrity/integrity-receipt.json` | `709a9f0dcd77a1373613dfeb9f3b24213324b2a5fff2d0dcad3ea4c01fb8747f` |
| `integrity_report` | `evaluation/earned-trust-1.2.0/integrity/integrity-report.json` | `862b78ee0ebf0c9ffbf2211a8ffc0589e64d7f0fb46f6308d88038be884d2d54` |
| `timing_branch` | `evaluation/earned-trust-1.2.0/timing/report-branch.json` | **absent from 1.2.0 evidence** (no substitute) |
| `timing_ct` | `evaluation/earned-trust-1.2.0/timing/report-ct.json` | **absent from 1.2.0 evidence** (no substitute) |
| `timing_length` | `evaluation/earned-trust-1.2.0/timing/report-length.json` | **absent from 1.2.0 evidence** (no substitute) |
| `information_flow_model` | `evaluation/earned-trust-1.2.0/information-flow/model.json` | **absent from 1.2.0 evidence** (no substitute) |
| `information_flow_report` | `evaluation/earned-trust-1.2.0/information-flow/report.json` | **absent from 1.2.0 evidence** (no substitute) |
| `witness_execution` | `evaluation/earned-trust-1.2.0/witness/frf-etp.execution-witness.v1` | **absent from 1.2.0 evidence** (no substitute) |
| `proof_manifest` | `tests/proof/coq/manifest-acceptance.json` | `1faf8997e193fa93b6c6ea87651fd7a19c1a6bab272863a9025a72f283e0d861` |
| `proof_file` | `tests/proof/coq/etp_acceptance.v` | `b0db6791d67db799a3c73f177e6da5e3adfccda1b6879be5457b030d51dfb8ab` |
| `acceptance_controls` | `evaluation/earned-trust-1.2.0/acceptance-controls/receipt.json` | `6cf8b0f51a3fdd85f25f84e02e569d9fa8253573148486c8b2d1113ad2528ad9` |
| `receipt_atomic` | `evaluation/earned-trust-1.2.0/receipts/atomic-control-c.json` | `baae83dd28618e1e27ba362f5db13a1c2d157566d22192eb91c97311a6e5bdde` |
| `receipt_data_race` | `evaluation/earned-trust-1.2.0/receipts/data-race-c.json` | `6881be75a3cd26b43d87e9b8d99baa19509530575ec675c310deb1cd26c2cdff` |
| `receipt_deferred` | `evaluation/earned-trust-1.2.0/receipts/deferred-callback-c.json` | `c637f2087eb2dbf745d41c3ae79f1fbd04c1bd74bbc15836307fbd8b847bed40` |
| `receipt_legal_c` | `evaluation/earned-trust-1.2.0/receipts/legal-transfer-free-c.json` | `718ee234dd1698a32a9bd50cc8b4b079e6a341d9a84a8aeb5eb6bb797a7b6801` |
| `receipt_legal_rust` | `evaluation/earned-trust-1.2.0/receipts/legal-transfer-free-rust.json` | `aca80973173fdc9186b323467507d1ff540700ec50cfc1e9147d38e73ab2e389` |
| `receipt_mutable` | `evaluation/earned-trust-1.2.0/receipts/mutable-alias-c.json` | `9746175061e5ce4f9dd0abaf1611adf97ca96a1460871d673700a0aae087a567` |
| `receipt_nondet` | `evaluation/earned-trust-1.2.0/receipts/nondeterministic-c.json` | `1458419b2783ad98f825ad06bd18a4964722ebe6750845a3c2086296e78d7942` |
| `receipt_oversized` | `evaluation/earned-trust-1.2.0/receipts/oversized-output-c.json` | `ada5334f9297d4e4c9e42ba5f3e0914a639c6f525fcbcbc5e59dc34a883a13e8` |
| `receipt_skipped` | `evaluation/earned-trust-1.2.0/receipts/skipped-free-c.json` | `1bf56b7c62671ec5b878304f1e0f6b96b1ec6141dab1b32e5b3cdeeb92eedd4f` |
| `receipt_stale` | `evaluation/earned-trust-1.2.0/receipts/stale-generation-c.json` | `05880d24a354ae2ee306016c9c03358dbe6137f0543dcb9636936999e78398db` |
| `receipt_sync` | `evaluation/earned-trust-1.2.0/receipts/sync-callback-c.json` | `7cb03011ee5692ff4de6713e310f2c92fc552aaa11d5356514220a0bfb733c9a` |
| `receipt_uaf_c` | `evaluation/earned-trust-1.2.0/receipts/use-after-free-c.json` | `bb0a9b582887b15dcd27f272df7bbda4fc0f2cc6be70b6eace91ef2c96b3b195` |
| `receipt_uaf_rust` | `evaluation/earned-trust-1.2.0/receipts/use-after-free-rust.json` | `a2317058c76714ca64331b2dcf91eb5b407d8e1b94b288f85fe577e9b1e6d44e` |
| `raw_uaf_transcript` | `evaluation/earned-trust-1.2.0/receipts/raw/use-after-free-c.transcript.json` | `fcc814e901d77a55003155cf61a5609f8c3efc98926895bacb5516e466b79746` |
| `raw_uaf_court` | `evaluation/earned-trust-1.2.0/receipts/raw/use-after-free-c.court.json` | `69de440d6b027acafa86a6c783e007dee7abaed8ca9973d20e7e67205910556a` |
| `raw_nondet_transcript` | `evaluation/earned-trust-1.2.0/receipts/raw/nondeterministic-c.transcript.json` | `9449f14e34d97d26a54ed16f5be886207c862298c7d7a6618afbdec82b557e57` |
| `raw_nondet_court` | `evaluation/earned-trust-1.2.0/receipts/raw/nondeterministic-c.court.json` | `135c677f068204546894e0358706509c41448115df0f135b2d491daa1bda0ba2` |
| `raw_data_race_transcript` | `evaluation/earned-trust-1.2.0/receipts/raw/data-race-c.transcript.json` | `699a27479fcc5b0315ff36deeaeb121e27b017b678fcca722282096c50b18ebb` |
| `raw_data_race_court` | `evaluation/earned-trust-1.2.0/receipts/raw/data-race-c.court.json` | `34d1d99181ca6ed0a4951ce6bbdc80602da635d8a7fed6605c1bdde5b8b0e841` |
| `attestation_policy` | `evaluation/earned-trust-1.2.0/attestations/trust-policy.json` | `721b9558bb1df2bfbedc44b23298db423d44cd632fa095da673705946bca0e46` |

## Absent artifacts

The published 1.2.0 evidence set does not contain this artifact and no 1.2.0 counterpart exists; the 1.1.0 artifact is not substituted.

Artifacts still absent from the published 1.2.0 evidence set: `information_flow_model`, `information_flow_report`, `timing_branch`, `timing_ct`, `timing_length`, `witness_execution`.

`cross_property_faulty`, `cross_property_fixed`, `interop_report` and `tls_matrix_report` were absent from the published 1.2.0 evidence set and are now produced by the declared 1.2.0 instrument gates under amendment `A002` (see `REPLAY-1.2.0.md`). Their bindings are `present_in_1.2.0_replay`; they are not published campaign evidence and are not 1.1.0 copies.

No case is typed `NOT_RUN` after the `A002` replay. `c14-cross-property-regression`, `c15-interop-collapsed-cell` and `c16-tls-matrix-collapsed-cell` were typed `NOT_RUN` in the original run and were replayed.

