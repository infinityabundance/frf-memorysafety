# Offline reconstruction

Images: `python:3.11-slim` (OpenSSL 3.5.7) and `rust:1.85.0-slim`
(OpenSSL 3.0.15). Run from the archive root with `--network=none`.

The declared candidate and instrument source files are archived under their
repository-relative paths, so the reconstructor verifies their exact bytes from
the archive root. This is presence and digest bookkeeping, not authenticity.

1. Campaign bookkeeping and artifact reconstruction:

```sh
python3 evaluation/earned-trust-1.2.0/reconstruct.py
```

2. Attestation verification and its executable controls:

```sh
python3 evaluation/earned-trust-1.2.0/verify_attestations.py \
  --attestations evaluation/earned-trust-1.2.0/attestations \
  --policy evaluation/earned-trust-1.2.0/trust-policy.json \
  --campaign evaluation/earned-trust-1.2.0/MANIFEST.json --controls
```

3. Timestamp verification over the exact closure digest `ece999b403e7ce05f94dbe2304a2b86b24afb1a9cd5dc5e1a5f57d22482d735a`:

```sh
python3 evaluation/earned-trust-1.2.0/verify_time.py \
  --token evaluation/earned-trust-1.2.0/time/token.tsr \
  --imprint ece999b403e7ce05f94dbe2304a2b86b24afb1a9cd5dc5e1a5f57d22482d735a \
  --tsa-cert evaluation/earned-trust-1.2.0/time/tsa-ca.pem \
  --policy-oid 1.3.6.1.4.1.99999.1 --controls
```

4. Revocation and founded-support verification:

```sh
python3 evaluation/earned-trust-1.2.0/verify_revocation.py \
  --registry evaluation/earned-trust-1.2.0/revocations/registry.json \
  --policy evaluation/earned-trust-1.2.0/trust-policy.json \
  --support evaluation/earned-trust-1.2.0/revocations/support-model.json \
  --historical evaluation/earned-trust-1.2.0/revocations/historical-verdict.json --controls
```

5. Rust CLI verification:

```sh
./ci/etp-time-gate.sh
```

6. Local transparency proof and witness-model verification:

```sh
python3 evaluation/earned-trust-1.2.0/verify_transparency.py \
  --dir evaluation/earned-trust-1.2.0/transparency --controls
```

7. Policy metadata verification at the declared generation-time bound:

```sh
python3 evaluation/earned-trust-1.2.0/verify_policy_metadata.py \
  --policy evaluation/earned-trust-1.2.0/policy-metadata.json \
  --now 1795417304 --controls
```

8. SARIF 2.1.0 projection verification and its self-test:

```sh
python3 evaluation/earned-trust-1.2.0/verify_sarif.py \
  --campaign evaluation/earned-trust-1.2.0/MANIFEST.json \
  --sarf evaluation/earned-trust-1.2.0/campaign.sarif \
  --review evaluation/earned-trust-1.2.0/suppression-review.json \
  --statement evaluation/earned-trust-1.2.0/attestations/campaign-closure.statement.json \
  --self-test
python3 evaluation/earned-trust-1.2.0/verify_sarif.py \
  --campaign evaluation/earned-trust-1.2.0/MANIFEST.json \
  --sarf evaluation/earned-trust-1.2.0/campaign.sarif \
  --review evaluation/earned-trust-1.2.0/suppression-review.json \
  --statement evaluation/earned-trust-1.2.0/attestations/campaign-closure.statement.json
```

Knowledge horizon: Unix `1795417198`. This archive is not an external anchor,
not a public transparency log, and not proof that the evidence is true.
