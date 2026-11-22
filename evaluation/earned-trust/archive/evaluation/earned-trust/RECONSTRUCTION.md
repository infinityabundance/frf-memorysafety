# Offline reconstruction

Images: `python:3.11-slim` (OpenSSL 3.5.7) and `rust:1.85.0-slim`
(OpenSSL 3.0.15). Run from the archive root with `--network=none`.

1. Campaign bookkeeping and artifact reconstruction:

```sh
python3 evaluation/earned-trust/reconstruct.py
```

2. Attestation verification and its executable controls:

```sh
python3 evaluation/earned-trust/verify_attestations.py \
  --attestations evaluation/earned-trust/attestations \
  --policy evaluation/earned-trust/trust-policy.json \
  --campaign evaluation/earned-trust/MANIFEST.json --controls
```

3. Timestamp verification over the exact closure digest `20743ae9b2315a66c4529e8f14e8799bfa4fdb48a6a9849bf5d5c8524b39ac25`:

```sh
python3 evaluation/earned-trust/verify_time.py \
  --token evaluation/earned-trust/time/token.tsr \
  --imprint 20743ae9b2315a66c4529e8f14e8799bfa4fdb48a6a9849bf5d5c8524b39ac25 \
  --tsa-cert evaluation/earned-trust/time/tsa-ca.pem \
  --policy-oid 1.3.6.1.4.1.99999.1 --controls
```

4. Revocation and founded-support verification:

```sh
python3 evaluation/earned-trust/verify_revocation.py \
  --registry evaluation/earned-trust/revocations/registry.json \
  --policy evaluation/earned-trust/trust-policy.json \
  --support evaluation/earned-trust/revocations/support-model.json \
  --historical evaluation/earned-trust/revocations/historical-verdict.json --controls
```

5. Rust CLI verification:

```sh
./ci/etp-time-gate.sh
```

6. Local transparency proof and witness-model verification:

```sh
python3 evaluation/earned-trust/verify_transparency.py \
  --dir evaluation/earned-trust/transparency --controls
```

Knowledge horizon: Unix `1795334947`. This archive is not an external anchor,
not a public transparency log, and not proof that the evidence is true.
