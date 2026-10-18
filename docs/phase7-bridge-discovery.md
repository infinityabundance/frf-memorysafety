# Phase 7.1: native provider discovery and bridge foundation

Snapshot: `staging` at `4cf3416` (tag `v0.7.0`), crate
`frf-memorysafety 0.7.0`, no version bump. Phase 7.1 adds discovery, exact
pinning, opaque external identities, fail-closed bundle verification, and the
custody pipeline. **Phase 7 is not complete.** No authentic native
FRF -> FRF-Fuzz -> Gemel custody chain was produced, because the pinned
FRF-Fuzz provider cannot be built in the mandated `rust:1.85.0-slim` container
and no provider was executed by the bridge.

## 1. Discovery

Discovery used the authenticated `infinityabundance` GitHub account:

```sh
gh repo list infinityabundance --limit 200 --json name,defaultBranchRef,isPrivate,isArchived,licenseInfo,pushedAt
gh repo view infinityabundance/frf --json name,description,defaultBranchRef,isPrivate,isFork,isArchived,licenseInfo,pushedAt,url
git ls-remote https://github.com/infinityabundance/frf.git HEAD refs/heads/main refs/heads/master
```

Candidate names were inspected rather than guessed. The three provider
repositories are:

| Role | Repository | Visibility | Default branch | License | Pinned commit | Accessible |
|---|---|---|---|---|---|---|
| FRF / OpenReceipt court | `infinityabundance/frf` | public | `main` | MIT OR Apache-2.0 (GitHub: Apache-2.0) | `ce461ce311bfe10fe90d2be03fba6217a6e8ba28` | yes |
| FRF-Fuzz | `infinityabundance/frf-fuzz` | public | `master` | MIT OR Apache-2.0 (GitHub: Apache-2.0) | `054b45cda974852ccce62bc14dbeacb5fef0336b` | yes |
| Gemel | `infinityabundance/gemel` | public | `main` | MIT OR Apache-2.0 (GitHub: Apache-2.0) | `54fc581bff09e67b9d4cc533d157a8c9fc575424` | yes |

Pinned clones live only under the gitignored `target/external/`:

```sh
git clone --depth 1 --branch main   https://github.com/infinityabundance/frf.git      target/external/frf
git clone --depth 1 --branch master https://github.com/infinityabundance/frf-fuzz.git target/external/frf-fuzz
git clone --depth 1 --branch main   https://github.com/infinityabundance/gemel.git    target/external/gemel
git -C target/external/frf rev-parse HEAD       # ce461ce311bfe10fe90d2be03fba6217a6e8ba28
git -C target/external/frf-fuzz rev-parse HEAD  # 054b45cda974852ccce62bc14dbeacb5fef0336b
git -C target/external/gemel rev-parse HEAD     # 54fc581bff09e67b9d4cc533d157a8c9fc575424
```

The clones were never modified.

## 2. Exact external contracts

### 2.1 FRF

* Crate `frf 0.1.86`, Rust edition 2021, declared MSRV 1.85.
* Current OpenReceipt schema constant: `frf-receipt-v20`
  (`src/model.rs`). `spec/openreceipt.schema.json` accepts the registered
  versions `frf-receipt-v5`, `v7`, `v12`, `v15` through `v20`; this bridge
  accepts only `v20`.
* Canonical encoding: RFC 8785 JCS over a value domain of strings, arrays,
  booleans, and null only. Numbers are refused by the protocol.
* Receipt identity: `receipt-{run}-{SHA-256(canonical bytes)}`, where
  `run = run-{court}-{SHA-256}`. No truncated digest is an identity.
* Required top-level receipt fields (from the external schema):
  `schema_version`, `run`, `court`, `provenance`, `comparator_semantics`,
  `normalizer_semantics`, `adapter_semantics`, `execution_profile`,
  `capture_bounds`, `authority`, `candidate`, `environment`, `fixtures`,
  `observables`, `residuals`, `endoduction`, `claims`, `replay`.
* Candidate binding: `candidate.identity_hash` is the SHA-256 of the exact
  artifact bytes.
* Invocations used/inspected:

  ```text
  frf [--root DIR] authority admit PATH --name NAME --version VERSION
  frf [--root DIR] court run MANIFEST.yaml [--repeat N] [--candidate-revisions ...]
  frf [--root DIR] replay RUN_ID --policy exact|semantic
  frf [--root DIR] receipt emit RUN_ID
  frf [--root DIR] bundle verify PATH
  frf [--root DIR] evidence status
  ```

* FRF is the only OpenReceipt producer. The bridge never calls
  `receipt emit`, parses no local receipt template, and never writes a
  receipt.

### 2.2 FRF-Fuzz

* Crate `frf-fuzz 0.8.3`, declared coordinator MSRV 1.98, pinned instrumented
  target toolchain `nightly-2026-07-24`
  (`rustc 1.99.0-nightly (89c61a754 2026-07-23)`, LLVM 22.1.8).
* Finding object framing (`src/canon.rs`):

  ```text
  magic "FRFZ" | family 0x02 (Finding) | major 0 | minor 1
  | payload length u64 LE | payload
  ```

* Finding payload (`src/execute/finding.rs`, `FINDING_VERSION = 1`):

  ```text
  version 1 | kind (1=crash, 2=timeout, 3=unattributed) | parent_short[8]
  | mutation coordinate[49] | replay (0=not-replayed, 1=reproduced,
  2=not-reproduced) | input length u32 LE | input bytes
  ```

* Identity: BLAKE3-256 over the **full framed object** (header plus payload),
  textual form 64 lowercase hex. The internal identity namespace is separate
  from FRF SHA-256 ids and Gemel GIDs.
* Verification record (`src/frf_bridge.rs`) is `FRFZ` family `0x0F` with
  version 1, finding id, authority name/version, outcome byte, and optional
  note/run/receipt/claim. It retains FRF ids verbatim.
* Fixture invocation contract:

  ```text
  target --frf-fuzz-fixture <path>
  ```

* Coordinator invocations inspected:

  ```text
  frf-fuzz replay <finding-id> --target <name>
  frf-fuzz verify <finding-id> --authority PATH [--candidate PATH|--target NAME]
  frf-fuzz report [--json]
  frf-fuzz fsck
  ```

* The finding does not embed the candidate artifact digest; the candidate is
  bound by the campaign/target artifact and the caller's observation. The
  bridge therefore requires `candidate_sha256` in the observation and refuses
  a mismatch, but it cannot derive that digest from the finding alone.

### 2.3 Gemel

* Crate `gemel 0.12.0`, Rust edition 2021, declared MSRV 1.85.
* Canonical encoding: GCE `1`, all families `schemever 1`.
  Envelope:

  ```text
  "GEML" | encver 1 | family code | schemever 1 | flags 0
  | body length (canonical unsigned LEB128) | field sequence
  ```

* `evidence` is family `0x0B`; `producer` is `0x0E`; all 24 family short names
  are defined in `src/family.rs`.
* Evidence required fields:
  * `0x01 producer` — `GID(producer)`, 33-byte reference (family byte +
    32-byte digest);
  * `0x02 kind` — string enum including `court_receipt`, `fuzz_result`,
    `oracle_comparison`, `runtime_trace`, `external_attestation`.
* Object identity: 33-byte binary `{family code, BLAKE3-256(envelope)}`;
  textual `{family}.{64 lowercase hex}`. This bridge accepts `evidence.*`.
* The bridge's `gemel_custody` stage requires `kind = court_receipt` and an
  explicit subject binding to the retained FRF receipt.
* Live invocation inspected and executed:

  ```text
  gemel init DIR --json
  gemel --repo DIR evidence ingest FILE --json
  gemel --repo DIR evidence list [--json]
  gemel --repo DIR evidence show GID [--json]
  ```

  Ingestion validates the `gemel.evidence.v1` JSON document and publishes a
  canonical evidence object. It never executes the recorded reproduction
  command.

## 3. Build and run observations

All builds and executions used the mandated hardened container:

```sh
docker run --rm \
  --memory=2g --memory-swap=2g --pids-limit=512 --cpus=2 \
  --ulimit nofile=1024:1024 --oom-score-adj=500 \
  --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
  --security-opt no-new-privileges \
  -v <pinned-clone>:/src:ro -v <build-dir>:/build -v frf-cargo:/cargo \
  -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/build -w /src \
  rust:1.85.0-slim cargo build --release --locked
```

| Provider | Command | Result | Observed executable SHA-256 |
|---|---|---|---|
| FRF | `cargo build --release --locked` | `Finished ... in 50.12s` | `0728aac10c4198717e04097201db55c2fbe3801e3917bc36160fc97da2a28f8b` |
| Gemel | `cargo build --release --locked` | `Finished ... in 47.97s` | `01b7f4cc2281a33dee3ecfe9a747845cef3a8b3c3a4c71078c3ecf8a29bf7696` |
| FRF-Fuzz | `cargo build --release --locked` | **blocked**, exit 101 | not built |

FRF and Gemel ran live for version probes:

```text
frf 0.1.86
gemel 0.12.0
```

The FRF golden loop was run on a writable temporary copy of the read-only
clone, with the built binary:

```sh
cp -a /src /tmp/frf && cd /tmp/frf && FRF_BIN=/build/release/frf sh golden/demo.sh
```

The court, capture, replay, and receipt stages succeeded. Exact observations:

```text
replay (exact) run-cli-malformed-input-0d8350dd68152adc7e2a721154456978a45dee4960f8ed9c4a1448a57d33a806:
  reproduced — sides byte-identical, 1 residual(s) with matching fingerprints
receipt receipt-run-cli-malformed-input-0d8350dd68152adc7e2a721154456978a45dee4960f8ed9c4a1448a57d33a806-13f02322a00764b6319543becf5de5bdbdda5f66b9e745a25daa02737ca3b612
reduction 76f5ce9d21259653: 4 -> 1 line(s) (ddmin, 4 attempt(s), minimality one-minimal/line proven=true)
```

The slim image has no `python3`, so the external-minimizer, external-witness,
and high-assurance independence steps reported interpreter failures. Those
are honest **NOT_RUN** extension-protocol steps, not bridge failures. They mean
the full golden demo is not green in this image; the core native court,
receipt, and replay path is.

Gemel ran live initialization and evidence ingestion:

```json
{"evidence":"evidence.79b13769665dd47b20f6f1232bf67524a7c36e92d3e0f0bb608bb42c156db1a9",
 "executed":false}
```

That GID is a real native Gemel object for a synthetic `fuzz_result` subject.
It is not an FRF-backed custody chain and is not used as a test fixture or
hardcoded into the bridge.

FRF-Fuzz build output:

```text
error: rustc 1.85.0 is not supported by the following packages:
  frf-fuzz@0.8.3 requires rustc 1.98
exit: 101
```

The pinned `nightly-2026-07-24` is not installed in the mandated image. Under
the current hard execution rule (1.85.0-slim only), FRF-Fuzz is **NOT_RUN** and
is recorded as an explicit blocker.

## 4. Identity boundary

`src/bridge.rs` defines three provider-typed identities:

* `FrfReceiptId`
* `FrfFuzzFindingId`
* `GemelGceId`

Each has private fields and **no public string constructor or `Deserialize`**.
The only admission path is `verify_bundle_bytes`, and admission requires:

* exact provider repository and commit;
* exact schema token;
* the external identity's textual form;
* the exact external canonical bytes supplied in the bundle;
* the external digest recomputed from those bytes (SHA-256 for FRF, BLAKE3-256
  for FRF-Fuzz and Gemel);
* for FRF: the receipt `run` field and candidate binding;
* for FRF-Fuzz: the `FRFZ` framing, family, versions, payload structure, and
  input length;
* for Gemel: the `GEML` envelope, family, schema version, canonical LEB128
  lengths, ascending unique tags, required producer reference, and evidence
  kind.

The crate reports `generated_identities: 0` on every report. It never emits an
`OpenReceipt`, a finding, a GCE object, or a GID. A digest match binds bytes; it
is not authentication. `authentic_native` is a **declared** provenance label
that must also match the recorded executable digest and a declared matched
re-execution. There is no signature, transparency log, or trusted build root.

The older `model.rs` `FrfReceiptId`, `FuzzContentId`, and `GemelGid` remain as
textual label types for the Phase 1 claim model. They are not used by the
bridge and are not a custody boundary. The bridge types are re-exported as
`BridgeFrfReceiptId`, `BridgeFrfFuzzFindingId`, and `BridgeGemelGceId` to keep
the namespaces distinct.

## 5. Custody pipeline

```text
discover -> reconstruct -> native_confirm -> frf_receipt -> gemel_custody
```

| Stage | Required evidence | Failure behavior |
|---|---|---|
| `discover` | pinned contracts accessible; a FRF-Fuzz discovery record | `NotRun::MissingFinding`, `NotRun::ProviderUnavailable` |
| `reconstruct` | exact schemas, provider pins, candidate binding, external bytes, digests, identity forms, no substituted DSO | `Integrity::*`, `Refused::StaleCandidate`, `Refused::SubstitutedDso` |
| `native_confirm` | declared `authentic_native`, executed executable equals the recorded build digest, matched independent re-execution, native DSO binding | `Refused::{ModeledEvidence, ModifiedProvider, SubstituteProvider}`, `Integrity::ReexecutionMismatch`, `NotRun::ReexecutionNotRun` |
| `frf_receipt` | an admitted authentic FRF receipt observation | `NotRun::MissingFrfReceipt` |
| `gemel_custody` | Gemel `evidence` / `court_receipt` whose subject is the retained FRF receipt | `Refused::UnboundCustody`, `NotRun::MissingGemelCustody` |

Provenance labels are:

```text
authentic_native   exact pinned provider + pinned executable + matched re-execution
modified_provider  modified provider/harness; refused
substitute          substitute provider; refused
modeled             local model; refused
```

The `authentic_native` path is implemented but not demonstrated end to end in
this environment. Tests deliberately use only `modeled`, `modified_provider`,
and `substitute` observations.

## 6. Evidence bundle schema

```json
{
  "schema": "frf-memorysafety.bridge-bundle.v1",
  "spec": "frf-memorysafety-spec-v1",
  "expected_candidate_sha256": "<64 lowercase hex>",
  "observations": [
    {
      "provider": "frf | frf_fuzz | gemel",
      "provenance": "authentic_native | modified_provider | substitute | modeled",
      "repository": "https://github.com/infinityabundance/...",
      "commit": "<40 lowercase hex>",
      "schema": "<exact provider schema token>",
      "identity": "<external identity, verbatim>",
      "subject_identity": "<FRF receipt, Gemel only>",
      "canonical_bytes_hex": "<exact external canonical bytes>",
      "candidate_sha256": "<64 lowercase hex>",
      "executable_sha256": "<64 lowercase hex>",
      "dso_binding": "native | substituted | unknown",
      "reexecution": {"status": "matched"}
    }
  ]
}
```

`reexecution` is one of `{"status":"matched"}`,
`{"status":"mismatch","detail":"..."}`, or
`{"status":"not_run","reason":"..."}`. Unknown fields are rejected. The bundle
is parsed with the crate's strict JSON parser (duplicate keys and floats are
refused) before typed decoding.

## 7. Seal controls

`tests/bridge.rs` adds 17 executing tests; `src/bridge.rs` adds 3 unit tests.
None is ignored. They use only explicitly non-authentic evidence.

| Control | Expected outcome | Exit |
|---|---|---|
| modeled evidence | `Refused::ModeledEvidence` | 4 |
| modified provider | `Refused::ModifiedProvider` | 4 |
| substitute provider | `Refused::SubstituteProvider` | 4 |
| missing discovery record | `NotRun::MissingFinding` | 6 |
| re-execution not run | `NotRun::ReexecutionNotRun` | 6 |
| re-execution mismatch | `Integrity::ReexecutionMismatch` | 3 |
| missing schema | `Integrity::MissingSchema` | 3 |
| schema mismatch | `Integrity::SchemaMismatch` | 3 |
| tampered FRF receipt bytes | `Integrity::DigestMismatch` | 3 |
| tampered FRF-Fuzz finding bytes | `Integrity::DigestMismatch` | 3 |
| tampered Gemel GCE bytes | `Integrity::DigestMismatch` | 3 |
| stale candidate | `Refused::StaleCandidate` | 4 |
| substituted DSO | `Refused::SubstitutedDso` | 4 |
| provider commit mismatch | `Integrity::ProviderPinMismatch` | 3 |
| candidate binding mismatch | `Integrity::CandidateBindingMismatch` | 3 |
| external expected candidate | `Refused::StaleCandidate` | 4 |
| CLI modeled bundle | exit 4 | 4 |

The two CLI tests also cover `bridge verify FILE --json` and `bridge status
--json`. The status test accepts exit 6 when no provider executable is
configured, which is the default.

## 8. CLI

```text
bridge status [--json]
bridge verify FILE [--json] [--candidate SHA256]
```

Exit statuses follow `SPEC.md` §14:

```text
0  every custody stage completed
2  invalid input or usage
3  evidence integrity failure
4  evidence refused / custody blocked
6  external provider or required stage NOT_RUN
7  internal harness error
```

Default status output in this environment:

```text
bridge status: native providers NOT_RUN
  frf ... accessible=true live=false executable=<not configured>
  frf-fuzz ... accessible=true live=false executable=<not configured>
  gemel ... accessible=true live=false executable=<not configured>
exit: 6
```

A provider is `live_available` only when its environment variable
(`FRF_BRIDGE_FRF_BIN`, `FRF_BRIDGE_FRF_FUZZ_BIN`, `FRF_BRIDGE_GEMEL_BIN`)
names a file whose SHA-256 equals the recorded build digest. This is an
installation observation, not an execution or sensitivity claim.

## 9. Blockers

1. **FRF-Fuzz cannot be built under the mandated toolchain.** Its coordinator
   requires Rust 1.98 and its instrumented target requires
   `nightly-2026-07-24`; the hard rule permits only `rust:1.85.0-slim`.
   `bridge status` reports this as `blocked`; `native_confirm` cannot be
   demonstrated from an FRF-Fuzz finding.
2. **No authentic native chain was captured.** The bridge validates supplied
   bundles; it has no `bridge run`/`bridge capture` command. Producing the
   three-provider chain requires executing the providers and recording their
   exact outputs, which is Phase 7.2 work.
3. **The FRF golden demo is not fully green in `rust:1.85.0-slim`.** The core
   court/receipt/replay path succeeds, but `python3` is absent, so extension
   steps (external minimizer, witness, high-assurance independence) report
   `NOT_RUN`.
4. **Provenance is not authenticated.** A bundle can declare
   `authentic_native`; the bridge checks the pin, executable digest, DSO
   declaration, candidate, and re-execution declaration, but it cannot prove a
   process ran. There is no signature or trusted build root.
5. **Schema validation is a bridge subset, not full external conformance.**
   FRF validation covers the schema token, required top-level fields, run,
   candidate binding, identity, and digest; it does not re-run FRF's full
   semantic conformance rules. Gemel validation covers envelope framing,
   canonical lengths, tags, producer, kind, identity, and digest; it does not
   decode every optional evidence field. FRF-Fuzz validation covers the entire
   finding framing and payload layout, but the candidate digest comes from the
   observation.

## 10. Claim ceiling

Phase 7.1 establishes only:

* the three repositories, branches, licenses, and exact commits above are
  accessible and pinned;
* FRF 0.1.86 and Gemel 0.12.0 build and run under the hardened 1.85.0
  container;
* the bridge retains provider identities only after exact byte, schema,
  identity-form, digest, and candidate checks;
* modeled, modified-provider, substitute, stale-candidate, substituted-DSO,
  schema-mismatch, tampered-object, and re-execution-mismatch evidence is
  refused or classified with the documented exit status;
* the bridge generates no external identity.

It does **not** establish:

* that any native FRF, FRF-Fuzz, or Gemel process actually ran for a supplied
  bundle;
* an authentic FRF receipt for the FRF-MemorySafety candidate;
* an FRF-Fuzz finding or replay for the candidate;
* a Gemel custody chain bound to an authentic FRF receipt;
* full external schema or semantic conformance;
* detector sensitivity, memory-safety soundness, `SOUND_SAFE_INTERIOR`, or
  `SAFE_COMPATIBLE`.

## 11. Remaining work for Phase 7.2

1. Obtain authorization for a second hardened image (or an explicit toolchain
   exception) that can build FRF-Fuzz with Rust 1.98 and the pinned
   `nightly-2026-07-24`; otherwise record Phase 7 as blocked rather than
   complete.
2. Add an opt-in native capture command that invokes only the pinned
   `frf`, `frf-fuzz`, and `gemel` executables with explicit argv, a cleared
   environment, bounded time/output, and the same hardened container limits.
3. Capture one real candidate-bound chain:
   FRF-Fuzz finding -> deliberate replay -> FRF court/receipt ->
   Gemel `evidence`/`court_receipt` ingestion.
4. Independently re-execute the candidate and record a real matched
   re-execution, not a declared flag.
5. Record and validate the loader/DSO closure of the provider executables so
   `dso_binding` reflects observed libraries instead of a declaration.
6. Add the FRF semantic conformance subset and the Gemel full evidence schema
   to the bridge, or explicitly cap validation as it is now.
7. Keep the current claim ceiling until 2-5 produce authentic evidence.

## 12. References

* `infinityabundance/frf` at `ce461ce311bfe10fe90d2be03fba6217a6e8ba28`
  (`README.md`, `spec/openreceipt.md`, `spec/openreceipt.schema.json`,
  `src/model.rs`, `src/cli.rs`, `src/verify.rs`).
* `infinityabundance/frf-fuzz` at `054b45cda974852ccce62bc14dbeacb5fef0336b`
  (`README.md`, `src/canon.rs`, `src/id.rs`, `src/execute/finding.rs`,
  `src/frf_bridge.rs`, `src/gemel_bridge.rs`, `src/cli.rs`,
  `docs/DESIGN-FRF-BRIDGE.md`, `docs/DESIGN-GEMEL-BRIDGE.md`).
* `infinityabundance/gemel` at `54fc581bff09e67b9d4cc533d157a8c9fc575424`
  (`README.md`, `docs/SPECIFICATION.md`, `docs/OBJECT_MODEL.md`,
  `src/family.rs`, `src/gid.rs`, `src/spec.rs`, `src/evidence.rs`,
  `src/bin/gemel.rs`).
* FRF-MemorySafety `SPEC.md` §4, §12, §14 and the paper's FRF/FRF-Fuzz/Gemel
  identity and custody sections.
