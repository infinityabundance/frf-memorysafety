//! Phase 7.1 seal controls for the native bridge.
//!
//! Every test uses evidence explicitly labeled `modeled`, `modified_provider`,
//! or `substitute`. No test constructs an authentic `OpenReceipt` or GID, and
//! no test asserts that this crate generated an external identity.

use frf_memorysafety::bridge::{
    native_provider_contracts, verify_bundle_bytes, BridgeIntegrity, BridgeNotRun, BridgeOutcome,
    BridgeRefusal, BridgeStatus, DsoBinding, EvidenceBundle, EvidenceProvenance,
    ExternalObservation, ExternalProvider, Reexecution, BRIDGE_BUNDLE_SCHEMA, BRIDGE_SPEC,
};
use frf_memorysafety::cli;
use serde_json::json;
use sha2::{Digest, Sha256};

const CANDIDATE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_CANDIDATE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const EXECUTABLE: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const HEX: &[u8; 16] = b"0123456789abcdef";

fn sha256_hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in Sha256::digest(bytes) {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn push_uint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = u8::try_from(value & 0x7f).expect("seven bits");
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Build a synthetic, explicitly non-authentic FRF receipt object.
fn frf_object(candidate: &str) -> (String, String) {
    let run = format!("run-bridge-test-{}", "1".repeat(64));
    let value = json!({
        "schema_version": "frf-receipt-v20",
        "run": run,
        "court": {"id": "bridge-test", "question": "modeled", "falsifier": "modeled",
                  "admissibility_envelope": {}, "semantic_identity": "modeled"},
        "provenance": {},
        "authority": {},
        "candidate": {"identity_hash": candidate},
        "environment": {},
        "fixtures": [],
        "observables": [],
        "residuals": [],
        "endoduction": {},
        "claims": {},
        "replay": {}
    });
    let bytes = serde_json::to_vec(&value).expect("modeled receipt serializes");
    let identity = format!("receipt-{run}-{}", sha256_hex(&bytes));
    (identity, hex_encode(&bytes))
}

/// Build a synthetic, explicitly non-authentic FRF-Fuzz framed finding.
fn finding_object() -> (String, String) {
    let input = b"modeled";
    let mut payload = Vec::new();
    payload.push(1); // finding payload version
    payload.push(1); // crash
    payload.extend_from_slice(&[0u8; 8]); // parent short key
    let mut coordinate = [0u8; 49];
    coordinate[0] = 1; // mutation-coordinate version
    payload.extend_from_slice(&coordinate);
    payload.push(1); // reproduced
    payload.extend_from_slice(
        &u32::try_from(input.len())
            .expect("small input")
            .to_le_bytes(),
    );
    payload.extend_from_slice(input);

    let mut bytes = b"FRFZ".to_vec();
    bytes.push(0x02); // Family::Finding
    bytes.push(0); // framing major
    bytes.push(1); // framing minor
    bytes.extend_from_slice(
        &u64::try_from(payload.len())
            .expect("small payload")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&payload);
    let identity = blake3::hash(&bytes).to_hex().to_string();
    (identity, hex_encode(&bytes))
}

/// Build a synthetic, explicitly non-authentic Gemel GCE evidence envelope.
fn gemel_object(kind: &str) -> (String, String) {
    let mut producer = [0u8; 33];
    producer[0] = 0x0E; // Family::Producer

    let mut kind_value = Vec::new();
    push_uint(
        &mut kind_value,
        u64::try_from(kind.len()).expect("small kind"),
    );
    kind_value.extend_from_slice(kind.as_bytes());

    let mut body = Vec::new();
    push_uint(&mut body, 0x01);
    push_uint(&mut body, 34);
    push_uint(&mut body, 33);
    body.extend_from_slice(&producer);
    push_uint(&mut body, 0x02);
    push_uint(
        &mut body,
        u64::try_from(kind_value.len()).expect("small kind"),
    );
    body.extend_from_slice(&kind_value);

    let mut bytes = b"GEML".to_vec();
    bytes.push(1); // encoding version
    bytes.push(0x0B); // Family::Evidence
    bytes.push(1); // evidence schemever
    bytes.push(0); // flags
    push_uint(&mut bytes, u64::try_from(body.len()).expect("small body"));
    bytes.extend_from_slice(&body);
    let identity = format!("evidence.{}", blake3::hash(&bytes).to_hex());
    (identity, hex_encode(&bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn hex_decode(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = u8::try_from(char::from(pair[0]).to_digit(16).expect("hex"))
                .expect("one hex digit");
            let low = u8::try_from(char::from(pair[1]).to_digit(16).expect("hex"))
                .expect("one hex digit");
            (high << 4) | low
        })
        .collect()
}

/// Change a JSON string body while keeping the bytes valid JSON.
fn tamper_json(hex: &str) -> String {
    let mut bytes = hex_decode(hex);
    let needle = b"bridge-test";
    let position = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("modeled receipt contains its court id");
    bytes[position + needle.len() - 1] = b'u';
    hex_encode(&bytes)
}

fn observation(
    provider: ExternalProvider,
    provenance: EvidenceProvenance,
    dso: DsoBinding,
    reexecution: Reexecution,
    candidate: &str,
    subject: Option<String>,
) -> ExternalObservation {
    let (identity, bytes) = match provider {
        ExternalProvider::Frf => frf_object(candidate),
        ExternalProvider::FrfFuzz => finding_object(),
        ExternalProvider::Gemel => gemel_object("court_receipt"),
    };
    let contract = native_provider_contracts()
        .into_iter()
        .find(|contract| contract.provider == provider)
        .expect("provider contract");
    ExternalObservation {
        provider,
        provenance,
        repository: contract.repository.to_owned(),
        commit: contract.commit.to_owned(),
        schema: contract.schema.to_owned(),
        identity,
        subject_identity: subject,
        canonical_bytes_hex: bytes,
        candidate_sha256: candidate.to_owned(),
        executable_sha256: EXECUTABLE.to_owned(),
        dso_binding: dso,
        reexecution,
        capture: None,
    }
}

fn base_observations(
    provenance: EvidenceProvenance,
    dso: DsoBinding,
    reexecution: Reexecution,
) -> Vec<ExternalObservation> {
    let frf = observation(
        ExternalProvider::Frf,
        provenance,
        dso,
        reexecution.clone(),
        CANDIDATE,
        None,
    );
    let subject = frf.identity.clone();
    vec![
        observation(
            ExternalProvider::FrfFuzz,
            provenance,
            dso,
            reexecution.clone(),
            CANDIDATE,
            None,
        ),
        frf,
        observation(
            ExternalProvider::Gemel,
            provenance,
            dso,
            reexecution,
            CANDIDATE,
            Some(subject),
        ),
    ]
}

fn bundle(observations: Vec<ExternalObservation>, expected: &str) -> EvidenceBundle {
    EvidenceBundle {
        schema: BRIDGE_BUNDLE_SCHEMA.to_owned(),
        spec: BRIDGE_SPEC.to_owned(),
        expected_candidate_sha256: expected.to_owned(),
        observations,
    }
}

fn verify(bundle: &EvidenceBundle) -> frf_memorysafety::bridge::BridgeReport {
    let bytes = serde_json::to_vec(bundle).expect("bundle serializes");
    verify_bundle_bytes(&bytes, None)
}

fn modeled() -> Vec<ExternalObservation> {
    base_observations(
        EvidenceProvenance::Modeled,
        DsoBinding::Native,
        Reexecution::Matched,
    )
}

#[test]
fn modeled_evidence_is_refused_without_generating_identities() {
    let report = verify(&bundle(modeled(), CANDIDATE));
    assert_eq!(
        report.outcome,
        BridgeOutcome::Refused {
            reason: BridgeRefusal::ModeledEvidence {
                provider: ExternalProvider::FrfFuzz
            }
        }
    );
    assert_eq!(report.exit_code(), 4);
    assert_eq!(report.generated_identities, 0);
    assert_eq!(report.authentic_native_identities, 0);
}

#[test]
fn modified_and_substitute_providers_are_refused() {
    for provenance in [
        EvidenceProvenance::ModifiedProvider,
        EvidenceProvenance::Substitute,
    ] {
        let report = verify(&bundle(
            base_observations(provenance, DsoBinding::Native, Reexecution::Matched),
            CANDIDATE,
        ));
        assert_eq!(report.exit_code(), 4);
        assert!(matches!(report.outcome, BridgeOutcome::Refused { .. }));
        assert_eq!(report.authentic_native_identities, 0);
    }
}

#[test]
fn missing_finding_is_typed_not_run() {
    let report = verify(&bundle(Vec::new(), CANDIDATE));
    assert_eq!(
        report.outcome,
        BridgeOutcome::NotRun {
            reason: BridgeNotRun::MissingFinding
        }
    );
    assert_eq!(report.exit_code(), 6);
}

#[test]
fn reexecution_not_run_is_typed_not_run() {
    let report = verify(&bundle(
        base_observations(
            EvidenceProvenance::Modeled,
            DsoBinding::Native,
            Reexecution::NotRun {
                reason: "no independent runner".to_owned(),
            },
        ),
        CANDIDATE,
    ));
    assert!(matches!(
        report.outcome,
        BridgeOutcome::NotRun {
            reason: BridgeNotRun::ReexecutionNotRun { .. }
        }
    ));
    assert_eq!(report.exit_code(), 6);
}

#[test]
fn reexecution_mismatch_is_integrity() {
    let report = verify(&bundle(
        base_observations(
            EvidenceProvenance::Modeled,
            DsoBinding::Native,
            Reexecution::Mismatch {
                detail: "modeled output changed".to_owned(),
            },
        ),
        CANDIDATE,
    ));
    assert!(matches!(
        report.outcome,
        BridgeOutcome::Integrity {
            reason: BridgeIntegrity::ReexecutionMismatch { .. }
        }
    ));
    assert_eq!(report.exit_code(), 3);
}

#[test]
fn missing_and_mismatched_schemas_are_integrity() {
    for (schema, expected_missing) in [("", true), ("frf-receipt-v19", false)] {
        let mut observations = modeled();
        observations[1].schema = schema.to_owned();
        let report = verify(&bundle(observations, CANDIDATE));
        assert_eq!(report.exit_code(), 3);
        if expected_missing {
            assert!(matches!(
                report.outcome,
                BridgeOutcome::Integrity {
                    reason: BridgeIntegrity::MissingSchema { .. }
                }
            ));
        } else {
            assert!(matches!(
                report.outcome,
                BridgeOutcome::Integrity {
                    reason: BridgeIntegrity::SchemaMismatch { .. }
                }
            ));
        }
    }
}

#[test]
fn tampered_receipt_is_integrity() {
    let mut observations = modeled();
    observations[1].canonical_bytes_hex = tamper_json(&observations[1].canonical_bytes_hex);
    let report = verify(&bundle(observations, CANDIDATE));
    assert!(matches!(
        report.outcome,
        BridgeOutcome::Integrity {
            reason: BridgeIntegrity::DigestMismatch {
                provider: ExternalProvider::Frf,
                ..
            }
        }
    ));
    assert_eq!(report.exit_code(), 3);
}

#[test]
fn tampered_finding_is_integrity() {
    let mut observations = modeled();
    observations[0].canonical_bytes_hex.push_str("00");
    let report = verify(&bundle(observations, CANDIDATE));
    assert!(matches!(
        report.outcome,
        BridgeOutcome::Integrity {
            reason: BridgeIntegrity::DigestMismatch {
                provider: ExternalProvider::FrfFuzz,
                ..
            }
        }
    ));
    assert_eq!(report.exit_code(), 3);
}

#[test]
fn tampered_gce_is_integrity() {
    let mut observations = modeled();
    observations[2].canonical_bytes_hex.push_str("00");
    let report = verify(&bundle(observations, CANDIDATE));
    assert!(matches!(
        report.outcome,
        BridgeOutcome::Integrity {
            reason: BridgeIntegrity::DigestMismatch {
                provider: ExternalProvider::Gemel,
                ..
            }
        }
    ));
    assert_eq!(report.exit_code(), 3);
}

#[test]
fn stale_candidate_is_refused() {
    let report = verify(&bundle(modeled(), OTHER_CANDIDATE));
    assert!(matches!(
        report.outcome,
        BridgeOutcome::Refused {
            reason: BridgeRefusal::StaleCandidate { .. }
        }
    ));
    assert_eq!(report.exit_code(), 4);
}

#[test]
fn substituted_dso_is_refused() {
    let report = verify(&bundle(
        base_observations(
            EvidenceProvenance::Modeled,
            DsoBinding::Substituted,
            Reexecution::Matched,
        ),
        CANDIDATE,
    ));
    assert!(matches!(
        report.outcome,
        BridgeOutcome::Refused {
            reason: BridgeRefusal::SubstitutedDso {
                provider: ExternalProvider::FrfFuzz
            }
        }
    ));
    assert_eq!(report.exit_code(), 4);
}

#[test]
fn provider_pin_mismatch_is_integrity() {
    let mut observations = modeled();
    observations[1].commit = "0".repeat(40);
    let report = verify(&bundle(observations, CANDIDATE));
    assert!(matches!(
        report.outcome,
        BridgeOutcome::Integrity {
            reason: BridgeIntegrity::ProviderPinMismatch { .. }
        }
    ));
    assert_eq!(report.exit_code(), 3);
}

#[test]
fn candidate_binding_mismatch_is_integrity() {
    let mut observations = modeled();
    // The observation declares CANDIDATE, but the modeled receipt object was
    // itself built for a different candidate.
    let (identity, bytes) = frf_object(OTHER_CANDIDATE);
    observations[1].identity = identity;
    observations[1].canonical_bytes_hex = bytes;
    let report = verify(&bundle(observations, CANDIDATE));
    assert!(matches!(
        report.outcome,
        BridgeOutcome::Integrity {
            reason: BridgeIntegrity::CandidateBindingMismatch { .. }
        }
    ));
    assert_eq!(report.exit_code(), 3);
}

#[test]
fn external_expected_candidate_is_checked() {
    let bytes = serde_json::to_vec(&bundle(modeled(), CANDIDATE)).expect("bundle serializes");
    let report = verify_bundle_bytes(&bytes, Some(OTHER_CANDIDATE));
    assert!(matches!(
        report.outcome,
        BridgeOutcome::Refused {
            reason: BridgeRefusal::StaleCandidate { .. }
        }
    ));
    assert_eq!(report.exit_code(), 4);
}

#[test]
fn status_reports_exact_pins_and_never_claims_live_without_an_executable() {
    let status = BridgeStatus::observe();
    assert_eq!(status.providers.len(), 3);
    let frf = status
        .providers
        .iter()
        .find(|provider| provider.provider == ExternalProvider::Frf)
        .expect("frf contract");
    assert_eq!(frf.commit, "ce461ce311bfe10fe90d2be03fba6217a6e8ba28");
    assert_eq!(frf.schema, "frf-receipt-v20");
    assert!(frf.accessible);
    let fuzz = status
        .providers
        .iter()
        .find(|provider| provider.provider == ExternalProvider::FrfFuzz)
        .expect("frf-fuzz contract");
    assert_eq!(fuzz.commit, "054b45cda974852ccce62bc14dbeacb5fef0336b");
    assert!(!fuzz.live_available);
    assert_eq!(
        status.exit_code(),
        if status.all_live_available { 0 } else { 6 }
    );
}

#[test]
fn cli_verify_reports_refusal_for_modeled_evidence() {
    let path = std::env::temp_dir().join(format!(
        "frf-memorysafety-bridge-{}-modeled.json",
        std::process::id()
    ));
    let bytes = serde_json::to_vec(&bundle(modeled(), CANDIDATE)).expect("bundle serializes");
    std::fs::write(&path, bytes).expect("temporary bundle");
    let exit = cli::run([
        "bridge".to_owned(),
        "verify".to_owned(),
        path.to_string_lossy().into_owned(),
        "--json".to_owned(),
    ]);
    let _ = std::fs::remove_file(path);
    assert_eq!(exit, 4);
}

#[test]
fn cli_status_is_not_run_without_configured_executables() {
    // The test environment sets no bridge executable variables.
    let exit = cli::run([
        "bridge".to_owned(),
        "status".to_owned(),
        "--json".to_owned(),
    ]);
    assert!(exit == 0 || exit == 6);
}
