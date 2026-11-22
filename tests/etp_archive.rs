//! Phase 10.4a durable offline archive tests.
//!
//! Every test executes. The tests build a small self-contained archive under
//! `target/` and require the declared integrity or completeness failure for
//! each corrupted control. No network access is used.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use frf_memorysafety::etp::ETP_SPEC;
use frf_memorysafety::etp_archive::{verify_archive, ArchiveStatus};
use frf_memorysafety::identity::{canonical_bytes, hex_lower};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const OBSERVED: u64 = 1_795_330_364;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn sha256(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

struct Builder {
    root: PathBuf,
    objects: Vec<Value>,
    horizon: u64,
}

impl Builder {
    fn new(name: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let root = repo()
            .join("target/etp-archive-tests")
            .join(format!("{name}-{}-{nanos}", std::process::id()))
            .join("archive");
        fs::create_dir_all(root.join("objects")).expect("archive root");
        Self {
            root,
            objects: Vec::new(),
            horizon: OBSERVED,
        }
    }

    fn add_bytes(
        &mut self,
        path: &str,
        bytes: &[u8],
        category: &str,
        schema: &str,
        required: bool,
        observed_at_unix: u64,
    ) {
        let target = self.root.join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).expect("object parent");
        }
        fs::write(&target, bytes).expect("object bytes");
        self.horizon = self.horizon.max(observed_at_unix);
        self.objects.push(json!({
            "path": path,
            "sha256": sha256(bytes),
            "size": bytes.len(),
            "schema": schema,
            "category": category,
            "applicability": "Phase 10.4a test archive object",
            "required": required,
            "observed_at_unix": observed_at_unix
        }));
    }

    fn add_copy(
        &mut self,
        path: &str,
        source: &Path,
        category: &str,
        schema: &str,
        required: bool,
    ) {
        let bytes = fs::read(source).expect("source bytes");
        self.add_bytes(path, &bytes, category, schema, required, OBSERVED);
    }

    fn add_file(&mut self, path: &str, contents: &str, category: &str, required: bool) {
        self.add_bytes(
            path,
            contents.as_bytes(),
            category,
            "opaque-bytes",
            required,
            OBSERVED,
        );
    }

    fn write_manifest(
        &self,
        required_categories: &[&str],
        input_objects: &[&str],
        command_requires: &[&str],
    ) {
        let manifest = json!({
            "schema": "frf-etp.archive-manifest.v1",
            "spec": ETP_SPEC,
            "archive_id": "frf-etp-phase10.4a-test-archive",
            "created_at_unix": self.horizon,
            "knowledge_horizon_unix": self.horizon,
            "objects": self.objects,
            "required_categories": required_categories,
            "reconstruction": {
                "instructions": "RECONSTRUCTION.md",
                "commands": [{
                    "purpose": "verify the archived campaign closure",
                    "working_directory": ".",
                    "argv": ["python3", "objects/reconstruct.py", "objects/closure.json"],
                    "requires": command_requires
                }],
                "input_objects": input_objects
            },
            "unsupported_features": ["transparency_inclusion", "witness_observation"],
            "claim_ceiling": "test archive claim ceiling",
            "non_claims": ["no external anchor"]
        });
        let bytes = canonical_bytes(&manifest).expect("manifest bytes");
        fs::write(self.root.join("manifest.json"), bytes).expect("manifest");
    }
}

fn populate(builder: &mut Builder) {
    builder.add_copy(
        "objects/closure.json",
        &repo().join("evaluation/earned-trust/MANIFEST.json"),
        "closure_manifest",
        "frf-etp.campaign-closure.v1",
        true,
    );
    builder.add_copy(
        "objects/receipt.json",
        &repo().join("evaluation/earned-trust/receipts/atomic-control-c.json"),
        "receipt",
        "frf-etp.campaign-receipt.v1",
        true,
    );
    builder.add_copy(
        "objects/campaign.sarif",
        &repo().join("evaluation/earned-trust/campaign.sarif"),
        "sarif",
        "sarif-2.1.0",
        true,
    );
    builder.add_copy(
        "objects/attestation.envelope.json",
        &repo().join("evaluation/earned-trust/attestations/campaign-closure.envelope.json"),
        "attestation",
        "frf-etp.dsse-envelope.v1",
        true,
    );
    builder.add_file(
        "objects/token.tsr",
        "local-test-only-timestamp-token-placeholder",
        "time_token",
        true,
    );
    builder.add_file(
        "objects/revocation-registry.json",
        "{\"schema\":\"frf-etp.revocation-registry.v1\"}",
        "revocation_registry",
        true,
    );
    builder.add_copy(
        "objects/trust-policy.json",
        &repo().join("evaluation/earned-trust/trust-policy.json"),
        "policy",
        "frf-etp.trust-policy.v1",
        true,
    );
    builder.add_file(
        "objects/support-model.json",
        "{\"schema\":\"frf-etp.support-model.v1\"}",
        "support_model",
        true,
    );
    builder.add_file(
        "objects/historical-verdict.json",
        "{\"schema\":\"frf-etp.historical-verdict.v1\"}",
        "historical_verdict",
        true,
    );
    builder.add_file(
        "objects/reconstruct.py",
        "#!/usr/bin/env python3\nprint('offline reconstruction')\n",
        "verifier",
        true,
    );
    builder.add_file(
        "RECONSTRUCTION.md",
        "# Reconstruction\n\nRun the declared Python command offline.\n",
        "reconstruction",
        true,
    );
}

const REQUIRED: &[&str] = &[
    "closure_manifest",
    "receipt",
    "sarif",
    "attestation",
    "time_token",
    "revocation_registry",
    "policy",
    "reconstruction",
];

const INPUTS: &[&str] = &[
    "objects/closure.json",
    "objects/reconstruct.py",
    "objects/token.tsr",
    "objects/revocation-registry.json",
];

#[test]
fn valid_archive_verifies() {
    let mut builder = Builder::new("valid");
    populate(&mut builder);
    builder.write_manifest(REQUIRED, INPUTS, INPUTS);
    let report = verify_archive(&builder.root).expect("verification");
    assert_eq!(
        report.status,
        ArchiveStatus::Verified,
        "{:?}",
        report.problems
    );
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.verified_objects, report.object_count);
    assert!(report.problems.is_empty());
    assert!(report.unlisted_objects.is_empty());
    assert!(report.reconstruction.complete);
    assert_eq!(report.knowledge_horizon_unix, OBSERVED);
}

#[test]
fn tampered_archive_object_is_an_integrity_failure() {
    let mut builder = Builder::new("tampered");
    populate(&mut builder);
    builder.write_manifest(REQUIRED, INPUTS, INPUTS);
    fs::write(builder.root.join("objects/closure.json"), b"tampered bytes").expect("tamper");
    let report = verify_archive(&builder.root).expect("verification");
    assert_eq!(report.status, ArchiveStatus::IntegrityFailure);
    assert_eq!(report.exit_code(), 3);
    assert!(report
        .problems
        .iter()
        .any(|problem| problem.problem == "size_mismatch" || problem.problem == "digest_mismatch"));
}

#[test]
fn missing_archive_object_is_an_integrity_failure() {
    let mut builder = Builder::new("missing");
    populate(&mut builder);
    builder.write_manifest(REQUIRED, INPUTS, INPUTS);
    fs::remove_file(builder.root.join("objects/receipt.json")).expect("remove");
    let report = verify_archive(&builder.root).expect("verification");
    assert_eq!(report.status, ArchiveStatus::IntegrityFailure);
    assert_eq!(report.exit_code(), 3);
    assert!(report
        .problems
        .iter()
        .any(|problem| problem.path == "objects/receipt.json" && problem.problem == "missing"));
}

#[test]
fn missing_required_evidence_is_refused() {
    let mut builder = Builder::new("required");
    populate(&mut builder);
    let mut required = REQUIRED.to_vec();
    required.push("witness_observation");
    builder.write_manifest(&required, INPUTS, INPUTS);
    let report = verify_archive(&builder.root).expect("verification");
    assert_eq!(report.status, ArchiveStatus::Refused);
    assert_eq!(report.exit_code(), 4);
    assert_eq!(
        report.missing_required_categories,
        vec!["witness_observation".to_owned()]
    );
}

#[test]
fn incomplete_reconstruction_inputs_are_refused() {
    let mut builder = Builder::new("incomplete");
    populate(&mut builder);
    builder.write_manifest(REQUIRED, &["objects/absent.json"], INPUTS);
    let report = verify_archive(&builder.root).expect("verification");
    assert_eq!(report.status, ArchiveStatus::Refused);
    assert_eq!(report.exit_code(), 4);
    assert!(!report.reconstruction.complete);
    assert!(report
        .reconstruction
        .missing_inputs
        .contains(&"objects/absent.json".to_owned()));
}

#[test]
fn unlisted_object_is_an_integrity_failure() {
    let mut builder = Builder::new("unlisted");
    populate(&mut builder);
    builder.write_manifest(REQUIRED, INPUTS, INPUTS);
    fs::write(builder.root.join("objects/extra.txt"), b"extra").expect("extra");
    let report = verify_archive(&builder.root).expect("verification");
    assert_eq!(report.status, ArchiveStatus::IntegrityFailure);
    assert_eq!(report.exit_code(), 3);
    assert_eq!(
        report.unlisted_objects,
        vec!["objects/extra.txt".to_owned()]
    );
}

#[test]
fn path_escape_is_an_integrity_failure() {
    let mut builder = Builder::new("escape");
    populate(&mut builder);
    builder.write_manifest(REQUIRED, INPUTS, INPUTS);
    let manifest_path = builder.root.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest")).expect("JSON");
    manifest["objects"][0]["path"] = Value::String("../escape.json".to_owned());
    let bytes = canonical_bytes(&manifest).expect("manifest bytes");
    fs::write(&manifest_path, bytes).expect("manifest");
    let error = verify_archive(&builder.root).expect_err("path escape");
    assert_eq!(error.exit_code(), 3);
}

#[test]
fn knowledge_horizon_violation_is_an_integrity_failure() {
    let mut builder = Builder::new("horizon");
    populate(&mut builder);
    builder.write_manifest(REQUIRED, INPUTS, INPUTS);
    let manifest_path = builder.root.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest")).expect("JSON");
    manifest["knowledge_horizon_unix"] = Value::from(OBSERVED - 1);
    let bytes = canonical_bytes(&manifest).expect("manifest bytes");
    fs::write(&manifest_path, bytes).expect("manifest");
    let error = verify_archive(&builder.root).expect_err("horizon");
    assert_eq!(error.exit_code(), 3);
}
