//! ETP schema, vector, freeze, and CLI conformance tests.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use frf_memorysafety::etp::{
    parse_claim, parse_dimensions, parse_inventory, validate_manifest_bytes, EtpRefusalCode,
    EtpValidationStatus, StatusDimensions, COORDINATE_COUNT, DIMENSION_COUNT, ETP_CLAIM_SCHEMA,
    ETP_MANIFEST_SCHEMA, ETP_OBLIGATION_SCHEMA, ETP_SPEC, ETP_STATUS_SCHEMA, FROZEN_COMMIT,
    FROZEN_EVIDENCE_ROOT_SHA256, FROZEN_RELEASE,
};
use sha2::{Digest, Sha256};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn sha_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        write!(&mut out, "{byte:02x}").expect("hex write");
    }
    out
}

fn run(args: &[&str]) -> i32 {
    frf_memorysafety::cli::run(args.iter().map(|value| (*value).to_owned()))
}

fn vector_path(relative: &str) -> PathBuf {
    root().join("schemas/etp/vectors").join(relative)
}

fn scan_for_scalars(value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for key in map.keys() {
                assert!(
                    !matches!(
                        key.as_str(),
                        "confidence" | "score" | "assurance_level" | "rating"
                    ),
                    "unexpected scalar field {key}"
                );
            }
            for item in map.values() {
                scan_for_scalars(item);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                scan_for_scalars(item);
            }
        }
        _ => {}
    }
}

#[test]
fn cli_validates_accepts_and_refuses_with_spec_exit_statuses() {
    let valid = vector_path("valid/manifest.json");
    assert_eq!(
        run(&["etp", "validate", valid.to_str().unwrap(), "--json"]),
        0
    );

    let integrity = vector_path("invalid/missing-coordinate.manifest.json");
    assert_eq!(run(&["etp", "validate", integrity.to_str().unwrap()]), 3);

    let refused = vector_path("invalid/unknown-premise-eligible.manifest.json");
    assert_eq!(run(&["etp", "validate", refused.to_str().unwrap()]), 4);

    assert_eq!(run(&["etp"]), 2);
    assert_eq!(run(&["etp", "validate"]), 2);
    assert_eq!(run(&["etp", "validate", "--json"]), 2);
    assert_eq!(run(&["etp", "validate", "no-such-file.json"]), 2);
}

#[test]
fn conformance_vectors_match_their_declared_expectations() {
    let index_path = vector_path("index.json");
    let index: serde_json::Value =
        serde_json::from_slice(&read(&index_path)).expect("vector index JSON");
    assert_eq!(index["schema"], "frf-etp.vector-index.v1");
    assert_eq!(index["spec"], ETP_SPEC);

    let mut checked = 0_usize;
    for vector in index["vectors"].as_array().expect("vectors array") {
        let relative = vector["path"].as_str().expect("vector path");
        let document = vector["document"].as_str().expect("vector document");
        let expectation = vector["expect"].as_str().expect("vector expectation");
        let bytes = read(&vector_path(relative));
        match (document, expectation) {
            ("manifest", "valid") => {
                let report = validate_manifest_bytes(&bytes).expect("valid manifest");
                assert_eq!(report.status, EtpValidationStatus::Valid);
            }
            ("manifest", "integrity") => {
                let error = validate_manifest_bytes(&bytes).expect_err("integrity error");
                assert_eq!(error.exit_code(), 3, "{relative}");
            }
            ("manifest", "refused") => {
                let report = validate_manifest_bytes(&bytes).expect("structurally valid");
                assert_eq!(report.status, EtpValidationStatus::Refused, "{relative}");
                let code = vector["code"].as_str().expect("refusal code");
                let expected: EtpRefusalCode =
                    serde_json::from_value(serde_json::json!(code)).expect("known code");
                assert!(
                    report.refusals.iter().any(|item| item.code == expected),
                    "{relative} did not produce {code}"
                );
            }
            ("claim", "valid") => {
                parse_claim(&bytes).expect("valid claim");
            }
            ("obligation_inventory", "valid") => {
                parse_inventory(&bytes).expect("valid inventory");
            }
            ("status_dimensions", "valid") => {
                parse_dimensions(&bytes).expect("valid dimensions");
            }
            other => panic!("unhandled vector expectation {other:?} for {relative}"),
        }
        checked += 1;
    }
    assert_eq!(checked, index["vectors"].as_array().expect("vectors").len());
    assert!(checked >= 17);
}

#[test]
fn registry_digests_match_and_cover_every_schema_and_vector() {
    let registry_path = root().join("schemas/etp/registry.json");
    let registry: serde_json::Value =
        serde_json::from_slice(&read(&registry_path)).expect("registry JSON");
    assert_eq!(registry["schema"], "frf-etp.version-registry.v1");
    assert_eq!(registry["spec"], ETP_SPEC);
    assert_eq!(registry["baseline"]["release"], FROZEN_RELEASE);
    assert_eq!(registry["baseline"]["commit"], FROZEN_COMMIT);
    assert_eq!(
        registry["baseline"]["evidence_root_sha256"],
        FROZEN_EVIDENCE_ROOT_SHA256
    );

    let mut schema_ids = Vec::new();
    for schema in registry["schemas"].as_array().expect("schemas") {
        let id = schema["id"].as_str().expect("schema id");
        let path = root()
            .join("schemas/etp")
            .join(schema["path"].as_str().expect("path"));
        assert_eq!(
            sha_hex(&read(&path)),
            schema["sha256"].as_str().expect("sha")
        );
        schema_ids.push(id.to_owned());
    }
    for id in [
        ETP_MANIFEST_SCHEMA,
        ETP_CLAIM_SCHEMA,
        ETP_OBLIGATION_SCHEMA,
        ETP_STATUS_SCHEMA,
        "frf-etp.campaign-protocol.v1",
        "frf-etp.campaign-receipt.v1",
        "frf-etp.campaign-closure.v1",
        "frf-etp.sarif-projection.v1",
    ] {
        assert!(schema_ids.iter().any(|value| value == id), "missing {id}");
    }
    assert_eq!(schema_ids.len(), 8);

    let freeze = registry["freeze"].as_object().expect("freeze");
    let freeze_path = root()
        .join("schemas/etp")
        .join(freeze["path"].as_str().expect("freeze path"));
    assert_eq!(
        sha_hex(&read(&freeze_path)),
        freeze["sha256"].as_str().expect("freeze sha")
    );

    let mut listed = Vec::new();
    for vector in registry["vectors"].as_array().expect("vectors") {
        let path = root()
            .join("schemas/etp")
            .join(vector["path"].as_str().expect("vector path"));
        assert_eq!(
            sha_hex(&read(&path)),
            vector["sha256"].as_str().expect("vector sha")
        );
        listed.push(vector["path"].as_str().expect("vector path").to_owned());
    }
    assert!(listed.iter().any(|path| path == "vectors/index.json"));
    for entry in fs::read_dir(root().join("schemas/etp/vectors"))
        .expect("vector dir")
        .flatten()
    {
        let directory = entry.path();
        if directory.is_dir() {
            for child in fs::read_dir(&directory).expect("vector subdir").flatten() {
                let relative = format!(
                    "vectors/{}/{}",
                    directory.file_name().unwrap().to_string_lossy(),
                    child.file_name().to_string_lossy()
                );
                assert!(listed.contains(&relative), "unlisted vector {relative}");
            }
        }
    }
}

#[test]
fn schemas_are_well_formed_and_require_all_coordinates_and_dimensions() {
    for name in [
        "etp-manifest.v1.schema.json",
        "etp-claim.v1.schema.json",
        "etp-obligation-inventory.v1.schema.json",
        "etp-status-dimensions.v1.schema.json",
    ] {
        let path = root().join("schemas/etp").join(name);
        let schema: serde_json::Value = serde_json::from_slice(&read(&path)).expect("schema JSON");
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert!(schema["$id"].as_str().is_some_and(|id| id.ends_with(name)));
        assert_eq!(schema["additionalProperties"], false);
    }

    let claim: serde_json::Value =
        serde_json::from_slice(&read(&root().join("schemas/etp/etp-claim.v1.schema.json")))
            .expect("claim schema");
    let required = claim["required"].as_array().expect("claim required");
    assert_eq!(required.len(), COORDINATE_COUNT + 4);
    for coordinate in [
        "schema",
        "spec",
        "id",
        "property",
        "interpretation",
        "quantification",
        "legal_domain",
        "threat_model",
        "leakage_model",
        "subject_identity",
        "source_identity",
        "build_identity",
        "artifact_identity",
        "runtime_environment",
        "deployment_scope",
        "semantic_model",
        "assumptions",
        "trusted_computing_base",
        "obligations",
        "supporting_evidence",
        "contradictory_evidence",
        "policy_identity",
        "invalidation_dependencies",
        "status_dimensions",
    ] {
        assert!(
            required.iter().any(|value| value == coordinate),
            "missing coordinate {coordinate}"
        );
    }

    let dimensions: serde_json::Value = serde_json::from_slice(&read(
        &root().join("schemas/etp/etp-status-dimensions.v1.schema.json"),
    ))
    .expect("dimensions schema");
    let required = dimensions["required"]
        .as_array()
        .expect("dimension required");
    assert_eq!(required.len(), DIMENSION_COUNT + 2);
    for dimension in StatusDimensions::names() {
        assert!(
            required.iter().any(|value| value == dimension),
            "missing dimension {dimension}"
        );
    }
    for forbidden in ["confidence", "score", "assurance_level", "rating"] {
        assert!(dimensions["properties"].get(forbidden).is_none());
        assert!(claim["properties"].get(forbidden).is_none());
    }
}

#[test]
fn frozen_1_0_0_evidence_references_are_immutable() {
    let freeze_path = root().join("schemas/etp/etp-freeze-1.0.0.json");
    let freeze: serde_json::Value =
        serde_json::from_slice(&read(&freeze_path)).expect("freeze JSON");
    assert_eq!(freeze["schema"], "frf-etp.freeze.v1");
    assert_eq!(freeze["release"], FROZEN_RELEASE);
    assert_eq!(freeze["commit"], FROZEN_COMMIT);
    assert_eq!(freeze["evidence_root_sha256"], FROZEN_EVIDENCE_ROOT_SHA256);

    let mut lines = Vec::new();
    for file in freeze["files"].as_array().expect("files") {
        let path = file["path"].as_str().expect("path");
        let digest = sha_hex(&read(&root().join(path)));
        assert_eq!(digest, file["sha256"].as_str().expect("sha"), "{path}");
        lines.push(format!("{path}:{digest}"));
    }

    let expected = [
        (
            "SPEC.md",
            "2aa1b931554689d540dc8b05c582c43f53f669d776ff74d335e1a5982f84c131",
        ),
        (
            "PAPER.md",
            "9f2e78fddeb754d528e20486e27b50c3a77027c18a94b57d64f9d320fdda087a",
        ),
        (
            "evaluation/CLAIMS.json",
            "42b79068953157ec64b7c6e22a57c74c923f2919fb43f0ccfca78305df7dcd97",
        ),
        (
            "evaluation/LIMITATIONS.md",
            "896aecc5dda70b5601282ec9912c244388b32af9dde32bb27ac39c5933996791",
        ),
        (
            "evaluation/protocol.json",
            "02deb982c61c2a8307dbf3d34cf90f5aeb367e9ea7b1d794314aea9dd094d5ce",
        ),
        (
            "evaluation/receipts/MANIFEST.json",
            "aef7cd4f88269ea516e57eda6f5f1d1da42785ec2c3060f60568495b2118ffd5",
        ),
    ];
    for (path, digest) in expected {
        assert!(
            lines.iter().any(|line| line == &format!("{path}:{digest}")),
            "{path} digest changed"
        );
    }

    let receipts = &freeze["receipts"];
    assert_eq!(receipts["count"], 60);
    let receipt_dir = root().join("evaluation/receipts");
    let mut receipt_lines = Vec::new();
    for entry in fs::read_dir(&receipt_dir).expect("receipt dir").flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("json")
            && path.file_name().and_then(|value| value.to_str()) != Some("MANIFEST.json")
        {
            receipt_lines.push(format!(
                "{}:{}",
                path.file_name().unwrap().to_string_lossy(),
                sha_hex(&read(&path))
            ));
        }
    }
    receipt_lines.sort();
    assert_eq!(receipt_lines.len(), 60);
    let aggregate = sha_hex(format!("{}\n", receipt_lines.join("\n")).as_bytes());
    assert_eq!(aggregate, receipts["aggregate_sha256"]);
    lines.push(format!("evaluation/receipts/*:{aggregate}"));
    lines.sort();
    let recomputed = sha_hex(format!("{}\n", lines.join("\n")).as_bytes());
    assert_eq!(recomputed, FROZEN_EVIDENCE_ROOT_SHA256);
}

#[test]
fn reports_and_schemas_never_carry_a_scalar_assurance_score() {
    let bytes = read(&vector_path("valid/manifest.json"));
    let report = validate_manifest_bytes(&bytes).expect("valid");
    let value = serde_json::to_value(&report).expect("report JSON");
    scan_for_scalars(&value);

    let status: serde_json::Value = serde_json::from_slice(&read(
        &root().join("schemas/etp/etp-status-dimensions.v1.schema.json"),
    ))
    .expect("dimensions schema");
    scan_for_scalars(&status);
}

#[test]
fn existing_1_0_0_claim_ledger_and_receipt_count_are_untouched() {
    let claims: serde_json::Value =
        serde_json::from_slice(&read(&root().join("evaluation/CLAIMS.json"))).expect("claims JSON");
    assert_eq!(claims["schema"], "frf-memorysafety.paper-claims.v1");
    assert_eq!(claims["protocol_version"], "phase9.1-v1");
    assert_eq!(
        claims["protocol_sha256"],
        "02deb982c61c2a8307dbf3d34cf90f5aeb367e9ea7b1d794314aea9dd094d5ce"
    );
    assert_eq!(claims["constants"]["receipts"], 60);
    assert_eq!(claims["constants"]["cases"], 31);
    assert_eq!(claims["constants"]["held_out_cases"], 20);
    assert_eq!(claims["constants"]["development_cases"], 11);
    assert_eq!(claims["constants"]["paper_claims"], 18);
    assert_eq!(claims["claims"].as_array().expect("claims").len(), 18);
    assert!(claims["claims"]
        .as_array()
        .expect("claims")
        .iter()
        .all(|claim| claim["status"] == "supported"));
}

#[test]
fn dimension_names_are_ten_and_distinct() {
    let names = StatusDimensions::names();
    assert_eq!(names.len(), DIMENSION_COUNT);
    let unique: std::collections::BTreeSet<_> = names.iter().collect();
    assert_eq!(unique.len(), DIMENSION_COUNT);
    let encoded = serde_json::to_value(names).expect("names");
    assert_eq!(encoded.as_array().map(Vec::len), Some(10));
}
