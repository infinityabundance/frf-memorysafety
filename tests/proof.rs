//! Phase 6.1 proof manifest, closure, admission, and correspondence tests.
//!
//! Every test executes. None is ignored. The fixtures are generated in a
//! temporary directory and written as canonical `frf-memorysafety.proof-manifest.v1`
//! documents. No proof checker is invoked.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use frf_memorysafety::identity::{canonical_bytes, require_canonical};
use frf_memorysafety::proof::{
    evaluate_admission, evaluate_correspondence, parse_manifest, verify_manifest_bytes,
    AdmissionStatus, CheckerContext, CheckerKind, CheckerRun, CorrespondenceReport, GateStatus,
    ProofDigest, ProofError, ProofManifest, ProofOutcome, ProofReport, TransitionKind,
    PROOF_MANIFEST_SCHEMA, PROOF_SPEC,
};
use frf_memorysafety::source::scan_source_default;

const HELPER_PROOF: &str = "\
Lemma frf_helper : forall n : nat, n = n.
Proof.
  intros n.
  reflexivity.
Qed.
";

const MAIN_PROOF: &str = "\
Require Import Coq.Init.Nat.
Require Import helper.

Theorem frf_safe_wrapper : forall n : nat, n = n.
Proof.
  intros n.
  apply frf_helper.
Qed.
";

const SUPPORT_PROOF: &str = "\
Theorem unrelated_support : forall n : nat, n = n.
Proof.
  intros n.
  reflexivity.
Qed.
";

const SOURCE: &str = "\
use std::os::raw::c_int;

extern \"C\" {
    pub fn frf_foreign_create(value: c_int) -> *mut c_int;
    pub fn frf_foreign_free(ptr: *mut c_int);
}

pub type FrfCallback = unsafe extern \"C\" fn(*mut std::ffi::c_void);

#[no_mangle]
pub unsafe extern \"C\" fn frf_wrapper_callback(callback: FrfCallback) {
    callback(std::ptr::null_mut());
}

pub fn frf_safe_create(value: c_int) -> *mut c_int {
    // The wrapper is separately checked by correspondence evidence.
    unsafe { frf_foreign_create(value) }
}
";

const WRAPPER_EVIDENCE: &str =
    "correspondence: frf_safe_create inspects the frf_foreign_create result and refuses null";
const LIFECYCLE_EVIDENCE: &str =
    "correspondence: lifecycle allocation and initialization are enumerated";
const TRANSFER_EVIDENCE: &str =
    "correspondence: ownership transfer between frf_safe_create and the caller is enumerated";
const FREE_EVIDENCE: &str = "correspondence: frf_foreign_free consumes the transferred pointer";
const CALLBACK_EVIDENCE: &str =
    "correspondence: frf_wrapper_callback is a reentrant callback transition";

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "frf-proof-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn sha(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    frf_memorysafety::identity::hex_lower(&hasher.finalize())
}

struct Fixture {
    dir: TempDir,
    manifest: Value,
    manifest_path: PathBuf,
}

impl Fixture {
    fn parse(&self) -> ProofManifest {
        let bytes = canonical_bytes(&self.manifest).unwrap();
        parse_manifest(&bytes).unwrap()
    }

    fn bytes(&self) -> Vec<u8> {
        canonical_bytes(&self.manifest).unwrap()
    }

    fn admission(&self) -> frf_memorysafety::proof::AdmissionReport {
        evaluate_admission(&self.parse(), self.dir.path()).unwrap()
    }

    fn correspondence(&self) -> CorrespondenceReport {
        evaluate_correspondence(&self.parse(), self.dir.path()).unwrap()
    }

    fn verify(&self, context: &CheckerContext) -> Result<ProofReport, ProofError> {
        verify_manifest_bytes(&self.bytes(), self.dir.path(), context)
    }

    fn write_manifest(&self) -> &Path {
        fs::write(&self.manifest_path, self.bytes()).unwrap();
        &self.manifest_path
    }

    fn proof_entry(&mut self, file_id: &str) -> &mut Value {
        self.manifest["proof_files"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["id"] == file_id)
            .unwrap()
    }

    fn set_proof_text(&mut self, file_id: &str, text: &str) {
        let path = self.proof_entry(file_id)["path"]
            .as_str()
            .unwrap()
            .to_owned();
        fs::write(self.dir.path().join(path), text).unwrap();
        let digest = sha(text);
        self.proof_entry(file_id)["sha256"] = json!(digest);
        let digest_entry = self.manifest["admission"]["proof_digests"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["file_id"] == file_id)
            .unwrap();
        digest_entry["sha256"] = json!(digest);
    }

    fn run(&self) -> CheckerRun {
        let proof_digests = self.manifest["admission"]["proof_digests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| ProofDigest {
                file_id: entry["file_id"].as_str().unwrap().to_owned(),
                sha256: entry["sha256"].as_str().unwrap().to_owned(),
            })
            .collect();
        let theorems = self.manifest["admission"]["theorems"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| frf_memorysafety::proof::AdmissionTheorem {
                name: entry["name"].as_str().unwrap().to_owned(),
                status: serde_json::from_value(entry["status"].clone()).unwrap(),
            })
            .collect();
        CheckerRun {
            kind: CheckerKind::Coq,
            version: self.manifest["checker"]["version"]
                .as_str()
                .unwrap()
                .to_owned(),
            exit_code: 0,
            proof_digests,
            theorems,
        }
    }
}

fn fixture() -> Fixture {
    base_fixture()
}

#[allow(clippy::too_many_lines)]
fn base_fixture() -> Fixture {
    let dir = TempDir::new("base");
    let proofs = dir.path().join("proofs");
    let src = dir.path().join("src");
    let correspondence = dir.path().join("correspondence");
    fs::create_dir_all(&proofs).unwrap();
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&correspondence).unwrap();
    fs::write(proofs.join("helper.v"), HELPER_PROOF).unwrap();
    fs::write(proofs.join("main.v"), MAIN_PROOF).unwrap();
    fs::write(src.join("lib.rs"), SOURCE).unwrap();
    for (name, text) in [
        ("ev-wrapper.txt", WRAPPER_EVIDENCE),
        ("ev-lifecycle.txt", LIFECYCLE_EVIDENCE),
        ("ev-transfer.txt", TRANSFER_EVIDENCE),
        ("ev-free.txt", FREE_EVIDENCE),
        ("ev-callback.txt", CALLBACK_EVIDENCE),
    ] {
        fs::write(correspondence.join(name), text).unwrap();
    }

    let helper_digest = sha(HELPER_PROOF);
    let main_digest = sha(MAIN_PROOF);
    let source_digest = sha(SOURCE);
    let evidence = |name: &str, text: &str, kind: &str, detail: &str| {
        json!({
            "id": name,
            "kind": kind,
            "path": format!("correspondence/{name}.txt"),
            "sha256": sha(text),
            "detail": detail,
        })
    };

    let manifest = json!({
        "schema": PROOF_MANIFEST_SCHEMA,
        "spec": PROOF_SPEC,
        "claim_ceiling": frf_memorysafety::proof::PROOF_CLAIM_CEILING,
        "checker": {
            "kind": "coq",
            "version": "8.19.2",
            "executable": "coqc"
        },
        "proof_files": [
            {
                "id": "helper",
                "path": "proofs/helper.v",
                "sha256": helper_digest,
                "language": "coq",
                "role": "dependency",
                "theorems": ["frf_helper"],
                "imports": ["Coq.Init.Nat"]
            },
            {
                "id": "main",
                "path": "proofs/main.v",
                "sha256": main_digest,
                "language": "coq",
                "role": "theorem",
                "theorems": ["frf_safe_wrapper"],
                "imports": ["helper", "Coq.Init.Nat"]
            }
        ],
        "theorem": {
            "name": "frf_safe_wrapper",
            "claim_ids": ["claim-safe-wrapper"]
        },
        "scope": {
            "claim_ids": ["claim-safe-wrapper"],
            "finite_domain": "the declared finite FFI wrapper state machine",
            "proved": "the wrapper preserves the finite-domain memory-safety predicate",
            "not_proved": [
                "universal Rust soundness",
                "native execution of the foreign implementation",
                "completeness of the declared dependency graph"
            ]
        },
        "closure": {
            "theorems": ["frf_helper", "frf_safe_wrapper"],
            "local_dependencies": [
                {
                    "theorem": "frf_safe_wrapper",
                    "depends_on": ["frf_helper"]
                }
            ],
            "stdlib_allowlist": ["Coq.Init.*"]
        },
        "assumptions": [
            {
                "id": "h-bound",
                "kind": "hypothesis",
                "name": "bounded_input",
                "justification": "bound by the theorem's universally quantified parameter",
                "scope": "frf_safe_wrapper",
                "discharged_by": "frf_safe_wrapper"
            }
        ],
        "admission": {
            "origin": "authentic_checker_run",
            "checker_kind": "coq",
            "checker_version": "8.19.2",
            "exit_code": 0,
            "proof_digests": [
                {"file_id": "helper", "sha256": helper_digest},
                {"file_id": "main", "sha256": main_digest}
            ],
            "theorems": [
                {"name": "frf_helper", "status": "proved"},
                {"name": "frf_safe_wrapper", "status": "proved"}
            ],
            "classification": "accepted_within_scope"
        },
        "implementation_binding": {
            "statement": "frf_safe_create refines the finite-domain theorem frf_safe_wrapper for every enumerated transition",
            "source_inventory": null,
            "rust_symbols": [
                {
                    "symbol": "frf_foreign_create",
                    "kind": "ffi_declaration",
                    "source_path": "src/lib.rs",
                    "source_sha256": source_digest,
                    "ffi": {
                        "declaration": "extern \"C\" { pub fn frf_foreign_create(value: c_int) -> *mut c_int; }",
                        "wrapper_symbol": "frf_safe_create",
                        "wrapper_checked": true,
                        "wrapper_evidence": "ev-wrapper"
                    }
                },
                {
                    "symbol": "frf_wrapper_callback",
                    "kind": "callback",
                    "source_path": "src/lib.rs",
                    "source_sha256": source_digest
                }
            ],
            "binding_evidence": [
                {
                    "symbol": "frf_foreign_create",
                    "path": "src/lib.rs",
                    "sha256": source_digest,
                    "detail": "exact FFI declaration and wrapper call site"
                },
                {
                    "symbol": "frf_wrapper_callback",
                    "path": "src/lib.rs",
                    "sha256": source_digest,
                    "detail": "exact callback definition"
                }
            ],
            "transitions": [
                {"id": "t-create", "kind": "lifecycle", "description": "allocate and initialize", "evidence": "ev-lifecycle"},
                {"id": "t-transfer", "kind": "transfer", "description": "transfer ownership", "evidence": "ev-transfer"},
                {"id": "t-free", "kind": "free", "description": "release the transferred pointer", "evidence": "ev-free"},
                {"id": "t-callback", "kind": "reentrant_callback", "description": "reentrant callback may mutate live state", "evidence": "ev-callback"}
            ],
            "required_transitions": ["lifecycle", "transfer", "free", "reentrant_callback"],
            "correspondence_evidence": [
                evidence("ev-wrapper", WRAPPER_EVIDENCE, "refinement", "checked wrapper"),
                evidence("ev-lifecycle", LIFECYCLE_EVIDENCE, "transition_enumeration", "lifecycle"),
                evidence("ev-transfer", TRANSFER_EVIDENCE, "transition_enumeration", "transfer"),
                evidence("ev-free", FREE_EVIDENCE, "transition_enumeration", "free"),
                evidence("ev-callback", CALLBACK_EVIDENCE, "transition_enumeration", "reentrant callback")
            ]
        },
        "provenance": {
            "origin": "authentic_checker_run",
            "run_id": "fixture-run-1",
            "detail": "recorded fixture result; this test does not invoke a checker"
        }
    });

    let manifest_path = dir.path().join("manifest.json");
    Fixture {
        dir,
        manifest,
        manifest_path,
    }
}

fn cli(args: &[&str]) -> i32 {
    frf_memorysafety::cli::run(args.iter().map(|value| (*value).to_owned()))
}

#[test]
fn approved_manifest_is_well_formed_but_not_accepted_without_a_live_checker() {
    let fixture = fixture();
    let manifest = fixture.parse();
    assert_eq!(manifest.theorem.name, "frf_safe_wrapper");

    let admission = fixture.admission();
    assert_eq!(admission.outcome, ProofOutcome::AcceptedWithinScope);
    assert_eq!(admission.scanned_files.len(), 2);
    assert!(admission.forbidden_findings.is_empty());
    assert_eq!(admission.assumptions.len(), 1);
    assert_eq!(
        admission.assumptions[0].status,
        frf_memorysafety::proof::AssumptionStatus::AllowedHypothesis
    );

    let correspondence = fixture.correspondence();
    assert_eq!(correspondence.status, GateStatus::Pass);
    assert!(correspondence.outcome.is_none());
    assert_eq!(correspondence.symbols.len(), 2);
    assert!(correspondence
        .required_transitions
        .contains(&TransitionKind::ReentrantCallback));
    assert!(correspondence.missing_transitions.is_empty());

    let report = fixture.verify(&CheckerContext::NotConfigured).unwrap();
    assert_eq!(report.outcome, ProofOutcome::CheckerUnavailable);
    assert_eq!(report.outcome.exit_code(), 6);
    assert!(!report.live_checker_invoked);
    assert!(!report.live_checker_configured);
    assert_eq!(
        report.universal_soundness,
        frf_memorysafety::profile::UNIVERSAL_SOUNDNESS
    );
    require_canonical(&report.canonical_bytes().unwrap()).unwrap();

    let recorded = fixture
        .verify(&CheckerContext::Recorded(fixture.run()))
        .unwrap();
    assert_eq!(recorded.outcome, ProofOutcome::AcceptedWithinScope);
    assert_eq!(recorded.outcome.exit_code(), 0);
    assert_eq!(
        recorded.acceptance_basis,
        frf_memorysafety::proof::AcceptanceBasis::RecordedAuthenticCheckerRun
    );
    assert!(!recorded.live_checker_invoked);
}

#[test]
fn verification_is_deterministic() {
    let fixture = fixture();
    let first = fixture
        .verify(&CheckerContext::NotConfigured)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let second = fixture
        .verify(&CheckerContext::NotConfigured)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    assert_eq!(first, second);
    let value = require_canonical(&first).unwrap();
    assert_eq!(
        value["schema"],
        frf_memorysafety::proof::PROOF_REPORT_SCHEMA
    );
}

#[test]
fn admitted_sorry_and_axiom_are_rejected() {
    let mut admitted = fixture();
    admitted.set_proof_text("main", &format!("{MAIN_PROOF}\nAdmitted.\n"));
    let report = admitted.admission();
    assert_eq!(report.outcome, ProofOutcome::RejectedAssumption);
    assert!(report
        .forbidden_findings
        .iter()
        .any(|finding| finding.token == "Admitted"));

    let mut sorry = fixture();
    sorry.set_proof_text(
        "helper",
        &format!("{HELPER_PROOF}\nTheorem helper_stub : True.\nsorry\n"),
    );
    let report = sorry.admission();
    assert_eq!(report.outcome, ProofOutcome::RejectedAssumption);
    assert!(report
        .forbidden_findings
        .iter()
        .any(|finding| finding.token == "sorry"));

    let mut axiom = fixture();
    axiom.set_proof_text(
        "helper",
        &format!("Axiom frf_axiom : forall n : nat, n = n.\n{HELPER_PROOF}"),
    );
    let report = axiom.admission();
    assert_eq!(report.outcome, ProofOutcome::RejectedAssumption);
    let finding = report
        .forbidden_findings
        .iter()
        .find(|finding| finding.token == "Axiom")
        .unwrap();
    assert_eq!(finding.declared_name.as_deref(), Some("frf_axiom"));
    assert!(!finding.declared_in_manifest);
}

#[test]
fn declared_axiom_is_rejected_even_without_a_lexical_hit() {
    let mut fixture = fixture();
    fixture.manifest["assumptions"] = json!([
        {
            "id": "a-global",
            "kind": "axiom",
            "name": "global_axiom",
            "justification": "claimed to be a specification axiom",
            "scope": "frf_safe_wrapper"
        }
    ]);
    let report = fixture.admission();
    assert_eq!(report.outcome, ProofOutcome::RejectedAssumption);
    assert_eq!(
        report.assumptions[0].status,
        frf_memorysafety::proof::AssumptionStatus::Rejected
    );
}

#[test]
fn unrelated_admission_is_rejected() {
    let mut fixture = fixture();
    fixture.manifest["admission"]["theorems"] = json!([
        {"name": "other_theorem", "status": "proved"}
    ]);
    let report = fixture.admission();
    assert_eq!(report.outcome, ProofOutcome::RejectedUnrelated);
    assert!(report.detail.contains("outside the declared closure"));

    let mut extra = base_fixture();
    extra.manifest["admission"]["theorems"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": "other_theorem", "status": "proved"}));
    let report = extra.admission();
    assert_eq!(report.outcome, ProofOutcome::RejectedUnrelated);
}

#[test]
fn theorem_outside_declared_scope_is_rejected() {
    let mut fixture = fixture();
    fixture.manifest["theorem"]["claim_ids"] = json!(["claim-outside-scope"]);
    let report = fixture.admission();
    assert_eq!(report.outcome, ProofOutcome::RejectedUnrelated);
    assert!(report.detail.contains("outside scope.claim_ids"));
}

#[test]
fn unrelated_admission_in_an_unscanned_file_is_not_attributed() {
    let mut fixture = fixture();
    let support = fixture.dir.path().join("proofs/support.v");
    fs::write(&support, SUPPORT_PROOF).unwrap();
    let support_digest = sha(SUPPORT_PROOF);
    fixture.manifest["proof_files"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": "support",
            "path": "proofs/support.v",
            "sha256": support_digest,
            "language": "coq",
            "role": "support",
            "theorems": ["unrelated_support"],
            "imports": []
        }));
    fixture.manifest["admission"]["proof_digests"]
        .as_array_mut()
        .unwrap()
        .push(json!({"file_id": "support", "sha256": support_digest}));

    // The support file contains `sorry`, but it is outside the requested
    // theorem's dependency closure and must not be attributed to it.
    fs::write(
        &support,
        format!("{SUPPORT_PROOF}\nTheorem support_stub : True.\nsorry\n"),
    )
    .unwrap();
    let unsupported_digest = sha(&format!(
        "{SUPPORT_PROOF}\nTheorem support_stub : True.\nsorry\n"
    ));
    fixture.proof_entry("support")["sha256"] = json!(unsupported_digest);
    let digest_entry = fixture.manifest["admission"]["proof_digests"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entry| entry["file_id"] == "support")
        .unwrap();
    digest_entry["sha256"] = json!(unsupported_digest);

    let report = fixture.admission();
    assert_eq!(report.outcome, ProofOutcome::AcceptedWithinScope);
    assert!(report.forbidden_findings.is_empty());
}

#[test]
fn missing_and_tampered_proof_files_are_integrity_failures() {
    let fixture = fixture();
    fs::remove_file(fixture.dir.path().join("proofs/helper.v")).unwrap();
    let error = evaluate_admission(&fixture.parse(), fixture.dir.path()).unwrap_err();
    assert!(matches!(error, ProofError::MissingFile { .. }));
    assert_eq!(
        error.category(),
        frf_memorysafety::proof::ProofErrorCategory::Integrity
    );

    let mut tampered = base_fixture();
    tampered.proof_entry("helper")["sha256"] = json!("0".repeat(64));
    let digest_entry = tampered.manifest["admission"]["proof_digests"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entry| entry["file_id"] == "helper")
        .unwrap();
    digest_entry["sha256"] = json!("0".repeat(64));
    let error = evaluate_admission(&tampered.parse(), tampered.dir.path()).unwrap_err();
    assert!(matches!(error, ProofError::DigestMismatch { .. }));
}

#[test]
fn missing_digest_field_is_rejected_by_the_typed_schema() {
    let mut fixture = fixture();
    fixture.manifest["proof_files"][0]
        .as_object_mut()
        .unwrap()
        .remove("sha256");
    let bytes = canonical_bytes(&fixture.manifest).unwrap();
    let error = parse_manifest(&bytes).unwrap_err();
    assert!(matches!(error, ProofError::Invalid { .. }));
    assert!(error.to_string().contains("sha256"));
}

#[test]
fn checker_version_and_digest_mismatch_are_rejected() {
    let mut version = fixture();
    version.manifest["admission"]["checker_version"] = json!("8.18.0");
    let bytes = canonical_bytes(&version.manifest).unwrap();
    let error = parse_manifest(&bytes).unwrap_err();
    assert!(matches!(error, ProofError::CheckerMismatch { .. }));

    let mut digest = fixture();
    digest.manifest["admission"]["proof_digests"][0]["sha256"] = json!("0".repeat(64));
    let bytes = canonical_bytes(&digest.manifest).unwrap();
    let error = parse_manifest(&bytes).unwrap_err();
    assert!(matches!(error, ProofError::CheckerMismatch { .. }));
}

#[test]
fn recorded_checker_run_must_match_the_manifest() {
    let fixture = fixture();
    let mut run = fixture.run();
    run.version = "8.18.0".to_owned();
    let report = fixture.verify(&CheckerContext::Recorded(run)).unwrap();
    assert_eq!(report.outcome, ProofOutcome::CheckerFailed);
    assert_eq!(report.outcome.exit_code(), 4);

    let mut substituted = fixture.run();
    substituted.theorems[0].status = AdmissionStatus::Admitted;
    let report = fixture
        .verify(&CheckerContext::Recorded(substituted))
        .unwrap();
    assert_eq!(report.outcome, ProofOutcome::CheckerFailed);
}

#[test]
fn duplicate_and_unknown_fields_are_rejected() {
    let duplicate = br#"{"schema":"a","schema":"b"}"#;
    let error = parse_manifest(duplicate).unwrap_err();
    assert!(matches!(error, ProofError::Identity(_)));
    assert!(error.to_string().contains("duplicate"));

    let mut unknown = fixture();
    unknown.manifest["unexpected"] = json!(true);
    let error = parse_manifest(&canonical_bytes(&unknown.manifest).unwrap()).unwrap_err();
    assert!(matches!(error, ProofError::Invalid { .. }));

    let mut nested = fixture();
    nested.manifest["proof_files"][0]["unexpected"] = json!(true);
    let error = parse_manifest(&canonical_bytes(&nested.manifest).unwrap()).unwrap_err();
    assert!(matches!(error, ProofError::Invalid { .. }));

    let mut duplicate_id = fixture();
    let clone = duplicate_id.manifest["proof_files"][0].clone();
    duplicate_id.manifest["proof_files"]
        .as_array_mut()
        .unwrap()
        .push(clone);
    duplicate_id.proof_entry("helper")["path"] = json!("proofs/duplicate.v");
    let error = parse_manifest(&canonical_bytes(&duplicate_id.manifest).unwrap()).unwrap_err();
    assert!(matches!(error, ProofError::Invalid { .. }));
    assert!(error.to_string().contains("duplicate"));
}

#[test]
fn unchecked_ffi_wrapper_is_rejected_even_when_theorem_is_proved() {
    let mut fixture = fixture();
    fixture.manifest["implementation_binding"]["rust_symbols"][0]["ffi"]["wrapper_checked"] =
        json!(false);

    let admission = fixture.admission();
    assert_eq!(admission.outcome, ProofOutcome::AcceptedWithinScope);

    let correspondence = fixture.correspondence();
    assert_eq!(correspondence.status, GateStatus::Fail);
    assert_eq!(
        correspondence.outcome,
        Some(ProofOutcome::RejectedUncheckedImplementation)
    );
    assert_eq!(
        correspondence.unchecked_wrappers,
        vec!["frf_foreign_create"]
    );

    let report = fixture
        .verify(&CheckerContext::Recorded(fixture.run()))
        .unwrap();
    assert_eq!(report.admission.outcome, ProofOutcome::AcceptedWithinScope);
    assert_eq!(
        report.outcome,
        ProofOutcome::RejectedUncheckedImplementation
    );
    assert_eq!(report.outcome.exit_code(), 4);
}

#[test]
fn missing_reentrant_callback_transition_is_rejected() {
    let mut fixture = fixture();
    let transitions = fixture.manifest["implementation_binding"]["transitions"]
        .as_array_mut()
        .unwrap();
    transitions.retain(|transition| transition["kind"] != "reentrant_callback");

    let correspondence = fixture.correspondence();
    assert_eq!(correspondence.status, GateStatus::Fail);
    assert_eq!(
        correspondence.outcome,
        Some(ProofOutcome::RejectedMissingTransition)
    );
    assert!(correspondence
        .missing_transitions
        .contains(&TransitionKind::ReentrantCallback));

    let report = fixture
        .verify(&CheckerContext::Recorded(fixture.run()))
        .unwrap();
    assert_eq!(report.outcome, ProofOutcome::RejectedMissingTransition);
}

#[test]
fn correspondence_gate_runs_independently_of_admission() {
    let mut fixture = fixture();
    fixture.set_proof_text("main", &format!("{MAIN_PROOF}\nAdmitted.\n"));
    let admission = fixture.admission();
    assert_eq!(admission.outcome, ProofOutcome::RejectedAssumption);
    let correspondence = fixture.correspondence();
    assert_eq!(correspondence.status, GateStatus::Pass);
    assert!(correspondence.outcome.is_none());
}

#[test]
fn source_inventory_binding_is_verified() {
    let mut fixture = fixture();
    let inventory = scan_source_default(fixture.dir.path()).unwrap();
    let inventory_bytes = inventory.canonical_bytes().unwrap();
    fs::write(fixture.dir.path().join("inventory.json"), &inventory_bytes).unwrap();
    fixture.manifest["implementation_binding"]["source_inventory"] = json!({
        "path": "inventory.json",
        "sha256": frf_memorysafety::identity::hex_lower(&Sha256::digest(&inventory_bytes))
    });
    let correspondence = fixture.correspondence();
    assert_eq!(correspondence.status, GateStatus::Pass);
    assert!(correspondence.source_inventory.is_some());

    fixture.manifest["implementation_binding"]["source_inventory"]["sha256"] =
        json!("0".repeat(64));
    let error = evaluate_correspondence(&fixture.parse(), fixture.dir.path()).unwrap_err();
    assert!(matches!(error, ProofError::DigestMismatch { .. }));
}

#[test]
fn explicit_binding_evidence_is_required_without_an_inventory() {
    let mut fixture = fixture();
    fixture.manifest["implementation_binding"]["binding_evidence"] = json!([]);
    let correspondence = fixture.correspondence();
    assert_eq!(correspondence.status, GateStatus::Fail);
    assert_eq!(
        correspondence.outcome,
        Some(ProofOutcome::RejectedUncheckedImplementation)
    );
    assert!(correspondence
        .symbols
        .iter()
        .any(|symbol| symbol.detail.contains("no explicit binding evidence")));
}

#[test]
fn cli_returns_checker_unavailable_without_a_live_checker() {
    let fixture = fixture();
    let path = fixture.write_manifest().to_str().unwrap().to_owned();
    assert_eq!(cli(&["proof", "verify", &path]), 6);
    assert_eq!(cli(&["proof", "verify", &path, "--json"]), 6);
}

#[test]
fn cli_rejects_admission_and_integrity_failures_with_section_14_statuses() {
    let mut admitted = fixture();
    admitted.set_proof_text("main", &format!("{MAIN_PROOF}\nAdmitted.\n"));
    let path = admitted.write_manifest().to_str().unwrap().to_owned();
    assert_eq!(cli(&["proof", "verify", &path, "--json"]), 4);

    let mut unknown = fixture();
    unknown.manifest["unexpected"] = json!(true);
    let path = unknown.write_manifest().to_str().unwrap().to_owned();
    assert_eq!(cli(&["proof", "verify", &path]), 3);

    let missing = fixture();
    let path = missing.write_manifest().to_str().unwrap().to_owned();
    fs::remove_file(missing.dir.path().join("proofs/helper.v")).unwrap();
    assert_eq!(cli(&["proof", "verify", &path]), 3);
}

#[test]
fn proof_cli_usage_errors_return_two() {
    assert_eq!(cli(&["proof"]), 2);
    assert_eq!(cli(&["proof", "verify"]), 2);
    assert_eq!(cli(&["proof", "verify", "--json"]), 2);
    assert_eq!(cli(&["proof", "verify", "a", "b"]), 2);
    assert_eq!(cli(&["proof", "verify", "/definitely/not/a/file"]), 2);
}

#[test]
fn proof_manifest_rejects_absolute_and_parent_paths() {
    let mut fixture = fixture();
    fixture.manifest["proof_files"][0]["path"] = json!("../escape.v");
    let error = parse_manifest(&canonical_bytes(&fixture.manifest).unwrap()).unwrap_err();
    assert!(matches!(error, ProofError::PathEscape { .. }));

    let mut absolute = base_fixture();
    absolute.manifest["proof_files"][0]["path"] = json!("/tmp/escape.v");
    let error = parse_manifest(&canonical_bytes(&absolute.manifest).unwrap()).unwrap_err();
    assert!(matches!(error, ProofError::PathEscape { .. }));
}

#[test]
fn imports_outside_the_closure_and_allowlist_are_rejected() {
    let mut fixture = fixture();
    fixture.manifest["proof_files"][1]["imports"]
        .as_array_mut()
        .unwrap()
        .push(json!("Unlisted.Library"));
    let error = parse_manifest(&canonical_bytes(&fixture.manifest).unwrap()).unwrap_err();
    assert!(matches!(error, ProofError::Invalid { .. }));
    assert!(error.to_string().contains("stdlib allowlist"));
}
