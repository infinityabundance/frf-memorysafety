//! CLI integration tests: real parsing, file I/O, and exit statuses.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use frf_memorysafety::identity::canonical_bytes;
use frf_memorysafety::profile::{
    canonical_bundle_bytes, local_buffer_bundle, local_buffer_records,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "frf-memorysafety-{label}-{}-{sequence}",
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

fn run(args: &[&str]) -> i32 {
    frf_memorysafety::cli::run(args.iter().map(|value| (*value).to_owned()))
}

fn write_canonical(path: &Path, value: &serde_json::Value) {
    fs::write(path, canonical_bytes(value).unwrap()).unwrap();
}

#[test]
fn version_and_capabilities_succeed_as_json() {
    assert_eq!(run(&["version", "--json"]), 0);
    assert_eq!(run(&["capabilities", "--json"]), 0);
    assert_eq!(run(&["help"]), 0);
}

#[test]
fn usage_errors_return_two() {
    assert_eq!(frf_memorysafety::cli::run(Vec::<String>::new()), 2);
    assert_eq!(run(&["unknown-command"]), 2);
    assert_eq!(run(&["profile"]), 2);
    assert_eq!(run(&["profile", "validate"]), 2);
    assert_eq!(run(&["profile", "enumerate"]), 2);
    assert_eq!(run(&["support", "evaluate"]), 2);
    assert_eq!(run(&["evidence", "verify"]), 2);
    assert_eq!(run(&["report"]), 2);
}

#[test]
fn live_commands_return_six() {
    assert_eq!(run(&["court", "run", "--case", "x"]), 6);
    assert_eq!(run(&["detector", "calibrate", "--live"]), 6);
    assert_eq!(run(&["frf", "promote", "--case", "x"]), 6);
    assert_eq!(run(&["gemel", "publish", "--case", "x"]), 6);
}

#[test]
fn profile_enumerate_writes_canonical_inputs() {
    let temp = TempDir::new("enumerate");
    let out = temp.path().join("bundle");
    assert_eq!(
        run(&["profile", "enumerate", "--out", out.to_str().unwrap()]),
        0
    );
    for name in ["bundle.json", "policy.json", "claims.json", "cases.json"] {
        let bytes = fs::read(out.join(name)).unwrap();
        frf_memorysafety::identity::require_canonical(&bytes)
            .unwrap_or_else(|error| panic!("{name} is not canonical: {error}"));
    }
    let cases: Vec<serde_json::Value> =
        serde_json::from_slice(&fs::read(out.join("cases.json")).unwrap()).unwrap();
    assert_eq!(cases.len(), local_buffer_records().len());
}

#[test]
fn profile_validate_and_report_keep_universal_soundness_withheld() {
    let temp = TempDir::new("validate");
    let bundle_path = temp.path().join("bundle.json");
    fs::write(
        &bundle_path,
        canonical_bundle_bytes(&local_buffer_bundle()).unwrap(),
    )
    .unwrap();
    // The fixture deliberately includes one universal request per variant, so
    // the profile refuses those requests (exit 4) while keeping every other
    // finite claim evaluable.
    assert_eq!(
        run(&["profile", "validate", bundle_path.to_str().unwrap()]),
        4
    );
    assert_eq!(
        run(&[
            "report",
            "--case",
            bundle_path.to_str().unwrap(),
            "--format",
            "json"
        ]),
        4
    );
    assert_eq!(
        run(&[
            "report",
            "--case",
            bundle_path.to_str().unwrap(),
            "--format",
            "markdown"
        ]),
        4
    );
}

#[test]
fn profile_validate_rejects_unknown_fields_with_integrity_exit() {
    let temp = TempDir::new("unknown");
    let path = temp.path().join("bundle.json");
    let mut value = serde_json::to_value(local_buffer_bundle()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), serde_json::json!(1));
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(run(&["profile", "validate", path.to_str().unwrap()]), 3);
}

#[test]
fn support_evaluate_and_explain_work() {
    let temp = TempDir::new("support");
    let path = temp.path().join("support.json");
    write_canonical(
        &path,
        &serde_json::json!({
            "schema": "frf-memorysafety.support.v1",
            "spec": "frf-memorysafety-spec-v1",
            "rules": {
                "rules": {"q": [["a"]]},
                "admitted_leaves": ["a"]
            },
            "revoked": [],
            "challenged": [],
            "claim": "q"
        }),
    );
    assert_eq!(run(&["support", "evaluate", path.to_str().unwrap()]), 0);
    assert_eq!(run(&["support", "explain", path.to_str().unwrap()]), 0);
}

#[test]
fn support_evaluate_rejects_unknown_nested_fields() {
    let temp = TempDir::new("support-unknown");
    let path = temp.path().join("support.json");
    write_canonical(
        &path,
        &serde_json::json!({
            "schema": "frf-memorysafety.support.v1",
            "spec": "frf-memorysafety-spec-v1",
            "rules": {
                "rules": {"q": [["a"]]},
                "admitted_leaves": ["a"],
                "unexpected": true
            },
            "claim": "q"
        }),
    );
    assert_eq!(run(&["support", "evaluate", path.to_str().unwrap()]), 3);
}

#[test]
fn evidence_verify_detects_noncanonical_files() {
    let temp = TempDir::new("evidence");
    write_canonical(&temp.path().join("good.json"), &serde_json::json!({"a": 1}));
    fs::write(temp.path().join("bad.json"), b"{ \"a\": 1 }").unwrap();
    fs::write(temp.path().join("ignored.txt"), b"not json").unwrap();
    assert_eq!(
        run(&[
            "evidence",
            "verify",
            "--root",
            temp.path().to_str().unwrap()
        ]),
        3
    );

    fs::remove_file(temp.path().join("bad.json")).unwrap();
    assert_eq!(
        run(&[
            "evidence",
            "verify",
            "--root",
            temp.path().to_str().unwrap()
        ]),
        0
    );
}

#[test]
fn file_errors_are_usage_errors() {
    assert_eq!(run(&["profile", "validate", "/definitely/not/a/file"]), 2);
    assert_eq!(
        run(&["evidence", "verify", "--root", "/definitely/not/a/dir"]),
        2
    );
}
