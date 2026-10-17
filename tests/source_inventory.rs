//! Integration tests for the conservative source inventory.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use frf_memorysafety::identity::require_canonical;
use frf_memorysafety::source::{
    scan_source, scan_source_default, FindingKind, ScanLimits, SourceError, SourceInventory,
    UnknownKind, SOURCE_INVENTORY_SCHEMA,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "frf-memorysafety-source-{label}-{}-{sequence}",
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

fn write(path: &Path, text: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, text).unwrap();
}

fn has_kind(inventory: &SourceInventory, kind: FindingKind) -> bool {
    inventory
        .findings
        .iter()
        .any(|finding| finding.kind == kind)
}

fn has_target(inventory: &SourceInventory, kind: FindingKind, target: &str) -> bool {
    inventory
        .findings
        .iter()
        .any(|finding| finding.kind == kind && finding.target == target)
}

fn has_unknown(inventory: &SourceInventory, kind: UnknownKind) -> bool {
    inventory
        .unknowns
        .iter()
        .any(|unknown| unknown.kind == kind)
}

#[test]
fn safe_unsafe_ffi_and_interior_mutability_are_recorded() {
    let temp = TempDir::new("basic");
    let source = r#"
use std::cell::UnsafeCell;

union U { a: u8, b: u8 }

struct S { cell: UnsafeCell<u8> }

extern "C" {
    fn puts(s: *const u8) -> i32;
}

#[no_mangle]
pub extern "C" fn exported() {}

unsafe fn danger(p: *const u8) -> u8 {
    unsafe { *p }
}

fn safe() -> u8 { 1 }
"#;
    let path = temp.path().join("basic.rs");
    write(&path, source);
    let inventory = scan_source_default(temp.path()).unwrap();

    for kind in [
        FindingKind::UnsafeBlock,
        FindingKind::UnsafeFn,
        FindingKind::ExternBlock,
        FindingKind::FfiDeclaration,
        FindingKind::NoMangle,
        FindingKind::RawPointerType,
        FindingKind::RawPointerOperation,
        FindingKind::UnionDeclaration,
        FindingKind::UnsafeCellUse,
    ] {
        assert!(has_kind(&inventory, kind), "missing {kind:?}");
    }
    assert!(has_target(&inventory, FindingKind::FfiDeclaration, "puts"));
    assert!(has_target(
        &inventory,
        FindingKind::UnsafeCellUse,
        "UnsafeCell"
    ));
    assert_eq!(inventory.files.len(), 1);
    assert_eq!(inventory.files[0].role.label(), "rust_source");
    assert!(inventory.files[0].parsed);
    assert_eq!(inventory.files[0].sha256.len(), 64);
    assert!(inventory.files[0].findings > 0);

    for finding in &inventory.findings {
        assert!(finding.byte_start <= finding.byte_end);
        assert!(finding.byte_end <= source.len());
        assert_eq!(finding.content_sha256.len(), 64);
        assert!(finding.line_start >= 1);
        assert!(finding.line_end >= finding.line_start);
    }
    assert_eq!(inventory.schema, SOURCE_INVENTORY_SCHEMA);
}

#[test]
fn ffi_calls_callbacks_cfg_and_transmute_are_unresolved_edges() {
    let temp = TempDir::new("edges");
    write(
        &temp.path().join("edges.rs"),
        r#"
extern "C" {
    fn register_cb(cb: extern "C" fn(i32));
    fn trigger();
}

extern "C" fn handler(_: i32) {}

unsafe fn run(p: *mut u8) {
    let _: usize = std::mem::transmute::<*mut u8, usize>(p);
    register_cb(handler);
    trigger();
}

#[cfg(feature = "extra")]
fn extra() {
    let _f = |x: i32| x + 1;
}
"#,
    );
    let inventory = scan_source_default(temp.path()).unwrap();

    assert!(has_target(&inventory, FindingKind::FfiCall, "register_cb"));
    assert!(has_target(&inventory, FindingKind::FfiCall, "trigger"));
    assert!(has_target(
        &inventory,
        FindingKind::CallbackRegistration,
        "register_cb -> handler"
    ));
    assert!(has_kind(&inventory, FindingKind::Closure));
    assert!(has_kind(&inventory, FindingKind::CfgGated));
    assert!(has_target(&inventory, FindingKind::FeatureGate, "extra"));
    assert!(has_kind(&inventory, FindingKind::Transmute));
    assert!(inventory.summary.features.contains(&"extra".to_owned()));
    assert!(inventory.summary.unresolved_call_edges >= 2);
}

#[test]
fn allocation_ownership_and_maybe_uninit_sites_are_recorded() {
    let temp = TempDir::new("alloc");
    write(
        &temp.path().join("alloc.rs"),
        r"
use std::alloc::{alloc, dealloc, Layout};
use std::mem::MaybeUninit;
use std::ptr;

fn f() {
    let layout = Layout::new::<u8>();
    unsafe {
        let p = alloc(layout);
        dealloc(p, layout);
        let mut v: Vec<u8> = Vec::from_raw_parts(p, 1, 1);
        v.set_len(0);
        let mut m = MaybeUninit::<u8>::uninit();
        let _ = ptr::read(m.as_ptr());
        let _ = Box::into_raw(Box::new(1u8));
    }
}
",
    );
    let inventory = scan_source_default(temp.path()).unwrap();

    assert!(has_target(&inventory, FindingKind::Allocation, "alloc"));
    assert!(has_target(&inventory, FindingKind::Deallocation, "dealloc"));
    assert!(has_target(
        &inventory,
        FindingKind::OwnershipCall,
        "from_raw_parts"
    ));
    assert!(has_target(
        &inventory,
        FindingKind::OwnershipCall,
        "set_len"
    ));
    assert!(has_target(
        &inventory,
        FindingKind::OwnershipCall,
        "into_raw"
    ));
    assert!(has_target(
        &inventory,
        FindingKind::MaybeUninitUse,
        "MaybeUninit"
    ));
    assert!(has_target(
        &inventory,
        FindingKind::RawPointerOperation,
        "read"
    ));
    assert!(has_target(
        &inventory,
        FindingKind::RawPointerOperation,
        "as_ptr"
    ));
}

#[test]
fn attributes_and_unsafe_traits_and_impls_are_recorded() {
    let temp = TempDir::new("attrs");
    write(
        &temp.path().join("attrs.rs"),
        r#"
#[link(name = "native")]
extern "C" {
    #[link_name = "real_symbol"]
    fn imported();
}

#[export_name = "aliased"]
fn exported() {}

#[repr(C)]
struct Layout { value: u8 }

#[cfg_attr(feature = "exported", no_mangle)]
fn conditional_export() {}

unsafe trait Marker {}
unsafe impl Marker for u8 {}
"#,
    );
    let inventory = scan_source_default(temp.path()).unwrap();

    assert!(has_target(&inventory, FindingKind::LinkAttribute, "native"));
    assert!(has_target(
        &inventory,
        FindingKind::LinkNameAttribute,
        "real_symbol"
    ));
    assert!(has_target(&inventory, FindingKind::ExportName, "aliased"));
    assert!(has_kind(&inventory, FindingKind::ReprAttribute));
    assert!(has_kind(&inventory, FindingKind::UnsafeTrait));
    assert!(has_kind(&inventory, FindingKind::UnsafeImpl));
    assert!(has_target(
        &inventory,
        FindingKind::NoMangle,
        "conditional_export"
    ));
    assert!(has_target(&inventory, FindingKind::FeatureGate, "exported"));
}

#[test]
fn spans_cover_the_exact_syntax_slice() {
    let temp = TempDir::new("spans");
    let source = "unsafe fn danger(p: *const u8) -> u8 {\n    unsafe { *p }\n}\n";
    write(&temp.path().join("spans.rs"), source);
    let inventory = scan_source_default(temp.path()).unwrap();

    let function = inventory
        .findings
        .iter()
        .find(|finding| finding.kind == FindingKind::UnsafeFn)
        .unwrap();
    assert_eq!(
        &source[function.byte_start..function.byte_end],
        "unsafe fn danger(p: *const u8) -> u8 {\n    unsafe { *p }\n}"
    );
    let block = inventory
        .findings
        .iter()
        .find(|finding| finding.kind == FindingKind::UnsafeBlock)
        .unwrap();
    assert_eq!(&source[block.byte_start..block.byte_end], "unsafe { *p }");
}

#[test]
fn rust_2024_unsafe_attributes_are_recognized() {
    let temp = TempDir::new("unsafe-attr");
    write(
        &temp.path().join("attr.rs"),
        "#[unsafe(no_mangle)]\npub extern \"C\" fn wrapped() {}\n",
    );
    let inventory = scan_source_default(temp.path()).unwrap();
    assert!(has_target(&inventory, FindingKind::NoMangle, "wrapped"));
}

#[cfg(unix)]
#[test]
fn non_utf8_paths_are_explicit_unknowns() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let temp = TempDir::new("nonutf8-path");
    let name = OsString::from_vec(vec![b'f', 0xff, b'.', b'r', b's']);
    fs::write(temp.path().join(&name), "unsafe fn f() {}\n").unwrap();
    let inventory = scan_source_default(temp.path()).unwrap();
    assert!(has_unknown(&inventory, UnknownKind::NonUtf8Path));
    assert!(inventory.files.is_empty());
}

#[test]
fn build_script_and_manifest_feature_evidence_are_recorded() {
    let temp = TempDir::new("manifest");
    write(
        &temp.path().join("Cargo.toml"),
        r#"[package]
name = "fixture"
version = "0.1.0"
build = "build.rs"

[features]
default = []
extra = ["dep"]
"#,
    );
    write(&temp.path().join("build.rs"), "fn main() {}\n");
    write(
        &temp.path().join("src/lib.rs"),
        "pub fn value() -> u8 { 1 }\n",
    );

    let inventory = scan_source_default(temp.path()).unwrap();

    assert!(has_target(
        &inventory,
        FindingKind::BuildScriptDeclared,
        "build.rs"
    ));
    assert!(has_target(&inventory, FindingKind::BuildScript, "build.rs"));
    assert!(has_target(
        &inventory,
        FindingKind::FeatureDeclaration,
        "default"
    ));
    assert!(has_target(
        &inventory,
        FindingKind::FeatureDeclaration,
        "extra"
    ));
    assert_eq!(inventory.summary.build_scripts, 1);
    assert_eq!(inventory.summary.cargo_manifests, 1);
    assert_eq!(inventory.summary.rust_files, 2);
}

#[test]
fn parse_failure_is_an_explicit_unknown_not_a_panic() {
    let temp = TempDir::new("parse");
    write(&temp.path().join("broken.rs"), "fn broken( {");
    let inventory = scan_source_default(temp.path()).unwrap();

    assert!(has_unknown(&inventory, UnknownKind::ParseFailure));
    assert_eq!(inventory.summary.parse_failures, 1);
    assert_eq!(inventory.files.len(), 1);
    assert!(!inventory.files[0].parsed);
    assert_eq!(inventory.summary.findings_by_kind.len(), 0);
}

#[test]
fn invalid_utf8_is_rejected_explicitly() {
    let temp = TempDir::new("utf8");
    fs::write(temp.path().join("bad.rs"), [0xff, 0xfe]).unwrap();
    let error = scan_source_default(temp.path()).unwrap_err();
    assert!(matches!(error, SourceError::InvalidUtf8 { .. }));
}

#[test]
fn file_byte_file_count_total_byte_and_node_limits_are_hard_errors() {
    let temp = TempDir::new("limits");

    write(&temp.path().join("one.rs"), "unsafe fn one() {}\n");
    let error = scan_source(
        temp.path(),
        ScanLimits {
            max_file_bytes: 4,
            ..ScanLimits::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SourceError::LimitExceeded {
            resource: "file_bytes",
            ..
        }
    ));

    let error = scan_source(
        temp.path(),
        ScanLimits {
            max_files: 0,
            ..ScanLimits::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SourceError::LimitExceeded {
            resource: "files",
            ..
        }
    ));

    let error = scan_source(
        temp.path(),
        ScanLimits {
            max_total_bytes: 2,
            ..ScanLimits::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SourceError::LimitExceeded {
            resource: "total_bytes",
            ..
        }
    ));

    let error = scan_source(
        temp.path(),
        ScanLimits {
            max_nodes: 0,
            ..ScanLimits::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SourceError::LimitExceeded {
            resource: "nodes",
            ..
        }
    ));

    let error = scan_source(
        temp.path(),
        ScanLimits {
            max_findings: 0,
            ..ScanLimits::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SourceError::LimitExceeded {
            resource: "findings",
            ..
        }
    ));

    let unknowns = TempDir::new("unknown-limit");
    write(
        &unknowns.path().join("macro.rs"),
        "fn f() { println!(\"x\"); }\n",
    );
    let error = scan_source(
        unknowns.path(),
        ScanLimits {
            max_unknowns: 0,
            ..ScanLimits::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SourceError::LimitExceeded {
            resource: "unknowns",
            ..
        }
    ));
}

#[test]
fn file_count_limit_is_enforced_across_multiple_files() {
    let temp = TempDir::new("filecount");
    write(&temp.path().join("a.rs"), "fn a() {}\n");
    write(&temp.path().join("b.rs"), "fn b() {}\n");
    let error = scan_source(
        temp.path(),
        ScanLimits {
            max_files: 1,
            ..ScanLimits::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SourceError::LimitExceeded {
            resource: "files",
            ..
        }
    ));
}

#[cfg(unix)]
#[test]
fn symlink_escape_is_reported_and_never_followed() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new("symlink");
    let root = temp.path().join("root");
    let outside = temp.path().join("outside");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&outside).unwrap();
    write(&root.join("inside.rs"), "fn inside() {}\n");
    write(&outside.join("outside.rs"), "unsafe fn outside() {}\n");
    symlink(outside.join("outside.rs"), root.join("escape.rs")).unwrap();
    symlink(&outside, root.join("outside-dir")).unwrap();

    let inventory = scan_source_default(&root).unwrap();

    assert!(!inventory
        .findings
        .iter()
        .any(|finding| finding.target == "outside"));
    assert_eq!(inventory.files.len(), 1);
    assert_eq!(inventory.files[0].path, "inside.rs");
    let symlink_unknowns = inventory
        .unknowns
        .iter()
        .filter(|unknown| unknown.kind == UnknownKind::SymlinkNotFollowed)
        .count();
    assert_eq!(symlink_unknowns, 2);
}

#[test]
fn non_rust_files_are_skipped() {
    let temp = TempDir::new("nonrust");
    write(&temp.path().join("notes.txt"), "unsafe { }");
    let inventory = scan_source_default(temp.path()).unwrap();
    assert!(inventory.findings.is_empty());
    assert!(inventory.files.is_empty());
    assert_eq!(inventory.summary.files_skipped_non_rust, 1);
}

#[test]
fn output_is_deterministic_canonical_and_sorted() {
    let temp = TempDir::new("determinism");
    write(
        &temp.path().join("b.rs"),
        "extern \"C\" { fn b(); }\nfn call() { unsafe { b(); } }\n",
    );
    write(
        &temp.path().join("a.rs"),
        "#[no_mangle]\nfn a() { let _ = |x: u8| x; }\n",
    );
    write(&temp.path().join("Cargo.toml"), "[features]\nz = []\n");
    write(&temp.path().join("build.rs"), "fn main() {}\n");

    let first = scan_source_default(temp.path()).unwrap();
    let second = scan_source_default(temp.path()).unwrap();
    let first_bytes = first.canonical_bytes().unwrap();
    let second_bytes = second.canonical_bytes().unwrap();
    assert_eq!(first_bytes, second_bytes);
    require_canonical(&first_bytes).unwrap();

    let decoded: SourceInventory = serde_json::from_slice(&first_bytes).unwrap();
    assert_eq!(decoded, first);
    let paths: Vec<&str> = decoded
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    let mut sorted = paths.clone();
    sorted.sort_unstable();
    assert_eq!(paths, sorted);

    let keys: Vec<(&str, usize, usize, FindingKind, &str)> = decoded
        .findings
        .iter()
        .map(|finding| {
            (
                finding.path.as_str(),
                finding.byte_start,
                finding.byte_end,
                finding.kind,
                finding.target.as_str(),
            )
        })
        .collect();
    let mut sorted_keys = keys.clone();
    sorted_keys.sort_unstable();
    assert_eq!(keys, sorted_keys);
}

#[test]
fn cli_source_scan_returns_spec_exit_statuses() {
    let temp = TempDir::new("cli");
    let good = temp.path().join("good");
    fs::create_dir_all(&good).unwrap();
    write(&good.join("good.rs"), "unsafe fn f() {}\n");

    assert_eq!(
        frf_memorysafety::cli::run(["source".to_owned(), "scan".to_owned(), path_string(&good)]),
        0
    );
    assert_eq!(
        frf_memorysafety::cli::run([
            "source".to_owned(),
            "scan".to_owned(),
            path_string(&good),
            "--json".to_owned()
        ]),
        0
    );
    assert_eq!(frf_memorysafety::cli::run(["source".to_owned()]), 2);
    assert_eq!(
        frf_memorysafety::cli::run(["source".to_owned(), "scan".to_owned()]),
        2
    );
    assert_eq!(
        frf_memorysafety::cli::run([
            "source".to_owned(),
            "scan".to_owned(),
            path_string(&good),
            "--unknown".to_owned()
        ]),
        2
    );
    assert_eq!(
        frf_memorysafety::cli::run([
            "source".to_owned(),
            "scan".to_owned(),
            "/definitely/not/a/source/path".to_owned()
        ]),
        2
    );

    let broken = temp.path().join("broken");
    fs::create_dir_all(&broken).unwrap();
    write(&broken.join("bad.rs"), "fn broken( {");
    assert_eq!(
        frf_memorysafety::cli::run(["source".to_owned(), "scan".to_owned(), path_string(&broken)]),
        0
    );

    let invalid = temp.path().join("invalid");
    fs::create_dir_all(&invalid).unwrap();
    fs::write(invalid.join("bad.rs"), [0xff]).unwrap();
    assert_eq!(
        frf_memorysafety::cli::run([
            "source".to_owned(),
            "scan".to_owned(),
            path_string(&invalid)
        ]),
        3
    );

    assert_eq!(
        frf_memorysafety::cli::run([
            "source".to_owned(),
            "scan".to_owned(),
            path_string(&temp.path().join("Cargo.toml"))
        ]),
        2
    );
    let not_rust = temp.path().join("notes.txt");
    write(&not_rust, "not rust");
    assert_eq!(
        frf_memorysafety::cli::run([
            "source".to_owned(),
            "scan".to_owned(),
            path_string(&not_rust)
        ]),
        2
    );
}

#[test]
fn cli_version_and_capabilities_advertise_the_inventory_honestly() {
    assert_eq!(
        frf_memorysafety::cli::run(["version".to_owned(), "--json".to_owned()]),
        0
    );
    assert_eq!(
        frf_memorysafety::cli::run(["capabilities".to_owned(), "--json".to_owned()]),
        0
    );
    let capabilities = frf_memorysafety::capabilities();
    assert!(capabilities
        .implemented
        .iter()
        .any(|item| item.contains("source inventory")));
    assert!(capabilities.not_run.iter().any(|item| item.contains("MIR")));
    assert!(capabilities
        .not_run
        .iter()
        .any(|item| item.contains("alias")));
}

fn path_string(path: &Path) -> String {
    path.to_str().unwrap().to_owned()
}

// Keep the role label used by assertions tied to the public serialization.
trait RoleLabel {
    fn label(self) -> &'static str;
}

impl RoleLabel for frf_memorysafety::source::SourceFileRole {
    fn label(self) -> &'static str {
        match self {
            Self::RustSource => "rust_source",
            Self::BuildScript => "build_script",
            Self::CargoManifest => "cargo_manifest",
        }
    }
}
