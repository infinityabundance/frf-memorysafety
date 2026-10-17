//! Lockfile presence and metadata checks.
//!
//! The authoritative `--locked` check is the `cargo test --locked` invocation
//! documented in README.md. This test makes a missing or stale lockfile fail
//! loudly in the ordinary test run as well.

use std::fs;
use std::path::PathBuf;

#[test]
fn cargo_lock_exists_and_names_this_package() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cargo_toml = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    assert!(cargo_toml.contains("name = \"frf-memorysafety\""));
    assert!(cargo_toml.contains("version = \"0.2.0\""));

    let lock_path = root.join("Cargo.lock");
    assert!(
        lock_path.is_file(),
        "Cargo.lock is required for cargo test --locked"
    );
    let lock = fs::read_to_string(lock_path).unwrap();
    assert!(lock.contains("name = \"frf-memorysafety\""));
    assert!(lock.contains("version = \"0.2.0\""));
    assert!(lock.contains("name = \"serde\""));
    assert!(lock.contains("name = \"sha2\""));
    assert!(lock.contains("name = \"thiserror\""));
}

#[test]
fn toolchain_is_pinned() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let toolchain = fs::read_to_string(root.join("rust-toolchain.toml")).unwrap();
    assert!(toolchain.contains("channel = \"1.85.0\""));
    let cargo = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    assert!(cargo.contains("rust-version = \"1.85\""));
    assert!(cargo.contains("edition = \"2021\""));
}
