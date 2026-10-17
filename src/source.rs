//! Conservative, syntax-only Rust source inventory.
//!
//! This module parses Rust files with `syn` 2.x and records syntactic
//! constructs that are relevant to a later unsafe-effect study. It is
//! deliberately **not** a caller graph, an alias analysis, a type checker, or a
//! whole-program analysis. Every call edge is an unresolved syntactic
//! observation. Macro expansions, external module bodies, and foreign dynamic
//! dispatch remain explicit unknowns.
//!
//! # Claim ceiling
//!
//! A successful scan establishes only that the named files were read, decoded,
//! parsed within the declared limits, and that the listed syntax was observed.
//! It does not establish:
//!
//! * that all unsafe operations or call edges were found;
//! * that a function call resolves to any particular definition;
//! * that references alias, or that they do not alias;
//! * that foreign code obeys a callback contract;
//! * any native memory-safety property.
//!
//! In particular, a parsed inventory is a *declaration-like* source view, not
//! the observed edge set used by `SPEC.md` §8. An observed omission can falsify
//! an inventory; a syntactic inventory cannot establish conservative closure,
//! and absence of a finding is never evidence of absence.
//!
//! # Limits
//!
//! Scans are bounded by [`ScanLimits`]. Exceeding a limit is an error, never a
//! warning or a silent truncation. Findings are ordered deterministically by
//! path, byte span, kind, and target, so equal inputs produce equal canonical
//! bytes.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use proc_macro2::{LineColumn, Span, TokenStream, TokenTree};
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, ForeignItem, Item, Lit, Meta, Pat, Token, Type};

/// Schema identifier for a source inventory.
pub const SOURCE_INVENTORY_SCHEMA: &str = "frf-memorysafety.source-inventory.v1";
/// Protocol specification identifier this inventory reports under.
pub const SOURCE_INVENTORY_SPEC: &str = "frf-memorysafety-spec-v1";
/// Text embedded in every inventory to state the claim ceiling.
pub const SOURCE_INVENTORY_CLAIM_CEILING: &str = "Syntactic inventory only. Not a caller graph, alias analysis, whole-program inventory, or memory-safety result. Unresolved calls, macro-generated code, foreign dispatch, and external module bodies remain unknown; absence of a finding is not evidence of absence.";

/// Default maximum bytes in one scanned file.
pub const DEFAULT_MAX_FILE_BYTES: usize = 1_048_576;
/// Default maximum number of scanned Rust/manifest files.
pub const DEFAULT_MAX_FILES: usize = 2_048;
/// Default maximum aggregate bytes across scanned files.
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 33_554_432;
/// Default maximum syntax nodes visited across the scan.
pub const DEFAULT_MAX_NODES: usize = 262_144;
/// Default maximum retained findings.
pub const DEFAULT_MAX_FINDINGS: usize = 4_096;
/// Default maximum retained explicit unknowns.
pub const DEFAULT_MAX_UNKNOWNS: usize = 4_096;

/// Hard resource limits for one source scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanLimits {
    /// Maximum bytes in one file.
    pub max_file_bytes: usize,
    /// Maximum number of scanned files (Rust sources and `Cargo.toml`).
    pub max_files: usize,
    /// Maximum aggregate bytes of scanned files.
    pub max_total_bytes: usize,
    /// Maximum syntax nodes visited.
    pub max_nodes: usize,
    /// Maximum retained findings.
    pub max_findings: usize,
    /// Maximum retained explicit unknowns.
    pub max_unknowns: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_files: DEFAULT_MAX_FILES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_nodes: DEFAULT_MAX_NODES,
            max_findings: DEFAULT_MAX_FINDINGS,
            max_unknowns: DEFAULT_MAX_UNKNOWNS,
        }
    }
}

/// Category used by the CLI to choose a `SPEC.md` §14 exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceErrorCategory {
    /// Invalid input or usage.
    Usage,
    /// Evidence/input integrity failure, including a limit violation.
    Integrity,
    /// Internal encoding or harness failure.
    Harness,
}

/// Errors produced while scanning source or encoding the inventory.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    /// A filesystem operation failed.
    #[error("cannot access {path}: {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// The root is neither a regular file nor a directory.
    #[error("root is not a regular file or directory: {path}")]
    UnsupportedRoot {
        /// Rejected path.
        path: PathBuf,
    },
    /// A single-file scan was asked to read a non-Rust file.
    #[error("not a Rust source file (.rs): {path}")]
    NotRustSource {
        /// Rejected path.
        path: PathBuf,
    },
    /// A scanned file is not valid UTF-8.
    #[error("invalid UTF-8 in {path} at byte {valid_up_to}")]
    InvalidUtf8 {
        /// File containing invalid UTF-8.
        path: PathBuf,
        /// Byte offset of the first invalid sequence.
        valid_up_to: usize,
    },
    /// A declared resource limit was exceeded.
    #[error("source scan limit exceeded: {resource} (limit {limit})")]
    LimitExceeded {
        /// Resource name.
        resource: &'static str,
        /// Configured limit.
        limit: usize,
    },
    /// The canonical encoder rejected the inventory.
    #[error("cannot encode source inventory: {message}")]
    Canonical {
        /// Encoder diagnostic.
        message: String,
    },
}

impl SourceError {
    /// Category used for exit-status selection.
    #[must_use]
    pub fn category(&self) -> SourceErrorCategory {
        match self {
            Self::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
                SourceErrorCategory::Usage
            }
            Self::Io { .. } | Self::InvalidUtf8 { .. } | Self::LimitExceeded { .. } => {
                SourceErrorCategory::Integrity
            }
            Self::UnsupportedRoot { .. } | Self::NotRustSource { .. } => SourceErrorCategory::Usage,
            Self::Canonical { .. } => SourceErrorCategory::Harness,
        }
    }
}

/// Role of a scanned file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFileRole {
    /// An ordinary Rust source file.
    RustSource,
    /// A `build.rs` build script.
    BuildScript,
    /// A `Cargo.toml` manifest used only for build/feature evidence.
    CargoManifest,
}

/// One scanned file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFileRecord {
    /// Path relative to the scan root, or the file name for a single-file scan.
    pub path: String,
    /// File role.
    pub role: SourceFileRole,
    /// Byte length.
    pub bytes: usize,
    /// SHA-256 of the exact file bytes, lowercase hexadecimal.
    pub sha256: String,
    /// Whether the file was parsed successfully (manifests are line-scanned).
    pub parsed: bool,
    /// Findings attributed to this file.
    pub findings: usize,
    /// Explicit unknowns attributed to this file.
    pub unknowns: usize,
}

/// Kinds of syntactic finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// An `unsafe { ... }` block.
    UnsafeBlock,
    /// A function declared with the `unsafe` qualifier.
    UnsafeFn,
    /// An `unsafe impl` block.
    UnsafeImpl,
    /// A trait declared with the `unsafe` qualifier.
    UnsafeTrait,
    /// An `extern` block.
    ExternBlock,
    /// A function or static declaration inside an `extern` block.
    FfiDeclaration,
    /// A call whose callee name matches a declaration in the same file.
    FfiCall,
    /// An exported function with `extern` ABI but no extern-block declaration.
    ExternFn,
    /// `#[no_mangle]` or `#[unsafe(no_mangle)]`.
    NoMangle,
    /// `#[export_name = ...]`.
    ExportName,
    /// `#[link(...)]`.
    LinkAttribute,
    /// `#[link_name = ...]`.
    LinkNameAttribute,
    /// `#[repr(...)]`.
    ReprAttribute,
    /// A raw-pointer type such as `*const T` or `*mut T`.
    RawPointerType,
    /// A syntactic operation that may involve a raw pointer.
    RawPointerOperation,
    /// A call to `transmute` or `transmute_copy`.
    Transmute,
    /// A union declaration.
    UnionDeclaration,
    /// A use of `MaybeUninit`.
    MaybeUninitUse,
    /// A use of `UnsafeCell`.
    UnsafeCellUse,
    /// A use of `NonNull`.
    NonNullUse,
    /// An allocation call.
    Allocation,
    /// A deallocation call.
    Deallocation,
    /// An ownership-relevant call such as `into_raw`, `from_raw`, or `forget`.
    OwnershipCall,
    /// A syntactic function call.
    FunctionCall,
    /// A syntactic method call.
    MethodCall,
    /// A closure expression.
    Closure,
    /// A syntactic callback registration candidate.
    CallbackRegistration,
    /// An item or expression guarded by `cfg` or `cfg_attr`.
    CfgGated,
    /// A feature named in a `cfg` predicate.
    FeatureGate,
    /// A feature declared in `Cargo.toml`.
    FeatureDeclaration,
    /// A `build.rs` file found in the scan.
    BuildScript,
    /// A `build = ...` declaration in `Cargo.toml`.
    BuildScriptDeclared,
    /// A `Cargo.toml` file itself.
    CargoManifest,
}

impl FindingKind {
    /// Stable snake-case label used in summaries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsafeBlock => "unsafe_block",
            Self::UnsafeFn => "unsafe_fn",
            Self::UnsafeImpl => "unsafe_impl",
            Self::UnsafeTrait => "unsafe_trait",
            Self::ExternBlock => "extern_block",
            Self::FfiDeclaration => "ffi_declaration",
            Self::FfiCall => "ffi_call",
            Self::ExternFn => "extern_fn",
            Self::NoMangle => "no_mangle",
            Self::ExportName => "export_name",
            Self::LinkAttribute => "link_attribute",
            Self::LinkNameAttribute => "link_name_attribute",
            Self::ReprAttribute => "repr_attribute",
            Self::RawPointerType => "raw_pointer_type",
            Self::RawPointerOperation => "raw_pointer_operation",
            Self::Transmute => "transmute",
            Self::UnionDeclaration => "union_declaration",
            Self::MaybeUninitUse => "maybe_uninit_use",
            Self::UnsafeCellUse => "unsafe_cell_use",
            Self::NonNullUse => "non_null_use",
            Self::Allocation => "allocation",
            Self::Deallocation => "deallocation",
            Self::OwnershipCall => "ownership_call",
            Self::FunctionCall => "function_call",
            Self::MethodCall => "method_call",
            Self::Closure => "closure",
            Self::CallbackRegistration => "callback_registration",
            Self::CfgGated => "cfg_gated",
            Self::FeatureGate => "feature_gate",
            Self::FeatureDeclaration => "feature_declaration",
            Self::BuildScript => "build_script",
            Self::BuildScriptDeclared => "build_script_declared",
            Self::CargoManifest => "cargo_manifest",
        }
    }
}

/// One retained syntactic finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFinding {
    /// Finding kind.
    pub kind: FindingKind,
    /// File path relative to the scan root.
    pub path: String,
    /// Inclusive byte offset of the first token.
    pub byte_start: usize,
    /// Exclusive byte offset after the last token.
    pub byte_end: usize,
    /// One-based starting line.
    pub line_start: usize,
    /// Zero-based starting Unicode-scalar column.
    pub column_start: usize,
    /// One-based ending line.
    pub line_end: usize,
    /// Zero-based ending Unicode-scalar column.
    pub column_end: usize,
    /// Construct label (callee, item name, symbol, and so on).
    pub target: String,
    /// Optional context. Never a proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// SHA-256 of the exact source slice covered by the byte span.
    pub content_sha256: String,
}

impl Ord for SourceFinding {
    fn cmp(&self, other: &Self) -> Ordering {
        self.path
            .cmp(&other.path)
            .then(self.byte_start.cmp(&other.byte_start))
            .then(self.byte_end.cmp(&other.byte_end))
            .then(self.kind.cmp(&other.kind))
            .then(self.target.cmp(&other.target))
            .then(self.line_start.cmp(&other.line_start))
            .then(self.column_start.cmp(&other.column_start))
            .then(self.line_end.cmp(&other.line_end))
            .then(self.column_end.cmp(&other.column_end))
            .then(self.detail.cmp(&other.detail))
            .then(self.content_sha256.cmp(&other.content_sha256))
    }
}

impl PartialOrd for SourceFinding {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Kinds of explicit unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownKind {
    /// `syn` could not parse the file.
    ParseFailure,
    /// A macro invocation was not expanded.
    MacroInvocationNotExpanded,
    /// An include-like macro was not expanded.
    IncludeNotExpanded,
    /// A `mod name;` body lives outside this file.
    ExternalModuleDeclaration,
    /// A `syn` verbatim item was preserved without structural understanding.
    VerbatimItem,
    /// A `syn` verbatim expression was preserved without structural understanding.
    VerbatimExpr,
    /// A `syn` verbatim type was preserved without structural understanding.
    VerbatimType,
    /// A `syn` verbatim pattern was preserved without structural understanding.
    VerbatimPattern,
    /// A symlink was not followed. This includes links escaping the scan root.
    SymlinkNotFollowed,
    /// A path was not valid UTF-8 and was skipped.
    NonUtf8Path,
}

impl UnknownKind {
    /// Stable snake-case label used in summaries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ParseFailure => "parse_failure",
            Self::MacroInvocationNotExpanded => "macro_invocation_not_expanded",
            Self::IncludeNotExpanded => "include_not_expanded",
            Self::ExternalModuleDeclaration => "external_module_declaration",
            Self::VerbatimItem => "verbatim_item",
            Self::VerbatimExpr => "verbatim_expr",
            Self::VerbatimType => "verbatim_type",
            Self::VerbatimPattern => "verbatim_pattern",
            Self::SymlinkNotFollowed => "symlink_not_followed",
            Self::NonUtf8Path => "non_utf8_path",
        }
    }
}

/// One explicit unknown retained in the inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceUnknown {
    /// Unknown kind.
    pub kind: UnknownKind,
    /// File path relative to the scan root.
    pub path: String,
    /// Inclusive byte offset.
    pub byte_start: usize,
    /// Exclusive byte offset.
    pub byte_end: usize,
    /// One-based starting line.
    pub line_start: usize,
    /// Zero-based starting column.
    pub column_start: usize,
    /// One-based ending line.
    pub line_end: usize,
    /// Zero-based ending column.
    pub column_end: usize,
    /// Diagnostic or context.
    pub detail: String,
    /// SHA-256 of the covered source slice.
    pub content_sha256: String,
}

impl Ord for SourceUnknown {
    fn cmp(&self, other: &Self) -> Ordering {
        self.path
            .cmp(&other.path)
            .then(self.byte_start.cmp(&other.byte_start))
            .then(self.byte_end.cmp(&other.byte_end))
            .then(self.kind.cmp(&other.kind))
            .then(self.detail.cmp(&other.detail))
            .then(self.line_start.cmp(&other.line_start))
            .then(self.column_start.cmp(&other.column_start))
            .then(self.line_end.cmp(&other.line_end))
            .then(self.column_end.cmp(&other.column_end))
            .then(self.content_sha256.cmp(&other.content_sha256))
    }
}

impl PartialOrd for SourceUnknown {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Aggregate inventory summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSummary {
    /// Files scanned, including manifests.
    pub files_scanned: usize,
    /// Rust files scanned, including build scripts.
    pub rust_files: usize,
    /// Aggregate bytes scanned.
    pub total_bytes: usize,
    /// Non-Rust regular files skipped during directory traversal.
    pub files_skipped_non_rust: usize,
    /// Syntax nodes visited across all parsed files.
    pub nodes_visited: usize,
    /// Count per finding kind.
    pub findings_by_kind: BTreeMap<String, usize>,
    /// Explicit unknown count.
    pub unknown_count: usize,
    /// Count per unknown kind.
    pub unknowns_by_kind: BTreeMap<String, usize>,
    /// Unresolved syntactic call edges: function calls, method calls, callbacks.
    pub unresolved_call_edges: usize,
    /// Files that failed to parse.
    pub parse_failures: usize,
    /// Macro invocations or definitions not expanded.
    pub macros_not_expanded: usize,
    /// Build scripts found.
    pub build_scripts: usize,
    /// Cargo manifests scanned.
    pub cargo_manifests: usize,
    /// Feature names seen in `cfg` predicates or manifests.
    pub features: Vec<String>,
}

/// A deterministic, syntax-only source inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInventory {
    /// Inventory schema.
    pub schema: String,
    /// Specification identifier.
    pub spec: String,
    /// Canonical scan root.
    pub root: String,
    /// Claim ceiling embedded in the artifact.
    pub claim_ceiling: String,
    /// Limits applied to this scan.
    pub limits: ScanLimits,
    /// Scanned files, sorted by path.
    pub files: Vec<SourceFileRecord>,
    /// Findings, sorted by path, byte span, kind, and target.
    pub findings: Vec<SourceFinding>,
    /// Explicit unknowns, sorted by path, byte span, kind, and detail.
    pub unknowns: Vec<SourceUnknown>,
    /// Aggregate counts.
    pub summary: SourceSummary,
}

impl SourceInventory {
    /// Encode this inventory as strict `ms-canonical-json-v1` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SourceError::Canonical`] if the inventory cannot be represented
    /// as a JSON value or exceeds the canonical encoding limits.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SourceError> {
        let value = serde_json::to_value(self).map_err(|error| SourceError::Canonical {
            message: error.to_string(),
        })?;
        match crate::identity::canonical_bytes(&value) {
            Ok(bytes) => Ok(bytes),
            Err(crate::identity::IdentityError::TooLarge { limit, .. }) => {
                Err(SourceError::LimitExceeded {
                    resource: "canonical_bytes",
                    limit,
                })
            }
            Err(error) => Err(SourceError::Canonical {
                message: error.to_string(),
            }),
        }
    }
}

/// Scan a directory or single Rust file with default limits.
///
/// # Errors
///
/// Returns [`SourceError`] on I/O failure, invalid UTF-8, or a limit violation.
pub fn scan_source_default(path: impl AsRef<Path>) -> Result<SourceInventory, SourceError> {
    scan_source(path, ScanLimits::default())
}

/// Scan a directory or single Rust file.
///
/// Directory traversal sorts entries and does not follow any symlink. A
/// symlinked entry is retained as an explicit [`UnknownKind::SymlinkNotFollowed`]
/// unknown, so a link cannot escape the scanned root. Non-Rust files are
/// skipped; `Cargo.toml` and `build.rs` are retained as build/feature evidence.
///
/// # Errors
///
/// Returns [`SourceError`] on I/O failure, invalid UTF-8, or a limit violation.
pub fn scan_source(
    path: impl AsRef<Path>,
    limits: ScanLimits,
) -> Result<SourceInventory, SourceError> {
    let requested = path.as_ref();
    let root = std::fs::canonicalize(requested).map_err(|source| SourceError::Io {
        path: requested.to_path_buf(),
        source,
    })?;
    let root_string = root
        .to_str()
        .ok_or_else(|| SourceError::UnsupportedRoot { path: root.clone() })?
        .to_owned();
    let metadata = std::fs::metadata(&root).map_err(|source| SourceError::Io {
        path: root.clone(),
        source,
    })?;

    let mut accumulator = Accumulator::new(limits);
    if metadata.is_file() {
        if !is_rust_source(&root) {
            return Err(SourceError::NotRustSource { path: root });
        }
        let display = root
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| SourceError::UnsupportedRoot { path: root.clone() })?
            .to_owned();
        scan_file(&root, &display, &mut accumulator)?;
    } else if metadata.is_dir() {
        walk_directory(&root, "", &mut accumulator)?;
    } else {
        return Err(SourceError::UnsupportedRoot { path: root });
    }

    if let Some(resource) = accumulator.limit_hit {
        return Err(SourceError::LimitExceeded {
            resource,
            limit: accumulator.limit_for(resource),
        });
    }
    Ok(accumulator.finish(root_string))
}

fn is_rust_source(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension == "rs")
}

fn is_manifest(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "Cargo.toml")
}

fn is_build_script(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "build.rs")
}

fn scan_candidate(path: &Path) -> bool {
    is_rust_source(path) || is_manifest(path)
}

fn walk_directory(
    directory: &Path,
    relative: &str,
    accumulator: &mut Accumulator,
) -> Result<(), SourceError> {
    if accumulator.limit_hit.is_some() {
        return Ok(());
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(directory)
        .map_err(|source| SourceError::Io {
            path: directory.to_path_buf(),
            source,
        })?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|source| SourceError::Io {
                    path: directory.to_path_buf(),
                    source,
                })
        })
        .collect::<Result<_, _>>()?;
    entries.sort_by(|left, right| {
        left.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .cmp(
                &right
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned()),
            )
    });

    for entry in entries {
        if accumulator.limit_hit.is_some() {
            return Ok(());
        }
        let name = entry
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let child_relative = if relative.is_empty() {
            name.clone()
        } else {
            format!("{relative}/{name}")
        };
        if entry
            .file_name()
            .is_some_and(|name| name.to_str().is_none())
        {
            accumulator.record_unknown(SourceUnknown {
                kind: UnknownKind::NonUtf8Path,
                path: child_relative,
                byte_start: 0,
                byte_end: 0,
                line_start: 1,
                column_start: 0,
                line_end: 1,
                column_end: 0,
                detail: "path is not valid UTF-8; entry skipped".to_owned(),
                content_sha256: sha256_hex(&[]),
            });
            continue;
        }
        let metadata = std::fs::symlink_metadata(&entry).map_err(|source| SourceError::Io {
            path: entry.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            let target = std::fs::canonicalize(&entry).map_or_else(
                |_| "<unresolved>".to_owned(),
                |target| target.display().to_string(),
            );
            accumulator.record_unknown(SourceUnknown {
                kind: UnknownKind::SymlinkNotFollowed,
                path: child_relative,
                byte_start: 0,
                byte_end: 0,
                line_start: 1,
                column_start: 0,
                line_end: 1,
                column_end: 0,
                detail: format!("symlink not followed; target {target}"),
                content_sha256: sha256_hex(&[]),
            });
            continue;
        }
        if metadata.is_dir() {
            walk_directory(&entry, &child_relative, accumulator)?;
        } else if metadata.is_file() {
            if scan_candidate(&entry) {
                scan_file(&entry, &child_relative, accumulator)?;
            } else {
                accumulator.files_skipped_non_rust += 1;
            }
        }
    }
    Ok(())
}

fn scan_file(path: &Path, display: &str, accumulator: &mut Accumulator) -> Result<(), SourceError> {
    let metadata = std::fs::metadata(path).map_err(|source| SourceError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let declared_len = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    accumulator.check_file_limits(declared_len)?;
    let bytes = std::fs::read(path).map_err(|source| SourceError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    accumulator.check_file_limits(bytes.len())?;
    let text = std::str::from_utf8(&bytes).map_err(|error| SourceError::InvalidUtf8 {
        path: path.to_path_buf(),
        valid_up_to: error.valid_up_to(),
    })?;
    let digest = sha256_hex(&bytes);
    let role = if is_build_script(path) {
        SourceFileRole::BuildScript
    } else if is_manifest(path) {
        SourceFileRole::CargoManifest
    } else {
        SourceFileRole::RustSource
    };

    accumulator.total_bytes = accumulator.total_bytes.saturating_add(bytes.len());
    let findings_before = accumulator.findings.len();
    let unknowns_before = accumulator.unknowns.len();
    let parsed = if role == SourceFileRole::CargoManifest {
        scan_manifest(display, text, accumulator);
        true
    } else {
        scan_rust(
            display,
            text,
            role == SourceFileRole::BuildScript,
            accumulator,
        )
    };
    accumulator.files.push(SourceFileRecord {
        path: display.to_owned(),
        role,
        bytes: bytes.len(),
        sha256: digest,
        parsed,
        findings: accumulator.findings.len().saturating_sub(findings_before),
        unknowns: accumulator.unknowns.len().saturating_sub(unknowns_before),
    });
    Ok(())
}

fn scan_rust(
    display: &str,
    text: &str,
    is_build_script: bool,
    accumulator: &mut Accumulator,
) -> bool {
    let index = LineIndex::new(text);
    if is_build_script {
        accumulator.record_finding(make_finding(
            text,
            &index,
            display,
            FindingKind::BuildScript,
            0,
            text.len(),
            display.to_owned(),
            Some("build script is parsed as Rust source".to_owned()),
        ));
    }
    let file = match syn::parse_file(text) {
        Ok(file) => file,
        Err(error) => {
            let (byte_start, byte_end, line_start, column_start, line_end, column_end) = index
                .span_bytes(error.span(), error.span())
                .unwrap_or((0, 0, 1, 0, 1, 0));
            accumulator.record_unknown(SourceUnknown {
                kind: UnknownKind::ParseFailure,
                path: display.to_owned(),
                byte_start,
                byte_end,
                line_start,
                column_start,
                line_end,
                column_end,
                detail: error.to_string(),
                content_sha256: sha256_hex(slice(text, byte_start, byte_end)),
            });
            return false;
        }
    };
    let mut foreign_names = BTreeSet::new();
    let mut collector = ForeignCollector {
        names: &mut foreign_names,
    };
    collector.visit_file(&file);
    let mut visitor = InventoryVisitor {
        path: display.to_owned(),
        source: text,
        index: &index,
        accumulator,
        scope: Vec::new(),
        foreign_names,
    };
    visitor.visit_file(&file);
    true
}

fn scan_manifest(display: &str, text: &str, accumulator: &mut Accumulator) {
    let index = LineIndex::new(text);
    accumulator.record_finding(make_finding(
        text,
        &index,
        display,
        FindingKind::CargoManifest,
        0,
        text.len(),
        display.to_owned(),
        Some("manifest used only for build and feature evidence".to_owned()),
    ));
    let mut section = String::new();
    let mut line_start = 0usize;
    for line in text.split_inclusive('\n') {
        let this_line_start = line_start;
        line_start = line_start.saturating_add(line.len());
        let without_newline = line.trim_end_matches(['\n', '\r']);
        let trimmed = without_newline.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            trimmed[1..trimmed.len() - 1]
                .trim()
                .clone_into(&mut section);
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || key.starts_with('#') {
            continue;
        }
        if section == "features" {
            accumulator.features.insert(key.to_owned());
            accumulator.record_finding(make_finding(
                text,
                &index,
                display,
                FindingKind::FeatureDeclaration,
                this_line_start,
                this_line_start + without_newline.len(),
                key.to_owned(),
                Some("feature key declared in Cargo.toml [features]".to_owned()),
            ));
        } else if section == "package" && key == "build" {
            let declared = value.trim_matches('"').trim_matches('\'').to_owned();
            accumulator.record_finding(make_finding(
                text,
                &index,
                display,
                FindingKind::BuildScriptDeclared,
                this_line_start,
                this_line_start + without_newline.len(),
                declared.clone(),
                Some("package build script declaration in Cargo.toml".to_owned()),
            ));
        }
    }
}

struct ForeignCollector<'a> {
    names: &'a mut BTreeSet<String>,
}

impl<'ast> Visit<'ast> for ForeignCollector<'_> {
    fn visit_foreign_item_fn(&mut self, node: &'ast syn::ForeignItemFn) {
        self.names.insert(node.sig.ident.to_string());
        visit::visit_foreign_item_fn(self, node);
    }
}

struct Accumulator {
    limits: ScanLimits,
    files: Vec<SourceFileRecord>,
    findings: BTreeSet<SourceFinding>,
    unknowns: BTreeSet<SourceUnknown>,
    features: BTreeSet<String>,
    nodes: usize,
    total_bytes: usize,
    files_skipped_non_rust: usize,
    limit_hit: Option<&'static str>,
}

impl Accumulator {
    fn new(limits: ScanLimits) -> Self {
        Self {
            limits,
            files: Vec::new(),
            findings: BTreeSet::new(),
            unknowns: BTreeSet::new(),
            features: BTreeSet::new(),
            nodes: 0,
            total_bytes: 0,
            files_skipped_non_rust: 0,
            limit_hit: None,
        }
    }

    fn limit_for(&self, resource: &str) -> usize {
        match resource {
            "file_bytes" => self.limits.max_file_bytes,
            "files" => self.limits.max_files,
            "total_bytes" => self.limits.max_total_bytes,
            "nodes" => self.limits.max_nodes,
            "findings" => self.limits.max_findings,
            "unknowns" => self.limits.max_unknowns,
            _ => 0,
        }
    }

    fn check_file_limits(&mut self, length: usize) -> Result<(), SourceError> {
        if length > self.limits.max_file_bytes {
            return Err(SourceError::LimitExceeded {
                resource: "file_bytes",
                limit: self.limits.max_file_bytes,
            });
        }
        if self.files.len() >= self.limits.max_files {
            return Err(SourceError::LimitExceeded {
                resource: "files",
                limit: self.limits.max_files,
            });
        }
        if self.total_bytes.saturating_add(length) > self.limits.max_total_bytes {
            return Err(SourceError::LimitExceeded {
                resource: "total_bytes",
                limit: self.limits.max_total_bytes,
            });
        }
        Ok(())
    }

    fn bump_node(&mut self) -> bool {
        if self.limit_hit.is_some() {
            return true;
        }
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > self.limits.max_nodes {
            self.limit_hit = Some("nodes");
            return true;
        }
        false
    }

    fn record_finding(&mut self, finding: SourceFinding) {
        if self.limit_hit.is_some() {
            return;
        }
        if !self.findings.contains(&finding) {
            if self.findings.len() >= self.limits.max_findings {
                self.limit_hit = Some("findings");
                return;
            }
            self.findings.insert(finding);
        }
    }

    fn record_unknown(&mut self, unknown: SourceUnknown) {
        if self.limit_hit.is_some() {
            return;
        }
        if !self.unknowns.contains(&unknown) {
            if self.unknowns.len() >= self.limits.max_unknowns {
                self.limit_hit = Some("unknowns");
                return;
            }
            self.unknowns.insert(unknown);
        }
    }

    fn finish(mut self, root: String) -> SourceInventory {
        self.files.sort_by(|left, right| left.path.cmp(&right.path));
        let findings: Vec<SourceFinding> = self.findings.into_iter().collect();
        let unknowns: Vec<SourceUnknown> = self.unknowns.into_iter().collect();
        let mut findings_by_kind: BTreeMap<String, usize> = BTreeMap::new();
        for finding in &findings {
            *findings_by_kind
                .entry(finding.kind.as_str().to_owned())
                .or_insert(0) += 1;
        }
        let mut unknowns_by_kind: BTreeMap<String, usize> = BTreeMap::new();
        for unknown in &unknowns {
            *unknowns_by_kind
                .entry(unknown.kind.as_str().to_owned())
                .or_insert(0) += 1;
        }
        let unresolved_call_edges = findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.kind,
                    FindingKind::FunctionCall
                        | FindingKind::MethodCall
                        | FindingKind::CallbackRegistration
                )
            })
            .count();
        let parse_failures = unknowns
            .iter()
            .filter(|unknown| unknown.kind == UnknownKind::ParseFailure)
            .count();
        let macros_not_expanded = unknowns
            .iter()
            .filter(|unknown| {
                matches!(
                    unknown.kind,
                    UnknownKind::MacroInvocationNotExpanded | UnknownKind::IncludeNotExpanded
                )
            })
            .count();
        let rust_files = self
            .files
            .iter()
            .filter(|file| file.role != SourceFileRole::CargoManifest)
            .count();
        let build_scripts = self
            .files
            .iter()
            .filter(|file| file.role == SourceFileRole::BuildScript)
            .count();
        let cargo_manifests = self
            .files
            .iter()
            .filter(|file| file.role == SourceFileRole::CargoManifest)
            .count();
        let files_scanned = self.files.len();
        let unknown_count = unknowns.len();
        SourceInventory {
            schema: SOURCE_INVENTORY_SCHEMA.to_owned(),
            spec: SOURCE_INVENTORY_SPEC.to_owned(),
            root,
            claim_ceiling: SOURCE_INVENTORY_CLAIM_CEILING.to_owned(),
            limits: self.limits,
            files: self.files,
            findings,
            unknowns,
            summary: SourceSummary {
                files_scanned,
                rust_files,
                total_bytes: self.total_bytes,
                files_skipped_non_rust: self.files_skipped_non_rust,
                nodes_visited: self.nodes,
                findings_by_kind,
                unknown_count,
                unknowns_by_kind,
                unresolved_call_edges,
                parse_failures,
                macros_not_expanded,
                build_scripts,
                cargo_manifests,
                features: self.features.into_iter().collect(),
            },
        }
    }
}

struct InventoryVisitor<'a> {
    path: String,
    source: &'a str,
    index: &'a LineIndex<'a>,
    accumulator: &'a mut Accumulator,
    scope: Vec<String>,
    foreign_names: BTreeSet<String>,
}

impl InventoryVisitor<'_> {
    fn bump(&mut self) -> bool {
        self.accumulator.bump_node()
    }

    fn scope_label(&self) -> String {
        if self.scope.is_empty() {
            "<module>".to_owned()
        } else {
            self.scope.join("::")
        }
    }

    fn push_scope(&mut self, label: impl Into<String>) {
        self.scope.push(label.into());
    }

    fn pop_scope(&mut self) {
        let _ = self.scope.pop();
    }

    fn record_node<T: ToTokens>(
        &mut self,
        kind: FindingKind,
        node: &T,
        target: String,
        detail: Option<String>,
    ) {
        if let Some((start, end)) = span_bounds(&node.to_token_stream()) {
            self.record_spans(kind, start, end, target, detail);
        } else {
            self.record_bytes(kind, 0, 0, target, detail);
        }
    }

    fn record_spans(
        &mut self,
        kind: FindingKind,
        start: Span,
        end: Span,
        target: String,
        detail: Option<String>,
    ) {
        if let Some((byte_start, byte_end, line_start, column_start, line_end, column_end)) =
            self.index.span_bytes(start, end)
        {
            self.record_bytes_with_position(
                kind,
                byte_start,
                byte_end,
                line_start,
                column_start,
                line_end,
                column_end,
                target,
                detail,
            );
        } else {
            self.record_bytes(kind, 0, 0, target, detail);
        }
    }

    fn record_bytes(
        &mut self,
        kind: FindingKind,
        byte_start: usize,
        byte_end: usize,
        target: String,
        detail: Option<String>,
    ) {
        let (line_start, column_start) = self.index.byte_position(byte_start);
        let (line_end, column_end) = self.index.byte_position(byte_end);
        self.record_bytes_with_position(
            kind,
            byte_start,
            byte_end,
            line_start,
            column_start,
            line_end,
            column_end,
            target,
            detail,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn record_bytes_with_position(
        &mut self,
        kind: FindingKind,
        byte_start: usize,
        byte_end: usize,
        line_start: usize,
        column_start: usize,
        line_end: usize,
        column_end: usize,
        target: String,
        detail: Option<String>,
    ) {
        let finding = SourceFinding {
            kind,
            path: self.path.clone(),
            byte_start,
            byte_end,
            line_start,
            column_start,
            line_end,
            column_end,
            target,
            detail,
            content_sha256: sha256_hex(slice(self.source, byte_start, byte_end)),
        };
        self.accumulator.record_finding(finding);
    }

    fn record_unknown_tokens(&mut self, kind: UnknownKind, tokens: &TokenStream, detail: String) {
        let (byte_start, byte_end, line_start, column_start, line_end, column_end) =
            match span_bounds(tokens) {
                Some((start, end)) => self
                    .index
                    .span_bytes(start, end)
                    .unwrap_or((0, 0, 1, 0, 1, 0)),
                None => (0, 0, 1, 0, 1, 0),
            };
        self.accumulator.record_unknown(SourceUnknown {
            kind,
            path: self.path.clone(),
            byte_start,
            byte_end,
            line_start,
            column_start,
            line_end,
            column_end,
            detail,
            content_sha256: sha256_hex(slice(self.source, byte_start, byte_end)),
        });
    }

    fn record_unknown_node<T: ToTokens>(&mut self, kind: UnknownKind, node: &T, detail: String) {
        let tokens = node.to_token_stream();
        let (byte_start, byte_end, line_start, column_start, line_end, column_end) =
            match span_bounds(&tokens) {
                Some((start, end)) => self
                    .index
                    .span_bytes(start, end)
                    .unwrap_or((0, 0, 1, 0, 1, 0)),
                None => (0, 0, 1, 0, 1, 0),
            };
        self.accumulator.record_unknown(SourceUnknown {
            kind,
            path: self.path.clone(),
            byte_start,
            byte_end,
            line_start,
            column_start,
            line_end,
            column_end,
            detail,
            content_sha256: sha256_hex(slice(self.source, byte_start, byte_end)),
        });
    }

    fn classify_name<T: ToTokens>(&mut self, name: &str, node: &T) {
        let kind = match name {
            "transmute" | "transmute_copy" => Some(FindingKind::Transmute),
            "alloc" | "alloc_zeroed" | "malloc" | "calloc" | "realloc" | "alloca" => {
                Some(FindingKind::Allocation)
            }
            "dealloc" | "free" | "_aligned_free" => Some(FindingKind::Deallocation),
            "from_raw" | "into_raw" | "from_raw_parts" | "from_raw_parts_mut"
            | "into_raw_parts" | "forget" | "drop_in_place" | "set_len" | "leak" => {
                Some(FindingKind::OwnershipCall)
            }
            "offset"
            | "add"
            | "sub"
            | "wrapping_add"
            | "wrapping_sub"
            | "byte_add"
            | "byte_offset"
            | "read"
            | "write"
            | "read_unaligned"
            | "write_unaligned"
            | "read_volatile"
            | "write_volatile"
            | "copy"
            | "copy_nonoverlapping"
            | "as_ptr"
            | "as_mut_ptr"
            | "cast"
            | "addr"
            | "get_unchecked"
            | "get_unchecked_mut" => Some(FindingKind::RawPointerOperation),
            _ => None,
        };
        if let Some(kind) = kind {
            self.record_node(
                kind,
                node,
                name.to_owned(),
                Some(
                    "syntactic classification; callee and type resolution are not performed"
                        .to_owned(),
                ),
            );
        }
    }

    fn record_attribute(&mut self, attribute: &Attribute) {
        let name = attribute
            .path()
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        let scope = self.scope_label();
        match name.as_str() {
            "no_mangle" => self.record_node(FindingKind::NoMangle, attribute, scope, None),
            "export_name" => {
                let target = meta_name_value_string(attribute).unwrap_or(scope);
                self.record_node(
                    FindingKind::ExportName,
                    attribute,
                    target,
                    Some("exported symbol name".to_owned()),
                );
            }
            "link" => {
                let target = meta_name_value_string(attribute).unwrap_or_else(|| {
                    truncate_label(attribute.to_token_stream().to_string(), 120)
                });
                self.record_node(
                    FindingKind::LinkAttribute,
                    attribute,
                    target,
                    Some("native link attribute".to_owned()),
                );
            }
            "link_name" => {
                let target = meta_name_value_string(attribute).unwrap_or(scope);
                self.record_node(
                    FindingKind::LinkNameAttribute,
                    attribute,
                    target,
                    Some("foreign symbol rename".to_owned()),
                );
            }
            "repr" => {
                let target = truncate_label(attribute.to_token_stream().to_string(), 120);
                self.record_node(FindingKind::ReprAttribute, attribute, target, None);
            }
            "cfg" => {
                let detail = attribute
                    .meta
                    .to_token_stream()
                    .to_string()
                    .trim()
                    .to_owned();
                self.record_node(
                    FindingKind::CfgGated,
                    attribute,
                    scope,
                    Some(format!("cfg predicate: {detail}")),
                );
                self.collect_cfg_features(attribute);
            }
            "cfg_attr" => {
                let detail = attribute
                    .meta
                    .to_token_stream()
                    .to_string()
                    .trim()
                    .to_owned();
                self.record_node(
                    FindingKind::CfgGated,
                    attribute,
                    scope,
                    Some(format!("cfg_attr predicate: {detail}")),
                );
                self.collect_cfg_features(attribute);
                self.record_cfg_attr_effects(attribute);
            }
            "unsafe" => {
                let text = attribute.meta.to_token_stream().to_string();
                for (needle, kind) in [
                    ("no_mangle", FindingKind::NoMangle),
                    ("export_name", FindingKind::ExportName),
                    ("link_name", FindingKind::LinkNameAttribute),
                ] {
                    if text.contains(needle) {
                        self.record_node(
                            kind,
                            attribute,
                            scope.clone(),
                            Some("Rust 2024 unsafe attribute wrapper".to_owned()),
                        );
                    }
                }
            }
            _ => {}
        }
    }

    fn record_cfg_attr_effects(&mut self, attribute: &Attribute) {
        let Meta::List(list) = &attribute.meta else {
            return;
        };
        let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
        let Ok(items) = parser.parse2(list.tokens.clone()) else {
            return;
        };
        for meta in items.iter().skip(1) {
            let name = meta_path(meta)
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_default();
            let scope = self.scope_label();
            match name.as_str() {
                "no_mangle" => {
                    self.record_node(FindingKind::NoMangle, meta, scope, None);
                }
                "export_name" => {
                    let target = meta_name_value_string_meta(meta).unwrap_or(scope);
                    self.record_node(FindingKind::ExportName, meta, target, None);
                }
                "link" => {
                    let target = meta_name_value_string_meta(meta)
                        .unwrap_or_else(|| truncate_label(meta.to_token_stream().to_string(), 120));
                    self.record_node(FindingKind::LinkAttribute, meta, target, None);
                }
                "link_name" => {
                    let target = meta_name_value_string_meta(meta).unwrap_or(scope);
                    self.record_node(FindingKind::LinkNameAttribute, meta, target, None);
                }
                "repr" => {
                    let target = truncate_label(meta.to_token_stream().to_string(), 120);
                    self.record_node(FindingKind::ReprAttribute, meta, target, None);
                }
                _ => {}
            }
        }
    }

    fn collect_cfg_features(&mut self, attribute: &Attribute) {
        let Meta::List(list) = &attribute.meta else {
            return;
        };
        let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
        let Ok(items) = parser.parse2(list.tokens.clone()) else {
            return;
        };
        for item in &items {
            self.collect_features_meta(item, attribute);
        }
    }

    fn collect_features_meta(&mut self, meta: &Meta, attribute: &Attribute) {
        match meta {
            Meta::NameValue(name_value) if name_value.path.is_ident("feature") => {
                if let Some(feature) = literal_string(&name_value.value) {
                    self.accumulator.features.insert(feature.clone());
                    self.record_node(
                        FindingKind::FeatureGate,
                        attribute,
                        feature,
                        Some("cfg feature predicate".to_owned()),
                    );
                }
            }
            Meta::List(list) => {
                let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
                if let Ok(items) = parser.parse2(list.tokens.clone()) {
                    for item in &items {
                        self.collect_features_meta(item, attribute);
                    }
                }
            }
            _ => {}
        }
    }
}

impl<'ast> Visit<'ast> for InventoryVisitor<'_> {
    fn visit_item(&mut self, node: &'ast Item) {
        if self.bump() {
            return;
        }
        if let Item::Verbatim(tokens) = node {
            self.record_unknown_tokens(
                UnknownKind::VerbatimItem,
                tokens,
                "syn preserved an item it could not structurally parse".to_owned(),
            );
        }
        visit::visit_item(self, node);
    }

    fn visit_expr(&mut self, node: &'ast Expr) {
        if self.bump() {
            return;
        }
        if let Expr::Verbatim(tokens) = node {
            self.record_unknown_tokens(
                UnknownKind::VerbatimExpr,
                tokens,
                "syn preserved an expression it could not structurally parse".to_owned(),
            );
        }
        visit::visit_expr(self, node);
    }

    fn visit_type(&mut self, node: &'ast Type) {
        if self.bump() {
            return;
        }
        if let Type::Verbatim(tokens) = node {
            self.record_unknown_tokens(
                UnknownKind::VerbatimType,
                tokens,
                "syn preserved a type it could not structurally parse".to_owned(),
            );
        }
        visit::visit_type(self, node);
    }

    fn visit_pat(&mut self, node: &'ast Pat) {
        if self.bump() {
            return;
        }
        if let Pat::Verbatim(tokens) = node {
            self.record_unknown_tokens(
                UnknownKind::VerbatimPattern,
                tokens,
                "syn preserved a pattern it could not structurally parse".to_owned(),
            );
        }
        visit::visit_pat(self, node);
    }

    fn visit_foreign_item(&mut self, node: &'ast ForeignItem) {
        if self.bump() {
            return;
        }
        if let ForeignItem::Verbatim(tokens) = node {
            self.record_unknown_tokens(
                UnknownKind::VerbatimItem,
                tokens,
                "syn preserved a foreign item it could not structurally parse".to_owned(),
            );
        }
        visit::visit_foreign_item(self, node);
    }

    fn visit_attribute(&mut self, node: &'ast Attribute) {
        if self.bump() {
            return;
        }
        self.record_attribute(node);
        visit::visit_attribute(self, node);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        if self.bump() {
            return;
        }
        visit::visit_path(self, node);
    }

    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        if self.bump() {
            return;
        }
        visit::visit_stmt(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if self.bump() {
            return;
        }
        let name = path_string(&node.path);
        let kind = if name == "include" {
            UnknownKind::IncludeNotExpanded
        } else {
            UnknownKind::MacroInvocationNotExpanded
        };
        self.record_unknown_node(
            kind,
            node,
            format!("macro `{name}` is not expanded; generated items are outside this inventory"),
        );
        visit::visit_macro(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if node.sig.unsafety.is_some() {
            self.record_node(
                FindingKind::UnsafeFn,
                node,
                node.sig.ident.to_string(),
                None,
            );
        }
        if let Some(abi) = &node.sig.abi {
            self.record_node(
                FindingKind::ExternFn,
                node,
                node.sig.ident.to_string(),
                Some(abi_label(abi)),
            );
        }
        self.push_scope(node.sig.ident.to_string());
        visit::visit_item_fn(self, node);
        self.pop_scope();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if node.sig.unsafety.is_some() {
            self.record_node(
                FindingKind::UnsafeFn,
                node,
                node.sig.ident.to_string(),
                None,
            );
        }
        if let Some(abi) = &node.sig.abi {
            self.record_node(
                FindingKind::ExternFn,
                node,
                node.sig.ident.to_string(),
                Some(abi_label(abi)),
            );
        }
        self.push_scope(node.sig.ident.to_string());
        visit::visit_impl_item_fn(self, node);
        self.pop_scope();
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        if node.sig.unsafety.is_some() {
            self.record_node(
                FindingKind::UnsafeFn,
                node,
                node.sig.ident.to_string(),
                None,
            );
        }
        if let Some(abi) = &node.sig.abi {
            self.record_node(
                FindingKind::ExternFn,
                node,
                node.sig.ident.to_string(),
                Some(abi_label(abi)),
            );
        }
        self.push_scope(node.sig.ident.to_string());
        visit::visit_trait_item_fn(self, node);
        self.pop_scope();
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let self_ty = truncate_label(node.self_ty.to_token_stream().to_string(), 120);
        let label = if let Some((_, path, _)) = &node.trait_ {
            format!("{} for {}", path_string(path), self_ty)
        } else {
            self_ty
        };
        if node.unsafety.is_some() {
            self.record_node(FindingKind::UnsafeImpl, node, label.clone(), None);
        }
        self.push_scope(label);
        visit::visit_item_impl(self, node);
        self.pop_scope();
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        if node.unsafety.is_some() {
            self.record_node(FindingKind::UnsafeTrait, node, node.ident.to_string(), None);
        }
        self.push_scope(node.ident.to_string());
        visit::visit_item_trait(self, node);
        self.pop_scope();
    }

    fn visit_item_union(&mut self, node: &'ast syn::ItemUnion) {
        self.record_node(
            FindingKind::UnionDeclaration,
            node,
            node.ident.to_string(),
            Some("union requires field validity reasoning outside this inventory".to_owned()),
        );
        self.push_scope(node.ident.to_string());
        visit::visit_item_union(self, node);
        self.pop_scope();
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        self.push_scope(node.ident.to_string());
        visit::visit_item_struct(self, node);
        self.pop_scope();
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        self.push_scope(node.ident.to_string());
        visit::visit_item_enum(self, node);
        self.pop_scope();
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if node.content.is_none() {
            self.record_unknown_node(
                UnknownKind::ExternalModuleDeclaration,
                node,
                format!(
                    "module `{}` body is in another file; it is inventoried only if present under the scan root",
                    node.ident
                ),
            );
        }
        self.push_scope(node.ident.to_string());
        visit::visit_item_mod(self, node);
        self.pop_scope();
    }

    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        self.push_scope(node.ident.to_string());
        visit::visit_item_static(self, node);
        self.pop_scope();
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        self.push_scope(node.ident.to_string());
        visit::visit_item_const(self, node);
        self.pop_scope();
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        self.push_scope(node.ident.to_string());
        visit::visit_item_type(self, node);
        self.pop_scope();
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast syn::ItemForeignMod) {
        let abi = abi_label(&node.abi);
        self.record_node(
            FindingKind::ExternBlock,
            node,
            abi.clone(),
            Some(if node.unsafety.is_some() {
                "unsafe extern block".to_owned()
            } else {
                "extern block".to_owned()
            }),
        );
        self.push_scope(abi);
        visit::visit_item_foreign_mod(self, node);
        self.pop_scope();
    }

    fn visit_foreign_item_fn(&mut self, node: &'ast syn::ForeignItemFn) {
        self.record_node(
            FindingKind::FfiDeclaration,
            node,
            node.sig.ident.to_string(),
            Some(if node.sig.unsafety.is_some() {
                "extern function declaration (unsafe qualifier)".to_owned()
            } else {
                "extern function declaration (implicitly unsafe in pre-2024 editions)".to_owned()
            }),
        );
        self.push_scope(node.sig.ident.to_string());
        visit::visit_foreign_item_fn(self, node);
        self.pop_scope();
    }

    fn visit_foreign_item_static(&mut self, node: &'ast syn::ForeignItemStatic) {
        self.record_node(
            FindingKind::FfiDeclaration,
            node,
            node.ident.to_string(),
            Some("extern static declaration".to_owned()),
        );
        visit::visit_foreign_item_static(self, node);
    }

    fn visit_foreign_item_type(&mut self, node: &'ast syn::ForeignItemType) {
        self.record_node(
            FindingKind::FfiDeclaration,
            node,
            node.ident.to_string(),
            Some("extern type declaration".to_owned()),
        );
        visit::visit_foreign_item_type(self, node);
    }

    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        self.record_node(
            FindingKind::UnsafeBlock,
            node,
            "unsafe block".to_owned(),
            None,
        );
        visit::visit_expr_unsafe(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        let (callee, name) = match &*node.func {
            Expr::Path(path) => (
                path_string(&path.path),
                path.path
                    .segments
                    .last()
                    .map(|segment| segment.ident.to_string()),
            ),
            other => (
                truncate_label(other.to_token_stream().to_string(), 160),
                None,
            ),
        };
        self.record_node(
            FindingKind::FunctionCall,
            node,
            callee.clone(),
            Some(format!(
                "caller {}; unresolved syntactic edge",
                self.scope_label()
            )),
        );
        if let Some(name) = &name {
            if self.foreign_names.contains(name) {
                self.record_node(
                    FindingKind::FfiCall,
                    node,
                    callee.clone(),
                    Some("callee name matches an extern declaration in this file".to_owned()),
                );
            }
            self.classify_name(name, node);
        }
        if let Some(argument) = callback_argument(&node.args) {
            self.record_node(
                FindingKind::CallbackRegistration,
                node,
                format!("{callee} -> {argument}"),
                Some(
                    "function pointer or closure passed to a call; registration is not proven"
                        .to_owned(),
                ),
            );
        }
        if name.as_deref().is_some_and(looks_like_registration) {
            self.record_node(
                FindingKind::CallbackRegistration,
                node,
                callee,
                Some("call name suggests callback registration; unresolved".to_owned()),
            );
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        let receiver = truncate_label(node.receiver.to_token_stream().to_string(), 120);
        let target = format!("{receiver}.{method}");
        self.record_node(
            FindingKind::MethodCall,
            node,
            target.clone(),
            Some(format!(
                "caller {}; unresolved syntactic edge",
                self.scope_label()
            )),
        );
        self.classify_name(&method, node);
        if let Some(argument) = callback_argument(&node.args) {
            self.record_node(
                FindingKind::CallbackRegistration,
                node,
                format!("{target} -> {argument}"),
                Some(
                    "function pointer or closure passed to a method; registration is not proven"
                        .to_owned(),
                ),
            );
        }
        if looks_like_registration(&method) {
            self.record_node(
                FindingKind::CallbackRegistration,
                node,
                target,
                Some("method name suggests callback registration; unresolved".to_owned()),
            );
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.record_node(
            FindingKind::Closure,
            node,
            "closure".to_owned(),
            Some("closure body treated as an unresolved callable".to_owned()),
        );
        visit::visit_expr_closure(self, node);
    }

    fn visit_expr_cast(&mut self, node: &'ast syn::ExprCast) {
        if matches!(&*node.ty, Type::Ptr(_)) {
            self.record_node(
                FindingKind::RawPointerOperation,
                node,
                "cast_to_raw_pointer".to_owned(),
                Some("cast target is a raw-pointer type".to_owned()),
            );
        }
        visit::visit_expr_cast(self, node);
    }

    fn visit_expr_unary(&mut self, node: &'ast syn::ExprUnary) {
        if matches!(node.op, syn::UnOp::Deref(_)) {
            self.record_node(
                FindingKind::RawPointerOperation,
                node,
                "dereference".to_owned(),
                Some("syntactic `*`; raw-pointer versus reference is not resolved".to_owned()),
            );
        }
        visit::visit_expr_unary(self, node);
    }

    fn visit_expr_raw_addr(&mut self, node: &'ast syn::ExprRawAddr) {
        self.record_node(
            FindingKind::RawPointerOperation,
            node,
            "raw_address_of".to_owned(),
            None,
        );
        visit::visit_expr_raw_addr(self, node);
    }

    fn visit_type_ptr(&mut self, node: &'ast syn::TypePtr) {
        self.record_node(
            FindingKind::RawPointerType,
            node,
            truncate_label(node.to_token_stream().to_string(), 120),
            None,
        );
        visit::visit_type_ptr(self, node);
    }

    fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
        self.record_symbols(&node.path, node);
        visit::visit_type_path(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        self.record_symbols(&node.path, node);
        visit::visit_expr_path(self, node);
    }
}

impl InventoryVisitor<'_> {
    fn record_symbols<T: ToTokens>(&mut self, path: &syn::Path, node: &T) {
        let names: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        for (needle, kind) in [
            ("MaybeUninit", FindingKind::MaybeUninitUse),
            ("UnsafeCell", FindingKind::UnsafeCellUse),
            ("NonNull", FindingKind::NonNullUse),
        ] {
            if names.iter().any(|name| name == needle) {
                self.record_node(kind, node, needle.to_owned(), None);
            }
        }
    }
}

fn path_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn abi_label(abi: &syn::Abi) -> String {
    match &abi.name {
        Some(name) => format!("extern {:?}", name.value()),
        None => "extern \"C\" (default)".to_owned(),
    }
}

fn callback_argument(args: &Punctuated<Expr, Token![,]>) -> Option<String> {
    args.iter().find_map(|argument| match argument {
        Expr::Closure(_) => Some("closure".to_owned()),
        Expr::Path(path) => Some(path_string(&path.path)),
        Expr::Reference(reference) => match &*reference.expr {
            Expr::Path(path) => Some(path_string(&path.path)),
            _ => None,
        },
        Expr::Cast(cast) => Some(truncate_label(cast.expr.to_token_stream().to_string(), 80)),
        _ => None,
    })
}

fn looks_like_registration(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("register")
        || lower.contains("subscribe")
        || lower.contains("callback")
        || lower.starts_with("set_")
        || lower.starts_with("on_")
}

fn literal_string(expression: &Expr) -> Option<String> {
    if let Expr::Lit(literal) = expression {
        if let Lit::Str(value) = &literal.lit {
            return Some(value.value());
        }
    }
    None
}

fn meta_path(meta: &Meta) -> &syn::Path {
    match meta {
        Meta::Path(path) => path,
        Meta::List(list) => &list.path,
        Meta::NameValue(name_value) => &name_value.path,
    }
}

fn meta_name_value_string(attribute: &Attribute) -> Option<String> {
    meta_name_value_string_meta(&attribute.meta)
}

fn meta_name_value_string_meta(meta: &Meta) -> Option<String> {
    match meta {
        Meta::NameValue(name_value) => literal_string(&name_value.value),
        Meta::List(list) => {
            let parser = Punctuated::<syn::MetaNameValue, Token![,]>::parse_terminated;
            let values = parser.parse2(list.tokens.clone()).ok()?;
            values
                .into_iter()
                .find_map(|name_value| literal_string(&name_value.value))
        }
        Meta::Path(_) => None,
    }
}

fn truncate_label(value: String, maximum_chars: usize) -> String {
    if value.chars().count() <= maximum_chars {
        value
    } else {
        let mut truncated: String = value.chars().take(maximum_chars).collect();
        truncated.push_str("...");
        truncated
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn slice(source: &str, start: usize, end: usize) -> &[u8] {
    let start = start.min(source.len());
    let end = end.min(source.len()).max(start);
    source.as_bytes().get(start..end).unwrap_or(&[])
}

fn span_bounds(tokens: &TokenStream) -> Option<(Span, Span)> {
    let mut tokens = tokens.clone().into_iter();
    let first = tokens.next()?.span();
    let mut last = first;
    for token in tokens {
        last = match token {
            TokenTree::Group(group) => group.span(),
            other => other.span(),
        };
    }
    Some((first, last))
}

struct LineIndex<'a> {
    source: &'a str,
    char_to_byte: Vec<usize>,
    char_line_starts: Vec<usize>,
    byte_line_starts: Vec<usize>,
}

impl<'a> LineIndex<'a> {
    fn new(source: &'a str) -> Self {
        let char_count = source.chars().count();
        let mut char_to_byte = Vec::with_capacity(char_count.saturating_add(1));
        let mut char_line_starts = vec![0];
        let mut byte_line_starts = vec![0];
        let mut chars = 0usize;
        for (byte_index, character) in source.char_indices() {
            char_to_byte.push(byte_index);
            chars = chars.saturating_add(1);
            if character == '\n' {
                char_line_starts.push(chars);
                byte_line_starts.push(byte_index + character.len_utf8());
            }
        }
        char_to_byte.push(source.len());
        Self {
            source,
            char_to_byte,
            char_line_starts,
            byte_line_starts,
        }
    }

    fn position(&self, position: LineColumn) -> Option<(usize, usize, usize)> {
        if position.line == 0 {
            return None;
        }
        let line_index = position.line.checked_sub(1)?;
        let line_start = *self.char_line_starts.get(line_index)?;
        let char_index = line_start.checked_add(position.column)?;
        let byte = *self.char_to_byte.get(char_index)?;
        Some((byte, position.line, position.column))
    }

    fn span_bytes(
        &self,
        start: Span,
        end: Span,
    ) -> Option<(usize, usize, usize, usize, usize, usize)> {
        let (byte_start, line_start, column_start) = self.position(start.start())?;
        let (byte_end, line_end, column_end) = self.position(end.end())?;
        let byte_end = byte_end.max(byte_start);
        Some((
            byte_start,
            byte_end,
            line_start,
            column_start,
            line_end,
            column_end,
        ))
    }

    fn byte_position(&self, byte: usize) -> (usize, usize) {
        let byte = byte.min(self.source.len());
        let line_index = match self.byte_line_starts.binary_search(&byte) {
            Ok(index) => index,
            Err(index) => index.saturating_sub(1),
        };
        let line_start = self.byte_line_starts[line_index];
        let column = self.source[line_start..byte].chars().count();
        (line_index + 1, column)
    }
}

#[allow(clippy::too_many_arguments)]
fn make_finding(
    source: &str,
    index: &LineIndex<'_>,
    path: &str,
    kind: FindingKind,
    byte_start: usize,
    byte_end: usize,
    target: String,
    detail: Option<String>,
) -> SourceFinding {
    let (line_start, column_start) = index.byte_position(byte_start);
    let (line_end, column_end) = index.byte_position(byte_end);
    SourceFinding {
        kind,
        path: path.to_owned(),
        byte_start,
        byte_end,
        line_start,
        column_start,
        line_end,
        column_end,
        target,
        detail,
        content_sha256: sha256_hex(slice(source, byte_start, byte_end)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_index_maps_unicode_columns_to_bytes() {
        let source = "fn main() {\n    let π = 3;\n}\n";
        let index = LineIndex::new(source);
        let (byte, line, column) = index.position(LineColumn { line: 2, column: 8 }).unwrap();
        assert_eq!(line, 2);
        assert_eq!(column, 8);
        assert_eq!(&source[byte..byte + 2], "π");
    }

    #[test]
    fn symbol_classification_is_syntactic() {
        assert!(looks_like_registration("register_callback"));
        assert!(looks_like_registration("on_event"));
        assert!(!looks_like_registration("compute"));
    }
}
