//! Test-only native event recording harness (Phase 4.2).
//!
//! This module is deliberately **not** exposed through the command-line
//! interface and cannot run arbitrary user code. It compiles a closed registry
//! of checked-in C and Rust fixtures, executes each one in a private `0700`
//! temporary directory with a cleared environment, null stdin, its own process
//! group, per-child resource limits, and bounded output capture. The captured
//! JSONL event stream is turned into a `native-event-transcript.v1` transcript
//! and handed to the Phase 4.1 verifier in [`crate::court`].
//!
//! # Replay rule
//!
//! Every fixture is executed twice with the identical executable, argv,
//! environment, and working directory. The two canonical transcripts must be
//! byte-identical. Any difference is reported as
//! [`NativeOutcome::Unresolved`]; a replay difference is never promoted to a
//! clean verdict.
//!
//! # What a live record establishes
//!
//! It establishes that a checked-in fixture, compiled by the recorded compiler
//! versions and executed under the recorded limits, emitted the recorded finite
//! event stream twice. It does **not** establish memory safety, Rust borrow
//! validity, C object lifetime, real-scheduler concurrency, the absence of
//! unrecorded events, or any universal result. The fixture schedule is
//! scripted and deterministic; concurrency is represented in the transcript,
//! not observed from an operating-system scheduler.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::court::{
    parse_transcript, verify_transcript, CaseLegality, CourtReport, Event, EventRef, Finding,
    FindingClass, LibraryVersion, NativeEventTranscript, ObjectDecl, RecordingMetadata, SyncEdge,
    ThreadTrace, TranscriptOrigin, TranscriptOutcome, TranscriptProvenance, TranscriptRequirements,
};
use crate::identity::{canonical_bytes, hex_lower, parse_strict};

/// Environment flag that enables live native compilation and execution.
///
/// When the flag is absent, every case returns [`NativeOutcome::NotRun`]. This
/// keeps the default gate runnable in an image without a C toolchain while still
/// exercising the typed `NOT_RUN` path.
pub const NATIVE_HARNESS_ENV: &str = "FRF_NATIVE_HARNESS";

/// Recorder identity written into transcript provenance.
pub const NATIVE_TOOL: &str = "frf-native-fixture-harness";

/// Declared scope written into transcript provenance.
pub const NATIVE_SCOPE: &str = "Phase 4.2 checked-in test-only native fixtures; \
scripted deterministic event schedule; transcript-scoped; no real scheduler observation";

/// Maximum captured standard-output or standard-error bytes from one execution.
pub const MAX_CAPTURE_BYTES: usize = 256 * 1024;

/// Maximum captured compiler standard-output or standard-error bytes.
pub const MAX_COMPILER_OUTPUT_BYTES: usize = 64 * 1024;

/// Wall-clock bound for one fixture execution.
pub const RUN_TIMEOUT: Duration = Duration::from_secs(10);

/// Wall-clock bound for one fixture compilation.
pub const COMPILE_TIMEOUT: Duration = Duration::from_secs(120);

const ADDRESS_SPACE_LIMIT: u64 = 512 * 1024 * 1024;
const CPU_LIMIT_SECONDS: u64 = 5;
const NPROC_LIMIT: u64 = 64;
const FSIZE_LIMIT: u64 = 1024 * 1024;
const COMPILER_PATH: &str = "/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin";
const FIXTURE_DIR: &str = "tests/native/fixtures";
const RECORDING_SEED: u64 = 42;
const RUST_TOOLCHAIN_FILE: &str = include_str!("../rust-toolchain.toml");

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Source language of a registered fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureLanguage {
    /// C fixture compiled with `cc` (falling back to `gcc`).
    C,
    /// Rust fixture compiled with `rustc`.
    Rust,
}

impl FixtureLanguage {
    /// Stable lower-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::C => "c",
            Self::Rust => "rust",
        }
    }
}

/// Typed result of a native harness request.
///
/// The first five variants mirror [`TranscriptOutcome`]; the last two describe
/// harness availability and harness failure. None of them is a memory-safety
/// or universal result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeOutcome {
    /// The recorded transcript verified cleanly and replayed identically.
    VerifiedCompatibleWithinTranscript,
    /// The recorded transcript contains a definite contradiction.
    ObservedViolation,
    /// The recorded transcript is missing a required event.
    IncompleteTranscript,
    /// The evidence is not usable, including a replay mismatch.
    Unresolved,
    /// The declared case is illegal or the ordering graph is cyclic.
    IllegalCase,
    /// The harness was disabled or a required tool is unavailable (`NOT_RUN`).
    NotRun,
    /// Internal harness failure such as a compiler or fixture error.
    HarnessFailure,
}

impl NativeOutcome {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedCompatibleWithinTranscript => "verified_compatible_within_transcript",
            Self::ObservedViolation => "observed_violation",
            Self::IncompleteTranscript => "incomplete_transcript",
            Self::Unresolved => "unresolved",
            Self::IllegalCase => "illegal_case",
            Self::NotRun => "not_run",
            Self::HarnessFailure => "harness_failure",
        }
    }

    const fn from_court(outcome: TranscriptOutcome) -> Self {
        match outcome {
            TranscriptOutcome::VerifiedCompatibleWithinTranscript => {
                Self::VerifiedCompatibleWithinTranscript
            }
            TranscriptOutcome::ObservedViolation => Self::ObservedViolation,
            TranscriptOutcome::IncompleteTranscript => Self::IncompleteTranscript,
            TranscriptOutcome::Unresolved => Self::Unresolved,
            TranscriptOutcome::IllegalCase => Self::IllegalCase,
        }
    }
}

/// Result of the two-run replay check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayStatus {
    /// Both runs produced byte-identical canonical transcripts.
    Identical {
        /// SHA-256 of the first canonical transcript.
        first_sha256: String,
        /// SHA-256 of the second canonical transcript.
        second_sha256: String,
    },
    /// The two runs produced different canonical transcripts.
    Mismatch {
        /// SHA-256 of the first canonical transcript.
        first_sha256: String,
        /// SHA-256 of the second canonical transcript.
        second_sha256: String,
    },
    /// Replay was not attempted.
    NotPerformed,
}

impl ReplayStatus {
    /// Stable lower-case label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Identical { .. } => "identical",
            Self::Mismatch { .. } => "mismatch",
            Self::NotPerformed => "not_performed",
        }
    }
}

/// One declared object in a fixture case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeObject {
    /// Object identifier used by fixture events.
    pub id: &'static str,
    /// Whether the object is declared atomic.
    pub atomic: bool,
}

/// Explicit required-event obligations for a fixture case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NativeRequirements {
    /// Objects that must have a create event.
    pub required_creates: &'static [&'static str],
    /// Objects that must have a free event.
    pub required_frees: &'static [&'static str],
    /// Borrow tokens that must have a borrow-end event.
    pub required_borrow_ends: &'static [&'static str],
    /// Objects that must have a reallocation generation transition.
    pub required_generation_transitions: &'static [&'static str],
    /// Callbacks that must be recorded through enter and exit.
    pub required_callbacks: &'static [&'static str],
}

const NO_REQUIREMENTS: NativeRequirements = NativeRequirements {
    required_creates: &[],
    required_frees: &[],
    required_borrow_ends: &[],
    required_generation_transitions: &[],
    required_callbacks: &[],
};

/// One checked-in fixture known to the harness.
#[derive(Debug, Clone, Copy)]
pub struct NativeCase {
    /// Stable case identifier used by tests and reports.
    pub id: &'static str,
    /// Fixture file name relative to `tests/native/fixtures`.
    pub source: &'static str,
    /// Fixture source language.
    pub language: FixtureLanguage,
    /// Declared objects.
    pub objects: &'static [NativeObject],
    /// Declared logical thread identifiers.
    pub threads: &'static [&'static str],
    /// Required-event obligations.
    pub requirements: NativeRequirements,
    /// Explicit argv passed after the executable path.
    pub args: &'static [&'static str],
    /// Number of events the recorder claims to emit.
    pub expected_event_count: usize,
    /// Default completeness claim.
    pub claimed_complete: bool,
    /// Expected live outcome when the harness is enabled.
    pub expected_outcome: NativeOutcome,
}

/// Closed registry of checked-in native fixtures.
///
/// There is no API that accepts a caller-supplied source file or executable, so
/// the harness cannot become a general-purpose code runner.
pub static CASES: &[NativeCase] = &[
    NativeCase {
        id: "legal-transfer-free-c",
        source: "legal_transfer_free.c",
        language: FixtureLanguage::C,
        objects: &[NativeObject {
            id: "obj",
            atomic: false,
        }],
        threads: &["t0"],
        requirements: NativeRequirements {
            required_creates: &["obj"],
            required_frees: &["obj"],
            ..NO_REQUIREMENTS
        },
        args: &[],
        expected_event_count: 6,
        claimed_complete: true,
        expected_outcome: NativeOutcome::VerifiedCompatibleWithinTranscript,
    },
    NativeCase {
        id: "legal-transfer-free-rust",
        source: "legal_transfer_free.rs",
        language: FixtureLanguage::Rust,
        objects: &[NativeObject {
            id: "obj",
            atomic: false,
        }],
        threads: &["t0"],
        requirements: NativeRequirements {
            required_creates: &["obj"],
            required_frees: &["obj"],
            ..NO_REQUIREMENTS
        },
        args: &[],
        expected_event_count: 6,
        claimed_complete: true,
        expected_outcome: NativeOutcome::VerifiedCompatibleWithinTranscript,
    },
    NativeCase {
        id: "use-after-free-c",
        source: "use_after_free.c",
        language: FixtureLanguage::C,
        objects: &[NativeObject {
            id: "obj",
            atomic: false,
        }],
        threads: &["t0"],
        requirements: NativeRequirements {
            required_creates: &["obj"],
            required_frees: &["obj"],
            ..NO_REQUIREMENTS
        },
        args: &[],
        expected_event_count: 4,
        claimed_complete: true,
        expected_outcome: NativeOutcome::ObservedViolation,
    },
    NativeCase {
        id: "use-after-free-rust",
        source: "use_after_free.rs",
        language: FixtureLanguage::Rust,
        objects: &[NativeObject {
            id: "obj",
            atomic: false,
        }],
        threads: &["t0"],
        requirements: NativeRequirements {
            required_creates: &["obj"],
            required_frees: &["obj"],
            ..NO_REQUIREMENTS
        },
        args: &[],
        expected_event_count: 4,
        claimed_complete: true,
        expected_outcome: NativeOutcome::ObservedViolation,
    },
    NativeCase {
        id: "mutable-alias-c",
        source: "mutable_alias.c",
        language: FixtureLanguage::C,
        objects: &[NativeObject {
            id: "obj",
            atomic: false,
        }],
        threads: &["t0"],
        requirements: NativeRequirements {
            required_creates: &["obj"],
            required_frees: &["obj"],
            ..NO_REQUIREMENTS
        },
        args: &[],
        expected_event_count: 6,
        claimed_complete: true,
        expected_outcome: NativeOutcome::ObservedViolation,
    },
    NativeCase {
        id: "stale-generation-c",
        source: "stale_generation.c",
        language: FixtureLanguage::C,
        objects: &[NativeObject {
            id: "obj",
            atomic: false,
        }],
        threads: &["t0"],
        requirements: NativeRequirements {
            required_creates: &["obj"],
            required_frees: &["obj"],
            required_generation_transitions: &["obj"],
            ..NO_REQUIREMENTS
        },
        args: &[],
        expected_event_count: 6,
        claimed_complete: true,
        expected_outcome: NativeOutcome::ObservedViolation,
    },
    NativeCase {
        id: "sync-callback-c",
        source: "sync_callback.c",
        language: FixtureLanguage::C,
        objects: &[NativeObject {
            id: "obj",
            atomic: false,
        }],
        threads: &["t0"],
        requirements: NativeRequirements {
            required_creates: &["obj"],
            required_frees: &["obj"],
            required_callbacks: &["on_done"],
            ..NO_REQUIREMENTS
        },
        args: &[],
        expected_event_count: 6,
        claimed_complete: true,
        expected_outcome: NativeOutcome::VerifiedCompatibleWithinTranscript,
    },
    NativeCase {
        id: "deferred-callback-c",
        source: "deferred_callback.c",
        language: FixtureLanguage::C,
        objects: &[NativeObject {
            id: "obj",
            atomic: false,
        }],
        threads: &["t0"],
        requirements: NativeRequirements {
            required_creates: &["obj"],
            required_frees: &["obj"],
            required_callbacks: &["on_done"],
            ..NO_REQUIREMENTS
        },
        args: &[],
        expected_event_count: 6,
        claimed_complete: true,
        expected_outcome: NativeOutcome::ObservedViolation,
    },
    NativeCase {
        id: "data-race-c",
        source: "data_race.c",
        language: FixtureLanguage::C,
        objects: &[NativeObject {
            id: "obj",
            atomic: false,
        }],
        threads: &["t0", "t1"],
        requirements: NativeRequirements {
            required_creates: &["obj"],
            required_frees: &["obj"],
            ..NO_REQUIREMENTS
        },
        args: &[],
        expected_event_count: 6,
        claimed_complete: true,
        expected_outcome: NativeOutcome::ObservedViolation,
    },
    NativeCase {
        id: "atomic-control-c",
        source: "atomic_control.c",
        language: FixtureLanguage::C,
        objects: &[NativeObject {
            id: "obj",
            atomic: true,
        }],
        threads: &["t0", "t1"],
        requirements: NativeRequirements {
            required_creates: &["obj"],
            required_frees: &["obj"],
            ..NO_REQUIREMENTS
        },
        args: &[],
        expected_event_count: 5,
        claimed_complete: true,
        expected_outcome: NativeOutcome::VerifiedCompatibleWithinTranscript,
    },
    NativeCase {
        id: "skipped-free-c",
        source: "skipped_event.c",
        language: FixtureLanguage::C,
        objects: &[NativeObject {
            id: "obj",
            atomic: false,
        }],
        threads: &["t0"],
        requirements: NativeRequirements {
            required_creates: &["obj"],
            required_frees: &["obj"],
            ..NO_REQUIREMENTS
        },
        args: &["skip-free"],
        expected_event_count: 6,
        claimed_complete: false,
        expected_outcome: NativeOutcome::IncompleteTranscript,
    },
    NativeCase {
        id: "nondeterministic-c",
        source: "nondeterministic.c",
        language: FixtureLanguage::C,
        objects: &[NativeObject {
            id: "obj",
            atomic: false,
        }],
        threads: &["t0"],
        requirements: NativeRequirements {
            required_creates: &["obj"],
            required_frees: &["obj"],
            ..NO_REQUIREMENTS
        },
        args: &[],
        expected_event_count: 6,
        claimed_complete: true,
        expected_outcome: NativeOutcome::Unresolved,
    },
    NativeCase {
        id: "oversized-output-c",
        source: "oversized_output.c",
        language: FixtureLanguage::C,
        objects: &[NativeObject {
            id: "obj",
            atomic: false,
        }],
        threads: &["t0"],
        requirements: NO_REQUIREMENTS,
        args: &[],
        expected_event_count: 1,
        claimed_complete: true,
        expected_outcome: NativeOutcome::Unresolved,
    },
];

/// Return the closed fixture registry.
#[must_use]
pub fn cases() -> &'static [NativeCase] {
    CASES
}

/// Whether the live harness is enabled by [`NATIVE_HARNESS_ENV`].
#[must_use]
pub fn native_harness_enabled() -> bool {
    matches!(
        std::env::var(NATIVE_HARNESS_ENV).as_deref(),
        Ok("1" | "true" | "yes")
    )
}

/// Optional overrides for a harness record.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeRecordOptions {
    /// Override the declared completeness claim.
    pub claimed_complete: Option<bool>,
    /// Override the declared provenance origin (test-only control).
    pub origin: Option<TranscriptOrigin>,
}

/// One native recording attempt.
#[derive(Debug, Clone)]
pub struct NativeRecord {
    /// Case identifier.
    pub case_id: String,
    /// Typed outcome.
    pub outcome: NativeOutcome,
    /// Human-readable detail.
    pub detail: String,
    /// Parsed transcript when one was produced.
    pub transcript: Option<NativeEventTranscript>,
    /// Court report when verification ran.
    pub report: Option<CourtReport>,
    /// Recorded provenance when a transcript was produced.
    pub provenance: Option<TranscriptProvenance>,
    /// Replay result.
    pub replay: ReplayStatus,
    /// SHA-256 of the checked-in fixture source.
    pub fixture_sha256: Option<String>,
    /// SHA-256 of the compiled executable.
    pub executable_sha256: Option<String>,
}

impl NativeRecord {
    /// Whether this attempt was the typed `NOT_RUN` path.
    #[must_use]
    pub const fn is_not_run(&self) -> bool {
        matches!(self.outcome, NativeOutcome::NotRun)
    }
}

/// Record, replay, and verify one registered native fixture.
///
/// When [`NATIVE_HARNESS_ENV`] is absent, or a required tool is missing, the
/// result is [`NativeOutcome::NotRun`] and no compilation or execution is
/// attempted.
#[must_use]
pub fn record_case(case_id: &str) -> NativeRecord {
    record_case_with(case_id, NativeRecordOptions::default())
}

/// Record, replay, and verify one registered native fixture with overrides.
///
/// `options.origin` is a test-only control. Declaring `substitute` or `modeled`
/// still executes the fixture, but the court correctly returns
/// [`NativeOutcome::Unresolved`] because only authentic-native origin can reach
/// a clean verdict.
#[must_use]
pub fn record_case_with(case_id: &str, options: NativeRecordOptions) -> NativeRecord {
    let Some(case) = CASES.iter().find(|case| case.id == case_id) else {
        return failure(case_id, format!("unknown native case id: {case_id}"));
    };
    if !native_harness_enabled() {
        return not_run(
            case,
            format!(
                "native harness disabled; set {NATIVE_HARNESS_ENV}=1 and install cc, rustc, and prlimit"
            ),
        );
    }
    let tools = match resolve_tools(case.language) {
        Ok(tools) => tools,
        Err(reason) => return not_run(case, reason),
    };
    record_live(case, &tools, options)
}

struct Tools {
    compiler: PathBuf,
    cc: Option<PathBuf>,
    linker: Option<PathBuf>,
    prlimit: PathBuf,
}

fn resolve_tools(language: FixtureLanguage) -> Result<Tools, String> {
    let prlimit = resolve_tool("prlimit").ok_or_else(|| {
        format!(
            "missing required tool: prlimit; set {NATIVE_HARNESS_ENV}=1 only when it is installed"
        )
    })?;
    let cc = resolve_tool("cc").or_else(|| resolve_tool("gcc"));
    let linker = resolve_tool("ld");
    let compiler = match language {
        FixtureLanguage::C => cc
            .clone()
            .ok_or_else(|| "missing required C compiler: cc or gcc".to_owned())?,
        FixtureLanguage::Rust => {
            resolve_tool("rustc").ok_or_else(|| "missing required tool: rustc".to_owned())?
        }
    };
    Ok(Tools {
        compiler,
        cc,
        linker,
        prlimit,
    })
}

fn resolve_tool(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        let Ok(metadata) = fs::metadata(&candidate) else {
            continue;
        };
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            return Some(candidate);
        }
    }
    None
}

#[allow(clippy::too_many_lines)]
fn record_live(case: &NativeCase, tools: &Tools, options: NativeRecordOptions) -> NativeRecord {
    let directory = match PrivateDir::new(case.id) {
        Ok(directory) => directory,
        Err(error) => {
            return failure(
                case.id,
                format!("cannot create private temp directory: {error}"),
            )
        }
    };

    let source = fixture_path(case.source);
    let fixture_sha256 = match sha256_file(&source) {
        Ok(digest) => digest,
        Err(error) => return failure(case.id, error),
    };

    let executable = match compile(case, tools, directory.path(), &source) {
        Ok(executable) => executable,
        Err(error) => return failure(case.id, error),
    };
    let executable_sha256 = match sha256_file(&executable) {
        Ok(digest) => digest,
        Err(error) => return failure(case.id, error),
    };

    let library_versions = collect_versions(case.language, tools, directory.path());
    let compiler_name = match case.language {
        FixtureLanguage::C => "cc",
        FixtureLanguage::Rust => "rustc",
    };
    if !library_versions
        .iter()
        .any(|library| library.name == compiler_name)
    {
        return failure(
            case.id,
            format!("could not obtain the exact {compiler_name} version"),
        );
    }

    let provenance = TranscriptProvenance {
        origin: options.origin.unwrap_or(TranscriptOrigin::AuthenticNative),
        tool: NATIVE_TOOL.to_owned(),
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        library_versions,
        executable_digest: executable_sha256.clone(),
        fixture_digest: fixture_sha256.clone(),
        case_legality: CaseLegality::TestOnly,
        scope: format!("{NATIVE_SCOPE}; case={}", case.id),
        claimed_complete: options.claimed_complete.unwrap_or(case.claimed_complete),
    };

    let first_stdout = match run_fixture(case, tools, directory.path(), &executable, 1) {
        Ok(stdout) => stdout,
        Err(error) => return classify_run_error(case, &error),
    };
    let second_stdout = match run_fixture(case, tools, directory.path(), &executable, 2) {
        Ok(stdout) => stdout,
        Err(error) => return classify_run_error(case, &error),
    };

    let first = match build_transcript(case, &first_stdout, &provenance) {
        Ok(built) => built,
        Err(error) => return failure(case.id, error),
    };
    let second = match build_transcript(case, &second_stdout, &provenance) {
        Ok(built) => built,
        Err(error) => return failure(case.id, error),
    };

    let first_sha256 = sha256_bytes(&first.0);
    let second_sha256 = sha256_bytes(&second.0);
    let report = match verify_transcript(&first.1) {
        Ok(report) => report,
        Err(error) => return failure(case.id, format!("court verification failed: {error}")),
    };

    if first_sha256 != second_sha256 {
        let report = unresolved_replay_report(report, &first_sha256, &second_sha256);
        return NativeRecord {
            case_id: case.id.to_owned(),
            outcome: NativeOutcome::Unresolved,
            detail: format!(
                "replay mismatch: identical executable input produced different canonical transcripts \
                 ({first_sha256} != {second_sha256})"
            ),
            transcript: Some(first.1),
            report: Some(report),
            provenance: Some(provenance),
            replay: ReplayStatus::Mismatch {
                first_sha256,
                second_sha256,
            },
            fixture_sha256: Some(fixture_sha256),
            executable_sha256: Some(executable_sha256),
        };
    }

    let outcome = NativeOutcome::from_court(report.outcome);
    NativeRecord {
        case_id: case.id.to_owned(),
        outcome,
        detail: format!(
            "recorded and replayed identical canonical transcripts; outcome {}",
            outcome.as_str()
        ),
        transcript: Some(first.1),
        report: Some(report),
        provenance: Some(provenance),
        replay: ReplayStatus::Identical {
            first_sha256,
            second_sha256,
        },
        fixture_sha256: Some(fixture_sha256),
        executable_sha256: Some(executable_sha256),
    }
}

fn not_run(case: &NativeCase, detail: String) -> NativeRecord {
    NativeRecord {
        case_id: case.id.to_owned(),
        outcome: NativeOutcome::NotRun,
        detail,
        transcript: None,
        report: None,
        provenance: None,
        replay: ReplayStatus::NotPerformed,
        fixture_sha256: None,
        executable_sha256: None,
    }
}

fn failure(case_id: &str, detail: String) -> NativeRecord {
    NativeRecord {
        case_id: case_id.to_owned(),
        outcome: NativeOutcome::HarnessFailure,
        detail,
        transcript: None,
        report: None,
        provenance: None,
        replay: ReplayStatus::NotPerformed,
        fixture_sha256: None,
        executable_sha256: None,
    }
}

fn classify_run_error(case: &NativeCase, error: &str) -> NativeRecord {
    if error.starts_with("captured output exceeded") {
        return NativeRecord {
            case_id: case.id.to_owned(),
            outcome: NativeOutcome::Unresolved,
            detail: error.to_owned(),
            transcript: None,
            report: None,
            provenance: None,
            replay: ReplayStatus::NotPerformed,
            fixture_sha256: None,
            executable_sha256: None,
        };
    }
    failure(case.id, error.to_owned())
}

fn unresolved_replay_report(mut report: CourtReport, first: &str, second: &str) -> CourtReport {
    report.outcome = TranscriptOutcome::Unresolved;
    report.findings.push(Finding {
        class: FindingClass::Unresolved,
        code: "replay_mismatch".to_owned(),
        subject: "transcript".to_owned(),
        detail: format!(
            "identical executable input produced different canonical transcripts: {first} != {second}"
        ),
        events: Vec::new(),
    });
    report.findings.sort();
    report.findings.dedup();
    report
}

fn fixture_path(source: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURE_DIR)
        .join(source)
}

fn compile(
    case: &NativeCase,
    tools: &Tools,
    directory: &Path,
    source: &Path,
) -> Result<PathBuf, String> {
    let executable = directory.join("fixture");
    let mut args: Vec<OsString> = Vec::new();
    match case.language {
        FixtureLanguage::C => {
            for argument in ["-std=c11", "-O0", "-Wall", "-Wextra", "-Werror"] {
                args.push(OsString::from(argument));
            }
        }
        FixtureLanguage::Rust => {
            for argument in ["--edition=2021", "-C", "opt-level=0", "-C", "debuginfo=0"] {
                args.push(OsString::from(argument));
            }
            if let Some(cc) = &tools.cc {
                args.push(OsString::from("-C"));
                let mut linker = OsString::from("linker=");
                linker.push(cc);
                args.push(linker);
            }
        }
    }
    args.push(OsString::from("-o"));
    args.push(executable.clone().into_os_string());
    args.push(source.as_os_str().to_owned());

    let captured = run_capture(
        &tools.compiler,
        &args,
        directory,
        Environment::Compiler,
        COMPILE_TIMEOUT,
        MAX_COMPILER_OUTPUT_BYTES,
        "compile",
    )?;
    if captured.timed_out {
        return Err(format!(
            "compiler timed out after {} seconds",
            COMPILE_TIMEOUT.as_secs()
        ));
    }
    if captured.stdout_truncated || captured.stderr_truncated {
        return Err("compiler output exceeded the capture bound".to_owned());
    }
    if !captured.status.is_some_and(|status| status.success()) {
        return Err(format!(
            "compiler failed with status {}: {}",
            status_label(captured.status),
            captured.stderr.trim()
        ));
    }
    if !executable.is_file() {
        return Err("compiler did not produce an executable".to_owned());
    }
    Ok(executable)
}

fn run_fixture(
    case: &NativeCase,
    tools: &Tools,
    directory: &Path,
    executable: &Path,
    run: u32,
) -> Result<String, String> {
    let mut args: Vec<OsString> = vec![
        OsString::from(format!("--as={ADDRESS_SPACE_LIMIT}")),
        OsString::from(format!("--cpu={CPU_LIMIT_SECONDS}")),
        OsString::from(format!("--nproc={NPROC_LIMIT}")),
        OsString::from(format!("--fsize={FSIZE_LIMIT}")),
        OsString::from("--core=0"),
        OsString::from("--"),
        executable.as_os_str().to_owned(),
    ];
    for argument in case.args {
        args.push(OsString::from(argument));
    }

    let captured = run_capture(
        &tools.prlimit,
        &args,
        directory,
        Environment::Cleared,
        RUN_TIMEOUT,
        MAX_CAPTURE_BYTES,
        &format!("run-{run}"),
    )?;
    if captured.timed_out {
        return Err(format!(
            "fixture execution timed out after {} seconds",
            RUN_TIMEOUT.as_secs()
        ));
    }
    if captured.stdout_truncated || captured.stderr_truncated {
        return Err(format!(
            "captured output exceeded {MAX_CAPTURE_BYTES} bytes"
        ));
    }
    if !captured.status.is_some_and(|status| status.success()) {
        return Err(format!(
            "fixture exited with status {}: {}",
            status_label(captured.status),
            captured.stderr.trim()
        ));
    }
    Ok(captured.stdout)
}

fn collect_versions(
    language: FixtureLanguage,
    tools: &Tools,
    directory: &Path,
) -> Vec<LibraryVersion> {
    let mut versions = Vec::new();
    let mut push = |name: &str, path: &Path| {
        if let Some(version) = tool_version(path, directory) {
            versions.push(LibraryVersion {
                name: name.to_owned(),
                version,
            });
        }
    };
    match language {
        FixtureLanguage::C => {
            push("cc", &tools.compiler);
            if let Some(linker) = &tools.linker {
                push("ld", linker);
            }
        }
        FixtureLanguage::Rust => {
            push("rustc", &tools.compiler);
            if let Some(cc) = &tools.cc {
                push("cc", cc);
            }
            if let Some(linker) = &tools.linker {
                push("ld", linker);
            }
        }
    }
    versions
}

fn tool_version(path: &Path, directory: &Path) -> Option<String> {
    let captured = run_capture(
        path,
        &[OsString::from("--version")],
        directory,
        Environment::Compiler,
        Duration::from_secs(5),
        4 * 1024,
        "version",
    )
    .ok()?;
    if captured.timed_out || !captured.status.is_some_and(|status| status.success()) {
        return None;
    }
    captured
        .stdout
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
}

fn build_transcript(
    case: &NativeCase,
    stdout: &str,
    provenance: &TranscriptProvenance,
) -> Result<(Vec<u8>, NativeEventTranscript), String> {
    let (mut events, synchronizes_with) = parse_stream(case, stdout)?;

    let mut threads = Vec::with_capacity(case.threads.len());
    for id in case.threads {
        threads.push(ThreadTrace {
            id: (*id).to_owned(),
            events: events.remove(*id).unwrap_or_default(),
        });
    }

    let objects = case
        .objects
        .iter()
        .map(|object| ObjectDecl {
            id: object.id.to_owned(),
            atomic: object.atomic,
        })
        .collect();

    let transcript = NativeEventTranscript {
        schema: crate::court::NATIVE_EVENT_TRANSCRIPT_SCHEMA.to_owned(),
        spec: crate::court::COURT_SPEC.to_owned(),
        provenance: provenance.clone(),
        objects,
        threads,
        synchronizes_with,
        requirements: build_requirements(case.requirements),
        recording: Some(RecordingMetadata {
            seed: Some(RECORDING_SEED),
            expected_event_count: Some(case.expected_event_count),
            schedule: Some(
                "scripted deterministic fixture schedule; two identical replays required"
                    .to_owned(),
            ),
        }),
        unknown_provider_edges: Vec::new(),
    };

    let value = serde_json::to_value(&transcript)
        .map_err(|error| format!("cannot encode transcript: {error}"))?;
    let bytes = canonical_bytes(&value)
        .map_err(|error| format!("cannot canonicalize transcript: {error}"))?;
    let parsed = parse_transcript(&bytes)
        .map_err(|error| format!("recorded transcript is invalid: {error}"))?;
    Ok((bytes, parsed))
}

type ParsedStream = (BTreeMap<&'static str, Vec<Event>>, Vec<SyncEdge>);

fn parse_stream(case: &NativeCase, stdout: &str) -> Result<ParsedStream, String> {
    let mut events: BTreeMap<&'static str, Vec<Event>> = case
        .threads
        .iter()
        .map(|thread| (*thread, Vec::new()))
        .collect();
    let mut synchronizes_with = Vec::new();

    for (line_number, line) in stdout.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut value = parse_strict(line.as_bytes())
            .map_err(|error| format!("line {}: invalid JSON: {error}", line_number + 1))?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| format!("line {}: event record must be an object", line_number + 1))?;
        let record = object
            .remove("record")
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| format!("line {}: missing record kind", line_number + 1))?;

        match record.as_str() {
            "event" => {
                let thread = object
                    .remove("thread")
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .ok_or_else(|| format!("line {}: missing thread", line_number + 1))?;
                let Some(buffer) = events.get_mut(thread.as_str()) else {
                    return Err(format!(
                        "line {}: undeclared thread {thread}",
                        line_number + 1
                    ));
                };
                let event: Event = serde_json::from_value(value)
                    .map_err(|error| format!("line {}: invalid event: {error}", line_number + 1))?;
                buffer.push(event);
            }
            "sync" => {
                let from_thread = take_string(object, "from_thread", line_number)?;
                let from_seq = take_u64(object, "from_seq", line_number)?;
                let to_thread = take_string(object, "to_thread", line_number)?;
                let to_seq = take_u64(object, "to_seq", line_number)?;
                synchronizes_with.push(SyncEdge {
                    from: EventRef {
                        thread: from_thread,
                        seq: from_seq,
                    },
                    to: EventRef {
                        thread: to_thread,
                        seq: to_seq,
                    },
                });
            }
            other => {
                return Err(format!(
                    "line {}: unknown record kind {other}",
                    line_number + 1
                ));
            }
        }
    }

    Ok((events, synchronizes_with))
}

fn take_string(
    object: &mut serde_json::Map<String, serde_json::Value>,
    field: &str,
    line_number: usize,
) -> Result<String, String> {
    object
        .remove(field)
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| format!("line {}: missing {field}", line_number + 1))
}

fn take_u64(
    object: &mut serde_json::Map<String, serde_json::Value>,
    field: &str,
    line_number: usize,
) -> Result<u64, String> {
    object
        .remove(field)
        .and_then(|value| value.as_u64())
        .ok_or_else(|| format!("line {}: missing or invalid {field}", line_number + 1))
}

fn build_requirements(spec: NativeRequirements) -> Option<TranscriptRequirements> {
    let requirements = TranscriptRequirements {
        required_creates: owned(spec.required_creates),
        required_frees: owned(spec.required_frees),
        required_borrow_ends: owned(spec.required_borrow_ends),
        required_generation_transitions: owned(spec.required_generation_transitions),
        required_callbacks: owned(spec.required_callbacks),
    };
    if requirements.required_creates.is_empty()
        && requirements.required_frees.is_empty()
        && requirements.required_borrow_ends.is_empty()
        && requirements.required_generation_transitions.is_empty()
        && requirements.required_callbacks.is_empty()
    {
        None
    } else {
        Some(requirements)
    }
}

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

struct Captured {
    stdout: String,
    stderr: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
    status: Option<ExitStatus>,
    timed_out: bool,
}

#[derive(Debug, Clone, Copy)]
enum Environment {
    Cleared,
    Compiler,
}

#[allow(clippy::too_many_arguments)]
fn run_capture(
    program: &Path,
    args: &[OsString],
    directory: &Path,
    environment: Environment,
    timeout: Duration,
    limit: usize,
    label: &str,
) -> Result<Captured, String> {
    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    let stdout_path = directory.join(format!("{label}-{sequence}.stdout"));
    let stderr_path = directory.join(format!("{label}-{sequence}.stderr"));
    let stdout_file = open_private(&stdout_path)?;
    let stderr_file = open_private(&stderr_path)?;

    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .process_group(0);
    command.env_clear();
    if matches!(environment, Environment::Compiler) {
        command
            .env("PATH", COMPILER_PATH)
            .env("HOME", directory)
            .env("TMPDIR", directory);
        if let Some(home) = compiler_rustup_home() {
            command.env("RUSTUP_HOME", home);
        }
        if let Some(channel) = rust_toolchain_channel() {
            command.env("RUSTUP_TOOLCHAIN", channel);
        }
    }

    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot spawn {}: {error}", program.display()))?;
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    break child.wait().ok();
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("cannot wait for {}: {error}", program.display()));
            }
        }
    };

    let (stdout, stdout_truncated) = read_bounded(&stdout_path, limit)?;
    let (stderr, stderr_truncated) = read_bounded(&stderr_path, limit)?;
    Ok(Captured {
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        status,
        timed_out,
    })
}

fn compiler_rustup_home() -> Option<OsString> {
    if let Some(home) = std::env::var_os("RUSTUP_HOME") {
        return Some(home);
    }
    let default = Path::new("/usr/local/rustup");
    if default.is_dir() {
        return Some(default.as_os_str().to_owned());
    }
    None
}

fn rust_toolchain_channel() -> Option<&'static str> {
    for line in RUST_TOOLCHAIN_FILE.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "channel" {
            continue;
        }
        let value = value.trim();
        if let Some(value) = value.strip_prefix('"') {
            if let Some(value) = value.strip_suffix('"') {
                return Some(value);
            }
        }
    }
    None
}

fn open_private(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))
}

fn read_bounded(path: &Path, limit: usize) -> Result<(String, bool), String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
    let size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    let mut file =
        File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let mut buffer = Vec::new();
    file.by_ref()
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut buffer)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let truncated = size > limit || buffer.len() > limit;
    if buffer.len() > limit {
        buffer.truncate(limit);
    }
    Ok((String::from_utf8_lossy(&buffer).into_owned(), truncated))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    Ok(sha256_bytes(&bytes))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

fn status_label(status: Option<ExitStatus>) -> String {
    match status {
        Some(status) => match (status.code(), status.signal()) {
            (Some(code), _) => format!("exit {code}"),
            (None, Some(signal)) => format!("signal {signal}"),
            (None, None) => "unknown".to_owned(),
        },
        None => "unknown".to_owned(),
    }
}

struct PrivateDir {
    path: PathBuf,
}

impl PrivateDir {
    fn new(label: &str) -> Result<Self, String> {
        let base = std::env::temp_dir();
        for _ in 0..16 {
            let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = base.join(format!(
                "frf-native-{label}-{}-{sequence}-{nanos}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(
                        |error| format!("cannot set 0700 on {}: {error}", path.display()),
                    )?;
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(format!("cannot create {}: {error}", path.display())),
            }
        }
        Err("could not allocate a unique private temp directory".to_owned())
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
