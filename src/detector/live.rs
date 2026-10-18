//! Live Phase 5.2 detector adapters.
//!
//! Every adapter runs a **closed, checked-in fixture** through an external
//! instrument. There is no API for caller-supplied source, arbitrary input, an
//! arbitrary executable, or a shell. Each execution uses an explicit argv
//! vector, a private `0700` temporary directory, `0600` capture files, a
//! cleared fixture environment, null stdin, its own process group, a wall-clock
//! bound, and a bounded stdout/stderr capture. The captured text, its SHA-256,
//! the exit status, the signal, and the duration are placed directly into the
//! Phase 5.1 [`DetectorEvidence`](super::DetectorEvidence) shape.
//!
//! # Claim ceiling
//!
//! A live calibration establishes only that the named checked-in fixture was
//! compiled (where applicable) and executed by the recorded tool identity in
//! this run, that the recorded stdout/stderr was captured within the declared
//! bounds, that a known-bad case produced the declared mechanism-specific
//! diagnostic fingerprint with a nonzero exit, and that the harmless control
//! produced no finding and exited zero. It does **not** establish memory safety,
//! soundness, universal detector sensitivity or specificity, coverage of
//! another input/flags/target/build, cryptographic constant-time behavior,
//! native FFI behavior, or any `SAFE_COMPATIBLE` result. Digests bind this run;
//! they are not signatures or attestations. A tool that cannot be installed or
//! run is reported as a typed `NOT_RUN` with the exact reason, never as a pass.
//!
//! # Enablement
//!
//! Live execution is opt-in through [`LIVE_ENV`] (`FRF_DETECTOR_LIVE=1`). The
//! default source gate leaves it unset and exercises the typed `NOT_RUN` path.

#![allow(clippy::module_name_repetitions)]

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

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{
    evaluate_calibration, BuildIdentity, CalibrationCase, CalibrationOutcome, CalibrationReport,
    CalibrationRole, CaptureStream, CapturedStream, CaseProvenance, DetectorAvailability,
    DetectorEvidence, DetectorIdentity, DetectorOrigin, ObservedFinding, RawCapture,
    CALIBRATION_CLAIM_CEILING, DETECTOR_EVIDENCE_SCHEMA, DETECTOR_SPEC, MAX_CAPTURE_BYTES,
};
use crate::court::CaseLegality;
use crate::identity::hex_lower;
use crate::model::DetectorKind;

/// Environment flag that enables live detector execution.
pub const LIVE_ENV: &str = "FRF_DETECTOR_LIVE";

/// Pinned nightly toolchain used for Miri.
pub const MIRI_TOOLCHAIN: &str = "nightly-2025-02-20";

/// Stable identifier of the OpenSSL known-answer detector kind.
pub const OPENSSL_KAT_ID: &str = "openssl-sha256-kat";

/// Typed `NOT_RUN` schema for the live CLI.
pub const LIVE_NOT_RUN_SCHEMA: &str = "frf-memorysafety.live-detector-not-run.v1";

/// Claim ceiling embedded in a typed live `NOT_RUN` response.
pub const LIVE_NOT_RUN_CLAIM_CEILING: &str = "NOT_RUN means the instrument or its checked-in fixture could not be executed in this environment. It is not an empty successful calibration and it establishes no detector sensitivity or specificity.";

/// NIST FIPS 180-4 SHA-256 known-answer vector for the three-byte message
/// `abc`.
pub const SHA256_ABC_DIGEST: &str =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

const FIXTURES: &str = "tests/detector/fixtures";
const COMPILER_PATH: &str = "/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin";
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const COMPILE_TIMEOUT: Duration = Duration::from_secs(180);
const RUN_TIMEOUT: Duration = Duration::from_secs(20);
const TOOL_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_COMPILER_OUTPUT: usize = 64 * 1024;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Status of one live calibration attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveStatus {
    /// The live mechanism ran and every control passed.
    Calibrated,
    /// The live mechanism ran but at least one control failed.
    Refused,
    /// The instrument or fixture was unavailable. This is never a pass.
    NotRun,
}

impl LiveStatus {
    /// Stable lower-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Calibrated => "calibrated",
            Self::Refused => "refused",
            Self::NotRun => "not_run",
        }
    }
}

/// Result of one live calibration attempt.
#[derive(Debug, Clone)]
pub struct LiveCalibration {
    /// Detector kind that was requested.
    pub detector: DetectorKind,
    /// Typed outcome.
    pub status: LiveStatus,
    /// Exact reason for `NOT_RUN`, when applicable.
    pub reason: Option<String>,
    /// Real evidence, when the mechanism ran.
    pub evidence: Option<DetectorEvidence>,
    /// Deterministic calibration report, when the mechanism ran.
    pub report: Option<CalibrationReport>,
}

impl LiveCalibration {
    /// Whether the mechanism was not run.
    #[must_use]
    pub const fn is_not_run(&self) -> bool {
        matches!(self.status, LiveStatus::NotRun)
    }

    fn not_run(detector: DetectorKind, reason: impl Into<String>) -> Self {
        Self {
            detector,
            status: LiveStatus::NotRun,
            reason: Some(reason.into()),
            evidence: None,
            report: None,
        }
    }
}

/// Whether live detector execution is enabled by [`LIVE_ENV`].
#[must_use]
pub fn live_enabled() -> bool {
    std::env::var(LIVE_ENV).is_ok_and(|value| value == "1")
}

/// Parse a CLI detector selector into a built-in live detector kind.
///
/// The OpenSSL known-answer adapter uses the custom kind
/// [`OPENSSL_KAT_ID`] because a SHA-256 known-answer test is not a
/// constant-time leakage oracle and must not be labelled `constant_time`.
#[must_use]
pub fn parse_detector_kind(value: &str) -> Option<DetectorKind> {
    match value {
        "miri" => Some(DetectorKind::Miri),
        "asan" | "address" | "address_sanitizer" | "address-sanitizer" => {
            Some(DetectorKind::AddressSanitizer)
        }
        "lsan" | "leak" | "leak_sanitizer" | "leak-sanitizer" => Some(DetectorKind::LeakSanitizer),
        "tsan" | "thread" | "thread_sanitizer" | "thread-sanitizer" => {
            Some(DetectorKind::ThreadSanitizer)
        }
        "loom" => Some(DetectorKind::Loom),
        "kani" => Some(DetectorKind::Kani),
        "crypto" | "openssl" | "crypto_secret_oracle" | "crypto-secret-oracle" => {
            Some(DetectorKind::Custom(OPENSSL_KAT_ID.to_owned()))
        }
        _ => None,
    }
}

/// All detector kinds that have a built-in live fixture.
#[must_use]
pub fn supported_kinds() -> Vec<DetectorKind> {
    vec![
        DetectorKind::Miri,
        DetectorKind::AddressSanitizer,
        DetectorKind::LeakSanitizer,
        DetectorKind::ThreadSanitizer,
        DetectorKind::Loom,
        DetectorKind::Kani,
        DetectorKind::Custom(OPENSSL_KAT_ID.to_owned()),
    ]
}

/// Probe every built-in detector for runtime availability.
///
/// Probes execute only a bounded `--version` style command with a minimal
/// environment. They never run a fixture and never accept caller input.
#[must_use]
pub fn availability() -> Vec<DetectorAvailability> {
    vec![
        availability_miri(),
        availability_gcc("asan", DetectorKind::AddressSanitizer, "address"),
        availability_gcc("lsan", DetectorKind::LeakSanitizer, "leak"),
        availability_gcc("tsan", DetectorKind::ThreadSanitizer, "thread"),
        availability_cargo("loom", DetectorKind::Loom),
        availability_kani(),
        availability_openssl(),
    ]
}

/// Run one built-in live calibration.
///
/// The function never fabricates a result: absent tools, refused network
/// fetches, unsupported runtimes, timeouts, and oversized captures are typed
/// [`LiveStatus::NotRun`] with the exact reason. A tool that runs but fails a
/// control yields [`LiveStatus::Refused`] with a calibration report.
#[must_use]
pub fn calibrate_live(kind: &DetectorKind) -> LiveCalibration {
    if !live_enabled() {
        return LiveCalibration::not_run(
            kind.clone(),
            format!("live detector execution is disabled; set {LIVE_ENV}=1"),
        );
    }
    match kind {
        DetectorKind::Miri => live_miri(),
        DetectorKind::AddressSanitizer => live_sanitizer(&ASAN),
        DetectorKind::LeakSanitizer => live_sanitizer(&LSAN),
        DetectorKind::ThreadSanitizer => live_sanitizer(&TSAN),
        DetectorKind::Loom => live_loom(),
        DetectorKind::Kani => live_kani(),
        DetectorKind::Custom(name) if name == OPENSSL_KAT_ID => live_openssl(),
        other => {
            LiveCalibration::not_run(other.clone(), "detector kind has no built-in live fixture")
        }
    }
}

#[derive(Debug, Clone)]
struct SanitizerSpec {
    id: &'static str,
    kind: DetectorKind,
    mechanism: &'static str,
    flag: &'static str,
    extra_flags: &'static [&'static str],
    env_key: &'static str,
    env_value: &'static str,
    bad_fixture: &'static str,
    good_fixture: &'static str,
    fingerprint: &'static str,
}

const ASAN: SanitizerSpec = SanitizerSpec {
    id: "asan",
    kind: DetectorKind::AddressSanitizer,
    mechanism: "address",
    flag: "-fsanitize=address",
    extra_flags: &["-fno-omit-frame-pointer"],
    env_key: "ASAN_OPTIONS",
    env_value: "detect_leaks=0:halt_on_error=1:abort_on_error=0",
    bad_fixture: "c/asan_use_after_free.c",
    good_fixture: "c/asan_clean.c",
    fingerprint: "AddressSanitizer: heap-use-after-free",
};

const LSAN: SanitizerSpec = SanitizerSpec {
    id: "lsan",
    kind: DetectorKind::LeakSanitizer,
    mechanism: "leak",
    flag: "-fsanitize=leak",
    extra_flags: &[],
    env_key: "LSAN_OPTIONS",
    env_value: "exitcode=23:report_objects=0",
    bad_fixture: "c/lsan_leak.c",
    good_fixture: "c/lsan_clean.c",
    fingerprint: "LeakSanitizer: detected memory leaks",
};

const TSAN: SanitizerSpec = SanitizerSpec {
    id: "tsan",
    kind: DetectorKind::ThreadSanitizer,
    mechanism: "data_race",
    flag: "-fsanitize=thread",
    extra_flags: &["-pthread"],
    env_key: "TSAN_OPTIONS",
    env_value: "halt_on_error=1:exitcode=66",
    bad_fixture: "c/tsan_data_race.c",
    good_fixture: "c/tsan_atomic_control.c",
    fingerprint: "ThreadSanitizer: data race",
};

fn availability_miri() -> DetectorAvailability {
    availability_probe(
        "miri",
        DetectorKind::Miri,
        "cargo",
        &["+nightly-2025-02-20", "miri", "--version"],
    )
}

fn availability_gcc(id: &'static str, kind: DetectorKind, mechanism: &str) -> DetectorAvailability {
    match probe_tool("gcc", &["--version"], &probe_env()) {
        Ok(version) => DetectorAvailability {
            id,
            kind,
            status: "available",
            detail: format!(
                "{version}; live compilation and execution are required to confirm {mechanism} \
                 sanitizer support on this target"
            ),
        },
        Err(reason) => DetectorAvailability {
            id,
            kind,
            status: "not_run",
            detail: format!("gcc is unavailable: {reason}"),
        },
    }
}

fn availability_cargo(id: &'static str, kind: DetectorKind) -> DetectorAvailability {
    availability_probe(id, kind, "cargo", &["--version"])
}

fn availability_kani() -> DetectorAvailability {
    availability_probe("kani", DetectorKind::Kani, "kani", &["--version"])
}

fn availability_openssl() -> DetectorAvailability {
    availability_probe(
        "crypto",
        DetectorKind::Custom(OPENSSL_KAT_ID.to_owned()),
        "openssl",
        &["version"],
    )
}

fn availability_probe(
    id: &'static str,
    kind: DetectorKind,
    program: &str,
    args: &[&str],
) -> DetectorAvailability {
    let env = if program == "kani" {
        kani_env(probe_env())
    } else {
        probe_env()
    };
    match probe_tool(program, args, &env) {
        Ok(version) => DetectorAvailability {
            id,
            kind,
            status: "available",
            detail: version,
        },
        Err(reason) => DetectorAvailability {
            id,
            kind,
            status: "not_run",
            detail: reason,
        },
    }
}

fn probe_tool(
    program: &str,
    args: &[&str],
    env: &BTreeMap<String, String>,
) -> Result<String, String> {
    let Some(path) = find_tool(program) else {
        return Err(format!("{program} is not installed or not on PATH"));
    };
    let arguments: Vec<OsString> = args.iter().map(OsString::from).collect();
    let captured = run_capture(
        &path,
        &arguments,
        None,
        env,
        PROBE_TIMEOUT,
        MAX_COMPILER_OUTPUT,
        "probe",
    )?;
    if captured.timed_out {
        return Err(format!(
            "{program} did not answer within {} seconds",
            PROBE_TIMEOUT.as_secs()
        ));
    }
    if captured.exit_code != 0 {
        let detail = first_nonempty(&captured.stderr)
            .or_else(|| first_nonempty(&captured.stdout))
            .unwrap_or_else(|| format!("exit {}", captured.exit_code));
        return Err(format!("{program} probe failed: {detail}"));
    }
    first_nonempty(&captured.stdout)
        .or_else(|| first_nonempty(&captured.stderr))
        .ok_or_else(|| format!("{program} probe produced no version text"))
}

#[allow(clippy::too_many_lines)]
fn live_sanitizer(spec: &SanitizerSpec) -> LiveCalibration {
    let detector = spec.kind.clone();
    let Some(gcc) = find_tool("gcc") else {
        return LiveCalibration::not_run(detector, "gcc is not installed");
    };
    let probe_env = probe_env();
    let version = match probe_tool("gcc", &["--version"], &probe_env) {
        Ok(version) => version,
        Err(reason) => return LiveCalibration::not_run(spec.kind.clone(), reason),
    };
    let target = match probe_tool("gcc", &["-dumpmachine"], &probe_env) {
        Ok(target) => target,
        Err(reason) => return LiveCalibration::not_run(spec.kind.clone(), reason),
    };

    let fixtures = fixtures_root();
    let bad_source = fixtures.join(spec.bad_fixture);
    let good_source = fixtures.join(spec.good_fixture);
    let bad_fixture_digest = match sha256_file(&bad_source) {
        Ok(digest) => digest,
        Err(reason) => return LiveCalibration::not_run(spec.kind.clone(), reason),
    };
    let good_fixture_digest = match sha256_file(&good_source) {
        Ok(digest) => digest,
        Err(reason) => return LiveCalibration::not_run(spec.kind.clone(), reason),
    };

    let session = match PrivateDir::new(&format!("sanitizer-{}", spec.id)) {
        Ok(session) => session,
        Err(reason) => return LiveCalibration::not_run(spec.kind.clone(), reason),
    };
    let instrumented_dir = session.path().join("instrumented");
    let baseline_dir = session.path().join("baseline");
    let run_dir = session.path().join("run");
    for directory in [&instrumented_dir, &baseline_dir, &run_dir] {
        if let Err(reason) = create_private_dir(directory) {
            return LiveCalibration::not_run(spec.kind.clone(), reason);
        }
    }

    let build_env = compiler_env(session.path());
    let instrumented_flags = instrumented_flags(spec);
    let baseline_flags = baseline_flags(spec);
    let bad_instrumented = instrumented_dir.join("bad");
    let good_instrumented = instrumented_dir.join("good");
    let bad_baseline = baseline_dir.join("bad");
    let good_baseline = baseline_dir.join("good");
    for (source, output, flags) in [
        (&bad_source, &bad_instrumented, &instrumented_flags),
        (&good_source, &good_instrumented, &instrumented_flags),
        (&bad_source, &bad_baseline, &baseline_flags),
        (&good_source, &good_baseline, &baseline_flags),
    ] {
        let directory = output.parent().unwrap_or(session.path());
        if let Err(reason) = compile_c(&gcc, source, output, directory, &build_env, flags) {
            return LiveCalibration::not_run(spec.kind.clone(), reason);
        }
    }

    let build_artifact = match sha256_file(&bad_instrumented) {
        Ok(digest) => digest,
        Err(reason) => return LiveCalibration::not_run(spec.kind.clone(), reason),
    };
    let baseline_artifact = match sha256_file(&bad_baseline) {
        Ok(digest) => digest,
        Err(reason) => return LiveCalibration::not_run(spec.kind.clone(), reason),
    };
    let build_directory = format!("live/{}/instrumented", spec.id);
    let baseline_directory = format!("live/{}/baseline", spec.id);
    let build_separation_verified = build_directory != baseline_directory
        && build_artifact != baseline_artifact
        && !is_zero_digest(&build_artifact)
        && !is_zero_digest(&baseline_artifact)
        && instrumented_flags.iter().any(|flag| *flag == spec.flag)
        && !baseline_flags.iter().any(|flag| *flag == spec.flag);

    let fixture_env = fixture_env(spec);
    let bad_capture = match run_fixture(&bad_instrumented, &run_dir, &fixture_env, "known-bad") {
        Ok(capture) => capture,
        Err(reason) => return LiveCalibration::not_run(spec.kind.clone(), reason),
    };
    let good_capture = match run_fixture(&good_instrumented, &run_dir, &fixture_env, "control") {
        Ok(capture) => capture,
        Err(reason) => return LiveCalibration::not_run(spec.kind.clone(), reason),
    };

    if let Some(reason) = sanitizer_environment_failure(spec, &bad_capture, &good_capture) {
        return LiveCalibration::not_run(spec.kind.clone(), reason);
    }

    let bad_finding = ObservedFinding {
        mechanism: spec.mechanism.to_owned(),
        diagnostic_fingerprint: spec.fingerprint.to_owned(),
        source: stream_containing(&bad_capture, spec.fingerprint),
    };
    let bad_case = build_case(
        &format!("{}-known-bad", spec.id),
        CalibrationRole::KnownBad,
        bad_fixture_digest,
        spec.mechanism,
        &bad_capture,
        Some(bad_finding),
    );
    let good_case = build_case(
        &format!("{}-harmless-control", spec.id),
        CalibrationRole::KnownGood,
        good_fixture_digest,
        spec.mechanism,
        &good_capture,
        None,
    );

    let identity = DetectorIdentity {
        kind: spec.kind.clone(),
        tool_name: format!("gcc-{}", spec.id),
        tool_version: version,
        executable_sha256: build_artifact.clone(),
        invocation_argv: vec![bad_instrumented.display().to_string()],
        environment_digest: environment_digest(&fixture_env),
        mechanism_enablement: vec![
            spec.mechanism.to_owned(),
            spec.flag.trim_start_matches("-fsanitize=").to_owned(),
        ],
        build: BuildIdentity {
            flags: instrumented_flags
                .iter()
                .map(|flag| (*flag).to_owned())
                .collect(),
            target: target.clone(),
            profile: "c11-O1".to_owned(),
            build_directory,
            artifact_sha256: build_artifact,
        },
        baseline_build: BuildIdentity {
            flags: baseline_flags
                .iter()
                .map(|flag| (*flag).to_owned())
                .collect(),
            target,
            profile: "c11-O1".to_owned(),
            build_directory: baseline_directory,
            artifact_sha256: baseline_artifact,
        },
        build_separation_verified,
    };
    finish(spec.kind.clone(), identity, vec![bad_case, good_case])
}

// Small helper so the compile loop can choose the directory that owns `output`.

fn instrumented_flags(spec: &SanitizerSpec) -> Vec<&'static str> {
    let mut flags = vec!["-std=c11", spec.flag];
    flags.extend(spec.extra_flags.iter().copied());
    flags.push("-g");
    flags.push("-O1");
    flags
}

fn baseline_flags(spec: &SanitizerSpec) -> Vec<&'static str> {
    let mut flags = vec!["-std=c11"];
    flags.extend(spec.extra_flags.iter().copied());
    flags.push("-g");
    flags.push("-O1");
    flags
}

fn compile_c(
    gcc: &Path,
    source: &Path,
    output: &Path,
    directory: &Path,
    env: &BTreeMap<String, String>,
    flags: &[&str],
) -> Result<(), String> {
    let mut arguments: Vec<OsString> = flags.iter().map(OsString::from).collect();
    arguments.push(source.as_os_str().to_owned());
    arguments.push(OsString::from("-o"));
    arguments.push(output.as_os_str().to_owned());
    let captured = run_capture(
        gcc,
        &arguments,
        Some(directory),
        env,
        COMPILE_TIMEOUT,
        MAX_COMPILER_OUTPUT,
        "compile",
    )?;
    if captured.timed_out {
        return Err(format!(
            "gcc compilation timed out after {} seconds",
            COMPILE_TIMEOUT.as_secs()
        ));
    }
    if captured.exit_code != 0 {
        return Err(format!(
            "gcc compilation failed: {}",
            first_nonempty(&captured.stderr).unwrap_or_else(|| "unknown error".to_owned())
        ));
    }
    Ok(())
}

fn run_fixture(
    executable: &Path,
    directory: &Path,
    env: &BTreeMap<String, String>,
    label: &str,
) -> Result<Captured, String> {
    let captured = run_capture(
        executable,
        &[],
        Some(directory),
        env,
        RUN_TIMEOUT,
        MAX_CAPTURE_BYTES,
        label,
    )?;
    if captured.timed_out {
        return Err(format!(
            "{label} timed out after {} seconds",
            RUN_TIMEOUT.as_secs()
        ));
    }
    if captured.stdout_truncated || captured.stderr_truncated {
        return Err(format!(
            "{label} produced output beyond the {MAX_CAPTURE_BYTES}-byte capture limit"
        ));
    }
    Ok(captured)
}

fn fixture_env(spec: &SanitizerSpec) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert(spec.env_key.to_owned(), spec.env_value.to_owned());
    env
}

fn sanitizer_environment_failure(
    spec: &SanitizerSpec,
    bad: &Captured,
    good: &Captured,
) -> Option<String> {
    let bad_text = format!("{}\n{}", bad.stdout, bad.stderr);
    let good_text = format!("{}\n{}", good.stdout, good.stderr);
    let markers = [
        "FATAL: ThreadSanitizer",
        "can not mmap the shadow memory",
        "unexpected memory mapping",
        "Shadow memory range interleaves",
        "ASan runtime does not come first",
        "LeakSanitizer has encountered a fatal error",
        "failed to allocate",
        "cannot allocate memory",
    ];
    if !bad_text.contains(spec.fingerprint) {
        if let Some(marker) = markers.iter().find(|marker| bad_text.contains(**marker)) {
            return Some(format!(
                "{} runtime is unavailable in this environment: {marker}",
                spec.id
            ));
        }
    }
    if let Some(marker) = markers.iter().find(|marker| good_text.contains(**marker)) {
        return Some(format!(
            "{} runtime is unavailable in this environment: {marker}",
            spec.id
        ));
    }
    None
}

#[allow(clippy::too_many_lines)]
fn live_miri() -> LiveCalibration {
    let detector = DetectorKind::Miri;
    let Some(cargo) = find_tool("cargo") else {
        return LiveCalibration::not_run(detector, "cargo is not installed");
    };
    let cargo_sha256 = match sha256_file(&cargo) {
        Ok(digest) => digest,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let Some(rustup) = find_tool("rustup") else {
        return LiveCalibration::not_run(detector, "rustup is not installed");
    };
    let session = match PrivateDir::new("miri") {
        Ok(session) => session,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let probe = probe_env();
    let version = match probe_tool(
        "cargo",
        &["+nightly-2025-02-20", "miri", "--version"],
        &probe,
    ) {
        Ok(version) => version,
        Err(reason) => {
            return LiveCalibration::not_run(
                detector,
                format!("pinned Miri toolchain {MIRI_TOOLCHAIN} is unavailable: {reason}"),
            );
        }
    };
    let fixture_source = fixtures_root().join("miri");
    let crate_dir = session.path().join("fixture");
    if let Err(reason) = copy_tree(&fixture_source, &crate_dir) {
        return LiveCalibration::not_run(detector, reason);
    }
    let mut env = compiler_env(session.path());
    env.insert("RUSTUP_HOME".to_owned(), rustup_home());
    env.insert("CARGO_HOME".to_owned(), cargo_home());
    env.insert("RUSTUP_TOOLCHAIN".to_owned(), MIRI_TOOLCHAIN.to_owned());

    let setup = match run_capture(
        &cargo,
        &["+nightly-2025-02-20", "miri", "setup"].map(OsString::from),
        Some(&crate_dir),
        &env,
        TOOL_TIMEOUT,
        MAX_COMPILER_OUTPUT,
        "miri-setup",
    ) {
        Ok(capture) => capture,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    if setup.timed_out {
        return LiveCalibration::not_run(
            detector,
            format!(
                "cargo miri setup timed out after {} seconds",
                TOOL_TIMEOUT.as_secs()
            ),
        );
    }
    if setup.exit_code != 0 {
        return LiveCalibration::not_run(
            detector,
            format!(
                "cargo miri setup failed: {}",
                first_nonempty(&setup.stderr).unwrap_or_else(|| "unknown error".to_owned())
            ),
        );
    }

    let bad_capture = match run_miri_binary(&cargo, &crate_dir, &env, session.path(), "ub") {
        Ok(capture) => capture,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let clean_capture = match run_miri_binary(&cargo, &crate_dir, &env, session.path(), "clean") {
        Ok(capture) => capture,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let harmless_capture =
        match run_miri_binary(&cargo, &crate_dir, &env, session.path(), "harmless") {
            Ok(capture) => capture,
            Err(reason) => return LiveCalibration::not_run(detector, reason),
        };

    if let Some(reason) = miri_environment_failure(&bad_capture, &clean_capture, &harmless_capture)
    {
        return LiveCalibration::not_run(detector, reason);
    }

    let target = match rustc_host(&cargo, &env) {
        Ok(target) => target,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let Some(rustc) = find_tool("rustc") else {
        return LiveCalibration::not_run(detector, "rustc is not installed");
    };
    let baseline_dir = session.path().join("baseline");
    if let Err(reason) = create_private_dir(&baseline_dir) {
        return LiveCalibration::not_run(detector, reason);
    }
    let baseline_binary = baseline_dir.join("clean");
    let baseline_source = crate_dir.join("clean.rs");
    let baseline_flags = ["--edition=2021", "-C", "opt-level=0"];
    if let Err(reason) = compile_rust(
        &rustc,
        &baseline_source,
        &baseline_binary,
        &baseline_dir,
        &env,
        &baseline_flags,
    ) {
        return LiveCalibration::not_run(detector, reason);
    }
    let baseline_artifact = match sha256_file(&baseline_binary) {
        Ok(digest) => digest,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let miri_executable = resolve_miri_executable(&rustup, &cargo, &env, session.path());
    let miri_driver_sha256 = match sha256_file(&miri_executable) {
        Ok(digest) => digest,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let build_directory = "live/miri/interpreter".to_owned();
    let baseline_directory = "live/miri/native".to_owned();
    let build_separation_verified = build_directory != baseline_directory
        && miri_driver_sha256 != baseline_artifact
        && !is_zero_digest(&miri_driver_sha256)
        && !is_zero_digest(&baseline_artifact);

    let bad_case = build_case(
        "miri-known-bad",
        CalibrationRole::KnownBad,
        fixture_digest(&fixture_source.join("ub.rs")),
        "stacked_borrows",
        &bad_capture,
        Some(ObservedFinding {
            mechanism: "stacked_borrows".to_owned(),
            diagnostic_fingerprint: "Undefined Behavior".to_owned(),
            source: stream_containing(&bad_capture, "Undefined Behavior"),
        }),
    );
    let clean_case = build_case(
        "miri-clean-control",
        CalibrationRole::KnownGood,
        fixture_digest(&fixture_source.join("clean.rs")),
        "stacked_borrows",
        &clean_capture,
        None,
    );
    let harmless_case = build_case(
        "miri-harmless-control",
        CalibrationRole::KnownGood,
        fixture_digest(&fixture_source.join("harmless.rs")),
        "stacked_borrows",
        &harmless_capture,
        None,
    );

    let identity = DetectorIdentity {
        kind: DetectorKind::Miri,
        tool_name: "cargo-miri".to_owned(),
        tool_version: version,
        executable_sha256: cargo_sha256,
        invocation_argv: miri_argv("ub", &session.path().join("target-ub"))
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect(),
        environment_digest: environment_digest(&env),
        mechanism_enablement: vec!["miri".to_owned(), "stacked-borrows".to_owned()],
        build: BuildIdentity {
            flags: vec![
                "cargo-miri".to_owned(),
                "+nightly-2025-02-20".to_owned(),
                "stacked-borrows(default)".to_owned(),
            ],
            target: target.clone(),
            profile: "miri-debug".to_owned(),
            build_directory,
            artifact_sha256: miri_driver_sha256,
        },
        baseline_build: BuildIdentity {
            flags: baseline_flags
                .iter()
                .map(|flag| (*flag).to_owned())
                .collect(),
            target,
            profile: "miri-debug".to_owned(),
            build_directory: baseline_directory,
            artifact_sha256: baseline_artifact,
        },
        build_separation_verified,
    };
    finish(
        DetectorKind::Miri,
        identity,
        vec![bad_case, clean_case, harmless_case],
    )
}

fn miri_argv(binary: &str, target_dir: &Path) -> Vec<OsString> {
    vec![
        OsString::from(format!("+{MIRI_TOOLCHAIN}")),
        OsString::from("miri"),
        OsString::from("run"),
        OsString::from("--bin"),
        OsString::from(binary),
        OsString::from("--target-dir"),
        target_dir.as_os_str().to_owned(),
    ]
}

fn run_miri_binary(
    cargo: &Path,
    crate_dir: &Path,
    env: &BTreeMap<String, String>,
    root: &Path,
    binary: &str,
) -> Result<Captured, String> {
    let target_dir = root.join(format!("target-{binary}"));
    let arguments = miri_argv(binary, &target_dir);
    let captured = run_capture(
        cargo,
        &arguments,
        Some(crate_dir),
        env,
        TOOL_TIMEOUT,
        MAX_CAPTURE_BYTES,
        &format!("miri-{binary}"),
    )?;
    if captured.timed_out {
        return Err(format!(
            "cargo miri run --bin {binary} timed out after {} seconds",
            TOOL_TIMEOUT.as_secs()
        ));
    }
    if captured.stdout_truncated || captured.stderr_truncated {
        return Err(format!(
            "cargo miri run --bin {binary} exceeded the {MAX_CAPTURE_BYTES}-byte capture limit"
        ));
    }
    Ok(captured)
}

fn miri_environment_failure(
    bad: &Captured,
    clean: &Captured,
    harmless: &Captured,
) -> Option<String> {
    let bad_text = format!("{}\n{}", bad.stdout, bad.stderr);
    let clean_text = format!("{}\n{}", clean.stdout, clean.stderr);
    let harmless_text = format!("{}\n{}", harmless.stdout, harmless.stderr);
    let markers = [
        "can't call foreign function",
        "unsupported operation",
        "toolchain 'nightly-2025-02-20' is not installed",
        "failed to install",
        "could not download",
        "error: failed to get",
        "no matching package",
        "linker `cc` not found",
        "can't find crate",
        "cannot find crate",
    ];
    if !bad_text.contains("Undefined Behavior") {
        if let Some(marker) = markers.iter().find(|marker| bad_text.contains(**marker)) {
            return Some(format!("Miri is unavailable in this environment: {marker}"));
        }
    }
    if let Some(marker) = markers
        .iter()
        .find(|marker| clean_text.contains(**marker) || harmless_text.contains(**marker))
    {
        return Some(format!("Miri is unavailable in this environment: {marker}"));
    }
    None
}

fn resolve_miri_executable(
    rustup: &Path,
    cargo: &Path,
    env: &BTreeMap<String, String>,
    root: &Path,
) -> PathBuf {
    let arguments = ["which", "cargo-miri", "--toolchain", MIRI_TOOLCHAIN].map(OsString::from);
    if let Ok(captured) = run_capture(
        rustup,
        &arguments,
        Some(root),
        env,
        PROBE_TIMEOUT,
        MAX_COMPILER_OUTPUT,
        "miri-which",
    ) {
        if captured.exit_code == 0 {
            if let Some(line) = first_nonempty(&captured.stdout) {
                let path = PathBuf::from(line.trim());
                if path.is_file() {
                    return path;
                }
            }
        }
    }
    cargo.to_path_buf()
}

fn rustc_host(cargo: &Path, env: &BTreeMap<String, String>) -> Result<String, String> {
    let captured = run_capture(
        cargo,
        &[OsString::from("-vV")],
        None,
        env,
        PROBE_TIMEOUT,
        MAX_COMPILER_OUTPUT,
        "cargo-host",
    )?;
    if captured.exit_code != 0 {
        return Err("cargo -vV failed while resolving the host target".to_owned());
    }
    for line in captured.stdout.lines().chain(captured.stderr.lines()) {
        if let Some(host) = line.strip_prefix("host: ") {
            let host = host.trim();
            if !host.is_empty() {
                return Ok(host.to_owned());
            }
        }
    }
    Err("cargo -vV did not report a host target".to_owned())
}

fn compile_rust(
    rustc: &Path,
    source: &Path,
    output: &Path,
    directory: &Path,
    env: &BTreeMap<String, String>,
    flags: &[&str],
) -> Result<(), String> {
    let mut arguments: Vec<OsString> = flags.iter().map(OsString::from).collect();
    arguments.push(source.as_os_str().to_owned());
    arguments.push(OsString::from("-o"));
    arguments.push(output.as_os_str().to_owned());
    let captured = run_capture(
        rustc,
        &arguments,
        Some(directory),
        env,
        COMPILE_TIMEOUT,
        MAX_COMPILER_OUTPUT,
        "rustc",
    )?;
    if captured.timed_out {
        return Err(format!(
            "rustc baseline compilation timed out after {} seconds",
            COMPILE_TIMEOUT.as_secs()
        ));
    }
    if captured.exit_code != 0 {
        return Err(format!(
            "rustc baseline compilation failed: {}",
            first_nonempty(&captured.stderr).unwrap_or_else(|| "unknown error".to_owned())
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn live_loom() -> LiveCalibration {
    let detector = DetectorKind::Loom;
    let Some(cargo) = find_tool("cargo") else {
        return LiveCalibration::not_run(detector, "cargo is not installed");
    };
    let cargo_sha256 = match sha256_file(&cargo) {
        Ok(digest) => digest,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let probe = probe_env();
    let cargo_version = match probe_tool("cargo", &["--version"], &probe) {
        Ok(version) => version,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let session = match PrivateDir::new("loom") {
        Ok(session) => session,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let crate_dir = session.path().join("fixture");
    if let Err(reason) = copy_tree(&fixtures_root().join("loom"), &crate_dir) {
        return LiveCalibration::not_run(detector, reason);
    }
    let env = compiler_env(session.path());
    let race_capture = match run_loom_binary(&cargo, &crate_dir, &env, session.path(), "race") {
        Ok(capture) => capture,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let atomic_capture = match run_loom_binary(&cargo, &crate_dir, &env, session.path(), "atomic") {
        Ok(capture) => capture,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    if let Some(reason) = loom_environment_failure(&race_capture, &atomic_capture) {
        return LiveCalibration::not_run(detector, reason);
    }

    let race_binary = session.path().join("target-race/release/race");
    let atomic_binary = session.path().join("target-atomic/release/atomic");
    let build_artifact = match sha256_file(&race_binary) {
        Ok(digest) => digest,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let baseline_artifact = match sha256_file(&atomic_binary) {
        Ok(digest) => digest,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let target = match rustc_host(&cargo, &env) {
        Ok(target) => target,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let loom_version = package_version(&crate_dir.join("Cargo.lock"), "loom")
        .map(|version| format!("loom {version}; {cargo_version}"))
        .unwrap_or(cargo_version);
    let build_directory = "live/loom/race".to_owned();
    let baseline_directory = "live/loom/atomic".to_owned();
    let build_separation_verified = build_directory != baseline_directory
        && build_artifact != baseline_artifact
        && !is_zero_digest(&build_artifact)
        && !is_zero_digest(&baseline_artifact);

    let bad_case = build_case(
        "loom-known-bad",
        CalibrationRole::KnownBad,
        fixture_digest(&crate_dir.join("src/bin/race.rs")),
        "interleaving",
        &race_capture,
        Some(ObservedFinding {
            mechanism: "interleaving".to_owned(),
            diagnostic_fingerprint:
                "Causality violation: Concurrent read and write accesses to `UnsafeCell`".to_owned(),
            source: stream_containing(&race_capture, "Causality violation"),
        }),
    );
    let control_case = build_case(
        "loom-atomic-control",
        CalibrationRole::KnownGood,
        fixture_digest(&crate_dir.join("src/bin/atomic.rs")),
        "interleaving",
        &atomic_capture,
        None,
    );

    let identity = DetectorIdentity {
        kind: DetectorKind::Loom,
        tool_name: "cargo-loom".to_owned(),
        tool_version: loom_version,
        executable_sha256: cargo_sha256,
        invocation_argv: loom_argv("race", &session.path().join("target-race"))
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect(),
        environment_digest: environment_digest(&env),
        mechanism_enablement: vec!["loom".to_owned(), "interleaving".to_owned()],
        build: BuildIdentity {
            flags: vec![
                "--release".to_owned(),
                "--bin".to_owned(),
                "race".to_owned(),
            ],
            target: target.clone(),
            profile: "release".to_owned(),
            build_directory,
            artifact_sha256: build_artifact,
        },
        baseline_build: BuildIdentity {
            flags: vec![
                "--release".to_owned(),
                "--bin".to_owned(),
                "atomic".to_owned(),
            ],
            target,
            profile: "release".to_owned(),
            build_directory: baseline_directory,
            artifact_sha256: baseline_artifact,
        },
        build_separation_verified,
    };
    finish(DetectorKind::Loom, identity, vec![bad_case, control_case])
}

fn loom_argv(binary: &str, target_dir: &Path) -> Vec<OsString> {
    vec![
        OsString::from("run"),
        OsString::from("--release"),
        OsString::from("--bin"),
        OsString::from(binary),
        OsString::from("--target-dir"),
        target_dir.as_os_str().to_owned(),
    ]
}

fn run_loom_binary(
    cargo: &Path,
    crate_dir: &Path,
    env: &BTreeMap<String, String>,
    root: &Path,
    binary: &str,
) -> Result<Captured, String> {
    let target_dir = root.join(format!("target-{binary}"));
    let arguments = loom_argv(binary, &target_dir);
    let captured = run_capture(
        cargo,
        &arguments,
        Some(crate_dir),
        env,
        TOOL_TIMEOUT,
        MAX_CAPTURE_BYTES,
        &format!("loom-{binary}"),
    )?;
    if captured.timed_out {
        return Err(format!(
            "cargo run --bin {binary} timed out after {} seconds",
            TOOL_TIMEOUT.as_secs()
        ));
    }
    if captured.stdout_truncated || captured.stderr_truncated {
        return Err(format!(
            "cargo run --bin {binary} exceeded the {MAX_CAPTURE_BYTES}-byte capture limit"
        ));
    }
    Ok(captured)
}

fn loom_environment_failure(race: &Captured, atomic: &Captured) -> Option<String> {
    let race_text = format!("{}\n{}", race.stdout, race.stderr);
    if race_text.contains("Causality violation") || race_text.contains("loom race witness") {
        return None;
    }
    let combined = format!(
        "{}\n{}\n{}\n{}",
        race.stdout, race.stderr, atomic.stdout, atomic.stderr
    );
    for marker in [
        "failed to get `loom` as a dependency",
        "failed to download",
        "no matching package named `loom`",
        "Could not resolve host",
        "network failure",
        "error: failed to fetch",
        "error: failed to select a version",
        "error: no matching package",
    ] {
        if combined.contains(marker) {
            return Some(format!(
                "loom fixture dependencies are unavailable in this environment: {marker}"
            ));
        }
    }
    None
}

#[allow(clippy::too_many_lines)]
fn live_kani() -> LiveCalibration {
    let detector = DetectorKind::Kani;
    let Some(kani) = find_tool("kani") else {
        return LiveCalibration::not_run(
            detector,
            "kani is not installed; install with `cargo install --locked kani-verifier` and \
             `cargo kani setup`",
        );
    };
    let probe = kani_env(probe_env());
    let version = match probe_tool("kani", &["--version"], &probe) {
        Ok(version) => version,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let session = match PrivateDir::new("kani") {
        Ok(session) => session,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let run_dir = session.path().join("run");
    if let Err(reason) = create_private_dir(&run_dir) {
        return LiveCalibration::not_run(detector, reason);
    }
    let fixture_dir = session.path().join("fixture");
    if let Err(reason) = copy_tree(&fixtures_root().join("kani"), &fixture_dir) {
        return LiveCalibration::not_run(detector, reason);
    }
    let fixture = fixture_dir.join("kani_fixture.rs");
    let env = kani_env(compiler_env(session.path()));
    let bad_capture = match run_kani(&kani, &fixture, "known_bad", &run_dir, &env, &session) {
        Ok(capture) => capture,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let control_capture = match run_kani(&kani, &fixture, "proof_control", &run_dir, &env, &session)
    {
        Ok(capture) => capture,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    if let Some(reason) = kani_environment_failure(&bad_capture, &control_capture) {
        return LiveCalibration::not_run(detector, reason);
    }

    let Some(rustc) = find_tool("rustc") else {
        return LiveCalibration::not_run(detector, "rustc is not installed");
    };
    let baseline_dir = session.path().join("baseline");
    if let Err(reason) = create_private_dir(&baseline_dir) {
        return LiveCalibration::not_run(detector, reason);
    }
    let baseline_source = fixtures_root().join("kani/kani_baseline.rs");
    let baseline_binary = baseline_dir.join("kani_baseline");
    let baseline_flags = ["--edition=2021", "-C", "opt-level=0"];
    if let Err(reason) = compile_rust(
        &rustc,
        &baseline_source,
        &baseline_binary,
        &baseline_dir,
        &env,
        &baseline_flags,
    ) {
        return LiveCalibration::not_run(detector, reason);
    }
    let executable_sha256 = match sha256_file(&kani) {
        Ok(digest) => digest,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let baseline_artifact = match sha256_file(&baseline_binary) {
        Ok(digest) => digest,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let target = match rustc_host(&find_tool("cargo").unwrap_or_else(|| rustc.clone()), &env) {
        Ok(target) => target,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let build_directory = "live/kani/proof".to_owned();
    let baseline_directory = "live/kani/native".to_owned();
    let build_separation_verified = build_directory != baseline_directory
        && executable_sha256 != baseline_artifact
        && !is_zero_digest(&executable_sha256)
        && !is_zero_digest(&baseline_artifact);

    let bad_case = build_case(
        "kani-known-bad",
        CalibrationRole::KnownBad,
        fixture_digest(&fixture),
        "bounded_model",
        &bad_capture,
        Some(ObservedFinding {
            mechanism: "bounded_model".to_owned(),
            diagnostic_fingerprint: "VERIFICATION:- FAILED".to_owned(),
            source: stream_containing(&bad_capture, "VERIFICATION:- FAILED"),
        }),
    );
    let control_case = build_case(
        "kani-proof-control",
        CalibrationRole::KnownGood,
        fixture_digest(&fixture),
        "bounded_model",
        &control_capture,
        None,
    );

    let identity = DetectorIdentity {
        kind: DetectorKind::Kani,
        tool_name: "kani".to_owned(),
        tool_version: version,
        executable_sha256: executable_sha256.clone(),
        invocation_argv: vec![
            "kani".to_owned(),
            fixture.display().to_string(),
            "--harness".to_owned(),
            "known_bad".to_owned(),
        ],
        environment_digest: environment_digest(&env),
        mechanism_enablement: vec!["kani".to_owned(), "bounded_model".to_owned()],
        build: BuildIdentity {
            flags: vec![
                "--harness".to_owned(),
                "known_bad".to_owned(),
                "default-unwind".to_owned(),
            ],
            target: target.clone(),
            profile: "kani-bounded".to_owned(),
            build_directory,
            artifact_sha256: executable_sha256,
        },
        baseline_build: BuildIdentity {
            flags: baseline_flags
                .iter()
                .map(|flag| (*flag).to_owned())
                .collect(),
            target,
            profile: "kani-bounded".to_owned(),
            build_directory: baseline_directory,
            artifact_sha256: baseline_artifact,
        },
        build_separation_verified,
    };
    finish(DetectorKind::Kani, identity, vec![bad_case, control_case])
}

fn run_kani(
    kani: &Path,
    fixture: &Path,
    harness: &str,
    run_dir: &Path,
    env: &BTreeMap<String, String>,
    _session: &PrivateDir,
) -> Result<Captured, String> {
    let run_env = env.clone();
    let arguments = vec![
        fixture.as_os_str().to_owned(),
        OsString::from("--harness"),
        OsString::from(harness),
    ];
    let captured = run_capture(
        kani,
        &arguments,
        Some(run_dir),
        &run_env,
        TOOL_TIMEOUT,
        MAX_CAPTURE_BYTES,
        &format!("kani-{harness}"),
    )?;
    if captured.timed_out {
        return Err(format!(
            "kani --harness {harness} timed out after {} seconds",
            TOOL_TIMEOUT.as_secs()
        ));
    }
    if captured.stdout_truncated || captured.stderr_truncated {
        return Err(format!(
            "kani --harness {harness} exceeded the {MAX_CAPTURE_BYTES}-byte capture limit"
        ));
    }
    Ok(captured)
}

fn kani_environment_failure(bad: &Captured, control: &Captured) -> Option<String> {
    let bad_text = format!("{}\n{}", bad.stdout, bad.stderr);
    let control_text = format!("{}\n{}", control.stdout, control.stderr);
    let markers = [
        "Could not find CBMC",
        "CBMC not found",
        "kani is not installed",
        "Kani is not installed",
        "failed to download",
        "error: no such command",
    ];
    if !bad_text.contains("VERIFICATION:- FAILED") {
        if let Some(marker) = markers.iter().find(|marker| bad_text.contains(**marker)) {
            return Some(format!("Kani is unavailable in this environment: {marker}"));
        }
    }
    if let Some(marker) = markers
        .iter()
        .find(|marker| control_text.contains(**marker))
    {
        return Some(format!("Kani is unavailable in this environment: {marker}"));
    }
    None
}

#[allow(clippy::too_many_lines)]
fn live_openssl() -> LiveCalibration {
    let detector = DetectorKind::Custom(OPENSSL_KAT_ID.to_owned());
    let Some(openssl) = find_tool("openssl") else {
        return LiveCalibration::not_run(detector, "openssl is not installed");
    };
    let probe = probe_env();
    let version = match probe_tool("openssl", &["version"], &probe) {
        Ok(version) => version,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let executable_sha256 = match sha256_file(&openssl) {
        Ok(digest) => digest,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let fixtures = fixtures_root().join("crypto");
    let kat_input = fixtures.join("kat_input.txt");
    let message = fixtures.join("message.txt");
    let public_key = fixtures.join("public.pem");
    let signature = fixtures.join("signature.bin");
    let corrupt_signature = fixtures.join("signature_corrupt.bin");
    for path in [
        &kat_input,
        &message,
        &public_key,
        &signature,
        &corrupt_signature,
    ] {
        if !path.is_file() {
            return LiveCalibration::not_run(
                detector,
                format!("crypto fixture is missing: {}", path.display()),
            );
        }
    }
    let session = match PrivateDir::new("openssl") {
        Ok(session) => session,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let run_dir = session.path().join("run");
    if let Err(reason) = create_private_dir(&run_dir) {
        return LiveCalibration::not_run(detector, reason);
    }
    let env = compiler_env(session.path());

    let kat_args = vec![
        OsString::from("dgst"),
        OsString::from("-sha256"),
        OsString::from("-r"),
        kat_input.as_os_str().to_owned(),
    ];
    let kat_capture = match run_capture(
        &openssl,
        &kat_args,
        Some(&run_dir),
        &env,
        RUN_TIMEOUT,
        MAX_CAPTURE_BYTES,
        "openssl-kat",
    ) {
        Ok(capture) => capture,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    if kat_capture.timed_out {
        return LiveCalibration::not_run(detector, "openssl SHA-256 KAT timed out");
    }
    if kat_capture.exit_code != 0 {
        return LiveCalibration::not_run(
            detector,
            format!(
                "openssl SHA-256 KAT failed: {}",
                first_nonempty(&kat_capture.stderr).unwrap_or_else(|| "unknown error".to_owned())
            ),
        );
    }
    let kat_ok = kat_capture
        .stdout
        .split_whitespace()
        .next()
        .is_some_and(|digest| digest.eq_ignore_ascii_case(SHA256_ABC_DIGEST));

    let verify_args = |signature: &Path| {
        vec![
            OsString::from("dgst"),
            OsString::from("-sha256"),
            OsString::from("-verify"),
            public_key.as_os_str().to_owned(),
            OsString::from("-signature"),
            signature.as_os_str().to_owned(),
            message.as_os_str().to_owned(),
        ]
    };
    let good_capture = match run_capture(
        &openssl,
        &verify_args(&signature),
        Some(&run_dir),
        &env,
        RUN_TIMEOUT,
        MAX_CAPTURE_BYTES,
        "openssl-verify-good",
    ) {
        Ok(capture) => capture,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    let bad_capture = match run_capture(
        &openssl,
        &verify_args(&corrupt_signature),
        Some(&run_dir),
        &env,
        RUN_TIMEOUT,
        MAX_CAPTURE_BYTES,
        "openssl-verify-bad",
    ) {
        Ok(capture) => capture,
        Err(reason) => return LiveCalibration::not_run(detector, reason),
    };
    for (label, capture) in [("known-good", &good_capture), ("known-bad", &bad_capture)] {
        if capture.timed_out {
            return LiveCalibration::not_run(
                detector,
                format!("openssl {label} verification timed out"),
            );
        }
        if capture.stdout_truncated || capture.stderr_truncated {
            return LiveCalibration::not_run(
                detector,
                format!("openssl {label} verification exceeded the capture limit"),
            );
        }
    }
    let bad_text = format!("{}\n{}", bad_capture.stdout, bad_capture.stderr);
    let good_text = format!("{}\n{}", good_capture.stdout, good_capture.stderr);
    let failure_fingerprint = if bad_text.contains("Verification failure") {
        Some("Verification failure")
    } else if bad_text.contains("Verification Failure") {
        Some("Verification Failure")
    } else {
        None
    };
    let good_failure = if good_text.contains("Verification failure") {
        Some("Verification failure")
    } else if good_text.contains("Verification Failure") {
        Some("Verification Failure")
    } else {
        None
    };

    let kat_finding = if kat_ok {
        None
    } else {
        Some(ObservedFinding {
            mechanism: "known_answer".to_owned(),
            diagnostic_fingerprint: first_nonempty(&kat_capture.stdout)
                .unwrap_or_else(|| "missing digest".to_owned()),
            source: CaptureStream::Stdout,
        })
    };
    let kat_case = build_case(
        "openssl-sha256-kat",
        CalibrationRole::KnownGood,
        fixture_digest(&kat_input),
        "known_answer",
        &kat_capture,
        kat_finding,
    );
    let good_finding = good_failure.map(|fingerprint| ObservedFinding {
        mechanism: "known_answer".to_owned(),
        diagnostic_fingerprint: fingerprint.to_owned(),
        source: stream_containing(&good_capture, fingerprint),
    });
    let good_case = build_case(
        "openssl-known-good-signature",
        CalibrationRole::KnownGood,
        fixture_digest(&signature),
        "known_answer",
        &good_capture,
        good_finding,
    );
    let bad_case = build_case(
        "openssl-known-bad-signature",
        CalibrationRole::KnownBad,
        fixture_digest(&corrupt_signature),
        "known_answer",
        &bad_capture,
        Some(ObservedFinding {
            mechanism: "known_answer".to_owned(),
            diagnostic_fingerprint: failure_fingerprint
                .unwrap_or("Verification failure")
                .to_owned(),
            source: stream_containing(
                &bad_capture,
                failure_fingerprint.unwrap_or("Verification failure"),
            ),
        }),
    );

    let build_directory = "live/crypto/kat".to_owned();
    let baseline_directory = "live/crypto/signature".to_owned();
    let build_artifact = fixture_digest(&kat_input);
    let baseline_artifact = fixture_digest(&message);
    let build_separation_verified = build_directory != baseline_directory
        && build_artifact != baseline_artifact
        && !is_zero_digest(&build_artifact)
        && !is_zero_digest(&baseline_artifact);
    let target = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
    let identity = DetectorIdentity {
        kind: detector.clone(),
        tool_name: "openssl".to_owned(),
        tool_version: version,
        executable_sha256,
        invocation_argv: vec![
            "openssl".to_owned(),
            "dgst".to_owned(),
            "-sha256".to_owned(),
            "-verify".to_owned(),
            public_key.display().to_string(),
            "-signature".to_owned(),
            corrupt_signature.display().to_string(),
            message.display().to_string(),
        ],
        environment_digest: environment_digest(&env),
        mechanism_enablement: vec![
            "known_answer".to_owned(),
            "openssl".to_owned(),
            "sha256".to_owned(),
        ],
        build: BuildIdentity {
            flags: vec!["dgst".to_owned(), "-sha256".to_owned(), "-r".to_owned()],
            target: target.clone(),
            profile: "openssl-known-answer".to_owned(),
            build_directory,
            artifact_sha256: build_artifact,
        },
        baseline_build: BuildIdentity {
            flags: vec![
                "dgst".to_owned(),
                "-sha256".to_owned(),
                "-verify".to_owned(),
            ],
            target,
            profile: "openssl-known-answer".to_owned(),
            build_directory: baseline_directory,
            artifact_sha256: baseline_artifact,
        },
        build_separation_verified,
    };
    finish(detector, identity, vec![kat_case, good_case, bad_case])
}

#[allow(clippy::too_many_lines)]
fn build_case(
    case_id: &str,
    role: CalibrationRole,
    fixture_digest: String,
    mechanism: &str,
    capture: &Captured,
    finding: Option<ObservedFinding>,
) -> CalibrationCase {
    let provenance = CaseProvenance {
        origin: DetectorOrigin::AuthenticLiveTool,
        case_id: case_id.to_owned(),
        fixture_digest: fixture_digest.clone(),
        mechanism: mechanism.to_owned(),
        legality: CaseLegality::TestOnly,
    };
    CalibrationCase {
        case_id: case_id.to_owned(),
        role,
        fixture_digest,
        expected_mechanism: mechanism.to_owned(),
        legality: CaseLegality::TestOnly,
        capture: RawCapture {
            stdout: CapturedStream {
                text: capture.stdout.clone(),
                sha256: sha256_hex(capture.stdout.as_bytes()),
                truncated: capture.stdout_truncated,
            },
            stderr: CapturedStream {
                text: capture.stderr.clone(),
                sha256: sha256_hex(capture.stderr.as_bytes()),
                truncated: capture.stderr_truncated,
            },
            exit_code: capture.exit_code,
            signal: capture.signal,
            duration_ms: capture.duration_ms,
        },
        provenance,
        finding,
    }
}

fn finish(
    detector: DetectorKind,
    identity: DetectorIdentity,
    cases: Vec<CalibrationCase>,
) -> LiveCalibration {
    let evidence = DetectorEvidence {
        schema: DETECTOR_EVIDENCE_SCHEMA.to_owned(),
        spec: DETECTOR_SPEC.to_owned(),
        detector: identity,
        cases,
    };
    match evaluate_calibration(&evidence) {
        Ok(report) => {
            let status = if report.outcome == CalibrationOutcome::Calibrated {
                LiveStatus::Calibrated
            } else {
                LiveStatus::Refused
            };
            LiveCalibration {
                detector,
                status,
                reason: None,
                evidence: Some(evidence),
                report: Some(report),
            }
        }
        Err(error) => LiveCalibration::not_run(
            detector,
            format!("cannot adjudicate live evidence: {error}"),
        ),
    }
}

fn stream_containing(capture: &Captured, fingerprint: &str) -> CaptureStream {
    if capture.stderr.contains(fingerprint) {
        CaptureStream::Stderr
    } else {
        CaptureStream::Stdout
    }
}

#[derive(Debug)]
struct Captured {
    stdout: String,
    stderr: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
    exit_code: i32,
    signal: Option<i32>,
    duration_ms: u64,
    timed_out: bool,
}

#[allow(clippy::too_many_arguments)]
fn run_capture(
    program: &Path,
    args: &[OsString],
    directory: Option<&Path>,
    env: &BTreeMap<String, String>,
    timeout: Duration,
    limit: usize,
    label: &str,
) -> Result<Captured, String> {
    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    let capture_dir = directory.map_or_else(
        || {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            std::env::temp_dir().join(format!(
                "frf-live-capture-{}-{sequence}-{nanos}",
                std::process::id()
            ))
        },
        Path::to_path_buf,
    );
    if !capture_dir.is_dir() {
        create_private_dir(&capture_dir)?;
    }
    let stdout_path = capture_dir.join(format!("{label}-{sequence}.stdout"));
    let stderr_path = capture_dir.join(format!("{label}-{sequence}.stderr"));
    let stdout_file = open_private(&stdout_path)?;
    let stderr_file = open_private(&stderr_path)?;

    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .process_group(0);
    if let Some(directory) = directory {
        command.current_dir(directory);
    }
    command.env_clear();
    for (key, value) in env {
        command.env(key, value);
    }

    let started = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot execute {}: {error}", program.display()))?;
    let deadline = started + timeout;
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
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    let (stdout, stdout_truncated) = read_bounded(&stdout_path, limit)?;
    let (stderr, stderr_truncated) = read_bounded(&stderr_path, limit)?;
    let _ = fs::remove_file(&stdout_path);
    let _ = fs::remove_file(&stderr_path);
    if directory.is_none() {
        let _ = fs::remove_dir(&capture_dir);
    }
    let (exit_code, signal) = exit_status(status);
    Ok(Captured {
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        exit_code,
        signal,
        duration_ms,
        timed_out,
    })
}

fn exit_status(status: Option<ExitStatus>) -> (i32, Option<i32>) {
    match status {
        Some(status) => {
            let signal = status.signal();
            let code = status
                .code()
                .unwrap_or_else(|| signal.map_or(1, |value| 128 + value));
            (code, signal)
        }
        None => (1, None),
    }
}

fn create_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("cannot set 0700 on {}: {error}", path.display()))
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

fn find_tool(name: &str) -> Option<PathBuf> {
    let candidate = Path::new(name);
    if candidate.components().count() > 1 {
        return candidate.is_file().then(|| candidate.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn probe_env() -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert("PATH".to_owned(), COMPILER_PATH.to_owned());
    env.insert("LC_ALL".to_owned(), "C".to_owned());
    env.insert("RUSTUP_AUTO_INSTALL".to_owned(), "0".to_owned());
    if let Some(home) = std::env::var_os("HOME") {
        env.insert("HOME".to_owned(), home.to_string_lossy().into_owned());
    }
    if let Some(rustup) = std::env::var_os("RUSTUP_HOME") {
        env.insert(
            "RUSTUP_HOME".to_owned(),
            rustup.to_string_lossy().into_owned(),
        );
    }
    if let Some(cargo) = std::env::var_os("CARGO_HOME") {
        env.insert(
            "CARGO_HOME".to_owned(),
            cargo.to_string_lossy().into_owned(),
        );
    }
    env
}

fn compiler_env(home: &Path) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert("PATH".to_owned(), COMPILER_PATH.to_owned());
    env.insert("HOME".to_owned(), home.display().to_string());
    env.insert("TMPDIR".to_owned(), home.display().to_string());
    env.insert("LC_ALL".to_owned(), "C".to_owned());
    env.insert("RUSTUP_AUTO_INSTALL".to_owned(), "0".to_owned());
    env.insert("RUSTUP_HOME".to_owned(), rustup_home());
    env.insert("CARGO_HOME".to_owned(), cargo_home());
    env
}

fn rustup_home() -> String {
    std::env::var("RUSTUP_HOME").unwrap_or_else(|_| "/usr/local/rustup".to_owned())
}

fn cargo_home() -> String {
    std::env::var("CARGO_HOME").unwrap_or_else(|_| "/usr/local/cargo".to_owned())
}

fn kani_env(mut env: BTreeMap<String, String>) -> BTreeMap<String, String> {
    if let Ok(home) = std::env::var("KANI_CARGO_HOME") {
        env.insert("CARGO_HOME".to_owned(), home);
    }
    if let Ok(home) = std::env::var("KANI_HOME") {
        env.insert("KANI_HOME".to_owned(), home);
    }
    env
}

fn environment_digest(env: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    for (key, value) in env {
        hasher.update(key.as_bytes());
        hasher.update([0]);
        hasher.update(value.as_bytes());
        hasher.update([0xff]);
    }
    hex_lower(&hasher.finalize())
}

fn fixture_digest(path: &Path) -> String {
    fs::read(path).map_or_else(|_| String::new(), |bytes| sha256_hex(&bytes))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

fn is_zero_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte == b'0')
}

fn first_nonempty(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
}

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURES)
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), String> {
    create_private_dir(destination)?;
    let entries = fs::read_dir(source)
        .map_err(|error| format!("cannot read {}: {error}", source.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read fixture entry: {error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot stat fixture entry: {error}"))?;
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &target).map_err(|error| {
                format!(
                    "cannot copy {} to {}: {error}",
                    entry.path().display(),
                    target.display()
                )
            })?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("cannot set 0600 on {}: {error}", target.display()))?;
        } else {
            return Err(format!(
                "unsupported non-regular fixture entry: {}",
                entry.path().display()
            ));
        }
    }
    Ok(())
}

fn package_version(lockfile: &Path, package: &str) -> Option<String> {
    let text = fs::read_to_string(lockfile).ok()?;
    let mut current = None;
    for line in text.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            current = None;
        } else if let Some(name) = line.strip_prefix("name = \"") {
            current = name.strip_suffix('"').map(str::to_owned);
        } else if let Some(version) = line.strip_prefix("version = \"") {
            if current.as_deref() == Some(package) {
                return version.strip_suffix('"').map(str::to_owned);
            }
        }
    }
    None
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
                "frf-live-{label}-{}-{sequence}-{nanos}",
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
        Err("could not allocate a unique private temporary directory".to_owned())
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

/// Serialize one typed live `NOT_RUN` response.
///
/// # Errors
///
/// Returns an error if the response cannot be serialized.
pub fn not_run_json(detector: &DetectorKind, reason: &str) -> Result<serde_json::Value, String> {
    let kind = serde_json::to_value(detector)
        .map_err(|error| format!("cannot encode detector kind: {error}"))?;
    Ok(serde_json::json!({
        "schema": LIVE_NOT_RUN_SCHEMA,
        "status": "NOT_RUN",
        "detector": kind,
        "reason": reason,
        "claim_ceiling": LIVE_NOT_RUN_CLAIM_CEILING,
    }))
}

/// Serialize the live calibration evidence for tests and callers that need the
/// full captured stream. The calibration report remains the primary output.
///
/// # Errors
///
/// Returns an error if the evidence cannot be encoded.
pub fn evidence_json(evidence: &DetectorEvidence) -> Result<serde_json::Value, String> {
    serde_json::to_value(evidence).map_err(|error| format!("cannot encode live evidence: {error}"))
}

/// Convenience re-export of the calibration claim ceiling for live callers.
#[must_use]
pub const fn claim_ceiling() -> &'static str {
    CALIBRATION_CLAIM_CEILING
}

/// Return a human-readable label for a detector kind.
#[must_use]
pub fn detector_label(kind: &DetectorKind) -> String {
    match kind {
        DetectorKind::Miri => "Miri".to_owned(),
        DetectorKind::AddressSanitizer => "AddressSanitizer".to_owned(),
        DetectorKind::LeakSanitizer => "LeakSanitizer".to_owned(),
        DetectorKind::ThreadSanitizer => "ThreadSanitizer".to_owned(),
        DetectorKind::Loom => "loom".to_owned(),
        DetectorKind::Kani => "Kani".to_owned(),
        DetectorKind::Custom(name) if name == OPENSSL_KAT_ID => {
            "OpenSSL SHA-256 known-answer".to_owned()
        }
        other => format!("{other:?}"),
    }
}

/// The set of live mechanisms reported by the detector gate.
#[must_use]
pub fn gate_kinds() -> Vec<&'static str> {
    vec!["miri", "asan", "lsan", "tsan", "loom", "kani", "crypto"]
}

/// Maximum retained bytes for one live capture.
pub const LIVE_MAX_CAPTURE_BYTES: usize = MAX_CAPTURE_BYTES;

/// Serialize `value` as pretty JSON. This is used only by tests and diagnostics.
///
/// # Errors
///
/// Returns an error if the value cannot be serialized.
pub fn pretty_json<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string_pretty(value).map_err(|error| format!("cannot encode JSON: {error}"))
}
