//! Manual command-line interface.
//!
//! The parser is deliberately hand-written and does not invoke a shell. It
//! reads only files under the paths supplied by the caller and never executes
//! an external program.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::identity::{parse_strict, require_canonical, MsId, MAX_BYTES};
use crate::mir::{
    MirAdapter, MirError, MirErrorCategory, MirScanOutcome, MIR_NOT_RUN_SCHEMA,
    MIR_OBSERVATION_SCHEMA,
};
use crate::path_effect::{
    analyze, analyze_inventory, PathEffectsInput, PathErrorCategory, PATH_EFFECT_INPUT_SCHEMA,
};
use crate::profile::{
    canonical_bundle_bytes, evaluate_profile_json, local_buffer_bundle, local_buffer_records,
    ProfileEvaluation, ProfileRefusalKind, UNIVERSAL_SOUNDNESS,
};
use crate::source::{
    scan_source_default, SourceError, SourceErrorCategory, SourceInventory, SOURCE_INVENTORY_SCHEMA,
};
use crate::support::{evaluate, explain, RuleSystem, SupportError, SupportPolicy};

/// Command completed and its declared checks passed.
pub const EXIT_OK: i32 = 0;
/// Invalid input or usage.
pub const EXIT_USAGE: i32 = 2;
/// Evidence integrity failure.
pub const EXIT_INTEGRITY: i32 = 3;
/// Promotion refused or claim blocked.
pub const EXIT_REFUSED: i32 = 4;
/// Detector failure or missed control.
pub const EXIT_DETECTOR: i32 = 5;
/// External tool or integration unavailable (`NOT_RUN`).
pub const EXIT_NOT_RUN: i32 = 6;
/// Internal harness error.
pub const EXIT_HARNESS: i32 = 7;

const USAGE: &str = "\
frf-memorysafety <command>

Commands:
  version [--json]
  capabilities [--json]
  profile validate FILE
  profile enumerate --out DIR
  support evaluate FILE [--policy POLICY_FILE] [--expect-policy-digest MS1_ID] [--expect-policy-version VERSION]
  support explain FILE  [--policy POLICY_FILE] [--expect-policy-digest MS1_ID] [--expect-policy-version VERSION]
  source scan PATH [--json]
  path analyze FILE [--json]
  mir scan FILE [--json] [--toolchain NAME]
  evidence verify --root DIR
  report --case FILE --format json|markdown

Live external commands (always NOT_RUN, exit 6):
  court run ...
  detector calibrate --live ...
  frf promote ...
  gemel publish ...

Exit statuses follow SPEC.md §14. A zero status never establishes universal
soundness; universal soundness is always WITHHELD_NOT_RUN in this build.
";

/// Run the CLI and return its process exit status.
///
/// # Panics
///
/// This function does not panic on malformed input. I/O failures that occur
/// while writing to standard output are reported by the Rust runtime, as with
/// any console program.
pub fn run<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args: Vec<String> = args.into_iter().map(Into::into).collect();
    match dispatch(&args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("frf-memorysafety: {error}");
            EXIT_HARNESS
        }
    }
}

fn dispatch(args: &[String]) -> Result<i32, String> {
    let Some(command) = args.first().map(String::as_str) else {
        print!("{USAGE}");
        return Ok(EXIT_USAGE);
    };
    match command {
        "version" => command_version(&args[1..]),
        "capabilities" => command_capabilities(&args[1..]),
        "profile" => command_profile(&args[1..]),
        "support" => command_support(&args[1..]),
        "source" => Ok(command_source(&args[1..])),
        "path" => Ok(command_path(&args[1..])),
        "mir" => Ok(command_mir(&args[1..])),
        "evidence" => command_evidence(&args[1..]),
        "report" => command_report(&args[1..]),
        "court" => command_not_run("court run", args),
        "detector" => command_detector(&args[1..]),
        "frf" => command_not_run("frf promote", args),
        "gemel" => command_not_run("gemel publish", args),
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(EXIT_OK)
        }
        other => {
            eprintln!("unknown command: {other}");
            print!("{USAGE}");
            Ok(EXIT_USAGE)
        }
    }
}

fn only_flags(rest: &[String], allowed: &[&str]) -> bool {
    rest.iter().all(|arg| allowed.contains(&arg.as_str()))
}

fn command_version(rest: &[String]) -> Result<i32, String> {
    if !only_flags(rest, &["--json"]) {
        eprintln!("usage: version [--json]");
        return Ok(EXIT_USAGE);
    }
    let json = rest.iter().any(|arg| arg == "--json");
    if json {
        emit_json(&serde_json::json!({
            "name": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
            "canonical_schema": crate::CANONICAL_SCHEMA,
            "profile_schema": crate::profile::PROFILE_SCHEMA,
            "source_inventory_schema": crate::source::SOURCE_INVENTORY_SCHEMA,
            "path_effects_input_schema": crate::path_effect::PATH_EFFECT_INPUT_SCHEMA,
            "path_effects_report_schema": crate::path_effect::PATH_EFFECT_REPORT_SCHEMA,
            "mir_observation_schema": MIR_OBSERVATION_SCHEMA,
            "mir_not_run_schema": MIR_NOT_RUN_SCHEMA,
            "universal_soundness": UNIVERSAL_SOUNDNESS,
        }))?;
    } else {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        println!("canonical schema: {}", crate::CANONICAL_SCHEMA);
        println!(
            "source inventory schema: {}",
            crate::source::SOURCE_INVENTORY_SCHEMA
        );
        println!(
            "path-effects input schema: {}",
            crate::path_effect::PATH_EFFECT_INPUT_SCHEMA
        );
        println!("MIR observation schema: {MIR_OBSERVATION_SCHEMA}");
        println!("universal soundness: {UNIVERSAL_SOUNDNESS}");
    }
    Ok(EXIT_OK)
}

fn command_capabilities(rest: &[String]) -> Result<i32, String> {
    if !only_flags(rest, &["--json"]) {
        eprintln!("usage: capabilities [--json]");
        return Ok(EXIT_USAGE);
    }
    let capabilities = crate::capabilities();
    if rest.iter().any(|arg| arg == "--json") {
        emit_json(&capabilities)?;
    } else {
        println!("{} {}", capabilities.version, capabilities.canonical_schema);
        println!("implemented:");
        for item in &capabilities.implemented {
            println!("  - {item}");
        }
        println!("not run:");
        for item in &capabilities.not_run {
            println!("  - {item}");
        }
        println!("external authorities:");
        for item in &capabilities.external_authorities {
            println!("  - {item}");
        }
    }
    Ok(EXIT_OK)
}

fn command_profile(rest: &[String]) -> Result<i32, String> {
    match rest.first().map(String::as_str) {
        Some("validate") => {
            let Some(path) = rest.get(1) else {
                eprintln!("usage: profile validate FILE");
                return Ok(EXIT_USAGE);
            };
            if rest.len() != 2 {
                eprintln!("usage: profile validate FILE");
                return Ok(EXIT_USAGE);
            }
            let bytes = match read_limited(Path::new(path)) {
                Ok(bytes) => bytes,
                Err(error) => {
                    eprintln!("{error}");
                    return Ok(EXIT_USAGE);
                }
            };
            let evaluation = evaluate_profile_json(&bytes);
            emit_json(&evaluation)?;
            Ok(evaluation_exit_code(&evaluation))
        }
        Some("enumerate") => command_profile_enumerate(&rest[1..]),
        _ => {
            eprintln!("usage: profile validate FILE | profile enumerate --out DIR");
            Ok(EXIT_USAGE)
        }
    }
}

fn command_profile_enumerate(rest: &[String]) -> Result<i32, String> {
    if rest.len() != 2 || rest[0] != "--out" {
        eprintln!("usage: profile enumerate --out DIR");
        return Ok(EXIT_USAGE);
    }
    let out = Path::new(&rest[1]);
    if let Err(error) = fs::create_dir_all(out) {
        eprintln!("cannot create {}: {error}", out.display());
        return Ok(EXIT_HARNESS);
    }
    let bundle = local_buffer_bundle();
    let records = local_buffer_records();
    let bundle_bytes = match canonical_bundle_bytes(&bundle) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot encode bundle: {error}");
            return Ok(EXIT_HARNESS);
        }
    };
    write_canonical(&out.join("bundle.json"), &bundle_bytes)?;
    write_json(&out.join("policy.json"), &bundle.policy)?;
    write_json(&out.join("claims.json"), &bundle.claims)?;
    write_json(&out.join("cases.json"), &records)?;
    emit_json(&serde_json::json!({
        "status": "ENUMERATED",
        "out": out.display().to_string(),
        "records": records.len(),
        "claims": bundle.claims.len(),
        "universal_soundness": UNIVERSAL_SOUNDNESS,
    }))?;
    Ok(EXIT_OK)
}

fn command_source(rest: &[String]) -> i32 {
    if rest.first().map(String::as_str) != Some("scan") {
        eprintln!("usage: source scan PATH [--json]");
        return EXIT_USAGE;
    }
    let mut path = None;
    let mut json = false;
    for argument in &rest[1..] {
        match argument.as_str() {
            "--json" => json = true,
            value if value.starts_with("--") => {
                eprintln!("usage: source scan PATH [--json]");
                return EXIT_USAGE;
            }
            value => {
                if path.is_some() {
                    eprintln!("usage: source scan PATH [--json]");
                    return EXIT_USAGE;
                }
                path = Some(value);
            }
        }
    }
    let Some(path) = path else {
        eprintln!("usage: source scan PATH [--json]");
        return EXIT_USAGE;
    };
    let inventory = match scan_source_default(path) {
        Ok(inventory) => inventory,
        Err(error) => {
            eprintln!("{error}");
            return source_error_exit(&error);
        }
    };
    let bytes = match inventory.canonical_bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("{error}");
            return EXIT_HARNESS;
        }
    };
    // `--json` is accepted explicitly; both spellings emit the same canonical
    // machine form so callers cannot accidentally depend on a lossy pretty form.
    let _ = json;
    if let Err(error) = std::io::stdout().write_all(&bytes) {
        eprintln!("cannot write source inventory: {error}");
        return EXIT_HARNESS;
    }
    EXIT_OK
}

fn source_error_exit(error: &SourceError) -> i32 {
    match error.category() {
        SourceErrorCategory::Usage => EXIT_USAGE,
        SourceErrorCategory::Integrity => EXIT_INTEGRITY,
        SourceErrorCategory::Harness => EXIT_HARNESS,
    }
}

fn command_path(rest: &[String]) -> i32 {
    if rest.first().map(String::as_str) != Some("analyze") {
        eprintln!("usage: path analyze FILE [--json]");
        return EXIT_USAGE;
    }
    let mut path = None;
    let mut json = false;
    for argument in &rest[1..] {
        match argument.as_str() {
            "--json" => json = true,
            value if value.starts_with("--") => {
                eprintln!("usage: path analyze FILE [--json]");
                return EXIT_USAGE;
            }
            value => {
                if path.is_some() {
                    eprintln!("usage: path analyze FILE [--json]");
                    return EXIT_USAGE;
                }
                path = Some(value);
            }
        }
    }
    let Some(path) = path else {
        eprintln!("usage: path analyze FILE [--json]");
        return EXIT_USAGE;
    };
    let bytes = match read_limited(Path::new(path)) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("{error}");
            return EXIT_USAGE;
        }
    };
    let value = match parse_strict(&bytes) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("invalid path-effects input: {error}");
            return EXIT_INTEGRITY;
        }
    };
    let schema = value.get("schema").and_then(|item| item.as_str());
    let report = match schema {
        Some(PATH_EFFECT_INPUT_SCHEMA) => {
            let input: PathEffectsInput = match serde_json::from_value(value) {
                Ok(input) => input,
                Err(error) => {
                    eprintln!("invalid path-effects input: {error}");
                    return EXIT_INTEGRITY;
                }
            };
            analyze(&input)
        }
        Some(SOURCE_INVENTORY_SCHEMA) => {
            let inventory: SourceInventory = match serde_json::from_value(value) {
                Ok(inventory) => inventory,
                Err(error) => {
                    eprintln!("invalid source inventory: {error}");
                    return EXIT_INTEGRITY;
                }
            };
            analyze_inventory(&inventory)
        }
        Some(other) => {
            eprintln!(
                "unsupported path-effects input schema: {other}; expected {PATH_EFFECT_INPUT_SCHEMA} or {SOURCE_INVENTORY_SCHEMA}"
            );
            return EXIT_INTEGRITY;
        }
        None => {
            eprintln!("path-effects input is missing a schema field");
            return EXIT_INTEGRITY;
        }
    };
    let report = match report {
        Ok(report) => report,
        Err(error) => {
            eprintln!("{error}");
            return path_error_exit(error.category());
        }
    };
    let bytes = match report.canonical_bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("{error}");
            return path_error_exit(error.category());
        }
    };
    // `--json` is accepted explicitly; both spellings emit the same canonical
    // machine form so callers cannot accidentally depend on a lossy pretty form.
    let _ = json;
    if let Err(error) = std::io::stdout().write_all(&bytes) {
        eprintln!("cannot write path-effects report: {error}");
        return EXIT_HARNESS;
    }
    EXIT_OK
}

fn path_error_exit(category: PathErrorCategory) -> i32 {
    match category {
        PathErrorCategory::Usage => EXIT_USAGE,
        PathErrorCategory::Integrity => EXIT_INTEGRITY,
        PathErrorCategory::Harness => EXIT_HARNESS,
    }
}

fn command_mir(rest: &[String]) -> i32 {
    if rest.first().map(String::as_str) != Some("scan") {
        eprintln!("usage: mir scan FILE [--json] [--toolchain NAME]");
        return EXIT_USAGE;
    }
    let mut path = None;
    let mut json = false;
    let mut toolchain = None;
    let mut index = 1;
    while index < rest.len() {
        match rest[index].as_str() {
            "--json" => json = true,
            "--toolchain" => {
                index += 1;
                let Some(value) = rest.get(index) else {
                    eprintln!("usage: mir scan FILE [--json] [--toolchain NAME]");
                    return EXIT_USAGE;
                };
                if value.is_empty() || value.starts_with("--") {
                    eprintln!("usage: mir scan FILE [--json] [--toolchain NAME]");
                    return EXIT_USAGE;
                }
                toolchain = Some(value.clone());
            }
            value if value.starts_with("--") => {
                eprintln!("usage: mir scan FILE [--json] [--toolchain NAME]");
                return EXIT_USAGE;
            }
            value => {
                if path.is_some() {
                    eprintln!("usage: mir scan FILE [--json] [--toolchain NAME]");
                    return EXIT_USAGE;
                }
                path = Some(value.to_owned());
            }
        }
        index += 1;
    }
    let Some(path) = path else {
        eprintln!("usage: mir scan FILE [--json] [--toolchain NAME]");
        return EXIT_USAGE;
    };

    let mut adapter = MirAdapter::new();
    if let Some(toolchain) = toolchain {
        adapter = adapter.with_toolchain(toolchain);
    }
    let _ = json;
    match adapter.scan(&path) {
        Ok(MirScanOutcome::Live(observation)) => {
            let bytes = match observation.canonical_bytes() {
                Ok(bytes) => bytes,
                Err(error) => {
                    eprintln!("{error}");
                    return mir_error_exit(&error);
                }
            };
            if let Err(error) = std::io::stdout().write_all(&bytes) {
                eprintln!("cannot write MIR observation: {error}");
                return EXIT_HARNESS;
            }
            EXIT_OK
        }
        Ok(MirScanOutcome::NotRun(not_run)) => {
            eprintln!(
                "MIR adapter NOT_RUN ({}): {}",
                not_run.reason.as_str(),
                not_run.detail
            );
            let value = match serde_json::to_value(&not_run) {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("cannot encode MIR NOT_RUN response: {error}");
                    return EXIT_HARNESS;
                }
            };
            let bytes = match crate::identity::canonical_bytes(&value) {
                Ok(bytes) => bytes,
                Err(error) => {
                    eprintln!("cannot encode MIR NOT_RUN response: {error}");
                    return EXIT_HARNESS;
                }
            };
            if let Err(error) = std::io::stdout().write_all(&bytes) {
                eprintln!("cannot write MIR NOT_RUN response: {error}");
                return EXIT_HARNESS;
            }
            EXIT_NOT_RUN
        }
        Err(error) => {
            eprintln!("{error}");
            mir_error_exit(&error)
        }
    }
}

fn mir_error_exit(error: &MirError) -> i32 {
    match error.category() {
        MirErrorCategory::Usage => EXIT_USAGE,
        MirErrorCategory::Integrity => EXIT_INTEGRITY,
        MirErrorCategory::Harness => EXIT_HARNESS,
    }
}

fn command_support(rest: &[String]) -> Result<i32, String> {
    let action = rest.first().map(String::as_str);
    if !matches!(action, Some("evaluate" | "explain")) {
        eprintln!("usage: support evaluate|explain FILE [--policy POLICY_FILE] [--expect-policy-digest MS1_ID] [--expect-policy-version VERSION]");
        return Ok(EXIT_USAGE);
    }
    let explain_mode = action == Some("explain");
    let Some(arguments) = parse_support_args(rest) else {
        eprintln!("usage: support evaluate|explain FILE [--policy POLICY_FILE] [--expect-policy-digest MS1_ID] [--expect-policy-version VERSION]");
        return Ok(EXIT_USAGE);
    };

    let file: SupportFile = match read_typed_file(&arguments.path, "support file") {
        Ok(file) => file,
        Err(code) => return Ok(code),
    };
    if let Err(error) = file.rules.validate() {
        eprintln!("invalid rule system: {error}");
        return Ok(EXIT_INTEGRITY);
    }

    let policy = match bind_policy(&arguments, &file) {
        Ok(policy) => policy,
        Err(code) => return Ok(code),
    };
    if let Some(policy) = &policy {
        if let Err((code, error)) = check_policy_expectations(&arguments, policy) {
            eprintln!("{error}");
            return Ok(code);
        }
    } else if arguments.expect_policy_digest.is_some() || arguments.expect_policy_version.is_some()
    {
        eprintln!(
            "a policy identity is required for --expect-policy-digest or --expect-policy-version"
        );
        return Ok(EXIT_USAGE);
    }

    if explain_mode {
        let Some(claim) = file.claim.as_deref() else {
            eprintln!("support explain requires a \"claim\" field");
            return Ok(EXIT_USAGE);
        };
        let explanation = explain(&file.rules, claim, &file.revoked, &file.challenged, 256);
        emit_json(&explanation)?;
    } else {
        let result = evaluate(&file.rules, &file.revoked, &file.challenged);
        emit_json(&result)?;
    }
    Ok(EXIT_OK)
}

struct SupportArgs {
    path: String,
    policy_path: Option<String>,
    expect_policy_digest: Option<String>,
    expect_policy_version: Option<String>,
}

fn parse_support_args(rest: &[String]) -> Option<SupportArgs> {
    let mut path = None;
    let mut policy_path = None;
    let mut expect_policy_digest = None;
    let mut expect_policy_version = None;
    let mut index = 1;
    while index < rest.len() {
        match rest[index].as_str() {
            "--policy" => {
                index += 1;
                if policy_path.is_some() {
                    return None;
                }
                policy_path = Some(rest.get(index)?.clone());
            }
            "--expect-policy-digest" => {
                index += 1;
                if expect_policy_digest.is_some() {
                    return None;
                }
                expect_policy_digest = Some(rest.get(index)?.clone());
            }
            "--expect-policy-version" => {
                index += 1;
                if expect_policy_version.is_some() {
                    return None;
                }
                expect_policy_version = Some(rest.get(index)?.clone());
            }
            value if value.starts_with("--") => return None,
            value => {
                if path.is_some() {
                    return None;
                }
                path = Some(value.to_owned());
            }
        }
        index += 1;
    }
    Some(SupportArgs {
        path: path?,
        policy_path,
        expect_policy_digest,
        expect_policy_version,
    })
}

fn bind_policy(arguments: &SupportArgs, file: &SupportFile) -> Result<Option<SupportPolicy>, i32> {
    let mut identity = file.policy.clone();
    if let Some(path) = &arguments.policy_path {
        let policy: PolicyFile = read_typed_file(path, "policy file")?;
        if let Err(error) = policy.rules.validate() {
            eprintln!("invalid policy rule system: {error}");
            return Err(EXIT_INTEGRITY);
        }
        if policy.rules != file.rules {
            eprintln!(
                "policy rules differ from the support file rules; policy substitution rejected"
            );
            return Err(EXIT_INTEGRITY);
        }
        if identity
            .as_ref()
            .is_some_and(|identity| identity.id != policy.id || identity.version != policy.version)
        {
            eprintln!("support file policy identity differs from the policy file");
            return Err(EXIT_INTEGRITY);
        }
        identity = Some(PolicyIdentity {
            id: policy.id,
            version: policy.version,
        });
    }
    Ok(identity.map(|identity| SupportPolicy {
        id: identity.id,
        version: identity.version,
        rules: file.rules.clone(),
    }))
}

fn check_policy_expectations(
    arguments: &SupportArgs,
    policy: &SupportPolicy,
) -> Result<(), (i32, String)> {
    let digest = policy.digest().map_err(|error| {
        (
            EXIT_INTEGRITY,
            format!("cannot compute policy digest: {error}"),
        )
    })?;
    if let Some(expected) = &arguments.expect_policy_digest {
        let expected = MsId::parse(expected.clone()).map_err(|error| {
            (
                EXIT_USAGE,
                format!("invalid expected policy digest: {error}"),
            )
        })?;
        if digest != expected {
            return Err((
                EXIT_INTEGRITY,
                "policy digest differs from the expected digest; policy substitution rejected"
                    .to_owned(),
            ));
        }
    }
    if arguments
        .expect_policy_version
        .as_ref()
        .is_some_and(|expected| policy.version != *expected)
    {
        return Err((
            EXIT_INTEGRITY,
            "policy version differs from the expected version; policy substitution rejected"
                .to_owned(),
        ));
    }
    Ok(())
}

fn read_typed_file<T: DeserializeOwned>(path: &str, label: &str) -> Result<T, i32> {
    let bytes = match read_limited(Path::new(path)) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("{error}");
            return Err(EXIT_USAGE);
        }
    };
    let value = match parse_strict(&bytes) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("invalid {label}: {error}");
            return Err(EXIT_INTEGRITY);
        }
    };
    match serde_json::from_value(value) {
        Ok(file) => Ok(file),
        Err(error) => {
            eprintln!("invalid {label}: {error}");
            Err(EXIT_INTEGRITY)
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyIdentity {
    id: String,
    version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    id: String,
    version: String,
    rules: RuleSystem,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupportFile {
    #[serde(default, rename = "schema")]
    _schema: Option<String>,
    #[serde(default, rename = "spec")]
    _spec: Option<String>,
    rules: RuleSystem,
    #[serde(default)]
    revoked: BTreeSet<String>,
    #[serde(default)]
    challenged: BTreeSet<String>,
    #[serde(default)]
    claim: Option<String>,
    #[serde(default)]
    policy: Option<PolicyIdentity>,
}

fn command_evidence(rest: &[String]) -> Result<i32, String> {
    if rest.first().map(String::as_str) != Some("verify") || rest.len() != 3 || rest[1] != "--root"
    {
        eprintln!("usage: evidence verify --root DIR");
        return Ok(EXIT_USAGE);
    }
    let root = Path::new(&rest[2]);
    if !root.is_dir() {
        eprintln!("not a directory: {}", root.display());
        return Ok(EXIT_USAGE);
    }

    let mut files = Vec::new();
    let mut walk_error = None;
    walk_json(root, 0, &mut files, &mut walk_error);
    if let Some(error) = walk_error {
        eprintln!("{error}");
        return Ok(EXIT_HARNESS);
    }
    files.sort();

    let mut checked = 0usize;
    let mut canonical = 0usize;
    let mut errors = Vec::new();
    for path in files {
        checked += 1;
        match read_limited(&path) {
            Ok(bytes) => match require_canonical(&bytes) {
                Ok(_) => canonical += 1,
                Err(error) => errors.push(serde_json::json!({
                    "file": path.display().to_string(),
                    "error": error.to_string(),
                })),
            },
            Err(error) => errors.push(serde_json::json!({
                "file": path.display().to_string(),
                "error": error,
            })),
        }
    }
    let ok = errors.is_empty();
    emit_json(&serde_json::json!({
        "root": root.display().to_string(),
        "files_checked": checked,
        "canonical": canonical,
        "errors": errors,
        "status": if ok { "OK" } else { "INVALID_EVIDENCE" },
    }))?;
    Ok(if ok { EXIT_OK } else { EXIT_INTEGRITY })
}

fn walk_json(directory: &Path, depth: usize, files: &mut Vec<PathBuf>, error: &mut Option<String>) {
    if depth > 64 {
        *error = Some(format!(
            "directory nesting exceeds 64 at {}",
            directory.display()
        ));
        return;
    }
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(read_error) => {
            *error = Some(format!("cannot read {}: {read_error}", directory.display()));
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(read_error) => {
                *error = Some(format!(
                    "cannot read entry in {}: {read_error}",
                    directory.display()
                ));
                return;
            }
        };
        let path = entry.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(metadata_error) => {
                *error = Some(format!("cannot stat {}: {metadata_error}", path.display()));
                return;
            }
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            walk_json(&path, depth + 1, files, error);
        } else if metadata.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            files.push(path);
        }
    }
}

fn command_report(rest: &[String]) -> Result<i32, String> {
    let mut case = None;
    let mut format = None;
    let mut index = 0usize;
    while index < rest.len() {
        match rest[index].as_str() {
            "--case" => {
                let Some(value) = rest.get(index + 1) else {
                    eprintln!("usage: report --case FILE --format json|markdown");
                    return Ok(EXIT_USAGE);
                };
                case = Some(value.clone());
                index += 2;
            }
            "--format" => {
                let Some(value) = rest.get(index + 1) else {
                    eprintln!("usage: report --case FILE --format json|markdown");
                    return Ok(EXIT_USAGE);
                };
                format = Some(value.clone());
                index += 2;
            }
            _ => {
                eprintln!("usage: report --case FILE --format json|markdown");
                return Ok(EXIT_USAGE);
            }
        }
    }
    let (Some(case), Some(format)) = (case, format) else {
        eprintln!("usage: report --case FILE --format json|markdown");
        return Ok(EXIT_USAGE);
    };
    if format != "json" && format != "markdown" {
        eprintln!("--format must be json or markdown");
        return Ok(EXIT_USAGE);
    }
    let bytes = match read_limited(Path::new(&case)) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("{error}");
            return Ok(EXIT_USAGE);
        }
    };
    let evaluation = evaluate_profile_json(&bytes);
    if format == "json" {
        emit_json(&evaluation)?;
    } else {
        print!("{}", render_markdown(&case, &evaluation));
    }
    Ok(evaluation_exit_code(&evaluation))
}

fn render_markdown(case: &str, evaluation: &ProfileEvaluation) -> String {
    let mut output = String::new();
    output.push_str("# FRF-MemorySafety report\n\n");
    output.push_str(&format!("- Case file: `{case}`\n"));
    output.push_str(&format!(
        "- Protocol checks: {}\n",
        if evaluation.protocol_ok {
            "clean"
        } else {
            "refused"
        }
    ));
    output.push_str(&format!(
        "- Universal soundness: `{}` (not an established fact)\n\n",
        evaluation.universal_soundness
    ));
    if !evaluation.refusals.is_empty() {
        output.push_str("## Refusals\n\n");
        for refusal in &evaluation.refusals {
            output.push_str(&format!(
                "- `{}`{}: {}\n",
                refusal.kind.as_str(),
                refusal
                    .claim
                    .as_ref()
                    .map(|claim| format!(" ({claim})"))
                    .unwrap_or_default(),
                refusal.detail
            ));
        }
        output.push('\n');
    }
    output.push_str("## Claims\n\n");
    output.push_str("| claim | rule | property | disposition | cases | detail |\n");
    output.push_str("|---|---|---|---|---:|---|\n");
    for verdict in evaluation.claims.values() {
        output.push_str(&format!(
            "| `{}` | {:?} | {} | {:?} | {} | {} |\n",
            verdict.claim_id,
            verdict.rule,
            verdict.property,
            verdict.disposition,
            verdict.case_count,
            verdict.detail.replace('|', "\\|")
        ));
    }
    output
}

fn command_detector(rest: &[String]) -> Result<i32, String> {
    if rest.first().map(String::as_str) == Some("calibrate") {
        if rest.iter().any(|arg| arg == "--live") {
            not_run("detector calibrate --live")
        } else {
            eprintln!(
                "detector calibrate without --live is not implemented; live runs are NOT_RUN"
            );
            Ok(EXIT_USAGE)
        }
    } else {
        eprintln!("usage: detector calibrate --live ...");
        Ok(EXIT_USAGE)
    }
}

fn command_not_run(expected: &str, args: &[String]) -> Result<i32, String> {
    let matches = match expected {
        "court run" => {
            args.first().is_some_and(|arg| arg == "court")
                && args.get(1).is_some_and(|arg| arg == "run")
        }
        "frf promote" => {
            args.first().is_some_and(|arg| arg == "frf")
                && args.get(1).is_some_and(|arg| arg == "promote")
        }
        "gemel publish" => {
            args.first().is_some_and(|arg| arg == "gemel")
                && args.get(1).is_some_and(|arg| arg == "publish")
        }
        _ => false,
    };
    if !matches {
        eprintln!("unknown subcommand for {expected}");
        return Ok(EXIT_USAGE);
    }
    not_run(expected)
}

fn not_run(command: &str) -> Result<i32, String> {
    emit_json(&serde_json::json!({
        "status": "NOT_RUN",
        "command": command,
        "reason": "external integration is unavailable in this build",
        "universal_soundness": UNIVERSAL_SOUNDNESS,
    }))?;
    Ok(EXIT_NOT_RUN)
}

fn evaluation_exit_code(evaluation: &ProfileEvaluation) -> i32 {
    if evaluation
        .refusals
        .iter()
        .any(|refusal| refusal.kind.exit_code() == EXIT_INTEGRITY)
    {
        EXIT_INTEGRITY
    } else if evaluation.refusals.iter().any(|refusal| {
        refusal.kind.exit_code() == EXIT_REFUSED
            || refusal.kind == ProfileRefusalKind::UniversalOrNativeClaim
    }) {
        EXIT_REFUSED
    } else {
        EXIT_OK
    }
}

fn emit_json<T: Serialize>(value: &T) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|error| format!("cannot encode JSON: {error}"))?;
    println!("{text}");
    Ok(())
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let value =
        serde_json::to_value(value).map_err(|error| format!("cannot encode JSON: {error}"))?;
    let bytes = crate::identity::canonical_bytes(&value)
        .map_err(|error| format!("cannot canonicalize {}: {error}", path.display()))?;
    write_canonical(path, &bytes)
}

fn write_canonical(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

fn read_limited(path: &Path) -> Result<Vec<u8>, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("not a regular file: {}", path.display()));
    }
    let length = usize::try_from(metadata.len())
        .map_err(|_| format!("file is too large: {}", path.display()))?;
    if length > MAX_BYTES {
        return Err(format!(
            "file {} is {length} bytes; limit is {MAX_BYTES}",
            path.display()
        ));
    }
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() > MAX_BYTES {
        return Err(format!("file {} exceeds {MAX_BYTES} bytes", path.display()));
    }
    Ok(bytes)
}

/// Exit status for a support error, used by callers that embed the CLI.
#[must_use]
pub fn support_error_exit(error: &SupportError) -> i32 {
    match error {
        SupportError::PolicyMismatch | SupportError::HistoryMismatch(_) => EXIT_INTEGRITY,
        SupportError::UnjustifiedLeaf(_)
        | SupportError::UnknownClaim(_)
        | SupportError::CertificateLimitExceeded { .. } => EXIT_USAGE,
        SupportError::InconsistentSupport(_) => EXIT_HARNESS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_args(args: &[&str]) -> i32 {
        run(args.iter().copied())
    }

    #[test]
    fn version_json_is_available() {
        assert_eq!(run_args(&["version", "--json"]), EXIT_OK);
    }

    #[test]
    fn live_commands_are_not_run() {
        assert_eq!(run_args(&["court", "run", "x"]), EXIT_NOT_RUN);
        assert_eq!(run_args(&["detector", "calibrate", "--live"]), EXIT_NOT_RUN);
        assert_eq!(run_args(&["frf", "promote", "x"]), EXIT_NOT_RUN);
        assert_eq!(run_args(&["gemel", "publish", "x"]), EXIT_NOT_RUN);
    }

    #[test]
    fn unknown_command_is_usage_error() {
        assert_eq!(run_args(&["nope"]), EXIT_USAGE);
    }

    #[test]
    fn report_rejects_bad_format() {
        assert_eq!(
            run_args(&["report", "--case", "x", "--format", "yaml"]),
            EXIT_USAGE
        );
    }
}
