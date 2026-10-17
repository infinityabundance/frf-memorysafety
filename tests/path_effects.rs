//! Phase 3.2 seal controls for explicit path effects.
//!
//! The fixtures are explicit finite inputs. They are not source extraction,
//! native callback observation, or whole-program alias analysis.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use frf_memorysafety::identity::require_canonical;
use frf_memorysafety::path_effect::{
    analyze, analyze_inventory, path_input_from_inventory, PathEffectsInput, PathReport,
    QualifiedOutcome, QualifiedStatus, PATH_EFFECT_INPUT_SCHEMA, PATH_EFFECT_REPORT_SCHEMA,
};
use frf_memorysafety::source::{scan_source_default, SOURCE_INVENTORY_SCHEMA};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "frf-memorysafety-path-{label}-{}-{sequence}",
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

fn analyze_json(text: &str) -> PathReport {
    let input: PathEffectsInput = serde_json::from_str(text).expect("valid explicit input");
    analyze(&input).expect("analysis completes")
}

fn has_status(report: &PathReport, status: QualifiedStatus) -> bool {
    report
        .outcomes
        .iter()
        .any(|outcome| outcome.status == status)
}

fn has_code(report: &PathReport, code: &str) -> bool {
    report.outcomes.iter().any(|outcome| outcome.code == code)
}

fn has_unknown(report: &PathReport, code: &str) -> bool {
    report.unknowns.iter().any(|unknown| unknown.code == code)
}

fn outcome<'a>(report: &'a PathReport, code: &str) -> &'a QualifiedOutcome {
    report
        .outcomes
        .iter()
        .find(|outcome| outcome.code == code)
        .unwrap_or_else(|| panic!("missing outcome {code}"))
}

fn statuses(report: &PathReport) -> BTreeSet<QualifiedStatus> {
    report
        .outcomes
        .iter()
        .map(|outcome| outcome.status)
        .collect()
}

fn interval(id: &str, alias: &str, start: u64, end: Option<u64>) -> String {
    match end {
        Some(end) => format!(r#"{{"id":"{id}","alias":"{alias}","start":{start},"end":{end}}}"#),
        None => format!(r#"{{"id":"{id}","alias":"{alias}","start":{start}}}"#),
    }
}

fn footprint(kind: &str) -> String {
    format!(r#"{{"kind":"{kind}"}}"#)
}

fn footprint_range(kind: &str, offset: u64, length: u64) -> String {
    format!(r#"{{"kind":"{kind}","range":{{"offset":{offset},"length":{length}}}}}"#)
}

#[allow(clippy::too_many_arguments)]
fn event(
    point: u64,
    kind: &str,
    alias: &str,
    access: &str,
    footprint: &str,
    interval: Option<&str>,
    callback: Option<&str>,
) -> String {
    let interval = interval.map_or_else(String::new, |id| format!(r#","interval":"{id}""#));
    let callback = callback.map_or_else(String::new, |id| format!(r#","callback":"{id}""#));
    format!(
        r#"{{"point":{point},"kind":"{kind}","alias":"{alias}","access":"{access}","footprint":{footprint}{interval}{callback}}}"#
    )
}

const HEAD: &str =
    r#""schema":"frf-memorysafety.path-effects-input.v1","spec":"frf-memorysafety-spec-v1""#;

fn document(
    objects: &[String],
    aliases: &[String],
    intervals: &[String],
    events: &[String],
    callbacks: &[String],
    providers: &[String],
) -> String {
    format!(
        r#"{{{HEAD},"objects":[{}],"aliases":[{}],"intervals":[{}],"events":[{}],"callbacks":[{}],"providers":[{}]}}"#,
        objects.join(","),
        aliases.join(","),
        intervals.join(","),
        events.join(","),
        callbacks.join(","),
        providers.join(",")
    )
}

fn object(id: &str, interior_mutable: bool) -> String {
    format!(r#"{{"id":"{id}","interior_mutable":{interior_mutable}}}"#)
}

fn exact_alias(id: &str, object: &str) -> String {
    format!(r#"{{"id":"{id}","kind":"exact_object","object":"{object}"}}"#)
}

fn descendant_alias(id: &str, object: &str, offset: u64, length: u64) -> String {
    format!(
        r#"{{"id":"{id}","kind":"descendant","object":"{object}","range":{{"offset":{offset},"length":{length}}}}}"#
    )
}

fn shared_alias(id: &str, mapping: &str, offset: u64, length: u64) -> String {
    format!(
        r#"{{"id":"{id}","kind":"shared_mapping","mapping":"{mapping}","range":{{"offset":{offset},"length":{length}}}}}"#
    )
}

fn top_alias(id: &str) -> String {
    format!(r#"{{"id":"{id}","kind":"top_unknown"}}"#)
}

fn callback(id: &str, behavior: &str, legally_absent: bool) -> String {
    format!(r#"{{"id":"{id}","behavior":"{behavior}","legally_absent":{legally_absent}}}"#)
}

fn provider(id: &str, behavior: &str) -> String {
    format!(r#"{{"id":"{id}","behavior":"{behavior}"}}"#)
}

// ---------------------------------------------------------------------------
// Alias mutants: exact vs descendant, descendant vs top, shared mapping, omitted
// ---------------------------------------------------------------------------

#[test]
fn exact_and_descendant_aliases_are_not_confused() {
    let objects = vec![object("a", false)];
    let exact = document(
        &objects,
        &[
            exact_alias("whole", "a"),
            descendant_alias("part", "a", 8, 8),
        ],
        &[
            interval("i1", "whole", 0, Some(10)),
            interval("i2", "part", 0, Some(10)),
        ],
        &[
            event(
                0,
                "use",
                "whole",
                "write",
                &footprint("exact"),
                Some("i1"),
                None,
            ),
            event(
                1,
                "use",
                "part",
                "write",
                &footprint("descendant"),
                Some("i2"),
                None,
            ),
        ],
        &[],
        &[],
    );
    let exact_report = analyze_json(&exact);
    assert_eq!(exact_report.overall, QualifiedStatus::ObservedConflict);
    assert!(has_code(&exact_report, "definite_write_overlap"));

    let descendant = document(
        &objects,
        &[
            descendant_alias("whole", "a", 0, 8),
            descendant_alias("part", "a", 8, 8),
        ],
        &[
            interval("i1", "whole", 0, Some(10)),
            interval("i2", "part", 0, Some(10)),
        ],
        &[
            event(
                0,
                "use",
                "whole",
                "write",
                &footprint_range("descendant", 0, 8),
                Some("i1"),
                None,
            ),
            event(
                1,
                "use",
                "part",
                "write",
                &footprint_range("descendant", 8, 8),
                Some("i2"),
                None,
            ),
        ],
        &[],
        &[],
    );
    let descendant_report = analyze_json(&descendant);
    assert_eq!(
        descendant_report.overall,
        QualifiedStatus::CompatibleWithinFiniteFootprint
    );
    assert!(!has_status(
        &descendant_report,
        QualifiedStatus::ObservedConflict
    ));
    assert_ne!(exact_report.overall, descendant_report.overall);
}

#[test]
fn descendant_and_top_aliases_are_not_confused() {
    let objects = vec![object("a", false)];
    let descendant = document(
        &objects,
        &[
            descendant_alias("p", "a", 0, 8),
            descendant_alias("q", "a", 8, 8),
        ],
        &[
            interval("i1", "p", 0, Some(10)),
            interval("i2", "q", 0, Some(10)),
        ],
        &[
            event(
                0,
                "use",
                "p",
                "write",
                &footprint("descendant"),
                Some("i1"),
                None,
            ),
            event(
                1,
                "use",
                "q",
                "write",
                &footprint("descendant"),
                Some("i2"),
                None,
            ),
        ],
        &[],
        &[],
    );
    let descendant_report = analyze_json(&descendant);
    assert_eq!(
        descendant_report.overall,
        QualifiedStatus::CompatibleWithinFiniteFootprint
    );

    let top = document(
        &objects,
        &[descendant_alias("p", "a", 0, 8), top_alias("u")],
        &[
            interval("i1", "p", 0, Some(10)),
            interval("i2", "u", 0, Some(10)),
        ],
        &[
            event(
                0,
                "use",
                "p",
                "write",
                &footprint("descendant"),
                Some("i1"),
                None,
            ),
            event(1, "use", "u", "write", &footprint("top"), Some("i2"), None),
        ],
        &[],
        &[],
    );
    let top_report = analyze_json(&top);
    assert_eq!(top_report.overall, QualifiedStatus::NotFalsified);
    assert!(!has_status(&top_report, QualifiedStatus::ObservedConflict));
    assert!(!has_status(
        &top_report,
        QualifiedStatus::CompatibleWithinFiniteFootprint
    ));
    assert!(has_code(&top_report, "possible_write_overlap"));
    assert!(has_code(&top_report, "top_unknown_alias"));
    assert!(has_unknown(&top_report, "alias_identity_unknown"));
    assert!(has_unknown(&top_report, "footprint_extent_unknown"));
}

#[test]
fn wrong_shared_mapping_is_not_treated_as_independent() {
    let objects = vec![object("a", false), object("b", false)];

    // A shared-mapping alias is not silently treated as an independent exact
    // allocation, even when its explicit range is disjoint from the other
    // alias's range.
    let shared = document(
        &objects,
        &[exact_alias("p", "a"), shared_alias("s", "m", 8, 8)],
        &[
            interval("i1", "p", 0, Some(10)),
            interval("i2", "s", 0, Some(10)),
        ],
        &[
            event(
                0,
                "use",
                "p",
                "write",
                &footprint("exact"),
                Some("i1"),
                None,
            ),
            event(
                1,
                "use",
                "s",
                "write",
                &footprint("descendant"),
                Some("i2"),
                None,
            ),
        ],
        &[],
        &[],
    );
    let shared_report = analyze_json(&shared);
    assert_eq!(shared_report.overall, QualifiedStatus::NotFalsified);
    assert!(!has_status(
        &shared_report,
        QualifiedStatus::CompatibleWithinFiniteFootprint
    ));
    assert!(has_unknown(&shared_report, "shared_mapping_alias"));

    let independent = document(
        &objects,
        &[exact_alias("p", "a"), exact_alias("s", "b")],
        &[
            interval("i1", "p", 0, Some(10)),
            interval("i2", "s", 0, Some(10)),
        ],
        &[
            event(
                0,
                "use",
                "p",
                "write",
                &footprint("exact"),
                Some("i1"),
                None,
            ),
            event(
                1,
                "use",
                "s",
                "write",
                &footprint("exact"),
                Some("i2"),
                None,
            ),
        ],
        &[],
        &[],
    );
    let independent_report = analyze_json(&independent);
    assert_eq!(
        independent_report.overall,
        QualifiedStatus::CompatibleWithinFiniteFootprint
    );
    assert_ne!(shared_report.overall, independent_report.overall);
}

#[test]
fn shared_mapping_overlap_can_still_be_an_observed_conflict() {
    let objects = vec![object("a", false)];
    let shared = document(
        &objects,
        &[shared_alias("s1", "m", 0, 8), shared_alias("s2", "m", 0, 8)],
        &[
            interval("i1", "s1", 0, Some(10)),
            interval("i2", "s2", 0, Some(10)),
        ],
        &[
            event(
                0,
                "use",
                "s1",
                "write",
                &footprint("descendant"),
                Some("i1"),
                None,
            ),
            event(
                1,
                "use",
                "s2",
                "write",
                &footprint("descendant"),
                Some("i2"),
                None,
            ),
        ],
        &[],
        &[],
    );
    let report = analyze_json(&shared);
    assert_eq!(report.overall, QualifiedStatus::ObservedConflict);
    assert!(has_code(&report, "definite_write_overlap"));
    assert!(has_unknown(&report, "shared_mapping_alias"));
}

#[test]
fn omitted_alias_is_not_evidence_of_compatibility() {
    let objects = vec![object("a", false)];
    let base = document(
        &objects,
        &[
            descendant_alias("p", "a", 0, 8),
            descendant_alias("q", "a", 8, 8),
        ],
        &[
            interval("i1", "p", 0, Some(10)),
            interval("i2", "q", 0, Some(10)),
        ],
        &[
            event(
                0,
                "use",
                "p",
                "write",
                &footprint("descendant"),
                Some("i1"),
                None,
            ),
            event(
                1,
                "use",
                "q",
                "write",
                &footprint("descendant"),
                Some("i2"),
                None,
            ),
        ],
        &[],
        &[],
    );
    let base_report = analyze_json(&base);
    assert_eq!(
        base_report.overall,
        QualifiedStatus::CompatibleWithinFiniteFootprint
    );

    let with_omitted = document(
        &objects,
        &[
            descendant_alias("p", "a", 0, 8),
            descendant_alias("q", "a", 8, 8),
            top_alias("u"),
        ],
        &[
            interval("i1", "p", 0, Some(10)),
            interval("i2", "q", 0, Some(10)),
            interval("i3", "u", 0, Some(10)),
        ],
        &[
            event(
                0,
                "use",
                "p",
                "write",
                &footprint("descendant"),
                Some("i1"),
                None,
            ),
            event(
                1,
                "use",
                "q",
                "write",
                &footprint("descendant"),
                Some("i2"),
                None,
            ),
            event(2, "use", "u", "write", &footprint("top"), Some("i3"), None),
        ],
        &[],
        &[],
    );
    let with_report = analyze_json(&with_omitted);
    assert_eq!(with_report.overall, QualifiedStatus::NotFalsified);
    assert_ne!(base_report.overall, with_report.overall);
}

// ---------------------------------------------------------------------------
// Benign controls: UnsafeCell interior mutation and independent allocations
// ---------------------------------------------------------------------------

#[test]
fn unsafecell_interior_mutation_is_compatible() {
    let objects = vec![object("cell", true)];
    let input = document(
        &objects,
        &[
            exact_alias("shared", "cell"),
            exact_alias("mutable", "cell"),
        ],
        &[
            interval("i1", "shared", 0, Some(10)),
            interval("i2", "mutable", 0, Some(10)),
        ],
        &[
            event(
                0,
                "use",
                "shared",
                "read",
                &footprint("exact"),
                Some("i1"),
                None,
            ),
            event(
                1,
                "use",
                "mutable",
                "write",
                &footprint("exact"),
                Some("i2"),
                None,
            ),
        ],
        &[],
        &[],
    );
    let report = analyze_json(&input);
    assert_eq!(
        report.overall,
        QualifiedStatus::CompatibleWithinFiniteFootprint
    );
    assert!(!has_status(&report, QualifiedStatus::ObservedConflict));
}

#[test]
fn unsafecell_flag_does_not_hide_write_write_conflict() {
    let objects = vec![object("cell", true)];
    let input = document(
        &objects,
        &[exact_alias("p", "cell"), exact_alias("q", "cell")],
        &[
            interval("i1", "p", 0, Some(10)),
            interval("i2", "q", 0, Some(10)),
        ],
        &[
            event(
                0,
                "use",
                "p",
                "write",
                &footprint("exact"),
                Some("i1"),
                None,
            ),
            event(
                1,
                "use",
                "q",
                "write",
                &footprint("exact"),
                Some("i2"),
                None,
            ),
        ],
        &[],
        &[],
    );
    let report = analyze_json(&input);
    assert_eq!(report.overall, QualifiedStatus::ObservedConflict);
    assert!(has_code(&report, "definite_write_overlap"));
}

#[test]
fn two_independent_allocations_are_compatible() {
    let objects = vec![object("a", false), object("b", false)];
    let input = document(
        &objects,
        &[exact_alias("pa", "a"), exact_alias("pb", "b")],
        &[
            interval("i1", "pa", 0, Some(10)),
            interval("i2", "pb", 0, Some(10)),
        ],
        &[
            event(
                0,
                "use",
                "pa",
                "write",
                &footprint("exact"),
                Some("i1"),
                None,
            ),
            event(
                1,
                "use",
                "pb",
                "write",
                &footprint("exact"),
                Some("i2"),
                None,
            ),
        ],
        &[],
        &[],
    );
    let report = analyze_json(&input);
    assert_eq!(
        report.overall,
        QualifiedStatus::CompatibleWithinFiniteFootprint
    );
    assert!(!has_status(&report, QualifiedStatus::ObservedConflict));
}

// ---------------------------------------------------------------------------
// C callback controls
// ---------------------------------------------------------------------------

fn synchronous_callback(behavior: &str, legally_absent: bool) -> String {
    document(
        &[object("a", false)],
        &[exact_alias("p", "a")],
        &[interval("i1", "p", 0, Some(10))],
        &[
            event(
                0,
                "creation",
                "p",
                "none",
                &footprint("exact"),
                Some("i1"),
                None,
            ),
            event(
                1,
                "callback",
                "p",
                "read",
                &footprint("exact"),
                Some("i1"),
                Some("cb"),
            ),
        ],
        &[callback("cb", behavior, legally_absent)],
        &[],
    )
}

#[test]
fn synchronous_callback_is_compatible() {
    let report = analyze_json(&synchronous_callback("synchronous_legal", false));
    assert_eq!(
        report.overall,
        QualifiedStatus::CompatibleWithinFiniteFootprint
    );
}

#[test]
fn retained_pointer_callback_is_not_falsified() {
    let report = analyze_json(&synchronous_callback("retained_pointer", false));
    assert_eq!(report.overall, QualifiedStatus::NotFalsified);
    assert!(has_code(&report, "retained_pointer_escaped"));
    assert!(has_unknown(&report, "retained_pointer_escaped"));
}

#[test]
fn deferred_callback_is_not_falsified() {
    let report = analyze_json(&synchronous_callback("deferred", false));
    assert_eq!(report.overall, QualifiedStatus::NotFalsified);
    assert!(has_code(&report, "deferred_callback"));
    assert!(has_unknown(&report, "deferred_callback"));
}

#[test]
fn callback_after_free_is_observed_conflict() {
    let input = document(
        &[object("a", false)],
        &[exact_alias("p", "a")],
        &[],
        &[
            event(0, "free", "p", "none", &footprint("exact"), None, None),
            event(
                1,
                "callback",
                "p",
                "read",
                &footprint("exact"),
                None,
                Some("cb"),
            ),
        ],
        &[callback("cb", "callback_after_free", false)],
        &[],
    );
    let report = analyze_json(&input);
    assert_eq!(report.overall, QualifiedStatus::ObservedConflict);
    assert!(has_code(&report, "callback_after_free"));
    let outcome = outcome(&report, "callback_after_free");
    assert_eq!(outcome.evidence.len(), 2);
    assert_eq!(outcome.evidence[0].kind.as_str(), "free");
    assert_eq!(outcome.evidence[1].kind.as_str(), "callback");
}

#[test]
fn foreign_provider_dispatch_is_not_falsified() {
    let input = document(
        &[object("a", false)],
        &[exact_alias("p", "a")],
        &[interval("i1", "p", 0, Some(10))],
        &[
            event(
                0,
                "creation",
                "p",
                "none",
                &footprint("exact"),
                Some("i1"),
                None,
            ),
            event(
                1,
                "callback",
                "p",
                "read",
                &footprint("exact"),
                Some("i1"),
                Some("cb"),
            ),
        ],
        &[callback("cb", "foreign_provider_dispatch", false)],
        &[
            provider("foreign", "foreign_unknown"),
            provider("dyn", "dynamic_dispatch"),
        ],
    );
    let report = analyze_json(&input);
    assert_eq!(report.overall, QualifiedStatus::NotFalsified);
    assert!(has_code(&report, "foreign_provider_dispatch"));
    assert!(has_code(&report, "foreign_provider_behavior_unknown"));
    assert!(has_code(&report, "dynamic_dispatch_unknown"));
    assert!(!has_status(&report, QualifiedStatus::ObservedConflict));
}

// ---------------------------------------------------------------------------
// Paper §12.4: omission and not-falsified differ without an observed conflict
// ---------------------------------------------------------------------------

#[test]
fn omission_and_not_falsified_differ_without_an_observed_conflict() {
    let omitted = document(
        &[],
        &[],
        &[],
        &[],
        &[callback("cb", "synchronous_legal", true)],
        &[],
    );
    let omitted_report = analyze_json(&omitted);
    assert_eq!(omitted_report.overall, QualifiedStatus::Omission);
    assert!(has_status(&omitted_report, QualifiedStatus::Omission));
    assert!(!has_status(
        &omitted_report,
        QualifiedStatus::ObservedConflict
    ));
    assert!(has_code(&omitted_report, "callback_legally_absent"));

    let unknown = document(
        &[],
        &[],
        &[],
        &[],
        &[callback("cb", "deferred", false)],
        &[],
    );
    let unknown_report = analyze_json(&unknown);
    assert_eq!(unknown_report.overall, QualifiedStatus::NotFalsified);
    assert!(has_status(&unknown_report, QualifiedStatus::NotFalsified));
    assert!(!has_status(
        &unknown_report,
        QualifiedStatus::ObservedConflict
    ));
    assert!(has_code(&unknown_report, "callback_not_observed"));
    assert!(has_unknown(&unknown_report, "callback_not_observed"));

    assert_ne!(omitted_report.overall, unknown_report.overall);
    assert_ne!(statuses(&omitted_report), statuses(&unknown_report));
}

// ---------------------------------------------------------------------------
// Reference intervals
// ---------------------------------------------------------------------------

#[test]
fn reference_interval_membership_and_order_are_enforced() {
    let outside = document(
        &[object("a", false)],
        &[exact_alias("p", "a")],
        &[interval("i1", "p", 5, Some(10))],
        &[event(
            0,
            "use",
            "p",
            "write",
            &footprint("exact"),
            Some("i1"),
            None,
        )],
        &[],
        &[],
    );
    let outside_report = analyze_json(&outside);
    assert_eq!(outside_report.overall, QualifiedStatus::ObservedConflict);
    assert!(has_code(
        &outside_report,
        "event_outside_reference_interval"
    ));

    let ordered = document(
        &[object("a", false)],
        &[exact_alias("p", "a"), exact_alias("q", "a")],
        &[
            interval("i1", "p", 0, Some(2)),
            interval("i2", "q", 2, Some(4)),
        ],
        &[
            event(
                0,
                "use",
                "p",
                "write",
                &footprint("exact"),
                Some("i1"),
                None,
            ),
            event(
                2,
                "use",
                "q",
                "write",
                &footprint("exact"),
                Some("i2"),
                None,
            ),
        ],
        &[],
        &[],
    );
    let ordered_report = analyze_json(&ordered);
    assert_eq!(
        ordered_report.overall,
        QualifiedStatus::CompatibleWithinFiniteFootprint
    );
}

// ---------------------------------------------------------------------------
// Inventory consumption, CLI, determinism
// ---------------------------------------------------------------------------

#[test]
fn inventory_derived_path_effects_are_not_falsified() {
    let temp = TempDir::new("inventory");
    write(
        &temp.path().join("lib.rs"),
        r#"
use std::cell::UnsafeCell;

struct S { cell: UnsafeCell<u8> }

extern "C" { fn register(cb: extern "C" fn()); }

unsafe fn write_raw(p: *mut u8) { unsafe { *p = 1; } }

fn allocate() -> *mut u8 { Box::into_raw(Box::new(0)) }

fn release(p: *mut u8) { unsafe { drop(Box::from_raw(p)); } }

fn install(cb: extern "C" fn()) { unsafe { register(cb); } }
"#,
    );
    let inventory = scan_source_default(temp.path()).unwrap();
    let input = path_input_from_inventory(&inventory);
    assert!(input
        .aliases
        .iter()
        .any(|alias| alias.kind.as_str() == "top_unknown"));

    let report = analyze_inventory(&inventory).unwrap();
    assert_eq!(report.input_schema, SOURCE_INVENTORY_SCHEMA);
    assert_eq!(report.overall, QualifiedStatus::NotFalsified);
    assert!(has_unknown(&report, "top_unknown_alias"));
    assert!(has_unknown(&report, "foreign_provider_behavior_unknown"));
    assert!(!has_status(
        &report,
        QualifiedStatus::CompatibleWithinFiniteFootprint
    ));
}

#[test]
fn path_cli_accepts_explicit_and_inventory_inputs() {
    let temp = TempDir::new("cli");
    let explicit = temp.path().join("explicit.json");
    write(
        &explicit,
        &document(
            &[object("a", false)],
            &[exact_alias("p", "a")],
            &[interval("i1", "p", 0, Some(2))],
            &[event(
                0,
                "use",
                "p",
                "write",
                &footprint("exact"),
                Some("i1"),
                None,
            )],
            &[],
            &[],
        ),
    );
    assert_eq!(
        frf_memorysafety::cli::run([
            "path".to_owned(),
            "analyze".to_owned(),
            explicit.display().to_string(),
            "--json".to_owned()
        ]),
        0
    );

    let source = temp.path().join("src");
    write(
        &source.join("lib.rs"),
        r"
unsafe fn write_raw(p: *mut u8) { unsafe { *p = 1; } }
fn allocate() -> *mut u8 { Box::into_raw(Box::new(0)) }
",
    );
    let inventory = scan_source_default(&source).unwrap();
    let inventory_path = temp.path().join("inventory.json");
    fs::write(&inventory_path, inventory.canonical_bytes().unwrap()).unwrap();
    assert_eq!(
        frf_memorysafety::cli::run([
            "path".to_owned(),
            "analyze".to_owned(),
            inventory_path.display().to_string()
        ]),
        0
    );

    let bad_schema = temp.path().join("bad.json");
    write(&bad_schema, r#"{"schema":"unknown","spec":"x"}"#);
    assert_eq!(
        frf_memorysafety::cli::run([
            "path".to_owned(),
            "analyze".to_owned(),
            bad_schema.display().to_string()
        ]),
        3
    );

    assert_eq!(frf_memorysafety::cli::run(["path".to_owned()]), 2);
    assert_eq!(
        frf_memorysafety::cli::run(["path".to_owned(), "analyze".to_owned()]),
        2
    );
    assert_eq!(
        frf_memorysafety::cli::run([
            "path".to_owned(),
            "analyze".to_owned(),
            temp.path().join("missing.json").display().to_string()
        ]),
        2
    );
}

#[test]
fn path_report_is_deterministic_and_canonical() {
    let input = document(
        &[object("a", false)],
        &[exact_alias("p", "a")],
        &[interval("i1", "p", 0, Some(2))],
        &[event(
            0,
            "use",
            "p",
            "write",
            &footprint("exact"),
            Some("i1"),
            None,
        )],
        &[],
        &[],
    );
    let first = analyze_json(&input);
    let second = analyze_json(&input);
    assert_eq!(first, second);
    assert_eq!(first.schema, PATH_EFFECT_REPORT_SCHEMA);
    assert_eq!(first.input_schema, PATH_EFFECT_INPUT_SCHEMA);
    assert_eq!(first.input_sha256.len(), 64);
    let bytes = first.canonical_bytes().unwrap();
    assert_eq!(bytes, second.canonical_bytes().unwrap());
    require_canonical(&bytes).unwrap();
    assert_eq!(
        first.overall,
        QualifiedStatus::CompatibleWithinFiniteFootprint
    );
}
