//! The nine constructed acceptance checks from paper §12.4.
//!
//! Provenance: these fixtures and expected outcomes are transcribed from the
//! paper's original executable oracle, not newly invented cases:
//!
//! * `research/paper/research/acceptance_cases.py`
//!   SHA-256 `3a577b985868d087db9ebb655a40da64d2e8844f7e75c2d2a14263777aa6e997`
//! * `research/paper/research/claim_model.py`
//!   SHA-256 `41eb75d88deb735313fda6c1f0c43129ee7179936340e2b12b1a416ac81ea23f`
//! * `research/paper/research/acceptance-cases-results.json`
//!   SHA-256 `abc4e0c2a080d2c918ce971e91caabcd7871ed70f14ac210d678d1d17665a2d5`
//!
//! The recorded results were produced with Python 3.14.7. This test does not
//! execute the Python oracle; it replays the identical inputs through the Rust
//! engine and asserts the same exact outcomes. Agreement is a consistency
//! result, not authenticated historical execution or independent authorship of
//! the original cases.

use std::collections::BTreeSet;

use frf_memorysafety::closure::{compare_inventory, CoverageOutcome, EdgeKey};
use frf_memorysafety::identity::canonical_bytes;
use frf_memorysafety::support::{
    certificates, evaluate, exact_cut, reconstruct_recorded_verdict, HistoricVerdict, RuleSystem,
    SupportPolicy, SupportResult,
};
use sha2::{Digest, Sha256};

fn edges(items: &[(&str, &str)]) -> BTreeSet<EdgeKey> {
    items
        .iter()
        .map(|(caller, callback)| EdgeKey::new(*caller, *callback))
        .collect()
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn declared() -> BTreeSet<EdgeKey> {
    edges(&[("entry", "read")])
}

// Group A: observed versus declared edges. Only an observed omission falsifies.

#[test]
fn observed_omission_falsifies_the_inventory() {
    let observed = edges(&[("entry", "callback")]);
    let outcome = compare_inventory(&declared(), &observed);
    assert!(outcome.is_falsified());
    assert!(!outcome.is_conservative_closure());
    assert_eq!(
        outcome,
        CoverageOutcome::Falsified {
            observed_omissions: edges(&[("entry", "callback")]),
        }
    );
}

#[test]
fn unexercised_callback_is_not_falsified_and_not_closure() {
    let outcome = compare_inventory(&declared(), &BTreeSet::new());
    assert!(!outcome.is_falsified());
    assert!(!outcome.is_conservative_closure());
    assert_eq!(
        outcome,
        CoverageOutcome::NotFalsified {
            matched: BTreeSet::new(),
            unobserved_declared: declared(),
        }
    );
}

#[test]
fn observed_declared_edge_is_not_falsified_and_not_closure() {
    let outcome = compare_inventory(&declared(), &declared());
    assert!(!outcome.is_falsified());
    assert!(!outcome.is_conservative_closure());
    assert_eq!(
        outcome,
        CoverageOutcome::NotFalsified {
            matched: declared(),
            unobserved_declared: BTreeSet::new(),
        }
    );
}

// Group B: identical evidence bytes, changed policy identity, historical replay.

fn policy(version: &str, rules: RuleSystem) -> SupportPolicy {
    SupportPolicy {
        id: "section-12-4-policy".to_owned(),
        version: version.to_owned(),
        rules,
    }
}

fn policy_pair() -> (SupportPolicy, SupportPolicy) {
    let mut original_rules = RuleSystem::new();
    original_rules.admit_leaf("e");
    original_rules.add_rule("q", ["e".to_owned()]).unwrap();

    let mut revised_rules = RuleSystem::new();
    revised_rules.admit_leaf("e");

    (
        policy("original", original_rules),
        policy("revised", revised_rules),
    )
}

fn decision_bytes(
    evidence_sha256: &str,
    policy: &SupportPolicy,
    result: &SupportResult,
) -> Vec<u8> {
    let policy_digest = policy.digest().unwrap();
    let value = serde_json::json!({
        "evidence_sha256": evidence_sha256,
        "policy_sha256": policy_digest.as_str(),
        "supported": result.positive.iter().collect::<Vec<_>>(),
    });
    canonical_bytes(&value).unwrap()
}

#[test]
fn old_policy_supports_the_conclusion() {
    let (original, _) = policy_pair();
    let result = evaluate(&original.rules, &BTreeSet::new(), &BTreeSet::new());
    assert_eq!(result.positive, set(&["e", "q"]));
}

#[test]
fn new_policy_withholds_the_conclusion_under_identical_evidence() {
    let (_, revised) = policy_pair();
    let evidence = b"{\"candidate\":\"abstract-C\",\"kind\":\"stipulated_leaf\",\"value\":7}";
    let evidence_before = evidence.to_vec();
    let result = evaluate(&revised.rules, &BTreeSet::new(), &BTreeSet::new());

    assert_eq!(result.positive, set(&["e"]));
    assert_eq!(
        &evidence[..],
        evidence_before.as_slice(),
        "the policy change does not alter evidence bytes"
    );
}

#[test]
fn historical_decision_is_reconstructed_under_its_original_policy() {
    let (original, revised) = policy_pair();
    let evidence = b"{\"candidate\":\"abstract-C\",\"kind\":\"stipulated_leaf\",\"value\":7}";
    let evidence_sha256 = format!("{:x}", Sha256::digest(evidence));
    let evidence_before = evidence.to_vec();

    let original_result = evaluate(&original.rules, &BTreeSet::new(), &BTreeSet::new());
    let historical_bytes = decision_bytes(&evidence_sha256, &original, &original_result);
    let history = HistoricVerdict::record(&original, &BTreeSet::new(), &BTreeSet::new()).unwrap();
    let reconstructed = reconstruct_recorded_verdict(&history, &original, &revised).unwrap();

    assert!(reconstructed.byte_identical_historical);
    assert_eq!(
        decision_bytes(&evidence_sha256, &original, &reconstructed.historical),
        historical_bytes,
        "historical decision bytes are unchanged"
    );
    assert_eq!(reconstructed.historical.positive, set(&["e", "q"]));
    assert_eq!(reconstructed.current.positive, set(&["e"]));
    assert_ne!(
        original.digest().unwrap(),
        revised.digest().unwrap(),
        "the policies have different identities"
    );
    assert_eq!(&evidence[..], evidence_before.as_slice());
    assert!(
        history.verify(&revised).is_err(),
        "the revised policy cannot be substituted for the recorded one"
    );
}

// Group C: two routes sharing one mapping premise, then an independent route.

fn shared_mapping_system() -> RuleSystem {
    let mut system = RuleSystem::new();
    system.admit_leaf("m");
    system.add_rule("a", ["m".to_owned()]).unwrap();
    system.add_rule("b", ["m".to_owned()]).unwrap();
    system.admit_leaf("c");
    system.add_rule("q", ["a".to_owned()]).unwrap();
    system.add_rule("q", ["b".to_owned()]).unwrap();
    system
}

fn alternate_support_system() -> RuleSystem {
    let mut system = shared_mapping_system();
    system.add_rule("q", ["c".to_owned()]).unwrap();
    system
}

#[test]
fn shared_mapping_defeats_both_routes() {
    let system = shared_mapping_system();
    let excluded = set(&["m"]);
    let result = evaluate(&system, &excluded, &BTreeSet::new());
    assert_eq!(result.positive, set(&["c"]));

    let certs = certificates(&system, "q", &BTreeSet::new(), 16).unwrap();
    assert!(exact_cut(&certs, &excluded));
}

#[test]
fn support_without_the_failed_mapping_survives() {
    let system = alternate_support_system();
    let excluded = set(&["m"]);
    let result = evaluate(&system, &excluded, &BTreeSet::new());
    assert_eq!(result.positive, set(&["c", "q"]));

    let certs = certificates(&system, "q", &BTreeSet::new(), 16).unwrap();
    assert!(!exact_cut(&certs, &excluded));
    assert!(certs.contains(&set(&["c", "q"])));
}

#[test]
fn all_available_routes_blocked() {
    let system = alternate_support_system();
    let excluded = set(&["m", "c"]);
    let result = evaluate(&system, &excluded, &BTreeSet::new());
    assert_eq!(result.positive, BTreeSet::new());

    let certs = certificates(&system, "q", &BTreeSet::new(), 16).unwrap();
    assert!(exact_cut(&certs, &excluded));
}
