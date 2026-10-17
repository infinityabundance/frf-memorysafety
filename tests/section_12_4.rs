//! The nine constructed acceptance cases described in paper §12.4.
//!
//! Group A compares declared and observed edge sets. Group B separates evidence
//! bytes, policy identity, and verdict. Group C exercises alternative support
//! through a shared mapping premise. All expected outcomes are exact.

use std::collections::BTreeSet;

use frf_memorysafety::closure::{compare_inventory, CoverageOutcome, EdgeKey};
use frf_memorysafety::support::{
    certificates, evaluate, exact_cut, reconstruct_recorded_verdict, HistoricVerdict, RuleSystem,
    SupportPolicy,
};

fn edges(items: &[(&str, &str)]) -> BTreeSet<EdgeKey> {
    items
        .iter()
        .map(|(caller, callback)| EdgeKey::new(*caller, *callback))
        .collect()
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn policy(version: &str, rules: RuleSystem) -> SupportPolicy {
    SupportPolicy {
        id: "section-12-4-policy".to_owned(),
        version: version.to_owned(),
        rules,
    }
}

#[test]
fn a1_observed_omission_falsifies_the_declared_inventory() {
    let declared = edges(&[("timer", "cb_a"), ("timer", "cb_b")]);
    let observed = edges(&[("timer", "cb_a"), ("timer", "cb_b"), ("timer", "cb_c")]);
    let outcome = compare_inventory(&declared, &observed);
    assert!(outcome.is_falsified());
    assert!(!outcome.is_conservative_closure());
    assert_eq!(
        outcome,
        CoverageOutcome::Falsified {
            observed_omissions: edges(&[("timer", "cb_c")]),
        }
    );
}

#[test]
fn a2_declared_but_unobserved_callback_is_not_falsified_and_not_closure() {
    let declared = edges(&[("timer", "cb_a"), ("timer", "cb_b")]);
    let observed = edges(&[("timer", "cb_a")]);
    let outcome = compare_inventory(&declared, &observed);
    assert!(!outcome.is_falsified());
    assert!(!outcome.is_conservative_closure());
    assert_eq!(
        outcome,
        CoverageOutcome::NotFalsified {
            matched: edges(&[("timer", "cb_a")]),
            unobserved_declared: edges(&[("timer", "cb_b")]),
        }
    );
}

#[test]
fn a3_observed_declared_callback_is_not_falsified_and_not_closure() {
    let declared = edges(&[("timer", "cb_a")]);
    let observed = edges(&[("timer", "cb_a")]);
    let outcome = compare_inventory(&declared, &observed);
    assert!(!outcome.is_falsified());
    assert!(!outcome.is_conservative_closure());
    assert_eq!(
        outcome,
        CoverageOutcome::NotFalsified {
            matched: declared,
            unobserved_declared: BTreeSet::new(),
        }
    );
}

fn policy_change_policies() -> (SupportPolicy, SupportPolicy) {
    let mut old_rules = RuleSystem::new();
    old_rules.admit_leaf("e");
    old_rules.add_rule("q", ["e".to_owned()]).unwrap();

    let mut new_rules = RuleSystem::new();
    new_rules.admit_leaf("e");

    (policy("1", old_rules), policy("2", new_rules))
}

#[test]
fn b1_identical_evidence_loses_support_under_the_new_rule() {
    let (old_policy, new_policy) = policy_change_policies();
    let evidence_bytes = b"identical evidence bytes".to_vec();
    let old_result = evaluate(&old_policy.rules, &BTreeSet::new(), &BTreeSet::new());
    let new_result = evaluate(&new_policy.rules, &BTreeSet::new(), &BTreeSet::new());

    assert!(!evidence_bytes.is_empty());
    assert!(old_result.is_supported("q"));
    assert!(!new_result.is_supported("q"));

    let history = HistoricVerdict::record(&old_policy, &BTreeSet::new(), &BTreeSet::new()).unwrap();
    history.verify(&old_policy).unwrap();
    assert!(history.verify(&new_policy).is_err());
}

#[test]
fn b2_identical_bytes_do_not_hide_a_policy_identity_change() {
    let (old_policy, new_policy) = policy_change_policies();
    let old_history =
        HistoricVerdict::record(&old_policy, &BTreeSet::new(), &BTreeSet::new()).unwrap();
    let new_history =
        HistoricVerdict::record(&new_policy, &BTreeSet::new(), &BTreeSet::new()).unwrap();

    assert_ne!(old_policy.digest().unwrap(), new_policy.digest().unwrap());
    assert_ne!(old_history.policy_digest, new_history.policy_digest);
    assert_ne!(old_history.verdict_digest, new_history.verdict_digest);
    assert!(old_history.result.is_supported("q"));
    assert!(!new_history.result.is_supported("q"));
}

#[test]
fn b3_reconstruction_under_the_original_policy_is_byte_identical() {
    let (old_policy, new_policy) = policy_change_policies();
    let history = HistoricVerdict::record(&old_policy, &BTreeSet::new(), &BTreeSet::new()).unwrap();
    let reconstructed = reconstruct_recorded_verdict(&history, &old_policy, &new_policy).unwrap();

    assert_eq!(reconstructed.historical, history.result);
    assert!(reconstructed.historical.is_supported("q"));
    assert!(!reconstructed.current.is_supported("q"));
    assert!(reconstructed.byte_identical_historical);
}

fn shared_mapping_system() -> RuleSystem {
    let mut system = RuleSystem::new();
    system.admit_leaf("m");
    system.add_rule("a", ["m".to_owned()]).unwrap();
    system.add_rule("b", ["m".to_owned()]).unwrap();
    system.add_rule("q", ["a".to_owned()]).unwrap();
    system.add_rule("q", ["b".to_owned()]).unwrap();
    system
}

#[test]
fn c1_excluding_the_shared_mapping_blocks_both_routes() {
    let system = shared_mapping_system();
    let excluded = set(&["m"]);
    assert!(!evaluate(&system, &excluded, &BTreeSet::new()).is_supported("q"));

    let certs = certificates(&system, "q", &BTreeSet::new(), 16).unwrap();
    assert_eq!(certs, vec![set(&["a", "m", "q"]), set(&["b", "m", "q"])]);
    assert!(exact_cut(&certs, &excluded));
}

#[test]
fn c2_an_independent_third_route_survives_the_shared_mapping_cut() {
    let mut system = shared_mapping_system();
    system.admit_leaf("d");
    system.add_rule("q", ["d".to_owned()]).unwrap();
    let excluded = set(&["m"]);

    assert!(evaluate(&system, &excluded, &BTreeSet::new()).is_supported("q"));
    let certs = certificates(&system, "q", &BTreeSet::new(), 16).unwrap();
    assert!(!exact_cut(&certs, &excluded));
    assert!(certs.contains(&set(&["d", "q"])));
}

#[test]
fn c3_revoking_the_independent_premise_blocks_the_conclusion_again() {
    let mut system = shared_mapping_system();
    system.admit_leaf("d");
    system.add_rule("q", ["d".to_owned()]).unwrap();
    let excluded = set(&["d", "m"]);

    assert!(!evaluate(&system, &excluded, &BTreeSet::new()).is_supported("q"));
    let certs = certificates(&system, "q", &BTreeSet::new(), 16).unwrap();
    assert!(exact_cut(&certs, &excluded));
}
