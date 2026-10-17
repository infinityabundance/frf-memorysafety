//! Semantic lock-in tests for founded support, challenges, and exact cuts.

use std::collections::BTreeSet;

use frf_memorysafety::support::{
    certificates, evaluate, exact_cut, explain, has_unsupported_cycle, reconstruct_under_policy,
    IncrementalSupport, RuleSystem, SupportError, SupportPolicy, SupportState,
};

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

#[test]
fn self_cycle_without_entry_derives_nothing() {
    let mut system = RuleSystem::new();
    system.add_rule("q", ["q".to_owned()]).unwrap();
    let result = evaluate(&system, &BTreeSet::new(), &BTreeSet::new());
    assert!(!result.is_supported("q"));
    assert!(has_unsupported_cycle(&system, &set(&["q"])));
}

#[test]
fn unadmitted_empty_rule_is_refused() {
    let mut system = RuleSystem::new();
    let error = system.add_rule("q", Vec::new()).unwrap_err();
    assert_eq!(error, SupportError::UnjustifiedLeaf("q".to_owned()));

    // A directly constructed empty rule must not derive support either.
    let raw = RuleSystem {
        rules: [("q".to_owned(), vec![BTreeSet::new()])]
            .into_iter()
            .collect(),
        admitted_leaves: BTreeSet::new(),
    };
    assert!(!evaluate(&raw, &BTreeSet::new(), &BTreeSet::new()).is_supported("q"));
}

#[test]
fn alternative_support_survives_one_revocation_and_exact_cut() {
    let mut system = RuleSystem::new();
    system.admit_leaf("a");
    system.admit_leaf("b");
    system.add_rule("q", ["a".to_owned()]).unwrap();
    system.add_rule("q", ["b".to_owned()]).unwrap();
    let certs = certificates(&system, "q", &BTreeSet::new(), 16).unwrap();
    assert_eq!(certs.len(), 2);
    assert!(evaluate(&system, &set(&["a"]), &BTreeSet::new()).is_supported("q"));
    assert!(!evaluate(&system, &set(&["a", "b"]), &BTreeSet::new()).is_supported("q"));
    assert!(!exact_cut(&certs, &set(&["a"])));
    assert!(exact_cut(&certs, &set(&["a", "b"])));
    assert!(exact_cut(&certs, &set(&["q"])));
}

#[test]
fn hidden_intermediate_node_is_required_and_revocable() {
    let mut system = RuleSystem::new();
    system.admit_leaf("a");
    system.admit_leaf("b");
    system
        .add_rule("u", ["a".to_owned(), "b".to_owned()])
        .unwrap();
    system.add_rule("q", ["u".to_owned()]).unwrap();
    let certs = certificates(&system, "q", &BTreeSet::new(), 16).unwrap();
    assert_eq!(certs, vec![set(&["a", "b", "q", "u"])]);

    let exposed = evaluate(&system, &BTreeSet::new(), &set(&["u"]));
    assert!(exposed.is_supported("q"));
    assert!(!exposed.is_admissible("q"));
    assert!(exposed.is_withheld("q"));
    assert_eq!(
        exposed.states.get("q"),
        Some(&SupportState::SupportedButChallenged)
    );
}

#[test]
fn challenge_withholds_positive_support_without_erasing_it() {
    let mut system = RuleSystem::new();
    system.admit_leaf("a");
    system.add_rule("q", ["a".to_owned()]).unwrap();
    let result = evaluate(&system, &BTreeSet::new(), &set(&["q"]));
    assert!(result.is_supported("q"));
    assert!(!result.is_admissible("q"));
    assert_eq!(
        result.states.get("q"),
        Some(&SupportState::SupportedButChallenged)
    );
    let explanation = explain(&system, "q", &BTreeSet::new(), &set(&["q"]), 16);
    assert!(explanation.supported);
    assert!(!explanation.admissible);
    assert!(explanation.reason.contains("challenge"));
}

#[test]
fn policy_only_change_reconstructs_the_historical_verdict() {
    let mut old_rules = RuleSystem::new();
    old_rules.admit_leaf("e");
    old_rules.add_rule("q", ["e".to_owned()]).unwrap();
    let old_policy = SupportPolicy {
        id: "policy".to_owned(),
        version: "1".to_owned(),
        rules: old_rules,
    };

    let mut new_rules = RuleSystem::new();
    new_rules.admit_leaf("e");
    let new_policy = SupportPolicy {
        id: "policy".to_owned(),
        version: "2".to_owned(),
        rules: new_rules,
    };

    let reconstructed =
        reconstruct_under_policy(&old_policy, &new_policy, &BTreeSet::new(), &BTreeSet::new())
            .unwrap();
    assert!(reconstructed.historical.is_supported("q"));
    assert!(!reconstructed.current.is_supported("q"));
    assert!(reconstructed.byte_identical_historical);
    assert_ne!(
        old_policy.digest().unwrap(),
        new_policy.digest().unwrap(),
        "policy-only changes alter the policy identity"
    );
}

#[test]
fn incremental_support_matches_full_reevaluation() {
    let mut system = RuleSystem::new();
    system.admit_leaf("a");
    system.add_rule("q", ["a".to_owned()]).unwrap();
    let mut incremental = IncrementalSupport::new(system.clone(), BTreeSet::new(), BTreeSet::new());
    assert!(incremental.result().is_supported("q"));

    let removed = incremental.revoke(["a".to_owned()]);
    assert!(removed.contains("q"));
    assert!(!incremental.result().is_supported("q"));
    assert_eq!(
        incremental.result(),
        &evaluate(&system, &set(&["a"]), &BTreeSet::new())
    );

    let restored = incremental.restore("a");
    assert!(restored.contains("q"));
    assert!(incremental.result().is_supported("q"));
}

#[test]
fn certificate_and_exact_cut_characterization_hold_on_a_fixture() {
    let mut system = RuleSystem::new();
    system.admit_leaf("a");
    system.admit_leaf("b");
    system
        .add_rule("q", ["a".to_owned(), "b".to_owned()])
        .unwrap();
    system.add_rule("q", ["a".to_owned()]).unwrap();
    let certs = certificates(&system, "q", &BTreeSet::new(), 16).unwrap();
    // {a,q} is minimal; {a,b,q} is a superset and is removed.
    assert_eq!(certs, vec![set(&["a", "q"])]);
    for excluded in [set(&["a"]), set(&["b"]), set(&["a", "b"])] {
        let supported = evaluate(&system, &excluded, &BTreeSet::new()).is_supported("q");
        let by_certificate = certs.iter().any(|cert| cert.is_disjoint(&excluded));
        assert_eq!(supported, by_certificate);
    }
}
