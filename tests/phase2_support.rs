//! Phase 2 semantic tests: founded support, certificates, cuts, and custody.

use std::collections::BTreeSet;

use frf_memorysafety::support::{
    certificates, evaluate, exact_cut, noninterference, reconstruct_recorded_verdict,
    reconstruct_under_policy, HistoricVerdict, RuleSystem, SupportError, SupportPolicy,
    SupportState,
};

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn policy(version: &str, rules: RuleSystem) -> SupportPolicy {
    SupportPolicy {
        id: "phase2-policy".to_owned(),
        version: version.to_owned(),
        rules,
    }
}

#[test]
fn admitted_leaf_with_non_nullary_rules_keeps_singleton_certificate() {
    let mut system = RuleSystem::new();
    system.admit_leaf("a");
    system.admit_leaf("b");
    system.add_rule("a", ["b".to_owned()]).unwrap();

    let result = evaluate(&system, &BTreeSet::new(), &BTreeSet::new());
    assert!(result.is_supported("a"));
    assert_eq!(
        certificates(&system, "a", &BTreeSet::new(), 16).unwrap(),
        vec![set(&["a"])],
        "leaf admission is a nullary justification independent of its other rules"
    );
}

#[test]
fn admitted_leaf_without_any_rule_is_supported_and_certified() {
    let mut system = RuleSystem::new();
    system.admit_leaf("a");
    let result = evaluate(&system, &BTreeSet::new(), &BTreeSet::new());
    assert!(result.is_supported("a"));
    assert_eq!(
        certificates(&system, "a", &BTreeSet::new(), 16).unwrap(),
        vec![set(&["a"])]
    );
}

#[test]
fn unadmitted_empty_rules_derive_nothing_in_either_view() {
    let raw = RuleSystem {
        rules: [("q".to_owned(), vec![BTreeSet::new()])]
            .into_iter()
            .collect(),
        admitted_leaves: BTreeSet::new(),
    };
    let result = evaluate(&raw, &BTreeSet::new(), &BTreeSet::new());
    assert!(!result.is_supported("q"));
    assert!(certificates(&raw, "q", &BTreeSet::new(), 16)
        .unwrap()
        .is_empty());
}

#[test]
fn challenged_premise_cannot_support_an_admissible_conclusion() {
    let mut system = RuleSystem::new();
    system.admit_leaf("a");
    system.add_rule("p", ["a".to_owned()]).unwrap();
    system.add_rule("q", ["p".to_owned()]).unwrap();

    let result = evaluate(&system, &BTreeSet::new(), &set(&["p"]));
    assert!(result.is_supported("q"), "positive history is preserved");
    assert!(
        !result.is_admissible("q"),
        "a challenged premise cannot support"
    );
    assert!(result.is_withheld("q"));
    assert_eq!(
        result.states.get("q"),
        Some(&SupportState::SupportedButChallenged)
    );
    assert_eq!(
        result.states.get("p"),
        Some(&SupportState::SupportedButChallenged)
    );
}

#[test]
fn all_node_certificate_covers_the_whole_chain() {
    let mut system = RuleSystem::new();
    system.admit_leaf("a");
    system.admit_leaf("b");
    system
        .add_rule("v", ["a".to_owned(), "b".to_owned()])
        .unwrap();
    system.add_rule("u", ["v".to_owned()]).unwrap();
    system.add_rule("q", ["u".to_owned()]).unwrap();

    assert_eq!(
        certificates(&system, "q", &BTreeSet::new(), 16).unwrap(),
        vec![set(&["a", "b", "q", "u", "v"])]
    );
    let exposed = evaluate(&system, &BTreeSet::new(), &set(&["v"]));
    assert!(exposed.is_supported("q"));
    assert!(!exposed.is_admissible("q"));
}

#[test]
fn exact_rule_cut_at_the_rule_boundary_preserves_unrelated_derivations() {
    let mut system = RuleSystem::new();
    for leaf in ["a", "b", "c"] {
        system.admit_leaf(leaf);
    }
    system.add_rule("q", ["a".to_owned()]).unwrap();
    system.add_rule("q", ["b".to_owned()]).unwrap();
    system.add_rule("r", ["c".to_owned()]).unwrap();
    system.add_rule("t", ["q".to_owned()]).unwrap();

    let before = evaluate(&system, &BTreeSet::new(), &BTreeSet::new());
    assert!(before.is_supported("q") && before.is_supported("r") && before.is_supported("t"));

    // Cutting only q <- a leaves q supported through q <- b, and leaves r alone.
    assert!(system.remove_rule("q", &set(&["a"])));
    let after_first = evaluate(&system, &BTreeSet::new(), &BTreeSet::new());
    assert!(after_first.is_supported("q"));
    assert!(after_first.is_supported("t"));
    assert!(after_first.is_supported("r"));

    // A non-matching premise set is not a cut.
    assert!(!system.remove_rule("q", &set(&["a"])));
    assert!(!system.remove_rule("r", &set(&["a"])));
    assert!(system.remove_rule("q", &set(&["b"])));

    let after_second = evaluate(&system, &BTreeSet::new(), &BTreeSet::new());
    assert!(!after_second.is_supported("q"));
    assert!(!after_second.is_supported("t"));
    assert!(
        after_second.is_supported("r"),
        "unrelated valid derivation survives both cuts"
    );
}

#[test]
fn noninterference_reports_retained_support_and_witnesses() {
    let mut system = RuleSystem::new();
    for leaf in ["a", "b", "c"] {
        system.admit_leaf(leaf);
    }
    system.add_rule("q1", ["a".to_owned()]).unwrap();
    system.add_rule("q2", ["b".to_owned()]).unwrap();
    system.add_rule("q3", ["c".to_owned()]).unwrap();

    let before = evaluate(&system, &BTreeSet::new(), &BTreeSet::new());
    let after = evaluate(&system, &set(&["a"]), &BTreeSet::new());
    let report = noninterference(&system, &before, &after, 16).unwrap();

    assert_eq!(report.lost, set(&["a", "q1"]));
    assert!(report.gained.is_empty());
    assert_eq!(report.retained, set(&["b", "c", "q2", "q3"]));
    assert!(report.withheld.is_empty());
    assert_eq!(report.witnesses.get("q2"), Some(&set(&["b", "q2"])));
    assert_eq!(report.witnesses.get("q3"), Some(&set(&["c", "q3"])));
    for (claim, witness) in &report.witnesses {
        assert!(
            witness.is_disjoint(&set(&["a"])),
            "{claim} witness must avoid revoked leaves"
        );
    }
}

#[test]
fn challenge_noninterference_keeps_positive_support_but_records_withholding() {
    let mut system = RuleSystem::new();
    system.admit_leaf("a");
    system.admit_leaf("b");
    system.add_rule("q1", ["a".to_owned()]).unwrap();
    system.add_rule("q2", ["b".to_owned()]).unwrap();

    let before = evaluate(&system, &BTreeSet::new(), &BTreeSet::new());
    let after = evaluate(&system, &BTreeSet::new(), &set(&["a"]));
    let report = noninterference(&system, &before, &after, 16).unwrap();

    assert!(report.lost.is_empty());
    assert_eq!(report.retained, set(&["a", "b", "q1", "q2"]));
    assert_eq!(report.withheld, set(&["a", "q1"]));
    assert!(after.is_admissible("q2"));
    assert!(!after.is_admissible("q1"));
}

#[test]
fn policy_change_noninterference_retains_unrelated_claims() {
    let mut old_rules = RuleSystem::new();
    old_rules.admit_leaf("a");
    old_rules.admit_leaf("b");
    old_rules.add_rule("q1", ["a".to_owned()]).unwrap();
    old_rules.add_rule("q2", ["b".to_owned()]).unwrap();
    let old_policy = policy("1", old_rules);

    let mut new_rules = RuleSystem::new();
    new_rules.admit_leaf("a");
    new_rules.admit_leaf("b");
    new_rules.add_rule("q2", ["b".to_owned()]).unwrap();
    let new_policy = policy("2", new_rules);

    let before = evaluate(&old_policy.rules, &BTreeSet::new(), &BTreeSet::new());
    let after = evaluate(&new_policy.rules, &BTreeSet::new(), &BTreeSet::new());
    let report = noninterference(&new_policy.rules, &before, &after, 16).unwrap();

    assert_eq!(report.lost, set(&["q1"]));
    assert!(report.gained.is_empty());
    assert_eq!(report.retained, set(&["a", "b", "q2"]));
    assert_eq!(report.witnesses.get("q2"), Some(&set(&["b", "q2"])));
}

#[test]
fn recorded_verdict_detects_policy_substitution_and_tampering() {
    let mut rules = RuleSystem::new();
    rules.admit_leaf("e");
    rules.add_rule("q", ["e".to_owned()]).unwrap();
    let old_policy = policy("1", rules);

    let mut new_rules = RuleSystem::new();
    new_rules.admit_leaf("e");
    let new_policy = policy("2", new_rules);

    let history = HistoricVerdict::record(&old_policy, &BTreeSet::new(), &BTreeSet::new()).unwrap();
    history.verify(&old_policy).unwrap();
    assert_eq!(
        history.verify(&new_policy).unwrap_err(),
        SupportError::PolicyMismatch
    );

    let mut tampered_result = history.clone();
    tampered_result.result.positive.insert("forged".to_owned());
    assert!(matches!(
        tampered_result.verify(&old_policy),
        Err(SupportError::HistoryMismatch(_))
    ));

    let mut tampered_digest = history.clone();
    tampered_digest.verdict_digest = frf_memorysafety::identity::digest_bytes(
        frf_memorysafety::identity::IdentityDomain::Assessment,
        b"other",
    );
    assert!(matches!(
        tampered_digest.verify(&old_policy),
        Err(SupportError::HistoryMismatch(_))
    ));

    let mut tampered_version = history.clone();
    tampered_version.policy_version = "0".to_owned();
    assert_eq!(
        tampered_version.verify(&old_policy).unwrap_err(),
        SupportError::PolicyMismatch
    );
}

#[test]
fn new_policy_cannot_rewrite_recorded_history() {
    let mut old_rules = RuleSystem::new();
    old_rules.admit_leaf("e");
    old_rules.add_rule("q", ["e".to_owned()]).unwrap();
    let old_policy = policy("1", old_rules);

    let mut new_rules = RuleSystem::new();
    new_rules.admit_leaf("e");
    let new_policy = policy("2", new_rules);

    let history = HistoricVerdict::record(&old_policy, &BTreeSet::new(), &BTreeSet::new()).unwrap();
    let recorded = history.clone();
    let reconstructed = reconstruct_recorded_verdict(&history, &old_policy, &new_policy).unwrap();

    assert!(reconstructed.historical.is_supported("q"));
    assert!(!reconstructed.current.is_supported("q"));
    assert!(reconstructed.byte_identical_historical);
    assert_eq!(history, recorded, "history is not rewritten in place");

    // Substituting a different policy for the recorded one is detected.
    let substituted = policy("9", old_policy.rules.clone());
    assert_eq!(
        reconstruct_recorded_verdict(&history, &substituted, &new_policy).unwrap_err(),
        SupportError::PolicyMismatch
    );
}

#[test]
fn reconstruct_under_policy_keeps_the_old_decision_bytes() {
    let mut old_rules = RuleSystem::new();
    old_rules.admit_leaf("e");
    old_rules.add_rule("q", ["e".to_owned()]).unwrap();
    let old_policy = policy("1", old_rules);

    let mut new_rules = RuleSystem::new();
    new_rules.admit_leaf("e");
    let new_policy = policy("2", new_rules);

    let reconstructed =
        reconstruct_under_policy(&old_policy, &new_policy, &BTreeSet::new(), &BTreeSet::new())
            .unwrap();
    assert!(reconstructed.historical.is_supported("q"));
    assert!(!reconstructed.current.is_supported("q"));
    assert!(reconstructed.byte_identical_historical);
    assert_ne!(old_policy.digest().unwrap(), new_policy.digest().unwrap());
}

#[test]
fn grounded_mutual_cycle_is_supported_only_through_its_entry() {
    let mut system = RuleSystem::new();
    system.admit_leaf("a");
    system.add_rule("p", ["q".to_owned()]).unwrap();
    system.add_rule("p", ["a".to_owned()]).unwrap();
    system.add_rule("q", ["p".to_owned()]).unwrap();

    assert!(evaluate(&system, &BTreeSet::new(), &BTreeSet::new()).is_supported("p"));
    assert!(evaluate(&system, &BTreeSet::new(), &BTreeSet::new()).is_supported("q"));
    assert!(!evaluate(&system, &set(&["a"]), &BTreeSet::new()).is_supported("q"));
    assert!(exact_cut(
        &certificates(&system, "q", &BTreeSet::new(), 16).unwrap(),
        &set(&["a"])
    ));
}
