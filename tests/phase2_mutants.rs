//! Seeded-semantic mutant courts required by the Phase 2 seal.
//!
//! Each mutant is a deliberately wrong, test-local evaluator. The court shows
//! that the shipped evaluator rejects the mutant's verdict and that a positive
//! control of unrelated valid support survives revocation, challenge, and a
//! policy change.

use std::collections::BTreeSet;

use frf_memorysafety::support::{
    certificates, evaluate, exact_cut, has_unsupported_cycle, reconstruct_recorded_verdict,
    HistoricVerdict, RuleSystem, SupportPolicy,
};

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn policy(version: &str, rules: RuleSystem) -> SupportPolicy {
    SupportPolicy {
        id: "mutant-policy".to_owned(),
        version: version.to_owned(),
        rules,
    }
}

/// Wrong greatest-fixed-point mutant: start from every non-excluded node and
/// remove only nodes with no satisfied rule. An ungrounded cycle survives.
fn greatest_fixed_point_mutant(
    system: &RuleSystem,
    excluded: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut supported: BTreeSet<String> = system
        .nodes()
        .into_iter()
        .filter(|claim| !excluded.contains(claim))
        .collect();
    loop {
        let mut remove = Vec::new();
        for claim in &supported {
            if system.admitted_leaves.contains(claim) {
                continue;
            }
            let has_satisfied_rule = system.rules.get(claim).is_some_and(|rules| {
                rules
                    .iter()
                    .any(|premises| premises.iter().all(|premise| supported.contains(premise)))
            });
            if !has_satisfied_rule {
                remove.push(claim.clone());
            }
        }
        if remove.is_empty() {
            break;
        }
        for claim in remove {
            supported.remove(&claim);
        }
    }
    supported
}

/// Hidden-intermediate certificate mutant: keep only the conclusion and its
/// admitted leaves, dropping intermediate nodes from the certificate.
fn hidden_intermediate_certificate(
    system: &RuleSystem,
    claim: &str,
    premises: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut mutant = BTreeSet::new();
    mutant.insert(claim.to_owned());
    for premise in premises {
        if system.admitted_leaves.contains(premise) {
            mutant.insert(premise.clone());
        }
    }
    mutant
}

/// Shared-mapping mutant: treat a conclusion's direct premises as independent
/// terminal evidence, ignoring their shared transitive dependency.
fn shared_mapping_mutant(system: &RuleSystem, claim: &str, excluded: &BTreeSet<String>) -> bool {
    system.rules.get(claim).is_some_and(|rules| {
        rules.iter().any(|premises| {
            !premises.is_empty() && premises.iter().all(|premise| !excluded.contains(premise))
        })
    })
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
fn wrong_greatest_fixed_point_accepts_ungrounded_cycles_and_is_rejected() {
    let mut self_cycle = RuleSystem::new();
    self_cycle.add_rule("q", ["q".to_owned()]).unwrap();
    assert!(greatest_fixed_point_mutant(&self_cycle, &BTreeSet::new()).contains("q"));
    assert!(!evaluate(&self_cycle, &BTreeSet::new(), &BTreeSet::new()).is_supported("q"));
    assert!(has_unsupported_cycle(&self_cycle, &set(&["q"])));

    let mut mutual = RuleSystem::new();
    mutual.add_rule("p", ["q".to_owned()]).unwrap();
    mutual.add_rule("q", ["p".to_owned()]).unwrap();
    let mutant = greatest_fixed_point_mutant(&mutual, &BTreeSet::new());
    assert!(mutant.contains("p") && mutant.contains("q"));
    assert!(!evaluate(&mutual, &BTreeSet::new(), &BTreeSet::new()).is_supported("p"));
    assert!(!evaluate(&mutual, &BTreeSet::new(), &BTreeSet::new()).is_supported("q"));
    assert!(has_unsupported_cycle(&mutual, &set(&["p"])));
}

#[test]
fn greatest_fixed_point_positive_control_agrees_on_grounded_cycles() {
    let mut system = RuleSystem::new();
    system.admit_leaf("a");
    system.add_rule("p", ["q".to_owned()]).unwrap();
    system.add_rule("p", ["a".to_owned()]).unwrap();
    system.add_rule("q", ["p".to_owned()]).unwrap();
    let shipped = evaluate(&system, &BTreeSet::new(), &BTreeSet::new());
    let mutant = greatest_fixed_point_mutant(&system, &BTreeSet::new());
    assert!(shipped.is_supported("p") && shipped.is_supported("q"));
    assert!(mutant.contains("p") && mutant.contains("q"));
}

#[test]
fn hidden_intermediate_mutant_is_rejected_by_all_node_certificates() {
    let mut system = RuleSystem::new();
    system.admit_leaf("a");
    system.add_rule("u", ["a".to_owned()]).unwrap();
    system.add_rule("q", ["u".to_owned()]).unwrap();

    let real = certificates(&system, "q", &BTreeSet::new(), 16).unwrap();
    assert_eq!(real, vec![set(&["a", "q", "u"])]);
    let mutant = hidden_intermediate_certificate(&system, "q", &set(&["u"]));
    assert_eq!(mutant, set(&["q"]));

    // The hidden-intermediate cut predicts survival; the founded evaluator does
    // not, because u is a required intermediate node.
    assert!(!exact_cut(&[mutant], &set(&["u"])));
    assert!(exact_cut(&real, &set(&["u"])));
    assert!(!evaluate(&system, &set(&["u"]), &BTreeSet::new()).is_supported("q"));
    assert!(!evaluate(&system, &BTreeSet::new(), &set(&["u"])).is_admissible("q"));
}

#[test]
fn shared_mapping_mutant_cannot_outvote_shared_invalidity() {
    let system = shared_mapping_system();
    let excluded = set(&["m"]);

    assert!(shared_mapping_mutant(&system, "q", &excluded));
    assert!(!evaluate(&system, &excluded, &BTreeSet::new()).is_supported("q"));

    let real = certificates(&system, "q", &BTreeSet::new(), 16).unwrap();
    assert_eq!(real, vec![set(&["a", "m", "q"]), set(&["b", "m", "q"])]);
    assert!(exact_cut(&real, &excluded));
}

#[test]
fn changed_policy_mutant_cannot_rewrite_a_recorded_verdict() {
    let mut old_rules = RuleSystem::new();
    old_rules.admit_leaf("e");
    old_rules.add_rule("q", ["e".to_owned()]).unwrap();
    let old_policy = policy("1", old_rules);

    let mut new_rules = RuleSystem::new();
    new_rules.admit_leaf("e");
    let new_policy = policy("2", new_rules);

    let history = HistoricVerdict::record(&old_policy, &BTreeSet::new(), &BTreeSet::new()).unwrap();
    let mutant_history = evaluate(&new_policy.rules, &BTreeSet::new(), &BTreeSet::new());

    assert!(history.result.is_supported("q"));
    assert!(!mutant_history.is_supported("q"));
    assert!(history.verify(&old_policy).is_ok());
    assert!(history.verify(&new_policy).is_err());

    let reconstructed = reconstruct_recorded_verdict(&history, &old_policy, &new_policy).unwrap();
    assert!(reconstructed.historical.is_supported("q"));
    assert!(!reconstructed.current.is_supported("q"));
    assert!(reconstructed.byte_identical_historical);
    assert_ne!(reconstructed.historical, mutant_history);
}

#[test]
fn unadmitted_leaf_mutant_is_rejected() {
    // The mutant grants every empty rule a base case.
    fn empty_rule_mutant(system: &RuleSystem, claim: &str) -> bool {
        system
            .rules
            .get(claim)
            .is_some_and(|rules| rules.iter().any(BTreeSet::is_empty))
    }
    let raw = RuleSystem {
        rules: [("q".to_owned(), vec![BTreeSet::new()])]
            .into_iter()
            .collect(),
        admitted_leaves: BTreeSet::new(),
    };
    assert!(empty_rule_mutant(&raw, "q"));
    assert!(!evaluate(&raw, &BTreeSet::new(), &BTreeSet::new()).is_supported("q"));
    assert!(certificates(&raw, "q", &BTreeSet::new(), 16)
        .unwrap()
        .is_empty());
}

#[test]
fn positive_control_unrelated_support_survives_every_change() {
    let mut rules = RuleSystem::new();
    rules.admit_leaf("a");
    rules.admit_leaf("b");
    rules.admit_leaf("c");
    rules.add_rule("q1", ["a".to_owned()]).unwrap();
    rules.add_rule("u", ["b".to_owned()]).unwrap();
    rules.add_rule("q2", ["u".to_owned()]).unwrap();
    rules.add_rule("q3", ["c".to_owned()]).unwrap();
    let old_policy = policy("1", rules);

    let mut new_rules = RuleSystem::new();
    new_rules.admit_leaf("a");
    new_rules.admit_leaf("b");
    new_rules.admit_leaf("c");
    new_rules.add_rule("q2", ["u".to_owned()]).unwrap();
    new_rules.add_rule("q3", ["c".to_owned()]).unwrap();
    let new_policy = policy("2", new_rules);

    // q3 is unrelated to the revoked leaf a, the challenged intermediate u, and
    // the policy edit that removes q1.
    let before = evaluate(&old_policy.rules, &BTreeSet::new(), &BTreeSet::new());
    assert!(before.is_supported("q3"));

    let revoked = evaluate(&old_policy.rules, &set(&["a"]), &BTreeSet::new());
    assert!(revoked.is_supported("q3"));

    let challenged = evaluate(&old_policy.rules, &BTreeSet::new(), &set(&["u"]));
    assert!(challenged.is_supported("q3"));
    assert!(challenged.is_admissible("q3"));

    let changed = evaluate(&new_policy.rules, &BTreeSet::new(), &BTreeSet::new());
    assert!(changed.is_supported("q3"));
    let witnesses = certificates(&new_policy.rules, "q3", &BTreeSet::new(), 16).unwrap();
    assert!(witnesses.contains(&set(&["c", "q3"])));
}
