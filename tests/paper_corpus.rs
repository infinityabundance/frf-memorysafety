//! Alignment with the paper's exact-cut corpus.
//!
//! The paper reports 331,776 node-level certificate comparisons and 17,712
//! "exact revocation cut checks" over the same 110,592-configuration universe.
//! The counts use different denominators: 331,776 is nodes times
//! configurations, while 17,712 counts only nodes in `S(revoked)` for each
//! `(revoked, challenged)` pair. This test pins both definitions and checks the
//! exact-cut condition on the paper's 17,712 cases through production code.
//! It also pins the paper's monotonicity and optimistic-mutant counts.

mod support_oracle;

use std::collections::{BTreeMap, BTreeSet};

use frf_memorysafety::support::{certificates, evaluate, exact_cut, ClaimId, RuleSystem};
use support_oracle::System;

fn to_production(system: &System) -> RuleSystem {
    let mut rules = BTreeMap::new();
    let mut admitted_leaves = BTreeSet::new();
    for (index, name) in system.nodes.iter().enumerate() {
        if !system.rules[index].is_empty() {
            let clauses = system.rules[index]
                .iter()
                .map(|clause| {
                    clause
                        .iter()
                        .map(|premise| system.nodes[*premise].clone())
                        .collect()
                })
                .collect();
            rules.insert(name.clone(), clauses);
        }
        if system.admitted[index] {
            admitted_leaves.insert(name.clone());
        }
    }
    RuleSystem {
        rules,
        admitted_leaves,
    }
}

fn named_set(values: &[bool], names: &[String]) -> BTreeSet<ClaimId> {
    names
        .iter()
        .enumerate()
        .filter(|(index, _)| values[*index])
        .map(|(_, name)| name.clone())
        .collect()
}

#[test]
fn independent_oracle_reproduces_the_paper_corpus_counts() {
    let counts = support_oracle::paper_counts();
    assert_eq!(counts.rule_systems, 1_728);
    assert_eq!(counts.configurations, 110_592);
    assert_eq!(counts.certificate_checks, 331_776);
    assert_eq!(counts.exact_revocation_cut_checks, 17_712);
    assert_eq!(counts.monotonicity_checks, 165_888);
    assert_eq!(counts.optimistic_mutant_differences, 20_878);
    assert_eq!(counts.algorithm_disagreements, 0);
}

#[test]
fn production_exact_cuts_agree_on_the_paper_17_712_checks() {
    let systems = System::paper_universe();
    let empty = BTreeSet::new();
    let mut checks = 0usize;

    for system in &systems {
        let production = to_production(system);
        let certificates_by_node: BTreeMap<ClaimId, Vec<BTreeSet<ClaimId>>> = system
            .nodes
            .iter()
            .map(|name| {
                (
                    name.clone(),
                    certificates(&production, name, &empty, 256).expect("bounded certificates"),
                )
            })
            .collect();

        for revoked_mask in 0u8..8 {
            let revoked: Vec<bool> = (0..system.nodes.len())
                .map(|node| revoked_mask & (1u8 << node) != 0)
                .collect();
            let revoked_names = named_set(&revoked, &system.nodes);
            let before_challenge = evaluate(&production, &revoked_names, &empty);

            for challenged_mask in 0u8..8 {
                let challenged: Vec<bool> = (0..system.nodes.len())
                    .map(|node| challenged_mask & (1u8 << node) != 0)
                    .collect();
                let challenged_names = named_set(&challenged, &system.nodes);
                let result = evaluate(&production, &revoked_names, &challenged_names);

                for node in &before_challenge.positive {
                    checks += 1;
                    let surviving: Vec<BTreeSet<ClaimId>> = certificates_by_node[node]
                        .iter()
                        .filter(|certificate| certificate.is_disjoint(&revoked_names))
                        .cloned()
                        .collect();
                    assert_eq!(
                        exact_cut(&surviving, &challenged_names),
                        !result.is_admissible(node),
                        "paper exact-cut condition failed for {node}"
                    );
                }
            }
        }
    }

    assert_eq!(checks, 17_712);
}
