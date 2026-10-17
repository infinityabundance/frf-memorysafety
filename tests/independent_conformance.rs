//! Differential conformance over the paper's 110,592-configuration campaign.
//!
//! The oracle in `support_oracle` is written from `SPEC.md` §6 and does not
//! call the production evaluator, certificate enumerator, exact-cut predicate,
//! or conformance generators. Production functions are invoked only here, on
//! the other side of the comparison.
//!
//! Domain: three nodes (`a`, `b`, `c`), twelve rule patterns per node, all
//! 1,728 rule systems, all eight revocation masks, and all eight challenge
//! masks. Agreement is a consistency result inside this finite domain. It is
//! not a proof of `SPEC.md`, of any real rule system, or of Rust soundness.

mod support_oracle;

use std::collections::{BTreeMap, BTreeSet};

use frf_memorysafety::support::{
    certificates, evaluate, exact_cut, ClaimId, RuleSystem, SupportState,
};
use support_oracle::System;

type IndexCertificates = Vec<Vec<BTreeSet<usize>>>;
type NamedCertificates = Vec<Vec<BTreeSet<ClaimId>>>;

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

fn supported_names(values: &[bool], names: &[String]) -> BTreeSet<ClaimId> {
    names
        .iter()
        .enumerate()
        .filter(|(index, _)| values[*index])
        .map(|(_, name)| name.clone())
        .collect()
}

fn sort_sets(sets: &mut [BTreeSet<ClaimId>]) {
    sets.sort_by(|left, right| {
        left.len()
            .cmp(&right.len())
            .then_with(|| left.iter().cmp(right.iter()))
    });
}

fn expected_state(positive: bool, admissible: bool, challenged: bool) -> SupportState {
    match (positive, admissible) {
        (_, true) => SupportState::Supported,
        (true, false) => SupportState::SupportedButChallenged,
        (false, false) if challenged => SupportState::Challenged,
        (false, false) => SupportState::Unsupported,
    }
}

#[derive(Default)]
struct Counters {
    configurations: usize,
    node_comparisons: usize,
    exact_cut_comparisons: usize,
    certificates_checked: usize,
    verdict_state_comparisons: usize,
}

/// Build both certificate families and validate every independent certificate.
fn compare_certificates(
    system: &System,
    production: &RuleSystem,
    counters: &mut Counters,
) -> (IndexCertificates, NamedCertificates) {
    let empty = BTreeSet::new();
    let independent = system.certificates();
    let shipped: NamedCertificates = system
        .nodes
        .iter()
        .map(|name| {
            certificates(production, name, &empty, 256).expect("bounded certificate family")
        })
        .collect();

    for node in 0..system.nodes.len() {
        let mut independent_named: Vec<BTreeSet<ClaimId>> = independent[node]
            .iter()
            .map(|certificate| {
                certificate
                    .iter()
                    .map(|premise| system.nodes[*premise].clone())
                    .collect()
            })
            .collect();
        sort_sets(&mut independent_named);
        assert_eq!(
            shipped[node], independent_named,
            "independent certificate family differs for node {}",
            system.nodes[node]
        );
        for certificate in &independent[node] {
            counters.certificates_checked += 1;
            assert!(
                system.check_certificate(node, certificate),
                "independent checker rejected an independent certificate"
            );
            assert!(
                system.is_minimal_certificate(node, certificate),
                "independent certificate is not inclusion-minimal"
            );
        }
    }
    (independent, shipped)
}

/// Compare every revocation/challenge configuration for one rule system.
fn compare_configurations(
    system: &System,
    production: &RuleSystem,
    independent: &[Vec<BTreeSet<usize>>],
    shipped: &[Vec<BTreeSet<ClaimId>>],
    counters: &mut Counters,
) {
    for revoked_mask in 0u8..8 {
        let revoked: Vec<bool> = (0..system.nodes.len())
            .map(|node| revoked_mask & (1u8 << node) != 0)
            .collect();
        let revoked_names = supported_names(&revoked, &system.nodes);

        for challenged_mask in 0u8..8 {
            counters.configurations += 1;
            let challenged: Vec<bool> = (0..system.nodes.len())
                .map(|node| challenged_mask & (1u8 << node) != 0)
                .collect();
            let challenged_names = supported_names(&challenged, &system.nodes);
            let combined: Vec<bool> = revoked
                .iter()
                .zip(&challenged)
                .map(|(left, right)| *left || *right)
                .collect();
            let combined_names: BTreeSet<ClaimId> =
                revoked_names.union(&challenged_names).cloned().collect();

            let (positive, admissible) = system.verdict_sets(&revoked, &challenged);
            let shipped_result = evaluate(production, &revoked_names, &challenged_names);

            assert_eq!(
                shipped_result.positive,
                supported_names(&positive, &system.nodes),
                "positive support differs"
            );
            assert_eq!(
                shipped_result.admissible,
                supported_names(&admissible, &system.nodes),
                "admissible support differs"
            );

            for (node, name) in system.nodes.iter().enumerate() {
                if let Some(state) = shipped_result.states.get(name) {
                    counters.verdict_state_comparisons += 1;
                    assert_eq!(
                        *state,
                        expected_state(positive[node], admissible[node], challenged[node]),
                        "verdict state differs for {name}"
                    );
                }
            }

            for node in 0..system.nodes.len() {
                counters.node_comparisons += 1;
                let by_certificate = independent[node]
                    .iter()
                    .any(|certificate| certificate.iter().all(|item| !combined[*item]));
                assert_eq!(
                    admissible[node], by_certificate,
                    "independent certificate characterization differs"
                );

                counters.exact_cut_comparisons += 1;
                assert_eq!(
                    exact_cut(&shipped[node], &combined_names),
                    System::exact_cut(&independent[node], &combined),
                    "exact-cut predicate differs for node {}",
                    system.nodes[node]
                );
            }
        }
    }
}

#[test]
fn independent_oracle_agrees_over_the_full_campaign() {
    let systems = System::paper_universe();
    assert_eq!(support_oracle::patterns(3).len(), 12);
    assert_eq!(systems.len(), 1_728);

    let mut counters = Counters::default();
    for system in &systems {
        let production = to_production(system);
        production.validate().expect("oracle system is valid");
        let (independent, shipped) = compare_certificates(system, &production, &mut counters);
        compare_configurations(system, &production, &independent, &shipped, &mut counters);
    }

    // Exact paper-universe counts. See `tests/paper_corpus.rs` for the distinct
    // paper-definition exact-revocation-cut count (17,712).
    assert_eq!(counters.configurations, 110_592);
    assert_eq!(counters.node_comparisons, 331_776);
    assert_eq!(counters.exact_cut_comparisons, 331_776);
    assert!(counters.verdict_state_comparisons > 0);
    assert!(counters.verdict_state_comparisons <= 331_776);
    assert!(counters.certificates_checked > 0);
}
