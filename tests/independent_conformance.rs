//! Independent replay of the paper's 110,592-configuration support campaign.
//!
//! The shipping evaluator is compared against two different implementations
//! written in this test file:
//!
//! * a naive round-based least-fixed-point evaluator; and
//! * an independent certificate checker that resolves every node of a claimed
//!   certificate and verifies inclusion-minimality.
//!
//! Agreement is a consistency check within the enumerated finite domain. It is
//! not a proof of the rule system or of any real-world premise.

use std::collections::BTreeSet;

use frf_memorysafety::support::{
    certificates, conformance_patterns, conformance_system, evaluate, exact_cut, ClaimId,
    RuleSystem,
};

fn naive_fixed_point(system: &RuleSystem, excluded: &BTreeSet<ClaimId>) -> BTreeSet<ClaimId> {
    let mut supported = BTreeSet::new();
    loop {
        let mut changed = false;
        for claim in system.nodes() {
            if excluded.contains(&claim) || supported.contains(&claim) {
                continue;
            }
            let admitted = system.admitted_leaves.contains(&claim);
            let by_rule = system.rules.get(&claim).is_some_and(|rules| {
                rules.iter().any(|premises| {
                    (!premises.is_empty() || admitted)
                        && premises.iter().all(|premise| supported.contains(premise))
                })
            });
            if admitted || by_rule {
                supported.insert(claim);
                changed = true;
            }
        }
        if !changed {
            return supported;
        }
    }
}

/// Check that `certificate` is a finite, well-founded derivation of `claim`.
fn check_certificate(system: &RuleSystem, claim: &str, certificate: &BTreeSet<ClaimId>) -> bool {
    if !certificate.contains(claim) {
        return false;
    }
    let nodes = system.nodes();
    if !certificate.iter().all(|node| nodes.contains(node)) {
        return false;
    }
    let mut resolved: BTreeSet<ClaimId> = BTreeSet::new();
    loop {
        let mut changed = false;
        for node in certificate {
            if resolved.contains(node) {
                continue;
            }
            let admitted = system.admitted_leaves.contains(node);
            let by_rule = system.rules.get(node).is_some_and(|rules| {
                rules.iter().any(|premises| {
                    (!premises.is_empty() || admitted)
                        && premises.iter().all(|premise| {
                            certificate.contains(premise) && resolved.contains(premise)
                        })
                })
            });
            if admitted || by_rule {
                resolved.insert(node.clone());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    resolved.len() == certificate.len()
}

/// Check that no proper subset of the certificate is still a certificate.
fn is_minimal_certificate(
    system: &RuleSystem,
    claim: &str,
    certificate: &BTreeSet<ClaimId>,
) -> bool {
    if !check_certificate(system, claim, certificate) {
        return false;
    }
    for node in certificate {
        let mut reduced = certificate.clone();
        reduced.remove(node);
        if check_certificate(system, claim, &reduced) {
            return false;
        }
    }
    true
}

#[test]
fn independent_evaluator_and_checker_agree_over_the_full_campaign() {
    let nodes = ["a", "b", "c"];
    let patterns = conformance_patterns(&nodes);
    assert_eq!(patterns.len(), 12);

    let empty = BTreeSet::new();
    let mut configurations = 0usize;
    let mut node_comparisons = 0usize;
    let mut exact_cut_comparisons = 0usize;
    let mut certificates_checked = 0usize;

    for ia in 0..patterns.len() {
        for ib in 0..patterns.len() {
            for ic in 0..patterns.len() {
                let system = conformance_system([ia, ib, ic], &nodes);

                // Certificates are independent of the exclusion masks, so they
                // are enumerated once per rule system.
                let certificates_by_node: Vec<Vec<BTreeSet<ClaimId>>> = nodes
                    .iter()
                    .map(|node| certificates(&system, node, &empty, 256).unwrap())
                    .collect();
                for (node_index, node) in nodes.iter().enumerate() {
                    for certificate in &certificates_by_node[node_index] {
                        certificates_checked += 1;
                        assert!(
                            check_certificate(&system, node, certificate),
                            "certificate checker rejected a shipped certificate for {node}"
                        );
                        assert!(
                            is_minimal_certificate(&system, node, certificate),
                            "shipped certificate for {node} is not minimal"
                        );
                    }
                }

                for revocation_mask in 0u16..8 {
                    let revoked: BTreeSet<ClaimId> = nodes
                        .iter()
                        .enumerate()
                        .filter(|(index, _)| revocation_mask & (1 << index) != 0)
                        .map(|(_, node)| (*node).to_owned())
                        .collect();
                    let naive_positive = naive_fixed_point(&system, &revoked);
                    let shipped_positive = evaluate(&system, &revoked, &empty);
                    assert_eq!(
                        shipped_positive.positive, naive_positive,
                        "positive fixed point disagrees"
                    );

                    for challenge_mask in 0u16..8 {
                        configurations += 1;
                        let challenged: BTreeSet<ClaimId> = nodes
                            .iter()
                            .enumerate()
                            .filter(|(index, _)| challenge_mask & (1 << index) != 0)
                            .map(|(_, node)| (*node).to_owned())
                            .collect();
                        let mut exclusions = revoked.clone();
                        exclusions.extend(challenged.iter().cloned());
                        let naive_admissible = naive_fixed_point(&system, &exclusions);
                        let shipped_admissible = evaluate(&system, &revoked, &challenged);
                        assert_eq!(
                            shipped_admissible.admissible, naive_admissible,
                            "admissible fixed point disagrees"
                        );

                        for (node_index, node) in nodes.iter().enumerate() {
                            node_comparisons += 1;
                            let certificates = &certificates_by_node[node_index];
                            let by_positive = certificates
                                .iter()
                                .any(|certificate| certificate.is_disjoint(&revoked));
                            let by_admissible = certificates.iter().any(|certificate| {
                                certificate.is_disjoint(&revoked)
                                    && certificate.is_disjoint(&challenged)
                            });
                            assert_eq!(
                                naive_positive.contains(*node),
                                by_positive,
                                "positive certificate characterization mismatch for {node}"
                            );
                            assert_eq!(
                                naive_admissible.contains(*node),
                                by_admissible,
                                "admissible certificate characterization mismatch for {node}"
                            );

                            exact_cut_comparisons += 1;
                            assert_eq!(
                                exact_cut(certificates, &exclusions),
                                !naive_admissible.contains(*node),
                                "exact-cut characterization mismatch for {node}"
                            );
                        }
                    }
                }
            }
        }
    }

    assert_eq!(configurations, 110_592);
    assert_eq!(node_comparisons, 331_776);
    assert_eq!(exact_cut_comparisons, 331_776);
    assert!(certificates_checked > 0);
}
