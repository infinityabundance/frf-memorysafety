//! Independent founded-support oracle, written from `SPEC.md` §6.
//!
//! This module deliberately does not import or call the production evaluator,
//! certificate enumerator, exact-cut predicate, or conformance generators in
//! `src/support.rs`. It receives only plain data: node names, rules, and leaf
//! admissions. The integration tests call the production functions separately
//! and compare observations.
//!
//! The implementation uses a round-based least-fixed-point loop, an antichain
//! certificate computation, a depth-first finite-witness search, and a direct
//! set-based exact-cut predicate. Agreement with the production code is a
//! differential consistency result over the enumerated finite domain only.

#![allow(dead_code)]

use std::collections::BTreeSet;

/// A finite rule system in index form, independent of the production types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct System {
    /// Claim names, in index order.
    pub nodes: Vec<String>,
    /// Per node: alternative conjunctive clauses, each a premise-index list.
    pub rules: Vec<Vec<Vec<usize>>>,
    /// Per node: whether an empty clause is an externally justified leaf.
    pub admitted: Vec<bool>,
}

/// The twelve rule patterns used by the paper's three-node universe.
///
/// The order matches `SPEC.md`/paper: no derivation; the eight conjunctive
/// subsets; then the three alternative singleton pairs.
#[must_use]
pub fn patterns(node_count: usize) -> Vec<Vec<Vec<usize>>> {
    let mut patterns = Vec::new();
    patterns.push(Vec::new());
    for mask in 0usize..(1usize << node_count) {
        let clause: Vec<usize> = (0..node_count)
            .filter(|index| mask & (1usize << index) != 0)
            .collect();
        patterns.push(vec![clause]);
    }
    for left in 0..node_count {
        for right in (left + 1)..node_count {
            patterns.push(vec![vec![left], vec![right]]);
        }
    }
    patterns
}

impl System {
    /// Enumerate all 1,728 systems of the paper's concrete three-node universe.
    #[must_use]
    pub fn paper_universe() -> Vec<Self> {
        let names = ["a", "b", "c"];
        let nodes: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        let patterns = patterns(nodes.len());
        let mut systems = Vec::with_capacity(patterns.len().pow(3));
        for first in 0..patterns.len() {
            for second in 0..patterns.len() {
                for third in 0..patterns.len() {
                    let selected = [first, second, third];
                    let mut rules = vec![Vec::new(); nodes.len()];
                    let mut admitted = vec![false; nodes.len()];
                    for (node, pattern_index) in selected.iter().enumerate() {
                        for clause in &patterns[*pattern_index] {
                            if clause.is_empty() {
                                admitted[node] = true;
                            }
                            rules[node].push(clause.clone());
                        }
                    }
                    systems.push(Self {
                        nodes: nodes.clone(),
                        rules,
                        admitted,
                    });
                }
            }
        }
        systems
    }

    /// Round-based least fixed point over the explicitly excluded nodes.
    #[must_use]
    pub fn fixed_point(&self, excluded: &[bool]) -> Vec<bool> {
        let count = self.nodes.len();
        let mut supported = vec![false; count];
        loop {
            let mut changed = false;
            for node in 0..count {
                if excluded[node] || supported[node] {
                    continue;
                }
                let admitted = self.admitted[node];
                let by_clause = self.rules[node].iter().any(|clause| {
                    !clause.is_empty() && clause.iter().all(|premise| supported[*premise])
                });
                if admitted || by_clause {
                    supported[node] = true;
                    changed = true;
                }
            }
            if !changed {
                return supported;
            }
        }
    }

    /// Positive support is `S(revoked)`; admissible support is
    /// `S(revoked union challenged)`.
    #[must_use]
    pub fn verdict_sets(&self, revoked: &[bool], challenged: &[bool]) -> (Vec<bool>, Vec<bool>) {
        let positive = self.fixed_point(revoked);
        let combined: Vec<bool> = revoked
            .iter()
            .zip(challenged)
            .map(|(left, right)| *left || *right)
            .collect();
        let admissible = self.fixed_point(&combined);
        (positive, admissible)
    }

    /// Independent depth-first search for an acyclic finite proof witness.
    ///
    /// This is a second algorithm for the same specification: it does not use a
    /// fixed point. `path` is a bit mask of nodes already on the current proof
    /// branch, so a cycle cannot serve as its own base case.
    #[must_use]
    pub fn witness(&self, node: usize, path: u64, excluded: &[bool]) -> bool {
        if excluded[node] || path & (1u64 << node) != 0 {
            return false;
        }
        let next_path = path | (1u64 << node);
        self.rules[node].iter().any(|clause| {
            clause.is_empty()
                || clause
                    .iter()
                    .all(|premise| self.witness(*premise, next_path, excluded))
        })
    }

    /// All nodes with a finite proof witness.
    #[must_use]
    pub fn witness_set(&self, excluded: &[bool]) -> Vec<bool> {
        (0..self.nodes.len())
            .map(|node| self.witness(node, 0, excluded))
            .collect()
    }

    /// Inclusion-minimal all-node certificates for every node.
    ///
    /// The computation starts from the empty antichain and iterates the
    /// monotone certificate transformer to its least fixed point. It never
    /// treats an unadmitted empty clause as a justification.
    #[must_use]
    pub fn certificates(&self) -> Vec<Vec<BTreeSet<usize>>> {
        let count = self.nodes.len();
        let mut current: Vec<Vec<BTreeSet<usize>>> = vec![Vec::new(); count];
        loop {
            let mut next = current.clone();
            for (node, node_next) in next.iter_mut().enumerate() {
                if self.admitted[node] {
                    node_next.push(BTreeSet::from([node]));
                }
                for clause in &self.rules[node] {
                    if clause.is_empty() {
                        continue;
                    }
                    let combinations = Self::expand_clause(clause, &current);
                    for mut combination in combinations {
                        combination.insert(node);
                        node_next.push(combination);
                    }
                }
                minimize_sets(node_next);
            }
            if next == current {
                return current;
            }
            current = next;
        }
    }

    fn expand_clause(clause: &[usize], current: &[Vec<BTreeSet<usize>>]) -> Vec<BTreeSet<usize>> {
        let mut combinations: Vec<BTreeSet<usize>> = vec![BTreeSet::new()];
        for premise in clause {
            let alternatives = &current[*premise];
            if alternatives.is_empty() {
                return Vec::new();
            }
            let mut expanded = Vec::new();
            for base in &combinations {
                for alternative in alternatives {
                    let mut union = base.clone();
                    union.extend(alternative.iter().copied());
                    expanded.push(union);
                }
            }
            combinations = expanded;
        }
        combinations
    }

    /// Check that `certificate` is a finite, well-founded derivation of `node`.
    #[must_use]
    pub fn check_certificate(&self, node: usize, certificate: &BTreeSet<usize>) -> bool {
        let count = self.nodes.len();
        if !certificate.contains(&node) || certificate.iter().any(|item| *item >= count) {
            return false;
        }
        let mut resolved = vec![false; count];
        loop {
            let mut changed = false;
            for candidate in certificate {
                if resolved[*candidate] {
                    continue;
                }
                let admitted = self.admitted[*candidate];
                let by_clause = self.rules[*candidate].iter().any(|clause| {
                    !clause.is_empty()
                        && clause
                            .iter()
                            .all(|premise| certificate.contains(premise) && resolved[*premise])
                });
                if admitted || by_clause {
                    resolved[*candidate] = true;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        certificate.iter().all(|item| resolved[*item])
    }

    /// Check that no one-node deletion leaves a valid certificate. Because
    /// certificate validity is monotone in the node set, this is equivalent to
    /// inclusion-minimality.
    #[must_use]
    pub fn is_minimal_certificate(&self, node: usize, certificate: &BTreeSet<usize>) -> bool {
        if !self.check_certificate(node, certificate) {
            return false;
        }
        for removed in certificate {
            let mut reduced = certificate.clone();
            reduced.remove(removed);
            if self.check_certificate(node, &reduced) {
                return false;
            }
        }
        true
    }

    /// Exact-cut predicate for fixed rules: `true` when the new exclusions hit
    /// every previously surviving certificate.
    #[must_use]
    pub fn exact_cut(certificates: &[BTreeSet<usize>], excluded: &[bool]) -> bool {
        !certificates
            .iter()
            .any(|certificate| certificate.iter().all(|node| !excluded[*node]))
    }

    /// Deliberately wrong optimistic (greatest-fixed-point) variant used by the
    /// paper's seeded mutant: every unavailable node is seeded as accepted.
    #[must_use]
    pub fn optimistic_cycle_mutant(&self, excluded: &[bool]) -> Vec<bool> {
        let count = self.nodes.len();
        let mut accepted: Vec<bool> = excluded.iter().map(|value| !value).collect();
        loop {
            let mut updated = accepted.clone();
            for node in 0..count {
                if !accepted[node] {
                    continue;
                }
                let justified = self.rules[node]
                    .iter()
                    .any(|clause| clause.iter().all(|premise| accepted[*premise]));
                if !justified {
                    updated[node] = false;
                }
            }
            if updated == accepted {
                return accepted;
            }
            accepted = updated;
        }
    }
}

/// Normalize an antichain: deduplicate, then remove any set that has a proper
/// subset in the family.
fn minimize_sets(sets: &mut Vec<BTreeSet<usize>>) {
    sets.sort_by(|left, right| {
        left.len()
            .cmp(&right.len())
            .then_with(|| left.iter().cmp(right.iter()))
    });
    sets.dedup();
    let mut keep: Vec<BTreeSet<usize>> = Vec::new();
    'outer: for candidate in sets.iter() {
        for existing in &keep {
            if existing.is_subset(candidate) {
                continue 'outer;
            }
        }
        keep.push(candidate.clone());
    }
    *sets = keep;
}

/// Paper-aligned corpus counts over the exact enumerated universe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaperCounts {
    /// Number of rule systems: 12^3.
    pub rule_systems: usize,
    /// Number of revocation/challenge configurations: 12^3 * 8 * 8.
    pub configurations: usize,
    /// Node-level certificate comparisons: configurations * 3.
    pub certificate_checks: usize,
    /// The paper's "exact revocation cut checks": one per node in
    /// `S(revoked)` for each `(revoked, challenged)` pair.
    pub exact_revocation_cut_checks: usize,
    /// Single-revocation monotonicity relations.
    pub monotonicity_checks: usize,
    /// Configurations where the optimistic mutant differs from founded support.
    pub optimistic_mutant_differences: usize,
    /// Disagreements between fixed-point support and the DFS witness search.
    pub algorithm_disagreements: usize,
}

/// Recompute every count reported by the paper's `claim_model.py` using this
/// independently written implementation.
#[must_use]
pub fn paper_counts() -> PaperCounts {
    let systems = System::paper_universe();
    let node_count = 3;
    let mut configurations = 0usize;
    let mut certificate_checks = 0usize;
    let mut exact_revocation_cut_checks = 0usize;
    let mut monotonicity_checks = 0usize;
    let mut optimistic_mutant_differences = 0usize;
    let mut algorithm_disagreements = 0usize;

    for system in &systems {
        let certificates = system.certificates();
        for revoked_mask in 0u8..8 {
            let revoked: Vec<bool> = (0..node_count)
                .map(|node| revoked_mask & (1u8 << node) != 0)
                .collect();
            let before_challenge = system.fixed_point(&revoked);
            for challenged_mask in 0u8..8 {
                configurations += 1;
                let challenged: Vec<bool> = (0..node_count)
                    .map(|node| challenged_mask & (1u8 << node) != 0)
                    .collect();
                let (positive, admissible) = system.verdict_sets(&revoked, &challenged);
                let combined: Vec<bool> = revoked
                    .iter()
                    .zip(&challenged)
                    .map(|(left, right)| *left || *right)
                    .collect();

                // The paper compares its forward fixed point with a DFS finite
                // witness search for the same exclusion set. We check both the
                // positive and admissible fixed points.
                let positive_witnesses = system.witness_set(&revoked);
                let admissible_witnesses = system.witness_set(&combined);
                if positive != positive_witnesses || admissible != admissible_witnesses {
                    algorithm_disagreements += 1;
                }

                for node in 0..node_count {
                    certificate_checks += 1;
                    let characterized = certificates[node]
                        .iter()
                        .any(|certificate| certificate.iter().all(|item| !combined[*item]));
                    assert_eq!(
                        admissible[node], characterized,
                        "certificate characterization mismatch"
                    );
                }

                for node in 0..node_count {
                    if !before_challenge[node] {
                        continue;
                    }
                    exact_revocation_cut_checks += 1;
                    let surviving: Vec<&BTreeSet<usize>> = certificates[node]
                        .iter()
                        .filter(|certificate| certificate.iter().all(|item| !revoked[*item]))
                        .collect();
                    let every_route_hit = surviving
                        .iter()
                        .all(|certificate| certificate.iter().any(|item| challenged[*item]));
                    assert_eq!(!admissible[node], every_route_hit);
                }

                for extra in 0..node_count {
                    if revoked[extra] {
                        continue;
                    }
                    monotonicity_checks += 1;
                    let mut more_revoked = revoked.clone();
                    more_revoked[extra] = true;
                    let (_, smaller_admissible) = system.verdict_sets(&more_revoked, &challenged);
                    for node in 0..node_count {
                        assert!(!smaller_admissible[node] || admissible[node]);
                    }
                }

                let mutant = system.optimistic_cycle_mutant(&combined);
                if mutant != admissible {
                    optimistic_mutant_differences += 1;
                }
            }
        }
    }

    PaperCounts {
        rule_systems: systems.len(),
        configurations,
        certificate_checks,
        exact_revocation_cut_checks,
        monotonicity_checks,
        optimistic_mutant_differences,
        algorithm_disagreements,
    }
}
