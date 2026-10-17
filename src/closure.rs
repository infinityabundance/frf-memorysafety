//! Set-based declared/observed inventory comparison for the §12.4 fixtures.
//!
//! This module compares two explicitly supplied edge sets. It is not a source
//! extractor, a native callback recorder, or a conservative-closure proof.
//! Observation can falsify a declaration; it cannot by itself establish that
//! every supported interaction family has a justified edge.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// One directed interaction edge, named by its two endpoints.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeKey {
    /// Declaring or calling side.
    pub caller: String,
    /// Invoked or observed side.
    pub callback: String,
}

impl EdgeKey {
    /// Construct an edge key.
    #[must_use]
    pub fn new(caller: impl Into<String>, callback: impl Into<String>) -> Self {
        Self {
            caller: caller.into(),
            callback: callback.into(),
        }
    }
}

/// Outcome of comparing observed edges with a declared inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageOutcome {
    /// An observed edge is absent from the declaration.
    Falsified {
        /// Observed edges missing from the declaration.
        observed_omissions: BTreeSet<EdgeKey>,
    },
    /// No observed omission was found. This is not conservative closure.
    NotFalsified {
        /// Edges present in both sets.
        matched: BTreeSet<EdgeKey>,
        /// Declared edges not observed in this fixture.
        unobserved_declared: BTreeSet<EdgeKey>,
    },
}

impl CoverageOutcome {
    /// Whether an observation contradicted the declared inventory.
    #[must_use]
    pub fn is_falsified(&self) -> bool {
        matches!(self, Self::Falsified { .. })
    }

    /// Whether this fixture established a justified conservative closure.
    ///
    /// It never does: absence of an observed omission is not positive evidence
    /// that every supported interaction family was covered.
    #[must_use]
    pub const fn is_conservative_closure(&self) -> bool {
        false
    }
}

/// Compare declared and observed edge sets.
///
/// An observed omission falsifies the declaration. A declared-but-unobserved
/// edge and an observed declared edge both yield `NotFalsified`; neither yields
/// conservative closure.
#[must_use]
pub fn compare_inventory(
    declared: &BTreeSet<EdgeKey>,
    observed: &BTreeSet<EdgeKey>,
) -> CoverageOutcome {
    let observed_omissions: BTreeSet<EdgeKey> = observed.difference(declared).cloned().collect();
    if !observed_omissions.is_empty() {
        return CoverageOutcome::Falsified { observed_omissions };
    }
    CoverageOutcome::NotFalsified {
        matched: declared.intersection(observed).cloned().collect(),
        unobserved_declared: declared.difference(observed).cloned().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edges(items: &[(&str, &str)]) -> BTreeSet<EdgeKey> {
        items
            .iter()
            .map(|(caller, callback)| EdgeKey::new(*caller, *callback))
            .collect()
    }

    #[test]
    fn observed_omission_falsifies() {
        let declared = edges(&[("a", "b")]);
        let observed = edges(&[("a", "b"), ("a", "c")]);
        let outcome = compare_inventory(&declared, &observed);
        assert!(outcome.is_falsified());
        assert!(!outcome.is_conservative_closure());
        let CoverageOutcome::Falsified { observed_omissions } = outcome else {
            panic!("expected falsified");
        };
        assert_eq!(observed_omissions, edges(&[("a", "c")]));
    }

    #[test]
    fn unobserved_declaration_is_not_falsified_and_not_closure() {
        let declared = edges(&[("a", "b"), ("a", "c")]);
        let observed = edges(&[("a", "b")]);
        let outcome = compare_inventory(&declared, &observed);
        assert!(!outcome.is_falsified());
        assert!(!outcome.is_conservative_closure());
        let CoverageOutcome::NotFalsified {
            matched,
            unobserved_declared,
        } = outcome
        else {
            panic!("expected not falsified");
        };
        assert_eq!(matched, edges(&[("a", "b")]));
        assert_eq!(unobserved_declared, edges(&[("a", "c")]));
    }

    #[test]
    fn observed_declaration_is_not_falsified_and_not_closure() {
        let declared = edges(&[("a", "b")]);
        let observed = edges(&[("a", "b")]);
        let outcome = compare_inventory(&declared, &observed);
        assert!(!outcome.is_falsified());
        assert!(!outcome.is_conservative_closure());
        let CoverageOutcome::NotFalsified {
            matched,
            unobserved_declared,
        } = outcome
        else {
            panic!("expected not falsified");
        };
        assert_eq!(matched, declared);
        assert!(unobserved_declared.is_empty());
    }
}
