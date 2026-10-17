//! Bounded conformance corpus required by the phase-1 contract.
//!
//! This test MUST execute (it is not ignored). It exercises 12^3 systems,
//! 8 revocation masks, and 8 challenge masks: 110,592 configurations and
//! 331,776 node-certificate comparisons.

use frf_memorysafety::support::{conformance_counts, conformance_patterns};

#[test]
fn conformance_corpus_is_exhaustive_and_certificate_characterized() {
    assert_eq!(conformance_patterns(&["a", "b", "c"]).len(), 12);
    let (configurations, node_comparisons, exact_cut_cases) = conformance_counts();
    assert_eq!(configurations, 110_592);
    assert_eq!(node_comparisons, 331_776);
    assert!(exact_cut_cases > 0);
}
