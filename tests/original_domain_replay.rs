//! Independent replay of the original eight-case C0/C1/C2 constructed domain.
//!
//! The original model source is `research/paper/research/worked_bundle.py`.
//! This file is a separately written Rust reimplementation of its `run`
//! function and `EXPECTED` table, used to cross-check the crate's separately
//! identified local reconstruction. It establishes only that the finite model
//! results reproduce; it is not native execution, independent authorship of the
//! Python model, or a soundness proof.

use frf_memorysafety::profile::{
    evaluate_profile, local_buffer_bundle, local_buffer_records, BufferVariant, ClaimDisposition,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Case {
    replace: bool,
    refuse: bool,
    valid_identity: bool,
}

// `itertools.product((False, True), repeat=3)` in the original source.
const CASES: [Case; 8] = [
    Case {
        replace: false,
        refuse: false,
        valid_identity: false,
    },
    Case {
        replace: false,
        refuse: false,
        valid_identity: true,
    },
    Case {
        replace: false,
        refuse: true,
        valid_identity: false,
    },
    Case {
        replace: false,
        refuse: true,
        valid_identity: true,
    },
    Case {
        replace: true,
        refuse: false,
        valid_identity: false,
    },
    Case {
        replace: true,
        refuse: false,
        valid_identity: true,
    },
    Case {
        replace: true,
        refuse: true,
        valid_identity: false,
    },
    Case {
        replace: true,
        refuse: true,
        valid_identity: true,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Replay {
    Conflict,
    Adjudicated {
        byte: u8,
        verdict: &'static str,
        allocation: &'static str,
    },
}

// The original `EXPECTED` table for case-0 through case-7.
const EXPECTED: [Replay; 8] = [
    Replay::Adjudicated {
        byte: 7,
        verdict: "reject",
        allocation: "unused",
    },
    Replay::Adjudicated {
        byte: 7,
        verdict: "accept",
        allocation: "unused",
    },
    Replay::Adjudicated {
        byte: 7,
        verdict: "reject",
        allocation: "unused",
    },
    Replay::Adjudicated {
        byte: 7,
        verdict: "accept",
        allocation: "unused",
    },
    Replay::Adjudicated {
        byte: 9,
        verdict: "reject",
        allocation: "replaced",
    },
    Replay::Adjudicated {
        byte: 9,
        verdict: "accept",
        allocation: "replaced",
    },
    Replay::Adjudicated {
        byte: 7,
        verdict: "reject",
        allocation: "refused",
    },
    Replay::Adjudicated {
        byte: 7,
        verdict: "accept",
        allocation: "refused",
    },
];

fn replay(candidate: BufferVariant, case: Case) -> Replay {
    let borrow = candidate == BufferVariant::C0;
    let mut byte = 7u8;
    let mut allocation = "unused";
    if case.replace {
        if case.refuse {
            allocation = "refused";
        } else {
            if borrow {
                return Replay::Conflict;
            }
            byte = 9;
            allocation = "replaced";
        }
    }
    let verdict = if candidate == BufferVariant::C2 || case.valid_identity {
        "accept"
    } else {
        "reject"
    };
    Replay::Adjudicated {
        byte,
        verdict,
        allocation,
    }
}

fn original_counts(candidate: BufferVariant) -> (usize, usize, usize) {
    let mut conflicts = 0usize;
    let mut adjudicable = 0usize;
    let mut mismatches = 0usize;
    for (index, case) in CASES.iter().enumerate() {
        let actual = replay(candidate, *case);
        match actual {
            Replay::Conflict => conflicts += 1,
            Replay::Adjudicated { .. } => {
                adjudicable += 1;
                if actual != EXPECTED[index] {
                    mismatches += 1;
                }
            }
        }
    }
    (conflicts, adjudicable, mismatches)
}

fn reconstruction_counts(candidate: BufferVariant) -> (usize, usize, usize) {
    let records = local_buffer_records();
    let cases: Vec<_> = records
        .iter()
        .filter(|case| case.variant == candidate)
        .collect();
    assert_eq!(cases.len(), 8);
    let conflicts = cases
        .iter()
        .filter(|case| case.model_violation.is_some())
        .count();
    let adjudicable = cases.iter().filter(|case| case.adjudicable).count();
    let mismatches = cases
        .iter()
        .filter(|case| {
            case.adjudicable && case.model_replay_outcome != case.stipulated_oracle_outcome
        })
        .count();
    (conflicts, adjudicable, mismatches)
}

#[test]
fn original_model_replays_to_the_documented_counts() {
    assert_eq!(original_counts(BufferVariant::C0), (2, 6, 0));
    assert_eq!(original_counts(BufferVariant::C1), (0, 8, 0));
    assert_eq!(original_counts(BufferVariant::C2), (0, 8, 4));
}

#[test]
fn local_reconstruction_preserves_the_original_domain_counts() {
    for candidate in [BufferVariant::C0, BufferVariant::C1, BufferVariant::C2] {
        assert_eq!(
            reconstruction_counts(candidate),
            original_counts(candidate),
            "reconstruction counts diverged for {}",
            candidate.as_str()
        );
    }
}

#[test]
fn original_dispositions_agree_except_scoped_c0_parity() {
    let evaluation = evaluate_profile(&local_buffer_bundle());
    for (variant, clear, parity, restriction, conjunction) in [
        (
            "c0",
            ClaimDisposition::NotEstablished,
            ClaimDisposition::Established,
            ClaimDisposition::NotEstablished,
            ClaimDisposition::NotEstablished,
        ),
        (
            "c1",
            ClaimDisposition::Established,
            ClaimDisposition::Established,
            ClaimDisposition::Established,
            ClaimDisposition::Established,
        ),
        (
            "c2",
            ClaimDisposition::Established,
            ClaimDisposition::NotEstablished,
            ClaimDisposition::Established,
            ClaimDisposition::NotEstablished,
        ),
    ] {
        assert_eq!(
            evaluation.claims[&format!("{variant}-clear")].disposition,
            clear
        );
        assert_eq!(
            evaluation.claims[&format!("{variant}-parity")].disposition,
            parity
        );
        assert_eq!(
            evaluation.claims[&format!("{variant}-restriction")].disposition,
            restriction
        );
        assert_eq!(
            evaluation.claims[&format!("{variant}-conjunction")].disposition,
            conjunction
        );
        assert_eq!(
            evaluation.claims[&format!("{variant}-universal")].disposition,
            ClaimDisposition::Withheld
        );
    }

    // The original full-domain c0 parity claim is withheld because two cases
    // have modeled conflicts and no adjudicated observation. The crate scopes
    // its c0 parity claim to the six adjudicable cases, so that scoped claim is
    // established. This is the only disposition difference and it is a
    // domain-scoping difference, not a stronger conclusion over the full domain.
    assert_eq!(original_counts(BufferVariant::C0).0, 2);
    assert_eq!(original_counts(BufferVariant::C0).2, 0);
}
