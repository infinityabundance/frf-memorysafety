#![allow(clippy::module_name_repetitions)]
#![allow(clippy::too_many_lines)]

//! Phase 10.4b witness policy model.
//!
//! This module models administrative domains, shared trust assumptions, quorum
//! intersection, correlated witnesses, conflicting checkpoints, and rolled-back
//! witness state. It does **not** operate a witness, contact a witness, or
//! manufacture an external observation. A committed state that has no external
//! cosignatures reports `not_observed`; a policy that requires external
//! witnesses returns a typed `NOT_RUN` (exit 6).
//!
//! A witness quorum is not a protocol proof. The quorum-intersection condition
//! `2q - n > f` is a declared assumption about fault independence, not a
//! theorem about the deployed operators.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::etp::ETP_SPEC;
use crate::etp_auth::DimensionState;
use crate::etp_transparency::{
    decode_base64, encode_base64, note_key_id, parse_checkpoint, sha256_hex, Checkpoint,
    TransparencyStatus,
};
use crate::identity::hex_lower;

/// Witness state schema.
pub const WITNESS_STATE_SCHEMA: &str = "frf-etp.witness-state.v1";
/// Witness policy schema.
pub const WITNESS_POLICY_SCHEMA: &str = "frf-etp.witness-policy.v1";
/// Witness report schema.
pub const WITNESS_REPORT_SCHEMA: &str = "frf-etp.witness-verification.v1";
/// Claim ceiling.
pub const WITNESS_CLAIM_CEILING: &str = "A verified witness-policy model establishes only that the declared local test cosignatures satisfy the declared quorum and domain rules over the declared checkpoint under the declared trust assumptions. It does not establish that any external witness observed the log, that the witnesses are independent in reality, that the log is non-equivocating globally, or that the cosigned checkpoint is semantically valid. A witness quorum is not a protocol proof.";

/// One administrative domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdministrativeDomain {
    /// Stable domain identifier.
    pub id: String,
    /// Operator name or label.
    pub operator: String,
    /// Whether the domain declares itself operationally independent.
    pub independent: bool,
    /// Shared trust assumptions.
    pub shared_trust: Vec<String>,
    /// Whether a failure in this domain is a single fault domain.
    pub single_fault_domain: bool,
}

/// One witness key declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessKey {
    /// Stable witness identifier.
    pub id: String,
    /// Cosigner name used in the note signature line.
    pub name: String,
    /// Administrative domain identifier.
    pub domain: String,
    /// Raw 32-byte Ed25519 public key, canonical base64.
    pub public_key_base64: String,
    /// Optional explicit correlation group.
    pub correlation_group: Option<String>,
    /// Declared trust assumptions.
    pub trust_assumptions: Vec<String>,
}

/// Quorum model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumModel {
    /// Total declared witnesses.
    pub n: u32,
    /// Quorum threshold.
    pub q: u32,
    /// Maximum declared Byzantine witnesses.
    pub f: u32,
    /// Minimum distinct administrative domains in the quorum.
    pub required_domains: u32,
}

/// Witness policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessPolicy {
    /// Schema identifier.
    pub schema: String,
    /// ETP specification identifier.
    pub spec: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Log origin.
    pub log_origin: String,
    /// Local log identifier.
    pub log_id: String,
    /// Whether external witnessing is required.
    pub require_external_witnesses: bool,
    /// Administrative domains.
    pub administrative_domains: Vec<AdministrativeDomain>,
    /// Witness keys.
    pub witnesses: Vec<WitnessKey>,
    /// Quorum model.
    pub quorum: QuorumModel,
}

/// One observed root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRoot {
    /// Tree size.
    pub tree_size: u64,
    /// Root hash, lowercase hexadecimal.
    pub root_hash: String,
}

/// One witness observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessObservation {
    /// Witness identifier.
    pub id: String,
    /// `observed`, `not_observed`, or `local_test_only`.
    pub status: String,
    /// Highest tree size this witness previously observed.
    pub last_observed_tree_size: u64,
    /// Highest tree size this witness previously observed before the latest
    /// state. A larger value than `last_observed_tree_size` is a rollback.
    pub prior_max_tree_size: Option<u64>,
    /// Checkpoint digest the cosignature covers.
    pub checkpoint_sha256: String,
    /// Full note cosignature line, when present.
    pub cosignature: Option<String>,
    /// Historical roots declared by the witness.
    #[serde(default)]
    pub observed_roots: Vec<ObservedRoot>,
}

/// Self-contained witness state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessState {
    /// Schema identifier.
    pub schema: String,
    /// ETP specification identifier.
    pub spec: String,
    /// Exact checkpoint bytes, canonical base64.
    pub checkpoint_base64: String,
    /// Exact checkpoint digest, lowercase hexadecimal.
    pub checkpoint_sha256: String,
    /// Whether any external witness observed this checkpoint.
    pub external_witnessing: bool,
    /// Whether every cosignature is from a local test key.
    pub local_test_only: bool,
    /// Embedded policy.
    pub policy: WitnessPolicy,
    /// Per-witness observations.
    pub observations: Vec<WitnessObservation>,
}

/// Quorum report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumReport {
    /// Total declared witnesses.
    pub n: u32,
    /// Quorum threshold.
    pub q: u32,
    /// Maximum declared Byzantine witnesses.
    pub f: u32,
    /// Minimum distinct domains.
    pub required_domains: u32,
    /// The declared intersection condition.
    pub intersection_condition: String,
    /// Whether `2q - n > f` holds.
    pub intersection_holds: bool,
    /// Raw count of valid cosignatures.
    pub observed: u32,
    /// Count after collapsing correlated witnesses.
    pub effective_independent: u32,
    /// Distinct administrative domains.
    pub distinct_domains: u32,
    /// Whether the quorum is met.
    pub met: bool,
    /// Basis: `none`, `local_test_only`, or `declared_external`.
    pub basis: String,
}

/// One witness entry in the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessReportEntry {
    /// Witness identifier.
    pub id: String,
    /// Administrative domain.
    pub domain: String,
    /// Signature state.
    pub signature: DimensionState,
    /// Observation status.
    pub observation: String,
    /// Last observed tree size.
    pub last_observed_tree_size: u64,
    /// Rollback state.
    pub rollback: DimensionState,
}

/// One correlated pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelatedPair {
    /// First witness.
    pub left: String,
    /// Second witness.
    pub right: String,
    /// Reason.
    pub reason: String,
}

/// Witness refusal codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessRefusalCode {
    /// Malformed state or policy.
    MalformedState,
    /// Invalid cosignature.
    InvalidWitnessSignature,
    /// Unknown or duplicate witness.
    WitnessIdentityMismatch,
    /// Quorum assumption is inconsistent.
    QuorumAssumptionInvalid,
    /// Correlated witnesses were counted.
    CorrelatedWitnesses,
    /// Quorum not met.
    QuorumFailed,
    /// Conflicting equal-size checkpoints.
    ConflictingCheckpoints,
    /// Rolled-back witness state.
    WitnessStateRollback,
    /// External witnessing required but absent.
    ExternalObservationRequired,
    /// Checkpoint mismatch.
    CheckpointMismatch,
}

impl WitnessRefusalCode {
    /// Stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedState => "malformed_state",
            Self::InvalidWitnessSignature => "invalid_witness_signature",
            Self::WitnessIdentityMismatch => "witness_identity_mismatch",
            Self::QuorumAssumptionInvalid => "quorum_assumption_invalid",
            Self::CorrelatedWitnesses => "correlated_witnesses",
            Self::QuorumFailed => "quorum_failed",
            Self::ConflictingCheckpoints => "conflicting_checkpoints",
            Self::WitnessStateRollback => "witness_state_rollback",
            Self::ExternalObservationRequired => "external_observation_required",
            Self::CheckpointMismatch => "checkpoint_mismatch",
        }
    }
}

/// One witness refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessRefusal {
    /// Code.
    pub code: WitnessRefusalCode,
    /// Detail.
    pub detail: String,
}

/// Witness verification report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessReport {
    /// Schema identifier.
    pub schema: String,
    /// ETP specification identifier.
    pub spec: String,
    /// Overall status.
    pub status: TransparencyStatus,
    /// Policy identifier.
    pub policy_id: String,
    /// Log origin.
    pub log_origin: String,
    /// Local log identifier.
    pub log_id: String,
    /// Whether external witnessing is declared.
    pub external_witnessing: bool,
    /// Whether the state is local-test-only.
    pub local_test_only: bool,
    /// Witness observation state.
    pub witness_observation: String,
    /// Quorum report.
    pub quorum: QuorumReport,
    /// Per-witness entries.
    pub witnesses: Vec<WitnessReportEntry>,
    /// Correlated pairs.
    pub correlated_witnesses: Vec<CorrelatedPair>,
    /// Conflicting checkpoint descriptions.
    pub conflicting_checkpoints: Vec<String>,
    /// Refusals.
    pub refusals: Vec<WitnessRefusal>,
    /// Claim ceiling.
    pub claim_ceiling: String,
}

impl WitnessReport {
    /// Canonical report bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the report cannot be canonicalized.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WitnessError> {
        let value = serde_json::to_value(self).map_err(|error| WitnessError::Canonical {
            message: error.to_string(),
        })?;
        crate::identity::canonical_bytes(&value).map_err(|error| WitnessError::Canonical {
            message: error.to_string(),
        })
    }

    /// `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        self.status.exit_code()
    }
}

/// Witness error.
#[derive(Debug)]
pub enum WitnessError {
    /// Usage problem.
    Usage {
        /// Detail.
        message: String,
    },
    /// Integrity problem.
    Integrity {
        /// Detail.
        message: String,
    },
    /// Canonicalization problem.
    Canonical {
        /// Detail.
        message: String,
    },
}

impl fmt::Display for WitnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage { message } | Self::Integrity { message } | Self::Canonical { message } => {
                formatter.write_str(message)
            }
        }
    }
}

impl std::error::Error for WitnessError {}

impl WitnessError {
    /// `SPEC.md` §14 exit status.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Usage { .. } => 2,
            Self::Integrity { .. } => 3,
            Self::Canonical { .. } => 7,
        }
    }
}

/// Verify a witness state.
#[must_use]
pub fn verify_witness_state(bytes: &[u8]) -> WitnessReport {
    let mut report = WitnessReport {
        schema: WITNESS_REPORT_SCHEMA.to_owned(),
        spec: ETP_SPEC.to_owned(),
        status: TransparencyStatus::Verified,
        policy_id: String::new(),
        log_origin: String::new(),
        log_id: String::new(),
        external_witnessing: false,
        local_test_only: false,
        witness_observation: "not_observed".to_owned(),
        quorum: QuorumReport {
            n: 0,
            q: 0,
            f: 0,
            required_domains: 0,
            intersection_condition: "2q - n > f".to_owned(),
            intersection_holds: false,
            observed: 0,
            effective_independent: 0,
            distinct_domains: 0,
            met: false,
            basis: "none".to_owned(),
        },
        witnesses: Vec::new(),
        correlated_witnesses: Vec::new(),
        conflicting_checkpoints: Vec::new(),
        refusals: Vec::new(),
        claim_ceiling: WITNESS_CLAIM_CEILING.to_owned(),
    };

    let state: WitnessState = match serde_json::from_slice(bytes) {
        Ok(state) => state,
        Err(error) => {
            report.status = TransparencyStatus::IntegrityFailure;
            report.refusals.push(WitnessRefusal {
                code: WitnessRefusalCode::MalformedState,
                detail: format!("malformed witness state: {error}"),
            });
            return report;
        }
    };
    if state.schema != WITNESS_STATE_SCHEMA
        || state.spec != ETP_SPEC
        || state.policy.schema != WITNESS_POLICY_SCHEMA
        || state.policy.spec != ETP_SPEC
    {
        report.status = TransparencyStatus::IntegrityFailure;
        report.refusals.push(WitnessRefusal {
            code: WitnessRefusalCode::MalformedState,
            detail: "unsupported witness state or policy schema".to_owned(),
        });
        return report;
    }
    report.policy_id.clone_from(&state.policy.policy_id);
    report.log_origin.clone_from(&state.policy.log_origin);
    report.log_id.clone_from(&state.policy.log_id);
    report.external_witnessing = state.external_witnessing;
    report.local_test_only = state.local_test_only;

    let checkpoint_bytes = match decode_base64(&state.checkpoint_base64) {
        Ok(bytes) => bytes,
        Err(error) => {
            report.status = TransparencyStatus::IntegrityFailure;
            report.refusals.push(WitnessRefusal {
                code: WitnessRefusalCode::MalformedState,
                detail: format!("checkpoint base64 is invalid: {error}"),
            });
            return report;
        }
    };
    let checkpoint = match parse_checkpoint(&checkpoint_bytes) {
        Ok(checkpoint) => checkpoint,
        Err(error) => {
            report.status = TransparencyStatus::IntegrityFailure;
            report.refusals.push(WitnessRefusal {
                code: WitnessRefusalCode::MalformedState,
                detail: error.to_string(),
            });
            return report;
        }
    };
    if checkpoint.sha256 != state.checkpoint_sha256 || checkpoint.origin != state.policy.log_origin
    {
        report.status = TransparencyStatus::IntegrityFailure;
        report.refusals.push(WitnessRefusal {
            code: WitnessRefusalCode::CheckpointMismatch,
            detail: "checkpoint bytes, digest, or origin do not match the state".to_owned(),
        });
        return report;
    }

    let domains: BTreeMap<&str, &AdministrativeDomain> = state
        .policy
        .administrative_domains
        .iter()
        .map(|domain| (domain.id.as_str(), domain))
        .collect();
    let keys: BTreeMap<&str, &WitnessKey> = state
        .policy
        .witnesses
        .iter()
        .map(|witness| (witness.id.as_str(), witness))
        .collect();
    if keys.len() != state.policy.witnesses.len()
        || domains.len() != state.policy.administrative_domains.len()
    {
        report.status = TransparencyStatus::IntegrityFailure;
        report.refusals.push(WitnessRefusal {
            code: WitnessRefusalCode::MalformedState,
            detail: "duplicate witness or domain identifier".to_owned(),
        });
        return report;
    }
    let mut observations: BTreeMap<&str, &WitnessObservation> = BTreeMap::new();
    for observation in &state.observations {
        if observations
            .insert(observation.id.as_str(), observation)
            .is_some()
        {
            report.status = TransparencyStatus::IntegrityFailure;
            report.refusals.push(WitnessRefusal {
                code: WitnessRefusalCode::MalformedState,
                detail: format!("duplicate observation for {}", observation.id),
            });
            return report;
        }
    }
    if observations.len() != keys.len() || observations.keys().any(|id| !keys.contains_key(id)) {
        report.status = TransparencyStatus::IntegrityFailure;
        report.refusals.push(WitnessRefusal {
            code: WitnessRefusalCode::WitnessIdentityMismatch,
            detail: "observations do not match the declared witness set".to_owned(),
        });
        return report;
    }

    let mut counted = Vec::new();
    for witness in &state.policy.witnesses {
        let Some(observation) = observations.get(witness.id.as_str()) else {
            continue;
        };
        let Some(domain) = domains.get(witness.domain.as_str()) else {
            report.refusals.push(WitnessRefusal {
                code: WitnessRefusalCode::WitnessIdentityMismatch,
                detail: format!("witness {} names an undeclared domain", witness.id),
            });
            continue;
        };
        if !matches!(
            observation.status.as_str(),
            "observed" | "not_observed" | "local_test_only"
        ) {
            report.refusals.push(WitnessRefusal {
                code: WitnessRefusalCode::MalformedState,
                detail: format!("witness {} has an invalid observation status", witness.id),
            });
            continue;
        }

        let public_key = decode_base64(&witness.public_key_base64)
            .ok()
            .and_then(|bytes| {
                if bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    Some(key)
                } else {
                    None
                }
            });
        let Some(public_key) = public_key else {
            report.witnesses.push(WitnessReportEntry {
                id: witness.id.clone(),
                domain: domain.id.clone(),
                signature: DimensionState::Invalid,
                observation: observation.status.clone(),
                last_observed_tree_size: observation.last_observed_tree_size,
                rollback: DimensionState::NotChecked,
            });
            report.refusals.push(WitnessRefusal {
                code: WitnessRefusalCode::WitnessIdentityMismatch,
                detail: format!("witness {} public key is not 32-byte base64", witness.id),
            });
            continue;
        };

        let mut signature = DimensionState::NotApplicable;
        let mut signature_ok = false;
        if let Some(line) = &observation.cosignature {
            signature = DimensionState::Invalid;
            if verify_cosignature(line, witness, &public_key, &checkpoint) {
                signature = DimensionState::Valid;
                signature_ok = true;
            } else {
                report.refusals.push(WitnessRefusal {
                    code: WitnessRefusalCode::InvalidWitnessSignature,
                    detail: format!("witness {} cosignature is invalid", witness.id),
                });
            }
        }

        let rolled_back = observation
            .prior_max_tree_size
            .is_some_and(|prior| prior > observation.last_observed_tree_size);
        let ahead = observation.last_observed_tree_size > checkpoint.size;
        let rollback = if rolled_back || ahead {
            DimensionState::Invalid
        } else {
            DimensionState::Valid
        };
        if rolled_back {
            report.refusals.push(WitnessRefusal {
                code: WitnessRefusalCode::WitnessStateRollback,
                detail: format!(
                    "witness {} latest size {} is below its prior maximum",
                    witness.id, observation.last_observed_tree_size
                ),
            });
        }
        if ahead {
            report.refusals.push(WitnessRefusal {
                code: WitnessRefusalCode::WitnessStateRollback,
                detail: format!(
                    "witness {} observed size {} exceeds the checkpoint size {}",
                    witness.id, observation.last_observed_tree_size, checkpoint.size
                ),
            });
        }

        // Equal-size conflicting roots declared by the witness.
        let mut roots: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
        for observed in &observation.observed_roots {
            roots
                .entry(observed.tree_size)
                .or_default()
                .insert(observed.root_hash.to_lowercase());
        }
        for (size, values) in roots {
            if values.len() > 1 {
                report.conflicting_checkpoints.push(format!(
                    "witness {} declares conflicting roots at size {size}: {values:?}",
                    witness.id
                ));
                report.refusals.push(WitnessRefusal {
                    code: WitnessRefusalCode::ConflictingCheckpoints,
                    detail: format!(
                        "witness {} has conflicting equal-size checkpoints at size {size}",
                        witness.id
                    ),
                });
            }
        }

        if signature_ok && matches!(observation.status.as_str(), "observed" | "local_test_only") {
            counted.push((witness, observation, domain));
        }
        report.witnesses.push(WitnessReportEntry {
            id: witness.id.clone(),
            domain: domain.id.clone(),
            signature,
            observation: observation.status.clone(),
            last_observed_tree_size: observation.last_observed_tree_size,
            rollback,
        });
    }

    // Quorum assumptions.
    let quorum = &state.policy.quorum;
    report.quorum = QuorumReport {
        n: quorum.n,
        q: quorum.q,
        f: quorum.f,
        required_domains: quorum.required_domains,
        intersection_condition: "2q - n > f".to_owned(),
        intersection_holds: (2 * quorum.q) > (quorum.n + quorum.f),
        observed: u32::try_from(counted.len()).unwrap_or(u32::MAX),
        effective_independent: 0,
        distinct_domains: 0,
        met: false,
        basis: if state.local_test_only {
            "local_test_only".to_owned()
        } else if state.external_witnessing {
            "declared_external".to_owned()
        } else {
            "none".to_owned()
        },
    };
    if quorum.q == 0 || quorum.q > quorum.n || quorum.f >= quorum.n.max(1) {
        report.refusals.push(WitnessRefusal {
            code: WitnessRefusalCode::QuorumAssumptionInvalid,
            detail: "q must be in 1..=n and f must be below n".to_owned(),
        });
    }
    if quorum.n as usize != state.policy.witnesses.len() {
        report.refusals.push(WitnessRefusal {
            code: WitnessRefusalCode::QuorumAssumptionInvalid,
            detail: "declared n does not equal the number of witness keys".to_owned(),
        });
    }
    if !report.quorum.intersection_holds {
        report.refusals.push(WitnessRefusal {
            code: WitnessRefusalCode::QuorumAssumptionInvalid,
            detail: "2q - n > f does not hold".to_owned(),
        });
    }
    if u32::try_from(domains.len()).unwrap_or(u32::MAX) < quorum.required_domains {
        report.refusals.push(WitnessRefusal {
            code: WitnessRefusalCode::QuorumAssumptionInvalid,
            detail: "required_domains exceeds the declared administrative domains".to_owned(),
        });
    }

    // Correlation detection: administrative domain, explicit correlation group,
    // or a shared single-fault trust assumption.
    let mut units: BTreeSet<String> = BTreeSet::new();
    let mut domains_seen: BTreeSet<&str> = BTreeSet::new();
    for (index, (left, _, left_domain)) in counted.iter().enumerate() {
        for (right, _, right_domain) in counted.iter().skip(index + 1) {
            let mut reason = None;
            if left_domain.id == right_domain.id {
                reason = Some(format!("same administrative domain {}", left_domain.id));
            } else if left.correlation_group.is_some()
                && left.correlation_group == right.correlation_group
            {
                reason = Some(format!(
                    "same correlation group {}",
                    left.correlation_group.as_deref().unwrap_or("")
                ));
            } else {
                for assumption in &left_domain.shared_trust {
                    if left_domain.single_fault_domain
                        && right_domain.shared_trust.contains(assumption)
                    {
                        reason = Some(format!("shared single-fault assumption {assumption}"));
                        break;
                    }
                }
            }
            if let Some(reason) = reason {
                report.correlated_witnesses.push(CorrelatedPair {
                    left: left.id.clone(),
                    right: right.id.clone(),
                    reason,
                });
            }
        }
        domains_seen.insert(left_domain.id.as_str());
        units.insert(
            left.correlation_group
                .clone()
                .unwrap_or_else(|| left_domain.id.clone()),
        );
    }
    if !report.correlated_witnesses.is_empty() {
        report.refusals.push(WitnessRefusal {
            code: WitnessRefusalCode::CorrelatedWitnesses,
            detail: "counted witnesses are correlated and do not provide independent quorum"
                .to_owned(),
        });
    }
    report.quorum.effective_independent = u32::try_from(units.len()).unwrap_or(u32::MAX);
    report.quorum.distinct_domains = u32::try_from(domains_seen.len()).unwrap_or(u32::MAX);

    let quorum_met = report.correlated_witnesses.is_empty()
        && report.quorum.effective_independent >= quorum.q
        && report.quorum.distinct_domains >= quorum.required_domains;
    report.quorum.met = quorum_met;
    if !quorum_met {
        report.refusals.push(WitnessRefusal {
            code: WitnessRefusalCode::QuorumFailed,
            detail: format!(
                "effective independent witnesses {} and distinct domains {} do not meet q={} / required_domains={}",
                report.quorum.effective_independent,
                report.quorum.distinct_domains,
                quorum.q,
                quorum.required_domains
            ),
        });
    }

    let any_observed = state
        .observations
        .iter()
        .any(|observation| observation.status == "observed");
    if state.external_witnessing && any_observed {
        "declared_observed_not_independently_confirmed".clone_into(&mut report.witness_observation);
    } else {
        "not_observed".clone_into(&mut report.witness_observation);
    }

    if state.policy.require_external_witnesses && !state.external_witnessing {
        report.status = TransparencyStatus::NotRun;
        report.refusals.push(WitnessRefusal {
            code: WitnessRefusalCode::ExternalObservationRequired,
            detail: "policy requires external witnesses but the state declares none".to_owned(),
        });
        return report;
    }

    if report.quorum.met && report.refusals.is_empty() {
        report.status = TransparencyStatus::Verified;
    } else if report
        .refusals
        .iter()
        .any(|refusal| refusal.code == WitnessRefusalCode::ExternalObservationRequired)
    {
        report.status = TransparencyStatus::NotRun;
    } else {
        report.status = TransparencyStatus::Refused;
    }
    report
}

fn verify_cosignature(
    line: &str,
    witness: &WitnessKey,
    public_key: &[u8; 32],
    checkpoint: &Checkpoint,
) -> bool {
    let Some(rest) = line.strip_prefix("\u{2014} ") else {
        return false;
    };
    let Some((name, encoded)) = rest.split_once(' ') else {
        return false;
    };
    if name != witness.name {
        return false;
    }
    let Ok(raw) = decode_base64(encoded) else {
        return false;
    };
    if raw.len() != 4 + 8 + 64 {
        return false;
    }
    let Some(expected_keyid) = note_key_id(witness.name.as_str(), public_key, 0x04) else {
        return false;
    };
    if raw[..4] != expected_keyid {
        return false;
    }
    let timestamp = u64::from_be_bytes([
        raw[4], raw[5], raw[6], raw[7], raw[8], raw[9], raw[10], raw[11],
    ]);
    let message = cosignature_message(checkpoint, timestamp);
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    Signature::from_slice(&raw[12..])
        .is_ok_and(|signature| verifying_key.verify_strict(&message, &signature).is_ok())
}

fn cosignature_message(checkpoint: &Checkpoint, timestamp: u64) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(b"cosignature/v1\n");
    message.extend_from_slice(format!("time {timestamp}\n").as_bytes());
    message.extend_from_slice(checkpoint.origin.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(checkpoint.size.to_string().as_bytes());
    message.push(b'\n');
    message.extend_from_slice(encode_base64(&checkpoint.root).as_bytes());
    message.push(b'\n');
    for extension in &checkpoint.extensions {
        message.extend_from_slice(extension.as_bytes());
        message.push(b'\n');
    }
    message
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build a canonical base64 encoding of a checkpoint cosignature.
///
/// This helper exists for executable tests and fixture generation. It takes a
/// caller-supplied secret key; the repository never commits a private key.
#[must_use]
pub fn build_local_test_cosignature(
    signing_key: &ed25519_dalek::SigningKey,
    name: &str,
    checkpoint: &Checkpoint,
    timestamp: u64,
) -> String {
    let public_key = signing_key.verifying_key().to_bytes();
    let Some(keyid) = note_key_id(name, &public_key, 0x04) else {
        return String::new();
    };
    let message = cosignature_message(checkpoint, timestamp);
    let signature = ed25519_dalek::Signer::sign(signing_key, &message);
    let mut raw = Vec::with_capacity(4 + 8 + 64);
    raw.extend_from_slice(&keyid);
    raw.extend_from_slice(&timestamp.to_be_bytes());
    raw.extend_from_slice(&signature.to_bytes());
    format!("\u{2014} {name} {}", encode_base64(&raw))
}

/// Encode a checkpoint digest.
#[must_use]
pub fn checkpoint_digest(checkpoint: &Checkpoint) -> String {
    sha256_hex(&checkpoint.original)
}

/// Decode a 32-byte public key from canonical base64.
#[must_use]
pub fn decode_public_key(encoded: &str) -> Option<[u8; 32]> {
    decode_base64(encoded).ok().and_then(|bytes| {
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Some(key)
        } else {
            None
        }
    })
}

/// Lowercase hexadecimal helper for reports.
#[must_use]
pub fn hex32(value: &[u8; 32]) -> String {
    hex_lower(value)
}
