//! Least-fixed-point positive support, challenging, certificates, and exact cuts.
//!
//! This is bookkeeping over a declared rule system. It is not a semantic
//! soundness proof and it does not validate the truth of an external leaf.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::identity::{canonical_bytes, digest_bytes, IdentityDomain, MsId};

/// A claim identifier local to a finite support graph.
pub type ClaimId = String;
/// A conjunctive premise set.
pub type PremiseSet = BTreeSet<ClaimId>;

/// One inference rule system. Empty premise sets are admitted leaves only when
/// explicitly listed in [`RuleSystem::admitted_leaves`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RuleSystem {
    /// Rules keyed by conclusion.
    pub rules: BTreeMap<ClaimId, Vec<PremiseSet>>,
    /// Externally justified leaves. Membership is a policy admission, not truth.
    pub admitted_leaves: BTreeSet<ClaimId>,
}

impl RuleSystem {
    /// Construct an empty system.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule. An empty premise set is rejected unless the conclusion is
    /// an admitted leaf.
    ///
    /// # Errors
    ///
    /// Returns [`SupportError::UnjustifiedLeaf`] when an empty premise set is
    /// supplied for a claim that is not an admitted leaf.
    pub fn add_rule(
        &mut self,
        conclusion: impl Into<ClaimId>,
        premises: impl IntoIterator<Item = ClaimId>,
    ) -> Result<(), SupportError> {
        let conclusion = conclusion.into();
        let premises: PremiseSet = premises.into_iter().collect();
        if premises.is_empty() && !self.admitted_leaves.contains(&conclusion) {
            return Err(SupportError::UnjustifiedLeaf(conclusion));
        }
        self.rules.entry(conclusion).or_default().push(premises);
        Ok(())
    }

    /// Admit an externally justified leaf. The caller is responsible for the
    /// leaf's actual scope and owner; this method records only admission.
    pub fn admit_leaf(&mut self, claim: impl Into<ClaimId>) {
        self.admitted_leaves.insert(claim.into());
    }

    /// Remove exactly one rule instance `conclusion <- premises`.
    ///
    /// The match is at the rule boundary: a different premise set for the same
    /// conclusion, or the same premise set for a different conclusion, is not
    /// removed. Leaf admission is a separate external justification and is not
    /// revoked by this method.
    ///
    /// Returns `true` when a rule was removed.
    pub fn remove_rule(&mut self, conclusion: &str, premises: &PremiseSet) -> bool {
        let Some(rules) = self.rules.get_mut(conclusion) else {
            return false;
        };
        let Some(index) = rules.iter().position(|candidate| candidate == premises) else {
            return false;
        };
        rules.remove(index);
        if rules.is_empty() {
            self.rules.remove(conclusion);
        }
        true
    }

    /// Validate structural constraints, including empty-premise admission.
    ///
    /// # Errors
    ///
    /// Returns [`SupportError::UnjustifiedLeaf`] for an unadmitted empty rule.
    pub fn validate(&self) -> Result<(), SupportError> {
        for (conclusion, rules) in &self.rules {
            for premises in rules {
                if premises.is_empty() && !self.admitted_leaves.contains(conclusion) {
                    return Err(SupportError::UnjustifiedLeaf(conclusion.clone()));
                }
                if premises.contains(conclusion) {
                    // Self dependence is allowed to exist in an unchecked graph,
                    // but it can never create support. Keep it representable and
                    // let least-fixed-point evaluation reject the derivation.
                }
            }
        }
        Ok(())
    }

    /// All claim nodes named by rules or admissions.
    #[must_use]
    pub fn nodes(&self) -> BTreeSet<ClaimId> {
        let mut nodes: BTreeSet<ClaimId> = self.rules.keys().cloned().collect();
        for rules in self.rules.values() {
            for premises in rules {
                nodes.extend(premises.iter().cloned());
            }
        }
        nodes.extend(self.admitted_leaves.iter().cloned());
        nodes
    }
}

/// Errors from support evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportError {
    /// An empty rule was supplied for a claim that is not an admitted leaf.
    UnjustifiedLeaf(ClaimId),
    /// The named claim is not present in the rule system.
    UnknownClaim(ClaimId),
    /// Certificate enumeration exceeded the caller's cap.
    CertificateLimitExceeded {
        /// Claim being enumerated.
        claim: ClaimId,
        /// Maximum number of certificate sets.
        limit: usize,
    },
    /// The supplied policy identity does not match the stored verdict.
    PolicyMismatch,
    /// A recorded historical verdict does not match its policy or digest.
    HistoryMismatch(String),
    /// A claim reported as supported has no surviving certificate.
    InconsistentSupport(ClaimId),
}

impl fmt::Display for SupportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnjustifiedLeaf(claim) => {
                write!(
                    f,
                    "claim {claim:?} has an empty rule but is not an admitted leaf"
                )
            }
            Self::UnknownClaim(claim) => write!(f, "unknown claim {claim:?}"),
            Self::CertificateLimitExceeded { claim, limit } => {
                write!(
                    f,
                    "certificate enumeration for {claim:?} exceeded {limit} sets"
                )
            }
            Self::PolicyMismatch => f.write_str("policy identity mismatch"),
            Self::HistoryMismatch(detail) => write!(f, "historical verdict mismatch: {detail}"),
            Self::InconsistentSupport(claim) => {
                write!(f, "supported claim {claim:?} has no certificate")
            }
        }
    }
}

impl std::error::Error for SupportError {}

/// Bookkeeping state for one claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportState {
    /// No derivation avoids the exclusions.
    Unsupported,
    /// Supported and admissible.
    Supported,
    /// Excluded by an admitted challenge.
    Challenged,
    /// Positive support survives, but a challenge withholds admissibility.
    SupportedButChallenged,
}

/// Result of one fixed-point evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportResult {
    /// Positive support under revoked leaves only.
    pub positive: BTreeSet<ClaimId>,
    /// Support after excluding challenged claims as well.
    pub admissible: BTreeSet<ClaimId>,
    /// Revoked leaves.
    pub revoked: BTreeSet<ClaimId>,
    /// Admitted unresolved challenges.
    pub challenged: BTreeSet<ClaimId>,
    /// Per-claim bookkeeping state.
    pub states: BTreeMap<ClaimId, SupportState>,
}

impl SupportResult {
    /// Whether the claim is positively supported.
    #[must_use]
    pub fn is_supported(&self, claim: &str) -> bool {
        self.positive.contains(claim)
    }

    /// Whether the claim is currently admissible.
    #[must_use]
    pub fn is_admissible(&self, claim: &str) -> bool {
        self.admissible.contains(claim)
    }

    /// Whether positive support survives but an unresolved challenge withholds it.
    #[must_use]
    pub fn is_withheld(&self, claim: &str) -> bool {
        self.positive.contains(claim) && !self.admissible.contains(claim)
    }
}

/// A policy version binds inference rules to a digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportPolicy {
    /// Stable policy identifier.
    pub id: String,
    /// Policy version.
    pub version: String,
    /// Inference rules of this policy version.
    pub rules: RuleSystem,
}

impl SupportPolicy {
    /// Compute a canonical policy digest. This is an identity of the declared
    /// rules, not an authentication statement.
    ///
    /// # Errors
    ///
    /// Returns an [`crate::identity::IdentityError`] if the policy cannot be
    /// serialized into canonical form.
    pub fn digest(&self) -> Result<MsId, crate::identity::IdentityError> {
        let value = serde_json::to_value(self)
            .map_err(|error| crate::identity::IdentityError::Json(error.to_string()))?;
        let bytes = canonical_bytes(&value)?;
        Ok(crate::identity::digest_bytes(
            IdentityDomain::Policy,
            &bytes,
        ))
    }
}

/// An immutable historical verdict bound to its policy identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricVerdict {
    /// Policy identifier that produced the verdict.
    pub policy_id: String,
    /// Policy version that produced the verdict.
    pub policy_version: String,
    /// Canonical digest of the policy.
    pub policy_digest: MsId,
    /// Revoked leaves at evaluation time.
    pub revoked: BTreeSet<ClaimId>,
    /// Challenged claims at evaluation time.
    pub challenged: BTreeSet<ClaimId>,
    /// Recorded support result.
    pub result: SupportResult,
    /// Digest of the recorded verdict.
    pub verdict_digest: MsId,
}

#[derive(Serialize)]
struct VerdictDigestPayload<'a> {
    policy_id: &'a str,
    policy_version: &'a str,
    policy_digest: &'a MsId,
    revoked: &'a BTreeSet<ClaimId>,
    challenged: &'a BTreeSet<ClaimId>,
    result: &'a SupportResult,
}

fn verdict_digest(
    policy_id: &str,
    policy_version: &str,
    policy_digest: &MsId,
    revoked: &BTreeSet<ClaimId>,
    challenged: &BTreeSet<ClaimId>,
    result: &SupportResult,
) -> Result<MsId, SupportError> {
    let value = serde_json::to_value(VerdictDigestPayload {
        policy_id,
        policy_version,
        policy_digest,
        revoked,
        challenged,
        result,
    })
    .map_err(|error| SupportError::HistoryMismatch(error.to_string()))?;
    let bytes = canonical_bytes(&value)
        .map_err(|error| SupportError::HistoryMismatch(error.to_string()))?;
    Ok(digest_bytes(IdentityDomain::Assessment, &bytes))
}

impl HistoricVerdict {
    /// Record a verdict under `policy` and bind it to the policy digest.
    ///
    /// The record is a bookkeeping object. It does not authenticate the policy,
    /// the evidence, or the execution that produced either.
    ///
    /// # Errors
    ///
    /// Returns [`SupportError::UnjustifiedLeaf`] when the policy rules are
    /// structurally invalid, or [`SupportError::HistoryMismatch`] when the
    /// verdict cannot be encoded canonically.
    pub fn record(
        policy: &SupportPolicy,
        revoked: &BTreeSet<ClaimId>,
        challenged: &BTreeSet<ClaimId>,
    ) -> Result<Self, SupportError> {
        policy.rules.validate()?;
        let policy_digest = policy
            .digest()
            .map_err(|error| SupportError::HistoryMismatch(error.to_string()))?;
        let result = evaluate(&policy.rules, revoked, challenged);
        let verdict_digest = verdict_digest(
            &policy.id,
            &policy.version,
            &policy_digest,
            revoked,
            challenged,
            &result,
        )?;
        Ok(Self {
            policy_id: policy.id.clone(),
            policy_version: policy.version.clone(),
            policy_digest,
            revoked: revoked.clone(),
            challenged: challenged.clone(),
            result,
            verdict_digest,
        })
    }

    /// Verify that this verdict was produced by exactly `policy` and that its
    /// recorded result and digest are internally consistent.
    ///
    /// # Errors
    ///
    /// Returns [`SupportError::PolicyMismatch`] when the policy identifier,
    /// version, or digest differs. Returns [`SupportError::HistoryMismatch`]
    /// when the replay or verdict digest does not match the recorded bytes.
    pub fn verify(&self, policy: &SupportPolicy) -> Result<(), SupportError> {
        policy.rules.validate()?;
        let expected_policy_digest = policy
            .digest()
            .map_err(|error| SupportError::HistoryMismatch(error.to_string()))?;
        if self.policy_id != policy.id
            || self.policy_version != policy.version
            || self.policy_digest != expected_policy_digest
        {
            return Err(SupportError::PolicyMismatch);
        }
        let replayed = evaluate(&policy.rules, &self.revoked, &self.challenged);
        if replayed != self.result {
            return Err(SupportError::HistoryMismatch(
                "recorded support result does not match policy replay".to_owned(),
            ));
        }
        let expected = verdict_digest(
            &self.policy_id,
            &self.policy_version,
            &self.policy_digest,
            &self.revoked,
            &self.challenged,
            &self.result,
        )?;
        if self.verdict_digest != expected {
            return Err(SupportError::HistoryMismatch(
                "recorded verdict digest does not match its contents".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Evaluate positive and admissible support.
#[must_use]
pub fn evaluate(
    system: &RuleSystem,
    revoked: &BTreeSet<ClaimId>,
    challenged: &BTreeSet<ClaimId>,
) -> SupportResult {
    let positive = fixed_point(system, revoked);
    let mut admissible_exclusions = revoked.clone();
    admissible_exclusions.extend(challenged.iter().cloned());
    let admissible = fixed_point(system, &admissible_exclusions);

    let mut states = BTreeMap::new();
    for claim in system.nodes() {
        let positive_support = positive.contains(&claim);
        let admissible_support = admissible.contains(&claim);
        let state = match (positive_support, admissible_support) {
            (_, true) => SupportState::Supported,
            (true, false) => SupportState::SupportedButChallenged,
            (false, false) if challenged.contains(&claim) => SupportState::Challenged,
            (false, false) => SupportState::Unsupported,
        };
        states.insert(claim, state);
    }
    SupportResult {
        positive,
        admissible,
        revoked: revoked.clone(),
        challenged: challenged.clone(),
        states,
    }
}

/// Worklist least-fixed-point implementation. A claim enters only through an
/// admitted empty rule or a rule whose every premise is already present.
fn fixed_point(system: &RuleSystem, excluded: &BTreeSet<ClaimId>) -> BTreeSet<ClaimId> {
    let mut supported = BTreeSet::new();
    let mut queue = VecDeque::new();

    // Reverse dependencies from premise to (conclusion, rule index).
    let mut reverse: HashMap<&ClaimId, Vec<(&ClaimId, usize)>> = HashMap::new();
    // Remaining unsatisfied premises per rule.
    let mut remaining: HashMap<(&ClaimId, usize), usize> = HashMap::new();

    for (conclusion, rules) in &system.rules {
        for (index, premises) in rules.iter().enumerate() {
            remaining.insert((conclusion, index), premises.len());
            for premise in premises {
                reverse
                    .entry(premise)
                    .or_default()
                    .push((conclusion, index));
            }
        }
    }

    for (conclusion, rules) in &system.rules {
        if excluded.contains(conclusion) {
            continue;
        }
        for (index, premises) in rules.iter().enumerate() {
            if premises.is_empty() && system.admitted_leaves.contains(conclusion) {
                remaining.insert((conclusion, index), 1);
            }
        }
    }

    // Seed with admitted leaves.
    for conclusion in &system.admitted_leaves {
        if !excluded.contains(conclusion) && supported.insert(conclusion.clone()) {
            queue.push_back(conclusion.clone());
        }
    }

    while let Some(premise) = queue.pop_front() {
        if let Some(dependents) = reverse.get(&premise) {
            for &(conclusion, index) in dependents {
                if excluded.contains(conclusion) || supported.contains(conclusion) {
                    continue;
                }
                if let Some(count) = remaining.get_mut(&(conclusion, index)) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        let conclusion = conclusion.clone();
                        if !excluded.contains(&conclusion) && supported.insert(conclusion.clone()) {
                            queue.push_back(conclusion);
                        }
                    }
                }
            }
        }
    }

    supported
}

/// Enumerate inclusion-minimal certificate node sets for `claim`.
///
/// Each certificate includes the conclusion and every intermediate claim node
/// used by a finite derivation. A cycle cannot contribute an entry point.
///
/// # Errors
///
/// Returns [`SupportError::CertificateLimitExceeded`] when the enumeration
/// exceeds `cap`.
pub fn certificates(
    system: &RuleSystem,
    claim: &str,
    excluded: &BTreeSet<ClaimId>,
    cap: usize,
) -> Result<Vec<BTreeSet<ClaimId>>, SupportError> {
    let mut memo: BTreeMap<ClaimId, Vec<BTreeSet<ClaimId>>> = BTreeMap::new();
    let mut visiting = BTreeSet::new();
    let mut value = certificates_inner(system, claim, excluded, &mut visiting, &mut memo, cap)?;
    minimize(&mut value);
    if value.len() > cap {
        return Err(SupportError::CertificateLimitExceeded {
            claim: claim.to_owned(),
            limit: cap,
        });
    }
    Ok(value)
}

fn certificates_inner(
    system: &RuleSystem,
    claim: &str,
    excluded: &BTreeSet<ClaimId>,
    visiting: &mut BTreeSet<ClaimId>,
    memo: &mut BTreeMap<ClaimId, Vec<BTreeSet<ClaimId>>>,
    cap: usize,
) -> Result<Vec<BTreeSet<ClaimId>>, SupportError> {
    if excluded.contains(claim) {
        return Ok(Vec::new());
    }
    if let Some(cached) = memo.get(claim) {
        return Ok(cached.clone());
    }
    if !visiting.insert(claim.to_owned()) {
        // A circular path gives no base case.
        return Ok(Vec::new());
    }

    let mut result: Vec<BTreeSet<ClaimId>> = Vec::new();
    // Admission is the nullary justification. It is independent of whether an
    // empty rule is also present, so the singleton certificate must be emitted
    // even when the claim has other, non-nullary rules.
    if system.admitted_leaves.contains(claim) {
        let mut set = BTreeSet::new();
        set.insert(claim.to_owned());
        result.push(set);
    }
    if let Some(rules) = system.rules.get(claim) {
        for premises in rules {
            if premises.is_empty() {
                // An unadmitted empty rule derives nothing; an admitted leaf is
                // already recorded above.
                continue;
            }

            let mut combinations: Vec<BTreeSet<ClaimId>> = vec![BTreeSet::new()];
            let mut impossible = false;
            for premise in premises {
                let sub = certificates_inner(system, premise, excluded, visiting, memo, cap)?;
                if sub.is_empty() {
                    impossible = true;
                    break;
                }
                let mut next = Vec::new();
                for base in &combinations {
                    for certificate in &sub {
                        let mut union = base.clone();
                        union.extend(certificate.iter().cloned());
                        next.push(union);
                        if next.len() > cap {
                            visiting.remove(claim);
                            return Err(SupportError::CertificateLimitExceeded {
                                claim: claim.to_owned(),
                                limit: cap,
                            });
                        }
                    }
                }
                combinations = next;
            }
            if !impossible {
                for mut combination in combinations {
                    combination.insert(claim.to_owned());
                    result.push(combination);
                }
            }
        }
    }

    visiting.remove(claim);
    minimize(&mut result);
    memo.insert(claim.to_owned(), result.clone());
    Ok(result)
}

fn minimize(sets: &mut Vec<BTreeSet<ClaimId>>) {
    sets.sort_by(|left, right| {
        left.len()
            .cmp(&right.len())
            .then_with(|| left.iter().cmp(right.iter()))
    });
    sets.dedup();
    let mut keep: Vec<BTreeSet<ClaimId>> = Vec::new();
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

/// Exact-cut criterion under fixed rules. Returns `true` when newly excluded
/// nodes intersect every previously surviving certificate.
#[must_use]
pub fn exact_cut(
    previous_certificates: &[BTreeSet<ClaimId>],
    new_exclusions: &BTreeSet<ClaimId>,
) -> bool {
    !previous_certificates
        .iter()
        .any(|certificate| certificate.is_disjoint(new_exclusions))
}

/// One reconstruction of a historical verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconstructedVerdict {
    /// Result under the new policy.
    pub current: SupportResult,
    /// Result reconstructed under the original policy.
    pub historical: SupportResult,
    /// Whether two independent reconstructions produced identical canonical bytes.
    pub byte_identical_historical: bool,
}

/// Recompute under new rules while reconstructing the old verdict under the
/// original policy bytes. A policy-only change must not be reported as
/// evidence-byte corruption.
///
/// # Errors
///
/// Returns [`SupportError::PolicyMismatch`] when the policy identifiers differ
/// or a policy digest cannot be encoded. Returns
/// [`SupportError::UnjustifiedLeaf`] when either rule system is structurally
/// invalid.
pub fn reconstruct_under_policy(
    old_policy: &SupportPolicy,
    new_policy: &SupportPolicy,
    revoked: &BTreeSet<ClaimId>,
    challenged: &BTreeSet<ClaimId>,
) -> Result<ReconstructedVerdict, SupportError> {
    if old_policy.id != new_policy.id {
        return Err(SupportError::PolicyMismatch);
    }
    old_policy.rules.validate()?;
    new_policy.rules.validate()?;
    let historical = evaluate(&old_policy.rules, revoked, challenged);
    let current = evaluate(&new_policy.rules, revoked, challenged);
    let historical_bytes = canonical_bytes(
        &serde_json::to_value(&historical)
            .map_err(|error| SupportError::HistoryMismatch(error.to_string()))?,
    )
    .map_err(|error| SupportError::HistoryMismatch(error.to_string()))?;
    let historical_again = evaluate(&old_policy.rules, revoked, challenged);
    let historical_again_bytes = canonical_bytes(
        &serde_json::to_value(&historical_again)
            .map_err(|error| SupportError::HistoryMismatch(error.to_string()))?,
    )
    .map_err(|error| SupportError::HistoryMismatch(error.to_string()))?;
    Ok(ReconstructedVerdict {
        current,
        historical,
        byte_identical_historical: historical_bytes == historical_again_bytes,
    })
}

/// Reconstruct a recorded verdict under its original policy while evaluating
/// the same exclusions under a new policy version.
///
/// The recorded verdict is verified first. A caller cannot substitute a
/// different "old" policy: the policy identifier, version, and digest must all
/// match the record. The historical replay is then compared byte-for-byte with
/// the recorded result, so a new policy cannot rewrite history.
///
/// # Errors
///
/// Returns [`SupportError::PolicyMismatch`] when `old_policy` is not the policy
/// that produced `historical` or when the policy identifiers differ. Returns
/// [`SupportError::HistoryMismatch`] when the record is internally inconsistent
/// or its canonical bytes cannot be reproduced.
pub fn reconstruct_recorded_verdict(
    historical: &HistoricVerdict,
    old_policy: &SupportPolicy,
    new_policy: &SupportPolicy,
) -> Result<ReconstructedVerdict, SupportError> {
    historical.verify(old_policy)?;
    if old_policy.id != new_policy.id {
        return Err(SupportError::PolicyMismatch);
    }
    new_policy.rules.validate()?;
    let replayed = evaluate(
        &old_policy.rules,
        &historical.revoked,
        &historical.challenged,
    );
    let current = evaluate(
        &new_policy.rules,
        &historical.revoked,
        &historical.challenged,
    );
    let replayed_bytes = canonical_bytes(
        &serde_json::to_value(&replayed)
            .map_err(|error| SupportError::HistoryMismatch(error.to_string()))?,
    )
    .map_err(|error| SupportError::HistoryMismatch(error.to_string()))?;
    let recorded_bytes = canonical_bytes(
        &serde_json::to_value(&historical.result)
            .map_err(|error| SupportError::HistoryMismatch(error.to_string()))?,
    )
    .map_err(|error| SupportError::HistoryMismatch(error.to_string()))?;
    Ok(ReconstructedVerdict {
        current,
        historical: replayed,
        byte_identical_historical: replayed_bytes == recorded_bytes,
    })
}

/// Difference between two support results plus witnesses for retained claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonInterferenceReport {
    /// Claims positively supported before but not after the change.
    pub lost: BTreeSet<ClaimId>,
    /// Claims positively supported after but not before the change.
    pub gained: BTreeSet<ClaimId>,
    /// Claims positively supported in both results.
    pub retained: BTreeSet<ClaimId>,
    /// Retained claims whose admissibility is withheld by a challenge.
    pub withheld: BTreeSet<ClaimId>,
    /// One minimal certificate, disjoint from revoked leaves, per retained claim.
    pub witnesses: BTreeMap<ClaimId, BTreeSet<ClaimId>>,
}

/// Compare two support results and produce an explicit noninterference witness
/// for every positively retained claim.
///
/// Positive support is compared because a challenge withholds admissibility but
/// does not erase positive-support history. The `withheld` set records retained
/// claims whose admissibility is blocked. Witness certificates are computed
/// under `after.revoked`, so they demonstrate that unrelated positive support
/// survives the revocation actually applied by the later evaluation.
///
/// # Errors
///
/// Returns [`SupportError::CertificateLimitExceeded`] when witness enumeration
/// exceeds `cap`, or [`SupportError::InconsistentSupport`] when a retained claim
/// has no certificate.
pub fn noninterference(
    system: &RuleSystem,
    before: &SupportResult,
    after: &SupportResult,
    cap: usize,
) -> Result<NonInterferenceReport, SupportError> {
    let lost = before
        .positive
        .difference(&after.positive)
        .cloned()
        .collect();
    let gained = after
        .positive
        .difference(&before.positive)
        .cloned()
        .collect();
    let retained: BTreeSet<ClaimId> = before
        .positive
        .intersection(&after.positive)
        .cloned()
        .collect();
    let withheld = retained
        .iter()
        .filter(|claim| !after.is_admissible(claim))
        .cloned()
        .collect();
    let mut witnesses = BTreeMap::new();
    for claim in &retained {
        let surviving = certificates(system, claim, &after.revoked, cap)?;
        let Some(witness) = surviving.into_iter().next() else {
            return Err(SupportError::InconsistentSupport(claim.clone()));
        };
        witnesses.insert(claim.clone(), witness);
    }
    Ok(NonInterferenceReport {
        lost,
        gained,
        retained,
        withheld,
        witnesses,
    })
}

/// Incremental evaluator for monotone exclusion changes.
///
/// Adding exclusions is handled by dependency propagation. Restoring an
/// exclusion triggers a full reevaluation; that is safe and keeps the
/// implementation simple enough to audit.
#[derive(Debug, Clone)]
pub struct IncrementalSupport {
    system: RuleSystem,
    revoked: BTreeSet<ClaimId>,
    challenged: BTreeSet<ClaimId>,
    result: SupportResult,
}

impl IncrementalSupport {
    /// Construct and evaluate.
    #[must_use]
    pub fn new(
        system: RuleSystem,
        revoked: BTreeSet<ClaimId>,
        challenged: BTreeSet<ClaimId>,
    ) -> Self {
        let result = evaluate(&system, &revoked, &challenged);
        Self {
            system,
            revoked,
            challenged,
            result,
        }
    }

    /// Current result.
    #[must_use]
    pub fn result(&self) -> &SupportResult {
        &self.result
    }

    /// Add revoked leaves, returning only claims whose admissibility decreased.
    pub fn revoke(&mut self, leaves: impl IntoIterator<Item = ClaimId>) -> BTreeSet<ClaimId> {
        let before = self.result.admissible.clone();
        let mut changed_input = false;
        for leaf in leaves {
            changed_input |= self.revoked.insert(leaf);
        }
        if !changed_input {
            return BTreeSet::new();
        }
        self.result = evaluate(&self.system, &self.revoked, &self.challenged);
        before
            .difference(&self.result.admissible)
            .cloned()
            .collect()
    }

    /// Add admitted challenges, returning claims withheld from admissibility.
    pub fn challenge(&mut self, claims: impl IntoIterator<Item = ClaimId>) -> BTreeSet<ClaimId> {
        let before = self.result.admissible.clone();
        let mut changed_input = false;
        for claim in claims {
            changed_input |= self.challenged.insert(claim);
        }
        if !changed_input {
            return BTreeSet::new();
        }
        self.result = evaluate(&self.system, &self.revoked, &self.challenged);
        before
            .difference(&self.result.admissible)
            .cloned()
            .collect()
    }

    /// Restore an exclusion or challenge. Full reevaluation is intentional.
    pub fn restore(&mut self, claim: &str) -> BTreeSet<ClaimId> {
        let before = self.result.admissible.clone();
        self.revoked.remove(claim);
        self.challenged.remove(claim);
        self.result = evaluate(&self.system, &self.revoked, &self.challenged);
        self.result
            .admissible
            .difference(&before)
            .cloned()
            .collect()
    }
}

/// Rule-pattern universe used by the paper's bounded conformance experiment.
///
/// The 12 patterns per node are: no derivation; the eight subsets of the three
/// node universe as a single conjunctive rule; and the three pairs of
/// alternative singleton derivations. Two nodes may share a premise.
#[must_use]
pub fn conformance_patterns(nodes: &[&str]) -> Vec<Vec<PremiseSet>> {
    let mut patterns = Vec::new();
    let n = nodes.len();
    patterns.push(Vec::new()); // no derivation
    for mask in 0u32..(1 << n) {
        let mut premises = BTreeSet::new();
        for (index, node) in nodes.iter().enumerate() {
            if mask & (1 << index) != 0 {
                premises.insert((*node).to_owned());
            }
        }
        patterns.push(vec![premises]);
    }
    for left in 0..n {
        for right in (left + 1)..n {
            patterns.push(vec![
                BTreeSet::from([nodes[left].to_owned()]),
                BTreeSet::from([nodes[right].to_owned()]),
            ]);
        }
    }
    debug_assert_eq!(patterns.len(), 12);
    patterns
}

/// Build a three-node rule system from a base-12 pattern index per node.
#[must_use]
pub fn conformance_system(indices: [usize; 3], nodes: &[&str]) -> RuleSystem {
    let patterns = conformance_patterns(nodes);
    let mut system = RuleSystem::new();
    for (node_index, node) in nodes.iter().enumerate() {
        for premises in &patterns[indices[node_index]] {
            // The experiment assumes empty-premise leaves are justified.
            if premises.is_empty() {
                system.admit_leaf(*node);
            }
            system
                .rules
                .entry((*node).to_owned())
                .or_default()
                .push(premises.clone());
        }
    }
    system
}

/// Compute the bounded conformance counts used by the crate tests.
///
/// Returns `(configurations, node_certificate_comparisons, exact_cut_cases)`
/// for this implementation's explicitly stated pattern universe. Both the
/// positive and admissible fixed points must agree with the certificate
/// characterization on every configuration.
///
/// # Panics
///
/// Panics when the built-in certificate characterization fails. That is an
/// internal invariant violation, not an input error.
#[must_use]
pub fn conformance_counts() -> (usize, usize, usize) {
    let nodes = ["a", "b", "c"];
    let patterns = conformance_patterns(&nodes);
    let mut configurations = 0usize;
    let mut node_comparisons = 0usize;
    let mut exact_cut_cases = 0usize;
    let empty = BTreeSet::new();

    for ia in 0..patterns.len() {
        for ib in 0..patterns.len() {
            for ic in 0..patterns.len() {
                let system = conformance_system([ia, ib, ic], &nodes);
                // Certificates over the unexcluded system are independent of the
                // revocation/challenge masks, so enumerate them once per system.
                let certificates_by_node: Vec<Vec<BTreeSet<ClaimId>>> = nodes
                    .iter()
                    .map(|node| {
                        certificates(&system, node, &empty, 256).unwrap_or_else(|_| Vec::new())
                    })
                    .collect();

                for revocation_mask in 0u16..8 {
                    let revoked: BTreeSet<ClaimId> = nodes
                        .iter()
                        .enumerate()
                        .filter(|(index, _)| revocation_mask & (1 << index) != 0)
                        .map(|(_, node)| (*node).to_owned())
                        .collect();
                    let positive = evaluate(&system, &revoked, &empty);

                    for challenge_mask in 0u16..8 {
                        configurations += 1;
                        let challenged: BTreeSet<ClaimId> = nodes
                            .iter()
                            .enumerate()
                            .filter(|(index, _)| challenge_mask & (1 << index) != 0)
                            .map(|(_, node)| (*node).to_owned())
                            .collect();
                        let admissible = evaluate(&system, &revoked, &challenged);

                        for (node_index, node) in nodes.iter().enumerate() {
                            node_comparisons += 1;
                            let by_certificate = certificates_by_node[node_index]
                                .iter()
                                .any(|set| set.is_disjoint(&revoked));
                            let admissible_certificate =
                                certificates_by_node[node_index].iter().any(|set| {
                                    set.is_disjoint(&revoked) && set.is_disjoint(&challenged)
                                });
                            assert_eq!(
                                positive.is_supported(node),
                                by_certificate,
                                "certificate characterization mismatch for {node}"
                            );
                            assert_eq!(
                                admissible.is_admissible(node),
                                admissible_certificate,
                                "challenge characterization mismatch for {node}"
                            );
                            let withheld = positive.is_supported(node)
                                && !admissible.is_admissible(node)
                                && challenged.contains(*node);
                            if withheld {
                                exact_cut_cases += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    (configurations, node_comparisons, exact_cut_cases)
}

/// A compact explanation of support or refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Explanation {
    /// Claim being explained.
    pub claim: String,
    /// Whether positive support exists.
    pub supported: bool,
    /// Whether support is admissible after challenges.
    pub admissible: bool,
    /// Inclusion-minimal certificates that survive revocations.
    pub certificates: Vec<Vec<ClaimId>>,
    /// Human-readable reason for the disposition.
    pub reason: String,
}

/// Explain one claim under fixed rules.
#[must_use]
pub fn explain(
    system: &RuleSystem,
    claim: &str,
    revoked: &BTreeSet<ClaimId>,
    challenged: &BTreeSet<ClaimId>,
    cap: usize,
) -> Explanation {
    let result = evaluate(system, revoked, challenged);
    let certificates: Vec<Vec<ClaimId>> = certificates(system, claim, revoked, cap)
        .map(|sets| {
            sets.into_iter()
                .map(|set| set.into_iter().collect())
                .collect()
        })
        .unwrap_or_default();
    let reason = if !result.is_supported(claim) {
        "no finite derivation avoids revoked leaves".to_owned()
    } else if result.is_withheld(claim) {
        "positive support exists but an admitted challenge withholds admissibility".to_owned()
    } else {
        format!(
            "{} minimal certificate(s) survive revoked leaves",
            certificates.len()
        )
    };
    Explanation {
        claim: claim.to_owned(),
        supported: result.is_supported(claim),
        admissible: result.is_admissible(claim),
        certificates,
        reason,
    }
}

/// Check whether a reachable derivation contains a cycle made entirely of
/// claims that the least fixed point does not support. Such a cycle has no
/// justified entry and therefore derives nothing.
#[must_use]
pub fn has_unsupported_cycle(system: &RuleSystem, roots: &BTreeSet<ClaimId>) -> bool {
    let supported = fixed_point(system, &BTreeSet::new());
    let reachable = reachable_nodes(system, roots);
    let unsupported: HashSet<&str> = reachable
        .iter()
        .filter(|node| !supported.contains(*node))
        .map(String::as_str)
        .collect();
    if unsupported.is_empty() {
        return false;
    }

    let mut indegree: HashMap<&str, usize> = unsupported.iter().map(|node| (*node, 0)).collect();
    let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();
    for conclusion in &unsupported {
        if let Some(rules) = system.rules.get(*conclusion) {
            for premises in rules {
                for premise in premises {
                    if unsupported.contains(premise.as_str()) {
                        adjacency.entry(conclusion).or_default().push(premise);
                        *indegree.entry(premise.as_str()).or_insert(0) += 1;
                    }
                }
            }
        }
    }

    let mut queue: VecDeque<&str> = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(node, _)| *node)
        .collect();
    let mut removed = 0usize;
    while let Some(node) = queue.pop_front() {
        removed += 1;
        if let Some(premises) = adjacency.get(node) {
            for premise in premises {
                if let Some(degree) = indegree.get_mut(premise) {
                    *degree -= 1;
                    if *degree == 0 {
                        queue.push_back(premise);
                    }
                }
            }
        }
    }
    removed != unsupported.len()
}

fn reachable_nodes(system: &RuleSystem, roots: &BTreeSet<ClaimId>) -> BTreeSet<ClaimId> {
    let mut reachable = BTreeSet::new();
    let mut stack: Vec<&str> = roots.iter().map(String::as_str).collect();
    while let Some(node) = stack.pop() {
        if !reachable.insert(node.to_owned()) {
            continue;
        }
        if let Some(rules) = system.rules.get(node) {
            for premises in rules {
                for premise in premises {
                    if !reachable.contains(premise) {
                        stack.push(premise);
                    }
                }
            }
        }
    }
    reachable
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<ClaimId> {
        items.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn self_cycle_derives_nothing() {
        let mut system = RuleSystem::new();
        system.add_rule("q", ["q".to_owned()]).unwrap();
        let result = evaluate(&system, &BTreeSet::new(), &BTreeSet::new());
        assert!(!result.is_supported("q"));
    }

    #[test]
    fn alternative_derivation_survives_one_revocation() {
        let mut system = RuleSystem::new();
        system.admit_leaf("a");
        system.admit_leaf("b");
        system.add_rule("q", ["a".to_owned()]).unwrap();
        system.add_rule("q", ["b".to_owned()]).unwrap();
        let certs = certificates(&system, "q", &BTreeSet::new(), 16).unwrap();
        assert_eq!(certs.len(), 2);
        assert!(evaluate(&system, &set(&["a"]), &BTreeSet::new()).is_supported("q"));
        assert!(!evaluate(&system, &set(&["a", "b"]), &BTreeSet::new()).is_supported("q"));
        assert!(!exact_cut(&certs, &set(&["a"])));
        assert!(exact_cut(&certs, &set(&["a", "b"])));
    }

    #[test]
    fn challenge_withholds_without_erasing_positive_support() {
        let mut system = RuleSystem::new();
        system.admit_leaf("a");
        system.add_rule("q", ["a".to_owned()]).unwrap();
        let result = evaluate(&system, &BTreeSet::new(), &set(&["q"]));
        assert!(result.is_supported("q"));
        assert!(!result.is_admissible("q"));
        assert_eq!(
            result.states.get("q"),
            Some(&SupportState::SupportedButChallenged)
        );
    }

    #[test]
    fn hidden_intermediate_node_is_part_of_certificate() {
        let mut system = RuleSystem::new();
        system.admit_leaf("a");
        system.admit_leaf("b");
        system
            .add_rule("u", ["a".to_owned(), "b".to_owned()])
            .unwrap();
        system.add_rule("q", ["u".to_owned()]).unwrap();
        let cert = certificates(&system, "q", &BTreeSet::new(), 16).unwrap();
        assert_eq!(cert, vec![set(&["a", "b", "q", "u"])]);
        let rewritten = evaluate(&system, &BTreeSet::new(), &set(&["u"]));
        assert!(!rewritten.is_admissible("q"));
    }

    #[test]
    fn unsupported_cycles_are_detected_but_grounded_cycles_are_not() {
        let mut ungrounded = RuleSystem::new();
        ungrounded.add_rule("q", ["p".to_owned()]).unwrap();
        ungrounded.add_rule("p", ["q".to_owned()]).unwrap();
        assert!(has_unsupported_cycle(&ungrounded, &set(&["q"])));

        let mut grounded = RuleSystem::new();
        grounded.admit_leaf("a");
        grounded.add_rule("q", ["p".to_owned()]).unwrap();
        grounded.add_rule("p", ["q".to_owned()]).unwrap();
        grounded.add_rule("p", ["a".to_owned()]).unwrap();
        assert!(!has_unsupported_cycle(&grounded, &set(&["q"])));

        let mut detached = RuleSystem::new();
        detached.add_rule("q", ["p".to_owned()]).unwrap();
        detached.add_rule("p", ["q".to_owned()]).unwrap();
        detached.admit_leaf("root");
        assert!(!has_unsupported_cycle(&detached, &set(&["root"])));
    }

    #[test]
    fn policy_change_is_not_a_leaf_revocation() {
        let mut old = RuleSystem::new();
        old.admit_leaf("e");
        old.add_rule("q", ["e".to_owned()]).unwrap();
        let old_policy = SupportPolicy {
            id: "p".to_owned(),
            version: "1".to_owned(),
            rules: old,
        };
        let mut new = RuleSystem::new();
        new.admit_leaf("e");
        let new_policy = SupportPolicy {
            id: "p".to_owned(),
            version: "2".to_owned(),
            rules: new,
        };
        let reconstructed =
            reconstruct_under_policy(&old_policy, &new_policy, &BTreeSet::new(), &BTreeSet::new())
                .unwrap();
        assert!(reconstructed.historical.is_supported("q"));
        assert!(!reconstructed.current.is_supported("q"));
        assert!(reconstructed.byte_identical_historical);
    }

    #[test]
    fn bounded_conformance_counts_are_reproducible() {
        let (configurations, comparisons, cuts) = conformance_counts();
        assert_eq!(configurations, 110_592);
        assert_eq!(comparisons, 331_776);
        // This count is for this implementation's explicit withholding fixture,
        // not the paper's independently authored 17,712 exact-cut corpus.
        assert!(cuts > 0);
    }
}
