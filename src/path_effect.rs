//! Conservative path effects over explicit finite aliases and events.
//!
//! This module models a caller-supplied finite trace. It does **not** extract
//! aliases from source, resolve MIR, execute native code, or observe a real C
//! callback. Objects, aliases, reference intervals, callbacks, providers, and
//! events are explicit input coordinates. The analysis propagates only the
//! distinctions encoded by that input.
//!
//! # Qualification, not a boolean
//!
//! Every conclusion is one of four typed statuses:
//!
//! * [`QualifiedStatus::ObservedConflict`] — a definite overlap, use-after-free,
//!   double free, or reference-interval violation in the declared trace;
//! * [`QualifiedStatus::Omission`] — a declared event was not observed and the
//!   model states that its absence is legal in this finite trace;
//! * [`QualifiedStatus::NotFalsified`] — the event or overlap could still occur
//!   through an unknown alias, unknown footprint, callback, or provider;
//! * [`QualifiedStatus::CompatibleWithinFiniteFootprint`] — every observed
//!   access is disjoint or legally ordered within the declared finite
//!   footprint, with no unresolved uncertainty recorded.
//!
//! These are not points on a confidence ladder. In particular,
//! `NotFalsified` is not a weak `Compatible`, and `CompatibleWithinFiniteFootprint`
//! is not whole-program or universal closure.
//!
//! # Claim ceiling
//!
//! A successful analysis establishes only that the declared finite model was
//! internally qualified under the rules below. It does not establish a native
//! Rust aliasing property, a C callback contract, a compiler-resolved
//! footprint, or memory safety. Foreign and provider behavior is preserved as
//! unknown, never promoted to safe or unsafe.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::source::{FindingKind, SourceInventory, SOURCE_INVENTORY_SCHEMA};

/// Schema identifier for an explicit path-effects input.
pub const PATH_EFFECT_INPUT_SCHEMA: &str = "frf-memorysafety.path-effects-input.v1";
/// Schema identifier for a path-effects report.
pub const PATH_EFFECT_REPORT_SCHEMA: &str = "frf-memorysafety.path-effects-report.v1";
/// Protocol specification identifier.
pub const PATH_EFFECT_SPEC: &str = "frf-memorysafety-spec-v1";
/// Claim ceiling embedded in every report.
pub const PATH_EFFECT_CLAIM_CEILING: &str = "Finite explicit-input path-effect model only. Not a source/MIR alias analysis, native callback observation, whole-program closure, or memory-safety result. Unknown aliases, unknown footprints, unobserved callbacks, and foreign/provider dispatch remain unknown; compatible means compatible within the declared finite footprint only.";

/// Maximum number of explicit events analyzed in one trace.
pub const MAX_PATH_EVENTS: usize = 1_024;
/// Maximum number of pairwise event checks.
pub const MAX_PAIR_CHECKS: usize = 1_048_576;
/// Maximum number of qualified outcome records.
pub const MAX_OUTCOMES: usize = 65_536;

/// A byte range within one object or shared mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByteRange {
    /// Offset from the start of the object or mapping.
    pub offset: u64,
    /// Non-zero length in bytes.
    pub length: u64,
}

impl ByteRange {
    /// Whether two explicit ranges share at least one byte.
    #[must_use]
    pub const fn overlaps(self, other: Self) -> bool {
        let left_end = self.offset as u128 + self.length as u128;
        let right_end = other.offset as u128 + other.length as u128;
        (self.offset as u128) < right_end && (other.offset as u128) < left_end
    }
}

/// One declared allocation or storage object.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectDecl {
    /// Stable object identifier.
    pub id: String,
    /// Whether the object contains `UnsafeCell`-style interior mutability.
    ///
    /// This model uses the flag only to suppress a read/write pair on the same
    /// object. It does not suppress write/write, use-after-free, or double-free
    /// conflicts.
    #[serde(default)]
    pub interior_mutable: bool,
}

/// How an alias relates to storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasKind {
    /// The alias denotes the exact object.
    ExactObject,
    /// The alias is a derived pointer or subrange of the object.
    Descendant,
    /// The alias is obtained through a shared mapping whose storage identity is
    /// not resolved by this model.
    SharedMapping,
    /// The alias has top/unknown identity.
    TopUnknown,
}

impl AliasKind {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactObject => "exact_object",
            Self::Descendant => "descendant",
            Self::SharedMapping => "shared_mapping",
            Self::TopUnknown => "top_unknown",
        }
    }
}

/// One declared alias.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliasDecl {
    /// Stable alias identifier.
    pub id: String,
    /// Alias relationship.
    pub kind: AliasKind,
    /// Object identifier for exact and descendant aliases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// Mapping identifier for a shared-mapping alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping: Option<String>,
    /// Explicit subrange, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<ByteRange>,
}

/// Footprint extent attached to one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FootprintKind {
    /// The entire declared object.
    Exact,
    /// A descendant or subrange.
    Descendant,
    /// Unknown extent.
    Top,
}

impl FootprintKind {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Descendant => "descendant",
            Self::Top => "top",
        }
    }
}

/// Footprint used by an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Footprint {
    /// Footprint kind.
    pub kind: FootprintKind,
    /// Explicit range for a descendant footprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<ByteRange>,
}

/// Event kind in the explicit program-point order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Reference or pointer creation.
    Creation,
    /// Reference reborrow.
    Reborrow,
    /// Reference or pointer escape to foreign code.
    Escape,
    /// C callback invocation.
    Callback,
    /// Deallocation.
    Free,
    /// Ordinary use.
    Use,
}

impl EventKind {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Creation => "creation",
            Self::Reborrow => "reborrow",
            Self::Escape => "escape",
            Self::Callback => "callback",
            Self::Free => "free",
            Self::Use => "use",
        }
    }
}

/// Access mode of an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    /// Read access.
    Read,
    /// Write access.
    Write,
    /// No memory access (for example creation or free).
    #[serde(rename = "none")]
    NoAccess,
}

impl AccessMode {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::NoAccess => "none",
        }
    }
}

/// One event in the explicit program-point order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathEvent {
    /// Program point. Points are unique and totally ordered.
    pub point: u64,
    /// Event kind.
    pub kind: EventKind,
    /// Alias used by this event.
    pub alias: String,
    /// Access mode.
    pub access: AccessMode,
    /// Declared footprint.
    pub footprint: Footprint,
    /// Reference interval governing this event, when one is declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    /// Callback identifier for a callback event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback: Option<String>,
}

/// Explicit reference interval over program points.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceIntervalDecl {
    /// Stable interval identifier.
    pub id: String,
    /// Alias whose reference is live on this interval.
    pub alias: String,
    /// Inclusive start point.
    pub start: u64,
    /// Exclusive end point. Omitted means the interval is open to the end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<u64>,
}

/// Declared C callback behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackBehavior {
    /// Callback runs synchronously and retains no pointer after return.
    SynchronousLegal,
    /// Callback retains or escapes a pointer for later foreign use.
    RetainedPointer,
    /// Callback may run after the registering call returns.
    Deferred,
    /// Callback is declared to run after the target storage is freed.
    CallbackAfterFree,
    /// Callback dispatch is owned by a foreign provider and remains unknown.
    ForeignProviderDispatch,
}

impl CallbackBehavior {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SynchronousLegal => "synchronous_legal",
            Self::RetainedPointer => "retained_pointer",
            Self::Deferred => "deferred",
            Self::CallbackAfterFree => "callback_after_free",
            Self::ForeignProviderDispatch => "foreign_provider_dispatch",
        }
    }
}

/// One declared callback.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackDecl {
    /// Stable callback identifier.
    pub id: String,
    /// Declared behavior.
    pub behavior: CallbackBehavior,
    /// Whether the finite trace states that absence is legal.
    ///
    /// An unobserved callback with this flag is an [`QualifiedStatus::Omission`].
    /// Without the flag it is [`QualifiedStatus::NotFalsified`].
    #[serde(default)]
    pub legally_absent: bool,
}

/// Declared foreign/provider dynamic behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderBehavior {
    /// Foreign behavior is unresolved.
    ForeignUnknown,
    /// Dispatch is dynamic and unresolved.
    DynamicDispatch,
}

impl ProviderBehavior {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ForeignUnknown => "foreign_unknown",
            Self::DynamicDispatch => "dynamic_dispatch",
        }
    }
}

/// One declared provider whose behavior is preserved as unknown.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDecl {
    /// Stable provider identifier.
    pub id: String,
    /// Unknown behavior kind.
    pub behavior: ProviderBehavior,
}

/// Explicit finite path-effects input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathEffectsInput {
    /// Input schema.
    pub schema: String,
    /// Specification identifier.
    pub spec: String,
    /// Declared objects.
    #[serde(default)]
    pub objects: Vec<ObjectDecl>,
    /// Declared aliases.
    #[serde(default)]
    pub aliases: Vec<AliasDecl>,
    /// Declared reference intervals.
    #[serde(default)]
    pub intervals: Vec<ReferenceIntervalDecl>,
    /// Declared events, ordered by program point during analysis.
    #[serde(default)]
    pub events: Vec<PathEvent>,
    /// Declared callbacks.
    #[serde(default)]
    pub callbacks: Vec<CallbackDecl>,
    /// Declared foreign/provider behavior.
    #[serde(default)]
    pub providers: Vec<ProviderDecl>,
}

impl PathEffectsInput {
    /// Construct an empty explicit input with the required schema identifiers.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema: PATH_EFFECT_INPUT_SCHEMA.to_owned(),
            spec: PATH_EFFECT_SPEC.to_owned(),
            objects: Vec::new(),
            aliases: Vec::new(),
            intervals: Vec::new(),
            events: Vec::new(),
            callbacks: Vec::new(),
            providers: Vec::new(),
        }
    }
}

/// Typed qualification status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualifiedStatus {
    /// A definite conflict or violation was observed in the declared trace.
    ObservedConflict,
    /// The event was not observed and the model states that absence is legal.
    Omission,
    /// The outcome could still occur through an explicit unknown.
    NotFalsified,
    /// Every observed access was compatible within the finite footprint.
    CompatibleWithinFiniteFootprint,
}

impl QualifiedStatus {
    /// Stable snake-case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObservedConflict => "observed_conflict",
            Self::Omission => "omission",
            Self::NotFalsified => "not_falsified",
            Self::CompatibleWithinFiniteFootprint => "compatible_within_finite_footprint",
        }
    }
}

/// Stable reference to one event in a qualified outcome.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRef {
    /// Program point.
    pub point: u64,
    /// Alias used.
    pub alias: String,
    /// Event kind.
    pub kind: EventKind,
}

/// One qualified outcome with its evidence and explicit unknowns.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedOutcome {
    /// Typed status.
    pub status: QualifiedStatus,
    /// Stable rule code.
    pub code: String,
    /// Subject of the outcome.
    pub subject: String,
    /// Human-readable justification.
    pub detail: String,
    /// Events that justify the outcome.
    pub evidence: Vec<EventRef>,
    /// Unknown reasons that prevent a stronger conclusion.
    pub unknowns: Vec<String>,
}

/// One explicit unknown retained by the analysis.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathUnknown {
    /// Stable code.
    pub code: String,
    /// Subject that carries the unknown.
    pub subject: String,
    /// Explanation.
    pub detail: String,
}

/// Deterministic path-effects report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathReport {
    /// Report schema.
    pub schema: String,
    /// Specification identifier.
    pub spec: String,
    /// Schema of the consumed input.
    pub input_schema: String,
    /// SHA-256 of the canonical input bytes, lowercase hexadecimal.
    pub input_sha256: String,
    /// Claim ceiling embedded in the report.
    pub claim_ceiling: String,
    /// Qualified outcomes, sorted deterministically.
    pub outcomes: Vec<QualifiedOutcome>,
    /// Explicit unknowns, sorted deterministically.
    pub unknowns: Vec<PathUnknown>,
    /// Count per qualification status.
    pub summary: BTreeMap<String, usize>,
    /// Report label derived from the outcomes. Per-outcome records retain all
    /// distinctions; this label is not a soundness verdict.
    pub overall: QualifiedStatus,
}

impl PathReport {
    /// Encode this report as strict `ms-canonical-json-v1` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::Canonical`] if the report cannot be represented as
    /// a JSON value. Returns [`PathError::LimitExceeded`] if the canonical
    /// encoding exceeds the protocol limit.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PathError> {
        let value = serde_json::to_value(self).map_err(|error| PathError::Canonical {
            message: error.to_string(),
        })?;
        match crate::identity::canonical_bytes(&value) {
            Ok(bytes) => Ok(bytes),
            Err(crate::identity::IdentityError::TooLarge { limit, .. }) => {
                Err(PathError::LimitExceeded {
                    resource: "canonical_bytes",
                    limit,
                })
            }
            Err(error) => Err(PathError::Canonical {
                message: error.to_string(),
            }),
        }
    }
}

/// Category used by the CLI to choose a `SPEC.md` §14 exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathErrorCategory {
    /// Invalid input or usage.
    Usage,
    /// Evidence/input integrity failure.
    Integrity,
    /// Internal encoding or harness failure.
    Harness,
}

/// Errors produced while validating or analyzing explicit inputs.
#[derive(Debug, thiserror::Error)]
pub enum PathError {
    /// The explicit input is structurally invalid.
    #[error("invalid path-effects input: {message}")]
    Invalid {
        /// Diagnostic.
        message: String,
    },
    /// A hard analysis limit was exceeded.
    #[error("path-effects limit exceeded: {resource} (limit {limit})")]
    LimitExceeded {
        /// Resource name.
        resource: &'static str,
        /// Configured limit.
        limit: usize,
    },
    /// The canonical encoder rejected the report.
    #[error("cannot encode path-effects report: {message}")]
    Canonical {
        /// Encoder diagnostic.
        message: String,
    },
}

impl PathError {
    /// Category used for exit-status selection.
    #[must_use]
    pub const fn category(&self) -> PathErrorCategory {
        match self {
            Self::Invalid { .. } | Self::LimitExceeded { .. } => PathErrorCategory::Integrity,
            Self::Canonical { .. } => PathErrorCategory::Harness,
        }
    }
}

fn invalid(message: impl Into<String>) -> PathError {
    PathError::Invalid {
        message: message.into(),
    }
}

fn check_range(range: ByteRange, context: &str) -> Result<(), PathError> {
    if range.length == 0 {
        return Err(invalid(format!("{context}: range length must be non-zero")));
    }
    if range.offset.checked_add(range.length).is_none() {
        return Err(invalid(format!("{context}: range overflows u64")));
    }
    Ok(())
}

fn check_footprint(footprint: Footprint, context: &str) -> Result<(), PathError> {
    match footprint.kind {
        FootprintKind::Exact | FootprintKind::Top => {
            if footprint.range.is_some() {
                return Err(invalid(format!(
                    "{context}: exact and top footprints must not carry a range"
                )));
            }
        }
        FootprintKind::Descendant => {
            if let Some(range) = footprint.range {
                check_range(range, context)?;
            }
        }
    }
    Ok(())
}

/// Validate the structural integrity of an explicit input.
///
/// This function does not evaluate the trace. It rejects duplicate identifiers,
/// dangling references, empty ranges, range overflow, duplicate program points,
/// and inconsistent schema fields.
///
/// # Errors
///
/// Returns [`PathError::Invalid`] for structural violations and
/// [`PathError::LimitExceeded`] when the event cap is exceeded.
#[allow(clippy::too_many_lines)]
pub fn validate_input(input: &PathEffectsInput) -> Result<(), PathError> {
    if input.schema != PATH_EFFECT_INPUT_SCHEMA {
        return Err(invalid(format!(
            "schema must be {PATH_EFFECT_INPUT_SCHEMA}, got {}",
            input.schema
        )));
    }
    if input.spec != PATH_EFFECT_SPEC {
        return Err(invalid(format!(
            "spec must be {PATH_EFFECT_SPEC}, got {}",
            input.spec
        )));
    }
    if input.events.len() > MAX_PATH_EVENTS {
        return Err(PathError::LimitExceeded {
            resource: "events",
            limit: MAX_PATH_EVENTS,
        });
    }

    let mut object_ids = BTreeSet::new();
    for object in &input.objects {
        if object.id.is_empty() {
            return Err(invalid("object id must not be empty"));
        }
        if !object_ids.insert(object.id.as_str()) {
            return Err(invalid(format!("duplicate object id: {}", object.id)));
        }
    }

    let mut alias_ids = BTreeSet::new();
    for alias in &input.aliases {
        if alias.id.is_empty() {
            return Err(invalid("alias id must not be empty"));
        }
        if !alias_ids.insert(alias.id.as_str()) {
            return Err(invalid(format!("duplicate alias id: {}", alias.id)));
        }
        if let Some(range) = alias.range {
            check_range(range, &format!("alias {}", alias.id))?;
        }
        match alias.kind {
            AliasKind::ExactObject | AliasKind::Descendant => {
                let Some(object) = alias.object.as_deref() else {
                    return Err(invalid(format!(
                        "alias {} of kind {} requires an object",
                        alias.id,
                        alias.kind.as_str()
                    )));
                };
                if !object_ids.contains(object) {
                    return Err(invalid(format!(
                        "alias {} references unknown object {object}",
                        alias.id
                    )));
                }
                if alias.mapping.is_some() {
                    return Err(invalid(format!(
                        "alias {} of kind {} must not declare a mapping",
                        alias.id,
                        alias.kind.as_str()
                    )));
                }
            }
            AliasKind::SharedMapping => {
                let Some(mapping) = alias.mapping.as_deref() else {
                    return Err(invalid(format!(
                        "shared-mapping alias {} requires a mapping id",
                        alias.id
                    )));
                };
                if mapping.is_empty() {
                    return Err(invalid(format!(
                        "shared-mapping alias {} has an empty mapping id",
                        alias.id
                    )));
                }
                if let Some(object) = alias.object.as_deref() {
                    if !object_ids.contains(object) {
                        return Err(invalid(format!(
                            "alias {} references unknown object {object}",
                            alias.id
                        )));
                    }
                }
            }
            AliasKind::TopUnknown => {
                if alias.object.is_some() || alias.mapping.is_some() || alias.range.is_some() {
                    return Err(invalid(format!(
                        "top/unknown alias {} must not declare object, mapping, or range",
                        alias.id
                    )));
                }
            }
        }
    }

    let mut interval_ids = BTreeSet::new();
    for interval in &input.intervals {
        if interval.id.is_empty() {
            return Err(invalid("reference interval id must not be empty"));
        }
        if !interval_ids.insert(interval.id.as_str()) {
            return Err(invalid(format!(
                "duplicate reference interval id: {}",
                interval.id
            )));
        }
        if !alias_ids.contains(interval.alias.as_str()) {
            return Err(invalid(format!(
                "reference interval {} references unknown alias {}",
                interval.id, interval.alias
            )));
        }
        if interval.end.is_some_and(|end| end < interval.start) {
            return Err(invalid(format!(
                "reference interval {} ends before it starts",
                interval.id
            )));
        }
    }

    let mut callback_ids = BTreeSet::new();
    for callback in &input.callbacks {
        if callback.id.is_empty() {
            return Err(invalid("callback id must not be empty"));
        }
        if !callback_ids.insert(callback.id.as_str()) {
            return Err(invalid(format!("duplicate callback id: {}", callback.id)));
        }
    }

    let mut provider_ids = BTreeSet::new();
    for provider in &input.providers {
        if provider.id.is_empty() {
            return Err(invalid("provider id must not be empty"));
        }
        if !provider_ids.insert(provider.id.as_str()) {
            return Err(invalid(format!("duplicate provider id: {}", provider.id)));
        }
    }

    let mut points = BTreeSet::new();
    for event in &input.events {
        if !points.insert(event.point) {
            return Err(invalid(format!("duplicate program point: {}", event.point)));
        }
        if !alias_ids.contains(event.alias.as_str()) {
            return Err(invalid(format!(
                "event at point {} references unknown alias {}",
                event.point, event.alias
            )));
        }
        check_footprint(event.footprint, &format!("event at point {}", event.point))?;
        if let Some(interval) = event.interval.as_deref() {
            let Some(declaration) = input
                .intervals
                .iter()
                .find(|candidate| candidate.id == interval)
            else {
                return Err(invalid(format!(
                    "event at point {} references unknown interval {interval}",
                    event.point
                )));
            };
            if declaration.alias != event.alias {
                return Err(invalid(format!(
                    "event at point {} uses interval {interval} declared for alias {}",
                    event.point, declaration.alias
                )));
            }
        }
        match event.kind {
            EventKind::Callback => {
                let Some(callback) = event.callback.as_deref() else {
                    return Err(invalid(format!(
                        "callback event at point {} requires a callback id",
                        event.point
                    )));
                };
                if !callback_ids.contains(callback) {
                    return Err(invalid(format!(
                        "callback event at point {} references unknown callback {callback}",
                        event.point
                    )));
                }
            }
            _ => {
                if event.callback.is_some() {
                    return Err(invalid(format!(
                        "non-callback event at point {} must not carry a callback id",
                        event.point
                    )));
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Storage<'a> {
    Object(&'a str),
    Mapping(&'a str),
    Top,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StorageRelation {
    Same,
    Possible,
    Disjoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Extent {
    Exact,
    Range(ByteRange),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Overlap {
    Definite,
    Possible,
    Disjoint,
}

fn storage_of(alias: &AliasDecl) -> Storage<'_> {
    match alias.kind {
        AliasKind::ExactObject | AliasKind::Descendant => {
            Storage::Object(alias.object.as_deref().unwrap_or(""))
        }
        AliasKind::SharedMapping => {
            if let Some(object) = alias.object.as_deref() {
                Storage::Object(object)
            } else {
                Storage::Mapping(alias.mapping.as_deref().unwrap_or(""))
            }
        }
        AliasKind::TopUnknown => Storage::Top,
    }
}

fn storage_relation(left: Storage<'_>, right: Storage<'_>) -> StorageRelation {
    match (left, right) {
        (Storage::Object(a), Storage::Object(b)) => {
            if a == b {
                StorageRelation::Same
            } else {
                StorageRelation::Disjoint
            }
        }
        (Storage::Mapping(a), Storage::Mapping(b)) => {
            if a == b {
                StorageRelation::Same
            } else {
                // Mapping identity alone does not prove that two mappings are
                // disjoint views of physical storage.
                StorageRelation::Possible
            }
        }
        (Storage::Object(_), Storage::Mapping(_))
        | (Storage::Mapping(_), Storage::Object(_))
        | (Storage::Top, _)
        | (_, Storage::Top) => StorageRelation::Possible,
    }
}

fn extent_of(event: &PathEvent, alias: &AliasDecl) -> Extent {
    match event.footprint.kind {
        FootprintKind::Exact => Extent::Exact,
        FootprintKind::Top => Extent::Unknown,
        FootprintKind::Descendant => event
            .footprint
            .range
            .or(alias.range)
            .map_or(Extent::Unknown, Extent::Range),
    }
}

fn overlap_of(relation: StorageRelation, left: Extent, right: Extent) -> Overlap {
    if relation == StorageRelation::Disjoint {
        return Overlap::Disjoint;
    }
    if relation == StorageRelation::Possible {
        return Overlap::Possible;
    }
    match (left, right) {
        (Extent::Exact | Extent::Range(_), Extent::Exact | Extent::Range(_)) => {
            match (left, right) {
                (Extent::Range(a), Extent::Range(b)) if !a.overlaps(b) => Overlap::Disjoint,
                _ => Overlap::Definite,
            }
        }
        _ => Overlap::Possible,
    }
}

fn event_ref(event: &PathEvent) -> EventRef {
    EventRef {
        point: event.point,
        alias: event.alias.clone(),
        kind: event.kind,
    }
}

fn interval_window(interval: &ReferenceIntervalDecl) -> (u64, u64) {
    (interval.start, interval.end.unwrap_or(u64::MAX))
}

fn windows_overlap(left: (u64, u64), right: (u64, u64)) -> bool {
    left.0 < right.1 && right.0 < left.1
}

fn add_outcome(
    outcomes: &mut BTreeSet<QualifiedOutcome>,
    status: QualifiedStatus,
    code: &str,
    subject: impl Into<String>,
    detail: impl Into<String>,
    evidence: Vec<EventRef>,
    unknowns: impl IntoIterator<Item = &'static str>,
) {
    outcomes.insert(QualifiedOutcome {
        status,
        code: code.to_owned(),
        subject: subject.into(),
        detail: detail.into(),
        evidence,
        unknowns: unknowns.into_iter().map(str::to_owned).collect(),
    });
}

fn add_unknown(
    unknowns: &mut BTreeSet<PathUnknown>,
    code: &str,
    subject: impl Into<String>,
    detail: impl Into<String>,
) {
    unknowns.insert(PathUnknown {
        code: code.to_owned(),
        subject: subject.into(),
        detail: detail.into(),
    });
}

#[allow(clippy::too_many_lines)]
fn analyze_with_digest(
    input: &PathEffectsInput,
    input_schema: &str,
    input_sha256: &str,
) -> Result<PathReport, PathError> {
    validate_input(input)?;

    let objects: BTreeMap<&str, &ObjectDecl> = input
        .objects
        .iter()
        .map(|object| (object.id.as_str(), object))
        .collect();
    let aliases: BTreeMap<&str, &AliasDecl> = input
        .aliases
        .iter()
        .map(|alias| (alias.id.as_str(), alias))
        .collect();
    let intervals: BTreeMap<&str, &ReferenceIntervalDecl> = input
        .intervals
        .iter()
        .map(|interval| (interval.id.as_str(), interval))
        .collect();
    let mut events: Vec<&PathEvent> = input.events.iter().collect();
    events.sort_by_key(|event| event.point);

    let mut outcomes = BTreeSet::new();
    let mut unknowns = BTreeSet::new();

    // Declared alias uncertainty is retained even when the alias is unused.
    for alias in &input.aliases {
        match alias.kind {
            AliasKind::TopUnknown => {
                add_unknown(
                    &mut unknowns,
                    "top_unknown_alias",
                    &alias.id,
                    "top/unknown alias can overlap any storage",
                );
                add_outcome(
                    &mut outcomes,
                    QualifiedStatus::NotFalsified,
                    "top_unknown_alias",
                    &alias.id,
                    "alias has no resolved object identity; an overlapping access could occur",
                    Vec::new(),
                    ["top_unknown_alias"],
                );
            }
            AliasKind::SharedMapping => {
                add_unknown(
                    &mut unknowns,
                    "shared_mapping_alias",
                    &alias.id,
                    "shared-mapping storage identity is not resolved by this model",
                );
                add_outcome(
                    &mut outcomes,
                    QualifiedStatus::NotFalsified,
                    "shared_mapping_alias",
                    &alias.id,
                    "shared mapping may alias another view; disjointness is not established",
                    Vec::new(),
                    ["shared_mapping_alias"],
                );
            }
            AliasKind::Descendant if alias.range.is_none() => {
                add_unknown(
                    &mut unknowns,
                    "descendant_extent_unknown",
                    &alias.id,
                    "descendant alias has no explicit subrange",
                );
                add_outcome(
                    &mut outcomes,
                    QualifiedStatus::NotFalsified,
                    "descendant_extent_unknown",
                    &alias.id,
                    "descendant footprint extent is unknown; overlap remains possible",
                    Vec::new(),
                    ["descendant_extent_unknown"],
                );
            }
            AliasKind::ExactObject | AliasKind::Descendant => {}
        }
    }

    // Foreign and provider behavior is always preserved as unknown.
    for provider in &input.providers {
        let (code, detail) = match provider.behavior {
            ProviderBehavior::ForeignUnknown => (
                "foreign_provider_behavior_unknown",
                "foreign provider behavior is not observed or modeled",
            ),
            ProviderBehavior::DynamicDispatch => (
                "dynamic_dispatch_unknown",
                "dynamic provider dispatch is not resolved",
            ),
        };
        add_unknown(&mut unknowns, code, &provider.id, detail);
        add_outcome(
            &mut outcomes,
            QualifiedStatus::NotFalsified,
            code,
            &provider.id,
            detail,
            Vec::new(),
            [code],
        );
    }

    // Callback declarations and their observed/unobserved qualification.
    let observed_callbacks: BTreeSet<&str> = events
        .iter()
        .filter(|event| event.kind == EventKind::Callback)
        .filter_map(|event| event.callback.as_deref())
        .collect();
    for callback in &input.callbacks {
        let observed = observed_callbacks.contains(callback.id.as_str());
        if !observed {
            if callback.legally_absent {
                add_outcome(
                    &mut outcomes,
                    QualifiedStatus::Omission,
                    "callback_legally_absent",
                    &callback.id,
                    "declared callback was not observed and is legally absent in this finite trace",
                    Vec::new(),
                    std::iter::empty::<&'static str>(),
                );
                continue;
            }
            add_unknown(
                &mut unknowns,
                "callback_not_observed",
                &callback.id,
                "declared callback was not observed in the finite trace",
            );
            add_outcome(
                &mut outcomes,
                QualifiedStatus::NotFalsified,
                "callback_not_observed",
                &callback.id,
                "unobserved callback could still occur outside this finite trace",
                Vec::new(),
                ["callback_not_observed"],
            );
        }
        let (code, detail) = match callback.behavior {
            CallbackBehavior::SynchronousLegal => continue,
            CallbackBehavior::RetainedPointer => (
                "retained_pointer_escaped",
                "callback may retain or escape a pointer after return",
            ),
            CallbackBehavior::Deferred => (
                "deferred_callback",
                "callback may run after the registering call returns",
            ),
            CallbackBehavior::CallbackAfterFree => (
                "callback_after_free_declared",
                "callback is declared to run after the target storage is freed",
            ),
            CallbackBehavior::ForeignProviderDispatch => (
                "foreign_provider_dispatch",
                "callback dispatch is owned by a foreign provider and remains unknown",
            ),
        };
        add_unknown(&mut unknowns, code, &callback.id, detail);
        add_outcome(
            &mut outcomes,
            QualifiedStatus::NotFalsified,
            code,
            &callback.id,
            detail,
            Vec::new(),
            [code],
        );
    }

    // Reference-interval membership is checked explicitly.
    for event in &events {
        if let Some(interval_id) = event.interval.as_deref() {
            let interval = intervals[interval_id];
            let active =
                event.point >= interval.start && interval.end.is_none_or(|end| event.point < end);
            if !active {
                add_outcome(
                    &mut outcomes,
                    QualifiedStatus::ObservedConflict,
                    "event_outside_reference_interval",
                    format!("{}@{}", event.alias, event.point),
                    format!(
                        "event point {} is outside reference interval {}",
                        event.point, interval_id
                    ),
                    vec![event_ref(event)],
                    std::iter::empty::<&'static str>(),
                );
            }
        }
    }

    let frees: Vec<&PathEvent> = events
        .iter()
        .copied()
        .filter(|event| event.kind == EventKind::Free)
        .collect();

    // Double free is definite only for the same explicit object. A shared
    // mapping or top alias leaves the relation possible.
    for (index, left) in frees.iter().enumerate() {
        let left_alias = aliases[left.alias.as_str()];
        for right in frees.iter().skip(index + 1) {
            let right_alias = aliases[right.alias.as_str()];
            let relation = storage_relation(storage_of(left_alias), storage_of(right_alias));
            match relation {
                StorageRelation::Same => add_outcome(
                    &mut outcomes,
                    QualifiedStatus::ObservedConflict,
                    "double_free",
                    format!(
                        "{}@{}:{}@{}",
                        left.alias, left.point, right.alias, right.point
                    ),
                    "the same explicit object is freed more than once",
                    vec![event_ref(left), event_ref(right)],
                    std::iter::empty::<&'static str>(),
                ),
                StorageRelation::Possible => add_outcome(
                    &mut outcomes,
                    QualifiedStatus::NotFalsified,
                    "possible_double_free",
                    format!(
                        "{}@{}:{}@{}",
                        left.alias, left.point, right.alias, right.point
                    ),
                    "aliases may denote the same storage, so a double free remains possible",
                    vec![event_ref(left), event_ref(right)],
                    ["alias_identity_unknown"],
                ),
                StorageRelation::Disjoint => {}
            }
        }
    }

    // Any later event through a same-or-possibly-same alias is a use after free.
    for free in &frees {
        let free_alias = aliases[free.alias.as_str()];
        let free_storage = storage_of(free_alias);
        for event in &events {
            if event.point <= free.point || event.kind == EventKind::Free {
                continue;
            }
            let event_alias = aliases[event.alias.as_str()];
            let relation = storage_relation(storage_of(event_alias), free_storage);
            let (code, unknown) = if event.kind == EventKind::Callback {
                ("callback_after_free", "possible_callback_after_free")
            } else {
                ("use_after_free", "possible_use_after_free")
            };
            match relation {
                StorageRelation::Same => add_outcome(
                    &mut outcomes,
                    QualifiedStatus::ObservedConflict,
                    code,
                    format!(
                        "{}@{}:{}@{}",
                        free.alias, free.point, event.alias, event.point
                    ),
                    "an event occurs after the same explicit object was freed",
                    vec![event_ref(free), event_ref(event)],
                    std::iter::empty::<&'static str>(),
                ),
                StorageRelation::Possible => add_outcome(
                    &mut outcomes,
                    QualifiedStatus::NotFalsified,
                    unknown,
                    format!(
                        "{}@{}:{}@{}",
                        free.alias, free.point, event.alias, event.point
                    ),
                    "the event may use storage that was freed through an unresolved alias",
                    vec![event_ref(free), event_ref(event)],
                    ["alias_identity_unknown"],
                ),
                StorageRelation::Disjoint => {}
            }
        }
    }

    // Pairwise access conflicts over the explicit event order.
    let access_events: Vec<&PathEvent> = events
        .iter()
        .copied()
        .filter(|event| event.access != AccessMode::NoAccess)
        .collect();
    let pair_checks = access_events
        .len()
        .saturating_mul(access_events.len().saturating_sub(1))
        / 2;
    if pair_checks > MAX_PAIR_CHECKS {
        return Err(PathError::LimitExceeded {
            resource: "pair_checks",
            limit: MAX_PAIR_CHECKS,
        });
    }

    for (index, left) in access_events.iter().enumerate() {
        let left_alias = aliases[left.alias.as_str()];
        let left_storage = storage_of(left_alias);
        for right in access_events.iter().skip(index + 1) {
            if left.access == AccessMode::Read && right.access == AccessMode::Read {
                continue;
            }
            let left_window = match left.interval.as_deref() {
                Some(id) => interval_window(intervals[id]),
                None => (left.point, left.point.saturating_add(1)),
            };
            let right_window = match right.interval.as_deref() {
                Some(id) => interval_window(intervals[id]),
                None => (right.point, right.point.saturating_add(1)),
            };
            if !windows_overlap(left_window, right_window) {
                continue;
            }

            let right_alias = aliases[right.alias.as_str()];
            let relation = storage_relation(left_storage, storage_of(right_alias));
            if relation == StorageRelation::Disjoint {
                continue;
            }
            let overlap = overlap_of(
                relation,
                extent_of(left, left_alias),
                extent_of(right, right_alias),
            );
            if overlap == Overlap::Disjoint {
                continue;
            }

            let common_object = match (left_storage, storage_of(right_alias)) {
                (Storage::Object(a), Storage::Object(b)) if a == b => objects.get(a).copied(),
                _ => None,
            };
            let interior_mutation = common_object.is_some_and(|object| object.interior_mutable)
                && (left.access == AccessMode::Read || right.access == AccessMode::Read);
            if interior_mutation {
                continue;
            }

            let subject = format!(
                "{}@{}:{}@{}",
                left.alias, left.point, right.alias, right.point
            );
            let detail = format!(
                "{} footprint ({}) overlaps {} footprint ({}) with accesses {} and {}",
                left.alias,
                left.footprint.kind.as_str(),
                right.alias,
                right.footprint.kind.as_str(),
                left.access.as_str(),
                right.access.as_str()
            );
            match overlap {
                Overlap::Definite => add_outcome(
                    &mut outcomes,
                    QualifiedStatus::ObservedConflict,
                    "definite_write_overlap",
                    subject,
                    detail,
                    vec![event_ref(left), event_ref(right)],
                    std::iter::empty::<&'static str>(),
                ),
                Overlap::Possible => {
                    let mut codes = Vec::new();
                    if relation == StorageRelation::Possible {
                        codes.push("alias_identity_unknown");
                    }
                    if matches!(extent_of(left, left_alias), Extent::Unknown)
                        || matches!(extent_of(right, right_alias), Extent::Unknown)
                    {
                        codes.push("footprint_extent_unknown");
                    }
                    for code in &codes {
                        add_unknown(
                            &mut unknowns,
                            code,
                            &subject,
                            "an access pair cannot be proven disjoint in this finite model",
                        );
                    }
                    add_outcome(
                        &mut outcomes,
                        QualifiedStatus::NotFalsified,
                        "possible_write_overlap",
                        subject,
                        detail,
                        vec![event_ref(left), event_ref(right)],
                        codes,
                    );
                }
                Overlap::Disjoint => {}
            }
        }
    }

    if outcomes.is_empty() {
        let evidence = access_events.iter().map(|event| event_ref(event)).collect();
        add_outcome(
            &mut outcomes,
            QualifiedStatus::CompatibleWithinFiniteFootprint,
            "compatible_finite_footprint",
            "finite_event_footprint",
            "no observed conflict or explicit uncertainty in the declared finite footprint; this is not whole-program or universal closure",
            evidence,
            std::iter::empty::<&'static str>(),
        );
    }

    if outcomes.len() > MAX_OUTCOMES {
        return Err(PathError::LimitExceeded {
            resource: "outcomes",
            limit: MAX_OUTCOMES,
        });
    }

    let mut summary = BTreeMap::new();
    for outcome in &outcomes {
        *summary
            .entry(outcome.status.as_str().to_owned())
            .or_insert(0) += 1;
    }
    let overall = if outcomes
        .iter()
        .any(|outcome| outcome.status == QualifiedStatus::ObservedConflict)
    {
        QualifiedStatus::ObservedConflict
    } else if outcomes
        .iter()
        .any(|outcome| outcome.status == QualifiedStatus::NotFalsified)
    {
        QualifiedStatus::NotFalsified
    } else if outcomes
        .iter()
        .any(|outcome| outcome.status == QualifiedStatus::Omission)
    {
        QualifiedStatus::Omission
    } else {
        QualifiedStatus::CompatibleWithinFiniteFootprint
    };

    Ok(PathReport {
        schema: PATH_EFFECT_REPORT_SCHEMA.to_owned(),
        spec: PATH_EFFECT_SPEC.to_owned(),
        input_schema: input_schema.to_owned(),
        input_sha256: input_sha256.to_owned(),
        claim_ceiling: PATH_EFFECT_CLAIM_CEILING.to_owned(),
        outcomes: outcomes.into_iter().collect(),
        unknowns: unknowns.into_iter().collect(),
        summary,
        overall,
    })
}

fn canonical_input_digest(input: &PathEffectsInput) -> Result<String, PathError> {
    let value = serde_json::to_value(input).map_err(|error| PathError::Canonical {
        message: error.to_string(),
    })?;
    let bytes = crate::identity::canonical_bytes(&value).map_err(|error| match error {
        crate::identity::IdentityError::TooLarge { limit, .. } => PathError::LimitExceeded {
            resource: "input_canonical_bytes",
            limit,
        },
        other => PathError::Canonical {
            message: other.to_string(),
        },
    })?;
    Ok(hex_digest(&bytes))
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut text = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Analyze one explicit finite path-effects input.
///
/// # Errors
///
/// Returns [`PathError`] when the input is structurally invalid or exceeds a
/// hard limit.
pub fn analyze(input: &PathEffectsInput) -> Result<PathReport, PathError> {
    let digest = canonical_input_digest(input)?;
    analyze_with_digest(input, PATH_EFFECT_INPUT_SCHEMA, &digest)
}

/// Derive a deliberately coarse explicit input from a Phase 3.1 source
/// inventory.
///
/// The inventory has no alias, object, interval, or dynamic-dispatch identity.
/// Every derived event therefore uses one top/unknown alias and a top
/// footprint, and an explicit foreign-dispatch provider is added. The result
/// is expected to be `NOT_FALSIFIED`; it is never evidence of compatibility.
#[must_use]
pub fn path_input_from_inventory(inventory: &SourceInventory) -> PathEffectsInput {
    let alias = "inventory-top-alias";
    let mut input = PathEffectsInput::empty();
    input.aliases.push(AliasDecl {
        id: alias.to_owned(),
        kind: AliasKind::TopUnknown,
        object: None,
        mapping: None,
        range: None,
    });
    input.providers.push(ProviderDecl {
        id: "inventory-dynamic-dispatch".to_owned(),
        behavior: ProviderBehavior::ForeignUnknown,
    });

    let mut point = 0_u64;
    for finding in &inventory.findings {
        let (kind, access) = match finding.kind {
            FindingKind::Allocation => (EventKind::Creation, AccessMode::NoAccess),
            FindingKind::Deallocation => (EventKind::Free, AccessMode::NoAccess),
            FindingKind::CallbackRegistration => (EventKind::Callback, AccessMode::NoAccess),
            FindingKind::UnsafeCellUse
            | FindingKind::RawPointerOperation
            | FindingKind::OwnershipCall
            | FindingKind::FfiCall => (EventKind::Use, AccessMode::Write),
            _ => continue,
        };
        let callback = if kind == EventKind::Callback {
            let id = format!("inventory-callback-{point:06}");
            input.callbacks.push(CallbackDecl {
                id: id.clone(),
                behavior: CallbackBehavior::ForeignProviderDispatch,
                legally_absent: false,
            });
            Some(id)
        } else {
            None
        };
        input.events.push(PathEvent {
            point,
            kind,
            alias: alias.to_owned(),
            access,
            footprint: Footprint {
                kind: FootprintKind::Top,
                range: None,
            },
            interval: None,
            callback,
        });
        point += 1;
    }
    input
}

/// Analyze a Phase 3.1 source inventory as a coarse explicit path model.
///
/// # Errors
///
/// Returns [`PathError`] if the derived input is invalid or exceeds a hard
/// limit. The derived input uses a top/unknown alias, so an empty or
/// conflict-free inventory does not establish compatibility.
pub fn analyze_inventory(inventory: &SourceInventory) -> Result<PathReport, PathError> {
    let value = serde_json::to_value(inventory).map_err(|error| PathError::Canonical {
        message: error.to_string(),
    })?;
    let bytes = crate::identity::canonical_bytes(&value).map_err(|error| match error {
        crate::identity::IdentityError::TooLarge { limit, .. } => PathError::LimitExceeded {
            resource: "inventory_canonical_bytes",
            limit,
        },
        other => PathError::Canonical {
            message: other.to_string(),
        },
    })?;
    let digest = hex_digest(&bytes);
    let input = path_input_from_inventory(inventory);
    analyze_with_digest(&input, SOURCE_INVENTORY_SCHEMA, &digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_alias(id: &str, object: &str) -> AliasDecl {
        AliasDecl {
            id: id.to_owned(),
            kind: AliasKind::ExactObject,
            object: Some(object.to_owned()),
            mapping: None,
            range: None,
        }
    }

    fn event(point: u64, alias: &str) -> PathEvent {
        PathEvent {
            point,
            kind: EventKind::Use,
            alias: alias.to_owned(),
            access: AccessMode::Write,
            footprint: Footprint {
                kind: FootprintKind::Exact,
                range: None,
            },
            interval: None,
            callback: None,
        }
    }

    #[test]
    fn range_overlap_is_half_open_and_overflow_safe() {
        assert!(ByteRange {
            offset: 0,
            length: 4
        }
        .overlaps(ByteRange {
            offset: 3,
            length: 4
        }));
        assert!(!ByteRange {
            offset: 0,
            length: 4
        }
        .overlaps(ByteRange {
            offset: 4,
            length: 4
        }));
        assert!(!ByteRange {
            offset: u64::MAX,
            length: 1
        }
        .overlaps(ByteRange {
            offset: 0,
            length: 1
        }));
    }

    #[test]
    fn empty_input_is_vacuously_compatible() {
        let report = analyze(&PathEffectsInput::empty()).unwrap();
        assert_eq!(
            report.overall,
            QualifiedStatus::CompatibleWithinFiniteFootprint
        );
        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.outcomes[0].code, "compatible_finite_footprint");
    }

    #[test]
    fn exact_write_overlap_is_observed_conflict() {
        let mut input = PathEffectsInput::empty();
        input.objects.push(ObjectDecl {
            id: "a".to_owned(),
            interior_mutable: false,
        });
        input.aliases.push(exact_alias("p", "a"));
        input.aliases.push(exact_alias("q", "a"));
        input.intervals.push(ReferenceIntervalDecl {
            id: "i1".to_owned(),
            alias: "p".to_owned(),
            start: 0,
            end: Some(3),
        });
        input.intervals.push(ReferenceIntervalDecl {
            id: "i2".to_owned(),
            alias: "q".to_owned(),
            start: 0,
            end: Some(3),
        });
        let mut first = event(0, "p");
        first.interval = Some("i1".to_owned());
        let mut second = event(1, "q");
        second.interval = Some("i2".to_owned());
        input.events.push(first);
        input.events.push(second);
        let report = analyze(&input).unwrap();
        assert_eq!(report.overall, QualifiedStatus::ObservedConflict);
        assert!(report
            .outcomes
            .iter()
            .any(|outcome| outcome.code == "definite_write_overlap"));
    }

    #[test]
    fn interior_mutable_read_write_pair_is_compatible() {
        let mut input = PathEffectsInput::empty();
        input.objects.push(ObjectDecl {
            id: "cell".to_owned(),
            interior_mutable: true,
        });
        input.aliases.push(exact_alias("shared", "cell"));
        input.aliases.push(exact_alias("mutable", "cell"));
        input.intervals.push(ReferenceIntervalDecl {
            id: "i1".to_owned(),
            alias: "shared".to_owned(),
            start: 0,
            end: Some(3),
        });
        input.intervals.push(ReferenceIntervalDecl {
            id: "i2".to_owned(),
            alias: "mutable".to_owned(),
            start: 0,
            end: Some(3),
        });
        let mut read = event(0, "shared");
        read.access = AccessMode::Read;
        read.interval = Some("i1".to_owned());
        let mut write = event(1, "mutable");
        write.interval = Some("i2".to_owned());
        input.events.push(read);
        input.events.push(write);
        let report = analyze(&input).unwrap();
        assert_eq!(
            report.overall,
            QualifiedStatus::CompatibleWithinFiniteFootprint
        );
    }
}
