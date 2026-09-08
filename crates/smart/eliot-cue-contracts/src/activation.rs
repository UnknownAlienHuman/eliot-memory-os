//! Bounded activation: what a set of cues reaches, and how far the search got.
//!
//! Two rules from `I12.15` shape every type here.
//!
//! A direct match and a relation-derived match are different results. A direct
//! activation has no path because there is none; a derived activation always
//! has a contiguous path that begins at a direct seed. Merging them would let a
//! multi-hop inference be reported with the confidence of an exact hit.
//!
//! Truncation is a result, not a smaller answer. `Complete`, `Truncated`,
//! `SourceUnavailable` and `Stale` stay distinct, and an empty-and-complete
//! result — "searched everything, found nothing" — is not the same as "could
//! not read the snapshot".

use eliot_contracts::{ClockReading, StateFence};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{
    ActivationRequestId, ComparisonKey, CueContractError, MAX_DERIVED, MAX_DIRECT, MAX_PATH_LEN,
    MAX_RELATION_EDGES, MAX_SEEDS, MAX_TRACE_STEPS, NormalizationProfile, NormalizedCue,
    RelationEdgeId, SnapshotId, TargetHandle, bounds,
};

pub use crate::relation::RelationEdge as RelationEdgeInput;

/// How strongly a target was activated, on a bounded integer scale.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct ActivationStrength(pub u16);

/// The limits one activation request runs under.
///
/// Every bound is explicit. An unknown limit is not an unlimited one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ActivationBounds {
    /// Maximum hops from a direct seed. Zero means direct-only.
    pub max_depth: u8,
    /// Maximum edges followed out of any one node.
    pub max_fanout: u16,
    /// Maximum activations returned.
    pub max_results: u16,
    /// Maximum result node entries accounted for by this contract. A traversal
    /// owner must enforce its own inspected-node counter.
    pub max_nodes: u32,
    /// Maximum relation path edges accounted for by this contract. A traversal
    /// owner must enforce its own inspected-edge counter.
    pub max_edges: u32,
    /// Maximum bounded result-accounting work units. This shape does not claim
    /// to measure runtime traversal work.
    pub max_work: u64,
    /// Maximum edge path items in one derived result.
    pub max_path_len: u16,
    /// Maximum seeds accepted.
    pub max_seeds: u16,
    /// Maximum direct activations returned.
    pub max_direct: u16,
    /// Maximum derived activations returned.
    pub max_derived: u16,
    /// Maximum trace steps returned.
    pub max_trace_steps: u16,
    /// Maximum canonical output bytes.
    pub max_output_bytes: u32,
    /// Minimum strength for an activation to be returned at all.
    pub activation_threshold: ActivationStrength,
}

/// Constructible parameter record for [`ActivationBounds`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivationBoundsSpec {
    pub max_depth: u8,
    pub max_fanout: u16,
    pub max_results: u16,
    pub max_nodes: u32,
    pub max_edges: u32,
    pub max_work: u64,
    pub max_path_len: u16,
    pub max_seeds: u16,
    pub max_direct: u16,
    pub max_derived: u16,
    pub max_trace_steps: u16,
    pub max_output_bytes: u32,
    pub activation_threshold: ActivationStrength,
}

impl ActivationBounds {
    /// Constructs an explicit bound set.
    #[must_use]
    pub const fn new(spec: ActivationBoundsSpec) -> Self {
        Self {
            max_depth: spec.max_depth,
            max_fanout: spec.max_fanout,
            max_results: spec.max_results,
            max_nodes: spec.max_nodes,
            max_edges: spec.max_edges,
            max_work: spec.max_work,
            max_path_len: spec.max_path_len,
            max_seeds: spec.max_seeds,
            max_direct: spec.max_direct,
            max_derived: spec.max_derived,
            max_trace_steps: spec.max_trace_steps,
            max_output_bytes: spec.max_output_bytes,
            activation_threshold: spec.activation_threshold,
        }
    }

    /// Validates that every independent limit is explicit and finite.
    pub fn validate(&self) -> Result<(), CueContractError> {
        let output_bytes = usize::try_from(self.max_output_bytes).map_err(|_| {
            CueContractError::BoundExceeded {
                field: "bounds.max_output_bytes",
                limit: bounds::MAX_OUTPUT_BYTES,
            }
        })?;
        if self.max_results == 0
            || self.max_nodes == 0
            || self.max_work == 0
            || self.max_seeds == 0
            || self.max_direct == 0
            || self.max_trace_steps == 0
            || self.max_output_bytes == 0
            || output_bytes > bounds::MAX_OUTPUT_BYTES
            || (self.max_depth > 0
                && (self.max_fanout == 0
                    || self.max_edges == 0
                    || self.max_path_len == 0
                    || self.max_derived == 0))
        {
            return Err(CueContractError::InvalidText { field: "bounds" });
        }
        Ok(())
    }
}

/// One bounded activation request against one immutable snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ActivationRequest {
    /// Schema revision this record was written against.
    pub schema_revision: String,
    /// Identity of this request.
    pub request_id: ActivationRequestId,
    /// The cues to start from.
    pub seeds: Vec<NormalizedCue>,
    /// The snapshot to evaluate against.
    pub snapshot_id: SnapshotId,
    /// Relation edges available to the traversal.
    ///
    /// May be empty. A direct-only request must carry zero edges; offered
    /// relation edges are rejected when traversal is disabled.
    pub relation_edges: Vec<RelationEdgeInput>,
    /// The limits this request runs under.
    pub bounds: ActivationBounds,
    /// The causal snapshot the request was issued against.
    pub state_fence: StateFence,
    /// Profile that produced every seed key.
    pub normalization_profile: NormalizationProfile,
    /// Observation clock captured before activation began.
    pub observed_at: ClockReading,
    /// Optional wall-clock validity deadline in the same millisecond domain as
    /// `ClockReading::valid_time_ms`.
    pub deadline_ms: Option<i64>,
    /// Caller cancellation observation.
    pub cancelled: bool,
}

/// Constructible parameter record for [`ActivationRequest`].
pub struct ActivationRequestSpec {
    pub schema_revision: String,
    pub request_id: ActivationRequestId,
    pub seeds: Vec<NormalizedCue>,
    pub snapshot_id: SnapshotId,
    pub relation_edges: Vec<RelationEdgeInput>,
    pub bounds: ActivationBounds,
    pub state_fence: StateFence,
    pub normalization_profile: NormalizationProfile,
    pub observed_at: ClockReading,
    pub deadline_ms: Option<i64>,
    pub cancelled: bool,
}

impl ActivationRequest {
    /// Constructs an activation request. Call [`Self::validate`] before use.
    #[must_use]
    pub fn new(spec: ActivationRequestSpec) -> Self {
        Self {
            schema_revision: spec.schema_revision,
            request_id: spec.request_id,
            seeds: spec.seeds,
            snapshot_id: spec.snapshot_id,
            relation_edges: spec.relation_edges,
            bounds: spec.bounds,
            state_fence: spec.state_fence,
            normalization_profile: spec.normalization_profile,
            observed_at: spec.observed_at,
            deadline_ms: spec.deadline_ms,
            cancelled: spec.cancelled,
        }
    }

    /// Checks the intrinsic rules this record owns.
    ///
    /// # Errors
    /// Rejects an empty seed set, any collection past its bound, and a request
    /// that offers relation edges while forbidding traversal.
    pub fn validate(&self) -> Result<(), CueContractError> {
        if self.seeds.is_empty() {
            return Err(CueContractError::InvalidText { field: "seeds" });
        }
        bounds::collection(&self.seeds, MAX_SEEDS, "seeds")?;
        bounds::collection(&self.relation_edges, MAX_RELATION_EDGES, "relation_edges")?;
        if self.seeds.len() > usize::from(self.bounds.max_seeds) {
            return Err(CueContractError::BoundExceeded {
                field: "request.seeds",
                limit: usize::from(self.bounds.max_seeds),
            });
        }
        let max_edges = usize::try_from(self.bounds.max_edges).map_err(|_| {
            CueContractError::BoundExceeded {
                field: "request.relation_edges",
                limit: usize::MAX,
            }
        })?;
        if self.relation_edges.len() > max_edges {
            return Err(CueContractError::BoundExceeded {
                field: "request.relation_edges",
                limit: max_edges,
            });
        }
        if self.bounds.max_depth == 0 && !self.relation_edges.is_empty() {
            return Err(CueContractError::InvalidText {
                field: "request.relation_edges",
            });
        }
        if self.schema_revision != crate::CONTRACT_REVISION {
            return Err(CueContractError::InvalidText {
                field: "schema_revision",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| CueContractError::Foundation {
                field: "request.state_fence",
            })?;
        self.normalization_profile.validate()?;
        self.observed_at
            .validate()
            .map_err(|_| CueContractError::Foundation {
                field: "request.observed_at",
            })?;
        if let Some(deadline) = self.deadline_ms {
            let valid_time =
                self.observed_at
                    .valid_time_ms
                    .ok_or(CueContractError::Foundation {
                        field: "request.deadline_ms",
                    })?;
            if deadline < valid_time {
                return Err(CueContractError::Foundation {
                    field: "request.deadline_ms",
                });
            }
        }
        let mut edge_ids = BTreeSet::new();
        for seed in &self.seeds {
            seed.validate()?;
            if matches!(
                &seed.outcome,
                crate::NormalizationOutcome::Ambiguous { .. }
                    | crate::NormalizationOutcome::Unsupported { .. }
            ) {
                return Err(CueContractError::Foundation {
                    field: "request.seed_outcome",
                });
            }
            if seed
                .comparison_keys
                .iter()
                .any(|key| key.profile != self.normalization_profile)
            {
                return Err(CueContractError::Foundation {
                    field: "request.seed_profile",
                });
            }
            if seed.observed.context.state_fence != self.state_fence {
                return Err(CueContractError::Foundation {
                    field: "request.seed_fence",
                });
            }
        }
        for edge in &self.relation_edges {
            edge.validate()?;
            if !edge_ids.insert(edge.relation_edge_id.clone()) {
                return Err(CueContractError::DuplicateIdentity {
                    field: "request.relation_edges",
                });
            }
            if edge.evidence.state_fence != self.state_fence {
                return Err(CueContractError::Foundation {
                    field: "request.edge_fence",
                });
            }
        }
        self.bounds.validate()?;
        Ok(())
    }

    /// True when the request forbids traversal, so only direct hits are possible.
    #[must_use]
    pub const fn is_direct_only(&self) -> bool {
        self.bounds.max_depth == 0
    }
}

/// A direct hit. It carries no path, because there is none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct DirectActivation {
    /// What was activated.
    pub target: TargetHandle,
    /// The key that matched.
    pub matched_key: ComparisonKey,
    /// How strongly.
    pub strength: ActivationStrength,
}

impl DirectActivation {
    /// Constructs a direct activation.
    #[must_use]
    pub const fn new(
        target: TargetHandle,
        matched_key: ComparisonKey,
        strength: ActivationStrength,
    ) -> Self {
        Self {
            target,
            matched_key,
            strength,
        }
    }

    fn validate(&self) -> Result<(), CueContractError> {
        bounds::text(self.target.as_str(), "direct.target")?;
        self.matched_key.validate()
    }
}

/// A relation-derived hit. It always carries a path back to a direct seed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct DerivedActivation {
    /// What was activated.
    pub target: TargetHandle,
    /// Direct activation target from which this path begins.
    pub direct_seed: TargetHandle,
    /// Non-empty, contiguous, and beginning at a direct activation.
    pub path: Vec<RelationEdgeId>,
    /// Hops from the direct seed. Equals `path.len()`.
    pub depth: u8,
    /// How strongly.
    pub strength: ActivationStrength,
}

impl DerivedActivation {
    /// Constructs a derived activation.
    ///
    /// `depth` is taken from the path, so the two can never disagree.
    pub fn try_new(
        target: TargetHandle,
        direct_seed: TargetHandle,
        path: Vec<RelationEdgeId>,
        strength: ActivationStrength,
    ) -> Result<Self, CueContractError> {
        let depth = u8::try_from(path.len()).map_err(|_| CueContractError::BoundExceeded {
            field: "derived.path",
            limit: usize::from(u8::MAX),
        })?;
        Ok(Self {
            target,
            direct_seed,
            path,
            depth,
            strength,
        })
    }

    /// Constructs a derived activation with a caller-supplied depth.
    ///
    /// Exists so a decoder can round-trip a record whose depth disagrees with
    /// its path and have [`ActivationResult::validate`] reject it, rather than
    /// silently repairing corrupt input.
    #[must_use]
    pub const fn from_parts(
        target: TargetHandle,
        direct_seed: TargetHandle,
        path: Vec<RelationEdgeId>,
        depth: u8,
        strength: ActivationStrength,
    ) -> Self {
        Self {
            target,
            direct_seed,
            path,
            depth,
            strength,
        }
    }

    fn validate_shape(&self) -> Result<(), CueContractError> {
        bounds::text(self.target.as_str(), "derived.target")?;
        bounds::text(self.direct_seed.as_str(), "derived.direct_seed")?;
        bounds::collection(&self.path, MAX_PATH_LEN, "derived.path")?;
        for edge in &self.path {
            bounds::text(edge.as_str(), "derived.path.edge")?;
        }
        if self.path.is_empty() || usize::from(self.depth) != self.path.len() {
            return Err(CueContractError::BrokenActivationPath);
        }
        Ok(())
    }
}

/// Which bound stopped a search.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum BoundKind {
    /// `max_depth` was reached.
    Depth,
    /// `max_fanout` was reached.
    Fanout,
    /// `max_results` was reached.
    Results,
    /// Everything below `activation_threshold` was dropped.
    Threshold,
}

/// How complete the search was.
///
/// These states are never collapsed into one another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "completeness", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum Completeness {
    /// The whole denominator was searched. There is no frontier.
    Complete,
    /// A bound stopped the search. The frontier names where to resume.
    Truncated {
        /// Edges not yet followed.
        frontier: Vec<RelationEdgeId>,
        /// The bound that stopped it.
        bound_hit: BoundKind,
    },
    /// Evaluation completed only for a known subset of the denominator.
    Partial {
        /// Remaining work that can be resumed.
        frontier: Vec<RelationEdgeId>,
    },
    /// A policy or safety condition blocked evaluation.
    Blocked {
        /// Stable bounded reason class.
        reason: String,
    },
    /// The source projection could not be read.
    Unavailable {
        /// Stable bounded reason class.
        reason: String,
    },
    /// Evaluation could not classify the source or result.
    Unknown {
        /// Stable bounded reason class.
        reason: String,
    },
    /// The snapshot could not be read. This is not "found nothing".
    SourceUnavailable {
        /// Why it could not be read.
        reason: String,
    },
    /// The snapshot is older than the fence the request was issued against.
    Stale {
        /// The fence the snapshot was built at.
        snapshot_fence: StateFence,
    },
}

/// One recorded step of the traversal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TraceStep {
    /// The edge followed, or `None` for a direct match.
    pub edge: Option<RelationEdgeId>,
    /// Depth at which it happened.
    pub depth: u8,
    /// What it reached.
    pub target: TargetHandle,
}

impl TraceStep {
    /// Constructs one trace step.
    #[must_use]
    pub const fn new(edge: Option<RelationEdgeId>, depth: u8, target: TargetHandle) -> Self {
        Self {
            edge,
            depth,
            target,
        }
    }

    fn validate(&self) -> Result<(), CueContractError> {
        if let Some(edge) = &self.edge {
            bounds::text(edge.as_str(), "trace.edge")?;
        }
        bounds::text(self.target.as_str(), "trace.target")
    }
}

/// Why every returned activation is there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ActivationTrace {
    /// The steps taken, in order.
    pub steps: Vec<TraceStep>,
}

impl ActivationTrace {
    /// Constructs a trace.
    #[must_use]
    pub const fn new(steps: Vec<TraceStep>) -> Self {
        Self { steps }
    }

    /// Constructs an empty trace.
    #[must_use]
    pub const fn empty() -> Self {
        Self { steps: Vec::new() }
    }
}

/// The result of one bounded activation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ActivationResult {
    /// Schema revision this record was written against.
    pub schema_revision: String,
    /// The request this answers.
    pub request_id: ActivationRequestId,
    /// Snapshot evaluated by the request.
    pub snapshot_id: SnapshotId,
    /// Profile and fence bound to the evaluation.
    pub normalization_profile: NormalizationProfile,
    pub state_fence: StateFence,
    /// Observation/deadline/cancellation state retained with the result.
    pub observed_at: ClockReading,
    pub deadline_ms: Option<i64>,
    pub cancelled: bool,
    /// Exact hits.
    pub direct: Vec<DirectActivation>,
    /// Relation-derived hits.
    pub derived: Vec<DerivedActivation>,
    /// How complete the search was.
    pub completeness: Completeness,
    /// Why each hit is present.
    pub trace: ActivationTrace,
}

/// Constructible parameter record for [`ActivationResult`].
pub struct ActivationResultSpec {
    pub schema_revision: String,
    pub request_id: ActivationRequestId,
    pub snapshot_id: SnapshotId,
    pub normalization_profile: NormalizationProfile,
    pub state_fence: StateFence,
    pub observed_at: ClockReading,
    pub deadline_ms: Option<i64>,
    pub cancelled: bool,
    pub direct: Vec<DirectActivation>,
    pub derived: Vec<DerivedActivation>,
    pub completeness: Completeness,
    pub trace: ActivationTrace,
}

impl ActivationResult {
    /// Constructs an activation result. Call [`Self::validate`] before use.
    #[must_use]
    pub fn new(spec: ActivationResultSpec) -> Self {
        Self {
            schema_revision: spec.schema_revision,
            request_id: spec.request_id,
            snapshot_id: spec.snapshot_id,
            normalization_profile: spec.normalization_profile,
            state_fence: spec.state_fence,
            observed_at: spec.observed_at,
            deadline_ms: spec.deadline_ms,
            cancelled: spec.cancelled,
            direct: spec.direct,
            derived: spec.derived,
            completeness: spec.completeness,
            trace: spec.trace,
        }
    }

    /// True only for "searched everything and found nothing".
    ///
    /// False for a truncated search and false for an unreadable snapshot: those
    /// are unknowns, not known-empty answers.
    #[must_use]
    pub fn is_known_empty(&self) -> bool {
        self.direct.is_empty()
            && self.derived.is_empty()
            && matches!(self.completeness, Completeness::Complete)
    }

    /// Checks the intrinsic rules this record owns.
    ///
    /// # Errors
    /// Rejects a complete result that still names a frontier, a truncation with
    /// an empty frontier, a derived path that is empty or over its bound, and
    /// any collection past its bound.
    pub fn validate(&self) -> Result<(), CueContractError> {
        bounds::collection(&self.direct, MAX_DIRECT, "direct")?;
        bounds::collection(&self.derived, MAX_DERIVED, "derived")?;
        bounds::collection(&self.trace.steps, MAX_TRACE_STEPS, "trace.steps")?;
        if self.schema_revision != crate::CONTRACT_REVISION {
            return Err(CueContractError::InvalidText {
                field: "schema_revision",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| CueContractError::Foundation {
                field: "result.state_fence",
            })?;
        self.normalization_profile.validate()?;
        self.observed_at
            .validate()
            .map_err(|_| CueContractError::Foundation {
                field: "result.observed_at",
            })?;
        for reason in completeness_reasons(&self.completeness) {
            crate::bounds::text(reason, "completeness.reason")?;
        }

        for direct in &self.direct {
            direct.validate()?;
        }

        // A truncation that names no frontier is indistinguishable from a
        // complete search, which is exactly the collapse this cell forbids.
        if let Completeness::Truncated { frontier, .. } = &self.completeness {
            bounds::collection(frontier, MAX_RELATION_EDGES, "completeness.frontier")?;
            if frontier.is_empty() {
                return Err(CueContractError::TruncationWithoutBound);
            }
            for edge in frontier {
                bounds::text(edge.as_str(), "completeness.frontier.edge")?;
            }
        }

        for activation in &self.derived {
            activation.validate_shape()?;
        }
        for step in &self.trace.steps {
            step.validate()?;
        }
        if let Completeness::Partial { frontier } = &self.completeness {
            bounds::collection(frontier, MAX_RELATION_EDGES, "completeness.frontier")?;
            if frontier.is_empty() {
                return Err(CueContractError::TruncationWithoutBound);
            }
            for edge in frontier {
                bounds::text(edge.as_str(), "completeness.frontier.edge")?;
            }
        }
        if let Completeness::Stale { snapshot_fence } = &self.completeness {
            snapshot_fence
                .validate()
                .map_err(|_| CueContractError::Foundation {
                    field: "result.snapshot_fence",
                })?;
        }
        Ok(())
    }

    /// Validates exact request, snapshot, profile, fence and path lineage.
    pub fn validate_against(&self, request: &ActivationRequest) -> Result<(), CueContractError> {
        request.validate()?;
        self.validate()?;
        if self.request_id != request.request_id
            || self.snapshot_id != request.snapshot_id
            || self.normalization_profile != request.normalization_profile
            || self.state_fence != request.state_fence
            || self.observed_at != request.observed_at
            || self.deadline_ms != request.deadline_ms
            || self.cancelled != request.cancelled
        {
            return Err(CueContractError::Foundation {
                field: "result.request_binding",
            });
        }
        validate_result_budget(self, request)?;
        validate_result_membership(self, request)?;
        validate_result_output(self, request)?;
        Ok(())
    }

    /// Rejects a `Complete` result that still carries a frontier.
    ///
    /// Separate from [`Self::validate`] because the frontier lives in the
    /// completeness variant: a caller constructing a result by hand can satisfy
    /// every field bound and still claim completeness it did not reach.
    ///
    /// # Errors
    /// Returns [`CueContractError::CompleteWithFrontier`] when a caller pairs
    /// `Complete` with unresolved work.
    pub fn validate_completeness(
        &self,
        unresolved: &[RelationEdgeId],
    ) -> Result<(), CueContractError> {
        if matches!(self.completeness, Completeness::Complete) && !unresolved.is_empty() {
            return Err(CueContractError::CompleteWithFrontier);
        }
        Ok(())
    }
}

fn validate_result_budget(
    result: &ActivationResult,
    request: &ActivationRequest,
) -> Result<(), CueContractError> {
    if result.direct.len() > usize::from(request.bounds.max_direct)
        || result.derived.len() > usize::from(request.bounds.max_derived)
        || result.trace.steps.len() > usize::from(request.bounds.max_trace_steps)
    {
        return Err(CueContractError::BoundExceeded {
            field: "result.request_bounds",
            limit: usize::from(request.bounds.max_results),
        });
    }
    let result_count = result
        .direct
        .len()
        .checked_add(result.derived.len())
        .ok_or(CueContractError::BoundExceeded {
            field: "result.count",
            limit: usize::from(request.bounds.max_results),
        })?;
    let max_nodes =
        usize::try_from(request.bounds.max_nodes).map_err(|_| CueContractError::BoundExceeded {
            field: "result.count",
            limit: usize::MAX,
        })?;
    let max_edges =
        usize::try_from(request.bounds.max_edges).map_err(|_| CueContractError::BoundExceeded {
            field: "result.path_edges",
            limit: usize::MAX,
        })?;
    let max_work = usize::try_from(request.bounds.max_work).unwrap_or(usize::MAX);
    if result_count > usize::from(request.bounds.max_results) || result_count > max_nodes {
        return Err(CueContractError::BoundExceeded {
            field: "result.count",
            limit: usize::from(request.bounds.max_results),
        });
    }
    let path_edges = result
        .derived
        .iter()
        .try_fold(0usize, |total, item| total.checked_add(item.path.len()))
        .ok_or(CueContractError::BoundExceeded {
            field: "result.path_edges",
            limit: max_edges,
        })?;
    if path_edges > max_edges {
        return Err(CueContractError::BoundExceeded {
            field: "result.path_edges",
            limit: max_edges,
        });
    }
    let work = result_count
        .checked_add(path_edges)
        .and_then(|total| total.checked_add(result.trace.steps.len()))
        .ok_or(CueContractError::BoundExceeded {
            field: "result.work",
            limit: max_work,
        })?;
    let work_u64 = u64::try_from(work).map_err(|_| CueContractError::BoundExceeded {
        field: "result.work",
        limit: max_work,
    })?;
    if work_u64 > request.bounds.max_work {
        return Err(CueContractError::BoundExceeded {
            field: "result.work",
            limit: max_work,
        });
    }
    Ok(())
}

fn validate_result_membership(
    result: &ActivationResult,
    request: &ActivationRequest,
) -> Result<(), CueContractError> {
    for direct in &result.direct {
        if direct.strength < request.bounds.activation_threshold {
            return Err(CueContractError::Foundation {
                field: "result.direct.threshold",
            });
        }
        if direct.matched_key.profile != request.normalization_profile {
            return Err(CueContractError::Foundation {
                field: "result.key_profile",
            });
        }
        if !request.seeds.iter().any(|seed| {
            seed.comparison_keys
                .iter()
                .any(|key| key == &direct.matched_key)
        }) {
            return Err(CueContractError::Foundation {
                field: "result.matched_key",
            });
        }
    }
    for derived in &result.derived {
        if derived.strength < request.bounds.activation_threshold {
            return Err(CueContractError::Foundation {
                field: "result.derived.threshold",
            });
        }
        if derived.depth > request.bounds.max_depth
            || derived.path.len() > usize::from(request.bounds.max_path_len)
            || usize::from(derived.depth) != derived.path.len()
        {
            return Err(CueContractError::BrokenActivationPath);
        }
        let mut expected_from = &derived.direct_seed;
        for edge_id in &derived.path {
            let edge = request
                .relation_edges
                .iter()
                .find(|edge| &edge.relation_edge_id == edge_id)
                .ok_or(CueContractError::BrokenActivationPath)?;
            if edge.from != *expected_from {
                return Err(CueContractError::BrokenActivationPath);
            }
            expected_from = &edge.to;
        }
        if expected_from != &derived.target
            || !result
                .direct
                .iter()
                .any(|direct| direct.target == derived.direct_seed)
        {
            return Err(CueContractError::BrokenActivationPath);
        }
    }
    Ok(())
}

fn validate_result_output(
    result: &ActivationResult,
    request: &ActivationRequest,
) -> Result<(), CueContractError> {
    let max_output_bytes = usize::try_from(request.bounds.max_output_bytes).map_err(|_| {
        CueContractError::BoundExceeded {
            field: "result.output_bytes",
            limit: bounds::MAX_OUTPUT_BYTES,
        }
    })?;
    let bytes = eliot_contracts::canonical_json_bytes(result).map_err(|_| {
        CueContractError::Foundation {
            field: "result.canonical_payload",
        }
    })?;
    if bytes.len() > max_output_bytes {
        return Err(CueContractError::BoundExceeded {
            field: "result.output_bytes",
            limit: max_output_bytes,
        });
    }
    Ok(())
}

fn completeness_reasons(completeness: &Completeness) -> Vec<&str> {
    match completeness {
        Completeness::Blocked { reason }
        | Completeness::Unavailable { reason }
        | Completeness::Unknown { reason }
        | Completeness::SourceUnavailable { reason } => vec![reason.as_str()],
        Completeness::Complete
        | Completeness::Truncated { .. }
        | Completeness::Partial { .. }
        | Completeness::Stale { .. } => Vec::new(),
    }
}
