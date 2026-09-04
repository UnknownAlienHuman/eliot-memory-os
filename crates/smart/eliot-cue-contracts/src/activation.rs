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

use eliot_contracts::StateFence;
use serde::{Deserialize, Serialize};

use crate::{
    ActivationRequestId, ComparisonKey, CueContractError, MAX_DERIVED, MAX_DIRECT, MAX_PATH_LEN,
    MAX_RELATION_EDGES, MAX_SEEDS, MAX_TRACE_STEPS, NormalizedCue, RelationEdgeId, SnapshotId,
    TargetHandle, bound,
};

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

/// One typed relation edge offered to the traversal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RelationEdgeInput {
    /// Identity of the edge in the relation registry.
    pub relation_edge_id: RelationEdgeId,
    /// Where the edge starts.
    pub from: TargetHandle,
    /// Where the edge ends.
    pub to: TargetHandle,
}

impl RelationEdgeInput {
    /// Constructs a relation edge input.
    #[must_use]
    pub const fn new(
        relation_edge_id: RelationEdgeId,
        from: TargetHandle,
        to: TargetHandle,
    ) -> Self {
        Self {
            relation_edge_id,
            from,
            to,
        }
    }
}

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
    /// Minimum strength for an activation to be returned at all.
    pub activation_threshold: ActivationStrength,
}

impl ActivationBounds {
    /// Constructs an explicit bound set.
    #[must_use]
    pub const fn new(
        max_depth: u8,
        max_fanout: u16,
        max_results: u16,
        activation_threshold: ActivationStrength,
    ) -> Self {
        Self {
            max_depth,
            max_fanout,
            max_results,
            activation_threshold,
        }
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
    /// May be empty. A direct-only request carries zero edges and is valid.
    pub relation_edges: Vec<RelationEdgeInput>,
    /// The limits this request runs under.
    pub bounds: ActivationBounds,
    /// The causal snapshot the request was issued against.
    pub state_fence: StateFence,
}

impl ActivationRequest {
    /// Constructs an activation request. Call [`Self::validate`] before use.
    #[must_use]
    pub const fn new(
        schema_revision: String,
        request_id: ActivationRequestId,
        seeds: Vec<NormalizedCue>,
        snapshot_id: SnapshotId,
        relation_edges: Vec<RelationEdgeInput>,
        bounds: ActivationBounds,
        state_fence: StateFence,
    ) -> Self {
        Self {
            schema_revision,
            request_id,
            seeds,
            snapshot_id,
            relation_edges,
            bounds,
            state_fence,
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
        bound(&self.seeds, MAX_SEEDS, "seeds")?;
        bound(&self.relation_edges, MAX_RELATION_EDGES, "relation_edges")?;
        for seed in &self.seeds {
            seed.validate()?;
        }
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
}

/// A relation-derived hit. It always carries a path back to a direct seed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct DerivedActivation {
    /// What was activated.
    pub target: TargetHandle,
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
    #[must_use]
    pub fn new(
        target: TargetHandle,
        path: Vec<RelationEdgeId>,
        strength: ActivationStrength,
    ) -> Self {
        let depth = u8::try_from(path.len()).unwrap_or(u8::MAX);
        Self {
            target,
            path,
            depth,
            strength,
        }
    }

    /// Constructs a derived activation with a caller-supplied depth.
    ///
    /// Exists so a decoder can round-trip a record whose depth disagrees with
    /// its path and have [`ActivationResult::validate`] reject it, rather than
    /// silently repairing corrupt input.
    #[must_use]
    pub const fn from_parts(
        target: TargetHandle,
        path: Vec<RelationEdgeId>,
        depth: u8,
        strength: ActivationStrength,
    ) -> Self {
        Self {
            target,
            path,
            depth,
            strength,
        }
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
    /// Exact hits.
    pub direct: Vec<DirectActivation>,
    /// Relation-derived hits.
    pub derived: Vec<DerivedActivation>,
    /// How complete the search was.
    pub completeness: Completeness,
    /// Why each hit is present.
    pub trace: ActivationTrace,
}

impl ActivationResult {
    /// Constructs an activation result. Call [`Self::validate`] before use.
    #[must_use]
    pub const fn new(
        schema_revision: String,
        request_id: ActivationRequestId,
        direct: Vec<DirectActivation>,
        derived: Vec<DerivedActivation>,
        completeness: Completeness,
        trace: ActivationTrace,
    ) -> Self {
        Self {
            schema_revision,
            request_id,
            direct,
            derived,
            completeness,
            trace,
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
        bound(&self.direct, MAX_DIRECT, "direct")?;
        bound(&self.derived, MAX_DERIVED, "derived")?;
        bound(&self.trace.steps, MAX_TRACE_STEPS, "trace.steps")?;

        // A truncation that names no frontier is indistinguishable from a
        // complete search, which is exactly the collapse this cell forbids.
        if let Completeness::Truncated { frontier, .. } = &self.completeness
            && frontier.is_empty()
        {
            return Err(CueContractError::TruncationWithoutBound);
        }

        for activation in &self.derived {
            if activation.path.is_empty() {
                return Err(CueContractError::BrokenActivationPath);
            }
            bound(&activation.path, MAX_PATH_LEN, "derived.path")?;
            if usize::from(activation.depth) != activation.path.len() {
                return Err(CueContractError::BrokenActivationPath);
            }
        }
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
