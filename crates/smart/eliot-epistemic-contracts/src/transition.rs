//! Inert transitions: before/after positions with rollback, never applied.
//!
//! An [`EpistemicTransition`] records a proposed move from a before position
//! to an after position: the expected revision and fence, the trigger with
//! its evidence and operation identity, before/after support and
//! assertability, added/removed/retained handles with reasons, coverage and
//! conflict deltas, and rollback, repair, invalidation, and proof references.
//! Transitions are inert data: this crate applies nothing and allocates
//! nothing. Promotion out of unknown or partial support without fresh
//! evidence is rejected, so an unconditional promotion can never validate.

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use eliot_contracts::{OperationId, StateFence, TaskRevision};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::assertability::PositionAssertability;
use crate::error::{
    ContractError, MAX_HANDLES, MAX_SHORT_TEXT, shape_digest, validate_bounded_text,
    validate_digest,
};
use crate::identity::{PredecessorId, PropositionId};
use crate::support::SupportResult;

/// How a position record was invalidated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InvalidationKind {
    /// Replaced by a later governed record.
    Superseded,
    /// Withdrawn without replacement.
    Withdrawn,
    /// Reopened for further inquiry.
    Reopened,
    /// Repaired in place with a recorded reason.
    Repaired,
}

impl InvalidationKind {
    /// Returns the exact frozen wire name of this invalidation kind.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Superseded => "SUPERSEDED",
            Self::Withdrawn => "WITHDRAWN",
            Self::Reopened => "REOPENED",
            Self::Repaired => "REPAIRED",
        }
    }
}

/// One invalidation record with its reason and predecessor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InvalidationRecord {
    /// How the record was invalidated.
    pub kind: InvalidationKind,
    /// Bounded reason for the invalidation.
    pub reason: String,
    /// Predecessor retained as history.
    pub predecessor: PredecessorId,
}

impl InvalidationRecord {
    /// Constructs an invalidation record after validation.
    pub fn new(
        kind: InvalidationKind,
        reason: impl Into<String>,
        predecessor: PredecessorId,
    ) -> Result<Self, ContractError> {
        let record = Self {
            kind,
            reason: reason.into(),
            predecessor,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates the invalidation reason.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bounded_text(
            &self.reason,
            "transition.invalidation_reason",
            MAX_SHORT_TEXT,
        )?;
        Ok(())
    }
}

/// What triggered the proposed transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransitionTrigger {
    /// Fresh evidence arrived.
    NewEvidence,
    /// A revalidation run completed.
    Revalidation,
    /// The scope, fence, or snapshot changed.
    ContextChange,
    /// A supersession link was recorded.
    Supersession,
    /// A bounded repair was proposed.
    Repair,
}

/// Added, removed, and retained handles with reasons.
///
/// All three sets are disjoint: a handle is added, removed, or retained, and
/// every change carries a bounded reason in `reasons`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportDelta {
    /// Handles the transition adds; order carries no meaning.
    pub added: BTreeSet<ArtifactId>,
    /// Handles the transition removes; order carries no meaning.
    pub removed: BTreeSet<ArtifactId>,
    /// Handles the transition retains; order carries no meaning.
    pub retained: BTreeSet<ArtifactId>,
    /// Bounded reasons for the changes; order carries no meaning.
    pub reasons: BTreeSet<String>,
}

impl SupportDelta {
    /// Constructs a support delta after validation.
    pub fn new(
        added: BTreeSet<ArtifactId>,
        removed: BTreeSet<ArtifactId>,
        retained: BTreeSet<ArtifactId>,
        reasons: BTreeSet<String>,
    ) -> Result<Self, ContractError> {
        let delta = Self {
            added,
            removed,
            retained,
            reasons,
        };
        delta.validate()?;
        Ok(delta)
    }

    /// Validates disjointness, bounds, and non-empty reasons.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.added.len() > MAX_HANDLES
            || self.removed.len() > MAX_HANDLES
            || self.retained.len() > MAX_HANDLES
        {
            return Err(ContractError::TooMany {
                field: "transition.delta",
            });
        }
        if !self.added.is_disjoint(&self.removed)
            || !self.added.is_disjoint(&self.retained)
            || !self.removed.is_disjoint(&self.retained)
        {
            return Err(ContractError::ImpossibleCombination {
                field: "transition.delta",
            });
        }
        if self.reasons.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "transition.reasons",
            });
        }
        for reason in &self.reasons {
            validate_bounded_text(reason.as_str(), "transition.reasons", MAX_SHORT_TEXT)?;
        }
        Ok(())
    }
}

/// An inert, fully described position transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpistemicTransition {
    /// Position the transition bears on.
    pub position: PropositionId,
    /// Revision the transition expects to build on.
    pub expected_revision: TaskRevision,
    /// Fence the transition expects to build under.
    pub expected_fence: StateFence,
    /// What triggered the proposed transition.
    pub trigger: TransitionTrigger,
    /// Evidence references behind the transition; order carries no meaning.
    pub evidence_refs: BTreeSet<ArtifactId>,
    /// Operation identity the transition is proposed under.
    pub operation: OperationId,
    /// Support before the transition.
    pub before_support: SupportResult,
    /// Support after the transition.
    pub after_support: SupportResult,
    /// Assertability before the transition.
    pub before_assertability: PositionAssertability,
    /// Assertability after the transition.
    pub after_assertability: PositionAssertability,
    /// Handle delta with reasons.
    pub delta: SupportDelta,
    /// Digest of the coverage delta behind the transition.
    pub coverage_delta_digest: String,
    /// Digest of the conflict delta behind the transition.
    pub conflict_delta_digest: String,
    /// Bounded rollback description.
    pub rollback: String,
    /// Bounded repair description, when a repair is proposed.
    pub repair: Option<String>,
    /// Invalidation record, when the transition invalidates history.
    pub invalidation: Option<InvalidationRecord>,
    /// Digest of the bounded proof payload behind the transition.
    pub proof_digest: String,
    /// Canonical digest of the transition shape, excluding this field.
    pub digest: String,
}

/// Canonical digest shape of a transition, excluding the frozen digest field.
#[derive(Serialize)]
struct TransitionDigestShape<'a> {
    position: &'a PropositionId,
    expected_revision: &'a TaskRevision,
    expected_fence: &'a StateFence,
    trigger: &'a TransitionTrigger,
    evidence_refs: &'a BTreeSet<ArtifactId>,
    operation: &'a OperationId,
    before_support: &'a SupportResult,
    after_support: &'a SupportResult,
    before_assertability: &'a PositionAssertability,
    after_assertability: &'a PositionAssertability,
    delta: &'a SupportDelta,
    coverage_delta_digest: &'a str,
    conflict_delta_digest: &'a str,
    rollback: &'a str,
    repair: &'a Option<String>,
    invalidation: &'a Option<InvalidationRecord>,
    proof_digest: &'a str,
}

impl EpistemicTransition {
    /// Constructs a transition and freezes its canonical digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        position: PropositionId,
        expected_revision: TaskRevision,
        expected_fence: StateFence,
        trigger: TransitionTrigger,
        evidence_refs: BTreeSet<ArtifactId>,
        operation: OperationId,
        before_support: SupportResult,
        after_support: SupportResult,
        before_assertability: PositionAssertability,
        after_assertability: PositionAssertability,
        delta: SupportDelta,
        coverage_delta_digest: impl Into<String>,
        conflict_delta_digest: impl Into<String>,
        rollback: impl Into<String>,
        repair: Option<String>,
        invalidation: Option<InvalidationRecord>,
        proof_digest: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let mut transition = Self {
            position,
            expected_revision,
            expected_fence,
            trigger,
            evidence_refs,
            operation,
            before_support,
            after_support,
            before_assertability,
            after_assertability,
            delta,
            coverage_delta_digest: coverage_delta_digest.into(),
            conflict_delta_digest: conflict_delta_digest.into(),
            rollback: rollback.into(),
            repair,
            invalidation,
            proof_digest: proof_digest.into(),
            digest: String::new(),
        };
        transition.validate_shape()?;
        transition.digest = transition.compute_digest()?;
        Ok(transition)
    }

    /// Recomputes the canonical digest of the transition shape.
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&TransitionDigestShape {
            position: &self.position,
            expected_revision: &self.expected_revision,
            expected_fence: &self.expected_fence,
            trigger: &self.trigger,
            evidence_refs: &self.evidence_refs,
            operation: &self.operation,
            before_support: &self.before_support,
            after_support: &self.after_support,
            before_assertability: &self.before_assertability,
            after_assertability: &self.after_assertability,
            delta: &self.delta,
            coverage_delta_digest: self.coverage_delta_digest.as_str(),
            conflict_delta_digest: self.conflict_delta_digest.as_str(),
            rollback: self.rollback.as_str(),
            repair: &self.repair,
            invalidation: &self.invalidation,
            proof_digest: self.proof_digest.as_str(),
        })
    }

    fn validate_shape(&self) -> Result<(), ContractError> {
        self.expected_fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "transition.expected_fence",
            })?;
        if self.evidence_refs.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "transition.evidence_refs",
            });
        }
        self.delta.validate()?;
        validate_digest(
            &self.coverage_delta_digest,
            "transition.coverage_delta_digest",
        )?;
        validate_digest(
            &self.conflict_delta_digest,
            "transition.conflict_delta_digest",
        )?;
        validate_bounded_text(&self.rollback, "transition.rollback", MAX_SHORT_TEXT)?;
        if let Some(repair) = &self.repair {
            validate_bounded_text(repair.as_str(), "transition.repair", MAX_SHORT_TEXT)?;
        }
        if let Some(invalidation) = &self.invalidation {
            invalidation.validate()?;
        }
        validate_digest(&self.proof_digest, "transition.proof_digest")?;
        let promotion_base = matches!(
            self.before_support,
            SupportResult::Unknown
                | SupportResult::Partial
                | SupportResult::Stale
                | SupportResult::Superseded
                | SupportResult::OutsideManifest
        );
        let promotion_target = matches!(self.after_support, SupportResult::Supported);
        if promotion_base
            && promotion_target
            && (self.evidence_refs.is_empty() || self.delta.added.is_empty())
        {
            return Err(ContractError::CeilingViolation {
                field: "transition.promotion",
            });
        }
        Ok(())
    }

    /// Validates the transition shape and its frozen digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        validate_digest(&self.digest, "transition.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ContractError::DigestMismatch {
                field: "transition.digest",
            });
        }
        Ok(())
    }
}
