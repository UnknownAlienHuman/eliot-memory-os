//! Inert transitions: before/after positions with rollback, never applied.
//!
//! An [`EpistemicTransition`] records a proposed move from a before position to an after position: the expected
//! revision and fence, the trigger with its evidence and operation identity, before/after support and
//! assertability, added/removed/retained handles with reasons, coverage and conflict deltas, and rollback,
//! repair, invalidation, and proof references. Transitions are inert data: this crate applies nothing and
//! allocates nothing. Promotion out of unknown or partial support without fresh evidence is rejected.
use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use eliot_contracts::{OperationId, RequestId, StateFence, TaskId, TaskRevision};
use eliot_receipts::WorkScope;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::assertability::PositionAssertability;
use crate::candidate::EpistemicPositionCandidate;
use crate::error::{
    ContractError, MAX_HANDLES, MAX_SHORT_TEXT, check_frozen, shape_digest, validate_bounded_text,
    validate_digest,
};
use crate::identity::{PredecessorId, PropositionId};
use crate::request::PositionRequest;
use crate::support::{SupportRecord, SupportResult, weakest_link};
use crate::temporal::TemporalRecord;

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

/// Added, removed, and retained handles with reasons (disjoint sets, every
/// change carrying a bounded reason).
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
    /// Task binding the transition proposes under.
    pub task_id: TaskId,
    /// Attempt binding the transition proposes under.
    pub attempt_id: String,
    /// Caller request identity the transition answers.
    pub request_id: RequestId,
    /// Idempotency key binding retries of this exact transition.
    pub idempotency_key: String,
    /// Canonical work scope the transition proposes in.
    pub work_scope: WorkScope,
    /// Digest of the candidate this transition moves toward.
    pub candidate_digest: String,
    /// Revision the transition expects to build on.
    pub expected_revision: TaskRevision,
    /// Fence the transition expects to build under.
    pub expected_fence: StateFence,
    /// What triggered the proposed transition.
    pub trigger: TransitionTrigger,
    /// Evidence references behind the transition; order carries no meaning.
    /// Every reference must resolve into the before or after support records.
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
    /// Applicable temporal record, when the transition carries capture times.
    pub temporal: Option<TemporalRecord>,
    /// Bounded rollback description.
    pub rollback: String,
    /// Bounded repair description, when a repair is proposed.
    pub repair: Option<String>,
    /// Invalidation record, when the transition invalidates history. It must
    /// name the actual prior record validated in `validate_closed`.
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
    task_id: &'a TaskId,
    attempt_id: &'a str,
    request_id: &'a RequestId,
    idempotency_key: &'a str,
    work_scope: &'a WorkScope,
    candidate_digest: &'a str,
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
    temporal: &'a Option<TemporalRecord>,
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
        task_id: TaskId,
        attempt_id: impl Into<String>,
        request_id: RequestId,
        idempotency_key: impl Into<String>,
        work_scope: WorkScope,
        candidate_digest: impl Into<String>,
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
        temporal: Option<TemporalRecord>,
        rollback: impl Into<String>,
        repair: Option<String>,
        invalidation: Option<InvalidationRecord>,
        proof_digest: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let mut transition = Self {
            position,
            task_id,
            attempt_id: attempt_id.into(),
            request_id,
            idempotency_key: idempotency_key.into(),
            work_scope,
            candidate_digest: candidate_digest.into(),
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
            temporal,
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
            task_id: &self.task_id,
            attempt_id: self.attempt_id.as_str(),
            request_id: &self.request_id,
            idempotency_key: self.idempotency_key.as_str(),
            work_scope: &self.work_scope,
            candidate_digest: self.candidate_digest.as_str(),
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
            temporal: &self.temporal,
            rollback: self.rollback.as_str(),
            repair: &self.repair,
            invalidation: &self.invalidation,
            proof_digest: self.proof_digest.as_str(),
        })
    }

    /// Support-delta reconciliation: the delta is the exact partition of the before/after handle sets —
    /// added is after-minus-before, removed is before-minus-after, retained is the intersection, so an
    /// omitted, duplicated, extra, or misclassified handle fails.
    pub fn reconcile_delta(
        delta: &SupportDelta,
        before: &[SupportRecord],
        after: &[SupportRecord],
    ) -> Result<(), ContractError> {
        delta.validate()?;
        let before_handles: BTreeSet<ArtifactId> = before
            .iter()
            .flat_map(|record| record.handles.iter().cloned())
            .collect();
        let after_handles: BTreeSet<ArtifactId> = after
            .iter()
            .flat_map(|record| record.handles.iter().cloned())
            .collect();
        let field = "transition.delta";
        if delta.added != &after_handles - &before_handles {
            return Err(ContractError::ArithmeticMismatch { field });
        }
        if delta.removed != &before_handles - &after_handles {
            return Err(ContractError::ArithmeticMismatch { field });
        }
        if delta.retained != &before_handles & &after_handles {
            return Err(ContractError::ArithmeticMismatch { field });
        }
        Ok(())
    }
    fn validate_shape(&self) -> Result<(), ContractError> {
        self.expected_fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "transition.expected_fence",
            })?;
        validate_bounded_text(&self.attempt_id, "transition.attempt_id", MAX_SHORT_TEXT)?;
        validate_bounded_text(
            &self.idempotency_key,
            "transition.idempotency_key",
            MAX_SHORT_TEXT,
        )?;
        validate_digest(&self.candidate_digest, "transition.candidate_digest")?;
        self.work_scope
            .state_fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "transition.work_scope",
            })?;
        if !self
            .work_scope
            .state_fence
            .is_compatible_with(&self.expected_fence)
            || !self
                .expected_fence
                .is_compatible_with(&self.work_scope.state_fence)
        {
            return Err(ContractError::FenceMismatch {
                field: "transition.work_scope",
            });
        }
        if self.evidence_refs.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "transition.evidence_refs",
            });
        }
        self.delta.validate()?;
        if let Some(temporal) = &self.temporal {
            temporal.validate()?;
        }
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
        check_frozen(&self.digest, &self.compute_digest()?, "transition.digest")
    }

    /// Closes the transition against its governing request, candidate, and real
    /// before/after support records (binding, arithmetic, and terminality below).
    pub fn validate_closed(
        &self,
        request: &PositionRequest,
        candidate: &EpistemicPositionCandidate,
        before: &[SupportRecord],
        after: &[SupportRecord],
    ) -> Result<(), ContractError> {
        self.validate()?;
        request.validate()?;
        candidate.validate()?;
        // Before/after records bind to the expected task, scope, fence, and proposition by value:
        // structural validity alone never places a record in this transition.
        for record in before.iter().chain(after.iter()) {
            record.validate_for(
                &self.task_id,
                self.work_scope.scope_id.as_str(),
                &self.expected_fence,
            )?;
            if record.proposition != self.position {
                let field = "transition.records";
                return Err(ContractError::ScopeMismatch { field });
            }
        }
        self.check_request_binding(request)?;
        self.check_candidate_binding(candidate, before, after)?;
        self.check_arithmetic(before, after)?;
        self.check_terminality(candidate, before)?;
        Ok(())
    }
    fn check_request_binding(&self, request: &PositionRequest) -> Result<(), ContractError> {
        if request.task_id != self.task_id {
            return Err(ContractError::TaskMismatch {
                field: "transition.task_id",
            });
        }
        if request.attempt_id != self.attempt_id {
            return Err(ContractError::TaskMismatch {
                field: "transition.attempt_id",
            });
        }
        if request.request_id != self.request_id {
            return Err(ContractError::TaskMismatch {
                field: "transition.request_id",
            });
        }
        if request.idempotency_key != self.idempotency_key {
            return Err(ContractError::TaskMismatch {
                field: "transition.idempotency_key",
            });
        }
        if request.work_scope != self.work_scope {
            return Err(ContractError::ScopeMismatch {
                field: "transition.work_scope",
            });
        }
        if request.operation_id != self.operation {
            return Err(ContractError::OutsideManifest {
                field: "transition.operation",
            });
        }
        if request.revision != self.expected_revision {
            return Err(ContractError::StaleContext {
                field: "transition.expected_revision",
            });
        }
        if !self.expected_fence.is_compatible_with(&request.fence)
            || !request.fence.is_compatible_with(&self.expected_fence)
        {
            return Err(ContractError::FenceMismatch {
                field: "transition.expected_fence",
            });
        }
        Ok(())
    }
    fn check_candidate_binding(
        &self,
        candidate: &EpistemicPositionCandidate,
        before: &[SupportRecord],
        after: &[SupportRecord],
    ) -> Result<(), ContractError> {
        if candidate.task_id != self.task_id {
            return Err(ContractError::TaskMismatch {
                field: "transition.task_id",
            });
        }
        if candidate.work_scope != self.work_scope {
            return Err(ContractError::ScopeMismatch {
                field: "transition.work_scope",
            });
        }
        if candidate.digest != self.candidate_digest {
            return Err(ContractError::DigestMismatch {
                field: "transition.candidate_digest",
            });
        }
        if candidate.proposition != self.position {
            return Err(ContractError::ScopeMismatch {
                field: "transition.position",
            });
        }
        // The candidate must stand on the expected revision under the expected fence: a candidate from
        // another revision or fence answers another transition.
        if candidate.revision != self.expected_revision {
            let field = "transition.candidate_revision";
            return Err(ContractError::StaleContext { field });
        }
        if !candidate.fence.is_compatible_with(&self.expected_fence)
            || !self.expected_fence.is_compatible_with(&candidate.fence)
        {
            let field = "transition.candidate_fence";
            return Err(ContractError::FenceMismatch { field });
        }
        // The transition temporal must be owned by the candidate digest set: a valid but unrelated
        // temporal proves nothing here.
        let digests = &candidate.temporal_digests;
        if let Some(temporal) = &self.temporal
            && !digests.contains(&shape_digest(temporal)?)
        {
            let field = "transition.temporal";
            return Err(ContractError::MissingReference { field });
        }
        Self::reconcile_delta(&self.delta, before, after)?;
        let real: BTreeSet<_> = before
            .iter()
            .chain(after.iter())
            .flat_map(|record| record.handles.iter())
            .collect();
        for reference in &self.evidence_refs {
            if !real.contains(&reference) {
                return Err(ContractError::OutsideManifest {
                    field: "transition.evidence_refs",
                });
            }
        }
        Ok(())
    }
    fn check_arithmetic(
        &self,
        before: &[SupportRecord],
        after: &[SupportRecord],
    ) -> Result<(), ContractError> {
        let before_results: Vec<SupportResult> =
            before.iter().map(|record| record.result).collect();
        let after_results: Vec<SupportResult> = after.iter().map(|record| record.result).collect();
        if weakest_link(&before_results)? != self.before_support {
            return Err(ContractError::ArithmeticMismatch {
                field: "transition.before_support",
            });
        }
        if weakest_link(&after_results)? != self.after_support {
            return Err(ContractError::ArithmeticMismatch {
                field: "transition.after_support",
            });
        }
        let before_ceiling = PositionAssertability::support_cap(&before_results)?;
        if self.before_assertability.strength_rank() > before_ceiling.strength_rank() {
            let field = "transition.before_assertability";
            return Err(ContractError::CeilingViolation { field });
        }
        let after_ceiling = PositionAssertability::support_cap(&after_results)?;
        if self.after_assertability.strength_rank() > after_ceiling.strength_rank() {
            return Err(ContractError::CeilingViolation {
                field: "transition.after_assertability",
            });
        }
        if self.after_assertability == PositionAssertability::MaterialEffect
            && (self.evidence_refs.is_empty() || self.delta.added.is_empty())
        {
            return Err(ContractError::CeilingViolation {
                field: "transition.after_assertability",
            });
        }
        Ok(())
    }
    fn check_terminality(
        &self,
        candidate: &EpistemicPositionCandidate,
        before: &[SupportRecord],
    ) -> Result<(), ContractError> {
        let needs_prior = self.invalidation.is_some()
            || matches!(
                self.trigger,
                TransitionTrigger::Supersession | TransitionTrigger::Repair
            );
        if needs_prior {
            let Some(invalidation) = &self.invalidation else {
                return Err(ContractError::MissingReference {
                    field: "transition.invalidation",
                });
            };
            invalidation.validate()?;
            let names_predecessor = candidate.predecessor.as_ref().is_some_and(|predecessor| {
                predecessor.as_str() == invalidation.predecessor.as_str()
            });
            let names_before = before.iter().any(|record| {
                record
                    .handles
                    .iter()
                    .any(|handle| handle.as_str() == invalidation.predecessor.as_str())
            });
            if !names_predecessor && !names_before {
                return Err(ContractError::MissingReference {
                    field: "transition.invalidation",
                });
            }
        }
        Ok(())
    }
}
