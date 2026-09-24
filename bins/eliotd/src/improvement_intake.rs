//! Daemon-side Meta bridge: Self-Quality handoff to improvement intake.
//!
//! Production composition-root wiring for issue #1867
//! (`docs/architecture/I12-24-meta-learning-and-improvement-delivery.md`):
//! a real conformance-diagnosis handoff (or repeated verifier failure refs)
//! enters the Meta-owned improvement path, is admitted into the bounded
//! backlog as a durable deduplicated candidate, and yields an
//! owner-actionable [`ImprovementBrief`] at the safe boundary for an active
//! Main Agent or Human. Advisory records mutate nothing: owner decisions are
//! recorded, never executed, and replay-only promotion without a bound
//! budget/economics record plus live matched-budget evidence is refused by
//! the improvement crate before any backlog mutation.
//!
//! The caller retains the [`BoundedBacklog`]: dedup merges by evidence
//! lineage only while the same backlog is presented across passes.
//! Cross-restart durability of the backlog rides on the existing
//! Governor/Kernel persistence path and is out of scope for this bridge.

use std::collections::BTreeMap;

use eliot_conformance_contracts::SelfQualityHandoff;
use eliot_contracts::TaskId;
use eliot_governor::{LearningAdmissionError, LearningAdmissionRequest};
use eliot_improvement::candidate_bounds::{BoundedBacklog, CandidateBoundPolicy};
use eliot_improvement::{
    BudgetProof, EvidenceSource, ImprovementBrief, ImprovementError, ImprovementSurface,
    IntakeOutcome, IntakeRequest, OutcomeEvidence, OwnerDecision, OwnerDecisionKind, ReplayPlan,
    SafeBoundary, SourcedEvidence, intake_from_evidence, intake_from_evidence_governed,
    prepare_intake_for_owner, record_owner_decision, sourced_evidence, stamp_outcome_budget,
};
use eliot_self_quality::SelfQualityError;
use eliot_self_quality::improvement_handoff::sourced_evidence_from_handoff;
use thiserror::Error;

use super::DaemonComposition;

/// Failures of the daemon improvement-intake bridge.
#[derive(Debug, Error)]
pub enum IntakeBridgeError {
    /// The Self-Quality handoff carried no usable improvement refs.
    #[error("handoff mapping failed: {0}")]
    Handoff(#[from] SelfQualityError),
    /// The improvement intake refused the request.
    #[error("improvement intake failed: {0}")]
    Intake(#[from] ImprovementError),
    /// The retained intake queue is at its bounded capacity.
    #[error("governed improvement intake queue is full")]
    QueueFull,
    /// The current Governor owner could not project learning admission.
    #[error("Governor learning admission: {0}")]
    Admission(#[from] LearningAdmissionError),
    /// The Governor composition could not project the current owner record.
    #[error("Governor composition: {0}")]
    Composition(String),
}

/// Owned intake parameters beyond the mapped handoff evidence.
///
/// Every ref below is a canonical record handle, never an inline metric: the
/// brief carries evidence refs so the decision owner never searches raw
/// metrics (I12.24:74).
#[allow(
    clippy::struct_excessive_bools,
    reason = "four independent class-gate flags; grouping them would hide the per-class boundary"
)]
#[derive(Clone, Debug)]
pub struct HandoffIntakeParams {
    pub project_id: String,
    pub target_surface: ImprovementSurface,
    pub proposed_change: String,
    pub replay_plan: ReplayPlan,
    pub baseline_metrics: BTreeMap<String, f64>,
    pub delivery_target: String,
    pub canary_plan: String,
    /// Advisory request content; the governed path replaces this with the
    /// current Governor owner projection before any class gate runs.
    pub rollback: String,
    pub stop_condition: String,
    pub value: f64,
    /// Optional legacy registry hint; governed intake never authorizes from
    /// this caller string and replaces it with the current owner ref.
    pub owner: Option<String>,
    pub problem: String,
    pub likely_benefit: String,
    pub risk: String,
    pub proposed_owner: String,
    pub cost: String,
    pub next_reversible_step: String,
    pub unknowns: Vec<String>,
    pub boundary: SafeBoundary,
    pub bounded_tuning: bool,
    pub touches_protected: bool,
    pub has_work_item_ref: bool,
    pub live_experiments_on_surface: usize,
    pub work_item_ref: Option<String>,
    pub owner_approved: bool,
    pub migration_proof_ref: Option<String>,
    pub budget_proof: BudgetProof,
}

/// One owner-bound intake event retained by the daemon composition.
///
/// The event contains request material and the subject identity only. The
/// five authorization/revalidation refs are not accepted here; the daemon
/// obtains them from the current Governor owner when it drains the event.
#[derive(Clone, Debug)]
pub struct GovernedImprovementIntakeEvent {
    pub request: IntakeRequest,
    pub admission: LearningAdmissionRequest,
}

const MAX_PENDING_GOVERNED_INTAKES: usize = 64;
const GOVERNED_BACKLOG_MAX_ACTIVE: usize = 32;
const GOVERNED_BACKLOG_MIN_VALUE: f64 = 0.0;

/// Route one real conformance-diagnosis handoff into the improvement backlog
/// for crate-internal legacy preparation.
///
/// Production callers must use [`DaemonComposition::enqueue_self_quality_improvement_intake`],
/// which retains the backlog and obtains Governor admission. This compatibility
/// helper remains crate-private so a caller cannot present a caller-owned
/// authority string as production intake evidence.
#[allow(
    dead_code,
    reason = "crate-private compatibility preparation has no production caller until a daemon event supplies the complete owner-bound intake bundle"
)]
pub(crate) fn route_self_quality_handoff_to_backlog(
    backlog: &mut BoundedBacklog,
    handoff: &SelfQualityHandoff,
    trigger_problem_or_metric: &str,
    validity_scope: &str,
    params: HandoffIntakeParams,
) -> Result<IntakeOutcome, IntakeBridgeError> {
    let evidence: SourcedEvidence =
        sourced_evidence_from_handoff(handoff, trigger_problem_or_metric, validity_scope)?;
    run_intake(backlog, evidence, params)
}

/// Route canonical refs from any I12.24 evidence source into the backlog for
/// crate-internal legacy preparation.
///
/// Production callers use the daemon-owned governed event methods instead;
/// this compatibility helper cannot be used to establish authority outside
/// the crate.
#[allow(
    clippy::too_many_arguments,
    reason = "one validated slot per sourced-evidence field plus the intake bundle"
)]
#[allow(
    dead_code,
    reason = "crate-private compatibility preparation has no production caller until a daemon event supplies the complete owner-bound intake bundle"
)]
pub(crate) fn route_evidence_refs_to_backlog(
    backlog: &mut BoundedBacklog,
    source: EvidenceSource,
    evidence_refs: &[String],
    trace_refs: &[String],
    trigger_problem_or_metric: &str,
    root_cause_hypotheses: &[String],
    validity_scope: &str,
    owner_and_decision_authority: &str,
    params: HandoffIntakeParams,
) -> Result<IntakeOutcome, IntakeBridgeError> {
    let evidence = sourced_evidence(
        source,
        evidence_refs,
        trace_refs,
        trigger_problem_or_metric,
        root_cause_hypotheses,
        validity_scope,
        owner_and_decision_authority,
    )?;
    run_intake(backlog, evidence, params)
}

fn intake_request_from_params(
    evidence: SourcedEvidence,
    params: HandoffIntakeParams,
) -> IntakeRequest {
    IntakeRequest {
        project_id: params.project_id,
        target_surface: params.target_surface,
        proposed_change: params.proposed_change,
        evidence,
        replay_plan: params.replay_plan,
        baseline_metrics: params.baseline_metrics,
        delivery_target: params.delivery_target,
        canary_plan: params.canary_plan,
        rollback: params.rollback,
        stop_condition: params.stop_condition,
        value: params.value,
        owner: params.owner,
        problem: params.problem,
        likely_benefit: params.likely_benefit,
        risk: params.risk,
        proposed_owner: params.proposed_owner,
        cost: params.cost,
        next_reversible_step: params.next_reversible_step,
        unknowns: params.unknowns,
        boundary: params.boundary,
        bounded_tuning: params.bounded_tuning,
        touches_protected: params.touches_protected,
        has_work_item_ref: params.has_work_item_ref,
        live_experiments_on_surface: params.live_experiments_on_surface,
        work_item_ref: params.work_item_ref,
        owner_approved: params.owner_approved,
        migration_proof_ref: params.migration_proof_ref,
        budget_proof: params.budget_proof,
    }
}

#[allow(
    dead_code,
    reason = "used by the intentionally crate-private legacy preparation helpers only"
)]
fn run_intake(
    backlog: &mut BoundedBacklog,
    evidence: SourcedEvidence,
    params: HandoffIntakeParams,
) -> Result<IntakeOutcome, IntakeBridgeError> {
    Ok(intake_from_evidence(
        backlog,
        intake_request_from_params(evidence, params),
    )?)
}

impl DaemonComposition {
    /// Enqueue one bounded, owner-bound intake event on the single daemon
    /// composition. No caller-owned backlog or authority projection is
    /// accepted.
    pub fn enqueue_governed_improvement_intake(
        &mut self,
        event: GovernedImprovementIntakeEvent,
    ) -> Result<(), IntakeBridgeError> {
        event.admission.validate()?;
        if self.pending_governed_improvement_intakes.len() >= MAX_PENDING_GOVERNED_INTAKES {
            return Err(IntakeBridgeError::QueueFull);
        }
        self.pending_governed_improvement_intakes.push_back(event);
        Ok(())
    }

    /// Map a real Self-Quality handoff into the retained event queue.
    pub fn enqueue_self_quality_improvement_intake(
        &mut self,
        handoff: &SelfQualityHandoff,
        trigger_problem_or_metric: &str,
        validity_scope: &str,
        params: HandoffIntakeParams,
        admission: LearningAdmissionRequest,
    ) -> Result<(), IntakeBridgeError> {
        let evidence =
            sourced_evidence_from_handoff(handoff, trigger_problem_or_metric, validity_scope)?;
        self.enqueue_governed_improvement_intake(GovernedImprovementIntakeEvent {
            request: intake_request_from_params(evidence, params),
            admission,
        })
    }

    /// Drain at most one retained intake event.
    ///
    /// The existing daemon run loop invokes this bounded step. A failed
    /// event is put back at the head of the same owner queue, preserving the
    /// evidence and preventing a refusal from becoming silent loss.
    pub fn drive_governed_improvement_intake_once(
        &mut self,
    ) -> Result<Option<IntakeOutcome>, IntakeBridgeError> {
        let Some(event) = self.pending_governed_improvement_intakes.pop_front() else {
            return Ok(None);
        };
        let result = self.admit_governed_improvement_event(event.clone());
        if result.is_err() {
            self.pending_governed_improvement_intakes.push_front(event);
        }
        result.map(Some)
    }

    /// Read-only retained backlog access for the single daemon owner.
    #[must_use]
    pub fn improvement_backlog(&self) -> &BoundedBacklog {
        &self.improvement_backlog
    }

    /// Current number of queued owner-bound intake events.
    #[must_use]
    pub fn pending_governed_improvement_intake_count(&self) -> usize {
        self.pending_governed_improvement_intakes.len()
    }

    fn admit_governed_improvement_event(
        &mut self,
        event: GovernedImprovementIntakeEvent,
    ) -> Result<IntakeOutcome, IntakeBridgeError> {
        let task_id = TaskId::new(event.admission.target_task_id.clone())
            .map_err(|_| IntakeBridgeError::Admission(LearningAdmissionError::InvalidTargetTask))?;
        let owner = self
            .governor
            .learning_admission_owner_record(&task_id)
            .map_err(|error| IntakeBridgeError::Composition(error.to_string()))?;
        let prepared = prepare_intake_for_owner(event.request, &owner)?;
        if event.admission.candidate_id.as_deref() != Some(prepared.candidate_id()) {
            return Err(IntakeBridgeError::Admission(
                LearningAdmissionError::OwnerEvidenceMismatch("candidate_subject"),
            ));
        }
        let policy = CandidateBoundPolicy {
            target_surface: prepared.candidate().target_surface,
            max_active: GOVERNED_BACKLOG_MAX_ACTIVE,
            min_value: GOVERNED_BACKLOG_MIN_VALUE,
            governor_authority_ref: owner.authority_ref().to_owned(),
            policy_revision: owner.policy_revision(),
        };
        self.improvement_backlog
            .install_policy(policy)
            .map_err(|error| {
                IntakeBridgeError::Intake(ImprovementError::BacklogRefused(error.to_string()))
            })?;
        let permit = self
            .governor
            .issue_learning_admission_for_owner(&event.admission)?;
        let fence = self.governor.kernel_snapshot().state_fence();
        let verified = self
            .governor
            .verify_learning_admission_for_owner(&permit, &fence)?;
        intake_from_evidence_governed(&mut self.improvement_backlog, prepared, &verified)
            .map_err(IntakeBridgeError::from)
    }
}

/// Record a non-mutating owner decision against an improvement brief.
///
/// `reject` and `investigate` authorize no change; `work_item` and
/// `experiment` route into the normal work-item/canary/rollback flow through
/// the owning lanes. Recording itself mutates nothing.
pub fn record_brief_decision(
    brief: &ImprovementBrief,
    owner: &str,
    kind: OwnerDecisionKind,
    note: &str,
) -> Result<OwnerDecision, IntakeBridgeError> {
    Ok(record_owner_decision(brief, owner, kind, note)?)
}

/// Bind a matched-budget proof onto a promotion-bound outcome.
///
/// Refuses replay-only promotion without a bound budget-equivalence ledger,
/// conclusive complexity-economics delta, affected checks, live
/// matched-budget evidence, and delayed-harm visibility.
pub fn stamp_promotion_budget(
    outcome: &mut OutcomeEvidence,
    proof: &BudgetProof,
) -> Result<(), IntakeBridgeError> {
    Ok(stamp_outcome_budget(outcome, proof)?)
}
