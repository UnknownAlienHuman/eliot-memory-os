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
use eliot_improvement::candidate_bounds::BoundedBacklog;
use eliot_improvement::{
    intake_from_evidence, record_owner_decision, stamp_outcome_budget, BudgetProof,
    ImprovementBrief, ImprovementError, ImprovementSurface, IntakeOutcome, IntakeRequest,
    OutcomeEvidence, OwnerDecision, OwnerDecisionKind, ReplayPlan, SafeBoundary, SourcedEvidence,
};
use eliot_self_quality::improvement_handoff::sourced_evidence_from_handoff;
use eliot_self_quality::SelfQualityError;
use thiserror::Error;

/// Failures of the daemon improvement-intake bridge.
#[derive(Debug, Error)]
pub enum IntakeBridgeError {
    /// The Self-Quality handoff carried no usable improvement refs.
    #[error("handoff mapping failed: {0}")]
    Handoff(#[from] SelfQualityError),
    /// The improvement intake refused the request.
    #[error("improvement intake failed: {0}")]
    Intake(#[from] ImprovementError),
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
    pub rollback: String,
    pub stop_condition: String,
    pub value: f64,
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

/// Route one real conformance-diagnosis handoff into the improvement backlog.
///
/// Maps the inert handoff to sourced evidence, then runs the full intake:
/// evidence-bound candidate, safe-boundary brief, application-class gate,
/// matched-budget gate, and bounded-backlog admission (dedup-merge on
/// overlapping evidence lineage). Pure orchestration: no promotion, no
/// activation, no mutation beyond the caller-retained backlog.
pub fn route_self_quality_handoff_to_backlog(
    backlog: &mut BoundedBacklog,
    handoff: &SelfQualityHandoff,
    trigger_problem_or_metric: &str,
    validity_scope: &str,
    params: HandoffIntakeParams,
) -> Result<IntakeOutcome, IntakeBridgeError> {
    let evidence: SourcedEvidence =
        sourced_evidence_from_handoff(handoff, trigger_problem_or_metric, validity_scope)?;
    let request = IntakeRequest {
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
    };
    Ok(intake_from_evidence(backlog, request)?)
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
