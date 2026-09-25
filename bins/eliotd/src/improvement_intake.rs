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
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_improvement::candidate_bounds::BoundedBacklog;
use eliot_improvement::{
    BudgetProof, EvidenceSource, ImprovementBrief, ImprovementError, ImprovementSurface,
    IntakeOutcome, IntakeRequest, OutcomeEvidence, OwnerDecision, OwnerDecisionKind, ReplayPlan,
    SafeBoundary, SourcedEvidence, intake_from_evidence, record_owner_decision, sourced_evidence,
    stamp_outcome_budget,
};
use eliot_instrument_api::InstrumentInvocation;
use eliot_protocol::RequestIdentity;
use eliot_self_quality::SelfQualityError;
use eliot_self_quality::improvement_handoff::sourced_evidence_from_handoff;
use eliot_testd_core::{
    ImprovementDiscriminator, ImprovementExperimentRequest, ImprovementPrivacyClass,
    ImprovementRiskClass, MechanismDeclaration, RollbackContract, TestdProcessToolIntent,
};
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
    /// The exact candidate/brief/budget bridge could not be serialized or
    /// failed its owner-side shape checks.
    #[error("improvement experiment bridge failed: {0}")]
    Bridge(String),
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

/// Owner-supplied experiment declaration that is not present in the
/// `eliot-improvement` candidate itself. It is supplied by the current
/// Governor/TestD intake edge before the candidate can be submitted.
#[derive(Clone, Debug, PartialEq)]
pub struct ImprovementExperimentDeclaration {
    /// Predeclared falsifiable mechanism.
    pub mechanism: MechanismDeclaration,
    /// Expected measurable delta.
    pub expected_delta: String,
    /// Exact expected metric names.
    pub expected_metric_names: Vec<String>,
    /// Exact minimum expected deltas.
    pub expected_deltas: BTreeMap<String, f64>,
    /// Candidate counter-metric names.
    pub counter_metric_names: Vec<String>,
    /// Closed risk class.
    pub risk_class: ImprovementRiskClass,
    /// Closed privacy class.
    pub privacy_class: ImprovementPrivacyClass,
    /// Independent Instrument evaluator identity.
    pub evaluator_id: String,
    /// Owner of rollback/forward repair.
    pub rollback_owner_id: String,
    /// Exact forward-repair route.
    pub forward_repair_ref: String,
    /// Exact invalidation set.
    pub invalidation_set: Vec<String>,
    /// Optional new discriminator for a repeated experiment.
    pub new_discriminator: Option<ImprovementDiscriminator>,
}

/// Explicit, authenticated manual/admitted intake event for the current
/// daemon.  It is a typed event seam, not a timer or a test helper: the
/// current-daemon caller supplies the already-admitted candidate outcome and
/// the owner-issued experiment material, while Kernel rehydrates the live
/// fence, target, budget, generation, and tool identities before persistence.
#[derive(Clone, Debug)]
pub struct ManualImprovementIntakeEvent {
    pub identity: RequestIdentity,
    pub outcome: IntakeOutcome,
    pub declaration: ImprovementExperimentDeclaration,
    pub invocation: InstrumentInvocation,
    pub source_root: String,
    pub process_tool: TestdProcessToolIntent,
}

impl ManualImprovementIntakeEvent {
    /// Validates the event's owner-issued joins before any transport call.
    pub fn validate(&self) -> Result<(), IntakeBridgeError> {
        if !self.outcome.admitted {
            return Err(IntakeBridgeError::Bridge(
                "manual improvement intake requires an admitted candidate outcome".to_owned(),
            ));
        }
        self.identity
            .validate()
            .map_err(|error| IntakeBridgeError::Bridge(error.to_string()))?;
        self.invocation
            .validate()
            .map_err(|error| IntakeBridgeError::Bridge(error.to_string()))?;
        self.process_tool
            .observation
            .validate()
            .map_err(|error| IntakeBridgeError::Bridge(error.to_string()))?;
        if self.source_root.trim().is_empty()
            || self.source_root.chars().any(char::is_control)
            || self.identity.request.metadata != self.invocation.request
            || self.identity.request.state_fence != self.invocation.request.state_fence
        {
            return Err(IntakeBridgeError::Bridge(
                "manual improvement intake identity/source binding is not exact".to_owned(),
            ));
        }
        build_testd_improvement_request(&self.outcome, &self.declaration)?;
        Ok(())
    }
}

/// Projects the actual admitted candidate, safe-boundary brief, and budget
/// proof into the durable `TestD` request contract. This is the real intake
/// bridge: the returned request contains canonical bytes, not a candidate id
/// or a self-reported pass flag.
pub fn build_testd_improvement_request(
    outcome: &IntakeOutcome,
    declaration: &ImprovementExperimentDeclaration,
) -> Result<ImprovementExperimentRequest, IntakeBridgeError> {
    if !outcome.admitted {
        return Err(IntakeBridgeError::Bridge(
            "merged or rejected intake cannot start a new experiment".to_owned(),
        ));
    }
    outcome
        .candidate
        .validate()
        .map_err(|error| IntakeBridgeError::Bridge(error.to_string()))?;
    outcome
        .brief
        .validate()
        .map_err(|error| IntakeBridgeError::Bridge(error.to_string()))?;
    outcome
        .budget_proof
        .supports_promotion()
        .map_err(|error| IntakeBridgeError::Bridge(error.to_string()))?;
    let candidate_json = canonical_json(&outcome.candidate)?;
    let brief_json = canonical_json(&outcome.brief)?;
    let budget_json = canonical_json(&outcome.budget_proof)?;
    let target_surface = serde_json::to_value(outcome.candidate.target_surface)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .ok_or_else(|| {
            IntakeBridgeError::Bridge("candidate target surface is not serializable".to_owned())
        })?;
    let rollback = RollbackContract::new(
        declaration.rollback_owner_id.clone(),
        outcome.candidate.rollback.clone(),
        declaration.forward_repair_ref.clone(),
        declaration.invalidation_set.clone(),
    )
    .map_err(|error| IntakeBridgeError::Bridge(error.to_string()))?;
    let mut expected_metric_names = declaration.expected_metric_names.clone();
    expected_metric_names.sort();
    let mut counter_metric_names = declaration.counter_metric_names.clone();
    counter_metric_names.sort();
    let request = ImprovementExperimentRequest {
        candidate_id: outcome.candidate.candidate_id.clone(),
        candidate_revision: outcome.candidate.revision,
        candidate_digest: sha256_hex(candidate_json.as_bytes()),
        candidate_json,
        intake_brief_id: outcome.brief.brief_id.clone(),
        evaluator_id: declaration.evaluator_id.clone(),
        intake_brief_digest: sha256_hex(brief_json.as_bytes()),
        intake_brief_json: brief_json,
        project_id: outcome.candidate.project_id.clone(),
        target_surface,
        delivery_target: outcome.candidate.delivery_target.clone(),
        canary_plan: outcome.candidate.canary_plan.clone(),
        stop_condition: outcome.candidate.stop_condition.clone(),
        mechanism: declaration.mechanism.clone(),
        expected_delta: declaration.expected_delta.clone(),
        expected_metric_names,
        expected_deltas: declaration.expected_deltas.clone(),
        counter_metric_names,
        risk_class: declaration.risk_class,
        effect_ceiling: eliot_testd_core::IMPROVEMENT_EFFECT_CEILING.to_owned(),
        privacy_class: declaration.privacy_class,
        budget_ledger_ref: outcome.budget_proof.budget_ledger_ref.clone(),
        budget_proof_digest: sha256_hex(budget_json.as_bytes()),
        budget_proof_json: budget_json,
        rollback,
        new_discriminator: declaration.new_discriminator.clone(),
    };
    request
        .validate()
        .map_err(|error| IntakeBridgeError::Bridge(error.to_string()))?;
    Ok(request)
}

fn canonical_json<T: serde::Serialize>(value: &T) -> Result<String, IntakeBridgeError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| IntakeBridgeError::Bridge(error.to_string()))?;
    String::from_utf8(bytes).map_err(|error| IntakeBridgeError::Bridge(error.to_string()))
}

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
    run_intake(backlog, evidence, params)
}

/// Route canonical refs from any I12.24 evidence source into the backlog.
///
/// Covers every [`EvidenceSource`] variant (attempts, evaluator verdicts,
/// campaign closure, conformance diagnosis, security incidents, accepted
/// implementation deviations, complaints, Watchdog, Dreamer, Concilium
/// suggestions): all enter through the single validated
/// [`sourced_evidence`] funnel, then run the full intake. Pure
/// orchestration: no promotion, no activation, no mutation beyond the
/// caller-retained backlog.
#[allow(
    clippy::too_many_arguments,
    reason = "one validated slot per sourced-evidence field plus the intake bundle"
)]
pub fn route_evidence_refs_to_backlog(
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

fn run_intake(
    backlog: &mut BoundedBacklog,
    evidence: SourcedEvidence,
    params: HandoffIntakeParams,
) -> Result<IntakeOutcome, IntakeBridgeError> {
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
