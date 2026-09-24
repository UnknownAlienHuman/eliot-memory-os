//! Governed, advisory self-improvement candidates.
//!
//! This crate deliberately stops at the promotion boundary.  It records a
//! replayable proposal and produces an outcome-linked input for an external
//! governor decision; no API in this crate can make a candidate active.

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

pub mod application_class;
pub mod brief;
pub mod budget_proof;
pub mod candidate_bounds;
pub mod evidence_sources;
pub mod governed_screen;
pub mod intake;
pub mod learning_closure;
pub mod overlay_policy_routing;
pub mod producer;

pub use governed_screen::{
    CarriageMark, PresentedLearning, bounds_to_context_error, check_governed_carriage,
    datetime_from_unix,
};
pub use overlay_policy_routing::{ImprovementCandidateDraft, route_rejected_surface};
pub use producer::{
    LearningProduction, produce_learning_candidate, route_overlay_task_policy_change,
};

pub mod promotion_input;

pub use application_class::{
    ApplicationClass, ChangeDescriptor, check_class_gate, classify, is_prohibited_tuning_surface,
};
pub use brief::{
    ImprovementBrief, OwnerDecision, OwnerDecisionKind, SafeBoundary, brief_at_safe_boundary,
    record_owner_decision,
};
pub use budget_proof::{
    BudgetProof, ComplexityEconomicsDelta, require_matched_budget_for_promotion,
    stamp_outcome_budget,
};
pub use evidence_sources::{
    EvidenceSource, SourcedEvidence, candidate_from_evidence, sourced_evidence,
    sourced_evidence_from_repeated_verifier_failure,
};
pub use intake::{
    IntakeOutcome, IntakeRequest, PreparedIntake, admit_prepared_intake, intake_from_evidence,
    intake_from_evidence_governed, prepare_intake, prepare_intake_for_owner,
};

pub use promotion_input::{
    AGENT_ORDER, CAUSAL_PROPERTY, ClosureBinding, MODULE_ID, PriorPromotionHistory,
    PromotionCandidate, PromotionGateEvidence, PromotionInputError, PromotionInputPolicy,
    PromotionPreparation, PromotionRequest, RUNTIME_LAYER, SOURCE_LAYER, prepare_promotion_input,
    promotion_evidence_digest,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementSurface {
    Memory,
    Skill,
    ToolProfile,
    Rule,
    PacketCompiler,
    Verifier,
    Scheduler,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateState {
    Candidate,
    ReplayPending,
    Evaluating,
    Rejected,
    Retired,
}

impl CandidateState {
    pub fn is_experimental(self) -> bool {
        matches!(
            self,
            Self::Candidate | Self::ReplayPending | Self::Evaluating
        )
    }
}

/// Owner-decision lifecycle of an improvement candidate (I12.24:36-37).
///
/// `CandidateState` above tracks the advisory pipeline position (candidate,
/// replay, evaluation); this enum tracks the named owner decision lifecycle
/// from proposal to terminal disposition. Both are stored on the candidate so
/// deduplication, briefs, and promotion gates observe the full lineage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementLifecycle {
    Proposed,
    Triaged,
    AcceptedForExperiment,
    Running,
    Supported,
    Narrowed,
    Rejected,
    RolledBack,
    Stale,
    Archived,
}

impl ImprovementLifecycle {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Supported
                | Self::Narrowed
                | Self::Rejected
                | Self::RolledBack
                | Self::Stale
                | Self::Archived
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplayPlan {
    pub fixed_replay_refs: Vec<String>,
    pub holdout_refs: Vec<String>,
    pub transfer_refs: Vec<String>,
    pub counter_metric_names: Vec<String>,
    pub verifier_refs: Vec<String>,
}

impl ReplayPlan {
    fn validate(&self) -> Result<(), ImprovementError> {
        require_refs(&self.fixed_replay_refs, "fixed_replay_refs")?;
        require_refs(&self.holdout_refs, "holdout_refs")?;
        require_refs(&self.verifier_refs, "verifier_refs")?;
        require_names(&self.counter_metric_names, "counter_metric_names")?;
        if self.transfer_refs.is_empty() {
            return Err(ImprovementError::MissingField("transfer_refs"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImprovementCandidate {
    pub candidate_id: String,
    pub project_id: String,
    pub target_surface: ImprovementSurface,
    pub proposed_change: String,
    pub applies_when: Vec<String>,
    pub does_not_apply_when: Vec<String>,
    pub source_trace_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub replay_plan: ReplayPlan,
    pub baseline_metrics: BTreeMap<String, f64>,
    pub state: CandidateState,
    /// I12.24 trigger: problem statement or metric that raised the candidate.
    pub trigger_problem_or_metric: String,
    /// I12.24 root-cause hypotheses carried with the candidate.
    pub root_cause_hypotheses: Vec<String>,
    /// I12.24 counter-metrics that must not regress.
    pub counter_metrics: BTreeMap<String, f64>,
    /// I12.24 validity scope of the proposed change.
    pub validity_scope: String,
    /// I12.24 owner and decision authority for this candidate.
    pub owner_and_decision_authority: String,
    /// I12.24 delivery target (work item / module / config path).
    pub delivery_target: String,
    /// I12.24 canary plan reference.
    pub canary_plan: String,
    /// I12.24 rollback reference.
    pub rollback: String,
    /// I12.24 stop condition for the experiment.
    pub stop_condition: String,
    /// I12.24 owner-decision lifecycle (proposed .. archived).
    pub lifecycle: ImprovementLifecycle,
    pub revision: u64,
    pub advisory_only: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl ImprovementCandidate {
    #[allow(
        clippy::too_many_arguments,
        reason = "this public constructor is the established candidate protocol façade"
    )]
    pub fn new(
        project_id: impl Into<String>,
        target_surface: ImprovementSurface,
        proposed_change: impl Into<String>,
        applies_when: Vec<String>,
        does_not_apply_when: Vec<String>,
        source_trace_refs: Vec<String>,
        evidence_refs: Vec<String>,
        replay_plan: ReplayPlan,
        baseline_metrics: BTreeMap<String, f64>,
    ) -> Result<Self, ImprovementError> {
        let now = OffsetDateTime::now_utc();
        let candidate = Self {
            candidate_id: Uuid::now_v7().to_string(),
            project_id: project_id.into(),
            target_surface,
            proposed_change: proposed_change.into(),
            applies_when,
            does_not_apply_when,
            source_trace_refs,
            evidence_refs,
            replay_plan,
            baseline_metrics,
            state: CandidateState::Candidate,
            trigger_problem_or_metric: String::new(),
            root_cause_hypotheses: Vec::new(),
            counter_metrics: BTreeMap::new(),
            validity_scope: String::new(),
            owner_and_decision_authority: String::new(),
            delivery_target: String::new(),
            canary_plan: String::new(),
            rollback: String::new(),
            stop_condition: String::new(),
            lifecycle: ImprovementLifecycle::Proposed,
            revision: 0,
            advisory_only: true,
            created_at: now,
            updated_at: now,
        };
        candidate.validate_base()?;
        Ok(candidate)
    }

    /// Attach the I12.24 decision fields after construction.
    ///
    /// All fields are public, so evidence adapters (see
    /// [`crate::evidence_sources::candidate_from_evidence`]) may also assign
    /// them directly; this helper keeps the assignment in one place.
    #[allow(clippy::too_many_arguments)]
    pub fn set_details(
        &mut self,
        trigger_problem_or_metric: impl Into<String>,
        root_cause_hypotheses: Vec<String>,
        counter_metrics: BTreeMap<String, f64>,
        validity_scope: impl Into<String>,
        owner_and_decision_authority: impl Into<String>,
        delivery_target: impl Into<String>,
        canary_plan: impl Into<String>,
        rollback: impl Into<String>,
        stop_condition: impl Into<String>,
    ) {
        self.trigger_problem_or_metric = trigger_problem_or_metric.into();
        self.root_cause_hypotheses = root_cause_hypotheses;
        self.counter_metrics = counter_metrics;
        self.validity_scope = validity_scope.into();
        self.owner_and_decision_authority = owner_and_decision_authority.into();
        self.delivery_target = delivery_target.into();
        self.canary_plan = canary_plan.into();
        self.rollback = rollback.into();
        self.stop_condition = stop_condition.into();
        self.updated_at = OffsetDateTime::now_utc();
    }

    pub fn validate(&self) -> Result<(), ImprovementError> {
        self.validate_base()?;
        non_empty(&self.trigger_problem_or_metric, "trigger_problem_or_metric")?;
        require_names(&self.root_cause_hypotheses, "root_cause_hypotheses")?;
        if self
            .counter_metrics
            .values()
            .any(|value| !value.is_finite())
        {
            return Err(ImprovementError::NonFiniteMetric);
        }
        non_empty(&self.validity_scope, "validity_scope")?;
        non_empty(
            &self.owner_and_decision_authority,
            "owner_and_decision_authority",
        )?;
        non_empty(&self.delivery_target, "delivery_target")?;
        non_empty(&self.canary_plan, "canary_plan")?;
        non_empty(&self.rollback, "rollback")?;
        non_empty(&self.stop_condition, "stop_condition")?;
        Ok(())
    }

    /// Base structural checks that hold for every candidate, including
    /// freshly constructed ones whose I12.24 decision details are attached
    /// later via [`Self::set_details`].
    fn validate_base(&self) -> Result<(), ImprovementError> {
        non_empty(&self.project_id, "project_id")?;
        non_empty(&self.proposed_change, "proposed_change")?;
        require_refs(&self.source_trace_refs, "source_trace_refs")?;
        require_refs(&self.evidence_refs, "evidence_refs")?;
        require_names(&self.applies_when, "applies_when")?;
        require_names(&self.does_not_apply_when, "does_not_apply_when")?;
        if self
            .applies_when
            .iter()
            .any(|rule| self.does_not_apply_when.contains(rule))
        {
            return Err(ImprovementError::ConflictingScopeRule);
        }
        self.replay_plan.validate()?;
        if !self.advisory_only {
            return Err(ImprovementError::SelfPromotionForbidden);
        }
        if self
            .baseline_metrics
            .values()
            .any(|value| !value.is_finite())
        {
            return Err(ImprovementError::NonFiniteMetric);
        }
        Ok(())
    }

    pub fn transition(
        &mut self,
        expected_revision: u64,
        next: CandidateState,
    ) -> Result<(), ImprovementError> {
        self.validate()?;
        if self.revision != expected_revision {
            return Err(ImprovementError::RevisionConflict {
                expected: expected_revision,
                actual: self.revision,
            });
        }
        let allowed = matches!(
            (self.state, next),
            (CandidateState::Candidate, CandidateState::ReplayPending)
                | (CandidateState::ReplayPending, CandidateState::Evaluating)
                | (CandidateState::Evaluating, CandidateState::Rejected)
                | (CandidateState::Evaluating, CandidateState::Retired)
                | (CandidateState::ReplayPending, CandidateState::Rejected)
                | (CandidateState::Candidate, CandidateState::Rejected)
                | (CandidateState::Rejected, CandidateState::Retired)
        );
        if !allowed || next == CandidateState::Candidate {
            return Err(ImprovementError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        self.revision += 1;
        self.updated_at = OffsetDateTime::now_utc();
        Ok(())
    }

    /// Move the owner-decision lifecycle forward (I12.24:36-37).
    ///
    /// Terminal lifecycles admit no outgoing transition. The advisory
    /// `CandidateState` machine is untouched; lifecycle transitions only
    /// refresh `updated_at` and never touch `revision`, so pipeline guards
    /// keep their exact semantics.
    pub fn transition_lifecycle(
        &mut self,
        next: ImprovementLifecycle,
    ) -> Result<(), ImprovementError> {
        let allowed = matches!(
            (self.lifecycle, next),
            (
                ImprovementLifecycle::Proposed,
                ImprovementLifecycle::Triaged
            ) | (
                ImprovementLifecycle::Triaged,
                ImprovementLifecycle::AcceptedForExperiment
            ) | (
                ImprovementLifecycle::AcceptedForExperiment,
                ImprovementLifecycle::Running
            ) | (
                ImprovementLifecycle::Running,
                ImprovementLifecycle::Supported
            ) | (
                ImprovementLifecycle::Running,
                ImprovementLifecycle::Narrowed
            ) | (
                ImprovementLifecycle::Running,
                ImprovementLifecycle::Rejected
            ) | (
                ImprovementLifecycle::Running,
                ImprovementLifecycle::RolledBack
            ) | (
                ImprovementLifecycle::Triaged,
                ImprovementLifecycle::Rejected
            ) | (
                ImprovementLifecycle::AcceptedForExperiment,
                ImprovementLifecycle::Rejected
            ) | (
                ImprovementLifecycle::Proposed,
                ImprovementLifecycle::Rejected
            ) | (ImprovementLifecycle::Proposed, ImprovementLifecycle::Stale)
                | (ImprovementLifecycle::Triaged, ImprovementLifecycle::Stale)
                | (
                    ImprovementLifecycle::Narrowed,
                    ImprovementLifecycle::Archived
                )
                | (
                    ImprovementLifecycle::Supported,
                    ImprovementLifecycle::Archived
                )
                | (
                    ImprovementLifecycle::Rejected,
                    ImprovementLifecycle::Archived
                )
                | (
                    ImprovementLifecycle::RolledBack,
                    ImprovementLifecycle::Archived
                )
                | (ImprovementLifecycle::Stale, ImprovementLifecycle::Archived)
        );
        if !allowed {
            return Err(ImprovementError::InvalidLifecycleTransition {
                from: self.lifecycle,
                to: next,
            });
        }
        self.lifecycle = next;
        self.updated_at = OffsetDateTime::now_utc();
        Ok(())
    }

    pub fn promotion_input(
        &self,
        outcome: OutcomeEvidence,
    ) -> Result<PromotionInput, ImprovementError> {
        self.validate()?;
        if !matches!(self.state, CandidateState::Evaluating) {
            return Err(ImprovementError::OutcomeRequiresEvaluation);
        }
        outcome.validate_for(self)?;
        let digest = promotion_digest(self, &outcome);
        Ok(PromotionInput {
            input_id: Uuid::now_v7().to_string(),
            candidate_id: self.candidate_id.clone(),
            project_id: self.project_id.clone(),
            candidate_revision: self.revision,
            target_surface: self.target_surface,
            outcome,
            evidence_digest: digest,
            direct_promotion: false,
            created_at: OffsetDateTime::now_utc(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OutcomeEvidence {
    pub outcome_ref: String,
    pub downstream_outcome_ref: String,
    pub verifier_ref: String,
    pub verifier_passed: bool,
    pub replay_refs: Vec<String>,
    pub holdout_refs: Vec<String>,
    pub transfer_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub observed_metrics: BTreeMap<String, f64>,
    pub counter_metrics: BTreeMap<String, f64>,
    /// Canonical budget-equivalence ledger binding (I12.24:76, I18.47).
    ///
    /// Names the single `BudgetEquivalenceLedger` record this outcome is
    /// compared under. Replay-only outcomes leave it empty and are refused
    /// promotion by [`OutcomeEvidence::validate_for`].
    pub budget_ledger_ref: String,
    /// Complexity-economics delta record (I12.24:76, I18.47).
    pub complexity_delta_ref: String,
    /// Whether the bound complexity-economics delta is conclusive.
    /// An inconclusive delta never promotes, however good replay looks.
    pub economics_conclusive: bool,
    /// Affected checks evaluated under the matched budget.
    pub affected_check_refs: Vec<String>,
    /// Matched-budget live shadow evidence refs.
    pub live_shadow_refs: Vec<String>,
    /// Matched-budget live canary evidence refs.
    pub live_canary_refs: Vec<String>,
    /// Delayed-harm visibility window reference.
    pub delayed_harm_window_ref: String,
}

impl OutcomeEvidence {
    fn validate_for(&self, candidate: &ImprovementCandidate) -> Result<(), ImprovementError> {
        non_empty(&self.outcome_ref, "outcome_ref")?;
        non_empty(&self.downstream_outcome_ref, "downstream_outcome_ref")?;
        non_empty(&self.verifier_ref, "verifier_ref")?;
        if !self.verifier_passed {
            return Err(ImprovementError::VerifierNotPassed);
        }
        require_refs(&self.replay_refs, "replay_refs")?;
        require_refs(&self.holdout_refs, "holdout_refs")?;
        require_refs(&self.transfer_refs, "transfer_refs")?;
        require_refs(&self.evidence_refs, "evidence_refs")?;
        if !self
            .replay_refs
            .iter()
            .all(|item| candidate.replay_plan.fixed_replay_refs.contains(item))
            || !self
                .holdout_refs
                .iter()
                .all(|item| candidate.replay_plan.holdout_refs.contains(item))
            || !self
                .transfer_refs
                .iter()
                .all(|item| candidate.replay_plan.transfer_refs.contains(item))
            || !candidate
                .replay_plan
                .verifier_refs
                .contains(&self.verifier_ref)
        {
            return Err(ImprovementError::OutcomeOutsidePlan);
        }
        if self
            .counter_metrics
            .keys()
            .any(|name| !candidate.replay_plan.counter_metric_names.contains(name))
        {
            return Err(ImprovementError::UnknownCounterMetric);
        }
        if self
            .observed_metrics
            .values()
            .chain(self.counter_metrics.values())
            .any(|value| !value.is_finite())
        {
            return Err(ImprovementError::NonFiniteMetric);
        }
        // I12.24:76 promotion gate: replay-only evidence never promotes.
        // A promotion-bound outcome must bind the single canonical
        // budget-equivalence ledger and a conclusive complexity-economics
        // delta, name the affected checks, carry matched-budget live
        // shadow/canary evidence, and expose delayed-harm visibility.
        if self.budget_ledger_ref.trim().is_empty() {
            return Err(ImprovementError::MissingBudgetProof);
        }
        if self.complexity_delta_ref.trim().is_empty() {
            return Err(ImprovementError::MissingBudgetProof);
        }
        if !self.economics_conclusive {
            return Err(ImprovementError::BudgetGateViolation(
                "inconclusive complexity-economics delta cannot promote",
            ));
        }
        if self.affected_check_refs.is_empty()
            || self
                .affected_check_refs
                .iter()
                .any(|value| value.trim().is_empty())
        {
            return Err(ImprovementError::BudgetGateViolation(
                "promotion requires affected checks under the matched budget",
            ));
        }
        if self.live_shadow_refs.is_empty() && self.live_canary_refs.is_empty() {
            return Err(ImprovementError::BudgetGateViolation(
                "promotion requires matched-budget live shadow or canary evidence",
            ));
        }
        if self.delayed_harm_window_ref.trim().is_empty() {
            return Err(ImprovementError::BudgetGateViolation(
                "promotion requires delayed-harm visibility",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PromotionInput {
    pub input_id: String,
    pub candidate_id: String,
    pub project_id: String,
    pub candidate_revision: u64,
    pub target_surface: ImprovementSurface,
    pub outcome: OutcomeEvidence,
    pub evidence_digest: String,
    pub direct_promotion: bool,
    pub created_at: OffsetDateTime,
}

impl PromotionInput {
    pub fn validate(&self) -> Result<(), ImprovementError> {
        if self.direct_promotion {
            return Err(ImprovementError::SelfPromotionForbidden);
        }
        non_empty(&self.evidence_digest, "evidence_digest")?;
        non_empty(&self.candidate_id, "candidate_id")?;
        non_empty(&self.project_id, "project_id")?;
        Ok(())
    }
}

fn promotion_digest(candidate: &ImprovementCandidate, outcome: &OutcomeEvidence) -> String {
    let mut hasher = Hasher::new();
    hasher.update(candidate.candidate_id.as_bytes());
    hasher.update(candidate.revision.to_string().as_bytes());
    hasher.update(outcome.outcome_ref.as_bytes());
    hasher.update(outcome.downstream_outcome_ref.as_bytes());
    hasher.update(outcome.verifier_ref.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn non_empty(value: &str, field: &'static str) -> Result<(), ImprovementError> {
    if value.trim().is_empty() {
        Err(ImprovementError::MissingField(field))
    } else {
        Ok(())
    }
}

fn require_refs(values: &[String], field: &'static str) -> Result<(), ImprovementError> {
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        Err(ImprovementError::MissingField(field))
    } else {
        Ok(())
    }
}

fn require_names(values: &[String], field: &'static str) -> Result<(), ImprovementError> {
    require_refs(values, field)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ImprovementError {
    #[error("required field is missing: {0}")]
    MissingField(&'static str),
    #[error("candidate scope contains both apply and exclusion rule")]
    ConflictingScopeRule,
    #[error("non-finite metric is not admissible")]
    NonFiniteMetric,
    #[error("candidate lifecycle revision conflict: expected {expected}, actual {actual}")]
    RevisionConflict { expected: u64, actual: u64 },
    #[error("invalid candidate lifecycle transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: CandidateState,
        to: CandidateState,
    },
    #[error("improvement candidates cannot self-promote")]
    SelfPromotionForbidden,
    #[error("outcome input requires an evaluating candidate")]
    OutcomeRequiresEvaluation,
    #[error("verifier outcome did not pass")]
    VerifierNotPassed,
    #[error("outcome references data outside the candidate replay plan")]
    OutcomeOutsidePlan,
    #[error("outcome contains an undeclared counter metric")]
    UnknownCounterMetric,
    #[error("invalid owner lifecycle transition from {from:?} to {to:?}")]
    InvalidLifecycleTransition {
        from: ImprovementLifecycle,
        to: ImprovementLifecycle,
    },
    #[error("brief requires an active Main Agent or Human at a safe boundary")]
    UnsafeBoundary,
    #[error("application-class boundary refused the change")]
    ApplicationClassViolation,
    #[error("promotion requires a bound budget-equivalence and economics record")]
    MissingBudgetProof,
    #[error("budget gate refused promotion: {0}")]
    BudgetGateViolation(&'static str),
    #[error("backlog refused intake: {0}")]
    BacklogRefused(String),
}
