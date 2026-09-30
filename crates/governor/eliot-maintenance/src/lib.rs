//! G-19 deterministic maintenance trigger evaluation and job lifecycle.
//!
//! This crate owns maintenance policy decisions and the bounded Durable Job
//! state machine described by Implementation I14.22.  It does not run model
//! calls, mutate canonical state, launch processes, or become a second
//! scheduler.  Execution owners consume the typed decision and persist job
//! revisions through [`MaintenanceStateStore`].
//!
//! Unknown external outcomes remain attached to the exact job identity and
//! block blind retries until a caller supplies a reconciliation disposition.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeSet;
use std::fmt;

use eliot_contracts::{
    ContractIdentity, ContractVersion, StateFence, contract_identity as make_contract_identity,
};
use eliot_runtime_contracts::{LeaseState, RuntimeLease};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod end_of_activity;
mod improvement_admission;
pub mod improvement_pipeline;
mod outcome_observation;
pub mod result_obligation;
mod trigger_intake;

pub use outcome_observation::{
    AdmittedObservationReceipt, ExpectedOutcomeObservation, MaintenanceOutcomeDisposition,
    OBSERVATION_GAP_PROFILE, OBSERVATION_GAP_REASON, OUTCOME_OBSERVATION_OWNER,
    OUTCOME_OBSERVATION_RESOLUTION, ObservedOutcomeObservation, OutcomeObservationCoverage,
    OutstandingOutcome, OutstandingOutcomeObligation, RefusedReceiptStatus,
    admit_observation_delivery, outcome_observation_coverage, outcome_observation_disposition,
    record_observation_gap,
};

pub use result_obligation::{
    FOLLOW_UP_PENDING_REASON, MAINTENANCE_OBLIGATION_CONTRACT_VERSION, MAX_RESULT_OBLIGATIONS,
    MaintenanceResultObligation, NOT_APPLICABLE_REASON, SOURCE_EVALUATION_METHOD,
    SOURCE_EVALUATION_METHOD_REVISION, maintenance_observation_record,
};

pub use end_of_activity::{
    ActivationScopeReference, AssessmentRecordReference, AssessmentSourceCoverage,
    AssessmentSourceGap, AssessmentSourceRecord, AssessmentSourceSnapshot, ClosedActivityReference,
    END_OF_ACTIVITY_ASSESSMENT_CONTRACT_NAME, END_OF_ACTIVITY_ASSESSMENT_VERSION,
    EligibleServiceSafeRoute, EndOfActivityAssessment, EndOfActivityAssessmentDecision,
    EndOfActivityMaintenanceAssessment, EndOfActivityMaintenanceAssessmentOutcome,
    EndOfActivityMaintenanceAssessmentRequest, EndOfActivityMaintenanceAssessmentValidationError,
    MaintenanceDebtReference, MaintenanceDuePolicyReference, UserSessionRequiredWorkReference,
    assess_end_of_activity, end_of_activity_assessment_contract_identity,
};

pub use improvement_admission::{
    IMPROVEMENT_ADMISSION_AUTHORITY, IMPROVEMENT_CANDIDATE_BOUNDS,
    IMPROVEMENT_CANDIDATE_BOUNDS_REVISION, IMPROVEMENT_CLOSURE_MODULE, IMPROVEMENT_PRODUCT_PULSE,
    IMPROVEMENT_PROMOTION_MODULE, IMPROVEMENT_PROOF_CEILING, IMPROVEMENT_REQUESTED_EFFECT,
    ImprovementAdmissionDecision, ImprovementAdmissionError, ImprovementAdmissionPolicy,
    ImprovementBlockCause, ImprovementBlockRemedy, ImprovementBoundError, ImprovementCandidateView,
    ImprovementEvidenceView, ImprovementPulseOutcome, ImprovementRejectCause,
    ImprovementSurfaceBound, ImprovementTargetSurface, admit_improvement_candidate,
    improvement_admission_policy, resolve_candidate_surface_bound,
};
pub use improvement_pipeline::{
    ActivationEvidence, AdmittedResourceCeiling, AdmittedScopeRefinement, ExperimentPlan,
    IMPROVEMENT_EFFECT_CEILING, IMPROVEMENT_LEGACY_DIGEST_ALGORITHM,
    IMPROVEMENT_MATERIAL_EQUALITY_DOMAIN, IMPROVEMENT_MATERIAL_EQUALITY_ENCODING_VERSION,
    IMPROVEMENT_MAX_COMMITMENT_BYTES, IMPROVEMENT_MAX_REFERENCE_BYTES, IMPROVEMENT_MAX_SET_MEMBERS,
    IMPROVEMENT_MAX_TEXT_BYTES, IMPROVEMENT_PIPELINE_OWNER, IMPROVEMENT_PIPELINE_WIRE_REVISION,
    IMPROVEMENT_PROPOSAL_COMMITMENT_DOMAIN, IMPROVEMENT_PROPOSAL_DIGEST_ALGORITHM,
    IMPROVEMENT_PROPOSAL_ENCODING_VERSION, IMPROVEMENT_RISK_CEILING_BOUNDED,
    IMPROVEMENT_RISK_CEILING_ENCODING_VERSION, ImprovementCanaryHandoff,
    ImprovementCandidateIngress, ImprovementCurrentProposal, ImprovementEvidenceExecution,
    ImprovementMaterialEquality, ImprovementOperation, ImprovementPipelineInputs,
    ImprovementProposal, ImprovementProposalCommitmentEnvelope, ImprovementReplayAssessment,
    ImprovementTerminalDisposition, ImprovementUnknownEffect, ImprovementUnknownEffectIdentity,
    KERNEL_CANARY_OWNER, MechanismDeclaration, OP_ADMIT, OP_CANARY_ACTIVATE, OP_CANDIDATE_INGRESS,
    OP_EVALUATE, OP_EXECUTE_EXPERIMENT, OP_MEASURE, OP_PROMOTE, OP_PROPOSE, OP_ROLLBACK,
    PipelineError, ProposalCommitment, RetainedImprovementProposal, RollbackContract, TESTD_OWNER,
    UnboundOwnerOutcome, UncheckedRecordIdentity, UncheckedWireRevision, UnestablishedPriorCause,
    VERIFIER_OWNER_FAMILY, assess_improvement_replay, check_checked_record_identity,
    check_handoff_wire_revision, compare_improvement_commitments, improvement_retry_permitted,
    ingest_improvement_candidate, proposal_digest, reconcile_retained_unknown_effect,
    reconcile_unknown_activation, retained_improvement_completion,
    run_improvement_candidate_pipeline,
};
pub use trigger_intake::{
    MaintenanceTriggerIntake, TriggerIntakeClasses, TriggerIntakeOperation, TriggerIntakePayload,
    TriggerIntakePosition, TriggerIntakeRequest, TriggerIntakeRouting, TriggerIntakeSourceEvent,
    TriggerIntakeWindow, derive_trigger_intake,
};

/// Stable wire name for the maintenance governor contract.
pub const CONTRACT_NAME: &str = "eliot.governor.maintenance";
/// Current wire revision for the maintenance governor contract.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Stable maintenance family registered by I14.22.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MaintenanceFamily {
    /// Backup and restore rehearsal without restoring active authority.
    BackupRestoreRehearsal,
    /// Blob reachability and garbage-collection analysis.
    BlobGcReachability,
    /// Outbox and receipt reconciliation.
    OutboxReceiptReconciliation,
    /// Projection and index rebuild.
    ProjectionIndexRebuild,
    /// Cue, concept and graph maintenance.
    CueConceptGraph,
    /// Dreamer curation job.
    DreamerCuration,
    /// Calibration or understanding examination.
    CalibrationUnderstanding,
    /// Integration and capability survey.
    IntegrationCapabilitySurvey,
    /// Security or dependency scan.
    SecurityDependencyScan,
    /// Derived-index differential rebuild.
    DerivedIndexRebuild,
    /// `SessionEpisode` cursor and retrieval maintenance.
    SessionEpisodeRetrieval,
    /// Grant and disclosure closure reconciliation.
    GrantDisclosureClosure,
    /// Donor or conformance audit.
    DonorConformance,
    /// Self-quality and maintenance-debt review.
    SelfQualityDebt,
    /// External research exchange cleanup/requalification.
    ResearchExchangeCleanup,
}

impl fmt::Display for MaintenanceFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BackupRestoreRehearsal => "BACKUP_RESTORE_REHEARSAL",
            Self::BlobGcReachability => "BLOB_GC_REACHABILITY",
            Self::OutboxReceiptReconciliation => "OUTBOX_RECEIPT_RECONCILIATION",
            Self::ProjectionIndexRebuild => "PROJECTION_INDEX_REBUILD",
            Self::CueConceptGraph => "CUE_CONCEPT_GRAPH",
            Self::DreamerCuration => "DREAMER_CURATION",
            Self::CalibrationUnderstanding => "CALIBRATION_UNDERSTANDING",
            Self::IntegrationCapabilitySurvey => "INTEGRATION_CAPABILITY_SURVEY",
            Self::SecurityDependencyScan => "SECURITY_DEPENDENCY_SCAN",
            Self::DerivedIndexRebuild => "DERIVED_INDEX_REBUILD",
            Self::SessionEpisodeRetrieval => "SESSION_EPISODE_RETRIEVAL",
            Self::GrantDisclosureClosure => "GRANT_DISCLOSURE_CLOSURE",
            Self::DonorConformance => "DONOR_CONFORMANCE",
            Self::SelfQualityDebt => "SELF_QUALITY_DEBT",
            Self::ResearchExchangeCleanup => "RESEARCH_EXCHANGE_CLEANUP",
        })
    }
}

/// Human-owned automation mode for one maintenance family.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MaintenanceAutomationMode {
    /// No automatic job or proactive recommendation, except safety recovery.
    Off,
    /// Emit one deduplicated Human-board recommendation.
    SuggestOnly,
    /// Start only after an explicit request.
    Manual,
    /// Start only when no conflicting interactive work exists.
    IdleOnly,
    /// Start only inside an approved schedule window.
    Scheduled,
    /// Maintain a bounded admitted backlog.
    ContinuousBounded,
}

/// Origin of a deterministic maintenance trigger.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MaintenanceTrigger {
    /// Explicit Human UI/CLI request.
    Human,
    /// Accepted Dreamer maintenance plan candidate.
    Dreamer,
    /// Watchdog or Doctor recovery/problem recipe.
    WatchdogProblem,
    /// First-run or onboarding recommendation.
    Onboarding,
    /// Approved idle/scheduled policy.
    Policy,
    /// Installation, update or migration transaction.
    Installation,
}

/// Decision produced by the sole maintenance trigger evaluator.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AutomationDecision {
    /// Admit a bounded Durable Job request.
    Start,
    /// Preserve one Human-board recommendation.
    Suggest,
    /// Preserve the trigger for a later eligible window.
    Defer,
    /// An equivalent active request already owns this work.
    SuppressDuplicate,
    /// Policy, route, budget or session requirements deny execution.
    Block,
    /// Escalate to a Human or recovery owner.
    Escalate,
}

/// Stable reason for an automation decision.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionReason {
    /// All policy, route, budget, schedule, and session gates permit execution.
    Eligible,
    /// Background automation is disabled by policy.
    AutomationOff,
    /// Policy permits a suggestion but not autonomous execution.
    SuggestOnly,
    /// Policy requires a direct user request before execution.
    ExplicitRequestRequired,
    /// The governed system is not currently idle.
    NotIdle,
    /// The current time is outside the configured maintenance schedule.
    OutsideSchedule,
    /// No eligible execution route is available.
    RouteUnavailable,
    /// The required maintenance budget is unavailable.
    BudgetUnavailable,
    /// Execution requires an active user session.
    UserSessionRequired,
    /// An equivalent maintenance job is already active.
    DuplicateActiveJob,
    /// The trigger or its authority has expired.
    Expired,
    /// Safety policy requires recovery handling instead of normal execution.
    SafetyRecovery,
}

/// Inputs observed by the deterministic trigger evaluator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct MaintenanceTriggerInput {
    /// Trigger identity used for deduplication and evidence binding.
    pub trigger_id: String,
    /// Opaque evidence references supporting the trigger.
    pub evidence_refs: Vec<String>,
    /// Maintenance family selected by policy/trigger ownership.
    pub family: MaintenanceFamily,
    /// Scope that the job may affect.
    pub scope_ref: String,
    /// Applicable Human-owned automation mode.
    pub mode: MaintenanceAutomationMode,
    /// Trigger origin.
    pub trigger: MaintenanceTrigger,
    /// Whether the caller explicitly requested execution.
    pub explicit_request: bool,
    /// Whether conflicting interactive work is absent.
    pub idle: bool,
    /// Whether the current time is inside the approved window.
    pub scheduled_window: bool,
    /// Whether a service-safe execution route is available.
    pub route_available: bool,
    /// Whether an admitted cost/quota budget remains.
    pub budget_available: bool,
    /// Whether an authenticated User Broker/session is available.
    pub user_session_available: bool,
    /// Whether this job requires a user session.
    pub user_session_required: bool,
    /// Safety/recovery obligations may bypass ordinary automation mode.
    pub safety_required: bool,
    /// Current wall-clock observation used only for expiry comparison.
    pub now_ms: i64,
    /// Optional trigger expiry.
    pub expires_at_ms: Option<i64>,
    /// Existing active job identity for this family/scope, if known.
    pub active_job_id: Option<String>,
}

impl MaintenanceTriggerInput {
    /// Validates bounded identities and policy dimensions.
    pub fn validate(&self) -> Result<(), MaintenanceError> {
        text(&self.trigger_id, "trigger_id")?;
        text(&self.scope_ref, "scope_ref")?;
        nonempty(&self.evidence_refs, "evidence_refs")?;
        unique_text(&self.evidence_refs, "evidence_refs")?;
        if let Some(expiry) = self.expires_at_ms
            && expiry <= self.now_ms
        {
            return Err(MaintenanceError::Expired);
        }
        if let Some(active) = &self.active_job_id {
            text(active, "active_job_id")?;
        }
        Ok(())
    }
}

/// Inspectable output of trigger evaluation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationTriggerDecision {
    /// Trigger identity.
    pub trigger_id: String,
    /// Origin of the observation that produced this trigger.
    ///
    /// Carried verbatim from [`MaintenanceTriggerInput::trigger`], which is the
    /// caller-observed origin of that trigger: this evaluator copies the
    /// observed value and never selects, widens, or defaults one, so a decision
    /// cannot claim an origin the evaluated trigger did not carry.
    ///
    /// The field exists because I12.24:54 closes the trigger set with
    /// "Dreamer/Watchdog/Concilium suggestion": a downstream classifier has to
    /// read which kind of observation produced a decision, and the family alone
    /// cannot say that. `MaintenanceTrigger` names the origins this contract
    /// expresses today — a Concilium suggestion is not one of them yet, so this
    /// field widens no vocabulary and asserts none.
    pub trigger: MaintenanceTrigger,
    /// Selected family and scope.
    pub family: MaintenanceFamily,
    /// Affected scope.
    pub scope_ref: String,
    /// Deterministic action.
    pub decision: AutomationDecision,
    /// Stable reason for the action.
    pub reason: DecisionReason,
    /// Whether one job may be scheduled from this decision.
    pub admits_job: bool,
    /// Optional existing or newly allocated job identity.
    pub durable_job_ref: Option<String>,
}

/// Checkpoint for resumable maintenance work.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceCheckpoint {
    /// Stable stage identity.
    pub stage_ref: String,
    /// Opaque cursor into the owned subsystem.
    pub cursor_ref: Option<String>,
    /// Number of units processed in this job.
    pub processed_units: u64,
    /// Optional bounded estimate of total units.
    pub total_units: Option<u64>,
    /// Digest of the immutable input/fence at checkpoint time.
    pub input_digest: String,
}

impl MaintenanceCheckpoint {
    /// Validates checkpoint identity, progress and digest reference.
    pub fn validate(&self) -> Result<(), MaintenanceError> {
        text(&self.stage_ref, "checkpoint.stage_ref")?;
        text(&self.input_digest, "checkpoint.input_digest")?;
        if self
            .total_units
            .is_some_and(|total| self.processed_units > total)
        {
            return Err(MaintenanceError::InvalidField("checkpoint.processed_units"));
        }
        if let Some(cursor) = &self.cursor_ref {
            text(cursor, "checkpoint.cursor_ref")?;
        }
        Ok(())
    }
}

/// Durable maintenance job lifecycle.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MaintenanceJobState {
    /// Decision admitted a new job but execution has not started.
    Admitted,
    /// Execution owner is running one bounded attempt.
    Running,
    /// Execution owner persisted progress and released its active slot.
    Checkpointed,
    /// Job intentionally waits for an eligible route/window/session.
    Deferred,
    /// Job was cancelled before an irreversible effect.
    Cancelled,
    /// Job completed with a verified terminal receipt.
    Completed,
    /// Job failed with a typed disposition.
    Failed,
    /// External outcome is unresolved; blind retry is forbidden.
    UnknownOutcome,
    /// Forward repair or rollback is required before the scope can proceed.
    RollbackRequired,
}

impl fmt::Display for MaintenanceJobState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Admitted => "ADMITTED",
            Self::Running => "RUNNING",
            Self::Checkpointed => "CHECKPOINTED",
            Self::Deferred => "DEFERRED",
            Self::Cancelled => "CANCELLED",
            Self::Completed => "COMPLETED",
            Self::Failed => "FAILED",
            Self::UnknownOutcome => "UNKNOWN_OUTCOME",
            Self::RollbackRequired => "ROLLBACK_REQUIRED",
        })
    }
}

/// One immutable maintenance job identity and mutable lifecycle revision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceJob {
    /// Durable idempotency identity.
    pub job_id: String,
    /// Trigger identity that admitted this job.
    pub trigger_id: String,
    /// Identity of the exact source decision that admitted this job.
    ///
    /// Carried on the job because every later source result names the decision
    /// that produced it. Derived from the decision's own stable identity, so the
    /// decision a result is attributed to is the decision that admitted the
    /// work rather than a reference restated by the transition.
    pub decision_ref: String,
    /// Registered maintenance family.
    pub family: MaintenanceFamily,
    /// Narrow affected scope.
    pub scope_ref: String,
    /// State fence captured at admission.
    pub state_fence: StateFence,
    /// Runtime lease required while active.
    pub runtime_lease: RuntimeLease,
    /// Current job lifecycle state.
    pub state: MaintenanceJobState,
    /// Current bounded checkpoint.
    pub checkpoint: Option<MaintenanceCheckpoint>,
    /// Maximum attempts admitted by policy.
    pub max_attempts: u32,
    /// Attempts already begun.
    pub attempts: u32,
    /// Opaque budget reference.
    pub budget_ref: String,
    /// Latest evidence or terminal receipt reference.
    pub outcome_ref: Option<String>,
    /// Whether execution requires an authenticated user session.
    pub user_session_required: bool,
    /// Append-only result-to-observation obligations this job has produced.
    ///
    /// Persisted in the same `save` as the lifecycle revision that produced
    /// them, so the job state and the canonical observation it owes become
    /// durable together or in neither. The list is append-only: a reconciliation
    /// adds a linked entry and never rewrites or removes the earlier one, so the
    /// original uncertainty stays visible next to its resolution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub result_obligations: Vec<MaintenanceResultObligation>,
}

impl MaintenanceJob {
    /// Validates identity, fence, lease, attempt budget and checkpoint.
    pub fn validate(&self) -> Result<(), MaintenanceError> {
        text(&self.job_id, "job_id")?;
        text(&self.trigger_id, "trigger_id")?;
        text(&self.decision_ref, "decision_ref")?;
        text(&self.scope_ref, "scope_ref")?;
        text(&self.budget_ref, "budget_ref")?;
        if self.result_obligations.len() > result_obligation::MAX_RESULT_OBLIGATIONS {
            return Err(MaintenanceError::InvalidField("job.result_obligations"));
        }
        // The append chain is checked as a chain, not as a set: an obligation's
        // predecessor must be the entry before it, so a dropped or reordered
        // obligation is refused instead of silently orphaning the uncertainty it
        // was resolving.
        for (index, obligation) in self.result_obligations.iter().enumerate() {
            obligation.validate()?;
            let expected_predecessor = index
                .checked_sub(1)
                .and_then(|prior| self.result_obligations.get(prior))
                .map(|prior| prior.publication_id.as_str());
            if obligation.predecessor_obligation_ref.as_deref() != expected_predecessor {
                return Err(MaintenanceError::InvalidField(
                    "job.result_obligations.predecessor_obligation_ref",
                ));
            }
            // Every obligation must name the job, trigger, decision, family and
            // scope this revision actually has. An obligation that disagrees with
            // its own job would publish a result under another job's identity.
            if obligation.job_ref.as_deref() != Some(self.job_id.as_str())
                || obligation.source_trigger_ref != self.trigger_id
                || obligation.decision_ref != self.decision_ref
                || obligation.family != self.family
                || obligation.scope_ref != self.scope_ref
            {
                return Err(MaintenanceError::InvalidField("job.result_obligations"));
            }
        }
        self.state_fence
            .validate()
            .map_err(|_| MaintenanceError::FenceMismatch)?;
        self.runtime_lease
            .validate()
            .map_err(|_| MaintenanceError::LeaseInvalid)?;
        if self.runtime_lease.state != LeaseState::Active {
            return Err(MaintenanceError::LeaseInactive);
        }
        if self.runtime_lease.state_fence != self.state_fence {
            return Err(MaintenanceError::FenceMismatch);
        }
        if self.max_attempts == 0 || self.attempts > self.max_attempts {
            return Err(MaintenanceError::InvalidField("attempt_budget"));
        }
        if let Some(checkpoint) = &self.checkpoint {
            checkpoint.validate()?;
        }
        if let Some(outcome) = &self.outcome_ref {
            text(outcome, "outcome_ref")?;
        }
        Ok(())
    }

    fn transition(&self, next: MaintenanceJobState) -> Result<Self, MaintenanceError> {
        let legal = matches!(
            (self.state, next),
            (
                MaintenanceJobState::Admitted,
                MaintenanceJobState::Running
                    | MaintenanceJobState::Deferred
                    | MaintenanceJobState::Cancelled
            ) | (
                MaintenanceJobState::Running,
                MaintenanceJobState::Checkpointed
                    | MaintenanceJobState::Completed
                    | MaintenanceJobState::Failed
                    | MaintenanceJobState::UnknownOutcome
                    | MaintenanceJobState::Cancelled
            ) | (
                MaintenanceJobState::Checkpointed,
                MaintenanceJobState::Running
                    | MaintenanceJobState::Deferred
                    | MaintenanceJobState::Completed
                    | MaintenanceJobState::Cancelled
                    | MaintenanceJobState::UnknownOutcome
            ) | (
                MaintenanceJobState::Deferred,
                MaintenanceJobState::Running | MaintenanceJobState::Cancelled
            ) | (
                MaintenanceJobState::UnknownOutcome,
                MaintenanceJobState::Completed
                    | MaintenanceJobState::RollbackRequired
                    | MaintenanceJobState::Failed
            )
        );
        if !legal {
            return Err(MaintenanceError::IllegalTransition {
                from: self.state,
                to: next,
            });
        }
        Ok(Self {
            state: next,
            ..self.clone()
        })
    }
}

/// The stable identity of the source decision that produced one maintenance
/// result.
///
/// Derived from the decision's own stable identity — its trigger, family, scope,
/// action and reason — rather than assigned by a caller, so the decision a
/// result is attributed to is the decision that was actually evaluated. It is a
/// pure function of that decision, so re-evaluating the same decision yields the
/// same reference and a changed decision yields a different one.
#[must_use]
pub fn maintenance_decision_ref(decision: &AutomationTriggerDecision) -> String {
    format!(
        "maintenance-decision:{}:{}:{}:{}:{}",
        decision.family,
        decision.trigger_id,
        decision.scope_ref,
        match decision.decision {
            AutomationDecision::Start => "START",
            AutomationDecision::Suggest => "SUGGEST",
            AutomationDecision::Defer => "DEFER",
            AutomationDecision::SuppressDuplicate => "SUPPRESS_DUPLICATE",
            AutomationDecision::Block => "BLOCK",
            AutomationDecision::Escalate => "ESCALATE",
        },
        match decision.reason {
            DecisionReason::Eligible => "ELIGIBLE",
            DecisionReason::AutomationOff => "AUTOMATION_OFF",
            DecisionReason::SuggestOnly => "SUGGEST_ONLY",
            DecisionReason::ExplicitRequestRequired => "EXPLICIT_REQUEST_REQUIRED",
            DecisionReason::NotIdle => "NOT_IDLE",
            DecisionReason::OutsideSchedule => "OUTSIDE_SCHEDULE",
            DecisionReason::RouteUnavailable => "ROUTE_UNAVAILABLE",
            DecisionReason::BudgetUnavailable => "BUDGET_UNAVAILABLE",
            DecisionReason::UserSessionRequired => "USER_SESSION_REQUIRED",
            DecisionReason::DuplicateActiveJob => "DUPLICATE_ACTIVE_JOB",
            DecisionReason::Expired => "EXPIRED",
            DecisionReason::SafetyRecovery => "SAFETY_RECOVERY",
        }
    )
}

/// The result-to-observation obligation a non-execution decision owes.
///
/// A decision that starts no execution attempt is still a source result: it is
/// the answer the maintenance owner gave, and it is in coverage. This records the
/// real decision reference and the absent execution evidence, so a deferral, a
/// block, a suggestion, an escalation and a duplicate suppression each publish a
/// bound observation instead of a fabricated failed job — and instead of being
/// reported only through a diagnostic logger.
///
/// The durable job identity is carried when the decision names one (a
/// suppressed duplicate's existing job), because that job is the real owner of
/// the work the decision declined to duplicate. The execution outcome is
/// [`NotAttempted`](eliot_observation_contracts::MaintenanceExecutionOutcome::NotAttempted):
/// this decision began no attempt, so it carries no attempt, receipt, effect,
/// checkpoint or reconciliation reference.
#[must_use]
pub fn decision_result_obligation(
    decision: &AutomationTriggerDecision,
    state_fence: &StateFence,
) -> MaintenanceResultObligation {
    let decision_ref = maintenance_decision_ref(decision);
    let publication_id = format!("maintenance-result:{decision_ref}:not-attempted");
    MaintenanceResultObligation {
        contract_version: result_obligation::MAINTENANCE_OBLIGATION_CONTRACT_VERSION,
        publication_id: publication_id.clone(),
        source_trigger_ref: decision.trigger_id.clone(),
        decision_ref,
        family: decision.family,
        scope_ref: decision.scope_ref.clone(),
        job_ref: decision.durable_job_ref.clone(),
        attempt_ref: None,
        execution_receipt_ref: None,
        state_fence: state_fence.clone(),
        source_outcome_revision: "NOT_ATTEMPTED:0".to_owned(),
        actual_effect_refs: Vec::new(),
        checkpoint_refs: Vec::new(),
        reconciliation_refs: Vec::new(),
        execution_outcome: eliot_observation_contracts::MaintenanceExecutionOutcome::NotAttempted,
        delivery: eliot_observation_contracts::MaintenanceDeliveryState::Pending {
            obligation_ref: publication_id,
        },
        evaluation_revision: 1,
        predecessor_obligation_ref: None,
    }
}

/// Evidence-backed resolution of an unknown external outcome.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReconciliationDisposition {
    /// The provider proves the effect did not happen; same identity may retry.
    ProvenNoEffect,
    /// The provider proves the effect happened and supplies a terminal receipt.
    ProvenApplied,
    /// The provider remains unable to establish what happened.
    StillUnknown,
}

/// Typed maintenance failures and fail-closed lifecycle rejections.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MaintenanceError {
    /// A required field is malformed.
    #[error("invalid maintenance field: {0}")]
    InvalidField(&'static str),
    /// A required collection is empty.
    #[error("{0} must not be empty")]
    Empty(&'static str),
    /// A duplicate job/trigger identity was supplied.
    #[error("maintenance identity conflict")]
    IdentityConflict,
    /// The state fence is stale or inconsistent.
    #[error("maintenance state fence mismatch")]
    FenceMismatch,
    /// The runtime lease is malformed.
    #[error("maintenance runtime lease is invalid")]
    LeaseInvalid,
    /// The runtime lease is not active.
    #[error("maintenance runtime lease is not active")]
    LeaseInactive,
    /// The trigger expired before admission.
    #[error("maintenance trigger expired")]
    Expired,
    /// A required user-session route is unavailable.
    #[error("maintenance requires an authenticated user session")]
    UserSessionUnavailable,
    /// A lifecycle transition is not admitted.
    #[error("illegal maintenance transition from {from} to {to}")]
    IllegalTransition {
        /// Current state.
        from: MaintenanceJobState,
        /// Requested state.
        to: MaintenanceJobState,
    },
    /// Unknown outcome cannot be retried without reconciliation.
    #[error("maintenance outcome is unknown and requires reconciliation")]
    UnknownRequiresReconciliation,
    /// Attempt budget is exhausted.
    #[error("maintenance attempt budget exhausted")]
    BudgetExhausted,
    /// Persistence port rejected a revision.
    #[error("maintenance state store: {0}")]
    Store(String),
}

/// Persistence seam for durable maintenance job revisions.
pub trait MaintenanceStateStore {
    /// Loads the latest revision for an exact job identity.
    fn load(&mut self, job_id: &str) -> Result<Option<MaintenanceJob>, MaintenanceError>;
    /// Persists one validated job revision atomically for its identity.
    fn save(&mut self, job: &MaintenanceJob) -> Result<(), MaintenanceError>;
}

/// Proves one durable job intent from the owner's own committed bytes (I14.22,
/// issue #1694 W4).
///
/// A transport acknowledgement is never commit proof: the caller presents the
/// intent it saved (`saved`) and the committed revision the durable owner
/// served back (`committed`), and this function proves the read-back binds
/// that exact intent. Both revisions are validated — the original first, so a
/// malformed intent is refused as its own defect rather than as a read-back
/// mismatch — and the committed revision must carry the same nonblank
/// `job_id` and `trigger_id`. Anything else (a substituted job, a job for
/// another trigger, unvalidated bytes) is refused and the trigger stays
/// retained and unacknowledged; receipt absence or mismatch is never proof of
/// non-commit, so the caller reconciles through the owning read path instead
/// of retrying the effect blindly.
///
/// # Errors
///
/// Returns the owner's own [`MaintenanceError`] when either revision is
/// invalid, and [`MaintenanceError::InvalidField`] naming `job_ref` when the
/// committed read-back does not bind the saved intent's job and trigger
/// identity.
pub fn prove_job_intent_durable(
    saved: &MaintenanceJob,
    committed: &MaintenanceJob,
) -> Result<(), MaintenanceError> {
    saved.validate()?;
    committed.validate()?;
    if committed.job_id != saved.job_id || committed.trigger_id != saved.trigger_id {
        return Err(MaintenanceError::InvalidField("job_ref"));
    }
    Ok(())
}

/// Deterministic maintenance decision and job owner.
pub struct MaintenanceController<S> {
    store: S,
}

impl<S: MaintenanceStateStore> MaintenanceController<S> {
    /// Creates a controller over the caller-owned durable maintenance store.
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    /// The maintenance (`G-19`) improvement admission policy record for one
    /// exact operation, including the per-surface active-candidate bounds
    /// I12.24:297 requires.
    ///
    /// This is the existing maintenance admission path, not a second one: the
    /// same `G-19` owner that decides improvement candidate admission publishes
    /// the bound it decides, so a caller enforcing a backlog bound reads the
    /// owner's own record rather than choosing a number. Pure — no clock, I/O,
    /// store read, or live query — and it adds no scheduler, root record, or
    /// second policy source (I12.24:314).
    #[must_use]
    pub fn improvement_admission_policy(
        &self,
        operation_ref: &str,
        idempotency_key: &str,
        rollback_owner_id: &str,
    ) -> ImprovementAdmissionPolicy {
        improvement_admission_policy(operation_ref, idempotency_key, rollback_owner_id)
    }

    /// Evaluates one trigger without scheduling or executing a job.
    pub fn evaluate_trigger(
        &self,
        input: &MaintenanceTriggerInput,
    ) -> Result<AutomationTriggerDecision, MaintenanceError> {
        input.validate()?;
        if let Some(active) = &input.active_job_id {
            return Ok(AutomationTriggerDecision {
                trigger_id: input.trigger_id.clone(),
                // The observed origin travels with the suppressed decision too:
                // duplicate suppression says an equivalent request already owns
                // this work, it does not change where the trigger came from.
                trigger: input.trigger,
                family: input.family,
                scope_ref: input.scope_ref.clone(),
                decision: AutomationDecision::SuppressDuplicate,
                reason: DecisionReason::DuplicateActiveJob,
                admits_job: false,
                durable_job_ref: Some(active.clone()),
            });
        }
        if input.safety_required {
            // This input is only a caller-projected flag; the maintenance
            // evaluator does not own the registered protected-obligation
            // authority needed to admit safety work. Preserve `off` without a
            // proactive recommendation, and otherwise defer to the protected
            // recovery owner instead of letting the flag authorize effects.
            let (decision, reason) = if input.mode == MaintenanceAutomationMode::Off {
                (AutomationDecision::Block, DecisionReason::AutomationOff)
            } else {
                (AutomationDecision::Defer, DecisionReason::SafetyRecovery)
            };
            return Ok(Self::decision(input, decision, reason));
        }
        let (decision, reason) = match input.mode {
            MaintenanceAutomationMode::Off => {
                (AutomationDecision::Block, DecisionReason::AutomationOff)
            }
            MaintenanceAutomationMode::SuggestOnly => {
                (AutomationDecision::Suggest, DecisionReason::SuggestOnly)
            }
            MaintenanceAutomationMode::Manual if !input.explicit_request => (
                AutomationDecision::Suggest,
                DecisionReason::ExplicitRequestRequired,
            ),
            MaintenanceAutomationMode::IdleOnly if !input.idle => {
                (AutomationDecision::Defer, DecisionReason::NotIdle)
            }
            MaintenanceAutomationMode::Scheduled if !input.scheduled_window => {
                (AutomationDecision::Defer, DecisionReason::OutsideSchedule)
            }
            _ if !input.route_available => {
                (AutomationDecision::Defer, DecisionReason::RouteUnavailable)
            }
            _ if !input.budget_available => {
                (AutomationDecision::Defer, DecisionReason::BudgetUnavailable)
            }
            _ if input.user_session_required && !input.user_session_available => (
                AutomationDecision::Defer,
                DecisionReason::UserSessionRequired,
            ),
            _ => (AutomationDecision::Start, DecisionReason::Eligible),
        };
        Ok(Self::decision(input, decision, reason))
    }

    /// Admits one new job only from a `START` decision.
    pub fn admit(
        &mut self,
        decision: &AutomationTriggerDecision,
        state_fence: StateFence,
        runtime_lease: RuntimeLease,
        budget_ref: String,
        max_attempts: u32,
        user_session_required: bool,
    ) -> Result<MaintenanceJob, MaintenanceError> {
        if decision.decision != AutomationDecision::Start || !decision.admits_job {
            return Err(MaintenanceError::InvalidField("decision"));
        }
        text(&decision.trigger_id, "trigger_id")?;
        text(&decision.scope_ref, "scope_ref")?;
        text(&budget_ref, "budget_ref")?;
        let job_id = format!("maintenance:{}:{}", decision.family, decision.trigger_id);
        if self.store.load(&job_id)?.is_some() {
            return Err(MaintenanceError::IdentityConflict);
        }
        let job = MaintenanceJob {
            job_id,
            trigger_id: decision.trigger_id.clone(),
            // The admission names the exact decision that produced it, so every
            // later source result on this job is attributed to the decision that
            // actually admitted the work.
            decision_ref: maintenance_decision_ref(decision),
            family: decision.family,
            scope_ref: decision.scope_ref.clone(),
            state_fence,
            runtime_lease,
            state: MaintenanceJobState::Admitted,
            checkpoint: None,
            max_attempts,
            attempts: 0,
            budget_ref,
            outcome_ref: None,
            user_session_required,
            result_obligations: Vec::new(),
        };
        job.validate()?;
        self.store.save(&job)?;
        Ok(job)
    }

    /// Starts one admitted/deferred job under its exact current fence and lease.
    pub fn start(
        &mut self,
        job_id: &str,
        fence: &StateFence,
    ) -> Result<MaintenanceJob, MaintenanceError> {
        let job = self.load_checked(job_id, fence)?;
        if job.attempts >= job.max_attempts {
            return Err(MaintenanceError::BudgetExhausted);
        }
        if job.runtime_lease.state != LeaseState::Active {
            return Err(MaintenanceError::LeaseInactive);
        }
        let mut next = job.transition(MaintenanceJobState::Running)?;
        next.attempts = next
            .attempts
            .checked_add(1)
            .ok_or(MaintenanceError::BudgetExhausted)?;
        self.store.save(&next)?;
        Ok(next)
    }

    /// Persists bounded progress and releases the active execution slot.
    pub fn checkpoint(
        &mut self,
        job_id: &str,
        fence: &StateFence,
        checkpoint: MaintenanceCheckpoint,
    ) -> Result<MaintenanceJob, MaintenanceError> {
        checkpoint.validate()?;
        let job = self.load_checked(job_id, fence)?;
        if job.state != MaintenanceJobState::Running {
            return Err(MaintenanceError::IllegalTransition {
                from: job.state,
                to: MaintenanceJobState::Checkpointed,
            });
        }
        let mut next = job.transition(MaintenanceJobState::Checkpointed)?;
        next.checkpoint = Some(checkpoint);
        // A bounded partial result is a source result in its own right: it owes
        // an observation like any other outcome, and it is recorded in the same
        // write as the checkpoint that produced it.
        result_obligation::append_result_obligation(&mut next, None)?;
        self.store.save(&next)?;
        Ok(next)
    }

    /// Resumes a checkpointed job only with the same fence and active lease.
    pub fn resume(
        &mut self,
        job_id: &str,
        fence: &StateFence,
    ) -> Result<MaintenanceJob, MaintenanceError> {
        let job = self.load_checked(job_id, fence)?;
        if job.runtime_lease.state != LeaseState::Active {
            return Err(MaintenanceError::LeaseInactive);
        }
        if job.attempts >= job.max_attempts {
            return Err(MaintenanceError::BudgetExhausted);
        }
        let mut next = job.transition(MaintenanceJobState::Running)?;
        next.attempts = next
            .attempts
            .checked_add(1)
            .ok_or(MaintenanceError::BudgetExhausted)?;
        self.store.save(&next)?;
        Ok(next)
    }

    /// Records a verified terminal result; completion is not proof that the subsystem improved.
    pub fn complete(
        &mut self,
        job_id: &str,
        fence: &StateFence,
        outcome_ref: String,
    ) -> Result<MaintenanceJob, MaintenanceError> {
        text(&outcome_ref, "outcome_ref")?;
        let job = self.load_checked(job_id, fence)?;
        let mut next = job.transition(MaintenanceJobState::Completed)?;
        next.outcome_ref = Some(outcome_ref);
        result_obligation::append_result_obligation(&mut next, None)?;
        self.store.save(&next)?;
        Ok(next)
    }

    /// Marks an execution outcome unknown and forbids blind retry.
    pub fn mark_unknown(
        &mut self,
        job_id: &str,
        fence: &StateFence,
        evidence_ref: String,
    ) -> Result<MaintenanceJob, MaintenanceError> {
        text(&evidence_ref, "evidence_ref")?;
        let job = self.load_checked(job_id, fence)?;
        let mut next = job.transition(MaintenanceJobState::UnknownOutcome)?;
        next.outcome_ref = Some(evidence_ref);
        result_obligation::append_result_obligation(&mut next, None)?;
        self.store.save(&next)?;
        Ok(next)
    }

    /// Records a verified failed attempt without converting it into success.
    pub fn fail(
        &mut self,
        job_id: &str,
        fence: &StateFence,
        evidence_ref: String,
    ) -> Result<MaintenanceJob, MaintenanceError> {
        text(&evidence_ref, "evidence_ref")?;
        let job = self.load_checked(job_id, fence)?;
        let mut next = job.transition(MaintenanceJobState::Failed)?;
        next.outcome_ref = Some(evidence_ref);
        result_obligation::append_result_obligation(&mut next, None)?;
        self.store.save(&next)?;
        Ok(next)
    }

    /// Quarantines a job whose unresolved outcome requires an explicit repair.
    pub fn require_rollback(
        &mut self,
        job_id: &str,
        fence: &StateFence,
        evidence_ref: String,
    ) -> Result<MaintenanceJob, MaintenanceError> {
        text(&evidence_ref, "evidence_ref")?;
        let job = self.load_checked(job_id, fence)?;
        if job.state != MaintenanceJobState::UnknownOutcome {
            return Err(MaintenanceError::UnknownRequiresReconciliation);
        }
        // The unknown result is this job's current source result, so a
        // quarantine that follows it is an appended obligation naming it, not a
        // replacement of it. The uncertainty stays in the history.
        let predecessor = result_obligation::latest_obligation(&job).cloned();
        let mut next = job.transition(MaintenanceJobState::RollbackRequired)?;
        next.outcome_ref = Some(evidence_ref);
        result_obligation::append_result_obligation(&mut next, predecessor.as_ref())?;
        self.store.save(&next)?;
        Ok(next)
    }

    /// Reconciles an unknown result without retrying an unresolved external effect.
    pub fn reconcile_unknown(
        &mut self,
        job_id: &str,
        fence: &StateFence,
        disposition: ReconciliationDisposition,
        evidence_ref: String,
    ) -> Result<MaintenanceJob, MaintenanceError> {
        text(&evidence_ref, "evidence_ref")?;
        let job = self.load_checked(job_id, fence)?;
        if job.state != MaintenanceJobState::UnknownOutcome {
            return Err(MaintenanceError::UnknownRequiresReconciliation);
        }
        // The unknown result being reconciled is the predecessor of whatever this
        // resolves to. It is named, not replaced: the appended record adds linked
        // evidence and the original uncertainty remains in the job's history.
        let predecessor = result_obligation::latest_obligation(&job)
            .cloned()
            .ok_or(MaintenanceError::UnknownRequiresReconciliation)?;
        let target = match disposition {
            ReconciliationDisposition::ProvenNoEffect => MaintenanceJobState::Deferred,
            ReconciliationDisposition::ProvenApplied => MaintenanceJobState::Completed,
            ReconciliationDisposition::StillUnknown => {
                return Err(MaintenanceError::UnknownRequiresReconciliation);
            }
        };
        let mut next = job.transition(target)?;
        next.outcome_ref = Some(evidence_ref);
        result_obligation::append_reconciliation_obligation(&mut next, &predecessor)?;
        self.store.save(&next)?;
        Ok(next)
    }

    /// Cancels work before an irreversible external effect is acknowledged.
    pub fn cancel(
        &mut self,
        job_id: &str,
        fence: &StateFence,
    ) -> Result<MaintenanceJob, MaintenanceError> {
        let job = self.load_checked(job_id, fence)?;
        let mut next = job.transition(MaintenanceJobState::Cancelled)?;
        // A cancellation is a source result too. It records no outcome evidence
        // because none was produced, and it still owes an observation.
        result_obligation::append_result_obligation(&mut next, None)?;
        self.store.save(&next)?;
        Ok(next)
    }

    /// Records that the canonical observation route admitted one result this
    /// job owed an observation for, and persists that fact on the job revision.
    ///
    /// This is the only transition that makes the second of the three states
    /// durable. Before it the retained obligation is `Pending` — the work
    /// happened and the observation does not exist yet. After it the retained
    /// obligation carries the exact store receipt, so a later read can tell an
    /// admitted observation from a merely referenced one.
    ///
    /// It writes through the same [`MaintenanceStateStore::save`] every
    /// lifecycle transition uses, so the receipt and the revision it settles
    /// become durable together or in neither. It never touches the lifecycle
    /// state, the outcome reference or any earlier obligation, so admitting an
    /// observation cannot rewrite the execution history it observes, and it
    /// never writes an outcome: the only value it can add is a receipt the
    /// caller already holds.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::InvalidField`] when an identity is empty,
    /// when this job owes no result observation under `publication_id`, or
    /// when that obligation's delivery is already recorded as unavailable;
    /// [`MaintenanceError::IdentityConflict`] when a different receipt is
    /// already admitted under that identity; [`MaintenanceError::FenceMismatch`]
    /// for a stale or mismatched fence; and [`MaintenanceError::Store`] when
    /// the port refuses the write. Replaying the same receipt is a
    /// reconciliation and persists nothing.
    pub fn admit_observation_receipt(
        &mut self,
        job_id: &str,
        fence: &StateFence,
        publication_id: &str,
        observation_receipt_ref: &str,
    ) -> Result<MaintenanceJob, MaintenanceError> {
        let job = self.load_checked(job_id, fence)?;
        let next = outcome_observation::admit_observation_delivery(
            &job,
            publication_id,
            observation_receipt_ref,
        )?;
        if next == job {
            return Ok(job);
        }
        self.store.save(&next)?;
        Ok(next)
    }

    /// Records that the canonical observation route returned a terminal
    /// non-committed receipt for one result this job owed an observation for,
    /// and persists that disposition on the job revision.
    ///
    /// This is W5's gap disposition: the store issued a receipt and that receipt
    /// did not commit, so the writeback is unavailable rather than pending.
    /// Leaving it `Pending` would report a rejection or an outage as though the
    /// observation had merely not been attempted yet, and would keep
    /// re-presenting it with no visible consequence.
    ///
    /// It writes through the same [`MaintenanceStateStore::save`] every
    /// lifecycle transition and every receipt admission uses, so the gap and
    /// the revision it covers stay in one store with one atomic boundary. It
    /// appends no obligation and enters no producer, so recording a gap cannot
    /// recursively create another maintenance result.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::InvalidField`] when an identity is empty,
    /// when this job owes no result observation under `publication_id`, or when
    /// a different gap is already recorded there;
    /// [`MaintenanceError::IdentityConflict`] when a store receipt is already
    /// admitted under that identity; [`MaintenanceError::FenceMismatch`] for a
    /// stale or mismatched fence; and [`MaintenanceError::Store`] when the port
    /// refuses the write. Re-recording the same gap is a reconciliation and
    /// persists nothing.
    pub fn record_observation_gap(
        &mut self,
        job_id: &str,
        fence: &StateFence,
        publication_id: &str,
        refused_operation_id: &str,
        status: RefusedReceiptStatus,
    ) -> Result<MaintenanceJob, MaintenanceError> {
        let job = self.load_checked(job_id, fence)?;
        let next = outcome_observation::record_observation_gap(
            &job,
            publication_id,
            refused_operation_id,
            status,
        )?;
        if next == job {
            return Ok(job);
        }
        self.store.save(&next)?;
        Ok(next)
    }

    fn load_checked(
        &mut self,
        job_id: &str,
        fence: &StateFence,
    ) -> Result<MaintenanceJob, MaintenanceError> {
        text(job_id, "job_id")?;
        fence
            .validate()
            .map_err(|_| MaintenanceError::FenceMismatch)?;
        let job = self
            .store
            .load(job_id)?
            .ok_or(MaintenanceError::IdentityConflict)?;
        job.validate()?;
        if job.job_id != job_id || job.state_fence != *fence {
            return Err(MaintenanceError::FenceMismatch);
        }
        Ok(job)
    }

    fn decision(
        input: &MaintenanceTriggerInput,
        decision: AutomationDecision,
        reason: DecisionReason,
    ) -> AutomationTriggerDecision {
        AutomationTriggerDecision {
            trigger_id: input.trigger_id.clone(),
            trigger: input.trigger,
            family: input.family,
            scope_ref: input.scope_ref.clone(),
            decision,
            reason,
            admits_job: decision == AutomationDecision::Start,
            durable_job_ref: None,
        }
    }

    /// Checkpoints one running job for an idle-drain generation and reads the
    /// checkpoint back from the durable store before returning (#1686 item 4,
    /// I14.13 "checkpoint durable jobs", I14.23 "request jobs/modules
    /// checkpoint/cancel").
    ///
    /// Eligibility is the owner's, not the caller's: only a job in
    /// [`MaintenanceJobState::Running`] checkpoints, and only for the attempt
    /// ordinal the execution owner actually began (`attempt` must equal the
    /// job's admitted `attempts`), so a checkpoint can never bind a
    /// not-started, already-terminal, or foreign attempt. `policy_ref` must
    /// name the authorizing drain policy: the owner binds it into the returned
    /// outcome but never invents one, so a policy-unauthorized checkpoint is
    /// refused rather than recorded. The returned [`DrainCheckpointOutcome`]
    /// is built from the revision the store served back after the save — never
    /// from the request — so a planned reclamation or stop that consumes it
    /// proceeds only on a durably read-back checkpoint artifact.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::InvalidField`] for a malformed request or a
    /// wrong attempt ordinal, [`MaintenanceError::IllegalTransition`] when the
    /// job is not running, and [`MaintenanceError::Store`] when the read-back
    /// does not carry the saved checkpoint.
    pub fn checkpoint_for_drain(
        &mut self,
        request: &DrainCheckpointRequest,
        fence: &StateFence,
    ) -> Result<DrainCheckpointOutcome, MaintenanceError> {
        request.validate()?;
        let current = self.load_checked(&request.job_id, fence)?;
        if current.state != MaintenanceJobState::Running {
            return Err(MaintenanceError::IllegalTransition {
                from: current.state,
                to: MaintenanceJobState::Checkpointed,
            });
        }
        if current.attempts != request.attempt {
            return Err(MaintenanceError::InvalidField("drain.attempt"));
        }
        let saved = self.checkpoint(&request.job_id, fence, request.checkpoint.clone())?;
        self.read_back_drain_checkpoint(
            &request.drain_generation,
            &request.owner_ref,
            &request.policy_ref,
            &saved,
            fence,
        )
    }

    /// Reads one drain checkpoint back from the durable store and binds it to
    /// the calling drain generation (#1686 item 4, I14.13 "require durable
    /// checkpoint readback before planned reclamation/stop").
    ///
    /// `saved` is the revision the checkpoint call returned; the revision the
    /// store serves back must equal it — same identity, same fence, same
    /// checkpoint artifact, same `Checkpointed` state. Anything else (absent
    /// revision, substituted job, lost artifact, advanced state) is refused
    /// with [`MaintenanceError::Store`] and yields no outcome, so a planned
    /// stop never consumes an unproven checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::InvalidField`] for a malformed binding, and
    /// [`MaintenanceError::Store`] when the read-back does not equal the saved
    /// revision or carries no checkpoint artifact.
    pub fn read_back_drain_checkpoint(
        &mut self,
        drain_generation: &str,
        owner_ref: &str,
        policy_ref: &str,
        saved: &MaintenanceJob,
        fence: &StateFence,
    ) -> Result<DrainCheckpointOutcome, MaintenanceError> {
        text(drain_generation, "drain.generation")?;
        text(owner_ref, "drain.owner_ref")?;
        text(policy_ref, "drain.policy_ref")?;
        let read_back = self.load_checked(&saved.job_id, fence)?;
        if read_back != *saved {
            return Err(MaintenanceError::Store(
                "drain checkpoint read-back mismatch".to_owned(),
            ));
        }
        let checkpoint = read_back.checkpoint.clone().ok_or(MaintenanceError::Store(
            "drain checkpoint artifact absent on read-back".to_owned(),
        ))?;
        let outcome = DrainCheckpointOutcome {
            drain_generation: drain_generation.to_owned(),
            job_id: read_back.job_id.clone(),
            attempt: read_back.attempts,
            owner_ref: owner_ref.to_owned(),
            policy_ref: policy_ref.to_owned(),
            state_fence: read_back.state_fence.clone(),
            checkpoint,
            state: read_back.state,
        };
        outcome.validate()?;
        Ok(outcome)
    }

    /// Cancels one drain-eligible job for an idle-drain generation (#1686 item
    /// 4, I14.13 "cancel noncritical child tasks", I14.23 "request
    /// jobs/modules checkpoint/cancel").
    ///
    /// The request must name the authorizing drain policy (`policy_ref`); the
    /// owner binds it into the returned outcome but never invents one, so a
    /// policy-unauthorized cancellation is refused rather than recorded.
    /// Family criticality stays a policy input carried by that reference, not
    /// an owner guess. Pre-effect eligibility is the state machine's:
    /// [`MaintenanceJob::transition`] admits `Cancelled` only from `Admitted`,
    /// `Running`, `Checkpointed` and `Deferred`, so a completed, failed,
    /// quarantined (`RollbackRequired`) or still-unknown job is refused with
    /// [`MaintenanceError::IllegalTransition`]. An unknown external effect
    /// stays fenced and is never cancelled away, and a completed effect is
    /// never rewritten as cancelled. The returned [`DrainCancelOutcome`]
    /// carries the checkpoint and outcome references the persisted revision
    /// retains, proving the cancellation claimed no rollback of an
    /// already-executed effect.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::InvalidField`] for a malformed request,
    /// [`MaintenanceError::IllegalTransition`] when the job is not in a
    /// cancellable state, and [`MaintenanceError::Store`] when the persisted
    /// revision does not retain the pre-cancel checkpoint and outcome
    /// references.
    pub fn cancel_for_drain(
        &mut self,
        request: &DrainCancelRequest,
        fence: &StateFence,
    ) -> Result<DrainCancelOutcome, MaintenanceError> {
        request.validate()?;
        let current = self.load_checked(&request.job_id, fence)?;
        let retained_checkpoint = current.checkpoint.clone();
        let retained_outcome_ref = current.outcome_ref.clone();
        self.cancel(&request.job_id, fence)?;
        let read_back = self.load_checked(&request.job_id, fence)?;
        if read_back.state != MaintenanceJobState::Cancelled
            || read_back.checkpoint != retained_checkpoint
            || read_back.outcome_ref != retained_outcome_ref
        {
            return Err(MaintenanceError::Store(
                "drain cancel read-back mismatch".to_owned(),
            ));
        }
        let outcome = DrainCancelOutcome {
            drain_generation: request.drain_generation.clone(),
            job_id: read_back.job_id.clone(),
            owner_ref: request.owner_ref.clone(),
            policy_ref: request.policy_ref.clone(),
            state_fence: read_back.state_fence.clone(),
            state: read_back.state,
            retained_checkpoint,
            retained_outcome_ref,
        };
        outcome.validate()?;
        Ok(outcome)
    }

    /// Acknowledges the Governor drain flush over outcome-observation coverage
    /// for one declared job set (#1686 item 5, I14.23 "flush
    /// audit/outbox/ORS").
    ///
    /// Declared revisions are read through the durable port, never rebuilt
    /// from the obligation list: a declared job with no retained revision
    /// becomes `RevisionUnavailable` inside the coverage call instead of
    /// disappearing, so an unreadable revision keeps the acknowledgement
    /// incomplete. `outstanding` preserves every pending delivery the contract
    /// retains past durable handoff — delivery and durable handoff are
    /// distinct, and this acknowledgement never clears an obligation because a
    /// task stopped. `complete` is true only when nothing is outstanding; a
    /// transport send, a daemon idle state, or a zero in-memory count never
    /// sets it.
    ///
    /// # Errors
    ///
    /// Returns every [`MaintenanceError`] from the outcome-observation coverage
    /// call, plus [`MaintenanceError::InvalidField`] for a malformed drain
    /// binding and [`MaintenanceError::Store`] when the durable port refuses a
    /// revision read.
    pub fn drain_observation_flush_ack(
        &mut self,
        drain_generation: &str,
        owner_ref: &str,
        expected: &[ExpectedOutcomeObservation],
        admitted: &[AdmittedObservationReceipt],
    ) -> Result<DrainObservationFlushAck, MaintenanceError> {
        text(drain_generation, "drain.generation")?;
        text(owner_ref, "drain.owner")?;
        let mut jobs = Vec::with_capacity(expected.len());
        for entry in expected {
            if let Some(job) = self.store.load(&entry.job_id)? {
                jobs.push(job);
            }
        }
        let coverage =
            outcome_observation::outcome_observation_coverage(expected, &jobs, admitted)?;
        Ok(DrainObservationFlushAck {
            drain_generation: drain_generation.to_owned(),
            owner_ref: owner_ref.to_owned(),
            complete: coverage.is_complete(),
            observed: coverage.observed,
            outstanding: coverage.outstanding,
        })
    }
}

/// Drain-bound checkpoint request: one eligible job checkpoint for one drain
/// generation (#1686 item 4, I14.13/I14.23).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainCheckpointRequest {
    /// Drain generation this checkpoint is bound to.
    pub drain_generation: String,
    /// Durable job identity to checkpoint.
    pub job_id: String,
    /// Attempt ordinal the execution owner began; must equal the job's
    /// admitted `attempts`.
    pub attempt: u32,
    /// Drain owner presenting this request.
    pub owner_ref: String,
    /// Authorizing drain policy reference. The owner binds it into the outcome
    /// but never invents one.
    pub policy_ref: String,
    /// Checkpoint artifact the execution owner persisted.
    pub checkpoint: MaintenanceCheckpoint,
}

impl DrainCheckpointRequest {
    /// Validates drain, job, owner, policy and checkpoint identities.
    pub fn validate(&self) -> Result<(), MaintenanceError> {
        text(&self.drain_generation, "drain.generation")?;
        text(&self.job_id, "drain.job_id")?;
        text(&self.owner_ref, "drain.owner_ref")?;
        text(&self.policy_ref, "drain.policy_ref")?;
        self.checkpoint.validate()?;
        Ok(())
    }
}

/// Bound owner outcome for one drain checkpoint (#1686 item 4).
///
/// Every field is read from the durable revision the store served back after
/// the save, except `drain_generation`, `owner_ref` and `policy_ref`, which
/// are the validated request bindings this outcome answers. A checkpoint the
/// store did not durably retain produces no outcome.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainCheckpointOutcome {
    /// Drain generation this outcome answers.
    pub drain_generation: String,
    /// Durable job identity that checkpointed.
    pub job_id: String,
    /// Attempt ordinal the checkpoint binds.
    pub attempt: u32,
    /// Drain owner that presented the request.
    pub owner_ref: String,
    /// Authorizing drain policy reference bound into the outcome.
    pub policy_ref: String,
    /// State fence the checkpointed revision carries.
    pub state_fence: StateFence,
    /// Durably read-back checkpoint artifact.
    pub checkpoint: MaintenanceCheckpoint,
    /// Lifecycle state on read-back; always `Checkpointed`.
    pub state: MaintenanceJobState,
}

impl DrainCheckpointOutcome {
    /// Validates the bound outcome; only a `Checkpointed` outcome is one.
    pub fn validate(&self) -> Result<(), MaintenanceError> {
        text(&self.drain_generation, "drain.generation")?;
        text(&self.job_id, "drain.job_id")?;
        text(&self.owner_ref, "drain.owner_ref")?;
        text(&self.policy_ref, "drain.policy_ref")?;
        self.checkpoint.validate()?;
        if self.state != MaintenanceJobState::Checkpointed {
            return Err(MaintenanceError::InvalidField("drain.state"));
        }
        Ok(())
    }
}

/// Drain-bound cancellation request: one policy-authorized cancellation for
/// one drain generation (#1686 item 4, I14.13).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainCancelRequest {
    /// Drain generation this cancellation is bound to.
    pub drain_generation: String,
    /// Durable job identity to cancel.
    pub job_id: String,
    /// Drain owner presenting this request.
    pub owner_ref: String,
    /// Authorizing drain policy reference. The owner binds it into the outcome
    /// but never invents one.
    pub policy_ref: String,
}

impl DrainCancelRequest {
    /// Validates drain, job, owner and policy identities.
    pub fn validate(&self) -> Result<(), MaintenanceError> {
        text(&self.drain_generation, "drain.generation")?;
        text(&self.job_id, "drain.job_id")?;
        text(&self.owner_ref, "drain.owner_ref")?;
        text(&self.policy_ref, "drain.policy_ref")?;
        Ok(())
    }
}

/// Bound owner outcome for one drain cancellation (#1686 item 4).
///
/// `retained_checkpoint` and `retained_outcome_ref` are the checkpoint and
/// outcome references the persisted revision still carries after the cancel:
/// cancellation claims no rollback of an already-persisted checkpoint and
/// neither fabricates an outcome nor discards an already-recorded (completed
/// or unknown) external effect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainCancelOutcome {
    /// Drain generation this outcome answers.
    pub drain_generation: String,
    /// Durable job identity that cancelled.
    pub job_id: String,
    /// Drain owner that presented the request.
    pub owner_ref: String,
    /// Authorizing drain policy reference bound into the outcome.
    pub policy_ref: String,
    /// State fence the cancelled revision carries.
    pub state_fence: StateFence,
    /// Lifecycle state on read-back; always `Cancelled`.
    pub state: MaintenanceJobState,
    /// Checkpoint artifact retained verbatim through the cancel, if any.
    pub retained_checkpoint: Option<MaintenanceCheckpoint>,
    /// Outcome evidence retained verbatim through the cancel, if any.
    pub retained_outcome_ref: Option<String>,
}

impl DrainCancelOutcome {
    /// Validates the bound outcome; only a `Cancelled` outcome with retained
    /// references is one.
    pub fn validate(&self) -> Result<(), MaintenanceError> {
        text(&self.drain_generation, "drain.generation")?;
        text(&self.job_id, "drain.job_id")?;
        text(&self.owner_ref, "drain.owner_ref")?;
        text(&self.policy_ref, "drain.policy_ref")?;
        if let Some(checkpoint) = &self.retained_checkpoint {
            checkpoint.validate()?;
        }
        if let Some(outcome) = &self.retained_outcome_ref {
            text(outcome, "drain.retained_outcome_ref")?;
        }
        if self.state != MaintenanceJobState::Cancelled {
            return Err(MaintenanceError::InvalidField("drain.state"));
        }
        Ok(())
    }
}

/// Governor drain flush acknowledgement over outcome-observation coverage for
/// one declared job set (#1686 item 5, I14.23 "flush audit/outbox/ORS").
///
/// `observed` is the exact covered range: every declared job whose owed
/// observation the canonical route admitted, each with the store receipt that
/// proves it. `outstanding` is the exact remaining obligation: every declared
/// job not fully observed, including pending deliveries the contract retains
/// past durable handoff. `complete` is true only when nothing is outstanding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainObservationFlushAck {
    /// Drain generation this acknowledgement answers.
    pub drain_generation: String,
    /// Drain owner that presented the declared set.
    pub owner_ref: String,
    /// Declared jobs whose owed observation is admitted, with exact receipts.
    pub observed: Vec<ObservedOutcomeObservation>,
    /// Every declared job that is not fully observed, in declaration order.
    pub outstanding: Vec<OutstandingOutcome>,
    /// True only when `outstanding` is empty.
    pub complete: bool,
}

impl DrainObservationFlushAck {
    /// Whether the drain may treat the Governor observation flush as
    /// discharged.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }
}

/// Returns the stable contract identity for protocol/schema handshakes.
pub fn contract_identity() -> Result<ContractIdentity, eliot_contracts::ContractError> {
    make_contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &serde_json::json!({
            "surface": "maintenance_trigger_evaluator_and_durable_job",
            "unknown_rule": "pause_scope_until_receipt_reconciliation",
            "execution_rule": "controller_decides_execution_owner_does_effect",
        }),
    )
}

/// Human maintenance-policy evidence for one family and scope (I14.22 W1, issue #1692).
///
/// I14.22: "Human policy selects one `MaintenanceAutomationMode` per family."
/// The per-family revision/digest, the affected scope, the override provenance,
/// the separate `interactive_maintenance` permission, and the effect/budget
/// ceilings travel with that selection, so a mode value alone never authorizes
/// work. No Human maintenance-policy publisher exists on this seam yet, so the
/// only constructor records unpublished provenance (no revision/digest, no
/// override, no separate permission, no ceilings) around the registry-selected
/// mode; the fail-closed `Off` for every family comes from the caller's
/// registry, and the five non-Off modes are enforced by
/// [`MaintenanceController::evaluate_trigger`], which already implements the
/// whole deterministic decision surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenancePolicyEvidence {
    /// Registered maintenance family this evidence concerns.
    pub family: MaintenanceFamily,
    /// Affected scope this evidence was issued for.
    pub scope_ref: String,
    /// Selected automation mode.
    pub mode: MaintenanceAutomationMode,
    /// Publisher revision, when a Human policy owner publishes one.
    pub revision: Option<u64>,
    /// Digest of the canonical published policy bytes, when published.
    pub digest: Option<String>,
    /// Provenance of a Human override, when an override is in force.
    pub override_provenance: Option<String>,
    /// Separate `interactive_maintenance` permission (I14.22).
    pub interactive_permission: bool,
    /// Effect ceiling the publisher admits, when published.
    pub effect_ceiling: Option<String>,
    /// Budget ceiling the publisher admits, when published.
    pub budget_ceiling: Option<String>,
}

impl MaintenancePolicyEvidence {
    /// Records unpublished provenance around the registry-selected mode: no
    /// publisher revision/digest, no override, no separate interactive
    /// permission, and no effect/budget ceilings. The mode value itself comes
    /// from the caller's registry (the maintenance-family catalog), so this
    /// type never invents a second mode source; it carries the provenance the
    /// registry does not.
    #[must_use]
    pub fn unpublished(
        mode: MaintenanceAutomationMode,
        family: MaintenanceFamily,
        scope_ref: String,
    ) -> Self {
        Self {
            family,
            scope_ref,
            mode,
            revision: None,
            digest: None,
            override_provenance: None,
            interactive_permission: false,
            effect_ceiling: None,
            budget_ceiling: None,
        }
    }

    /// Selected automation mode.
    #[must_use]
    pub const fn mode(&self) -> MaintenanceAutomationMode {
        self.mode
    }

    /// Whether interactive work is permitted by the separate policy.
    #[must_use]
    pub const fn requires_interactive_session(&self) -> bool {
        self.interactive_permission
    }
}

/// Service-safe route/credential evidence (I14.22 W2, issue #1692).
///
/// I14.22: "Scheduled/background maintenance may use only service-safe routes
/// and credentials explicitly admitted for unattended operation." The selected
/// capability fingerprint/generation, the credential reference, and the
/// unattended-use suitability travel together, so `route_available` is decided
/// from an owner rather than a bare boolean. No route/credential owner
/// publishes to this seam yet, so the only constructor records the
/// unpublished, fail-closed evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceRouteEvidence {
    /// Admitted capability fingerprint, when published.
    pub capability_fingerprint: Option<String>,
    /// Admitted capability generation, when published.
    pub generation: Option<u64>,
    /// Credential reference admitted for unattended use, when published.
    pub credential_ref: Option<String>,
    /// Whether the published route is suitable for unattended operation.
    pub unattended_suitable: bool,
}

impl MaintenanceRouteEvidence {
    /// Records unpublished route evidence: nothing admitted, not suitable.
    #[must_use]
    pub const fn unpublished() -> Self {
        Self {
            capability_fingerprint: None,
            generation: None,
            credential_ref: None,
            unattended_suitable: false,
        }
    }

    /// Whether a service-safe execution route is available: suitability plus
    /// the exact admitted fingerprint, generation, and credential reference.
    /// A partial record grants nothing.
    #[must_use]
    pub fn is_service_safe(&self) -> bool {
        self.unattended_suitable
            && self.capability_fingerprint.is_some()
            && self.generation.is_some()
            && self.credential_ref.is_some()
    }
}

/// Admitted budget evidence (I14.22 W1, issue #1692).
///
/// No maintenance budget/quota owner publishes to this seam yet, so the only
/// constructor records the unpublished, fail-closed evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceBudgetEvidence {
    /// Budget reference admitted for this work, when published.
    pub budget_ref: Option<String>,
    /// Whether an admitted cost/quota slice remains.
    pub remaining: bool,
}

impl MaintenanceBudgetEvidence {
    /// Records unpublished budget evidence: no reference, nothing remaining.
    #[must_use]
    pub const fn unpublished() -> Self {
        Self {
            budget_ref: None,
            remaining: false,
        }
    }

    /// Whether an admitted cost/quota budget remains. A bare flag without the
    /// admitted reference grants nothing.
    #[must_use]
    pub fn has_budget(&self) -> bool {
        self.remaining && self.budget_ref.is_some()
    }
}

/// Approved schedule-window evidence (I14.22, issue #1692).
///
/// The window is a real Host wake / Task Scheduler occurrence, never a locally
/// invented one. `eliotd` holds no such occurrence, so the only constructor
/// records the unpublished, fail-closed evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceScheduleEvidence {
    /// Whether a real approved schedule occurrence is current.
    pub window_open: bool,
}

impl MaintenanceScheduleEvidence {
    /// Records unpublished schedule evidence: no approved window.
    #[must_use]
    pub const fn unpublished() -> Self {
        Self { window_open: false }
    }

    /// Whether the current time is inside the approved window.
    #[must_use]
    pub const fn is_current_window(&self) -> bool {
        self.window_open
    }
}

/// User Broker session evidence (I14.22/I14.24 W3, issue #1692).
///
/// I14.22 requires an active authenticated User Broker plus a separate
/// `interactive_maintenance` policy for subscription-, IDE-, browser- or
/// desktop-bound work; I14.24 requires broker loss/revocation to stop affected
/// interactive work while service-safe routes continue. The daemon's retained
/// transport-session facts are not User Broker evidence and never satisfy a
/// broker gate on their own. The current Kernel client has no daemon-facing
/// query for the authoritative broker registration/lease, so this evidence can
/// only represent that the required owner observation is unavailable. No
/// token, credential, or reusable desktop secret is carried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceBrokerEvidence;

impl MaintenanceBrokerEvidence {
    /// Records that the authenticated User Broker owner query is unavailable.
    ///
    /// A validated daemon transport session is deliberately not accepted as a
    /// substitute. Until the Kernel exposes a current authenticated broker
    /// observation, interactive maintenance remains denied.
    #[must_use]
    pub const fn owner_query_unavailable() -> Self {
        Self
    }

    /// Whether a current authenticated User Broker session is established.
    ///
    /// This returns `false` while the authoritative Kernel owner query is not
    /// available; transport presence cannot promote it to `true`.
    #[must_use]
    pub const fn authenticated_session_available(&self) -> bool {
        false
    }
}

/// Mandatory safety/recovery obligation evidence (I14.22, issue #1692).
///
/// Only a verified mandatory safety/recovery obligation published by its
/// owning authority may set this; a caller-projected flag never satisfies it.
/// No such owner publishes to this seam yet, so the only constructor records
/// the unpublished, fail-closed evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceSafetyEvidence {
    /// Whether a verified mandatory obligation is in force.
    pub required: bool,
}

impl MaintenanceSafetyEvidence {
    /// Records unpublished safety evidence: no verified obligation.
    #[must_use]
    pub const fn unpublished() -> Self {
        Self { required: false }
    }

    /// Whether a verified mandatory safety/recovery obligation is in force.
    #[must_use]
    pub const fn is_required(&self) -> bool {
        self.required
    }
}

fn text(value: &str, field: &'static str) -> Result<(), MaintenanceError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(MaintenanceError::InvalidField(field));
    }
    Ok(())
}

fn nonempty<T>(values: &[T], field: &'static str) -> Result<(), MaintenanceError> {
    if values.is_empty() {
        Err(MaintenanceError::Empty(field))
    } else {
        Ok(())
    }
}

fn unique_text(values: &[String], field: &'static str) -> Result<(), MaintenanceError> {
    let mut seen = BTreeSet::new();
    for value in values {
        text(value, field)?;
        if !seen.insert(value) {
            return Err(MaintenanceError::IdentityConflict);
        }
    }
    Ok(())
}
