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
}

impl MaintenanceJob {
    /// Validates identity, fence, lease, attempt budget and checkpoint.
    pub fn validate(&self) -> Result<(), MaintenanceError> {
        text(&self.job_id, "job_id")?;
        text(&self.trigger_id, "trigger_id")?;
        text(&self.scope_ref, "scope_ref")?;
        text(&self.budget_ref, "budget_ref")?;
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

/// Deterministic maintenance decision and job owner.
pub struct MaintenanceController<S> {
    store: S,
}

impl<S: MaintenanceStateStore> MaintenanceController<S> {
    /// Creates a controller over the caller-owned durable maintenance store.
    pub const fn new(store: S) -> Self {
        Self { store }
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
                family: input.family,
                scope_ref: input.scope_ref.clone(),
                decision: AutomationDecision::SuppressDuplicate,
                reason: DecisionReason::DuplicateActiveJob,
                admits_job: false,
                durable_job_ref: Some(active.clone()),
            });
        }
        if input.safety_required {
            let (decision, reason) = if !input.route_available {
                (
                    AutomationDecision::Escalate,
                    DecisionReason::RouteUnavailable,
                )
            } else if !input.budget_available {
                (AutomationDecision::Defer, DecisionReason::BudgetUnavailable)
            } else if input.user_session_required && !input.user_session_available {
                (
                    AutomationDecision::Defer,
                    DecisionReason::UserSessionRequired,
                )
            } else {
                (AutomationDecision::Start, DecisionReason::SafetyRecovery)
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
        let mut next = job.transition(MaintenanceJobState::RollbackRequired)?;
        next.outcome_ref = Some(evidence_ref);
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
        let target = match disposition {
            ReconciliationDisposition::ProvenNoEffect => MaintenanceJobState::Deferred,
            ReconciliationDisposition::ProvenApplied => MaintenanceJobState::Completed,
            ReconciliationDisposition::StillUnknown => {
                return Err(MaintenanceError::UnknownRequiresReconciliation);
            }
        };
        let mut next = job.transition(target)?;
        next.outcome_ref = Some(evidence_ref);
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
        let next = job.transition(MaintenanceJobState::Cancelled)?;
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
            family: input.family,
            scope_ref: input.scope_ref.clone(),
            decision,
            reason,
            admits_job: decision == AutomationDecision::Start,
            durable_job_ref: None,
        }
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
