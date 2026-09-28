//! G-19 governed task lifecycle ownership.
//!
//! This crate is the sole in-memory authority for task state transitions.  It
//! does not execute work or persist records: callers persist the returned event
//! and snapshot through the canonical write path.  Every mutation is fenced,
//! causally sequenced, and idempotent so a retry cannot create a second task
//! transition.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_contracts::{ClockReading, EpochId, StateFence, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod professional_execution;

pub use professional_execution::{
    PrematureAbandonmentSignal, ProfessionalAbandonmentDecision, ProfessionalApproachRevision,
    ProfessionalArtifactEntry, ProfessionalArtifactManifest, ProfessionalAttempt,
    ProfessionalAttemptOutcome, ProfessionalCompletionEvidence, ProfessionalEvaluationOutcome,
    ProfessionalEvaluatorResult, ProfessionalExecutionContract, ProfessionalExecutionError,
    ProfessionalExecutionState, ProfessionalIsolationPrincipal, ProfessionalIsolationRoute,
    ProfessionalPrincipalVisibility, ProfessionalReferenceIsolationReceipt,
    ProfessionalRequirement, ProfessionalRequirementKind, ProfessionalRoleOwners,
    ProfessionalWorkerPacket, TaskControllerDisposition,
};

pub const CONTRACT_NAME: &str = "eliot.governor.task_lifecycle";
pub const CONTRACT_VERSION: eliot_contracts::ContractVersion =
    eliot_contracts::ContractVersion::new(1, 0, 0);

fn text(value: &str, field: &'static str) -> Result<(), TaskError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(TaskError::InvalidField(field));
    }
    Ok(())
}

/// Fail-closed errors returned by the lifecycle owner.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TaskError {
    #[error("invalid task field: {0}")]
    InvalidField(&'static str),
    #[error("task {0} already exists")]
    DuplicateTask(TaskId),
    #[error("task {0} was not found")]
    TaskNotFound(TaskId),
    #[error("idempotency key {0} was reused with different input")]
    IdempotencyConflict(String),
    #[error("task revision mismatch: expected {expected}, current {current}")]
    RevisionMismatch { expected: u64, current: u64 },
    #[error("state fence is incompatible with the lifecycle owner")]
    FenceMismatch,
    #[error("authority epoch mismatch")]
    EpochMismatch,
    #[error("illegal task transition from {from:?} to {to:?}")]
    IllegalTransition { from: TaskState, to: TaskState },
    #[error("{field} is required for this transition")]
    MissingEvidence { field: &'static str },
    #[error("event sequence must follow the current causal sequence")]
    CausalSequenceMismatch,
    #[error("professional execution state rejected the task command: {0}")]
    ProfessionalExecution(#[from] ProfessionalExecutionError),
}

/// Canonical task state from Architecture 22.2.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskState {
    Proposed,
    Open,
    Framed,
    UnderstandingRequired,
    ActionAuthorized,
    Executing,
    Verifying,
    DoneVerified,
    Blocked,
    Failed,
    Partial,
}

impl TaskState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::DoneVerified | Self::Blocked | Self::Failed | Self::Partial
        )
    }

    #[must_use]
    pub const fn is_active(self) -> bool {
        !self.is_terminal()
    }
}

/// The state-changing command accepted by the owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TaskCommand {
    Open,
    Frame {
        frame_ref: String,
    },
    RequireUnderstanding,
    AuthorizeAction {
        authority_ref: String,
        understanding_ref: String,
    },
    BeginExecution,
    BeginVerification,
    Verify {
        verification_ref: String,
    },
    Block {
        reason_ref: String,
    },
    Fail {
        reason_ref: String,
    },
    MarkPartial {
        result_ref: String,
    },
    Reopen {
        reopen_ref: String,
    },
    SetProfessionalExecutionContract {
        contract: Box<ProfessionalExecutionContract>,
    },
    ReportProfessionalAttempt {
        attempt: Box<ProfessionalAttempt>,
        outcome: ProfessionalAttemptOutcome,
        signal_ref: String,
    },
    ChangeProfessionalApproach {
        revision: Box<ProfessionalApproachRevision>,
        attempt: Box<ProfessionalAttempt>,
        signal_ref: String,
    },
    DecideProfessionalAbandonment {
        decision: Box<ProfessionalAbandonmentDecision>,
    },
    RecordProfessionalCompletionEvidence {
        evidence: Box<ProfessionalCompletionEvidence>,
    },
}

impl TaskCommand {
    fn target(&self, current: TaskState) -> TaskState {
        match self {
            Self::Open | Self::Reopen { .. } => TaskState::Open,
            Self::Frame { .. } => TaskState::Framed,
            Self::RequireUnderstanding => TaskState::UnderstandingRequired,
            Self::AuthorizeAction { .. } => TaskState::ActionAuthorized,
            Self::BeginExecution => TaskState::Executing,
            Self::BeginVerification => TaskState::Verifying,
            Self::Verify { .. } => TaskState::DoneVerified,
            Self::Block { .. } => TaskState::Blocked,
            Self::Fail { .. } => TaskState::Failed,
            Self::MarkPartial { .. }
            | Self::ReportProfessionalAttempt {
                outcome: ProfessionalAttemptOutcome::Stopped,
                ..
            } => TaskState::Partial,
            Self::DecideProfessionalAbandonment { decision }
                if matches!(
                    &decision.disposition,
                    TaskControllerDisposition::AcceptPartial { .. }
                ) =>
            {
                TaskState::Partial
            }
            Self::SetProfessionalExecutionContract { .. }
            | Self::ReportProfessionalAttempt { .. }
            | Self::ChangeProfessionalApproach { .. }
            | Self::DecideProfessionalAbandonment { .. }
            | Self::RecordProfessionalCompletionEvidence { .. } => current,
        }
    }

    fn validate(&self) -> Result<(), TaskError> {
        match self {
            Self::Frame { frame_ref } => text(frame_ref, "frame_ref"),
            Self::AuthorizeAction {
                authority_ref,
                understanding_ref,
            } => {
                text(authority_ref, "authority_ref")?;
                text(understanding_ref, "understanding_ref")
            }
            Self::Verify { verification_ref } => text(verification_ref, "verification_ref"),
            Self::Block { reason_ref } | Self::Fail { reason_ref } => {
                text(reason_ref, "reason_ref")
            }
            Self::MarkPartial { result_ref } => text(result_ref, "result_ref"),
            Self::Reopen { reopen_ref } => text(reopen_ref, "reopen_ref"),
            Self::SetProfessionalExecutionContract { contract } => contract
                .validate()
                .map_err(TaskError::ProfessionalExecution),
            Self::ReportProfessionalAttempt {
                attempt,
                signal_ref,
                ..
            }
            | Self::ChangeProfessionalApproach {
                attempt,
                signal_ref,
                ..
            } => {
                if matches!(
                    self,
                    Self::ReportProfessionalAttempt {
                        outcome: ProfessionalAttemptOutcome::ApproachChanged,
                        ..
                    }
                ) {
                    return Err(TaskError::InvalidField("approach_revision_required"));
                }
                text(&attempt.attempt_ref, "attempt_ref")?;
                text(&attempt.reason, "attempt_reason")?;
                text(signal_ref, "signal_ref")
            }
            Self::DecideProfessionalAbandonment { decision } => match &decision.disposition {
                TaskControllerDisposition::Reframe { rationale }
                | TaskControllerDisposition::Supersede { rationale } => {
                    text(rationale, "rationale")
                }
                TaskControllerDisposition::AcceptPartial { acceptance_ref } => {
                    text(acceptance_ref, "acceptance_ref")
                }
                TaskControllerDisposition::RequestHumanInput { question } => {
                    text(question, "question")
                }
            },
            Self::RecordProfessionalCompletionEvidence { evidence } => {
                text(&evidence.artifact_manifest.manifest_ref, "manifest_ref")
            }
            Self::Open
            | Self::RequireUnderstanding
            | Self::BeginExecution
            | Self::BeginVerification => Ok(()),
        }
    }
}

/// Immutable admission context for one lifecycle command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskCommandContext {
    pub request_id: String,
    pub event_id: String,
    pub actor_ref: String,
    pub state_fence: StateFence,
    pub authority_epoch: EpochId,
    pub observed_at: ClockReading,
}

impl TaskCommandContext {
    fn validate(&self) -> Result<(), TaskError> {
        text(&self.request_id, "request_id")?;
        text(&self.event_id, "event_id")?;
        text(&self.actor_ref, "actor_ref")?;
        self.state_fence
            .validate()
            .map_err(|_| TaskError::FenceMismatch)
    }
}

/// The only command that creates a task record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskProposal {
    pub task_id: TaskId,
    pub project_ref: String,
    pub goal: String,
    pub context: TaskCommandContext,
}

/// Durable event emitted for every accepted command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskLifecycleEvent {
    pub sequence: u64,
    pub event_id: String,
    pub request_id: String,
    pub task_id: TaskId,
    pub actor_ref: String,
    pub from: Option<TaskState>,
    pub to: TaskState,
    pub command: Option<TaskCommand>,
    /// Updated professional state carried with the lifecycle event so its
    /// derived signals and decisions travel through the same canonical write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub professional_execution: Option<ProfessionalExecutionState>,
    pub state_fence: StateFence,
    pub authority_epoch: EpochId,
    pub observed_at: ClockReading,
}

/// Current canonical projection for a task.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskRecord {
    pub task_id: TaskId,
    pub project_ref: String,
    pub goal: String,
    pub state: TaskState,
    pub revision: u64,
    pub last_sequence: u64,
    pub last_event_id: String,
    pub state_fence: StateFence,
}

/// A read-only owner image suitable for canonical persistence and recovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskLifecycleSnapshot {
    pub next_sequence: u64,
    pub tasks: BTreeMap<TaskId, TaskRecord>,
    pub events: Vec<TaskLifecycleEvent>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub professional_execution: BTreeMap<TaskId, ProfessionalExecutionState>,
}

/// Deterministic owner of all task lifecycle transitions in one fence.
#[derive(Clone, Debug)]
pub struct TaskLifecycleOwner {
    authority_epoch: EpochId,
    state_fence: StateFence,
    next_sequence: u64,
    tasks: BTreeMap<TaskId, TaskRecord>,
    events: Vec<TaskLifecycleEvent>,
    professional_execution: BTreeMap<TaskId, ProfessionalExecutionState>,
    requests: BTreeMap<String, (TaskId, Option<TaskCommand>, TaskLifecycleEvent)>,
}

impl TaskLifecycleOwner {
    /// Creates an empty owner.  The fence is the owner-wide admission boundary.
    pub fn new(authority_epoch: EpochId, state_fence: StateFence) -> Result<Self, TaskError> {
        state_fence
            .validate()
            .map_err(|_| TaskError::FenceMismatch)?;
        if !authority_epoch.is_same_authority(&state_fence.authority_epoch) {
            return Err(TaskError::EpochMismatch);
        }
        Ok(Self {
            authority_epoch,
            state_fence,
            next_sequence: 1,
            tasks: BTreeMap::new(),
            events: Vec::new(),
            professional_execution: BTreeMap::new(),
            requests: BTreeMap::new(),
        })
    }

    /// Rebuilds an owner from its canonical snapshot; malformed ordering is rejected.
    pub fn from_snapshot(
        authority_epoch: EpochId,
        state_fence: StateFence,
        snapshot: TaskLifecycleSnapshot,
    ) -> Result<Self, TaskError> {
        let mut owner = Self::new(authority_epoch, state_fence)?;
        if snapshot.next_sequence == 0
            || snapshot.next_sequence != snapshot.events.len() as u64 + 1
            || snapshot
                .events
                .iter()
                .enumerate()
                .any(|(i, event)| event.sequence != (i as u64 + 1))
        {
            return Err(TaskError::CausalSequenceMismatch);
        }
        for record in snapshot.tasks.values() {
            if record.revision == 0
                || record.last_sequence == 0
                || record.state_fence != owner.state_fence
            {
                return Err(TaskError::FenceMismatch);
            }
            owner.tasks.insert(record.task_id.clone(), record.clone());
        }
        if snapshot
            .professional_execution
            .keys()
            .any(|task_id| !owner.tasks.contains_key(task_id))
        {
            return Err(TaskError::InvalidField("professional_execution_task"));
        }
        owner.professional_execution = snapshot.professional_execution;
        owner.next_sequence = snapshot.next_sequence;
        owner.events = snapshot.events;
        let mut event_completion_evidence: BTreeMap<TaskId, Vec<ProfessionalCompletionEvidence>> =
            BTreeMap::new();
        for event in &owner.events {
            if let Some(TaskCommand::RecordProfessionalCompletionEvidence { evidence }) =
                &event.command
            {
                let state = event
                    .professional_execution
                    .as_ref()
                    .ok_or(TaskError::InvalidField("professional_completion_history"))?;
                let mut checked = ProfessionalExecutionState::new(state.contract.clone())?;
                checked.record_completion_evidence(*evidence.clone())?;
                event_completion_evidence
                    .entry(event.task_id.clone())
                    .or_default()
                    .push(*evidence.clone());
            }
            if let Some(state) = &event.professional_execution {
                let recorded = event_completion_evidence
                    .get(&event.task_id)
                    .map_or(&[][..], Vec::as_slice);
                if state.completion_evidence.as_slice() != recorded {
                    return Err(TaskError::InvalidField("professional_completion_history"));
                }
            }
        }
        for (task_id, state) in &owner.professional_execution {
            if !state.completion_evidence.is_empty()
                && event_completion_evidence
                    .get(task_id)
                    .is_none_or(|recorded| *recorded != state.completion_evidence)
            {
                return Err(TaskError::InvalidField("professional_completion_history"));
            }
        }
        for event in &owner.events {
            if let Some(state) = &event.professional_execution {
                owner
                    .professional_execution
                    .insert(event.task_id.clone(), state.clone());
            }
        }
        for event in &owner.events {
            if let Some(command) = &event.command {
                owner.requests.insert(
                    event.request_id.clone(),
                    (event.task_id.clone(), Some(command.clone()), event.clone()),
                );
            }
        }
        Ok(owner)
    }

    /// Admits a proposed task and emits its first lifecycle event.
    pub fn propose(&mut self, proposal: TaskProposal) -> Result<TaskLifecycleEvent, TaskError> {
        proposal.context.validate()?;
        self.check_context(&proposal.context)?;
        text(&proposal.project_ref, "project_ref")?;
        text(&proposal.goal, "goal")?;
        if let Some((known_task, known_command, event)) =
            self.requests.get(&proposal.context.request_id)
        {
            if known_task == &proposal.task_id && known_command.is_none() {
                return Ok(event.clone());
            }
            return Err(TaskError::IdempotencyConflict(proposal.context.request_id));
        }
        if self.tasks.contains_key(&proposal.task_id) {
            return Err(TaskError::DuplicateTask(proposal.task_id.clone()));
        }
        let event = self.emit(
            &proposal.context,
            proposal.task_id.clone(),
            None,
            TaskState::Proposed,
            None,
            None,
        );
        self.tasks.insert(
            proposal.task_id.clone(),
            TaskRecord {
                task_id: proposal.task_id.clone(),
                project_ref: proposal.project_ref,
                goal: proposal.goal,
                state: TaskState::Proposed,
                revision: 1,
                last_sequence: event.sequence,
                last_event_id: event.event_id.clone(),
                state_fence: self.state_fence.clone(),
            },
        );
        self.requests.insert(
            proposal.context.request_id.clone(),
            (proposal.task_id.clone(), None, event.clone()),
        );
        Ok(event)
    }

    /// Applies one guarded transition.  Replaying the same request returns the original event.
    pub fn apply(
        &mut self,
        task_id: TaskId,
        context: TaskCommandContext,
        command: TaskCommand,
    ) -> Result<TaskLifecycleEvent, TaskError> {
        context.validate()?;
        command.validate()?;
        self.check_context(&context)?;
        if let Some((known_task, known_command, event)) = self.requests.get(&context.request_id) {
            if known_task == &task_id && known_command.as_ref() == Some(&command) {
                return Ok(event.clone());
            }
            return Err(TaskError::IdempotencyConflict(context.request_id));
        }
        let current = self
            .tasks
            .get(&task_id)
            .ok_or_else(|| TaskError::TaskNotFound(task_id.clone()))?
            .clone();
        let expected = context
            .state_fence
            .task_revision
            .as_ref()
            .map_or(current.revision, |revision| revision.value());
        if expected != current.revision {
            return Err(TaskError::RevisionMismatch {
                expected,
                current: current.revision,
            });
        }
        if matches!(command, TaskCommand::Verify { .. })
            && let Some(state) = self.professional_execution.get(&task_id)
        {
            state.require_evaluator_result()?;
        }
        if matches!(
            command,
            TaskCommand::Block { .. } | TaskCommand::Fail { .. }
        ) && self
            .professional_execution
            .get(&task_id)
            .is_some_and(|state| !state.latest_attempt_stopped_with_signal())
        {
            return Err(TaskError::MissingEvidence {
                field: "premature_abandonment_signal",
            });
        }
        if matches!(command, TaskCommand::MarkPartial { .. })
            && self.professional_execution.contains_key(&task_id)
        {
            return Err(TaskError::MissingEvidence {
                field: "task_controller_partial_disposition",
            });
        }
        let target = command.target(current.state);
        if !allowed(current.state, &command) {
            return Err(TaskError::IllegalTransition {
                from: current.state,
                to: target,
            });
        }
        let mut next_professional_execution = self.professional_execution.clone();
        Self::apply_professional_command(
            &mut next_professional_execution,
            &task_id,
            &context,
            &command,
        )?;
        let event = self.emit(
            &context,
            task_id.clone(),
            Some(current.state),
            target,
            Some(command.clone()),
            next_professional_execution.get(&task_id).cloned(),
        );
        self.professional_execution = next_professional_execution;
        let record = self
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| TaskError::TaskNotFound(task_id.clone()))?;
        record.state = target;
        record.revision += 1;
        record.last_sequence = event.sequence;
        record.last_event_id.clone_from(&event.event_id);
        self.requests
            .insert(context.request_id, (task_id, Some(command), event.clone()));
        Ok(event)
    }

    #[must_use]
    pub fn task(&self, task_id: &TaskId) -> Option<&TaskRecord> {
        self.tasks.get(task_id)
    }

    #[must_use]
    pub fn events(&self) -> &[TaskLifecycleEvent] {
        &self.events
    }

    #[must_use]
    pub fn snapshot(&self) -> TaskLifecycleSnapshot {
        TaskLifecycleSnapshot {
            next_sequence: self.next_sequence,
            tasks: self.tasks.clone(),
            events: self.events.clone(),
            professional_execution: self.professional_execution.clone(),
        }
    }

    fn check_context(&self, context: &TaskCommandContext) -> Result<(), TaskError> {
        if !context
            .authority_epoch
            .is_same_authority(&self.authority_epoch)
        {
            return Err(TaskError::EpochMismatch);
        }
        if !self.state_fence.is_compatible_with(&context.state_fence) {
            return Err(TaskError::FenceMismatch);
        }
        Ok(())
    }

    fn emit(
        &mut self,
        context: &TaskCommandContext,
        task_id: TaskId,
        from: Option<TaskState>,
        to: TaskState,
        command: Option<TaskCommand>,
        professional_execution: Option<ProfessionalExecutionState>,
    ) -> TaskLifecycleEvent {
        let event = TaskLifecycleEvent {
            sequence: self.next_sequence,
            event_id: context.event_id.clone(),
            request_id: context.request_id.clone(),
            task_id,
            actor_ref: context.actor_ref.clone(),
            from,
            to,
            command,
            professional_execution,
            state_fence: context.state_fence.clone(),
            authority_epoch: context.authority_epoch.clone(),
            observed_at: context.observed_at,
        };
        self.next_sequence += 1;
        self.events.push(event.clone());
        event
    }

    fn apply_professional_command(
        professional_execution: &mut BTreeMap<TaskId, ProfessionalExecutionState>,
        task_id: &TaskId,
        context: &TaskCommandContext,
        command: &TaskCommand,
    ) -> Result<(), TaskError> {
        match command {
            TaskCommand::SetProfessionalExecutionContract { contract } => {
                if professional_execution.contains_key(task_id) {
                    return Err(ProfessionalExecutionError::ContractAlreadyExists.into());
                }
                professional_execution.insert(
                    task_id.clone(),
                    ProfessionalExecutionState::new(*contract.clone())?,
                );
            }
            TaskCommand::ReportProfessionalAttempt {
                attempt,
                outcome,
                signal_ref,
            } => {
                let state = professional_execution
                    .get_mut(task_id)
                    .ok_or(ProfessionalExecutionError::ContractNotFound)?;
                state.record_attempt(
                    task_id.clone(),
                    context.state_fence.clone(),
                    *attempt.clone(),
                    *outcome,
                    signal_ref.clone(),
                )?;
            }
            TaskCommand::ChangeProfessionalApproach {
                revision,
                attempt,
                signal_ref,
            } => {
                let state = professional_execution
                    .get_mut(task_id)
                    .ok_or(ProfessionalExecutionError::ContractNotFound)?;
                state.change_approach(
                    *revision.clone(),
                    task_id.clone(),
                    context.state_fence.clone(),
                    *attempt.clone(),
                    signal_ref.clone(),
                )?;
            }
            TaskCommand::DecideProfessionalAbandonment { decision } => {
                let state = professional_execution
                    .get_mut(task_id)
                    .ok_or(ProfessionalExecutionError::ContractNotFound)?;
                state.decide(*decision.clone())?;
            }
            TaskCommand::RecordProfessionalCompletionEvidence { evidence } => {
                let state = professional_execution
                    .get_mut(task_id)
                    .ok_or(ProfessionalExecutionError::ContractNotFound)?;
                state.record_completion_evidence(*evidence.clone())?;
            }
            _ => {}
        }
        Ok(())
    }
}

fn allowed(from: TaskState, command: &TaskCommand) -> bool {
    match command {
        TaskCommand::Open => from == TaskState::Proposed,
        TaskCommand::Frame { .. } => from == TaskState::Open,
        TaskCommand::RequireUnderstanding => from == TaskState::Framed,
        TaskCommand::AuthorizeAction { .. } => from == TaskState::UnderstandingRequired,
        TaskCommand::BeginExecution => from == TaskState::ActionAuthorized,
        TaskCommand::BeginVerification => from == TaskState::Executing,
        TaskCommand::Verify { .. } | TaskCommand::RecordProfessionalCompletionEvidence { .. } => {
            from == TaskState::Verifying
        }
        TaskCommand::Block { .. } | TaskCommand::Fail { .. } | TaskCommand::MarkPartial { .. } => {
            from.is_active()
        }
        TaskCommand::Reopen { .. } => from.is_terminal(),
        TaskCommand::SetProfessionalExecutionContract { .. } => from.is_active(),
        TaskCommand::ReportProfessionalAttempt { .. }
        | TaskCommand::ChangeProfessionalApproach { .. } => {
            matches!(from, TaskState::Executing | TaskState::Verifying)
        }
        TaskCommand::DecideProfessionalAbandonment { .. } => from != TaskState::DoneVerified,
    }
}
