//! G-19 governed task lifecycle ownership.
//!
//! This crate is the sole in-memory authority for task state transitions.  It
//! does not execute work or persist records: callers persist the returned event
//! and snapshot through the canonical write path.  Every mutation is fenced,
//! causally sequenced, and idempotent so a retry cannot create a second task
//! transition.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_contracts::{AuthorityEpoch, ClockReading, StateFence, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
}

impl TaskCommand {
    fn target(&self) -> TaskState {
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
            Self::MarkPartial { .. } => TaskState::Partial,
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
    pub authority_epoch: AuthorityEpoch,
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
    pub state_fence: StateFence,
    pub authority_epoch: AuthorityEpoch,
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
}

/// Deterministic owner of all task lifecycle transitions in one fence.
#[derive(Clone, Debug)]
pub struct TaskLifecycleOwner {
    authority_epoch: AuthorityEpoch,
    state_fence: StateFence,
    next_sequence: u64,
    tasks: BTreeMap<TaskId, TaskRecord>,
    events: Vec<TaskLifecycleEvent>,
    requests: BTreeMap<String, (TaskId, Option<TaskCommand>, TaskLifecycleEvent)>,
}

impl TaskLifecycleOwner {
    /// Creates an empty owner.  The fence is the owner-wide admission boundary.
    pub fn new(
        authority_epoch: AuthorityEpoch,
        state_fence: StateFence,
    ) -> Result<Self, TaskError> {
        state_fence
            .validate()
            .map_err(|_| TaskError::FenceMismatch)?;
        if authority_epoch != state_fence.authority_epoch {
            return Err(TaskError::EpochMismatch);
        }
        Ok(Self {
            authority_epoch,
            state_fence,
            next_sequence: 1,
            tasks: BTreeMap::new(),
            events: Vec::new(),
            requests: BTreeMap::new(),
        })
    }

    /// Rebuilds an owner from its canonical snapshot; malformed ordering is rejected.
    pub fn from_snapshot(
        authority_epoch: AuthorityEpoch,
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
        owner.next_sequence = snapshot.next_sequence;
        owner.events = snapshot.events;
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
        let target = command.target();
        if !allowed(current.state, &command) {
            return Err(TaskError::IllegalTransition {
                from: current.state,
                to: target,
            });
        }
        let event = self.emit(
            &context,
            task_id.clone(),
            Some(current.state),
            target,
            Some(command.clone()),
        );
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
        }
    }

    fn check_context(&self, context: &TaskCommandContext) -> Result<(), TaskError> {
        if context.authority_epoch != self.authority_epoch {
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
            state_fence: context.state_fence.clone(),
            authority_epoch: context.authority_epoch,
            observed_at: context.observed_at,
        };
        self.next_sequence += 1;
        self.events.push(event.clone());
        event
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
        TaskCommand::Verify { .. } => from == TaskState::Verifying,
        TaskCommand::Block { .. } | TaskCommand::Fail { .. } | TaskCommand::MarkPartial { .. } => {
            from.is_active()
        }
        TaskCommand::Reopen { .. } => from.is_terminal(),
    }
}
