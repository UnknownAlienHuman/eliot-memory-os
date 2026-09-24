//! G-19 governed task lifecycle ownership.
//!
//! This crate is the sole in-memory authority for task state transitions.  It
//! does not execute work or persist records: callers persist the returned event
//! and snapshot through the canonical write path.  Every mutation is fenced,
//! causally sequenced, and idempotent so a retry cannot create a second task
//! transition.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_contracts::{
    ClockReading, EpochId, StateFence, TaskId, canonical_json_bytes, fences_match_exact, sha256_hex,
};
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
    #[error("task state does not permit this operation")]
    InvalidState,
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
}

/// Deterministic owner of all task lifecycle transitions in one fence.
#[derive(Clone, Debug)]
pub struct TaskLifecycleOwner {
    authority_epoch: EpochId,
    state_fence: StateFence,
    next_sequence: u64,
    tasks: BTreeMap<TaskId, TaskRecord>,
    events: Vec<TaskLifecycleEvent>,
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
            authority_epoch: context.authority_epoch.clone(),
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

/// Stable owner identity for the existing Task Controller compilation seam.
///
/// The value is fixed by the owner implementation. Consumers may read it from
/// a receipt, but cannot supply it as a compiler identity and thereby mint an
/// authority receipt.
pub const TASK_GRAPH_COMPILER_OWNER: &str = "eliot.task-controller";

/// Version of the owner-issued task-graph compilation projection.
pub const TASK_GRAPH_COMPILATION_RECEIPT_VERSION: &str = "eliot.task.graph-compilation-receipt.v1";

fn digest_text(value: &str, field: &'static str) -> Result<(), TaskError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(TaskError::InvalidField(field));
    }
    Ok(())
}

/// A typed, owner-neutral request for the existing Task Controller to bind
/// inquiry obligations to a live task definition.
///
/// This is a compilation projection, not a graph. The owner checks the request
/// against its current task record before issuing [`TaskGraphCompilationReceipt`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskGraphCompilationRequest {
    /// Exact task whose current definition is being compiled against.
    pub task_id: TaskId,
    /// Digest derived by the Task Controller from the current task record.
    pub task_definition_digest: String,
    /// Inquiry profile identity being compiled.
    pub profile_id: String,
    /// Inquiry profile revision being compiled.
    pub profile_revision: u64,
    /// Exact inquiry profile digest.
    pub profile_digest: String,
    /// Stable obligation identities, paired with `obligation_digests`.
    pub obligation_ids: Vec<String>,
    /// Exact obligation digests, paired with `obligation_ids`.
    pub obligation_digests: Vec<String>,
    /// Exact fence at which the task definition and profile are valid.
    pub state_fence: StateFence,
}

impl TaskGraphCompilationRequest {
    /// Validates the request shape without granting compilation authority.
    pub fn validate(&self) -> Result<(), TaskError> {
        text(self.task_id.as_str(), "task_graph.task_id")?;
        digest_text(
            &self.task_definition_digest,
            "task_graph.task_definition_digest",
        )?;
        text(&self.profile_id, "task_graph.profile_id")?;
        if self.profile_revision == 0 {
            return Err(TaskError::InvalidField("task_graph.profile_revision"));
        }
        digest_text(&self.profile_digest, "task_graph.profile_digest")?;
        self.state_fence
            .validate()
            .map_err(|_| TaskError::FenceMismatch)?;
        if self.obligation_ids.is_empty()
            || self.obligation_ids.len() != self.obligation_digests.len()
        {
            return Err(TaskError::InvalidField("task_graph.obligation_set"));
        }
        let mut ids = std::collections::BTreeSet::new();
        for (id, digest) in self.obligation_ids.iter().zip(&self.obligation_digests) {
            text(id, "task_graph.obligation_id")?;
            digest_text(digest, "task_graph.obligation_digest")?;
            if !ids.insert(id) {
                return Err(TaskError::InvalidField("task_graph.obligation_id"));
            }
        }
        Ok(())
    }
}

/// Typed receipt issued by the existing Task Controller owner.
///
/// Fields are private on purpose: a caller can consume and validate this
/// receipt, but cannot construct a successful owner receipt by choosing an
/// issuer string. The receipt carries no graph state and no canonical/admission
/// authority; it is a candidate binding for the existing work-graph owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskGraphCompilationReceipt {
    owner: String,
    version: String,
    task_id: TaskId,
    task_revision: u64,
    task_definition_digest: String,
    profile_id: String,
    profile_revision: u64,
    profile_digest: String,
    obligation_ids: Vec<String>,
    obligation_digests: Vec<String>,
    state_fence: StateFence,
    candidate_only: bool,
    canonical_write_authorized: bool,
    digest: String,
}

impl TaskGraphCompilationReceipt {
    fn compute_digest(&self) -> Result<String, TaskError> {
        let bytes = canonical_json_bytes(&(
            &self.owner,
            &self.version,
            &self.task_id,
            &self.task_revision,
            &self.task_definition_digest,
            &self.profile_id,
            &self.profile_revision,
            &self.profile_digest,
            &self.obligation_ids,
            &self.obligation_digests,
            &self.state_fence,
            &self.candidate_only,
            &self.canonical_write_authorized,
        ))
        .map_err(|_| TaskError::InvalidField("task_graph.receipt_digest"))?;
        Ok(sha256_hex(&bytes))
    }

    /// Returns the fixed owner identity that issued this receipt.
    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.owner
    }

    /// Returns the receipt wire version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the exact task identity.
    #[must_use]
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Returns the task revision observed by the owner.
    #[must_use]
    pub const fn task_revision(&self) -> u64 {
        self.task_revision
    }

    /// Returns the exact task-definition digest.
    #[must_use]
    pub fn task_definition_digest(&self) -> &str {
        &self.task_definition_digest
    }

    /// Returns the profile identity and revision bound by the owner.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Returns the profile revision bound by the owner.
    #[must_use]
    pub const fn profile_revision(&self) -> u64 {
        self.profile_revision
    }

    /// Returns the exact profile digest bound by the owner.
    #[must_use]
    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    /// Returns the sorted obligation identities.
    #[must_use]
    pub fn obligation_ids(&self) -> &[String] {
        &self.obligation_ids
    }

    /// Returns the sorted obligation digests paired with [`Self::obligation_ids`].
    #[must_use]
    pub fn obligation_digests(&self) -> &[String] {
        &self.obligation_digests
    }

    /// Returns the exact fence used by the owner.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Receipts are always candidate-only.
    #[must_use]
    pub const fn candidate_only(&self) -> bool {
        self.candidate_only
    }

    /// Receipts never authorize a canonical write.
    #[must_use]
    pub const fn canonical_write_authorized(&self) -> bool {
        self.canonical_write_authorized
    }

    /// Returns the recomputed receipt digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Checks that this owner receipt is still exactly bound to the request
    /// that the caller is compiling. This is deliberately explicit at the
    /// consumer edge rather than trusting a serialized issuer field.
    pub fn validate_against(&self, request: &TaskGraphCompilationRequest) -> Result<(), TaskError> {
        request.validate()?;
        if self.owner != TASK_GRAPH_COMPILER_OWNER
            || self.version != TASK_GRAPH_COMPILATION_RECEIPT_VERSION
            || self.task_id != request.task_id
            || self.task_definition_digest != request.task_definition_digest
            || self.profile_id != request.profile_id
            || self.profile_revision != request.profile_revision
            || self.profile_digest != request.profile_digest
            || self.obligation_ids != request.obligation_ids
            || self.obligation_digests != request.obligation_digests
            || !fences_match_exact(&self.state_fence, &request.state_fence)
            || !self.candidate_only
            || self.canonical_write_authorized
            || self.digest != self.compute_digest()?
        {
            return Err(TaskError::InvalidField("task_graph.receipt_binding"));
        }
        Ok(())
    }
}

impl TaskLifecycleOwner {
    /// Derives the exact definition identity for a live task record.
    ///
    /// The digest covers the current task ID, project, goal, revision and full
    /// fence. It is recomputed on every compilation request; a caller cannot
    /// substitute a free-standing task-definition string.
    pub fn task_definition_digest(&self, task_id: &TaskId) -> Result<String, TaskError> {
        let record = self
            .task(task_id)
            .ok_or_else(|| TaskError::TaskNotFound(task_id.clone()))?;
        let bytes = canonical_json_bytes(&(
            task_id,
            &record.project_ref,
            &record.goal,
            record.revision,
            &record.state_fence,
        ))
        .map_err(|_| TaskError::InvalidField("task_graph.task_definition_digest"))?;
        Ok(sha256_hex(&bytes))
    }

    /// Issues the only successful task-graph compilation receipt for an
    /// inquiry obligation set.
    ///
    /// The method is on the existing Task Controller lifecycle owner and
    /// deliberately does not retain obligations or construct a second graph.
    /// It re-reads the live task record and rejects stale or caller-forged
    /// bindings before returning the typed owner receipt.
    pub fn compile_inquiry_obligations(
        &self,
        request: TaskGraphCompilationRequest,
    ) -> Result<TaskGraphCompilationReceipt, TaskError> {
        request.validate()?;
        let record = self
            .task(&request.task_id)
            .ok_or_else(|| TaskError::TaskNotFound(request.task_id.clone()))?;
        if !record.state.is_active() {
            return Err(TaskError::InvalidState);
        }
        if !fences_match_exact(&record.state_fence, &self.state_fence)
            || !fences_match_exact(&request.state_fence, &self.state_fence)
        {
            return Err(TaskError::FenceMismatch);
        }
        let current_task_definition = self.task_definition_digest(&request.task_id)?;
        if request.task_definition_digest != current_task_definition || record.revision == 0 {
            return Err(TaskError::InvalidField("task_graph.task_definition_digest"));
        }

        let mut pairs = request
            .obligation_ids
            .iter()
            .cloned()
            .zip(request.obligation_digests.iter().cloned())
            .collect::<Vec<_>>();
        pairs.sort_by(|left, right| left.0.cmp(&right.0));
        let (obligation_ids, obligation_digests) = pairs.into_iter().unzip();
        let mut receipt = TaskGraphCompilationReceipt {
            owner: TASK_GRAPH_COMPILER_OWNER.to_owned(),
            version: TASK_GRAPH_COMPILATION_RECEIPT_VERSION.to_owned(),
            task_id: request.task_id,
            task_revision: record.revision,
            task_definition_digest: request.task_definition_digest,
            profile_id: request.profile_id,
            profile_revision: request.profile_revision,
            profile_digest: request.profile_digest,
            obligation_ids,
            obligation_digests,
            state_fence: request.state_fence,
            candidate_only: true,
            canonical_write_authorized: false,
            digest: String::new(),
        };
        receipt.digest = receipt.compute_digest()?;
        Ok(receipt)
    }
}
