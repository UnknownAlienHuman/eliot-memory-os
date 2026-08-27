//! G-18 durable multi-actor coordination ownership.
//!
//! The coordinator is deliberately a deterministic state owner.  It accepts
//! immutable commands, applies one causal sequence to each accepted event, and
//! keeps assignment, lease, mailbox, checkpoint and result state together.  A
//! caller may persist the returned snapshot/event stream in the canonical store;
//! this crate performs no I/O and never treats a worker's conclusion as truth.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{AuthorityEpoch, ClockReading, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.governor.coordination";
pub const CONTRACT_VERSION: eliot_contracts::ContractVersion =
    eliot_contracts::ContractVersion::new(1, 0, 0);

fn text(value: &str, field: &'static str) -> Result<(), CoordinationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CoordinationError::InvalidField(field));
    }
    Ok(())
}

fn nonzero(value: u64, field: &'static str) -> Result<(), CoordinationError> {
    if value == 0 {
        Err(CoordinationError::InvalidField(field))
    } else {
        Ok(())
    }
}

/// Fail-closed errors returned by coordination commands.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CoordinationError {
    #[error("invalid coordination field: {0}")]
    InvalidField(&'static str),
    #[error("unknown {kind}: {id}")]
    NotFound { kind: &'static str, id: String },
    #[error("idempotency key {0} was reused with different input")]
    IdempotencyConflict(String),
    #[error("state fence mismatch")]
    FenceMismatch,
    #[error("authority epoch mismatch")]
    EpochMismatch,
    #[error("lease is not held by {holder}")]
    LeaseOwnerMismatch { holder: String },
    #[error("lease is expired")]
    LeaseExpired,
    #[error("session heartbeat deadline is expired")]
    SessionExpired,
    #[error("lease is not yet valid")]
    LeaseNotYetValid,
    #[error("work item is already owned")]
    WorkAlreadyOwned,
    #[error("invalid lifecycle transition from {from} to {to}")]
    IllegalTransition { from: String, to: String },
    #[error("duplicate identity: {0}")]
    Duplicate(String),
    #[error("event predecessor is not the current sequence")]
    CausalPredecessorMismatch,
    #[error("operation is not permitted in the current state")]
    InvalidState,
    #[error("no active work binding exists")]
    NoActiveBinding,
    #[error("multiple active work bindings exist")]
    AmbiguousActiveBinding,
}

/// Lifecycle of an attached actor session.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionState {
    Active,
    Quiescing,
    Lost,
    Closed,
}

/// Durable lifecycle of one assigned work item.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkState {
    Ready,
    Claimed,
    Running,
    Checkpointed,
    Submitted,
    Reassigned,
    Cancelled,
    Failed,
}

/// Coordination event kind; all state-changing commands produce one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationEventKind {
    SessionRegistered,
    WorkRegistered,
    WorkClaimed,
    Heartbeat,
    MessageSent,
    Checkpointed,
    ResultSubmitted,
    IntegrationCandidateSubmitted,
    IntegrationClaimed,
    WorkReassigned,
    ReadyAdmitted,
}

/// A durable, idempotent event with its exact causal and fencing context.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoordinationEvent {
    pub sequence: u64,
    pub event_id: String,
    pub idempotency_key: String,
    pub kind: CoordinationEventKind,
    pub subject_id: String,
    pub actor_id: String,
    pub predecessor: Option<u64>,
    pub state_fence: StateFence,
    pub authority_epoch: AuthorityEpoch,
    pub payload_digest: String,
    pub observed_at: ClockReading,
}

/// A registered actor and its latest liveness observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSession {
    pub session_id: String,
    pub principal_id: String,
    pub route_ref: String,
    pub state: SessionState,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub last_heartbeat: u64,
    pub heartbeat_deadline: u64,
}

/// A durable item that may be claimed by exactly one live lease.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkItem {
    pub work_item_id: String,
    pub task_id: String,
    pub state: WorkState,
    pub state_fence: StateFence,
    pub owner_session_id: Option<String>,
    pub lease_id: Option<String>,
    pub attempt: u32,
    pub checkpoint_ref: Option<String>,
    pub result_ref: Option<String>,
}

/// The bounded authority to advance one work item.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkLease {
    pub lease_id: String,
    pub work_item_id: String,
    pub holder_session_id: String,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub issued_at: u64,
    pub expires_at: u64,
    pub last_heartbeat: u64,
}

/// The exact, cloned coordination records needed to inspect one live lease.
///
/// This projection deliberately carries the already-validated active session
/// alongside the work item and lease.  A resolver can therefore consume one
/// coherent read result without reconstructing authority from raw maps.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActiveWorkLeaseProjection {
    pub session: AgentSession,
    pub work_item: WorkItem,
    pub lease: WorkLease,
}

/// Exact assignment request.  `request_id` is the retry identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkLeaseRequest {
    pub request_id: String,
    pub lease_id: String,
    pub work_item_id: String,
    pub session_id: String,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub now: u64,
    pub lease_duration: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkLeaseDecision {
    pub lease: WorkLease,
    pub event: CoordinationEvent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterSession {
    pub request_id: String,
    pub session_id: String,
    pub principal_id: String,
    pub route_ref: String,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub now: u64,
    pub heartbeat_deadline: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentHeartbeat {
    pub request_id: String,
    pub session_id: String,
    pub lease_id: String,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub now: u64,
    pub extend_to: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatAck {
    pub lease: WorkLease,
    pub event: CoordinationEvent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailboxMessageDraft {
    pub request_id: String,
    pub message_id: String,
    pub sender_session_id: String,
    pub recipient_session_id: String,
    pub work_item_id: String,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub payload_digest: String,
    pub now: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailboxMessage {
    pub message_id: String,
    pub sender_session_id: String,
    pub recipient_session_id: String,
    pub work_item_id: String,
    pub payload_digest: String,
    pub delivered: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailboxReceipt {
    pub message: MailboxMessage,
    pub event: CoordinationEvent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkCheckpoint {
    pub request_id: String,
    pub checkpoint_id: String,
    pub lease_id: String,
    pub session_id: String,
    pub work_item_id: String,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub checkpoint_ref: String,
    pub now: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckpointReceipt {
    pub checkpoint_id: String,
    pub work_item_id: String,
    pub event: CoordinationEvent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentResultDraft {
    pub request_id: String,
    pub result_id: String,
    pub lease_id: String,
    pub session_id: String,
    pub work_item_id: String,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub result_ref: String,
    pub now: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentResultReceipt {
    pub result_id: String,
    pub work_item_id: String,
    pub event: CoordinationEvent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationCandidateDraft {
    pub request_id: String,
    pub candidate_id: String,
    pub source_work_item_id: String,
    pub session_id: String,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub candidate_ref: String,
    pub target_scope: String,
    pub now: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationCandidateReceipt {
    pub candidate_id: String,
    pub target_scope: String,
    pub event: CoordinationEvent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationLeaseRequest {
    pub request_id: String,
    pub lease_id: String,
    pub target_scope: String,
    pub session_id: String,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub now: u64,
    pub lease_duration: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationLease {
    pub lease_id: String,
    pub target_scope: String,
    pub holder_session_id: String,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub expires_at: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationLeaseDecision {
    pub lease: IntegrationLease,
    pub event: CoordinationEvent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReassignWorkRequest {
    pub request_id: String,
    pub work_item_id: String,
    pub old_lease_id: String,
    pub new_lease_id: String,
    pub new_session_id: String,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub now: u64,
    pub lease_duration: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoordinationEventDraft {
    pub request_id: String,
    pub event_id: String,
    pub kind: CoordinationEventKind,
    pub subject_id: String,
    pub actor_id: String,
    pub predecessor: Option<u64>,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub payload_digest: String,
    pub observed_at: ClockReading,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoordinationEventReceipt {
    pub event: CoordinationEvent,
}

/// ELIOT_ARCH_OWNER: ARCH-SWM-02
/// An in-memory canonical owner suitable for a store adapter or daemon cell.
#[allow(clippy::doc_markdown)]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CoordinationOwner {
    sequence: u64,
    sessions: BTreeMap<String, AgentSession>,
    work: BTreeMap<String, WorkItem>,
    leases: BTreeMap<String, WorkLease>,
    integrations: BTreeMap<String, IntegrationLease>,
    messages: BTreeMap<String, MailboxMessage>,
    event_by_request: BTreeMap<String, CoordinationEvent>,
    events: Vec<CoordinationEvent>,
}

impl CoordinationOwner {
    /// Creates an empty owner at the genesis causal sequence.
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuilds one owner from a canonical serialized image.
    ///
    /// The image is validated before it can be admitted: event sequences must
    /// be contiguous, and every event must carry one valid fence.  This keeps
    /// restart recovery on the canonical read path instead of silently
    /// replacing state with `Default`.
    pub fn from_snapshot(snapshot: Self) -> Result<Self, CoordinationError> {
        if snapshot.events.iter().enumerate().any(|(index, event)| {
            event.sequence != index as u64 + 1
                || event.state_fence.validate().is_err()
                || event.authority_epoch != event.state_fence.authority_epoch
        }) {
            return Err(CoordinationError::CausalPredecessorMismatch);
        }
        if snapshot.sequence != snapshot.events.len() as u64 {
            return Err(CoordinationError::CausalPredecessorMismatch);
        }
        if snapshot
            .event_by_request
            .values()
            .any(|event| !snapshot.events.contains(event))
        {
            return Err(CoordinationError::InvalidState);
        }
        Ok(snapshot)
    }
    pub fn current_sequence(&self) -> u64 {
        self.sequence
    }
    pub fn events(&self) -> &[CoordinationEvent] {
        &self.events
    }

    /// Reads one exact active session at the caller's supplied time.
    ///
    /// Unlike the mutation-only session helper below, this is a public
    /// resolver-facing boundary: the supplied epoch and fence must match the
    /// stored records exactly, and the heartbeat deadline must still be live.
    /// The returned record is a clone, never a reference into owner state.
    pub fn read_active_session(
        &self,
        session_id: &str,
        now: u64,
        authority_epoch: AuthorityEpoch,
        state_fence: &StateFence,
    ) -> Result<AgentSession, CoordinationError> {
        text(session_id, "session_id")?;
        self.common(authority_epoch, state_fence)?;
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "session",
                id: session_id.to_owned(),
            })?;
        if session.session_id != session_id
            || session.authority_epoch != authority_epoch
            || session.state_fence != *state_fence
        {
            return Err(CoordinationError::FenceMismatch);
        }
        if session.state != SessionState::Active {
            return Err(CoordinationError::InvalidState);
        }
        if session.heartbeat_deadline == 0 || session.heartbeat_deadline < session.last_heartbeat {
            return Err(CoordinationError::InvalidField("heartbeat_deadline"));
        }
        if session.last_heartbeat > now {
            return Err(CoordinationError::InvalidField("last_heartbeat"));
        }
        if now > session.heartbeat_deadline {
            return Err(CoordinationError::SessionExpired);
        }
        Ok(session.clone())
    }

    /// Reads one exact active work item and its live lease for one session.
    ///
    /// The session, work item and lease all have to agree on the supplied
    /// authority epoch and complete fence.  The owner and lease links are
    /// checked in both directions before any cloned projection is returned.
    pub fn read_active_work_lease(
        &self,
        work_item_id: &str,
        session_id: &str,
        now: u64,
        authority_epoch: AuthorityEpoch,
        state_fence: &StateFence,
    ) -> Result<ActiveWorkLeaseProjection, CoordinationError> {
        text(work_item_id, "work_item_id")?;
        text(session_id, "session_id")?;
        self.common(authority_epoch, state_fence)?;
        let session = self.read_active_session(session_id, now, authority_epoch, state_fence)?;
        let work_item = self
            .work
            .get(work_item_id)
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "work_item",
                id: work_item_id.to_owned(),
            })?;
        if work_item.work_item_id != work_item_id || work_item.state_fence != *state_fence {
            return Err(CoordinationError::FenceMismatch);
        }
        if !matches!(
            work_item.state,
            WorkState::Claimed | WorkState::Running | WorkState::Checkpointed
        ) {
            return Err(CoordinationError::InvalidState);
        }
        if work_item.owner_session_id.as_deref() != Some(session_id) {
            return Err(CoordinationError::LeaseOwnerMismatch {
                holder: work_item.owner_session_id.clone().unwrap_or_default(),
            });
        }
        let lease_id = work_item
            .lease_id
            .as_deref()
            .ok_or(CoordinationError::InvalidState)?;
        let lease = self
            .leases
            .get(lease_id)
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "lease",
                id: lease_id.to_owned(),
            })?;
        if lease.lease_id != lease_id
            || lease.work_item_id != work_item_id
            || lease.holder_session_id != session_id
        {
            return Err(CoordinationError::LeaseOwnerMismatch {
                holder: lease.holder_session_id.clone(),
            });
        }
        if lease.authority_epoch != authority_epoch || lease.state_fence != *state_fence {
            return Err(CoordinationError::FenceMismatch);
        }
        if lease.issued_at == 0 || lease.expires_at == 0 || lease.issued_at > lease.expires_at {
            return Err(CoordinationError::InvalidField("lease_interval"));
        }
        if lease.last_heartbeat < lease.issued_at
            || lease.last_heartbeat > lease.expires_at
            || lease.last_heartbeat > now
        {
            return Err(CoordinationError::InvalidField("lease_last_heartbeat"));
        }
        if now < lease.issued_at {
            return Err(CoordinationError::LeaseNotYetValid);
        }
        if now > lease.expires_at {
            return Err(CoordinationError::LeaseExpired);
        }
        Ok(ActiveWorkLeaseProjection {
            session,
            work_item: work_item.clone(),
            lease: lease.clone(),
        })
    }

    /// Reads the sole active work lease without accepting a semantic identity.
    ///
    /// Every active session and every nonterminal work item is validated before
    /// the result is counted.  Malformed or orphaned active-looking state is a
    /// hard error; map order is never used to select a result.
    pub fn read_unique_active_work_lease(
        &self,
        now: u64,
        authority_epoch: AuthorityEpoch,
        state_fence: &StateFence,
    ) -> Result<ActiveWorkLeaseProjection, CoordinationError> {
        self.common(authority_epoch, state_fence)?;
        for session_id in self.sessions.keys() {
            if self.sessions[session_id].state == SessionState::Active {
                self.read_active_session(session_id, now, authority_epoch, state_fence)?;
            }
        }

        let mut linked_leases = BTreeSet::new();
        let mut projections = Vec::new();
        for work_item_id in self.work.keys() {
            let work_item = &self.work[work_item_id];
            if let Some(lease_id) = work_item.lease_id.as_deref() {
                linked_leases.insert(lease_id.to_owned());
            }
            if !matches!(
                work_item.state,
                WorkState::Claimed | WorkState::Running | WorkState::Checkpointed
            ) {
                continue;
            }
            let session_id = work_item
                .owner_session_id
                .as_deref()
                .ok_or(CoordinationError::InvalidState)?;
            work_item
                .lease_id
                .as_deref()
                .ok_or(CoordinationError::InvalidState)?;
            let projection = self.read_active_work_lease(
                work_item_id,
                session_id,
                now,
                authority_epoch,
                state_fence,
            )?;
            projections.push(projection);
        }
        for (lease_id, lease) in &self.leases {
            if lease.expires_at >= now && !linked_leases.contains(lease_id) {
                return Err(CoordinationError::InvalidState);
            }
        }
        match projections.len() {
            0 => Err(CoordinationError::NoActiveBinding),
            1 => Ok(projections
                .pop()
                .ok_or(CoordinationError::NoActiveBinding)?),
            _ => Err(CoordinationError::AmbiguousActiveBinding),
        }
    }

    #[allow(clippy::unused_self)]
    fn common(&self, epoch: AuthorityEpoch, fence: &StateFence) -> Result<(), CoordinationError> {
        if epoch != fence.authority_epoch {
            return Err(CoordinationError::EpochMismatch);
        }
        fence
            .validate()
            .map_err(|_| CoordinationError::FenceMismatch)
    }
    #[allow(clippy::unused_self)]
    fn request(&self, id: &str) -> Result<(), CoordinationError> {
        text(id, "request_id")
    }
    fn commit(
        &mut self,
        request_id: &str,
        event: CoordinationEvent,
    ) -> Result<CoordinationEvent, CoordinationError> {
        self.request(request_id)?;
        if let Some(old) = self.event_by_request.get(request_id) {
            if old.payload_digest == event.payload_digest
                && old.kind == event.kind
                && old.subject_id == event.subject_id
            {
                return Ok(old.clone());
            }
            return Err(CoordinationError::IdempotencyConflict(
                request_id.to_owned(),
            ));
        }
        self.sequence = event.sequence;
        self.event_by_request
            .insert(request_id.to_owned(), event.clone());
        self.events.push(event.clone());
        Ok(event)
    }
    #[allow(clippy::too_many_arguments)]
    fn event(
        &self,
        request_id: &str,
        event_id: String,
        kind: CoordinationEventKind,
        subject: String,
        actor: String,
        predecessor: Option<u64>,
        epoch: AuthorityEpoch,
        fence: StateFence,
        digest: String,
        observed: ClockReading,
    ) -> Result<CoordinationEvent, CoordinationError> {
        text(&event_id, "event_id")?;
        text(&subject, "subject_id")?;
        text(&actor, "actor_id")?;
        text(&digest, "payload_digest")?;
        observed
            .validate()
            .map_err(|_| CoordinationError::InvalidField("observed_at"))?;
        if predecessor != Some(self.sequence) && self.sequence != 0 {
            return Err(CoordinationError::CausalPredecessorMismatch);
        }
        Ok(CoordinationEvent {
            sequence: self
                .sequence
                .checked_add(1)
                .ok_or(CoordinationError::InvalidField("sequence"))?,
            event_id,
            idempotency_key: request_id.to_owned(),
            kind,
            subject_id: subject,
            actor_id: actor,
            predecessor,
            state_fence: fence,
            authority_epoch: epoch,
            payload_digest: digest,
            observed_at: observed,
        })
    }
    fn session(
        &self,
        id: &str,
        epoch: AuthorityEpoch,
        fence: &StateFence,
    ) -> Result<AgentSession, CoordinationError> {
        let s = self
            .sessions
            .get(id)
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "session",
                id: id.to_owned(),
            })?;
        self.common(epoch, fence)?;
        if s.authority_epoch != epoch
            || !s.state_fence.is_compatible_with(fence)
            || s.state != SessionState::Active
        {
            return Err(CoordinationError::FenceMismatch);
        }
        Ok(s.clone())
    }
    fn lease(
        &self,
        id: &str,
        holder: &str,
        now: u64,
        epoch: AuthorityEpoch,
        fence: &StateFence,
    ) -> Result<WorkLease, CoordinationError> {
        let l = self
            .leases
            .get(id)
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "lease",
                id: id.to_owned(),
            })?;
        if l.holder_session_id != holder {
            return Err(CoordinationError::LeaseOwnerMismatch {
                holder: l.holder_session_id.clone(),
            });
        }
        if now > l.expires_at {
            return Err(CoordinationError::LeaseExpired);
        }
        if l.authority_epoch != epoch || l.state_fence != *fence {
            return Err(CoordinationError::FenceMismatch);
        }
        Ok(l.clone())
    }

    /// Registers a session exactly once, while allowing an identical retry.
    pub fn register_session(
        &mut self,
        req: RegisterSession,
    ) -> Result<AgentSession, CoordinationError> {
        text(&req.session_id, "session_id")?;
        text(&req.principal_id, "principal_id")?;
        text(&req.route_ref, "route_ref")?;
        nonzero(req.heartbeat_deadline, "heartbeat_deadline")?;
        self.common(req.authority_epoch, &req.state_fence)?;
        if let Some(old) = self.sessions.get(&req.session_id) {
            if old.principal_id == req.principal_id && old.state_fence == req.state_fence {
                return Ok(old.clone());
            }
            return Err(CoordinationError::Duplicate(req.session_id));
        }
        let session = AgentSession {
            session_id: req.session_id.clone(),
            principal_id: req.principal_id,
            route_ref: req.route_ref,
            state: SessionState::Active,
            authority_epoch: req.authority_epoch,
            state_fence: req.state_fence.clone(),
            last_heartbeat: req.now,
            heartbeat_deadline: req.heartbeat_deadline,
        };
        let event = self.event(
            &req.request_id,
            format!("session:{}", req.session_id),
            CoordinationEventKind::SessionRegistered,
            req.session_id.clone(),
            session.principal_id.clone(),
            (self.sequence != 0).then_some(self.sequence),
            req.authority_epoch,
            req.state_fence,
            session.route_ref.clone(),
            ClockReading {
                valid_time_ms: None,
                known_time_ms: None,
                transaction_sequence: None,
                monotonic_ns: None,
            },
        )?;
        self.commit(&req.request_id, event)?;
        self.sessions.insert(req.session_id, session.clone());
        Ok(session)
    }

    /// Adds a ready work item to the durable queue.
    pub fn register_work(
        &mut self,
        item: WorkItem,
        request_id: &str,
        actor_id: &str,
        observed_at: ClockReading,
    ) -> Result<(), CoordinationError> {
        text(&item.work_item_id, "work_item_id")?;
        text(&item.task_id, "task_id")?;
        self.common(item.state_fence.authority_epoch, &item.state_fence)?;
        if item.state != WorkState::Ready || self.work.contains_key(&item.work_item_id) {
            return Err(CoordinationError::Duplicate(item.work_item_id));
        }
        let event = self.event(
            request_id,
            format!("work:{}", item.work_item_id),
            CoordinationEventKind::WorkRegistered,
            item.work_item_id.clone(),
            actor_id.to_owned(),
            (self.sequence != 0).then_some(self.sequence),
            item.state_fence.authority_epoch,
            item.state_fence.clone(),
            item.task_id.clone(),
            observed_at,
        )?;
        self.commit(request_id, event)?;
        self.work.insert(item.work_item_id.clone(), item);
        Ok(())
    }

    /// Claims a ready item, or returns the exact prior assignment on retry.
    pub fn acquire_work(
        &mut self,
        req: WorkLeaseRequest,
    ) -> Result<WorkLeaseDecision, CoordinationError> {
        self.common(req.authority_epoch, &req.state_fence)?;
        nonzero(req.lease_duration, "lease_duration")?;
        let session = self.session(&req.session_id, req.authority_epoch, &req.state_fence)?;
        let item = self
            .work
            .get(&req.work_item_id)
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "work_item",
                id: req.work_item_id.clone(),
            })?;
        if item.state != WorkState::Ready {
            if item.lease_id.as_deref() == Some(&req.lease_id) {
                let l = self
                    .leases
                    .get(&req.lease_id)
                    .cloned()
                    .ok_or(CoordinationError::InvalidState)?;
                let e = self
                    .event_by_request
                    .get(&req.request_id)
                    .cloned()
                    .ok_or(CoordinationError::InvalidState)?;
                return Ok(WorkLeaseDecision { lease: l, event: e });
            }
            return Err(CoordinationError::WorkAlreadyOwned);
        }
        text(&req.lease_id, "lease_id")?;
        let lease = WorkLease {
            lease_id: req.lease_id.clone(),
            work_item_id: req.work_item_id.clone(),
            holder_session_id: session.session_id,
            authority_epoch: req.authority_epoch,
            state_fence: req.state_fence.clone(),
            issued_at: req.now,
            expires_at: req
                .now
                .checked_add(req.lease_duration)
                .ok_or(CoordinationError::InvalidField("lease_duration"))?,
            last_heartbeat: req.now,
        };
        let event = self.event(
            &req.request_id,
            format!("claim:{}", req.lease_id),
            CoordinationEventKind::WorkClaimed,
            req.work_item_id.clone(),
            req.session_id.clone(),
            (self.sequence != 0).then_some(self.sequence),
            req.authority_epoch,
            req.state_fence,
            req.lease_id.clone(),
            ClockReading {
                valid_time_ms: None,
                known_time_ms: None,
                transaction_sequence: None,
                monotonic_ns: None,
            },
        )?;
        let event = self.commit(&req.request_id, event)?;
        let item = self
            .work
            .get_mut(&req.work_item_id)
            .ok_or(CoordinationError::InvalidState)?;
        item.state = WorkState::Claimed;
        item.owner_session_id = Some(req.session_id);
        item.lease_id = Some(req.lease_id.clone());
        item.attempt = item.attempt.saturating_add(1);
        self.leases.insert(req.lease_id, lease.clone());
        Ok(WorkLeaseDecision { lease, event })
    }

    /// Extends a lease only when the actor still owns the exact fenced lease.
    pub fn heartbeat(&mut self, req: AgentHeartbeat) -> Result<HeartbeatAck, CoordinationError> {
        self.common(req.authority_epoch, &req.state_fence)?;
        let mut lease = self.lease(
            &req.lease_id,
            &req.session_id,
            req.now,
            req.authority_epoch,
            &req.state_fence,
        )?;
        nonzero(req.extend_to, "extend_to")?;
        if req.extend_to < req.now {
            return Err(CoordinationError::InvalidField("extend_to"));
        }
        lease.last_heartbeat = req.now;
        lease.expires_at = req.extend_to;
        let event = self.event(
            &req.request_id,
            format!("heartbeat:{}:{}", req.lease_id, req.now),
            CoordinationEventKind::Heartbeat,
            req.lease_id.clone(),
            req.session_id,
            (self.sequence != 0).then_some(self.sequence),
            req.authority_epoch,
            req.state_fence,
            req.lease_id.clone(),
            ClockReading {
                valid_time_ms: None,
                known_time_ms: None,
                transaction_sequence: None,
                monotonic_ns: None,
            },
        )?;
        let event = self.commit(&req.request_id, event)?;
        self.leases.insert(lease.lease_id.clone(), lease.clone());
        Ok(HeartbeatAck { lease, event })
    }

    /// Sends a typed mailbox item; delivery is recorded separately from acknowledgement.
    pub fn send_message(
        &mut self,
        req: MailboxMessageDraft,
    ) -> Result<MailboxReceipt, CoordinationError> {
        self.common(req.authority_epoch, &req.state_fence)?;
        self.session(
            &req.sender_session_id,
            req.authority_epoch,
            &req.state_fence,
        )?;
        self.session(
            &req.recipient_session_id,
            req.authority_epoch,
            &req.state_fence,
        )?;
        text(&req.message_id, "message_id")?;
        if let Some(old) = self.messages.get(&req.message_id) {
            if old.payload_digest == req.payload_digest {
                let e = self
                    .event_by_request
                    .get(&req.request_id)
                    .cloned()
                    .ok_or(CoordinationError::InvalidState)?;
                return Ok(MailboxReceipt {
                    message: old.clone(),
                    event: e,
                });
            }
            return Err(CoordinationError::Duplicate(req.message_id));
        }
        let message = MailboxMessage {
            message_id: req.message_id.clone(),
            sender_session_id: req.sender_session_id.clone(),
            recipient_session_id: req.recipient_session_id,
            work_item_id: req.work_item_id.clone(),
            payload_digest: req.payload_digest.clone(),
            delivered: true,
        };
        let event = self.event(
            &req.request_id,
            format!("message:{}", req.message_id),
            CoordinationEventKind::MessageSent,
            req.message_id,
            req.sender_session_id,
            (self.sequence != 0).then_some(self.sequence),
            req.authority_epoch,
            req.state_fence,
            req.payload_digest,
            ClockReading {
                valid_time_ms: None,
                known_time_ms: None,
                transaction_sequence: None,
                monotonic_ns: None,
            },
        )?;
        let event = self.commit(&req.request_id, event)?;
        self.messages
            .insert(message.message_id.clone(), message.clone());
        Ok(MailboxReceipt { message, event })
    }

    #[allow(clippy::too_many_arguments)]
    fn advance_item(
        &mut self,
        work_item_id: &str,
        lease_id: &str,
        session_id: &str,
        epoch: AuthorityEpoch,
        fence: &StateFence,
        now: u64,
        state: WorkState,
        reference: String,
        request_id: &str,
        kind: CoordinationEventKind,
    ) -> Result<CoordinationEvent, CoordinationError> {
        self.common(epoch, fence)?;
        self.lease(lease_id, session_id, now, epoch, fence)?;
        let current = self
            .work
            .get(work_item_id)
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "work_item",
                id: work_item_id.to_owned(),
            })?
            .state;
        if !matches!(
            (current, state),
            (
                WorkState::Claimed | WorkState::Running | WorkState::Checkpointed,
                WorkState::Checkpointed | WorkState::Submitted
            )
        ) {
            return Err(CoordinationError::InvalidState);
        }
        let event = self.event(
            request_id,
            format!("{work_item_id}:{request_id}"),
            kind,
            work_item_id.to_owned(),
            session_id.to_owned(),
            (self.sequence != 0).then_some(self.sequence),
            epoch,
            fence.clone(),
            reference.clone(),
            ClockReading {
                valid_time_ms: None,
                known_time_ms: None,
                transaction_sequence: None,
                monotonic_ns: None,
            },
        )?;
        let event = self.commit(request_id, event)?;
        let item = self
            .work
            .get_mut(work_item_id)
            .ok_or(CoordinationError::InvalidState)?;
        item.state = state;
        if state == WorkState::Checkpointed {
            item.checkpoint_ref = Some(reference);
        } else {
            item.result_ref = Some(reference);
        }
        Ok(event)
    }
    pub fn checkpoint(
        &mut self,
        req: WorkCheckpoint,
    ) -> Result<CheckpointReceipt, CoordinationError> {
        text(&req.checkpoint_ref, "checkpoint_ref")?;
        let event = self.advance_item(
            &req.work_item_id,
            &req.lease_id,
            &req.session_id,
            req.authority_epoch,
            &req.state_fence,
            req.now,
            WorkState::Checkpointed,
            req.checkpoint_ref,
            &req.request_id,
            CoordinationEventKind::Checkpointed,
        )?;
        Ok(CheckpointReceipt {
            checkpoint_id: req.checkpoint_id,
            work_item_id: req.work_item_id,
            event,
        })
    }
    pub fn submit_result(
        &mut self,
        req: AgentResultDraft,
    ) -> Result<AgentResultReceipt, CoordinationError> {
        text(&req.result_ref, "result_ref")?;
        let event = self.advance_item(
            &req.work_item_id,
            &req.lease_id,
            &req.session_id,
            req.authority_epoch,
            &req.state_fence,
            req.now,
            WorkState::Submitted,
            req.result_ref,
            &req.request_id,
            CoordinationEventKind::ResultSubmitted,
        )?;
        Ok(AgentResultReceipt {
            result_id: req.result_id,
            work_item_id: req.work_item_id,
            event,
        })
    }

    /// Reassignment fences the old lease before installing the new owner.
    pub fn reassign(
        &mut self,
        req: ReassignWorkRequest,
    ) -> Result<WorkLeaseDecision, CoordinationError> {
        self.common(req.authority_epoch, &req.state_fence)?;
        let old =
            self.leases
                .get(&req.old_lease_id)
                .ok_or_else(|| CoordinationError::NotFound {
                    kind: "lease",
                    id: req.old_lease_id.clone(),
                })?;
        if old.authority_epoch == req.authority_epoch && old.state_fence != req.state_fence {
            return Err(CoordinationError::FenceMismatch);
        }
        let item = self
            .work
            .get(&req.work_item_id)
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "work_item",
                id: req.work_item_id.clone(),
            })?;
        if item.lease_id.as_deref() != Some(&req.old_lease_id) {
            return Err(CoordinationError::LeaseOwnerMismatch {
                holder: item.owner_session_id.clone().unwrap_or_default(),
            });
        }
        self.sessions
            .get(&req.new_session_id)
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "session",
                id: req.new_session_id.clone(),
            })?;
        let lease = WorkLease {
            lease_id: req.new_lease_id.clone(),
            work_item_id: req.work_item_id.clone(),
            holder_session_id: req.new_session_id.clone(),
            authority_epoch: req.authority_epoch,
            state_fence: req.state_fence.clone(),
            issued_at: req.now,
            expires_at: req
                .now
                .checked_add(req.lease_duration)
                .ok_or(CoordinationError::InvalidField("lease_duration"))?,
            last_heartbeat: req.now,
        };
        let event = self.event(
            &req.request_id,
            format!("reassign:{}", req.work_item_id),
            CoordinationEventKind::WorkReassigned,
            req.work_item_id.clone(),
            req.new_session_id.clone(),
            (self.sequence != 0).then_some(self.sequence),
            req.authority_epoch,
            req.state_fence,
            req.new_lease_id.clone(),
            ClockReading {
                valid_time_ms: None,
                known_time_ms: None,
                transaction_sequence: None,
                monotonic_ns: None,
            },
        )?;
        let event = self.commit(&req.request_id, event)?;
        let item = self
            .work
            .get_mut(&req.work_item_id)
            .ok_or(CoordinationError::InvalidState)?;
        item.state = WorkState::Reassigned;
        item.owner_session_id = Some(req.new_session_id);
        item.lease_id = Some(req.new_lease_id.clone());
        self.leases.insert(req.new_lease_id, lease.clone());
        Ok(WorkLeaseDecision { lease, event })
    }

    /// Records an integration candidate without applying it.
    pub fn submit_integration_candidate(
        &mut self,
        req: IntegrationCandidateDraft,
    ) -> Result<IntegrationCandidateReceipt, CoordinationError> {
        text(&req.candidate_id, "candidate_id")?;
        text(&req.candidate_ref, "candidate_ref")?;
        text(&req.target_scope, "target_scope")?;
        self.common(req.authority_epoch, &req.state_fence)?;
        self.lease_for_work(
            &req.source_work_item_id,
            &req.session_id,
            req.authority_epoch,
            &req.state_fence,
            req.now,
        )?;
        let event = self.event(
            &req.request_id,
            format!("candidate:{}", req.candidate_id),
            CoordinationEventKind::IntegrationCandidateSubmitted,
            req.candidate_id.clone(),
            req.session_id,
            (self.sequence != 0).then_some(self.sequence),
            req.authority_epoch,
            req.state_fence,
            req.candidate_ref,
            ClockReading {
                valid_time_ms: None,
                known_time_ms: None,
                transaction_sequence: None,
                monotonic_ns: None,
            },
        )?;
        let event = self.commit(&req.request_id, event)?;
        Ok(IntegrationCandidateReceipt {
            candidate_id: req.candidate_id,
            target_scope: req.target_scope,
            event,
        })
    }
    fn lease_for_work(
        &self,
        work: &str,
        session: &str,
        epoch: AuthorityEpoch,
        fence: &StateFence,
        now: u64,
    ) -> Result<(), CoordinationError> {
        let item = self
            .work
            .get(work)
            .ok_or_else(|| CoordinationError::NotFound {
                kind: "work_item",
                id: work.to_owned(),
            })?;
        let lease = item
            .lease_id
            .as_ref()
            .ok_or(CoordinationError::InvalidState)?;
        self.lease(lease, session, now, epoch, fence).map(|_| ())
    }

    /// Acquires the single integration writer for a target scope.
    pub fn acquire_integration(
        &mut self,
        req: IntegrationLeaseRequest,
    ) -> Result<IntegrationLeaseDecision, CoordinationError> {
        text(&req.target_scope, "target_scope")?;
        self.session(&req.session_id, req.authority_epoch, &req.state_fence)?;
        if let Some(old) = self.integrations.get(&req.target_scope)
            && old.expires_at >= req.now
        {
            return Err(CoordinationError::WorkAlreadyOwned);
        }
        let lease = IntegrationLease {
            lease_id: req.lease_id.clone(),
            target_scope: req.target_scope.clone(),
            holder_session_id: req.session_id.clone(),
            authority_epoch: req.authority_epoch,
            state_fence: req.state_fence.clone(),
            expires_at: req
                .now
                .checked_add(req.lease_duration)
                .ok_or(CoordinationError::InvalidField("lease_duration"))?,
        };
        let event = self.event(
            &req.request_id,
            format!("integration:{}", req.target_scope),
            CoordinationEventKind::IntegrationClaimed,
            req.target_scope.clone(),
            req.session_id,
            (self.sequence != 0).then_some(self.sequence),
            req.authority_epoch,
            req.state_fence,
            req.lease_id,
            ClockReading {
                valid_time_ms: None,
                known_time_ms: None,
                transaction_sequence: None,
                monotonic_ns: None,
            },
        )?;
        let event = self.commit(&req.request_id, event)?;
        self.integrations.insert(req.target_scope, lease.clone());
        Ok(IntegrationLeaseDecision { lease, event })
    }

    /// Appends a caller-supplied event while enforcing causal order and fences.
    pub fn record_coordination_event(
        &mut self,
        req: CoordinationEventDraft,
    ) -> Result<CoordinationEventReceipt, CoordinationError> {
        self.common(req.authority_epoch, &req.state_fence)?;
        let event = self.event(
            &req.request_id,
            req.event_id,
            req.kind,
            req.subject_id,
            req.actor_id,
            req.predecessor,
            req.authority_epoch,
            req.state_fence,
            req.payload_digest,
            req.observed_at,
        )?;
        let event = self.commit(&req.request_id, event)?;
        Ok(CoordinationEventReceipt { event })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::similar_names, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_contracts::ResourceGeneration;

    fn fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }

    fn clock() -> ClockReading {
        ClockReading {
            valid_time_ms: None,
            known_time_ms: None,
            transaction_sequence: None,
            monotonic_ns: None,
        }
    }

    fn claimed_owner() -> (CoordinationOwner, StateFence) {
        let mut owner = CoordinationOwner::new();
        let state_fence = fence();
        owner
            .register_session(RegisterSession {
                request_id: "register-session".to_owned(),
                session_id: "session-1".to_owned(),
                principal_id: "principal-1".to_owned(),
                route_ref: "route-1".to_owned(),
                authority_epoch: AuthorityEpoch::genesis(),
                state_fence: state_fence.clone(),
                now: 10,
                heartbeat_deadline: 100,
            })
            .expect("session registration");
        owner
            .register_work(
                WorkItem {
                    work_item_id: "work-1".to_owned(),
                    task_id: "task-1".to_owned(),
                    state: WorkState::Ready,
                    state_fence: state_fence.clone(),
                    owner_session_id: None,
                    lease_id: None,
                    attempt: 0,
                    checkpoint_ref: None,
                    result_ref: None,
                },
                "register-work",
                "principal-1",
                clock(),
            )
            .expect("work registration");
        owner
            .acquire_work(WorkLeaseRequest {
                request_id: "claim-work".to_owned(),
                lease_id: "lease-1".to_owned(),
                work_item_id: "work-1".to_owned(),
                session_id: "session-1".to_owned(),
                authority_epoch: AuthorityEpoch::genesis(),
                state_fence: state_fence.clone(),
                now: 20,
                lease_duration: 40,
            })
            .expect("work claim");
        (owner, state_fence)
    }

    fn add_claim(owner: &mut CoordinationOwner, state_fence: &StateFence, suffix: &str) {
        let session_id = format!("session-{suffix}");
        let work_item_id = format!("work-{suffix}");
        owner
            .register_session(RegisterSession {
                request_id: format!("register-session-{suffix}"),
                session_id: session_id.clone(),
                principal_id: format!("principal-{suffix}"),
                route_ref: format!("route-{suffix}"),
                authority_epoch: AuthorityEpoch::genesis(),
                state_fence: state_fence.clone(),
                now: 10,
                heartbeat_deadline: 100,
            })
            .expect("session registration");
        owner
            .register_work(
                WorkItem {
                    work_item_id: work_item_id.clone(),
                    task_id: format!("task-{suffix}"),
                    state: WorkState::Ready,
                    state_fence: state_fence.clone(),
                    owner_session_id: None,
                    lease_id: None,
                    attempt: 0,
                    checkpoint_ref: None,
                    result_ref: None,
                },
                &format!("register-work-{suffix}"),
                &format!("principal-{suffix}"),
                clock(),
            )
            .expect("work registration");
        owner
            .acquire_work(WorkLeaseRequest {
                request_id: format!("claim-work-{suffix}"),
                lease_id: format!("lease-{suffix}"),
                work_item_id,
                session_id,
                authority_epoch: AuthorityEpoch::genesis(),
                state_fence: state_fence.clone(),
                now: 20,
                lease_duration: 40,
            })
            .expect("work claim");
    }

    fn two_claimed_owner(order: [&str; 2]) -> (CoordinationOwner, StateFence) {
        let mut owner = CoordinationOwner::new();
        let state_fence = fence();
        for suffix in order {
            add_claim(&mut owner, &state_fence, suffix);
        }
        (owner, state_fence)
    }

    #[test]
    fn read_active_session_returns_an_owned_exact_clone() {
        let (owner, state_fence) = claimed_owner();
        let mut session = owner
            .read_active_session("session-1", 50, AuthorityEpoch::genesis(), &state_fence)
            .expect("active session");
        assert_eq!(session.session_id, "session-1");
        assert_eq!(session.state_fence, state_fence);
        session.principal_id = "mutated-clone".to_owned();
        assert_eq!(owner.sessions["session-1"].principal_id, "principal-1");
    }

    #[test]
    fn read_active_work_lease_returns_coherent_cloned_projection() {
        let (owner, state_fence) = claimed_owner();
        let projection = owner
            .read_active_work_lease(
                "work-1",
                "session-1",
                50,
                AuthorityEpoch::genesis(),
                &state_fence,
            )
            .expect("active work lease");
        assert_eq!(projection.session.session_id, "session-1");
        assert_eq!(
            projection.work_item.owner_session_id.as_deref(),
            Some("session-1")
        );
        assert_eq!(projection.work_item.lease_id.as_deref(), Some("lease-1"));
        assert_eq!(projection.lease.work_item_id, "work-1");
        assert_eq!(projection.lease.holder_session_id, "session-1");
        assert_eq!(projection.lease.state_fence, state_fence);
    }

    #[test]
    fn reads_reject_stale_epoch_and_fence() {
        let (owner, expected_fence) = claimed_owner();
        let stale_fence = StateFence::new(
            AuthorityEpoch::genesis(),
            ResourceGeneration::new(2).unwrap(),
        );
        assert_eq!(
            owner.read_active_session("session-1", 50, AuthorityEpoch::genesis(), &stale_fence,),
            Err(CoordinationError::FenceMismatch)
        );
        let stale_epoch = AuthorityEpoch::new(2).unwrap();
        let stale_epoch_fence = StateFence::new(stale_epoch, ResourceGeneration::genesis());
        assert_eq!(
            owner.read_active_work_lease(
                "work-1",
                "session-1",
                50,
                stale_epoch,
                &stale_epoch_fence,
            ),
            Err(CoordinationError::FenceMismatch)
        );
        assert_eq!(owner.current_sequence(), 3);
        assert_eq!(expected_fence.authority_epoch, AuthorityEpoch::genesis());
    }

    #[test]
    fn reads_reject_inactive_or_expired_sessions() {
        let (mut owner, state_fence) = claimed_owner();
        owner.sessions.get_mut("session-1").unwrap().state = SessionState::Quiescing;
        assert_eq!(
            owner.read_active_session("session-1", 50, AuthorityEpoch::genesis(), &state_fence,),
            Err(CoordinationError::InvalidState)
        );
        owner.sessions.get_mut("session-1").unwrap().state = SessionState::Active;
        owner
            .sessions
            .get_mut("session-1")
            .unwrap()
            .heartbeat_deadline = 49;
        assert_eq!(
            owner.read_active_session("session-1", 50, AuthorityEpoch::genesis(), &state_fence,),
            Err(CoordinationError::SessionExpired)
        );
    }

    #[test]
    fn reads_reject_wrong_work_links_and_terminal_work() {
        let (mut owner, state_fence) = claimed_owner();
        owner.work.get_mut("work-1").unwrap().owner_session_id = Some("other-session".to_owned());
        assert!(matches!(
            owner.read_active_work_lease(
                "work-1",
                "session-1",
                50,
                AuthorityEpoch::genesis(),
                &state_fence,
            ),
            Err(CoordinationError::LeaseOwnerMismatch { .. })
        ));
        owner.work.get_mut("work-1").unwrap().owner_session_id = Some("session-1".to_owned());
        owner.work.get_mut("work-1").unwrap().state = WorkState::Submitted;
        assert_eq!(
            owner.read_active_work_lease(
                "work-1",
                "session-1",
                50,
                AuthorityEpoch::genesis(),
                &state_fence,
            ),
            Err(CoordinationError::InvalidState)
        );
    }

    #[test]
    fn reads_reject_expired_or_malformed_leases() {
        let (mut owner, state_fence) = claimed_owner();
        owner.leases.get_mut("lease-1").unwrap().expires_at = 49;
        assert_eq!(
            owner.read_active_work_lease(
                "work-1",
                "session-1",
                50,
                AuthorityEpoch::genesis(),
                &state_fence,
            ),
            Err(CoordinationError::LeaseExpired)
        );
        owner.leases.get_mut("lease-1").unwrap().expires_at = 60;
        owner.leases.get_mut("lease-1").unwrap().last_heartbeat = 51;
        assert_eq!(
            owner.read_active_work_lease(
                "work-1",
                "session-1",
                50,
                AuthorityEpoch::genesis(),
                &state_fence,
            ),
            Err(CoordinationError::InvalidField("lease_last_heartbeat"))
        );
        owner.leases.get_mut("lease-1").unwrap().last_heartbeat = 20;
        owner.leases.get_mut("lease-1").unwrap().issued_at = 0;
        assert_eq!(
            owner.read_active_work_lease(
                "work-1",
                "session-1",
                50,
                AuthorityEpoch::genesis(),
                &state_fence,
            ),
            Err(CoordinationError::InvalidField("lease_interval"))
        );
    }

    #[test]
    fn unique_active_work_read_returns_an_owned_clone() {
        let (owner, state_fence) = claimed_owner();
        let mut projection = owner
            .read_unique_active_work_lease(50, AuthorityEpoch::genesis(), &state_fence)
            .expect("unique active work");
        assert_eq!(projection.work_item.work_item_id, "work-1");
        assert_eq!(projection.session.session_id, "session-1");
        projection.lease.lease_id = "mutated-clone".to_owned();
        assert_eq!(
            owner
                .read_unique_active_work_lease(50, AuthorityEpoch::genesis(), &state_fence)
                .expect("unique active work")
                .lease
                .lease_id,
            "lease-1"
        );
    }

    #[test]
    fn unique_active_work_read_reports_zero_without_candidates() {
        let owner = CoordinationOwner::new();
        let state_fence = fence();
        assert_eq!(
            owner.read_unique_active_work_lease(50, AuthorityEpoch::genesis(), &state_fence,),
            Err(CoordinationError::NoActiveBinding)
        );
    }

    #[test]
    fn unique_active_work_read_is_ambiguous_independent_of_insertion_order() {
        let (first, first_fence) = two_claimed_owner(["a", "b"]);
        let (second, second_fence) = two_claimed_owner(["b", "a"]);
        assert_eq!(
            first.read_unique_active_work_lease(50, AuthorityEpoch::genesis(), &first_fence),
            Err(CoordinationError::AmbiguousActiveBinding)
        );
        assert_eq!(
            second.read_unique_active_work_lease(50, AuthorityEpoch::genesis(), &second_fence),
            Err(CoordinationError::AmbiguousActiveBinding)
        );
    }

    #[test]
    fn unique_active_work_read_ignores_terminal_work() {
        let (mut owner, state_fence) = claimed_owner();
        owner.work.get_mut("work-1").unwrap().state = WorkState::Submitted;
        assert_eq!(
            owner.read_unique_active_work_lease(50, AuthorityEpoch::genesis(), &state_fence),
            Err(CoordinationError::NoActiveBinding)
        );
    }

    #[test]
    fn unique_active_work_read_rejects_invalid_candidate_alongside_valid_one() {
        let (mut owner, state_fence) = two_claimed_owner(["a", "b"]);
        owner.leases.get_mut("lease-b").unwrap().expires_at = 49;
        assert_eq!(
            owner.read_unique_active_work_lease(50, AuthorityEpoch::genesis(), &state_fence),
            Err(CoordinationError::LeaseExpired)
        );

        owner.leases.get_mut("lease-b").unwrap().expires_at = 60;
        owner.work.get_mut("work-b").unwrap().owner_session_id = None;
        assert_eq!(
            owner.read_unique_active_work_lease(50, AuthorityEpoch::genesis(), &state_fence),
            Err(CoordinationError::InvalidState)
        );
    }
}
