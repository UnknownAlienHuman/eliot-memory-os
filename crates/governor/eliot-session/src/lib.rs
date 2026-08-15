//! G-17 governed agent-session lifecycle ownership.
//!
//! This crate is the sole in-process owner of attached-agent session state. It
//! does not authenticate a transport, persist records, or perform cleanup: a
//! caller persists the returned event and snapshot and performs the external
//! close operation after the owner has admitted it. Every mutation is fenced,
//! causally ordered, and retry-safe.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_contracts::{AuthorityEpoch, ClockReading, SessionId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.governor.session_lifecycle";
pub const CONTRACT_VERSION: eliot_contracts::ContractVersion =
    eliot_contracts::ContractVersion::new(1, 0, 0);

fn text(value: &str, field: &'static str) -> Result<(), SessionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(SessionError::InvalidField(field))
    } else {
        Ok(())
    }
}

/// Fail-closed errors returned by session lifecycle commands.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SessionError {
    #[error("invalid session field: {0}")]
    InvalidField(&'static str),
    #[error("session {0} already exists")]
    DuplicateSession(SessionId),
    #[error("session {0} was not found")]
    SessionNotFound(SessionId),
    #[error("idempotency key {0} was reused with different input")]
    IdempotencyConflict(String),
    #[error("state fence mismatch")]
    FenceMismatch,
    #[error("authority epoch mismatch")]
    EpochMismatch,
    #[error("invalid session transition from {from:?} to {to:?}")]
    IllegalTransition {
        from: SessionState,
        to: SessionState,
    },
    #[error("session {0} is not accepting this operation")]
    InvalidState(SessionId),
    #[error("heartbeat deadline must be after the heartbeat time")]
    InvalidDeadline,
    #[error("session clock moved backwards")]
    ClockMovedBackwards,
    #[error("event sequence is not contiguous")]
    CausalSequenceMismatch,
    #[error("observed clock reading is invalid")]
    InvalidClock,
}

/// Durable status of an attached agent session.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionState {
    Registering,
    Active,
    Idle,
    Disconnected,
    Expired,
    Revoked,
    Draining,
    Closed,
}

impl SessionState {
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Expired | Self::Revoked | Self::Closed)
    }
}

/// Agent identity and bounded liveness data owned by the lifecycle authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSession {
    pub session_id: SessionId,
    pub agent_id: String,
    pub model_route: String,
    pub harness: String,
    pub role: String,
    pub project_scope: String,
    pub task_scope: Option<String>,
    pub capability_profile_id: String,
    pub parent_session_id: Option<SessionId>,
    pub started_at: u64,
    pub heartbeat_at: u64,
    pub expires_at: u64,
    pub status: SessionState,
    pub policy_snapshot_id: String,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
}

/// The immutable identity and admission data for a new session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterSession {
    pub request_id: String,
    pub event_id: String,
    pub session_id: SessionId,
    pub agent_id: String,
    pub model_route: String,
    pub harness: String,
    pub role: String,
    pub project_scope: String,
    pub task_scope: Option<String>,
    pub capability_profile_id: String,
    pub parent_session_id: Option<SessionId>,
    pub policy_snapshot_id: String,
    pub authority_epoch: AuthorityEpoch,
    pub state_fence: StateFence,
    pub now: u64,
    pub expires_at: u64,
}

/// A command against a registered session.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionCommand {
    Activate,
    MarkIdle,
    Resume,
    Disconnect,
    Expire,
    Revoke,
    BeginDrain,
    Close,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionCommandContext {
    pub request_id: String,
    pub event_id: String,
    pub actor_ref: String,
    pub state_fence: StateFence,
    pub authority_epoch: AuthorityEpoch,
    pub observed_at: ClockReading,
    pub now: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionHeartbeat {
    pub request_id: String,
    pub event_id: String,
    pub session_id: SessionId,
    pub actor_ref: String,
    pub state_fence: StateFence,
    pub authority_epoch: AuthorityEpoch,
    pub observed_at: ClockReading,
    pub now: u64,
    pub expires_at: u64,
}

/// One durable state transition, including the fence under which it happened.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionLifecycleEvent {
    pub sequence: u64,
    pub event_id: String,
    pub request_id: String,
    pub session_id: SessionId,
    pub actor_ref: String,
    pub from: Option<SessionState>,
    pub to: SessionState,
    pub command: Option<SessionCommand>,
    pub state_fence: StateFence,
    pub authority_epoch: AuthorityEpoch,
    pub observed_at: ClockReading,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionLifecycleSnapshot {
    pub next_sequence: u64,
    pub sessions: BTreeMap<SessionId, AgentSession>,
    pub events: Vec<SessionLifecycleEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RequestResult {
    Register(SessionLifecycleEvent),
    Command(SessionCommand, SessionLifecycleEvent),
    Heartbeat(SessionHeartbeat, SessionLifecycleEvent),
    Replayed(SessionLifecycleEvent),
}

/// Deterministic, recoverable owner of all governed session transitions.
#[derive(Clone, Debug)]
pub struct SessionLifecycleOwner {
    authority_epoch: AuthorityEpoch,
    state_fence: StateFence,
    next_sequence: u64,
    sessions: BTreeMap<SessionId, AgentSession>,
    events: Vec<SessionLifecycleEvent>,
    requests: BTreeMap<String, RequestResult>,
}

impl SessionLifecycleOwner {
    /// Creates an empty owner at the genesis causal sequence.
    pub fn new(
        authority_epoch: AuthorityEpoch,
        state_fence: StateFence,
    ) -> Result<Self, SessionError> {
        state_fence
            .validate()
            .map_err(|_| SessionError::FenceMismatch)?;
        if authority_epoch != state_fence.authority_epoch {
            return Err(SessionError::EpochMismatch);
        }
        Ok(Self {
            authority_epoch,
            state_fence,
            next_sequence: 1,
            sessions: BTreeMap::new(),
            events: Vec::new(),
            requests: BTreeMap::new(),
        })
    }

    /// Rebuilds an owner from a canonical snapshot and rejects malformed order.
    pub fn from_snapshot(
        authority_epoch: AuthorityEpoch,
        state_fence: StateFence,
        snapshot: SessionLifecycleSnapshot,
    ) -> Result<Self, SessionError> {
        let mut owner = Self::new(authority_epoch, state_fence)?;
        if snapshot.next_sequence == 0
            || snapshot.next_sequence != snapshot.events.len() as u64 + 1
            || snapshot
                .events
                .iter()
                .enumerate()
                .any(|(i, e)| e.sequence != i as u64 + 1)
        {
            return Err(SessionError::CausalSequenceMismatch);
        }
        for session in snapshot.sessions.values() {
            if session.authority_epoch != authority_epoch
                || session.state_fence != owner.state_fence
                || session.expires_at < session.heartbeat_at
            {
                return Err(SessionError::FenceMismatch);
            }
            owner
                .sessions
                .insert(session.session_id.clone(), session.clone());
        }
        owner.next_sequence = snapshot.next_sequence;
        owner.events = snapshot.events;
        for event in &owner.events {
            if let Some(command) = event.command {
                owner.requests.insert(
                    event.request_id.clone(),
                    RequestResult::Command(command, event.clone()),
                );
            } else if event.from.is_some() {
                owner.requests.insert(
                    event.request_id.clone(),
                    RequestResult::Replayed(event.clone()),
                );
            } else {
                owner.requests.insert(
                    event.request_id.clone(),
                    RequestResult::Register(event.clone()),
                );
            }
        }
        Ok(owner)
    }

    #[must_use]
    pub const fn current_sequence(&self) -> u64 {
        self.next_sequence - 1
    }

    #[must_use]
    pub fn session(&self, id: &SessionId) -> Option<&AgentSession> {
        self.sessions.get(id)
    }

    #[must_use]
    pub fn sessions(&self) -> &BTreeMap<SessionId, AgentSession> {
        &self.sessions
    }

    #[must_use]
    pub fn events(&self) -> &[SessionLifecycleEvent] {
        &self.events
    }

    #[must_use]
    pub fn snapshot(&self) -> SessionLifecycleSnapshot {
        SessionLifecycleSnapshot {
            next_sequence: self.next_sequence,
            sessions: self.sessions.clone(),
            events: self.events.clone(),
        }
    }

    /// Registers a session in `REGISTERING`; activation is an explicit command.
    pub fn register(
        &mut self,
        req: RegisterSession,
    ) -> Result<SessionLifecycleEvent, SessionError> {
        text(&req.request_id, "request_id")?;
        text(&req.event_id, "event_id")?;
        text(&req.agent_id, "agent_id")?;
        text(&req.model_route, "model_route")?;
        text(&req.harness, "harness")?;
        text(&req.role, "role")?;
        text(&req.project_scope, "project_scope")?;
        text(&req.capability_profile_id, "capability_profile_id")?;
        text(&req.policy_snapshot_id, "policy_snapshot_id")?;
        self.check_fence(req.authority_epoch, &req.state_fence)?;
        if req.expires_at <= req.now {
            return Err(SessionError::InvalidDeadline);
        }
        if let Some(old) = self.requests.get(&req.request_id) {
            return match old {
                RequestResult::Register(event) if event.session_id == req.session_id => {
                    Ok(event.clone())
                }
                _ => Err(SessionError::IdempotencyConflict(req.request_id)),
            };
        }
        if self.sessions.contains_key(&req.session_id) {
            return Err(SessionError::DuplicateSession(req.session_id));
        }
        let actor_ref = req.agent_id.clone();
        let session = AgentSession {
            session_id: req.session_id.clone(),
            agent_id: req.agent_id,
            model_route: req.model_route,
            harness: req.harness,
            role: req.role,
            project_scope: req.project_scope,
            task_scope: req.task_scope,
            capability_profile_id: req.capability_profile_id,
            parent_session_id: req.parent_session_id,
            started_at: req.now,
            heartbeat_at: req.now,
            expires_at: req.expires_at,
            status: SessionState::Registering,
            policy_snapshot_id: req.policy_snapshot_id,
            authority_epoch: req.authority_epoch,
            state_fence: req.state_fence.clone(),
        };
        let event = self.emit(
            &req.request_id,
            &req.event_id,
            &req.session_id,
            &actor_ref,
            None,
            SessionState::Registering,
            None,
            req.state_fence,
            req.authority_epoch,
            ClockReading {
                monotonic_ns: Some(req.now),
                ..ClockReading::default()
            },
        );
        self.sessions.insert(req.session_id, session);
        self.requests
            .insert(req.request_id, RequestResult::Register(event.clone()));
        Ok(event)
    }

    /// Applies a legal lifecycle command; identical retries return the event.
    pub fn apply(
        &mut self,
        session_id: SessionId,
        context: SessionCommandContext,
        command: SessionCommand,
    ) -> Result<SessionLifecycleEvent, SessionError> {
        self.validate_context(&context)?;
        if let Some(old) = self.requests.get(&context.request_id) {
            return match old {
                RequestResult::Command(known, event)
                    if *known == command && event.session_id == session_id =>
                {
                    Ok(event.clone())
                }
                RequestResult::Replayed(event) if event.session_id == session_id => {
                    Ok(event.clone())
                }
                _ => Err(SessionError::IdempotencyConflict(context.request_id)),
            };
        }
        let current = self
            .sessions
            .get(&session_id)
            .ok_or_else(|| SessionError::SessionNotFound(session_id.clone()))?
            .clone();
        let target = target(current.status, command).ok_or(SessionError::IllegalTransition {
            from: current.status,
            to: current.status,
        })?;
        if !allowed(current.status, target) {
            return Err(SessionError::IllegalTransition {
                from: current.status,
                to: target,
            });
        }
        if matches!(command, SessionCommand::Expire) && context.now < current.expires_at {
            return Err(SessionError::InvalidState(session_id));
        }
        let event = self.emit(
            &context.request_id,
            &context.event_id,
            &session_id,
            &context.actor_ref,
            Some(current.status),
            target,
            Some(command),
            context.state_fence.clone(),
            context.authority_epoch,
            context.observed_at,
        );
        let record = self
            .sessions
            .get_mut(&session_id)
            .expect("session checked above");
        record.status = target;
        if matches!(command, SessionCommand::Resume | SessionCommand::Activate) {
            record.heartbeat_at = context.now;
        }
        self.requests.insert(
            context.request_id,
            RequestResult::Command(command, event.clone()),
        );
        Ok(event)
    }

    /// Records liveness and extends the absolute session deadline.
    pub fn heartbeat(
        &mut self,
        req: SessionHeartbeat,
    ) -> Result<SessionLifecycleEvent, SessionError> {
        self.validate_context(&SessionCommandContext {
            request_id: req.request_id.clone(),
            event_id: req.event_id.clone(),
            actor_ref: req.actor_ref.clone(),
            state_fence: req.state_fence.clone(),
            authority_epoch: req.authority_epoch,
            observed_at: req.observed_at,
            now: req.now,
        })?;
        if req.expires_at <= req.now {
            return Err(SessionError::InvalidDeadline);
        }
        if let Some(old) = self.requests.get(&req.request_id) {
            return match old {
                RequestResult::Heartbeat(known, event) if known == &req => Ok(event.clone()),
                RequestResult::Replayed(event) if event.session_id == req.session_id => {
                    Ok(event.clone())
                }
                _ => Err(SessionError::IdempotencyConflict(req.request_id)),
            };
        }
        let session = self
            .sessions
            .get(&req.session_id)
            .ok_or_else(|| SessionError::SessionNotFound(req.session_id.clone()))?
            .clone();
        if !matches!(session.status, SessionState::Active | SessionState::Idle) {
            return Err(SessionError::InvalidState(req.session_id));
        }
        if req.now < session.heartbeat_at {
            return Err(SessionError::ClockMovedBackwards);
        }
        let event = self.emit(
            &req.request_id,
            &req.event_id,
            &req.session_id,
            &req.actor_ref,
            Some(session.status),
            session.status,
            None,
            req.state_fence.clone(),
            req.authority_epoch,
            req.observed_at,
        );
        let record = self
            .sessions
            .get_mut(&req.session_id)
            .expect("session checked above");
        record.heartbeat_at = req.now;
        record.expires_at = req.expires_at;
        self.requests
            .insert(req.request_id, RequestResult::Heartbeat(req, event.clone()));
        Ok(event)
    }

    fn validate_context(&self, context: &SessionCommandContext) -> Result<(), SessionError> {
        text(&context.request_id, "request_id")?;
        text(&context.event_id, "event_id")?;
        text(&context.actor_ref, "actor_ref")?;
        context
            .observed_at
            .validate()
            .map_err(|_| SessionError::InvalidClock)?;
        self.check_fence(context.authority_epoch, &context.state_fence)
    }

    fn check_fence(&self, epoch: AuthorityEpoch, fence: &StateFence) -> Result<(), SessionError> {
        if epoch != self.authority_epoch || epoch != fence.authority_epoch {
            return Err(SessionError::EpochMismatch);
        }
        if fence != &self.state_fence {
            return Err(SessionError::FenceMismatch);
        }
        Ok(())
    }

    fn emit(
        &mut self,
        request_id: &str,
        event_id: &str,
        session_id: &SessionId,
        actor_ref: &str,
        from: Option<SessionState>,
        to: SessionState,
        command: Option<SessionCommand>,
        state_fence: StateFence,
        authority_epoch: AuthorityEpoch,
        observed_at: ClockReading,
    ) -> SessionLifecycleEvent {
        let event = SessionLifecycleEvent {
            sequence: self.next_sequence,
            event_id: event_id.to_owned(),
            request_id: request_id.to_owned(),
            session_id: session_id.clone(),
            actor_ref: actor_ref.to_owned(),
            from,
            to,
            command,
            state_fence,
            authority_epoch,
            observed_at,
        };
        self.next_sequence += 1;
        self.events.push(event.clone());
        event
    }
}

fn target(state: SessionState, command: SessionCommand) -> Option<SessionState> {
    Some(match command {
        SessionCommand::Activate if state == SessionState::Registering => SessionState::Active,
        SessionCommand::MarkIdle if state == SessionState::Active => SessionState::Idle,
        SessionCommand::Resume if state == SessionState::Idle => SessionState::Active,
        SessionCommand::Disconnect
            if matches!(state, SessionState::Active | SessionState::Idle) =>
        {
            SessionState::Disconnected
        }
        SessionCommand::Expire if state == SessionState::Disconnected => SessionState::Expired,
        SessionCommand::Revoke if matches!(state, SessionState::Active | SessionState::Idle) => {
            SessionState::Revoked
        }
        SessionCommand::BeginDrain if state == SessionState::Active => SessionState::Draining,
        SessionCommand::Close if state == SessionState::Draining => SessionState::Closed,
        _ => return None,
    })
}

fn allowed(from: SessionState, to: SessionState) -> bool {
    matches!(
        (from, to),
        (SessionState::Registering, SessionState::Active)
            | (
                SessionState::Active,
                SessionState::Idle
                    | SessionState::Disconnected
                    | SessionState::Revoked
                    | SessionState::Draining
            )
            | (
                SessionState::Idle,
                SessionState::Active | SessionState::Disconnected | SessionState::Revoked
            )
            | (SessionState::Disconnected, SessionState::Expired)
            | (SessionState::Draining, SessionState::Closed)
    )
}
