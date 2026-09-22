//! Live session-bound attempt facts for the reactive session snapshot
//! (issue #1942, lane O1).
//!
//! Owner: the agent Attempt lifecycle lives in this crate
//! (`agent.coordinator.attempt-reconciliation`; [`AgentCoordinator`] holds the
//! live `AttemptRecord` registry in `core.rs`). Session admission (T1/T5) is
//! implemented here: `AttemptRecord.session` starts `None` at admission and
//! the first provider-execution bind records the session carried by the
//! authenticated binding (`bind_provider_execution` in `core.rs`, checked by
//! the frozen S1 validator `eliot_agent_api::validate_execution_binding`). A
//! later bind naming another session fails closed as a silent rebind, so a
//! thread still cannot create a session — only the authenticated bind path
//! (sealed provider verifier plus fence/lease/route agreement) records one.
//!
//! [`produce_session_bound_attempts`] reads the live registry through
//! [`AgentCoordinator::attempt_records`] (deterministic attempt-identity
//! order) and returns every non-terminal session-bound record with its
//! identity, session, task, and fence. No caller-supplied identity is
//! accepted; every field is a clone of owner-held record data.
//!
//! Join contract for the D2 assembly (M2): match
//! [`SessionBoundAttemptFacts::session`] against the live attach session the
//! bridge owns, and verify [`SessionBoundAttemptFacts::state_fence`] equals
//! the live attach fence before using the identity as `snapshot.attempt_id`.
//! The compiled matcher [`verify_session_binding`] performs exactly this
//! check with typed equality and must be called before authoritative use.
//! Identity note: the coordinator `AttemptId` is the canonical
//! `eliot-agent-contracts::AgentAttemptId` by alias
//! (`eliot-agent-api/lib.rs`), so the returned identity passes through
//! unchanged — it is never re-derived from text (the coordinator test guards
//! forbid `AgentAttemptId::new(...)` text bridges; cloning the canonical
//! value is the sanctioned flow). `SessionId`, `TaskId`, and `StateFence`
//! are likewise the canonical `eliot-contracts` types shared with the bridge
//! with no conversion.
//!
//! Consumer: `resolve_runtime_envelope` in
//! `bins/eliot-agent-bridge/src/reactive_owner_publication.rs` (D2 lane,
//! read-only reference) names the missing `snapshot.attempt_id` fact this
//! producer resolves once the coordinator holds a session-bound attempt.

use eliot_agent_api::{AttemptId, SessionId, StateFence, TaskId};
use thiserror::Error;

use crate::core::AgentCoordinator;
use crate::model::AttemptRecord;

/// One live session-bound attempt read from the coordinator registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionBoundAttemptFacts {
    /// Identity of the live attempt.
    pub attempt_id: AttemptId,
    /// Session admitted at the first provider-execution bind.
    pub session: SessionId,
    /// Task the attempt was admitted for.
    pub task_id: TaskId,
    /// Fence admitted with the attempt, for assembly-side session binding
    /// against the live attach fence.
    pub state_fence: StateFence,
}

/// Fail-closed session-attempt errors. Each names the exact D2 fact that
/// cannot be resolved from live owner state.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SessionAttemptError {
    /// The coordinator registry holds no live (non-terminal) session-bound
    /// attempt, so `snapshot.attempt_id` has no live source. Unbound or
    /// terminal attempts never qualify.
    #[error("no live session-bound attempt in the coordinator registry for snapshot.attempt_id")]
    NoSessionBoundAttempts,
}

/// A registry record counts as session-bound while its lifecycle state is
/// non-terminal and a session was admitted at bind time. Terminal states
/// (`LostFenced`, `Cancelled`, `CandidateResultSubmitted`) are never the
/// attempt of record, and unbound attempts carry no session to join on.
fn is_live(record: &AttemptRecord) -> bool {
    !record.state.is_terminal()
}

/// Produce every live session-bound attempt from the coordinator registry.
///
/// Reads [`AgentCoordinator::attempt_records`] (deterministic
/// attempt-identity order), keeps non-terminal records, and keeps the ones
/// whose bind admitted a session. An empty result fails closed: with no
/// bound session there is no live source for `snapshot.attempt_id`. The D2
/// assembly joins on `session` against its own live attach-session read.
pub fn produce_session_bound_attempts(
    coordinator: &AgentCoordinator,
) -> Result<Vec<SessionBoundAttemptFacts>, SessionAttemptError> {
    let bound: Vec<SessionBoundAttemptFacts> = coordinator
        .attempt_records()
        .into_iter()
        .filter(is_live)
        .filter_map(|record| {
            Some(SessionBoundAttemptFacts {
                attempt_id: record.attempt_id.clone(),
                session: record.session.clone()?,
                task_id: record.task_id.clone(),
                state_fence: record.state_fence.clone(),
            })
        })
        .collect();
    if bound.is_empty() {
        return Err(SessionAttemptError::NoSessionBoundAttempts);
    }
    Ok(bound)
}

/// A recorded provider attestation matched against the live attach facts.
///
/// Carries only owner-read values that compared exactly equal; it mints no
/// identity, digest, or authority. Principal needs no cross-owner match: it
/// is single-owner state (bridge attach) read alongside the live session and
/// fence from the same binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSessionBinding {
    /// Matched attempt identity (canonical `AgentAttemptId` by alias).
    pub attempt_id: AttemptId,
    /// Matched session.
    pub session: SessionId,
    /// Matched task.
    pub task_id: TaskId,
    /// Matched fence.
    pub state_fence: StateFence,
}

/// Fail-closed attestation-match errors. Each names the exact owner-field
/// disagreement; matching is typed equality only, never digests or text
/// parsing, so there is no hash authority to dispute.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SessionMatchError {
    /// The recorded session does not equal the live attach session.
    #[error("recorded attempt session does not equal the live attach session")]
    SessionMismatch,
    /// The recorded fence does not equal the live attach fence.
    #[error("recorded attempt fence does not equal the live attach fence")]
    FenceMismatch,
    /// The recorded task does not equal the live attach task.
    #[error("recorded attempt task does not equal the live attach task")]
    TaskMismatch,
}

/// Match a recorded provider attestation against the live attach facts
/// before authoritative use (issue #1942 lane O1; M2 six-slot join).
///
/// Takes the coordinator-owned record plus the bridge-owned live reads
/// (session, fence, task from the same attach binding) and requires exact
/// typed equality on all three. Generation agreement rides along: the S1
/// validator already enforced `binding.runtime_generation ==
/// fence.resource_generation` at bind, and the snapshot's authoritative
/// runtime generation comes from the Kernel activation receipt (see the
/// `eliot-kernel-service` producer), so fence equality transitively pins the
/// S1-checked generation. Any disagreement fails closed with the exact
/// field; nothing is hashed, parsed, or minted.
pub fn verify_session_binding(
    record: &SessionBoundAttemptFacts,
    live_session: &SessionId,
    live_fence: &StateFence,
    live_task: &TaskId,
) -> Result<VerifiedSessionBinding, SessionMatchError> {
    if record.session != *live_session {
        return Err(SessionMatchError::SessionMismatch);
    }
    if record.state_fence != *live_fence {
        return Err(SessionMatchError::FenceMismatch);
    }
    if record.task_id != *live_task {
        return Err(SessionMatchError::TaskMismatch);
    }
    Ok(VerifiedSessionBinding {
        attempt_id: record.attempt_id.clone(),
        session: record.session.clone(),
        task_id: record.task_id.clone(),
        state_fence: record.state_fence.clone(),
    })
}
