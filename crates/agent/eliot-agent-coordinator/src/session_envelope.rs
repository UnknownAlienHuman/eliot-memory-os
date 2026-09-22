//! Live attempt-envelope facts for the reactive session snapshot
//! (issue #1942, lane O1).
//!
//! Owner: the agent Attempt lifecycle lives in this crate
//! (`agent.coordinator.attempt-reconciliation`; [`AgentCoordinator`] holds the
//! live `AttemptRecord` registry in `core.rs`). Every field below traces to a
//! read of that live registry through [`AgentCoordinator::attempt_records`];
//! no caller-supplied identity is accepted.
//!
//! Producer rule (CPU-side, deterministic): the registry iterates in
//! attempt-identity order; records whose state is terminal
//! ([`CoordinatedAttemptState::is_terminal`]) are never live. Exactly one
//! live record yields its identity, task, and fence; zero or several live
//! records fail closed naming `snapshot.attempt_id`.
//!
//! Session binding obligation (assembly-side): the coordinator admits no
//! session — the projected session is `None` (see `binding_subject_inner` in
//! `core.rs`). The returned [`AttemptEnvelopeFacts::state_fence`] is the
//! attempt's admitted fence; the session-snapshot assembly (which owns the
//! live attach fence read) must verify equality before using the identity as
//! `snapshot.attempt_id`. The `AgentAttemptId` construction from the returned
//! identity text is a checked re-validation at the assembly, never a type
//! bridge: the coordinator `AttemptId` (`eliot-agent-api`) and the snapshot
//! `AgentAttemptId` (`eliot-agent-contracts`) are distinct validated domains.
//!
//! Consumer: `resolve_runtime_envelope` in
//! `bins/eliot-agent-bridge/src/reactive_owner_publication.rs` (D2 lane,
//! read-only reference) names the missing `snapshot.attempt_id` fact this
//! producer resolves once the coordinator holds exactly one live attempt.

use eliot_agent_api::{AttemptId, StateFence, TaskId};
use thiserror::Error;

use crate::core::AgentCoordinator;
use crate::model::AttemptRecord;

/// Live attempt identity, task, and fence read from the coordinator registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptEnvelopeFacts {
    /// Identity of the single live attempt.
    pub attempt_id: AttemptId,
    /// Task the live attempt was admitted for.
    pub task_id: TaskId,
    /// Fence admitted with the live attempt, for assembly-side session
    /// binding against the live attach fence.
    pub state_fence: StateFence,
}

/// Fail-closed attempt-envelope errors. Each names the exact D2 fact that
/// cannot be resolved from live owner state.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AttemptEnvelopeError {
    /// The coordinator registry holds no live (non-terminal) attempt, so
    /// `snapshot.attempt_id` has no live source.
    #[error("no live attempt in the coordinator registry for snapshot.attempt_id")]
    NoLiveAttempt,
    /// The coordinator registry holds several live attempts, so no single
    /// identity can serve as `snapshot.attempt_id` without a caller choice.
    #[error(
        "ambiguous live attempts in the coordinator registry for snapshot.attempt_id: {count}"
    )]
    AmbiguousAttempts {
        /// Number of live (non-terminal) attempts observed.
        count: usize,
    },
}

/// A registry record counts as live while its lifecycle state is
/// non-terminal. Terminal states (`LostFenced`, `Cancelled`,
/// `CandidateResultSubmitted`) are never the attempt of record.
fn is_live(record: &AttemptRecord) -> bool {
    !record.state.is_terminal()
}

/// Produce the live attempt envelope from the coordinator's attempt registry.
///
/// Reads [`AgentCoordinator::attempt_records`] (deterministic
/// attempt-identity order), keeps non-terminal records, and requires exactly
/// one. Every returned field is a clone of owner-held record data.
pub fn produce_attempt_envelope(
    coordinator: &AgentCoordinator,
) -> Result<AttemptEnvelopeFacts, AttemptEnvelopeError> {
    let mut live = coordinator
        .attempt_records()
        .into_iter()
        .filter(is_live)
        .peekable();
    let first = live.next().ok_or(AttemptEnvelopeError::NoLiveAttempt)?;
    if live.peek().is_some() {
        let count = 1 + live.count();
        return Err(AttemptEnvelopeError::AmbiguousAttempts { count });
    }
    Ok(AttemptEnvelopeFacts {
        attempt_id: first.attempt_id.clone(),
        task_id: first.task_id.clone(),
        state_fence: first.state_fence.clone(),
    })
}
