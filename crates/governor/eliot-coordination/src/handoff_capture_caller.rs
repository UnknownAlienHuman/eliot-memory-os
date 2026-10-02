//! The one ELIOT-controlled compaction/handoff capture caller (I12.17).
//!
//! [`capture_handoff_checkpoint`] and [`read_back_capture`] in
//! [`super::handoff_persistence`] are the governed join; this module is the
//! real caller that reaches them, so a controlled boundary does not have to
//! assemble the durable chain itself and cannot skip a step of it.
//!
//! The chain, with every arrow an existing symbol:
//!
//! 1. **work input** — [`HandoffCaptureRequest`], the exact request the
//!    boundary caller already holds: the controlled
//!    [`HandoffCaptureBoundary`](eliot_agent_contracts::HandoffCaptureBoundary),
//!    the complete [`HandoffCheckpoint`](eliot_agent_contracts::HandoffCheckpoint)
//!    payload, the work item/lease/session/fence the boundary runs under, and
//!    the retention release condition the owner applies;
//! 2. **lawful data producer** —
//!    [`HandoffCheckpoint::capture_source`](eliot_agent_contracts::HandoffCheckpoint::capture_source)
//!    derives the bounded source snapshot *from the payload itself*, and
//!    [`HandoffCheckpoint::artifact_leases`](eliot_agent_contracts::HandoffCheckpoint::artifact_leases)
//!    derives the retention leases. A caller cannot hand in a source snapshot
//!    that disagrees with the checkpoint it claims to capture, and the frozen
//!    diff travels as a digest-bound immutable artifact with a lease owned by
//!    this capture;
//! 3. **carrier** —
//!    [`HandoffCaptureLedger::capture_and_register`](eliot_agent_contracts::HandoffCaptureLedger::capture_and_register)
//!    takes the snapshot against the ONE capture operation. A second identity
//!    for the same boundary and source attempt is refused, so a lost response
//!    cannot become a second checkpoint;
//! 4. **handler** — [`capture_handoff_checkpoint`] binds the governed draft to
//!    the capture and commits it through
//!    [`CoordinationOwner::checkpoint`](super::CoordinationOwner::checkpoint),
//!    persisting the checkpoint *and* its artifact reference together;
//! 5. **stored result** — the committed `CoordinationEvent` in the owner event
//!    stream;
//! 6. **caller/readback** — [`read_back_capture`] re-reads that event out of the
//!    owner independently of the commit receipt, parses the stored binding, and
//!    records the durable readback that admits the compaction permit. Only then
//!    is [`HandoffCaptureOutcome::admits_destructive_compaction`] true.
//!
//! Which real caller each boundary is:
//!
//! - [`HostPreCompactHook`](eliot_agent_contracts::HandoffCaptureBoundary::HostPreCompactHook)
//!   is [`crates/eliot-engine/src/plugin.rs::EliotHookService::evaluate_pre_compact`](eliot_agent_contracts::HandoffCaptureBoundary::caller_symbol),
//!   the host plugin's pre-compaction hook. It is the one destructive boundary:
//!   passing it destroys conversational state the checkpoint is the only
//!   remaining record of, so its permit is refused until the durable readback
//!   holds;
//! - [`DurableWorkUnitResume`](eliot_agent_contracts::HandoffCaptureBoundary::DurableWorkUnitResume),
//!   [`SealedAttachmentRehydration`](eliot_agent_contracts::HandoffCaptureBoundary::SealedAttachmentRehydration)
//!   and [`NextAttemptAfterEffect`](eliot_agent_contracts::HandoffCaptureBoundary::NextAttemptAfterEffect)
//!   are the durable work-unit resume, the sealed plan-attachment rehydration,
//!   and the post-effect next attempt. They are non-destructive, so they do not
//!   consume a destructive-compaction permit, but they are registered against
//!   the same one capture operation.
//!
//! What is deliberately *not* registered here is stated rather than implied:
//! provider-internal compaction has no controllable pre-hook on main (the
//! claude/codex/opencode adapters launch sidecars and only measure compaction
//! as probe telemetry), so no provider event is fabricated and no private native
//! reasoning or transcript is serialized; an observed provider compaction is
//! recorded as a
//! [`HandoffProviderGap`](eliot_agent_contracts::HandoffProviderGap) and
//! continues only on the explicitly partial/rehydrated path. Peer-board
//! compaction, maintenance-job checkpoints, worker progress checkpoints and
//! workscope saga resumes share vocabulary with this path but are not I12.17
//! handoffs.

#![forbid(unsafe_code)]

use eliot_agent_contracts::{
    AgentAttemptId, HandoffBoundaryRegistration, HandoffCapture, HandoffCaptureBoundary,
    HandoffCaptureError, HandoffCaptureLedger, HandoffCaptureRegistration, HandoffCaptureRegistry,
    HandoffCheckpoint, HandoffCheckpointError, HandoffCheckpointId, HandoffLeaseRelease,
    HandoffRecoveryOutput, HandoffResumeIntent,
};
use eliot_contracts::{
    ContractError as ReceiptContractError, EpochId, OperationId, ResourceGeneration, StateFence,
};
use thiserror::Error;

use super::{
    CheckpointReceipt, CoordinationError, CoordinationOwner, HandoffPersistenceError,
    HandoffResumeError, HandoffResumeRequest, WorkCheckpoint, capture_handoff_checkpoint,
    handoff_capture_binding_text, read_back_capture, resume_retained_handoff,
};

/// Failure of the controlled-boundary capture caller.
///
/// Each arm keeps the typed error of the owner that refused: the checkpoint
/// record owner, the controlled-boundary capture owner, the coordination owner,
/// the recovery owner, or the resume owner. Nothing is collapsed into a generic
/// code.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HandoffCaptureCallerError {
    /// The capture or its governed persistence was refused, already typed by
    /// the persistence join.
    #[error(transparent)]
    Persistence(#[from] HandoffPersistenceError),
    /// The checkpoint record was refused, already typed by its owner.
    #[error(transparent)]
    Checkpoint(#[from] HandoffCheckpointError),
    /// The controlled-boundary capture was refused, already typed by its owner.
    #[error(transparent)]
    Capture(#[from] HandoffCaptureError),
    /// The governed coordination path was refused, already typed by its owner.
    #[error(transparent)]
    Coordination(#[from] CoordinationError),
    /// The resume was refused, already typed by the resume owner.
    #[error(transparent)]
    Resume(#[from] HandoffResumeError),
    /// The capture operation identity was refused by the receipt contract on a
    /// ground the agent-contract family does not admit.
    ///
    /// `eliot-contracts` and `eliot-agent-contracts` each own a distinct
    /// `ContractError`, and neither is a supertype, an alias, or convertible
    /// into the other. A foundation rejection with no agent-contract
    /// counterpart is therefore *named* here rather than translated into a
    /// rejection that would misdescribe it. Only the failing field label and a
    /// fixed reason word are carried, both `&'static str` drawn from the
    /// refusing crate, so no rejected identity text is retained here.
    #[error("capture operation identity refused by the receipt contract: {field} {reason}")]
    ReceiptContractRefused {
        /// Label of the field the receipt contract refused.
        field: &'static str,
        /// Fixed, content-free description of the refusal ground.
        reason: &'static str,
    },
}

/// The request one controlled boundary hands to the capture caller.
///
/// Every field is something the boundary caller already holds. The bounded
/// snapshot, the frozen diff, the retained artifacts, the pending verifiers and
/// the in-flight operations are *not* fields: they are derived from
/// `checkpoint` by the payload's own constructors, so a caller cannot present a
/// capture whose source disagrees with the checkpoint it claims to capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffCaptureRequest {
    /// Controlled boundary this capture is taken at.
    ///
    /// This is the arm whose
    /// [`caller_symbol`](eliot_agent_contracts::HandoffCaptureBoundary::caller_symbol)
    /// names the real product function that reached this caller.
    pub boundary: HandoffCaptureBoundary,
    /// Complete checkpoint payload captured at the boundary.
    pub checkpoint: HandoffCheckpoint,
    /// Work item the capture belongs to.
    pub work_item_id: String,
    /// Session the capture belongs to.
    pub session_id: String,
    /// Lease the capture is taken under.
    pub lease_id: String,
    /// Authority epoch the capture is taken under.
    pub authority_epoch: EpochId,
    /// Fence the capture is taken under.
    pub state_fence: StateFence,
    /// Owner-supplied time the capture is taken at.
    pub now: u64,
    /// Condition under which the retained artifacts may be released.
    pub release: HandoffLeaseRelease,
}

/// What one controlled-boundary capture produced.
///
/// The outcome carries the receipt, the capture that reached its durable
/// readback, and the generation the read was served from. The permit is not a
/// separate assertion: it is
/// [`HandoffCapture::admits_destructive_compaction`] on the capture this
/// outcome returns, so a caller cannot report a permit the capture does not
/// hold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffCaptureOutcome {
    /// Identity of the checkpoint that was persisted.
    pub checkpoint_id: HandoffCheckpointId,
    /// Controlled boundary the capture was taken at.
    pub boundary: HandoffCaptureBoundary,
    /// Source attempt the capture was taken from.
    pub source_attempt_id: AgentAttemptId,
    /// The capture, holding its own durable readback.
    pub capture: HandoffCapture,
    /// The committed owner receipt.
    pub receipt: CheckpointReceipt,
    /// Canonical generation the durable readback was served from.
    pub read_generation: ResourceGeneration,
}

impl HandoffCaptureOutcome {
    /// Whether this boundary may now destroy conversational state.
    ///
    /// This is the capture's own read-backed decision, not a flag this
    /// outcome sets: a non-destructive boundary destroys nothing, and a
    /// destructive one is admitted only by a durable readback of the stored
    /// record.
    #[must_use]
    pub fn admits_destructive_compaction(&self) -> bool {
        self.boundary.is_destructive() && self.capture.admits_destructive_compaction()
    }
}

/// Captures and persists one checkpoint at a controlled boundary.
///
/// This is the entrypoint a real compaction/handoff caller reaches. It runs the
/// whole chain in order and returns only once the durable readback holds:
///
/// - the bounded source snapshot and the retention leases are derived from the
///   payload, so the frozen diff travels as a digest-bound immutable artifact
///   leased to this capture and the pending verifier/effect identities travel
///   with it;
/// - the capture is registered against the one capture operation for its
///   boundary and source attempt; a second identity for the same pair is
///   refused;
/// - the governed draft is committed through the coordination owner, which
///   re-checks the lease, session, epoch and fence;
/// - the committed event is read back out of the owner independently of the
///   receipt, and the readback is compared against this operation's own
///   recorded digests and both directions of every reference set before the
///   compaction permit is issued.
///
/// A retry that already committed under the same request identity reads the
/// stored event back and returns the exact prior receipt instead of minting a
/// second checkpoint.
pub fn capture_at_controlled_boundary(
    owner: &mut CoordinationOwner,
    registry: &mut HandoffCaptureRegistry,
    ledger: &mut HandoffCaptureLedger,
    request: &HandoffCaptureRequest,
) -> Result<HandoffCaptureOutcome, HandoffCaptureCallerError> {
    let operation_id = capture_operation_id(request)?;
    let mut capture = register_boundary_capture(ledger, request, &operation_id)?;
    let draft = governed_draft(request, &capture)?;
    let receipt = capture_handoff_checkpoint(owner, registry, &capture, draft)?;
    let read_generation = read_back_capture(owner, registry, &mut capture)?;
    Ok(HandoffCaptureOutcome {
        checkpoint_id: capture.capture_id.clone(),
        boundary: capture.boundary,
        source_attempt_id: capture.source_attempt_id.clone(),
        capture,
        receipt,
        read_generation,
    })
}

/// Resumes the checkpoint one controlled-boundary capture persisted.
///
/// This is the resume-side entrypoint for the same capture: it reads the
/// durable record back out of the owner, reads the current authority from the
/// live owner, and runs the recovery-handoff owners. A capture that did not
/// reach a durable readback admits no compaction and therefore no resume.
pub fn resume_captured_handoff(
    owner: &CoordinationOwner,
    request: &HandoffResumeRequest<'_>,
    intent: &mut HandoffResumeIntent,
) -> Result<HandoffRecoveryOutput, HandoffCaptureCallerError> {
    resume_retained_handoff(owner, request, intent).map_err(HandoffCaptureCallerError::from)
}

/// The identity the one capture operation runs under.
///
/// It is derived from the payload's own identity and the boundary, so the same
/// checkpoint at the same boundary always reconciles the same operation and can
/// never be captured under two.
///
/// A receipt-contract rejection of that identity is a refusal, never a coerced
/// success: [`capture_identity_refusal`] maps it without changing what the
/// check decided.
fn capture_operation_id(
    request: &HandoffCaptureRequest,
) -> Result<OperationId, HandoffCaptureCallerError> {
    let identity = format!(
        "handoff-capture:{}:{}",
        request.boundary.caller_symbol(),
        request.checkpoint.checkpoint_id.as_str()
    );
    OperationId::new(identity).map_err(capture_identity_refusal)
}

/// Maps a receipt-contract rejection of the capture operation identity.
///
/// The two `ContractError` families are distinct types in distinct packages:
/// `eliot_contracts::ContractError` (structure variants) and
/// `eliot_agent_contracts::ContractError` (tuple variants). Only the two
/// rejections an identity string can actually produce are translated, and each
/// translation keeps the *same* refusal — a blank identity stays
/// [`ContractError::Blank`](eliot_agent_contracts::ContractError::Blank) and a
/// control-character identity stays
/// [`ContractError::ControlCharacter`](eliot_agent_contracts::ContractError::ControlCharacter),
/// so neither becomes an admitted operation. Every other variant is matched
/// explicitly and named by
/// [`HandoffCaptureCallerError::ReceiptContractRefused`] with its failing field
/// label and a fixed reason; no error is discarded, and none is turned into a
/// successful operation identity.
///
/// The match is exhaustive over today's receipt-contract enum, so a new variant
/// there is a compile error in this file rather than a silently swallowed
/// refusal.
fn capture_identity_refusal(error: ReceiptContractError) -> HandoffCaptureCallerError {
    let refusal = |field: &'static str, reason: &'static str| {
        HandoffCaptureCallerError::ReceiptContractRefused { field, reason }
    };
    match error {
        ReceiptContractError::Blank { field } => {
            HandoffCaptureCallerError::Checkpoint(HandoffCheckpointError::Contract(
                eliot_agent_contracts::ContractError::Blank(field),
            ))
        }
        ReceiptContractError::ControlCharacter { field } => {
            HandoffCaptureCallerError::Checkpoint(HandoffCheckpointError::Contract(
                eliot_agent_contracts::ContractError::ControlCharacter(field),
            ))
        }
        ReceiptContractError::TooLong { field, .. } => {
            refusal(field, "exceeds the bounded identity length")
        }
        ReceiptContractError::Zero { field } => refusal(field, "must be greater than zero"),
        ReceiptContractError::InvalidInterval { field } => refusal(field, "has an invalid interval"),
        ReceiptContractError::EmptyFence => {
            refusal("state_fence", "must contain at least one dependency")
        }
        ReceiptContractError::IncompleteFenceKeyReceipt { key } => {
            refusal(key, "has no single named owner receipt")
        }
        ReceiptContractError::MissingRequestId => refusal("request_id", "must be present"),
        ReceiptContractError::InvalidDigest { field } => {
            refusal(field, "must be a lowercase SHA-256 hex digest")
        }
        ReceiptContractError::VersionOutOfRange => {
            refusal("contract_version", "has a component out of range")
        }
    }
}

/// Registers the bounded snapshot against the one capture operation.
///
/// The snapshot and the leases come from the payload, so the capture's expected
/// sets are the payload's own artifacts, verifiers and in-flight operations. A
/// replay returns the registered capture unchanged, which is what makes a lost
/// response reconcile one operation rather than mint a second checkpoint.
fn register_boundary_capture(
    ledger: &mut HandoffCaptureLedger,
    request: &HandoffCaptureRequest,
    operation_id: &OperationId,
) -> Result<HandoffCapture, HandoffCaptureCallerError> {
    let source = request
        .checkpoint
        .capture_source(operation_id.clone(), request.boundary)?;
    let leases = request.checkpoint.artifact_leases(request.release)?;
    Ok(
        match ledger.capture_and_register(source, leases)? {
            HandoffCaptureRegistration::First(capture)
            | HandoffCaptureRegistration::Replayed(capture) => capture,
        },
    )
}

/// Builds the governed draft the coordination owner commits.
///
/// The draft's `request_id` is the capture operation identity, which makes it
/// the owner idempotency key: a retry after a lost commit response reads the
/// stored event back under the same key instead of committing a second time.
fn governed_draft(
    request: &HandoffCaptureRequest,
    capture: &HandoffCapture,
) -> Result<WorkCheckpoint, HandoffCaptureCallerError> {
    Ok(WorkCheckpoint {
        request_id: capture.operation_id.as_str().to_owned(),
        checkpoint_id: capture.capture_id.as_str().to_owned(),
        lease_id: request.lease_id.clone(),
        session_id: request.session_id.clone(),
        work_item_id: request.work_item_id.clone(),
        authority_epoch: request.authority_epoch.clone(),
        state_fence: request.state_fence.clone(),
        checkpoint_ref: handoff_capture_binding_text(capture)?,
        now: request.now,
    })
}

/// Reports the controlled boundaries that currently have no registered capture.
///
/// The expected side is the owner-declared
/// [`CONTROLLED_BOUNDARIES`](eliot_agent_contracts::HandoffCaptureBoundary::CONTROLLED_BOUNDARIES)
/// set rather than a list a caller supplies, so a boundary cannot be dropped
/// from the denominator by the same registration that failed to cover it.
#[must_use]
pub fn unregistered_controlled_boundaries(
    ledger: &HandoffCaptureLedger,
) -> Vec<HandoffCaptureBoundary> {
    ledger.unregistered_boundaries()
}

/// The registration census of the controlled boundaries.
///
/// Each row names the boundary, the product symbol it is registered against,
/// and whether passing it is destructive, so a reader can check the coverage
/// against the owner-declared set rather than against a caller's own list.
#[must_use]
pub fn controlled_boundary_census(
    ledger: &HandoffCaptureLedger,
) -> Vec<HandoffBoundaryRegistration> {
    ledger.registration_census()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_agent_contracts::{
        ContractError, ContinuityKind, HANDOFF_CHECKPOINT_CONTRACT_VERSION, HandoffAttemptIdentity,
        HandoffCaptureAcceptance, HandoffCausalLink, HandoffCheckpointId, HandoffCompleteness,
        HandoffContinuity, HandoffCursors, HandoffCursor, HandoffDispatchDecision,
        HandoffEffectDisposition, HandoffEffectInstruction, HandoffEffectRecord, HandoffFencing,
        HandoffId, HandoffProviderCompactionCapability, HandoffRecoveryError,
        HandoffResumeAdmission, HandoffResumeEvidence, HandoffResumeIntent, HandoffResumeStatus,
        HandoffSourceGenerations, HandoffWorkSet, PublicReference, RetainedHandoffCheckpoint,
        RevisionId, Route, RouteId, TargetId, TaskControllerLease, WorkItemId,
    };
    use eliot_contracts::{ClockReading, EpochLineageId, TaskId};
    use std::num::NonZeroU64;

    use crate::{
        CoordinationEventKind, HandoffResumeAuthorityQuery, RegisterSession, WorkItem,
        WorkLeaseRequest, WorkState, reconcile_handoff_capture, stored_capture_binding,
    };

    const SESSION: &str = "session-1";
    const WORK: &str = "work-1";
    const LEASE: &str = "lease-1";
    const TASK: &str = "task-1";
    const HANDOFF: &str = "handoff-1";
    const DIGEST: &str = "sha256:3f1a9d0c5b7e2468a1c0d5e8f2b4a6c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f";

    fn epoch(sequence: u64) -> EpochId {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage");
        EpochId::new(
            lineage,
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn fence() -> StateFence {
        StateFence::new(epoch(1), ResourceGeneration::genesis())
    }

    fn clock() -> ClockReading {
        ClockReading {
            valid_time_ms: None,
            known_time_ms: None,
            transaction_sequence: None,
            monotonic_ns: None,
        }
    }

    fn generations() -> HandoffSourceGenerations {
        HandoffSourceGenerations {
            scope: ResourceGeneration::genesis(),
            world: ResourceGeneration::new(4).expect("world generation"),
            module: ResourceGeneration::new(5).expect("module generation"),
            route: ResourceGeneration::new(6).expect("route generation"),
        }
    }

    /// A coordination owner holding one live session, work item and lease.
    ///
    /// The lease runs from 20 to 120 and the session heartbeat runs to 200, so a
    /// read at 40 observes the live lease and a read at 130 observes it expired:
    /// the resume read is a real owner read, not an assertion.
    fn claimed_owner() -> (CoordinationOwner, StateFence) {
        let mut owner = CoordinationOwner::new();
        let state_fence = fence();
        owner
            .register_session(RegisterSession {
                request_id: "register-session".to_owned(),
                session_id: SESSION.to_owned(),
                principal_id: "principal-1".to_owned(),
                route_ref: "route-1".to_owned(),
                authority_epoch: epoch(1),
                state_fence: state_fence.clone(),
                now: 10,
                heartbeat_deadline: 200,
            })
            .expect("session registration");
        owner
            .register_work(
                WorkItem {
                    work_item_id: WORK.to_owned(),
                    task_id: TASK.to_owned(),
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
                lease_id: LEASE.to_owned(),
                work_item_id: WORK.to_owned(),
                session_id: SESSION.to_owned(),
                authority_epoch: epoch(1),
                state_fence: state_fence.clone(),
                now: 20,
                lease_duration: 100,
            })
            .expect("work claim");
        (owner, state_fence)
    }

    fn reference(kind: &str, id: &str, revision: &str, digest: Option<&str>) -> PublicReference {
        PublicReference {
            kind: kind.to_owned(),
            id: TargetId::new(id).expect("reference target"),
            revision: RevisionId::new(revision).expect("reference revision"),
            digest: digest.map(str::to_owned),
        }
    }

    fn attempt_id(text: &str) -> AgentAttemptId {
        AgentAttemptId::new(text).expect("attempt id")
    }

    fn checkpoint_id(text: &str) -> HandoffCheckpointId {
        HandoffCheckpointId::new(text).expect("checkpoint id")
    }

    /// A complete, valid checkpoint payload captured under one identity.
    fn checkpoint_under(text: &str) -> HandoffCheckpoint {
        HandoffCheckpoint {
            checkpoint_id: checkpoint_id(text),
            contract_version: HANDOFF_CHECKPOINT_CONTRACT_VERSION,
            continuity: HandoffContinuity::Rehydrated,
            source_task_id: TaskId::new(TASK).expect("task id"),
            source_attempt_id: attempt_id("attempt-1"),
            source_session_ref: reference("session", SESSION, "1", None),
            source_plan_revision: RevisionId::new("plan-1").expect("plan revision"),
            source_acceptance_revision: RevisionId::new("acceptance-1")
                .expect("acceptance revision"),
            goal_ref: reference("goal", "goal-1", "1", None),
            acceptance_ref: reference("acceptance", "acceptance-1", "1", None),
            work: HandoffWorkSet {
                expected_members: vec![WorkItemId::new("member-1").expect("member")],
                done: vec![WorkItemId::new("member-1").expect("member")],
                open: Vec::new(),
                killed: Vec::new(),
                deferred: Vec::new(),
                unavailable: Vec::new(),
            },
            epistemic_position_handles: vec![
                reference("evidence", "evidence-1", "1", Some(DIGEST))
            ],
            load_bearing_atom_handles: vec![reference("atom", "atom-1", "1", Some(DIGEST))],
            diff_ref: reference("frozen-diff", "diff-1", "1", Some(DIGEST)),
            artifact_refs: vec![reference("artifact", "artifact-1", "1", Some(DIGEST))],
            pending_verifier_refs: vec![reference("verifier", "verifier-1", "1", Some(DIGEST))],
            critical_items: Vec::new(),
            next_action: "continue the remaining member".to_owned(),
            stop_condition: "the member is done".to_owned(),
            source_generations: generations(),
            state_fence: fence(),
            source_cursors: HandoffCursors {
                event: HandoffCursor::Observed {
                    cursor: "event-42".to_owned(),
                },
                outbox: HandoffCursor::Unavailable {
                    cause: "outbox stream is not exposed to this boundary".to_owned(),
                },
            },
            effects: vec![HandoffEffectRecord {
                operation_id: OperationId::new("operation-1").expect("effect operation id"),
                disposition: HandoffEffectDisposition::OutcomeUnknown {
                    cause: "the acknowledgement was never observed".to_owned(),
                },
            }],
            known_losses: Vec::new(),
        }
    }

    fn checkpoint() -> HandoffCheckpoint {
        checkpoint_under("checkpoint-1")
    }

    fn capture_request_for(
        boundary: HandoffCaptureBoundary,
        checkpoint_identity: &str,
    ) -> HandoffCaptureRequest {
        HandoffCaptureRequest {
            boundary,
            checkpoint: checkpoint_under(checkpoint_identity),
            work_item_id: WORK.to_owned(),
            session_id: SESSION.to_owned(),
            lease_id: LEASE.to_owned(),
            authority_epoch: epoch(1),
            state_fence: fence(),
            now: 30,
            release: HandoffLeaseRelease::AfterResumeReconciled,
        }
    }

    fn capture_request(boundary: HandoffCaptureBoundary) -> HandoffCaptureRequest {
        capture_request_for(boundary, "checkpoint-1")
    }

    fn fresh() -> (CoordinationOwner, HandoffCaptureRegistry, HandoffCaptureLedger) {
        let (owner, _) = claimed_owner();
        (
            owner,
            HandoffCaptureRegistry::default(),
            HandoffCaptureLedger::new(),
        )
    }

    fn checkpoint_events(owner: &CoordinationOwner) -> usize {
        owner
            .events()
            .iter()
            .filter(|event| event.kind == CoordinationEventKind::Checkpointed)
            .count()
    }

    /// One capture that reached its durable readback through the governed owner.
    struct Captured {
        owner: CoordinationOwner,
        registry: HandoffCaptureRegistry,
        checkpoint: HandoffCheckpoint,
        checkpoint_id: HandoffCheckpointId,
    }

    impl Captured {
        fn take(boundary: HandoffCaptureBoundary, identity: &str) -> Self {
            let (mut owner, mut registry, mut ledger) = fresh();
            let request = capture_request_for(boundary, identity);
            let outcome =
                capture_at_controlled_boundary(&mut owner, &mut registry, &mut ledger, &request)
                    .expect("controlled-boundary capture reaches durable readback");
            Self {
                owner,
                registry,
                checkpoint: request.checkpoint,
                checkpoint_id: outcome.checkpoint_id,
            }
        }
    }

    #[test]
    fn pre_compact_capture_persists_and_reads_back_through_the_governed_owner() {
        let (mut owner, mut registry, mut ledger) = fresh();
        let outcome = capture_at_controlled_boundary(
            &mut owner,
            &mut registry,
            &mut ledger,
            &capture_request(HandoffCaptureBoundary::HostPreCompactHook),
        )
        .expect("controlled-boundary capture reaches durable readback");

        // The governed owner committed exactly one record.
        assert_eq!(outcome.receipt.checkpoint_id, "checkpoint-1");
        assert_eq!(checkpoint_events(&owner), 1);

        // The durable record holds the checkpoint AND its artifact reference.
        let stored = stored_capture_binding(&owner, &outcome.checkpoint_id)
            .expect("the stored binding reads back");
        assert_eq!(stored.checkpoint_id, outcome.checkpoint_id);
        assert_eq!(stored.frozen_diff.digest.as_deref(), Some(DIGEST));
        assert_eq!(stored.retained_artifacts.len(), 2);
        assert_eq!(stored.pending_verifiers.len(), 1);
        assert_eq!(stored.pending_effects.len(), 1);
        assert_eq!(
            stored.recorded_checkpoint_digest,
            outcome.capture.recorded_checkpoint_digest
        );
        assert_eq!(
            stored.recorded_diff_digest,
            outcome.capture.recorded_diff_digest
        );

        // The readback held, so the destructive boundary is admitted.
        assert!(outcome.capture.admits_destructive_compaction());
        assert!(outcome.admits_destructive_compaction());
        assert_eq!(outcome.read_generation, ResourceGeneration::genesis());
        registry
            .require_compaction_permit(&outcome.checkpoint_id)
            .expect("the durable readback admits the compaction permit");
    }

    #[test]
    fn a_commit_alone_never_admits_compaction_before_the_durable_readback() {
        let (mut owner, mut registry, mut ledger) = fresh();
        let request = capture_request(HandoffCaptureBoundary::HostPreCompactHook);
        let mut capture = register_boundary_capture(
            &mut ledger,
            &request,
            &capture_operation_id(&request).expect("operation identity"),
        )
        .expect("the bounded snapshot is registered against the one operation");
        let draft = governed_draft(&request, &capture).expect("governed draft");

        let receipt = capture_handoff_checkpoint(&mut owner, &mut registry, &capture, draft)
            .expect("the governed commit lands in the owner event stream");
        assert_eq!(receipt.checkpoint_id, "checkpoint-1");
        assert_eq!(checkpoint_events(&owner), 1);

        // The commit is a transport fact, not an observation of stored bytes.
        assert!(!capture.admits_destructive_compaction());
        assert!(matches!(
            registry.require_compaction_permit(&capture.capture_id),
            Err(HandoffRecoveryError::Checkpoint(
                HandoffCheckpointError::CompactionWithoutDurableReadback
            ))
        ));

        // Only the durable readback admits the permit.
        read_back_capture(&owner, &mut registry, &mut capture).expect("durable readback");
        assert!(capture.admits_destructive_compaction());
        registry
            .require_compaction_permit(&capture.capture_id)
            .expect("the durable readback admits the compaction permit");
    }

    #[test]
    fn a_lost_commit_response_reconciles_to_unknown_and_still_refuses_compaction() {
        let (mut owner, mut registry, mut ledger) = fresh();
        let request = capture_request(HandoffCaptureBoundary::HostPreCompactHook);
        let capture = register_boundary_capture(
            &mut ledger,
            &request,
            &capture_operation_id(&request).expect("operation identity"),
        )
        .expect("the bounded snapshot is registered against the one operation");
        let draft = governed_draft(&request, &capture).expect("governed draft");
        capture_handoff_checkpoint(&mut owner, &mut registry, &capture, draft)
            .expect("the governed commit lands in the owner event stream");

        // The caller lost the response and reconciles against an owner that
        // cannot show it the committed event.
        let (unaware, _) = claimed_owner();
        let acceptance = reconcile_handoff_capture(
            &mut registry,
            &unaware,
            &capture.operation_id,
            &request.checkpoint,
        )
        .expect("the same operation reconciles against the owner it can see");
        // The reconciled acceptance is unknown, so nothing compacts under it.
        assert!(matches!(acceptance, HandoffCaptureAcceptance::Unknown { .. }));
        assert!(matches!(
            registry.require_compaction_permit(&capture.capture_id),
            Err(HandoffRecoveryError::Checkpoint(
                HandoffCheckpointError::CompactionWithoutDurableReadback
            ))
        ));
    }

    #[test]
    fn a_retry_after_a_lost_commit_response_reads_the_same_record_back() {
        let (mut owner, mut registry, mut ledger) = fresh();
        let request = capture_request(HandoffCaptureBoundary::HostPreCompactHook);
        let first =
            capture_at_controlled_boundary(&mut owner, &mut registry, &mut ledger, &request)
                .expect("first capture");
        let second =
            capture_at_controlled_boundary(&mut owner, &mut registry, &mut ledger, &request)
                .expect("the retry reconciles the same operation");

        assert_eq!(first.receipt.event.event_id, second.receipt.event.event_id);
        assert_eq!(first.checkpoint_id, second.checkpoint_id);
        assert_eq!(checkpoint_events(&owner), 1);
        assert_eq!(
            unregistered_controlled_boundaries(&ledger),
            vec![
                HandoffCaptureBoundary::DurableWorkUnitResume,
                HandoffCaptureBoundary::SealedAttachmentRehydration,
                HandoffCaptureBoundary::NextAttemptAfterEffect,
            ]
        );
    }

    #[test]
    fn the_same_checkpoint_under_a_different_operation_is_refused() {
        let (mut owner, mut registry, mut ledger) = fresh();
        capture_at_controlled_boundary(
            &mut owner,
            &mut registry,
            &mut ledger,
            &capture_request(HandoffCaptureBoundary::HostPreCompactHook),
        )
        .expect("first capture");

        // A second, different operation for the same checkpoint identity, built
        // past the ledger so the registry is the owner that refuses it.
        let foreign = OperationId::new("handoff-capture:other-operation")
            .expect("foreign operation id");
        let stolen = foreign_capture(foreign.clone());

        // The ledger refuses the same boundary and attempt under it too.
        let source = checkpoint()
            .capture_source(foreign.clone(), HandoffCaptureBoundary::HostPreCompactHook)
            .expect("foreign source snapshot");
        let leases = checkpoint()
            .artifact_leases(HandoffLeaseRelease::AfterResumeReconciled)
            .expect("foreign leases");
        assert!(matches!(
            ledger.capture_and_register(source, leases),
            Err(HandoffCaptureError::ForeignCaptureIdentity { .. })
        ));

        // And the registry refuses to persist that checkpoint under it.
        let draft = WorkCheckpoint {
            request_id: foreign.as_str().to_owned(),
            checkpoint_id: "checkpoint-1".to_owned(),
            lease_id: LEASE.to_owned(),
            session_id: SESSION.to_owned(),
            work_item_id: WORK.to_owned(),
            authority_epoch: epoch(1),
            state_fence: fence(),
            checkpoint_ref: handoff_capture_binding_text(&stolen).expect("foreign binding text"),
            now: 30,
        };
        assert!(matches!(
            capture_handoff_checkpoint(&mut owner, &mut registry, &stolen, draft),
            Err(HandoffPersistenceError::Recovery(
                HandoffRecoveryError::DuplicateCaptureRegistration { .. }
            ))
        ));
    }

    /// One capture for the same checkpoint identity under a different operation,
    /// constructed past the boundary ledger so the registry is what answers.
    fn foreign_capture(operation: OperationId) -> HandoffCapture {
        let payload = checkpoint();
        let source = payload
            .capture_source(operation, HandoffCaptureBoundary::HostPreCompactHook)
            .expect("foreign source snapshot");
        let leases = payload
            .artifact_leases(HandoffLeaseRelease::AfterResumeReconciled)
            .expect("foreign leases");
        HandoffCapture::capture(source, leases).expect("foreign capture")
    }

    #[test]
    fn a_second_capture_identity_for_one_boundary_and_attempt_is_refused() {
        let (mut owner, mut registry, mut ledger) = fresh();
        capture_at_controlled_boundary(
            &mut owner,
            &mut registry,
            &mut ledger,
            &capture_request(HandoffCaptureBoundary::HostPreCompactHook),
        )
        .expect("first capture");

        // The same boundary and source attempt, but a different checkpoint
        // identity: the ledger refuses a second identity for that pair.
        let other = capture_request_for(HandoffCaptureBoundary::HostPreCompactHook, "checkpoint-2");
        let source = other
            .checkpoint
            .capture_source(
                OperationId::new("handoff-capture:second-identity")
                    .expect("second operation id"),
                other.boundary,
            )
            .expect("second source snapshot");
        let leases = other
            .checkpoint
            .artifact_leases(other.release)
            .expect("second leases");
        assert!(matches!(
            ledger.capture_and_register(source, leases),
            Err(HandoffCaptureError::ForeignCaptureIdentity { .. })
        ));
    }

    #[test]
    fn a_capture_with_a_mutable_diff_reference_is_refused() {
        let (mut owner, mut registry, mut ledger) = fresh();
        let mut request = capture_request(HandoffCaptureBoundary::HostPreCompactHook);
        // A path with no content digest is not an immutable artifact.
        request.checkpoint.diff_ref = reference("frozen-diff", "src/lib.rs", "1", None);
        assert!(matches!(
            capture_at_controlled_boundary(&mut owner, &mut registry, &mut ledger, &request),
            Err(HandoffCaptureCallerError::Checkpoint(
                HandoffCheckpointError::DiffReferenceIsNotImmutable
            ))
        ));
        assert_eq!(unregistered_controlled_boundaries(&ledger).len(), 4);
    }

    #[test]
    fn a_receipt_contract_refusal_of_the_capture_identity_is_still_refused() {
        // The two contract-error families are distinct types in distinct
        // packages, so the mapping is explicit rather than a conversion: a
        // blank identity is still Blank and a control-character identity is
        // still ControlCharacter, so neither becomes an admitted operation.
        assert!(matches!(
            capture_identity_refusal(ReceiptContractError::Blank {
                field: "operation_id"
            }),
            HandoffCaptureCallerError::Checkpoint(HandoffCheckpointError::Contract(
                ContractError::Blank("operation_id")
            ))
        ));
        assert!(matches!(
            capture_identity_refusal(ReceiptContractError::ControlCharacter {
                field: "operation_id"
            }),
            HandoffCaptureCallerError::Checkpoint(HandoffCheckpointError::Contract(
                ContractError::ControlCharacter("operation_id")
            ))
        ));

        // A ground the agent-contract family does not admit is named by its
        // failing field, not translated into a rejection that misdescribes it,
        // and the refused value itself is not carried.
        let refused = capture_identity_refusal(ReceiptContractError::TooLong {
            field: "operation_id",
            maximum_bytes: 64,
        });
        assert_eq!(
            refused,
            HandoffCaptureCallerError::ReceiptContractRefused {
                field: "operation_id",
                reason: "exceeds the bounded identity length"
            }
        );
        assert!(!refused.to_string().contains("64"));
    }

    #[test]
    fn the_bounded_snapshot_is_derived_from_the_payload_and_leased_to_this_capture() {
        let (mut owner, mut registry, mut ledger) = fresh();
        let request = capture_request(HandoffCaptureBoundary::HostPreCompactHook);
        let outcome =
            capture_at_controlled_boundary(&mut owner, &mut registry, &mut ledger, &request)
                .expect("capture");
        let capture = ledger
            .get(outcome.boundary, &outcome.source_attempt_id)
            .expect("the capture is registered for its boundary and attempt");
        // Every retained artifact is leased to this very capture.
        assert_eq!(capture.artifact_leases.len(), 2);
        for lease in &capture.artifact_leases {
            assert_eq!(lease.retained_by_capture, outcome.checkpoint_id);
        }
        // The frozen diff is retained under a lease, not merely named.
        assert!(
            capture
                .artifact_leases
                .iter()
                .any(|lease| lease.artifact_ref == capture.frozen_diff)
        );
        // The pending verifier and the unreconciled effect survived the boundary.
        assert_eq!(capture.expected_pending_verifiers.len(), 1);
        assert_eq!(capture.expected_pending_effects.len(), 1);
        assert!(request.checkpoint.has_unfinished_verifiers_or_effects());
    }

    #[test]
    fn a_capture_taken_under_a_foreign_lease_is_refused_by_the_owner() {
        let (mut owner, mut registry, mut ledger) = fresh();
        let mut request = capture_request(HandoffCaptureBoundary::HostPreCompactHook);
        request.lease_id = "lease-not-held".to_owned();
        assert!(matches!(
            capture_at_controlled_boundary(&mut owner, &mut registry, &mut ledger, &request),
            Err(HandoffCaptureCallerError::Persistence(
                HandoffPersistenceError::Coordination(CoordinationError::NotFound { .. })
            ))
        ));
        assert_eq!(checkpoint_events(&owner), 0);
    }

    #[test]
    fn a_non_destructive_boundary_is_registered_without_consuming_a_permit() {
        let (mut owner, mut registry, mut ledger) = fresh();
        let outcome = capture_at_controlled_boundary(
            &mut owner,
            &mut registry,
            &mut ledger,
            &capture_request_for(HandoffCaptureBoundary::DurableWorkUnitResume, "checkpoint-2"),
        )
        .expect("the non-destructive boundary reaches the same durable readback");

        // The record is durable, but this boundary destroys nothing.
        assert!(outcome.capture.admits_destructive_compaction());
        assert!(!outcome.admits_destructive_compaction());
        assert_eq!(
            unregistered_controlled_boundaries(&ledger),
            vec![
                HandoffCaptureBoundary::HostPreCompactHook,
                HandoffCaptureBoundary::SealedAttachmentRehydration,
                HandoffCaptureBoundary::NextAttemptAfterEffect,
            ]
        );
    }

    #[test]
    fn every_controlled_boundary_names_a_product_caller_symbol() {
        let census = controlled_boundary_census(&HandoffCaptureLedger::new());
        assert_eq!(census.len(), HandoffCaptureBoundary::CONTROLLED_BOUNDARIES.len());
        for row in census {
            assert!(row.caller_symbol.contains("::"), "{row:?}");
            assert!(!row.caller_symbol.contains("STITCH"), "{row:?}");
        }
        assert!(
            census
                .iter()
                .filter(|row| row.destructive)
                .all(|row| row.boundary == HandoffCaptureBoundary::HostPreCompactHook)
        );
    }

    /// The causal link the retained payload is bound to.
    fn link() -> HandoffCausalLink {
        HandoffCausalLink {
            handoff_id: HandoffId::new(HANDOFF).expect("handoff id"),
            source_attempt_id: attempt_id("attempt-1"),
            source_session_ref: reference("session", SESSION, "1", None),
            source_state_fence: fence(),
            source_revision: RevisionId::new("plan-1").expect("source revision"),
            target_attempt_id: attempt_id("attempt-2"),
            target_route: Route {
                route_id: RouteId::new("route-2").expect("route id"),
                adapter_id: "adapter-1".to_owned(),
                fingerprint: "fingerprint-1".to_owned(),
                continuity: ContinuityKind::Rehydrated,
            },
            target_revision: RevisionId::new("plan-2").expect("target revision"),
            continuity: HandoffContinuity::Rehydrated,
            checkpoint_ref: reference("handoff-checkpoint", "checkpoint-1", "plan-1", None),
            omission_manifest_digest: DIGEST.to_owned(),
            replay_bundle_ref: None,
            post_resume_revalidation_ref: None,
            completeness: HandoffCompleteness::Partial,
        }
    }

    /// The intent a fresh resume starts from, before compaction is observed.
    fn intent() -> HandoffResumeIntent {
        HandoffResumeIntent::new(
            HandoffId::new(HANDOFF).expect("handoff id"),
            attempt_id("attempt-2"),
        )
        .expect("resume intent")
    }

    /// The live-owner read the resume gate is decided against.
    ///
    /// `now` is the read time: 40 observes the live lease, 130 observes it
    /// expired, so the refusal on a stale lease comes from the owner.
    fn authority<'a>(now: u64, state_fence: &'a StateFence) -> HandoffResumeAuthorityQuery<'a> {
        HandoffResumeAuthorityQuery {
            work_item_id: WORK,
            session_id: SESSION,
            now,
            authority_epoch: epoch(1),
            state_fence,
            cross_owner_generations: generations(),
            claimed_lease: TaskControllerLease {
                holder: SESSION.to_owned(),
                epoch: 1,
            },
        }
    }

    #[test]
    fn a_durable_capture_resumes_through_the_real_owner_readback() {
        let captured = Captured::take(HandoffCaptureBoundary::HostPreCompactHook, "checkpoint-1");
        let link = link();
        let attempt_identity = HandoffAttemptIdentity::NewAttemptCreated;
        // The retained payload is revalidated against the same current
        // generations and fence the owner read reports, so no dependent
        // permission is fenced and no rebuild is owed.
        let retained = RetainedHandoffCheckpoint::revalidate_for_resume(
            captured.checkpoint.clone(),
            link.clone(),
            attempt_identity.clone(),
            generations(),
            fence(),
        )
        .expect("the retained payload revalidates under the current observations");
        let evidence = HandoffResumeEvidence::Complete(Box::new(retained));
        let recipe_ref = reference("recipe", "recipe-1", "1", None);
        let incoming = intent();
        let state_fence = fence();
        let authority = authority(40, &state_fence);
        let request = HandoffResumeRequest {
            capture_checkpoint_id: &captured.checkpoint_id,
            registry: &captured.registry,
            evidence: &evidence,
            attempt_identity: &attempt_identity,
            link: Some(&link),
            capability: HandoffProviderCompactionCapability::ControllablePreHook,
            gap: None,
            recipe_ref: &recipe_ref,
            resume_request: &incoming,
            authority: &authority,
        };
        let mut bound = intent();

        let output = resume_captured_handoff(&captured.owner, &request, &mut bound)
            .expect("the retained capture resumes through the owner read");

        assert!(matches!(
            output.admission,
            HandoffResumeAdmission::Executable {
                rebuild_required: false,
                effects_pending: true,
                ..
            }
        ));
        assert!(matches!(
            output.dispatch,
            Some(HandoffDispatchDecision::NewAttempt {
                continuity: HandoffContinuity::Rehydrated,
                ..
            })
        ));
        // A changed generation would have fenced only the dependent members and
        // owed a rebuild; nothing changed, so neither is issued.
        assert!(output.rebuild.is_none());
        assert_eq!(output.effect_instructions.len(), 1);
        assert!(matches!(
            &output.effect_instructions[0],
            HandoffEffectInstruction::RetainForReconciliation { cause, .. }
            if cause == "the acknowledgement was never observed"
        ));
        // The bound link carries the revalidation reference the run proved.
        let bound_link = output.bound_link.as_ref().expect("an admitted resume binds its link");
        assert!(bound_link.post_resume_revalidation_ref.is_some());
        assert_eq!(bound.status, HandoffResumeStatus::ResumeAdmitted);
    }

    #[test]
    fn a_crossed_resume_intent_is_refused_before_any_authority_is_minted() {
        let captured = Captured::take(HandoffCaptureBoundary::HostPreCompactHook, "checkpoint-1");
        let link = link();
        let attempt_identity = HandoffAttemptIdentity::NewAttemptCreated;
        let retained = RetainedHandoffCheckpoint::revalidate_for_resume(
            captured.checkpoint.clone(),
            link.clone(),
            attempt_identity.clone(),
            generations(),
            fence(),
        )
        .expect("the retained payload revalidates under the current observations");
        let evidence = HandoffResumeEvidence::Complete(Box::new(retained));
        let recipe_ref = reference("recipe", "recipe-1", "1", None);
        let incoming = intent();
        let state_fence = fence();
        let authority = authority(40, &state_fence);
        let request = HandoffResumeRequest {
            capture_checkpoint_id: &captured.checkpoint_id,
            registry: &captured.registry,
            evidence: &evidence,
            attempt_identity: &attempt_identity,
            link: Some(&link),
            capability: HandoffProviderCompactionCapability::ControllablePreHook,
            gap: None,
            recipe_ref: &recipe_ref,
            resume_request: &incoming,
            authority: &authority,
        };

        // The right target attempt under the wrong handoff is a stale request.
        let mut crossed = intent();
        crossed.handoff_id = HandoffId::new("handoff-other").expect("other handoff id");
        assert!(matches!(
            resume_captured_handoff(&captured.owner, &request, &mut crossed),
            Err(HandoffCaptureCallerError::Resume(HandoffResumeError::Recovery(
                HandoffRecoveryError::Checkpoint(HandoffCheckpointError::StaleResumeRequest { .. })
            )))
        ));

        // A live read the owner cannot satisfy refuses before any authority.
        let expired = authority(130, &state_fence);
        let stale_request = HandoffResumeRequest {
            authority: &expired,
            ..request
        };
        let mut bound = intent();
        assert!(matches!(
            resume_captured_handoff(&captured.owner, &stale_request, &mut bound),
            Err(HandoffCaptureCallerError::Resume(
                HandoffResumeError::Coordination(CoordinationError::LeaseExpired)
            ))
        ));
    }

    #[test]
    fn a_relevant_generation_change_fences_only_the_dependent_permissions() {
        let moved = HandoffSourceGenerations {
            world: ResourceGeneration::new(7).expect("moved world generation"),
            ..generations()
        };
        let retained = RetainedHandoffCheckpoint::revalidate_for_resume(
            checkpoint(),
            link(),
            HandoffAttemptIdentity::NewAttemptCreated,
            moved,
            fence(),
        )
        .expect("a changed generation is recorded, not refused");
        let revalidation = &retained.revalidation;
        assert!(revalidation.world_changed);
        assert!(!revalidation.scope_changed);
        assert!(!revalidation.module_changed);
        assert!(!revalidation.route_changed);
        assert!(!revalidation.fence_changed);
        assert!(retained.requires_fresh_authority_before_execution());

        // Unrelated work is untouched: only the world member is fenced, and the
        // dependent permissions and content are what the rebuild request owes.
        let fencing =
            HandoffFencing::for_resume(revalidation, None).expect("dependent-only fencing");
        assert_eq!(fencing.fenced_members, vec!["world".to_owned()]);
        assert!(fencing.requires_rebuild());
        assert!(fencing.stale_lease.is_none());
    }

    #[test]
    fn a_link_under_the_wrong_continuity_identity_rule_is_refused() {
        let link = link();
        // Equal source and target attempts under a new-attempt rule is refused,
        // so a rehydrated transfer can never reuse the source attempt.
        let mut crossed = link;
        crossed.target_attempt_id = attempt_id("attempt-1");
        assert!(matches!(
            crossed.validate(&HandoffAttemptIdentity::NewAttemptCreated),
            Err(ContractError::HandoffRequiresNewAttempt { .. })
        ));
    }
}
