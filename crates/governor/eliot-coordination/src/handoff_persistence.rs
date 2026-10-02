//! Canonical pre-compaction handoff persistence caller (I12.17).
//!
//! [`WorkCheckpoint`]/[`CheckpointReceipt`](super::CheckpointReceipt) perform
//! no IO, and the capture operation in `eliot-agent-contracts` registers
//! intent without persisting anything. This module is the one canonical
//! caller that joins them: it binds a validated capture to its governed
//! [`WorkCheckpoint`] draft, commits through
//! [`CoordinationOwner::checkpoint`](super::CoordinationOwner::checkpoint),
//! reads the committed event back out of the owner, reconciles the same
//! capture operation to durable acceptance, and only then admits the
//! compaction permit. It creates no second journal: the owner event stream
//! stays the single transaction record, and persisting the owner
//! snapshot/event stream into the canonical store remains the store bridge's
//! work.
//!
//! The committed text is the whole
//! [`HandoffCaptureBinding`](eliot_agent_contracts::HandoffCaptureBinding):
//! the checkpoint identity *and* its frozen diff, retained artifacts, pending
//! verifiers and in-flight operations, plus both digests the capture recorded
//! at the boundary. Persisting the checkpoint without those artifact
//! references would leave a durable record that proves nothing about what was
//! retained, so the readback parses the stored text back and compares it
//! against the capture's own recorded content before any permit is issued.
//!
//! The durable path, in order:
//!
//! - [`capture_handoff_checkpoint`] registers the capture operation (a
//!   different operation for the same checkpoint is refused), commits the
//!   governed draft, and confirms the commit landed in the owner event stream;
//! - [`read_back_capture`] then reads the committed event back out of the
//!   owner *independently of the commit receipt*, parses the stored binding,
//!   and records the readback through
//!   [`HandoffCapture::record_readback`](eliot_agent_contracts::HandoffCapture::record_readback),
//!   which compares the store's observed digests and both directions of every
//!   reference set against what this operation recorded;
//! - only after that does the registry reconcile to
//!   [`HandoffCaptureAcceptance::DurablyStored`](eliot_agent_contracts::HandoffCaptureAcceptance)
//!   and admit the compaction permit.
//!
//! A transport acknowledgement and a locally computed hash are never a
//! readback, and are never accepted here. A commit response that is lost
//! reconciles the *same* operation through [`reconcile_handoff_capture`],
//! which fails closed to
//! [`HandoffCaptureAcceptance::Unknown`](eliot_agent_contracts::HandoffCaptureAcceptance)
//! while no committed event reads back, and mints no second checkpoint
//! identity.
//!
//! Provider-internal compaction has no controllable pre-hook on main (the
//! claude/codex/opencode adapters launch sidecars and only measure compaction
//! as probe telemetry; they expose no capture entrypoint), so it is never
//! registered here: it is recorded as a
//! [`HandoffProviderGap`](eliot_agent_contracts::HandoffProviderGap) and
//! continues only on the explicitly partial/rehydrated path. Peer-board
//! compaction, maintenance-job checkpoints, worker progress checkpoints and
//! workscope saga resumes share vocabulary with this path but are not I12.17
//! handoffs and are not registered here.

#![forbid(unsafe_code)]

use eliot_agent_contracts::{
    HANDOFF_CHECKPOINT_REFERENCE_KIND, HandoffCapture, HandoffCaptureAcceptance,
    HandoffCaptureBinding, HandoffCaptureError, HandoffCaptureOperation, HandoffCaptureRegistry,
    HandoffCheckpoint, HandoffCheckpointError, HandoffCheckpointId, HandoffRecoveryError,
    PublicReference, RevisionId, TargetId,
};
use eliot_contracts::{OperationId, ResourceGeneration};
use thiserror::Error;

use super::{
    CheckpointReceipt, CoordinationError, CoordinationEvent, CoordinationEventKind,
    CoordinationOwner, WorkCheckpoint,
};

/// Failure of the canonical handoff persistence call.
///
/// Every variant reuses the owning error: capture-binding rejections keep their
/// typed checkpoint owner error, record rejections keep the controlled-boundary
/// capture error, governed-path rejections keep the coordination owner error,
/// and registry/permit rejections keep the recovery owner error. No failure is
/// collapsed into a generic code.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HandoffPersistenceError {
    /// A handoff checkpoint record rejection, already typed by its owner.
    #[error(transparent)]
    Checkpoint(#[from] HandoffCheckpointError),
    /// A controlled-boundary capture rejection, already typed by its owner.
    #[error(transparent)]
    Capture(#[from] HandoffCaptureError),
    /// A governed coordination-path rejection, already typed by its owner.
    #[error(transparent)]
    Coordination(#[from] CoordinationError),
    /// A capture-registry or compaction-permit rejection, already typed by its
    /// owner.
    #[error(transparent)]
    Recovery(#[from] HandoffRecoveryError),
}

/// The exact owner-digest text one capture commit stores.
///
/// The text is the capture's whole durable binding, so the checkpoint and its
/// artifact references are persisted together in one record. The same capture
/// always produces the same text, which is what lets a retry read the stored
/// event back and lets a later resume find it.
pub fn handoff_capture_binding_text(
    capture: &HandoffCapture,
) -> Result<String, HandoffPersistenceError> {
    Ok(capture.binding()?.to_text()?)
}

/// Builds the durable receipt reference for one read-back capture commit.
///
/// The reference keeps the checkpoint kind, identity and source plan revision
/// and carries the exact stored binding text as its digest, so the acceptance
/// names the durable record rather than a bare handle.
fn capture_receipt_ref(
    binding: &HandoffCaptureBinding,
) -> Result<PublicReference, HandoffCheckpointError> {
    let reference = PublicReference {
        kind: HANDOFF_CHECKPOINT_REFERENCE_KIND.to_owned(),
        id: TargetId::new(binding.checkpoint_id.as_str())?,
        revision: RevisionId::new(binding.checkpoint_id.as_str())?,
        digest: Some(binding.to_text()?),
    };
    reference.validate()?;
    Ok(reference)
}

/// Checks the governed draft against the capture it claims to persist.
///
/// The owner enforces the draft against its lease, session, epoch and fence;
/// this check enforces the draft against the capture: identity, fence,
/// source session, and the exact binding text must agree, otherwise the commit
/// would persist a checkpoint under a foreign binding.
fn check_capture_binding(
    capture: &HandoffCapture,
    draft: &WorkCheckpoint,
) -> Result<OperationId, HandoffPersistenceError> {
    let operation_id = OperationId::new(draft.request_id.clone())
        .map_err(|_| CoordinationError::InvalidField("handoff_capture.request_id"))?;
    let binding_text = handoff_capture_binding_text(capture)?;
    if draft.checkpoint_id != capture.capture_id.as_str() {
        return Err(CoordinationError::InvalidField("handoff_capture.checkpoint_id").into());
    }
    if draft.state_fence != capture.source_fence {
        return Err(CoordinationError::InvalidField("handoff_capture.state_fence").into());
    }
    if draft.session_id != capture.source_session_ref.id.as_str() {
        return Err(CoordinationError::InvalidField("handoff_capture.session_id").into());
    }
    if operation_id.as_str() != capture.operation_id.as_str() {
        return Err(CoordinationError::InvalidField("handoff_capture.operation_id").into());
    }
    if draft.checkpoint_ref != binding_text {
        return Err(CoordinationError::InvalidField("handoff_capture.checkpoint_ref").into());
    }
    Ok(operation_id)
}

/// Registers one capture operation under its checkpoint identity.
///
/// Registering the same operation again leaves its recorded acceptance alone:
/// an acceptance a durable readback already proved is a store observation and
/// is never withdrawn by a retry that has not reached its own readback yet.
/// Registering the same checkpoint under a *different* operation is refused with
/// [`HandoffRecoveryError::DuplicateCaptureRegistration`], so a lost response
/// can never become a second capture.
fn register_capture_operation(
    registry: &mut HandoffCaptureRegistry,
    operation_id: &OperationId,
    checkpoint_id: &HandoffCheckpointId,
) -> Result<(), HandoffPersistenceError> {
    if let Some(existing) = registry.operation(checkpoint_id) {
        if existing.operation_id.as_str() != operation_id.as_str() {
            return Err(HandoffRecoveryError::DuplicateCaptureRegistration {
                checkpoint_id: checkpoint_id.as_str().to_owned(),
            }
            .into());
        }
        return Ok(());
    }
    registry.register(HandoffCaptureOperation::new(
        operation_id.clone(),
        checkpoint_id.clone(),
        HandoffCaptureAcceptance::Unknown {
            cause: "capture commit not yet observed".to_owned(),
        },
    )?)?;
    Ok(())
}

/// Commits one capture through the governed transaction/recovery path.
///
/// Validates the capture, binds the governed draft to it, registers the
/// capture operation (a different operation for the same checkpoint identity
/// is refused), and commits through the owner. A retry that already committed
/// under this request identity reads the stored event back instead of
/// committing again, so repeating the call with the same draft after a
/// commit-response loss returns the exact prior receipt; repeating it with a
/// different draft under the same request identity fails with the owner's
/// idempotency conflict instead of minting a second checkpoint.
///
/// This returns once the commit is in the owner event stream. It deliberately
/// does **not** admit destructive compaction: the permit belongs to
/// [`read_back_capture`], which runs after the durable readback.
pub fn capture_handoff_checkpoint(
    owner: &mut CoordinationOwner,
    registry: &mut HandoffCaptureRegistry,
    capture: &HandoffCapture,
    draft: WorkCheckpoint,
) -> Result<CheckpointReceipt, HandoffPersistenceError> {
    let operation_id = check_capture_binding(capture, &draft)?;
    register_capture_operation(registry, &operation_id, &capture.capture_id)?;
    if let Some(receipt) = readback_committed_capture(owner, capture, &draft)? {
        return Ok(receipt);
    }
    let receipt = owner.checkpoint(draft)?;
    if !owner.events().contains(&receipt.event) {
        return Err(CoordinationError::InvalidState.into());
    }
    Ok(receipt)
}

/// Reads the already-committed capture event for one draft back out of the
/// owner without committing again.
///
/// The owner assigns a fresh causal sequence to every committed event, so a
/// retried draft can never replay its commit through the owner: the owner would
/// refuse the stale predecessor. The retry therefore reads the stored
/// `Checkpointed` event under this request identity instead, and checks that
/// the stored binding is the one this capture committed. A stored event whose
/// subject or binding differs from this draft is a different input under the
/// same key and fails with the owner's idempotency conflict; no match means the
/// first commit never landed and the caller proceeds to commit.
///
/// The return shape carries exactly that distinction: `Ok(None)` is "no prior
/// commit of this operation is in the stream", and `Err` is a refusal that
/// keeps its own typed owner error. A parse refusal is never read as "no prior
/// commit": letting one pass for that would let a foreign record stored under
/// this operation identity pass for this draft's capture.
fn readback_committed_capture(
    owner: &CoordinationOwner,
    capture: &HandoffCapture,
    draft: &WorkCheckpoint,
) -> Result<Option<CheckpointReceipt>, HandoffPersistenceError> {
    // `check_capture_binding` already proved the draft reference equals a real
    // binding's canonical text, so this parse is the round trip of the text this
    // caller is about to commit, not a new claim about the store.
    let expected = HandoffCaptureBinding::from_text(&draft.checkpoint_ref)?;
    let stored = owner.events().iter().find(|event| {
        event.kind == CoordinationEventKind::Checkpointed
            && event.idempotency_key == draft.request_id
    });
    let Some(stored) = stored else {
        return Ok(None);
    };
    if stored.subject_id != draft.work_item_id || stored.payload_digest != draft.checkpoint_ref {
        return Err(CoordinationError::IdempotencyConflict(draft.request_id.clone()).into());
    }
    // The compared binding is parsed back out of the stored event text, so the
    // retry admits the record the store holds rather than a recomputed one.
    let binding = HandoffCaptureBinding::from_text(&stored.payload_digest)?;
    if binding != expected || binding.checkpoint_id != capture.capture_id {
        return Err(CoordinationError::IdempotencyConflict(
            draft.request_id.clone(),
        )
        .into());
    }
    Ok(Some(CheckpointReceipt {
        checkpoint_id: draft.checkpoint_id.clone(),
        work_item_id: draft.work_item_id.clone(),
        event: stored.clone(),
    }))
}

/// Returns the committed `Checkpointed` event that stored one binding.
///
/// The lookup is by parsed content, not by a recomputed string: the stored text
/// is parsed and matched on the checkpoint identity it names, so a resume finds
/// the record the capture committed without being able to present a binding it
/// merely recomputed.
fn stored_capture_event<'a>(
    owner: &'a CoordinationOwner,
    checkpoint_id: &HandoffCheckpointId,
) -> Option<(&'a CoordinationEvent, HandoffCaptureBinding)> {
    owner
        .events()
        .iter()
        .filter(|event| event.kind == CoordinationEventKind::Checkpointed)
        .find_map(|event| {
            let binding = HandoffCaptureBinding::from_text(&event.payload_digest).ok()?;
            (binding.checkpoint_id == *checkpoint_id).then_some((event, binding))
        })
}

/// Reads one committed capture back out of the owner and records the readback.
///
/// This is the durable-readback step, and it is deliberately separate from the
/// commit: the committed event is re-read out of the owner *independently of
/// the commit receipt*, so a receipt a caller already holds is never its own
/// evidence. The stored text is parsed back into a
/// [`HandoffCaptureBinding`](eliot_agent_contracts::HandoffCaptureBinding) and
/// projected onto the readback the store observed, which
/// [`HandoffCapture::record_readback`](eliot_agent_contracts::HandoffCapture::record_readback)
/// then checks against this operation's own recorded digests, retained
/// artifacts, pending verifiers and pending effects in both directions.
///
/// Only a capture whose readback holds moves to
/// [`HandoffCaptureAcceptance::DurablyStored`](eliot_agent_contracts::HandoffCaptureAcceptance)
/// and admits the compaction permit. A commit that is not in the event stream,
/// or whose stored binding does not describe this operation, leaves the
/// acceptance unknown and the compaction refused.
pub fn read_back_capture(
    owner: &CoordinationOwner,
    registry: &mut HandoffCaptureRegistry,
    capture: &mut HandoffCapture,
) -> Result<ResourceGeneration, HandoffPersistenceError> {
    let stored = stored_capture_event(owner, &capture.capture_id).ok_or_else(|| {
        // The commit never landed, or landed under a different record: the
        // acceptance stays unknown and destructive compaction stays refused.
        HandoffRecoveryError::UnregisteredCaptureCaller {
            checkpoint_id: capture.capture_id.as_str().to_owned(),
        }
    })?;
    let (event, binding) = stored;
    if event.payload_digest != capture.binding()?.to_text()? {
        return Err(HandoffRecoveryError::UnregisteredCaptureCaller {
            checkpoint_id: capture.capture_id.as_str().to_owned(),
        }
        .into());
    }
    let read_generation = event.state_fence.resource_generation;
    if !capture.readback().is_some_and(|held| {
        *held == binding.to_readback(read_generation)
    }) {
        capture.record_readback(binding.to_readback(read_generation))?;
    }
    if !capture.admits_destructive_compaction() {
        return Err(HandoffCheckpointError::CaptureNotDurablyReadBack.into());
    }
    registry.reconcile_commit(
        &capture.operation_id,
        &capture.capture_id,
        HandoffCaptureAcceptance::DurablyStored {
            receipt_ref: capture_receipt_ref(&binding)?,
        },
    )?;
    registry.require_compaction_permit(&capture.capture_id)?;
    Ok(read_generation)
}

/// Returns the binding the owner durably holds for one retained checkpoint.
///
/// The stored text is parsed out of the committed event rather than recomputed
/// from the retained payload, so this is what the store holds, not what the
/// caller could produce. A checkpoint with no committed binding is refused:
/// there is no durable record to resume from.
pub fn stored_capture_binding(
    owner: &CoordinationOwner,
    checkpoint_id: &HandoffCheckpointId,
) -> Result<HandoffCaptureBinding, HandoffPersistenceError> {
    stored_capture_event(owner, checkpoint_id)
        .map(|(_, binding)| binding)
        .ok_or_else(|| {
            HandoffRecoveryError::UnregisteredCaptureCaller {
                checkpoint_id: checkpoint_id.as_str().to_owned(),
            }
            .into()
        })
}

/// Reconciles a lost capture-commit response against the same operation.
///
/// Reads the owner event stream back for the committed checkpoint event under
/// this operation identity and parses the binding it stored: a matching event
/// reconciles the operation to durable acceptance, while no match reconciles it
/// to unknown, which keeps refusing destructive compaction. The operation keeps
/// its identity either way; a second checkpoint identity is never created.
///
/// This only settles the *acceptance* of the operation. The capture's own
/// readback state still has to be recorded by [`read_back_capture`], so a
/// recovered operation is not a license to compact.
pub fn reconcile_handoff_capture(
    registry: &mut HandoffCaptureRegistry,
    owner: &CoordinationOwner,
    operation_id: &OperationId,
    checkpoint: &HandoffCheckpoint,
) -> Result<HandoffCaptureAcceptance, HandoffPersistenceError> {
    checkpoint.validate()?;
    let stored = owner
        .events()
        .iter()
        .filter(|event| event.kind == CoordinationEventKind::Checkpointed)
        .filter(|event| event.idempotency_key == operation_id.as_str())
        .find_map(|event| {
            HandoffCaptureBinding::from_text(&event.payload_digest)
                .ok()
                .filter(|binding| {
                    binding.checkpoint_id == checkpoint.checkpoint_id
                        && binding.operation_id.as_str() == operation_id.as_str()
                })
        });
    let acceptance = match stored {
        Some(binding) => HandoffCaptureAcceptance::DurablyStored {
            receipt_ref: capture_receipt_ref(&binding)?,
        },
        None => HandoffCaptureAcceptance::Unknown {
            cause: "capture commit response lost and no event reads back".to_owned(),
        },
    };
    registry.reconcile_commit(operation_id, &checkpoint.checkpoint_id, acceptance.clone())?;
    Ok(acceptance)
}
