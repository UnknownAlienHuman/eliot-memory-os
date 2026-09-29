//! Canonical pre-compaction handoff persistence caller (I12.17).
//!
//! [`WorkCheckpoint`]/[`CheckpointReceipt`](super::CheckpointReceipt) perform
//! no IO, and the capture operation in `eliot-agent-contracts` registers
//! intent without persisting anything. This module is the one canonical
//! caller that joins them: it binds a validated [`HandoffCheckpoint`] to its
//! governed [`WorkCheckpoint`] draft, commits through
//! [`CoordinationOwner::checkpoint`](super::CoordinationOwner::checkpoint),
//! reads the committed event back out of the owner, reconciles the same
//! capture operation to durable acceptance, and only then admits the
//! compaction permit. It creates no second journal: the owner event stream
//! stays the single transaction record, and persisting the owner
//! snapshot/event stream into the canonical store remains the store bridge's
//! work.
//!
//! Actual-caller coverage on current main:
//!
//! - the Governor/Task Controller capture producer calls
//!   [`capture_handoff_checkpoint`]; its operation is the registered ELIOT-
//!   controlled capture, and [`HandoffCaptureRegistry`](eliot_agent_contracts::HandoffCaptureRegistry)
//!   refuses the same checkpoint under any other operation;
//! - provider-internal compaction has no controllable pre-hook on main (the
//!   claude/codex/opencode adapters launch sidecars and only measure
//!   compaction as probe telemetry; they expose no capture entrypoint), so it
//!   is never registered here: it is recorded as a
//!   [`HandoffProviderGap`](eliot_agent_contracts::HandoffProviderGap) and
//!   continues only on the explicitly partial/rehydrated path;
//! - peer-board compaction, maintenance-job checkpoints, worker progress
//!   checkpoints and workscope saga resumes share vocabulary with this path
//!   but are not I12.17 handoffs and are not registered here.
//!
//! The draft's `request_id` is the owner idempotency key and the capture
//! operation identity at once: a retry after commit-response loss replays the
//! identical draft under the same key, so the owner returns the exact prior
//! receipt instead of minting a second checkpoint identity, and
//! [`reconcile_handoff_capture`] fails closed to
//! [`HandoffCaptureAcceptance::Unknown`](eliot_agent_contracts::HandoffCaptureAcceptance)
//! while no committed event reads back. A transport acknowledgement or a
//! locally computed hash is never durable readback and is never accepted
//! here.

#![forbid(unsafe_code)]

use eliot_agent_contracts::{
    HANDOFF_CHECKPOINT_REFERENCE_KIND, HandoffCaptureAcceptance, HandoffCaptureOperation,
    HandoffCaptureRegistry, HandoffCheckpoint, HandoffCheckpointError, HandoffRecoveryError,
    PublicReference, TargetId,
};
use eliot_contracts::OperationId;
use thiserror::Error;

use super::{CheckpointReceipt, CoordinationError, CoordinationEventKind, CoordinationOwner, WorkCheckpoint};

/// Failure of the canonical handoff persistence call.
///
/// Both variants reuse the owning error: record rejections keep their typed
/// checkpoint owner error, governed-path rejections keep the coordination
/// owner error, and registry/permit rejections keep the recovery owner
/// error. No failure is collapsed into a generic code.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HandoffPersistenceError {
    /// A handoff checkpoint record rejection, already typed by its owner.
    #[error(transparent)]
    Checkpoint(#[from] HandoffCheckpointError),
    /// A governed coordination-path rejection, already typed by its owner.
    #[error(transparent)]
    Coordination(#[from] CoordinationError),
    /// A capture-registry or compaction-permit rejection, already typed by
    /// its owner.
    #[error(transparent)]
    Recovery(#[from] HandoffRecoveryError),
}

/// Canonical owner-digest binding of one checkpoint to its governed draft.
///
/// The owner commits the draft's `checkpoint_ref` as the event payload
/// digest, so the binding must name the exact checkpoint identity: the
/// checkpoint reference kind with the checkpoint identity. The same text is
/// committed on every retry and read back before any compaction permit.
#[must_use]
pub fn handoff_checkpoint_ref_text(checkpoint: &HandoffCheckpoint) -> String {
    format!(
        "{HANDOFF_CHECKPOINT_REFERENCE_KIND}:{}",
        checkpoint.checkpoint_id.as_str()
    )
}

/// Builds the durable receipt reference for one committed capture.
///
/// The reference keeps the checkpoint kind, identity and source plan
/// revision and carries the exact committed owner-digest text, so the
/// acceptance names the durable record rather than a bare handle.
fn capture_receipt_ref(
    checkpoint: &HandoffCheckpoint,
) -> Result<PublicReference, HandoffCheckpointError> {
    let reference = PublicReference {
        kind: HANDOFF_CHECKPOINT_REFERENCE_KIND.to_owned(),
        id: TargetId::new(checkpoint.checkpoint_id.as_str())?,
        revision: checkpoint.source_plan_revision.clone(),
        digest: Some(handoff_checkpoint_ref_text(checkpoint)),
    };
    reference.validate()?;
    Ok(reference)
}

/// Checks the governed draft against the checkpoint it claims to persist.
///
/// The owner enforces the draft against its lease, session, epoch and fence;
/// this check enforces the draft against the checkpoint payload: identity,
/// fence, owner-digest binding and source session must agree, otherwise the
/// commit would persist a checkpoint under a foreign binding.
fn check_capture_binding(
    checkpoint: &HandoffCheckpoint,
    draft: &WorkCheckpoint,
) -> Result<OperationId, HandoffPersistenceError> {
    let operation_id =
        OperationId::new(draft.request_id.clone()).map_err(HandoffCheckpointError::Contract)?;
    if draft.checkpoint_id != checkpoint.checkpoint_id.as_str() {
        return Err(CoordinationError::InvalidField("handoff_capture.checkpoint_id").into());
    }
    if draft.state_fence != checkpoint.state_fence {
        return Err(CoordinationError::InvalidField("handoff_capture.state_fence").into());
    }
    if draft.checkpoint_ref != handoff_checkpoint_ref_text(checkpoint) {
        return Err(CoordinationError::InvalidField("handoff_capture.checkpoint_ref").into());
    }
    if draft.session_id != checkpoint.source_session_ref.id.as_str() {
        return Err(CoordinationError::InvalidField("handoff_capture.session_id").into());
    }
    Ok(operation_id)
}

/// Captures one checkpoint through the governed transaction/recovery path.
///
/// Validates the payload, binds the draft, registers the capture operation
/// (registering the same checkpoint under another operation is refused),
/// commits through the owner, reads the committed event back out of the
/// owner, reconciles the same operation to durable acceptance, and admits
/// the compaction permit. Repeating the call with the identical draft after
/// commit-response loss returns the exact prior receipt; repeating it with a
/// different draft under the same request identity fails with the owner's
/// idempotency conflict instead of minting a second checkpoint.
pub fn capture_handoff_checkpoint(
    owner: &mut CoordinationOwner,
    registry: &mut HandoffCaptureRegistry,
    checkpoint: &HandoffCheckpoint,
    draft: WorkCheckpoint,
) -> Result<CheckpointReceipt, HandoffPersistenceError> {
    checkpoint.validate()?;
    let operation_id = check_capture_binding(checkpoint, draft.clone())?;
    match registry.operation(&checkpoint.checkpoint_id) {
        None => registry.register(HandoffCaptureOperation::new(
            operation_id.clone(),
            checkpoint.checkpoint_id.clone(),
            HandoffCaptureAcceptance::Unknown {
                cause: "capture commit not yet observed".to_owned(),
            },
        )?)?,
        Some(existing)
            if existing.operation_id.as_str() != operation_id.as_str() =>
        {
            return Err(HandoffRecoveryError::DuplicateCaptureRegistration {
                checkpoint_id: checkpoint.checkpoint_id.as_str().to_owned(),
            }
            .into());
        }
        Some(_) => {}
    }
    let receipt = owner.checkpoint(draft)?;
    if !owner.events().contains(&receipt.event) {
        return Err(CoordinationError::InvalidState.into());
    }
    registry.reconcile_commit(
        &operation_id,
        &checkpoint.checkpoint_id,
        HandoffCaptureAcceptance::DurablyStored {
            receipt_ref: capture_receipt_ref(checkpoint)?,
        },
    )?;
    registry.require_compaction_permit(&checkpoint.checkpoint_id)?;
    Ok(receipt)
}

/// Reconciles a lost capture-commit response against the same operation.
///
/// Reads the owner event stream back for the committed checkpoint event
/// under this operation identity: a matching event reconciles the operation
/// to durable acceptance, while no match reconciles it to unknown, which
/// keeps refusing destructive compaction. The operation keeps its identity
/// either way; a second checkpoint identity is never created.
pub fn reconcile_handoff_capture(
    registry: &mut HandoffCaptureRegistry,
    owner: &CoordinationOwner,
    operation_id: &OperationId,
    checkpoint: &HandoffCheckpoint,
) -> Result<HandoffCaptureAcceptance, HandoffPersistenceError> {
    checkpoint.validate()?;
    let expected_digest = handoff_checkpoint_ref_text(checkpoint);
    let stored = owner.events().iter().any(|event| {
        event.kind == CoordinationEventKind::Checkpointed
            && event.idempotency_key == operation_id.as_str()
            && event.payload_digest == expected_digest
    });
    let acceptance = if stored {
        HandoffCaptureAcceptance::DurablyStored {
            receipt_ref: capture_receipt_ref(checkpoint)?,
        }
    } else {
        HandoffCaptureAcceptance::Unknown {
            cause: "capture commit response lost and no checkpoint event reads back under this operation"
                .to_owned(),
        }
    };
    registry.reconcile_commit(operation_id, &checkpoint.checkpoint_id, acceptance.clone())?;
    Ok(acceptance)
}
