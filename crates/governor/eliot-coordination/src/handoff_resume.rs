//! Governor resume-owner join for retained handoff resume (I12.17, I7.15).
//!
//! [`capture_handoff_checkpoint`](super::capture_handoff_checkpoint) is the one
//! canonical caller that persists a checkpoint through the governed owner event
//! stream. This module is its resume-side symmetric join: the Governor-side
//! entrypoint that admits a resume from one retained checkpoint only after the
//! durable capture reads back out of the same owner.
//!
//! The join performs no IO, mints no authority, launches no worker, and reads
//! no store:
//!
//! - resume evidence must be the complete retained payload: a checkpoint
//!   reference alone is refused with
//!   [`HandoffRecoveryError::CheckpointPayloadRequired`](eliot_agent_contracts::HandoffRecoveryError::CheckpointPayloadRequired),
//!   so a saved provider token, public reference, or bare continuation handle
//!   can never resume on its own;
//! - the retained payload is re-checked with the existing
//!   [`RetainedHandoffCheckpoint::validate`](eliot_agent_contracts::RetainedHandoffCheckpoint::validate),
//!   which re-runs the checkpoint-to-link binding (including the continuity
//!   attempt-identity rule) against the original digests;
//! - the payload must also be bound to the controlled-boundary capture the
//!   resume owner names through
//!   [`HandoffRecoveryInputs::ledger`](eliot_agent_contracts::HandoffRecoveryInputs),
//!   which
//!   [`recover_handoff`](eliot_agent_contracts::recover_handoff) enforces with
//!   the existing
//!   [`HandoffCheckpoint::validate_capture_binding`](eliot_agent_contracts::HandoffCheckpoint::validate_capture_binding):
//!   the named boundary must have registered a capture of exactly this payload
//!   and that capture must hold a durable readback, so a checkpoint that no
//!   boundary ever captured cannot be resumed on a commit permit alone;
//! - the durable capture is corroborated against the live owner event stream:
//!   the exact owner-digest text committed at capture must read back as a
//!   `Checkpointed` event, otherwise the resume is refused instead of running
//!   on trust in a capture that never landed or did not survive restart;
//! - current authority observations stay caller-supplied cross-owner reads
//!   (task, scope, world, module, policy, route, and lease owners); this join
//!   mints no generations and fabricates no fence, lease, or epoch;
//! - the admitted run itself is [`recover_handoff`](eliot_agent_contracts::recover_handoff),
//!   which gates destructive compaction on durable readback, admits the resume
//!   under fresh authority, dispatches the continuity branch (replayed
//!   messages stay inert and never re-execute tools), reconciles every
//!   in-flight operation without duplicating launch or effects, derives the
//!   rebuild request for the external Context caller, and binds the admitted
//!   outcome to the causal link and intent.
//!
//! What this join deliberately does not do belongs to its real owners, which
//! are named here rather than faked:
//!
//! - supplying current authority observations belongs to the Kernel and the
//!   task/scope/world/module/policy/route/lease owners;
//! - advancing an admitted intent to executed belongs to the worker owner and
//!   runs through
//!   [`HandoffRecoveryFinish::mark_executed`](eliot_agent_contracts::HandoffRecoveryFinish::mark_executed)
//!   only when the bound worker actually executes;
//! - updating the attempt record belongs to the attempt owner, which cites
//!   the bound link's revalidation reference;
//! - rebuilding the delta View belongs to the external Context
//!   delta-reconstruction caller, which feeds the returned rebuild request to
//!   the accepted pure Context compiler under the current approved recipe.

#![forbid(unsafe_code)]

use eliot_agent_contracts::{
    HandoffRecoveryInputs, HandoffRecoveryOutput, HandoffResumeIntent, recover_handoff,
};

use super::{
    CoordinationError, CoordinationEventKind, CoordinationOwner, HandoffPersistenceError,
    handoff_checkpoint_ref_text,
};

/// Resumes from one retained handoff checkpoint through the Governor owner.
///
/// Re-checks the complete retained payload with its existing validator,
/// corroborates the durable capture against the live owner event stream, and
/// runs the recovery-handoff owners in order. A reference-only resume, a
/// binding mismatch, or a capture that does not read back fails closed: no
/// executable resumed session is issued.
pub fn resume_from_retained_handoff(
    owner: &CoordinationOwner,
    inputs: &HandoffRecoveryInputs<'_>,
    intent: &mut HandoffResumeIntent,
) -> Result<HandoffRecoveryOutput, HandoffPersistenceError> {
    let retained = inputs.evidence.retained()?;
    retained.validate()?;
    let expected_digest = handoff_checkpoint_ref_text(&retained.checkpoint);
    let stored = owner.events().iter().any(|event| {
        event.kind == CoordinationEventKind::Checkpointed && event.payload_digest == expected_digest
    });
    if !stored {
        return Err(CoordinationError::InvalidState.into());
    }
    Ok(recover_handoff(inputs, intent)?)
}
