//! Kernel-owned mechanical admission for durable directed mailbox items.
//!
//! The Governor peer channel owns the live delivery protocol and supplies the
//! admitted item or advance in a prepared transition. Kernel binds that
//! transition to the exact task and State Fence, binds the sender and
//! acknowledging session claims to the submitting Kernel Session, then keeps
//! the operation under the existing candidate-only effect ceiling. Delivery
//! proves only that a step ran; acknowledgement proves only receipt.

use super::{Session, TransportError};
use eliot_store_api::{
    EffectClass, NamedMutationOperation, PreparedTransition, TransitionClass, decode_mailbox_ack,
    decode_mailbox_delivery, decode_mailbox_expiry, decode_mailbox_item,
};

fn is_mailbox_operation(operation: NamedMutationOperation) -> bool {
    matches!(
        operation,
        NamedMutationOperation::AdmitMailboxItem
            | NamedMutationOperation::RecordMailboxDelivery
            | NamedMutationOperation::AcknowledgeMailboxItem
            | NamedMutationOperation::ExpireMailboxItem
    )
}

/// Mechanically admits a mailbox operation in an existing owner-prepared
/// transition. This does not interpret delivery semantics or grant task
/// acceptance, truth, authority, or effect; those stay with the semantic
/// owner and are not inferred from the transport session.
pub(crate) fn validate_mailbox_transition(
    session: &Session,
    transition: &PreparedTransition,
) -> Result<(), TransportError> {
    let Some(operation) = transition
        .named_operations
        .iter()
        .find(|operation| is_mailbox_operation(operation.operation))
    else {
        return Ok(());
    };
    if transition.named_operations.len() != 1
        || transition.transition_class != TransitionClass::CaptureCandidate
        || transition.requested_effect_ceiling != EffectClass::Candidate
    {
        return Err(TransportError::SessionFenced);
    }
    match operation.operation {
        NamedMutationOperation::AdmitMailboxItem => {
            let revision = decode_mailbox_item(operation.operation, &operation.parameters)
                .map_err(|_| TransportError::SessionFenced)?;
            let record = revision.record;
            if transition.task_id.as_deref() != Some(record.task_id.as_str())
                || record.state_fence != transition.state_fence
            {
                return Err(TransportError::SessionFenced);
            }
            // The sender acts only as its own submitting session; the
            // session identity is the admitted connection, never an
            // asserted principal string.
            if record.sender_session_id != session.connection_id {
                return Err(TransportError::SessionFenced);
            }
        }
        NamedMutationOperation::RecordMailboxDelivery => {
            let advance = decode_mailbox_delivery(operation.operation, &operation.parameters)
                .map_err(|_| TransportError::SessionFenced)?;
            if transition.task_id.as_deref() != Some(advance.task_id.as_str())
                || advance.expected_head.state_fence != transition.state_fence
            {
                return Err(TransportError::SessionFenced);
            }
        }
        NamedMutationOperation::AcknowledgeMailboxItem => {
            let advance = decode_mailbox_ack(operation.operation, &operation.parameters)
                .map_err(|_| TransportError::SessionFenced)?;
            if transition.task_id.as_deref() != Some(advance.task_id.as_str())
                || advance.expected_head.state_fence != transition.state_fence
            {
                return Err(TransportError::SessionFenced);
            }
            // Only the recipient session acknowledges, and only as its own
            // submitting session.
            if advance.by_session != session.connection_id {
                return Err(TransportError::SessionFenced);
            }
        }
        NamedMutationOperation::ExpireMailboxItem => {
            let advance = decode_mailbox_expiry(operation.operation, &operation.parameters)
                .map_err(|_| TransportError::SessionFenced)?;
            if transition.task_id.as_deref() != Some(advance.task_id.as_str())
                || advance.expected_head.state_fence != transition.state_fence
            {
                return Err(TransportError::SessionFenced);
            }
        }
        _ => return Err(TransportError::SessionFenced),
    }
    Ok(())
}
