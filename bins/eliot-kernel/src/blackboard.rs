//! Kernel-owned mechanical admission for typed blackboard candidates.
//!
//! The semantic owner supplies the candidate and its producer-lineage
//! evidence in a prepared transition. Kernel binds that candidate to the
//! authenticated submitting principal, exact task and State Fence, then
//! keeps the operation under the existing candidate-only effect ceiling.

use super::{Session, TransportError};
use eliot_ipc::PeerIdentity;
use eliot_store_api::{
    EffectClass, NamedMutationOperation, PreparedTransition, TransitionClass,
    decode_blackboard_item,
};

/// Mechanically admits an `ApplyBlackboardItem` operation in an existing
/// owner-prepared transition. This does not authenticate the producer attempt
/// represented by `producer_lineage`; that binding remains with the semantic
/// producer owner and is not inferred from the transport authority epoch.
pub(crate) fn validate_blackboard_transition(
    session: &Session,
    transition: &PreparedTransition,
) -> Result<(), TransportError> {
    let Some(operation) = transition
        .named_operations
        .iter()
        .find(|operation| operation.operation == NamedMutationOperation::ApplyBlackboardItem)
    else {
        return Ok(());
    };
    if transition.named_operations.len() != 1
        || transition.transition_class != TransitionClass::CaptureCandidate
        || transition.requested_effect_ceiling != EffectClass::Candidate
    {
        return Err(TransportError::SessionFenced);
    }

    let revision = decode_blackboard_item(operation.operation, &operation.parameters)
        .map_err(|_| TransportError::SessionFenced)?;
    let record = revision.record;
    if transition.task_id.as_deref() != Some(record.task_id.as_str())
        || record.state_fence != transition.state_fence
    {
        return Err(TransportError::SessionFenced);
    }
    let principal = match &session.peer {
        PeerIdentity::Authenticated { user_identity, .. }
            if !user_identity.trim().is_empty() && !user_identity.chars().any(char::is_control) =>
        {
            user_identity
        }
        PeerIdentity::Authenticated { .. } => return Err(TransportError::SessionFenced),
        PeerIdentity::Unavailable { .. } => {
            return Err(TransportError::PeerIdentityUnavailable);
        }
    };
    if record.author_principal.as_str() != principal.as_str() {
        return Err(TransportError::SessionFenced);
    }
    // Existing receipt SessionBinding uses the admitted Kernel Session's
    // connection_id as session_id; its authority epoch and State Fence
    // remain separate fields. Do not derive this from the principal or
    // transport session epoch.
    if let eliot_contracts::BoardEntryState::Retracted { by_session, .. } = &record.lifecycle
        && by_session != &session.connection_id
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}
