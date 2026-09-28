//! Kernel-owned mechanical admission for integration-candidate manifests.
//!
//! The semantic owner supplies the manifest and its producer-lineage
//! evidence in a prepared transition. Kernel binds that manifest to the
//! exact task and State Fence, then keeps the operation under the existing
//! candidate-only effect ceiling. Candidate lifecycle stays owned by the
//! coordination record; this gate performs no lifecycle transition.

use super::{Session, TransportError};
use eliot_store_api::{
    EffectClass, NamedMutationOperation, PreparedTransition, TransitionClass,
    decode_integration_candidate,
};

/// Mechanically admits an `ApplyIntegrationCandidate` operation in an
/// existing owner-prepared transition. This does not authenticate the
/// producer attempt represented by `producer_lineage`; that binding remains
/// with the semantic producer owner and is not inferred from the transport
/// authority epoch.
pub(crate) fn validate_integration_candidate_transition(
    _session: &Session,
    transition: &PreparedTransition,
) -> Result<(), TransportError> {
    let Some(operation) = transition
        .named_operations
        .iter()
        .find(|operation| operation.operation == NamedMutationOperation::ApplyIntegrationCandidate)
    else {
        return Ok(());
    };
    if transition.named_operations.len() != 1
        || transition.transition_class != TransitionClass::CaptureCandidate
        || transition.requested_effect_ceiling != EffectClass::Candidate
    {
        return Err(TransportError::SessionFenced);
    }

    let revision = decode_integration_candidate(operation.operation, &operation.parameters)
        .map_err(|_| TransportError::SessionFenced)?;
    let record = revision.record;
    if transition.task_id.as_deref() != Some(record.task_id.as_str())
        || record.state_fence != transition.state_fence
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}
