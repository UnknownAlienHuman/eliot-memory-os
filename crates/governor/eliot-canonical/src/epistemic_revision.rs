//! Encoding of an epistemic decision already made by Governor admission.

use eliot_epistemic_contracts::{
    EpistemicPositionCandidate, EpistemicTransition, PositionId, PositionRevision,
};
use eliot_store_api::{
    NamedMutationRequest,
    epistemic_revision::{EPISTEMIC_REVISION_SCHEMA, EpistemicRevisionPayload},
};

use crate::CanonicalError;

/// Retains the exact inert contracts and an independent position predecessor.
/// Encoding alone neither establishes evidence nor admits a position.
pub fn epistemic_revision_command(
    position: PositionId,
    expected_position_revision: Option<PositionRevision>,
    transition: &EpistemicTransition,
    candidate: &EpistemicPositionCandidate,
) -> Result<NamedMutationRequest, CanonicalError> {
    EpistemicRevisionPayload {
        schema: EPISTEMIC_REVISION_SCHEMA.to_owned(),
        position,
        expected_position_revision,
        candidate: candidate.clone(),
        transition: transition.clone(),
    }
    .command()
    .map_err(CanonicalError::from)
}
