//! Named semantic validation phases for the pure A-05 gate.

use eliot_dreamer_contracts::PreservationReport;

use crate::error::DreamDraftValidationError;

/// Checks the complete seven-dimension preservation contract.
pub(crate) fn validate_preservation(
    preservation: &PreservationReport,
) -> Result<(), DreamDraftValidationError> {
    preservation
        .overall()
        .map_err(|error| DreamDraftValidationError::InvalidContract {
            phase: "preservation",
            error,
        })
}
