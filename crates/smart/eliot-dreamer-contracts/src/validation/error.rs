//! Structural failures used while forming a validated Dreamer handoff.

use thiserror::Error;

/// Typed failures before a candidate can be safely retained.
#[derive(Debug, Error)]
pub enum DreamDraftValidationError {
    /// A hostile nested input exceeds a preflight bound.
    #[error("{field} exceeds the bounded limit {maximum}: got {actual}")]
    Bound {
        /// Stable field path.
        field: &'static str,
        /// Maximum admitted count or bytes.
        maximum: usize,
        /// Observed count or bytes.
        actual: usize,
    },
    /// A canonical preimage could not be encoded.
    #[error("canonical encoding failed for {field}: {detail}")]
    Encoding {
        /// Preimage kind.
        field: &'static str,
        /// Encoding diagnostic.
        detail: String,
    },
    /// An A03 value was not structurally valid enough to preserve safely.
    #[error("invalid {phase} contract at {field}")]
    InvalidContract {
        /// Validation phase.
        phase: &'static str,
        /// Stable field or dimension identifier.
        field: &'static str,
    },
}

/// Reduces a closed contract failure to the stable historical A05 error API.
pub fn summarize_contract(
    phase: &'static str,
    error: &crate::ContractViolation,
) -> DreamDraftValidationError {
    use crate::ContractViolation;
    let field = match error {
        ContractViolation::UnknownVariant { field, .. }
        | ContractViolation::MissingField(field)
        | ContractViolation::ImplicitDefault(field)
        | ContractViolation::OutOfBounds { field, .. }
        | ContractViolation::BindingMismatch { field, .. }
        | ContractViolation::Malformed { field, .. } => *field,
        ContractViolation::Budget { dimension, .. } => *dimension,
        ContractViolation::CrossStage(_)
        | ContractViolation::KindPayload(_)
        | ContractViolation::Registry(_)
        | ContractViolation::ScreenIneligible(_)
        | ContractViolation::Preservation(_)
        | ContractViolation::ForbiddenCarry(_) => "contract",
    };
    DreamDraftValidationError::InvalidContract { phase, field }
}

pub(crate) fn binding(field: &'static str) -> DreamDraftValidationError {
    DreamDraftValidationError::InvalidContract {
        phase: "receipt binding",
        field,
    }
}
