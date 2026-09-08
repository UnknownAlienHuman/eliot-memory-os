//! Stable, redacted failures for the observation-only assessment boundary.

use thiserror::Error;

use eliot_learning_contracts::LearningContractError;

/// Failure which prevents constructing the candidate composition.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ActivationAssessmentError {
    /// A supplied collection or serialized input exceeded a finite bound.
    #[error("{field} exceeds the activation assessment bound")]
    Bound { field: &'static str },
    /// A supplied identity was repeated or paired with a different payload.
    #[error("{field} contains a conflicting duplicate")]
    Duplicate { field: &'static str },
    /// Two immutable records cannot be joined at the declared lineage.
    #[error("{field} has incompatible activation assessment lineage")]
    LineageMismatch { field: &'static str },
    /// The canonical owner rejected a supplied record.
    #[error("canonical learning contract rejected {field}")]
    Contract {
        field: &'static str,
        source: LearningContractError,
    },
    /// Canonical serialization was unavailable after bounded preflight.
    #[error("activation assessment canonicalization failed")]
    Canonicalization,
}

impl ActivationAssessmentError {
    pub(crate) fn contract(field: &'static str, source: LearningContractError) -> Self {
        Self::Contract { field, source }
    }
}
