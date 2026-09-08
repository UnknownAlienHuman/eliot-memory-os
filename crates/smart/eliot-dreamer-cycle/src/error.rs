//! Closed errors for the one-step Dreamer cycle controller.

use eliot_contracts::ContractError;
use eliot_dreamer_contracts::ContractViolation;
use eliot_receipts::ReceiptError;
use thiserror::Error;

/// Failure returned by a pure Dreamer cycle transition.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CycleError {
    /// A supplied identity, fence, predecessor or payload disagreed.
    #[error("cycle binding mismatch on {field}: {reason}")]
    BindingMismatch {
        /// Binding that failed.
        field: &'static str,
        /// Stable explanation.
        reason: &'static str,
    },
    /// A repeated identity carried changed content.
    #[error("cycle identity conflict for {identity}")]
    IdentityConflict {
        /// Conflicting request, outcome or cycle identity.
        identity: String,
    },
    /// A legal adjacent transition was not available.
    #[error("cycle phase transition is invalid: {0}")]
    PhaseViolation(&'static str),
    /// A required observation was absent or incompatible.
    #[error("cycle outcome is incomplete: {0}")]
    IncompleteOutcome(&'static str),
    /// A bounded collection or text value exceeded its limit.
    #[error("cycle input bound exceeded on {field}: maximum {maximum}")]
    Bound {
        /// Bounded field.
        field: &'static str,
        /// Inclusive maximum.
        maximum: usize,
    },
    /// A budget or cancellation policy prevented further transition.
    #[error("cycle budget or cancellation policy blocked the transition")]
    BudgetBlocked,
    /// A lower-level contract rejected the supplied value.
    #[error("cycle contract violation: {0}")]
    Contract(String),
    /// A supplied neutral receipt failed intrinsic validation.
    #[error("cycle receipt violation: {0}")]
    Receipt(String),
    /// Canonical digest encoding failed.
    #[error("cycle canonical encoding failed: {0}")]
    Encoding(String),
}

impl From<ContractError> for CycleError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error.to_string())
    }
}

impl From<ContractViolation> for CycleError {
    fn from(error: ContractViolation) -> Self {
        Self::Contract(error.to_string())
    }
}

impl From<ReceiptError> for CycleError {
    fn from(error: ReceiptError) -> Self {
        Self::Receipt(error.to_string())
    }
}
