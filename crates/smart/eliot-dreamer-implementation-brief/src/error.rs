use eliot_conformance_contracts::ConformanceContractError;
use eliot_dreamer_contracts::SelfQueryContractError;
use thiserror::Error;

/// Closed failures of the pure Implementation-brief projection boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ImplementationBriefError {
    #[error(transparent)]
    SelfQuery(#[from] SelfQueryContractError),
    #[error(transparent)]
    Conformance(#[from] ConformanceContractError),
    #[error("{field} is missing")]
    Missing { field: &'static str },
    #[error("{field} exceeds {maximum} bytes/items (got {actual})")]
    Bound {
        field: &'static str,
        maximum: usize,
        actual: usize,
    },
    #[error("{field} is invalid: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    #[error("{field} contains duplicate identity {value}")]
    Duplicate {
        field: &'static str,
        value: String,
    },
    #[error("{field} does not match its governing identity")]
    BindingMismatch { field: &'static str },
    #[error("{field} digest does not match its canonical preimage")]
    DigestMismatch { field: &'static str },
    #[error("changed content was supplied under the same identity in {field}")]
    IdentityConflict { field: &'static str },
    #[error("{field} contains a dependency cycle")]
    DependencyCycle { field: &'static str },
    #[error("cannot encode {field} canonically")]
    Encoding { field: &'static str },
}
