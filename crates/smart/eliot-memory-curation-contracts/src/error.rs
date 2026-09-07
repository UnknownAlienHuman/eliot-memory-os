use thiserror::Error;

/// Intrinsic validation failures for the screening boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContractError {
    /// Required text was blank.
    #[error("{field} must be non-blank")]
    Blank { field: &'static str },
    /// Identity or text contained a control character.
    #[error("{field} contains a control character")]
    ControlCharacter { field: &'static str },
    /// A bounded counter was zero.
    #[error("{field} must be greater than zero")]
    Zero { field: &'static str },
    /// A value exceeded a declared bound.
    #[error("{field} exceeds its bound")]
    Bound { field: &'static str },
    /// A list that is semantically a set contained a duplicate.
    #[error("{field} contains a duplicate")]
    Duplicate { field: &'static str },
    /// Two records disagree about an immutable binding.
    #[error("{field} binding mismatch")]
    BindingMismatch { field: &'static str },
    /// An immutable record identity was reused with changed content.
    #[error("{field} changed content for an existing identity")]
    ChangedIdentity { field: &'static str },
    /// A closed vocabulary value was not admitted.
    #[error("{field} contains an unsupported value")]
    Unsupported { field: &'static str },
    /// A digest was not canonical lowercase SHA-256.
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    /// A complete denominator or result did not reconcile.
    #[error("{field} does not reconcile")]
    Reconciliation { field: &'static str },
    /// Canonical encoding failed.
    #[error("cannot canonicalize contract: {0}")]
    Canonicalization(String),
}
