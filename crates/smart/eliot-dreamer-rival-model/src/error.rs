//! Errors emitted by the bounded rival structuring boundary.

use std::fmt::{Display, Formatter};

/// Fail-closed errors for input binding and bounded output construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RivalModelError {
    /// The A03 candidate did not retain typed rival declarations.
    MissingRivalDeclarations,
    /// A lower contract rejected its own supplied value.
    InvalidContract(&'static str),
    /// Two supplied identities that must agree differ.
    IdentityMismatch(&'static str),
    /// A bounded input or output exceeded a declared limit.
    Bound {
        /// Bounded value name.
        field: &'static str,
        /// Maximum accepted size.
        maximum: usize,
        /// Supplied size.
        actual: usize,
    },
    /// The supplied policy requested cancellation before work began.
    Cancelled,
}

impl Display for RivalModelError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRivalDeclarations => formatter.write_str("rival declarations are missing"),
            Self::InvalidContract(name) => write!(formatter, "invalid contract: {name}"),
            Self::IdentityMismatch(name) => write!(formatter, "identity mismatch: {name}"),
            Self::Bound {
                field,
                maximum,
                actual,
            } => write!(formatter, "{field} exceeds {maximum} with {actual}"),
            Self::Cancelled => formatter.write_str("rival structuring was cancelled"),
        }
    }
}

impl std::error::Error for RivalModelError {}
