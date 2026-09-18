use thiserror::Error;

/// Fail-closed validation or identity failure for clarification candidate construction.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ClarificationError {
    /// A required field is malformed, blank, unbounded, or semantically invalid.
    #[error("invalid clarification field {field}: {reason}")]
    InvalidField {
        /// Stable field name; never contains caller data.
        field: &'static str,
        /// Bounded diagnostic reason.
        reason: String,
    },
    /// Two records that must describe the same owner identity disagree.
    #[error("clarification binding mismatch: {field}")]
    BindingMismatch {
        /// Stable field name; never contains protected payload data.
        field: &'static str,
    },
    /// A finite input or output bound was exceeded.
    #[error("clarification limit exceeded: {field} (limit {limit})")]
    LimitExceeded {
        /// Stable bounded field name.
        field: &'static str,
        /// Exact configured limit.
        limit: usize,
    },
    /// A set-like identity was repeated.
    #[error("duplicate clarification identity in {field}")]
    DuplicateIdentity {
        /// Stable collection field name.
        field: &'static str,
    },
    /// A closed answer family is internally inconsistent.
    #[error("unsupported clarification answer schema: {reason}")]
    UnsupportedAnswerSchema {
        /// Bounded reason without an answer or protected payload.
        reason: String,
    },
    /// The valid-answer denominator is not mapped exactly once.
    #[error("incomplete clarification branch map: {reason}")]
    IncompleteBranchMap {
        /// Bounded reason without answer data.
        reason: String,
    },
    /// The same logical decision identity was replayed with changed meaning.
    #[error("clarification identity conflict")]
    IdentityConflict,
    /// Canonical encoding failed before a candidate could be emitted.
    #[error("clarification canonicalization failed")]
    Canonicalization,
}

impl ClarificationError {
    pub(crate) fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidField {
            field,
            reason: reason.into(),
        }
    }

    pub(crate) const fn binding(field: &'static str) -> Self {
        Self::BindingMismatch { field }
    }

    pub(crate) const fn limit(field: &'static str, limit: usize) -> Self {
        Self::LimitExceeded { field, limit }
    }
}
