//! Closed, redacted validation failures for the learning contracts.

use thiserror::Error;

/// A failure that prevents a learning contract from being accepted.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum LearningContractError {
    /// A required field has no usable value.
    #[error("{field} is required")]
    Missing { field: &'static str },
    /// A bounded field exceeds its contract limit.
    #[error("{field} exceeds its contract bound")]
    Bound { field: &'static str },
    /// A collection contains the same semantic identity twice.
    #[error("{field} contains a duplicate identity")]
    Duplicate { field: &'static str },
    /// A record's digest does not match its canonical shape.
    #[error("{field} does not match its canonical shape")]
    DigestMismatch { field: &'static str },
    /// A digest is not a lowercase SHA-256 value.
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    /// Two records claim incompatible scope or fence.
    #[error("{field} has incompatible scope or state fence")]
    ScopeMismatch { field: &'static str },
    /// A protected surface changed in a candidate.
    #[error("protected surface changed")]
    ProtectedSurfaceChanged,
    /// A lifecycle stage skips its required predecessor.
    #[error("lifecycle predecessor is incompatible")]
    IncompatiblePredecessor,
    /// Owner-issued evidence is required for this disposition.
    #[error("{field} requires owner-issued evidence")]
    MissingOwnerEvidence { field: &'static str },
    /// A no-change result has no affirmative evidence or contradicts a change.
    #[error("no-change disposition is not evidence-backed")]
    InvalidNoChange,
    /// An inverse is absent for a reversible change.
    #[error("reversible change is missing its inverse")]
    MissingInverse,
    /// A candidate attempted to cross the package's proof ceiling.
    #[error("candidate-only proof ceiling was crossed")]
    CandidateCeiling,
    /// An observation was marked complete without its declared denominator.
    #[error("declared observation denominator is incomplete")]
    IncompleteCoverage,
    /// An assessment dimension appeared more than once or was conflated.
    #[error("assessment dimensions must remain independent")]
    NonIndependentAssessment,
    /// Canonical serialization failed without exposing payload contents.
    #[error("canonical serialization failed")]
    Canonicalization,
    /// A foundation identity rejected its shape.
    #[error("foundation contract identity is invalid")]
    Foundation,
    /// An evidence envelope rejected its shape.
    #[error("evidence envelope is invalid")]
    Evidence,
}
