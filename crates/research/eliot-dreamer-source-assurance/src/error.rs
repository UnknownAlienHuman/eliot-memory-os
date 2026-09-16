//! Typed failures for role-separated source assurance.
//!
//! Every failure names its genuine condition. One satisfied check never fills
//! another missing check, and no failure defaults to a permissive evaluation.

use thiserror::Error;

/// Validation or canonicalization failure in the role-separation contract.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum RoleSeparationError {
    /// A required field is missing or blank.
    #[error("required field is missing or blank: {0}")]
    MissingField(&'static str),
    /// A text field exceeds its byte cap.
    #[error("field exceeds its byte cap: {0}")]
    TextTooLong(&'static str),
    /// A field is not a valid lowercase hexadecimal digest.
    #[error("field is not a valid lowercase hexadecimal digest: {0}")]
    InvalidDigest(&'static str),
    /// The portfolio exceeds the bounded member cap.
    #[error("portfolio exceeds the bounded member cap: {0}")]
    TooManyMembers(usize),
    /// Two expected members share one identity.
    #[error("duplicate portfolio member id: {0}")]
    DuplicateMemberId(String),
    /// An expected member has no claim linkage.
    #[error("expected portfolio member has no claim linkage: {0}")]
    MissingLinkage(String),
    /// An expected member has no observation.
    #[error("expected portfolio member has no observation: {0}")]
    MissingObservation(String),
    /// An observation names no expected member.
    #[error("observation names no expected portfolio member: {0}")]
    UnknownObservation(String),
    /// The portfolio denominator is absent.
    #[error("portfolio denominator is missing: no expected members")]
    MissingDenominator,
    /// An observation or policy was evaluated under another boundary.
    #[error("mixed evaluation boundary: expected {expected}, observed {observed}")]
    MixedEvaluationBoundary {
        /// Boundary declared by the frozen set.
        expected: String,
        /// Boundary carried by the offending observation or policy.
        observed: String,
    },
    /// Same immutable identity carries changed content.
    #[error("changed content under one immutable member identity: {0}")]
    ChangedContentUnderImmutableIdentity(String),
    /// A withheld member cites no declared policy or credential exclusion.
    #[error("withheld member cites an undeclared exclusion: {0}")]
    UndeclaredExclusion(String),
    /// A linkage names no expected member.
    #[error("claim linkage names no expected portfolio member: {0}")]
    UnknownMemberLinkage(String),
    /// A member carries two claim linkages.
    #[error("member carries two claim linkages: {0}")]
    DuplicateLinkage(String),
    /// A linkage has no claim while asserting a stance, or vice versa.
    #[error("claim linkage binds claim and stance inconsistently: {0}")]
    InconsistentClaimBinding(String),
    /// The evaluation window is empty or inverted.
    #[error("evaluation window is empty or inverted")]
    InvalidEvaluationWindow,
    /// The assurance schema version is unsupported.
    #[error("assurance schema version is unsupported: {0}")]
    UnsupportedSchema(String),
    /// The assurance policy version is unsupported.
    #[error("assurance policy version is unsupported: {0}")]
    UnsupportedPolicy(String),
    /// A consumer envelope does not bind the exact evidence set and result.
    #[error("consumer envelope does not bind the exact evidence set and result")]
    EnvelopeBindingMismatch,
    /// A consumer envelope failed re-verification against its evidence.
    #[error("consumer envelope failed re-verification against its evidence")]
    EnvelopeVerificationFailed,
    /// Canonical JSON encoding failed.
    #[error("assurance JSON encoding failed: {0}")]
    Json(String),
}

impl From<serde_json::Error> for RoleSeparationError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}
