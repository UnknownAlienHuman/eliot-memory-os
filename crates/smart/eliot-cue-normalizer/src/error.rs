//! Stable, redacted failures from the pure normalizer.

use eliot_cue_contracts::CueContractError;

/// Error returned by the A-11 normalization operation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NormalizationError {
    /// A nested A-10 contract rejected the input or result.
    #[error("cue contract rejected {0}")]
    Contract(CueContractError),
    /// A stable field failed its local shape rule.
    #[error("invalid normalization field: {field}")]
    InvalidField {
        /// Stable field path, never caller payload.
        field: &'static str,
    },
    /// A bounded input or output was too large.
    #[error("{field} exceeds bound {limit}")]
    BoundExceeded {
        /// Stable field path.
        field: &'static str,
        /// Maximum permitted units.
        limit: usize,
    },
    /// Two policy rules covered the same cue kind.
    #[error("normalization policy contains duplicate rules")]
    DuplicateRule,
    /// The supplied profile does not equal the policy-bound profile.
    #[error("normalization profile does not match the policy binding")]
    ProfileMismatch,
    /// The policy digest does not match its canonical parameter preimage.
    #[error("normalization policy digest does not match its parameters")]
    PolicyDigestMismatch,
    /// A requested transformation cannot prove equivalence for this spelling.
    #[error("requested normalization is unsupported for this cue")]
    Unsupported,
    /// An owner-qualified signature does not satisfy its declared shape.
    #[error("owner-qualified signature shape is invalid")]
    InvalidSignature,
    /// Canonical bytes could not be produced for a bounded record.
    #[error("cannot canonicalize {field}")]
    Canonicalization {
        /// Stable record name.
        field: &'static str,
    },
    /// The produced A-10 record failed intrinsic validation.
    #[error("normalized cue result is invalid")]
    ResultInvalid,
}
