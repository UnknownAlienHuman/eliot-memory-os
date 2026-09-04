//! One closed typed error family for the cue vocabulary.
//!
//! Per `I7.20` a failure is classifiable, not a formatted string. Every variant
//! names the field it is about, so a caller can act without parsing prose.

use serde::{Deserialize, Serialize};

/// Every way a cue contract can be rejected.
#[derive(
    Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(tag = "code", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum CueContractError {
    /// A required text field was empty or carried a control character.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText {
        /// Stable field path.
        field: &'static str,
    },

    /// A bounded collection, string or path exceeded its declared limit.
    #[error("{field} exceeds its declared bound of {limit}")]
    BoundExceeded {
        /// Stable field path.
        field: &'static str,
        /// The declared limit that was crossed.
        limit: usize,
    },

    /// A canonical identity was reused as a comparison key, or the reverse.
    ///
    /// Canonical identity preserves meaningful spelling; a comparison key is a
    /// policy-folded form. One value cannot serve both roles.
    #[error("canonical identity and comparison key must remain distinct")]
    IdentityCollapsedIntoKey,

    /// A derived activation carried an empty, non-contiguous path, or a path
    /// that does not begin at one of the result's direct activations.
    #[error("derived activation path is empty, broken, or does not start at a direct seed")]
    BrokenActivationPath,

    /// A result declared itself complete while still naming a frontier.
    #[error("a complete result cannot carry an unresolved frontier")]
    CompleteWithFrontier,

    /// A truncated result did not name the bound that stopped the search.
    #[error("a truncated result must name the bound it hit")]
    TruncationWithoutBound,

    /// A snapshot digest disagreed with the inputs recorded for its rebuild.
    #[error("snapshot digest does not match its recorded rebuild inputs")]
    SnapshotNotRebuildable,

    /// A duplicate semantic identity appeared where each must be unique.
    #[error("duplicate identity in {field}")]
    DuplicateIdentity {
        /// Stable field path.
        field: &'static str,
    },

    /// A foundation identity or fence was rejected by its own owner.
    #[error("foundation contract rejected {field}")]
    Foundation {
        /// Stable field path.
        field: &'static str,
    },
}
