//! Opaque identities and digests.
//!
//! Each newtype is validated on construction and is not interchangeable with
//! any other, so a snapshot id cannot be passed where a cue id is expected.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::CueContractError;

const MAX_ID_BYTES: usize = 512;

fn validate(value: &str, field: &'static str) -> Result<(), CueContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CueContractError::InvalidText { field });
    }
    if value.len() > MAX_ID_BYTES {
        return Err(CueContractError::BoundExceeded {
            field,
            limit: MAX_ID_BYTES,
        });
    }
    Ok(())
}

macro_rules! cue_id {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, schemars::JsonSchema)]
        #[serde(transparent)]
        #[schemars(transparent)]
        pub struct $name(String);

        impl $name {
            /// Constructs a validated identity.
            ///
            /// # Errors
            /// Rejects blank text, control characters and text over the bound.
            pub fn new(value: impl Into<String>) -> Result<Self, CueContractError> {
                let value = value.into();
                validate(&value, $field)?;
                Ok(Self(value))
            }

            /// Returns the identity text without assigning semantics to it.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

cue_id!(
    /// Identity of one observation of source material, before normalization.
    ObservedCueId,
    "observed_cue_id"
);
cue_id!(
    /// Identity of one canonical cue, preserving meaningful spelling.
    CanonicalCueId,
    "canonical_cue_id"
);
cue_id!(
    /// Identity of one comparison key derived under a normalization profile.
    ComparisonKeyId,
    "comparison_key_id"
);
cue_id!(
    /// Identity of one admitted binding candidate.
    BindingCandidateId,
    "binding_candidate_id"
);
cue_id!(
    /// Identity of one immutable snapshot.
    SnapshotId,
    "snapshot_id"
);
cue_id!(
    /// Identity of one activation request.
    ActivationRequestId,
    "activation_request_id"
);
cue_id!(
    /// Identity of one typed relation edge in the registry.
    RelationEdgeId,
    "relation_edge_id"
);
cue_id!(
    /// Immutable handle to the thing a cue points at.
    ///
    /// A target is always a handle. This vocabulary never carries target bytes.
    TargetHandle,
    "target_handle"
);

/// A lowercase hexadecimal content digest.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct Digest(String);

impl Digest {
    /// Constructs a validated digest.
    ///
    /// # Errors
    /// Rejects anything that is not 64 lowercase hexadecimal characters.
    pub fn new(value: impl Into<String>) -> Result<Self, CueContractError> {
        let value = value.into();
        let well_formed = value.len() == 64
            && value
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character));
        if !well_formed {
            return Err(CueContractError::InvalidText { field: "digest" });
        }
        Ok(Self(value))
    }

    /// Returns the digest text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
