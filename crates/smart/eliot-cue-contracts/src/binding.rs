//! Candidate bindings between a normalized cue and a target.
//!
//! A binding is a proposal. It is not membership in a snapshot, and it is not
//! an activation. Admission is A-12's decision; this module carries its shape.

use eliot_evidence::EvidenceFreshness;
use serde::{Deserialize, Serialize};

use crate::{BindingCandidateId, CanonicalCueIdentity, CueContractError, Digest, TargetHandle};

/// Why a target is bound to a cue.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum BindingRole {
    /// The cue names the target directly.
    Names,
    /// The target was touched while the cue was observed.
    Touched,
    /// The caller expects this target to be reused with this cue.
    ExpectedReuse,
}

/// What was decided about a candidate.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum BindingDisposition {
    /// Admitted into the snapshot under construction.
    Admitted,
    /// Held back, with the reason recorded by the deciding cell.
    Withheld,
    /// Rejected outright.
    Rejected,
}

/// One proposed binding from a canonical cue to a target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CueBindingCandidate {
    /// Identity of this candidate.
    pub binding_candidate_id: BindingCandidateId,
    /// The canonical cue side of the binding.
    pub canonical: CanonicalCueIdentity,
    /// The target side. Always a handle.
    pub target: TargetHandle,
    /// Why the two are bound.
    pub role: BindingRole,
    /// How fresh the evidence behind the binding is.
    pub freshness: EvidenceFreshness,
    /// What was decided.
    pub disposition: BindingDisposition,
    /// Digest over the candidate's identity-bearing fields.
    pub digest: Digest,
}

impl CueBindingCandidate {
    /// Constructs a binding candidate. Call [`Self::validate`] before use.
    #[must_use]
    pub const fn new(
        binding_candidate_id: BindingCandidateId,
        canonical: CanonicalCueIdentity,
        target: TargetHandle,
        role: BindingRole,
        freshness: EvidenceFreshness,
        disposition: BindingDisposition,
        digest: Digest,
    ) -> Self {
        Self {
            binding_candidate_id,
            canonical,
            target,
            role,
            freshness,
            disposition,
            digest,
        }
    }

    /// Checks the intrinsic rules this record owns.
    ///
    /// # Errors
    /// Rejects a candidate whose canonical side is not itself well formed.
    pub fn validate(&self) -> Result<(), CueContractError> {
        if self.canonical.canonical_value.trim().is_empty() {
            return Err(CueContractError::InvalidText {
                field: "canonical.canonical_value",
            });
        }
        Ok(())
    }
}
