//! Source material exactly as observed, before any normalization.
//!
//! An observed cue is not an identity, not a key, not a match and not an
//! activation. It records what was seen and where it came from.

use eliot_evidence::Provenance;
use serde::{Deserialize, Serialize};

use crate::{
    CueContext, CueContractError, Digest, ObservedCueId, TargetHandle, bounds,
    normalization::CueKind,
};

/// Immutable reference to the material a cue was observed in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SourceHandle {
    /// Handle to the observed artifact. Never its bytes.
    pub target: TargetHandle,
    /// Content digest of the observed revision.
    pub digest: Digest,
    /// Where the observation came from and under what authority.
    pub provenance: Provenance,
}

impl SourceHandle {
    /// Constructs a source handle.
    #[must_use]
    pub const fn new(target: TargetHandle, digest: Digest, provenance: Provenance) -> Self {
        Self {
            target,
            digest,
            provenance,
        }
    }

    /// Validates the nested source lineage and immutable digest shape.
    pub fn validate(&self) -> Result<(), CueContractError> {
        bounds::text(self.target.as_str(), "source.target")?;
        if self.digest.as_str().len() != 64 {
            return Err(CueContractError::InvalidText {
                field: "source.digest",
            });
        }
        bounds::provenance(&self.provenance, "source.provenance")?;
        self.provenance
            .validate()
            .map_err(|_| CueContractError::Foundation {
                field: "source.provenance",
            })
    }
}

/// One cue as observed, before normalization has been applied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ObservedCue {
    /// Schema revision this record was written against.
    pub schema_revision: String,
    /// Identity of this observation.
    pub observed_cue_id: ObservedCueId,
    /// What kind of cue this is.
    pub kind: CueKind,
    /// The value exactly as observed, with original spelling and case.
    pub original_value: String,
    /// The material the cue was observed in.
    pub source: SourceHandle,
    /// Exact task/scope/fence/provenance/lifecycle/privacy/proof closure.
    pub context: CueContext,
}

impl ObservedCue {
    /// Constructs an observed cue.
    #[must_use]
    pub const fn new(
        schema_revision: String,
        observed_cue_id: ObservedCueId,
        kind: CueKind,
        original_value: String,
        source: SourceHandle,
        context: CueContext,
    ) -> Self {
        Self {
            schema_revision,
            observed_cue_id,
            kind,
            original_value,
            source,
            context,
        }
    }

    /// Checks the intrinsic rules this record owns.
    ///
    /// # Errors
    /// Rejects a blank observed value and an oversized one.
    pub fn validate(&self) -> Result<(), CueContractError> {
        const MAX_OBSERVED_BYTES: usize = 8192;
        if self.schema_revision != crate::CONTRACT_REVISION {
            return Err(CueContractError::InvalidText {
                field: "schema_revision",
            });
        }
        bounds::text(&self.original_value, "original_value")?;
        if self.original_value.trim().is_empty()
            || self.original_value.chars().any(char::is_control)
        {
            return Err(CueContractError::InvalidText {
                field: "original_value",
            });
        }
        if self.original_value.len() > MAX_OBSERVED_BYTES {
            return Err(CueContractError::BoundExceeded {
                field: "original_value",
                limit: MAX_OBSERVED_BYTES,
            });
        }
        self.source.validate()?;
        self.context.validate()?;
        if self.source.provenance != self.context.evidence.provenance {
            return Err(CueContractError::Foundation {
                field: "source.context_provenance",
            });
        }
        Ok(())
    }
}
