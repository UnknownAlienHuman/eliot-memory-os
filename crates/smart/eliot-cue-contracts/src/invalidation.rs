//! Snapshot invalidation: why a snapshot stopped being usable, on whose evidence,
//! and what came before.
//!
//! An invalidation never rewrites history: the invalidated snapshot keeps its
//! digest, the predecessor and the bounded prior history stay addressable, and
//! the cause carries the exact owner evidence that forced the decision. There
//! is no "refresh in place" on this shape.

use eliot_contracts::StateFence;
use eliot_evidence::EvidenceEnvelope;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{CueContractError, Digest, SnapshotId, bounds};

/// Why a snapshot stopped being usable.
///
/// Every variant carries the exact prior and current owner values whose
/// difference forced the invalidation. Equal prior and current values are not
/// a change and are rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "cause", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum InvalidationCause {
    /// The normalization profile digest changed under the snapshot.
    ProfileChanged {
        /// Digest of the profile the snapshot was built under.
        prior_profile_digest: Digest,
        /// Digest of the profile that replaced it.
        current_profile_digest: Digest,
    },
    /// A source revision changed under the snapshot.
    SourceChanged {
        /// Digest of the source revision the snapshot was built from.
        prior_source_digest: Digest,
        /// Digest of the source revision that replaced it.
        current_source_digest: Digest,
    },
    /// The causal fence moved past the snapshot.
    FenceChanged {
        /// Fence the snapshot was built against.
        prior_fence: StateFence,
        /// Fence that replaced it.
        current_fence: StateFence,
    },
    /// The relation registry revision changed under the snapshot.
    RegistryChanged {
        /// Revision the snapshot was built against.
        prior_registry_revision: String,
        /// Revision that replaced it.
        current_registry_revision: String,
    },
    /// A newer snapshot superseded this one.
    SnapshotSuperseded {
        /// The snapshot that replaced this one.
        successor: SnapshotId,
    },
}

impl InvalidationCause {
    /// Checks that the cause names a real change with bounded values.
    ///
    /// # Errors
    /// Rejects equal prior and current values, unbounded revision text, and
    /// any fence its own owner rejects.
    pub fn validate(&self) -> Result<(), CueContractError> {
        match self {
            Self::ProfileChanged {
                prior_profile_digest,
                current_profile_digest,
            } => {
                if prior_profile_digest == current_profile_digest {
                    return Err(CueContractError::InvalidText {
                        field: "invalidation.cause",
                    });
                }
            }
            Self::SourceChanged {
                prior_source_digest,
                current_source_digest,
            } => {
                if prior_source_digest == current_source_digest {
                    return Err(CueContractError::InvalidText {
                        field: "invalidation.cause",
                    });
                }
            }
            Self::FenceChanged {
                prior_fence,
                current_fence,
            } => {
                prior_fence
                    .validate()
                    .map_err(|_| CueContractError::Foundation {
                        field: "invalidation.prior_fence",
                    })?;
                current_fence
                    .validate()
                    .map_err(|_| CueContractError::Foundation {
                        field: "invalidation.current_fence",
                    })?;
                if prior_fence == current_fence {
                    return Err(CueContractError::InvalidText {
                        field: "invalidation.cause",
                    });
                }
            }
            Self::RegistryChanged {
                prior_registry_revision,
                current_registry_revision,
            } => {
                bounds::text(
                    prior_registry_revision,
                    "invalidation.prior_registry_revision",
                )?;
                bounds::text(
                    current_registry_revision,
                    "invalidation.current_registry_revision",
                )?;
                if prior_registry_revision == current_registry_revision {
                    return Err(CueContractError::InvalidText {
                        field: "invalidation.cause",
                    });
                }
            }
            Self::SnapshotSuperseded { successor } => {
                bounds::text(successor.as_str(), "invalidation.successor")?;
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct InvalidationPreimage<'a> {
    schema_revision: &'a str,
    snapshot_id: &'a SnapshotId,
    cause: &'a InvalidationCause,
    evidence: &'a EvidenceEnvelope,
    predecessor: &'a SnapshotId,
    history: &'a [SnapshotId],
}

/// One recorded invalidation of an immutable snapshot.
///
/// The invalidated snapshot is not modified: this record names it, names the
/// cause with exact owner evidence, and preserves the predecessor and the
/// bounded prior history so the chain stays addressable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SnapshotInvalidation {
    /// Schema revision this record was written against.
    pub schema_revision: String,
    /// The snapshot this invalidation retires. That snapshot is unchanged.
    pub snapshot_id: SnapshotId,
    /// Why it was retired, with the exact prior and current owner values.
    pub cause: InvalidationCause,
    /// Owner evidence behind the decision, validated by its own owner.
    pub evidence: EvidenceEnvelope,
    /// The snapshot that came immediately before `snapshot_id`.
    pub predecessor: SnapshotId,
    /// Older snapshots, oldest first. The predecessor is not repeated here.
    pub history: Vec<SnapshotId>,
    /// Digest over every identity-bearing field above.
    pub digest: Digest,
}

impl SnapshotInvalidation {
    /// Seals an invalidation: validates cause, evidence and lineage, then binds
    /// the digest.
    ///
    /// # Errors
    /// Rejects a predecessor that is the snapshot itself, any overlap between
    /// snapshot, predecessor and history, history past its bound, a cause that
    /// names no change, evidence its own owner rejects, and a digest that does
    /// not match the recorded inputs.
    pub fn seal(
        snapshot_id: SnapshotId,
        cause: InvalidationCause,
        evidence: EvidenceEnvelope,
        predecessor: SnapshotId,
        history: Vec<SnapshotId>,
    ) -> Result<Self, CueContractError> {
        let mut value = Self {
            schema_revision: crate::CONTRACT_REVISION.to_owned(),
            snapshot_id,
            cause,
            evidence,
            predecessor,
            history,
            digest: Digest::new("0".repeat(64))?,
        };
        value.validate_shape()?;
        value.digest = value.canonical_digest()?;
        Ok(value)
    }

    /// Returns the versioned canonical JSON preimage, excluding `digest`.
    ///
    /// History order is significant — oldest first — and is preserved, not
    /// sorted: reordering history changes the digest.
    pub fn canonical_payload_bytes(&self) -> Result<Vec<u8>, CueContractError> {
        self.validate_shape()?;
        let preimage = InvalidationPreimage {
            schema_revision: &self.schema_revision,
            snapshot_id: &self.snapshot_id,
            cause: &self.cause,
            evidence: &self.evidence,
            predecessor: &self.predecessor,
            history: &self.history,
        };
        let bytes = eliot_contracts::canonical_json_bytes(&preimage).map_err(|_| {
            CueContractError::Foundation {
                field: "invalidation.canonical_payload",
            }
        })?;
        let mut total = 0;
        bounds::bytes(&mut total, bytes.len(), "invalidation.canonical_payload")?;
        Ok(bytes)
    }

    /// Computes this invalidation's canonical digest.
    pub fn canonical_digest(&self) -> Result<Digest, CueContractError> {
        let bytes = self.canonical_payload_bytes()?;
        Digest::new(eliot_contracts::sha256_hex(&bytes))
    }

    /// Checks the intrinsic rules this record owns.
    ///
    /// # Errors
    /// Rejects history past its bound, any identity overlap between the
    /// snapshot, its predecessor and its history, a changeless cause, evidence
    /// its own owner rejects, and a digest that does not match.
    pub fn validate(&self) -> Result<(), CueContractError> {
        self.validate_shape()?;
        if self.digest != self.canonical_digest()? {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), CueContractError> {
        if !crate::is_supported_schema_revision(&self.schema_revision) {
            return Err(CueContractError::InvalidText {
                field: "schema_revision",
            });
        }
        bounds::collection(
            &self.history,
            crate::MAX_INVALIDATION_HISTORY,
            "invalidation.history",
        )?;
        bounds::text(self.snapshot_id.as_str(), "invalidation.snapshot_id")?;
        bounds::text(self.predecessor.as_str(), "invalidation.predecessor")?;
        if self.predecessor == self.snapshot_id {
            return Err(CueContractError::InvalidText {
                field: "invalidation.predecessor",
            });
        }
        let mut seen = BTreeSet::new();
        seen.insert(self.snapshot_id.clone());
        if !seen.insert(self.predecessor.clone()) {
            return Err(CueContractError::DuplicateIdentity {
                field: "invalidation.predecessor",
            });
        }
        for prior in &self.history {
            bounds::text(prior.as_str(), "invalidation.history")?;
            if !seen.insert(prior.clone()) {
                return Err(CueContractError::DuplicateIdentity {
                    field: "invalidation.history",
                });
            }
        }
        self.cause.validate()?;
        self.evidence
            .validate()
            .map_err(|_| CueContractError::Foundation {
                field: "invalidation.evidence",
            })?;
        crate::bounds::provenance(
            &self.evidence.provenance,
            "invalidation.evidence.provenance",
        )?;
        Ok(())
    }
}
