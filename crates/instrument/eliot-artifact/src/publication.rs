//! Staged-to-published atomic publication of immutable artifacts.

use crate::{
    ArtifactError, ArtifactIdentity, ArtifactManifest, ArtifactResolution, ContentAddress,
};
use eliot_contracts::{ClockReading, OperationId, ReceiptId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Lifecycle phase of an immutable artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum PublicationPhase {
    /// Content is being written to a temporary, non-visible identity.
    Staging,
    /// Content is staged and validated but not yet visible.
    Staged,
    /// Content is atomically published and immutable.
    Published,
    /// Content has been superseded by a newer immutable identity.
    Superseded,
    /// Content failed structural integrity.
    Corrupted,
}

/// A staged, not-yet-visible immutable artifact.
///
/// Staging validates the manifest but makes nothing visible; only
/// [`StagedArtifact::publish`] atomically promotes it to a published identity.
/// There is no partial-publication state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedArtifact {
    manifest: ArtifactManifest,
}

impl StagedArtifact {
    /// Stages an already-validated manifest.
    pub fn stage(manifest: ArtifactManifest) -> Result<Self, ArtifactError> {
        manifest.validate()?;
        Ok(Self { manifest })
    }

    /// Returns the staged manifest without making it visible.
    pub fn manifest(&self) -> &ArtifactManifest {
        &self.manifest
    }

    /// The current publication phase.
    pub const fn phase(&self) -> PublicationPhase {
        PublicationPhase::Staged
    }

    /// Atomically promotes the staged artifact to a published identity.
    pub(crate) fn publish(
        self,
        operation: Option<OperationId>,
        published_at: ClockReading,
    ) -> Result<PublishedArtifact, ArtifactError> {
        published_at
            .validate()
            .map_err(|_| ArtifactError::InvalidInterval {
                field: "published_at",
            })?;
        let receipt_id =
            ReceiptId::new(format!("pub:{}", self.manifest.identity.content.digest_hex))?;
        let receipt = PublicationReceipt {
            receipt_id,
            manifest_identity: self.manifest.identity.clone(),
            content: self.manifest.identity.content.clone(),
            operation,
            state_fence: self.manifest.state_fence.clone(),
            published_at,
        };
        Ok(PublishedArtifact {
            manifest: self.manifest,
            receipt,
        })
    }
}

/// A durable receipt proving that an artifact reached a published identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicationReceipt {
    /// Receipt identity, derived from the manifest content digest.
    receipt_id: ReceiptId,
    /// The published manifest identity.
    manifest_identity: ArtifactIdentity,
    /// Content address of the published manifest.
    content: ContentAddress,
    /// Effect-capable operation, when one published the artifact.
    operation: Option<OperationId>,
    /// State fence under which the publication was admitted.
    state_fence: StateFence,
    /// Publication clock.
    published_at: ClockReading,
}

impl PublicationReceipt {
    /// Returns the owner-issued receipt identity.
    #[must_use]
    pub fn receipt_id(&self) -> &ReceiptId {
        &self.receipt_id
    }

    /// Returns the immutable manifest identity bound by the receipt.
    #[must_use]
    pub fn manifest_identity(&self) -> &ArtifactIdentity {
        &self.manifest_identity
    }

    /// Returns the content address bound by the receipt.
    #[must_use]
    pub const fn content(&self) -> &ContentAddress {
        &self.content
    }

    /// Returns the optional effect operation.
    #[must_use]
    pub const fn operation(&self) -> Option<&OperationId> {
        self.operation.as_ref()
    }

    /// Returns the publication fence.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the owner-observed publication clock.
    #[must_use]
    pub const fn published_at(&self) -> &ClockReading {
        &self.published_at
    }

    /// Validates receipt identity, manifest identity and fence invariants.
    pub fn validate(&self) -> Result<(), ArtifactError> {
        self.manifest_identity.validate()?;
        if self.content != self.manifest_identity.content {
            return Err(ArtifactError::Corrupted {
                reason: "receipt content does not match manifest identity".to_owned(),
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| ArtifactError::InvalidInterval {
                field: "state_fence",
            })?;
        self.published_at
            .validate()
            .map_err(|_| ArtifactError::InvalidInterval {
                field: "published_at",
            })
    }
}

/// An atomically published, immutable artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedArtifact {
    manifest: ArtifactManifest,
    receipt: PublicationReceipt,
}

impl PublishedArtifact {
    /// Returns the published manifest.
    pub fn manifest(&self) -> &ArtifactManifest {
        &self.manifest
    }

    /// Returns the publication receipt.
    pub fn receipt(&self) -> &PublicationReceipt {
        &self.receipt
    }

    /// The publication phase of a published artifact.
    pub const fn phase(&self) -> PublicationPhase {
        PublicationPhase::Published
    }

    /// Resolves the published identity to an available outcome.
    pub fn resolve(&self) -> ArtifactResolution {
        ArtifactResolution::Available {
            identity: self.manifest.artifact.clone(),
        }
    }
}
