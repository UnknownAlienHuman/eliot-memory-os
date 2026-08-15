//! S-04-backed artifact reads and immutable reference binding.
//!
//! This module owns no blob root, filesystem path, key, receipt issuer, or
//! garbage collector.  It only adapts the provider-neutral S-04 read result
//! into an artifact identity after S-04 has authenticated and integrity-checked
//! the bytes.  The composition layer supplies the [`ArtifactBlobReader`]
//! adapter around the one `eliot_blob_api::BlobStoreClient` owner.

use crate::{
    ArtifactError, ArtifactExport, ArtifactIdentity, ArtifactManifest, ImportedArtifact,
    PublishedArtifact, StagedArtifact,
};
use eliot_blob_api::{BlobError, BlobLocator, BlobReadChunk};
use eliot_contracts::{ArtifactId, ClockReading, OperationId};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;

/// A bounded request passed from I-01 to the S-04 composition adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBlobReadRequest {
    /// Exact S-04 content locator.
    pub locator: BlobLocator,
    /// Expected authenticated S-04 metadata digest.
    pub expected_metadata_sha256: String,
    /// Expected ready-receipt identity selected by the owning caller.
    pub expected_ready_receipt_id: String,
    /// Maximum bytes that may cross this boundary.
    pub max_bytes: u64,
}

impl ArtifactBlobReadRequest {
    /// Validates bounded request shape without granting a read capability.
    pub fn validate(&self) -> Result<(), ArtifactError> {
        self.locator
            .validate()
            .map_err(|error| ArtifactError::Unavailable {
                reason: format!("S-04 locator rejected: {error}"),
            })?;
        crate::validate_digest(&self.expected_metadata_sha256, "expected_metadata_sha256")?;
        if self.expected_ready_receipt_id.trim().is_empty()
            || self.expected_ready_receipt_id.chars().any(char::is_control)
        {
            return Err(ArtifactError::InvalidText {
                field: "expected_ready_receipt_id",
            });
        }
        if self.max_bytes == 0 {
            return Err(ArtifactError::Unsupported {
                field: "max_bytes",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

/// Boxed future returned by the S-04 adapter.
pub type BlobReadFuture<'a> =
    Pin<Box<dyn Future<Output = Result<BlobReadChunk, BlobError>> + Send + 'a>>;

/// Boxed future returned by I-01 artifact operations.
pub type ArtifactFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ArtifactError>> + Send + 'a>>;

/// Narrow I-01/S-04 composition port.
///
/// The implementation must delegate to the one S-04 `BlobStoreClient` and
/// preserve its exact context, root lease, metadata binding and receipt
/// verification.  I-01 never implements storage or accepts a raw path.
pub trait ArtifactBlobReader: Send + Sync {
    /// Reads one authenticated, complete S-04 payload under the supplied
    /// bounded request.
    fn read<'a>(&'a self, request: ArtifactBlobReadRequest) -> BlobReadFuture<'a>;
}

/// Immutable reference to an artifact's bytes and its S-04 backing identity.
///
/// This is an untrusted, deserializable reference.  It is not a receipt and
/// cannot authorize a read until the S-04 adapter returns a verified chunk.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReference {
    /// Content/schema/source/provenance-bound artifact identity.
    pub identity: ArtifactIdentity,
    /// S-04 content locator selected by the composition owner.
    pub locator: BlobLocator,
    /// Authenticated S-04 metadata digest expected for this identity.
    pub expected_metadata_sha256: String,
    /// Exact ready-receipt identity bound by the S-04 request adapter.
    pub expected_ready_receipt_id: String,
}

impl ArtifactReference {
    /// Creates an untrusted reference after validating its structural shape.
    pub fn new(
        identity: ArtifactIdentity,
        locator: BlobLocator,
        expected_metadata_sha256: impl Into<String>,
        expected_ready_receipt_id: impl Into<String>,
    ) -> Result<Self, ArtifactError> {
        let value = Self {
            identity,
            locator,
            expected_metadata_sha256: expected_metadata_sha256.into(),
            expected_ready_receipt_id: expected_ready_receipt_id.into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates identity and exact S-04 request binding.
    pub fn validate(&self) -> Result<(), ArtifactError> {
        self.identity.validate()?;
        ArtifactBlobReadRequest {
            locator: self.locator.clone(),
            expected_metadata_sha256: self.expected_metadata_sha256.clone(),
            expected_ready_receipt_id: self.expected_ready_receipt_id.clone(),
            max_bytes: 1,
        }
        .validate()
    }
}

/// Non-deserializable artifact bytes accepted only after S-04 verification and
/// a second I-01 content-address check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedArtifact {
    identity: ArtifactIdentity,
    bytes: Vec<u8>,
    locator: BlobLocator,
    metadata_sha256: String,
    ready_receipt_id: String,
    anchor_fingerprint: String,
}

impl VerifiedArtifact {
    /// Returns the accepted immutable artifact identity.
    #[must_use]
    pub fn identity(&self) -> &ArtifactIdentity {
        &self.identity
    }

    /// Returns the exact bytes that passed both S-04 and I-01 checks.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the S-04 locator that was read.
    #[must_use]
    pub const fn locator(&self) -> &BlobLocator {
        &self.locator
    }

    /// Returns the authenticated S-04 metadata digest.
    #[must_use]
    pub fn metadata_sha256(&self) -> &str {
        &self.metadata_sha256
    }

    /// Returns the S-04 ready receipt identity that matched the reference.
    #[must_use]
    pub fn ready_receipt_id(&self) -> &str {
        &self.ready_receipt_id
    }

    /// Returns the S-04 trust-anchor fingerprint carried by the verified chunk.
    #[must_use]
    pub fn anchor_fingerprint(&self) -> &str {
        &self.anchor_fingerprint
    }
}

/// Non-mintable read receipt issued by [`ArtifactOwner`] after exact checks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactReadReceipt {
    identity_digest: String,
    content_digest: String,
    locator: BlobLocator,
    metadata_sha256: String,
    ready_receipt_id: String,
    anchor_fingerprint: String,
    byte_count: u64,
}

impl ArtifactReadReceipt {
    /// Returns the accepted artifact identity digest.
    #[must_use]
    pub fn identity_digest(&self) -> &str {
        &self.identity_digest
    }

    /// Returns the accepted content digest.
    #[must_use]
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    /// Returns the authenticated S-04 metadata digest.
    #[must_use]
    pub fn metadata_sha256(&self) -> &str {
        &self.metadata_sha256
    }

    /// Returns the exact ready receipt identity bound by S-04.
    #[must_use]
    pub fn ready_receipt_id(&self) -> &str {
        &self.ready_receipt_id
    }

    /// Returns the S-04 trust-anchor fingerprint.
    #[must_use]
    pub fn anchor_fingerprint(&self) -> &str {
        &self.anchor_fingerprint
    }

    /// Returns the exact S-04 locator.
    #[must_use]
    pub const fn locator(&self) -> &BlobLocator {
        &self.locator
    }

    /// Returns the verified payload length.
    #[must_use]
    pub const fn byte_count(&self) -> u64 {
        self.byte_count
    }
}

/// The I-01 immutable artifact owner.  It owns identity and transfer policy,
/// while S-04 remains the sole physical BlobStore owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactOwner {
    max_read_bytes: u64,
}

impl ArtifactOwner {
    /// Creates an owner with a non-zero bounded read ceiling.
    pub fn new(max_read_bytes: u64) -> Result<Self, ArtifactError> {
        if max_read_bytes == 0 {
            return Err(ArtifactError::Unsupported {
                field: "max_read_bytes",
                reason: "must be greater than zero",
            });
        }
        Ok(Self { max_read_bytes })
    }

    /// Returns the configured maximum read size.
    #[must_use]
    pub const fn max_read_bytes(self) -> u64 {
        self.max_read_bytes
    }

    /// Reads and verifies one artifact through the injected S-04 adapter.
    pub fn read<'a>(
        &'a self,
        reference: ArtifactReference,
        reader: &'a dyn ArtifactBlobReader,
    ) -> crate::ArtifactFuture<'a, (VerifiedArtifact, ArtifactReadReceipt)> {
        Box::pin(async move {
            reference.validate()?;
            if reference.identity.content.size_bytes > self.max_read_bytes {
                return Err(ArtifactError::Unsupported {
                    field: "artifact.size_bytes",
                    reason: "artifact exceeds the configured read ceiling",
                });
            }
            let request = ArtifactBlobReadRequest {
                locator: reference.locator.clone(),
                expected_metadata_sha256: reference.expected_metadata_sha256.clone(),
                expected_ready_receipt_id: reference.expected_ready_receipt_id.clone(),
                max_bytes: self.max_read_bytes,
            };
            let chunk = reader
                .read(request)
                .await
                .map_err(|error| ArtifactError::Unavailable {
                    reason: format!("S-04 read unavailable: {error}"),
                })?;
            chunk.validate().map_err(|error| ArtifactError::Corrupted {
                reason: format!("S-04 chunk integrity rejected: {error}"),
            })?;
            if chunk.ready_receipt().locator() != &reference.locator
                || chunk.ready_receipt().receipt().receipt_id.as_str()
                    != reference.expected_ready_receipt_id
                || chunk.ready_receipt().metadata_sha256() != reference.expected_metadata_sha256
                || chunk.bytes().len() as u64 > self.max_read_bytes
            {
                return Err(ArtifactError::Corrupted {
                    reason: "S-04 chunk does not match the immutable artifact reference".to_owned(),
                });
            }
            reference.identity.verify_content(chunk.bytes())?;
            let identity_digest = reference.identity.identity_digest()?;
            let content_digest = reference.identity.content.digest_hex.clone();
            let receipt = ArtifactReadReceipt {
                identity_digest,
                content_digest,
                locator: reference.locator.clone(),
                metadata_sha256: reference.expected_metadata_sha256.clone(),
                ready_receipt_id: reference.expected_ready_receipt_id.clone(),
                anchor_fingerprint: chunk.anchor_fingerprint().to_owned(),
                byte_count: chunk.bytes().len() as u64,
            };
            let artifact = VerifiedArtifact {
                identity: reference.identity,
                bytes: chunk.bytes().to_vec(),
                locator: reference.locator,
                metadata_sha256: receipt.metadata_sha256.clone(),
                ready_receipt_id: receipt.ready_receipt_id.clone(),
                anchor_fingerprint: receipt.anchor_fingerprint.clone(),
            };
            Ok((artifact, receipt))
        })
    }

    /// Builds a transfer envelope only after the manifest has revalidated.
    pub fn export(
        &self,
        transfer_id: ArtifactId,
        manifest: ArtifactManifest,
        exported_at: ClockReading,
    ) -> Result<ArtifactExport, ArtifactError> {
        ArtifactExport::build(transfer_id, manifest, exported_at)
    }

    /// Verifies an imported transfer envelope and returns an untrusted manifest
    /// only after its complete canonical digest has been recomputed.
    pub fn import(
        &self,
        export: ArtifactExport,
        verified_at: ClockReading,
    ) -> Result<ImportedArtifact, ArtifactError> {
        crate::verify_import(export, verified_at)
    }

    /// Stages an immutable manifest under I-01 validation.
    pub fn stage(&self, manifest: ArtifactManifest) -> Result<StagedArtifact, ArtifactError> {
        StagedArtifact::stage(manifest)
    }

    /// Atomically publishes a staged manifest through the sole I-01 owner.
    pub fn publish(
        &self,
        staged: StagedArtifact,
        operation: Option<OperationId>,
        published_at: ClockReading,
    ) -> Result<PublishedArtifact, ArtifactError> {
        staged.publish(operation, published_at)
    }
}
