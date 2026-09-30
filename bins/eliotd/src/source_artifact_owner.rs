//! Same-stack D1 source artifact owner for the production daemon.
//!
//! I5.2 allows the internal Blob backend to be co-located in `eliotd`; I5.12
//! keeps payload admissibility with the daemon/source owner. This module owns
//! one original S-04 root claim and the real Windows/Zstandard/DPAPI provider
//! stack. It accepts only the live Governor source-effect admission for
//! request bindings. Durable Blob availability alone is never projected as
//! source admissibility.

use std::future::Future;
use std::path::Path;

use eliot_artifact::{
    ArtifactBlobReadRequest, ArtifactBlobReader, ArtifactError, ArtifactIdentity, ArtifactOwner,
    ArtifactReadReceipt, ArtifactReference, VerifiedArtifact,
};
use eliot_blob::{
    BlobRootOwner, BlobServicePorts, BlobStoreService, DpapiUserAeadPort,
    DpapiUserKeyPort, WindowsBlobPlatform, ZstdBlobCompression,
};
use eliot_blob_api::{BlobError, BlobId, BlobReadRequest, BlobReceiptContext};
use eliot_governor::SourceArtifactAdmission;
use eliot_platform_windows::WindowsPlatform;
use eliot_receipts::EffectClass;
use thiserror::Error;

/// Bounded maximum accepted by the canonical Blob plaintext path.
const MAX_SOURCE_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024;
const SOURCE_BLOB_DIRECTORY: &str = "source-artifacts";
const SOURCE_BLOB_OWNER_ID: &str = "eliotd-source-artifact-owner-v1";
const SOURCE_BLOB_KEY_LINEAGE: &str = "eliotd-source-artifact-key-v1";

type SourceBlobService =
    BlobStoreService<WindowsBlobPlatform, ZstdBlobCompression, DpapiUserKeyPort, DpapiUserAeadPort, ()>;

/// The sole same-stack daemon owner for source-artifact Blob publication and
/// readback. The source backend is D1 per I5.2; this composition does not
/// extract or launch a separate D2 process.
pub struct SourceArtifactOwner {
    root_owner: BlobRootOwner,
    artifact: ArtifactOwner,
    key_generation: u64,
}

impl std::fmt::Debug for SourceArtifactOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceArtifactOwner")
            .field("root_id", &self.root_owner.root_id())
            .field("owner_id", &self.root_owner.owner_id())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum SourceArtifactOwnerError {
    #[error("source Blob owner refused composition: {0}")]
    Blob(#[from] BlobError),
    #[error("artifact owner refused source binding: {0}")]
    Artifact(#[from] ArtifactError),
    #[error("source artifact stage requires original owner-issued Blob policy and six-domain residency evidence")]
    MissingAdmissibilityEvidence,
    #[error("source artifact effect is not admitted for this operation")]
    WrongEffect,
}

impl SourceArtifactOwner {
    /// Claims the daemon's protected-state child root under the exact Kernel
    /// lifecycle fence already admitted by the live Governor composition.
    /// The daemon is the only Blob root owner; the canonical Store process
    /// retains only its configured credential-access platform handle.
    pub fn new(
        state_root: &Path,
        lifecycle_fence: eliot_contracts::StateFence,
    ) -> Result<Self, SourceArtifactOwnerError> {
        lifecycle_fence
            .validate()
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        let key_generation = lifecycle_fence.resource_generation.value();
        if key_generation == 0 {
            return Err(BlobError::StaleFence.into());
        }
        let root = state_root.join(SOURCE_BLOB_DIRECTORY);
        let root_owner = BlobRootOwner::claim_with_lifecycle_fence(
            root.to_string_lossy().into_owned(),
            SOURCE_BLOB_OWNER_ID,
            std::process::id(),
            lifecycle_fence,
        )?;
        let artifact = ArtifactOwner::new(MAX_SOURCE_ARTIFACT_BYTES)?;
        Ok(Self {
            root_owner,
            artifact,
            key_generation,
        })
    }

    /// Stages exact archive bytes only after an original source-policy owner
    /// provides the Blob policy and six-domain residency evidence. The
    /// current Governor admission proves only effect authorization; it does
    /// not contain those data-governance facts, so this path refuses until
    /// that original-owner evidence is threaded into the same call stack.
    pub fn stage_source_snapshot(
        &self,
        admission: &SourceArtifactAdmission,
        identity: ArtifactIdentity,
        bytes: &[u8],
    ) -> Result<ArtifactReference, SourceArtifactOwnerError> {
        if admission.operation().effect != EffectClass::ReversibleMutation {
            return Err(SourceArtifactOwnerError::WrongEffect);
        }
        identity.verify_content(bytes)?;
        Err(SourceArtifactOwnerError::MissingAdmissibilityEvidence)
    }

    /// Reopens one exact persisted Artifact reference through the original
    /// Blob owner. The returned proof preserves the S-04 read receipt lineage
    /// and verifies the artifact identity against the bytes a second time.
    pub fn read_source_reference<'a>(
        &'a self,
        admission: &'a SourceArtifactAdmission,
        reference: ArtifactReference,
    ) -> impl Future<Output = Result<(VerifiedArtifact, ArtifactReadReceipt), SourceArtifactOwnerError>> + 'a
    {
        async move {
            if admission.operation().effect != EffectClass::Read {
                return Err(SourceArtifactOwnerError::WrongEffect);
            }
            let context = receipt_context(admission);
            let blob = self.blob_for_context(&context)?;
            let reader = AdmissionBlobReader {
                blob: &blob,
                root_owner: &self.root_owner,
                context,
            };
            self.artifact
                .read(reference, &reader)
                .await
                .map_err(SourceArtifactOwnerError::Artifact)
        }
    }

    fn blob_for_context(
        &self,
        context: &BlobReceiptContext,
    ) -> Result<SourceBlobService, SourceArtifactOwnerError> {
        let root_lease = self.root_owner.lease_for_request(&context.request)?;
        let platform = WindowsBlobPlatform::new(self.root_owner.clone())?;
        let issuer_anchor = platform.receipt_issuer_anchor()?;
        let credential_platform = WindowsPlatform::new(self.root_owner.root_id().to_owned())
            .map_err(|error| BlobError::Provider(format!("construct DPAPI platform: {error}")))?;
        let keys = DpapiUserKeyPort::new(BlobId::new(SOURCE_BLOB_KEY_LINEAGE)?, self.key_generation)?;
        Ok(SourceBlobService::new_with_owner(
            &self.root_owner,
            root_lease,
            BlobServicePorts {
                platform,
                compression: ZstdBlobCompression::default(),
                keys,
                aead: DpapiUserAeadPort::new(credential_platform),
                live_sets: (),
                issuer_anchor,
            },
        )?)
    }
}

struct AdmissionBlobReader<'a> {
    blob: &'a SourceBlobService,
    root_owner: &'a BlobRootOwner,
    context: BlobReceiptContext,
}

impl ArtifactBlobReader for AdmissionBlobReader<'_> {
    fn read(&self, request: ArtifactBlobReadRequest) -> eliot_artifact::BlobReadFuture<'_> {
        Box::pin(async move {
            request.validate().map_err(|error| {
                BlobError::InvalidContract(format!("artifact read request refused: {error}"))
            })?;
            let root_lease = self.root_owner.lease_for_request(&self.context.request)?;
            self.blob.read_source(BlobReadRequest {
                context: self.context.clone(),
                root_lease,
                locator: request.locator,
                expected_metadata_sha256: request.expected_metadata_sha256,
                expected_ready_receipt_id: request.expected_ready_receipt_id,
                max_bytes: request.max_bytes,
            })
        })
    }
}

fn receipt_context(admission: &SourceArtifactAdmission) -> BlobReceiptContext {
    BlobReceiptContext {
        work_scope: admission.work_scope().clone(),
        task: Some(admission.task().clone()),
        session: Some(admission.session().clone()),
        causal: admission.causal().clone(),
        request: admission.request().clone(),
        operation: admission.operation().clone(),
        authority: admission.authority().clone(),
    }
}
