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
    BlobResidencyDomains, BlobRootOwner, BlobServicePorts, BlobStoreService,
    DpapiUserAeadPort, DpapiUserKeyPort, WindowsBlobPlatform, ZstdBlobCompression,
};
use eliot_blob_api::{
    BlobError, BlobId, BlobPolicyBinding, BlobReadRequest, BlobReceiptContext,
    ObjectResidencyKey, RetentionClass,
};
use eliot_governor::{
    SourceArtifactAdmission, SourceArtifactBlobProfile, SourceArtifactBlobProfileError,
    SourceArtifactRetentionClass,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::WindowsPlatform;
use eliot_receipts::EffectClass;
use thiserror::Error;

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
    #[error("source artifact policy profile refused this admission: {0}")]
    Profile(#[from] SourceArtifactBlobProfileError),
    #[error("source artifact policy reference is invalid: {0}")]
    PolicyReference(#[from] eliot_platform::PortError),
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
        Ok(Self {
            root_owner,
            key_generation,
        })
    }

    /// Stages exact archive bytes after the original PolicyOwner profile has
    /// been validated against this live source admission and the active Blob
    /// key lineage. Blob derives the versioned content digest from these exact
    /// bytes; neither Governor nor this composition invents residency facts.
    pub fn stage_source_snapshot(
        &self,
        admission: &SourceArtifactAdmission,
        profile: &SourceArtifactBlobProfile,
        identity: ArtifactIdentity,
        bytes: &[u8],
    ) -> Result<ArtifactReference, SourceArtifactOwnerError> {
        if admission.operation().effect != EffectClass::ReversibleMutation {
            return Err(SourceArtifactOwnerError::WrongEffect);
        }
        identity.verify_content(bytes)?;
        identity.validate()?;
        profile.validate_for(admission, SOURCE_BLOB_KEY_LINEAGE, self.key_generation)?;

        let policy = blob_policy_binding(profile)?;
        let residency = blob_residency_domains(profile)?;
        let context = receipt_context(admission);
        let blob = self.blob_for_context(&context)?;
        let root_lease = self.root_owner.lease_for_request(&context.request)?;
        let ready = blob.stage_source_with_domains(context, root_lease, bytes, policy, residency)?;
        ready.validate()?;
        ArtifactReference::new(
            identity,
            ready.locator().clone(),
            ready.metadata_sha256().to_owned(),
            ready.receipt().identity.receipt_id.to_string(),
        )
        .map_err(SourceArtifactOwnerError::Artifact)
    }

    /// Reopens one exact persisted Artifact reference through the original
    /// Blob owner. The current PolicyOwner profile must match the authenticated
    /// policy and six residency domains on that reference; the returned proof
    /// preserves the S-04 read receipt lineage and verifies the artifact
    /// identity against the bytes a second time.
    pub fn read_source_reference<'a>(
        &'a self,
        admission: &'a SourceArtifactAdmission,
        profile: &'a SourceArtifactBlobProfile,
        reference: ArtifactReference,
    ) -> impl Future<Output = Result<(VerifiedArtifact, ArtifactReadReceipt), SourceArtifactOwnerError>> + 'a
    {
        async move {
            if admission.operation().effect != EffectClass::Read {
                return Err(SourceArtifactOwnerError::WrongEffect);
            }
            reference.validate()?;
            profile.validate_for(admission, SOURCE_BLOB_KEY_LINEAGE, self.key_generation)?;
            let policy = blob_policy_binding(profile)?;
            let residency = blob_residency_domains(profile)?;
            if !matches_residency_domains(&reference.locator.residency, &residency) {
                return Err(BlobError::MetadataPayloadMismatch.into());
            }
            let context = receipt_context(admission);
            let blob = self.blob_for_context(&context)?;
            let reader = AdmissionBlobReader {
                blob: &blob,
                root_owner: &self.root_owner,
                context,
                policy,
                residency,
            };
            // The persisted identity supplies this read's exact byte ceiling;
            // BlobStoreCore enforces its own canonical plaintext ceiling.
            let artifact = ArtifactOwner::new(reference.identity.content.size_bytes.max(1))?;
            artifact
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
    policy: BlobPolicyBinding,
    residency: BlobResidencyDomains,
}

impl ArtifactBlobReader for AdmissionBlobReader<'_> {
    fn read(&self, request: ArtifactBlobReadRequest) -> eliot_artifact::BlobReadFuture<'_> {
        Box::pin(async move {
            request.validate().map_err(|error| {
                BlobError::InvalidContract(format!("artifact read request refused: {error}"))
            })?;
            let root_lease = self.root_owner.lease_for_request(&self.context.request)?;
            let chunk = self.blob.read_source(BlobReadRequest {
                context: self.context.clone(),
                root_lease,
                locator: request.locator,
                expected_metadata_sha256: request.expected_metadata_sha256,
                expected_ready_receipt_id: request.expected_ready_receipt_id,
                max_bytes: request.max_bytes,
            })?;
            chunk.validate()?;
            let ready = chunk.ready_receipt();
            if ready.policy() != &self.policy
                || !matches_residency_domains(&ready.locator().residency, &self.residency)
            {
                return Err(BlobError::MetadataPayloadMismatch);
            }
            Ok(chunk)
        })
    }
}

fn blob_policy_binding(
    profile: &SourceArtifactBlobProfile,
) -> Result<BlobPolicyBinding, SourceArtifactOwnerError> {
    Ok(BlobPolicyBinding {
        privacy_class: profile.policy().privacy_class(),
        retention_class: match profile.policy().retention_class() {
            SourceArtifactRetentionClass::Session => RetentionClass::Session,
            SourceArtifactRetentionClass::Task => RetentionClass::Task,
            SourceArtifactRetentionClass::Durable => RetentionClass::Durable,
            SourceArtifactRetentionClass::LegalHold => RetentionClass::LegalHold,
        },
        policy_ref: PlatformHandle::new(profile.policy().policy_ref().to_owned())?,
        instruction_taint: profile.policy().instruction_taint(),
        effect_ceiling: profile.policy().effect_ceiling(),
    })
}

fn blob_residency_domains(
    profile: &SourceArtifactBlobProfile,
) -> Result<BlobResidencyDomains, SourceArtifactOwnerError> {
    let domains = profile.residency_domains();
    Ok(BlobResidencyDomains::new(
        BlobId::new(domains.scope_domain_id().to_owned())?,
        BlobId::new(domains.access_domain_id().to_owned())?,
        BlobId::new(domains.confidentiality_domain_id().to_owned())?,
        BlobId::new(domains.encryption_key_domain_id().to_owned())?,
        BlobId::new(domains.retention_domain_id().to_owned())?,
        BlobId::new(domains.erasure_domain_id().to_owned())?,
    ))
}

fn matches_residency_domains(
    observed: &ObjectResidencyKey,
    expected: &BlobResidencyDomains,
) -> bool {
    observed.scope_domain_id == expected.scope_domain_id
        && observed.access_domain_id == expected.access_domain_id
        && observed.confidentiality_domain_id == expected.confidentiality_domain_id
        && observed.encryption_key_domain_id == expected.encryption_key_domain_id
        && observed.retention_domain_id == expected.retention_domain_id
        && observed.erasure_domain_id == expected.erasure_domain_id
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
