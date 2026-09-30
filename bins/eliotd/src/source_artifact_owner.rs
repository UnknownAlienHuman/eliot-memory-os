//! Same-stack D1 source artifact owner for the production daemon.
//!
//! I5.2 allows the internal Blob backend to be co-located in `eliotd`; I5.12
//! keeps payload admissibility with the daemon/source owner. This module owns
//! one original S-04 root claim and the real Windows/Zstandard/DPAPI provider
//! stack. It accepts only the live Governor source-effect admission for
//! request bindings. Durable Blob availability alone is never projected as
//! source admissibility.

use std::path::Path;

use eliot_artifact::{
    ArtifactBlobReadRequest, ArtifactBlobReader, ArtifactError, ArtifactIdentity, ArtifactOwner,
    ArtifactReadReceipt, ArtifactReference, VerifiedArtifact,
};
use eliot_blob::{
    BlobResidencyDomains, BlobRootOwner, BlobServicePorts, BlobStoreService, DpapiUserAeadPort,
    DpapiUserKeyPort, WindowsBlobPlatform, ZstdBlobCompression,
};
use eliot_blob_api::{
    BlobError, BlobId, BlobPolicyBinding, BlobReadChunk, BlobReadRequest, BlobReceiptContext,
    ObjectResidencyKey, RetentionClass,
};
use eliot_governor::{
    SourceArtifactAdmission, SourceArtifactBlobProfile, SourceArtifactBlobProfileError,
    SourceArtifactRetentionClass,
};
use eliot_lsp_bridge::{
    LSP_TOOL_OBSERVATION_RECEIPT_KIND, LspAdoptionProjection, RetainedLspObservationV1,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::WindowsPlatform;
use eliot_receipts::EffectClass;
use thiserror::Error;

const SOURCE_BLOB_DIRECTORY: &str = "source-artifacts";
const SOURCE_BLOB_OWNER_ID: &str = "eliotd-source-artifact-owner-v1";
const SOURCE_BLOB_KEY_LINEAGE: &str = "eliotd-source-artifact-key-v1";

type SourceBlobService = BlobStoreService<
    WindowsBlobPlatform,
    ZstdBlobCompression,
    DpapiUserKeyPort,
    DpapiUserAeadPort,
    (),
>;

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
    #[error("captured source payload pointer is invalid: {0}")]
    CapturedPayload(#[from] eliot_store_api::StoreError),
    #[error("captured payload does not identify an LSP observation envelope")]
    WrongCapturedPayloadKind,
    #[error("generic source staging cannot use the reserved LSP observation operation kind")]
    ReservedLspObservationOperationKind,
    #[error("LSP observation publication requires the exact admitted request and live bridge projection")]
    LspObservationBindingMismatch,
    #[error("LSP observation publication requires its reserved operation kind")]
    WrongLspObservationOperationKind,
    #[error("captured LSP observation payload could not be decoded: {0}")]
    LspObservationPayload(#[source] serde_json::Error),
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

    /// Stages exact archive bytes after the original `PolicyOwner` profile has
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
        if admission.operation().operation_kind == LSP_TOOL_OBSERVATION_RECEIPT_KIND {
            return Err(SourceArtifactOwnerError::ReservedLspObservationOperationKind);
        }
        identity.verify_content(bytes)?;
        identity.validate()?;
        profile.validate_for(admission, SOURCE_BLOB_KEY_LINEAGE, self.key_generation)?;

        let policy = blob_policy_binding(profile)?;
        let residency = blob_residency_domains(profile)?;
        let context = receipt_context(admission);
        let blob = self.blob_for_context(&context)?;
        let root_lease = self.root_owner.lease_for_request(&context.request)?;
        let ready =
            blob.stage_source_with_domains(context, root_lease, bytes, policy, residency)?;
        ready.validate()?;
        ArtifactReference::new(
            identity,
            ready.locator().clone(),
            ready.metadata_sha256().to_owned(),
            ready.receipt().identity.receipt_id.to_string(),
        )
        .map_err(SourceArtifactOwnerError::Artifact)
    }

    /// Stages one bridge-owned LSP observation under its reserved operation
    /// kind. The payload is decoded only to prove that these exact original
    /// bytes join the non-Serde bridge projection and admitted request; Blob
    /// receives the original byte slice unchanged.
    pub fn stage_lsp_observation_payload(
        &self,
        admission: &SourceArtifactAdmission,
        profile: &SourceArtifactBlobProfile,
        projection: &LspAdoptionProjection,
        record: &RetainedLspObservationV1,
        original_payload: &[u8],
    ) -> Result<eliot_store_api::CapturedBlobPayloadRefV1, SourceArtifactOwnerError> {
        let operation = admission.operation();
        if operation.effect != EffectClass::ReversibleMutation {
            return Err(SourceArtifactOwnerError::WrongEffect);
        }
        if operation.operation_kind != LSP_TOOL_OBSERVATION_RECEIPT_KIND {
            return Err(SourceArtifactOwnerError::WrongLspObservationOperationKind);
        }

        let decoded: RetainedLspObservationV1 = serde_json::from_slice(original_payload)
            .map_err(SourceArtifactOwnerError::LspObservationPayload)?;
        let invocation_request = &record.instrument_invocation.request;
        if decoded != *record
            || invocation_request != &admission.request().metadata
            || invocation_request.task_id.as_ref() != Some(&admission.task().task_id)
            || invocation_request.session_id.as_ref() != Some(&admission.session().session_id)
            || invocation_request.state_fence != operation.state_fence
            || operation.request_id != invocation_request.request_id
            || !projection.matches_retained_observation(record)
            || projection.observation() != &record.result
        {
            return Err(SourceArtifactOwnerError::LspObservationBindingMismatch);
        }

        profile.validate_for(admission, SOURCE_BLOB_KEY_LINEAGE, self.key_generation)?;
        let policy = blob_policy_binding(profile)?;
        let residency = blob_residency_domains(profile)?;
        let context = receipt_context(admission);
        let blob = self.blob_for_context(&context)?;
        let root_lease = self.root_owner.lease_for_request(&context.request)?;
        let ready = blob.stage_source_with_domains(
            context,
            root_lease,
            original_payload,
            policy,
            residency,
        )?;
        ready.validate()?;
        if ready.receipt().core.operation.operation_kind != LSP_TOOL_OBSERVATION_RECEIPT_KIND {
            return Err(BlobError::MetadataPayloadMismatch.into());
        }
        eliot_store_api::CapturedBlobPayloadRefV1::from_ready_receipt(
            LSP_TOOL_OBSERVATION_RECEIPT_KIND,
            &ready,
        )
        .map_err(SourceArtifactOwnerError::CapturedPayload)
    }

    /// Reopens one exact persisted Artifact reference through the original
    /// Blob owner. The current `PolicyOwner` profile must match the authenticated
    /// policy and six residency domains on that reference; the returned proof
    /// preserves the S-04 read receipt lineage and verifies the artifact
    /// identity against the bytes a second time.
    pub async fn read_source_reference(
        &self,
        admission: &SourceArtifactAdmission,
        profile: &SourceArtifactBlobProfile,
        reference: ArtifactReference,
    ) -> Result<(VerifiedArtifact, ArtifactReadReceipt), SourceArtifactOwnerError> {
        if admission.operation().effect != EffectClass::Read {
            return Err(SourceArtifactOwnerError::WrongEffect);
        }
        reference.validate()?;
        if admission.resource_ref() != reference.expected_ready_receipt_id.as_str() {
            return Err(BlobError::MetadataPayloadMismatch.into());
        }
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

    /// Reads the exact retained LSP observation payload named by its original
    /// `Store` pointer. This path returns the verified `Blob` chunk directly
    /// and does not mint an `ArtifactIdentity` for a non-`Artifact` observation
    /// envelope.
    pub fn read_captured_observation_payload(
        &self,
        admission: &SourceArtifactAdmission,
        profile: &SourceArtifactBlobProfile,
        payload: &eliot_store_api::CapturedBlobPayloadRefV1,
    ) -> Result<BlobReadChunk, SourceArtifactOwnerError> {
        if admission.operation().effect != EffectClass::Read {
            return Err(SourceArtifactOwnerError::WrongEffect);
        }
        payload.validate()?;
        if admission.resource_ref() != payload.ready_receipt_id.as_str() {
            return Err(BlobError::MetadataPayloadMismatch.into());
        }
        if payload.receipt_kind != eliot_lsp_bridge::LSP_TOOL_OBSERVATION_RECEIPT_KIND {
            return Err(SourceArtifactOwnerError::WrongCapturedPayloadKind);
        }
        profile.validate_for(admission, SOURCE_BLOB_KEY_LINEAGE, self.key_generation)?;
        let policy = blob_policy_binding(profile)?;
        let residency = blob_residency_domains(profile)?;
        if !matches_residency_domains(&payload.locator.residency, &residency) {
            return Err(BlobError::MetadataPayloadMismatch.into());
        }

        let context = receipt_context(admission);
        let blob = self.blob_for_context(&context)?;
        let root_lease = self.root_owner.lease_for_request(&context.request)?;
        let chunk = blob.read_source(&BlobReadRequest {
            context,
            root_lease,
            locator: payload.locator.clone(),
            expected_metadata_sha256: payload.metadata_sha256.clone(),
            expected_ready_receipt_id: payload.ready_receipt_id.clone(),
            max_bytes: payload.plaintext_length,
        })?;
        chunk.validate()?;

        let ready = chunk.ready_receipt();
        if ready.receipt().core.operation.operation_kind != LSP_TOOL_OBSERVATION_RECEIPT_KIND
            || ready.locator() != &payload.locator
            || ready.metadata_sha256() != payload.metadata_sha256.as_str()
            || ready.receipt().identity.receipt_id.as_str() != payload.ready_receipt_id.as_str()
            || ready.policy() != &policy
            || !matches_residency_domains(&ready.locator().residency, &residency)
            || ready.plaintext_length() != payload.plaintext_length
            || ready.plaintext_sha256() != payload.plaintext_sha256.as_str()
            || chunk.bytes().len() as u64 != payload.plaintext_length
            || eliot_contracts::sha256_hex(chunk.bytes()).as_str()
                != payload.plaintext_sha256.as_str()
        {
            return Err(BlobError::MetadataPayloadMismatch.into());
        }
        Ok(chunk)
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
        let keys =
            DpapiUserKeyPort::new(BlobId::new(SOURCE_BLOB_KEY_LINEAGE)?, self.key_generation)?;
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
            let chunk = self.blob.read_source(&BlobReadRequest {
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
