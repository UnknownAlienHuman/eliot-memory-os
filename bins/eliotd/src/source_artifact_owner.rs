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
    BlobError, BlobId, BlobLocator, BlobPolicyBinding, BlobReadChunk, BlobReadRequest,
    BlobReadyReceipt, BlobReceiptContext, ObjectResidencyKey, RetentionClass,
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
    #[error(
        "LSP observation publication requires the exact admitted request and live bridge projection"
    )]
    LspObservationBindingMismatch,
    #[error("LSP observation publication requires its reserved operation kind")]
    WrongLspObservationOperationKind,
    #[error("captured LSP observation payload could not be decoded: {0}")]
    LspObservationPayload(#[source] serde_json::Error),
    #[error("source artifact effect is not admitted for this operation")]
    WrongEffect,
    #[error("source snapshot staging target differs from the current Blob owner, policy, or bytes")]
    StagingTargetMismatch,
}

/// Sealed, non-Serde prospective S-04 locator for one exact source archive.
///
/// This is an inert target derived by the original Blob root owner and the
/// currently read Policy scope before the Governor issues a distinct write
/// admission. Its resource reference is the canonical existing Blob locator,
/// not a second caller-selected resource namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceArtifactStagingTarget {
    locator: BlobLocator,
    resource_ref: String,
    source_id: eliot_contracts::SourceId,
    archive_sha256: String,
    blob_root_id: String,
    policy_snapshot_id: String,
    policy_snapshot_digest: String,
    state_fence: eliot_contracts::StateFence,
}

impl SourceArtifactStagingTarget {
    pub(crate) fn locator(&self) -> &BlobLocator {
        &self.locator
    }

    pub(crate) fn resource_ref(&self) -> &str {
        &self.resource_ref
    }

    pub(crate) fn blob_root_id(&self) -> &str {
        &self.blob_root_id
    }
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

    /// Derives the exact prospective Blob locator from current original
    /// Policy-owned residency domains, this owner's lifecycle generation,
    /// and the exact captured plaintext. No lease, action, authority, or write
    /// is created here.
    pub(crate) fn prepare_source_snapshot_target(
        &self,
        policy_profile: &SourceArtifactBlobProfile,
        source_id: &eliot_contracts::SourceId,
        exact_archive_bytes: &[u8],
    ) -> Result<SourceArtifactStagingTarget, SourceArtifactOwnerError> {
        let state_fence = policy_profile.state_fence().clone();
        let root_generation = self
            .root_owner
            .lifecycle_resource_generation()
            .ok_or(SourceArtifactOwnerError::StagingTargetMismatch)?;
        if state_fence.resource_generation.value() != root_generation
            || root_generation != self.key_generation
            || exact_archive_bytes.is_empty()
        {
            return Err(SourceArtifactOwnerError::StagingTargetMismatch);
        }
        let domains = blob_residency_domains(policy_profile)?;
        // This method is supplied by the original Blob owner and reuses its
        // S-04 BLAKE3/residency/path-generation derivation. Do not duplicate
        // those rules in the daemon composition.
        let locator = domains.locator_for_exact_bytes(exact_archive_bytes, root_generation)?;
        locator.validate()?;
        let resource_ref = String::from_utf8(eliot_contracts::canonical_json_bytes(&locator)?)
            .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        Ok(SourceArtifactStagingTarget {
            locator,
            resource_ref,
            source_id: source_id.clone(),
            archive_sha256: eliot_contracts::sha256_hex(exact_archive_bytes),
            blob_root_id: self.root_owner.root_id().to_owned(),
            policy_snapshot_id: policy_profile.policy_snapshot_id().to_owned(),
            policy_snapshot_digest: policy_profile.policy_snapshot_digest().to_owned(),
            state_fence,
        })
    }

    /// Stages exact bytes only when the distinct original mutation admission
    /// targets the prospective locator derived before that admission.
    pub(crate) fn stage_source_snapshot_at_target(
        &self,
        admission: &SourceArtifactAdmission,
        profile: &SourceArtifactBlobProfile,
        target: &SourceArtifactStagingTarget,
        identity: ArtifactIdentity,
        bytes: &[u8],
    ) -> Result<ArtifactReference, SourceArtifactOwnerError> {
        let current_target = self.prepare_source_snapshot_target(
            profile,
            &target.source_id,
            bytes,
        )?;
        if target != &current_target
            || admission.operation().effect != EffectClass::ReversibleMutation
            || admission.resource_ref() != target.resource_ref
            || admission.request().state_fence != target.state_fence
            || admission.work_scope().state_fence != target.state_fence
            || profile.policy_snapshot_id() != target.policy_snapshot_id
            || profile.policy_snapshot_digest() != target.policy_snapshot_digest
            || identity.source.as_ref().is_none_or(|source| {
                source.source_id != target.source_id
                    || source.integrity.as_deref() != Some(target.archive_sha256.as_str())
            })
        {
            return Err(SourceArtifactOwnerError::StagingTargetMismatch);
        }
        let reference = self.stage_source_snapshot(admission, profile, identity, bytes)?;
        if reference.locator != target.locator {
            return Err(SourceArtifactOwnerError::StagingTargetMismatch);
        }
        Ok(reference)
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
        identity.validate()?;
        identity.verify_content(bytes)?;
        profile.validate_for(admission, SOURCE_BLOB_KEY_LINEAGE, self.key_generation)?;

        let policy = blob_policy_binding(profile)?;
        let residency = blob_residency_domains(profile)?;
        let context = receipt_context(admission);
        let blob = self.blob_for_context(&context)?;
        let root_lease = self.root_owner.lease_for_request(&context.request)?;
        let ready =
            blob.stage_source_with_domains(context, root_lease, bytes, policy, residency)?;
        validate_ready_receipt_for_admission(&ready, admission)?;
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

        validate_live_lsp_observation_binding(admission, projection, record, original_payload)?;

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
        validate_ready_receipt_for_admission(&ready, admission)?;
        let original_core = &ready.receipt().core;
        if original_core.operation.operation_kind != LSP_TOOL_OBSERVATION_RECEIPT_KIND {
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

fn validate_ready_receipt_for_admission(
    ready: &BlobReadyReceipt,
    admission: &SourceArtifactAdmission,
) -> Result<(), SourceArtifactOwnerError> {
    ready.validate()?;
    let core = &ready.receipt().core;
    if core.work_scope != *admission.work_scope()
        || core.task.as_ref() != Some(admission.task())
        || core.session.as_ref() != Some(admission.session())
        || core.causal != *admission.causal()
        || core.request != *admission.request()
        || core.operation != *admission.operation()
        || core.authority != *admission.authority()
    {
        return Err(BlobError::MetadataPayloadMismatch.into());
    }
    Ok(())
}

fn validate_live_lsp_observation_binding(
    admission: &SourceArtifactAdmission,
    projection: &LspAdoptionProjection,
    record: &RetainedLspObservationV1,
    original_payload: &[u8],
) -> Result<(), SourceArtifactOwnerError> {
    let decoded: RetainedLspObservationV1 = serde_json::from_slice(original_payload)
        .map_err(SourceArtifactOwnerError::LspObservationPayload)?;
    if decoded != *record
        || !projection.matches_retained_observation(&decoded)
        || projection.observation() != &decoded.result
    {
        return Err(SourceArtifactOwnerError::LspObservationBindingMismatch);
    }
    let record = &decoded;
    let invocation_request = &record.instrument_invocation.request;
    let source_binding = record.result.receipt().source_binding.as_ref();
    let dispatch_source =
        source_binding.and_then(|binding| binding.source_artifact_at_dispatch.as_ref());
    let expected_source_artifact_id =
        format!("source-snapshot:{}", invocation_request.request_id.as_str());
    let source_artifact_joins_request =
        |source: &eliot_lsp_bridge::LspSourceArtifactProjectionV1| {
            let identity = &source.artifact_reference.identity;
            identity.artifact_id.as_str() == expected_source_artifact_id.as_str()
                && identity.source.as_ref().is_some_and(|source_binding| {
                    source_binding.integrity.as_deref()
                        == Some(identity.content.digest_hex.as_str())
                        && source_binding.revision == source.git_tree_id
                })
                && record
                    .instrument_invocation
                    .input_artifacts
                    .iter()
                    .filter(|artifact| *artifact == &identity.artifact_id)
                    .count()
                    == 1
        };
    let dispatch_source_joins_request = dispatch_source.is_some_and(&source_artifact_joins_request);
    let after_run_source_joins_request = source_binding
        .and_then(|binding| binding.source_artifact_after_run.as_ref())
        .is_none_or(source_artifact_joins_request);
    let source_binding_joins_invocation = source_binding.is_some_and(|binding| {
        binding.instrument_request_id == invocation_request.request_id.as_str()
            && binding.instrument_target == record.instrument_invocation.target
            && binding.instrument_declared_scope == record.instrument_invocation.declared_scope
            && binding.instrument_input_artifacts == record.instrument_invocation.input_artifacts
    });
    if invocation_request != &admission.request().metadata
        || invocation_request.product_id != admission.work_scope().product_id
        || invocation_request.task_id.as_ref() != Some(&admission.task().task_id)
        || invocation_request.session_id.as_ref() != Some(&admission.session().session_id)
        || invocation_request.state_fence != admission.operation().state_fence
        || admission.operation().request_id != invocation_request.request_id
        || !dispatch_source_joins_request
        || !after_run_source_joins_request
        || !source_binding_joins_invocation
    {
        return Err(SourceArtifactOwnerError::LspObservationBindingMismatch);
    }
    Ok(())
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
