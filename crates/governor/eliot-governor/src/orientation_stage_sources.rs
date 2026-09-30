//! Authenticated source readback for Orientation's independent classification profile.
//!
//! The profile is an owner-published campaign source, separate from the
//! fixed 26-role learning view. This module only decodes the exact original
//! named-read result; it does not turn task, context, or model fields into a
//! substitute profile.

use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, ContractError, OperationId, RequestMetadata, StateFence,
    TaskId, TaskRevision, TransactionSequence,
};
use eliot_cue_contracts::{
    AdmittedCueBindingProjection, CueBindingAdmissionRef, CueProjectionDenominator,
    OrientationCueBindingsSource, RelationEdge, SnapshotEdgeWeight, SnapshotId, WorkScopeId,
};
use eliot_cue_binding::{
    BindingProfile, CueBindingError, CueBindingResult, ExpectedReuseHint, TouchedResourceProjection,
    derive_cue_binding_candidates,
};
use eliot_cue_contracts::CueContractError;
use eliot_dreamer_contracts::{
    DreamInputBundle, DreamJobAdmission, DreamJobInput, JobClass, OrientationClassificationProfile,
    canonical_bytes, digest_hex, is_hex64_lower,
};
use eliot_dreamer_orientation::{AdmittedOrientationJob, OrientationError};
use eliot_learning_contracts::CampaignSourceRole;
use eliot_receipts::{
    ArtifactBinding, AuthorityBinding, CausalBinding, EffectClass, OperationBinding, ProofCeiling,
    ReceiptCore, ReceiptDisposition, ReceiptEnvelope, ReceiptKind, RequestBinding,
    SessionBinding, TaskBinding, WorkScopeBinding,
};
use eliot_task::{TaskCommand, TaskState};
use eliot_observation::{ObservationAdmissionReceipt, ObservationAdmissionResult};
use eliot_store_api::{
    CampaignOwnerProjectionBody, CampaignOwnerReadReceipt, CampaignOwnerRecordId,
    CampaignOwnerRevision, CampaignSourceDocument, CampaignSourceDocumentSchema,
    CampaignSourceHead, CampaignSourceReadStatus, CampaignSourceRecord,
    CampaignSourceRevisionRead, OwnerId, StoreError, campaign_source_owner_id,
};
use eliot_protocol::OpaqueContentRef;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Borrowed wire view over the explicit, original TaskController cue supplier.
///
/// The runtime transport stays owner-neutral; this Governor boundary decodes
/// each field into its native contract and rejects values that do not round
/// trip byte-for-byte through the existing canonical JSON encoder.
#[derive(Clone, Copy, Debug)]
pub struct OrientationCueAdmissionValuesV1<'a> {
    /// Original accepted Observation admission receipt.
    pub observation_admission: &'a serde_json::Value,
    /// Original touched source rows, including the complete admitted denominator.
    pub touched: &'a [serde_json::Value],
    /// Original optional expected-reuse hint, if present.
    pub hint: Option<&'a serde_json::Value>,
    /// Original A-12 binding profile.
    pub binding_profile: &'a serde_json::Value,
    /// Original A-10 snapshot identity.
    pub snapshot_id: &'a serde_json::Value,
    /// Original A-10 denominator including every omission identity.
    pub denominator: &'a serde_json::Value,
    /// Original A-10 relation edges.
    pub relation_edges: &'a [serde_json::Value],
    /// Original relation registry revision, if any.
    pub registry_revision: Option<&'a str>,
    /// Original A-10 relation weights.
    pub weights: &'a [serde_json::Value],
}

/// Original source values required to admit one Orientation cue closure.
///
/// The observation must be the accepted receipt retained by this Governor's
/// journal. The touched rows, A-12 profile, and A-10 closure are passed as the
/// exact native values admitted by their upstream source owners.
#[derive(Clone, Debug)]
pub struct OrientationCueAdmissionInput<'a> {
    /// Original request identity, caller session, task, source, clock, and fence.
    pub request: &'a RequestMetadata,
    /// Original authenticated request clock supplied by the live owner boundary.
    pub owner_clock: &'a ClockReading,
    /// Kernel-issued operation identity for this owner operation.
    pub operation_id: &'a OperationId,
    /// Original accepted Observation owner receipt used as A-12 admission input.
    pub observation: &'a ObservationAdmissionReceipt,
    /// Exact original A-12 touched denominator rows.
    pub touched: &'a [TouchedResourceProjection],
    /// Original optional A-12 expected-reuse evidence.
    pub hint: Option<&'a ExpectedReuseHint>,
    /// Original A-12 rule profile and normalization binding.
    pub profile: &'a BindingProfile,
    /// Original A-10 snapshot identity supplied by its source owner.
    pub snapshot_id: SnapshotId,
    /// Frozen original A-10 row and edge denominator.
    pub denominator: &'a CueProjectionDenominator,
    /// Original A-10 relation edges.
    pub relation_edges: &'a [RelationEdge],
    /// Original relation-registry revision, when the source carried one.
    pub registry_revision: Option<&'a str>,
    /// Original A-10 edge weights.
    pub weights: &'a [SnapshotEdgeWeight],
}

/// Typed refusal from the Governor's native Orientation cue admission owner.
#[derive(Debug, Error)]
pub enum OrientationCueAdmissionError {
    /// The Governor composition is not ready to admit a candidate.
    #[error("Governor composition is not ready")]
    NotReady,
    /// A required current owner is absent.
    #[error("current Governor owner is unavailable: {0}")]
    OwnerUnavailable(&'static str),
    /// The authenticated request or active session does not join this task.
    #[error("Orientation cue request binding failed: {0}")]
    RequestBinding(&'static str),
    /// Current Governor task, policy, scope, or session authorization disagrees.
    #[error("Orientation cue admission is not authorized by current owners: {0}")]
    Authorization(&'static str),
    /// The original Observation receipt is not the exact accepted journal entry.
    #[error("original Observation receipt is invalid: {0}")]
    ObservationReceipt(eliot_observation::GovernorObservationError),
    /// A transported source value could not be decoded as its native type.
    #[error("Orientation cue source field {field} could not be decoded: {source}")]
    SourceFieldDecode {
        /// The native field whose exact source value failed.
        field: &'static str,
        /// Native JSON decoder failure.
        source: serde_json::Error,
    },
    /// A source field could not be canonically encoded for exact comparison.
    #[error("Orientation cue source field {field} could not be canonicalized: {source}")]
    SourceFieldCanonicalization {
        /// The native field whose exact source value failed.
        field: &'static str,
        /// Native JSON canonicalization failure.
        source: serde_json::Error,
    },
    /// A decoded source value differs from its original canonical bytes.
    #[error("Orientation cue source field {0} differs from its original canonical value")]
    SourceFieldMismatch(&'static str),
    /// The exact accepted task-bound journal entry was absent or mismatched.
    #[error("original Observation admission binding failed at {0}")]
    ObservationBinding(&'static str),
    /// Native A-12 derivation rejected the original inputs.
    #[error("native A-12 cue derivation failed: {0}")]
    A12(CueBindingError),
    /// Native A-12 output failed an exact predecessor join.
    #[error("native A-12 result binding failed at {0}")]
    A12Binding(&'static str),
    /// Exact A-10 closure construction rejected the original inputs.
    #[error("native A-10 cue closure failed: {0}")]
    A10(CueContractError),
    /// Native A-10 output failed an exact predecessor join.
    #[error("native A-10 result binding failed at {0}")]
    A10Binding(&'static str),
    /// The authenticated owner clock is invalid or differs from request metadata.
    #[error("Orientation cue owner clock is invalid at {0}")]
    OwnerClock(&'static str),
    /// The original request clock failed its native contract.
    #[error("Orientation cue request clock is invalid")]
    RequestClock(ContractError),
    /// Standard C0-02 receipt issuance rejected the complete owner decision.
    #[error("Governor cue admission receipt is invalid: {0}")]
    Receipt(eliot_receipts::ReceiptError),
    /// Store rejected the constructed cue source row.
    #[error("Orientation cue campaign source record is invalid: {0}")]
    Store(StoreError),
}

/// Build the immutable Store source row from the exact Governor-issued native
/// cue source. Its A-12 and A-10 values and decision receipt remain embedded
/// unchanged in the owner projection.
pub fn orientation_cue_bindings_campaign_source_record(
    source: &OrientationCueBindingsSource,
) -> Result<CampaignSourceRecord, OrientationCueAdmissionError> {
    source
        .validate()
        .map_err(OrientationCueAdmissionError::A10)?;
    let task_revision = source
        .state_fence
        .task_revision
        .clone()
        .ok_or(OrientationCueAdmissionError::RequestBinding("task_revision"))?;
    let owner_id = OwnerId::from_artifact(
        ArtifactId::new(
            campaign_source_owner_id(CampaignSourceRole::OrientationCueBindings).to_owned(),
        )
        .map_err(|_| OrientationCueAdmissionError::RequestBinding("owner_id"))?,
    );
    let projection = serde_json::to_value(source)
        .map_err(|_| OrientationCueAdmissionError::A10Binding("campaign_projection"))?;
    let projection_bytes = eliot_contracts::canonical_json_bytes(&projection)
        .map_err(|_| OrientationCueAdmissionError::A10Binding("campaign_projection_bytes"))?;
    let projection_body = CampaignOwnerProjectionBody {
        owner_id: owner_id.as_str().to_owned(),
        record_id: source.task_id.as_str().to_owned(),
        revision: task_revision.value().to_string(),
        state_fence: source.state_fence.clone(),
        projection_digest: digest_hex(&projection_bytes),
        required_references: Vec::new(),
        projection,
    };
    let document = CampaignSourceDocument {
        schema: CampaignSourceDocumentSchema::OrientationCueBindingsRecord,
        schema_version: CampaignSourceDocument::SCHEMA_VERSION,
        body: serde_json::to_value(projection_body)
            .map_err(|_| OrientationCueAdmissionError::A10Binding("campaign_document"))?,
    };
    CampaignSourceRecord::new(
        CampaignSourceRole::OrientationCueBindings,
        owner_id,
        CampaignOwnerRecordId::Task(source.task_id.clone()),
        CampaignOwnerRevision::Task(task_revision),
        source.state_fence.clone(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        document,
    )
    .map_err(OrientationCueAdmissionError::Store)
}

/// Typed failure while admitting the original Orientation profile readback.
#[derive(Debug, Error)]
pub enum OrientationClassificationSourceError {
    /// The named read was missing, stale, or blocked.
    #[error("Orientation classification source read is not current: {0}")]
    NotCurrent(&'static str),
    /// The read did not contain the complete authenticated current tuple.
    #[error("Orientation classification source read is incomplete")]
    IncompleteRead,
    /// The immutable source row was not the exact Orientation role/owner/schema.
    #[error("Orientation classification source identity does not match")]
    IdentityMismatch,
    /// The exact stored row or read receipt failed its native validation.
    #[error("Orientation classification source read is invalid: {0}")]
    InvalidRead(StoreError),
    /// The closed owner projection did not decode as its native read type.
    #[error("Orientation classification source projection could not be decoded: {0}")]
    ProjectionDecode(serde_json::Error),
    /// The native profile did not decode as its closed source type.
    #[error("Orientation classification profile could not be decoded: {0}")]
    ProfileDecode(serde_json::Error),
    /// The stored native profile failed its own contract validation.
    #[error("Orientation classification profile is invalid: {0}")]
    InvalidProfile(eliot_dreamer_contracts::ContractViolation),
    /// The original profile does not bind the admitted live task, scope, or fence.
    #[error("Orientation classification profile is not bound to the live task context: {0}")]
    RuntimeBinding(&'static str),
}

/// Decoded semantic profile paired with the unchanged authenticated owner read.
///
/// `read` retains the original CampaignSourceRecord, current head,
/// CampaignOwnerReadReceipt, and read fence. The profile is only a typed view
/// of the source document's native `projection` field; the original row and
/// receipt remain the provenance authority.
#[derive(Clone, Debug)]
pub struct OrientationClassificationSourceReadback<'a> {
    profile: OrientationClassificationProfile,
    read: &'a CampaignSourceRevisionRead,
}

/// Exact original canonical source bytes carried through Orientation admission.
///
/// The reference and byte vector are retained unchanged beside the decoded
/// native value so the admission row can prove which original publication it
/// consumed. This wrapper carries no admission authority by itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrientationOriginalSourceBytes {
    /// Original owner-issued immutable content reference.
    pub reference: OpaqueContentRef,
    /// Exact original canonical JSON bytes named by `reference`.
    pub canonical_bytes: Vec<u8>,
}

/// Original byte publications for the four native Orientation inputs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrientationAdmissionOriginalSources {
    /// Original semantic Dreamer job input publication.
    pub job_input: OrientationOriginalSourceBytes,
    /// Original admitted job publication.
    pub admission: OrientationOriginalSourceBytes,
    /// Original bounded input bundle publication.
    pub bundle: OrientationOriginalSourceBytes,
    /// Original source-bound Orientation job/frame publication.
    pub admitted_orientation_job: OrientationOriginalSourceBytes,
}

/// Authenticated input to the Governor's Orientation admission owner.
pub struct OrientationAdmissionInput<'a> {
    /// Exact request identity from the authenticated Kernel claim.
    pub request: &'a RequestMetadata,
    /// Original authenticated request clock supplied at this owner boundary.
    pub owner_clock: &'a ClockReading,
    /// Kernel-issued operation identity for the admission owner operation.
    pub operation_id: &'a OperationId,
    /// Original decoded canonical semantic job input.
    pub job_input: &'a DreamJobInput,
    /// Original decoded canonical Dreamer admission.
    pub admission: &'a DreamJobAdmission,
    /// Original decoded canonical bounded input bundle.
    pub bundle: &'a DreamInputBundle,
    /// Original decoded source-bound Orientation job/frame publication.
    pub admitted_orientation_job: &'a AdmittedOrientationJob,
    /// Exact original reference/byte pairs from the authenticated request.
    pub sources: &'a OrientationAdmissionOriginalSources,
}

/// Original Governor admission decision plus the untouched native inputs that
/// decision admitted. The embedded receipt is the only decision proof; the
/// source read/write evidence remains separate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrientationAdmissionRecord {
    /// Native schema revision for this source document.
    pub schema_version: u32,
    /// Exact request metadata that authorized this decision.
    pub request: RequestMetadata,
    /// Kernel-issued operation identity used by this decision.
    pub operation_id: OperationId,
    /// Original native semantic job input.
    pub job_input: DreamJobInput,
    /// Original native Dreamer admission.
    pub admission: DreamJobAdmission,
    /// Original native input bundle.
    pub bundle: DreamInputBundle,
    /// Original native source-bound Orientation job/frame value.
    pub admitted_orientation_job: AdmittedOrientationJob,
    /// Original references and bytes, retained without resealing.
    pub original_sources: OrientationAdmissionOriginalSources,
    /// Current Policy owner snapshot identity used during admission.
    pub policy_snapshot_id: String,
    /// Existing exact Policy owner snapshot digest used during admission.
    pub policy_snapshot_digest: String,
    /// Newly issued CandidateArtifact admission decision receipt.
    pub decision_receipt: ReceiptEnvelope,
}

/// Typed refusal while admitting the original Orientation job.
#[derive(Debug, Error)]
pub enum OrientationAdmissionError {
    /// Governor owners are not ready to admit a new candidate.
    #[error("Governor composition is not ready")]
    NotReady,
    /// A required current owner is absent.
    #[error("current Governor owner is unavailable: {0}")]
    OwnerUnavailable(&'static str),
    /// Request and original semantic values do not bind each other.
    #[error("Orientation admission request binding failed: {0}")]
    RequestBinding(&'static str),
    /// Current task/session/scope/policy owners refuse this admission.
    #[error("Orientation admission is not authorized by current owners: {0}")]
    Authorization(&'static str),
    /// One exact source ref or byte payload failed its original-content check.
    #[error("Orientation admission source {field} is invalid: {source}")]
    SourceReference {
        /// Source field whose original bytes were rejected.
        field: &'static str,
        /// Native protocol validation error.
        source: eliot_protocol::dreamer_job::DurableJobError,
    },
    /// A decoded native source differs from its exact original canonical bytes.
    #[error("Orientation admission source {0} differs from its original bytes")]
    SourceCanonicalMismatch(&'static str),
    /// A canonical source reference names a different native contract schema.
    #[error("Orientation admission source {0} has the wrong native contract identity")]
    SourceContractIdentity(&'static str),
    /// Native contract identity construction failed for an owner schema.
    #[error("Orientation admission source contract identity is invalid: {0}")]
    ContractIdentity(eliot_contracts::ContractError),
    /// The original source bytes did not decode as the exact native record.
    #[error("Orientation admission source {field} could not be decoded: {source}")]
    NativeDecode {
        /// Original source field that failed native decoding.
        field: &'static str,
        /// Typed serde decoding failure.
        source: serde_json::Error,
    },
    /// Native Dreamer input or admission contract validation failed.
    #[error("Orientation admission contract is invalid: {0}")]
    Contract(eliot_dreamer_contracts::ContractViolation),
    /// Native Orientation frame/material binding failed.
    #[error("Orientation admission frame is invalid: {0}")]
    Orientation(OrientationError),
    /// Canonical receipt issuance or validation failed.
    #[error("Orientation admission receipt is invalid: {0}")]
    Receipt(eliot_receipts::ReceiptError),
    /// Store owner row could not be constructed without changing its identity.
    #[error("Orientation admission campaign record is invalid: {0}")]
    Store(StoreError),
    /// Exact reference or receipt artifacts are duplicated.
    #[error("Orientation admission source artifact identity is duplicated")]
    DuplicateArtifact,
}

/// Typed failure while consuming the independently-read Orientation
/// admission source.
#[derive(Debug, Error)]
pub enum OrientationAdmissionSourceError {
    /// The named source read was stale, blocked, or absent.
    #[error("Orientation admission source read is not current: {0}")]
    NotCurrent(&'static str),
    /// The named read omitted its row, head, or authenticated read receipt.
    #[error("Orientation admission source read is incomplete")]
    IncompleteRead,
    /// The campaign row, head, or receipt identifies a different source owner.
    #[error("Orientation admission source owner identity does not match")]
    IdentityMismatch,
    /// The native source read failed its Store API validation.
    #[error("Orientation admission source read is invalid: {0}")]
    InvalidRead(StoreError),
    /// The original Governor admission row failed native validation.
    #[error("Orientation admission source record is invalid: {0}")]
    InvalidRecord(OrientationAdmissionError),
}

/// Native admission record paired with its original authenticated Store read.
#[derive(Clone, Debug)]
pub struct OrientationAdmissionSourceReadback<'a> {
    record: OrientationAdmissionRecord,
    read: &'a CampaignSourceRevisionRead,
}

impl OrientationAdmissionRecord {
    /// Validates the immutable admission row without replacing its decision
    /// receipt or any of the original input publications.
    pub fn validate(&self) -> Result<(), OrientationAdmissionError> {
        validate_orientation_admission_native_record(self)?;
        validate_orientation_admission_receipt(self)?;
        Ok(())
    }

    /// Builds the Store API's closed owner projection body while keeping this
    /// native record as the exact projection value.
    pub fn campaign_projection_body(
        &self,
    ) -> Result<CampaignOwnerProjectionBody, OrientationAdmissionError> {
        self.validate()?;
        let owner_id = campaign_source_owner_id(CampaignSourceRole::OrientationAdmission);
        let task_id = TaskId::new(self.admission.task_id.clone())
            .map_err(|_| OrientationAdmissionError::RequestBinding("task_id"))?;
        let task_revision = self
            .admission
            .state_fence
            .task_revision
            .clone()
            .ok_or(OrientationAdmissionError::RequestBinding("task_revision"))?;
        let projection = serde_json::to_value(self).map_err(|_| {
            OrientationAdmissionError::RequestBinding("campaign_projection")
        })?;
        let projection_bytes = eliot_contracts::canonical_json_bytes(&projection).map_err(|_| {
            OrientationAdmissionError::RequestBinding("campaign_projection_bytes")
        })?;
        let required_references = [
            &self.original_sources.job_input,
            &self.original_sources.admission,
            &self.original_sources.bundle,
            &self.original_sources.admitted_orientation_job,
        ]
        .into_iter()
        .map(|source| {
            source
                .reference
                .artifact_id
                .clone()
                .ok_or(OrientationAdmissionError::RequestBinding(
                    "source_artifact_id",
                ))
        })
        .collect::<Result<Vec<_>, _>>()?;
        Ok(CampaignOwnerProjectionBody {
            owner_id: owner_id.to_owned(),
            record_id: task_id.as_str().to_owned(),
            revision: task_revision.value().to_string(),
            state_fence: self.admission.state_fence.clone(),
            projection_digest: digest_hex(&projection_bytes),
            required_references,
            projection,
        })
    }

    /// Builds the exact independently-owned campaign source row for this
    /// Governor admission decision. Publication/CAS and the resulting Store
    /// effect receipt remain the caller's separate responsibilities.
    pub fn campaign_source_record(
        &self,
    ) -> Result<CampaignSourceRecord, OrientationAdmissionError> {
        let projection_body = self.campaign_projection_body()?;
        let task_id = TaskId::new(self.admission.task_id.clone())
            .map_err(|_| OrientationAdmissionError::RequestBinding("task_id"))?;
        let task_revision = self
            .admission
            .state_fence
            .task_revision
            .clone()
            .ok_or(OrientationAdmissionError::RequestBinding("task_revision"))?;
        let owner_id = OwnerId::from_artifact(
            ArtifactId::new(
                campaign_source_owner_id(CampaignSourceRole::OrientationAdmission).to_owned(),
            )
            .map_err(|_| OrientationAdmissionError::RequestBinding("owner_id"))?,
        );
        let required_references = projection_body.required_references.clone();
        let document = CampaignSourceDocument {
            schema: CampaignSourceDocumentSchema::OrientationAdmissionRecord,
            schema_version: CampaignSourceDocument::SCHEMA_VERSION,
            body: serde_json::to_value(projection_body).map_err(|_| {
                OrientationAdmissionError::RequestBinding("campaign_document")
            })?,
        };
        CampaignSourceRecord::new(
            CampaignSourceRole::OrientationAdmission,
            owner_id,
            CampaignOwnerRecordId::Task(task_id),
            CampaignOwnerRevision::Task(task_revision),
            self.admission.state_fence.clone(),
            Vec::new(),
            Vec::new(),
            required_references,
            Vec::new(),
            Vec::new(),
            document,
        )
        .map_err(OrientationAdmissionError::Store)
    }
}

fn validate_orientation_admission_native_record(
    record: &OrientationAdmissionRecord,
) -> Result<(), OrientationAdmissionError> {
    record
        .request
        .validate()
        .map_err(|_| OrientationAdmissionError::RequestBinding("request_metadata"))?;
    record
        .job_input
        .validate()
        .map_err(OrientationAdmissionError::Contract)?;
    record
        .admission
        .validate()
        .map_err(OrientationAdmissionError::Contract)?;
    record
        .bundle
        .validate()
        .map_err(OrientationAdmissionError::Contract)?;
    record
        .admitted_orientation_job
        .validate_for(&record.bundle)
        .map_err(OrientationAdmissionError::Orientation)?;
    validate_orientation_original_source(
        &record.original_sources.job_input,
        &record.job_input,
        "job_input",
    )?;
    validate_orientation_original_source(
        &record.original_sources.admission,
        &record.admission,
        "admission",
    )?;
    validate_orientation_original_source(
        &record.original_sources.bundle,
        &record.bundle,
        "bundle",
    )?;
    validate_orientation_original_source(
        &record.original_sources.admitted_orientation_job,
        &record.admitted_orientation_job,
        "admitted_orientation_job",
    )?;

    let task_id = record
        .request
        .task_id
        .as_ref()
        .ok_or(OrientationAdmissionError::RequestBinding("task_id"))?;
    let session_id = record
        .request
        .session_id
        .as_ref()
        .ok_or(OrientationAdmissionError::RequestBinding("session_id"))?;
    if record.schema_version != 1
        || record.admission.job_class != JobClass::Orientation
        || record.job_input.job_class != JobClass::Orientation
        || record.job_input.job_id != record.admission.canonical_id()
        || record.job_input.requester != record.admission.requester.principal
        || record.job_input.privacy_profile != record.admission.privacy_profile
        || record.admission.operation_id != record.operation_id.as_str()
        || record.admission.idempotency_key != record.request.request_id.as_str()
        || record.admission.task_id != task_id.as_str()
        || record.admission.scope_id != record.bundle.scope_id
        || record.admission.state_fence != record.request.state_fence
        || record.job_input.task_id.as_deref() != Some(task_id.as_str())
        || record.job_input.scope_id != record.admission.scope_id
        || record.job_input.state_fence != record.admission.state_fence
        || record.bundle.job_id != record.admission.canonical_id()
        || record.bundle.task_id != record.admission.task_id
        || record.bundle.scope_id != record.admission.scope_id
        || record.bundle.state_fence != record.admission.state_fence
        || record.bundle.manifest_digest != record.admission.frozen_manifest_digest
        || record.admitted_orientation_job.job != record.admission
        || record.admission.requester.session.as_deref() != Some(session_id.as_str())
        || !is_hex64_lower(&record.policy_snapshot_digest)
    {
        return Err(OrientationAdmissionError::RequestBinding(
            "admitted_originals",
        ));
    }
    Ok(())
}

fn orientation_admission_expected_artifacts(
    record: &OrientationAdmissionRecord,
) -> Result<Vec<ArtifactBinding>, OrientationAdmissionError> {
    let request_bytes = eliot_contracts::canonical_json_bytes(&record.request)
        .map_err(|_| OrientationAdmissionError::RequestBinding("request_canonical_bytes"))?;
    let mut artifacts = Vec::with_capacity(6);
    for original in [
        &record.original_sources.job_input,
        &record.original_sources.admission,
        &record.original_sources.bundle,
        &record.original_sources.admitted_orientation_job,
    ] {
        original
            .reference
            .validate("orientation_admission.source")
            .map_err(|source| OrientationAdmissionError::SourceReference {
                field: "source_reference",
                source,
            })?;
        let artifact_id = original
            .reference
            .artifact_id
            .clone()
            .ok_or(OrientationAdmissionError::RequestBinding(
                "source_artifact_id",
            ))?;
        artifacts.push(ArtifactBinding {
            artifact_id,
            sha256: original.reference.sha256.clone(),
            role: ReceiptKind::Artifact,
            source_revision: Some(original.reference.source_revision.clone()),
        });
    }
    artifacts.push(ArtifactBinding {
        artifact_id: ArtifactId::new("orientation-request-metadata")
            .map_err(|_| OrientationAdmissionError::RequestBinding("request_artifact"))?,
        sha256: digest_hex(&request_bytes),
        role: ReceiptKind::Artifact,
        source_revision: Some(record.request.request_id.as_str().to_owned()),
    });
    artifacts.push(ArtifactBinding {
        artifact_id: ArtifactId::new("orientation-policy-snapshot")
            .map_err(|_| OrientationAdmissionError::Authorization("policy_artifact"))?,
        sha256: record.policy_snapshot_digest.clone(),
        role: ReceiptKind::Artifact,
        source_revision: Some(record.policy_snapshot_id.clone()),
    });
    let unique_ids = artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if unique_ids.len() != artifacts.len() {
        return Err(OrientationAdmissionError::DuplicateArtifact);
    }
    Ok(artifacts)
}

fn validate_orientation_admission_receipt(
    record: &OrientationAdmissionRecord,
) -> Result<(), OrientationAdmissionError> {
    record
        .decision_receipt
        .validate()
        .map_err(OrientationAdmissionError::Receipt)?;
    let task_id = record
        .request
        .task_id
        .as_ref()
        .ok_or(OrientationAdmissionError::RequestBinding("task_id"))?;
    let session_id = record
        .request
        .session_id
        .as_ref()
        .ok_or(OrientationAdmissionError::RequestBinding("session_id"))?;
    let task_revision = record
        .request
        .state_fence
        .task_revision
        .as_ref()
        .ok_or(OrientationAdmissionError::RequestBinding("task_revision"))?;
    let task_revision = TaskRevision::new(task_revision.value())
        .map_err(|_| OrientationAdmissionError::RequestBinding("task_revision"))?;
    let scope_id = eliot_receipts::WorkScopeId::new(record.admission.scope_id.clone())
        .map_err(OrientationAdmissionError::Receipt)?;
    let core = &record.decision_receipt.core;
    if core.artifacts != orientation_admission_expected_artifacts(record)?
        || core.kind != ReceiptKind::Operation
        || core.request.metadata != record.request
        || core.request.state_fence != record.request.state_fence
        || core.operation.operation_id != record.operation_id
        || core.operation.request_id != record.request.request_id
        || core.operation.idempotency_key != record.request.request_id.as_str()
        || core.operation.operation_kind != ORIENTATION_ADMISSION_OPERATION_KIND
        || core.operation.effect != EffectClass::Candidate
        || core.operation.state_fence != record.request.state_fence
        || core.work_scope.scope_id != scope_id
        || core.work_scope.product_id != record.request.product_id
        || core.work_scope.state_fence != record.request.state_fence
        || core.task.as_ref().is_none_or(|task| {
            task.task_id != *task_id
                || task.task_revision != task_revision
                || task.state_fence != record.request.state_fence
        })
        || core.session.as_ref().is_none_or(|session| {
            session.session_id != *session_id
                || session.state_fence != record.request.state_fence
        })
        || core.causal.state_fence != record.request.state_fence
        || core.causal.parent_receipt_id.is_some()
        || !core.causal.predecessor_receipt_ids.is_empty()
        || core.authority.authority_owner != ORIENTATION_ADMISSION_AUTHORITY_OWNER
        || core.authority.allowed_effect != EffectClass::Candidate
        || core.authority.proof_ceiling != ProofCeiling::CandidateArtifact
        || core.disposition
            != (ReceiptDisposition::Success {
                proof: ProofCeiling::CandidateArtifact,
            })
    {
        return Err(OrientationAdmissionError::RequestBinding(
            "decision_receipt_binding",
        ));
    }
    Ok(())
}

/// Operation-kind discriminator recorded by the original admission receipt.
pub const ORIENTATION_ADMISSION_OPERATION_KIND: &str = "orientation-job-admission";

const ORIENTATION_ADMISSION_AUTHORITY_OWNER: &str =
    "owner:eliot-governor/orientation-admission";

/// Decode the original source-bound Orientation job in the Governor owner,
/// validating its exact contract identity, bytes, bundle, and admission.
pub fn decode_admitted_orientation_job_source(
    reference: &OpaqueContentRef,
    original_bytes: &[u8],
    bundle: &DreamInputBundle,
    admission: &DreamJobAdmission,
) -> Result<AdmittedOrientationJob, OrientationAdmissionError> {
    reference
        .validate("admitted_orientation_job")
        .map_err(|source| OrientationAdmissionError::SourceReference {
            field: "admitted_orientation_job",
            source,
        })?;
    reference
        .validate_original_bytes(original_bytes)
        .map_err(|source| OrientationAdmissionError::SourceReference {
            field: "admitted_orientation_job",
            source,
        })?;
    let expected_contract =
        eliot_dreamer_orientation::input::admitted_orientation_job_contract_identity()
            .map_err(OrientationAdmissionError::ContractIdentity)?;
    if reference.contract != expected_contract {
        return Err(OrientationAdmissionError::SourceContractIdentity(
            "admitted_orientation_job",
        ));
    }
    let admitted: AdmittedOrientationJob = serde_json::from_slice(original_bytes).map_err(
        |source| OrientationAdmissionError::NativeDecode {
            field: "admitted_orientation_job",
            source,
        },
    )?;
    let canonical = canonical_bytes(&admitted).map_err(OrientationAdmissionError::Contract)?;
    if canonical.as_slice() != original_bytes {
        return Err(OrientationAdmissionError::SourceCanonicalMismatch(
            "admitted_orientation_job",
        ));
    }
    admitted
        .validate_for(bundle)
        .map_err(OrientationAdmissionError::Orientation)?;
    if admitted.job != *admission {
        return Err(OrientationAdmissionError::RequestBinding(
            "admitted_orientation_job_admission",
        ));
    }
    Ok(admitted)
}

fn validate_orientation_original_source<T: Serialize>(
    source: &OrientationOriginalSourceBytes,
    value: &T,
    field: &'static str,
) -> Result<(), OrientationAdmissionError> {
    source
        .reference
        .validate(field)
        .map_err(|source| OrientationAdmissionError::SourceReference { field, source })?;
    source
        .reference
        .validate_original_bytes(&source.canonical_bytes)
        .map_err(|source| OrientationAdmissionError::SourceReference { field, source })?;
    let canonical = canonical_bytes(value).map_err(OrientationAdmissionError::Contract)?;
    if source.canonical_bytes != canonical {
        return Err(OrientationAdmissionError::SourceCanonicalMismatch(field));
    }
    Ok(())
}

struct OrientationAdmissionAuthorization {
    task_binding: TaskBinding,
    session_binding: SessionBinding,
    authority_id: ContractId,
    policy_snapshot_id: String,
    policy_snapshot_digest: String,
}

struct OrientationTaskAuthorization {
    task_binding: TaskBinding,
    authority_id: ContractId,
}

struct OrientationPolicyAuthorization {
    snapshot_id: String,
    snapshot_digest: String,
}

/// Admit original Orientation inputs using the currently recovered Governor
/// owners, then issue one CandidateArtifact decision receipt for that exact
/// tuple. No source or Store write receipt is converted into this decision.
pub fn admit_orientation_job<P: crate::composition::KernelGenerationPort + ?Sized>(
    composition: &crate::composition::GovernorComposition<P>,
    input: OrientationAdmissionInput<'_>,
) -> Result<OrientationAdmissionRecord, OrientationAdmissionError> {
    validate_orientation_admission_input(&input)?;
    let authorization = authorize_orientation_job(
        composition,
        input.request,
        input.owner_clock,
        input.admission,
    )?;
    let decision_receipt = issue_orientation_admission_receipt(&input, &authorization)?;

    let record = OrientationAdmissionRecord {
        schema_version: 1,
        request: input.request.clone(),
        operation_id: input.operation_id.clone(),
        job_input: input.job_input.clone(),
        admission: input.admission.clone(),
        bundle: input.bundle.clone(),
        admitted_orientation_job: input.admitted_orientation_job.clone(),
        original_sources: input.sources.clone(),
        policy_snapshot_id: authorization.policy_snapshot_id,
        policy_snapshot_digest: authorization.policy_snapshot_digest,
        decision_receipt,
    };
    record.validate()?;
    Ok(record)
}

fn issue_orientation_admission_receipt(
    input: &OrientationAdmissionInput<'_>,
    authorization: &OrientationAdmissionAuthorization,
) -> Result<ReceiptEnvelope, OrientationAdmissionError> {
    let request_bytes = eliot_contracts::canonical_json_bytes(input.request)
        .map_err(|_| OrientationAdmissionError::RequestBinding("request_canonical_bytes"))?;
    let mut artifact_ids = std::collections::BTreeSet::new();
    let mut artifacts = Vec::with_capacity(6);
    for original in [
        &input.sources.job_input,
        &input.sources.admission,
        &input.sources.bundle,
        &input.sources.admitted_orientation_job,
    ] {
        let artifact_id = original
            .reference
            .artifact_id
            .clone()
            .ok_or(OrientationAdmissionError::RequestBinding(
                "source_artifact_id",
            ))?;
        if !artifact_ids.insert(artifact_id.as_str().to_owned()) {
            return Err(OrientationAdmissionError::DuplicateArtifact);
        }
        artifacts.push(ArtifactBinding {
            artifact_id,
            sha256: original.reference.sha256.clone(),
            role: ReceiptKind::Artifact,
            source_revision: Some(original.reference.source_revision.clone()),
        });
    }
    append_admission_receipt_artifact(
        &mut artifacts,
        &mut artifact_ids,
        "orientation-request-metadata",
        digest_hex(&request_bytes),
        Some(input.request.request_id.as_str().to_owned()),
    )?;
    append_admission_receipt_artifact(
        &mut artifacts,
        &mut artifact_ids,
        "orientation-policy-snapshot",
        authorization.policy_snapshot_digest.clone(),
        Some(authorization.policy_snapshot_id.clone()),
    )?;

    let scope_id = eliot_receipts::WorkScopeId::new(input.admission.scope_id.clone())
        .map_err(OrientationAdmissionError::Receipt)?;
    ReceiptEnvelope::issue(ReceiptCore {
        contract: eliot_receipts::contract_identity()
            .map_err(OrientationAdmissionError::Receipt)?,
        kind: ReceiptKind::Operation,
        work_scope: WorkScopeBinding {
            scope_id,
            product_id: input.request.product_id.clone(),
            resource_generation: input.request.state_fence.resource_generation,
            state_fence: input.request.state_fence.clone(),
        },
        task: Some(authorization.task_binding.clone()),
        session: Some(authorization.session_binding.clone()),
        causal: CausalBinding {
            state_fence: input.request.state_fence.clone(),
            transaction_sequence: TransactionSequence::genesis(),
            parent_receipt_id: None,
            predecessor_receipt_ids: Vec::new(),
        },
        request: RequestBinding {
            metadata: input.request.clone(),
            state_fence: input.request.state_fence.clone(),
        },
        operation: OperationBinding {
            operation_id: input.operation_id.clone(),
            request_id: input.request.request_id.clone(),
            idempotency_key: input.request.request_id.as_str().to_owned(),
            operation_kind: ORIENTATION_ADMISSION_OPERATION_KIND.to_owned(),
            effect: EffectClass::Candidate,
            state_fence: input.request.state_fence.clone(),
        },
        authority: AuthorityBinding {
            authority_id: authorization.authority_id.clone(),
            authority_owner: ORIENTATION_ADMISSION_AUTHORITY_OWNER.to_owned(),
            authority_epoch: input.request.state_fence.authority_epoch.clone(),
            state_fence: input.request.state_fence.clone(),
            allowed_effect: EffectClass::Candidate,
            proof_ceiling: ProofCeiling::CandidateArtifact,
        },
        artifacts,
        verifier: None,
        problem: None,
        coordination: None,
        disposition: ReceiptDisposition::Success {
            proof: ProofCeiling::CandidateArtifact,
        },
    })
    .map_err(OrientationAdmissionError::Receipt)
}

fn append_admission_receipt_artifact(
    artifacts: &mut Vec<ArtifactBinding>,
    artifact_ids: &mut std::collections::BTreeSet<String>,
    id: &'static str,
    sha256: String,
    source_revision: Option<String>,
) -> Result<(), OrientationAdmissionError> {
    let artifact_id = ArtifactId::new(id)
        .map_err(|_| OrientationAdmissionError::RequestBinding("receipt_artifact"))?;
    if !artifact_ids.insert(artifact_id.as_str().to_owned()) {
        return Err(OrientationAdmissionError::DuplicateArtifact);
    }
    artifacts.push(ArtifactBinding {
        artifact_id,
        sha256,
        role: ReceiptKind::Artifact,
        source_revision,
    });
    Ok(())
}

fn validate_orientation_admission_input(
    input: &OrientationAdmissionInput<'_>,
) -> Result<(), OrientationAdmissionError> {
    input
        .request
        .validate()
        .map_err(|_| OrientationAdmissionError::RequestBinding("request_metadata"))?;
    input
        .owner_clock
        .validate()
        .map_err(|_| OrientationAdmissionError::RequestBinding("request_clock"))?;
    if input.owner_clock != &input.request.clock {
        return Err(OrientationAdmissionError::RequestBinding("owner_clock"));
    }
    input
        .job_input
        .validate()
        .map_err(OrientationAdmissionError::Contract)?;
    input
        .admission
        .validate()
        .map_err(OrientationAdmissionError::Contract)?;
    input
        .bundle
        .validate()
        .map_err(OrientationAdmissionError::Contract)?;
    input
        .admitted_orientation_job
        .validate_for(input.bundle)
        .map_err(OrientationAdmissionError::Orientation)?;
    validate_orientation_original_source(
        &input.sources.job_input,
        input.job_input,
        "job_input",
    )?;
    validate_orientation_original_source(
        &input.sources.admission,
        input.admission,
        "admission",
    )?;
    validate_orientation_original_source(
        &input.sources.bundle,
        input.bundle,
        "bundle",
    )?;
    validate_orientation_original_source(
        &input.sources.admitted_orientation_job,
        input.admitted_orientation_job,
        "admitted_orientation_job",
    )?;

    let task_id = input
        .request
        .task_id
        .as_ref()
        .ok_or(OrientationAdmissionError::RequestBinding("task_id"))?;
    let session_id = input
        .request
        .session_id
        .as_ref()
        .ok_or(OrientationAdmissionError::RequestBinding("session_id"))?;
    if input.admission.job_class != JobClass::Orientation
        || input.job_input.job_class != JobClass::Orientation
        || input.admission.operation_id != input.operation_id.as_str()
        || input.admission.idempotency_key != input.request.request_id.as_str()
        || input.admission.task_id != task_id.as_str()
        || input.admission.scope_id != input.bundle.scope_id
        || input.admission.state_fence != input.request.state_fence
        || input.job_input.job_id != input.admission.canonical_id()
        || input.job_input.requester != input.admission.requester.principal
        || input.job_input.privacy_profile != input.admission.privacy_profile
        || input.job_input.task_id.as_deref() != Some(task_id.as_str())
        || input.job_input.scope_id != input.admission.scope_id
        || input.job_input.state_fence != input.admission.state_fence
        || input.bundle.job_id != input.admission.canonical_id()
        || input.bundle.task_id != input.admission.task_id
        || input.bundle.scope_id != input.admission.scope_id
        || input.bundle.state_fence != input.admission.state_fence
        || input.bundle.manifest_digest != input.admission.frozen_manifest_digest
        || input.admitted_orientation_job.job != *input.admission
        || input.admission.requester.session.as_deref() != Some(session_id.as_str())
    {
        return Err(OrientationAdmissionError::RequestBinding(
            "admission_job_bundle",
        ));
    }
    Ok(())
}

fn authorize_orientation_job<P: crate::composition::KernelGenerationPort + ?Sized>(
    composition: &crate::composition::GovernorComposition<P>,
    request: &RequestMetadata,
    owner_clock: &ClockReading,
    admission: &DreamJobAdmission,
) -> Result<OrientationAdmissionAuthorization, OrientationAdmissionError> {
    use crate::composition::CompositionReadiness;

    if composition.readiness() != CompositionReadiness::Ready {
        return Err(OrientationAdmissionError::NotReady);
    }
    if composition.kernel_snapshot().state_fence() != &request.state_fence {
        return Err(OrientationAdmissionError::RequestBinding("kernel_fence"));
    }
    let task = authorize_orientation_task(composition, request)?;
    authorize_orientation_scope(composition, admission, &request.state_fence)?;
    let policy = current_orientation_policy(composition, admission, &request.state_fence)?;
    let session = authorize_orientation_session(
        composition,
        request,
        owner_clock,
        &policy.snapshot_id,
    )?;
    Ok(OrientationAdmissionAuthorization {
        task_binding: task.task_binding,
        session_binding: session,
        authority_id: task.authority_id,
        policy_snapshot_id: policy.snapshot_id,
        policy_snapshot_digest: policy.snapshot_digest,
    })
}

fn authorize_orientation_task<P: crate::composition::KernelGenerationPort + ?Sized>(
    composition: &crate::composition::GovernorComposition<P>,
    request: &RequestMetadata,
) -> Result<OrientationTaskAuthorization, OrientationAdmissionError> {
    let task_id = request
        .task_id
        .as_ref()
        .ok_or(OrientationAdmissionError::RequestBinding("task_id"))?;
    let fence = &request.state_fence;
    let owners = composition.owners();
    let task = owners
        .task
        .task(task_id)
        .ok_or(OrientationAdmissionError::OwnerUnavailable("task"))?;
    let task_revision = TaskRevision::new(task.revision)
        .map_err(|_| OrientationAdmissionError::Authorization("task_revision"))?;
    if task.task_id != *task_id
        || task.state_fence != *fence
        || fence.task_revision.as_ref() != Some(&task_revision)
        || task.revision == 0
        || task.project_ref != request.product_id.as_str()
        || !matches!(
            task.state,
            TaskState::ActionAuthorized | TaskState::Executing | TaskState::Verifying
        )
    {
        return Err(OrientationAdmissionError::Authorization("task"));
    }
    let authority_ref = owners
        .task
        .events()
        .iter()
        .filter_map(|event| {
            if event.task_id != *task_id
                || event.to != TaskState::ActionAuthorized
                || !event
                    .authority_epoch
                    .is_same_authority(&fence.authority_epoch)
            {
                return None;
            }
            match event.command.as_ref()? {
                TaskCommand::AuthorizeAction { authority_ref, .. } => {
                    Some((event.sequence, authority_ref.as_str()))
                }
                _ => None,
            }
        })
        .max_by_key(|(sequence, _)| *sequence)
        .map(|(_, authority_ref)| authority_ref.to_owned())
        .ok_or(OrientationAdmissionError::Authorization(
            "task_action_authority",
        ))?;
    let authority_id = ContractId::new(authority_ref)
        .map_err(|_| OrientationAdmissionError::Authorization("task_action_authority_id"))?;
    Ok(OrientationTaskAuthorization {
        task_binding: TaskBinding {
            task_id: task_id.clone(),
            task_revision,
            state_fence: fence.clone(),
        },
        authority_id,
    })
}

fn authorize_orientation_scope<P: crate::composition::KernelGenerationPort + ?Sized>(
    composition: &crate::composition::GovernorComposition<P>,
    admission: &DreamJobAdmission,
    fence: &StateFence,
) -> Result<(), OrientationAdmissionError> {
    use eliot_workscope::ScopeBindingDisposition;

    let owners = composition.owners();
    let scope_owner = owners
        .work_scope
        .as_ref()
        .ok_or(OrientationAdmissionError::OwnerUnavailable("work_scope"))?;
    let current_scope = scope_owner
        .read_current(fence)
        .map_err(|_| OrientationAdmissionError::Authorization("work_scope_fence"))?;
    if current_scope.binding.scope.scope_ref != admission.scope_id
        || current_scope.guard_receipt.disposition != ScopeBindingDisposition::Matched
        || current_scope.guard_receipt.expected_scope_ref != admission.scope_id
        || current_scope.guard_receipt.observed_scope_ref != admission.scope_id
    {
        return Err(OrientationAdmissionError::Authorization("work_scope_binding"));
    }
    Ok(())
}

fn current_orientation_policy<P: crate::composition::KernelGenerationPort + ?Sized>(
    composition: &crate::composition::GovernorComposition<P>,
    admission: &DreamJobAdmission,
    fence: &StateFence,
) -> Result<OrientationPolicyAuthorization, OrientationAdmissionError> {
    let owners = composition.owners();
    let policy = owners
        .policy
        .as_ref()
        .ok_or(OrientationAdmissionError::OwnerUnavailable("policy"))?;
    if policy.state_fence() != fence
        || policy.snapshot().state_fence != *fence
        || policy.snapshot().scope_id != admission.scope_id
    {
        return Err(OrientationAdmissionError::Authorization("policy_fence"));
    }
    policy
        .snapshot()
        .validate()
        .map_err(|_| OrientationAdmissionError::Authorization("policy_snapshot"))?;
    let policy_snapshot_digest = policy
        .snapshot_digest()
        .to_owned();
    if policy
        .rebuilt_digest()
        .map_err(|_| OrientationAdmissionError::Authorization("policy_digest"))?
        != policy_snapshot_digest
        || policy
            .rebuilt_envelope_digest()
            .map_err(|_| OrientationAdmissionError::Authorization("policy_envelope"))?
            != policy.canonical_digest()
        || !is_hex64_lower(&policy_snapshot_digest)
    {
        return Err(OrientationAdmissionError::Authorization("policy_commitment"));
    }
    Ok(OrientationPolicyAuthorization {
        snapshot_id: policy.snapshot().snapshot_id.clone(),
        snapshot_digest: policy_snapshot_digest,
    })
}

fn authorize_orientation_session<P: crate::composition::KernelGenerationPort + ?Sized>(
    composition: &crate::composition::GovernorComposition<P>,
    request: &RequestMetadata,
    owner_clock: &ClockReading,
    policy_snapshot_id: &str,
) -> Result<SessionBinding, OrientationAdmissionError> {
    let task_id = request
        .task_id
        .as_ref()
        .ok_or(OrientationAdmissionError::RequestBinding("task_id"))?;
    let session_id = request
        .session_id
        .as_ref()
        .ok_or(OrientationAdmissionError::RequestBinding("session_id"))?;
    let fence = &request.state_fence;
    let now = owner_clock
        .valid_time_ms
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(OrientationAdmissionError::Authorization("owner_clock"))?;
    let owners = composition.owners();
    let session = owners
        .session
        .session(session_id)
        .ok_or(OrientationAdmissionError::OwnerUnavailable("session"))?;
    if session.session_id != *session_id
        || session.status != eliot_session::SessionState::Active
        || session.state_fence != *fence
        || !session
            .authority_epoch
            .is_same_authority(&fence.authority_epoch)
        || session.task_scope.as_deref() != Some(task_id.as_str())
        || session.project_scope != request.product_id.as_str()
        || session.policy_snapshot_id != policy_snapshot_id
        || session.started_at == 0
        || session.heartbeat_at < session.started_at
        || session.heartbeat_at > now
        || session.expires_at < session.heartbeat_at
        || now > session.expires_at
    {
        return Err(OrientationAdmissionError::Authorization("active_session"));
    }
    Ok(SessionBinding {
        session_id: session_id.clone(),
        authority_epoch: session.authority_epoch.clone(),
        state_fence: fence.clone(),
    })
}

/// Typed failure while admitting the original Orientation cue source readback.
#[derive(Debug, Error)]
pub enum OrientationCueBindingsSourceError {
    /// The named read was missing, stale, or blocked.
    #[error("Orientation cue source read is not current: {0}")]
    NotCurrent(&'static str),
    /// The read did not contain the complete authenticated current tuple.
    #[error("Orientation cue source read is incomplete")]
    IncompleteRead,
    /// The immutable source row was not the exact Orientation cue role/owner/schema.
    #[error("Orientation cue source identity does not match")]
    IdentityMismatch,
    /// The exact stored row or read receipt failed its native validation.
    #[error("Orientation cue source read is invalid: {0}")]
    InvalidRead(StoreError),
    /// The closed owner projection did not decode as its native read type.
    #[error("Orientation cue source projection could not be decoded: {0}")]
    ProjectionDecode(serde_json::Error),
    /// The native cue source projection did not decode as its closed type.
    #[error("Orientation cue source could not be decoded: {0}")]
    SourceDecode(serde_json::Error),
    /// The stored native source failed its own contract validation.
    #[error("Orientation cue source is invalid: {0}")]
    InvalidSource(CueContractError),
    /// The source's retained original A-12 result did not decode as its native type.
    #[error("Orientation cue A-12 result could not be decoded: {0}")]
    A12Decode(serde_json::Error),
    /// The retained A-12 result could not be canonically encoded.
    #[error("Orientation cue A-12 result could not be canonicalized: {0}")]
    A12Canonicalization(serde_json::Error),
    /// The retained original A-12 result differs from its native derivation.
    #[error("Orientation cue A-12 result binding failed at {0}")]
    A12Binding(&'static str),
    /// Native A-12 derivation rejected the retained original inputs.
    #[error("native A-12 cue derivation failed: {0}")]
    A12(CueBindingError),
    /// The original source does not bind the admitted runtime task, scope, or fence.
    #[error("Orientation cue source is not bound to the live task context: {0}")]
    RuntimeBinding(&'static str),
}

/// Derives A-12 and the closed A-10 snapshot from original retained inputs,
/// then issues one bounded Governor admission receipt for that exact result.
///
/// The C0-02 receipt starts an independent genesis chain because the original
/// TaskController claim carries no C0-02 receipt parent. The receipt claims no
/// parent or predecessor and is never linked to the later Store write receipt.
pub fn admit_orientation_cue_bindings<P: crate::composition::KernelGenerationPort + ?Sized>(
    composition: &crate::composition::GovernorComposition<P>,
    input: OrientationCueAdmissionInput<'_>,
) -> Result<OrientationCueBindingsSource, OrientationCueAdmissionError> {
    use crate::composition::CompositionReadiness;
    use eliot_observation::CandidateDisposition as ObservationCandidateDisposition;
    use eliot_workscope::ScopeBindingDisposition;

    if composition.readiness() != CompositionReadiness::Ready {
        return Err(OrientationCueAdmissionError::NotReady);
    }
    input
        .request
        .validate()
        .map_err(|_| OrientationCueAdmissionError::RequestBinding("request_metadata"))?;
    input
        .owner_clock
        .validate()
        .map_err(OrientationCueAdmissionError::RequestClock)?;
    if input.owner_clock != &input.request.clock {
        return Err(OrientationCueAdmissionError::OwnerClock(
            "request metadata clock mismatch",
        ));
    }
    let task_id = input
        .request
        .task_id
        .as_ref()
        .ok_or(OrientationCueAdmissionError::RequestBinding("task_id"))?;
    let session_id = input
        .request
        .session_id
        .as_ref()
        .ok_or(OrientationCueAdmissionError::RequestBinding("session_id"))?;
    let fence = &input.request.state_fence;
    if composition.kernel_snapshot().state_fence() != fence {
        return Err(OrientationCueAdmissionError::RequestBinding("kernel_fence"));
    }
    if input.profile.state_fence != *fence
        || input.observation.state_fence != *fence
        || input.denominator.source_revision == 0
    {
        return Err(OrientationCueAdmissionError::RequestBinding("source_fence"));
    }
    let scope_id = input.profile.scope_id.clone();

    let owners = composition.owners();
    let task = owners
        .task
        .task(task_id)
        .ok_or(OrientationCueAdmissionError::OwnerUnavailable("task"))?;
    let expected_task_revision = TaskRevision::new(task.revision)
        .map_err(|_| OrientationCueAdmissionError::Authorization("task_revision"))?;
    if task.task_id != *task_id
        || task.state_fence != *fence
        || fence.task_revision.as_ref() != Some(&expected_task_revision)
        || task.revision == 0
        || task.project_ref != input.request.product_id.as_str()
        || !matches!(
            task.state,
            TaskState::ActionAuthorized | TaskState::Executing | TaskState::Verifying
        )
    {
        return Err(OrientationCueAdmissionError::Authorization("task"));
    }

    let scope_owner = owners
        .work_scope
        .as_ref()
        .ok_or(OrientationCueAdmissionError::OwnerUnavailable("work_scope"))?;
    let current_scope = scope_owner
        .read_current(fence)
        .map_err(|_| OrientationCueAdmissionError::Authorization("work_scope_fence"))?;
    if current_scope.binding.scope.scope_ref != scope_id.as_str()
        || current_scope.guard_receipt.disposition != ScopeBindingDisposition::Matched
        || current_scope.guard_receipt.expected_scope_ref != scope_id.as_str()
        || current_scope.guard_receipt.observed_scope_ref != scope_id.as_str()
    {
        return Err(OrientationCueAdmissionError::Authorization("work_scope_binding"));
    }

    let policy = owners
        .policy
        .as_ref()
        .ok_or(OrientationCueAdmissionError::OwnerUnavailable("policy"))?;
    if policy.state_fence() != fence
        || policy.snapshot().state_fence != *fence
        || policy.snapshot().scope_id != scope_id.as_str()
    {
        return Err(OrientationCueAdmissionError::Authorization("policy_fence"));
    }
    policy
        .snapshot()
        .validate()
        .map_err(|_| OrientationCueAdmissionError::Authorization("policy_snapshot"))?;
    if policy
        .rebuilt_digest()
        .map_err(|_| OrientationCueAdmissionError::Authorization("policy_digest"))?
        != policy.snapshot_digest()
        || policy
            .rebuilt_envelope_digest()
            .map_err(|_| OrientationCueAdmissionError::Authorization("policy_envelope"))?
            != policy.canonical_digest()
    {
        return Err(OrientationCueAdmissionError::Authorization("policy_commitment"));
    }

    let now = input
        .owner_clock
        .valid_time_ms
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(OrientationCueAdmissionError::RequestBinding("valid_time"))?;
    let session = owners
        .session
        .session(session_id)
        .ok_or(OrientationCueAdmissionError::OwnerUnavailable("session"))?;
    if session.session_id != *session_id
        || session.status != eliot_session::SessionState::Active
        || session.state_fence != *fence
        || !session
            .authority_epoch
            .is_same_authority(&fence.authority_epoch)
        || session.task_scope.as_deref() != Some(task_id.as_str())
        || session.project_scope != input.request.product_id.as_str()
        || session.policy_snapshot_id != policy.snapshot().snapshot_id
        || session.started_at == 0
        || session.heartbeat_at < session.started_at
        || session.heartbeat_at > now
        || session.expires_at < session.heartbeat_at
        || now > session.expires_at
    {
        return Err(OrientationCueAdmissionError::Authorization("active_session"));
    }

    let authority_ref = owners
        .task
        .events()
        .iter()
        .filter_map(|event| {
            if event.task_id != *task_id
                || event.to != TaskState::ActionAuthorized
                || !event
                    .authority_epoch
                    .is_same_authority(&fence.authority_epoch)
            {
                return None;
            }
            match event.command.as_ref()? {
                TaskCommand::AuthorizeAction { authority_ref, .. } => {
                    Some((event.sequence, authority_ref.as_str()))
                }
                _ => None,
            }
        })
        .max_by_key(|(sequence, _)| *sequence)
        .map(|(_, authority_ref)| authority_ref.to_owned())
        .ok_or(OrientationCueAdmissionError::Authorization(
            "task_action_authority",
        ))?;
    let authority_id = ContractId::new(authority_ref)
        .map_err(|_| OrientationCueAdmissionError::Authorization("task_action_authority_id"))?;

    input
        .observation
        .validate()
        .map_err(OrientationCueAdmissionError::ObservationReceipt)?;
    let observation_entry = owners
        .observation
        .get(&input.observation.idempotency_key)
        .ok_or(OrientationCueAdmissionError::ObservationBinding(
            "not retained by the current observation journal",
        ))?;
    if observation_entry.request_digest != input.observation.request_digest
        || !matches!(
            &observation_entry.result,
            ObservationAdmissionResult::Accepted { receipt } if receipt == input.observation
        )
        || input.observation.candidate_disposition != ObservationCandidateDisposition::TaskBound
    {
        return Err(OrientationCueAdmissionError::ObservationBinding(
            "not the exact accepted task-bound journal result",
        ));
    }
    let selection = input
        .observation
        .task_selection
        .as_ref()
        .ok_or(OrientationCueAdmissionError::ObservationBinding(
            "task selection is absent",
        ))?;
    if selection.task_ref != task_id.as_str()
        || selection.task_revision != task.revision
        || selection.work_scope_ref != scope_id.as_str()
        || selection.is_contaminated()
    {
        return Err(OrientationCueAdmissionError::ObservationBinding(
            "task selection does not bind the current task and scope",
        ));
    }

    let a12_result = derive_cue_binding_candidates(
        input.observation,
        input.touched,
        input.hint,
        input.profile,
    )
    .map_err(OrientationCueAdmissionError::A12)?;
    if a12_result.admission != *input.observation
        || a12_result.profile != *input.profile
        || a12_result.state_fence != *fence
    {
        return Err(OrientationCueAdmissionError::A12Binding(
            "original_inputs",
        ));
    }
    input
        .denominator
        .validate()
        .map_err(OrientationCueAdmissionError::A10)?;

    let policy_snapshot_id = policy.snapshot().snapshot_id.clone();
    let policy_snapshot_digest = eliot_cue_contracts::Digest::new(
        policy.snapshot_digest().to_owned(),
    )
    .map_err(|error| OrientationCueAdmissionError::Authorization("policy_digest_shape"))?;
    let a12_result_canonical_bytes = eliot_contracts::canonical_json_bytes(&a12_result)
        .map_err(|_| OrientationCueAdmissionError::A12Binding("canonical_result"))?;

    let mut artifacts = Vec::with_capacity(a12_result.candidates.len() + 2);
    artifacts.push(ArtifactBinding {
        artifact_id: ArtifactId::new("orientation-a12-result")
            .map_err(|_| OrientationCueAdmissionError::A12Binding("result_artifact_id"))?,
        sha256: a12_result.result_digest.as_str().to_owned(),
        role: ReceiptKind::Artifact,
        source_revision: None,
    });
    artifacts.push(ArtifactBinding {
        artifact_id: ArtifactId::new("orientation-policy-snapshot")
            .map_err(|_| OrientationCueAdmissionError::Authorization("policy_artifact_id"))?,
        sha256: policy_snapshot_digest.as_str().to_owned(),
        role: ReceiptKind::Artifact,
        source_revision: Some(policy_snapshot_id.clone()),
    });
    let mut artifact_ids = std::collections::BTreeSet::from([
        "orientation-a12-result".to_owned(),
        "orientation-policy-snapshot".to_owned(),
    ]);
    for candidate in &a12_result.candidates {
        candidate
            .validate()
            .map_err(OrientationCueAdmissionError::A12)?;
        if !artifact_ids.insert(candidate.binding_candidate_id.as_str().to_owned()) {
            return Err(OrientationCueAdmissionError::A12Binding(
                "candidate_artifact_identity",
            ));
        }
        artifacts.push(ArtifactBinding {
            artifact_id: ArtifactId::new(candidate.binding_candidate_id.as_str().to_owned())
                .map_err(|_| OrientationCueAdmissionError::A12Binding("candidate_artifact_id"))?,
            sha256: candidate.digest.as_str().to_owned(),
            role: ReceiptKind::Artifact,
            source_revision: None,
        });
    }

    let request_metadata = input.request.clone();
    let causal = CausalBinding {
        state_fence: fence.clone(),
        transaction_sequence: TransactionSequence::genesis(),
        parent_receipt_id: None,
        predecessor_receipt_ids: Vec::new(),
    };
    let task_binding = TaskBinding {
        task_id: task_id.clone(),
        task_revision: expected_task_revision,
        state_fence: fence.clone(),
    };
    let session_binding = SessionBinding {
        session_id: session_id.clone(),
        authority_epoch: session.authority_epoch.clone(),
        state_fence: fence.clone(),
    };
    let receipt = ReceiptEnvelope::issue(ReceiptCore {
        contract: eliot_receipts::contract_identity()
            .map_err(OrientationCueAdmissionError::Receipt)?,
        kind: ReceiptKind::Operation,
        work_scope: WorkScopeBinding {
            scope_id: scope_id.clone(),
            product_id: request_metadata.product_id.clone(),
            resource_generation: fence.resource_generation,
            state_fence: fence.clone(),
        },
        task: Some(task_binding),
        session: Some(session_binding),
        causal,
        request: RequestBinding {
            metadata: request_metadata.clone(),
            state_fence: fence.clone(),
        },
        operation: OperationBinding {
            operation_id: input.operation_id.clone(),
            request_id: request_metadata.request_id.clone(),
            idempotency_key: request_metadata.request_id.as_str().to_owned(),
            operation_kind: eliot_cue_contracts::ORIENTATION_CUE_ADMISSION_OPERATION_KIND
                .to_owned(),
            effect: EffectClass::Candidate,
            state_fence: fence.clone(),
        },
        authority: AuthorityBinding {
            authority_id,
            authority_owner: "owner:eliot-governor/orientation-cue-bindings".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
            allowed_effect: EffectClass::Candidate,
            proof_ceiling: ProofCeiling::CandidateArtifact,
        },
        artifacts,
        verifier: None,
        problem: None,
        coordination: None,
        disposition: ReceiptDisposition::Success {
            proof: ProofCeiling::CandidateArtifact,
        },
    })
    .map_err(OrientationCueAdmissionError::Receipt)?;

    let mut projections = Vec::with_capacity(a12_result.candidates.len());
    let mut used_touched_rows = std::collections::BTreeSet::new();
    for candidate in &a12_result.candidates {
        let mut matches = input.touched.iter().enumerate().filter(|(_, row)| {
            row.target == candidate.target
                && row.normalization.normalized.canonical.as_ref() == Some(&candidate.canonical)
        });
        let Some((index, row)) = matches.next() else {
        return Err(OrientationCueAdmissionError::A12Binding(
                "candidate_source_row_missing",
            ));
        };
        if matches.next().is_some() || !used_touched_rows.insert(index) {
            return Err(OrientationCueAdmissionError::A12Binding(
                "candidate_source_row_ambiguous",
            ));
        }
        if row.normalization.policy.profile != a12_result.profile.expected_normalization_profile
            || row.normalization.normalized.observed.context.task_id != *task_id
            || row.normalization.normalized.observed.context.scope_id != scope_id
            || row.normalization.normalized.observed.context.state_fence != *fence
        {
            return Err(OrientationCueAdmissionError::A12Binding(
                "candidate_source_row_context",
            ));
        }
        let admission = CueBindingAdmissionRef::new(
            receipt.identity.clone(),
            candidate.binding_candidate_id.clone(),
            candidate.digest.clone(),
            task_id.clone(),
            scope_id.clone(),
            fence.clone(),
        );
        let projection = AdmittedCueBindingProjection::new(
            candidate.clone(),
            row.normalization.normalized.clone(),
            admission,
        );
        projection
            .validate()
            .map_err(OrientationCueAdmissionError::A10)?;
        projections.push(projection);
    }

    let snapshot_candidate = eliot_cue_index::build_cue_snapshot_closed(
        &scope_id,
        input.snapshot_id.clone(),
        a12_result.profile.expected_normalization_profile.clone(),
        fence.clone(),
        &projections,
        input.relation_edges,
        input.registry_revision,
        input.denominator,
        input.weights,
    )
    .map_err(OrientationCueAdmissionError::A10)?;
    let source = OrientationCueBindingsSource {
        schema_version: OrientationCueBindingsSource::SCHEMA_VERSION,
        task_id: task_id.clone(),
        scope_id,
        state_fence: fence.clone(),
        source_revision: input.denominator.source_revision,
        snapshot_id: input.snapshot_id,
        normalization_profile: a12_result.profile.expected_normalization_profile.clone(),
        policy_snapshot_id,
        policy_snapshot_digest,
        a12_result_digest: a12_result.result_digest.clone(),
        a12_result_canonical_bytes,
        snapshot_candidate,
        admission_receipt: receipt,
    };
    source
        .validate()
        .map_err(OrientationCueAdmissionError::A10)?;
    Ok(source)
}

/// Decode the original owner-neutral supplier fields exactly, then run the
/// same native admission path as [`admit_orientation_cue_bindings`].
///
/// A successful decode must reproduce the input's canonical JSON bytes. This
/// rejects ignored/unknown members and prevents this adapter from silently
/// narrowing an upstream source value before A-12 or A-10 validation.
pub fn admit_orientation_cue_bindings_from_values<
    P: crate::composition::KernelGenerationPort + ?Sized,
>(
    composition: &crate::composition::GovernorComposition<P>,
    request: &RequestMetadata,
    owner_clock: &ClockReading,
    operation_id: &OperationId,
    values: OrientationCueAdmissionValuesV1<'_>,
) -> Result<OrientationCueBindingsSource, OrientationCueAdmissionError> {
    let observation = decode_exact_native(values.observation_admission, "observation_admission")?;
    let touched = values
        .touched
        .iter()
        .map(|value| decode_exact_native(value, "touched"))
        .collect::<Result<Vec<_>, _>>()?;
    let hint = values
        .hint
        .map(|value| decode_exact_native(value, "hint"))
        .transpose()?;
    let profile = decode_exact_native(values.binding_profile, "binding_profile")?;
    let snapshot_id = decode_exact_native(values.snapshot_id, "snapshot_id")?;
    let denominator = decode_exact_native(values.denominator, "denominator")?;
    let relation_edges = values
        .relation_edges
        .iter()
        .map(|value| decode_exact_native(value, "relation_edges"))
        .collect::<Result<Vec<_>, _>>()?;
    let weights = values
        .weights
        .iter()
        .map(|value| decode_exact_native(value, "weights"))
        .collect::<Result<Vec<_>, _>>()?;

    admit_orientation_cue_bindings(
        composition,
        OrientationCueAdmissionInput {
            request,
            owner_clock,
            operation_id,
            observation: &observation,
            touched: &touched,
            hint: hint.as_ref(),
            profile: &profile,
            snapshot_id,
            denominator: &denominator,
            relation_edges: &relation_edges,
            registry_revision: values.registry_revision,
            weights: &weights,
        },
    )
}

fn decode_exact_native<T>(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<T, OrientationCueAdmissionError>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let decoded: T = serde_json::from_value(value.clone()).map_err(|error| {
        OrientationCueAdmissionError::SourceFieldDecode {
            field,
            source: error,
        }
    })?;
    let original = eliot_contracts::canonical_json_bytes(value).map_err(|error| {
        OrientationCueAdmissionError::SourceFieldCanonicalization {
            field,
            source: error,
        }
    })?;
    let decoded_bytes = eliot_contracts::canonical_json_bytes(&decoded).map_err(|error| {
        OrientationCueAdmissionError::SourceFieldCanonicalization {
            field,
            source: error,
        }
    })?;
    if original != decoded_bytes {
        return Err(OrientationCueAdmissionError::SourceFieldMismatch(field));
    }
    Ok(decoded)
}

/// Typed source paired with the unchanged authenticated owner read.
#[derive(Clone, Debug)]
pub struct OrientationCueBindingsSourceReadback<'a> {
    source: OrientationCueBindingsSource,
    a12_result: CueBindingResult,
    read: &'a CampaignSourceRevisionRead,
}

impl<'a> OrientationCueBindingsSourceReadback<'a> {
    /// Admit one current named-read result for the separate Orientation cue role.
    pub fn from_read(
        read: &'a CampaignSourceRevisionRead,
    ) -> Result<Self, OrientationCueBindingsSourceError> {
        read.validate()
            .map_err(OrientationCueBindingsSourceError::InvalidRead)?;
        match read.status {
            CampaignSourceReadStatus::Current => {}
            CampaignSourceReadStatus::Stale => {
                return Err(OrientationCueBindingsSourceError::NotCurrent("stale"));
            }
            CampaignSourceReadStatus::Blocked => {
                return Err(OrientationCueBindingsSourceError::NotCurrent("blocked"));
            }
            CampaignSourceReadStatus::Missing => {
                return Err(OrientationCueBindingsSourceError::NotCurrent("missing"));
            }
        }
        let (Some(record), Some(head), Some(receipt)) =
            (&read.source, &read.current_head, &read.read_receipt)
        else {
            return Err(OrientationCueBindingsSourceError::IncompleteRead);
        };
        if !is_orientation_cue_source(record, head, receipt) {
            return Err(OrientationCueBindingsSourceError::IdentityMismatch);
        }
        let body: CampaignOwnerProjectionBody =
            serde_json::from_value(record.document.body.clone())
                .map_err(OrientationCueBindingsSourceError::ProjectionDecode)?;
        body.validate()
            .map_err(OrientationCueBindingsSourceError::InvalidRead)?;
        let source: OrientationCueBindingsSource = serde_json::from_value(body.projection)
            .map_err(OrientationCueBindingsSourceError::SourceDecode)?;
        source
            .validate()
            .map_err(OrientationCueBindingsSourceError::InvalidSource)?;
        if !orientation_cue_record_matches(record, &source) {
            return Err(OrientationCueBindingsSourceError::IdentityMismatch);
        }
        let a12_result: CueBindingResult = serde_json::from_slice(&source.a12_result_canonical_bytes)
            .map_err(OrientationCueBindingsSourceError::A12Decode)?;
        let canonical_a12 = eliot_contracts::canonical_json_bytes(&a12_result)
            .map_err(OrientationCueBindingsSourceError::A12Canonicalization)?;
        if canonical_a12 != source.a12_result_canonical_bytes
            || a12_result.result_digest != source.a12_result_digest
            || a12_result.profile.expected_normalization_profile != source.normalization_profile
        {
            return Err(OrientationCueBindingsSourceError::A12Binding(
                "canonical bytes, result digest, or normalization profile",
            ));
        }
        let derived = derive_cue_binding_candidates(
            &a12_result.admission,
            &a12_result.touched,
            a12_result.hint.as_ref(),
            &a12_result.profile,
        )
        .map_err(OrientationCueBindingsSourceError::A12)?;
        if derived != a12_result {
            return Err(OrientationCueBindingsSourceError::A12Binding(
                "retained result differs from native owner derivation",
            ));
        }
        Ok(Self {
            source,
            a12_result,
            read,
        })
    }

    /// Bind the independently published source to the exact admitted runtime context.
    pub fn validate_for_runtime(
        &self,
        task_id: &str,
        scope_id: &str,
        state_fence: &StateFence,
    ) -> Result<(), OrientationCueBindingsSourceError> {
        self.read
            .validate()
            .map_err(OrientationCueBindingsSourceError::InvalidRead)?;
        if self.read.status != CampaignSourceReadStatus::Current {
            return Err(OrientationCueBindingsSourceError::NotCurrent("not current"));
        }
        self.source
            .validate()
            .map_err(OrientationCueBindingsSourceError::InvalidSource)?;
        let record = self
            .read
            .source
            .as_ref()
            .ok_or(OrientationCueBindingsSourceError::IncompleteRead)?;
        if !is_orientation_cue_record(record)
            || !orientation_cue_record_matches(record, &self.source)
        {
            return Err(OrientationCueBindingsSourceError::IdentityMismatch);
        }
        if self.source.task_id.as_str() != task_id {
            return Err(OrientationCueBindingsSourceError::RuntimeBinding("task_id"));
        }
        if self.source.scope_id.as_str() != scope_id {
            return Err(OrientationCueBindingsSourceError::RuntimeBinding("scope_id"));
        }
        if &self.source.state_fence != state_fence
            || &record.recorded_state_fence != state_fence
            || &self.read.read_state_fence != state_fence
        {
            return Err(OrientationCueBindingsSourceError::RuntimeBinding("state_fence"));
        }
        Ok(())
    }

    /// Borrow the typed cue source decoded from the original owner row.
    #[must_use]
    pub const fn source(&self) -> &OrientationCueBindingsSource {
        &self.source
    }

    /// Borrow the complete original A-12 result decoded and re-derived from its retained bytes.
    #[must_use]
    pub const fn a12_result(&self) -> &CueBindingResult {
        &self.a12_result
    }

    /// Borrow the unchanged authenticated owner readback.
    #[must_use]
    pub const fn read(&self) -> &'a CampaignSourceRevisionRead {
        self.read
    }

    /// Return the unchanged original record and authenticated read proof.
    pub fn owner_evidence(
        &self,
    ) -> Result<(&CampaignSourceRecord, &CampaignSourceHead, &CampaignOwnerReadReceipt, &StateFence), OrientationCueBindingsSourceError> {
        let record = self
            .read
            .source
            .as_ref()
            .ok_or(OrientationCueBindingsSourceError::IncompleteRead)?;
        let head = self
            .read
            .current_head
            .as_ref()
            .ok_or(OrientationCueBindingsSourceError::IncompleteRead)?;
        let receipt = self
            .read
            .read_receipt
            .as_ref()
            .ok_or(OrientationCueBindingsSourceError::IncompleteRead)?;
        Ok((record, head, receipt, &self.read.read_state_fence))
    }
}

impl<'a> OrientationClassificationSourceReadback<'a> {
    /// Admit one current named-read result for the separate Orientation role.
    pub fn from_read(
        read: &'a CampaignSourceRevisionRead,
    ) -> Result<Self, OrientationClassificationSourceError> {
        read.validate()
            .map_err(OrientationClassificationSourceError::InvalidRead)?;
        match read.status {
            CampaignSourceReadStatus::Current => {}
            CampaignSourceReadStatus::Stale => {
                return Err(OrientationClassificationSourceError::NotCurrent("stale"));
            }
            CampaignSourceReadStatus::Blocked => {
                return Err(OrientationClassificationSourceError::NotCurrent("blocked"));
            }
            CampaignSourceReadStatus::Missing => {
                return Err(OrientationClassificationSourceError::NotCurrent("missing"));
            }
        }
        let (Some(record), Some(head), Some(receipt)) =
            (&read.source, &read.current_head, &read.read_receipt)
        else {
            return Err(OrientationClassificationSourceError::IncompleteRead);
        };
        if !is_orientation_source(record, head, receipt) {
            return Err(OrientationClassificationSourceError::IdentityMismatch);
        }
        let body: CampaignOwnerProjectionBody =
            serde_json::from_value(record.document.body.clone())
                .map_err(OrientationClassificationSourceError::ProjectionDecode)?;
        body.validate()
            .map_err(OrientationClassificationSourceError::InvalidRead)?;
        let profile: OrientationClassificationProfile = serde_json::from_value(body.projection)
            .map_err(OrientationClassificationSourceError::ProfileDecode)?;
        profile.validate().map_err(|error| {
            OrientationClassificationSourceError::InvalidProfile(error)
        })?;
        if !orientation_record_matches_profile(record, &profile) {
            return Err(OrientationClassificationSourceError::IdentityMismatch);
        }
        Ok(Self { profile, read })
    }

    /// Bind the independently-published profile to the exact admitted runtime context.
    pub fn validate_for_runtime(
        &self,
        task_id: &str,
        scope_id: &str,
        state_fence: &StateFence,
    ) -> Result<(), OrientationClassificationSourceError> {
        self.read
            .validate()
            .map_err(OrientationClassificationSourceError::InvalidRead)?;
        if self.read.status != CampaignSourceReadStatus::Current {
            return Err(OrientationClassificationSourceError::NotCurrent(
                "not current",
            ));
        }
        self.profile.validate().map_err(|error| {
            OrientationClassificationSourceError::InvalidProfile(error)
        })?;
        let record = self
            .read
            .source
            .as_ref()
            .ok_or(OrientationClassificationSourceError::IncompleteRead)?;
        if !is_orientation_record(record)
            || !orientation_record_matches_profile(record, &self.profile)
        {
            return Err(OrientationClassificationSourceError::IdentityMismatch);
        }
        if self.profile.target.task_id.as_str() != task_id {
            return Err(OrientationClassificationSourceError::RuntimeBinding(
                "task_id",
            ));
        }
        if self.profile.target.scope_id.as_str() != scope_id {
            return Err(OrientationClassificationSourceError::RuntimeBinding(
                "scope_id",
            ));
        }
        if &self.profile.target.state_fence != state_fence
            || &record.recorded_state_fence != state_fence
            || &self.read.read_state_fence != state_fence
        {
            return Err(OrientationClassificationSourceError::RuntimeBinding(
                "state_fence",
            ));
        }
        Ok(())
    }

    /// Borrow the typed profile decoded from the original owner row.
    #[must_use]
    pub const fn profile(&self) -> &OrientationClassificationProfile {
        &self.profile
    }

    /// Borrow the unchanged authenticated owner readback.
    #[must_use]
    pub const fn read(&self) -> &'a CampaignSourceRevisionRead {
        self.read
    }

    /// Return the unchanged original record and authenticated read proof.
    pub fn owner_evidence(
        &self,
    ) -> Result<
        (
            &CampaignSourceRecord,
            &CampaignSourceHead,
            &CampaignOwnerReadReceipt,
            &StateFence,
        ),
        OrientationClassificationSourceError,
    > {
        let record = self
            .read
            .source
            .as_ref()
            .ok_or(OrientationClassificationSourceError::IncompleteRead)?;
        let head = self
            .read
            .current_head
            .as_ref()
            .ok_or(OrientationClassificationSourceError::IncompleteRead)?;
        let receipt = self
            .read
            .read_receipt
            .as_ref()
            .ok_or(OrientationClassificationSourceError::IncompleteRead)?;
        Ok((record, head, receipt, &self.read.read_state_fence))
    }
}

fn is_orientation_source(
    record: &CampaignSourceRecord,
    head: &CampaignSourceHead,
    receipt: &CampaignOwnerReadReceipt,
) -> bool {
    is_orientation_record(record)
        && head.role == CampaignSourceRole::OrientationClassification
        && head.owner_id.as_str()
            == campaign_source_owner_id(CampaignSourceRole::OrientationClassification)
        && head.record_id == record.record_id
        && head.revision == record.revision
        && receipt.role == CampaignSourceRole::OrientationClassification
        && receipt.owner_id.as_str()
            == campaign_source_owner_id(CampaignSourceRole::OrientationClassification)
        && receipt.record_id == record.record_id
        && receipt.revision == record.revision
}

fn is_orientation_record(record: &CampaignSourceRecord) -> bool {
    record.role == CampaignSourceRole::OrientationClassification
        && record.owner_id.as_str()
            == campaign_source_owner_id(CampaignSourceRole::OrientationClassification)
        && record.document.schema
            == eliot_store_api::CampaignSourceDocumentSchema::OrientationClassificationProfile
}

fn orientation_record_matches_profile(
    record: &CampaignSourceRecord,
    profile: &OrientationClassificationProfile,
) -> bool {
    record.record_id == CampaignOwnerRecordId::Artifact(profile.target.target_id.clone())
        && record.revision
        == CampaignOwnerRevision::ResourceSnapshot(profile.target.target_revision.clone())
}

fn is_orientation_cue_source(
    record: &CampaignSourceRecord,
    head: &CampaignSourceHead,
    receipt: &CampaignOwnerReadReceipt,
) -> bool {
    is_orientation_cue_record(record)
        && head.role == CampaignSourceRole::OrientationCueBindings
        && head.owner_id.as_str()
            == campaign_source_owner_id(CampaignSourceRole::OrientationCueBindings)
        && head.record_id == record.record_id
        && head.revision == record.revision
        && receipt.role == CampaignSourceRole::OrientationCueBindings
        && receipt.owner_id.as_str()
            == campaign_source_owner_id(CampaignSourceRole::OrientationCueBindings)
        && receipt.record_id == record.record_id
        && receipt.revision == record.revision
}

fn is_orientation_cue_record(record: &CampaignSourceRecord) -> bool {
    record.role == CampaignSourceRole::OrientationCueBindings
        && record.owner_id.as_str()
            == campaign_source_owner_id(CampaignSourceRole::OrientationCueBindings)
        && record.document.schema == CampaignSourceDocumentSchema::OrientationCueBindingsRecord
}

fn orientation_cue_record_matches(
    record: &CampaignSourceRecord,
    source: &OrientationCueBindingsSource,
) -> bool {
    let Some(task_revision) = source.state_fence.task_revision.as_ref() else {
        return false;
    };
    record.record_id == CampaignOwnerRecordId::Task(source.task_id.clone())
        && record.revision == CampaignOwnerRevision::Task(task_revision.clone())
        && record.recorded_state_fence == source.state_fence
}

fn is_orientation_admission_source(
    record: &CampaignSourceRecord,
    head: &CampaignSourceHead,
    receipt: &CampaignOwnerReadReceipt,
) -> bool {
    is_orientation_admission_record(record)
        && head.role == CampaignSourceRole::OrientationAdmission
        && head.owner_id.as_str()
            == campaign_source_owner_id(CampaignSourceRole::OrientationAdmission)
        && head.record_id == record.record_id
        && head.revision == record.revision
        && receipt.role == CampaignSourceRole::OrientationAdmission
        && receipt.owner_id.as_str()
            == campaign_source_owner_id(CampaignSourceRole::OrientationAdmission)
        && receipt.record_id == record.record_id
        && receipt.revision == record.revision
}

fn is_orientation_admission_record(record: &CampaignSourceRecord) -> bool {
    record.role == CampaignSourceRole::OrientationAdmission
        && record.owner_id.as_str()
            == campaign_source_owner_id(CampaignSourceRole::OrientationAdmission)
        && record.document.schema == CampaignSourceDocumentSchema::OrientationAdmissionRecord
}

fn orientation_admission_record_matches(
    record: &CampaignSourceRecord,
    source: &OrientationAdmissionRecord,
) -> bool {
    let Some(task_revision) = source.admission.state_fence.task_revision.as_ref() else {
        return false;
    };
    let Ok(task_id) = TaskId::new(source.admission.task_id.clone()) else {
        return false;
    };
    record.record_id == CampaignOwnerRecordId::Task(task_id)
        && record.revision == CampaignOwnerRevision::Task(task_revision.clone())
        && record.recorded_state_fence == source.admission.state_fence
}

impl<'a> OrientationAdmissionSourceReadback<'a> {
    /// Admit one current native named-read result for Orientation admission.
    pub fn from_read(
        read: &'a CampaignSourceRevisionRead,
    ) -> Result<Self, OrientationAdmissionSourceError> {
        read.validate()
            .map_err(OrientationAdmissionSourceError::InvalidRead)?;
        match read.status {
            CampaignSourceReadStatus::Current => {}
            CampaignSourceReadStatus::Stale => {
                return Err(OrientationAdmissionSourceError::NotCurrent("stale"));
            }
            CampaignSourceReadStatus::Blocked => {
                return Err(OrientationAdmissionSourceError::NotCurrent("blocked"));
            }
            CampaignSourceReadStatus::Missing => {
                return Err(OrientationAdmissionSourceError::NotCurrent("missing"));
            }
        }
        let (Some(source_row), Some(head), Some(receipt)) =
            (&read.source, &read.current_head, &read.read_receipt)
        else {
            return Err(OrientationAdmissionSourceError::IncompleteRead);
        };
        if !is_orientation_admission_source(source_row, head, receipt) {
            return Err(OrientationAdmissionSourceError::IdentityMismatch);
        }
        let body: CampaignOwnerProjectionBody =
            serde_json::from_value(source_row.document.body.clone())
                .map_err(|_| OrientationAdmissionSourceError::IdentityMismatch)?;
        body.validate()
            .map_err(OrientationAdmissionSourceError::InvalidRead)?;
        let record: OrientationAdmissionRecord = serde_json::from_value(body.projection)
            .map_err(|_| OrientationAdmissionSourceError::IdentityMismatch)?;
        record
            .validate()
            .map_err(OrientationAdmissionSourceError::InvalidRecord)?;
        if !orientation_admission_record_matches(source_row, &record) {
            return Err(OrientationAdmissionSourceError::IdentityMismatch);
        }
        Ok(Self { record, read })
    }

    /// Bind the admitted source record to the exact queued job originals.
    pub fn validate_for_runtime(
        &self,
        request: &RequestMetadata,
        operation_id: &OperationId,
        admission: &DreamJobAdmission,
        bundle: &DreamInputBundle,
        admitted_orientation_job: &AdmittedOrientationJob,
    ) -> Result<(), OrientationAdmissionSourceError> {
        self.read
            .validate()
            .map_err(OrientationAdmissionSourceError::InvalidRead)?;
        self.record
            .validate()
            .map_err(OrientationAdmissionSourceError::InvalidRecord)?;
        let task_id = request
            .task_id
            .as_ref()
            .ok_or(OrientationAdmissionSourceError::IdentityMismatch)?;
        if self.read.status != CampaignSourceReadStatus::Current
            || !self
                .read
                .source
                .as_ref()
                .is_some_and(|row| is_orientation_admission_record(row))
            || self.record.request != *request
            || self.record.operation_id != *operation_id
            || self.record.admission != *admission
            || self.record.bundle != *bundle
            || self.record.admitted_orientation_job != *admitted_orientation_job
            || self.record.admission.task_id != task_id.as_str()
            || self.record.admission.state_fence != request.state_fence
            || self.read.read_state_fence != request.state_fence
        {
            return Err(OrientationAdmissionSourceError::IdentityMismatch);
        }
        Ok(())
    }

    /// Borrow the native source decoded from the exact campaign owner row.
    #[must_use]
    pub const fn record(&self) -> &OrientationAdmissionRecord {
        &self.record
    }

    /// Borrow the unchanged authenticated named-read result.
    #[must_use]
    pub const fn read(&self) -> &'a CampaignSourceRevisionRead {
        self.read
    }

    /// Return the unchanged source row and Store-authenticated read evidence.
    pub fn owner_evidence(
        &self,
    ) -> Result<
        (
            &CampaignSourceRecord,
            &CampaignSourceHead,
            &CampaignOwnerReadReceipt,
            &StateFence,
        ),
        OrientationAdmissionSourceError,
    > {
        let record = self
            .read
            .source
            .as_ref()
            .ok_or(OrientationAdmissionSourceError::IncompleteRead)?;
        let head = self
            .read
            .current_head
            .as_ref()
            .ok_or(OrientationAdmissionSourceError::IncompleteRead)?;
        let receipt = self
            .read
            .read_receipt
            .as_ref()
            .ok_or(OrientationAdmissionSourceError::IncompleteRead)?;
        Ok((record, head, receipt, &self.read.read_state_fence))
    }
}
