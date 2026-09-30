//! Authenticated source readback for Orientation's independent classification profile.
//!
//! The profile is an owner-published campaign source, separate from the
//! fixed 26-role learning view. This module only decodes the exact original
//! named-read result; it does not turn task, context, or model fields into a
//! substitute profile.

use eliot_contracts::{
    ArtifactId, ContractId, OperationId, RequestMetadata, StateFence, TaskId, TaskRevision,
    TransactionSequence,
};
use eliot_cue_contracts::{
    AdmittedCueBindingProjection, CueBindingAdmissionRef, CueProjectionDenominator,
    OrientationCueBindingsSource, RelationEdge, SnapshotEdgeWeight, SnapshotId, WorkScopeId,
};
use eliot_cue_binding::{
    BindingProfile, CueBindingResult, ExpectedReuseHint, TouchedResourceProjection,
    derive_cue_binding_candidates,
};
use eliot_dreamer_contracts::OrientationClassificationProfile;
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
    CampaignOwnerRevision, CampaignSourceHead, CampaignSourceReadStatus, CampaignSourceRecord,
    CampaignSourceDocumentSchema, CampaignSourceRevisionRead, campaign_source_owner_id,
};
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
#[derive(Clone, Debug, Eq, Error, PartialEq)]
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
    #[error("original Observation admission is invalid: {0}")]
    Observation(String),
    /// A transported value does not exactly decode as its native source contract.
    #[error("Orientation cue source field {field} is not an exact native value: {detail}")]
    SourceField {
        /// The native field whose exact source value failed.
        field: &'static str,
        /// Bounded decoding or canonical comparison detail.
        detail: String,
    },
    /// Native A-12 derivation rejected the original inputs.
    #[error("native A-12 cue derivation failed: {0}")]
    A12(String),
    /// Exact A-10 closure construction rejected the original inputs.
    #[error("native A-10 cue closure failed: {0}")]
    A10(String),
    /// Standard C0-02 receipt issuance rejected the complete owner decision.
    #[error("Governor cue admission receipt is invalid: {0}")]
    Receipt(String),
}

/// Typed failure while admitting the original Orientation profile readback.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
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
    InvalidRead(String),
    /// The stored native profile failed its own contract validation.
    #[error("Orientation classification profile is invalid: {0}")]
    InvalidProfile(String),
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

/// Typed failure while admitting the original Orientation cue source readback.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
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
    InvalidRead(String),
    /// The stored native source failed its own contract validation.
    #[error("Orientation cue source is invalid: {0}")]
    InvalidSource(String),
    /// The retained original A-12 result did not decode or reproduce exactly.
    #[error("Orientation cue A-12 result is invalid: {0}")]
    InvalidA12Result(String),
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
        .request
        .clock
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
        .map_err(|error| OrientationCueAdmissionError::Observation(error.to_string()))?;
    let observation_entry = owners
        .observation
        .get(&input.observation.idempotency_key)
        .ok_or(OrientationCueAdmissionError::Observation(
            "not retained by the current observation journal".to_owned(),
        ))?;
    if observation_entry.request_digest != input.observation.request_digest
        || !matches!(
            &observation_entry.result,
            ObservationAdmissionResult::Accepted { receipt } if receipt == input.observation
        )
        || input.observation.candidate_disposition != ObservationCandidateDisposition::TaskBound
    {
        return Err(OrientationCueAdmissionError::Observation(
            "not the exact accepted task-bound journal result".to_owned(),
        ));
    }
    let selection = input
        .observation
        .task_selection
        .as_ref()
        .ok_or(OrientationCueAdmissionError::Observation(
            "task selection is absent".to_owned(),
        ))?;
    if selection.task_ref != task_id.as_str()
        || selection.task_revision != task.revision
        || selection.work_scope_ref != scope_id.as_str()
        || selection.is_contaminated()
    {
        return Err(OrientationCueAdmissionError::Observation(
            "task selection does not bind the current task and scope".to_owned(),
        ));
    }

    let a12_result = derive_cue_binding_candidates(
        input.observation,
        input.touched,
        input.hint,
        input.profile,
    )
    .map_err(|error| OrientationCueAdmissionError::A12(error.to_string()))?;
    if a12_result.admission != *input.observation
        || a12_result.profile != *input.profile
        || a12_result.state_fence != *fence
    {
        return Err(OrientationCueAdmissionError::A12(
            "native result differs from the exact original input".to_owned(),
        ));
    }
    input
        .denominator
        .validate()
        .map_err(|error| OrientationCueAdmissionError::A10(error.to_string()))?;

    let policy_snapshot_id = policy.snapshot().snapshot_id.clone();
    let policy_snapshot_digest = eliot_cue_contracts::Digest::new(
        policy.snapshot_digest().to_owned(),
    )
    .map_err(|error| OrientationCueAdmissionError::Authorization("policy_digest_shape"))?;
    let a12_result_canonical_bytes = eliot_contracts::canonical_json_bytes(&a12_result)
        .map_err(|error| OrientationCueAdmissionError::A12(error.to_string()))?;

    let mut artifacts = Vec::with_capacity(a12_result.candidates.len() + 2);
    artifacts.push(ArtifactBinding {
        artifact_id: ArtifactId::new("orientation-a12-result")
            .map_err(|_| OrientationCueAdmissionError::A12("result artifact id".to_owned()))?,
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
            .map_err(|error| OrientationCueAdmissionError::A12(error.to_string()))?;
        if !artifact_ids.insert(candidate.binding_candidate_id.as_str().to_owned()) {
            return Err(OrientationCueAdmissionError::A12(
                "duplicate or reserved candidate artifact identity".to_owned(),
            ));
        }
        artifacts.push(ArtifactBinding {
            artifact_id: ArtifactId::new(candidate.binding_candidate_id.as_str().to_owned())
                .map_err(|_| OrientationCueAdmissionError::A12("candidate artifact id".to_owned()))?,
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
            .map_err(|error| OrientationCueAdmissionError::Receipt(error.to_string()))?,
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
    .map_err(|error| OrientationCueAdmissionError::Receipt(error.to_string()))?;

    let mut projections = Vec::with_capacity(a12_result.candidates.len());
    let mut used_touched_rows = std::collections::BTreeSet::new();
    for candidate in &a12_result.candidates {
        let mut matches = input.touched.iter().enumerate().filter(|(_, row)| {
            row.target == candidate.target
                && row.normalization.normalized.canonical.as_ref() == Some(&candidate.canonical)
        });
        let Some((index, row)) = matches.next() else {
            return Err(OrientationCueAdmissionError::A12(
                "candidate has no exact normalized source row".to_owned(),
            ));
        };
        if matches.next().is_some() || !used_touched_rows.insert(index) {
            return Err(OrientationCueAdmissionError::A12(
                "candidate source-row join is ambiguous".to_owned(),
            ));
        }
        if row.normalization.policy.profile != a12_result.profile.expected_normalization_profile
            || row.normalization.normalized.observed.context.task_id != *task_id
            || row.normalization.normalized.observed.context.scope_id != scope_id
            || row.normalization.normalized.observed.context.state_fence != *fence
        {
            return Err(OrientationCueAdmissionError::A12(
                "candidate source row is outside the exact task context".to_owned(),
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
            .map_err(|error| OrientationCueAdmissionError::A10(error.to_string()))?;
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
    .map_err(|error| OrientationCueAdmissionError::A10(error.to_string()))?;
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
        .map_err(|error| OrientationCueAdmissionError::A10(error.to_string()))?;
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
        OrientationCueAdmissionError::SourceField {
            field,
            detail: error.to_string(),
        }
    })?;
    let original = eliot_contracts::canonical_json_bytes(value).map_err(|error| {
        OrientationCueAdmissionError::SourceField {
            field,
            detail: error.to_string(),
        }
    })?;
    let decoded_bytes = eliot_contracts::canonical_json_bytes(&decoded).map_err(|error| {
        OrientationCueAdmissionError::SourceField {
            field,
            detail: error.to_string(),
        }
    })?;
    if original != decoded_bytes {
        return Err(OrientationCueAdmissionError::SourceField {
            field,
            detail: "canonical native value differs from original source field".to_owned(),
        });
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
            .map_err(|error| OrientationCueBindingsSourceError::InvalidRead(error.to_string()))?;
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
            serde_json::from_value(record.document.body.clone()).map_err(|error| {
                OrientationCueBindingsSourceError::InvalidRead(error.to_string())
            })?;
        body.validate()
            .map_err(|error| OrientationCueBindingsSourceError::InvalidRead(error.to_string()))?;
        let source: OrientationCueBindingsSource = serde_json::from_value(body.projection)
            .map_err(|error| OrientationCueBindingsSourceError::InvalidSource(error.to_string()))?;
        source
            .validate()
            .map_err(|error| OrientationCueBindingsSourceError::InvalidSource(error.to_string()))?;
        if !orientation_cue_record_matches(record, &source) {
            return Err(OrientationCueBindingsSourceError::IdentityMismatch);
        }
        let a12_result: CueBindingResult =
            serde_json::from_slice(&source.a12_result_canonical_bytes).map_err(|error| {
                OrientationCueBindingsSourceError::InvalidA12Result(error.to_string())
            })?;
        let canonical_a12 = eliot_contracts::canonical_json_bytes(&a12_result).map_err(|error| {
            OrientationCueBindingsSourceError::InvalidA12Result(error.to_string())
        })?;
        if canonical_a12 != source.a12_result_canonical_bytes
            || a12_result.result_digest != source.a12_result_digest
            || a12_result.profile.expected_normalization_profile != source.normalization_profile
        {
            return Err(OrientationCueBindingsSourceError::InvalidA12Result(
                "retained canonical bytes, result digest, or normalization profile differ"
                    .to_owned(),
            ));
        }
        let derived = derive_cue_binding_candidates(
            &a12_result.admission,
            &a12_result.touched,
            a12_result.hint.as_ref(),
            &a12_result.profile,
        )
        .map_err(|error| OrientationCueBindingsSourceError::InvalidA12Result(error.to_string()))?;
        if derived != a12_result {
            return Err(OrientationCueBindingsSourceError::InvalidA12Result(
                "retained A-12 result differs from the native owner derivation".to_owned(),
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
            .map_err(|error| OrientationCueBindingsSourceError::InvalidRead(error.to_string()))?;
        if self.read.status != CampaignSourceReadStatus::Current {
            return Err(OrientationCueBindingsSourceError::NotCurrent("not current"));
        }
        self.source
            .validate()
            .map_err(|error| OrientationCueBindingsSourceError::InvalidSource(error.to_string()))?;
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
            .map_err(|error| OrientationClassificationSourceError::InvalidRead(error.to_string()))?;
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
            serde_json::from_value(record.document.body.clone()).map_err(|error| {
                OrientationClassificationSourceError::InvalidRead(error.to_string())
            })?;
        body.validate()
            .map_err(|error| OrientationClassificationSourceError::InvalidRead(error.to_string()))?;
        let profile: OrientationClassificationProfile =
            serde_json::from_value(body.projection).map_err(|error| {
                OrientationClassificationSourceError::InvalidProfile(error.to_string())
            })?;
        profile
            .validate()
            .map_err(|error| OrientationClassificationSourceError::InvalidProfile(error.to_string()))?;
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
            .map_err(|error| OrientationClassificationSourceError::InvalidRead(error.to_string()))?;
        if self.read.status != CampaignSourceReadStatus::Current {
            return Err(OrientationClassificationSourceError::NotCurrent("not current"));
        }
        self.profile
            .validate()
            .map_err(|error| OrientationClassificationSourceError::InvalidProfile(error.to_string()))?;
        let record = self
            .read
            .source
            .as_ref()
            .ok_or(OrientationClassificationSourceError::IncompleteRead)?;
        if !is_orientation_record(record) || !orientation_record_matches_profile(record, &self.profile) {
            return Err(OrientationClassificationSourceError::IdentityMismatch);
        }
        if self.profile.target.task_id.as_str() != task_id {
            return Err(OrientationClassificationSourceError::RuntimeBinding("task_id"));
        }
        if self.profile.target.scope_id.as_str() != scope_id {
            return Err(OrientationClassificationSourceError::RuntimeBinding("scope_id"));
        }
        if &self.profile.target.state_fence != state_fence
            || &record.recorded_state_fence != state_fence
            || &self.read.read_state_fence != state_fence
        {
            return Err(OrientationClassificationSourceError::RuntimeBinding("state_fence"));
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
        && head.owner_id.as_str() == campaign_source_owner_id(CampaignSourceRole::OrientationClassification)
        && head.record_id == record.record_id
        && head.revision == record.revision
        && receipt.role == CampaignSourceRole::OrientationClassification
        && receipt.owner_id.as_str() == campaign_source_owner_id(CampaignSourceRole::OrientationClassification)
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
    record.record_id
        == CampaignOwnerRecordId::Artifact(profile.target.target_id.clone())
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
