//! Original-owner READ admission for one retained source-artifact Blob pointer.

use eliot_authority::{
    ActionContract, ImpactClass, LeaseId, ReceiptObligation, SnapshotId,
};
use eliot_contracts::{
    ClockReading, OperationId, RequestId, ResourceGeneration, StateFence, TaskRevision,
    canonical_json_bytes,
};
use eliot_protocol::{RequestIdentity, host_request_operation_id};
use eliot_receipts::{
    EffectClass, OperationBinding, RequestBinding, SessionBinding, TaskBinding, WorkScopeBinding,
    WorkScopeId,
};
use eliot_store_api::NamedReadOperation;

use super::{CompositionReadiness, GovernorComposition, KernelGenerationPort};
use crate::{SourceArtifactAdmission, SourceArtifactAdmissionError, SourceArtifactAdmissionRequest};

const LSP_OBSERVATION_RECEIPT_KIND: &str = "instrument.lsp_observation.v1";
const CONTEXT_RECONSTRUCTION_REQUEST_PREFIX: &str = "eliotd:context-reconstruction:";
const CONTEXT_RECONSTRUCTION_SERVICE: &str = "eliotd";

impl<P: KernelGenerationPort + ?Sized> GovernorComposition<P> {
    /// Admits the current `eliot.query` context-reconstruction request to read
    /// one already-retained LSP Blob payload through the original Governor
    /// authority owners.
    ///
    /// The request carries original host/`ReadApi`/Store identities only. The
    /// current `WorkScope`, task revision, session and `GrantGraph` path are
    /// re-read here; this READ never creates ORS reservation or canonical-write
    /// evidence.
    pub fn admit_source_artifact_read(
        &mut self,
        input: crate::SourceArtifactReadRequest,
    ) -> Result<SourceArtifactAdmission, SourceArtifactAdmissionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(SourceArtifactAdmissionError::Owner(
                "Governor composition is not ready".to_owned(),
            ));
        }
        let fence = self.snapshot.state_fence();
        let original = validate_original_read_request(&input, &fence)?;
        let owners = read_current_owner_bindings(self, &input, &original, &fence)?;
        let admission = source_artifact_read_admission_request(&input, &original, owners, &fence)?;
        if self.owners.authority.state_fence() != &fence {
            return Err(SourceArtifactAdmissionError::Binding(
                "source-artifact AuthorityOwner is stale against the current Governor fence",
            ));
        }
        crate::issue_source_artifact_admission(&mut self.owners.authority, admission)
    }
}

struct OriginalReadRequestContext<'a> {
    host_operation_id: String,
    work_scope_ref: &'a str,
    request_binding: RequestBinding,
    request_identity: RequestIdentity,
}

struct CurrentOwnerBindings {
    work_scope: WorkScopeBinding,
    task: TaskBinding,
    session: SessionBinding,
}

fn validate_original_read_request<'a>(
    input: &'a crate::SourceArtifactReadRequest,
    fence: &StateFence,
) -> Result<OriginalReadRequestContext<'a>, SourceArtifactAdmissionError> {
    input.envelope.validate()?;
    input.attempt.validate()?;
    input.payload_ref.validate()?;

    let host_operation_id = host_request_operation_id(&input.envelope);
    let expected_request_id =
        RequestId::new(format!("{CONTEXT_RECONSTRUCTION_REQUEST_PREFIX}{host_operation_id}"))?;
    let identity = &input.envelope.identity;
    let metadata = &input.request_metadata;
    let work_scope_ref = identity
        .work_scope_id
        .as_deref()
        .filter(|scope| !scope.trim().is_empty() && !scope.chars().any(char::is_control))
        .ok_or(SourceArtifactAdmissionError::Binding(
            "context reconstruction request lacks its original WorkScope identity",
        ))?;
    let metadata_task = metadata.task_id.as_ref().ok_or(
        SourceArtifactAdmissionError::Binding(
            "context reconstruction metadata lacks its task identity",
        ),
    )?;
    let metadata_session = metadata.session_id.as_ref().ok_or(
        SourceArtifactAdmissionError::Binding(
            "context reconstruction metadata lacks its session identity",
        ),
    )?;

    if identity.capability != "eliot.query"
        || identity.request_id.as_str().trim().is_empty()
        || identity.task_id.as_deref() != Some(metadata_task.as_str())
        || identity.session_id.as_deref() != Some(metadata_session.as_str())
        || identity.work_scope_id.as_deref() != Some(work_scope_ref)
        || identity.deadline_unix_ms != input.attempt.expires_at_unix_ms
        || input.envelope.state_fence != *fence
        || metadata.request_id != expected_request_id
        || metadata.state_fence != *fence
        || metadata.product_id.as_str() != CONTEXT_RECONSTRUCTION_SERVICE
        || metadata.source_id.as_str() != CONTEXT_RECONSTRUCTION_SERVICE
        || metadata.clock != ClockReading::default()
        || input.attempt.operation_id != host_operation_id
        || input.attempt.facet_method != identity.capability
        || input.attempt.scope_id != work_scope_ref
        || input.attempt.session_id != metadata_session.as_str()
        || input.attempt.authority_epoch != fence.authority_epoch
        || input.now.value() >= identity.deadline_unix_ms
    {
        return Err(SourceArtifactAdmissionError::Binding(
            "context metadata or Kernel attempt differs from the original admitted host request",
        ));
    }

    let request_binding = RequestBinding {
        metadata: metadata.clone(),
        state_fence: fence.clone(),
    };
    let request_identity = RequestIdentity {
        request: request_binding.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        deadline_unix_ms: identity.deadline_unix_ms,
        cancellation_id: identity.cancellation_id.clone(),
    };
    request_identity.validate()?;

    let task_frame = &input.task_frame_readback;
    let task_frame_principal = task_frame.principal();
    if task_frame.operation() != NamedReadOperation::GetTaskState
        || task_frame.request_id() != &metadata.request_id
        || task_frame.state_fence() != fence
        || task_frame.scope_id().map(|scope| scope.as_str()) != Some(work_scope_ref)
        || task_frame_principal.product_id() != &metadata.product_id
        || task_frame_principal.source_id() != &metadata.source_id
        || task_frame_principal.session_id() != Some(metadata_session)
        || task_frame_principal.task_id() != Some(metadata_task)
    {
        return Err(SourceArtifactAdmissionError::Binding(
            "GetTaskState readback is not bound to this exact context request",
        ));
    }
    if input.causal_binding.state_fence != *fence {
        return Err(SourceArtifactAdmissionError::Binding(
            "Store causal readback does not share the current request fence",
        ));
    }
    if input.payload_ref.receipt_kind != LSP_OBSERVATION_RECEIPT_KIND {
        return Err(SourceArtifactAdmissionError::Binding(
            "source pointer is not a retained LSP observation payload",
        ));
    }

    Ok(OriginalReadRequestContext {
        host_operation_id,
        work_scope_ref,
        request_binding,
        request_identity,
    })
}

fn read_current_owner_bindings<P: KernelGenerationPort + ?Sized>(
    composition: &GovernorComposition<P>,
    input: &crate::SourceArtifactReadRequest,
    original: &OriginalReadRequestContext<'_>,
    fence: &StateFence,
) -> Result<CurrentOwnerBindings, SourceArtifactAdmissionError> {
    let work_scope_owner = composition.owners.work_scope.as_ref().ok_or(
        SourceArtifactAdmissionError::Binding("current WorkScope owner is unbound"),
    )?;
    let current_scope = work_scope_owner.read_current(fence)?;
    let current_scope_identity = &current_scope.binding.scope;
    if current_scope.state_fence != *fence
        || current_scope_identity.scope_ref != original.work_scope_ref
        || current_scope_identity.generation != fence.resource_generation.value()
    {
        return Err(SourceArtifactAdmissionError::Binding(
            "current WorkScope owner differs from the admitted host/read request",
        ));
    }
    let work_scope = WorkScopeBinding {
        scope_id: WorkScopeId::new(current_scope_identity.scope_ref.clone())?,
        product_id: input.request_metadata.product_id.clone(),
        resource_generation: ResourceGeneration::new(current_scope_identity.generation)?,
        state_fence: fence.clone(),
    };

    let metadata_task = input
        .request_metadata
        .task_id
        .as_ref()
        .ok_or(SourceArtifactAdmissionError::Binding(
            "context reconstruction metadata lacks its task identity",
        ))?;
    let metadata_session = input
        .request_metadata
        .session_id
        .as_ref()
        .ok_or(SourceArtifactAdmissionError::Binding(
            "context reconstruction metadata lacks its session identity",
        ))?;
    let current_task = composition
        .owners
        .task
        .task(metadata_task)
        .ok_or(SourceArtifactAdmissionError::Binding(
            "current Task owner lacks the requested task",
        ))?;
    if !current_task.state.is_active() || current_task.state_fence != *fence {
        return Err(SourceArtifactAdmissionError::Binding(
            "current Task owner is not active under the admitted request fence",
        ));
    }
    let task = TaskBinding {
        task_id: current_task.task_id.clone(),
        task_revision: TaskRevision::new(current_task.revision)?,
        state_fence: current_task.state_fence.clone(),
    };

    let current_session = composition
        .owners
        .session
        .session(metadata_session)
        .ok_or(SourceArtifactAdmissionError::Binding(
            "current Session owner lacks the requested session",
        ))?;
    if current_session.status != eliot_session::SessionState::Active
        || current_session.state_fence != *fence
        || current_session.authority_epoch != fence.authority_epoch
        || current_session.expires_at <= input.envelope.identity.deadline_unix_ms
        || current_session
            .task_scope
            .as_deref()
            .is_some_and(|task_scope| task_scope != current_task.task_id.to_string())
    {
        return Err(SourceArtifactAdmissionError::Binding(
            "current Session owner is not the exact active session for this request",
        ));
    }
    let session = SessionBinding {
        session_id: current_session.session_id.clone(),
        authority_epoch: current_session.authority_epoch.clone(),
        state_fence: current_session.state_fence.clone(),
    };
    Ok(CurrentOwnerBindings {
        work_scope,
        task,
        session,
    })
}

fn source_artifact_read_admission_request(
    input: &crate::SourceArtifactReadRequest,
    original: &OriginalReadRequestContext<'_>,
    owners: CurrentOwnerBindings,
    fence: &StateFence,
) -> Result<SourceArtifactAdmissionRequest, SourceArtifactAdmissionError> {
    let operation_name = input.envelope.identity.capability.clone();
    let operation = OperationBinding {
        operation_id: OperationId::new(original.host_operation_id.clone())?,
        request_id: input.request_metadata.request_id.clone(),
        idempotency_key: input.envelope.identity.idempotency_key.clone(),
        operation_kind: operation_name.clone(),
        effect: EffectClass::Read,
        state_fence: fence.clone(),
    };
    let resource_ref = input.payload_ref.ready_receipt_id.clone();
    let pointer_json = String::from_utf8(canonical_json_bytes(&input.payload_ref)?)?;
    let contract = ActionContract::new(
        format!("source-artifact-read:{}", original.host_operation_id),
        owners.task.task_id.to_string(),
        format!("Read retained LSP Blob pointer {pointer_json}"),
        owners.work_scope.clone(),
        operation_name.clone(),
        [pointer_json],
        [resource_ref.clone()],
        ImpactClass::Observe,
        ["canonical_state_unchanged".to_owned()],
        format!("Blob owner readback for ready receipt {resource_ref}"),
        "eliot.blob.read",
        "read only; no canonical mutation is proposed",
        [
            "current_request_fence_mismatch".to_owned(),
            "blob_owner_readback_refused".to_owned(),
        ],
    )?;
    Ok(SourceArtifactAdmissionRequest {
        snapshot_id: SnapshotId::new(format!(
            "source-artifact-read:{}",
            original.host_operation_id
        ))?,
        holder: input.holder.clone(),
        work_scope: owners.work_scope,
        task: owners.task,
        session: owners.session,
        causal: input.causal_binding.clone(),
        request: original.request_binding.clone(),
        request_identity: original.request_identity.clone(),
        operation,
        operation_name,
        resource_ref,
        executor_boundary: "eliot.blob.read".to_owned(),
        lease_id: LeaseId::new(format!(
            "source-artifact-read:{}",
            original.host_operation_id
        ))?,
        receipt_obligations: vec![ReceiptObligation::ExternalReadback],
        contract,
        active_reservation: None,
        expected_work_item_id: None,
        expected_proposed_attempt_id: None,
        now: input.now,
    })
}
