//! Original Governor READ admission for the exact currently selected source
//! candidate. This producer consumes owner-issued task selection evidence,
//! the current WorkScope projection, the canonical ProposedAttempt receipt,
//! and bytes freshly observed beneath that WorkScope; request path fields are
//! selectors only.

use eliot_authority::{ActionContract, ActionLease, GrantId, ImpactClass, LeaseId, LogicalTime, PrincipalRef, ReceiptObligation, SnapshotId};
use eliot_contracts::{OperationId, ResourceGeneration, StateFence, TaskRevision, WorkScopeId};
use eliot_protocol::{HostRequestEnvelope, HostRequestKind, RequestIdentity, host_request_operation_id};
use eliot_receipts::{EffectClass, OperationBinding, RequestBinding, SessionBinding, TaskBinding, WorkScopeBinding};

use super::{CompositionReadiness, GovernorComposition, KernelGenerationPort};
use crate::{
    ActiveReservationUsePort, SourceArtifactAdmission, SourceArtifactAdmissionError,
    SourceArtifactAdmissionRequest,
};
use eliot_ors::{AdmissionReservationClaims, OperationIdentity};

/// Governor-prepared source snapshot E action. Its exact ActionContract and
/// Graph-issued ActionLease are retained before the Kernel stages the E
/// reservation; the effect is not compiled or executable until the original
/// ORS owner returns the active E row at use.
#[derive(Debug)]
pub struct PreparedSelectedSourceSnapshotMutation {
    input: SourceArtifactAdmissionRequest,
    action_lease: ActionLease,
    supporting_grant_path: Vec<GrantId>,
    grant_graph_revision: u64,
    action_contract_sha256: String,
}

impl PreparedSelectedSourceSnapshotMutation {
    pub fn child_identity(&self) -> &RequestIdentity {
        &self.input.request_identity
    }

    pub fn action_contract(&self) -> &ActionContract {
        &self.input.contract
    }

    pub fn action_lease(&self) -> &ActionLease {
        &self.action_lease
    }

    pub fn operation(&self) -> &OperationBinding {
        &self.input.operation
    }

    pub fn resource_ref(&self) -> &str {
        &self.input.resource_ref
    }

    pub fn action_contract_sha256(&self) -> &str {
        &self.action_contract_sha256
    }

    pub fn host_request_operation_id(&self) -> &eliot_ors::OperationIdentity {
        &self.input.host_request_operation_id
    }

    pub fn host_request_digest(&self) -> &str {
        &self.input.host_request_digest
    }

    pub fn semantic_admission_revision(&self) -> &str {
        &self.action_contract_sha256
    }

    pub fn work_scope_id(&self) -> &str {
        self.input.work_scope.scope_id.as_str()
    }

    pub fn task_id(&self) -> &str {
        self.input.task.task_id.as_str()
    }

    pub fn state_fence(&self) -> &StateFence {
        &self.input.operation.state_fence
    }
}

impl<P: KernelGenerationPort + ?Sized> GovernorComposition<P> {
    /// Issues the original READ effect for one selected-source observation.
    /// The GrantGraph and EffectAuthorizer remain the authority: this method
    /// only assembles their request from existing original owner records.
    pub fn admit_selected_source_capture_read(
        &mut self,
        envelope: &HostRequestEnvelope,
        identity: &RequestIdentity,
        selected: &crate::TaskSelectionAdmissionBinding,
        causal_receipt: &eliot_store_api::CausalWriteReceipt,
        selected_relative_path: &str,
        source_digest: &str,
        selector: Option<&str>,
        profile: &str,
        profile_revision: u64,
        instrument: &str,
        configuration_digest: &str,
        executable_path: &str,
        executable_digest: &str,
    ) -> Result<SourceArtifactAdmission, SourceArtifactAdmissionError> {
        identity.validate()?;
        envelope.validate_for_admission()?;
        if self.readiness != CompositionReadiness::Ready {
            return Err(SourceArtifactAdmissionError::Owner(
                "Governor composition is not ready".to_owned(),
            ));
        }
        let fence = self.snapshot.state_fence();
        let original = &envelope.identity;
        let metadata = &identity.request.metadata;
        if envelope.kind != HostRequestKind::SelectedSourceCapture
            || envelope.state_fence != *fence
            || identity.request.state_fence != *fence
            || original.request_id != metadata.request_id
            || original.idempotency_key != identity.idempotency_key
            || original.cancellation_id != identity.cancellation_id
            || original.deadline_unix_ms != identity.deadline_unix_ms
            || original.capability != eliot_protocol::SELECTED_SOURCE_CAPTURE_CAPABILITY
            || original.work_scope_id.as_deref()
                != Some(selected.work_scope().binding.scope.scope_ref.as_str())
            || metadata.task_id.as_ref().map(ToString::to_string).as_deref()
                != Some(selected.task_ref())
            || metadata.session_id.as_ref().map(ToString::to_string).as_deref()
                != Some(selected.session_ref())
            || selected.state_fence() != fence
            || selected_relative_path.is_empty()
            || source_digest.len() != 64
            || !source_digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || configuration_digest.len() != 64
            || !configuration_digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || executable_digest.len() != 64
            || !executable_digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || profile.trim().is_empty()
            || profile_revision == 0
            || instrument.trim().is_empty()
            || executable_path.trim().is_empty()
            || causal_receipt.receipt.state_fence != *fence
            || causal_receipt.causal.state_fence != *fence
        {
            return Err(SourceArtifactAdmissionError::Binding(
                "selected-source READ inputs differ from the exact current request, owner selection, source bytes, profile, or canonical receipt",
            ));
        }
        let current_scope = self
            .owners
            .work_scope
            .as_ref()
            .ok_or(SourceArtifactAdmissionError::Binding(
                "current WorkScope owner is unbound",
            ))?
            .read_current(fence)?;
        super::ensure_snapshot_fresh(&current_scope, "selected-source WorkScope is stale")
            .map_err(|error| SourceArtifactAdmissionError::OwnerComposition(Box::new(error)))?;
        let scope = &current_scope.binding.scope;
        if scope.scope_ref != selected.work_scope().binding.scope.scope_ref
            || scope.generation != selected.work_scope().binding.scope.generation
            || current_scope.state_fence != *fence
        {
            return Err(SourceArtifactAdmissionError::Binding(
                "selected-source WorkScope changed since the original selection",
            ));
        }
        let task_id = metadata.task_id.clone().ok_or(SourceArtifactAdmissionError::Binding(
            "selected-source RequestIdentity has no Task",
        ))?;
        let session_id = metadata.session_id.clone().ok_or(SourceArtifactAdmissionError::Binding(
            "selected-source RequestIdentity has no Session",
        ))?;
        let task_record = self.owners.task.task(&task_id).ok_or(SourceArtifactAdmissionError::Binding(
            "current Task owner lacks the selected Task",
        ))?;
        if !task_record.state.is_active()
            || task_record.state_fence != *fence
            || task_record.revision != selected.task_revision()
        {
            return Err(SourceArtifactAdmissionError::Binding(
                "selected Task owner is stale or no longer active",
            ));
        }
        let session_record = self.owners.session.session(&session_id).ok_or(SourceArtifactAdmissionError::Binding(
            "current Session owner lacks the selected Session",
        ))?;
        if session_record.status != eliot_session::SessionState::Active
            || session_record.state_fence != *fence
            || session_record.authority_epoch != fence.authority_epoch
            || session_record.expires_at <= identity.deadline_unix_ms
        {
            return Err(SourceArtifactAdmissionError::Binding(
                "selected Session owner is stale, expired, or not active",
            ));
        }
        if self.owners.authority.state_fence() != fence {
            return Err(SourceArtifactAdmissionError::Binding(
                "selected-source AuthorityOwner is stale against the current fence",
            ));
        }
        let work_scope = WorkScopeBinding {
            scope_id: WorkScopeId::new(scope.scope_ref.clone())?,
            product_id: metadata.product_id.clone(),
            resource_generation: ResourceGeneration::new(scope.generation)?,
            state_fence: fence.clone(),
        };
        let task = TaskBinding {
            task_id,
            task_revision: TaskRevision::new(task_record.revision)?,
            state_fence: fence.clone(),
        };
        let session = SessionBinding {
            session_id,
            authority_epoch: session_record.authority_epoch.clone(),
            state_fence: fence.clone(),
        };
        let holder = PrincipalRef::new(selected.principal_ref().to_owned())
            .map_err(|_| SourceArtifactAdmissionError::Binding(
                "selected principal is not a valid original authority identity",
            ))?;
        let host_operation = host_request_operation_id(envelope);
        let operation_id = OperationId::new(host_operation.clone())?;
        let operation_name = "eliot.source-capture.read".to_owned();
        let resource_ref = format!("source:{}:{}", selected.work_scope().binding.scope.scope_ref, selected_relative_path);
        let operation = OperationBinding {
            operation_id,
            request_id: metadata.request_id.clone(),
            idempotency_key: identity.idempotency_key.clone(),
            operation_kind: operation_name.clone(),
            effect: EffectClass::Read,
            state_fence: fence.clone(),
        };
        let payload = serde_json::json!({
            "schema": "eliot.selected-source-read.v1",
            "host_request_operation_id": host_operation,
            "work_scope_id": scope.scope_ref,
            "selected_relative_path": selected_relative_path,
            "selector": selector,
            "source_sha256": source_digest,
            "profile": profile,
            "profile_revision": profile_revision,
            "instrument": instrument,
            "configuration_sha256": configuration_digest,
            "executable_path": executable_path,
            "executable_sha256": executable_digest,
        });
        let contract = ActionContract::new(
            format!("selected-source-read:{host_operation}"),
            task.task_id.to_string(),
            "Read the exact selected source candidate under its current WorkScope".to_owned(),
            work_scope.clone(),
            operation_name.clone(),
            [payload.to_string()],
            [resource_ref.clone()],
            ImpactClass::Observe,
            ["canonical_state_unchanged".to_owned()],
            format!("Current selected source bytes sha256={source_digest}"),
            "eliot.source-capture.read",
            "read-only source observation; no canonical mutation is proposed",
            ["source_candidate_changed".to_owned(), "owner_binding_stale".to_owned()],
        )?;
        let input = SourceArtifactAdmissionRequest {
            snapshot_id: SnapshotId::new(format!("selected-source-read:{host_operation}"))?,
            holder,
            work_scope,
            task,
            session,
            causal: causal_receipt.causal.clone(),
            request: RequestBinding {
                metadata: metadata.clone(),
                state_fence: fence.clone(),
            },
            request_identity: identity.clone(),
            host_request_operation_id: eliot_ors::OperationIdentity::new(host_operation.clone())
                .map_err(|_| SourceArtifactAdmissionError::Binding(
                    "selected-source host operation identity is invalid",
                ))?,
            host_request_digest: envelope.envelope_sha256.clone(),
            operation,
            operation_name,
            resource_ref,
            executor_boundary: "eliot.source-capture.read".to_owned(),
            lease_id: LeaseId::new(format!("selected-source-read:{host_operation}"))?,
            receipt_obligations: vec![ReceiptObligation::ExternalReadback],
            contract,
            active_reservation: None,
            expected_work_item_id: None,
            expected_proposed_attempt_id: None,
            now: eliot_authority::LogicalTime::new(
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| SourceArtifactAdmissionError::Binding(
                        "system clock is before the Unix epoch",
                    ))?
                    .as_millis()
                    .try_into()
                    .map_err(|_| SourceArtifactAdmissionError::Binding(
                        "system clock exceeds the authority time range",
                    ))?,
            ),
        };
        crate::issue_source_artifact_admission(&mut self.owners.authority, input)
    }

    /// Admits a distinct READ of the exact staged SourceTreeSnapshot artifact
    /// reference. This does not reuse the selected-file READ resource: the
    /// ArtifactOwner reference and ready-receipt identity are retained in the
    /// immutable action payload and the current GrantGraph must independently
    /// authorize that exact receipt resource for this operation.
    pub fn admit_selected_source_snapshot_reference_read(
        &mut self,
        envelope: &HostRequestEnvelope,
        parent_identity: &RequestIdentity,
        selected: &crate::TaskSelectionAdmissionBinding,
        causal_receipt: &eliot_store_api::CausalWriteReceipt,
        reference_ready_receipt_id: &str,
        reference_payload: &serde_json::Value,
    ) -> Result<SourceArtifactAdmission, SourceArtifactAdmissionError> {
        parent_identity.validate()?;
        envelope.validate_for_admission()?;
        if self.readiness != CompositionReadiness::Ready {
            return Err(SourceArtifactAdmissionError::Owner(
                "Governor composition is not ready".to_owned(),
            ));
        }
        let fence = self.snapshot.state_fence();
        let host = &envelope.identity;
        let parent_metadata = &parent_identity.request.metadata;
        let scope_selector = host.work_scope_id.as_deref().ok_or(
            SourceArtifactAdmissionError::Binding(
                "selected-source snapshot read omitted its original WorkScope",
            ),
        )?;
        let task_id = parent_metadata.task_id.clone().ok_or(
            SourceArtifactAdmissionError::Binding(
                "selected-source snapshot read omitted its original Task",
            ),
        )?;
        let session_id = parent_metadata.session_id.clone().ok_or(
            SourceArtifactAdmissionError::Binding(
                "selected-source snapshot read omitted its original Session",
            ),
        )?;
        if envelope.kind != HostRequestKind::SelectedSourceCapture
            || host.capability != eliot_protocol::SELECTED_SOURCE_CAPTURE_CAPABILITY
            || host.request_id != parent_metadata.request_id
            || host.idempotency_key != parent_identity.idempotency_key
            || host.cancellation_id != parent_identity.cancellation_id
            || host.deadline_unix_ms != parent_identity.deadline_unix_ms
            || host.task_id.as_deref() != Some(task_id.as_str())
            || host.session_id.as_deref() != Some(session_id.as_str())
            || scope_selector != selected.work_scope().binding.scope.scope_ref
            || parent_identity.request.state_fence != *fence
            || envelope.state_fence != *fence
            || selected.state_fence() != fence
            || causal_receipt.receipt.state_fence != *fence
            || causal_receipt.causal.state_fence != *fence
            || reference_ready_receipt_id.trim().is_empty()
            || reference_ready_receipt_id.chars().any(char::is_control)
            || !reference_payload.is_object()
        {
            return Err(SourceArtifactAdmissionError::Binding(
                "snapshot ArtifactReference differs from the original selected-source request, causal receipt, or current fence",
            ));
        }

        let current_scope = self
            .owners
            .work_scope
            .as_ref()
            .ok_or(SourceArtifactAdmissionError::Binding(
                "current WorkScope owner is unbound",
            ))?
            .read_current(fence)?;
        super::ensure_snapshot_fresh(&current_scope, "source snapshot WorkScope is stale")
            .map_err(|error| SourceArtifactAdmissionError::OwnerComposition(Box::new(error)))?;
        if current_scope.state_fence != *fence
            || current_scope.binding.scope.scope_ref != scope_selector
            || current_scope.binding.scope.generation
                != selected.work_scope().binding.scope.generation
        {
            return Err(SourceArtifactAdmissionError::Binding(
                "WorkScope changed since selected-source snapshot staging",
            ));
        }
        let task_record = self.owners.task.task(&task_id).ok_or(
            SourceArtifactAdmissionError::Binding(
                "current Task owner lacks the selected Task",
            ),
        )?;
        let session_record = self.owners.session.session(&session_id).ok_or(
            SourceArtifactAdmissionError::Binding(
                "current Session owner lacks the selected Session",
            ),
        )?;
        if !task_record.state.is_active()
            || task_record.revision != selected.task_revision()
            || task_record.state_fence != *fence
            || session_record.status != eliot_session::SessionState::Active
            || session_record.state_fence != *fence
            || session_record.authority_epoch != fence.authority_epoch
            || session_record.expires_at <= parent_identity.deadline_unix_ms
            || self.owners.authority.state_fence() != fence
        {
            return Err(SourceArtifactAdmissionError::Binding(
                "Task, Session, or AuthorityOwner changed before source snapshot read admission",
            ));
        }

        let child_id = format!("source-snapshot-read:{}", reference_ready_receipt_id);
        let child_request_id = eliot_contracts::RequestId::new(child_id.clone())?;
        let mut child_metadata = parent_metadata.clone();
        child_metadata.request_id = child_request_id.clone();
        let child_idempotency = format!("{child_id}:read");
        let request_binding = RequestBinding {
            metadata: child_metadata.clone(),
            state_fence: fence.clone(),
        };
        let identity = RequestIdentity {
            request: request_binding.clone(),
            idempotency_key: child_idempotency.clone(),
            deadline_unix_ms: parent_identity.deadline_unix_ms,
            cancellation_id: format!("{child_id}:cancel"),
        };
        identity.validate()?;

        let work_scope = WorkScopeBinding {
            scope_id: WorkScopeId::new(current_scope.binding.scope.scope_ref.clone())?,
            product_id: child_metadata.product_id.clone(),
            resource_generation: ResourceGeneration::new(current_scope.binding.scope.generation)?,
            state_fence: fence.clone(),
        };
        let task = TaskBinding {
            task_id: task_id.clone(),
            task_revision: TaskRevision::new(task_record.revision)?,
            state_fence: fence.clone(),
        };
        let session = SessionBinding {
            session_id,
            authority_epoch: session_record.authority_epoch.clone(),
            state_fence: fence.clone(),
        };
        let holder = PrincipalRef::new(selected.principal_ref().to_owned())
            .map_err(|_| SourceArtifactAdmissionError::Binding(
                "selected principal is not a valid original authority identity",
            ))?;
        let host_operation = host_request_operation_id(envelope);
        let operation_name = "eliot.source-capture.snapshot-reference.read".to_owned();
        let operation = OperationBinding {
            operation_id: OperationId::new(child_id.clone())?,
            request_id: child_request_id,
            idempotency_key: child_idempotency,
            operation_kind: operation_name.clone(),
            effect: EffectClass::Read,
            state_fence: fence.clone(),
        };
        let pointer_json = String::from_utf8(canonical_json_bytes(reference_payload)?)?;
        let contract = ActionContract::new(
            format!("source-snapshot-reference-read:{host_operation}"),
            task.task_id.to_string(),
            format!("Read the exact staged SourceTreeSnapshot reference {pointer_json}"),
            work_scope.clone(),
            operation_name.clone(),
            [pointer_json],
            [reference_ready_receipt_id.to_owned()],
            ImpactClass::Observe,
            ["canonical_state_unchanged".to_owned()],
            format!("ArtifactOwner readback for ready receipt {reference_ready_receipt_id}"),
            "eliot.source-artifact.reference.read",
            "read exact staged source snapshot bytes under the original Blob owner",
            ["owner_binding_stale".to_owned(), "artifact_readback_refused".to_owned()],
        )?;
        let now = LogicalTime::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| SourceArtifactAdmissionError::Binding(
                    "system clock is before the Unix epoch",
                ))?
                .as_millis()
                .try_into()
                .map_err(|_| SourceArtifactAdmissionError::Binding(
                    "system clock exceeds the authority time range",
                ))?,
        );
        let request = SourceArtifactAdmissionRequest {
            snapshot_id: SnapshotId::new(format!("source-snapshot-read:{host_operation}"))?,
            holder,
            work_scope,
            task,
            session,
            causal: causal_receipt.causal.clone(),
            request: request_binding,
            request_identity: identity,
            host_request_operation_id: eliot_ors::OperationIdentity::new(host_operation.clone())
                .map_err(|_| SourceArtifactAdmissionError::Binding(
                    "original HostRequest operation identity is invalid",
                ))?,
            host_request_digest: envelope.envelope_sha256.clone(),
            operation,
            operation_name,
            resource_ref: reference_ready_receipt_id.to_owned(),
            executor_boundary: "eliot.source-artifact.reference.read".to_owned(),
            lease_id: LeaseId::new(format!("source-snapshot-read:{host_operation}"))?,
            receipt_obligations: vec![ReceiptObligation::ExternalReadback],
            contract,
            active_reservation: None,
            expected_work_item_id: None,
            expected_proposed_attempt_id: None,
            now,
        };
        crate::issue_source_artifact_admission(&mut self.owners.authority, request)
    }

    /// Prepares the original E ActionContract and ActionLease for persisting
    /// the exact selected source-tree archive. The target is selected by the
    /// original SourceArtifactOwner staging carrier. This prepares no
    /// executable effect; the caller stages/commits/activates the distinct E
    /// reservation before asking the use-time owner to compile it.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_selected_source_snapshot_mutation(
        &mut self,
        envelope: &HostRequestEnvelope,
        identity: &RequestIdentity,
        selected: &crate::TaskSelectionAdmissionBinding,
        source_read_admission: &SourceArtifactAdmission,
        blob_root_id: &str,
        artifact_staging_resource_ref: &str,
        work_item_id: OperationIdentity,
        proposed_attempt_id: OperationIdentity,
        causal_receipt: &eliot_store_api::CausalWriteReceipt,
        selected_relative_path: &str,
        source_digest: &str,
        archive_digest: &str,
    ) -> Result<PreparedSelectedSourceSnapshotMutation, SourceArtifactAdmissionError> {
        identity.validate()?;
        envelope.validate_for_admission()?;
        let fence = self.snapshot.state_fence();
        let metadata = &identity.request.metadata;
        let host_identity = &envelope.identity;
        let valid_digest = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if self.readiness != CompositionReadiness::Ready
            || envelope.kind != HostRequestKind::SelectedSourceCapture
            || host_identity.capability != eliot_protocol::SELECTED_SOURCE_CAPTURE_CAPABILITY
            || envelope.state_fence != *fence
            || identity.request.state_fence != *fence
            || metadata.state_fence != *fence
            || host_identity.request_id != metadata.request_id
            || host_identity.idempotency_key != identity.idempotency_key
            || host_identity.cancellation_id != identity.cancellation_id
            || host_identity.deadline_unix_ms != identity.deadline_unix_ms
            || host_identity.work_scope_id.as_deref()
                != Some(selected.work_scope().binding.scope.scope_ref.as_str())
            || metadata.task_id.as_ref().map(ToString::to_string).as_deref()
                != Some(selected.task_ref())
            || metadata.session_id.as_ref().map(ToString::to_string).as_deref()
                != Some(selected.session_ref())
            || source_read_admission.request_identity() != identity
            || source_read_admission.operation().operation_kind != "eliot.source-capture.read"
            || source_read_admission.operation().effect != EffectClass::Read
            || source_read_admission.work_scope() != &selected.work_scope().binding
            || source_read_admission.task().task_id.as_str() != selected.task_ref()
            || source_read_admission.session().session_id.as_str() != selected.session_ref()
            || source_read_admission.holder().as_str() != selected.principal_ref()
            || source_read_admission.operation().state_fence != *fence
            || source_read_admission.resource_ref().trim().is_empty()
            || blob_root_id.trim().is_empty()
            || blob_root_id.chars().any(char::is_control)
            || artifact_staging_resource_ref.trim().is_empty()
            || artifact_staging_resource_ref.chars().any(char::is_control)
            || selected.state_fence() != fence
            || selected.active_work().work_item.work_item_id.as_str() != work_item_id.as_str()
            || selected_relative_path.is_empty()
            || !valid_digest(source_digest)
            || !valid_digest(archive_digest)
            || causal_receipt.receipt.state_fence != *fence
            || causal_receipt.causal.state_fence != *fence
        {
            return Err(SourceArtifactAdmissionError::Binding(
            "source snapshot mutation inputs differ from the exact current HostRequest, selected owner state, archive, or canonical predecessor",
            ));
        }

        let current_scope = self
            .owners
            .work_scope
            .as_ref()
            .ok_or(SourceArtifactAdmissionError::Binding(
                "current WorkScope owner is unbound",
            ))?
            .read_current(fence)?;
        super::ensure_snapshot_fresh(&current_scope, "selected-source WorkScope is stale")
            .map_err(|error| SourceArtifactAdmissionError::OwnerComposition(Box::new(error)))?;
        if current_scope.state_fence != *fence
            || current_scope.binding.scope.scope_ref
                != selected.work_scope().binding.scope.scope_ref
            || current_scope.binding.scope.generation
                != selected.work_scope().binding.scope.generation
        {
            return Err(SourceArtifactAdmissionError::Binding(
                "current WorkScope changed since selected-source canonical admission",
            ));
        }

        let task_id = metadata.task_id.clone().ok_or(SourceArtifactAdmissionError::Binding(
            "selected-source mutation RequestIdentity has no Task",
        ))?;
        let task_record = self.owners.task.task(&task_id).ok_or(
            SourceArtifactAdmissionError::Binding("current Task owner lacks the selected Task"),
        )?;
        if !task_record.state.is_active()
            || task_record.state_fence != *fence
            || task_record.revision != selected.task_revision()
        {
            return Err(SourceArtifactAdmissionError::Binding(
                "selected Task owner is stale or no longer active",
            ));
        }
        let session_id = metadata.session_id.clone().ok_or(
            SourceArtifactAdmissionError::Binding(
                "selected-source mutation RequestIdentity has no Session",
            ),
        )?;
        let session_record = self.owners.session.session(&session_id).ok_or(
            SourceArtifactAdmissionError::Binding("current Session owner lacks the selected Session"),
        )?;
        if session_record.status != eliot_session::SessionState::Active
            || session_record.state_fence != *fence
            || session_record.authority_epoch != fence.authority_epoch
            || session_record.expires_at <= identity.deadline_unix_ms
        {
            return Err(SourceArtifactAdmissionError::Binding(
                "selected Session owner is stale, expired, or not active",
            ));
        }
        if self.owners.authority.state_fence() != fence {
            return Err(SourceArtifactAdmissionError::Binding(
                "selected-source AuthorityOwner is stale against the current fence",
            ));
        }

        let work_scope = WorkScopeBinding {
            scope_id: WorkScopeId::new(current_scope.binding.scope.scope_ref.clone())?,
            product_id: metadata.product_id.clone(),
            resource_generation: ResourceGeneration::new(current_scope.binding.scope.generation)?,
            state_fence: fence.clone(),
        };
        let task = TaskBinding {
            task_id,
            task_revision: TaskRevision::new(task_record.revision)?,
            state_fence: fence.clone(),
        };
        let session = SessionBinding {
            session_id,
            authority_epoch: session_record.authority_epoch.clone(),
            state_fence: fence.clone(),
        };
        let holder = PrincipalRef::new(selected.principal_ref().to_owned()).map_err(|_| {
            SourceArtifactAdmissionError::Binding(
                "selected principal is not a valid original authority identity",
            )
        })?;
        let host_operation = host_request_operation_id(envelope);
        let operation_name = "eliot.source-capture.snapshot.stage".to_owned();
        // S remains the original HostRequest/ORS saga identity. E is a
        // separate owner-issued source-artifact mutation identity derived
        // only after the exact captured archive digest is known.
        let effect_operation_id = format!(
            "source-snapshot-stage:{}:{}",
            envelope.envelope_sha256, archive_digest
        );
        let effect_request_id = eliot_contracts::RequestId::new(effect_operation_id.clone())?;
        let mut effect_metadata = metadata.clone();
        effect_metadata.request_id = effect_request_id.clone();
        let effect_idempotency_key = format!("{effect_operation_id}:mutation");
        let effect_identity = RequestIdentity {
            request: RequestBinding {
                metadata: effect_metadata.clone(),
                state_fence: fence.clone(),
            },
            idempotency_key: effect_idempotency_key.clone(),
            deadline_unix_ms: identity.deadline_unix_ms,
            cancellation_id: format!("{effect_operation_id}:cancel"),
        };
        effect_identity.validate().map_err(|_| SourceArtifactAdmissionError::Binding(
            "source snapshot mutation child identity is invalid",
        ))?;
        // This target must come from the original SourceArtifactOwner's
        // scoped staging owner. It is a distinct artifact destination, not
        // the selected file's Read resource and not a local namespace.
        let resource_ref = artifact_staging_resource_ref.to_owned();
        let operation = OperationBinding {
            operation_id: OperationId::new(effect_operation_id.clone())?,
            request_id: effect_request_id,
            idempotency_key: effect_idempotency_key,
            operation_kind: operation_name.clone(),
            effect: EffectClass::ReversibleMutation,
            state_fence: fence.clone(),
        };
        let action_payload = serde_json::json!({
            "schema": "eliot.selected-source-tree-snapshot-stage.v1",
            "host_request_operation_id": host_operation,
            "effect_request_identity": effect_identity,
            "work_scope_id": current_scope.binding.scope.scope_ref,
            "selected_relative_path": selected_relative_path,
            "source_sha256": source_digest,
            "archive_sha256": archive_digest,
            "source_read_operation": source_read_admission.operation(),
            "source_read_action_payload_sha256": source_read_admission.action_payload_sha256(),
            "mutation_target_resource_ref": resource_ref,
            "blob_root_owner_id": blob_root_id,
            "work_item_id": work_item_id,
            "proposed_attempt_id": proposed_attempt_id,
        });
        let contract = ActionContract::new(
            format!("source-snapshot-stage:{effect_operation_id}"),
            task.task_id.to_string(),
            "Persist the exact selected source-tree archive under the current WorkScope".to_owned(),
            work_scope.clone(),
            operation_name.clone(),
            [serde_json::to_string(&action_payload).map_err(|_| {
                SourceArtifactAdmissionError::Binding("source snapshot action payload is invalid")
            })?],
            [resource_ref.clone()],
            ImpactClass::Material,
            ["source_snapshot_archive_staged_and_read_back".to_owned()],
            format!("Current selected source archive sha256={archive_digest}"),
            "eliot.source-artifact.snapshot.stage",
            "persist the exact source archive through the original ArtifactOwner and verify its receipt",
            ["owner_binding_stale".to_owned(), "source_archive_changed".to_owned()],
        )?;
        let input = SourceArtifactAdmissionRequest {
            snapshot_id: SnapshotId::new(format!("source-snapshot-stage:{effect_operation_id}"))?,
            holder,
            work_scope,
            task,
            session,
            causal: causal_receipt.causal.clone(),
            request: RequestBinding {
                metadata: effect_metadata,
                state_fence: fence.clone(),
            },
            request_identity: effect_identity,
            host_request_operation_id: eliot_ors::OperationIdentity::new(host_operation)
                .map_err(|_| SourceArtifactAdmissionError::Binding(
                    "original HostRequest operation identity is invalid",
                ))?,
            host_request_digest: envelope.envelope_sha256.clone(),
            operation,
            operation_name,
            resource_ref,
            executor_boundary: "eliot.source-artifact.snapshot.stage".to_owned(),
            lease_id: LeaseId::new(format!("source-snapshot-stage:{}", archive_digest))?,
            receipt_obligations: vec![ReceiptObligation::ExternalReadback],
            contract,
            active_reservation: None,
            expected_work_item_id: Some(work_item_id),
            expected_proposed_attempt_id: Some(proposed_attempt_id),
            now: LogicalTime::new(
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| SourceArtifactAdmissionError::Binding(
                        "system clock is before the Unix epoch",
                    ))?
                    .as_millis()
                    .try_into()
                    .map_err(|_| SourceArtifactAdmissionError::Binding(
                        "system clock exceeds the authority time range",
                    ))?,
            ),
        };
        let capability = self.owners.authority.grants.snapshot(
            input.snapshot_id.clone(),
            &input.holder,
            &input.work_scope,
            &input.session,
            input.now,
        )?;
        capability.validate_context(&input.work_scope, &input.session)?;
        let supporting_grant_path = capability
            .supporting_path(
                &input.operation_name,
                &input.resource_ref,
                input.operation.effect,
            )?
            .grant_path
            .clone();
        let grant_graph_revision = capability.grant_graph_revision();
        let action_lease = capability.issue_action_lease(
            input.lease_id.clone(),
            input.operation.idempotency_key.clone(),
            input.operation_name.clone(),
            input.resource_ref.clone(),
            input.operation.effect,
            input.receipt_obligations.clone(),
        )?;
        let authority_after = self
            .owners
            .authority
            .snapshot()
            .map_err(|error| SourceArtifactAdmissionError::Owner(error.to_string()))?;
        if authority_after.state_fence != *fence
            || authority_after.grant_graph.revision != grant_graph_revision
        {
            return Err(SourceArtifactAdmissionError::Binding(
                "AuthorityOwner changed while preparing the source snapshot E action",
            ));
        }
        let action_contract_bytes = canonical_json_bytes(&input.contract)
            .map_err(|_| SourceArtifactAdmissionError::Binding(
                "prepared source E ActionContract could not be canonically encoded",
            ))?;
        let action_contract_sha256 = eliot_contracts::sha256_hex(&action_contract_bytes);
        Ok(PreparedSelectedSourceSnapshotMutation {
            input,
            action_lease,
            supporting_grant_path,
            grant_graph_revision,
            action_contract_sha256,
        })
    }

    /// Completes the prepared E action only after the original Kernel/ORS
    /// owner rechecks the distinct ACTIVE E reservation at use. The outer
    /// `identity` remains the selected-source S lineage for the Kernel read.
    pub async fn admit_prepared_selected_source_snapshot_mutation(
        &mut self,
        identity: &RequestIdentity,
        mut prepared: PreparedSelectedSourceSnapshotMutation,
        reservation_id: OperationIdentity,
        work_item_id: OperationIdentity,
        proposed_attempt_id: OperationIdentity,
        claims: AdmissionReservationClaims,
        use_port: &dyn ActiveReservationUsePort,
    ) -> Result<SourceArtifactAdmission, SourceArtifactAdmissionError> {
        identity.validate()?;
        let fence = self.snapshot.state_fence();
        if identity.request.state_fence != *fence
            || identity.request.metadata.state_fence != *fence
            || prepared.input.operation.state_fence != *fence
            || prepared.input.request_identity.request.metadata.task_id
                != identity.request.metadata.task_id
            || prepared.input.request_identity.request.metadata.session_id
                != identity.request.metadata.session_id
            || prepared.input.request_identity.request.metadata.product_id
                != identity.request.metadata.product_id
            || prepared.input.host_request_operation_id.as_str()
                != identity.request.metadata.request_id.as_str()
            || prepared.input.request_identity.request.metadata.request_id
                == identity.request.metadata.request_id
        {
            return Err(SourceArtifactAdmissionError::Binding(
                "prepared E action no longer joins the original S identity and current State Fence",
            ));
        }
        prepared.input.expected_work_item_id = Some(work_item_id);
        prepared.input.expected_proposed_attempt_id = Some(proposed_attempt_id);
        // Sample the Governor clock immediately before the original Kernel
        // active-use read. The preparation-time timestamp cannot extend an
        // ActionLease across a delayed ORS stage/commit/activation round trip.
        prepared.input.now = LogicalTime::new(
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| SourceArtifactAdmissionError::Binding(
                    "system clock is before the Unix epoch",
                ))?
                .as_millis()
                .try_into()
                .map_err(|_| SourceArtifactAdmissionError::Binding(
                    "system clock exceeds the authority time range",
                ))?,
        );
        crate::issue_source_artifact_admission_with_prepared_lease(
            &mut self.owners.authority,
            prepared.input,
            identity,
            reservation_id,
            claims,
            use_port,
            prepared.action_lease,
            prepared.supporting_grant_path,
            prepared.grant_graph_revision,
        )
        .await
    }
}

use std::time::SystemTime;
