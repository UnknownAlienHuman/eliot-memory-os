//! Original canonical `SourceSnapshotStage` admission for the selected-source E effect.
//!
//! The source HostRequest remains the S parent. This module stages and activates a
//! distinct E reservation through the existing Kernel/ORS route, commits the exact
//! ProposedAttempt through the existing canonical owner, and returns the sealed
//! Governor preparation for its later use-time admission. It does not publish Blob
//! bytes or promote the source Read permission.

use eliot_contracts::{OperationId, StateFence};
use eliot_governor::{
    CanonicalWriteEnvelope, GoverningSourceSet, KernelTransitionPort,
    PreparedSelectedSourceSnapshotMutation, PrivacyProfile, TaskSelectionAdmissionBinding,
};
use eliot_ors::{
    AdmissionReservationIdentityInput, AdmissionReservationState, OperationalPhase,
    OperationIdentity,
    StateFenceSnapshot, epoch_lineage_for, proposed_attempt_identity,
};
use eliot_store_api::{
    EventProjectionRelationIntents, ProposedAttemptRecord,
};
use eliot_protocol::RequestIdentity;

use crate::{
    CapturedLspAdoptionError, DaemonComposition, DaemonKernelClient,
    SelectedSourceCaptureCanonicalAdmission,
    daemon_kernel_client::SelectedSourceCaptureClaimedInvocation,
    lsp_launch_claims::LspSourcePublicationClaimSet,
    source_artifact_owner::SourceArtifactStagingTarget,
    lsp_source_owner_inputs::ObservedSelectedSourceSnapshot,
};

/// Original E mutation and separate exact-reference Read admissions retained
/// with the owner-readback proof used by the W1 caller.
pub(crate) struct SelectedSourceSnapshotPublicationReadback {
    pub(crate) mutation_admission: eliot_governor::SourceArtifactAdmission,
    pub(crate) reference_read_admission: eliot_governor::SourceArtifactAdmission,
    pub(crate) artifact_inputs: crate::lsp_source_owner_inputs::SelectedSourceArtifactInputs,
}

/// A committed and activated source-snapshot E reservation. The original
/// action preparation remains non-Serde and is needed by the later original
/// Blob-owner admission/use call.
pub(crate) struct SelectedSourceSnapshotCanonicalAdmission {
    pub(crate) record: ProposedAttemptRecord,
    pub(crate) prepared: PreparedSelectedSourceSnapshotMutation,
    pub(crate) claims: eliot_ors::AdmissionReservationClaims,
    pub(crate) reservation_id: OperationIdentity,
    pub(crate) work_item_id: OperationIdentity,
    pub(crate) proposed_attempt_id: OperationIdentity,
}

impl DaemonComposition {
    /// Derives the distinct E ActionContract and exact AuthorityOwner lease
    /// only after the original Git owner retained the exact archive bytes and
    /// the Blob owner resolved its real canonical locator.
    pub(crate) fn prepare_selected_source_snapshot_mutation(
        &mut self,
        claimed: &SelectedSourceCaptureClaimedInvocation,
        selected: &TaskSelectionAdmissionBinding,
        source_stage: &SelectedSourceCaptureCanonicalAdmission,
        source_read_admission: &eliot_governor::SourceArtifactAdmission,
        target: &SourceArtifactStagingTarget,
        observed: &ObservedSelectedSourceSnapshot,
    ) -> Result<PreparedSelectedSourceSnapshotMutation, CapturedLspAdoptionError> {
        if target.archive_sha256_for_admission() != observed.archive_sha256()
            || target.blob_root_id().trim().is_empty()
            || target.resource_ref().trim().is_empty()
        {
            return Err(CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "Blob owner target does not bind the exact retained archive bytes",
            ));
        }
        let work_item_id = OperationIdentity::new(source_stage.record.work_item_id.clone())
            .map_err(|_| CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "original selected-source WorkItem identity is invalid for E",
            ))?;
        let proposed_attempt_id = OperationIdentity::new(
            source_stage.record.proposed_attempt_id.clone(),
        )
        .map_err(|_| CapturedLspAdoptionError::SelectedSourceCaptureRequest(
            "original selected-source ProposedAttempt identity is invalid for E",
        ))?;
        self.governor
            .prepare_selected_source_snapshot_mutation(
                &claimed.host_request_envelope,
                &claimed.request_identity,
                selected,
                source_read_admission,
                target.blob_root_id(),
                target.resource_ref(),
                work_item_id,
                proposed_attempt_id,
                &source_stage.causal_receipt,
                &claimed.invocation.selected_relative_path,
                &source_stage.record.source_digest,
                observed.archive_sha256(),
            )
            .map_err(CapturedLspAdoptionError::Admission)
    }

    /// Runs the canonical ADMITTED half of an exact archive-publication E
    /// reservation. The inactive ORS row comes first; canonical commit and
    /// receipt readback precede activation. E keeps a separate child identity
    /// and operation while retaining the original S request as its parent.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn commit_selected_source_snapshot_stage(
        &mut self,
        kernel: &DaemonKernelClient,
        claimed: &SelectedSourceCaptureClaimedInvocation,
        selected: &TaskSelectionAdmissionBinding,
        source_stage: &SelectedSourceCaptureCanonicalAdmission,
        prepared: PreparedSelectedSourceSnapshotMutation,
        publication_claims: &LspSourcePublicationClaimSet,
        target: &SourceArtifactStagingTarget,
        observed: &ObservedSelectedSourceSnapshot,
        governing_sources: &GoverningSourceSet,
        privacy_profile: &PrivacyProfile,
    ) -> Result<SelectedSourceSnapshotCanonicalAdmission, CapturedLspAdoptionError> {
        let current = self
            .selected_source_capture_task_selection(
                &claimed.host_request_envelope,
                &claimed.request_identity,
            )
            .await?;
        if &current != selected
            || observed.archive_sha256()
                != publication_claims.archive_sha256_for_admission()
            || target.blob_root_id()
                != publication_claims.blob_root_id_for_admission()
            || target.resource_ref()
                != publication_claims.artifact_resource_ref_for_admission()
            || observed.archive_sha256()
                != target.archive_sha256_for_admission()
            || prepared.state_fence() != selected.state_fence()
            || prepared.task_id() != selected.task_ref()
            || prepared.work_scope_id() != selected.work_scope().binding.scope.scope_ref
            || prepared.child_identity().request.state_fence != *selected.state_fence()
            || source_stage.record.work_item_id != selected.evidence_ref()
            || source_stage.record.state_fence != *selected.state_fence()
            || source_stage.record.parent_operation_id
                != eliot_protocol::host_request_operation_id(&claimed.host_request_envelope)
        {
            return Err(CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "source-snapshot E inputs changed from the exact current S selection, archive target, or action",
            ));
        }
        let source_binding = eliot_store_api::SourceSnapshotAdmissionBinding {
            archive_sha256: observed.archive_sha256().to_owned(),
            blob_root_owner_id: target.blob_root_id().to_owned(),
            canonical_locator: target.resource_ref().to_owned(),
            owner_claim_payloads: publication_claims.owner_claim_payloads(),
        };
        let claims = publication_claims.claims().clone();
        claims.validate().map_err(|_| {
            CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "source-snapshot E owner claims failed their original validator",
            )
        })?;
        let state_fence = selected.state_fence().clone();
        let work_item_id = OperationIdentity::new(
            current.active_work().work_item.work_item_id.as_str().to_owned(),
        )
        .map_err(|_| CapturedLspAdoptionError::SelectedSourceCaptureRequest(
            "current WorkItem identity is invalid for source-snapshot E",
        ))?;
        let parent_operation_id =
            OperationIdentity::new(eliot_protocol::host_request_operation_id(
                &claimed.host_request_envelope,
            ))
            .map_err(|_| CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "original S HostRequest operation identity is invalid",
            ))?;
        let fence_snapshot = StateFenceSnapshot::capture(
            &state_fence,
            state_fence.authority_epoch.sequence.get(),
        )
        .map_err(|_| CapturedLspAdoptionError::SelectedSourceCaptureRequest(
            "source-snapshot E fence could not be captured by the existing ORS owner",
        ))?;
        let authority_epoch = epoch_lineage_for(&state_fence.authority_epoch, None)
            .map_err(|_| CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "source-snapshot E authority epoch is invalid",
            ))?;
        let identity_seed = OperationIdentity::new(format!(
            "source-snapshot-seed:{}",
            prepared.child_identity().request.metadata.request_id.as_str()
        ))
        .map_err(|_| CapturedLspAdoptionError::SelectedSourceCaptureRequest(
            "source-snapshot E attempt seed is invalid",
        ))?;
        let attempt_input = AdmissionReservationIdentityInput {
            work_item_id: work_item_id.clone(),
            proposed_attempt_id: identity_seed,
            causal_operation_id: Some(parent_operation_id.clone()),
            semantic_admission_revision: prepared.semantic_admission_revision().to_owned(),
            claims: claims.clone(),
            state_fence: fence_snapshot,
            authority_epoch: authority_epoch.clone(),
        };
        let proposed_attempt_id = proposed_attempt_identity(&attempt_input).map_err(|_| {
            CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "existing ORS owner refused the source-snapshot E attempt identity",
            )
        })?;
        let child_identity = prepared.child_identity().clone();
        let stage = kernel
            .stage_source_snapshot_effect_reservation_async(
                &claimed.request_identity,
                &parent_operation_id,
                &claimed.host_request_envelope.envelope_sha256,
                &child_identity,
                selected.work_scope().binding.scope.scope_ref.as_str(),
                &work_item_id,
                &proposed_attempt_id,
                &claims,
                prepared.semantic_admission_revision(),
                prepared.action_contract_sha256(),
                child_identity.deadline_unix_ms,
            )
            .await
            .map_err(|error| CapturedLspAdoptionError::KernelTransition(
                eliot_governor::KernelPortError::Contract(error.to_string()),
            ))?;
        let stage_value = stage.get("value").cloned().ok_or(
            CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "Kernel source-snapshot E stage omitted its typed owner response",
            ),
        )?;
        let stage_response: eliot_protocol::InstrumentRegistryEffectReservationStageResponse =
            serde_json::from_value(stage_value).map_err(|_| {
                CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                    "Kernel source-snapshot E stage response failed its protocol decoder",
                )
            })?;
        let stage_record: eliot_ors::AdmissionReservationRecord =
            serde_json::from_value(stage_response.record.clone()).map_err(|_| {
                CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                    "Kernel source-snapshot E stage omitted its original ORS record",
                )
            })?;
        stage_record.validate().map_err(|_| {
            CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "original ORS source-snapshot E stage record failed validation",
            )
        })?;
        let stage_receipt: eliot_ors::OperationalMutationReceipt =
            serde_json::from_value(stage_response.receipt.clone()).map_err(|_| {
                CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                    "Kernel source-snapshot E stage omitted its original ORS receipt",
                )
            })?;
        let stage_receipt_id = stage_receipt.record_id().as_str();
        if stage_response.parent_operation_id != parent_operation_id.as_str()
            || stage_response.parent_request_digest
                != claimed.host_request_envelope.envelope_sha256
            || stage_response.parent_request_identity != claimed.request_identity
            || stage_response.child_request_identity != child_identity
            || stage_response.work_scope_id
                != selected.work_scope().binding.scope.scope_ref
            || stage_response.work_item_id != work_item_id.as_str()
            || stage_response.proposed_attempt_id != proposed_attempt_id.as_str()
            || stage_response.reservation_id != stage_record.reservation_id.as_str()
            || stage_response.stage_operation_id != stage_record.stage_operation_id.as_str()
            || stage_response.row_operation_id != stage_record.operation_id.as_str()
            || stage_response.receipt_operation_order != stage_receipt.operation_order()
            || stage_receipt.subject_id() != &stage_record.reservation_id
            || stage_receipt.phase() != OperationalPhase::Staged
            || stage_record.work_item_id != work_item_id
            || stage_record.proposed_attempt_id != proposed_attempt_id
            || stage_record.claims != claims
            || stage_record.state != AdmissionReservationState::StagedInactive
            || stage_record.state_fence != stage_fence_from(&state_fence)?
            || stage_record.authority_epoch != authority_epoch
            || stage_record.stage_operation_id.as_str() != stage_receipt_id
        {
            return Err(CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "original ORS E stage row, receipt, or request joins changed",
            ));
        }

        let created_at_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                    "system clock is before Unix epoch",
                ))?
                .as_millis(),
        )
        .map_err(|_| CapturedLspAdoptionError::SelectedSourceCaptureRequest(
            "system clock exceeds source-snapshot record range",
        ))?;
        let record = ProposedAttemptRecord {
            work_item_id: work_item_id.as_str().to_owned(),
            proposed_attempt_id: proposed_attempt_id.as_str().to_owned(),
            reservation_id: stage_record.reservation_id.as_str().to_owned(),
            reservation_stage_receipt_id: stage_receipt_id.to_owned(),
            request_identity: serde_json::to_value(&child_identity)?,
            parent_operation_id: parent_operation_id.as_str().to_owned(),
            task_id: selected.task_ref().to_owned(),
            session_id: selected.session_ref().to_owned(),
            work_scope_id: selected.work_scope().binding.scope.scope_ref.clone(),
            work_lease_id: selected.selection_source_ref().to_owned(),
            principal_id: selected.principal_ref().to_owned(),
            operation: eliot_store_api::SOURCE_SNAPSHOT_STAGE_OPERATION.to_owned(),
            selected_relative_path: claimed.invocation.selected_relative_path.clone(),
            selector: None,
            source_digest: source_stage.record.source_digest.clone(),
            configuration_digest: source_stage.record.configuration_digest.clone(),
            action_contract_digest: prepared.action_contract_sha256().to_owned(),
            authority_epoch: serde_json::to_value(&authority_epoch)?,
            reservation_claims: serde_json::to_value(&claims)?,
            source_snapshot_admission: Some(source_binding.clone()),
            state_fence: state_fence.clone(),
            disposition: "ADMITTED".to_owned(),
            created_at_ms,
        };
        record.validate().map_err(|error| {
            CapturedLspAdoptionError::CanonicalEnvelope(error.to_string())
        })?;
        self.governor
            .check_canonical_write_work_scope(
                &record.work_scope_id,
                &current.work_scope().binding,
                Some((governing_sources, privacy_profile)),
            )
            .map_err(CapturedLspAdoptionError::TaskSelection)?;
        let command = eliot_store_api::proposed_attempt_record_request(&record)
            .map_err(|error| CapturedLspAdoptionError::CanonicalEnvelope(error.to_string()))?;
        let manifests = eliot_store_api::generated_operation_manifests()
            .map_err(|error| CapturedLspAdoptionError::CanonicalEnvelope(error.to_string()))?;
        let operation_manifest_digest = eliot_store_api::operation_manifest_set_digest(&manifests)
            .map_err(|error| CapturedLspAdoptionError::CanonicalEnvelope(error.to_string()))?;
        let operation_id = OperationId::new(stage_response.stage_operation_id.clone())
            .map_err(|error| CapturedLspAdoptionError::CanonicalEnvelope(error.to_string()))?;
        let envelope = CanonicalWriteEnvelope {
            operation_id: operation_id.clone(),
            request: child_identity.request.metadata.clone(),
            idempotency_key: child_identity.idempotency_key.clone(),
            scope_id: eliot_store_api::ScopeId::new(record.work_scope_id.clone())
                .map_err(|error| CapturedLspAdoptionError::CanonicalEnvelope(error.to_string()))?,
            task_id: Some(record.task_id.clone()),
            transition_class: eliot_store_api::TransitionClass::TaskControl,
            requested_effect_ceiling: eliot_store_api::EffectClass::ReversibleMutation,
            admission_contract_set_digest: eliot_canonical::supported_admission_contract_set_digest()
                .map_err(|error| CapturedLspAdoptionError::CanonicalEnvelope(error.to_string()))?,
            operation_manifest_digest,
            semantic_commands: vec![command],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: eliot_store_api::SecurityContext::default(),
            required_proof_and_approval_refs: vec![
                record.work_item_id.clone(),
                record.proposed_attempt_id.clone(),
                record.reservation_stage_receipt_id.clone(),
                record.source_digest.clone(),
                record.configuration_digest.clone(),
                record.action_contract_digest.clone(),
                source_binding.archive_sha256.clone(),
                source_binding.blob_root_owner_id.clone(),
                source_binding.canonical_locator.clone(),
            ],
            expected_revision_heads: Vec::new(),
            expected_ordering_heads: Vec::new(),
        };
        envelope.validate().map_err(|error| {
            CapturedLspAdoptionError::CanonicalEnvelope(error.to_string())
        })?;
        let transition = self
            .governor
            .owners()
            .canonical
            .prepare(&envelope)
            .map_err(|error| CapturedLspAdoptionError::CanonicalEnvelope(error.to_string()))?;
        if transition.identity.operation_id != operation_id
            || transition.named_operations.len() != 1
            || transition.named_operations[0].operation
                != eliot_store_api::NamedMutationOperation::AdmitProposedAttempt
        {
            return Err(CapturedLspAdoptionError::CanonicalEnvelope(
                "canonical owner changed the exact SourceSnapshotStage operation".to_owned(),
            ));
        }
        let causal = KernelTransitionPort::apply_prepared_with_causal(
            kernel,
            &child_identity,
            transition,
            Vec::new(),
            Vec::new(),
        )
        .await
        .map_err(CapturedLspAdoptionError::KernelTransition)?;
        let receipt = &causal.receipt;
        if receipt.operation_id != operation_id
            || receipt.idempotency_key != child_identity.idempotency_key
            || receipt.state_fence != state_fence
            || receipt.status != eliot_store_api::WriteReceiptStatus::Committed
            || receipt.commit_id.is_none()
            || receipt.outbox_refs.is_empty()
        {
            return Err(CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "canonical E receipt does not commit the exact staged SourceSnapshotStage operation",
            ));
        }
        let readback = KernelTransitionPort::receipt(kernel, operation_id.clone())
            .await
            .map_err(CapturedLspAdoptionError::KernelTransition)?
            .ok_or(CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "canonical owner omitted the exact SourceSnapshotStage receipt readback",
            ))?;
        if readback != *receipt {
            return Err(CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "canonical SourceSnapshotStage receipt changed at the original owner readback",
            ));
        }
        let activated = kernel
            .activate_source_snapshot_effect_reservation_async(
                &claimed.request_identity,
                &parent_operation_id,
                &claimed.host_request_envelope.envelope_sha256,
                &child_identity,
                selected.work_scope().binding.scope.scope_ref.as_str(),
                &stage_record.reservation_id,
                &work_item_id,
                &proposed_attempt_id,
                &claims,
                prepared.semantic_admission_revision(),
                prepared.action_contract_sha256(),
                receipt,
                &readback,
            )
            .await
            .map_err(|error| CapturedLspAdoptionError::KernelTransition(
                eliot_governor::KernelPortError::Contract(error.to_string()),
            ))?;
        let active_value = activated.get("value").cloned().ok_or(
            CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "Kernel source-snapshot E activation omitted its typed owner response",
            ),
        )?;
        let active: eliot_protocol::InstrumentRegistryEffectReservationActivateResponse =
            serde_json::from_value(active_value).map_err(|_| {
                CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                    "Kernel source-snapshot E activation failed its protocol decoder",
                )
            })?;
        let active_record: eliot_ors::AdmissionReservationRecord =
            serde_json::from_value(active.record.clone()).map_err(|_| {
                CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                    "Kernel source-snapshot E activation omitted its original ORS record",
                )
            })?;
        let active_receipt: eliot_ors::OperationalMutationReceipt =
            serde_json::from_value(active.receipt.clone()).map_err(|_| {
                CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                    "Kernel source-snapshot E activation omitted its original ORS receipt",
                )
            })?;
        active_record.validate().map_err(|_| {
            CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "original ORS source-snapshot E active record failed validation",
            )
        })?;
        if active.parent_operation_id != parent_operation_id.as_str()
            || active.parent_request_digest != claimed.host_request_envelope.envelope_sha256
            || active.parent_request_identity != claimed.request_identity
            || active.child_request_identity != child_identity
            || active.work_scope_id != selected.work_scope().binding.scope.scope_ref
            || active.reservation_id != stage_record.reservation_id.as_str()
            || active.stage_operation_id != stage_record.stage_operation_id.as_str()
            || active.row_operation_id != active_record.operation_id.as_str()
            || active.receipt_operation_order != active_receipt.operation_order()
            || active_receipt.record_id().as_str() != active_record.operation_id.as_str()
            || active_receipt.subject_id() != &stage_record.reservation_id
            || active_receipt.phase() != OperationalPhase::Active
            || active_record.reservation_id != stage_record.reservation_id
            || active_record.claims != claims
            || active_record.state != AdmissionReservationState::Active
            || active_record.canonical_admission.as_ref().is_none_or(|admission| {
                admission.operation_id.as_str() != operation_id.as_str()
                    || admission.commit_id.as_str()
                        != receipt.commit_id.as_ref().map(|id| id.as_str()).unwrap_or_default()
            })
            || active_record.state_fence != stage_record.state_fence
            || active_record.authority_epoch != stage_record.authority_epoch
        {
            return Err(CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "active E ORS row does not retain the exact staged claims and canonical receipt",
            ));
        }
        Ok(SelectedSourceSnapshotCanonicalAdmission {
            record,
            prepared,
            claims,
            reservation_id: stage_record.reservation_id,
            work_item_id,
            proposed_attempt_id,
        })
    }

    /// Rebuilds the exact E claims from current owners, performs Kernel's
    /// original ACTIVE-use read, stages the retained archive under the
    /// resulting distinct mutation admission, then issues a separate Read
    /// against the exact Blob ready receipt and verifies the original owner
    /// readback. The selected-source S Read is never promoted to a write.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn admit_and_readback_selected_source_snapshot(
        &mut self,
        kernel: &DaemonKernelClient,
        claimed: &SelectedSourceCaptureClaimedInvocation,
        selected: &TaskSelectionAdmissionBinding,
        source_stage: &SelectedSourceCaptureCanonicalAdmission,
        canonical: SelectedSourceSnapshotCanonicalAdmission,
        source_read_admission: &eliot_governor::SourceArtifactAdmission,
        target: &SourceArtifactStagingTarget,
        observed: ObservedSelectedSourceSnapshot,
        staged_claims: &LspSourcePublicationClaimSet,
        current_claims: &LspSourcePublicationClaimSet,
    ) -> Result<SelectedSourceSnapshotPublicationReadback, CapturedLspAdoptionError> {
        staged_claims.require_same_current_owners(current_claims).map_err(|_| {
            CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "source-snapshot E original owner roles changed before use-time admission",
            )
        })?;
        let fresh = self
            .selected_source_capture_task_selection(
                &claimed.host_request_envelope,
                &claimed.request_identity,
            )
            .await?;
        if &fresh != selected
            || canonical.record.source_snapshot_admission.as_ref().is_none_or(|binding| {
                binding.owner_claim_payloads != current_claims.owner_claim_payloads()
                    || binding.archive_sha256 != observed.archive_sha256()
                    || binding.blob_root_owner_id != target.blob_root_id()
                    || binding.canonical_locator != target.resource_ref()
            })
            || canonical.claims != *current_claims.claims()
            || canonical.reservation_id.as_str() != canonical.record.reservation_id
            || canonical.work_item_id.as_str() != canonical.record.work_item_id
            || canonical.proposed_attempt_id.as_str() != canonical.record.proposed_attempt_id
        {
            return Err(CapturedLspAdoptionError::SelectedSourceCaptureRequest(
                "canonical SourceSnapshotStage record, current E roles, and exact archive target diverged",
            ));
        }
        let mutation_admission = self
            .governor
            .admit_prepared_selected_source_snapshot_mutation(
                &claimed.request_identity,
                canonical.prepared,
                canonical.reservation_id,
                canonical.work_item_id,
                canonical.proposed_attempt_id,
                canonical.claims,
                kernel,
            )
            .await?;
        let mutation_profile = self
            .policy_owner()
            .ok_or(CapturedLspAdoptionError::MissingPolicyOwner)?
            .source_artifact_blob_profile(&mutation_admission)?;
        let staged = crate::lsp_source_owner_inputs::stage_selected_source_snapshot(
            self.source_artifact_owner(),
            &mutation_admission,
            &mutation_profile,
            target,
            observed,
        )?;
        let reference = staged.artifact_reference();
        let reference_payload = serde_json::to_value(reference)?;
        let reference_read_admission = self
            .governor
            .admit_selected_source_snapshot_reference_read(
                &claimed.host_request_envelope,
                &claimed.request_identity,
                selected,
                &source_stage.causal_receipt,
                &reference.expected_ready_receipt_id,
                &reference_payload,
            )?;
        let reference_read_profile = self
            .policy_owner()
            .ok_or(CapturedLspAdoptionError::MissingPolicyOwner)?
            .source_artifact_blob_profile(&reference_read_admission)?;
        let artifact_inputs = crate::lsp_source_owner_inputs::readback_selected_source_snapshot(
            self.source_artifact_owner(),
            &reference_read_admission,
            &reference_read_profile,
            staged,
        )
        .await?;
        Ok(SelectedSourceSnapshotPublicationReadback {
            mutation_admission,
            reference_read_admission,
            artifact_inputs,
        })
    }
}

fn stage_fence_from(fence: &StateFence) -> Result<StateFenceSnapshot, CapturedLspAdoptionError> {
    StateFenceSnapshot::capture(fence, fence.authority_epoch.sequence.get()).map_err(|_| {
        CapturedLspAdoptionError::SelectedSourceCaptureRequest(
            "source-snapshot E fence failed the original ORS snapshot validator",
        )
    })
}
