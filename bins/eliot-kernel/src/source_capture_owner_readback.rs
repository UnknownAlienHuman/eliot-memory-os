//! Exact selected-source owner readback for the authenticated queue parent.
//!
//! Documentation route/read receipts: route `d2fef4e5c729c1358c5c425825fa9a610c7cfb79d843b033d4d799dc76fb55c3`, read `8256815a55dc14d430cd511e927cae811b2bf5c1cb9a31c48b2581204b02b7da`, verified bundle SHA-256 `fd7f6ffa3352e4e462b3563ddcd929326324b5e099218e696898e608c6357bec` (107 required paths; generic-source, host-kernel, canonical-storage, instrument-verification, memory-context, security-privacy, workspace-governance). Read I5.1-5.7, I5.19, I5.26-5.27, I6.15, A12.2-12.3, A13.2/A13.6-A13.9 and I14.14, plus `bins/AGENTS.md` and `crates/kernel/AGENTS.md`. Also read optional I6.6 (`ee8f294bdae82c727429553262c52051699ac8a7b7c9d28474c6f3b98acf3965`) and I8.1 (`879b591421a381daa15c17bb565f949e90a63aaaed124af8dd13fc5b30853228`).
//!
//! The response carries owner-issued values as data only. Kernel derives them
//! from the retained request, canonical Store readback and ORS readback; the
//! Governor still compares those values to its original typed owner stack and
//! obtains active typestate only through ORS's existing verifier.

use crate::{KernelComposition, Session, TransportError};
use eliot_contracts::canonical_json_bytes;
use eliot_kernel_service::source_capture_mutation::{
    CanonicalProposedAttemptAdmission, verify_proposed_attempt_readback,
};
use eliot_ors::{
    AdmissionReservationIdentityInput, AdmissionReservationState, EpochLineage,
    OperationIdentity as OrsOperationIdentity, StateFenceSnapshot, admission_reservation_identity,
    canonical_admission_from_owner_commit, canonical_admission_receipt_from_owner_receipt,
    epoch_lineage_for, proposed_attempt_identity, stage_operation_identity,
    verify_admission_reservation_launch_prerequisite,
};
use eliot_protocol::{
    RequestIdentity, SelectedSourceCaptureInvocation, SelectedSourceOwnerReadback,
};
use eliot_store_api::{
    CONTRACT_VERSION, OperationId, OperationIdentity as StoreOperationIdentity,
    ProposedAttemptRecord, StoreRecoveryRequest, proposed_attempt_record_key,
};

impl KernelComposition {
    /// Reads one exact selected-source parent after canonical admission and ORS
    /// activation. `parent_identity` must equal the request identity retained
    /// with the authenticated queue frame; a same-session sibling request is
    /// never substituted.
    pub(crate) async fn read_selected_source_owner_readback(
        &self,
        session: &Session,
        parent_identity: &RequestIdentity,
    ) -> Result<Option<SelectedSourceOwnerReadback>, TransportError> {
        parent_identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let Some((envelope, invocation, retained_identity)) =
            self.claim_selected_source_capture_pair(session)?
        else {
            return Ok(None);
        };
        if &retained_identity != parent_identity
            || session.module_generation.state_fence != envelope.state_fence
            || parent_identity.request.state_fence != envelope.state_fence
            || envelope.kind != eliot_protocol::HostRequestKind::SelectedSourceCapture
        {
            return Err(TransportError::IdentityConflict);
        }
        invocation
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;

        let parent_operation_id = eliot_protocol::host_request_operation_id(&envelope);
        let retained_stage_intent = {
            let index = self
                .host_request_connection_index
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            index
                .values()
                .flatten()
                .find(|row| {
                    row.operation_id == parent_operation_id
                        && row.request_digest == envelope.envelope_sha256
                        && row.source_capture_envelope.as_ref() == Some(&envelope)
                        && row.source_capture_invocation.as_ref() == Some(&invocation)
                        && row.source_capture_request_identity.as_ref() == Some(parent_identity)
                })
                .and_then(|row| row.source_capture_stage_intent.clone())
        };
        let Some(stage_intent) = retained_stage_intent else {
            return Ok(None);
        };

        let authority_epoch = epoch_lineage_for(&envelope.state_fence.authority_epoch, None)
            .map_err(|_| TransportError::SessionFenced)?;
        let staged_fence = StateFenceSnapshot::capture(
            &envelope.state_fence,
            envelope.state_fence.authority_epoch.sequence.get(),
        )
        .and_then(|snapshot| {
            snapshot
                .validate_against_lineage(&authority_epoch)
                .map(|()| snapshot)
        })
        .map_err(|_| TransportError::SessionFenced)?;

        let causal_operation_id = OrsOperationIdentity::new(parent_operation_id.clone())
            .map_err(|_| TransportError::SessionFenced)?;
        let seed_attempt_id =
            OrsOperationIdentity::new(format!("source-capture-seed:{parent_operation_id}"))
                .map_err(|_| TransportError::SessionFenced)?;
        let mut identity_input = AdmissionReservationIdentityInput {
            work_item_id: stage_intent.work_item_id.clone(),
            proposed_attempt_id: seed_attempt_id,
            causal_operation_id: Some(causal_operation_id),
            semantic_admission_revision: stage_intent.semantic_admission_revision.clone(),
            claims: stage_intent.claims.clone(),
            state_fence: staged_fence.clone(),
            authority_epoch: authority_epoch.clone(),
        };
        let attempt_id = proposed_attempt_identity(&identity_input)
            .map_err(|_| TransportError::SessionFenced)?;
        identity_input.proposed_attempt_id = attempt_id.clone();
        let reservation_id = admission_reservation_identity(&identity_input)
            .map_err(|_| TransportError::SessionFenced)?;
        let stage_operation_id =
            stage_operation_identity(&reservation_id).map_err(|_| TransportError::SessionFenced)?;

        let reservation_snapshot = self
            .generation_gateway
            .ors
            .load_kernel_admission_reservation(&reservation_id)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        let reservation_record = reservation_snapshot.record();
        if reservation_record.state != AdmissionReservationState::Active
            || reservation_record.reservation_id != reservation_id
            || reservation_record.work_item_id != stage_intent.work_item_id
            || reservation_record.proposed_attempt_id != attempt_id
            || reservation_record.stage_operation_id != stage_operation_id
            || reservation_record.claims != stage_intent.claims
            || reservation_record.authority_epoch != authority_epoch
            || reservation_record.state_fence != staged_fence
            || reservation_snapshot.receipt().record_id() != &reservation_record.operation_id
            || reservation_snapshot.receipt().subject_id() != &reservation_id
        {
            return Err(TransportError::IdentityConflict);
        }
        let canonical_admission = reservation_record
            .canonical_admission
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;

        let store = self.retained_store_gateway()?;
        let recovery = store
            .recovery(StoreRecoveryRequest {
                contract_version: CONTRACT_VERSION,
                state_fence: envelope.state_fence.clone(),
                records: vec![proposed_attempt_record_key(
                    stage_intent.work_item_id.as_str(),
                    attempt_id.as_str(),
                )],
                include_receipts: false,
                include_jobs: false,
            })
            .await
            .map_err(|_| TransportError::SessionFenced)?;
        let canonical_recovery_record = recovery
            .owner_records
            .into_iter()
            .next()
            .ok_or(TransportError::UnknownRequest)?;
        canonical_recovery_record
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let attempt_payload = std::str::from_utf8(&canonical_recovery_record.payload)
            .map_err(|_| TransportError::SessionFenced)?;
        let proposed_attempt: ProposedAttemptRecord =
            serde_json::from_str(attempt_payload).map_err(|_| TransportError::SessionFenced)?;
        proposed_attempt
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if canonical_recovery_record
            != proposed_attempt
                .recovery_record()
                .map_err(|_| TransportError::SessionFenced)?
        {
            return Err(TransportError::IdentityConflict);
        }
        validate_attempt_join(
            &proposed_attempt,
            &stage_intent,
            parent_identity,
            &envelope,
            &invocation,
            &reservation_id,
            &attempt_id,
            &stage_operation_id,
            &authority_epoch,
        )?;

        let canonical_operation_id =
            OperationId::new(canonical_admission.operation_id.as_str().to_owned())
                .map_err(|_| TransportError::SessionFenced)?;
        let canonical_causal_receipt = store
            .receipt_with_causal(&envelope.state_fence, canonical_operation_id)
            .await
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        canonical_causal_receipt
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let canonical_write_receipt = canonical_causal_receipt.receipt.clone();
        let original_identity = StoreOperationIdentity {
            operation_id: canonical_write_receipt.operation_id.clone(),
            idempotency_key: canonical_write_receipt.idempotency_key.clone(),
            canonical_request_hash: canonical_write_receipt.canonical_request_hash.clone(),
        };
        let canonical_admission_receipt = canonical_admission_receipt_from_owner_receipt(
            &canonical_write_receipt,
            &canonical_admission.operation_id,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let expected_canonical_admission = canonical_admission_from_owner_commit(
            &canonical_write_receipt,
            canonical_admission.operation_id.as_str(),
            &canonical_admission.launch_outbox_operation_id,
            &canonical_admission.launch_outbox_id,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        if &canonical_admission_receipt != &canonical_admission.admission_receipt
            || expected_canonical_admission != *canonical_admission
            || canonical_write_receipt.state_fence != envelope.state_fence
        {
            return Err(TransportError::IdentityConflict);
        }
        let canonical_admission_outcome: CanonicalProposedAttemptAdmission =
            verify_proposed_attempt_readback(
                store.as_ref(),
                proposed_attempt,
                original_identity,
                canonical_causal_receipt,
            )
            .await
            .map_err(|_| TransportError::SessionFenced)?;
        if canonical_admission_outcome.record_readback
            != canonical_admission_outcome
                .record
                .recovery_record()
                .map_err(|_| TransportError::SessionFenced)?
        {
            return Err(TransportError::IdentityConflict);
        }

        // Recheck the exact parent queue identity and retained stage intent
        // after Store/ORS reads, then sample current authority immediately
        // before the existing launch-prerequisite verifier.
        let Some((current_envelope, current_invocation, current_identity)) =
            self.claim_selected_source_capture_pair(session)?
        else {
            return Err(TransportError::UnknownRequest);
        };
        if current_envelope != envelope
            || current_invocation != invocation
            || current_identity != *parent_identity
        {
            return Err(TransportError::IdentityConflict);
        }
        let current_intent_matches = {
            let index = self
                .host_request_connection_index
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            index
                .values()
                .flatten()
                .find(|row| {
                    row.operation_id == parent_operation_id
                        && row.request_digest == envelope.envelope_sha256
                        && row.source_capture_envelope.as_ref() == Some(&envelope)
                        && row.source_capture_request_identity.as_ref() == Some(parent_identity)
                })
                .is_some_and(|row| row.source_capture_stage_intent.as_ref() == Some(&stage_intent))
        };
        if !current_intent_matches {
            return Err(TransportError::IdentityConflict);
        }

        let current_state_fence = self
            .current_state_fence()
            .ok_or(TransportError::SessionFenced)?;
        if current_state_fence != envelope.state_fence {
            return Err(TransportError::SessionFenced);
        }
        let current_authority_epoch = epoch_lineage_for(&current_state_fence.authority_epoch, None)
            .map_err(|_| TransportError::SessionFenced)?;
        let current_state_fence_snapshot = StateFenceSnapshot::capture(
            &current_state_fence,
            current_state_fence.authority_epoch.sequence.get(),
        )
        .and_then(|snapshot| {
            snapshot
                .validate_against_lineage(&current_authority_epoch)
                .map(|()| snapshot)
        })
        .map_err(|_| TransportError::SessionFenced)?;
        let observed_at_unix_ms =
            i64::try_from(crate::unix_ms()).map_err(|_| TransportError::SessionFenced)?;
        match verify_admission_reservation_launch_prerequisite(
            Some(&reservation_snapshot),
            &stage_intent.work_item_id,
            &attempt_id,
            &current_authority_epoch,
            &current_state_fence_snapshot,
            observed_at_unix_ms,
        )
        .map_err(|_| TransportError::SessionFenced)?
        {
            eliot_ors::AdmissionReservationLaunchPrerequisite::Active(_) => {}
            _ => return Err(TransportError::SessionFenced),
        }

        let owner_readback = SelectedSourceOwnerReadback::from_owner_readback(
            retained_identity,
            invocation,
            serde_json::to_value(&canonical_admission_outcome.record)
                .map_err(|_| TransportError::SessionFenced)?,
            serde_json::to_value(&canonical_admission_outcome.record_readback)
                .map_err(|_| TransportError::SessionFenced)?,
            serde_json::to_value(&canonical_admission_outcome.receipt)
                .map_err(|_| TransportError::SessionFenced)?,
            serde_json::to_value(&canonical_admission_outcome.causal_receipt)
                .map_err(|_| TransportError::SessionFenced)?,
            serde_json::to_value(reservation_snapshot.record())
                .map_err(|_| TransportError::SessionFenced)?,
            serde_json::to_value(reservation_snapshot.receipt())
                .map_err(|_| TransportError::SessionFenced)?,
            serde_json::to_value(&current_authority_epoch)
                .map_err(|_| TransportError::SessionFenced)?,
            serde_json::to_value(&current_state_fence_snapshot)
                .map_err(|_| TransportError::SessionFenced)?,
            observed_at_unix_ms,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        Ok(Some(owner_readback))
    }
}

fn validate_attempt_join(
    record: &ProposedAttemptRecord,
    intent: &eliot_kernel_service::source_capture_mutation::SelectedSourceCaptureStageIntent,
    request_identity: &RequestIdentity,
    envelope: &eliot_protocol::HostRequestEnvelope,
    invocation: &SelectedSourceCaptureInvocation,
    reservation_id: &OrsOperationIdentity,
    attempt_id: &OrsOperationIdentity,
    stage_operation_id: &OrsOperationIdentity,
    authority_epoch: &EpochLineage,
) -> Result<(), TransportError> {
    let expected_operation = String::from_utf8(
        canonical_json_bytes(&invocation.operation).map_err(|_| TransportError::SessionFenced)?,
    )
    .map_err(|_| TransportError::SessionFenced)?;
    let task_id = envelope
        .identity
        .task_id
        .as_deref()
        .ok_or(TransportError::SessionFenced)?;
    let session_id = envelope
        .identity
        .session_id
        .as_deref()
        .ok_or(TransportError::SessionFenced)?;
    let work_scope_id = envelope
        .identity
        .work_scope_id
        .as_deref()
        .ok_or(TransportError::SessionFenced)?;
    let expected_request_identity =
        serde_json::to_value(request_identity).map_err(|_| TransportError::SessionFenced)?;
    let expected_authority_epoch =
        serde_json::to_value(authority_epoch).map_err(|_| TransportError::SessionFenced)?;
    let expected_claims =
        serde_json::to_value(&intent.claims).map_err(|_| TransportError::SessionFenced)?;
    if record.work_item_id != intent.work_item_id.as_str()
        || record.proposed_attempt_id != attempt_id.as_str()
        || record.reservation_id != reservation_id.as_str()
        || record.reservation_stage_receipt_id != stage_operation_id.as_str()
        || record.request_identity != expected_request_identity
        || record.parent_operation_id != eliot_protocol::host_request_operation_id(envelope)
        || record.task_id != task_id
        || record.session_id != session_id
        || record.work_scope_id != work_scope_id
        || record.work_lease_id != intent.work_lease_id
        || record.principal_id != intent.principal_id
        || record.operation != expected_operation
        || intent.operation != expected_operation
        || record.selected_relative_path != invocation.selected_relative_path
        || record.selected_relative_path != intent.selected_relative_path
        || record.selector != invocation.selector
        || record.selector != intent.selector
        || record.source_digest != intent.source_digest
        || record.configuration_digest != intent.configuration_digest
        || record.action_contract_digest != intent.action_contract_digest
        || record.authority_epoch != expected_authority_epoch
        || record.reservation_claims != expected_claims
        || record.state_fence != envelope.state_fence
        || record.disposition != "ADMITTED"
    {
        return Err(TransportError::IdentityConflict);
    }
    Ok(())
}
