//! Daemon claim lanes that are not evidence queries.
//!
//! Two admitted daemon shapes travel this path and neither of them is an
//! evidence query:
//!
//! - the campaign packet (`eliot.packet`), which compiles one immutable
//!   campaign learning-state view from owner-issued rows, and
//! - the Task Controller invocation (`eliot.task-controller`), which is
//!   decoded by the daemon only after it claimed the exact fenced attempt.
//!
//! Each owns an independent queue slot, an independent attempt ledger, and an
//! independent result submit gate, so a packet result can never complete a
//! query claim and a query claim can never be reinterpreted as a packet. The
//! shared submission gate, the shared attempt-capability derivation, and the
//! evidence-query queue itself stay in the parent host-request route: this
//! module owns only the two lanes that the P-04 route did not admit.
//!
//! The lanes are Kernel-owned queue memory, not durable state: the ORS
//! host-request record owns lifecycle state, so eviction and retirement here
//! only drop daemon-leg memory and never fabricate admission.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use eliot_ors::{HostRequestRecord, HostRequestState, OperationIdentity, OrsError};
use eliot_protocol::{
    FinishAttempt, FinishResultBody, HOST_REQUEST_INVOKE_READ_WIRE_ID,
    HostRequestAdmissionReceipt, HostRequestEnvelope, HostRequestInvokeReadPayload,
    HostRequestResultBody, TaskControllerAttempt, TaskControllerInvocation,
    TaskControllerResultBody, host_request_operation_id,
};
use eliot_store_api::{CONTRACT_VERSION, OperationId, ScopeId, StoreRecoveryRequest, WriteReceipt};

use crate::{
    AuditEventDraft, KernelComposition, Session, TransportError, activation_deadline_expired,
    unix_ms,
};

use super::{
    DaemonReadQueue, ExpiredClaimObservation, ExpiryRetireLane, HostRequestOperationRef,
    LOCAL_READ_ENQUEUE_SALT, LocalReadAdmission, LocalReadAttemptState, LocalReadSubmitDisposition,
    MAX_QUEUED_LOCAL_READS, StaleLocalReadObservation, StaleLocalReadReason,
    check_local_read_admission,
};

/// Refuses a campaign-packet staging candidate that repeats retained work.
///
/// I7.24 step 5: a materially repeated effect-capable call on unchanged
/// inputs without new owner-observed evidence is a loop/no-progress signal,
/// not a fresh dispatch. Only campaign-packet pairs are compared; other
/// lanes and unreconstructible pairs never match. The class derives from the
/// accepted `admission` the enqueue path already owns, and a reworded
/// expected delta alone is not progress.
fn refuse_campaign_staged_repeat(
    admission: &LocalReadAdmission,
    index: &BTreeMap<String, Vec<HostRequestOperationRef>>,
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<(), TransportError> {
    let Some(current) = crate::tool_exposure::build_tool_call_request(envelope, tool, admission)
    else {
        return Ok(());
    };
    let retained = index.values().flatten().filter_map(|candidate| {
        Some((
            candidate.campaign_packet_envelope.as_ref()?,
            candidate.campaign_packet_tool.as_ref()?,
        ))
    });
    if crate::tool_exposure::staged_repeat_without_progress(retained, &current).is_some() {
        return Err(TransportError::IdentityConflict);
    }
    Ok(())
}

/// Evicts one stale (non-live) campaign-packet candidate across scopes.
///
/// Returns whether a slot was freed; when nothing is evictable the queue is
/// genuinely full and the caller refuses with backpressure.
fn evict_one_stale_campaign_packet(
    index: &mut std::collections::BTreeMap<String, Vec<HostRequestOperationRef>>,
) -> bool {
    for refs in index.values_mut() {
        if let Some(position) = refs.iter().position(|candidate| {
            candidate.campaign_packet_envelope.is_some()
                && !candidate.campaign_packet_attempt.is_live()
        }) {
            refs.remove(position);
            return true;
        }
    }
    false
}

impl KernelComposition {
    async fn read_finish_decision_authority(
        &self,
        gateway: &crate::KernelStoreGateway,
        envelope: &HostRequestEnvelope,
        operation_id: &str,
    ) -> Result<Option<(WriteReceipt, serde_json::Value)>, TransportError> {
        let operation = OperationId::new(operation_id.to_owned())
            .map_err(|_| TransportError::SessionFenced)?;
        let observed = gateway
            .receipt(&envelope.state_fence, operation.clone())
            .await
            .map_err(|_| TransportError::SessionFenced)?;
        let Some(observed) = observed else {
            return Ok(None);
        };
        if observed.status != eliot_store_api::WriteReceiptStatus::Committed
            || observed.transition_class != eliot_store_api::TransitionClass::RecoverySchema
        {
            return Ok(None);
        }
        let snapshot = gateway
            .recovery(StoreRecoveryRequest {
                contract_version: CONTRACT_VERSION,
                state_fence: envelope.state_fence.clone(),
                records: Vec::new(),
                include_receipts: true,
                include_jobs: false,
                receipt_authority_operation_ids: vec![operation.clone()],
            })
            .await
            .map_err(|_| TransportError::SessionFenced)?;
        finish_authority_from_snapshot(&snapshot, &observed, &operation, envelope)
    }

    /// Reconciles an exact completed Finish invoke-read on the asynchronous
    /// public bridge path. The presented envelope/tool/admission receipt bind
    /// the original request; the ORS result body is served only after the
    /// current retained application owner is revalidated around an actual
    /// canonical Store receipt read.
    pub async fn finish_replay_reply(
        &self,
        connection_id: &str,
        replay: crate::FinishReplayAction,
    ) -> Result<crate::Frame, TransportError> {
        let crate::FinishReplayAction {
            request_id,
            protocol_version,
            envelope,
            tool,
            admission_receipt,
            record: expected_record,
            reconnect_envelope,
            logical_key,
        } = replay;
        let persisted: super::PersistedFinishReplayBinding = serde_json::from_value(
            expected_record
                .finish_replay_binding
                .clone()
                .ok_or(TransportError::UnknownRequest)?,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        if persisted.envelope != envelope || persisted.tool != tool {
            return Err(TransportError::IdentityConflict);
        }
        let session_before = self.host_request_bridge_session(connection_id)?;
        let validate = |session: &Session| {
            if let Some(current) = reconnect_envelope.as_ref() {
                self.validate_finish_reconnect_binding(
                    session,
                    current,
                    &persisted,
                    &admission_receipt,
                    &expected_record,
                )
            } else {
                self.validate_finish_replay_binding(
                    session,
                    &envelope,
                    &tool,
                    &admission_receipt,
                    &expected_record,
                    &persisted.owner,
                )
            }
        };
        let (operation_id, owner_before) = validate(&session_before)?;
        let gateway = self.retained_store_gateway()?;
        let historical = self
            .read_finish_decision_authority(&gateway, &envelope, &operation_id)
            .await?;

        // Store I/O may overlap cancellation, owner revocation, or queue
        // retirement. Reacquire every original owner binding after the await;
        // no Kernel mutex is held across the asynchronous receipt query.
        let session_after = self.host_request_bridge_session(connection_id)?;
        if session_before != session_after {
            return Err(TransportError::SessionFenced);
        }
        let (operation_after, owner_after) = validate(&session_after)?;
        if operation_after != operation_id || owner_after != owner_before {
            return Err(TransportError::SessionFenced);
        }
        let operation = OperationIdentity::new(operation_id.clone())
            .map_err(|_| TransportError::SessionFenced)?;
        let response = expected_record
            .result_response
            .as_ref()
            .ok_or(TransportError::UnknownRequest)?;
        let result_digest = expected_record
            .result_digest
            .as_deref()
            .ok_or(TransportError::UnknownRequest)?;
        if !finish_result_digest_matches(response, result_digest) {
            return Err(TransportError::IdentityConflict);
        }
        match historical {
            Some((receipt, decision))
                if committed_finish_receipt_matches_owner(
                    &receipt,
                    &operation,
                    &envelope,
                    &owner_after,
                ) && finish_response_matches_committed_decision(
                    response,
                    &envelope,
                    &tool,
                    &receipt,
                    &decision,
                ) => {}
            None if finish_refusal_response_matches(response, &operation_id, &envelope) => {}
            _ => return Err(TransportError::IdentityConflict),
        }
        let value = if let Some(key) = logical_key.as_deref() {
            super::host_request_resolved_response(&expected_record, Some(key))
        } else if reconnect_envelope.is_some() {
            super::host_request_resolved_response(&expected_record, None)
        } else {
            super::host_request_admitted_response(&admission_receipt, &expected_record)
        };
        super::KernelComposition::host_request_correlated_reply(
            &session_after,
            request_id,
            protocol_version,
            value,
        )
        .and_then(|action| match action {
            crate::KernelFrameAction::Reply(frame) => Ok(frame),
            _ => Err(TransportError::SessionFenced),
        })
    }

    fn validate_finish_replay_binding(
        &self,
        session: &Session,
        envelope: &HostRequestEnvelope,
        tool: &serde_json::Value,
        admission_receipt: &eliot_protocol::HostRequestAdmissionReceipt,
        expected_record: &HostRequestRecord,
        original_owner: &super::super::ActivatedApplicationBinding,
    ) -> Result<(String, super::super::ActivatedApplicationBinding), TransportError> {
        envelope
            .validate_for_admission()
            .map_err(|_| TransportError::SessionFenced)?;
        admission_receipt
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if envelope.kind != eliot_protocol::HostRequestKind::Invocation
            || envelope.identity.capability != "eliot.finish"
            || envelope.connection_id != session.connection_id
            || session.module_generation.state_fence != envelope.state_fence
            || !session
                .authority_epoch
                .is_same_authority(&envelope.state_fence.authority_epoch)
            || eliot_protocol::HostRequestAdmissionReceipt::issue(envelope)
                .map_err(|_| TransportError::SessionFenced)?
                != *admission_receipt
        {
            return Err(TransportError::SessionFenced);
        }
        eliot_protocol::HostRequestInvokeReadPayload {
            wire_id: HOST_REQUEST_INVOKE_READ_WIRE_ID.to_owned(),
            wire_version: HostRequestInvokeReadPayload::CONTRACT_VERSION,
            envelope: envelope.clone(),
            tool: tool.clone(),
        }
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
        super::check_finish_admission(envelope, tool)?;
        expected_record
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if !matches!(
            expected_record.state,
            HostRequestState::ResultReceived | HostRequestState::Terminal
        ) || expected_record.result_digest.is_none()
            || expected_record.result_response.is_none()
            || expected_record.payload_body.as_ref() != Some(tool)
        {
            return Err(TransportError::SessionFenced);
        }
        let persisted: super::PersistedFinishReplayBinding = serde_json::from_value(
            expected_record
                .finish_replay_binding
                .clone()
                .ok_or(TransportError::UnknownRequest)?,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        if persisted.envelope != *envelope
            || persisted.tool != *tool
            || persisted.owner != *original_owner
        {
            return Err(TransportError::IdentityConflict);
        }
        let operation_id = host_request_operation_id(envelope);
        let operation = OperationIdentity::new(operation_id.clone())
            .map_err(|_| TransportError::SessionFenced)?;
        let stored = self
            .generation_gateway
            .ors
            .load_host_request(&operation, &envelope.envelope_sha256)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        if stored != *expected_record
            || stored.operation_id.as_str() != operation_id
            || stored.request_digest != envelope.envelope_sha256
            || stored.capability_ref.as_str() != "eliot.finish"
        {
            return Err(TransportError::IdentityConflict);
        }
        let mut expected = super::requested_host_request_record(envelope)?;
        expected
            .finish_replay_binding
            .clone_from(&expected_record.finish_replay_binding);
        if !stored.same_binding(&expected) {
            return Err(TransportError::IdentityConflict);
        }
        let retained_attempt = stored
            .attempt
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        if retained_attempt.phase != eliot_ors::HostRequestAttemptPhase::ResponseReceived {
            return Err(TransportError::SessionFenced);
        }
        let _transition = self.agent_bridge_transition_read()?;
        let admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        // Historical readback is bound to the original retained activation
        // tuple below; requiring a still-live task lease here would turn a
        // completed decision into a new-work admission and strand legitimate
        // post-closure replay.
        let owner = self.finish_owner_binding_for_pair(envelope, tool, &admission_owner)?;
        if &owner != original_owner {
            return Err(TransportError::IdentityConflict);
        }
        Ok((operation_id, owner))
    }

    fn validate_finish_reconnect_binding(
        &self,
        session: &Session,
        reconnect_envelope: &HostRequestEnvelope,
        persisted: &super::PersistedFinishReplayBinding,
        admission_receipt: &eliot_protocol::HostRequestAdmissionReceipt,
        expected_record: &HostRequestRecord,
    ) -> Result<(String, super::super::ActivatedApplicationBinding), TransportError> {
        validate_finish_reconnect_request(
            session,
            reconnect_envelope,
            persisted,
            admission_receipt,
            expected_record,
        )?;
        let original = &persisted.owner;
        let current = self
            .agent_bridge_connections
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .get(&reconnect_envelope.connection_id)
            .and_then(|state| state.activated_binding.clone())
            .ok_or(TransportError::SessionFenced)?;
        let pending = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let lifecycle = self
            .generation_gateway
            .ors
            .load_activation_lifecycle(&original.activation_ticket_id)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        if !KernelComposition::activation_result_still_retained_in(&pending, original)
            || !self.activation_result_still_retained(&pending, original, &lifecycle.connection_id)
        {
            return Err(TransportError::SessionFenced);
        }
        if current.principal_id != original.principal_id
            || current.session_id != original.session_id
            || current.task_id != original.task_id
            || current.work_scope_id != original.work_scope_id
            || !current
                .authority_epoch
                .is_same_authority(&original.authority_epoch)
            || current.activation_generation != original.activation_generation
            || expected_record.operation_id.as_str()
                != host_request_operation_id(&persisted.envelope)
            || expected_record.request_digest != persisted.envelope.envelope_sha256
            || expected_record.capability_ref.as_str() != "eliot.finish"
            || expected_record.payload_body.as_ref() != Some(&persisted.tool)
            || expected_record.finish_replay_binding.as_ref()
                != serde_json::to_value(persisted).ok().as_ref()
        {
            return Err(TransportError::IdentityConflict);
        }
        let operation_id = self.validate_finish_reconnect_record(persisted, expected_record)?;
        Ok((operation_id, original.clone()))
    }

    fn validate_finish_reconnect_record(
        &self,
        persisted: &super::PersistedFinishReplayBinding,
        expected_record: &HostRequestRecord,
    ) -> Result<String, TransportError> {
        let operation_id = host_request_operation_id(&persisted.envelope);
        let operation = OperationIdentity::new(operation_id.clone())
            .map_err(|_| TransportError::SessionFenced)?;
        let stored = self
            .generation_gateway
            .ors
            .load_host_request(&operation, &persisted.envelope.envelope_sha256)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        let mut requested = super::requested_host_request_record(&persisted.envelope)?;
        requested
            .finish_replay_binding
            .clone_from(&expected_record.finish_replay_binding);
        if stored != *expected_record
            || !stored.same_binding(&requested)
            || !matches!(
                stored.state,
                HostRequestState::ResultReceived | HostRequestState::Terminal
            )
            || stored.result_digest.is_none()
            || stored.result_response.is_none()
            || stored.attempt.as_ref().is_none_or(|attempt| {
                attempt.phase != eliot_ors::HostRequestAttemptPhase::ResponseReceived
            })
        {
            return Err(TransportError::IdentityConflict);
        }
        Ok(operation_id)
    }

    pub(super) fn enqueue_campaign_packet_pair_under_transition(
        &self,
        envelope: &HostRequestEnvelope,
        tool: &serde_json::Value,
    ) -> Result<(), TransportError> {
        let admission = check_local_read_admission(envelope, tool)?;
        match admission {
            LocalReadAdmission::CampaignPacket { .. } => {}
            LocalReadAdmission::Query(_) | LocalReadAdmission::Skill => {
                return Err(TransportError::SessionFenced);
            }
        }
        let _admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        self.host_request_connection_gate_under_transition(envelope)?;
        let durable_operation_id = OperationIdentity::new(host_request_operation_id(envelope))
            .map_err(|_| TransportError::SessionFenced)?;
        let durable = self
            .generation_gateway
            .ors
            .bind_host_request_payload(&durable_operation_id, &envelope.envelope_sha256, tool)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        if durable.payload_body.as_ref() != Some(tool) {
            return Err(TransportError::IdentityConflict);
        }
        let mut index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let operation_id = host_request_operation_id(envelope);
        let existing_connection = index.iter().find_map(|(connection_id, refs)| {
            refs.iter()
                .find(|candidate| {
                    candidate.operation_id == operation_id
                        && candidate.request_digest == envelope.envelope_sha256
                })
                .map(|_| connection_id.clone())
        });
        if let Some(existing_connection) = existing_connection.as_deref() {
            if existing_connection != envelope.connection_id {
                return Err(TransportError::IdentityConflict);
            }
            if index
                .get(existing_connection)
                .into_iter()
                .flatten()
                .any(|candidate| {
                    candidate.operation_id == operation_id
                        && candidate.request_digest == envelope.envelope_sha256
                        && candidate.campaign_packet_envelope.is_some()
                })
            {
                return Ok(());
            }
        }
        refuse_campaign_staged_repeat(&admission, &index, envelope, tool)?;
        let queued = index
            .values()
            .flatten()
            .filter(|candidate| candidate.campaign_packet_envelope.is_some())
            .count();
        if queued >= MAX_QUEUED_LOCAL_READS && !evict_one_stale_campaign_packet(&mut index) {
            return Err(TransportError::Backpressure);
        }
        let campaign_packet_attempt = LocalReadAttemptState {
            enqueue_salt: LOCAL_READ_ENQUEUE_SALT.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            ..LocalReadAttemptState::default()
        };
        let refs = index.entry(envelope.connection_id.clone()).or_default();
        if let Some(candidate) = refs.iter_mut().find(|candidate| {
            candidate.operation_id == operation_id
                && candidate.request_digest == envelope.envelope_sha256
        }) {
            candidate.campaign_packet_envelope = Some(envelope.clone());
            candidate.campaign_packet_tool = Some(tool.clone());
            candidate.campaign_packet_attempt = campaign_packet_attempt;
        } else {
            refs.push(HostRequestOperationRef {
                operation_id,
                request_digest: envelope.envelope_sha256.clone(),
                local_read_envelope: None,
                local_read_tool: None,
                local_read_held_bytes: 0,
                local_read_attempt: LocalReadAttemptState::default(),
                observe_envelope: None,
                observe_tool: None,
                observe_reservation: None,
                observe_attempt: LocalReadAttemptState::default(),
                campaign_packet_envelope: Some(envelope.clone()),
                campaign_packet_tool: Some(tool.clone()),
                campaign_packet_attempt,
                task_controller_envelope: None,
                task_controller_tool: None,
                task_controller_attempt: LocalReadAttemptState::default(),
                finish_envelope: None,
                finish_tool: None,
                finish_attempt: LocalReadAttemptState::default(),
                finish_result_received: false,
            });
        }
        self.observe_campaign_packet_exposure(envelope, tool, &admission);
        Ok(())
    }

    fn observe_campaign_packet_exposure(
        &self,
        envelope: &HostRequestEnvelope,
        tool: &serde_json::Value,
        admission: &LocalReadAdmission,
    ) {
        // Exposure evidence is recorded only on fresh staging. Failure to
        // populate remains observation-only and cannot undo queue admission.
        crate::tool_exposure::observe_dispatch_exposure(envelope, tool, admission, |draft| {
            self.audit_observe(draft);
        });
    }

    pub(super) fn enqueue_task_controller_pair_under_transition(
        &self,
        envelope: &HostRequestEnvelope,
        tool: &serde_json::Value,
    ) -> Result<(), TransportError> {
        check_task_controller_admission(envelope, tool)?;
        let _admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        self.host_request_connection_gate_under_transition(envelope)?;
        let mut index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let operation_id = host_request_operation_id(envelope);
        let existing_connection = index.iter().find_map(|(connection_id, refs)| {
            refs.iter()
                .find(|candidate| {
                    candidate.operation_id == operation_id
                        && candidate.request_digest == envelope.envelope_sha256
                })
                .map(|_| connection_id.clone())
        });
        if let Some(existing_connection) = existing_connection.as_deref() {
            if existing_connection != envelope.connection_id {
                return Err(TransportError::IdentityConflict);
            }
            if index
                .get(existing_connection)
                .into_iter()
                .flatten()
                .any(|candidate| {
                    candidate.operation_id == operation_id
                        && candidate.request_digest == envelope.envelope_sha256
                        && candidate.task_controller_envelope.is_some()
                })
            {
                return Ok(());
            }
        }
        let queued = index
            .values()
            .flatten()
            .filter(|candidate| candidate.task_controller_envelope.is_some())
            .count();
        if queued >= MAX_QUEUED_LOCAL_READS {
            let mut evicted = false;
            for refs in index.values_mut() {
                if let Some(position) = refs.iter().position(|candidate| {
                    candidate.task_controller_envelope.is_some()
                        && !candidate.task_controller_attempt.is_live()
                }) {
                    refs.remove(position);
                    evicted = true;
                    break;
                }
            }
            if !evicted {
                return Err(TransportError::Backpressure);
            }
        }
        let task_controller_attempt = LocalReadAttemptState {
            enqueue_salt: LOCAL_READ_ENQUEUE_SALT.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            ..LocalReadAttemptState::default()
        };
        let refs = index.entry(envelope.connection_id.clone()).or_default();
        if let Some(candidate) = refs.iter_mut().find(|candidate| {
            candidate.operation_id == operation_id
                && candidate.request_digest == envelope.envelope_sha256
        }) {
            candidate.task_controller_envelope = Some(envelope.clone());
            candidate.task_controller_tool = Some(tool.clone());
            candidate.task_controller_attempt = task_controller_attempt;
        } else {
            refs.push(HostRequestOperationRef {
                operation_id,
                request_digest: envelope.envelope_sha256.clone(),
                local_read_envelope: None,
                local_read_tool: None,
                local_read_held_bytes: 0,
                local_read_attempt: LocalReadAttemptState::default(),
                observe_envelope: None,
                observe_tool: None,
                observe_reservation: None,
                observe_attempt: LocalReadAttemptState::default(),
                campaign_packet_envelope: None,
                campaign_packet_tool: None,
                campaign_packet_attempt: LocalReadAttemptState::default(),
                task_controller_envelope: Some(envelope.clone()),
                task_controller_tool: Some(tool.clone()),
                task_controller_attempt,
                finish_envelope: None,
                finish_tool: None,
                finish_attempt: LocalReadAttemptState::default(),
                finish_result_received: false,
            });
        }
        Ok(())
    }

    /// Claims the next admitted campaign packet from its independent queue.
    /// The returned capability is never consumable by the evidence-query leg.
    pub(crate) fn claim_campaign_packet_pair(
        &self,
        session: &Session,
    ) -> Result<
        Option<(
            HostRequestEnvelope,
            serde_json::Value,
            eliot_protocol::LocalReadAttempt,
        )>,
        TransportError,
    > {
        let _transition = self.agent_bridge_transition_read()?;
        let admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let mut index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let now = unix_ms();
        for refs in index.values_mut() {
            for candidate in refs.iter_mut() {
                let (Some(envelope), Some(tool)) = (
                    candidate.campaign_packet_envelope.as_ref(),
                    candidate.campaign_packet_tool.as_ref(),
                ) else {
                    continue;
                };
                if activation_deadline_expired(now, envelope.identity.deadline_unix_ms)
                    || envelope.identity.capability != "eliot.packet"
                {
                    continue;
                }
                campaign_packet_admission(envelope, tool)?;
                if !self.application_binding_live_for_claim(envelope, &admission_owner, true)? {
                    continue;
                }
                if !candidate.campaign_packet_attempt.is_owned_by(session) {
                    let generation = candidate
                        .campaign_packet_attempt
                        .generation
                        .checked_add(1)
                        .ok_or(TransportError::SessionFenced)?;
                    candidate.campaign_packet_attempt = LocalReadAttemptState {
                        attempt_id: self.mint_local_read_attempt_id(
                            &candidate.operation_id,
                            candidate.campaign_packet_attempt.enqueue_salt,
                            generation,
                        ),
                        generation,
                        enqueue_salt: candidate.campaign_packet_attempt.enqueue_salt,
                        owner_connection_id: session.connection_id.clone(),
                        owner_launch_nonce: session.launch_nonce.clone(),
                        owner_session_epoch: session.session_epoch,
                    };
                }
                let attempt = self.local_read_attempt_capability(
                    envelope,
                    &candidate.operation_id,
                    &candidate.campaign_packet_attempt,
                )?;
                return Ok(Some((envelope.clone(), tool.clone(), attempt)));
            }
        }
        Ok(None)
    }

    /// Claims the next admitted Task Controller invocation under the same
    /// governed attempt ownership used by local reads. The owner-native
    /// invocation is returned only with its exact admitted envelope/tool pair
    /// and a Kernel-minted attempt capability.
    pub(crate) fn claim_task_controller_pair(
        &self,
        session: &Session,
    ) -> Result<
        Option<(
            HostRequestEnvelope,
            serde_json::Value,
            TaskControllerInvocation,
            TaskControllerAttempt,
        )>,
        TransportError,
    > {
        let _transition = self.agent_bridge_transition_read()?;
        let admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let mut index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let now = unix_ms();
        for refs in index.values_mut() {
            for candidate in refs.iter_mut() {
                let (Some(envelope), Some(tool)) = (
                    candidate.task_controller_envelope.as_ref(),
                    candidate.task_controller_tool.as_ref(),
                ) else {
                    continue;
                };
                if activation_deadline_expired(now, envelope.identity.deadline_unix_ms) {
                    continue;
                }
                let invocation = task_controller_admission(envelope, tool)?;
                if !self.application_binding_live_for_claim(envelope, &admission_owner, true)? {
                    continue;
                }
                if !candidate.task_controller_attempt.is_owned_by(session) {
                    let generation = candidate
                        .task_controller_attempt
                        .generation
                        .checked_add(1)
                        .ok_or(TransportError::SessionFenced)?;
                    candidate.task_controller_attempt = LocalReadAttemptState {
                        attempt_id: self.mint_local_read_attempt_id(
                            &candidate.operation_id,
                            candidate.task_controller_attempt.enqueue_salt,
                            generation,
                        ),
                        generation,
                        enqueue_salt: candidate.task_controller_attempt.enqueue_salt,
                        owner_connection_id: session.connection_id.clone(),
                        owner_launch_nonce: session.launch_nonce.clone(),
                        owner_session_epoch: session.session_epoch,
                    };
                }
                let task_id = envelope
                    .identity
                    .task_id
                    .as_deref()
                    .and_then(|value| value.parse().ok())
                    .ok_or(TransportError::SessionFenced)?;
                let scope_id = envelope
                    .identity
                    .work_scope_id
                    .as_deref()
                    .ok_or(TransportError::SessionFenced)?;
                let session_id = envelope
                    .identity
                    .session_id
                    .as_deref()
                    .ok_or(TransportError::SessionFenced)?;
                let attempt = TaskControllerAttempt {
                    wire_id: eliot_protocol::TASK_CONTROLLER_ATTEMPT_WIRE_ID.to_owned(),
                    wire_version: eliot_protocol::TASK_CONTROLLER_ATTEMPT_WIRE_VERSION,
                    operation_id: candidate.operation_id.clone(),
                    attempt_id: candidate.task_controller_attempt.attempt_id.clone(),
                    fencing_generation: candidate.task_controller_attempt.generation,
                    session_id: session_id.to_owned(),
                    authority_epoch: envelope.state_fence.authority_epoch.clone(),
                    scope_id: scope_id.to_owned(),
                    expires_at_unix_ms: envelope.identity.deadline_unix_ms,
                    use_budget: 1,
                    task_id,
                    state_fence: envelope.state_fence.clone(),
                };
                attempt
                    .validate()
                    .map_err(|_| TransportError::SessionFenced)?;
                return Ok(Some((envelope.clone(), tool.clone(), invocation, attempt)));
            }
        }
        Ok(None)
    }

    pub(super) fn enqueue_finish_pair_under_transition(
        &self,
        envelope: &HostRequestEnvelope,
        tool: &serde_json::Value,
    ) -> Result<(), TransportError> {
        finish_admission(envelope, tool)?;
        let admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        self.finish_owner_binding_for_pair(envelope, tool, &admission_owner)?;
        self.host_request_connection_gate_under_transition(envelope)?;
        let mut index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let operation_id = host_request_operation_id(envelope);
        let existing_connection = index.iter().find_map(|(connection_id, refs)| {
            refs.iter()
                .find(|candidate| {
                    candidate.operation_id == operation_id
                        && candidate.request_digest == envelope.envelope_sha256
                })
                .map(|_| connection_id.clone())
        });
        if let Some(existing_connection) = existing_connection.as_deref() {
            if existing_connection != envelope.connection_id {
                return Err(TransportError::IdentityConflict);
            }
            if index
                .get(existing_connection)
                .into_iter()
                .flatten()
                .any(|candidate| {
                    candidate.operation_id == operation_id
                        && candidate.request_digest == envelope.envelope_sha256
                        && candidate.finish_envelope.is_some()
                })
            {
                return Ok(());
            }
        }
        let queued = index
            .values()
            .flatten()
            .filter(|candidate| candidate.finish_envelope.is_some())
            .count();
        if queued >= MAX_QUEUED_LOCAL_READS {
            let mut evicted = false;
            for refs in index.values_mut() {
                if let Some(position) = refs.iter().position(|candidate| {
                    candidate.finish_envelope.is_some()
                        && (!candidate.finish_attempt.is_live() || candidate.finish_result_received)
                }) {
                    refs.remove(position);
                    evicted = true;
                    break;
                }
            }
            if !evicted {
                return Err(TransportError::Backpressure);
            }
        }
        let finish_attempt = LocalReadAttemptState {
            enqueue_salt: LOCAL_READ_ENQUEUE_SALT.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            ..LocalReadAttemptState::default()
        };
        let refs = index.entry(envelope.connection_id.clone()).or_default();
        if let Some(candidate) = refs.iter_mut().find(|candidate| {
            candidate.operation_id == operation_id
                && candidate.request_digest == envelope.envelope_sha256
        }) {
            candidate.finish_envelope = Some(envelope.clone());
            candidate.finish_tool = Some(tool.clone());
            candidate.finish_attempt = finish_attempt;
            candidate.finish_result_received = false;
        } else {
            refs.push(HostRequestOperationRef {
                operation_id,
                request_digest: envelope.envelope_sha256.clone(),
                local_read_envelope: None,
                local_read_tool: None,
                local_read_held_bytes: 0,
                local_read_attempt: LocalReadAttemptState::default(),
                observe_envelope: None,
                observe_tool: None,
                observe_reservation: None,
                observe_attempt: LocalReadAttemptState::default(),
                campaign_packet_envelope: None,
                campaign_packet_tool: None,
                campaign_packet_attempt: LocalReadAttemptState::default(),
                task_controller_envelope: None,
                task_controller_tool: None,
                task_controller_attempt: LocalReadAttemptState::default(),
                finish_envelope: Some(envelope.clone()),
                finish_tool: Some(tool.clone()),
                finish_attempt,
                finish_result_received: false,
            });
        }
        Ok(())
    }

    /// Claims the next admitted `eliot.finish` pair under the same governed
    /// attempt ownership used by the other daemon lanes. The exact admitted
    /// envelope/tool pair is returned only with a Kernel-minted fenced attempt
    /// capability; the owner-native draft stays opaque here and is decoded by
    /// the daemon only after the claim.
    pub(crate) fn claim_finish_pair(
        &self,
        session: &Session,
    ) -> Result<Option<(HostRequestEnvelope, serde_json::Value, FinishAttempt)>, TransportError>
    {
        let _transition = self.agent_bridge_transition_read()?;
        let admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let mut index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let now = unix_ms();
        for refs in index.values_mut() {
            for candidate in refs.iter_mut() {
                let (Some(envelope), Some(tool)) = (
                    candidate.finish_envelope.as_ref(),
                    candidate.finish_tool.as_ref(),
                ) else {
                    continue;
                };
                finish_admission(envelope, tool)?;
                if !self.application_binding_live_for_claim(envelope, &admission_owner, true)? {
                    continue;
                }
                let owner_binding =
                    self.finish_owner_binding_for_pair(envelope, tool, &admission_owner)?;
                let operation = OperationIdentity::new(candidate.operation_id.clone())
                    .map_err(|_| TransportError::SessionFenced)?;
                let stored = self
                    .generation_gateway
                    .ors
                    .load_host_request(&operation, &candidate.request_digest)
                    .map_err(|_| TransportError::SessionFenced)?
                    .ok_or(TransportError::UnknownRequest)?;
                if stored.operation_id.as_str() != candidate.operation_id
                    || stored.request_digest != candidate.request_digest
                    || stored.capability_ref.as_str() != "eliot.finish"
                {
                    return Err(TransportError::SessionFenced);
                }
                let mut expected = super::requested_host_request_record(envelope)?;
                expected
                    .finish_replay_binding
                    .clone_from(&stored.finish_replay_binding);
                if !stored.same_binding(&expected) || stored.payload_body.as_ref() != Some(tool) {
                    return Err(TransportError::IdentityConflict);
                }
                if !self.bind_claimed_finish_attempt(
                    candidate,
                    &operation,
                    &stored,
                    session,
                    now,
                    envelope,
                )? {
                    continue;
                }
                let attempt = finish_attempt_from_claim(candidate, envelope, &owner_binding)?;
                return Ok(Some((envelope.clone(), tool.clone(), attempt)));
            }
        }
        Ok(None)
    }

    fn bind_claimed_finish_attempt(
        &self,
        candidate: &mut HostRequestOperationRef,
        operation: &OperationIdentity,
        stored: &HostRequestRecord,
        session: &Session,
        now: u64,
        envelope: &HostRequestEnvelope,
    ) -> Result<bool, TransportError> {
        let expired = activation_deadline_expired(now, envelope.identity.deadline_unix_ms);
        if expired {
            // Expired claims reuse the pre-deadline durable attempt. They do
            // not mint a new effect capability; submit still requires receipt.
            if !matches!(
                stored.state,
                HostRequestState::Routed | HostRequestState::Unknown | HostRequestState::Reconciling
            ) {
                return Ok(false);
            }
            let Some(prior) = stored.attempt.as_ref().filter(|attempt| {
                attempt.phase == eliot_ors::HostRequestAttemptPhase::Claimed
            }) else {
                return Ok(false);
            };
            candidate.finish_attempt = LocalReadAttemptState {
                attempt_id: prior.attempt_id.as_str().to_owned(),
                generation: prior.generation,
                enqueue_salt: candidate.finish_attempt.enqueue_salt,
                owner_connection_id: session.connection_id.clone(),
                owner_launch_nonce: session.launch_nonce.clone(),
                owner_session_epoch: session.session_epoch,
            };
            return Ok(true);
        }
        let queue_attempt = candidate.finish_attempt.clone();
        let Some(durable) = self.persist_observe_claim_attempt(
            operation,
            &candidate.request_digest,
            stored,
            &queue_attempt,
            session,
        )? else {
            return Ok(false);
        };
        candidate.finish_attempt = LocalReadAttemptState {
            attempt_id: durable.attempt_id.as_str().to_owned(),
            generation: durable.generation,
            enqueue_salt: candidate.finish_attempt.enqueue_salt,
            owner_connection_id: durable.owner_connection_ref.as_str().to_owned(),
            owner_launch_nonce: durable.owner_launch_nonce.as_str().to_owned(),
            owner_session_epoch: durable.owner_session_epoch,
        };
        Ok(true)
    }

    pub(super) fn live_campaign_packet_attempt_under_transition(
        &self,
        operation_id: &str,
        request_digest: &str,
    ) -> Result<Option<LocalReadAttemptState>, TransportError> {
        let index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(index
            .values()
            .flatten()
            .find(|candidate| {
                candidate.operation_id == operation_id
                    && candidate.request_digest == request_digest
                    && candidate.campaign_packet_envelope.is_some()
            })
            .map(|candidate| candidate.campaign_packet_attempt.clone())
            .filter(LocalReadAttemptState::is_live))
    }

    pub(super) fn retire_campaign_packet_pair_under_transition(
        &self,
        operation_id: &str,
        request_digest: &str,
    ) {
        let Ok(mut index) = self.host_request_connection_index.lock() else {
            return;
        };
        for refs in index.values_mut() {
            refs.retain(|candidate| {
                !(candidate.operation_id == operation_id
                    && candidate.request_digest == request_digest
                    && candidate.campaign_packet_envelope.is_some())
            });
        }
    }

    /// Submits a campaign packet result through its independent attempt and
    /// queue ledger. It cannot consume a query claim.
    pub(crate) fn submit_campaign_packet_result(
        &self,
        session: &Session,
        body: &HostRequestResultBody,
    ) -> Result<LocalReadSubmitDisposition, TransportError> {
        self.submit_claimed_result(session, body, DaemonReadQueue::CampaignPacket)
    }

    /// Submits the result of one claimed Task Controller invocation. The
    /// attempt, task, scope, authority and State Fence joins are checked
    /// against the same live queue record before the result reaches ORS.
    pub(crate) fn submit_task_controller_result(
        &self,
        session: &Session,
        body: &TaskControllerResultBody,
    ) -> Result<LocalReadSubmitDisposition, TransportError> {
        body.validate().map_err(|_| TransportError::SessionFenced)?;
        let _transition = self.agent_bridge_transition_read()?;
        let _admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let operation_id = OperationIdentity::new(body.operation_id.clone())
            .map_err(|_| TransportError::SessionFenced)?;
        let stored = self
            .generation_gateway
            .ors
            .load_host_request(&operation_id, &body.request_sha256)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        if stored.operation_id.as_str() != body.operation_id
            || stored.request_digest != body.request_sha256
            || stored.capability_ref.as_str() != "eliot.task-controller"
        {
            // Issue #1839: durable audit evidence for the refused route.
            if stored.capability_ref.as_str() != "eliot.task-controller" {
                self.audit_observe(AuditEventDraft::route_mismatch_submit(
                    session,
                    &stored,
                    "task-controller",
                ));
            }
            return Err(TransportError::SessionFenced);
        }
        if stored.state == HostRequestState::ResultReceived
            && stored.result_digest.as_deref() == Some(body.result_digest.as_str())
            && stored.result_response.as_ref() == Some(&body.response)
        {
            return Ok(LocalReadSubmitDisposition::Persisted(Box::new(stored)));
        }
        if activation_deadline_expired(unix_ms(), stored.deadline_unix_ms) {
            return self.expired_claim_timeout(ExpiredClaimObservation {
                session: Some(session),
                stored: &stored,
                lane: "task-controller",
                retire: Some(ExpiryRetireLane::TaskController),
                phase: "submit",
                presented_attempt_id: Some(body.attempt.attempt_id.as_str()),
                presented_generation: Some(body.attempt.fencing_generation),
            });
        }
        let (envelope, state) = self.task_controller_queued_pair(body)?;
        if let Some(observation) = task_controller_stale_attempt(body, &state, session, &envelope) {
            return Ok(LocalReadSubmitDisposition::StaleAttempt(observation));
        }
        if !session
            .authority_epoch
            .is_same_authority(&envelope.state_fence.authority_epoch)
            || session.module_generation.state_fence != envelope.state_fence
        {
            return Err(TransportError::SessionFenced);
        }
        let persisted = self
            .generation_gateway
            .ors
            .persist_host_request_result(
                &operation_id,
                &body.request_sha256,
                &body.result_digest,
                &body.response,
                // Issue #1853 W2: a task-controller result body carries neither an
                // executor-observed evidence slot nor a result-lineage slot, so
                // this leg retains neither. The absence means this leg
                // observed and claimed nothing, never a clean execution and
                // never clean provenance.
                None,
                None,
            )
            .map_err(|error| match error {
                OrsError::HostRequestIdentityConflict { .. } => TransportError::IdentityConflict,
                _ => TransportError::SessionFenced,
            })?
            .ok_or(TransportError::UnknownRequest)?;
        self.retire_task_controller_pair_under_transition(&body.operation_id, &body.request_sha256);
        Ok(LocalReadSubmitDisposition::Persisted(Box::new(persisted)))
    }

    /// Submits the result of one claimed `eliot.finish` candidate. The
    /// attempt, operation, authority and State Fence joins are checked
    /// against the same live queue record before the result reaches ORS.
    pub(crate) async fn submit_finish_result_async(
        &self,
        session: &Session,
        body: &FinishResultBody,
    ) -> Result<LocalReadSubmitDisposition, TransportError> {
        body.validate().map_err(|_| TransportError::SessionFenced)?;
        // Read the immutable canonical receipt before entering the synchronous
        // route locks. Every Finish result, including an ordinary first submit,
        // must match the committed canonical operation before ORS can retain
        // its response. A deadline can pass while the Store read is in flight;
        // a missing receipt still times out below.
        let (envelope, _, _) = self.finish_queued_pair(body)?;
        let gateway = self.retained_store_gateway()?;
        let historical = self
            .read_finish_decision_authority(
                &gateway,
                &envelope,
                &body.operation_id,
            )
            .await?;
        self.submit_finish_result(session, body, historical.as_ref())
    }

    fn submit_finish_result(
        &self,
        session: &Session,
        body: &FinishResultBody,
        historical: Option<&(WriteReceipt, serde_json::Value)>,
    ) -> Result<LocalReadSubmitDisposition, TransportError> {
        body.validate().map_err(|_| TransportError::SessionFenced)?;
        let _transition = self.agent_bridge_transition_read()?;
        let admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let operation_id = OperationIdentity::new(body.operation_id.clone())
            .map_err(|_| TransportError::SessionFenced)?;
        let stored = self.load_finish_submit_record(session, body, &operation_id)?;
        let expired = activation_deadline_expired(unix_ms(), stored.deadline_unix_ms);
        if expired && historical.is_none() {
            return self.expired_claim_timeout(ExpiredClaimObservation {
                session: Some(session),
                stored: &stored,
                lane: "finish",
                retire: Some(ExpiryRetireLane::Finish),
                phase: "submit",
                presented_attempt_id: Some(body.attempt.attempt_id.as_str()),
                presented_generation: Some(body.attempt.fencing_generation),
            });
        }
        let (envelope, state, tool) = self.finish_queued_pair(body)?;
        let mut expected = super::requested_host_request_record(&envelope)?;
        expected
            .finish_replay_binding
            .clone_from(&stored.finish_replay_binding);
        if !stored.same_binding(&expected) || stored.payload_body.as_ref() != tool.as_ref() {
            return Err(TransportError::IdentityConflict);
        }
        if !self.application_binding_live_for_claim(&envelope, &admission_owner, true)?
            || !self.finish_attempt_binding_matches_owner(
                body,
                &envelope,
                tool.as_ref().ok_or(TransportError::SessionFenced)?,
                &admission_owner,
            )?
        {
            return Ok(LocalReadSubmitDisposition::StaleAttempt(
                StaleLocalReadObservation {
                    operation_id: body.operation_id.clone(),
                    request_digest: body.request_sha256.clone(),
                    presented_attempt_id: Some(body.attempt.attempt_id.clone()),
                    presented_generation: Some(body.attempt.fencing_generation),
                    current_generation: Some(state.generation),
                    reason: StaleLocalReadReason::Superseded,
                },
            ));
        }
        if let Some(observation) = finish_stale_attempt(body, &state, session, &envelope) {
            return Ok(LocalReadSubmitDisposition::StaleAttempt(observation));
        }
        if !finish_result_matches_committed_authority(
            historical,
            body,
            &envelope,
            tool.as_ref().ok_or(TransportError::SessionFenced)?,
        ) {
            return Err(TransportError::IdentityConflict);
        }
        if !session
            .authority_epoch
            .is_same_authority(&envelope.state_fence.authority_epoch)
            || session.module_generation.state_fence != envelope.state_fence
        {
            return Err(TransportError::SessionFenced);
        }
        // #1824 (I10.21 A2/A3 durability): rebuild the Kernel ledger from
        // its durable sidecar when this process started fresh, so an
        // unreconciled unknown-origin Material change recorded before a
        // restart still blocks governed finish-candidate acceptance. A
        // corrupt or unreadable sidecar fails closed: acceptance blocks
        // instead of trusting a half-read projection.
        if !expired && super::change_monitor::hydrate_ledger_sidecar_if_empty().is_err() {
            return Err(TransportError::SessionFenced);
        }
        // #1824 (I10.21 A2): an unreconciled unknown-origin Material change
        // (or a still-unverified host/filesystem hint) blocks governed
        // finish-candidate acceptance until reconciled. The block is scoped
        // per tracked resource the candidate names: a candidate touching a
        // blocked resource waits for explicit reconciliation of that
        // resource, while unrelated resources are unaffected. A candidate
        // that carries no resource keeps the global gate as fallback. Exact
        // replays above stay readback and unrelated lanes are untouched: the
        // monitor owns its ledger, this leg only queries its gate, and the
        // refusal fails closed without crashing the route.
        if !expired && finish_candidate_acceptance_blocked(tool.as_ref()) {
            return Err(TransportError::SessionFenced);
        }
        let persisted = self
            .generation_gateway
            .ors
            .persist_host_request_result(
                &operation_id,
                &body.request_sha256,
                &body.result_digest,
                &body.response,
                // Issue #1853 W2: a finish result body carries neither an
                // executor-observed evidence slot nor a result-lineage slot, so
                // this leg retains neither. The absence means this leg
                // observed and claimed nothing, never a clean execution and
                // never clean provenance.
                None,
                None,
            )
            .map_err(|error| match error {
                OrsError::HostRequestIdentityConflict { .. } => TransportError::IdentityConflict,
                _ => TransportError::SessionFenced,
            })?
            .ok_or(TransportError::UnknownRequest)?;
        self.mark_finish_result_received_under_transition(
            &body.operation_id,
            &body.request_sha256,
        )?;
        Ok(LocalReadSubmitDisposition::Persisted(Box::new(persisted)))
    }

    fn load_finish_submit_record(
        &self,
        session: &Session,
        body: &FinishResultBody,
        operation_id: &OperationIdentity,
    ) -> Result<HostRequestRecord, TransportError> {
        let stored = self
            .generation_gateway
            .ors
            .load_host_request(operation_id, &body.request_sha256)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        if stored.operation_id.as_str() != body.operation_id
            || stored.request_digest != body.request_sha256
            || stored.capability_ref.as_str() != "eliot.finish"
        {
            if stored.capability_ref.as_str() != "eliot.finish" {
                self.audit_observe(AuditEventDraft::route_mismatch_submit(
                    session, &stored, "finish",
                ));
            }
            return Err(TransportError::SessionFenced);
        }
        Ok(stored)
    }

    fn finish_attempt_binding_matches_owner(
        &self,
        body: &FinishResultBody,
        envelope: &HostRequestEnvelope,
        tool: &serde_json::Value,
        pending: &super::super::AgentActivationPendingState,
    ) -> Result<bool, TransportError> {
        let owner_binding = self.finish_owner_binding_for_pair(envelope, tool, pending)?;
        let mut semantic_fence = envelope.state_fence.clone();
        semantic_fence.task_revision = Some(owner_binding.task_revision);
        Ok(body.attempt.principal_id == owner_binding.principal_id
            && body.attempt.session_id == owner_binding.session_id
            && body.attempt.task_id == owner_binding.task_id
            && body.attempt.work_scope_id == owner_binding.work_scope_id
            && body.attempt.task_revision == owner_binding.task_revision.value()
            && body.attempt.semantic_state_fence == semantic_fence)
    }

    /// Loads the exact live finish queue record for a submitted result. An
    /// absent queue entry is [`TransportError::UnknownRequest`]. The exact
    /// admitted strict finish draft travels with the record so the submit
    /// leg can scope the `ChangeMonitor` acceptance gate to the resources
    /// the candidate names.
    fn finish_queued_pair(
        &self,
        body: &FinishResultBody,
    ) -> Result<
        (
            HostRequestEnvelope,
            LocalReadAttemptState,
            Option<serde_json::Value>,
        ),
        TransportError,
    > {
        let index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let (envelope, state, tool) = index
            .values()
            .flatten()
            .find(|candidate| {
                candidate.operation_id == body.operation_id
                    && candidate.request_digest == body.request_sha256
                    && candidate.finish_envelope.is_some()
            })
            .map(|candidate| {
                (
                    candidate.finish_envelope.clone(),
                    candidate.finish_attempt.clone(),
                    candidate.finish_tool.clone(),
                )
            })
            .ok_or(TransportError::UnknownRequest)?;
        let envelope = envelope.ok_or(TransportError::UnknownRequest)?;
        let tool = tool.ok_or(TransportError::UnknownRequest)?;
        finish_admission(&envelope, &tool)?;
        Ok((envelope, state, Some(tool)))
    }

    pub(crate) fn finish_pair_for_operation(
        &self,
        operation_id: &str,
        request_digest: &str,
    ) -> Result<(HostRequestEnvelope, serde_json::Value), TransportError> {
        let index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let (envelope, tool) = index
            .values()
            .flatten()
            .find(|candidate| {
                candidate.operation_id == operation_id
                    && candidate.request_digest == request_digest
                    && candidate.finish_envelope.is_some()
            })
            .and_then(|candidate| {
                Some((
                    candidate.finish_envelope.clone()?,
                    candidate.finish_tool.clone()?,
                ))
            })
            .ok_or(TransportError::UnknownRequest)?;
        finish_admission(&envelope, &tool)?;
        Ok((envelope, tool))
    }

    /// Reads the original canonical Finish receipt before a pending
    /// cancellation is applied. Store I/O occurs with no Kernel mutex held;
    /// the exact queued bytes and retained activation binding are re-read after
    /// the await so a concurrent retirement or owner change fails closed.
    pub(crate) async fn finish_receipt_before_cancellation(
        &self,
        cancellation: &HostRequestEnvelope,
    ) -> Result<bool, TransportError> {
        let (parent_operation, parent_digest) = super::parent_operation_key(cancellation)?;
        let parent = self
            .generation_gateway
            .ors
            .load_host_request(&parent_operation, &parent_digest)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        if parent.capability_ref.as_str() != "eliot.finish"
            || matches!(
                parent.state,
                HostRequestState::ResultReceived
                    | HostRequestState::Cancelled
                    | HostRequestState::Expired
                    | HostRequestState::Conflicted
                    | HostRequestState::Terminal
            )
        {
            return Ok(false);
        }
        if parent.attempt.is_none()
            && matches!(
                parent.state,
                HostRequestState::Admitted | HostRequestState::Routed
            )
        {
            // Finish owner work cannot be reached until Kernel has durably
            // claimed an ORS attempt. With no attempt to reconcile, there is
            // no Finish capability that has been handed to the daemon.
            return Ok(false);
        }
        let (envelope_before, tool_before) =
            self.finish_pair_for_operation(parent_operation.as_str(), &parent_digest)?;
        let mut expected = super::requested_host_request_record(&envelope_before)?;
        expected
            .finish_replay_binding
            .clone_from(&parent.finish_replay_binding);
        if !parent.same_binding(&expected) {
            return Err(TransportError::IdentityConflict);
        }
        let gateway = self.retained_store_gateway()?;
        let historical = self
            .read_finish_decision_authority(
                &gateway,
                &envelope_before,
                parent_operation.as_str(),
            )
            .await?;

        let parent_after = self
            .generation_gateway
            .ors
            .load_host_request(&parent_operation, &parent_digest)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::UnknownRequest)?;
        if parent_after.state == HostRequestState::ResultReceived
            || matches!(
                parent_after.state,
                HostRequestState::Cancelled
                    | HostRequestState::Expired
                    | HostRequestState::Conflicted
                    | HostRequestState::Terminal
            )
        {
            return Ok(false);
        }
        if !parent_after.same_binding(&expected) {
            return Err(TransportError::IdentityConflict);
        }

        let (envelope_after, tool_after) =
            self.finish_pair_for_operation(parent_operation.as_str(), &parent_digest)?;
        if envelope_after != envelope_before || tool_after != tool_before {
            return Err(TransportError::SessionFenced);
        }
        let pending = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let owner = self.finish_owner_binding_for_pair(&envelope_after, &tool_after, &pending)?;
        let Some((receipt, decision)) = historical else {
            return Ok(false);
        };
        if !committed_finish_receipt_matches_owner(
            &receipt,
            &parent_operation,
            &envelope_after,
            &owner,
        ) || !finish_decision_matches_owner(&decision, &envelope_after, &owner) {
            return Err(TransportError::IdentityConflict);
        }
        Ok(true)
    }

    fn mark_finish_result_received_under_transition(
        &self,
        operation_id: &str,
        request_digest: &str,
    ) -> Result<(), TransportError> {
        let mut index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let candidate = index
            .values_mut()
            .flatten()
            .find(|candidate| {
                candidate.operation_id == operation_id
                    && candidate.request_digest == request_digest
                    && candidate.finish_envelope.is_some()
            })
            .ok_or(TransportError::UnknownRequest)?;
        candidate.finish_result_received = true;
        Ok(())
    }

    /// Loads the exact live Task Controller queue record for a submitted
    /// result. An absent queue entry is [`TransportError::UnknownRequest`].
    fn task_controller_queued_pair(
        &self,
        body: &TaskControllerResultBody,
    ) -> Result<(HostRequestEnvelope, LocalReadAttemptState), TransportError> {
        let index = self
            .host_request_connection_index
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let (envelope, state) = index
            .values()
            .flatten()
            .find(|candidate| {
                candidate.operation_id == body.operation_id
                    && candidate.request_digest == body.request_sha256
                    && candidate.task_controller_envelope.is_some()
            })
            .map(|candidate| {
                (
                    candidate.task_controller_envelope.clone(),
                    candidate.task_controller_attempt.clone(),
                )
            })
            .ok_or(TransportError::UnknownRequest)?;
        let envelope = envelope.ok_or(TransportError::UnknownRequest)?;
        Ok((envelope, state))
    }

    fn retire_task_controller_pair_under_transition(
        &self,
        operation_id: &str,
        request_digest: &str,
    ) {
        let Ok(mut index) = self.host_request_connection_index.lock() else {
            return;
        };
        for refs in index.values_mut() {
            refs.retain(|candidate| {
                !(candidate.operation_id == operation_id
                    && candidate.request_digest == request_digest
                    && candidate.task_controller_envelope.is_some())
            });
        }
    }
}

fn validate_finish_reconnect_request(
    session: &Session,
    reconnect_envelope: &HostRequestEnvelope,
    persisted: &super::PersistedFinishReplayBinding,
    admission_receipt: &HostRequestAdmissionReceipt,
    expected_record: &HostRequestRecord,
) -> Result<(), TransportError> {
    reconnect_envelope
        .validate_for_admission()
        .map_err(|_| TransportError::SessionFenced)?;
    persisted
        .envelope
        .validate_for_admission()
        .map_err(|_| TransportError::SessionFenced)?;
    super::check_finish_admission(&persisted.envelope, &persisted.tool)?;
    HostRequestInvokeReadPayload {
        wire_id: HOST_REQUEST_INVOKE_READ_WIRE_ID.to_owned(),
        wire_version: HostRequestInvokeReadPayload::CONTRACT_VERSION,
        envelope: persisted.envelope.clone(),
        tool: persisted.tool.clone(),
    }
    .validate()
    .map_err(|_| TransportError::SessionFenced)?;
    admission_receipt
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    expected_record
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;

    let owner = &persisted.owner;
    let original = &persisted.envelope;
    let matches_reconnect = reconnect_envelope.kind == eliot_protocol::HostRequestKind::Status
        && reconnect_envelope.connection_id == session.connection_id
        && session.module_generation.state_fence == reconnect_envelope.state_fence
        && session
            .authority_epoch
            .is_same_authority(&reconnect_envelope.state_fence.authority_epoch)
        && owner.activation_generation == original.state_fence.resource_generation
        && owner
            .authority_epoch
            .is_same_authority(&original.state_fence.authority_epoch)
        && original.identity.session_id.as_deref() == Some(owner.session_id.as_str())
        && original.identity.task_id.as_deref() == Some(owner.task_id.as_str())
        && original.identity.work_scope_id.as_deref() == Some(owner.work_scope_id.as_str())
        && !owner.principal_id.trim().is_empty()
        && reconnect_envelope.identity.session_id.as_deref() == Some(owner.session_id.as_str())
        && reconnect_envelope.identity.task_id.as_deref() == Some(owner.task_id.as_str())
        && reconnect_envelope.identity.work_scope_id.as_deref() == Some(owner.work_scope_id.as_str())
        && HostRequestAdmissionReceipt::issue(original)
            .map_err(|_| TransportError::SessionFenced)?
            == *admission_receipt;
    if !matches_reconnect {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

fn finish_authority_from_snapshot(
    snapshot: &eliot_store_api::StoreRecoverySnapshot,
    observed: &WriteReceipt,
    operation: &OperationId,
    envelope: &HostRequestEnvelope,
) -> Result<Option<(WriteReceipt, serde_json::Value)>, TransportError> {
    let receipts = snapshot
        .receipts
        .iter()
        .filter(|receipt| receipt.operation_id == *operation)
        .collect::<Vec<_>>();
    let authorities = snapshot
        .receipt_authorities
        .iter()
        .filter(|authority| authority.operation_id == *operation)
        .collect::<Vec<_>>();
    if receipts.is_empty() && authorities.is_empty() {
        return Ok(None);
    }
    if receipts.len() != 1 || authorities.len() != 1 {
        return Err(TransportError::IdentityConflict);
    }
    let receipt = receipts[0];
    let authority = authorities[0];
    if receipt != observed
        || receipt.status != eliot_store_api::WriteReceiptStatus::Committed
        || receipt.operation_id != *operation
        || receipt.idempotency_key != envelope.identity.idempotency_key
        || receipt.state_fence != envelope.state_fence
        || receipt.transition_class != eliot_store_api::TransitionClass::RecoverySchema
        || authority.state_fence != envelope.state_fence
        || authority.commit_sequence == 0
        || receipt.committed_at.as_deref()
            != Some(format!("commit-sequence-{:016}", authority.commit_sequence).as_str())
        || authority.named_operation_count != authority.records.len()
    {
        return Err(TransportError::IdentityConflict);
    }

    let mut finish_receipts = Vec::new();
    for record in &authority.records {
        let parameters: serde_json::Value = serde_json::from_slice(&record.parameters.bytes)
            .map_err(|_| TransportError::SessionFenced)?;
        let Some(object) = parameters.as_object() else {
            return Err(TransportError::IdentityConflict);
        };
        if object.contains_key("attempt_id")
            && object.contains_key("expected_finish_revision")
            && object.contains_key("receipt_json")
        {
            if object.len() != 4
                || object.get("attempt_id").and_then(serde_json::Value::as_str)
                    != Some(envelope.identity.idempotency_key.as_str())
                || object
                    .get("expected_finish_revision")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|revision| revision.parse::<u64>().ok())
                    .is_none_or(|revision| revision == 0)
                || object
                    .get("task_revision")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|revision| revision.parse::<u64>().ok())
                    .is_none_or(|revision| revision == 0)
            {
                return Err(TransportError::IdentityConflict);
            }
            let raw = object
                .get("receipt_json")
                .and_then(serde_json::Value::as_str)
                .ok_or(TransportError::IdentityConflict)?;
            let retained_decisions: serde_json::Value = serde_json::from_str(raw)
                .map_err(|_| TransportError::IdentityConflict)?;
            let retained_decisions = retained_decisions
                .as_array()
                .ok_or(TransportError::IdentityConflict)?;
            let current_attempt = retained_decisions
                .iter()
                .filter(|decision| {
                    decision.get("attempt_id").and_then(serde_json::Value::as_str)
                        == Some(envelope.identity.idempotency_key.as_str())
                })
                .collect::<Vec<_>>();
            if current_attempt.len() != 1 {
                return Err(TransportError::IdentityConflict);
            }
            let decision = current_attempt[0];
            if object
                .get("task_revision")
                .and_then(serde_json::Value::as_str)
                .and_then(|revision| revision.parse::<u64>().ok())
                != decision.get("task_revision").and_then(serde_json::Value::as_u64)
                || !finish_decision_projection_shape(decision)
            {
                return Err(TransportError::IdentityConflict);
            }
            finish_receipts.push(decision.to_owned());
        }
    }
    if finish_receipts.len() != 1 {
        return Err(TransportError::IdentityConflict);
    }
    Ok(Some((receipt.clone(), finish_receipts.remove(0))))
}

fn finish_attempt_from_claim(
    candidate: &HostRequestOperationRef,
    envelope: &HostRequestEnvelope,
    owner: &super::super::ActivatedApplicationBinding,
) -> Result<FinishAttempt, TransportError> {
    let session_id = envelope
        .identity
        .session_id
        .as_deref()
        .ok_or(TransportError::SessionFenced)?;
    let mut semantic_state_fence = envelope.state_fence.clone();
    semantic_state_fence.task_revision = Some(owner.task_revision);
    let attempt = FinishAttempt {
        wire_id: eliot_protocol::FINISH_ATTEMPT_WIRE_ID.to_owned(),
        wire_version: eliot_protocol::FINISH_ATTEMPT_WIRE_VERSION,
        operation_id: candidate.operation_id.clone(),
        attempt_id: candidate.finish_attempt.attempt_id.clone(),
        fencing_generation: candidate.finish_attempt.generation,
        session_id: session_id.to_owned(),
        principal_id: owner.principal_id.clone(),
        task_id: owner.task_id.clone(),
        work_scope_id: owner.work_scope_id.clone(),
        task_revision: owner.task_revision.value(),
        semantic_state_fence,
        authority_epoch: envelope.state_fence.authority_epoch.clone(),
        expires_at_unix_ms: envelope.identity.deadline_unix_ms,
        use_budget: 1,
    };
    attempt
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    Ok(attempt)
}

fn finish_candidate_acceptance_blocked(tool: Option<&serde_json::Value>) -> bool {
    let resources = finish_candidate_resources(tool);
    let mut resolved_paths = Vec::new();
    let mut has_opaque_handle = false;
    for resource in &resources {
        match normalize_finish_candidate_resource(resource) {
            Some(normalized) => resolved_paths.push(normalized),
            None => has_opaque_handle = true,
        }
    }
    if resolved_paths.is_empty() || has_opaque_handle {
        // No resolvable declared target, or an opaque job/operation handle
        // that could name a blocked resource: keep the global gate as fallback
        // instead of letting an unresolvable list silently pass below.
        super::change_monitor::governed_acceptance_blocked()
    } else {
        resolved_paths.iter().any(|resource| {
            super::change_monitor::governed_acceptance_blocked_for(resource.as_str())
        })
    }
}

/// Requires an actual committed Store receipt for expired Finish reconciliation.
/// The owner tuple is independently checked against the retained Kernel
/// activation binding by `finish_attempt_binding_matches_owner`; this receipt
/// check binds the immutable canonical operation and its semantic task revision
/// while keeping the transport State Fence in its original shape.
fn committed_finish_receipt_matches_attempt(
    receipt: &eliot_store_api::WriteReceipt,
    body: &FinishResultBody,
    envelope: &HostRequestEnvelope,
) -> bool {
    if receipt.validate().is_err()
        || receipt.operation_id.as_str() != body.operation_id
        || receipt.idempotency_key != envelope.identity.idempotency_key
        || receipt.state_fence != envelope.state_fence
        || receipt.transition_class != eliot_store_api::TransitionClass::RecoverySchema
        || receipt.status != eliot_store_api::WriteReceiptStatus::Committed
    {
        return false;
    }
    let Some(core) = receipt.envelope.as_ref().map(|envelope| &envelope.core) else {
        return false;
    };
    let Some(task) = core.task.as_ref() else {
        return false;
    };
    core.operation.operation_id.as_str() == body.operation_id
        && core.operation.idempotency_key == envelope.identity.idempotency_key
        && core.request.state_fence == envelope.state_fence
        && core.request.metadata.task_id.as_ref().is_some_and(|task_id| {
            task_id.as_str() == body.attempt.task_id
        })
        && core.request.metadata.session_id.as_ref().is_some_and(|session_id| {
            session_id.as_str() == body.attempt.session_id
        })
        && task.task_id.as_str() == body.attempt.task_id
        && task.task_revision.value() == body.attempt.task_revision
        && task.state_fence == body.attempt.semantic_state_fence
        // Governor's canonical owner mutations intentionally use this fixed
        // physical Store scope; the application WorkScope remains bound by the
        // retained Kernel activation tuple checked separately above.
        && core.work_scope.scope_id.as_str() == "governor"
}

fn finish_result_matches_committed_authority(
    historical: Option<&(WriteReceipt, serde_json::Value)>,
    body: &FinishResultBody,
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> bool {
    match historical {
        Some((receipt, decision)) => {
            committed_finish_receipt_matches_attempt(receipt, body, envelope)
                && finish_response_matches_committed_decision(
                    &body.response,
                    envelope,
                    tool,
                    receipt,
                    decision,
                )
        }
        None => finish_refusal_response_matches(
            &body.response,
            &body.attempt.operation_id,
            envelope,
        ),
    }
}

fn finish_response_matches_committed_decision(
    response: &serde_json::Value,
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
    receipt: &eliot_store_api::WriteReceipt,
    decision: &serde_json::Value,
) -> bool {
    let Some(arguments) = tool.get("arguments").and_then(serde_json::Value::as_object) else {
        return false;
    };
    let task_id = arguments.get("task_id").and_then(serde_json::Value::as_str);
    let task_revision = arguments
        .get("expected_task_revision")
        .and_then(serde_json::Value::as_u64);
    let requested_outcome = arguments.get("requested_outcome");
    let decision_task_id = decision.get("task_id").and_then(serde_json::Value::as_str);
    let decision_revision = decision.get("task_revision").and_then(serde_json::Value::as_u64);
    let decision_fence = decision.get("state_fence");
    let decision_outcome = decision.get("requested_outcome");
    let Ok(expected_fence) = serde_json::to_value(&envelope.state_fence) else {
        return false;
    };
    if !finish_decision_projection_shape(decision)
        || task_id.is_none()
        || task_revision.is_none()
        || requested_outcome.is_none()
        || decision.get("attempt_id").and_then(serde_json::Value::as_str)
            != Some(envelope.identity.idempotency_key.as_str())
        || decision_task_id != task_id
        || decision_revision != task_revision
        || decision_fence != Some(&expected_fence)
        || decision_outcome != requested_outcome
        || decision
            .get("decision")
            .and_then(|value| value.get("proof"))
            .and_then(|proof| proof.get("task_id"))
            .and_then(serde_json::Value::as_str)
            != task_id
        || decision
            .get("decision")
            .and_then(|value| value.get("proof"))
            .and_then(|proof| proof.get("task_revision"))
            .and_then(serde_json::Value::as_u64)
            != task_revision
        || receipt.idempotency_key != envelope.identity.idempotency_key
        || receipt.state_fence != envelope.state_fence
    {
        return false;
    }
    let Ok(request_sha) = eliot_contracts::canonical_json_bytes(&(
        envelope.envelope_sha256.clone(),
        envelope.identity.request_id.clone(),
        envelope.identity.idempotency_key.clone(),
    ))
    .map(|bytes| eliot_contracts::sha256_hex(&bytes)) else {
        return false;
    };
    let expected = serde_json::json!({
        "request_id": envelope.identity.request_id.clone(),
        "idempotency_key": envelope.identity.idempotency_key.clone(),
        "canonical_request_sha256": request_sha,
        "kind": "CANDIDATE",
        "canonical_tool_name": "eliot.finish",
        "content": decision,
        "artifacts": [],
        "proof_ceiling": "SCOPED_VERIFICATION",
        "resource": null,
        "job": null,
    });
    response == &expected
}

fn finish_result_digest_matches(response: &serde_json::Value, digest: &str) -> bool {
    eliot_contracts::canonical_json_bytes(response)
        .map(|bytes| eliot_contracts::sha256_hex(&bytes) == digest)
        .unwrap_or(false)
}

fn finish_decision_projection_shape(decision: &serde_json::Value) -> bool {
    let Some(receipt) = decision.as_object() else {
        return false;
    };
    let Some(derived) = receipt.get("decision").and_then(serde_json::Value::as_object) else {
        return false;
    };
    let Some(proof) = derived.get("proof").and_then(serde_json::Value::as_object) else {
        return false;
    };
    exact_projection_fields(
        receipt,
        &[
        "decision_id",
        "attempt_id",
        "task_id",
        "task_revision",
        "state_fence",
        "finish_authority_ref",
        "closure_authority_ref",
        "requested_outcome",
        "decision",
        "lifecycle_action",
        "unresolved_descendant_refs",
        "attempt_digest",
        "receipt_digest",
        ],
    ) && exact_projection_fields(derived, &["outcome", "proof", "next_allowed_action"])
        && exact_projection_fields(
            proof,
            &[
        "task_id",
        "task_revision",
        "per_acceptance_coverage",
        "artifact_and_verifier_bindings",
        "checks_not_executed_or_stale",
        "unresolved_effects_and_unknowns",
        "proof_ceiling",
        "derivation_digest",
            ],
        )
        && finish_receipt_fields_valid(receipt)
        && finish_derived_fields_valid(derived)
        && finish_proof_fields_valid(proof)
}

fn exact_projection_fields(
    object: &serde_json::Map<String, serde_json::Value>,
    required: &[&str],
) -> bool {
    object.len() == required.len() && required.iter().all(|key| object.contains_key(*key))
}

fn finish_receipt_fields_valid(receipt: &serde_json::Map<String, serde_json::Value>) -> bool {
    [
            "decision_id",
            "attempt_id",
            "task_id",
            "finish_authority_ref",
            "lifecycle_action",
            "attempt_digest",
            "receipt_digest",
        ]
        .iter()
        .all(|key| receipt.get(*key).is_some_and(serde_json::Value::is_string))
        && receipt
            .get("task_revision")
            .is_some_and(serde_json::Value::is_u64)
        && receipt.get("state_fence").is_some_and(serde_json::Value::is_object)
        && receipt.get("requested_outcome").is_some_and(serde_json::Value::is_string)
        && receipt.get("decision").is_some_and(serde_json::Value::is_object)
        && receipt
            .get("unresolved_descendant_refs")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|values| values.iter().all(serde_json::Value::is_string))
        && receipt
            .get("closure_authority_ref")
            .is_some_and(|value| value.is_null() || value.is_string())
}

fn finish_derived_fields_valid(derived: &serde_json::Map<String, serde_json::Value>) -> bool {
    derived.get("outcome").is_some_and(serde_json::Value::is_string)
        && derived
            .get("next_allowed_action")
            .is_some_and(serde_json::Value::is_string)
}

fn finish_proof_fields_valid(proof: &serde_json::Map<String, serde_json::Value>) -> bool {
    ["task_id", "derivation_digest"]
            .iter()
            .all(|key| proof.get(*key).is_some_and(serde_json::Value::is_string))
        && proof
            .get("task_revision")
            .is_some_and(serde_json::Value::is_u64)
        && proof
            .get("proof_ceiling")
            .is_some_and(serde_json::Value::is_string)
        && [
            "per_acceptance_coverage",
            "artifact_and_verifier_bindings",
            "checks_not_executed_or_stale",
            "unresolved_effects_and_unknowns",
        ]
        .iter()
        .all(|key| {
            proof
                .get(*key)
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| values.iter().all(serde_json::Value::is_string))
        })
}

fn finish_decision_matches_owner(
    decision: &serde_json::Value,
    envelope: &HostRequestEnvelope,
    owner: &super::super::ActivatedApplicationBinding,
) -> bool {
    if !finish_decision_projection_shape(decision) {
        return false;
    }
    let Ok(expected_fence) = serde_json::to_value(&envelope.state_fence) else {
        return false;
    };
    decision.get("attempt_id").and_then(serde_json::Value::as_str)
        == Some(envelope.identity.idempotency_key.as_str())
        && decision.get("task_id").and_then(serde_json::Value::as_str)
            == Some(owner.task_id.as_str())
        && decision.get("task_revision").and_then(serde_json::Value::as_u64)
            == Some(owner.task_revision.value())
        && decision.get("state_fence") == Some(&expected_fence)
        && decision
            .get("decision")
            .and_then(|value| value.get("proof"))
            .and_then(|proof| proof.get("task_id"))
            .and_then(serde_json::Value::as_str)
            == Some(owner.task_id.as_str())
        && decision
            .get("decision")
            .and_then(|value| value.get("proof"))
            .and_then(|proof| proof.get("task_revision"))
            .and_then(serde_json::Value::as_u64)
            == Some(owner.task_revision.value())
}

fn finish_refusal_response_matches(
    response: &serde_json::Value,
    operation_id: &str,
    envelope: &HostRequestEnvelope,
) -> bool {
    let Ok(request_sha) = eliot_contracts::canonical_json_bytes(&(
        envelope.envelope_sha256.clone(),
        envelope.identity.request_id.clone(),
        envelope.identity.idempotency_key.clone(),
    ))
    .map(|bytes| eliot_contracts::sha256_hex(&bytes)) else {
        return false;
    };
    let Some(content) = response.get("content").and_then(serde_json::Value::as_object) else {
        return false;
    };
    response.get("request_id") == Some(&serde_json::json!(envelope.identity.request_id))
        && response.get("idempotency_key")
            == Some(&serde_json::json!(envelope.identity.idempotency_key))
        && response.get("canonical_request_sha256") == Some(&serde_json::json!(request_sha))
        && response.get("kind") == Some(&serde_json::json!("PLAN_GAP"))
        && response.get("canonical_tool_name") == Some(&serde_json::json!("eliot.finish"))
        && response.get("artifacts") == Some(&serde_json::json!([]))
        && response.get("proof_ceiling") == Some(&serde_json::json!("OBSERVATION"))
        && response.get("resource").is_some_and(serde_json::Value::is_null)
        && response.get("job").is_some_and(serde_json::Value::is_null)
        && response.as_object().is_some_and(|object| object.len() == 10)
        && content.len() == 4
        && content.get("status") == Some(&serde_json::json!("rejected"))
        && content.get("reason").and_then(serde_json::Value::as_str).is_some()
        && content.get("disposition").and_then(serde_json::Value::as_str).is_some()
        && content.get("reason_code").and_then(serde_json::Value::as_str).is_some()
        && operation_id == host_request_operation_id(envelope)
}

fn committed_finish_receipt_matches_owner(
    receipt: &eliot_store_api::WriteReceipt,
    operation_id: &OperationIdentity,
    envelope: &HostRequestEnvelope,
    owner: &super::super::ActivatedApplicationBinding,
) -> bool {
    if receipt.validate().is_err()
        || receipt.operation_id.as_str() != operation_id.as_str()
        || receipt.idempotency_key != envelope.identity.idempotency_key
        || receipt.state_fence != envelope.state_fence
        || receipt.transition_class != eliot_store_api::TransitionClass::RecoverySchema
        || receipt.status != eliot_store_api::WriteReceiptStatus::Committed
    {
        return false;
    }
    let Some(core) = receipt.envelope.as_ref().map(|envelope| &envelope.core) else {
        return false;
    };
    let Some(task) = core.task.as_ref() else {
        return false;
    };
    let mut semantic_fence = envelope.state_fence.clone();
    semantic_fence.task_revision = Some(owner.task_revision);
    core.operation.operation_id.as_str() == operation_id.as_str()
        && core.operation.idempotency_key == envelope.identity.idempotency_key
        && core.request.state_fence == envelope.state_fence
        && core
            .request
            .metadata
            .task_id
            .as_ref()
            .is_some_and(|task_id| task_id.as_str() == owner.task_id.as_str())
        && core
            .request
            .metadata
            .session_id
            .as_ref()
            .is_some_and(|session_id| session_id.as_str() == owner.session_id.as_str())
        && task.task_id.as_str() == owner.task_id.as_str()
        && task.task_revision == owner.task_revision
        && task.state_fence == semantic_fence
        && core.work_scope.scope_id.as_str() == "governor"
}

/// Joins a presented Task Controller result against its live queue record.
///
/// Returns `None` only when the presented attempt, task, scope, authority, and
/// State Fence all match the current live record and the presenting session
/// owns it — that is, when the result is allowed to reach ORS. Any mismatch
/// is a noncanonical stale observation with an audit receipt; the durable ORS
/// record is untouched, so the waiter never observes the stale result.
fn task_controller_stale_attempt(
    body: &TaskControllerResultBody,
    state: &LocalReadAttemptState,
    session: &Session,
    envelope: &HostRequestEnvelope,
) -> Option<StaleLocalReadObservation> {
    let observation = |reason| StaleLocalReadObservation {
        operation_id: body.operation_id.clone(),
        request_digest: body.request_sha256.clone(),
        presented_attempt_id: Some(body.attempt.attempt_id.clone()),
        presented_generation: Some(body.attempt.fencing_generation),
        current_generation: Some(state.generation),
        reason,
    };
    if !state.is_owned_by(session) {
        return Some(observation(StaleLocalReadReason::OwnerMismatch));
    }
    if body.attempt.operation_id != body.operation_id
        || body.attempt.attempt_id != state.attempt_id
        || body.attempt.fencing_generation != state.generation
        || body.attempt.task_id.as_str()
            != envelope
                .identity
                .task_id
                .as_deref()
                .ok_or(TransportError::SessionFenced)
                .ok()?
        || body.attempt.scope_id
            != envelope
                .identity
                .work_scope_id
                .as_deref()
                .ok_or(TransportError::SessionFenced)
                .ok()?
        || body.attempt.session_id
            != envelope
                .identity
                .session_id
                .as_deref()
                .ok_or(TransportError::SessionFenced)
                .ok()?
        || body.attempt.expires_at_unix_ms != envelope.identity.deadline_unix_ms
        || body.attempt.state_fence != envelope.state_fence
        || !body
            .attempt
            .authority_epoch
            .is_same_authority(&envelope.state_fence.authority_epoch)
    {
        return Some(observation(StaleLocalReadReason::Superseded));
    }
    None
}

const MAX_CAMPAIGN_PACKET_MATERIALS: usize = 256;
const MAX_CAMPAIGN_PACKET_SELECTOR_BYTES: usize = 4096;

const MAX_FINISH_REF_COUNT: usize = 256;
const MAX_FINISH_REF_BYTES: usize = 4096;

/// Closed requested-outcome set for one strict `eliot.finish` candidate draft
/// (issue #1741, I7.9). The Kernel shape-checks the closed set without naming
/// the Governor draft type; the daemon decodes the exact admitted bytes
/// authoritatively after the claim.
fn finish_requested_outcome(value: &str) -> bool {
    matches!(
        value,
        "COMPLETE_CANDIDATE"
            | "PARTIAL"
            | "BLOCKED"
            | "FAILED_VERIFICATION"
            | "DEGRADED_NO_PROOF"
            | "UNSAFE_TO_FINISH"
            | "CANCELLED"
            | "SUPERSEDED"
    )
}

fn finish_ref_list(value: Option<&serde_json::Value>) -> Result<(), TransportError> {
    let Some(items) = value else {
        return Ok(());
    };
    let items = items.as_array().ok_or(TransportError::SessionFenced)?;
    if items.len() > MAX_FINISH_REF_COUNT {
        return Err(TransportError::SessionFenced);
    }
    let mut seen = std::collections::BTreeSet::new();
    for item in items {
        let text = item
            .as_str()
            .filter(|text| !text.trim().is_empty() && !text.chars().any(char::is_control))
            .ok_or(TransportError::SessionFenced)?;
        if text.len() > MAX_FINISH_REF_BYTES || !seen.insert(text) {
            return Err(TransportError::SessionFenced);
        }
    }
    Ok(())
}

/// Validates the closed `eliot.finish` invoke-read pair before it enters the
/// Kernel-owned queue. The owner-native finish draft remains opaque beyond
/// its closed strict field set: the daemon decodes it only after claiming
/// the exact fenced attempt (issue #1741).
fn finish_admission(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<(), TransportError> {
    HostRequestInvokeReadPayload {
        wire_id: HOST_REQUEST_INVOKE_READ_WIRE_ID.to_owned(),
        wire_version: HostRequestInvokeReadPayload::CONTRACT_VERSION,
        envelope: envelope.clone(),
        tool: tool.clone(),
    }
    .validate()
    .map_err(|_| TransportError::SessionFenced)?;
    let object = tool.as_object().ok_or(TransportError::SessionFenced)?;
    if object.get("name").and_then(serde_json::Value::as_str) != Some("eliot.finish")
        || envelope.identity.capability != "eliot.finish"
        || envelope.identity.payload_schema_id != eliot_protocol::FINISH_INVOKE_PAYLOAD_SCHEMA_ID
    {
        return Err(TransportError::SessionFenced);
    }
    let arguments = object
        .get("arguments")
        .and_then(serde_json::Value::as_object)
        .ok_or(TransportError::SessionFenced)?;
    if arguments.len() != 8
        || arguments.keys().any(|key| {
            !matches!(
                key.as_str(),
                "task_id"
                    | "expected_task_revision"
                    | "requested_outcome"
                    | "artifact_refs"
                    | "observation_refs"
                    | "verifier_run_refs"
                    | "remaining_unknowns_declared_by_caller"
                    | "rationale_candidate"
            )
        })
    {
        return Err(TransportError::SessionFenced);
    }
    let task_id = arguments
        .get("task_id")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        .ok_or(TransportError::SessionFenced)?;
    if task_id.len() > MAX_FINISH_REF_BYTES {
        return Err(TransportError::SessionFenced);
    }
    // Draft task/revision are selectors only. Both must join to an activation
    // owner before staging, and the task/scope fields are mandatory here so a
    // caller draft can never supply its own missing binding.
    if envelope.identity.task_id.as_deref() != Some(task_id)
        || envelope
            .identity
            .work_scope_id
            .as_deref()
            .is_none_or(|scope| scope.trim().is_empty() || scope.chars().any(char::is_control))
        || envelope.state_fence.task_revision.is_some()
    {
        return Err(TransportError::SessionFenced);
    }
    if arguments
        .get("expected_task_revision")
        .and_then(serde_json::Value::as_u64)
        .is_none_or(|value| value == 0)
    {
        return Err(TransportError::SessionFenced);
    }
    let requested_outcome = arguments
        .get("requested_outcome")
        .and_then(serde_json::Value::as_str)
        .ok_or(TransportError::SessionFenced)?;
    if !finish_requested_outcome(requested_outcome) {
        return Err(TransportError::SessionFenced);
    }
    finish_ref_list(arguments.get("artifact_refs"))?;
    finish_ref_list(arguments.get("observation_refs"))?;
    finish_ref_list(arguments.get("verifier_run_refs"))?;
    finish_ref_list(arguments.get("remaining_unknowns_declared_by_caller"))?;
    let rationale = arguments
        .get("rationale_candidate")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        .ok_or(TransportError::SessionFenced)?;
    if rationale.len() > MAX_FINISH_REF_BYTES {
        return Err(TransportError::SessionFenced);
    }
    if envelope.identity.session_id.is_none() {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

pub(super) fn check_finish_admission(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<(), TransportError> {
    finish_admission(envelope, tool)
}

/// Returns the tracked resources one admitted `eliot.finish` candidate
/// names: the `artifact_refs` of its exact digest-bound strict draft. The
/// draft travelled the queue with the candidate, so these are the resources
/// the candidate touches in the ledger's own identity. Anything unexpected
/// (absent tool, unexpected shape) yields no resource, so the submit leg
/// keeps the global acceptance gate as fallback.
///
/// Issue #1824 (I10.21 A2): per-resource scope for the finish-acceptance
/// leg; this only reads the admitted draft, never the monitor ledger.
fn finish_candidate_resources(tool: Option<&serde_json::Value>) -> Vec<String> {
    tool.and_then(|draft| draft.as_object())
        .and_then(|draft| draft.get("arguments"))
        .and_then(serde_json::Value::as_object)
        .and_then(|arguments| arguments.get("artifact_refs"))
        .and_then(serde_json::Value::as_array)
        .map(|refs| {
            refs.iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Resolves one admitted finish-candidate `artifact_ref` into the Kernel
/// ledger's tracked-source identity when it names an absolute path, and
/// reports an opaque job/operation handle otherwise (issue #1824, I10.21
/// A2).
///
/// The ledger keys hints and unknown-origin records by the lexically
/// normalized absolute tracked source (`process_execution` admits argv
/// targets with the same recipe), so the same recipe is applied here:
/// trim, require an absolute path, resolve `.`/`..` lexically, drop
/// trailing separators, and re-emit platform spelling. Anything that is
/// not an absolute path — job ids (`testd-<hex>`), operation ids,
/// relative names, blanks, control-carrying values, or `..` escapes past
/// the root — is `None`: this submit leg holds no job/operation record
/// that could resolve such a handle to declared resource identity (the
/// `TestD` job row lives daemon-side), so the caller keeps the global
/// acceptance gate instead of comparing a handle against absolute-path
/// identity by `==` and silently passing. Total: no I/O, no panics, and
/// unrelated lanes are untouched.
fn normalize_finish_candidate_resource(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return None;
    }
    let path = Path::new(trimmed);
    if !path.is_absolute() {
        return None;
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(part) => out.push(part.as_os_str()),
            Component::RootDir => out.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::Normal(part) => out.push(part),
        }
    }
    let normalized = out.to_string_lossy().into_owned();
    if normalized.trim().is_empty() {
        return None;
    }
    Some(normalized)
}

/// Joins a presented finish result against its live queue record.
///
/// Returns `None` only when the presented attempt, session, authority and
/// admitted envelope all match the current live record and the presenting
/// session owns it — that is, when the result is allowed to reach ORS. Any
/// mismatch is a noncanonical stale observation with an audit receipt.
fn finish_stale_attempt(
    body: &FinishResultBody,
    state: &LocalReadAttemptState,
    session: &Session,
    envelope: &HostRequestEnvelope,
) -> Option<StaleLocalReadObservation> {
    let mut semantic_fence = envelope.state_fence.clone();
    semantic_fence.task_revision =
        eliot_contracts::TaskRevision::new(body.attempt.task_revision).ok();
    let observation = |reason| StaleLocalReadObservation {
        operation_id: body.operation_id.clone(),
        request_digest: body.request_sha256.clone(),
        presented_attempt_id: Some(body.attempt.attempt_id.clone()),
        presented_generation: Some(body.attempt.fencing_generation),
        current_generation: Some(state.generation),
        reason,
    };
    if !state.is_owned_by(session) {
        return Some(observation(StaleLocalReadReason::OwnerMismatch));
    }
    if body.attempt.operation_id != body.operation_id
        || body.attempt.attempt_id != state.attempt_id
        || body.attempt.fencing_generation != state.generation
        || body.attempt.principal_id.trim().is_empty()
        || body.attempt.session_id
            != envelope
                .identity
                .session_id
                .as_deref()
                .ok_or(TransportError::SessionFenced)
                .ok()?
        || body.attempt.task_id
            != envelope
                .identity
                .task_id
                .as_deref()
                .ok_or(TransportError::SessionFenced)
                .ok()?
        || body.attempt.work_scope_id
            != envelope
                .identity
                .work_scope_id
                .as_deref()
                .ok_or(TransportError::SessionFenced)
                .ok()?
        || body.attempt.semantic_state_fence != semantic_fence
        || body.attempt.expires_at_unix_ms != envelope.identity.deadline_unix_ms
        || !body
            .attempt
            .authority_epoch
            .is_same_authority(&envelope.state_fence.authority_epoch)
    {
        return Some(observation(StaleLocalReadReason::Superseded));
    }
    None
}

/// Validates the closed Task Controller invoke-read pair before it enters the
/// Kernel-owned queue. The owner-native task payload remains opaque here; the
/// daemon decodes it only after claiming the exact fenced attempt.
fn task_controller_admission(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<TaskControllerInvocation, TransportError> {
    let object = tool.as_object().ok_or(TransportError::SessionFenced)?;
    if object.get("name").and_then(serde_json::Value::as_str) != Some("eliot.task-controller")
        || envelope.identity.capability != "eliot.task-controller"
        || envelope.identity.payload_schema_id != "eliot.task-controller.invoke.v1"
    {
        return Err(TransportError::SessionFenced);
    }
    let arguments = object
        .get("arguments")
        .cloned()
        .ok_or(TransportError::SessionFenced)?;
    let invocation: TaskControllerInvocation =
        serde_json::from_value(arguments).map_err(|_| TransportError::SessionFenced)?;
    invocation
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    if invocation.task_id.as_str()
        != envelope
            .identity
            .task_id
            .as_deref()
            .ok_or(TransportError::SessionFenced)?
        || invocation.work_scope_id
            != envelope
                .identity
                .work_scope_id
                .as_deref()
                .ok_or(TransportError::SessionFenced)?
        || envelope.state_fence.task_revision.is_none()
        || envelope.identity.session_id.is_none()
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(invocation)
}

pub(super) fn check_task_controller_admission(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<(), TransportError> {
    task_controller_admission(envelope, tool).map(|_| ())
}

pub(super) fn campaign_packet_admission(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Result<LocalReadAdmission, TransportError> {
    let object = tool.as_object().ok_or(TransportError::SessionFenced)?;
    if object.get("name").and_then(serde_json::Value::as_str) != Some("eliot.packet")
        || envelope.identity.capability != "eliot.packet"
    {
        return Err(TransportError::SessionFenced);
    }
    let arguments = object
        .get("arguments")
        .and_then(serde_json::Value::as_object)
        .ok_or(TransportError::SessionFenced)?;
    if arguments.len() > 2
        || arguments
            .keys()
            .any(|key| !matches!(key.as_str(), "packet_ref" | "material_refs"))
    {
        return Err(TransportError::SessionFenced);
    }
    if let Some(packet_ref) = arguments.get("packet_ref")
        && (!packet_ref.is_string()
            || packet_ref.as_str().is_some_and(|value| {
                value.trim().is_empty() || value.len() > MAX_CAMPAIGN_PACKET_SELECTOR_BYTES
            }))
    {
        return Err(TransportError::SessionFenced);
    }
    if let Some(materials) = arguments.get("material_refs") {
        let materials = materials.as_array().ok_or(TransportError::SessionFenced)?;
        if materials.len() > MAX_CAMPAIGN_PACKET_MATERIALS
            || materials.iter().any(|value| {
                value.as_str().is_none_or(|value| {
                    value.trim().is_empty()
                        || value.len() > MAX_CAMPAIGN_PACKET_SELECTOR_BYTES
                        || value.chars().any(char::is_control)
                })
            })
        {
            return Err(TransportError::SessionFenced);
        }
    }
    let task_id = envelope
        .identity
        .task_id
        .as_deref()
        .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        .ok_or(TransportError::SessionFenced)?
        .to_owned();
    let task_revision = envelope
        .state_fence
        .task_revision
        .ok_or(TransportError::SessionFenced)?
        .value();
    let scope_text = envelope
        .identity
        .work_scope_id
        .as_deref()
        .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        .ok_or(TransportError::SessionFenced)?;
    let scope_id = ScopeId::new(scope_text).map_err(|_| TransportError::SessionFenced)?;
    Ok(LocalReadAdmission::CampaignPacket {
        scope_id,
        task_id,
        task_revision,
    })
}
