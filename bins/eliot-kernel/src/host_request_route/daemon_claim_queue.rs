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

use eliot_ors::{HostRequestState, OperationIdentity, OrsError};
use eliot_protocol::{
    HostRequestEnvelope, HostRequestResultBody, TaskControllerAttempt, TaskControllerInvocation,
    TaskControllerResultBody, host_request_operation_id,
};
use eliot_store_api::ScopeId;

use crate::{KernelComposition, Session, TransportError, activation_deadline_expired, unix_ms};

use super::{
    DaemonReadQueue, HostRequestOperationRef, LOCAL_READ_ENQUEUE_SALT, LocalReadAdmission,
    LocalReadAttemptState, LocalReadSubmitDisposition, MAX_QUEUED_LOCAL_READS,
    StaleLocalReadObservation, StaleLocalReadReason, check_local_read_admission,
};

impl KernelComposition {
    pub(super) fn enqueue_campaign_packet_pair_under_transition(
        &self,
        envelope: &HostRequestEnvelope,
        tool: &serde_json::Value,
    ) -> Result<(), TransportError> {
        match check_local_read_admission(envelope, tool)? {
            LocalReadAdmission::CampaignPacket { .. } => {}
            LocalReadAdmission::Query(_) => return Err(TransportError::SessionFenced),
        }
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
                        && candidate.campaign_packet_envelope.is_some()
                })
            {
                return Ok(());
            }
        }
        let queued = index
            .values()
            .flatten()
            .filter(|candidate| candidate.campaign_packet_envelope.is_some())
            .count();
        if queued >= MAX_QUEUED_LOCAL_READS {
            let mut evicted = false;
            for refs in index.values_mut() {
                if let Some(position) = refs.iter().position(|candidate| {
                    candidate.campaign_packet_envelope.is_some()
                        && !candidate.campaign_packet_attempt.is_live()
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
            });
        }
        Ok(())
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
        let _admission_owner = self
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
        let _admission_owner = self
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
            return Err(TransportError::SessionFenced);
        }
        if stored.state == HostRequestState::ResultReceived
            && stored.result_digest.as_deref() == Some(body.result_digest.as_str())
            && stored.result_response.as_ref() == Some(&body.response)
        {
            return Ok(LocalReadSubmitDisposition::Persisted(Box::new(stored)));
        }
        if activation_deadline_expired(unix_ms(), stored.deadline_unix_ms) {
            return Err(TransportError::Timeout);
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
            )
            .map_err(|error| match error {
                OrsError::HostRequestIdentityConflict { .. } => TransportError::IdentityConflict,
                _ => TransportError::SessionFenced,
            })?
            .ok_or(TransportError::UnknownRequest)?;
        self.retire_task_controller_pair_under_transition(&body.operation_id, &body.request_sha256);
        Ok(LocalReadSubmitDisposition::Persisted(Box::new(persisted)))
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
