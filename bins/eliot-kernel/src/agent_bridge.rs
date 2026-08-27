//! ARCH-MOD-01 — Kernel agent-bridge protocol isolation (A13.2/A13.3; I6.4-I6.5/I7.1-I7.5/I7.14).
//! Neutral Kernel admission/transport only; no Governor semantics, Store SDK, or default success.

use std::collections::BTreeSet;
use std::time::Duration;

use super::{
    AGENT_BRIDGE_ACTIVATION_WINDOW_MS, ActivationDecisionDisposition, AgentActivationPending,
    AgentBridgeHandshake, AgentBridgeProfile, KernelComposition, activation_deadline_expired,
    classify_activation_decision, load_agent_bridge_declaration, sha256_json, unix_ms,
};
use eliot_ipc::{
    PeerIdentity, ServerFirstConnection, Session, TransportError,
    agent_bridge_admission_receipt_frame,
};
use eliot_kernel_service::{AgentBridgeAdmissionDescriptor, KernelServiceState};
use eliot_platform_windows::{
    NamedPipePeerKind, NamedPipePeerSelection, fresh_activation_nonce_material,
};
use eliot_protocol::{
    AGENT_BRIDGE_ACTIVATION_OPERATION, AGENT_BRIDGE_MODULE_ID, AGENT_BRIDGE_PEER_CHALLENGE_WIRE_ID,
    AGENT_BRIDGE_PEER_CHALLENGE_WIRE_VERSION, AgentActivationResolutionDecision,
    AgentActivationResolutionTicket, AgentBridgeActivationDenialCode, AgentBridgeActivationFence,
    AgentBridgeActivationRequest, AgentBridgeActivationResponse, AgentBridgeAuthenticatedBinding,
    AgentBridgePeerChallenge, Frame, FrameKind, MessageType, ProtocolPayload,
};

impl KernelComposition {
    /// Reports whether the exact bounded peer-set selection and Host-approved
    /// bridge profile admit this authenticated OS peer. A positive result is
    /// transport admission only; it does not create a semantic Session or
    /// principal.
    #[cfg(windows)]
    pub fn agent_bridge_peer_admitted(
        &self,
        selection: &NamedPipePeerSelection,
        peer: &PeerIdentity,
    ) -> bool {
        self.agent_bridge_profile
            .lock()
            .ok()
            .and_then(|profile| profile.clone())
            .is_some_and(|profile| {
                selection.kind() == NamedPipePeerKind::AgentBridge
                    && selection.module_id() == AGENT_BRIDGE_MODULE_ID
                    && selection.profile_id() == Some(profile.admission.profile_id.as_str())
                    && Self::validate_agent_bridge_peer(&profile.admission, peer).is_ok()
            })
    }

    #[cfg(windows)]
    fn validate_agent_bridge_peer(
        admission: &AgentBridgeAdmissionDescriptor,
        peer: &PeerIdentity,
    ) -> Result<(), TransportError> {
        admission
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let PeerIdentity::Authenticated {
            user_identity,
            session_identity,
            ..
        } = peer
        else {
            return Err(TransportError::PeerIdentityUnavailable);
        };
        if user_identity != &admission.approved_user_sid {
            return Err(TransportError::SessionFenced);
        }
        let session_id = session_identity
            .parse::<u32>()
            .map_err(|_| TransportError::SessionFenced)?;
        if session_id == 0 {
            return Err(TransportError::SessionFenced);
        }
        match admission.process_policy {
            eliot_kernel_service::AgentBridgeProcessPolicy::ExactProcessPerConnection => {}
        }
        let process = peer
            .process_binding()
            .ok_or(TransportError::PeerIdentityUnavailable)?;
        if !process
            .image_path()
            .eq_ignore_ascii_case(admission.executable.as_str())
        {
            return Err(TransportError::SessionFenced);
        }
        let (volume_serial_number, file_index) = process
            .executable_file_identity()
            .ok_or(TransportError::PeerIdentityUnavailable)?;
        if volume_serial_number != admission.executable_identity.volume_serial_number
            || file_index != admission.executable_identity.file_index
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    /// Validates and materializes the exact protected declaration before the
    /// enclosing Host activation mutates service state.
    #[cfg(windows)]
    pub(super) fn prepare_agent_bridge_admission(
        admission: Option<&AgentBridgeAdmissionDescriptor>,
    ) -> Result<Option<AgentBridgeProfile>, TransportError> {
        admission
            .as_ref()
            .map(|admission| -> Result<AgentBridgeProfile, TransportError> {
                admission
                    .validate()
                    .map_err(|_| TransportError::SessionFenced)?;
                Ok(AgentBridgeProfile {
                    admission: (*admission).clone(),
                    declaration: load_agent_bridge_declaration(admission)
                        .map_err(|_| TransportError::SessionFenced)?,
                })
            })
            .transpose()
    }

    /// Atomically replaces the live bridge profile after the enclosing Host
    /// activation succeeds. Replacing or removing a profile revokes every
    /// pending connection from the previous activation lineage.
    #[cfg(windows)]
    pub(super) fn promote_agent_bridge_profile(
        &self,
        next: Option<AgentBridgeProfile>,
    ) -> Result<(), TransportError> {
        self.revoke_all_agent_bridges()?;
        *self
            .agent_bridge_profile
            .lock()
            .map_err(|_| TransportError::SessionFenced)? = next;
        self.note_agent_bridge_peer_set_change();
        Ok(())
    }

    #[cfg(windows)]
    fn revoke_all_agent_bridges(&self) -> Result<(), TransportError> {
        let mut connections = self
            .agent_bridge_connections
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        for (_, mut state) in std::mem::take(&mut *connections) {
            state.exchange.abort();
            if let Some(mut session) = state.session {
                session.fence();
            }
            state.accepted_transport = None;
        }
        if let Ok(mut pending) = self.agent_activation_pending.lock() {
            pending.fifo.clear();
            pending.entries.clear();
        } else {
            return Err(TransportError::SessionFenced);
        }
        self.agent_activation_changed.notify_waiters();
        Ok(())
    }

    #[cfg(windows)]
    fn validate_active_bridge_profile(
        &self,
        admission: &AgentBridgeAdmissionDescriptor,
    ) -> Result<(), TransportError> {
        let service = self
            .service
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        if service.state() != KernelServiceState::Ready {
            return Err(TransportError::SessionFenced);
        }
        let candidate = service
            .candidate_binding()
            .ok_or(TransportError::SessionFenced)?;
        if candidate.agent_bridge_admission.as_ref() != Some(admission) {
            return Err(TransportError::SessionFenced);
        }
        let activation = service
            .activation_receipt()
            .ok_or(TransportError::SessionFenced)?;
        if activation.generation != admission.generation
            || activation.authority_epoch != admission.authority_epoch
            || activation.candidate_binding_digest
                != candidate
                    .compute_digest()
                    .map_err(|_| TransportError::SessionFenced)?
            || admission.state_fence.resource_generation != activation.generation
            || admission.state_fence.authority_epoch != activation.authority_epoch
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    /// Starts one server-first bridge exchange for the exact admitted peer.
    /// The returned identity and nonce are fresh and retained by Kernel until
    /// hello acceptance, timeout, disconnect, or explicit revocation.
    #[cfg(windows)]
    pub fn begin_agent_bridge(
        &self,
        selection: &NamedPipePeerSelection,
        peer: PeerIdentity,
    ) -> Result<AgentBridgeHandshake, TransportError> {
        let profile = self
            .agent_bridge_profile
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        let admission = &profile.admission;
        self.validate_active_bridge_profile(admission)?;
        if selection.kind() != NamedPipePeerKind::AgentBridge
            || selection.module_id() != AGENT_BRIDGE_MODULE_ID
            || selection.profile_id() != Some(admission.profile_id.as_str())
        {
            return Err(TransportError::SessionFenced);
        }
        Self::validate_agent_bridge_peer(admission, &peer)?;
        let declaration = profile.declaration;
        let kernel_policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone();
        let kernel_artifact_sha256 = kernel_policy
            .config_snapshot
            .get("artifact_digest")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or(TransportError::SessionFenced)?
            .to_owned();
        let kernel_config_snapshot_sha256 = sha256_json(&kernel_policy.config_snapshot)
            .map_err(|_| TransportError::SessionFenced)?;
        if declaration.expected_kernel_principal_binding != kernel_policy.session_principal_binding
            || declaration.expected_kernel_authority_epoch
                != kernel_policy.module_generation.state_fence.authority_epoch
            || declaration.expected_kernel_generation != kernel_policy.module_generation.generation
            || declaration.expected_kernel_artifact_sha256 != kernel_artifact_sha256
            || declaration.expected_kernel_config_snapshot_sha256 != kernel_config_snapshot_sha256
        {
            return Err(TransportError::SessionFenced);
        }
        let nonce = fresh_activation_nonce_material()
            .map_err(|_| TransportError::SessionFenced)?
            .to_string();
        let connection_nonce = fresh_activation_nonce_material()
            .map_err(|_| TransportError::SessionFenced)?
            .to_string();
        let connection_id = format!("agent-bridge:{connection_nonce}");
        let challenge = AgentBridgePeerChallenge {
            wire_id: AGENT_BRIDGE_PEER_CHALLENGE_WIRE_ID.to_owned(),
            wire_version: AGENT_BRIDGE_PEER_CHALLENGE_WIRE_VERSION,
            module_id: AGENT_BRIDGE_MODULE_ID.to_owned(),
            profile_id: admission.profile_id.as_str().to_owned(),
            descriptor_sha256: admission.descriptor_sha256.clone(),
            client_declaration_sha256: admission.client_declaration_sha256.clone(),
            bridge_generation: admission.generation,
            state_fence: admission.state_fence.clone(),
            kernel_principal_binding: kernel_policy.session_principal_binding,
            kernel_authority_epoch: kernel_policy.module_generation.state_fence.authority_epoch,
            kernel_generation: kernel_policy.module_generation.generation,
            kernel_artifact_sha256,
            kernel_config_snapshot_sha256,
            activation_deadline_unix_ms: unix_ms()
                .saturating_add(AGENT_BRIDGE_ACTIVATION_WINDOW_MS),
            challenge_nonce: nonce,
            challenge_sha256: String::new(),
        }
        .with_computed_digest()
        .map_err(|_| TransportError::SessionFenced)?;
        let exchange = ServerFirstConnection::new(&connection_id, challenge.clone(), &declaration)?;
        let challenge_frame = exchange.challenge_frame()?;
        let mut connections = self
            .agent_bridge_connections
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        if connections.contains_key(&connection_id) {
            return Err(TransportError::SessionFenced);
        }
        connections.insert(
            connection_id.clone(),
            super::AgentBridgeConnectionState {
                exchange,
                declaration,
                peer,
                accepted_transport: None,
                session: None,
                activation_completed: false,
            },
        );
        Ok(super::AgentBridgeHandshake {
            connection_id,
            challenge,
            challenge_frame,
        })
    }

    /// Accepts the one exact dynamic bridge hello and retains its immutable
    /// OS-observation receipt for the subsequent closed activation operation.
    #[cfg(windows)]
    pub fn accept_agent_bridge_hello(
        &self,
        connection_id: &str,
        frame: &Frame,
    ) -> Result<eliot_protocol::AgentBridgePeerAdmissionReceipt, TransportError> {
        let mut connections = self
            .agent_bridge_connections
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let result = {
            let state = connections
                .get_mut(connection_id)
                .ok_or(TransportError::SessionFenced)?;
            if activation_deadline_expired(
                unix_ms(),
                state.exchange.challenge().activation_deadline_unix_ms,
            ) {
                return Err(TransportError::SessionFenced);
            }
            state
                .exchange
                .accept_client_hello_with_peer(frame, &state.declaration, &state.peer)
                .map(|accepted| {
                    let receipt = accepted.admission_receipt().clone();
                    state.accepted_transport = Some(accepted);
                    receipt
                })
        };
        if result.is_err()
            && let Some(mut state) = connections.remove(connection_id)
        {
            state.exchange.fence();
            state.accepted_transport = None;
        }
        result
    }

    /// Builds the typed Control/Ready receipt sent after the exact bridge
    /// hello. The bridge must consume this Kernel-authored receipt to form its
    /// activation request; it is never reconstructed from caller input.
    #[cfg(windows)]
    pub fn agent_bridge_admission_receipt_frame(
        &self,
        connection_id: &str,
    ) -> Result<Frame, TransportError> {
        let connections = self
            .agent_bridge_connections
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let state = connections
            .get(connection_id)
            .ok_or(TransportError::SessionFenced)?;
        let receipt = state
            .accepted_transport
            .as_ref()
            .ok_or(TransportError::SessionFenced)?
            .admission_receipt();
        agent_bridge_admission_receipt_frame(connection_id, receipt)
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the queue admission gate keeps request, receipt, and replay checks ordered"
    )]
    fn enqueue_agent_bridge_activation(
        &self,
        connection_id: &str,
        frame: &Frame,
    ) -> Result<AgentActivationResolutionTicket, TransportError> {
        let (request, receipt) = {
            let connections = self
                .agent_bridge_connections
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let state = connections
                .get(connection_id)
                .ok_or(TransportError::SessionFenced)?;
            if state.activation_completed || state.session.is_some() {
                return Err(TransportError::IdentityConflict);
            }
            let accepted = state
                .accepted_transport
                .as_ref()
                .ok_or(TransportError::SessionFenced)?;
            let receipt = accepted.admission_receipt();
            let profile = self
                .agent_bridge_profile
                .lock()
                .map_err(|_| TransportError::SessionFenced)?
                .clone()
                .ok_or(TransportError::SessionFenced)?;
            if receipt.descriptor_sha256 != profile.admission.descriptor_sha256
                || receipt.profile_id != profile.admission.profile_id.as_str()
                || receipt.state_fence != profile.admission.state_fence
            {
                return Err(TransportError::SessionFenced);
            }
            self.validate_active_bridge_profile(&profile.admission)?;
            if activation_deadline_expired(unix_ms(), receipt.activation_deadline_unix_ms) {
                return Err(TransportError::Timeout);
            }
            frame.validate()?;
            if frame.connection_id != connection_id
                || frame.kind != FrameKind::Request
                || frame.message_type != MessageType::Execute
                || frame.request_identity.is_none()
            {
                return Err(TransportError::SessionFenced);
            }
            let request_id = frame
                .request_id
                .clone()
                .ok_or(TransportError::SessionFenced)?;
            let ProtocolPayload::Json(payload) = &frame.payload else {
                return Err(TransportError::SessionFenced);
            };
            let request: AgentBridgeActivationRequest = serde_json::from_value(payload.clone())
                .map_err(|_| TransportError::SessionFenced)?;
            if frame.request_identity.as_ref() != Some(&request.request_identity)
                || request.request_identity.request.metadata.request_id != request_id
                || request.operation != AGENT_BRIDGE_ACTIVATION_OPERATION
            {
                return Err(TransportError::SessionFenced);
            }
            request
                .validate_admission(receipt)
                .map_err(|_| TransportError::SessionFenced)?;
            (request, receipt.clone())
        };
        let mut pending = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let request_id = request
            .request_identity
            .request
            .metadata
            .request_id
            .as_str();
        if pending.replay.contains_key(request_id)
            || pending.entries.values().any(|entry| {
                entry.ticket.connection_id == connection_id
                    || entry.ticket.activation_request_id
                        == request.request_identity.request.metadata.request_id
            })
        {
            return Err(TransportError::IdentityConflict);
        }
        if pending.entries.len() >= 32 {
            return Err(TransportError::RegistryFull);
        }
        let ticket_nonce = fresh_activation_nonce_material()
            .map_err(|_| TransportError::SessionFenced)?
            .to_string();
        let ticket = AgentActivationResolutionTicket {
            wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
            wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
            ticket_id: format!("agent-activation:{ticket_nonce}"),
            activation_request_id: request.request_identity.request.metadata.request_id.clone(),
            activation_request_sha256: request.request_sha256.clone(),
            peer_admission_receipt_sha256: receipt.receipt_sha256.clone(),
            connection_id: connection_id.to_owned(),
            state_fence: receipt.state_fence.clone(),
            kernel_deadline_unix_ms: receipt.activation_deadline_unix_ms,
            ticket_sha256: String::new(),
        }
        .with_computed_digest()
        .map_err(|_| TransportError::SessionFenced)?;
        ticket
            .validate_against(&request, &receipt)
            .map_err(|_| TransportError::SessionFenced)?;
        pending.fifo.push_back(ticket.ticket_id.clone());
        if pending.replay.len() >= 64
            && let Some(oldest) = pending.replay.keys().next().cloned()
        {
            pending.replay.remove(&oldest);
        }
        pending
            .replay
            .insert(request_id.to_owned(), ticket.ticket_id.clone());
        pending.entries.insert(
            ticket.ticket_id.clone(),
            AgentActivationPending {
                ticket: ticket.clone(),
                request,
                decision: None,
                claim_lease_until_unix_ms: None,
            },
        );
        self.agent_activation_changed.notify_waiters();
        Ok(ticket)
    }

    #[cfg(windows)]
    pub(super) fn claim_agent_activation_ticket(
        &self,
    ) -> Result<Option<AgentActivationResolutionTicket>, TransportError> {
        let mut pending = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(pending.claim_at(unix_ms()))
    }

    #[cfg(windows)]
    pub(super) fn submit_agent_activation_decision(
        &self,
        decision: AgentActivationResolutionDecision,
    ) -> Result<(), TransportError> {
        decision
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let mut pending = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let entry = pending
            .entries
            .get_mut(&decision.ticket_id)
            .ok_or(TransportError::UnknownRequest)?;
        decision
            .validate_against(&entry.ticket)
            .map_err(|_| TransportError::SessionFenced)?;
        match classify_activation_decision(entry.decision.as_ref(), &decision) {
            ActivationDecisionDisposition::ExactReplay => return Ok(()),
            ActivationDecisionDisposition::Conflict => {
                return Err(TransportError::IdentityConflict);
            }
            ActivationDecisionDisposition::Commit => {}
        }
        if activation_deadline_expired(unix_ms(), entry.ticket.kernel_deadline_unix_ms) {
            return Err(TransportError::Timeout);
        }
        entry.decision = Some(decision);
        let ticket_id = entry.ticket.ticket_id.clone();
        pending.fifo.retain(|queued_id| queued_id != &ticket_id);
        drop(pending);
        self.agent_activation_changed.notify_waiters();
        Ok(())
    }

    #[cfg(windows)]
    fn activation_response_frame(
        &self,
        connection_id: &str,
        original: &Frame,
        pending: &AgentActivationPending,
        decision: &AgentActivationResolutionDecision,
    ) -> Result<Frame, TransportError> {
        decision
            .validate_against(&pending.ticket)
            .map_err(|_| TransportError::SessionFenced)?;
        let session_nonce = fresh_activation_nonce_material()
            .map_err(|_| TransportError::SessionFenced)?
            .to_string();
        let accepted = {
            let connections = self
                .agent_bridge_connections
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let state = connections
                .get(connection_id)
                .ok_or(TransportError::SessionFenced)?;
            state
                .accepted_transport
                .as_ref()
                .ok_or(TransportError::SessionFenced)?
                .clone()
        };
        let session = Session::establish_agent_bridge(
            connection_id,
            accepted.peer().clone(),
            accepted.client_hello().module_generation.clone(),
            session_nonce.clone(),
        )?;
        let binding = AgentBridgeAuthenticatedBinding {
            principal_id: decision.principal_id.clone(),
            session_id: decision.session_id.clone(),
            activation_generation: decision.state_fence.resource_generation,
            state_fence: AgentBridgeActivationFence {
                authority_epoch: decision.state_fence.authority_epoch,
                generation: decision.state_fence.resource_generation,
                nonce: session_nonce,
            },
            task_id: decision.task_id.clone(),
            work_unit_id: decision.work_unit_id.clone(),
            work_scope_id: decision.work_scope_id.clone(),
            task_revision: decision.task_revision.clone(),
            plan_id: decision.plan_id.clone(),
            plan_revision: decision.plan_revision.clone(),
        };
        let response = AgentBridgeActivationResponse {
            wire_id: eliot_protocol::AGENT_BRIDGE_ACTIVATION_RESPONSE_WIRE_ID.to_owned(),
            wire_version: AgentBridgeActivationResponse::CONTRACT_VERSION,
            request_id: pending
                .request
                .request_identity
                .request
                .metadata
                .request_id
                .clone(),
            request_sha256: pending.request.request_sha256.clone(),
            disposition: eliot_protocol::AgentBridgeActivationDisposition::Authenticated {
                binding: Box::new(binding),
            },
            response_sha256: String::new(),
        }
        .with_computed_digest()
        .map_err(|_| TransportError::SessionFenced)?;
        response
            .validate_request(&pending.request)
            .map_err(|_| TransportError::SessionFenced)?;
        let reply = Frame {
            protocol_version: original.protocol_version,
            encoding_profile: original.encoding_profile,
            connection_id: connection_id.to_owned(),
            request_id: Some(response.request_id.clone()),
            kind: FrameKind::Response,
            message_type: MessageType::Result,
            request_identity: None,
            payload: ProtocolPayload::Json(
                serde_json::to_value(response).map_err(|_| TransportError::SessionFenced)?,
            ),
            trace_context: original.trace_context.clone(),
        };
        reply.validate()?;
        let mut connections = self
            .agent_bridge_connections
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let state = connections
            .get_mut(connection_id)
            .ok_or(TransportError::SessionFenced)?;
        if state.activation_completed || state.session.is_some() {
            return Err(TransportError::IdentityConflict);
        }
        state.session = Some(session);
        state.activation_completed = true;
        Ok(reply)
    }

    /// Queues one validated bridge request and waits for the sole eliotd
    /// resolver decision. Kernel owns the final transport Session/fence.
    #[cfg(windows)]
    pub async fn await_agent_bridge_activation_response(
        &self,
        connection_id: &str,
        frame: &Frame,
    ) -> Result<Frame, TransportError> {
        let ticket = self.enqueue_agent_bridge_activation(connection_id, frame)?;
        loop {
            let outcome = {
                let pending = self
                    .agent_activation_pending
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?;
                pending
                    .entries
                    .get(&ticket.ticket_id)
                    .and_then(|entry| entry.decision.clone())
            };
            if let Some(decision) = outcome {
                let pending = {
                    let pending = self
                        .agent_activation_pending
                        .lock()
                        .map_err(|_| TransportError::SessionFenced)?;
                    pending
                        .entries
                        .get(&ticket.ticket_id)
                        .ok_or(TransportError::SessionFenced)?
                        .clone()
                };
                let reply =
                    self.activation_response_frame(connection_id, frame, &pending, &decision)?;
                self.agent_activation_pending
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?
                    .entries
                    .remove(&ticket.ticket_id);
                return Ok(reply);
            }
            let now = unix_ms();
            if activation_deadline_expired(now, ticket.kernel_deadline_unix_ms) {
                let request = {
                    let pending = self
                        .agent_activation_pending
                        .lock()
                        .map_err(|_| TransportError::SessionFenced)?;
                    pending
                        .entries
                        .get(&ticket.ticket_id)
                        .ok_or(TransportError::SessionFenced)?
                        .request
                        .clone()
                };
                self.agent_activation_pending
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?
                    .entries
                    .remove(&ticket.ticket_id);
                self.revoke_agent_bridge(connection_id);
                let response = AgentBridgeActivationResponse::denied(
                    &request,
                    AgentBridgeActivationDenialCode::SemanticResolutionUnavailable,
                )
                .map_err(|_| TransportError::SessionFenced)?;
                let reply = Frame {
                    protocol_version: frame.protocol_version,
                    encoding_profile: frame.encoding_profile,
                    connection_id: connection_id.to_owned(),
                    request_id: Some(response.request_id.clone()),
                    kind: FrameKind::Response,
                    message_type: MessageType::Result,
                    request_identity: None,
                    payload: ProtocolPayload::Json(
                        serde_json::to_value(response)
                            .map_err(|_| TransportError::SessionFenced)?,
                    ),
                    trace_context: frame.trace_context.clone(),
                };
                reply.validate()?;
                return Ok(reply);
            }
            let notified = self.agent_activation_changed.notified();
            tokio::select! {
                () = notified => {}
                () = tokio::time::sleep(Duration::from_millis(25)) => {}
            }
        }
    }

    /// Validates one closed bridge activation operation and emits the sole
    /// R13.1b typed denial. No Kernel `Session` or semantic authority is made.
    #[cfg(windows)]
    pub fn agent_bridge_activation_response(
        &self,
        connection_id: &str,
        frame: &Frame,
    ) -> Result<Frame, TransportError> {
        let mut connections = self
            .agent_bridge_connections
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let result = (|| {
            let state = connections
                .get_mut(connection_id)
                .ok_or(TransportError::SessionFenced)?;
            let accepted = state
                .accepted_transport
                .as_ref()
                .ok_or(TransportError::SessionFenced)?;
            let receipt = accepted.admission_receipt();
            let profile = self
                .agent_bridge_profile
                .lock()
                .map_err(|_| TransportError::SessionFenced)?
                .clone()
                .ok_or(TransportError::SessionFenced)?;
            if receipt.descriptor_sha256 != profile.admission.descriptor_sha256
                || receipt.profile_id != profile.admission.profile_id.as_str()
                || receipt.state_fence != profile.admission.state_fence
            {
                return Err(TransportError::SessionFenced);
            }
            self.validate_active_bridge_profile(&profile.admission)?;
            if activation_deadline_expired(unix_ms(), receipt.activation_deadline_unix_ms) {
                return Err(TransportError::SessionFenced);
            }
            frame.validate()?;
            if frame.connection_id != connection_id
                || frame.kind != FrameKind::Request
                || frame.message_type != MessageType::Execute
                || frame.request_identity.is_none()
            {
                return Err(TransportError::SessionFenced);
            }
            let request_id = frame
                .request_id
                .clone()
                .ok_or(TransportError::SessionFenced)?;
            let ProtocolPayload::Json(payload) = &frame.payload else {
                return Err(TransportError::SessionFenced);
            };
            let request: AgentBridgeActivationRequest = serde_json::from_value(payload.clone())
                .map_err(|_| TransportError::SessionFenced)?;
            if frame.request_identity.as_ref() != Some(&request.request_identity)
                || request.request_identity.request.metadata.request_id != request_id
                || request.operation != AGENT_BRIDGE_ACTIVATION_OPERATION
            {
                return Err(TransportError::SessionFenced);
            }
            request
                .validate_admission(receipt)
                .map_err(|_| TransportError::SessionFenced)?;
            let response = AgentBridgeActivationResponse::denied(
                &request,
                AgentBridgeActivationDenialCode::SemanticResolutionUnavailable,
            )
            .map_err(|_| TransportError::SessionFenced)?;
            response
                .validate_request(&request)
                .map_err(|_| TransportError::SessionFenced)?;
            let reply = Frame {
                protocol_version: frame.protocol_version,
                encoding_profile: frame.encoding_profile,
                connection_id: connection_id.to_owned(),
                request_id: Some(response.request_id.clone()),
                kind: FrameKind::Response,
                message_type: MessageType::Result,
                request_identity: None,
                payload: ProtocolPayload::Json(
                    serde_json::to_value(response).map_err(|_| TransportError::SessionFenced)?,
                ),
                trace_context: frame.trace_context.clone(),
            };
            reply.validate()?;
            Ok(reply)
        })();
        if let Some(mut state) = connections.remove(connection_id) {
            if result.is_ok() {
                state.exchange.abort();
            } else {
                state.exchange.fence();
            }
            state.accepted_transport = None;
        }
        result
    }

    /// Revokes all retained bridge authority for one disconnected connection.
    #[cfg(windows)]
    pub fn revoke_agent_bridge(&self, connection_id: &str) {
        if let Ok(mut connections) = self.agent_bridge_connections.lock()
            && let Some(mut state) = connections.remove(connection_id)
        {
            state.exchange.abort();
            if let Some(mut session) = state.session.take() {
                session.fence();
            }
            state.accepted_transport = None;
        }
        if let Ok(mut pending) = self.agent_activation_pending.lock() {
            let removed = pending
                .entries
                .iter()
                .filter(|(_, entry)| entry.ticket.connection_id == connection_id)
                .map(|(ticket_id, _)| ticket_id.clone())
                .collect::<Vec<_>>();
            for ticket_id in removed {
                pending.entries.remove(&ticket_id);
            }
            let live_ticket_ids = pending.entries.keys().cloned().collect::<BTreeSet<_>>();
            pending
                .fifo
                .retain(|ticket_id| live_ticket_ids.contains(ticket_id));
        }
        self.agent_activation_changed.notify_waiters();
    }
}
