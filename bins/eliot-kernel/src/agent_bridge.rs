//! ARCH-MOD-01 — Kernel agent-bridge protocol isolation (A13.2/A13.3; I6.4-I6.5/I7.1-I7.5/I7.14).
//! Neutral Kernel admission/transport only; no Governor semantics, Store SDK, or default success.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use super::{
    AGENT_ACTIVATION_CLAIM_LEASE_MS, AGENT_BRIDGE_ACTIVATION_WINDOW_MS,
    ActivationResultDisposition, AgentActivationLifecycle, AgentActivationPending,
    AgentActivationPendingState, AgentActivationResultPhase, AgentActivationResultRecord,
    AgentBridgeHandshake, AgentBridgeProfile, BoundCanonicalOwner, KernelBuildError,
    KernelComposition, activation_deadline_expired, classify_activation_result,
    load_agent_bridge_declaration, sha256_json, unix_ms,
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
    AGENT_BRIDGE_PEER_CHALLENGE_WIRE_VERSION, AgentActivationOwnerReadback,
    AgentActivationResolutionDisposition, AgentActivationResolutionResult,
    AgentActivationResolutionTicket, AgentActivationResolvedBinding, AgentActivationResultAck,
    AgentActivationResultReconcile, AgentActivationResultSubmit, AgentBridgeActivationDenialCode,
    AgentBridgeActivationFence, AgentBridgeActivationRequest, AgentBridgeActivationResponse,
    AgentBridgeAuthenticatedBinding, AgentBridgePeerChallenge, Frame, FrameKind, MessageType,
    ProtocolPayload, RequestIdentity,
};

fn observe_bridge(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "agent bridge observation"
    );
}

fn bridge_terminal_code(error: &TransportError) -> &'static str {
    match error {
        TransportError::SessionFenced => "bridge_fenced",
        TransportError::PeerIdentityUnavailable => "bridge_peer_unavailable",
        TransportError::Timeout => "bridge_timeout",
        TransportError::UnknownRequest => "bridge_unknown_request",
        TransportError::UnknownOutcome => "bridge_unknown_outcome",
        TransportError::IdentityConflict => "bridge_identity_conflict",
        TransportError::Cancelled => "bridge_cancelled",
        TransportError::Backpressure => "bridge_backpressure",
        TransportError::InvalidLimits => "bridge_invalid_limits",
        TransportError::UnauthenticatedPeer => "bridge_unauthenticated_peer",
        TransportError::InvalidPipeName => "bridge_invalid_pipe",
        TransportError::RegistryFull => "bridge_registry_full",
        TransportError::Io(_) => "bridge_io",
        TransportError::PlanGap { .. } => "bridge_plan_gap",
        TransportError::Protocol(_) => "bridge_protocol",
    }
}

fn pending_state_from_lifecycle(
    state: eliot_ors::ActivationLifecycleState,
) -> AgentActivationLifecycle {
    match state {
        eliot_ors::ActivationLifecycleState::Pending => AgentActivationLifecycle::Pending,
        eliot_ors::ActivationLifecycleState::Claimed => AgentActivationLifecycle::Claimed,
        eliot_ors::ActivationLifecycleState::DeferredNotReady => {
            AgentActivationLifecycle::DeferredNotReady
        }
        eliot_ors::ActivationLifecycleState::ResultAccepted => AgentActivationLifecycle::Accepted,
        eliot_ors::ActivationLifecycleState::Cancelled => AgentActivationLifecycle::Cancelled,
        eliot_ors::ActivationLifecycleState::Expired => AgentActivationLifecycle::Expired,
        eliot_ors::ActivationLifecycleState::Reconciling => AgentActivationLifecycle::Reconciling,
    }
}

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
        observe_bridge("kernel.bridge_peer_observed", "attempt");
        let Ok(_transition) = self.agent_bridge_transition_read() else {
            observe_bridge("kernel.bridge_peer_observed", "not_admitted");
            return false;
        };
        let Ok(_admission_owner) = self.agent_activation_pending.lock() else {
            observe_bridge("kernel.bridge_peer_observed", "not_admitted");
            return false;
        };
        let admitted = self
            .agent_bridge_profile
            .lock()
            .ok()
            .and_then(|profile| profile.clone())
            .is_some_and(|profile| {
                selection.kind() == NamedPipePeerKind::AgentBridge
                    && selection.module_id() == AGENT_BRIDGE_MODULE_ID
                    && selection.profile_id() == Some(profile.admission.profile_id.as_str())
                    && Self::validate_agent_bridge_peer(&profile.admission, peer).is_ok()
            });
        if admitted {
            observe_bridge("kernel.bridge_peer_observed", "admitted");
        } else {
            observe_bridge("kernel.bridge_peer_observed", "not_admitted");
        }
        admitted
    }

    #[cfg(windows)]
    fn validate_agent_bridge_peer(
        admission: &AgentBridgeAdmissionDescriptor,
        peer: &PeerIdentity,
    ) -> Result<(), TransportError> {
        observe_bridge("kernel.bridge_peer_validate", "attempt");
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
        let _transition = self.agent_bridge_transition_write()?;
        // `agent_activation_pending` is the single Kernel admission owner for
        // the bridge generation.  Keep it held across the no-profile fence,
        // ownership drain, and replacement publication so no old snapshot can
        // become reachable between revocation and the profile swap.
        let (mut pending, pending_poisoned) = match self.agent_activation_pending.lock() {
            Ok(pending) => (pending, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        let (mut profile, profile_poisoned) = match self.agent_bridge_profile.lock() {
            Ok(profile) => (profile, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        // Publish the outgoing generation's fence before detaching any owned
        // state. A poisoned inner lock is cleaned through its recovered guard,
        // but it never permits replacement publication.
        *profile = None;
        let revocation = self.revoke_all_agent_bridges(&mut pending);
        self.note_agent_bridge_peer_set_change();
        if pending_poisoned || profile_poisoned || revocation.is_err() {
            return Err(TransportError::SessionFenced);
        }
        *profile = next;
        Ok(())
    }

    #[cfg(windows)]
    fn revoke_all_agent_bridges(
        &self,
        pending: &mut AgentActivationPendingState,
    ) -> Result<(), TransportError> {
        // Keep the Kernel owner lock order identical to activation result
        // admission: pending state is the cross-representation CAS owner and
        // the connection map is acquired only after it. This prevents profile
        // promotion from waiting on connections while a submitter waits on
        // pending state.
        let (mut connections, connections_poisoned) = match self.agent_bridge_connections.lock() {
            Ok(connections) => (connections, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        let revoked = std::mem::take(&mut *connections);
        let removed = pending.entries.keys().cloned().collect::<Vec<_>>();
        for ticket_id in &removed {
            self.persist_resultless_activation_revocation(
                pending,
                ticket_id,
                "bridge profile promotion reached a resultless terminal boundary",
            )?;
        }
        pending.fifo.clear();
        pending.entries.clear();
        drop(connections);
        for (_, mut state) in revoked {
            state.exchange.abort();
            if let Some(mut session) = state.session {
                session.fence();
            }
            state.accepted_transport = None;
        }
        // The index is drained while the same admission owner is held.  Its
        // detached store fencing may continue after the map ownership is gone,
        // but a poisoned index must prevent replacement publication.
        let index_fenced = self.fence_all_host_requests();
        self.agent_activation_changed.notify_waiters();
        if connections_poisoned || index_fenced.is_err() {
            Err(TransportError::SessionFenced)
        } else {
            Ok(())
        }
    }

    #[cfg(windows)]
    pub(super) fn validate_active_bridge_profile(
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
        observe_bridge("kernel.bridge_connect", "attempt");
        let _transition = self.agent_bridge_transition_read()?;
        let result = self.begin_agent_bridge_inner(selection, peer);
        match &result {
            Ok(_) => {
                observe_bridge("kernel.bridge_connect", "success");
                observe_bridge("kernel.bridge_attach", "success");
                observe_bridge("kernel.bridge_readiness", "success");
            }
            Err(error) => {
                observe_bridge("kernel.bridge_connect", "fenced");
                super::kernel_diagnostics::observe_terminal_error(bridge_terminal_code(error));
            }
        }
        result
    }

    #[cfg(windows)]
    fn begin_agent_bridge_inner(
        &self,
        selection: &NamedPipePeerSelection,
        peer: PeerIdentity,
    ) -> Result<AgentBridgeHandshake, TransportError> {
        let _admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let observed_peer_set_revision = self.agent_bridge_peer_set_revision();
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
        let current_profile = self
            .agent_bridge_profile
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        if current_profile.admission != profile.admission
            || self.agent_bridge_peer_set_revision() != observed_peer_set_revision
        {
            return Err(TransportError::SessionFenced);
        }
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
        observe_bridge("kernel.bridge_hello_accept", "attempt");
        let _transition = self.agent_bridge_transition_read()?;
        let result = self.accept_agent_bridge_hello_inner(connection_id, frame);
        match &result {
            Ok(_) => observe_bridge("kernel.bridge_hello_accept", "success"),
            Err(error) => {
                observe_bridge("kernel.bridge_hello_reject", "fenced");
                super::kernel_diagnostics::observe_terminal_error(bridge_terminal_code(error));
            }
        }
        result
    }

    #[cfg(windows)]
    fn accept_agent_bridge_hello_inner(
        &self,
        connection_id: &str,
        frame: &Frame,
    ) -> Result<eliot_protocol::AgentBridgePeerAdmissionReceipt, TransportError> {
        let _admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
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
        observe_bridge("kernel.bridge_receipt_prepared", "attempt");
        let _transition = self.agent_bridge_transition_read()?;
        let result = self.agent_bridge_admission_receipt_frame_inner(connection_id);
        match &result {
            Ok(_) => observe_bridge("kernel.bridge_receipt_prepared", "success"),
            Err(error) => {
                observe_bridge("kernel.bridge_receipt_prepared", "fenced");
                super::kernel_diagnostics::observe_terminal_error(bridge_terminal_code(error));
            }
        }
        result
    }

    #[cfg(windows)]
    fn agent_bridge_admission_receipt_frame_inner(
        &self,
        connection_id: &str,
    ) -> Result<Frame, TransportError> {
        let _admission_owner = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
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
        observe_bridge("kernel.bridge_activation_enqueue", "attempt");
        let _transition = self.agent_bridge_transition_read()?;
        let mut pending = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        // The pending owner serializes ticket publication with disconnect
        // revocation.  Within that owner, retain the same profile ->
        // connection order used by host-request admission.  The connection
        // guard is only needed for the immutable receipt snapshot; service
        // validation and frame parsing happen after it is released, so no
        // inner lock is held across a second owner lookup.
        let profile = self
            .agent_bridge_profile
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        self.validate_active_bridge_profile(&profile.admission)?;
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
            let receipt = accepted.admission_receipt().clone();
            if receipt.descriptor_sha256 != profile.admission.descriptor_sha256
                || receipt.profile_id != profile.admission.profile_id.as_str()
                || receipt.state_fence != profile.admission.state_fence
            {
                return Err(TransportError::SessionFenced);
            }
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
                .validate_admission(&receipt)
                .map_err(|_| TransportError::SessionFenced)?;
            (request, receipt)
        };
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
        let enqueue_now = unix_ms();
        let successor_of = pending.successor_candidate_for(enqueue_now, &request.demand_id)?;
        let ticket_nonce = fresh_activation_nonce_material()
            .map_err(|_| TransportError::SessionFenced)?
            .to_string();
        let ticket = AgentActivationResolutionTicket {
            wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
            wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
            ticket_id: format!("agent-activation:{ticket_nonce}"),
            activation_request_id: request.request_identity.request.metadata.request_id.clone(),
            demand_id: request.demand_id.clone(),
            activation_request_sha256: request.request_sha256.clone(),
            peer_admission_receipt_sha256: receipt.receipt_sha256.clone(),
            connection_id: connection_id.to_owned(),
            cancellation_id: request.request_identity.cancellation_id.clone(),
            state_fence: receipt.state_fence.clone(),
            kernel_deadline_unix_ms: receipt.activation_deadline_unix_ms,
            successor_of: successor_of.as_ref().map(|successor| {
                eliot_protocol::AgentActivationTicketPredecessor {
                    predecessor_ticket_id: successor.predecessor_ticket_id.clone(),
                    predecessor_ticket_sha256: successor.predecessor_ticket_sha256.clone(),
                    predecessor_result_sha256: successor.predecessor_result_sha256.clone(),
                    dependency_ref: successor.dependency_ref.clone(),
                    observed_dependency_revision: successor.observed_dependency_revision.clone(),
                    not_before_unix_ms: successor.not_before_unix_ms,
                }
            }),
            ticket_sha256: String::new(),
        }
        .with_computed_digest()
        .map_err(|_| TransportError::SessionFenced)?;
        ticket
            .validate_against(&request, &receipt)
            .map_err(|_| TransportError::SessionFenced)?;
        let (_, evicted_ticket_ids) = self
            .generation_gateway
            .ors
            .stage_activation_ticket_with_protection(
                &eliot_ors::ActivationLifecycleRecord {
                    ticket_id: ticket.ticket_id.clone(),
                    ticket_sha256: ticket.ticket_sha256.clone(),
                    ticket_payload: serde_json::to_string(&ticket)
                        .map_err(|_| TransportError::SessionFenced)?,
                    activation_request_id: request
                        .request_identity
                        .request
                        .metadata
                        .request_id
                        .as_str()
                        .to_owned(),
                    activation_request_sha256: request.request_sha256.clone(),
                    connection_id: connection_id.to_owned(),
                    state_fence: sha256_json(&ticket.state_fence)
                        .map_err(|_| TransportError::SessionFenced)?,
                    kernel_deadline_unix_ms: ticket.kernel_deadline_unix_ms,
                    cancellation_id: request.request_identity.cancellation_id.clone(),
                    state: eliot_ors::ActivationLifecycleState::Pending,
                    lifecycle_order: 0,
                    result_sha256: None,
                    claim_owner: None,
                    claim_expires_at_unix_ms: None,
                    successor_of: successor_of.clone(),
                    successor_ticket_id: None,
                    terminal_reason: None,
                },
                enqueue_now,
                &pending.entries.keys().cloned().collect::<BTreeSet<_>>(),
            )
            .map_err(|error| match error {
                eliot_ors::OrsError::ActivationLifecycleIdentityConflict { .. } => {
                    TransportError::IdentityConflict
                }
                _ => TransportError::SessionFenced,
            })?;
        for evicted_ticket_id in evicted_ticket_ids {
            pending.results.remove(&evicted_ticket_id);
            pending
                .result_order
                .retain(|candidate| candidate != &evicted_ticket_id);
            pending.lifecycle.remove(&evicted_ticket_id);
        }
        if let Some(successor) = &successor_of {
            pending
                .successor_consumed
                .insert(successor.predecessor_ticket_id.clone());
        }
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
                claim_lease_until_unix_ms: None,
                claim_dependency_ref: None,
                claim_dependency_revision: None,
                successor_of,
                owner_readback: None,
            },
        );
        pending.mark_lifecycle(&ticket.ticket_id, AgentActivationLifecycle::Pending);
        self.agent_activation_changed.notify_waiters();
        Ok(ticket)
    }

    #[cfg(windows)]
    pub(super) fn claim_agent_activation_ticket(
        &self,
        dependency_ref: &str,
        dependency_revision: &str,
    ) -> Result<Option<AgentActivationResolutionTicket>, TransportError> {
        observe_bridge("kernel.bridge_activation_claim", "attempt");
        let _transition = self.agent_bridge_transition_read()?;
        let mut pending = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let now = unix_ms();
        let Some(ticket) = pending.claim_at(now, dependency_ref, dependency_revision) else {
            return Ok(None);
        };
        let claim_expires_at = now
            .saturating_add(AGENT_ACTIVATION_CLAIM_LEASE_MS)
            .min(ticket.kernel_deadline_unix_ms);
        match self.generation_gateway.ors.claim_activation_ticket(
            &ticket.ticket_id,
            "eliotd",
            now,
            claim_expires_at,
        ) {
            Ok(Some(_)) => Ok(Some(ticket)),
            Ok(None) => {
                pending.mark_lifecycle(&ticket.ticket_id, AgentActivationLifecycle::Reconciling);
                pending.entries.remove(&ticket.ticket_id);
                self.agent_activation_changed.notify_waiters();
                Ok(None)
            }
            Err(_) => {
                let reconciled = self
                    .generation_gateway
                    .ors
                    .terminate_activation_without_result(
                        &ticket.ticket_id,
                        eliot_ors::ActivationLifecycleState::Reconciling,
                        "activation claim was lost before durable result admission",
                        now,
                    )
                    .is_ok()
                    || self
                        .generation_gateway
                        .ors
                        .load_activation_lifecycle(&ticket.ticket_id)
                        .ok()
                        .flatten()
                        .is_some_and(|lifecycle| {
                            lifecycle.state == eliot_ors::ActivationLifecycleState::Reconciling
                        });
                if reconciled {
                    pending
                        .mark_lifecycle(&ticket.ticket_id, AgentActivationLifecycle::Reconciling);
                    pending.entries.remove(&ticket.ticket_id);
                    self.agent_activation_changed.notify_waiters();
                    Ok(None)
                } else {
                    Err(TransportError::SessionFenced)
                }
            }
        }
    }

    /// Validates that the ticket's bridge leg is still owned by the live
    /// admitted transport under the current profile and fence. This is the
    /// Kernel-owned half of result validation: exact ticket binding is
    /// checked by the protocol `validate_against`, while connection liveness,
    /// admission receipt identity, profile currency, and service readiness
    /// are checked here against current Kernel owners. Governor-side semantic
    /// currency (task/plan revision against current Governor state) is owned
    /// by the trusted resolver read per I1.8; Kernel rechecks only what it
    /// owns and never invents semantic identity.
    ///
    /// The helper itself does not acquire pending state. Callers that hold the
    /// pending lock acquire it before this profile/connection/service
    /// sequence; bridge revocation uses the same order.
    #[cfg(windows)]
    fn validate_result_bridge_leg(
        &self,
        ticket: &AgentActivationResolutionTicket,
    ) -> Result<(), TransportError> {
        // The pending owner is held by every caller. Read the profile before
        // the connection map so host-request admission (profile ->
        // connection) and result publication cannot form an inner-lock ABBA.
        let profile = self
            .agent_bridge_profile
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        let receipt = {
            let connections = self
                .agent_bridge_connections
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let state = connections
                .get(&ticket.connection_id)
                .ok_or(TransportError::SessionFenced)?;
            if state.activation_completed || state.session.is_some() {
                return Err(TransportError::SessionFenced);
            }
            let accepted = state
                .accepted_transport
                .as_ref()
                .ok_or(TransportError::SessionFenced)?;
            accepted.admission_receipt().clone()
        };
        if receipt.receipt_sha256 != ticket.peer_admission_receipt_sha256
            || receipt.connection_id != ticket.connection_id
            || receipt.state_fence != ticket.state_fence
        {
            return Err(TransportError::SessionFenced);
        }
        if receipt.descriptor_sha256 != profile.admission.descriptor_sha256
            || receipt.profile_id != profile.admission.profile_id.as_str()
            || receipt.state_fence != profile.admission.state_fence
        {
            return Err(TransportError::SessionFenced);
        }
        self.validate_active_bridge_profile(&profile.admission)?;
        Ok(())
    }

    /// Validates a result for a fresh successor ticket against its immutable
    /// predecessor. Same-ticket replacement is intentionally absent.
    #[cfg(windows)]
    fn successor_result_allowed(
        pending: &AgentActivationPendingState,
        successor: &super::AgentActivationSuccessorBinding,
        incoming: &AgentActivationResolutionResult,
        demand_id: &str,
    ) -> Result<(), TransportError> {
        let predecessor = pending
            .results
            .get(&successor.predecessor_ticket_id)
            .ok_or(TransportError::IdentityConflict)?;
        if predecessor.demand_id != demand_id
            || predecessor.result.result_sha256 != successor.predecessor_result_sha256
            || predecessor.result.ticket_id != successor.predecessor_ticket_id
        {
            return Err(TransportError::IdentityConflict);
        }
        let AgentActivationResolutionDisposition::NotReady {
            retry: predecessor_retry,
            ..
        } = &predecessor.result.disposition
        else {
            return Err(TransportError::IdentityConflict);
        };
        if incoming.resolved_at_unix_ms < predecessor_retry.not_before_unix_ms
            || incoming.resolved_at_unix_ms < successor.not_before_unix_ms
        {
            return Err(TransportError::Timeout);
        }
        let observation = incoming
            .dependency_observation
            .as_ref()
            .ok_or(TransportError::IdentityConflict)?;
        let Some(claim_entry) = pending.entries.get(&incoming.ticket_id) else {
            return Err(TransportError::IdentityConflict);
        };
        if claim_entry.claim_dependency_ref.as_deref() != Some(observation.dependency_ref.as_str())
            || claim_entry.claim_dependency_revision.as_deref()
                != Some(observation.observed_dependency_revision.as_str())
            || predecessor.result.ticket_sha256 != successor.predecessor_ticket_sha256
            || observation.dependency_ref != successor.dependency_ref
            || observation.observed_dependency_revision == successor.observed_dependency_revision
        {
            return Err(TransportError::IdentityConflict);
        }
        if let AgentActivationResolutionDisposition::NotReady {
            retry: incoming_retry,
            ..
        } = &incoming.disposition
            && (incoming_retry.dependency_ref != observation.dependency_ref
                || incoming_retry.observed_dependency_revision
                    != observation.observed_dependency_revision)
        {
            return Err(TransportError::IdentityConflict);
        }
        Ok(())
    }

    /// Maps one validated disposition to its retention phase: only
    /// `NotReady` defers reconsideration, every other disposition is
    /// terminal on commit.
    #[cfg(windows)]
    fn result_phase_for_disposition(
        disposition: &AgentActivationResolutionDisposition,
    ) -> AgentActivationResultPhase {
        match disposition {
            AgentActivationResolutionDisposition::NotReady { .. } => {
                AgentActivationResultPhase::DeferredNotReady
            }
            _ => AgentActivationResultPhase::AcceptedTerminal,
        }
    }

    /// Decodes and validates one coherent ORS lifecycle/result snapshot before
    /// Kernel readiness. No live connection, claim, pending entry, or Session is
    /// restored; result-bearing and terminal/reconciling identities are.
    ///
    /// The snapshot is validated in two passes because the second pass reads
    /// the lifecycle projection the first pass publishes: every retained result
    /// is admitted only when its durable lifecycle phase already agrees with
    /// it, so an orphaned or cross-phase result can never be rehydrated.
    #[cfg(windows)]
    pub(super) fn rehydrate_agent_activation_state(
        ors: &eliot_ors::RedbRecoveryStore,
    ) -> Result<AgentActivationPendingState, KernelBuildError> {
        let snapshot = ors.load_activation_recovery_snapshot().map_err(|_| {
            KernelBuildError::Ors("activation recovery snapshot load failed".to_owned())
        })?;
        if snapshot.lifecycles.len() > eliot_ors::MAX_ACTIVATION_LIFECYCLE_RECORDS
            || snapshot.results.len() > eliot_ors::MAX_ACTIVATION_RESULT_RETENTION_RECORDS
        {
            return Err(KernelBuildError::Ors(
                "activation recovery retention bound exceeded".to_owned(),
            ));
        }
        let (lifecycle, successor_consumed) = rehydrate_activation_lifecycles(snapshot.lifecycles)?;
        let results = rehydrate_activation_results(snapshot.results, &lifecycle)?;
        Ok(AgentActivationPendingState::from_rehydrated_results(
            results,
            lifecycle,
            successor_consumed,
        ))
    }

    #[cfg(windows)]
    pub(super) fn retain_activation_result_durably(
        &self,
        pending: &mut AgentActivationPendingState,
        ticket: &AgentActivationResolutionTicket,
        result: &AgentActivationResolutionResult,
        phase: AgentActivationResultPhase,
    ) -> Result<(), TransportError> {
        let retention_phase = match phase {
            AgentActivationResultPhase::AcceptedTerminal => {
                eliot_ors::ActivationResultRetentionPhase::AcceptedTerminal
            }
            AgentActivationResultPhase::DeferredNotReady => {
                eliot_ors::ActivationResultRetentionPhase::DeferredNotReady
            }
        };
        let record = eliot_ors::ActivationResultRetentionRecord {
            ticket_id: ticket.ticket_id.clone(),
            ticket_sha256: ticket.ticket_sha256.clone(),
            ticket_payload: serde_json::to_string(ticket)
                .map_err(|_| TransportError::SessionFenced)?,
            result_sha256: result.result_sha256.clone(),
            result_payload: serde_json::to_string(result)
                .map_err(|_| TransportError::SessionFenced)?,
            connection_id: ticket.connection_id.clone(),
            state_fence: sha256_json(&ticket.state_fence)
                .map_err(|_| TransportError::SessionFenced)?,
            phase: retention_phase,
            retention_order: 0,
        };
        let canonical_stage = pending
            .stage_result_retention(AgentActivationResultRecord {
                result: result.clone(),
                demand_id: ticket.demand_id.clone(),
                phase,
                retention_order: 0,
            })
            .ok_or(TransportError::SessionFenced)?;
        // ORS is the sole durable semantic authority. Its lifecycle/result CAS
        // decides deadline, claim, successor, and immutable replay before the
        // in-memory projection is published.
        let dependency_observation = result.dependency_observation.as_ref().map(|observation| {
            (
                observation.dependency_ref.as_str(),
                observation.observed_dependency_revision.as_str(),
            )
        });
        let (retained, evicted_ticket_ids) = self
            .generation_gateway
            .ors
            .commit_activation_result_with_protection(
                &record,
                "eliotd",
                dependency_observation,
                unix_ms(),
                &pending.entries.keys().cloned().collect::<BTreeSet<_>>(),
            )
            .map_err(|error| match error {
                eliot_ors::OrsError::ActivationLifecycleExpired { .. } => TransportError::Timeout,
                eliot_ors::OrsError::ActivationLifecycleIdentityConflict { .. }
                | eliot_ors::OrsError::ActivationResultRetentionIdentityConflict { .. }
                | eliot_ors::OrsError::ActivationLifecycleStateConflict { .. } => {
                    TransportError::IdentityConflict
                }
                _ => TransportError::SessionFenced,
            })?;
        pending.publish_staged_result_retention(
            canonical_stage,
            &retained.ticket_id,
            retained.retention_order,
            &evicted_ticket_ids,
        );
        Ok(())
    }

    /// Submits against an already-retained per-ticket record. Exact digest
    /// replay returns the same stable acknowledgement; every changed payload
    /// under the immutable ticket is an identity conflict. Reconsideration
    /// uses a fresh successor ticket, never a same-ticket replacement.
    ///
    /// The caller holds `agent_activation_pending` across the durable identity
    /// decision and in-memory publication.
    #[cfg(windows)]
    fn submit_against_retained_result(
        &self,
        pending: &mut AgentActivationPendingState,
        entry_ticket: Option<AgentActivationResolutionTicket>,
        retained: &AgentActivationResultRecord,
        incoming: &AgentActivationResolutionResult,
        owner_readback: Option<&AgentActivationOwnerReadback>,
    ) -> Result<AgentActivationResultAck, TransportError> {
        if Self::result_phase_for_disposition(&retained.result.disposition) != retained.phase {
            return Err(TransportError::SessionFenced);
        }
        match classify_activation_result(Some(&retained.result), incoming) {
            ActivationResultDisposition::ExactReplay => {
                if let Some(ticket) = entry_ticket {
                    let stored_readback = pending
                        .entries
                        .get(&ticket.ticket_id)
                        .and_then(|entry| entry.owner_readback.as_ref());
                    let same_readback = match (stored_readback, owner_readback) {
                        (Some(stored), Some(incoming)) => stored.same_owner_projection(incoming),
                        (None, None) => true,
                        _ => false,
                    };
                    if !same_readback {
                        return Err(TransportError::IdentityConflict);
                    }
                    incoming
                        .validate_against(&ticket)
                        .map_err(|_| TransportError::SessionFenced)?;
                    retained
                        .result
                        .validate_against(&ticket)
                        .map_err(|_| TransportError::SessionFenced)?;
                    self.validate_result_bridge_leg(&ticket)?;
                }
                AgentActivationResultAck::accepted(&retained.result)
                    .map_err(|_| TransportError::SessionFenced)
            }
            // ORS retains one immutable result identity per ticket. A changed
            // same-ticket result is never a NotReady replacement; only a fresh
            // successor ticket can be considered by the admission path.
            ActivationResultDisposition::Commit | ActivationResultDisposition::Conflict => {
                Err(TransportError::IdentityConflict)
            }
        }
    }

    /// Returns the canonical in-memory projection of the durable result.
    /// The ORS mirror is checked only during the publish transaction; it is
    /// never consulted as an alternate semantic result source.
    #[cfg(windows)]
    fn retained_activation_result_for_ticket(
        pending: &AgentActivationPendingState,
        ticket_id: &str,
    ) -> Option<AgentActivationResultRecord> {
        pending.results.get(ticket_id).cloned()
    }

    /// Accepts one v2 semantic result for its exact pending ticket. This is
    /// the production submit path: the typed result (all seven dispositions)
    /// is validated against the pending ticket, the live bridge
    /// admission/connection, the current fence, and the deadline, then
    /// retained with its exact identity, digest, disposition, and submission
    /// phase before the acknowledgement is built.
    ///
    /// Replay and race semantics, all decided from retained identity plus
    /// digests: an exact digest replay is idempotent (even across deadline
    /// expiry, which never invalidates a terminal accepted result); a
    /// changed same-ticket result is `IdentityConflict` unless it meets the
    /// `NotReady` supersede gate while the bridge leg is still open.
    #[cfg(all(test, windows))]
    pub(super) fn submit_agent_activation_result(
        &self,
        submit: AgentActivationResultSubmit,
    ) -> Result<AgentActivationResultAck, TransportError> {
        self.submit_agent_activation_result_authenticated(submit, None, None)
    }

    /// Admits one typed activation result, authenticated or local.
    ///
    /// Submission keeps the protocol, bridge, deadline, and durable identity
    /// checks in one admission transaction: this entry validates the envelope
    /// and classifies the ticket as a retained replay or a fresh commit, and
    /// [`Self::commit_fresh_activation_result`] runs the fresh-commit leg
    /// under the same held Kernel owner lock.
    pub(super) fn submit_agent_activation_result_authenticated(
        &self,
        submit: AgentActivationResultSubmit,
        session: Option<&Session>,
        request_identity: Option<&RequestIdentity>,
    ) -> Result<AgentActivationResultAck, TransportError> {
        if let (Some(session), Some(identity)) = (session, request_identity) {
            Self::validate_activation_submitter(session, Some(identity))?;
        }
        observe_bridge("kernel.bridge_activation_result_submit", "attempt");
        // Unknown submission versions are rejected before any inner result
        // field is adopted.
        submit
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let owner_readback = submit.owner_readback.clone();
        if matches!(
            &submit.result.disposition,
            AgentActivationResolutionDisposition::Resolved { .. }
        ) && owner_readback
            .as_ref()
            .and_then(|readback| readback.kernel_owner.as_ref())
            .is_none()
        {
            // The production admission boundary must carry the exact P-07
            // revision/digest token before durable retention or acknowledgement;
            // the later Session projector repeats the current-owner check.
            return Err(TransportError::SessionFenced);
        }
        let incoming = submit.result;
        let ticket_id = incoming.ticket_id.clone();
        let _transition = self.agent_bridge_transition_read()?;
        // This is the one cross-representation admission guard. Keep the
        // existing Kernel owner locked through the identity check, durable
        // retention, and canonical-v2 ledger update so the raw P-04 path
        // cannot pass its own check and write a different result in between.
        let mut pending = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let entry = pending.entries.get(&ticket_id).cloned();
        let entry_ticket = entry.as_ref().map(|entry| entry.ticket.clone());
        // Restart rehydrates the durable result ledger, while pending tickets
        // remain fresh-process state. Classify retained identities before
        // requiring a live pending entry or consulting the deadline.
        let retained = Self::retained_activation_result_for_ticket(&pending, &ticket_id);
        if let Some(retained) = retained {
            return self.submit_against_retained_result(
                &mut pending,
                entry_ticket,
                &retained,
                &incoming,
                owner_readback.as_ref(),
            );
        }
        // Fresh commit: the bridge leg must still be open.
        let Some(entry_ticket) = entry_ticket else {
            return Err(TransportError::UnknownRequest);
        };
        let ack = self.commit_fresh_activation_result(
            &mut pending,
            entry.as_ref(),
            &entry_ticket,
            &incoming,
            owner_readback,
            &ticket_id,
        )?;
        drop(pending);
        self.agent_activation_changed.notify_waiters();
        Ok(ack)
    }

    /// Runs the fresh-commit leg of one activation result admission.
    ///
    /// The caller still holds the Kernel owner lock across this call, so the
    /// raw P-04 path cannot pass its own identity check and write a different
    /// result in between. A ticket with no live bridge entry, a closed
    /// (cancelled, expired, or reconciling) lifecycle, a mismatched
    /// cancellation or successor binding, a deadline that already elapsed, or
    /// an entry that already carries a result is refused here. Only a live
    /// entry with no retained result reaches the durable write, the owner
    /// readback publication, the lifecycle publication, and the FIFO retire,
    /// all still under the held lock.
    fn commit_fresh_activation_result(
        &self,
        pending: &mut std::sync::MutexGuard<'_, AgentActivationPendingState>,
        entry: Option<&AgentActivationPending>,
        entry_ticket: &AgentActivationResolutionTicket,
        incoming: &AgentActivationResolutionResult,
        owner_readback: Option<AgentActivationOwnerReadback>,
        ticket_id: &str,
    ) -> Result<AgentActivationResultAck, TransportError> {
        if matches!(
            pending.lifecycle(ticket_id),
            AgentActivationLifecycle::Cancelled
                | AgentActivationLifecycle::Expired
                | AgentActivationLifecycle::Reconciling
        ) {
            return Err(TransportError::IdentityConflict);
        }
        if entry_ticket.cancellation_id
            != entry
                .ok_or(TransportError::IdentityConflict)?
                .request
                .request_identity
                .cancellation_id
        {
            return Err(TransportError::IdentityConflict);
        }
        if let Some(successor) = entry.and_then(|entry| entry.successor_of.as_ref()) {
            let ticket_predecessor = entry_ticket
                .successor_of
                .as_ref()
                .ok_or(TransportError::IdentityConflict)?;
            if ticket_predecessor.predecessor_ticket_id != successor.predecessor_ticket_id
                || ticket_predecessor.predecessor_ticket_sha256
                    != successor.predecessor_ticket_sha256
                || ticket_predecessor.predecessor_result_sha256
                    != successor.predecessor_result_sha256
                || ticket_predecessor.dependency_ref != successor.dependency_ref
                || ticket_predecessor.observed_dependency_revision
                    != successor.observed_dependency_revision
                || ticket_predecessor.not_before_unix_ms != successor.not_before_unix_ms
            {
                return Err(TransportError::IdentityConflict);
            }
            Self::successor_result_allowed(pending, successor, incoming, &entry_ticket.demand_id)?;
        } else if entry_ticket.successor_of.is_some() {
            return Err(TransportError::IdentityConflict);
        }
        incoming
            .validate_against(entry_ticket)
            .map_err(|_| TransportError::SessionFenced)?;
        self.validate_result_bridge_leg(entry_ticket)?;
        // Deadline expiry with no retained result is the expected race at
        // this boundary. A retained result would have taken the replay path
        // above and survived the deadline; here there is nothing terminal to
        // preserve.
        if activation_deadline_expired(unix_ms(), entry_ticket.kernel_deadline_unix_ms) {
            return Err(TransportError::Timeout);
        }
        if !pending.entries.contains_key(ticket_id) || pending.results.contains_key(ticket_id) {
            return Err(TransportError::IdentityConflict);
        }
        let phase = Self::result_phase_for_disposition(&incoming.disposition);
        let ack = AgentActivationResultAck::accepted(incoming)
            .map_err(|_| TransportError::SessionFenced)?;
        self.retain_activation_result_durably(pending, entry_ticket, incoming, phase)?;
        if let Some(entry) = pending.entries.get_mut(ticket_id) {
            entry.owner_readback = owner_readback;
        } else {
            return Err(TransportError::IdentityConflict);
        }
        pending.mark_lifecycle(
            ticket_id,
            if phase == AgentActivationResultPhase::DeferredNotReady {
                AgentActivationLifecycle::DeferredNotReady
            } else {
                AgentActivationLifecycle::Accepted
            },
        );
        pending.fifo.retain(|queued_id| queued_id != ticket_id);
        Ok(ack)
    }

    /// Answers one lost-acknowledgement reconcile query purely from the
    /// retained per-ticket record. This path never reads the Governor and
    /// never recomputes semantics: a digest match returns the exact retained
    /// result (including its observed dependency revision for `NotReady`),
    /// an unknown ticket returns a typed `Unknown` so the daemon resubmits
    /// its retained result instead of re-reading, and a digest mismatch is
    /// an identity conflict that must never overwrite retention.
    #[cfg(all(test, windows))]
    pub(super) fn reconcile_agent_activation_result(
        &self,
        query: &AgentActivationResultReconcile,
    ) -> Result<AgentActivationResultAck, TransportError> {
        self.reconcile_agent_activation_result_authenticated(query, None, None)
    }

    pub(super) fn reconcile_agent_activation_result_authenticated(
        &self,
        query: &AgentActivationResultReconcile,
        session: Option<&Session>,
        request_identity: Option<&RequestIdentity>,
    ) -> Result<AgentActivationResultAck, TransportError> {
        if let (Some(session), Some(identity)) = (session, request_identity) {
            Self::validate_activation_submitter(session, Some(identity))?;
        }
        observe_bridge("kernel.bridge_activation_reconcile", "attempt");
        query
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let _transition = self.agent_bridge_transition_read()?;
        let retained = match self
            .generation_gateway
            .ors
            .load_activation_result(&query.ticket_id, &query.result_sha256)
        {
            Ok(retained) => retained,
            Err(eliot_ors::OrsError::ActivationResultRetentionIdentityConflict { .. }) => {
                return Err(TransportError::IdentityConflict);
            }
            Err(_) => return Err(TransportError::SessionFenced),
        };
        let Some(retained) = retained else {
            return AgentActivationResultAck::unknown(query)
                .map_err(|_| TransportError::SessionFenced);
        };
        let lifecycle = self
            .generation_gateway
            .ors
            .load_activation_lifecycle(&query.ticket_id)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::IdentityConflict)?;
        if lifecycle.result_sha256.as_deref() != Some(query.result_sha256.as_str())
            || lifecycle.ticket_sha256 != retained.ticket_sha256
            || lifecycle.connection_id != retained.connection_id
            || lifecycle.state_fence != retained.state_fence
        {
            return Err(TransportError::IdentityConflict);
        }
        let ticket: AgentActivationResolutionTicket =
            serde_json::from_str(&lifecycle.ticket_payload)
                .map_err(|_| TransportError::SessionFenced)?;
        ticket
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let ticket_digest = ticket
            .compute_digest()
            .map_err(|_| TransportError::SessionFenced)?;
        if ticket.ticket_id != lifecycle.ticket_id
            || ticket_digest != lifecycle.ticket_sha256
            || ticket.activation_request_id.as_str() != lifecycle.activation_request_id
            || ticket.activation_request_sha256 != lifecycle.activation_request_sha256
            || ticket.kernel_deadline_unix_ms != lifecycle.kernel_deadline_unix_ms
            || ticket.cancellation_id != lifecycle.cancellation_id
        {
            return Err(TransportError::IdentityConflict);
        }
        let result: AgentActivationResolutionResult =
            serde_json::from_str(&retained.result_payload)
                .map_err(|_| TransportError::SessionFenced)?;
        result
            .validate_against(&ticket)
            .map_err(|_| TransportError::SessionFenced)?;
        if result.ticket_id != query.ticket_id || result.result_sha256 != query.result_sha256 {
            return Err(TransportError::IdentityConflict);
        }
        let expected_state = if Self::result_phase_for_disposition(&result.disposition)
            == AgentActivationResultPhase::DeferredNotReady
        {
            AgentActivationLifecycle::DeferredNotReady
        } else {
            AgentActivationLifecycle::Accepted
        };
        if pending_state_from_lifecycle(lifecycle.state) != expected_state {
            return Err(TransportError::IdentityConflict);
        }
        AgentActivationResultAck::accepted(&result).map_err(|_| TransportError::SessionFenced)
    }

    /// Maps one non-`Resolved` daemon disposition to its exact agent-visible
    /// denial code. The match is exhaustive with no wildcard arm, so a future
    /// disposition breaks compilation here and at every projection site instead
    /// of collapsing into another code. `Resolved` yields `None` because it
    /// never projects a denial; it builds the `Authenticated` binding instead.
    /// Kernel-owned refusals with no daemon disposition at all (pre-ticket
    /// immediate denial, result-less expiry) never reach this function; they
    /// keep the Kernel-owned `SemanticResolutionUnavailable` code.
    pub(super) fn activation_denial_code_for_disposition(
        disposition: &AgentActivationResolutionDisposition,
    ) -> Option<AgentBridgeActivationDenialCode> {
        match disposition {
            AgentActivationResolutionDisposition::Resolved { .. } => None,
            AgentActivationResolutionDisposition::TaskSelectionRequired { .. } => {
                Some(AgentBridgeActivationDenialCode::TaskSelectionRequired)
            }
            AgentActivationResolutionDisposition::ScopeSelectionRequired { .. } => {
                Some(AgentBridgeActivationDenialCode::ScopeSelectionRequired)
            }
            AgentActivationResolutionDisposition::ScopeAmbiguous { .. } => {
                Some(AgentBridgeActivationDenialCode::ScopeAmbiguous)
            }
            AgentActivationResolutionDisposition::NotReady { .. } => {
                Some(AgentBridgeActivationDenialCode::NotReady)
            }
            AgentActivationResolutionDisposition::StaleFence { .. } => {
                Some(AgentBridgeActivationDenialCode::StaleFence)
            }
            AgentActivationResolutionDisposition::FailedInternal { .. } => {
                Some(AgentBridgeActivationDenialCode::FailedInternal)
            }
        }
    }

    /// Projects one accepted v2 result to its exact bridge connection. The
    /// match is exhaustive over all seven typed dispositions with no
    /// fallback arm, so the compiler rejects any silent coercion: only an
    /// exact valid `Resolved` binding creates a Session, and every
    /// non-`Resolved` disposition receives an immediate typed denial carrying
    /// its own exact denial code plus the full owner-issued denial detail
    /// (candidate/recovery handles, retry directive, observed fence, or
    /// failure handle), creating no Session, authority, capability,
    /// or Finish state. The exact disposition remains retained in the Kernel
    /// record and the daemon-facing acknowledgement; mapping is decided by
    /// these typed arms alone and never by human detail or log text.
    /// The Resolved arm compares the daemon's semantic owner readback with the
    /// exact ticket/binding and compares the captured P-07 revision/digest with
    /// the owner still installed in Kernel. The P-07 transition read guard and
    /// both owner locks remain held through Session/connection publication, so
    /// an owner rotation cannot pass between validation and Session creation.
    #[cfg(windows)]
    fn with_current_activation_owner<T>(
        &self,
        pending: &AgentActivationPending,
        result: &AgentActivationResolutionResult,
        binding: &eliot_protocol::AgentActivationResolvedBinding,
        project: impl FnOnce() -> Result<T, TransportError>,
    ) -> Result<T, TransportError> {
        let _owner_transition = self
            .p07_owner_transition
            .read()
            .map_err(|_| TransportError::SessionFenced)?;
        let evidence = result
            .owner_evidence
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let readback = pending
            .owner_readback
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let expected_kernel_owner = readback
            .kernel_owner
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        if readback.evidence.owner_id != evidence.owner_id
            || readback.evidence.owner_revision < evidence.owner_revision
        {
            return Err(TransportError::SessionFenced);
        }
        readback
            .validate_against_binding(binding, &pending.ticket.state_fence)
            .map_err(|_| TransportError::SessionFenced)?;
        let owner = self
            .p07_owner
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let owner_digest = self
            .p07_owner_digest
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let current_revision = owner.as_ref().map(BoundCanonicalOwner::bound_revision);
        if current_revision != Some(expected_kernel_owner.revision)
            || owner_digest.as_deref() != Some(expected_kernel_owner.bundle_sha256.as_str())
        {
            return Err(TransportError::SessionFenced);
        }
        // Do not drop either owner guard before the connection map and Session
        // are updated: an owner publish cannot pass between validation and
        // publication.
        project()
    }

    #[cfg(windows)]
    fn activation_result_response_frame(
        &self,
        connection_id: &str,
        original: &Frame,
        pending: &AgentActivationPending,
        result: &AgentActivationResolutionResult,
    ) -> Result<Frame, TransportError> {
        result
            .validate_against(&pending.ticket)
            .map_err(|_| TransportError::SessionFenced)?;
        if pending.ticket.ticket_id != result.ticket_id
            || pending.ticket.connection_id != connection_id
        {
            return Err(TransportError::SessionFenced);
        }
        self.validate_result_bridge_leg(&pending.ticket)?;
        // The match stays exhaustive with no wildcard arm, so adding a
        // future disposition breaks compilation instead of silently
        // coercing. All six non-success dispositions share the bridge
        // outcome below: an immediate typed denial carrying the exact
        // per-disposition code plus the full owner-issued denial detail,
        // with no Session, authority, capability, or
        // Finish. Their exact typed content stays retained in the Kernel
        // record and the daemon-facing acknowledgement; mapping is decided
        // by these typed arms alone.
        match &result.disposition {
            AgentActivationResolutionDisposition::Resolved { binding } => self
                .with_current_activation_owner(pending, result, binding, || {
                    self.resolved_result_response_frame(connection_id, original, pending, binding)
                }),
            AgentActivationResolutionDisposition::TaskSelectionRequired { .. }
            | AgentActivationResolutionDisposition::ScopeSelectionRequired { .. }
            | AgentActivationResolutionDisposition::ScopeAmbiguous { .. }
            | AgentActivationResolutionDisposition::NotReady { .. }
            | AgentActivationResolutionDisposition::StaleFence { .. }
            | AgentActivationResolutionDisposition::FailedInternal { .. } => {
                let reason_code = Self::activation_denial_code_for_disposition(&result.disposition)
                    .ok_or(TransportError::SessionFenced)?;
                self.denied_result_response_frame(
                    connection_id,
                    original,
                    pending,
                    reason_code,
                    Some(result.disposition.clone()),
                )
            }
        }
    }

    /// Completes one waiting bridge exchange from a full typed result.
    ///
    /// The retained result is re-validated against its exact pending ticket
    /// before anything is consumed; a tampered, wrong-ticket, or wrong-fence
    /// result is rejected with the pending evidence preserved.
    /// A `Resolved` disposition builds the Authenticated transport binding by
    /// copying the Governor-owned resolved fields and the exact ticket fence;
    /// Kernel performs no semantic selection or retry interpretation. Any
    /// other disposition revokes the connection and returns the immediate
    /// typed denial carrying that disposition's exact denial code, without
    /// creating a Session. The match stays exhaustive with no wildcard arm.
    #[cfg(all(test, windows))]
    pub(super) fn activation_result_response(
        &self,
        connection_id: &str,
        frame: &Frame,
        ticket_id: &str,
        result: &AgentActivationResolutionResult,
    ) -> Result<Frame, TransportError> {
        let _transition = self.agent_bridge_transition_read()?;
        self.activation_result_response_under_transition(connection_id, frame, ticket_id, result)
    }

    #[cfg(all(test, windows))]
    fn activation_result_response_under_transition(
        &self,
        connection_id: &str,
        frame: &Frame,
        ticket_id: &str,
        result: &AgentActivationResolutionResult,
    ) -> Result<Frame, TransportError> {
        let mut pending = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let mut pending_entry = pending
            .entries
            .get(ticket_id)
            .ok_or(TransportError::SessionFenced)?
            .clone();
        if let Some(evidence) = result.owner_evidence.clone() {
            pending_entry.owner_readback = Some(
                AgentActivationOwnerReadback::from_evidence(evidence, result.resolved_at_unix_ms)
                    .map_err(|_| TransportError::SessionFenced)?,
            );
        }
        // #203: reject a tampered, wrong-ticket, or wrong-fence retained
        // result before mutating any ledger. The submit path validates before
        // retaining, so this is defense-in-depth; a failure here preserves
        // both the pending entry and the retained result verbatim. This
        // closes the negative-disposition arm, which otherwise projects
        // without any ticket binding check.
        result
            .validate_against(&pending_entry.ticket)
            .map_err(|_| TransportError::SessionFenced)?;
        self.validate_result_bridge_leg(&pending_entry.ticket)?;
        // Exhaustive per-disposition projection with no wildcard arm: a
        // future disposition breaks compilation here instead of silently
        // reusing another denial code. Only `Resolved` reaches the binding
        // projector; every other disposition is revoked and denied with its
        // exact code, creating no Session.
        match &result.disposition {
            AgentActivationResolutionDisposition::Resolved { binding } => {
                let reply = self.activation_response_frame_for_resolution(
                    connection_id,
                    frame,
                    &pending_entry,
                    result,
                    binding,
                )?;
                pending.entries.remove(ticket_id);
                Ok(reply)
            }
            AgentActivationResolutionDisposition::TaskSelectionRequired { .. }
            | AgentActivationResolutionDisposition::ScopeSelectionRequired { .. }
            | AgentActivationResolutionDisposition::ScopeAmbiguous { .. }
            | AgentActivationResolutionDisposition::NotReady { .. }
            | AgentActivationResolutionDisposition::StaleFence { .. }
            | AgentActivationResolutionDisposition::FailedInternal { .. } => {
                let reason_code = Self::activation_denial_code_for_disposition(&result.disposition)
                    .ok_or(TransportError::SessionFenced)?;
                let reply = self.denied_result_response_frame(
                    connection_id,
                    frame,
                    &pending_entry,
                    reason_code,
                    Some(result.disposition.clone()),
                )?;
                pending.entries.remove(ticket_id);
                self.revoke_agent_bridge_under_transition(connection_id, &mut pending)?;
                Ok(reply)
            }
        }
    }

    /// Builds the Authenticated transport binding for a `Resolved` result.
    ///
    /// This is the mechanical twin of [`Self::activation_response_frame`]:
    /// the binding fields and the ticket fence come from the exact retained
    /// ticket and Governor-owned result, and the fresh Session nonce is the
    /// only Kernel-minted value. It is never called for a non-`Resolved`
    /// disposition.
    #[cfg(all(test, windows))]
    fn activation_response_frame_for_resolution(
        &self,
        connection_id: &str,
        original: &Frame,
        pending: &AgentActivationPending,
        result: &AgentActivationResolutionResult,
        binding: &eliot_protocol::AgentActivationResolvedBinding,
    ) -> Result<Frame, TransportError> {
        result
            .validate_against(&pending.ticket)
            .map_err(|_| TransportError::SessionFenced)?;
        let owner_evidence = result
            .owner_evidence
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        owner_evidence
            .validate_against_binding(binding, &pending.ticket.state_fence)
            .map_err(|_| TransportError::SessionFenced)?;
        if pending.ticket.ticket_id != result.ticket_id
            || pending.ticket.connection_id != connection_id
        {
            return Err(TransportError::SessionFenced);
        }
        // The ticket binding is exact on both legs here: `validate_against`
        // above enforces `result.ticket_state_fence == pending.ticket.state_fence`,
        // so the shared `Resolved` projector below builds the identical fence
        // the inline P-04 construction built. This path keeps its own
        // ticket/connection checks and performs no additional v2 bridge-leg
        // validation.
        self.resolved_result_response_frame(connection_id, original, pending, binding)
    }
    /// Creates the bridge Session for exactly one valid `Resolved` binding.
    ///
    /// Binding validation rechecks every Kernel-owned property: the result
    /// binds the exact pending ticket identity, digest, and fence; the
    /// ticket binds the exact live admission receipt, connection, and fence;
    /// and the admission binds the current profile, candidate, and
    /// activation receipt. Task/plan semantic currency against live Governor
    /// state is owned by the trusted resolver read (I1.8); Kernel never
    /// invents semantic identity here, it only projects the exact validated
    /// binding into a transport Session.
    #[cfg(windows)]
    fn resolved_result_response_frame(
        &self,
        connection_id: &str,
        original: &Frame,
        pending: &AgentActivationPending,
        binding: &AgentActivationResolvedBinding,
    ) -> Result<Frame, TransportError> {
        let session_nonce = fresh_activation_nonce_material()
            .map_err(|_| TransportError::SessionFenced)?
            .to_string();
        // Keep the connection owner guard through Session construction and
        // publication. A detached connection or a poisoned map therefore
        // cannot leave a locally-created Session without an atomic owner
        // update; projection either commits both fields or returns fenced.
        let mut connections = self
            .agent_bridge_connections
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let accepted = connections
            .get(connection_id)
            .ok_or(TransportError::SessionFenced)?
            .accepted_transport
            .as_ref()
            .ok_or(TransportError::SessionFenced)?
            .clone();
        let session = Session::establish_agent_bridge(
            connection_id,
            accepted.peer().clone(),
            accepted.client_hello().module_generation.clone(),
            session_nonce.clone(),
        )?;
        let authenticated = AgentBridgeAuthenticatedBinding {
            principal_id: binding.principal_id.clone(),
            session_id: binding.session_id.clone(),
            activation_generation: pending.ticket.state_fence.resource_generation,
            state_fence: AgentBridgeActivationFence {
                authority_epoch: pending.ticket.state_fence.authority_epoch.clone(),
                generation: pending.ticket.state_fence.resource_generation,
                nonce: session_nonce,
            },
            task_id: binding.task_id.clone(),
            work_unit_id: binding.work_unit_id.clone(),
            work_scope_id: binding.work_scope_id.clone(),
            task_revision: binding.task_revision.clone(),
            plan_id: binding.plan_id.clone(),
            plan_revision: binding.plan_revision.clone(),
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
                binding: Box::new(authenticated),
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

    /// Returns the immediate typed denial for one non-`Resolved` result,
    /// carrying the exact per-disposition denial code plus the full
    /// owner-issued denial detail supplied by the caller. No Session,
    /// authority, capability, or Finish state is created on any
    /// path through this function; the bridge leg is only marked complete.
    #[cfg(windows)]
    fn denied_result_response_frame(
        &self,
        connection_id: &str,
        original: &Frame,
        pending: &AgentActivationPending,
        reason_code: AgentBridgeActivationDenialCode,
        detail: Option<AgentActivationResolutionDisposition>,
    ) -> Result<Frame, TransportError> {
        let response = AgentBridgeActivationResponse::denied(&pending.request, reason_code, detail)
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
        state.activation_completed = true;
        Ok(reply)
    }

    /// Queues one validated bridge request and waits for the sole eliotd
    /// resolver result. Kernel owns the final transport Session/fence and
    /// every deadline/cancel race: an accepted v2 result is projected even
    /// if the deadline expires while it is retained, and only a result-less
    /// expired ticket falls back to the typed denial. The pending entry is
    /// consumed after projecting, but the exact v2 result record stays
    /// retained for daemon replay/reconcile.
    ///
    /// Queues one validated bridge request and waits for the sole eliotd
    /// resolver outcome. Kernel owns the final transport Session/fence.
    ///
    /// The exchange accepts one full typed resolution result for the exact
    /// ticket. A `Resolved` result yields the Authenticated transport
    /// binding; every other disposition yields the immediate typed denial
    /// every other disposition yields the immediate typed denial carrying that
    /// disposition's exact denial code and creates no Session. The full typed
    /// result stays addressable under its ticket and result digests for
    /// Governor reconciliation through the host-request route; the denial wire
    /// carries the exact per-disposition code so the agent can distinguish
    /// selection, ambiguity, retry, fence, and internal outcomes.
    #[cfg(windows)]
    pub async fn await_agent_bridge_activation_response(
        &self,
        connection_id: &str,
        frame: &Frame,
    ) -> Result<Frame, TransportError> {
        let ticket = self.enqueue_agent_bridge_activation(connection_id, frame)?;
        loop {
            enum BridgeWaiterOutcome {
                ResultAvailable,
                Waiting,
                Gone,
            }
            let outcome = {
                let _transition = self.agent_bridge_transition_read()?;
                let pending = self
                    .agent_activation_pending
                    .lock()
                    .map_err(|_| TransportError::SessionFenced)?;
                match pending.entries.get(&ticket.ticket_id) {
                    None => BridgeWaiterOutcome::Gone,
                    Some(_) if pending.results.contains_key(&ticket.ticket_id) => {
                        BridgeWaiterOutcome::ResultAvailable
                    }
                    Some(_) => BridgeWaiterOutcome::Waiting,
                }
            };
            match outcome {
                BridgeWaiterOutcome::ResultAvailable => {
                    return self.project_retained_activation_result(
                        connection_id,
                        frame,
                        &ticket.ticket_id,
                    );
                }
                BridgeWaiterOutcome::Gone => {
                    // The bridge leg was revoked (disconnect, profile
                    // replacement, or deadline consumption). Retained v2
                    // results still serve daemon-leg replay/reconcile; this
                    // waiter has no connection left to answer.
                    return Err(TransportError::SessionFenced);
                }
                BridgeWaiterOutcome::Waiting => {}
            }
            let now = unix_ms();
            if activation_deadline_expired(now, ticket.kernel_deadline_unix_ms) {
                return self.expire_agent_bridge_activation(connection_id, frame, &ticket);
            }
            let notified = self.agent_activation_changed.notified();
            tokio::select! {
                () = notified => {}
                () = tokio::time::sleep(Duration::from_millis(25)) => {}
            }
        }
    }

    /// Projects one retained v2 result to its bridge connection and consumes
    /// the pending entry. The exact result record stays retained for daemon
    /// replay/reconcile.
    #[cfg(windows)]
    fn project_retained_activation_result(
        &self,
        connection_id: &str,
        frame: &Frame,
        ticket_id: &str,
    ) -> Result<Frame, TransportError> {
        let _transition = self.agent_bridge_transition_read()?;
        self.project_retained_activation_result_under_transition(connection_id, frame, ticket_id)
    }

    #[cfg(windows)]
    fn project_retained_activation_result_under_transition(
        &self,
        connection_id: &str,
        frame: &Frame,
        ticket_id: &str,
    ) -> Result<Frame, TransportError> {
        let mut pending = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let pending_entry = pending
            .entries
            .get(ticket_id)
            .ok_or(TransportError::SessionFenced)?
            .clone();
        let result = pending
            .results
            .get(ticket_id)
            .ok_or(TransportError::SessionFenced)?
            .result
            .clone();
        let reply =
            self.activation_result_response_frame(connection_id, frame, &pending_entry, &result)?;
        pending.entries.remove(ticket_id);
        Ok(reply)
    }

    /// Consumes one result-less expired ticket: removes the pending entry,
    /// revokes the bridge leg, and returns the immediate typed denial. This
    /// runs only when no v2 result is retained; an
    /// accepted result always wins the deadline race and is projected by the
    /// waiter instead.
    #[cfg(windows)]
    fn expire_agent_bridge_activation(
        &self,
        connection_id: &str,
        frame: &Frame,
        ticket: &AgentActivationResolutionTicket,
    ) -> Result<Frame, TransportError> {
        let _transition = self.agent_bridge_transition_read()?;
        self.expire_agent_bridge_activation_under_transition(connection_id, frame, ticket)
    }

    #[cfg(windows)]
    fn expire_agent_bridge_activation_under_transition(
        &self,
        connection_id: &str,
        frame: &Frame,
        ticket: &AgentActivationResolutionTicket,
    ) -> Result<Frame, TransportError> {
        let mut pending = self
            .agent_activation_pending
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        if pending.results.contains_key(&ticket.ticket_id) {
            drop(pending);
            return self.project_retained_activation_result_under_transition(
                connection_id,
                frame,
                &ticket.ticket_id,
            );
        }
        let request = pending
            .entries
            .get(&ticket.ticket_id)
            .ok_or(TransportError::SessionFenced)?
            .request
            .clone();
        self.generation_gateway
            .ors
            .terminate_activation_without_result(
                &ticket.ticket_id,
                eliot_ors::ActivationLifecycleState::Expired,
                "deadline elapsed before result retention",
                unix_ms(),
            )
            .map_err(|error| match error {
                eliot_ors::OrsError::ActivationLifecycleIdentityConflict { .. }
                | eliot_ors::OrsError::ActivationResultRetentionIdentityConflict { .. } => {
                    TransportError::IdentityConflict
                }
                _ => TransportError::SessionFenced,
            })?;
        pending.mark_lifecycle(&ticket.ticket_id, AgentActivationLifecycle::Expired);
        pending.entries.remove(&ticket.ticket_id);
        self.revoke_agent_bridge_under_transition(connection_id, &mut pending)?;
        // Result-less expiry has no daemon disposition to project, so it keeps
        // the Kernel-owned no-result denial code. Mapping it to any of the six
        // disposition codes would fabricate a daemon semantic result after the
        // deadline, which the expiry race must never do.
        let response = AgentBridgeActivationResponse::denied(
            &request,
            AgentBridgeActivationDenialCode::SemanticResolutionUnavailable,
            None,
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
                serde_json::to_value(response).map_err(|_| TransportError::SessionFenced)?,
            ),
            trace_context: frame.trace_context.clone(),
        };
        reply.validate()?;
        Ok(reply)
    }

    /// Validates one closed bridge activation operation and emits the sole
    /// R13.1b typed denial. No Kernel `Session` or semantic authority is made.
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the activation response keeps request, receipt, and replay checks ordered with its diagnostic terminal"
    )]
    pub fn agent_bridge_activation_response(
        &self,
        connection_id: &str,
        frame: &Frame,
    ) -> Result<Frame, TransportError> {
        observe_bridge("kernel.bridge_activation_request", "attempt");
        let _transition = self.agent_bridge_transition_read()?;
        let (mut pending, pending_poisoned) = match self.agent_activation_pending.lock() {
            Ok(pending) => (pending, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        let result = if pending_poisoned {
            Err(TransportError::SessionFenced)
        } else {
            (|| {
                let profile = match self.agent_bridge_profile.lock() {
                    Ok(profile) => profile.clone().ok_or(TransportError::SessionFenced)?,
                    Err(poisoned) => {
                        let mut profile = poisoned.into_inner();
                        *profile = None;
                        return Err(TransportError::SessionFenced);
                    }
                };
                self.validate_active_bridge_profile(&profile.admission)?;
                let receipt = {
                    let connections = match self.agent_bridge_connections.lock() {
                        Ok(connections) => connections,
                        Err(poisoned) => {
                            drop(poisoned.into_inner());
                            return Err(TransportError::SessionFenced);
                        }
                    };
                    let state = connections
                        .get(connection_id)
                        .ok_or(TransportError::SessionFenced)?;
                    if state.activation_completed || state.session.is_some() {
                        return Err(TransportError::IdentityConflict);
                    }
                    state
                        .accepted_transport
                        .as_ref()
                        .ok_or(TransportError::SessionFenced)?
                        .admission_receipt()
                        .clone()
                };
                if receipt.descriptor_sha256 != profile.admission.descriptor_sha256
                    || receipt.profile_id != profile.admission.profile_id.as_str()
                    || receipt.state_fence != profile.admission.state_fence
                {
                    return Err(TransportError::SessionFenced);
                }
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
                    .validate_admission(&receipt)
                    .map_err(|_| TransportError::SessionFenced)?;
                let response = AgentBridgeActivationResponse::denied(
                    &request,
                    AgentBridgeActivationDenialCode::SemanticResolutionUnavailable,
                    None,
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
                        serde_json::to_value(response)
                            .map_err(|_| TransportError::SessionFenced)?,
                    ),
                    trace_context: frame.trace_context.clone(),
                };
                reply.validate()?;
                Ok(reply)
            })()
        };
        let cleanup = self.cleanup_agent_bridge_activation_response_under_transition(
            connection_id,
            &mut pending,
            result.is_ok(),
        );
        let result = match (result, cleanup, pending_poisoned) {
            (Ok(reply), Ok(()), false) => Ok(reply),
            (Err(error), _, _) => Err(error),
            (Ok(_), Err(error), _) => Err(error),
            (Ok(_), Ok(()), true) => Err(TransportError::SessionFenced),
        };
        match &result {
            Ok(_) => observe_bridge("kernel.bridge_activation_request", "success"),
            Err(error) => {
                observe_bridge("kernel.bridge_activation_request", "fenced");
                super::kernel_diagnostics::observe_terminal_error(bridge_terminal_code(error));
            }
        }
        result
    }

    #[cfg(windows)]
    fn persist_resultless_activation_revocation(
        &self,
        pending: &mut AgentActivationPendingState,
        ticket_id: &str,
        reason: &'static str,
    ) -> Result<(), TransportError> {
        if pending.results.contains_key(ticket_id) {
            return Ok(());
        }
        let target = match pending.lifecycle(ticket_id) {
            AgentActivationLifecycle::Pending => eliot_ors::ActivationLifecycleState::Cancelled,
            AgentActivationLifecycle::Claimed => eliot_ors::ActivationLifecycleState::Reconciling,
            AgentActivationLifecycle::Cancelled
            | AgentActivationLifecycle::Reconciling
            | AgentActivationLifecycle::Expired => return Ok(()),
            AgentActivationLifecycle::Accepted | AgentActivationLifecycle::DeferredNotReady => {
                return Err(TransportError::IdentityConflict);
            }
        };
        let terminal = match target {
            eliot_ors::ActivationLifecycleState::Cancelled => {
                let cancellation_id = pending
                    .entries
                    .get(ticket_id)
                    .map(|entry| entry.request.request_identity.cancellation_id.as_str())
                    .ok_or(TransportError::SessionFenced)?;
                self.generation_gateway
                    .ors
                    .cancel_activation_without_result(ticket_id, cancellation_id, reason, unix_ms())
            }
            eliot_ors::ActivationLifecycleState::Reconciling => self
                .generation_gateway
                .ors
                .terminate_activation_without_result(ticket_id, target, reason, unix_ms()),
            _ => return Err(TransportError::SessionFenced),
        };
        terminal.map_err(|_| TransportError::SessionFenced)?;
        pending.mark_lifecycle(
            ticket_id,
            match target {
                eliot_ors::ActivationLifecycleState::Cancelled => {
                    AgentActivationLifecycle::Cancelled
                }
                eliot_ors::ActivationLifecycleState::Reconciling => {
                    AgentActivationLifecycle::Reconciling
                }
                _ => return Err(TransportError::SessionFenced),
            },
        );
        Ok(())
    }

    #[cfg(windows)]
    fn cleanup_agent_bridge_activation_response_under_transition(
        &self,
        connection_id: &str,
        pending: &mut AgentActivationPendingState,
        response_valid: bool,
    ) -> Result<(), TransportError> {
        // This cleanup is part of the denial linearization point. It
        // must still detach the bridge when validation failed because an
        // inner lock was poisoned; otherwise the caller could retry against
        // a half-validated connection. Recovering a poisoned guard permits
        // removal and fencing, but the caller still receives SessionFenced.
        let (mut connections, connections_poisoned) = match self.agent_bridge_connections.lock() {
            Ok(connections) => (connections, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        let revoked = connections.remove(connection_id);
        let removed = pending
            .entries
            .iter()
            .filter(|(_, entry)| entry.ticket.connection_id == connection_id)
            .map(|(ticket_id, _)| ticket_id.clone())
            .collect::<Vec<_>>();
        for ticket_id in &removed {
            self.persist_resultless_activation_revocation(
                pending,
                ticket_id,
                "bridge response cleanup reached a resultless terminal boundary",
            )?;
            pending.entries.remove(ticket_id);
        }
        let live_ticket_ids = pending.entries.keys().cloned().collect::<BTreeSet<_>>();
        pending
            .fifo
            .retain(|ticket_id| live_ticket_ids.contains(ticket_id));
        drop(connections);
        if let Some(mut state) = revoked {
            if response_valid {
                state.exchange.abort();
            } else {
                state.exchange.fence();
            }
            if let Some(mut session) = state.session.take() {
                session.fence();
            }
            state.accepted_transport = None;
        }
        self.fence_host_requests_for_connection(connection_id);
        self.note_agent_bridge_peer_set_change();
        self.agent_activation_changed.notify_waiters();
        if connections_poisoned {
            Err(TransportError::SessionFenced)
        } else {
            Ok(())
        }
    }

    /// Revokes all retained bridge authority for one disconnected connection.
    ///
    /// Transport revocation is connection-scoped: the exchange is aborted,
    /// the transport Session is fenced, and the accepted transport is dropped,
    /// so a reconnected bridge generation never inherits this connection's
    /// Session, capabilities, or pending activation tickets. Durable
    /// P-04 host-request ORS records are never deleted here; records staged
    /// through the presenting connection that are still in an uncertain
    /// pre-terminal state are fenced to `Unknown` so a later exact replay or
    /// reconciliation observes the disconnect honestly instead of retrying
    /// blindly. Records that may already have produced effects, and all
    /// terminal records, stay under their owner's continuation rules.
    #[cfg(windows)]
    pub fn revoke_agent_bridge(&self, connection_id: &str) {
        observe_bridge("kernel.bridge_cleanup", "attempt");
        let Ok(_transition) = self.agent_bridge_transition_read() else {
            observe_bridge("kernel.bridge_cleanup", "fenced");
            return;
        };
        let (mut pending, pending_poisoned) = match self.agent_activation_pending.lock() {
            Ok(pending) => (pending, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        let revocation = self.revoke_agent_bridge_under_transition(connection_id, &mut pending);
        if pending_poisoned || revocation.is_err() {
            observe_bridge("kernel.bridge_cleanup", "fenced");
        } else {
            observe_bridge("kernel.bridge_cleanup", "complete");
        }
    }

    #[cfg(windows)]
    fn revoke_agent_bridge_under_transition(
        &self,
        connection_id: &str,
        pending: &mut AgentActivationPendingState,
    ) -> Result<(), TransportError> {
        // This is the same pending-then-connections order used by result
        // admission. Removing both records while both guards are held keeps a
        // submitter from validating a live connection and then committing
        // against a ticket that profile/disconnect revocation has removed.
        let (mut connections, connections_poisoned) = match self.agent_bridge_connections.lock() {
            Ok(connections) => (connections, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        let revoked = connections.remove(connection_id);
        let removed = pending
            .entries
            .iter()
            .filter(|(_, entry)| entry.ticket.connection_id == connection_id)
            .map(|(ticket_id, _)| ticket_id.clone())
            .collect::<Vec<_>>();
        for ticket_id in &removed {
            self.persist_resultless_activation_revocation(
                pending,
                ticket_id,
                "bridge response cleanup reached a resultless terminal boundary",
            )?;
            pending.entries.remove(ticket_id);
        }
        let live_ticket_ids = pending.entries.keys().cloned().collect::<BTreeSet<_>>();
        pending
            .fifo
            .retain(|ticket_id| live_ticket_ids.contains(ticket_id));
        drop(connections);
        if let Some(mut state) = revoked {
            state.exchange.abort();
            if let Some(mut session) = state.session.take() {
                session.fence();
            }
            state.accepted_transport = None;
        }
        self.fence_host_requests_for_connection(connection_id);
        self.note_agent_bridge_peer_set_change();
        self.agent_activation_changed.notify_waiters();
        if connections_poisoned {
            Err(TransportError::SessionFenced)
        } else {
            Ok(())
        }
    }
}

/// Rebuilds the durable activation lifecycle projection and the successor
/// identities those records consume, from one coherent ORS recovery snapshot.
///
/// Every durable record must validate, must match the exact ticket it
/// retained in every identity field, and must not be a live `Pending` or
/// `Claimed` lifecycle: a live ticket is re-issued by the claim step, never
/// restored from a previous incarnation. Each ticket identity may appear at
/// most once, and a record naming a successor ticket marks that predecessor
/// as already consumed so it can never be re-bound.
#[cfg(windows)]
fn rehydrate_activation_lifecycles(
    durable_lifecycles: Vec<eliot_ors::ActivationLifecycleRecord>,
) -> Result<(BTreeMap<String, AgentActivationLifecycle>, BTreeSet<String>), KernelBuildError> {
    let mut lifecycle = BTreeMap::new();
    let mut successor_consumed = BTreeSet::new();
    for durable in durable_lifecycles {
        if durable.successor_ticket_id.is_some() {
            successor_consumed.insert(durable.ticket_id.clone());
        }
        durable.validate().map_err(|_| {
            KernelBuildError::Ors("activation lifecycle record is invalid".to_owned())
        })?;
        let ticket: AgentActivationResolutionTicket = serde_json::from_str(&durable.ticket_payload)
            .map_err(|_| {
                KernelBuildError::Ors("activation lifecycle ticket payload is invalid".to_owned())
            })?;
        ticket.validate().map_err(|_| {
            KernelBuildError::Ors("activation lifecycle ticket validation failed".to_owned())
        })?;
        let ticket_json = serde_json::to_string(&ticket).map_err(|_| {
            KernelBuildError::Ors("activation lifecycle ticket encoding failed".to_owned())
        })?;
        let fence_digest = sha256_json(&ticket.state_fence).map_err(|_| {
            KernelBuildError::Ors("activation lifecycle fence digest failed".to_owned())
        })?;
        let ticket_successor =
            ticket
                .successor_of
                .as_ref()
                .map(|successor| eliot_ors::ActivationSuccessorBinding {
                    predecessor_ticket_id: successor.predecessor_ticket_id.clone(),
                    predecessor_ticket_sha256: successor.predecessor_ticket_sha256.clone(),
                    predecessor_result_sha256: successor.predecessor_result_sha256.clone(),
                    dependency_ref: successor.dependency_ref.clone(),
                    observed_dependency_revision: successor.observed_dependency_revision.clone(),
                    not_before_unix_ms: successor.not_before_unix_ms,
                });
        if durable.ticket_id != ticket.ticket_id
            || durable.ticket_sha256 != ticket.ticket_sha256
            || durable.activation_request_id != ticket.activation_request_id.as_str()
            || durable.activation_request_sha256 != ticket.activation_request_sha256
            || durable.connection_id != ticket.connection_id
            || durable.state_fence != fence_digest
            || durable.kernel_deadline_unix_ms != ticket.kernel_deadline_unix_ms
            || durable.cancellation_id != ticket.cancellation_id
            || durable.ticket_payload != ticket_json
            || durable.successor_of != ticket_successor
            || matches!(
                durable.state,
                eliot_ors::ActivationLifecycleState::Pending
                    | eliot_ors::ActivationLifecycleState::Claimed
            )
        {
            return Err(KernelBuildError::Ors(
                "activation lifecycle identity validation failed".to_owned(),
            ));
        }
        if lifecycle
            .insert(
                durable.ticket_id.clone(),
                AgentActivationLifecycle::from(durable.state),
            )
            .is_some()
        {
            return Err(KernelBuildError::Ors(
                "activation lifecycle ticket identity is duplicated".to_owned(),
            ));
        }
    }
    Ok((lifecycle, successor_consumed))
}

/// Rebuilds the durable activation result retention projection against the
/// already-restored lifecycle projection.
///
/// A retained result is admitted only when its retention order is unique, the
/// record matches the exact ticket and result it retained, its retention phase
/// agrees with the result's own disposition, and the restored lifecycle phase
/// for that same ticket already agrees with the retention phase. Reading
/// `lifecycle` is what makes an orphaned or cross-phase result fail closed
/// instead of being rehydrated on its own.
#[cfg(windows)]
fn rehydrate_activation_results(
    durable_results: Vec<eliot_ors::ActivationResultRetentionRecord>,
    lifecycle: &BTreeMap<String, AgentActivationLifecycle>,
) -> Result<BTreeMap<String, AgentActivationResultRecord>, KernelBuildError> {
    let mut results = BTreeMap::new();
    let mut retention_orders = BTreeSet::new();
    for retained in durable_results {
        if !retention_orders.insert(retained.retention_order) {
            return Err(KernelBuildError::Ors(
                "activation result retention order is not unique".to_owned(),
            ));
        }
        let (ticket_id, record) = rehydrate_one_activation_result(retained, lifecycle)?;
        if results.insert(ticket_id, record).is_some() {
            return Err(KernelBuildError::Ors(
                "activation result retention ticket identity is duplicated".to_owned(),
            ));
        }
    }
    Ok(results)
}

/// Validates exactly one retained activation result record and returns the
/// projection Kernel publishes for it, keyed by the ticket identity the
/// record itself retained.
#[cfg(windows)]
fn rehydrate_one_activation_result(
    retained: eliot_ors::ActivationResultRetentionRecord,
    lifecycle: &BTreeMap<String, AgentActivationLifecycle>,
) -> Result<(String, AgentActivationResultRecord), KernelBuildError> {
    retained.validate().map_err(|_| {
        KernelBuildError::Ors("activation result retention record is invalid".to_owned())
    })?;
    let ticket: AgentActivationResolutionTicket = serde_json::from_str(&retained.ticket_payload)
        .map_err(|_| {
            KernelBuildError::Ors("activation result ticket payload is invalid".to_owned())
        })?;
    let result: AgentActivationResolutionResult = serde_json::from_str(&retained.result_payload)
        .map_err(|_| KernelBuildError::Ors("activation result payload is invalid".to_owned()))?;
    ticket.validate().map_err(|_| {
        KernelBuildError::Ors("activation result ticket validation failed".to_owned())
    })?;
    result.validate_against(&ticket).map_err(|_| {
        KernelBuildError::Ors("activation result binding validation failed".to_owned())
    })?;
    let ticket_json = serde_json::to_string(&ticket).map_err(|_| {
        KernelBuildError::Ors("activation result ticket encoding failed".to_owned())
    })?;
    let result_json = serde_json::to_string(&result)
        .map_err(|_| KernelBuildError::Ors("activation result encoding failed".to_owned()))?;
    let fence_digest = sha256_json(&ticket.state_fence)
        .map_err(|_| KernelBuildError::Ors("activation result fence digest failed".to_owned()))?;
    let phase_matches = match retained.phase {
        eliot_ors::ActivationResultRetentionPhase::AcceptedTerminal => !matches!(
            &result.disposition,
            AgentActivationResolutionDisposition::NotReady { .. }
        ),
        eliot_ors::ActivationResultRetentionPhase::DeferredNotReady => matches!(
            &result.disposition,
            AgentActivationResolutionDisposition::NotReady { .. }
        ),
    };
    let lifecycle_matches = matches!(
        (lifecycle.get(&ticket.ticket_id), retained.phase),
        (
            Some(AgentActivationLifecycle::Accepted),
            eliot_ors::ActivationResultRetentionPhase::AcceptedTerminal
        ) | (
            Some(AgentActivationLifecycle::DeferredNotReady),
            eliot_ors::ActivationResultRetentionPhase::DeferredNotReady
        )
    );
    if retained.ticket_id != ticket.ticket_id
        || retained.ticket_sha256 != ticket.ticket_sha256
        || retained.result_sha256 != result.result_sha256
        || retained.connection_id != ticket.connection_id
        || retained.state_fence != fence_digest
        || retained.ticket_payload != ticket_json
        || retained.result_payload != result_json
        || !phase_matches
        || !lifecycle_matches
    {
        return Err(KernelBuildError::Ors(
            "activation result retention identity validation failed".to_owned(),
        ));
    }
    Ok((
        ticket.ticket_id.clone(),
        AgentActivationResultRecord {
            result,
            demand_id: ticket.demand_id.clone(),
            phase: match retained.phase {
                eliot_ors::ActivationResultRetentionPhase::AcceptedTerminal => {
                    AgentActivationResultPhase::AcceptedTerminal
                }
                eliot_ors::ActivationResultRetentionPhase::DeferredNotReady => {
                    AgentActivationResultPhase::DeferredNotReady
                }
            },
            retention_order: retained.retention_order,
        },
    ))
}
