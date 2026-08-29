//! Kernel frame dispatch gateway.
//!
//! Closed semantic gateway owned by [`crate::KernelComposition::dispatch_frame`].
//! Validates session/frame identity, fences poisoned generations, and routes
//! heartbeat / daemon / process frames without fabricating execution outcomes.
//!
//! Architecture: A12.2 Principal, Session и visibility; A12.3 Один governed write path; A13.2 Kernel и failure domains; ARCH-AUTH-01; ARCH-SEC-02
//! Implementation: I1.2 Обязательные процессы первого полного runtime; I1.8 Exact ownership and call paths; I7.2 Frame; I7.14 Session lifecycle; I14.6 Durable work, admission and execution axes; I15.2 Principal and Session binding
//! Forbidden authority: must not fabricate execution success, must not accept peer-owned shutdown authority, must not bypass `ServerHandshakePolicy`, generation poison, or state-fence compatibility.
//! Ordinary module: I2.2 Когда capability становится отдельным crate; I2.23 Capability-family topology and crate extraction decisions — ordinary single-file extraction (<10k LOC) owning only `KernelComposition::dispatch_frame` plus inseparable dispatch-only helpers with zero external users.

use super::{
    ACTIVE_DAEMON_CALLER, Frame, FrameKind, KernelComposition, KernelFrameAction,
    KernelServiceState, MessageType, ProcessExecutionRequest, ProtocolPayload, Session,
    TransportError, caller_binding, probe_ready_state_admitted, status_frame,
};

impl KernelComposition {
    /// Runs the currently admitted, deliberately closed semantic gateway.
    ///
    /// Heartbeats are handled locally. Other validated frames, including
    /// shutdown requests, are rejected and fenced until the durable
    /// execution gateway is supplied; this boundary never fabricates
    /// execution success or accepts a peer-owned shutdown authority.
    #[allow(
        clippy::too_many_lines,
        reason = "the closed dispatch matrix keeps session, identity, and service-state gates in one auditable order"
    )]
    pub fn dispatch_frame(
        &self,
        session: &Session,
        frame: &Frame,
    ) -> Result<KernelFrameAction, TransportError> {
        if self
            .generation_poison
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .is_some()
        {
            return Err(TransportError::SessionFenced);
        }
        frame.validate()?;
        if !session.accepts(session.authority_epoch, session.session_epoch)
            || frame.connection_id != session.connection_id
            || frame.protocol_version != session.protocol_version
        {
            return Err(TransportError::SessionFenced);
        }
        #[cfg(windows)]
        self.require_current_daemon_session(session)?;
        if let Some(identity) = &frame.request_identity
            && !session
                .module_generation
                .state_fence
                .is_compatible_with(&identity.request.state_fence)
        {
            return Err(TransportError::SessionFenced);
        }

        if frame.kind == FrameKind::Heartbeat && frame.message_type == MessageType::Health {
            return Ok(KernelFrameAction::Reply(status_frame(
                session,
                FrameKind::Heartbeat,
                MessageType::Health,
                serde_json::json!({
                    "status": "OPEN",
                    "authority_epoch": session.authority_epoch,
                }),
            )?));
        }

        if frame.kind == FrameKind::Request && frame.message_type == MessageType::Execute {
            let request_id = frame
                .request_id
                .clone()
                .ok_or(TransportError::SessionFenced)?;
            let payload = match &frame.payload {
                ProtocolPayload::Json(payload) => payload.clone(),
                _ => return Err(TransportError::SessionFenced),
            };
            let operation = payload
                .get("operation")
                .and_then(serde_json::Value::as_str)
                .ok_or(TransportError::SessionFenced)?;
            if session.module_generation.module_id.as_str() == ACTIVE_DAEMON_CALLER
                && matches!(
                    operation,
                    "snapshot"
                        | "daemon_ready"
                        | "health"
                        | "daemon_degraded"
                        | "daemon_fatal"
                        | "agent_activation_claim"
                        | "agent_activation_submit"
                        | "store_recovery"
                        | "store_initialize_genesis"
                        | "apply_prepared"
                        | "receipt"
                )
            {
                if !probe_ready_state_admitted(
                    self.service_state()
                        .map_err(|_| TransportError::SessionFenced)?,
                ) {
                    return Err(TransportError::SessionFenced);
                }
                let identity = frame
                    .request_identity
                    .as_ref()
                    .ok_or(TransportError::SessionFenced)?;
                if !session
                    .module_generation
                    .state_fence
                    .is_compatible_with(&identity.request.state_fence)
                {
                    return Err(TransportError::SessionFenced);
                }
                return Ok(KernelFrameAction::Daemon {
                    request_id,
                    operation: operation.to_owned(),
                    payload,
                });
            }
        }

        if (frame.kind == FrameKind::Request && frame.message_type == MessageType::Execute)
            || (frame.kind == FrameKind::Cancel && frame.message_type == MessageType::Cancel)
        {
            if self
                .service_state()
                .map_err(|_| TransportError::SessionFenced)?
                != KernelServiceState::Ready
            {
                return Err(TransportError::SessionFenced);
            }
            let request_id = frame
                .request_id
                .clone()
                .ok_or(TransportError::SessionFenced)?;
            session
                .peer
                .validate()
                .map_err(|_| TransportError::PeerIdentityUnavailable)?;
            let payload = match &frame.payload {
                ProtocolPayload::Json(payload) => payload.clone(),
                _ => return Err(TransportError::SessionFenced),
            };
            let request: ProcessExecutionRequest =
                serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
            request
                .validate()
                .map_err(|_| TransportError::SessionFenced)?;
            let identity = frame
                .request_identity
                .as_ref()
                .ok_or(TransportError::SessionFenced)?;
            if request
                .operation_id()
                .is_none_or(|operation_id| identity.idempotency_key != operation_id.as_str())
            {
                return Err(TransportError::SessionFenced);
            }
            if let ProcessExecutionRequest::Start(admission) = &request {
                if admission.recipient_module_id() != session.module_generation.module_id.as_str() {
                    return Err(TransportError::SessionFenced);
                }
                if identity.deadline_unix_ms != admission.deadline_unix_ms()
                    || identity.request.state_fence.authority_epoch.value()
                        != admission.state_fence().authority_epoch()
                    || identity.request.state_fence.resource_generation.value()
                        != admission.state_fence().generation().get()
                {
                    return Err(TransportError::SessionFenced);
                }

                // A pipe connection is replaceable transport routing, not a
                // durable process/effect Session. Until #79 composes an exact
                // process-owner/session binding, no Start request can cross
                // this gateway. In particular, copying `connection_id` into
                // `ProcessIntent.session_id` no longer grants launch authority.
                return Err(TransportError::SessionFenced);
            }
            let (_, session_binding) = caller_binding(session)?;
            return Ok(KernelFrameAction::Process {
                request_id,
                request,
                session_binding,
            });
        }

        Ok(KernelFrameAction::Fence(
            eliot_ipc::handshake_rejection_frame(
                &session.connection_id,
                "kernel semantic gateway is closed for this session",
            )?,
        ))
    }
}
