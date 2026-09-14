//! Kernel frame dispatch gateway.
//!
//! Closed semantic gateway owned by [`crate::KernelComposition::dispatch_frame`].
//! Validates session/frame identity, fences poisoned generations, and routes
//! heartbeat / daemon / process / Doctor (P-07) frames without fabricating
//! execution outcomes.
//!
//! Architecture: A12.2 Principal, Session и visibility; A12.3 Один governed write path; A13.2 Kernel и failure domains; ARCH-AUTH-01; ARCH-SEC-02
//! Implementation: I1.2 Обязательные процессы первого полного runtime; I1.8 Exact ownership and call paths; I7.2 Frame; I7.14 Session lifecycle; I14.6 Durable work, admission and execution axes; I15.2 Principal and Session binding
//! Forbidden authority: must not fabricate execution success, must not accept peer-owned shutdown authority, must not bypass `ServerHandshakePolicy`, generation poison, or state-fence compatibility.
//! Ordinary module: I2.23 Capability-family topology and crate extraction decisions — ordinary single-file extraction (<10k LOC) owning only `KernelComposition::dispatch_frame` plus inseparable dispatch-only helpers with zero external users.

use super::front_door_session::DOCTOR_MODULE_ID;
use super::native_worker_lifecycle_route::is_native_worker_operation;
use super::{
    ACTIVE_DAEMON_CALLER, DOCTOR_REPAIR_WIRE_ID, DoctorAdmissionContext,
    DoctorRepairAttemptRequest, Frame, FrameKind, KernelComposition, KernelFrameAction,
    KernelServiceState, MessageType, ProcessExecutionRequest, ProtocolPayload, Session,
    TransportError, caller_binding, probe_ready_state_admitted, route_doctor_repair, status_frame,
    unix_ms,
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
        if !session.accepts(&session.authority_epoch, session.session_epoch)
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
                        | "agent_activation_reconcile"
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
            let payload = match &frame.payload {
                ProtocolPayload::Json(payload) => payload.clone(),
                _ => return Err(TransportError::SessionFenced),
            };
            let native_operation = payload
                .get("operation")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if is_native_worker_operation(native_operation) {
                // Native-worker lifecycle operations delegate to the Wave-C
                // route file. Ready-gating and peer authentication mirror the
                // Process gate below; per-operation fence checks, exact
                // generation/binding validation, and persist-before-ack live
                // in the route. Unknown or stale generations fence the
                // session there and are never granted authority.
                if self
                    .service_state()
                    .map_err(|_| TransportError::SessionFenced)?
                    != KernelServiceState::Ready
                {
                    return Err(TransportError::SessionFenced);
                }
                session
                    .peer
                    .validate()
                    .map_err(|_| TransportError::PeerIdentityUnavailable)?;
                if frame.request_id.is_none() || frame.request_identity.is_none() {
                    return Err(TransportError::SessionFenced);
                }
                return self.dispatch_native_worker_frame(session, frame);
            }
            if super::native_worker_replay_route::is_native_worker_replay_operation(
                native_operation,
            ) {
                // Native-worker durable-replay operations (T9-03) delegate to
                // the replay route file. Same Ready-gating and peer
                // authentication as the lifecycle branch; per-operation
                // admission (T9-02 gate revalidation + wire admit) and
                // persist-before-ack live in the route. Stale bindings fence
                // the session there and are never granted authority.
                if self
                    .service_state()
                    .map_err(|_| TransportError::SessionFenced)?
                    != KernelServiceState::Ready
                {
                    return Err(TransportError::SessionFenced);
                }
                session
                    .peer
                    .validate()
                    .map_err(|_| TransportError::PeerIdentityUnavailable)?;
                if frame.request_id.is_none() || frame.request_identity.is_none() {
                    return Err(TransportError::SessionFenced);
                }
                return self.dispatch_native_worker_replay_frame(session, frame);
            }
            if super::provider_capability_route::is_provider_capability_operation(native_operation)
            {
                // Provider-capability verification (T9-04) delegates to the
                // capability route file. Same Ready-gating and peer
                // authentication as the lifecycle/replay branches; per-call
                // session authentication, the ORS claim lookup, the fresh
                // live-epoch query, and the owner delegation live in the
                // route. Stale bindings fence the session there and are never
                // granted authority.
                if self
                    .service_state()
                    .map_err(|_| TransportError::SessionFenced)?
                    != KernelServiceState::Ready
                {
                    return Err(TransportError::SessionFenced);
                }
                session
                    .peer
                    .validate()
                    .map_err(|_| TransportError::PeerIdentityUnavailable)?;
                if frame.request_id.is_none() || frame.request_identity.is_none() {
                    return Err(TransportError::SessionFenced);
                }
                return self.dispatch_provider_capability_frame(session, frame);
            }
            #[cfg(windows)]
            if super::host_request_route::is_host_request_operation(native_operation) {
                // P-04 admitted host-request envelopes ride the same admitted
                // transport through this closed gateway. `Ready` admits every
                // kind, while `Degraded` still routes Cancellation, Status,
                // and Reconciliation through the exact per-kind service gate
                // inside the admit path. Peer, correlation, and fence joins
                // mirror the native-worker gate above; envelope
                // digest/connection/generation joins live in the route. Off
                // Windows the payload falls through to the typed process
                // operation below, which rejects the unknown operation and
                // fences.
                if !matches!(
                    self.service_state()
                        .map_err(|_| TransportError::SessionFenced)?,
                    KernelServiceState::Ready | KernelServiceState::Degraded
                ) {
                    return Err(TransportError::SessionFenced);
                }
                session
                    .peer
                    .validate()
                    .map_err(|_| TransportError::PeerIdentityUnavailable)?;
                if frame.request_id.is_none() || frame.request_identity.is_none() {
                    return Err(TransportError::SessionFenced);
                }
                return self.dispatch_host_request_frame(session, frame);
            }
            if is_doctor_operation(native_operation) {
                // P-07 Doctor repair-attempt intake rides the same admitted
                // transport through this closed gateway. New-effect intake
                // (`Request`/`Execute`) requires `Ready`; control frames
                // (`Cancel`/`Cancel`) additionally route while `Degraded`, so
                // a blanket `Ready` gate never destroys cancel/reconcile
                // recovery capability (host-request `Ready|Degraded` pattern
                // above). Peer, correlation, and fence joins mirror the
                // host-request gate; wire/shape/digest joins live in
                // `dispatch_doctor_frame`. Stale or unauthenticated sessions
                // fence here and are never granted protected input.
                let control =
                    frame.kind == FrameKind::Cancel && frame.message_type == MessageType::Cancel;
                if control {
                    if !matches!(
                        self.service_state()
                            .map_err(|_| TransportError::SessionFenced)?,
                        KernelServiceState::Ready | KernelServiceState::Degraded
                    ) {
                        return Err(TransportError::SessionFenced);
                    }
                } else {
                    if frame.kind != FrameKind::Request
                        || frame.message_type != MessageType::Execute
                    {
                        return Err(TransportError::SessionFenced);
                    }
                    if self
                        .service_state()
                        .map_err(|_| TransportError::SessionFenced)?
                        != KernelServiceState::Ready
                    {
                        return Err(TransportError::SessionFenced);
                    }
                }
                session
                    .peer
                    .validate()
                    .map_err(|_| TransportError::PeerIdentityUnavailable)?;
                if frame.request_id.is_none() || frame.request_identity.is_none() {
                    return Err(TransportError::SessionFenced);
                }
                return self.dispatch_doctor_frame(session, frame);
            }
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
                    || !identity
                        .request
                        .state_fence
                        .authority_epoch
                        .is_same_authority(admission.state_fence().authority_epoch())
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

/// Returns whether the operation string selects the P-07 Doctor repair route.
///
/// The operation string is the stable wire identity itself
/// (`DOCTOR_REPAIR_WIRE_ID`); there is no second dispatch vocabulary and no
/// generic JSON command routing. Callers must still prove the exact
/// (`wire_id`, `wire_version`) pair through `route_doctor_repair` on the
/// decoded typed request: the operation string only selects this closed entry.
///
/// INTEGRATOR (Slice A): if `doctor_front_door.rs` introduces kind-suffixed
/// operation names (submit/cancel/reconcile/rehydrate), extend this predicate
/// there and rewire the call in `dispatch_frame` above; keep the exact
/// `route_doctor_repair` wire check in `dispatch_doctor_frame` as authority.
pub(crate) fn is_doctor_operation(operation: &str) -> bool {
    operation == DOCTOR_REPAIR_WIRE_ID
}

impl KernelComposition {
    /// Dispatches one Doctor repair-attempt frame from an admitted session.
    ///
    /// The caller ([`KernelComposition::dispatch_frame`]) has already run the
    /// closed-gateway gates (generation poison, session/frame identity,
    /// daemon-session currency) and the per-kind service gate (new-effect
    /// intake requires `Ready`, control additionally routes while `Degraded`);
    /// those joins are re-checked here so direct callers cannot bypass them.
    /// The frame must ride the presenting session's connection, the operation
    /// string must be the exact Doctor wire identity, and the payload must
    /// carry the typed [`DoctorRepairAttemptRequest`] under `request` with a
    /// valid shape, canonical digest, and exact wire version. The validated
    /// request is forwarded as [`KernelFrameAction::Doctor`]; ledger-bound
    /// admission itself runs in [`KernelComposition::execute_doctor_request`].
    /// Unknown operations and mismatched joins fence; nothing is retried
    /// blindly and no admission is fabricated here.
    pub(crate) fn dispatch_doctor_frame(
        &self,
        session: &Session,
        frame: &Frame,
    ) -> Result<KernelFrameAction, TransportError> {
        let control = frame.kind == FrameKind::Cancel && frame.message_type == MessageType::Cancel;
        if control {
            if !matches!(
                self.service_state()
                    .map_err(|_| TransportError::SessionFenced)?,
                KernelServiceState::Ready | KernelServiceState::Degraded
            ) {
                return Err(TransportError::SessionFenced);
            }
        } else {
            if frame.kind != FrameKind::Request || frame.message_type != MessageType::Execute {
                return Err(TransportError::SessionFenced);
            }
            if self
                .service_state()
                .map_err(|_| TransportError::SessionFenced)?
                != KernelServiceState::Ready
            {
                return Err(TransportError::SessionFenced);
            }
        }
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let request_id = frame
            .request_id
            .clone()
            .ok_or(TransportError::SessionFenced)?;
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
        if frame.connection_id != session.connection_id {
            return Err(TransportError::SessionFenced);
        }
        let payload = match &frame.payload {
            ProtocolPayload::Json(payload) => payload.clone(),
            _ => return Err(TransportError::SessionFenced),
        };
        let operation = payload
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .ok_or(TransportError::SessionFenced)?;
        if !is_doctor_operation(operation) {
            return Err(TransportError::SessionFenced);
        }
        let request = doctor_request_from_payload(&payload)?;
        if operation != request.wire_id
            || !route_doctor_repair(&request.wire_id, request.wire_version)
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(KernelFrameAction::Doctor {
            request_id,
            operation: operation.to_owned(),
            payload,
        })
    }

    /// Executes one validated Doctor repair-attempt operation (T6-D2 P-07).
    ///
    /// Revalidates the closed operation name, the presenting session's Doctor
    /// binding, and the typed request shape/digest/wire version through the
    /// existing `doctor.rs` entries, then builds the live admission context
    /// from Kernel-owned state (service state, `KernelService` authority
    /// epoch, consumed activation generation) following the
    /// `host_request_binding` live-authority pattern. Neither the epoch nor
    /// the generation is ever taken from the request envelope.
    ///
    /// INTEGRATOR (T6-D2 B->A) — REWIRE RECORD. Attempted to replace the
    /// fail-closed tail with `eliot_kernel_service::handle_doctor_repair_attempt`
    /// (Slice A `doctor_front_door.rs`, over `admit_doctor_repair`): no
    /// production `DoctorRecoveryLedger` accessor exists in bins scope (only
    /// `TestLedger` in kernel-service tests; `RedbRecoveryStore` implements
    /// `OperationalRecoveryStore`, not the Doctor ledger), no immutable
    /// `DoctorRecipeRegistry` accessor exists, and no bootstrap-bound doctor
    /// principal accessor exists for `AuthenticatedDoctorSession::bind`.
    /// Fabricating any of them would violate authority, so admission stays
    /// fail-closed without minting, persisting, or projecting any admission.
    /// Control-frame `reconcile_doctor_repair_admission` likewise stays
    /// unavailable here: it needs a retained admission plus envelope which
    /// this frame path does not carry. No new constants, no relaxations, no
    /// silent tuple drop.
    pub async fn execute_doctor_request(
        &self,
        session: &Session,
        _request_id: super::RequestId,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<Frame, TransportError> {
        if !is_doctor_operation(operation) {
            return Err(TransportError::SessionFenced);
        }
        if session.module_generation.module_id.as_str() != DOCTOR_MODULE_ID {
            return Err(TransportError::SessionFenced);
        }
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        if !matches!(
            self.service_state()
                .map_err(|_| TransportError::SessionFenced)?,
            KernelServiceState::Ready | KernelServiceState::Degraded
        ) {
            return Err(TransportError::SessionFenced);
        }
        let request = doctor_request_from_payload(&payload)?;
        if operation != request.wire_id
            || !route_doctor_repair(&request.wire_id, request.wire_version)
        {
            return Err(TransportError::SessionFenced);
        }
        let (service_state, authority_epoch, generation) = {
            let service = self
                .service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let generation = service
                .activation_receipt()
                .ok_or(TransportError::SessionFenced)?
                .generation
                .value();
            (service.state(), service.authority_epoch(), generation)
        };
        let _context = DoctorAdmissionContext::new(service_state, authority_epoch, generation)
            .map_err(|_| TransportError::SessionFenced)?;
        let now_unix_nanos = unix_ms().saturating_mul(1_000_000);
        if now_unix_nanos == 0 {
            return Err(TransportError::SessionFenced);
        }
        // Explicit fail-closed (see rewire record above): the validated
        // context and request are retained but never admitted. No
        // `let _ = (...)` silent-drop placeholder.
        Err(TransportError::SessionFenced)
    }
}

/// Decodes the exact typed Doctor repair-attempt request from a P-07 frame
/// payload.
///
/// The payload carries the closed operation string plus the full typed request
/// under `request`; the request shape, its canonical digest, and its exact
/// wire version are re-validated through the existing `doctor.rs` entries, so
/// this is typed dispatch, not generic JSON routing.
///
/// INTEGRATOR (Slice A): if `doctor_front_door.rs` nests the request under a
/// different payload key, adjust this one decode site; the validation chain
/// below stays unchanged.
fn doctor_request_from_payload(
    payload: &serde_json::Value,
) -> Result<DoctorRepairAttemptRequest, TransportError> {
    let request_value = payload
        .get("request")
        .cloned()
        .ok_or(TransportError::SessionFenced)?;
    let request: DoctorRepairAttemptRequest =
        serde_json::from_value(request_value).map_err(|_| TransportError::SessionFenced)?;
    request
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    request
        .validate_canonical_digest()
        .map_err(|_| TransportError::SessionFenced)?;
    if !route_doctor_repair(&request.wire_id, request.wire_version) {
        return Err(TransportError::SessionFenced);
    }
    Ok(request)
}
