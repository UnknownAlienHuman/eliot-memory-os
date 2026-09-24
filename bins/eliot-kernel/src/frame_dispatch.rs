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

use super::daemon_request_dispatch::DAEMON_STARTUP_EVIDENCE_OPERATION;
use super::dreamer_job_dispatch::is_dreamer_operation;
use super::front_door_session::{DOCTOR_MODULE_ID, TESTD_MODULE_ID};
use super::generation_control::ACTIVE_GENERATION_REGISTRY_QUERY_OPERATION;
use super::native_worker_lifecycle_route::is_native_worker_operation;
use super::wasm_runtime_port_grant::{
    HandlerSession, HostBinaryFacts, KernelObservedGrantFacts, WASM_GRANT_REQUEST_WIRE_ID,
    WASM_GRANT_REQUEST_WIRE_VERSION, WASM_PORT_GRANT_OPERATION, WasmGrantRequest,
    handle_wasm_port_grant,
};
use super::{
    ACTIVE_DAEMON_CALLER, DOCTOR_REPAIR_WIRE_ID, DoctorRepairAttemptRequest, Frame, FrameKind,
    KernelComposition, KernelFrameAction, KernelServiceState, MessageType, PeerIdentity,
    ProcessExecutionRequest, ProtocolPayload, Session, TESTD_ADMISSION_WIRE_ID,
    TestdAdmissionAttemptRequest, TransportError, caller_binding, probe_ready_state_admitted,
    route_doctor_repair, route_testd_admission, status_frame, unix_ms,
};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_kernel_core::{
    CapabilityReadiness, CompatibilityEnvelope, DurableCompatibilityState, HealthDimensionKind,
    KernelRuntimeHealthEvidence, NormativePairReceipt, ProcessHealthStatus, ProcessHealthVector,
    StateMigrationClass, VersionRange, admit_handshake, expected_seal_tag,
};
use eliot_research_exchange_api::{
    ResearchDispatchRequest, ResearchReconcileRequest, RESEARCH_DISPATCH_WIRE_ID,
    RESEARCH_RECONCILE_OPERATION,
};
use eliot_runtime_contracts::{GenerationCutoverState, HealthDimension};
#[cfg(windows)]
use eliot_runtime_contracts::{LeaseState, SupervisionLeaseVerifier};

const RUNTIME_HEALTH_CAPABILITY: &str = "worker.execute";
const RUNTIME_HEALTH_ROUTE_SCOPE: &str = "daemon";

/// Computes the I1.12 contract-set digest from the live contract identities.
///
/// The tuple order is the wire order for this producer. It is deliberately
/// made from contract shapes rather than artifact/configuration material, so a
/// successful digest proves the same public surfaces were admitted on both
/// sides of the carrier.
fn runtime_contract_set_digest() -> Result<String, TransportError> {
    let identities = (
        eliot_kernel_core::contract_identity().map_err(|_| TransportError::SessionFenced)?,
        eliot_kernel_service::contract_identity().map_err(|_| TransportError::SessionFenced)?,
        eliot_protocol::protocol_contract_identity().map_err(|_| TransportError::SessionFenced)?,
        eliot_runtime_contracts::contract_identity().map_err(|_| TransportError::SessionFenced)?,
    );
    let bytes = canonical_json_bytes(&identities).map_err(|_| TransportError::SessionFenced)?;
    Ok(sha256_hex(&bytes))
}

/// Runs the Kernel-owned compatibility admission for one authenticated
/// generation/epoch. The protocol and canonical-format revisions are the
/// current I1.12 handshake revisions; the contract-set digest is derived
/// above from the four public owners rather than from a binary or config hash.
fn runtime_compatibility_evidence(
    generation: eliot_contracts::ResourceGeneration,
    authority_epoch: &eliot_contracts::EpochId,
) -> Result<eliot_kernel_core::AcceptedCompatibilityEvidence, TransportError> {
    let protocol_range = VersionRange::new(1, 1).map_err(|_| TransportError::SessionFenced)?;
    let canonical_format_range =
        VersionRange::new(1, 1).map_err(|_| TransportError::SessionFenced)?;
    let contract_set_digest = runtime_contract_set_digest()?;
    let architecture_source_digest = eliot_kernel_core::CURRENT_ARCHITECTURE_SOURCE_DIGEST;
    let normative_receipt = NormativePairReceipt::new(
        architecture_source_digest,
        expected_seal_tag(architecture_source_digest),
    )
    .map_err(|_| TransportError::SessionFenced)?;
    let candidate = CompatibilityEnvelope::new(
        protocol_range,
        contract_set_digest.clone(),
        canonical_format_range,
        architecture_source_digest,
        normative_receipt,
        generation,
        authority_epoch.clone(),
        vec![RUNTIME_HEALTH_CAPABILITY.to_owned()],
        Vec::new(),
        StateMigrationClass::NoMigration,
    )
    .map_err(|_| TransportError::SessionFenced)?;
    let durable = DurableCompatibilityState::new(
        protocol_range,
        contract_set_digest,
        canonical_format_range,
        architecture_source_digest,
        authority_epoch.clone(),
        vec![RUNTIME_HEALTH_CAPABILITY.to_owned()],
        StateMigrationClass::NoMigration,
    )
    .map_err(|_| TransportError::SessionFenced)?;
    admit_handshake(&candidate, &durable).map_err(|_| TransportError::SessionFenced)
}

fn observe_frame(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "frame dispatch observation"
    );
}

fn frame_terminal_code(error: &TransportError) -> &'static str {
    match error {
        TransportError::SessionFenced => "frame_fenced",
        TransportError::PeerIdentityUnavailable => "frame_peer_unavailable",
        TransportError::Timeout => "frame_timeout",
        TransportError::UnknownRequest => "frame_unknown_request",
        TransportError::UnknownOutcome => "frame_unknown_outcome",
        TransportError::IdentityConflict => "frame_identity_conflict",
        TransportError::Cancelled => "frame_cancelled",
        TransportError::Backpressure => "frame_backpressure",
        TransportError::InvalidLimits => "frame_invalid_limits",
        TransportError::UnauthenticatedPeer => "frame_unauthenticated_peer",
        TransportError::InvalidPipeName => "frame_invalid_pipe",
        TransportError::RegistryFull => "frame_registry_full",
        TransportError::Io(_) => "frame_io",
        TransportError::PlanGap { .. } => "frame_plan_gap",
        TransportError::Protocol(_) => "frame_protocol",
    }
}

impl KernelComposition {
    /// Projects one authenticated runtime-health carrier from the live Kernel
    /// owners. Every receipt is read and validated before it reaches the
    /// transport; the session is only used to bind the projection to the
    /// server policy's current generation and exact authority epoch.
    fn runtime_health_payload(
        &self,
        session: &Session,
    ) -> Result<serde_json::Value, TransportError> {
        let policy_generation = {
            let policy = self
                .front_door_policy
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let generation = policy.module_generation.clone();
            if session.module_generation.generation != generation.generation
                || session.module_generation.artifact_id != generation.artifact_id
                || session.module_generation.state_fence != generation.state_fence
                || !session
                    .authority_epoch
                    .is_same_authority(&generation.state_fence.authority_epoch)
            {
                return Err(TransportError::SessionFenced);
            }
            generation
        };
        let evidence = self.runtime_health_evidence_from_policy_generation(policy_generation)?;
        serde_json::to_value(evidence).map_err(|_| TransportError::SessionFenced)
    }

    /// Produces the same owner-authenticated carrier for the Host control
    /// lane. The request boundary has already authenticated the peer and
    /// candidate; this method rebinds the requested generation and epoch to
    /// the current front-door policy before reading the Kernel-owned receipts.
    pub(super) fn runtime_health_evidence_for_control(
        &self,
        module_generation: eliot_contracts::ResourceGeneration,
        authority_epoch: &eliot_contracts::EpochId,
    ) -> Result<KernelRuntimeHealthEvidence, TransportError> {
        let policy_generation = {
            let policy = self
                .front_door_policy
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            if policy.module_generation.generation != module_generation
                || !policy
                    .module_generation
                    .state_fence
                    .authority_epoch
                    .is_same_authority(authority_epoch)
            {
                return Err(TransportError::SessionFenced);
            }
            policy.module_generation.clone()
        };
        self.runtime_health_evidence_from_policy_generation(policy_generation)
    }

    fn runtime_health_evidence_from_policy_generation(
        &self,
        policy_generation: eliot_runtime_contracts::ModuleGeneration,
    ) -> Result<KernelRuntimeHealthEvidence, TransportError> {
        policy_generation
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;

        let (candidate, activation, ready) = {
            let service = self
                .service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            if service.state() != KernelServiceState::Ready {
                return Err(TransportError::SessionFenced);
            }
            let candidate = service
                .candidate_binding()
                .cloned()
                .ok_or(TransportError::SessionFenced)?;
            let activation = service
                .activation_receipt()
                .cloned()
                .ok_or(TransportError::SessionFenced)?;
            let ready = service
                .ready_receipt()
                .cloned()
                .ok_or(TransportError::SessionFenced)?;
            (candidate, activation, ready)
        };

        candidate
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if !candidate
            .kernel_epoch
            .is_same_authority(&policy_generation.state_fence.authority_epoch)
            || !activation
                .authority_epoch
                .is_same_authority(&policy_generation.state_fence.authority_epoch)
            || activation.generation != policy_generation.generation
        {
            return Err(TransportError::SessionFenced);
        }
        ready
            .validate(&candidate, &activation)
            .map_err(|_| TransportError::SessionFenced)?;
        // The receipt carries both the process observation and Kernel health.
        // They must agree before the producer collapses them into the one
        // canonical six-dimensional health vector.
        if ready.process.health != ready.health {
            return Err(TransportError::SessionFenced);
        }

        let compatibility = runtime_compatibility_evidence(
            policy_generation.generation,
            &policy_generation.state_fence.authority_epoch,
        )?;
        let cutover_state = self.runtime_cutover_state(
            policy_generation.generation,
            &policy_generation.state_fence.authority_epoch,
        );
        let process_health = ProcessHealthStatus::new(
            ready.process.process_id.as_str().to_owned(),
            ready.process.state,
            ProcessHealthVector::new(
                ready.process.health,
                self.runtime_supervision_coverage(&candidate, &policy_generation),
            ),
            policy_generation.state,
            cutover_state,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let capability_readiness = CapabilityReadiness::new(
            RUNTIME_HEALTH_CAPABILITY,
            vec![
                HealthDimensionKind::Liveness,
                HealthDimensionKind::Readiness,
                HealthDimensionKind::Compatibility,
                HealthDimensionKind::Integrity,
                HealthDimensionKind::Capacity,
                HealthDimensionKind::SupervisionCoverage,
            ],
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let evidence = KernelRuntimeHealthEvidence::new(
            "OPEN",
            policy_generation.state_fence.authority_epoch,
            policy_generation.generation,
            compatibility,
            eliot_kernel_core::CURRENT_NORMATIVE_PAIR_KEY,
            eliot_kernel_core::CURRENT_IMPLEMENTATION_SOURCE_DIGEST,
            process_health,
            vec![capability_readiness],
            super::dispatch_launch::doctor_repair_advertised(),
        )
        .map_err(|_| TransportError::SessionFenced)?;
        Ok(evidence)
    }

    /// Only an ORS record for this authenticated daemon generation and epoch
    /// can complete the carrier's independent cutover state. An empty, stale,
    /// unrelated, or unreadable projection remains explicitly Preparing.
    fn runtime_cutover_state(
        &self,
        generation: eliot_contracts::ResourceGeneration,
        authority_epoch: &eliot_contracts::EpochId,
    ) -> GenerationCutoverState {
        let Ok(cutovers) = self
            .generation_gateway
            .ors
            .latest_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
        else {
            return GenerationCutoverState::Preparing;
        };
        if cutovers.iter().any(|snapshot| {
            let record = snapshot.record();
            record.route_scope == RUNTIME_HEALTH_ROUTE_SCOPE
                && record.state == GenerationCutoverState::Committed
                && record.new_generation == generation
                && record.new_epoch.value() == authority_epoch.sequence.get()
        }) {
            GenerationCutoverState::Completed
        } else {
            GenerationCutoverState::Preparing
        }
    }

    /// Reads the current signed supervision lease when the Windows authority
    /// is composed. Missing or stale supervision is represented as Unknown;
    /// the worker capability explicitly requires this dimension, so it cannot
    /// turn an absent watchdog proof into admission.
    fn runtime_supervision_coverage(
        &self,
        candidate: &eliot_kernel_service::HostKernelCandidateBinding,
        generation: &eliot_runtime_contracts::ModuleGeneration,
    ) -> HealthDimension {
        #[cfg(not(windows))]
        {
            let _ = (candidate, generation);
            return HealthDimension::Unknown;
        }

        #[cfg(windows)]
        {
            let Some(authority) = self.supervision_lease_authority.as_ref() else {
                return HealthDimension::Unknown;
            };
            let lease_id = candidate
                .supervision_incarnation
                .supervision_lease_id
                .as_str();
            let Ok(Some(snapshot)) = authority.current_snapshot(lease_id) else {
                return HealthDimension::Unknown;
            };
            if snapshot.validate().is_err()
                || snapshot.record.lease_id.as_str() != lease_id
                || snapshot.record.state != LeaseState::Active
                || snapshot.record.projection != eliot_ors::SupervisionLeaseProjection::Active
            {
                return HealthDimension::Unknown;
            }
            let Ok(context) = snapshot.active_verification_context(
                authority.trust_anchor().public_key_fingerprint(),
                super::unix_ms(),
            ) else {
                return HealthDimension::Unknown;
            };
            if authority
                .trust_anchor()
                .verify(&snapshot.record.artifact, &context)
                .is_err()
            {
                return HealthDimension::Unknown;
            }
            let binding = &snapshot.record.binding;
            let Ok(expected_scope_ref) = candidate.supervision_incarnation.derived_scope_ref()
            else {
                return HealthDimension::Unknown;
            };
            if binding.scope_ref.as_str() != expected_scope_ref
                || binding.observation_scope != candidate.supervision_incarnation.observation_scope
                || binding.wake_policy != candidate.supervision_incarnation.wake_policy
                || binding.installation_id.as_str() != candidate.installation_id.as_str()
                || binding.host_epoch.value() != candidate.host_epoch.value()
                || binding.activation_id.as_str() != candidate.activation_id.as_str()
                || binding.activation_generation != generation.generation
                || !binding
                    .kernel_epoch
                    .is_same_authority(&generation.state_fence.authority_epoch)
                || binding.watchdog_epoch.value()
                    != candidate.supervision_incarnation.watchdog_epoch.sequence
                || binding.state_fence != generation.state_fence
                || binding.generation_binding.target_id != generation.artifact_id.as_str()
                || binding.generation_binding.target_generation != generation.generation
                || binding.generation_binding.module_id != generation.module_id.as_str()
                || binding.generation_binding.module_generation != generation.generation
                || binding.generation_binding.process_generation != generation.generation
                || binding.generation_binding.process_id.trim().is_empty()
            {
                return HealthDimension::Unknown;
            }
            HealthDimension::Healthy
        }
    }

    /// Runs the currently admitted, deliberately closed semantic gateway.
    ///
    /// Heartbeats are handled locally. Other validated frames, including
    /// shutdown requests, are rejected and fenced until the durable
    /// execution gateway is supplied; this boundary never fabricates
    /// execution success or accepts a peer-owned shutdown authority.
    ///
    /// Diagnostic wrapper: received/validated/admitted/dispatched stay
    /// distinct, decode uses only trusted identities, and exactly one
    /// terminal is emitted per failed dispatch. Subordinate route helpers
    /// emit info only.
    pub fn dispatch_frame(
        &self,
        session: &Session,
        frame: &Frame,
    ) -> Result<KernelFrameAction, TransportError> {
        observe_frame("kernel.frame_received", "attempt");
        let result = self.dispatch_frame_inner(session, frame);
        match &result {
            Ok(action) => {
                let outcome = match action {
                    KernelFrameAction::Reply(_) => "replied",
                    KernelFrameAction::Daemon { .. } => "daemon_admitted",
                    KernelFrameAction::Process { .. } => "process_admitted",
                    KernelFrameAction::Doctor { .. } => "doctor_admitted",
                    KernelFrameAction::Testd { .. } => "testd_admitted",
                    KernelFrameAction::Dreamer { .. } => "dreamer_admitted",
                    KernelFrameAction::Research { .. } => "research_admitted",
                    KernelFrameAction::Fence(_) => "fenced_reply",
                };
                observe_frame("kernel.frame_validated", "success");
                observe_frame("kernel.frame_admitted", "success");
                observe_frame("kernel.frame_dispatched", outcome);
            }
            Err(error) => {
                observe_frame("kernel.frame_decode_reject", "fenced");
                super::kernel_diagnostics::observe_terminal_error(frame_terminal_code(error));
            }
        }
        result
    }

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
    fn dispatch_frame_inner(
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
            let payload = self.runtime_health_payload(session)?;
            return Ok(KernelFrameAction::Reply(status_frame(
                session,
                FrameKind::Heartbeat,
                MessageType::Health,
                payload,
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
                && is_daemon_operation(operation)
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
            #[cfg(windows)]
            if is_wasm_port_grant_operation(native_operation) {
                // #1780 D3 WASM port-grant issuance rides the same admitted
                // bridge transport as the host-request route above. Issuance
                // is new-effect intake (`Request`/`Execute`) and requires
                // `Ready`; there is no control kind. Peer, correlation, and
                // fence joins mirror the host-request gate; the live
                // HostRequest admission, the session/Kernel/host fact
                // threading, and the pure `handle_wasm_port_grant` call live
                // in `dispatch_wasm_port_grant_frame`. Stale or
                // unauthenticated sessions fence here and are never granted
                // protected input.
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
                session
                    .peer
                    .validate()
                    .map_err(|_| TransportError::PeerIdentityUnavailable)?;
                if frame.request_id.is_none() || frame.request_identity.is_none() {
                    return Err(TransportError::SessionFenced);
                }
                return self.dispatch_wasm_port_grant_frame(session, frame);
            }
            if is_research_operation(native_operation) {
                let control = frame.kind == FrameKind::Cancel
                    && frame.message_type == MessageType::Cancel;
                if session.module_generation.module_id.as_str() != ACTIVE_DAEMON_CALLER
                    || (!control
                        && !matches!(
                            self.service_state()
                                .map_err(|_| TransportError::SessionFenced)?,
                            KernelServiceState::Ready
                        ))
                    || (control
                        && !matches!(
                            self.service_state()
                                .map_err(|_| TransportError::SessionFenced)?,
                            KernelServiceState::Ready | KernelServiceState::Degraded
                        ))
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
                return self.dispatch_research_frame(session, frame);
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
            if is_testd_operation(native_operation) {
                // P-07 testd admission intake rides the same admitted
                // transport through this closed gateway. New-execution intake
                // (`Request`/`Execute`) requires `Ready`; control frames
                // (`Cancel`/`Cancel`) additionally route while `Degraded`, so
                // a blanket `Ready` gate never destroys cancel/reconcile
                // recovery capability (host-request `Ready|Degraded` pattern
                // above). Peer, correlation, and fence joins mirror the
                // host-request gate; wire/shape/digest joins live in
                // `dispatch_testd_frame`. Stale or unauthenticated sessions
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
                return self.dispatch_testd_frame(session, frame);
            }
            if is_dreamer_operation(native_operation) {
                // T12-05 K2 Dreamer requester routing rides the same admitted
                // transport through this closed gateway. Intake
                // (`Request`/`Execute`) requires `Ready`; peer, correlation,
                // and fence joins mirror the testd gate above; envelope,
                // role, and fence joins live in `dispatch_dreamer_frame`.
                // Stale or unauthenticated sessions fence here and are never
                // granted protected input. No process is spawned on this
                // path (worker handoff is T12-09).
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
                session
                    .peer
                    .validate()
                    .map_err(|_| TransportError::PeerIdentityUnavailable)?;
                if frame.request_id.is_none() || frame.request_identity.is_none() {
                    return Err(TransportError::SessionFenced);
                }
                return self.dispatch_dreamer_frame(session, frame);
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
                // durable process/effect Session. A Start crosses this gateway
                // only when `intent.session_id` validates against the
                // server-derived admitted process-owner/session binding
                // (issue #79): copying `connection_id` into
                // `ProcessIntent.session_id` never grants launch authority,
                // and anything not admitted/validated stays
                // `SessionFenced` fail-closed below.
                let caller = self.admitted_process_caller_session(session)?;
                eliot_process::validate_process_intent_session(
                    admission.intent(),
                    &caller,
                    caller.owner(),
                    admission.state_fence(),
                )
                .map_err(|_| TransportError::SessionFenced)?;
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

fn is_daemon_operation(operation: &str) -> bool {
    matches!(
        operation,
        "snapshot"
            | "daemon_ready"
            | ACTIVE_GENERATION_REGISTRY_QUERY_OPERATION
            | DAEMON_STARTUP_EVIDENCE_OPERATION
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
            | "store_named"
            | "local_read"
            | "local_read_claim"
            | "local_read_result"
    )
}

/// Returns whether the operation string selects the #1780 D3 WASM port-grant
/// issuance route.
///
/// The operation string is the stable wire identity itself
/// (`WASM_PORT_GRANT_OPERATION`); there is no second dispatch vocabulary and
/// no generic JSON command routing. Callers must still prove the exact
/// (`wire_id`, `wire_version`) pair through `wasm_grant_request_from_payload`
/// on the decoded typed request: the operation string only selects this
/// closed entry.
pub(crate) fn is_wasm_port_grant_operation(operation: &str) -> bool {
    operation == WASM_PORT_GRANT_OPERATION
}

#[cfg(test)]
mod daemon_operation_tests {
    use super::{DAEMON_STARTUP_EVIDENCE_OPERATION, is_daemon_operation};
    use crate::generation_control::ACTIVE_GENERATION_REGISTRY_QUERY_OPERATION;

    #[test]
    fn generation_and_startup_routes_are_in_the_authenticated_daemon_matrix() {
        assert!(is_daemon_operation(
            ACTIVE_GENERATION_REGISTRY_QUERY_OPERATION
        ));
        assert!(is_daemon_operation(DAEMON_STARTUP_EVIDENCE_OPERATION));
        assert!(!is_daemon_operation(
            "daemon_generation_registry_active_query"
        ));
        assert!(!is_daemon_operation("unowned-operation"));
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

/// Returns whether the operation string selects one of the closed TestD
/// admission or terminal-completion routes. Each entry still validates its
/// own exact wire id/version and typed payload.
/// Returns whether the operation selects the closed Kernel research route.
pub(crate) fn is_research_operation(operation: &str) -> bool {
    operation == RESEARCH_DISPATCH_WIRE_ID || operation == RESEARCH_RECONCILE_OPERATION
}

pub(crate) fn is_testd_operation(operation: &str) -> bool {
    operation == TESTD_ADMISSION_WIRE_ID
        || operation == super::testd_terminal_completion_route::OPERATION
        || operation == super::testd_terminal_completion_route::OWNER_SUBMIT_OPERATION
}

impl KernelComposition {
    /// Dispatches one authenticated research dispatch/reconcile frame after
    /// the closed gateway has checked session, connection, operation, and
    /// service state. The actual claim is issued only by the execute arm.
    pub(crate) fn dispatch_research_frame(
        &self,
        session: &Session,
        frame: &Frame,
    ) -> Result<KernelFrameAction, TransportError> {
        let request_id = frame
            .request_id
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        let identity = frame
            .request_identity
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        if frame.connection_id != session.connection_id
            || !session
                .module_generation
                .state_fence
                .is_compatible_with(&identity.request.state_fence)
        {
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
        if operation == RESEARCH_DISPATCH_WIRE_ID {
            if frame.kind != FrameKind::Request || frame.message_type != MessageType::Execute {
                return Err(TransportError::SessionFenced);
            }
            research_dispatch_request_from_payload(&payload)?;
        } else if operation == RESEARCH_RECONCILE_OPERATION {
            if frame.kind != FrameKind::Cancel || frame.message_type != MessageType::Cancel {
                return Err(TransportError::SessionFenced);
            }
            research_reconcile_request_from_payload(&payload)?;
        } else {
            return Err(TransportError::SessionFenced);
        }
        Ok(KernelFrameAction::Research {
            request_id,
            identity,
            operation: operation.to_owned(),
            payload,
        })
    }

    /// Executes a validated research dispatch or reconciliation request.
    /// This is the production call site that supplies the authenticated
    /// session/owner claim to the shared dispatch contour.
    pub async fn execute_research_request(
        &self,
        session: &Session,
        request_id: super::RequestId,
        identity: &super::RequestIdentity,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<Frame, TransportError> {
        if session.module_generation.module_id.as_str() != ACTIVE_DAEMON_CALLER
            || !is_research_operation(operation)
        {
            return Err(TransportError::SessionFenced);
        }
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if !session
            .module_generation
            .state_fence
            .is_compatible_with(&identity.request.state_fence)
        {
            return Err(TransportError::SessionFenced);
        }
        let response = if operation == RESEARCH_DISPATCH_WIRE_ID {
            if self.service_state().map_err(|_| TransportError::SessionFenced)?
                != KernelServiceState::Ready
            {
                return Err(TransportError::SessionFenced);
            }
            let request = research_dispatch_request_from_payload(&payload)?;
            if identity.idempotency_key != request.request.idempotency_key
                || identity.request.state_fence != request.request.state_fence
            {
                return Err(TransportError::SessionFenced);
            }
            let outcome = super::dispatch_launch::launch_admitted_research_attempt(
                self,
                session,
                &request.request,
                unix_ms().saturating_mul(1_000_000),
            )
            .await
            .map_err(|_| TransportError::SessionFenced)?;
            research_launch_response(&outcome)
        } else {
            if !matches!(
                self.service_state().map_err(|_| TransportError::SessionFenced)?,
                KernelServiceState::Ready | KernelServiceState::Degraded
            ) {
                return Err(TransportError::SessionFenced);
            }
            let request = research_reconcile_request_from_payload(&payload)?;
            if identity.idempotency_key != request.operation_id {
                return Err(TransportError::SessionFenced);
            }
            let outcome = super::dispatch_launch::reconcile_launched_research_attempt(
                self,
                &request.operation_id,
            )
            .map_err(|_| TransportError::SessionFenced)?;
            research_reconcile_response(&outcome)
        };
        let mut reply = status_frame(
            session,
            FrameKind::Response,
            MessageType::Result,
            serde_json::json!({ "operation": operation, "result": response }),
        )?;
        reply.request_id = Some(request_id);
        reply
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(reply)
    }
}

/// Decodes the exact typed research dispatch request from a frame payload.
fn research_dispatch_request_from_payload(
    payload: &serde_json::Value,
) -> Result<ResearchDispatchRequest, TransportError> {
    let value = payload
        .get("request")
        .cloned()
        .ok_or(TransportError::SessionFenced)?;
    let request: ResearchDispatchRequest =
        serde_json::from_value(value).map_err(|_| TransportError::SessionFenced)?;
    request.validate().map_err(|_| TransportError::SessionFenced)?;
    Ok(request)
}

/// Decodes the exact typed research reconcile request from a frame payload.
fn research_reconcile_request_from_payload(
    payload: &serde_json::Value,
) -> Result<ResearchReconcileRequest, TransportError> {
    let value = payload
        .get("request")
        .cloned()
        .ok_or(TransportError::SessionFenced)?;
    let request: ResearchReconcileRequest =
        serde_json::from_value(value).map_err(|_| TransportError::SessionFenced)?;
    request.validate().map_err(|_| TransportError::SessionFenced)?;
    Ok(request)
}

fn research_launch_response(
    outcome: &super::dispatch_launch::ResearchLaunchOutcome,
) -> serde_json::Value {
    use super::dispatch_launch::ResearchLaunchOutcome;
    match outcome {
        ResearchLaunchOutcome::Launched {
            claim,
            operation_id,
            receipt,
        } => serde_json::json!({
            "state": "launched",
            "operation_id": operation_id.as_str(),
            "claim_sha256": claim.claim_sha256,
            "request_sha256": claim.request_sha256,
            "receipt": receipt,
        }),
        ResearchLaunchOutcome::LaunchUnknown {
            claim,
            operation_id,
        } => serde_json::json!({
            "state": "unknown",
            "operation_id": operation_id.as_str(),
            "claim_sha256": claim.claim_sha256,
            "request_sha256": claim.request_sha256,
        }),
        ResearchLaunchOutcome::ReplayOriginal {
            claim,
            operation_id,
        } => serde_json::json!({
            "state": "replayed",
            "operation_id": operation_id.as_str(),
            "claim_sha256": claim.claim_sha256,
            "request_sha256": claim.request_sha256,
        }),
    }
}

fn research_reconcile_response(
    outcome: &super::dispatch_launch::ResearchReconcileOutcome,
) -> serde_json::Value {
    use super::dispatch_launch::ResearchReconcileOutcome;
    match outcome {
        ResearchReconcileOutcome::MaterialRetained {
            operation_id,
            claim_sha256,
        } => serde_json::json!({
            "state": "reconcile_required",
            "operation_id": operation_id,
            "claim_sha256": claim_sha256,
        }),
        ResearchReconcileOutcome::Unknown { operation_id } => serde_json::json!({
            "state": "unknown",
            "operation_id": operation_id,
        }),
    }
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
        observe_frame("kernel.frame_doctor_dispatch", "attempt");
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
    /// existing `doctor.rs` entries, then admits through the composed
    /// dispatch contour
    /// ([`dispatch_launch::admit_doctor_repair_attempt`](super::dispatch_launch::admit_doctor_repair_attempt)):
    /// the contour binds the Doctor session from live Kernel state plus its
    /// composed principal owner and delegates to the unchanged
    /// `handle_doctor_repair_attempt` gate over the production ledger and
    /// the immutable registry. Neither the epoch nor the generation is ever
    /// taken from the request envelope.
    ///
    /// REWIRED (T6-D2 Slice B): the fail-closed tail is replaced by the
    /// composed admission above. Admitted, rejected, and conflicted answers
    /// return as typed reply frames; only mechanical failures (uncomposed
    /// contour, fenced generation, closed admission, ledger storage) fence
    /// the session. Cancellation envelopes admit-as-cancelled through the
    /// same gate (the separate control entry stays available to direct API
    /// callers; the frame path cannot distinguish control from submit
    /// frames, and inventing a wire bit for it is refused). An exact replay
    /// under one attempt identity rebuilds the original admission — the
    /// lost-reply rule — and never spawns here: spawning is the explicit
    /// [`dispatch_launch::launch_admitted_doctor_attempt`](super::dispatch_launch::launch_admitted_doctor_attempt)
    /// seam, keeping the admission and execution axes separate (I14.6). No
    /// new constants, no relaxations.
    #[allow(
        clippy::unused_async,
        reason = "the front-door driver awaits this handler uniformly with the daemon/testd arms; spawning stays in the explicit async launch seam"
    )]
    pub async fn execute_doctor_request(
        &self,
        session: &Session,
        request_id: super::RequestId,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<Frame, TransportError> {
        observe_frame("kernel.frame_doctor_execute", "attempt");
        let result = self
            .execute_doctor_request_inner(session, request_id, operation, &payload)
            .await;
        match &result {
            Ok(_) => observe_frame("kernel.frame_doctor_execute", "success"),
            Err(error) => {
                observe_frame("kernel.frame_doctor_execute", "fenced");
                super::kernel_diagnostics::observe_terminal_error(frame_terminal_code(error));
            }
        }
        result
    }

    #[allow(
        clippy::unused_async,
        reason = "the front-door driver awaits this handler uniformly with the daemon/testd arms; spawning stays in the explicit async launch seam"
    )]
    async fn execute_doctor_request_inner(
        &self,
        session: &Session,
        request_id: super::RequestId,
        operation: &str,
        payload: &serde_json::Value,
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
        let request = doctor_request_from_payload(payload)?;
        if operation != request.wire_id
            || !route_doctor_repair(&request.wire_id, request.wire_version)
        {
            return Err(TransportError::SessionFenced);
        }
        let now_unix_nanos = unix_ms().saturating_mul(1_000_000);
        if now_unix_nanos == 0 {
            return Err(TransportError::SessionFenced);
        }
        // Admit through the composed contour: uncomposed contours,
        // stale sessions, and mechanical gate failures fence here, while
        // every typed answer (admitted, rejected, conflict) projects to a
        // reply frame below.
        let response = {
            let service = self
                .service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            super::dispatch_launch::admit_doctor_repair_attempt(&service, &request, now_unix_nanos)
                .map_err(|_| TransportError::SessionFenced)?
        };
        let mut reply = status_frame(
            session,
            FrameKind::Response,
            MessageType::Result,
            serde_json::to_value(&response).map_err(|_| TransportError::SessionFenced)?,
        )?;
        reply.request_id = Some(request_id);
        reply
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(reply)
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

impl KernelComposition {
    /// Dispatches one testd admission frame from an admitted session.
    ///
    /// The caller ([`KernelComposition::dispatch_frame`]) has already run the
    /// closed-gateway gates (generation poison, session/frame identity,
    /// daemon-session currency) and the per-kind service gate (new-execution
    /// intake requires `Ready`, control additionally routes while `Degraded`);
    /// those joins are re-checked here so direct callers cannot bypass them.
    /// The frame must ride the presenting session's connection, the operation
    /// string must be the exact testd wire identity, and the payload must
    /// carry the typed [`TestdAdmissionAttemptRequest`] under `request` with a
    /// valid shape, canonical digest, and exact wire version. The validated
    /// request is forwarded as [`KernelFrameAction::Testd`]; job-bound
    /// admission itself runs in [`KernelComposition::execute_testd_request`].
    /// Unknown operations and mismatched joins fence; nothing is retried
    /// blindly and no admission is fabricated here.
    pub(crate) fn dispatch_testd_frame(
        &self,
        session: &Session,
        frame: &Frame,
    ) -> Result<KernelFrameAction, TransportError> {
        observe_frame("kernel.frame_testd_dispatch", "attempt");
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
        if !is_testd_operation(operation) {
            return Err(TransportError::SessionFenced);
        }
        if operation == TESTD_ADMISSION_WIRE_ID {
            let request = testd_request_from_payload(&payload)?;
            if operation != request.wire_id
                || !route_testd_admission(&request.wire_id, request.wire_version)
            {
                return Err(TransportError::SessionFenced);
            }
        } else if operation == super::testd_terminal_completion_route::OPERATION {
            let request = super::testd_terminal_completion_route::request_from_payload(&payload)
                .map_err(|_| TransportError::SessionFenced)?;
            if operation != request.wire_id
                || request.wire_version != super::testd_terminal_completion_route::WIRE_VERSION
            {
                return Err(TransportError::SessionFenced);
            }
        } else if operation == super::testd_terminal_completion_route::OWNER_SUBMIT_OPERATION {
            let request =
                super::testd_terminal_completion_route::owner_submit_request_from_payload(&payload)
                    .map_err(|_| TransportError::SessionFenced)?;
            if operation != request.wire_id
                || request.wire_version
                    != super::testd_terminal_completion_route::OWNER_WIRE_VERSION
            {
                return Err(TransportError::SessionFenced);
            }
        } else {
            return Err(TransportError::SessionFenced);
        }
        Ok(KernelFrameAction::Testd {
            request_id,
            identity: identity.clone(),
            operation: operation.to_owned(),
            payload,
        })
    }

    /// Executes one validated testd admission operation (T6-X1 P-07).
    ///
    /// Revalidates the closed operation name, the presenting session's testd
    /// binding, and the typed request shape/digest/wire version through the
    /// existing `testd_front_door.rs` entries, then admits through the
    /// composed dispatch contour
    /// ([`dispatch_launch::admit_testd_attempt`](super::dispatch_launch::admit_testd_attempt)):
    /// the contour binds the testd session from live Kernel state plus its
    /// composed principal owner and delegates to the unchanged
    /// `handle_testd_admission_attempt` gate. Testd admission is stateless
    /// (wire plus live authority only), so no ledger composition is
    /// required. Neither the epoch nor the generation is ever taken from
    /// the request envelope.
    ///
    /// REWIRED (T6-X1 Slice B): the fail-closed tail is replaced by the
    /// composed admission above. Admitted, rejected, and conflicted answers
    /// return as typed reply frames; only mechanical failures (uncomposed
    /// contour, fenced generation, closed admission) fence the session.
    /// Cancellation envelopes admit-as-cancelled through the same gate (the
    /// separate control entry stays available to direct API callers). An
    /// exact resubmit re-derives the admission from the same wire and live
    /// authority — the lost-reply rule at the launch layer returns the
    /// retained original instead of recomputing under a new id (see
    /// [`dispatch_launch::launch_admitted_testd_attempt`](super::dispatch_launch::launch_admitted_testd_attempt)).
    /// Spawning stays in that explicit launch seam, keeping the admission
    /// and execution axes separate (I14.6). No new constants, no
    /// relaxations.
    #[allow(
        clippy::unused_async,
        reason = "the front-door driver awaits this handler uniformly with the daemon/doctor arms; spawning stays in the explicit async launch seam"
    )]
    pub async fn execute_testd_request(
        &self,
        session: &Session,
        request_id: super::RequestId,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<Frame, TransportError> {
        observe_frame("kernel.frame_testd_execute", "attempt");
        let result = self
            .execute_testd_request_inner(session, request_id, operation, &payload)
            .await;
        match &result {
            Ok(_) => observe_frame("kernel.frame_testd_execute", "success"),
            Err(error) => {
                observe_frame("kernel.frame_testd_execute", "fenced");
                super::kernel_diagnostics::observe_terminal_error(frame_terminal_code(error));
            }
        }
        result
    }

    #[allow(
        clippy::unused_async,
        reason = "the front-door driver awaits this handler uniformly with the daemon/doctor arms; spawning stays in the explicit async launch seam"
    )]
    async fn execute_testd_request_inner(
        &self,
        session: &Session,
        request_id: super::RequestId,
        operation: &str,
        payload: &serde_json::Value,
    ) -> Result<Frame, TransportError> {
        if !is_testd_operation(operation) {
            return Err(TransportError::SessionFenced);
        }
        if operation != TESTD_ADMISSION_WIRE_ID {
            return Err(TransportError::SessionFenced);
        }
        if session.module_generation.module_id.as_str() != TESTD_MODULE_ID {
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
        let request = testd_request_from_payload(payload)?;
        if operation != request.wire_id
            || !route_testd_admission(&request.wire_id, request.wire_version)
        {
            return Err(TransportError::SessionFenced);
        }
        let now_unix_nanos = unix_ms().saturating_mul(1_000_000);
        if now_unix_nanos == 0 {
            return Err(TransportError::SessionFenced);
        }
        // Admit through the composed contour: uncomposed contours,
        // stale sessions, and mechanical gate failures fence here, while
        // every typed answer (admitted, rejected, conflict) projects to a
        // reply frame below.
        let response = {
            let service = self
                .service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            super::dispatch_launch::admit_testd_attempt(&service, &request, now_unix_nanos)
                .map_err(|_| TransportError::SessionFenced)?
        };
        let mut reply = status_frame(
            session,
            FrameKind::Response,
            MessageType::Result,
            serde_json::to_value(&response).map_err(|_| TransportError::SessionFenced)?,
        )?;
        reply.request_id = Some(request_id);
        reply
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(reply)
    }
}

impl KernelComposition {
    /// Rehydrates one TestD terminal notice through the existing authenticated
    /// worker session and retained launch owner. Pending is returned until the
    /// daemon has persisted its committed Governor WriteReceipt.
    pub async fn execute_testd_terminal_completion(
        &self,
        session: &Session,
        request_id: super::RequestId,
        identity: &super::RequestIdentity,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<Frame, TransportError> {
        observe_frame("kernel.frame_testd_terminal_execute", "attempt");
        if operation != super::testd_terminal_completion_route::OPERATION
            || session.module_generation.module_id.as_str() != TESTD_MODULE_ID
        {
            return Err(TransportError::SessionFenced);
        }
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if !session
            .module_generation
            .state_fence
            .is_compatible_with(&identity.request.state_fence)
        {
            return Err(TransportError::SessionFenced);
        }
        let request = super::testd_terminal_completion_route::request_from_payload(&payload)
            .map_err(|_| TransportError::SessionFenced)?;
        let response = {
            let service = self
                .service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            super::dispatch_launch::read_testd_terminal_completion(&service, &request)
                .map_err(|_| TransportError::SessionFenced)?
        };
        let mut reply = status_frame(
            session,
            FrameKind::Response,
            MessageType::Result,
            serde_json::to_value(&response).map_err(|_| TransportError::SessionFenced)?,
        )?;
        reply.request_id = Some(request_id);
        reply
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(reply)
    }

    /// Executes one authenticated `TestD` owner-submit operation. The frame's
    /// `RequestIdentity` is the sole task/operation identity source; the owner
    /// rehydrates and commits it with the durable job before replying.
    pub async fn execute_testd_owner_submit(
        &self,
        session: &Session,
        request_id: super::RequestId,
        identity: &super::RequestIdentity,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<Frame, TransportError> {
        observe_frame("kernel.frame_testd_owner_submit", "attempt");
        if operation != super::testd_terminal_completion_route::OWNER_SUBMIT_OPERATION
            || session.module_generation.module_id.as_str() != TESTD_MODULE_ID
        {
            return Err(TransportError::SessionFenced);
        }
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if !session
            .module_generation
            .state_fence
            .is_compatible_with(&identity.request.state_fence)
            || self
                .service_state()
                .map_err(|_| TransportError::SessionFenced)?
                != KernelServiceState::Ready
        {
            return Err(TransportError::SessionFenced);
        }
        let request =
            super::testd_terminal_completion_route::owner_submit_request_from_payload(&payload)
                .map_err(|_| TransportError::SessionFenced)?;
        let response =
            super::dispatch_launch::submit_testd_owner_job(self, identity, &request, unix_ms())
                .await
                .map_err(|_| TransportError::SessionFenced)?;
        let mut reply = status_frame(
            session,
            FrameKind::Response,
            MessageType::Result,
            serde_json::to_value(response).map_err(|_| TransportError::SessionFenced)?,
        )?;
        reply.request_id = Some(request_id);
        reply
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(reply)
    }
}

/// Decodes the exact typed testd admission request from a P-07 frame
/// payload.
///
/// The payload carries the closed operation string plus the full typed request
/// under `request`; the request shape, its canonical digest, and its exact
/// wire version are re-validated through the existing `testd_front_door.rs`
/// entries, so this is typed dispatch, not generic JSON routing.
fn testd_request_from_payload(
    payload: &serde_json::Value,
) -> Result<TestdAdmissionAttemptRequest, TransportError> {
    let request_value = payload
        .get("request")
        .cloned()
        .ok_or(TransportError::SessionFenced)?;
    let request: TestdAdmissionAttemptRequest =
        serde_json::from_value(request_value).map_err(|_| TransportError::SessionFenced)?;
    request
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    request
        .validate_canonical_digest()
        .map_err(|_| TransportError::SessionFenced)?;
    if !route_testd_admission(&request.wire_id, request.wire_version) {
        return Err(TransportError::SessionFenced);
    }
    Ok(request)
}

impl KernelComposition {
    /// Dispatches one authenticated WASM port-grant issuance frame (#1780 D3).
    ///
    /// The caller ([`KernelComposition::dispatch_frame`]) has already run the
    /// closed-gateway gates (generation poison, session/frame identity,
    /// daemon-session currency) and the per-kind service gate (new-effect
    /// intake requires `Ready`); those joins are re-checked here so direct
    /// callers cannot bypass them. The frame must ride the presenting
    /// session's connection, the operation string must be the exact
    /// [`WASM_PORT_GRANT_OPERATION`] identity, and the payload must carry
    /// both the live host-request envelope under `envelope` and the typed
    /// [`WasmGrantRequest`] under `request`.
    ///
    /// The envelope is admitted live through the unchanged
    /// `admit_host_request_envelope` gate: the returned Writer-A receipt is
    /// the same-generation/fence admission decision that
    /// [`handle_wasm_port_grant`] binds, so a stale fence fails closed here
    /// and the caller re-admits through the `HostRequest` path instead of
    /// executing against a rotated fence. The [`HandlerSession`] principal
    /// is the transport session guard's authenticated peer identity bound to
    /// the presenting connection; the [`KernelObservedGrantFacts`] are the
    /// live admitted handshake fence/epoch/connection plus the Kernel clock.
    /// The issued digest-bound grant projects as a typed reply frame; every
    /// denial and every mechanical failure fences. No permits are minted, no
    /// Governor observations are minted, no keys are touched: the grant
    /// attests transport plus freshness and carries caller digests for
    /// downstream re-hashing.
    pub(crate) fn dispatch_wasm_port_grant_frame(
        &self,
        session: &Session,
        frame: &Frame,
    ) -> Result<KernelFrameAction, TransportError> {
        observe_frame("kernel.frame_wasm_grant_dispatch", "attempt");
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
        if !is_wasm_port_grant_operation(operation) {
            return Err(TransportError::SessionFenced);
        }
        let envelope = super::host_request_route::host_request_envelope_from_payload(&payload)?;
        let request = wasm_grant_request_from_payload(&payload)?;
        if envelope.connection_id != session.connection_id {
            return Err(TransportError::SessionFenced);
        }
        if frame.request_id.as_ref() != Some(&envelope.identity.request_id) {
            return Err(TransportError::SessionFenced);
        }
        // Composition readiness before durable side effects: the
        // installation-approved host binding is required to issue, so its
        // absence fails here rather than after staging an admission record.
        let host = wasm_host_binary_facts(
            self.wasm_host_executable_path.as_ref(),
            self.wasm_host_artifact_sha256.as_deref(),
        )?;
        // Live admission decision: the returned receipt binds the admitted
        // envelope to the current generation and fence. Stale fences fail
        // closed here; the caller re-admits through the HostRequest path.
        let (receipt, _) = self.admit_host_request_envelope(&envelope)?;
        let principal = match &session.peer {
            PeerIdentity::Authenticated { user_identity, .. } => user_identity.clone(),
            PeerIdentity::Unavailable { .. } => {
                return Err(TransportError::PeerIdentityUnavailable);
            }
        };
        let handler_session = HandlerSession {
            principal,
            connection_id: session.connection_id.clone(),
        };
        let kernel = KernelObservedGrantFacts {
            state_fence: session.module_generation.state_fence.clone(),
            authority_epoch: session.authority_epoch.clone(),
            connection_id: session.connection_id.clone(),
            now_unix_ms: unix_ms(),
        };
        // Single-snapshot discipline: the admitted envelope must bind the
        // exact live fence (`handle_wasm_port_grant` re-enforces this as
        // `envelope-fence`; the early join keeps the terminal obvious).
        if envelope.state_fence != kernel.state_fence {
            return Err(TransportError::SessionFenced);
        }
        let grant = handle_wasm_port_grant(
            &receipt,
            &envelope,
            &handler_session,
            &kernel,
            &request,
            &host,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let mut reply = status_frame(
            session,
            FrameKind::Response,
            MessageType::Result,
            serde_json::json!({
                "operation": operation,
                "grant": grant,
            }),
        )?;
        reply.request_id = Some(request_id);
        reply
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(KernelFrameAction::Reply(reply))
    }
}

/// Resolves the installation-approved WASM-host binary facts for grant issuance.
///
/// The sole approved source is
/// `eliot_installation::RuntimeLaunchDescriptor::wasm_host_artifact_binding()`,
/// Reads the installation-approved WASM-host binary facts retained by the
/// production composition (`KernelConfig::with_wasm_host_executable_path` /
/// `with_wasm_host_artifact_sha256`, validated at assembly). Missing fails
/// closed: the arm stages no admission record without an approved binding,
/// and the live image digest is re-proved at launch, never here.
fn wasm_host_binary_facts(
    executable_path: Option<&std::path::PathBuf>,
    artifact_digest: Option<&str>,
) -> Result<HostBinaryFacts, TransportError> {
    let executable_path = executable_path
        .map(|path| path.to_string_lossy().into_owned())
        .ok_or(TransportError::SessionFenced)?;
    let artifact_digest = artifact_digest
        .map(str::to_owned)
        .ok_or(TransportError::SessionFenced)?;
    if std::path::Path::new(&executable_path)
        .file_name()
        .and_then(|name| name.to_str())
        != Some("eliot-wasm-host.exe")
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(HostBinaryFacts {
        executable_path,
        artifact_digest,
    })
}

/// Decodes the exact typed WASM port-grant request from a grant frame payload.
///
/// The payload carries the closed operation string plus the full typed request
/// under `request`; the request shape, its canonical digest, and its exact
/// wire version are re-validated through the grant module entries, so this is
/// typed dispatch, not generic JSON routing.
fn wasm_grant_request_from_payload(
    payload: &serde_json::Value,
) -> Result<WasmGrantRequest, TransportError> {
    let request_value = payload
        .get("request")
        .cloned()
        .ok_or(TransportError::SessionFenced)?;
    let request: WasmGrantRequest =
        serde_json::from_value(request_value).map_err(|_| TransportError::SessionFenced)?;
    request
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    if request.wire_id != WASM_GRANT_REQUEST_WIRE_ID
        || request.wire_version != WASM_GRANT_REQUEST_WIRE_VERSION
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(request)
}
