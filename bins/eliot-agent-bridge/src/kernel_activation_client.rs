//! Kernel activation client — neutral one-shot Kernel front-door activation exchange.
//!
//! Architecture: A12 (Security, provenance and bounded influence), A13.2 (Kernel and failure
//! domains), ARCH-AUTH-01 (explicit, scoped, fenced authority), ARCH-SEC-02 (one canonical
//! transition path), ARCH-RES-01 (fail locally, recover globally) — the client remains neutral,
//! bounded, and fail-closed, carrying only the admission receipt, fence, deadline, and request
//! bindings with no Kernel, Governor, or Store authority.
//!
//! Implementation: I1 (core ELIOT substrate), I7 (EBP/transport boundary), B.1 (Kernel↔Daemon),
//! P.3 (Kernel control boundary), and I2.23 (capability-family topology) — this cell is a narrow
//! transport boundary that mints no authority and performs no semantic admission.
//!
//! Ownership: this module is the sole owner of `build_neutral_activation_request`,
//! `activation_frame_for_request`, `decode_activation_response`, `KernelHostActivationPort` and
//! its production `HostActivationPort` impl plus the strictly private `provider_failure` closure.
//! Non-ownership: tests, CLI, local broker, and Bridge semantic admission remain root-owned.

use eliot_agent_bridge_core::ActivationPortOutcome;
use eliot_agent_bridge_core::ActivationPortResult;
use eliot_agent_bridge_core::AttachRequest;
use eliot_agent_bridge_core::FencingToken;
use eliot_agent_bridge_core::Generation;
use eliot_agent_bridge_core::HostActivationPort;
use eliot_agent_bridge_core::PrincipalId;
use eliot_agent_bridge_core::ProviderFailure;
use eliot_agent_bridge_core::SessionId;
use eliot_agent_bridge_core::TaskId;
use eliot_agent_bridge_core::WorkUnitId;
use eliot_protocol::AgentBridgeActivationRequest;
use eliot_protocol::AgentBridgeActivationResponse;
use eliot_protocol::AgentBridgePeerAdmissionReceipt;
use eliot_protocol::Frame;
use eliot_protocol::FrameKind;
use eliot_protocol::MessageType;
use eliot_protocol::ProtocolPayload;

use crate::AdmittedConnection;
use crate::LoadedAgentBridgeDeclaration;

fn provider_failure() -> ProviderFailure {
    ProviderFailure::new(
        "eliot-kernel-front-door",
        "authenticated Kernel application exchange was rejected",
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the neutral activation request keeps receipt, fence, deadline, and request bindings contiguous"
)]
pub(super) fn build_neutral_activation_request(
    core_request: &AttachRequest,
    receipt: &AgentBridgePeerAdmissionReceipt,
    demand_id: &str,
) -> Result<AgentBridgeActivationRequest, ProviderFailure> {
    use eliot_contracts::ClockReading;
    use eliot_contracts::ProductId;
    use eliot_contracts::RequestId;
    use eliot_contracts::RequestMetadata;
    use eliot_contracts::SourceId;
    use eliot_contracts::StateFence as Cfence;
    use eliot_protocol::RequestIdentity;
    use eliot_receipts::RequestBinding;
    let deadline = receipt.activation_deadline_unix_ms;
    let state_fence = receipt.state_fence.clone();
    let cfence = Cfence::new(state_fence.authority_epoch, state_fence.resource_generation);
    if state_fence.task_revision.is_some()
        || state_fence.policy_revision.is_some()
        || state_fence.integration_revision.is_some()
    {
        return Err(provider_failure());
    }
    let request_id = RequestId::new(demand_id).map_err(|_| provider_failure())?;
    let metadata = RequestMetadata {
        request_id: request_id.clone(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("eliot-agent-bridge").map_err(|_| provider_failure())?,
        source_id: SourceId::new("agent-bridge").map_err(|_| provider_failure())?,
        state_fence: cfence.clone(),
        clock: ClockReading {
            valid_time_ms: None,
            known_time_ms: None,
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    let binding = RequestBinding {
        metadata,
        state_fence: cfence,
    };
    let request_identity = RequestIdentity {
        request: binding,
        idempotency_key: demand_id.to_owned(),
        deadline_unix_ms: deadline,
        cancellation_id: format!("{demand_id}:cancel"),
    };
    request_identity
        .validate()
        .map_err(|_| provider_failure())?;
    if request_identity.request.metadata.session_id.is_some()
        || request_identity.request.metadata.task_id.is_some()
        || request_identity
            .request
            .metadata
            .state_fence
            .task_revision
            .is_some()
        || request_identity
            .request
            .metadata
            .clock
            .valid_time_ms
            .is_some()
        || request_identity
            .request
            .metadata
            .clock
            .known_time_ms
            .is_some()
        || request_identity
            .request
            .metadata
            .clock
            .transaction_sequence
            .is_some()
        || request_identity
            .request
            .metadata
            .clock
            .monotonic_ns
            .is_some()
    {
        return Err(provider_failure());
    }
    let attach_kind = match core_request.attach_kind() {
        eliot_agent_bridge_core::AttachKind::Managed => {
            eliot_protocol::AgentBridgeAttachKind::Managed
        }
        eliot_agent_bridge_core::AttachKind::External => {
            eliot_protocol::AgentBridgeAttachKind::External
        }
    };
    let blind = match (attach_kind, core_request.pre_attach_blind_interval()) {
        (eliot_protocol::AgentBridgeAttachKind::Managed, None) => None,
        (eliot_protocol::AgentBridgeAttachKind::External, Some(interval)) => {
            Some(eliot_protocol::AgentBridgeBlindInterval {
                start: interval.interval.start,
                end: interval.interval.end,
                reason_ref: interval.reason_ref.clone(),
            })
        }
        _ => return Err(provider_failure()),
    };
    let req = AgentBridgeActivationRequest {
        wire_id: eliot_protocol::AGENT_BRIDGE_ACTIVATION_REQUEST_WIRE_ID.to_owned(),
        wire_version: AgentBridgeActivationRequest::CONTRACT_VERSION,
        operation: eliot_protocol::AGENT_BRIDGE_ACTIVATION_OPERATION.to_owned(),
        demand_id: demand_id.to_owned(),
        connection_id: receipt.connection_id.clone(),
        attach_kind,
        pre_attach_blind_interval: blind,
        request_identity,
        peer_admission_receipt_sha256: receipt.receipt_sha256.clone(),
        request_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|_| provider_failure())?;
    req.validate_admission(receipt)
        .map_err(|_| provider_failure())?;
    Ok(req)
}

pub(super) fn activation_frame_for_request(
    request: &AgentBridgeActivationRequest,
) -> Result<Frame, ProviderFailure> {
    let frame = Frame {
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        encoding_profile: eliot_protocol::EncodingProfile::JsonV1,
        connection_id: request.connection_id.clone(),
        request_id: Some(request.request_identity.request.metadata.request_id.clone()),
        kind: FrameKind::Request,
        message_type: MessageType::Execute,
        request_identity: Some(request.request_identity.clone()),
        payload: ProtocolPayload::Json(
            serde_json::to_value(request).map_err(|_| provider_failure())?,
        ),
        trace_context: std::collections::BTreeMap::new(),
    };
    frame.validate().map_err(|_| provider_failure())?;
    if frame.request_identity.is_none() || frame.request_id.is_none() {
        return Err(provider_failure());
    }
    Ok(frame)
}

pub(super) fn decode_activation_response(
    frame: &Frame,
    expected_request: &AgentBridgeActivationRequest,
    admission: &AgentBridgePeerAdmissionReceipt,
) -> Result<AgentBridgeActivationResponse, ProviderFailure> {
    frame.validate().map_err(|_| provider_failure())?;
    if frame.kind != FrameKind::Response || frame.message_type != MessageType::Result {
        return Err(provider_failure());
    }
    expected_request
        .validate_admission(admission)
        .map_err(|_| provider_failure())?;
    if frame.connection_id != expected_request.connection_id
        || frame.connection_id != admission.connection_id
    {
        return Err(provider_failure());
    }
    if frame.request_id.as_ref()
        != Some(
            &expected_request
                .request_identity
                .request
                .metadata
                .request_id,
        )
    {
        return Err(provider_failure());
    }
    if frame.request_identity.is_some() {
        return Err(provider_failure());
    }
    let payload = match &frame.payload {
        ProtocolPayload::Json(v) => v.clone(),
        _ => return Err(provider_failure()),
    };
    let response: AgentBridgeActivationResponse =
        serde_json::from_value(payload).map_err(|_| provider_failure())?;
    response.validate().map_err(|_| provider_failure())?;
    response
        .validate_request(expected_request)
        .map_err(|_| provider_failure())?;
    if let eliot_protocol::AgentBridgeActivationDisposition::Authenticated { binding } =
        &response.disposition
        && (binding.activation_generation != admission.state_fence.resource_generation
            || binding.state_fence.authority_epoch != admission.state_fence.authority_epoch
            || binding.state_fence.generation != admission.state_fence.resource_generation)
    {
        return Err(provider_failure());
    }
    Ok(response)
}

pub(super) struct KernelHostActivationPort {
    pub(super) admitted: AdmittedConnection,
    pub(super) runtime: tokio::runtime::Runtime,
    pub(super) _loaded: LoadedAgentBridgeDeclaration,
    pub(super) activation_used: bool,
    pub(super) limits: eliot_ipc::TransportLimits,
}

impl HostActivationPort for KernelHostActivationPort {
    fn activate(
        &mut self,
        request: &AttachRequest,
    ) -> Result<ActivationPortOutcome, ProviderFailure> {
        if self.activation_used {
            return Err(ProviderFailure::new(
                "eliot-kernel-front-door",
                "activation exchange already consumed; restart/reconnect contour not admitted",
            ));
        }
        self.activation_used = true;
        let demand = request.demand_id().as_str().to_owned();
        let activation_request =
            build_neutral_activation_request(request, &self.admitted.receipt, &demand)?;
        let frame = activation_frame_for_request(&activation_request)?;
        let wire = self.runtime.block_on(async {
            self.admitted
                .transport
                .send_frame(&frame, self.limits)
                .await
                .map_err(|_| provider_failure())?;
            self.admitted
                .transport
                .receive_frame(self.limits)
                .await
                .map_err(|_| provider_failure())
        })?;
        let response =
            decode_activation_response(&wire, &activation_request, &self.admitted.receipt)?;
        match response.disposition {
            eliot_protocol::AgentBridgeActivationDisposition::Denied { reason_code } => {
                let code: &'static str = match reason_code {
                    eliot_protocol::AgentBridgeActivationDenialCode::SemanticResolutionUnavailable => {
                        "SEMANTIC_RESOLUTION_UNAVAILABLE"
                    }
                };
                Ok(ActivationPortOutcome::Denied { reason_code: code })
            }
            eliot_protocol::AgentBridgeActivationDisposition::Authenticated { binding } => {
                let b = *binding;
                let principal_id =
                    PrincipalId::new(b.principal_id).map_err(|_| provider_failure())?;
                let session_id = SessionId::new(b.session_id).map_err(|_| provider_failure())?;
                let task_id = TaskId::new(b.task_id).map_err(|_| provider_failure())?;
                let work_unit_id =
                    WorkUnitId::new(b.work_unit_id).map_err(|_| provider_failure())?;
                let generation = Generation::new(b.activation_generation.value())
                    .map_err(|_| provider_failure())?;
                let fence = FencingToken::new(
                    b.state_fence.authority_epoch.value(),
                    generation,
                    b.state_fence.nonce,
                )
                .map_err(|_| provider_failure())?;
                Ok(ActivationPortOutcome::Authenticated(
                    ActivationPortResult::authenticated(
                        principal_id,
                        session_id,
                        generation,
                        fence,
                        task_id,
                        work_unit_id,
                        b.work_scope_id,
                        b.task_revision,
                        b.plan_id,
                        b.plan_revision,
                    )
                    .map_err(|_| provider_failure())?,
                ))
            }
        }
    }
}
