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
use eliot_protocol::AgentBridgeActivationDenialCode;
use eliot_protocol::AgentBridgeActivationRequest;
use eliot_protocol::AgentBridgeActivationResponse;
use eliot_protocol::AgentBridgePeerAdmissionReceipt;
use eliot_protocol::Frame;
use eliot_protocol::FrameKind;
use eliot_protocol::MessageType;
use eliot_protocol::ProtocolPayload;

use crate::KernelTransportOwner;
use crate::SharedTransport;

/// I7.20 agent-facing disposition projection for a typed activation denial.
///
/// Per `docs/architecture/I07-20-agent-facing-error-contract.md`, every
/// non-success response carries a two-layer `disposition` + exact
/// `reason_code` pair: bridges switch on the stable disposition and MAY
/// specialise known reason codes. Catalogue groups: `TASK_SELECTION_REQUIRED` is
/// request/identity; `AMBIGUOUS_RESULT` / `STALE_STATE_FENCE` is state/conflict;
/// `DEADLINE_EXCEEDED` is capacity; `UNKNOWN_OUTCOME` is security/recovery.
/// Exhaustive with no wildcard arm so a future denial code breaks compilation.
pub(super) fn agent_disposition_for_denial(code: AgentBridgeActivationDenialCode) -> &'static str {
    use eliot_agent_bridge_core::{
        ACTIVATION_DISPOSITION_FAILED, ACTIVATION_DISPOSITION_INVALID_REQUEST,
        ACTIVATION_DISPOSITION_STALE_OR_CONFLICT, ACTIVATION_DISPOSITION_UNAVAILABLE_OR_CAPACITY,
    };
    match code {
        AgentBridgeActivationDenialCode::TaskSelectionRequired
        | AgentBridgeActivationDenialCode::ScopeSelectionRequired => {
            ACTIVATION_DISPOSITION_INVALID_REQUEST
        }
        AgentBridgeActivationDenialCode::ScopeAmbiguous
        | AgentBridgeActivationDenialCode::StaleFence => ACTIVATION_DISPOSITION_STALE_OR_CONFLICT,
        AgentBridgeActivationDenialCode::NotReady => ACTIVATION_DISPOSITION_UNAVAILABLE_OR_CAPACITY,
        AgentBridgeActivationDenialCode::FailedInternal
        | AgentBridgeActivationDenialCode::SemanticResolutionUnavailable => {
            ACTIVATION_DISPOSITION_FAILED
        }
    }
}

/// Bridge-alias projection from the Kernel↔bridge transport denial code to
/// the exact I7.20 catalogue `reason_code` carried at the agent face.
///
/// Per `docs/architecture/I07-20-agent-facing-error-contract.md`, legacy
/// transport names translate only through the bridge-alias mapping and never
/// create host-specific semantic control enums. Every output below is a
/// verbatim member of the I7.20 Appendix D catalogue: `TASK_SELECTION_REQUIRED`
/// (request/identity), `TASK_SCOPE_INCOMPATIBLE` (request/identity),
/// `AMBIGUOUS_RESULT` (state/conflict), `DEFERRED_CAPACITY`
/// (capacity/availability), `STALE_STATE_FENCE` (state/conflict),
/// `RUNTIME_FAILED` (route/integration), `UNKNOWN_OUTCOME`
/// (security/recovery). Exhaustive with no wildcard arm.
pub(super) fn agent_reason_for_denial(code: AgentBridgeActivationDenialCode) -> &'static str {
    match code {
        AgentBridgeActivationDenialCode::TaskSelectionRequired => "TASK_SELECTION_REQUIRED",
        AgentBridgeActivationDenialCode::ScopeSelectionRequired => "TASK_SCOPE_INCOMPATIBLE",
        AgentBridgeActivationDenialCode::ScopeAmbiguous => "AMBIGUOUS_RESULT",
        AgentBridgeActivationDenialCode::NotReady => "DEFERRED_CAPACITY",
        AgentBridgeActivationDenialCode::StaleFence => "STALE_STATE_FENCE",
        AgentBridgeActivationDenialCode::FailedInternal => "RUNTIME_FAILED",
        AgentBridgeActivationDenialCode::SemanticResolutionUnavailable => "UNKNOWN_OUTCOME",
    }
}

/// I7.20 Recovery / Conflict Directive kind for a typed activation denial.
///
/// Per `docs/architecture/I07-20-agent-facing-error-contract.md`, every
/// non-success response includes the applicable Recovery or Conflict
/// Directive. Selection denials carry candidate-recovery with no
/// auto-selection; `NOT_READY` requires a new ticket on retry; stale fence is
/// fail-closed; internal failures resolve to the failure capsule. The
/// Kernel-owned no-result refusal carries no failure capsule (none exists),
/// so its honest recovery is a new ticket. Exhaustive with no wildcard arm.
pub(super) fn denial_directive_kind(code: AgentBridgeActivationDenialCode) -> &'static str {
    use eliot_agent_bridge_core::{
        ACTIVATION_DIRECTIVE_CANDIDATE_RECOVERY, ACTIVATION_DIRECTIVE_FAILURE_CAPSULE,
        ACTIVATION_DIRECTIVE_FENCE_CLOSED, ACTIVATION_DIRECTIVE_RETRY_NEW_TICKET,
    };
    match code {
        AgentBridgeActivationDenialCode::TaskSelectionRequired
        | AgentBridgeActivationDenialCode::ScopeSelectionRequired
        | AgentBridgeActivationDenialCode::ScopeAmbiguous => {
            ACTIVATION_DIRECTIVE_CANDIDATE_RECOVERY
        }
        AgentBridgeActivationDenialCode::NotReady
        | AgentBridgeActivationDenialCode::SemanticResolutionUnavailable => {
            ACTIVATION_DIRECTIVE_RETRY_NEW_TICKET
        }
        AgentBridgeActivationDenialCode::StaleFence => ACTIVATION_DIRECTIVE_FENCE_CLOSED,
        AgentBridgeActivationDenialCode::FailedInternal => ACTIVATION_DIRECTIVE_FAILURE_CAPSULE,
    }
}

/// I7.20 agent-facing denial report for one typed wire denial.
///
/// Routes through [`agent_reason_for_denial`]
/// (catalogue alias), [`agent_disposition_for_denial`], and
/// [`denial_directive_kind`], and carries the exact owner-issued `detail`
/// verbatim: candidate/recovery handles, retry dependency plus observed
/// revision plus earliest-retry bound, observed fence, or failure handle.
/// A typed detail is never dropped into a code-only denial; a
/// `SemanticResolutionUnavailable` code never carries a typed detail and a
/// typed code never arrives without one. Any mismatch fails closed as a
/// transport rejection, never as a fabricated negative.
pub(super) fn denial_report_for(
    code: AgentBridgeActivationDenialCode,
    detail: Option<eliot_protocol::AgentActivationResolutionDisposition>,
    operation: &str,
) -> Result<eliot_agent_bridge_core::ActivationDenialReport, ProviderFailure> {
    let coherent = match &detail {
        None => code == AgentBridgeActivationDenialCode::SemanticResolutionUnavailable,
        Some(eliot_protocol::AgentActivationResolutionDisposition::Resolved { .. }) => false,
        Some(_) => code != AgentBridgeActivationDenialCode::SemanticResolutionUnavailable,
    };
    if !coherent {
        return Err(provider_failure());
    }
    eliot_agent_bridge_core::ActivationDenialReport::new(
        agent_reason_for_denial(code),
        agent_disposition_for_denial(code),
        denial_directive_kind(code),
        operation.to_owned(),
        detail,
    )
}

/// Transport failure stays distinct from a typed denial: deadline/unknown
/// transport outcomes surface as the distinct `DeadlineExceeded` /
/// `UnknownOutcome` port outcomes and never collapse into a known negative
/// reason/disposition/directive triple.
fn provider_failure() -> ProviderFailure {
    ProviderFailure::new(
        "eliot-kernel-front-door",
        "authenticated Kernel application exchange was rejected",
    )
}

/// Maps a transport exchange that ended with no terminal result to its
/// distinct port outcome: past the ticket deadline the result can never
/// arrive (`DeadlineExceeded`); before the deadline the outcome is genuinely
/// unknown (`UnknownOutcome`) rather than any known negative. Neither mints
/// authority and neither is a denial.
fn observe_no_result_outcome(operation: &str, deadline_unix_ms: u64) -> ActivationPortOutcome {
    let now_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(u64::MAX, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        });
    if now_unix_ms >= deadline_unix_ms {
        ActivationPortOutcome::DeadlineExceeded {
            operation: operation.to_owned(),
            deadline_unix_ms,
        }
    } else {
        ActivationPortOutcome::UnknownOutcome {
            operation: operation.to_owned(),
        }
    }
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
            || !binding
                .state_fence
                .authority_epoch
                .is_same_authority(&admission.state_fence.authority_epoch)
            || binding.state_fence.generation != admission.state_fence.resource_generation)
    {
        return Err(provider_failure());
    }
    Ok(response)
}

/// Runner-side face of the single retained transport owner.
///
/// Holds no transport of its own: every activation call borrows the shared
/// owner, so the one-shot guard, the runtime, and the admitted transport stay
/// singular while the host-request face serves envelopes beside it.
pub(super) struct KernelHostActivationPort {
    pub(super) shared: SharedTransport,
}

impl HostActivationPort for KernelHostActivationPort {
    fn activate(
        &mut self,
        request: &AttachRequest,
    ) -> Result<ActivationPortOutcome, ProviderFailure> {
        self.shared
            .try_borrow_mut()
            .map_err(|_| provider_failure())?
            .activate_inner(request)
    }
}

impl KernelTransportOwner {
    fn activate_inner(
        &mut self,
        request: &AttachRequest,
    ) -> Result<ActivationPortOutcome, ProviderFailure> {
        if self.activation_used {
            return Err(ProviderFailure::new(
                "eliot-kernel-front-door",
                "activation exchange already consumed; restart/reconnect contour not admitted",
            ));
        }
        let demand = request.demand_id().as_str().to_owned();
        let activation_request =
            build_neutral_activation_request(request, &self.admitted.receipt, &demand)?;
        let frame = activation_frame_for_request(&activation_request)?;
        let deadline_unix_ms = self.admitted.receipt.activation_deadline_unix_ms;
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
        });
        // A failed transport exchange consumes no one-shot: nothing terminal
        // was observed, so a retry may still reach the Kernel exactly once.
        // Only a completed, decoded response below marks the exchange
        // consumed. A retry after a half-completed exchange still fails
        // closed: the Kernel revoked or completed the connection, so the
        // second send lands on `IdentityConflict`/`SessionFenced`, never on
        // a second Session.
        let Ok(wire) = wire else {
            return Ok(observe_no_result_outcome(&demand, deadline_unix_ms));
        };
        let response =
            decode_activation_response(&wire, &activation_request, &self.admitted.receipt)?;
        // A decoded response completes the one-shot even when its projection
        // below fails closed: the Kernel completed or revoked the connection
        // when it projected, so a second exchange on it can never mint a
        // fresh Session. Only a transport failure above (no terminal bytes
        // observed) leaves the one-shot open for one exact retry.
        self.activation_used = true;
        match response.disposition {
            eliot_protocol::AgentBridgeActivationDisposition::Denied {
                reason_code,
                detail,
            } => {
                // I7.20 agent-facing denial report: catalogue reason alias,
                // disposition, directive, operation correlation, and the exact
                // owner-issued detail. Selection denials carry their exact
                // candidate/recovery handles with no auto-selection; NOT_READY
                // carries the dependency revision plus earliest-retry bound
                // and requires a new ticket on retry; stale fence is
                // fail-closed with its observed fence; internal failures carry
                // the exact failure capsule handle. Transport deadline/unknown
                // never collapses into a known negative: those surface as the
                // distinct `DeadlineExceeded`/`UnknownOutcome` port outcomes.
                let report = denial_report_for(reason_code, detail, &demand)?;
                Ok(ActivationPortOutcome::Denied(report))
            }
            eliot_protocol::AgentBridgeActivationDisposition::Authenticated { binding } => {
                let b = *binding;
                self.activated_session = Some(b.session_id.clone());
                self.activated_work_scope_id = Some(b.work_scope_id.clone());
                let principal_id =
                    PrincipalId::new(b.principal_id).map_err(|_| provider_failure())?;
                let session_id = SessionId::new(b.session_id).map_err(|_| provider_failure())?;
                let task_id = TaskId::new(b.task_id).map_err(|_| provider_failure())?;
                let work_unit_id =
                    WorkUnitId::new(b.work_unit_id).map_err(|_| provider_failure())?;
                let generation = Generation::new(b.activation_generation.value())
                    .map_err(|_| provider_failure())?;
                // INTENDED EpochId shape (B→A→C): fence carries EpochId after B.
                let fence = FencingToken::new(
                    b.state_fence.authority_epoch.clone(),
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
