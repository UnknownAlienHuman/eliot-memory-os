//! Kernel host-request client — typed host-request envelopes over the shared admitted transport.
//!
//! Architecture: A12 (Security, provenance and bounded influence), A13.2 (Kernel and failure
//! domains), ARCH-AUTH-01 (explicit, scoped, fenced authority), ARCH-SEC-02 (one canonical
//! transition path), ARCH-RES-01 (fail locally, recover globally) — the client remains neutral,
//! bounded, and fail-closed, carrying only kernel-issued connection/session/fence facts with no
//! Kernel, Governor, or Store authority of its own.
//!
//! Implementation: I7.1/I7.2 (typed frames over the admitted front-door transport, never raw
//! frame ingress) and I7.20 (typed outcomes only; no prose drives routing) — envelopes ride
//! `Request`/`Execute` frames whose payload selects the closed kernel entry
//! (`agent_host_request_submit`, `agent_host_request_cancel`, or
//! `agent_host_request_reconcile`) and replies are decoded with the same
//! connection/digest/fence joins as the activation path.
//!
//! Ownership: this module is the sole owner of the invocation/cancellation/reconciliation
//! envelope builders, the envelope frame builder, the admitted-reply decoder, the replay-cache
//! entry shape, and the production `KernelHostRequestPort` impl. Non-ownership: activation,
//! kernel admission/dispatch, gateway validation/correlation, and any durable ledger.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::{
    ClockReading, ProductId, RequestId, RequestMetadata, SourceId, StateFence, canonical_json_bytes,
};
use eliot_mcp::{
    HostCancellationPortOutcome, HostCancellationRequest, HostInvocationPortOutcome,
    HostInvocationRequest, HostOperationHandle, KernelHostRequestPort, PortFailure, ToolRequest,
};
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, HOST_REQUEST_WIRE_ID, HostRequestAdmissionReceipt,
    HostRequestEnvelope, HostRequestIdentity, HostRequestKind, MessageType, ProtocolPayload,
    ProtocolVersion, RequestIdentity, host_request_operation_id,
};
use eliot_receipts::RequestBinding;
use serde::Deserialize;

use crate::{KernelTransportOwner, SharedTransport};

/// Closed kernel entry that admits one invocation envelope.
///
/// Owned by `bins/eliot-kernel/src/host_request_route.rs` (Writer C frame
/// wiring); the literal is repeated here because the constant is `pub(crate)`
/// to that binary and this crate takes no new dependencies.
const AGENT_HOST_REQUEST_SUBMIT_OPERATION: &str = "agent_host_request_submit";
/// Closed kernel entry that advances the exact parent of one cancellation envelope.
const AGENT_HOST_REQUEST_CANCEL_OPERATION: &str = "agent_host_request_cancel";
/// Closed kernel entry that reconciles one exact operation after an unknown delivery.
const AGENT_HOST_REQUEST_RECONCILE_OPERATION: &str = "agent_host_request_reconcile";
/// Canonical prefix of the kernel-derived opaque operation handle.
const HOST_REQUEST_OPERATION_ID_PREFIX: &str = "hostreq:";
/// Exact payload-schema identity for the canonical `ToolRequest` bytes.
const HOST_REQUEST_PAYLOAD_SCHEMA_ID: &str = "eliot.mcp.tool-request.v1";
/// Bridge-proposed relative deadline when the host states no preference.
/// The kernel owns the absolute deadline; this is a bounded preference only.
const DEFAULT_DEADLINE_PREFERENCE_MS: u64 = 60_000;

/// Gateway-side face of the single retained transport owner.
///
/// Holds no transport of its own: every call borrows the shared owner, so the
/// admitted transport, runtime, receipt facts, and activation session stay
/// singular while the activation face serves the one-shot exchange beside it.
pub(super) struct KernelHostRequestClient {
    pub(super) shared: SharedTransport,
}

/// Non-durable replay entry: one host correlation bound to its exact envelope.
///
/// Process memory only; it dies with this bridge process, which spans exactly
/// one admitted connection. An exact replay resends byte-identical envelopes
/// so the kernel deduplicates by digest; a changed payload under a known
/// correlation never reaches the wire.
#[derive(Clone, Debug)]
pub(super) struct ReplayCacheEntry {
    pub(super) payload_digest: String,
    pub(super) envelope: HostRequestEnvelope,
}

/// Kernel-issued facts snapshotted from the shared owner for one call.
pub(super) struct TransportFacts {
    pub(super) connection_id: String,
    pub(super) state_fence: StateFence,
    pub(super) descriptor_sha256: String,
    pub(super) receipt_sha256: String,
    pub(super) session: Option<String>,
}

/// Exact parent reference resolved from the replay cache for cancel/probe envelopes.
struct ParentLink {
    handle: String,
    capability: String,
    payload_digest: String,
    request_base: String,
}

impl ParentLink {
    fn of(envelope: &HostRequestEnvelope) -> Self {
        Self {
            handle: host_request_operation_id(envelope),
            capability: envelope.identity.capability.clone(),
            payload_digest: envelope.identity.payload_sha256.clone(),
            request_base: envelope.identity.request_id.as_str().to_owned(),
        }
    }
}

/// Minimal tolerant view of the kernel-returned durable record.
///
/// Only the operation join and the state matter here; every other record
/// field is kernel-owned progression the bridge never interprets. An unknown
/// future state fails decoding, which fails closed into the unknown-outcome path.
#[derive(Clone, Debug, Deserialize)]
struct AdmittedReplyView {
    operation_id: String,
    state: HostRequestRecordState,
}

/// Mirror of the kernel-owned durable host-request states for outcome mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum HostRequestRecordState {
    Requested,
    Admitted,
    Routed,
    Submitted,
    PossiblyEffected,
    ResultReceived,
    Cancelled,
    Expired,
    Conflicted,
    Unknown,
    Reconciling,
    Terminal,
}

fn request_failure() -> PortFailure {
    PortFailure::TransportBindingRejected {
        reason: "authenticated Kernel host-request exchange was rejected".to_owned(),
    }
}

fn plan_gap_bind(detail: &str) -> PortFailure {
    PortFailure::PlanGap {
        missing_capability: "kernel.host-request.bind-dispatch".to_owned(),
        reason: format!("host contract is invalid: {detail}"),
    }
}

fn plan_gap_no_session() -> PortFailure {
    PortFailure::PlanGap {
        missing_capability: "kernel.host-request.bind-dispatch".to_owned(),
        reason: "no admitted Kernel session; attach and activate before host-request dispatch"
            .to_owned(),
    }
}

fn plan_gap_cancel_no_session() -> PortFailure {
    PortFailure::PlanGap {
        missing_capability: "kernel.host-request.cancel".to_owned(),
        reason: "no admitted Kernel session; attach and activate before host-request cancel"
            .to_owned(),
    }
}

fn plan_gap_unknown_handle() -> PortFailure {
    PortFailure::PlanGap {
        missing_capability: "kernel.host-request.cancel".to_owned(),
        reason: "unknown operation handle for this bridge connection; the bridge that admitted the operation reconciles it"
            .to_owned(),
    }
}

fn unsupported_finish() -> PortFailure {
    PortFailure::Unsupported {
        capability: "kernel.host-request.finish-task-binding".to_owned(),
        reason: "finish requires Governor task admission; no Kernel task binding exists".to_owned(),
    }
}

fn unknown_outcome(digest: &str) -> PortFailure {
    PortFailure::TransportBindingRejected {
        reason: format!(
            "host-request exchange left an unknown outcome; re-attach and reconcile {HOST_REQUEST_OPERATION_ID_PREFIX}{digest}"
        ),
    }
}

fn unknown_cancel_outcome(handle: &str) -> PortFailure {
    PortFailure::TransportBindingRejected {
        reason: format!(
            "cancellation left an unknown outcome for {handle}; re-attach and reconcile it before retrying cancel"
        ),
    }
}

fn unknown_handle() -> PortFailure {
    PortFailure::TransportBindingRejected {
        reason: "unknown operation handle; use the exact handle from admission".to_owned(),
    }
}

fn unix_ms() -> Result<u64, PortFailure> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis().try_into().unwrap_or(u64::MAX))
        .map_err(|_| request_failure())
}

fn canonical_payload_digest(tool: &ToolRequest) -> Result<String, PortFailure> {
    use eliot_contracts::sha256_hex;
    let bytes = canonical_json_bytes(tool).map_err(|_| request_failure())?;
    Ok(sha256_hex(&bytes))
}

/// Requires the exact canonical handle shape without interpreting it.
fn parse_operation_handle(handle: &str) -> Result<String, PortFailure> {
    let digest = handle
        .strip_prefix(HOST_REQUEST_OPERATION_ID_PREFIX)
        .ok_or_else(unknown_handle)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(unknown_handle());
    }
    Ok(digest.to_owned())
}

impl KernelTransportOwner {
    pub(super) fn snapshot(&self) -> TransportFacts {
        TransportFacts {
            connection_id: self.admitted.receipt.connection_id.clone(),
            state_fence: self.admitted.receipt.state_fence.clone(),
            descriptor_sha256: self.admitted.receipt.descriptor_sha256.clone(),
            receipt_sha256: self.admitted.receipt.receipt_sha256.clone(),
            session: self.activated_session.clone(),
        }
    }

    fn exchange_host_request_frame(&mut self, frame: &Frame) -> Result<Frame, PortFailure> {
        let delivery = self.runtime.block_on(async {
            self.admitted
                .transport
                .send_frame(frame, self.limits)
                .await
                .map_err(|_| request_failure())
        })?;
        if !matches!(delivery, eliot_ipc::DeliveryOutcome::Delivered) {
            return Err(request_failure());
        }
        self.runtime.block_on(async {
            self.admitted
                .transport
                .receive_frame(self.limits)
                .await
                .map_err(|_| request_failure())
        })
    }
}

impl KernelHostRequestClient {
    fn exchange(&mut self, frame: &Frame) -> Result<Frame, PortFailure> {
        self.shared
            .try_borrow_mut()
            .map_err(|_| request_failure())?
            .exchange_host_request_frame(frame)
    }

    fn replay_or_build_invocation(
        &mut self,
        correlation: &str,
        request: &HostInvocationRequest,
        facts: &TransportFacts,
        session_id: &str,
        payload_digest: &str,
        now_ms: u64,
    ) -> Result<HostRequestEnvelope, PortFailure> {
        let mut owner = self
            .shared
            .try_borrow_mut()
            .map_err(|_| request_failure())?;
        if let Some(cached) = owner.replay_cache.get(correlation) {
            if cached.payload_digest == payload_digest {
                return Ok(cached.envelope.clone());
            }
            return Err(PortFailure::IdempotencyConflict);
        }
        let envelope =
            build_invocation_envelope(request, facts, session_id, payload_digest, now_ms)?;
        owner.replay_cache.insert(
            correlation.to_owned(),
            ReplayCacheEntry {
                payload_digest: payload_digest.to_owned(),
                envelope: envelope.clone(),
            },
        );
        Ok(envelope)
    }

    fn parent_link_for_handle(&self, digest: &str) -> Result<ParentLink, PortFailure> {
        let owner = self.shared.try_borrow().map_err(|_| request_failure())?;
        owner
            .replay_cache
            .values()
            .find(|entry| {
                host_request_operation_id(&entry.envelope)
                    == format!("{HOST_REQUEST_OPERATION_ID_PREFIX}{digest}")
            })
            .map(|entry| ParentLink::of(&entry.envelope))
            .ok_or_else(plan_gap_unknown_handle)
    }
}

fn build_invocation_envelope(
    request: &HostInvocationRequest,
    facts: &TransportFacts,
    session_id: &str,
    payload_digest: &str,
    now_ms: u64,
) -> Result<HostRequestEnvelope, PortFailure> {
    let correlation = request.correlation_id.as_str();
    let deadline = now_ms.saturating_add(
        request
            .deadline_preference_ms
            .unwrap_or(DEFAULT_DEADLINE_PREFERENCE_MS),
    );
    if deadline == 0 {
        return Err(request_failure());
    }
    let identity = HostRequestIdentity {
        request_id: RequestId::new(correlation).map_err(|_| request_failure())?,
        idempotency_key: format!("{correlation}:invoke"),
        cancellation_id: format!("{correlation}:invoke:cancel"),
        parent_operation_id: None,
        deadline_unix_ms: deadline,
        capability: request.tool.canonical_name().to_owned(),
        session_id: Some(session_id.to_owned()),
        task_id: None,
        work_scope_id: None,
        payload_schema_id: HOST_REQUEST_PAYLOAD_SCHEMA_ID.to_owned(),
        payload_sha256: payload_digest.to_owned(),
    };
    finish_envelope(facts, HostRequestKind::Invocation, identity)
}

fn build_cancellation_envelope(
    request: &HostCancellationRequest,
    facts: &TransportFacts,
    session_id: &str,
    parent: &ParentLink,
    now_ms: u64,
) -> Result<HostRequestEnvelope, PortFailure> {
    let correlation = request.correlation_id.as_str();
    let deadline = now_ms.saturating_add(
        request
            .deadline_preference_ms
            .unwrap_or(DEFAULT_DEADLINE_PREFERENCE_MS),
    );
    if deadline == 0 {
        return Err(request_failure());
    }
    let identity = HostRequestIdentity {
        request_id: RequestId::new(correlation).map_err(|_| request_failure())?,
        cancellation_id: format!("{correlation}:cancel:cancel"),
        idempotency_key: format!("{correlation}:cancel"),
        parent_operation_id: Some(parent.handle.clone()),
        deadline_unix_ms: deadline,
        capability: parent.capability.clone(),
        session_id: Some(session_id.to_owned()),
        task_id: None,
        work_scope_id: None,
        payload_schema_id: HOST_REQUEST_PAYLOAD_SCHEMA_ID.to_owned(),
        payload_sha256: parent.payload_digest.clone(),
    };
    finish_envelope(facts, HostRequestKind::Cancellation, identity)
}

fn build_reconciliation_envelope(
    facts: &TransportFacts,
    session_id: &str,
    parent: &ParentLink,
    now_ms: u64,
) -> Result<HostRequestEnvelope, PortFailure> {
    let request_id_text = format!("{}:reconcile:{now_ms}", parent.request_base);
    let deadline = now_ms.saturating_add(DEFAULT_DEADLINE_PREFERENCE_MS);
    if deadline == 0 {
        return Err(request_failure());
    }
    let identity = HostRequestIdentity {
        request_id: RequestId::new(&request_id_text).map_err(|_| request_failure())?,
        idempotency_key: format!("{request_id_text}:idempotent"),
        cancellation_id: format!("{request_id_text}:cancel"),
        parent_operation_id: Some(parent.handle.clone()),
        deadline_unix_ms: deadline,
        capability: parent.capability.clone(),
        session_id: Some(session_id.to_owned()),
        task_id: None,
        work_scope_id: None,
        payload_schema_id: HOST_REQUEST_PAYLOAD_SCHEMA_ID.to_owned(),
        payload_sha256: parent.payload_digest.clone(),
    };
    finish_envelope(facts, HostRequestKind::Reconciliation, identity)
}

fn finish_envelope(
    facts: &TransportFacts,
    kind: HostRequestKind,
    identity: HostRequestIdentity,
) -> Result<HostRequestEnvelope, PortFailure> {
    let envelope = HostRequestEnvelope {
        wire_id: HOST_REQUEST_WIRE_ID.to_owned(),
        wire_version: HostRequestEnvelope::CONTRACT_VERSION,
        kind,
        connection_id: facts.connection_id.clone(),
        identity,
        state_fence: facts.state_fence.clone(),
        descriptor_sha256: facts.descriptor_sha256.clone(),
        peer_admission_receipt_sha256: facts.receipt_sha256.clone(),
        activation_binding: None,
        envelope_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|_| request_failure())?;
    envelope.validate().map_err(|_| request_failure())?;
    Ok(envelope)
}

#[allow(
    clippy::too_many_lines,
    reason = "the neutral frame identity keeps receipt, fence, deadline, and envelope bindings contiguous"
)]
fn host_request_frame_for_envelope(
    operation: &str,
    envelope: &HostRequestEnvelope,
    facts: &TransportFacts,
) -> Result<Frame, PortFailure> {
    let fence = facts.state_fence.clone();
    if fence.task_revision.is_some()
        || fence.policy_revision.is_some()
        || fence.integration_revision.is_some()
    {
        return Err(request_failure());
    }
    let frame_fence = StateFence::new(fence.authority_epoch, fence.resource_generation);
    let metadata = RequestMetadata {
        request_id: envelope.identity.request_id.clone(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("eliot-agent-bridge").map_err(|_| request_failure())?,
        source_id: SourceId::new("agent-bridge").map_err(|_| request_failure())?,
        state_fence: frame_fence.clone(),
        clock: ClockReading {
            valid_time_ms: None,
            known_time_ms: None,
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    let binding = RequestBinding {
        metadata,
        state_fence: frame_fence,
    };
    let frame_identity = RequestIdentity {
        request: binding,
        idempotency_key: envelope.identity.idempotency_key.clone(),
        deadline_unix_ms: envelope.identity.deadline_unix_ms,
        cancellation_id: envelope.identity.cancellation_id.clone(),
    };
    frame_identity.validate().map_err(|_| request_failure())?;
    if frame_identity.request.metadata.session_id.is_some()
        || frame_identity.request.metadata.task_id.is_some()
        || frame_identity
            .request
            .metadata
            .state_fence
            .task_revision
            .is_some()
        || frame_identity
            .request
            .metadata
            .clock
            .valid_time_ms
            .is_some()
        || frame_identity
            .request
            .metadata
            .clock
            .known_time_ms
            .is_some()
        || frame_identity
            .request
            .metadata
            .clock
            .transaction_sequence
            .is_some()
        || frame_identity.request.metadata.clock.monotonic_ns.is_some()
    {
        return Err(request_failure());
    }
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: envelope.connection_id.clone(),
        request_id: Some(envelope.identity.request_id.clone()),
        kind: FrameKind::Request,
        message_type: MessageType::Execute,
        request_identity: Some(frame_identity),
        payload: ProtocolPayload::Json(serde_json::json!({
            "operation": operation,
            "envelope": envelope,
        })),
        trace_context: BTreeMap::new(),
    };
    frame.validate().map_err(|_| request_failure())?;
    if frame.request_identity.is_none() || frame.request_id.is_none() {
        return Err(request_failure());
    }
    Ok(frame)
}

/// Strictly decodes one admitted reply: response/result shape, connection and
/// request joins, closed `known`/`accepted` status, receipt digest validation
/// against the exact sent envelope, and the operation join. Any mismatch is
/// an unknown delivery (`None`), never a guessed outcome.
fn decode_admitted_reply(
    reply: &Frame,
    envelope: &HostRequestEnvelope,
) -> Option<(HostRequestAdmissionReceipt, AdmittedReplyView)> {
    reply.validate().ok()?;
    if reply.kind != FrameKind::Response || reply.message_type != MessageType::Result {
        return None;
    }
    if reply.connection_id != envelope.connection_id {
        return None;
    }
    if reply.request_id.as_ref() != Some(&envelope.identity.request_id) {
        return None;
    }
    if reply.request_identity.is_some() {
        return None;
    }
    let payload = match &reply.payload {
        ProtocolPayload::Json(value) => value.clone(),
        _ => return None,
    };
    if payload.get("status")?.as_str()? != "known" {
        return None;
    }
    let value = payload.get("value")?;
    if value.get("accepted")?.as_bool() != Some(true) {
        return None;
    }
    let receipt: HostRequestAdmissionReceipt =
        serde_json::from_value(value.get("receipt")?.clone()).ok()?;
    receipt.validate().ok()?;
    receipt.validate_envelope(envelope).ok()?;
    let record: AdmittedReplyView = serde_json::from_value(value.get("record")?.clone()).ok()?;
    if record.operation_id != receipt.operation_id {
        return None;
    }
    Some((receipt, record))
}

fn submit_outcome(
    receipt: &HostRequestAdmissionReceipt,
    record: &AdmittedReplyView,
) -> Result<HostInvocationPortOutcome, PortFailure> {
    let handle =
        HostOperationHandle::new(receipt.operation_id.clone()).map_err(|_| request_failure())?;
    match record.state {
        HostRequestRecordState::Requested
        | HostRequestRecordState::Admitted
        | HostRequestRecordState::Routed
        | HostRequestRecordState::Submitted
        | HostRequestRecordState::PossiblyEffected
        | HostRequestRecordState::Unknown
        | HostRequestRecordState::Reconciling
        | HostRequestRecordState::ResultReceived => Ok(HostInvocationPortOutcome::Accepted {
            operation_handle: handle,
        }),
        HostRequestRecordState::Expired => Err(PortFailure::DeadlineExceeded),
        HostRequestRecordState::Cancelled => Err(PortFailure::Cancelled),
        HostRequestRecordState::Conflicted | HostRequestRecordState::Terminal => {
            Err(PortFailure::TransportBindingRejected {
                reason: "operation is already terminal; reconcile the exact operation".to_owned(),
            })
        }
    }
}

impl KernelHostRequestPort for KernelHostRequestClient {
    fn invoke(
        &mut self,
        request: &HostInvocationRequest,
    ) -> Result<HostInvocationPortOutcome, PortFailure> {
        request
            .validate()
            .map_err(|error| plan_gap_bind(&error.to_string()))?;
        if matches!(request.tool, ToolRequest::Finish(_)) {
            return Err(unsupported_finish());
        }
        let now_ms = unix_ms()?;
        let facts = self
            .shared
            .try_borrow()
            .map_err(|_| request_failure())?
            .snapshot();
        let session = facts.session.clone().ok_or_else(plan_gap_no_session)?;
        let correlation = request.correlation_id.as_str().to_owned();
        let payload_digest = canonical_payload_digest(&request.tool)?;
        let envelope = self.replay_or_build_invocation(
            &correlation,
            request,
            &facts,
            &session,
            &payload_digest,
            now_ms,
        )?;
        if now_ms >= envelope.identity.deadline_unix_ms {
            // Only a cached replay can be stale here: fresh builds set
            // deadline to now plus a positive preference. The original attempt
            // may still be live kernel-side, so probe once instead of assuming
            // expiry; a failed probe settles as deadline exceeded.
            return self
                .probe_settles_invocation(&facts, &session, &envelope, now_ms)
                .map_err(|_| PortFailure::DeadlineExceeded);
        }
        let frame = host_request_frame_for_envelope(
            AGENT_HOST_REQUEST_SUBMIT_OPERATION,
            &envelope,
            &facts,
        )?;
        let Ok(reply) = self.exchange(&frame) else {
            return self.probe_settles_invocation(&facts, &session, &envelope, now_ms);
        };
        match decode_admitted_reply(&reply, &envelope) {
            Some((receipt, record)) => submit_outcome(&receipt, &record),
            None => self.probe_settles_invocation(&facts, &session, &envelope, now_ms),
        }
    }

    fn cancel(
        &mut self,
        request: &HostCancellationRequest,
    ) -> Result<HostCancellationPortOutcome, PortFailure> {
        request
            .validate()
            .map_err(|error| plan_gap_bind(&error.to_string()))?;
        let digest = parse_operation_handle(request.operation_handle.as_str())?;
        let now_ms = unix_ms()?;
        let facts = self
            .shared
            .try_borrow()
            .map_err(|_| request_failure())?
            .snapshot();
        let session = facts
            .session
            .clone()
            .ok_or_else(plan_gap_cancel_no_session)?;
        let parent = self.parent_link_for_handle(&digest)?;
        let envelope = build_cancellation_envelope(request, &facts, &session, &parent, now_ms)?;
        if now_ms >= envelope.identity.deadline_unix_ms {
            return Err(PortFailure::DeadlineExceeded);
        }
        let frame = host_request_frame_for_envelope(
            AGENT_HOST_REQUEST_CANCEL_OPERATION,
            &envelope,
            &facts,
        )?;
        let Ok(reply) = self.exchange(&frame) else {
            return self.probe_confirms_parent(&facts, &session, &parent, &envelope, now_ms);
        };
        match decode_admitted_reply(&reply, &envelope) {
            Some((_, record)) => match record.state {
                HostRequestRecordState::Expired => Err(PortFailure::DeadlineExceeded),
                HostRequestRecordState::Requested
                | HostRequestRecordState::Admitted
                | HostRequestRecordState::Routed
                | HostRequestRecordState::Submitted
                | HostRequestRecordState::PossiblyEffected
                | HostRequestRecordState::Unknown
                | HostRequestRecordState::Reconciling
                | HostRequestRecordState::ResultReceived
                | HostRequestRecordState::Cancelled => Ok(HostCancellationPortOutcome::Accepted),
                HostRequestRecordState::Conflicted | HostRequestRecordState::Terminal => {
                    Err(PortFailure::TransportBindingRejected {
                        reason:
                            "cancellation record is already terminal; reconcile the exact operation"
                                .to_owned(),
                    })
                }
            },
            None => self.probe_confirms_parent(&facts, &session, &parent, &envelope, now_ms),
        }
    }
}

impl KernelHostRequestClient {
    /// Sends one observation-only reconcile probe for an invocation whose
    /// delivery is unknown, settling existence as admission.
    ///
    /// The probe carries the exact parent handle: success proves the kernel
    /// staged the operation, so the invoke settles as `Accepted` with the
    /// kernel-derived handle. Failure stays an unknown outcome with the exact
    /// digest for re-attach reconciliation. The submit itself is never resent.
    fn probe_settles_invocation(
        &mut self,
        facts: &TransportFacts,
        session_id: &str,
        envelope: &HostRequestEnvelope,
        now_ms: u64,
    ) -> Result<HostInvocationPortOutcome, PortFailure> {
        let digest = envelope.envelope_sha256.clone();
        let probe =
            build_reconciliation_envelope(facts, session_id, &ParentLink::of(envelope), now_ms)?;
        let frame =
            host_request_frame_for_envelope(AGENT_HOST_REQUEST_RECONCILE_OPERATION, &probe, facts)?;
        let reply = self
            .exchange(&frame)
            .map_err(|_| unknown_outcome(&digest))?;
        match decode_admitted_reply(&reply, &probe) {
            Some(_) => {
                let handle = HostOperationHandle::new(host_request_operation_id(envelope))
                    .map_err(|_| request_failure())?;
                Ok(HostInvocationPortOutcome::Accepted {
                    operation_handle: handle,
                })
            }
            None => Err(unknown_outcome(&digest)),
        }
    }

    /// Sends one observation-only reconcile probe after an unknown
    /// cancellation delivery, reporting the outcome honestly either way.
    ///
    /// Probe success proves the parent exists but not that the cancellation
    /// applied, so both probe paths report the unknown cancellation outcome
    /// with the exact handle instead of claiming acceptance.
    fn probe_confirms_parent(
        &mut self,
        facts: &TransportFacts,
        session_id: &str,
        parent: &ParentLink,
        envelope: &HostRequestEnvelope,
        now_ms: u64,
    ) -> Result<HostCancellationPortOutcome, PortFailure> {
        let probe = build_reconciliation_envelope(facts, session_id, parent, now_ms)?;
        let frame =
            host_request_frame_for_envelope(AGENT_HOST_REQUEST_RECONCILE_OPERATION, &probe, facts)?;
        let digest = envelope.envelope_sha256.clone();
        let reply = self
            .exchange(&frame)
            .map_err(|_| unknown_outcome(&digest))?;
        match decode_admitted_reply(&reply, &probe) {
            Some(_) => Err(unknown_cancel_outcome(&parent.handle)),
            None => Err(unknown_outcome(&digest)),
        }
    }
}
