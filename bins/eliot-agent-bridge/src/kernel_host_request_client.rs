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
    sha256_hex,
};
use eliot_mcp::{
    HostCancellationPortOutcome, HostCancellationRequest, HostInvocationPortOutcome,
    HostInvocationRequest, HostOperationHandle, KernelHostRequestPort, McpResponse, PortFailure,
    ToolRequest,
};
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, HARD_STRUCTURED_RESPONSE_BYTES,
    HOST_REQUEST_RESULT_BODY_WIRE_ID, HOST_REQUEST_WIRE_ID, HostRequestAdmissionReceipt,
    HostRequestEnvelope, HostRequestIdentity, HostRequestKind, HostRequestResultBody, MessageType,
    ProtocolPayload, ProtocolVersion, RequestIdentity, host_request_operation_id,
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
/// Closed kernel entry that invokes one local read with its canonical tool
/// bytes (Implements #18: local read result).
///
/// Owned by `bins/eliot-kernel/src/host_request_route.rs`; the literal is
/// repeated here because the constant is `pub(crate)` to that binary and this
/// crate takes no new dependencies. Carries the exact envelope plus the
/// canonical `ToolRequest` JSON so the kernel can check tool linkage before
/// reading and serve the exact bounded result with its revision; the envelope
/// stays digest-only in spirit.
const AGENT_HOST_REQUEST_INVOKE_READ_OPERATION: &str = "agent_host_request_invoke_read";
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
/// Only the operation join, the state, and the optional result pair matter
/// here; every other record field is kernel-owned progression the bridge
/// never interprets. An unknown future state fails decoding, which fails
/// closed into the unknown-outcome path. `result_digest`/`result_response`
/// ride the record for `RESULT_RECEIVED` (and a `TERMINAL` carrying a result
/// forward); any other state carrying them fails decoding the same way.
#[derive(Clone, Debug, Deserialize)]
struct AdmittedReplyView {
    operation_id: String,
    state: HostRequestRecordState,
    #[serde(default)]
    result_digest: Option<String>,
    #[serde(default)]
    result_response: Option<serde_json::Value>,
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
    let frame_fence = StateFence::new(fence.authority_epoch.clone(), fence.resource_generation);
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

/// Returns whether one invocation is a local read served with its canonical
/// tool bytes (Implements #18: local read result).
///
/// `eliot.query` and `eliot.packet` ride the invoke-read entry so the kernel
/// can check tool linkage before reading and serve the exact bounded result
/// with its revision; every other tool keeps the admission-only submit entry.
/// `eliot.packet` parity falls out of the same op because the tool bytes are
/// opaque here: the kernel, not the pipe, owns their meaning.
fn invokes_local_read(request: &HostInvocationRequest) -> bool {
    matches!(
        request.tool,
        ToolRequest::Query(_) | ToolRequest::Packet(_)
    )
}

/// Builds one invoke-read frame carrying the exact envelope plus the exact
/// canonical tool bytes it admits.
///
/// Reuses the neutral frame identity of
/// [`host_request_frame_for_envelope`]; only the payload gains the `tool`
/// bytes. The kernel re-checks capability and payload-digest linkage before
/// any read, so a changed payload or forged descriptor fails there first.
fn host_request_invoke_read_frame(
    request: &HostInvocationRequest,
    envelope: &HostRequestEnvelope,
    facts: &TransportFacts,
) -> Result<Frame, PortFailure> {
    let mut frame =
        host_request_frame_for_envelope(AGENT_HOST_REQUEST_INVOKE_READ_OPERATION, envelope, facts)?;
    let tool = serde_json::to_value(&request.tool).map_err(|_| request_failure())?;
    let ProtocolPayload::Json(payload) = &mut frame.payload else {
        return Err(request_failure());
    };
    payload["tool"] = tool;
    frame.validate().map_err(|_| request_failure())?;
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
    // A result pair where none belongs (or a half-present pair) fails
    // decoding into the unknown-outcome path: the bridge never guesses which
    // half to trust. `RESULT_RECEIVED` must carry both; a `TERMINAL` may
    // carry both forward; every other state must carry neither.
    let carries_result =
        record.result_digest.is_some() || record.result_response.is_some();
    match (&record.state, carries_result) {
        (HostRequestRecordState::ResultReceived | HostRequestRecordState::Terminal, true)
        | (_, false) => {}
        _ => return None,
    }
    if let (Some(digest), Some(body)) = (&record.result_digest, &record.result_response) {
        HostRequestResultBody {
            wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
            wire_version: HostRequestResultBody::CONTRACT_VERSION,
            operation_id: record.operation_id.clone(),
            request_sha256: envelope.envelope_sha256.clone(),
            result_digest: digest.clone(),
            response: body.clone(),
            // Readback coherence only: stored rows predate attempt ownership,
            // so no attempt is presented here. Submissions always carry the
            // current attempt, enforced by the Kernel legs.
            attempt: None,
        }
        .validate()
        .ok()?;
    }
    Some((receipt, record))
}

/// Builds the typed rejection for a result-bearing reply whose body does not
/// bind the admitted request.
fn invalid_result(detail: &str) -> PortFailure {
    PortFailure::TransportBindingRejected {
        reason: format!("kernel result body is not the admitted answer: {detail}"),
    }
}

/// Decodes one stored bounded response and checks it against the admitted
/// request (Implements #18: local read result).
///
/// Mirrors `host_gateway.rs:406-436` (bounded size, tool binding) plus the
/// `check_response_binding` semantics (request/idempotency/tool/digest joins
/// against the exact sent envelope). Any mismatch is a typed rejection, never
/// a guessed outcome and never a silent admission.
fn decode_stored_response(
    record: &AdmittedReplyView,
    request: &HostInvocationRequest,
    envelope: &HostRequestEnvelope,
) -> Result<McpResponse, PortFailure> {
    let body = record.result_response.clone().ok_or_else(|| {
        invalid_result("a received result must carry its bounded body")
    })?;
    let encoded = serde_json::to_vec(&body).map_err(|_| invalid_result("unserializable body"))?;
    if encoded.len() > HARD_STRUCTURED_RESPONSE_BYTES {
        return Err(invalid_result("body exceeds the bounded ceiling"));
    }
    let response: McpResponse =
        serde_json::from_value(body).map_err(|_| invalid_result("body is not a bounded response"))?;
    if response.request_id != envelope.identity.request_id.as_str() {
        return Err(invalid_result("request identity mismatch"));
    }
    if response.idempotency_key != envelope.identity.idempotency_key {
        return Err(invalid_result("idempotency binding mismatch"));
    }
    if response.canonical_tool_name != request.tool.canonical_name() {
        return Err(invalid_result("tool binding mismatch"));
    }
    if response.canonical_request_sha256.len() != 64
        || !response
            .canonical_request_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid_result("response digest mismatch"));
    }
    let digest = record
        .result_digest
        .clone()
        .ok_or_else(|| invalid_result("a received result must carry its digest"))?;
    let bytes = canonical_json_bytes(&response).map_err(|_| invalid_result("uncanonicalizable"))?;
    if sha256_hex(&bytes) != digest {
        return Err(invalid_result("digest does not bind the exact body"));
    }
    Ok(response)
}

fn submit_outcome(
    receipt: &HostRequestAdmissionReceipt,
    record: &AdmittedReplyView,
    request: &HostInvocationRequest,
    envelope: &HostRequestEnvelope,
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
        | HostRequestRecordState::Reconciling => Ok(HostInvocationPortOutcome::Accepted {
            operation_handle: handle,
        }),
        // A received result with a valid body answers inline; a received
        // result without one (or with a forged one) fails closed instead of
        // degrading to a bare admission that would lose the answer.
        HostRequestRecordState::ResultReceived => {
            let response = decode_stored_response(record, request, envelope)?;
            Ok(HostInvocationPortOutcome::Responded {
                operation_handle: handle,
                response: Box::new(response),
            })
        }
        HostRequestRecordState::Expired => Err(PortFailure::DeadlineExceeded),
        HostRequestRecordState::Cancelled => Err(PortFailure::Cancelled),
        HostRequestRecordState::Terminal => {
            if record.result_digest.is_some() {
                let response = decode_stored_response(record, request, envelope)?;
                return Ok(HostInvocationPortOutcome::Responded {
                    operation_handle: handle,
                    response: Box::new(response),
                });
            }
            Err(PortFailure::TransportBindingRejected {
                reason: "operation is already terminal; reconcile the exact operation".to_owned(),
            })
        }
        HostRequestRecordState::Conflicted => Err(PortFailure::TransportBindingRejected {
            reason: "operation is already terminal; reconcile the exact operation".to_owned(),
        }),
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
            // expiry. A failed probe leaves delivery unknown -- the response
            // may already be completed kernel-side -- so the probe's
            // unknown-outcome error is returned unchanged and MUST NOT be
            // rewritten into DeadlineExceeded. Only the Kernel-owned Expired
            // record state maps to an owner timeout.
            return self.probe_settles_invocation(&facts, &session, &envelope, now_ms);
        }
        let frame = if invokes_local_read(request) {
            host_request_invoke_read_frame(request, &envelope, &facts)?
        } else {
            host_request_frame_for_envelope(AGENT_HOST_REQUEST_SUBMIT_OPERATION, &envelope, &facts)?
        };
        let Ok(reply) = self.exchange(&frame) else {
            return self.probe_settles_invocation(&facts, &session, &envelope, now_ms);
        };
        match decode_admitted_reply(&reply, &envelope) {
            Some((receipt, record)) => submit_outcome(&receipt, &record, request, &envelope),
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

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test fixtures use expect for fail-fast setup"
)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    const INVOCATION_JSON: &str = r#"{
        "protocol_version":"2026-07-28",
        "correlation_id":"host-request-1",
        "client_capabilities":{"tasks":false},
        "tool":{"name":"eliot.state","arguments":{"include":["task"]}},
        "deadline_preference_ms":5000,
        "observed_context":{
            "host_session_hint":"host-turn-1",
            "observed_resource_refs":[],
            "event_cursors":[],
            "trace_context":{}
        }
    }"#;

    fn test_facts(connection_id: &str) -> TransportFacts {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::new(3).expect("nonzero test sequence"),
        )
        .expect("valid test epoch");
        TransportFacts {
            connection_id: connection_id.to_owned(),
            state_fence: StateFence::new(
                epoch,
                ResourceGeneration::new(7).expect("nonzero test generation"),
            ),
            descriptor_sha256: "d".repeat(64),
            receipt_sha256: "e".repeat(64),
            session: Some("kernel-session-1".to_owned()),
        }
    }

    fn test_envelope() -> (HostInvocationRequest, TransportFacts, HostRequestEnvelope) {
        let request: HostInvocationRequest =
            serde_json::from_str(INVOCATION_JSON).expect("fixture must deserialize");
        let facts = test_facts("conn-test-1");
        let payload_digest =
            canonical_payload_digest(&request.tool).expect("payload digest must compute");
        let envelope = build_invocation_envelope(
            &request,
            &facts,
            "kernel-session-1",
            &payload_digest,
            1_000_000,
        )
        .expect("envelope must build");
        (request, facts, envelope)
    }

    fn admitted_reply_frame(
        envelope: &HostRequestEnvelope,
        receipt: &HostRequestAdmissionReceipt,
    ) -> Frame {
        admitted_reply_frame_with_state(envelope, receipt, "ADMITTED", None, None)
    }

    fn admitted_reply_frame_with_state(
        envelope: &HostRequestEnvelope,
        receipt: &HostRequestAdmissionReceipt,
        state: &str,
        result_digest: Option<&str>,
        result_response: Option<&serde_json::Value>,
    ) -> Frame {
        Frame {
            protocol_version: ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: envelope.connection_id.clone(),
            request_id: Some(envelope.identity.request_id.clone()),
            kind: FrameKind::Response,
            message_type: MessageType::Result,
            request_identity: None,
            payload: ProtocolPayload::Json(serde_json::json!({
                "status": "known",
                "value": {
                    "accepted": true,
                    "receipt": serde_json::to_value(receipt).expect("receipt must serialize"),
                    "record": {
                        "operation_id": receipt.operation_id,
                        "state": state,
                        "result_digest": result_digest,
                        "result_response": result_response,
                    },
                },
            })),
            trace_context: BTreeMap::new(),
        }
    }

    fn stored_test_response(envelope: &HostRequestEnvelope) -> (serde_json::Value, String) {
        let body = serde_json::json!({
            "request_id": envelope.identity.request_id.as_str(),
            "idempotency_key": envelope.identity.idempotency_key,
            "canonical_request_sha256": "a".repeat(64),
            "kind": "PROJECTION",
            "canonical_tool_name": "eliot.state",
            "content": {
                "operation": "GetEvidencePack",
                "evidence_pack": {"task": "bounded-state"},
                "revision_heads": [{"key": "scope:scope-1", "revision": 3}],
            },
            "artifacts": [],
            "proof_ceiling": "SCOPED_VERIFICATION",
            "resource": null,
            "job": null,
        });
        let digest = sha256_hex(
            &canonical_json_bytes(
                &serde_json::from_value::<McpResponse>(body.clone())
                    .expect("test body must decode"),
            )
            .expect("test body must canonicalize"),
        );
        (body, digest)
    }

    #[test]
    fn invocation_envelope_binds_kernel_session_and_neutral_identity() {
        let (request, facts, envelope) = test_envelope();
        assert_eq!(envelope.connection_id, "conn-test-1");
        assert_eq!(
            envelope.identity.session_id.as_deref(),
            Some("kernel-session-1")
        );
        assert!(envelope.identity.task_id.is_none());
        assert!(envelope.identity.work_scope_id.is_none());
        assert_eq!(
            envelope.identity.idempotency_key,
            format!("{}:invoke", request.correlation_id.as_str())
        );
        assert!(envelope.identity.parent_operation_id.is_none());
        assert_eq!(envelope.identity.capability, request.tool.canonical_name());
        assert_eq!(envelope.identity.request_id.as_str(), "host-request-1");
        assert!(facts.session.is_some());
        envelope.validate().expect("built envelope must validate");
        let empty: Result<HostInvocationRequest, _> =
            serde_json::from_str(&INVOCATION_JSON.replace("host-request-1", ""));
        assert!(
            empty.is_err(),
            "empty correlation must not deserialize into a dispatchable request"
        );
    }

    #[test]
    fn foreign_or_malformed_cancel_handle_rejected_without_wire() {
        let (_, _, envelope) = test_envelope();
        let handle = host_request_operation_id(&envelope);
        let digest = parse_operation_handle(&handle).expect("kernel handle must parse");
        assert_eq!(digest, envelope.envelope_sha256);
        assert!(
            parse_operation_handle(&format!("foreign:{digest}")).is_err(),
            "foreign prefix must be rejected without wire use"
        );
        assert!(
            parse_operation_handle(&digest).is_err(),
            "missing prefix must be rejected without wire use"
        );
        assert!(
            parse_operation_handle(&format!("hostreq:{}", "A".repeat(64))).is_err(),
            "uppercase digest must be rejected without wire use"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the updated outcome contract covers every state plus forgery cases contiguously"
    )]
    fn stale_reply_decodes_unknown_and_states_map_typed() {
        let (_, facts, envelope) = test_envelope();
        let receipt = HostRequestAdmissionReceipt::issue(&envelope).expect("receipt must issue");
        let reply = admitted_reply_frame(&envelope, &receipt);
        let (decoded_receipt, decoded_record) =
            decode_admitted_reply(&reply, &envelope).expect("valid reply must decode");
        assert_eq!(decoded_receipt.operation_id, receipt.operation_id);
        assert_eq!(decoded_record.operation_id, receipt.operation_id);

        let mut foreign_connection = reply.clone();
        foreign_connection.connection_id = "foreign-conn".to_owned();
        assert!(
            decode_admitted_reply(&foreign_connection, &envelope).is_none(),
            "wrong connection must decode to unknown"
        );

        let mut wrong_request = reply.clone();
        wrong_request.request_id =
            Some(RequestId::new("other-correlation").expect("valid test request id"));
        assert!(
            decode_admitted_reply(&wrong_request, &envelope).is_none(),
            "wrong request id must decode to unknown"
        );

        let request_frame =
            host_request_frame_for_envelope(AGENT_HOST_REQUEST_SUBMIT_OPERATION, &envelope, &facts)
                .expect("request frame must build");
        let mut with_identity = reply.clone();
        with_identity.request_identity = request_frame.request_identity.clone();
        assert!(
            with_identity.request_identity.is_some(),
            "fixture must carry a real request identity"
        );
        assert!(
            decode_admitted_reply(&with_identity, &envelope).is_none(),
            "present request identity must decode to unknown"
        );

        let sibling_request: HostInvocationRequest =
            serde_json::from_str(INVOCATION_JSON).expect("fixture must deserialize");
        let sibling = build_invocation_envelope(
            &sibling_request,
            &facts,
            "kernel-session-1",
            &"b".repeat(64),
            1_000_000,
        )
        .expect("sibling envelope must build");
        assert_eq!(
            sibling.identity.request_id, envelope.identity.request_id,
            "sibling keeps the same request identity"
        );
        assert_ne!(
            sibling.envelope_sha256, envelope.envelope_sha256,
            "sibling carries a different digest"
        );
        assert!(
            decode_admitted_reply(&reply, &sibling).is_none(),
            "digest mismatch must decode to unknown"
        );

        let record_for = |state| AdmittedReplyView {
            operation_id: receipt.operation_id.clone(),
            state,
            result_digest: None,
            result_response: None,
        };
        let (request_for_outcome, _, envelope_for_outcome) = test_envelope();
        let outcome_for = |state| {
            submit_outcome(
                &receipt,
                &record_for(state),
                &request_for_outcome,
                &envelope_for_outcome,
            )
        };
        assert!(matches!(
            outcome_for(HostRequestRecordState::Expired),
            Err(PortFailure::DeadlineExceeded)
        ));
        assert!(matches!(
            outcome_for(HostRequestRecordState::Cancelled),
            Err(PortFailure::Cancelled)
        ));
        for state in [
            HostRequestRecordState::Conflicted,
            HostRequestRecordState::Terminal,
        ] {
            match outcome_for(state) {
                Err(PortFailure::TransportBindingRejected { reason }) => {
                    assert!(
                        reason.contains("terminal"),
                        "terminal rejection must name reconciliation"
                    );
                }
                other => panic!("expected terminal rejection, got {other:?}"),
            }
        }
        // New contract (Implements #18): a bare `RESULT_RECEIVED` with no body
        // fails closed instead of degrading to a bare admission that would
        // lose the answer. The old pin asserting `Accepted` here is replaced
        // by this rejection plus the valid-body `Responded` case below; the
        // test is updated to the new contract, never deleted.
        match outcome_for(HostRequestRecordState::ResultReceived) {
            Err(PortFailure::TransportBindingRejected { .. }) => {}
            other => panic!("expected fail-closed rejection for bodyless result, got {other:?}"),
        }
        // A received result with its exact bounded body answers inline with
        // the payload and revision verbatim.
        let (request, _, envelope) = test_envelope();
        let (body, digest) = stored_test_response(&envelope);
        let received = AdmittedReplyView {
            operation_id: receipt.operation_id.clone(),
            state: HostRequestRecordState::ResultReceived,
            result_digest: Some(digest.clone()),
            result_response: Some(body.clone()),
        };
        match submit_outcome(&receipt, &received, &request, &envelope) {
            Ok(HostInvocationPortOutcome::Responded {
                operation_handle,
                response,
            }) => {
                assert_eq!(operation_handle.as_str(), receipt.operation_id.as_str());
                assert_eq!(response.request_id, "host-request-1");
                assert_eq!(response.canonical_tool_name, "eliot.state");
                assert_eq!(response.content["revision_heads"][0]["revision"], 3);
            }
            other => panic!("expected inline responded outcome, got {other:?}"),
        }
        // A forged body or digest under the same identity is rejected before
        // anything is served.
        let forged_body = AdmittedReplyView {
            result_response: Some(serde_json::json!({"forged": true})),
            ..received.clone()
        };
        assert!(
            submit_outcome(&receipt, &forged_body, &request, &envelope).is_err(),
            "forged body must be rejected before serving"
        );
        let forged_digest = AdmittedReplyView {
            result_digest: Some("0".repeat(64)),
            ..received.clone()
        };
        assert!(
            submit_outcome(&receipt, &forged_digest, &request, &envelope).is_err(),
            "forged digest must be rejected before serving"
        );
        // A result pair where none belongs never decodes to an outcome.
        let admitted_with_body = AdmittedReplyView {
            state: HostRequestRecordState::Admitted,
            ..received.clone()
        };
        let admitted_reply = admitted_reply_frame_with_state(
            &envelope,
            &receipt,
            "ADMITTED",
            admitted_with_body.result_digest.as_deref(),
            admitted_with_body.result_response.as_ref(),
        );
        assert!(
            decode_admitted_reply(&admitted_reply, &envelope).is_none(),
            "a body on a live state must decode to unknown"
        );
        // The result-bearing reply itself decodes with its digest binding.
        let result_reply = admitted_reply_frame_with_state(
            &envelope,
            &receipt,
            "RESULT_RECEIVED",
            Some(digest.as_str()),
            Some(&body),
        );
        let (_, decoded_result) =
            decode_admitted_reply(&result_reply, &envelope).expect("result reply must decode");
        assert_eq!(decoded_result.state, HostRequestRecordState::ResultReceived);
        assert!(decoded_result.result_digest.is_some());
    }

    #[test]
    fn local_read_tools_ride_invoke_read_with_tool_bytes() {
        let (request, facts, envelope) = test_envelope();
        assert!(
            !invokes_local_read(&request),
            "eliot.state keeps the admission-only submit entry"
        );
        for tool_json in [
            serde_json::json!({"name":"eliot.query","arguments":{
                "intent":{
                    "mode":"verification",
                    "time_scope":"session-window",
                    "branch_environment_scope":"branch",
                    "freshness_policy":"exact-fence",
                    "required_assurance":"evidence-provenance"
                },
                "query":"subject:evidence-alpha",
                "exact_resource_uri": null
            }}),
            serde_json::json!({"name":"eliot.packet","arguments":{
                "packet_ref": null,
                "material_refs": []
            }}),
        ] {
            let mut value = serde_json::to_value(&request).expect("request must serialize");
            value["tool"] = tool_json;
            let read_request: HostInvocationRequest =
                serde_json::from_value(value).expect("read request must deserialize");
            read_request.validate().expect("read request must validate");
            assert!(
                invokes_local_read(&read_request),
                "query and packet ride the invoke-read entry"
            );
            let frame = host_request_invoke_read_frame(&read_request, &envelope, &facts)
                .expect("invoke-read frame must build");
            let payload = match &frame.payload {
                ProtocolPayload::Json(payload) => payload.clone(),
                _ => panic!("invoke-read frame must carry JSON"),
            };
            assert_eq!(
                payload.get("operation").and_then(|operation| operation.as_str()),
                Some(AGENT_HOST_REQUEST_INVOKE_READ_OPERATION)
            );
            let tool = payload.get("tool").expect("invoke-read frame must carry tool bytes");
            assert_eq!(
                tool.get("name").and_then(|name| name.as_str()),
                Some(read_request.tool.canonical_name())
            );
        }
    }
}
