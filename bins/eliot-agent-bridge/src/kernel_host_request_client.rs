//! Kernel host-request client — typed host-request envelopes over the shared admitted transport.
//!
//! Architecture: A12 (Security, provenance and bounded influence), A13.2 (Kernel and failure
//! domains), ARCH-AUTH-01 (explicit, scoped, fenced authority), ARCH-SEC-02 (one canonical
//! transition path), ARCH-RES-01 (fail locally, recover globally) — the client remains neutral,
//! bounded, and fail-closed, carrying only kernel-issued connection/session/fence facts with no
//! Kernel, Governor, or Store authority of its own.
//!
//! Implementation: I7.1/I7.2 (typed frames over the admitted front-door transport, never raw
//! frame ingress) and I7.20 (typed outcomes only; no prose drives routing) — host-request
//! envelopes ride `Request`/`Execute` frames whose payload selects the closed kernel entry
//! (`agent_host_request_submit`, `agent_host_request_cancel`,
//! `agent_host_request_reconcile`, or `agent_host_request_rehydrate`). Live binding status uses
//! the existing `Heartbeat`/`Health` frame. Host-request replies are decoded with the same
//! connection/digest/fence joins as the activation path.
//!
//! Ownership: this module is the sole owner of the invocation/cancellation/reconciliation/
//! rehydration envelope builders, the envelope frame builder, the admitted-reply decoder
//! (submit-family and receipt-less rehydrate shapes), the replay-cache
//! entry shape, resource-source owner resolves, and the production
//! `KernelHostRequestPort` impl. Non-ownership: activation,
//! kernel admission/dispatch, gateway validation/correlation, and any durable ledger.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::{
    ClockReading, HostCorrelationDomain, HostCorrelationProjection, HostJsonRpcCorrelationId,
    HostRequestLogicalKind, ProductId, RequestId, RequestMetadata, SourceId, StateFence,
    canonical_json_bytes, host_request_legacy_presence_key, host_request_logical_key, sha256_hex,
};
use eliot_kernel_core::KernelRuntimeHealthEvidence;
use eliot_mcp::{
    HostCancellationPortOutcome, HostCancellationRequest, HostInvocationPortOutcome,
    HostInvocationRequest, HostOperationHandle, KernelHostRequestPort, McpResponse, PortFailure,
    ToolRequest,
};
use eliot_protocol::{
    AgentHostRequestFailure, EncodingProfile, FINISH_INVOKE_PAYLOAD_SCHEMA_ID, Frame, FrameKind,
    HARD_STRUCTURED_RESPONSE_BYTES, HOST_REQUEST_RESULT_BODY_WIRE_ID, HOST_REQUEST_WIRE_ID,
    HostRequestAdmissionReceipt, HostRequestEnvelope, HostRequestIdentity, HostRequestKind,
    HostRequestResultBody, HostRequestResultClass, HostRequestResultLineage, MessageType,
    ProtocolPayload, ProtocolVersion, REACTIVE_RESTORE_CAPABILITY, REACTIVE_RESTORE_OPERATION,
    REACTIVE_RESTORE_PAYLOAD_SCHEMA_ID, ReactiveRestoreQuery, ReactiveRestoreReply,
    RequestIdentity, host_request_operation_id, restore_correlation,
};
use eliot_receipts::RequestBinding;
use serde::Deserialize;

use crate::{ActivatedTaskBinding, KernelTransportOwner, SharedTransport};

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
/// Closed kernel entry that rehydrates one exact previously admitted operation
/// from the durable record without resubmission.
///
/// Owned by `bins/eliot-kernel/src/host_request_route.rs`
/// (`AGENT_HOST_REQUEST_REHYDRATE_OPERATION`); the literal is repeated here
/// because the constant is `pub(crate)` to that binary and this crate takes
/// no new dependencies. The frame carries the exact (envelope,
/// admission-receipt) pair the kernel admitted; the typed answer is the
/// durable record only, with no new receipt and no state advance.
const AGENT_HOST_REQUEST_REHYDRATE_OPERATION: &str = "agent_host_request_rehydrate";
/// Closed kernel entry that resolves one logical host request or one exact
/// operation handle without staging or dispatch (issue #2571).
///
/// Owned by `bins/eliot-kernel/src/host_request_route.rs` (resolve dispatch
/// arm); the literal is repeated here because that constant will be
/// `pub(crate)` to that binary and this crate takes no new dependencies. The
/// entry is lookup-only: it never stages a row, issues a receipt, advances
/// state, or runs provider work. It answers the two query forms built by
/// [`host_request_resolve_frame`] with either the durable record in the
/// existing rehydrated shape (no new receipt) or an explicit
/// `accepted:false` resolve value (`absent` or `conflict`). Any transport or
/// store failure surfaces as a transport failure, never as absence.
const AGENT_HOST_REQUEST_RESOLVE_OPERATION: &str = "agent_host_request_resolve";
/// Closed kernel entry that previews one invocation dry run without staging
/// or dispatch (issue #1939, I7.17).
///
/// Owned by `bins/eliot-kernel/src/host_request_route.rs`
/// (`AGENT_HOST_REQUEST_PREVIEW_OPERATION`); the literal is repeated here
/// because that constant is `pub(crate)` to that binary and this crate takes
/// no new dependencies. The entry runs the existing invoke-read validator
/// over the presented envelope plus canonical tool bytes and answers the
/// exact preview with its source/currentness ceiling, or the typed
/// unsupported value when the tool has no serving read lane. It never stages
/// a row, issues a receipt, advances state, or runs provider work.
const AGENT_HOST_REQUEST_PREVIEW_OPERATION: &str = "agent_host_request_preview";
/// Owner preview source the kernel preview entry emits on every answer.
///
/// Repeated here because the kernel constant is `pub(crate)` to that binary;
/// a preview reply carrying any other source fails closed as undecodable, so
/// the caller keeps the local static fallback.
const OWNER_DRY_RUN_PREVIEW_SOURCE: &str = "kernel-owner-preview.v1";
/// Canonical prefix of the kernel-derived opaque operation handle.
const HOST_REQUEST_OPERATION_ID_PREFIX: &str = "hostreq:";
/// Filler capability carried only on handle-form resolve envelopes
/// (issue #2571).
///
/// The owner ignores it: handle-form lookup loads by exact handle and
/// checks ownership and rights, never binding these echoes. It exists only
/// because the envelope shape requires a non-empty capability; it is never
/// staged, never receipted, and the resolve entry must never bind it.
const RESOLVE_HANDLE_CAPABILITY_FILLER: &str = "eliot.resolve.lookup";
/// Filler payload digest carried only on handle-form resolve envelopes
/// (issue #2571).
///
/// Sixty-four zeros, which is never a real payload digest. Same
/// never-bind contract as [`RESOLVE_HANDLE_CAPABILITY_FILLER`].
const RESOLVE_HANDLE_PAYLOAD_FILLER: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
/// Exact payload-schema identity for the canonical `ToolRequest` bytes.
const HOST_REQUEST_PAYLOAD_SCHEMA_ID: &str = "eliot.mcp.tool-request.v1";
/// Bridge-proposed relative deadline when the host states no preference.
/// Added to the local clock to form the submitted absolute deadline. The
/// Kernel enforces expiry at admission but neither re-derives nor clamps
/// the submitted value, so Kernel-issued absolute-deadline ownership stays
/// open contract work under issue #77 (`wave_1_kernel_contract`).
const DEFAULT_DEADLINE_PREFERENCE_MS: u64 = 60_000;

/// Gateway-side face of the single retained transport owner.
///
/// Holds no transport of its own: every call borrows the shared owner, so the
/// admitted transport, runtime, receipt facts, and activation session stay
/// singular while the activation face serves the one-shot exchange beside it.
///
/// `pub` for the binary composition root only: the bridge binary threads this
/// concrete client into its reconnect path to prove the live Kernel binding
/// before mutating local attach state. Construction stays inside this crate.
pub struct KernelHostRequestClient {
    pub(super) shared: SharedTransport,
}

/// Non-durable replay entry: one host correlation bound to its exact envelope.
///
/// Process memory only; it dies with this bridge process, which spans exactly
/// one admitted connection. An exact replay resends byte-identical envelopes
/// so the kernel deduplicates by digest; a changed payload under a known
/// correlation never reaches the wire. The cache is an optimization only:
/// on a miss the owner is asked to resolve the logical key (issue #2571)
/// before any fresh envelope is built, so a restarted Bridge still
/// converges on the original operation instead of dispatching twice.
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
    /// The task and `WorkScope` the same activation resolved (#2857).
    ///
    /// `None` before a `Resolved` activation, exactly like `session`. This is
    /// the authenticated identity an invocation envelope binds; it is never
    /// read from host request text and never defaulted.
    pub(super) task_binding: Option<ActivatedTaskBinding>,
}

/// Exact owner-derived facts retained beside one bridge-local resource URI.
///
/// This is only a local comparison commitment. Every read repeats an
/// operation-handle resolve under the current transport and compares the
/// complete owner result and attach binding before allowing registry
/// expansion; the digest itself never grants authority.
#[derive(serde::Serialize)]
struct ResourceAuthorizationPreimage<'a> {
    version: &'static str,
    operation_handle: &'a str,
    connection_id: &'a str,
    session_id: &'a str,
    state_fence: &'a StateFence,
    descriptor_sha256: &'a str,
    receipt_sha256: &'a str,
    request_digest: &'a str,
    request_id: &'a str,
    capability: &'a str,
    payload_digest: &'a str,
    result_digest: &'a str,
    result_response: &'a serde_json::Value,
    /// The result class the owner recorded for these exact bytes (issue #1809
    /// item 7).
    ///
    /// Carried as the owner's own wire spelling, rendered through the protocol
    /// crate's `Serialize` derive, so the authorization binding commits to the
    /// recorded claim verbatim rather than to a bridge-local projection of it. A
    /// resource captured under one recorded provenance claim therefore cannot be
    /// expanded under a different one: the class is part of what the read
    /// re-proves, which is what keeps a candidate-versus-admitted distinction
    /// from being decided by the resource surface's own memory.
    result_class: String,
    task_ref: Option<&'a str>,
    scope_ref: Option<&'a str>,
}

/// Renders one result class in the exact wire spelling the durable row carries
/// (issue #1809 item 7).
///
/// The class is an owner claim about provenance, so the authorization preimage
/// must bind the OWNER's spelling of it. This serializes through the protocol
/// crate's own `Serialize` derive instead of repeating a mapping here: a
/// hand-written table would be a second place to forget a variant, and a
/// mismatch would silently bind a different string than the row records.
fn result_class_wire_name(class: HostRequestResultClass) -> Result<String, PortFailure> {
    serde_json::to_value(class)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(request_failure)
}

/// Exact parent reference resolved from the replay cache for cancel/probe envelopes.
struct ParentLink {
    handle: String,
    capability: String,
    payload_digest: String,
    request_base: String,
    correlation_projection: Option<HostCorrelationProjection>,
}

impl ParentLink {
    fn of(envelope: &HostRequestEnvelope) -> Self {
        Self {
            handle: host_request_operation_id(envelope),
            capability: envelope.identity.capability.clone(),
            payload_digest: envelope.identity.payload_sha256.clone(),
            request_base: envelope.identity.request_id.as_str().to_owned(),
            correlation_projection: envelope.identity.correlation_projection.clone(),
        }
    }

    /// Rebuilds the exact parent reference from an owner-resolved durable
    /// record (issue #2571: cancellation/status across Bridge restart).
    ///
    /// Called only with a record the resolve entry returned for the exact
    /// queried handle under the current session: the capability and payload
    /// come from durable owner state, never from host text and never from a
    /// guessed default, so the cancellation envelope binds the original
    /// commitment instead of inventing one.
    fn from_owner_record(
        handle: &str,
        capability: &str,
        payload_digest: &str,
        request_base: &str,
        correlation_projection: HostCorrelationProjection,
    ) -> Result<Self, PortFailure> {
        if handle.is_empty()
            || capability.trim().is_empty()
            || capability.chars().any(char::is_control)
            || request_base.trim().is_empty()
            || request_base.chars().any(char::is_control)
        {
            return Err(unknown_handle());
        }
        if payload_digest.len() != 64
            || !payload_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(unknown_handle());
        }
        if correlation_projection.domain() != HostCorrelationDomain::Request
            || correlation_projection.validate().is_err()
            || reject_kernel_operational_correlation(&correlation_projection).is_err()
        {
            return Err(unknown_handle());
        }
        Ok(Self {
            handle: handle.to_owned(),
            capability: capability.to_owned(),
            payload_digest: payload_digest.to_owned(),
            request_base: request_base.to_owned(),
            correlation_projection: Some(correlation_projection),
        })
    }
}

/// Derives the logical key for one invocation replay lookup.
///
/// The occurrence is the request correlation; the bridge carries no
/// task/scope authority of its own. The logical key is scoped to the
/// authenticated session and typed projection; task, scope, payload and
/// parent are compared as the owner's durable commitment, so a changed
/// binding conflicts instead of creating a second operation. The key bytes
/// come from the shared canonical encoder
/// (`eliot_contracts::host_request_logical_key`): the bridge owns no key
/// recipe of its own.
fn logical_invocation_key(
    projection: &HostCorrelationProjection,
    session: &str,
) -> Result<String, PortFailure> {
    if projection.domain() != HostCorrelationDomain::Request {
        return Err(request_failure());
    }
    reject_kernel_operational_correlation(projection)?;
    projection.validate().map_err(|_| request_failure())?;
    host_request_logical_key(HostRequestLogicalKind::Invocation, session, projection)
        .map_err(|_| request_failure())
}

/// Derives the logical key for one cancellation intent.
///
/// The cancellation's typed projection and session identify its retained
/// intent. Its original parent handle and commitment are checked against the
/// owner result; they do not alter the logical key. Key bytes come from the
/// shared canonical encoder: the bridge owns no key recipe of its own.
fn logical_cancellation_key(
    projection: &HostCorrelationProjection,
    session: &str,
) -> Result<String, PortFailure> {
    projection.validate().map_err(|_| request_failure())?;
    host_request_logical_key(HostRequestLogicalKind::Cancellation, session, projection)
        .map_err(|_| request_failure())
}
///
/// Minimal tolerant view of the kernel-returned durable record.
///
/// Only the operation join, the state, and the optional result pair matter
/// here; every other record field is kernel-owned progression the bridge
/// never interprets. An unknown future state fails decoding, which fails
/// closed into the unknown-outcome path. `result_digest`/`result_response`
/// ride the record for `RESULT_RECEIVED` (and a `TERMINAL` carrying a result
/// forward); any other state carrying them fails decoding the same way.
///
/// `pub(crate)` so the composition caller driving `rehydrate_operation` can
/// read the exact durable state the Kernel owner returned; the bridge still
/// interprets nothing beyond this join.
///
/// The commitment tail (`request_digest` and below) is `None` on legacy
/// submit-family replies and `Some` wherever the Kernel serves the full
/// durable row (notably the resolve entry, issue #2571): the bridge
/// verifies a resolved record against the requested logical key from these
/// exact fields before adopting its handle, state, or result.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct AdmittedReplyView {
    pub(crate) operation_id: String,
    pub(crate) state: HostRequestRecordState,
    #[serde(default)]
    pub(crate) result_digest: Option<String>,
    #[serde(default)]
    pub(crate) result_response: Option<serde_json::Value>,
    /// Digest of the exact admitted envelope (`Some` on full-row replies).
    #[serde(default)]
    pub(crate) request_digest: Option<String>,
    /// Closed durable kind (`INVOCATION`, `CANCELLATION`, ...) on full rows.
    #[serde(default)]
    pub(crate) kind: Option<String>,
    /// Stable client occurrence on full rows.
    #[serde(default)]
    pub(crate) request_id: Option<String>,
    /// Exact typed correlation projection on marked durable rows.
    #[serde(default)]
    pub(crate) correlation_projection: Option<HostCorrelationProjection>,
    /// Exact targeted parent handle on full child rows.
    #[serde(default)]
    pub(crate) parent_operation_id: Option<String>,
    /// Kernel-issued session continuity on full rows.
    #[serde(default)]
    pub(crate) session_ref: Option<String>,
    /// Governor task binding (or absent for admitted-unbound) on full rows.
    #[serde(default)]
    pub(crate) task_ref: Option<String>,
    /// Governor scope binding (or absent for admitted-unbound) on full rows.
    #[serde(default)]
    pub(crate) scope_ref: Option<String>,
    /// Exact capability on full rows.
    #[serde(default)]
    pub(crate) capability_ref: Option<String>,
    /// Exact payload commitment on full rows.
    #[serde(default)]
    pub(crate) payload_digest: Option<String>,
    /// Retained result lineage the Kernel bound to this row's own result
    /// (issue #1809 items 2 and 7). Decoded as the SHARED
    /// [`HostRequestResultLineage`] contract, not as a local projection of it:
    /// the durable row serialises exactly those fields, so the bridge reads the
    /// same owner rule a submission and the Kernel replay leg read, instead of
    /// re-deciding the class/receipt relationship in a second dialect.
    ///
    /// `None` on a row that predates retained lineage. That stays an explicit
    /// unknown rather than defaulting to allowed: the resource surfaces below
    /// refuse an absent lineage outright, and an unknown class never presents
    /// as an admitted record.
    #[serde(default)]
    pub(crate) result_lineage: Option<HostRequestResultLineage>,
}

/// Mirror of the kernel-owned durable host-request states for outcome mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum HostRequestRecordState {
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

fn retain_agent_response(error: PortFailure, fallback: PortFailure) -> PortFailure {
    match error {
        response @ PortFailure::AgentResponse { .. } => response,
        _ => fallback,
    }
}

fn resource_source_refused() -> PortFailure {
    PortFailure::TransportBindingRejected {
        reason: "resource source is not authorized by the current Kernel attach".to_owned(),
    }
}

fn reject_kernel_operational_correlation(
    projection: &HostCorrelationProjection,
) -> Result<(), PortFailure> {
    if matches!(
        projection,
        HostCorrelationProjection::KernelOperational { .. }
    ) {
        return Err(PortFailure::TransportBindingRejected {
            reason: "Kernel operational correlation is not admitted on host transport".to_owned(),
        });
    }
    Ok(())
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

/// Builds the typed recovery limitation for a resolve with no durable
/// answer (issue #2571).
///
/// Returned when the owner lookup itself is unavailable — a failed
/// exchange, an undecodable reply, or a record that cannot be verified
/// against the requested commitment. It names the logical key so the
/// operator can reconcile that exact request, and it never authorizes a
/// fresh operation: store/readback failure cannot become absence or a safe
/// retry.
fn unknown_resolve_outcome(logical_key: &str) -> PortFailure {
    PortFailure::TransportBindingRejected {
        reason: format!(
            "host-request resolve left an unknown outcome for logical key {logical_key}; re-attach and reconcile it before retrying as a new occurrence"
        ),
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
            task_binding: self.activated_task_binding.clone(),
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
        let reply = self.runtime.block_on(async {
            self.admitted
                .transport
                .receive_frame(self.limits)
                .await
                .map_err(|_| request_failure())
        })?;
        if let Some(failure) = decode_host_request_failure(&reply, frame) {
            return Err(PortFailure::AgentResponse {
                failure: Box::new(failure),
            });
        }
        // The Kernel already reported non-success for this exact request, but
        // its failure envelope failed validation. Fail closed with a typed
        // rejection instead of reconciling toward a possible false success.
        if is_correlated_failure_reply(&reply, frame) {
            return Err(undecodable_failure_reply());
        }
        Ok(reply)
    }
}

/// Reports whether one reply is a correlated failure for the exact request
/// even when its canonical failure envelope failed validation.
///
/// The correlation joins mirror [`decode_host_request_failure`]: a response
/// for this exact request identity, protocol version, and connection whose
/// payload carries `status: "failure"`. Such a reply is never decoded as a
/// success and never reconciled as an unknown delivery.
fn is_correlated_failure_reply(reply: &Frame, request: &Frame) -> bool {
    reply.validate().is_ok()
        && request.validate().is_ok()
        && reply.kind == FrameKind::Response
        && reply.message_type == MessageType::Result
        && reply.protocol_version == request.protocol_version
        && reply.connection_id == request.connection_id
        && reply.request_id == request.request_id
        && reply.request_identity.is_none()
        && matches!(&reply.payload, ProtocolPayload::Json(payload)
            if payload.get("status").and_then(serde_json::Value::as_str) == Some("failure"))
}

/// Typed rejection for a correlated Kernel failure whose envelope failed
/// validation. The precise reason replaces the generic internal-error prose
/// that would otherwise reach the caller.
fn undecodable_failure_reply() -> PortFailure {
    PortFailure::TransportBindingRejected {
        reason: "Kernel reported a correlated host-request failure whose envelope failed validation; failing closed instead of reconciling".to_owned(),
    }
}

/// Decodes a canonical Kernel failure only after joining the reply to the
/// exact request envelope, request ID, and live connection. Unknown future
/// reason strings remain untouched in the typed envelope.
fn decode_host_request_failure(reply: &Frame, request: &Frame) -> Option<AgentHostRequestFailure> {
    reply.validate().ok()?;
    request.validate().ok()?;
    if reply.kind != FrameKind::Response
        || reply.message_type != MessageType::Result
        || reply.protocol_version != request.protocol_version
        || reply.connection_id != request.connection_id
        || reply.request_id != request.request_id
        || reply.request_identity.is_some()
    {
        return None;
    }
    let ProtocolPayload::Json(request_payload) = &request.payload else {
        return None;
    };
    let envelope: HostRequestEnvelope =
        serde_json::from_value(request_payload.get("envelope")?.clone()).ok()?;
    envelope.validate().ok()?;
    if envelope.connection_id != request.connection_id
        || request.request_id.as_ref() != Some(&envelope.identity.request_id)
    {
        return None;
    }
    let ProtocolPayload::Json(reply_payload) = &reply.payload else {
        return None;
    };
    if canonical_json_bytes(reply_payload).ok()?.len() > HARD_STRUCTURED_RESPONSE_BYTES {
        return None;
    }
    if reply_payload.get("status")?.as_str()? != "failure" {
        return None;
    }
    let failure: AgentHostRequestFailure =
        serde_json::from_value(reply_payload.get("failure")?.clone()).ok()?;
    failure.validate().ok()?;
    (failure.request_identity == envelope.identity
        && failure.envelope_sha256 == envelope.envelope_sha256
        && failure.protocol_version == request.protocol_version)
        .then_some(failure)
}

/// What one invocation preparation decided (issue #2571).
enum InvocationPreparation {
    /// Submit this envelope on the current transport: a cache-hit exact
    /// replay or a fresh build the owner proved stageable. Boxed: the
    /// envelope is the large variant beside the small recovered pair.
    Submit(Box<HostRequestEnvelope>),
    /// Return the owner-resolved original without dispatch: the logical
    /// key plus the verified record commitment. Boxed beside the small
    /// submit envelope so neither variant dominates the size.
    Recovered(Box<AdmittedReplyView>, String),
}

impl KernelHostRequestClient {
    fn exchange(&mut self, frame: &Frame) -> Result<Frame, PortFailure> {
        self.shared
            .try_borrow_mut()
            .map_err(|_| request_failure())?
            .exchange_host_request_frame(frame)
    }

    /// Captures owner-verified source-result and attach facts for a resource
    /// created from this exact responded operation. The returned digest is a
    /// local comparison commitment only; reads must call
    /// [`Self::authorize_resource_read`] to resolve the owner again.
    pub fn capture_resource_binding(
        &mut self,
        operation_handle: &HostOperationHandle,
        response: &McpResponse,
    ) -> Result<String, PortFailure> {
        let (facts, record) = self.resolve_resource_source(operation_handle)?;
        let expected_response = serde_json::to_value(response).map_err(|_| request_failure())?;
        if record.result_response.as_ref() != Some(&expected_response) {
            return Err(resource_source_refused());
        }
        resource_authorization_digest(operation_handle, &facts, &record)
    }

    /// Re-resolves the exact source operation on every resource read and
    /// requires the complete owner result and current attach binding to match
    /// the binding captured when that exact response produced the resource.
    pub fn authorize_resource_read(
        &mut self,
        operation_handle: &HostOperationHandle,
        expected_binding: &str,
    ) -> Result<(), PortFailure> {
        let (facts, record) = self.resolve_resource_source(operation_handle)?;
        let current = resource_authorization_digest(operation_handle, &facts, &record)?;
        if current != expected_binding {
            return Err(resource_source_refused());
        }
        Ok(())
    }

    /// Performs a fresh, observation-only exact-handle resolve under the
    /// current admitted transport. No local parent/replay cache is consulted.
    fn resolve_resource_source(
        &mut self,
        operation_handle: &HostOperationHandle,
    ) -> Result<(TransportFacts, AdmittedReplyView), PortFailure> {
        let handle = operation_handle.as_str();
        parse_operation_handle(handle).map_err(|_| resource_source_refused())?;
        let facts = self
            .shared
            .try_borrow()
            .map_err(|_| request_failure())?
            .snapshot();
        let session = facts.session.clone().ok_or_else(resource_source_refused)?;
        let now_ms = unix_ms()?;
        let digest = handle
            .strip_prefix(HOST_REQUEST_OPERATION_ID_PREFIX)
            .ok_or_else(resource_source_refused)?;
        let resolve_envelope = build_resolve_envelope(
            &resolve_request_label(digest),
            Some(handle),
            &facts,
            &session,
            RESOLVE_HANDLE_CAPABILITY_FILLER,
            RESOLVE_HANDLE_PAYLOAD_FILLER,
            now_ms,
        )?;
        let query = resolve_handle_query(handle);
        let frame = host_request_resolve_frame(&query, &resolve_envelope, &facts)?;
        let reply = self
            .exchange(&frame)
            .map_err(|error| retain_agent_response(error, resource_source_refused()))?;
        let record = match decode_resolve_reply(
            &reply,
            &resolve_envelope,
            &ResolveQuery::OperationHandle {
                handle: handle.to_owned(),
            },
        ) {
            LogicalOwnerOutcome::Resolved(record) => *record,
            LogicalOwnerOutcome::Absent
            | LogicalOwnerOutcome::Conflict
            | LogicalOwnerOutcome::LegacyUnresolved
            | LogicalOwnerOutcome::Unavailable => return Err(resource_source_refused()),
        };
        if record.operation_id != handle
            || record.kind.as_deref() != Some("INVOCATION")
            || record.session_ref.as_deref() != Some(session.as_str())
            || record.request_digest.is_none()
            || record.request_id.is_none()
            || record.capability_ref.is_none()
            || record.payload_digest.is_none()
            || record.result_digest.is_none()
            || record.result_response.is_none()
            || !matches!(
                record.state,
                HostRequestRecordState::ResultReceived | HostRequestRecordState::Terminal
            )
        {
            return Err(resource_source_refused());
        }
        // A resource preview or expansion re-discloses the exact retained bytes
        // under a different, longer-lived surface, so the owner must have named
        // what those bytes are. An absent lineage or an `Unclassified` one is an
        // explicit unknown about the result's provenance, and an unknown
        // provenance is refused here rather than expanded on the strength of a
        // matching digest. Note what this does NOT do: it does not treat a
        // named class as permission to disclose. Disclosure to this recipient
        // is the disclosure owner's decision, which has no producer on this
        // path; the check below only refuses the case where the owner recorded
        // nothing at all.
        match record
            .result_lineage
            .as_ref()
            .map(|lineage| lineage.result_class)
        {
            Some(HostRequestResultClass::Unclassified) | None => {
                return Err(resource_source_refused());
            }
            Some(_) => {}
        }
        // The recorded lineage must describe THIS row's own recorded result
        // before the bytes are expanded. The comparison is over the ORIGINALLY
        // RECORDED digests on the same row: nothing is recomputed over the
        // response the bridge holds, because a fresh checksum would replace the
        // owner's proof with a new one instead of checking it. The shared rule
        // (`HostRequestResultLineage::validate_retained`) also refuses a class
        // the row's own evidence does not support, so a substituted output
        // digest or an unrelated receipt reference cannot qualify the result
        // here.
        if let Some(lineage) = &record.result_lineage {
            let Some(result_digest) = record.result_digest.as_deref() else {
                return Err(resource_source_refused());
            };
            lineage
                .validate_retained(result_digest)
                .map_err(|_| resource_source_refused())?;
        }
        Ok((facts, record))
    }

    /// Replays, resolves, or builds one invocation (issue #2571).
    ///
    /// The local map is an optimization only. A cache hit with the same
    /// payload resends the byte-identical envelope; a changed payload
    /// under a known correlation stays a local conflict with no wire
    /// traffic. On a cache miss the logical key is resolved against the
    /// owner BEFORE any fresh invocation is constructed — including when
    /// no earlier admission acknowledgement reached the Bridge — so a
    /// restarted Bridge with an empty cache resolves the original
    /// operation/result. A typed-key hit with changed tool, payload, or
    /// parent binding remains a conflict across process restart; the key
    /// is scoped to kind, session, and explicit correlation projection.
    /// If the typed key is absent, the bounded bare and previous-qualified
    /// unmarked keys are presence-probed next; any legacy hit is unresolved
    /// and never yields a guessed handle. A fresh envelope is built only
    /// after authoritative absence from every candidate.
    fn replay_or_build_invocation(
        &mut self,
        correlation: &str,
        request: &HostInvocationRequest,
        facts: &TransportFacts,
        session_id: &str,
        payload_digest: &str,
        now_ms: u64,
    ) -> Result<InvocationPreparation, PortFailure> {
        if let Some(projection) = request.correlation_projection.as_ref() {
            reject_kernel_operational_correlation(projection)?;
        }
        let cached = {
            let owner = self.shared.try_borrow().map_err(|_| request_failure())?;
            owner.replay_cache.get(correlation).cloned()
        };
        if let Some(cached) = cached {
            if cached.payload_digest == payload_digest {
                return Ok(InvocationPreparation::Submit(Box::new(cached.envelope)));
            }
            // Changed payload under a known correlation: the durable Kernel
            // owner (ORS) is the cross-restart source of truth for which bytes
            // won, so the bridge sends nothing and reports the typed conflict.
            // Resolve via `rehydrate_operation` against the Kernel-owned
            // durable record; never resubmit under a new identity here.
            return Err(PortFailure::IdempotencyConflict);
        }
        let projection = request
            .correlation_projection
            .as_ref()
            .ok_or_else(request_failure)?;
        let logical_key = logical_invocation_key(projection, session_id)?;
        let resolve_label = resolve_request_label(correlation);
        let resolve_envelope = build_resolve_envelope(
            &resolve_label,
            None,
            facts,
            session_id,
            request.tool.canonical_name(),
            payload_digest,
            now_ms,
        )?;
        let query = resolve_key_query(
            &logical_key,
            correlation,
            request.tool.canonical_name(),
            payload_digest,
            request.correlation_projection.as_ref(),
            None,
        );
        let frame = host_request_resolve_frame(&query, &resolve_envelope, facts)?;
        let outcome = match self.exchange(&frame) {
            Ok(reply) => decode_resolve_reply(
                &reply,
                &resolve_envelope,
                &ResolveQuery::LogicalKey {
                    key: logical_key.clone(),
                },
            ),
            Err(error @ PortFailure::AgentResponse { .. }) => return Err(error),
            Err(_) => LogicalOwnerOutcome::Unavailable,
        };
        match outcome {
            LogicalOwnerOutcome::Resolved(record) => {
                // The recovered record is the durable winner of the ORIGINAL
                // invocation, so its `task_ref`/`scope_ref` are the task this
                // connection is activated for — the same identity the presented
                // resolve envelope now binds (#2857). Expected from the live
                // authenticated binding, so a record staged under a different
                // task still fails the equality check below.
                let (task_ref, scope_ref) = live_task_refs(facts);
                verify_resolved_key_commitment(
                    &record,
                    &ResolvedKeyCommitment {
                        key: &logical_key,
                        occurrence: correlation,
                        session: session_id,
                        task_ref,
                        scope_ref,
                        capability: request.tool.canonical_name(),
                        payload_digest,
                        parent: None,
                        projection: request
                            .correlation_projection
                            .as_ref()
                            .ok_or_else(request_failure)?,
                    },
                )?;
                Ok(InvocationPreparation::Recovered(record, logical_key))
            }
            LogicalOwnerOutcome::LegacyUnresolved => Err(PortFailure::LegacyCorrelationUnresolved),
            LogicalOwnerOutcome::Absent => {
                // Neither legacy text representation has a persisted JSON-RPC
                // type, so a hit is a typed unresolved disposition, never a
                // guessed owner handle/result. Only two owner-confirmed misses
                // permit a fresh marked stage.
                self.reject_legacy_invocation_if_present(
                    request,
                    facts,
                    session_id,
                    payload_digest,
                    now_ms,
                )?;
                let envelope =
                    build_invocation_envelope(request, facts, session_id, payload_digest, now_ms)?;
                self.shared
                    .try_borrow_mut()
                    .map_err(|_| request_failure())?
                    .replay_cache
                    .insert(
                        correlation.to_owned(),
                        ReplayCacheEntry {
                            payload_digest: payload_digest.to_owned(),
                            envelope: envelope.clone(),
                        },
                    );
                Ok(InvocationPreparation::Submit(Box::new(envelope)))
            }
            LogicalOwnerOutcome::Conflict => Err(PortFailure::IdempotencyConflict),
            LogicalOwnerOutcome::Unavailable => Err(unknown_resolve_outcome(&logical_key)),
        }
    }

    /// Probes the bounded legacy occurrence keys without recovering a
    /// handle. Both the original bare era and the former qualified-but-
    /// unmarked era lost the original JSON-RPC type, so any hit is typed
    /// unresolved. Only owner-confirmed absence of every old projection
    /// permits a fresh marked stage.
    fn reject_legacy_invocation_if_present(
        &mut self,
        request: &HostInvocationRequest,
        facts: &TransportFacts,
        session_id: &str,
        payload_digest: &str,
        now_ms: u64,
    ) -> Result<(), PortFailure> {
        let projection = request
            .correlation_projection
            .as_ref()
            .ok_or_else(request_failure)?;
        let candidates = match projection {
            HostCorrelationProjection::McpJsonRpc {
                id: HostJsonRpcCorrelationId::String(value),
                ..
            } => vec![value.clone(), format!("str:{value}")],
            HostCorrelationProjection::McpJsonRpc {
                id: HostJsonRpcCorrelationId::Integer(value),
                ..
            } => vec![value.to_string(), format!("int:{value}")],
            HostCorrelationProjection::Opaque { occurrence, .. } => vec![occurrence.clone()],
            HostCorrelationProjection::KernelOperational { .. } => {
                return reject_kernel_operational_correlation(projection);
            }
        };
        let capability = request.tool.canonical_name();
        for occurrence in candidates {
            let legacy_key = host_request_legacy_presence_key(
                HostRequestLogicalKind::Invocation,
                session_id,
                &occurrence,
            );
            let resolve_label = resolve_request_label(&occurrence);
            let resolve_envelope = build_resolve_envelope(
                &resolve_label,
                None,
                facts,
                session_id,
                capability,
                payload_digest,
                now_ms,
            )?;
            let query = legacy_presence_query(&legacy_key, "INVOCATION", session_id, &occurrence);
            let frame = host_request_resolve_frame(&query, &resolve_envelope, facts)?;
            let outcome = match self.exchange(&frame) {
                Ok(reply) => decode_resolve_reply(
                    &reply,
                    &resolve_envelope,
                    &ResolveQuery::LegacyPresence {
                        key: legacy_key.clone(),
                    },
                ),
                Err(_) => LogicalOwnerOutcome::Unavailable,
            };
            match outcome {
                LogicalOwnerOutcome::Absent => {}
                LogicalOwnerOutcome::LegacyUnresolved => {
                    return Err(PortFailure::LegacyCorrelationUnresolved);
                }
                LogicalOwnerOutcome::Conflict => return Err(PortFailure::IdempotencyConflict),
                LogicalOwnerOutcome::Resolved(_) | LogicalOwnerOutcome::Unavailable => {
                    return Err(unknown_resolve_outcome(&legacy_key));
                }
            }
        }
        Ok(())
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

    /// Resolves the exact parent reference for one operation handle,
    /// consulting the owner when the local cache no longer holds it
    /// (issue #2571: cancellation/status across Bridge restart).
    ///
    /// A cache hit keeps today's exact behavior. On a miss the resolve
    /// entry is asked for the durable parent record under the current
    /// session: the returned capability and payload rebuild the parent
    /// link from owner state, so a fresh connection performs authorized
    /// cancellation on the old handle while a foreign principal, scope, or
    /// unapproved continuity cannot — denial answers exactly like absence,
    /// disclosing neither task nor payload. An unavailable owner is the
    /// explicit recovery limitation, never a guessed parent.
    fn resolve_parent_link(
        &mut self,
        digest: &str,
        facts: &TransportFacts,
        session_id: &str,
        now_ms: u64,
    ) -> Result<ParentLink, PortFailure> {
        if let Ok(cached) = self.parent_link_for_handle(digest) {
            return Ok(cached);
        }
        let handle = format!("{HOST_REQUEST_OPERATION_ID_PREFIX}{digest}");
        let resolve_label = resolve_request_label(digest);
        let resolve_envelope = build_resolve_envelope(
            &resolve_label,
            Some(handle.as_str()),
            facts,
            session_id,
            RESOLVE_HANDLE_CAPABILITY_FILLER,
            RESOLVE_HANDLE_PAYLOAD_FILLER,
            now_ms,
        )?;
        let query = resolve_handle_query(&handle);
        let frame = host_request_resolve_frame(&query, &resolve_envelope, facts)?;
        let outcome = match self.exchange(&frame) {
            Ok(reply) => decode_resolve_reply(
                &reply,
                &resolve_envelope,
                &ResolveQuery::OperationHandle {
                    handle: handle.clone(),
                },
            ),
            Err(error @ PortFailure::AgentResponse { .. }) => return Err(error),
            Err(_) => LogicalOwnerOutcome::Unavailable,
        };
        match outcome {
            LogicalOwnerOutcome::Resolved(record) => {
                if record.operation_id != handle
                    || record.session_ref.as_deref() != Some(session_id)
                {
                    return Err(unknown_cancel_outcome(&handle));
                }
                if record.correlation_projection.is_none() {
                    return Err(PortFailure::LegacyCorrelationUnresolved);
                }
                let (capability, payload_digest, request_base, correlation_projection) = match (
                    &record.capability_ref,
                    &record.payload_digest,
                    &record.request_id,
                    &record.correlation_projection,
                ) {
                    (
                        Some(capability),
                        Some(payload_digest),
                        Some(request_base),
                        Some(correlation_projection),
                    ) => (
                        capability.clone(),
                        payload_digest.clone(),
                        request_base.clone(),
                        correlation_projection.clone(),
                    ),
                    _ => return Err(unknown_cancel_outcome(&handle)),
                };
                ParentLink::from_owner_record(
                    &handle,
                    &capability,
                    &payload_digest,
                    &request_base,
                    correlation_projection,
                )
                .map_err(|_| unknown_cancel_outcome(&handle))
            }
            LogicalOwnerOutcome::Absent | LogicalOwnerOutcome::Conflict => {
                Err(plan_gap_unknown_handle())
            }
            LogicalOwnerOutcome::LegacyUnresolved => Err(PortFailure::LegacyCorrelationUnresolved),
            LogicalOwnerOutcome::Unavailable => Err(unknown_cancel_outcome(&handle)),
        }
    }

    /// Resolves the exact parent operation after a cancellation result and
    /// maps that owner's current state, never the cancellation-intent state.
    /// This deliberately bypasses the replay cache: only a fresh operation-
    /// handle resolve on the admitted transport can establish disposition.
    fn resolve_cancellation_parent_disposition(
        &mut self,
        parent: &ParentLink,
        facts: &TransportFacts,
        session_id: &str,
    ) -> Result<HostCancellationPortOutcome, PortFailure> {
        let unknown = || unknown_cancel_outcome(&parent.handle);
        if facts.session.as_deref() != Some(session_id) {
            return Err(unknown());
        }
        let digest = parse_operation_handle(&parent.handle).map_err(|_| unknown())?;
        let projection = parent.correlation_projection.as_ref().ok_or_else(unknown)?;
        let logical_key = logical_invocation_key(projection, session_id).map_err(|_| unknown())?;
        let resolve_envelope = build_resolve_envelope(
            &resolve_request_label(&digest),
            Some(parent.handle.as_str()),
            facts,
            session_id,
            RESOLVE_HANDLE_CAPABILITY_FILLER,
            RESOLVE_HANDLE_PAYLOAD_FILLER,
            unix_ms().map_err(|_| unknown())?,
        )
        .map_err(|_| unknown())?;
        let query = resolve_handle_query(parent.handle.as_str());
        let frame =
            host_request_resolve_frame(&query, &resolve_envelope, facts).map_err(|_| unknown())?;
        let outcome = match self.exchange(&frame) {
            Ok(reply) => decode_resolve_reply(
                &reply,
                &resolve_envelope,
                &ResolveQuery::OperationHandle {
                    handle: parent.handle.clone(),
                },
            ),
            Err(error @ PortFailure::AgentResponse { .. }) => return Err(error),
            Err(_) => LogicalOwnerOutcome::Unavailable,
        };
        let LogicalOwnerOutcome::Resolved(record) = outcome else {
            return Err(unknown());
        };
        if record.operation_id != parent.handle
            || record.request_digest.as_deref() != Some(digest.as_str())
            || record.kind.as_deref() != Some("INVOCATION")
            || record.session_ref.as_deref() != Some(session_id)
            || record.request_id.as_deref() != Some(parent.request_base.as_str())
            || record.parent_operation_id.is_some()
            || record.task_ref.is_some()
            || record.scope_ref.is_some()
            || record.capability_ref.as_deref() != Some(parent.capability.as_str())
            || record.payload_digest.as_deref() != Some(parent.payload_digest.as_str())
        {
            return Err(unknown());
        }
        // The parent invocation is now admitted under the live authenticated
        // task (#2857), so the expected `task_ref`/`scope_ref` are that task
        // and the identical `is_some()` legs above require this connection to
        // actually be activated. Pre-activation (`None`) behaviour is
        // unchanged, because `live_task_refs` then yields `(None, None)`.
        let (task_ref, scope_ref) = live_task_refs(facts);
        verify_resolved_key_commitment(
            &record,
            &ResolvedKeyCommitment {
                key: &logical_key,
                occurrence: parent.request_base.as_str(),
                session: session_id,
                task_ref,
                scope_ref,
                capability: parent.capability.as_str(),
                payload_digest: parent.payload_digest.as_str(),
                parent: None,
                projection,
            },
        )
        .map_err(|_| unknown())?;
        map_parent_cancellation_disposition(record.state, parent.handle.as_str())
    }

    /// Resolves one cancellation's retained intent after an unknown
    /// delivery (issue #2571).
    ///
    /// The cancellation's own logical identity — its correlation bound to
    /// the original parent — is looked up before any probe. A staged intent
    /// whose acknowledgement was lost is reconciled without another cancel;
    /// its state is not the target disposition, so a fresh exact parent
    /// resolve follows. An authoritatively absent intent falls back to the
    /// observation-only parent probe; a conflicting intent is an
    /// idempotency conflict for the caller to re-issue under a new
    /// correlation; an unavailable owner stays the explicit limitation.
    fn resolve_retained_cancellation(
        &mut self,
        parent: &ParentLink,
        cancel_correlation: &str,
        cancel_envelope: &HostRequestEnvelope,
        facts: &TransportFacts,
        session_id: &str,
        now_ms: u64,
    ) -> Result<HostCancellationPortOutcome, PortFailure> {
        let projection = cancel_envelope
            .identity
            .correlation_projection
            .as_ref()
            .ok_or_else(|| unknown_cancel_outcome(&parent.handle))?;
        reject_kernel_operational_correlation(projection)?;
        let logical_key = logical_cancellation_key(projection, session_id)
            .map_err(|_| unknown_cancel_outcome(&parent.handle))?;
        let resolve_label = resolve_request_label(cancel_correlation);
        let resolve_envelope = build_resolve_envelope(
            &resolve_label,
            None,
            facts,
            session_id,
            parent.capability.as_str(),
            parent.payload_digest.as_str(),
            now_ms,
        )
        .map_err(|_| unknown_cancel_outcome(&parent.handle))?;
        let query = resolve_key_query(
            &logical_key,
            cancel_correlation,
            parent.capability.as_str(),
            parent.payload_digest.as_str(),
            Some(projection),
            Some(parent.handle.as_str()),
        );
        let frame = host_request_resolve_frame(&query, &resolve_envelope, facts)
            .map_err(|_| unknown_cancel_outcome(&parent.handle))?;
        let outcome = match self.exchange(&frame) {
            Ok(reply) => decode_resolve_reply(
                &reply,
                &resolve_envelope,
                &ResolveQuery::LogicalKey {
                    key: logical_key.clone(),
                },
            ),
            Err(error @ PortFailure::AgentResponse { .. }) => return Err(error),
            Err(_) => LogicalOwnerOutcome::Unavailable,
        };
        match outcome {
            LogicalOwnerOutcome::Resolved(record) => {
                let (task_ref, scope_ref) = live_task_refs(facts);
                verify_resolved_key_commitment(
                    &record,
                    &ResolvedKeyCommitment {
                        key: &logical_key,
                        occurrence: cancel_correlation,
                        session: session_id,
                        task_ref,
                        scope_ref,
                        capability: parent.capability.as_str(),
                        payload_digest: parent.payload_digest.as_str(),
                        parent: Some(parent.handle.as_str()),
                        projection,
                    },
                )
                .map_err(|_| unknown_cancel_outcome(&parent.handle))?;
                self.resolve_cancellation_parent_disposition(parent, facts, session_id)
            }
            LogicalOwnerOutcome::LegacyUnresolved => Err(PortFailure::LegacyCorrelationUnresolved),
            LogicalOwnerOutcome::Absent => {
                self.reject_legacy_cancellation_if_present(
                    cancel_envelope,
                    facts,
                    session_id,
                    parent,
                    now_ms,
                )?;
                self.probe_confirms_parent(facts, session_id, parent, cancel_envelope, now_ms)
            }
            LogicalOwnerOutcome::Conflict => Err(PortFailure::IdempotencyConflict),
            LogicalOwnerOutcome::Unavailable => Err(unknown_cancel_outcome(&parent.handle)),
        }
    }

    fn reject_legacy_cancellation_if_present(
        &mut self,
        cancel_envelope: &HostRequestEnvelope,
        facts: &TransportFacts,
        session_id: &str,
        parent: &ParentLink,
        now_ms: u64,
    ) -> Result<(), PortFailure> {
        let projection = cancel_envelope
            .identity
            .correlation_projection
            .as_ref()
            .ok_or_else(|| unknown_cancel_outcome(&parent.handle))?;
        let candidates = match projection {
            HostCorrelationProjection::McpJsonRpc {
                id: HostJsonRpcCorrelationId::String(value),
                ..
            } => vec![format!("cancel:{value}"), format!("cancel:str:{value}")],
            HostCorrelationProjection::McpJsonRpc {
                id: HostJsonRpcCorrelationId::Integer(value),
                ..
            } => vec![format!("cancel:{value}"), format!("cancel:int:{value}")],
            HostCorrelationProjection::Opaque { occurrence, .. } => {
                vec![occurrence.clone(), format!("cancel:{occurrence}")]
            }
            HostCorrelationProjection::KernelOperational { .. } => {
                return reject_kernel_operational_correlation(projection);
            }
        };
        for occurrence in candidates {
            let key = host_request_legacy_presence_key(
                HostRequestLogicalKind::Cancellation,
                session_id,
                &occurrence,
            );
            let label = resolve_request_label(&occurrence);
            let envelope = build_resolve_envelope(
                &label,
                None,
                facts,
                session_id,
                parent.capability.as_str(),
                parent.payload_digest.as_str(),
                now_ms,
            )?;
            let query = legacy_presence_query(&key, "CANCELLATION", session_id, &occurrence);
            let frame = host_request_resolve_frame(&query, &envelope, facts)?;
            let outcome = match self.exchange(&frame) {
                Ok(reply) => decode_resolve_reply(
                    &reply,
                    &envelope,
                    &ResolveQuery::LegacyPresence { key: key.clone() },
                ),
                Err(_) => LogicalOwnerOutcome::Unavailable,
            };
            match outcome {
                LogicalOwnerOutcome::Absent => {}
                LogicalOwnerOutcome::LegacyUnresolved => {
                    return Err(PortFailure::LegacyCorrelationUnresolved);
                }
                LogicalOwnerOutcome::Conflict => return Err(PortFailure::IdempotencyConflict),
                LogicalOwnerOutcome::Resolved(_) | LogicalOwnerOutcome::Unavailable => {
                    return Err(unknown_cancel_outcome(&parent.handle));
                }
            }
        }
        Ok(())
    }
}

/// The `task_ref`/`scope_ref` a durable record for this connection must carry.
///
/// One owner of the live authenticated task, read from the retained activation
/// binding and never from host text. Both callers that compare a resolved
/// record against the presented envelope use this, so the expected value and
/// the value the envelope actually binds are the SAME authenticated identity —
/// the equality check is joined to real authority rather than satisfied by a
/// hardcoded `None`.
fn live_task_refs(facts: &TransportFacts) -> (Option<&str>, Option<&str>) {
    match facts.task_binding.as_ref() {
        Some(binding) => (
            Some(binding.task_id.as_str()),
            Some(binding.work_scope_id.as_str()),
        ),
        None => (None, None),
    }
}

/// Builds one invocation envelope bound to the live authenticated identity.
///
/// **Task identity (#2857).** `task_id` and `work_scope_id` are the task and
/// `WorkScope` the one-shot activation exchange resolved for this connection,
/// taken from [`TransportFacts::task_binding`]. They were previously pinned to
/// `None`, which is what made every production `eliot.query` envelope
/// task-unbound: `eliotd`'s live reconstruction route then refused with
/// `MissingTaskBinding` before any read, so no `ContextReconstructionRequest`
/// was ever constructed and `GovernorContextInputs::reconstruct` was
/// unreachable from a real request.
///
/// The values are the Kernel's own resolved strings, never host request text:
/// `HostInvocationRequest` has no task/scope field at all, and
/// `scripts/verify-agent-bridge-protocol.py` fails the build if a host request
/// type ever grows one. The Kernel re-checks both against its retained
/// `ActivatedApplicationBinding` at admission
/// (`host_request_application_binding_gate_under_transition`), so a stale or
/// foreign binding is `IdentityConflict` there, not a silent success here.
///
/// **`task_revision` is deliberately NOT promoted into the frame fence.**
/// `StateFence::I45_KEY_OMISSIONS` gives the revision dimension to
/// `RevisionHeadExpectation` at the operation's own owner, and the transport
/// fence this envelope rides structurally carries no task revision
/// (`host_request_frame_for_envelope` refuses one outright). The task revision
/// is therefore NOT bound here either: it is resolved and matched by value
/// where the owner read returns its current head
/// (`eliotd::context_reconstruction_route::read_authenticated_task_recipe`),
/// which is that dimension's actual owner.
///
/// **Before activation** there is no authenticated task, so the two members
/// stay `None` exactly as before: the Kernel's own gate refuses a task-bearing
/// claim with no retained binding, and an unbound read still reaches the
/// ordinary forwarded path.
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
    let correlation_projection = request
        .correlation_projection
        .clone()
        .ok_or_else(request_failure)?;
    let (task_id, work_scope_id) = match facts.task_binding.as_ref() {
        Some(binding) => (
            Some(binding.task_id.clone()),
            Some(binding.work_scope_id.clone()),
        ),
        None => (None, None),
    };
    let identity = HostRequestIdentity {
        request_id: RequestId::new(correlation).map_err(|_| request_failure())?,
        correlation_projection: Some(correlation_projection),
        idempotency_key: format!("{correlation}:invoke"),
        cancellation_id: format!("{correlation}:invoke:cancel"),
        parent_operation_id: None,
        deadline_unix_ms: deadline,
        capability: request.tool.canonical_name().to_owned(),
        session_id: Some(session_id.to_owned()),
        task_id,
        work_scope_id,
        payload_schema_id: match &request.tool {
            // The finish candidate rides its own payload schema so the Kernel
            // finish lane can bind the exact admitted draft bytes (issue
            // #1741); every other tool keeps the shared tool-request schema.
            ToolRequest::Finish(_) => FINISH_INVOKE_PAYLOAD_SCHEMA_ID.to_owned(),
            _ => HOST_REQUEST_PAYLOAD_SCHEMA_ID.to_owned(),
        },
        payload_sha256: payload_digest.to_owned(),
    };
    finish_envelope(facts, HostRequestKind::Invocation, identity)
}

fn build_restore_envelope(
    correlation: &str,
    facts: &TransportFacts,
    session_id: &str,
    payload_digest: &str,
    deadline: u64,
) -> Result<HostRequestEnvelope, PortFailure> {
    let projection = HostCorrelationProjection::Opaque {
        domain: HostCorrelationDomain::Request,
        occurrence: correlation.to_owned(),
    };
    let identity = HostRequestIdentity {
        request_id: RequestId::new(projection.occurrence_text()).map_err(|_| request_failure())?,
        correlation_projection: Some(projection),
        idempotency_key: format!("{correlation}:restore"),
        cancellation_id: format!("{correlation}:restore:cancel"),
        parent_operation_id: None,
        deadline_unix_ms: deadline,
        capability: REACTIVE_RESTORE_CAPABILITY.to_owned(),
        session_id: Some(session_id.to_owned()),
        task_id: None,
        work_scope_id: None,
        payload_schema_id: REACTIVE_RESTORE_PAYLOAD_SCHEMA_ID.to_owned(),
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
        correlation_projection: request.correlation_projection.clone(),
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
        correlation_projection: None,
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

/// Maximum resolve request-label length: leaves room for the
/// `:idempotent`/`:cancel` derivations under the 512-byte envelope text
/// ceiling, so even the longest submittable correlation keeps a valid
/// resolve envelope.
const MAX_RESOLVE_LABEL_BYTES: usize = 480;

/// Derives the resolve request label for one occurrence or handle
/// (issue #2571).
///
/// Readable `{base}:resolve` while it fits the envelope text ceiling; a
/// digest fallback beyond that, so a long-but-submittable correlation
/// never loses its resolve path. Deterministic in both cases and unique
/// per query base, which is all the transport correlation needs.
fn resolve_request_label(base: &str) -> String {
    let direct = format!("{base}:resolve");
    if direct.len() <= MAX_RESOLVE_LABEL_BYTES {
        direct
    } else {
        format!("resolve:{}", sha256_hex(base.as_bytes()))
    }
}

/// Builds one lookup-only resolve envelope over the current transport
/// binding (issue #2571).
///
/// The envelope carries the CURRENT connection, session, fence, and
/// descriptor — never the recovered operation's original transport
/// material, never expired credentials. The recovery request therefore has
/// its own current transport identity while the recovered operation keeps
/// its original identity. The kind is `Status` (observation-only); the
/// handle form names its exact parent (which also satisfies the per-kind
/// presence rule), while the logical-key form carries the selectors the
/// owner recomputes the key from and is accepted only on the resolve entry.
///
/// **Task identity (#2857).** The resolve envelope carries the SAME live
/// authenticated task and `WorkScope` the invocation envelope now binds, from
/// [`TransportFacts::task_binding`]. The owner compares the durable record's
/// `task_ref`/`scope_ref` against the PRESENTED envelope's
/// `task_id`/`work_scope_id`
/// (`resolve_host_request_logical_key`, and `require_host_request_parent_owner`
/// for the parent forms), so a resolve that omitted them would stop matching
/// every task-bound record it is trying to recover. This keeps the existing
/// equality comparison exactly as strict — it is joined to the live
/// authenticated identity, not relaxed — and a record under a different task
/// still answers `conflict`.
fn build_resolve_envelope(
    request_label: &str,
    parent_operation_id: Option<&str>,
    facts: &TransportFacts,
    session_id: &str,
    capability: &str,
    payload_digest: &str,
    now_ms: u64,
) -> Result<HostRequestEnvelope, PortFailure> {
    let deadline = now_ms.saturating_add(DEFAULT_DEADLINE_PREFERENCE_MS);
    if deadline == 0 {
        return Err(request_failure());
    }
    let (task_id, work_scope_id) = match facts.task_binding.as_ref() {
        Some(binding) => (
            Some(binding.task_id.clone()),
            Some(binding.work_scope_id.clone()),
        ),
        None => (None, None),
    };
    let identity = HostRequestIdentity {
        request_id: RequestId::new(request_label).map_err(|_| request_failure())?,
        correlation_projection: None,
        idempotency_key: format!("{request_label}:idempotent"),
        cancellation_id: format!("{request_label}:cancel"),
        parent_operation_id: parent_operation_id.map(str::to_owned),
        deadline_unix_ms: deadline,
        capability: capability.to_owned(),
        session_id: Some(session_id.to_owned()),
        task_id,
        work_scope_id,
        payload_schema_id: HOST_REQUEST_PAYLOAD_SCHEMA_ID.to_owned(),
        payload_sha256: payload_digest.to_owned(),
    };
    finish_envelope(facts, HostRequestKind::Status, identity)
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

/// Builds the shared-transport liveness request without a request identity or
/// operation envelope. The Kernel Health route is a control observation, not
/// a durable host request.
fn kernel_health_probe_frame(facts: &TransportFacts) -> Result<Frame, PortFailure> {
    if facts.session.is_none() {
        return Err(plan_gap_no_session());
    }
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: facts.connection_id.clone(),
        request_id: None,
        kind: FrameKind::Heartbeat,
        message_type: MessageType::Health,
        request_identity: None,
        payload: ProtocolPayload::Json(serde_json::json!({ "status": "probe" })),
        trace_context: BTreeMap::new(),
    };
    frame.validate().map_err(|_| request_failure())?;
    Ok(frame)
}

/// Accepts only the uncorrelated Heartbeat/Health reply shape emitted by the
/// Kernel's current-session status path and validates its owner-typed evidence
/// against the retained admission fence.
fn decode_kernel_health_reply(
    reply: &Frame,
    request: &Frame,
    facts: &TransportFacts,
) -> Option<()> {
    if request.protocol_version != ProtocolVersion::CURRENT
        || request.encoding_profile != EncodingProfile::JsonV1
        || request.connection_id != facts.connection_id
        || request.kind != FrameKind::Heartbeat
        || request.message_type != MessageType::Health
        || request.request_id.is_some()
        || request.request_identity.is_some()
        || !request.trace_context.is_empty()
    {
        return None;
    }
    reply.validate().ok()?;
    if reply.protocol_version != request.protocol_version
        || reply.encoding_profile != request.encoding_profile
        || reply.connection_id != request.connection_id
        || reply.kind != FrameKind::Heartbeat
        || reply.message_type != MessageType::Health
        || reply.request_id.is_some()
        || reply.request_identity.is_some()
        || !reply.trace_context.is_empty()
    {
        return None;
    }
    let ProtocolPayload::Json(payload) = &reply.payload else {
        return None;
    };
    let evidence: KernelRuntimeHealthEvidence = serde_json::from_value(payload.clone()).ok()?;
    evidence.validate().ok()?;
    if evidence.status != "OPEN"
        || !evidence
            .authority_epoch
            .is_same_authority(&facts.state_fence.authority_epoch)
        || evidence.module_generation != facts.state_fence.resource_generation
    {
        return None;
    }
    Some(())
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

/// Builds the cold/operator submit frame with the exact typed request body.
///
/// The envelope remains the authenticated binding for the connection, session,
/// fence, capability, idempotency key, and canonical payload digest. The
/// `tool` member is carried only for the UserAutomation Kernel selector to
/// decode and re-canonicalize before it constructs the authenticated service
/// request. Reconciliation deliberately carries only the parent envelope and
/// digest; it never resubmits this body under a new identity.
fn host_request_user_automation_frame(
    request: &HostInvocationRequest,
    envelope: &HostRequestEnvelope,
    facts: &TransportFacts,
) -> Result<Frame, PortFailure> {
    let mut frame =
        host_request_frame_for_envelope(AGENT_HOST_REQUEST_SUBMIT_OPERATION, envelope, facts)?;
    let tool = serde_json::to_value(&request.tool).map_err(|_| request_failure())?;
    let ProtocolPayload::Json(payload) = &mut frame.payload else {
        return Err(request_failure());
    };
    payload["tool"] = tool;
    frame.validate().map_err(|_| request_failure())?;
    Ok(frame)
}

/// Builds the Observe submit frame carrying the exact canonical tool bytes
/// (issue #2565).
///
/// Rides the same `agent_host_request_submit` entry as the digest-only
/// submits; only the payload gains the exact `ToolRequest` JSON the Kernel
/// linkage gate binds to the admitted envelope digest before admission. The
/// Kernel retains the linked bytes for the daemon observe flight instead of
/// dropping to a digest-only stage, so a successful admission stays
/// recoverable input. A submit without these bytes keeps the legacy
/// digest-only shape and never enqueues an observe pair.
fn host_request_observe_submit_frame(
    request: &HostInvocationRequest,
    envelope: &HostRequestEnvelope,
    facts: &TransportFacts,
) -> Result<Frame, PortFailure> {
    let mut frame =
        host_request_frame_for_envelope(AGENT_HOST_REQUEST_SUBMIT_OPERATION, envelope, facts)?;
    let tool = serde_json::to_value(&request.tool).map_err(|_| request_failure())?;
    let ProtocolPayload::Json(payload) = &mut frame.payload else {
        return Err(request_failure());
    };
    payload["tool"] = tool;
    frame.validate().map_err(|_| request_failure())?;
    Ok(frame)
}

/// One finite dispatch row for every canonical tool (Implements #1739 item 1).
///
/// This is the single recorded dispatch map [`KernelHostRequestClient::invoke`]
/// consults: exactly one row per [`ToolRequest`] variant, chosen by an
/// exhaustive match, so adding a tool variant fails to compile until its row
/// is recorded here. No ninth hot tool can slip through: non-hot carriers
/// ([`ToolRequest::UserAutomation`], [`ToolRequest::SkillInject`],
/// [`ToolRequest::SkillDisplay`]) keep their own explicitly non-hot rows and
/// are never advertised on the canonical eight-tool surface (I7.6).
///
/// | tool | bridge entry | Kernel operation | completion boundary |
/// |---|---|---|---|
/// | `eliot.state` | submit frame (digest-only) | `agent_host_request_submit` | admission handle only; projection-owner readback join missing |
/// | `eliot.packet` | invoke-read frame (tool bytes) | `agent_host_request_invoke_read` | exact bounded compiler result with revision via Governor read owner |
/// | `eliot.observe` | submit frame (tool bytes) | `agent_host_request_submit` | daemon observe flight claims the retained pair, decodes the closed vocabulary and routes to the Governor observation owner; retained result via the governed submit leg |
/// | `eliot.query` | invoke-read frame (tool bytes) | `agent_host_request_invoke_read` | exact bounded read result with revision via Governor read owner |
/// | `eliot.act` | submit frame (digest-only, dispatch-time revalidated) | `agent_host_request_submit` | admission handle only; bridge revalidates session/fence/connection/payload linkage at dispatch and the Kernel submit gate revalidates the act dispatch binding pre-staging; the daemon-side `admit_material_decision` invocation over owner-resolved inputs with dispatch-time revalidation through a live act claim/flight is the remaining join (#1742 W4) |
/// | `eliot.verify` | submit frame (digest-only) | `agent_host_request_submit` | admission handle only; verifier-owner invocation + evidence preservation missing |
/// | `eliot.coordinate` | submit frame (digest-only) | `agent_host_request_submit` | admission handle only; execution-fabric join missing (#1740) |
/// | `eliot.finish` | invoke-read frame (tool bytes) | `agent_host_request_invoke_read` | exact bounded finish decision receipt from the Governor finish owner; a simulated/stale/unbound/unknown-verifier candidate and a caller-supplied proof never yield `VERIFIED_COMPLETE` |
/// | `eliot_user_automation` (non-hot) | submit frame (tool bytes) | `agent_host_request_submit` | operator carrier on its own leg; never a hot tool |
/// | `skill.inject` / `skill.display` (non-hot) | invoke-read frame (tool bytes) | `agent_host_request_invoke_read` | Hotset intake served through the linkage-checked leg; never advertised |
///
/// An `Accepted` submit reply is an operation handle, not completed work; only
/// the row's named owner execution plus a retained result completes it. The
/// `completion_join` / `missing_route` strings name that exact missing
/// interface per unresolved row instead of claiming seven tools do not exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CanonicalDispatchEntry {
    /// Linkage-checked invoke-read: the Kernel checks capability and
    /// payload-digest linkage before reading and serves the exact bounded
    /// result with its revision.
    InvokeRead,
    /// Admission-only submit: the Accepted reply is an operation handle.
    /// `completion_join` names the exact missing owner execution that must
    /// complete the row before a completed response is legitimate.
    SubmitAdmitOnly { completion_join: &'static str },
    /// Act effect dispatch with dispatch-time revalidation (issue #1742 W4,
    /// owned by #1739 dispatch).
    ///
    /// The bridge revalidates only what it owns at dispatch time (act shape,
    /// live session/fence/connection binding, exact payload-digest linkage)
    /// and rides the same `agent_host_request_submit` entry; the Kernel
    /// submit entry revalidates the act dispatch binding pre-staging
    /// (`check_act_submit_binding`). The daemon-side
    /// `eliot-context-admission::admit_material_decision` invocation over
    /// owner-resolved inputs with live-fence revalidation runs at the future
    /// live act claim/flight, not here. The Accepted reply stays an operation
    /// handle until the effect owner completes it.
    SubmitActGated { completion_join: &'static str },
    /// Observe submit carrying the exact canonical tool bytes (issue #2565).
    /// Rides the same `agent_host_request_submit` entry as the digest-only
    /// submits; the Kernel linkage gate binds the bytes to the admitted
    /// envelope before admission, retains them for the daemon observe flight,
    /// and enqueues the admitted pair. The Accepted reply stays an operation
    /// handle until the flight submits the retained result.
    SubmitObservePair,
    /// Non-hot operator carrier on the submit leg with tool bytes. Only
    /// [`ToolRequest::UserAutomation`] rides here.
    SubmitCarryingBytes,
}

/// Returns the recorded dispatch row for one invocation (Implements #1739
/// item 1: the finite dispatch map as code).
///
/// Exhaustive over [`ToolRequest`]: a new variant is a compile error here
/// until its decoder, capability, owner, receipt and readback are recorded
/// above. Behavior is byte-identical to the previous scattered predicates.
fn canonical_dispatch_entry(tool: &ToolRequest) -> CanonicalDispatchEntry {
    match tool {
        ToolRequest::State(_) => CanonicalDispatchEntry::SubmitAdmitOnly {
            completion_join: "projection-owner readback: submit-record execution (Kernel pair + daemon flight + task/scope projection owner)",
        },
        ToolRequest::Packet(_)
        | ToolRequest::Query(_)
        | ToolRequest::SkillInject(_)
        | ToolRequest::SkillDisplay(_)
        // #1741: the admitted strict finish draft rides the same linkage-checked
        // invoke-read lane; the Kernel finish queue binds the exact draft bytes
        // and the daemon flight claims them under a fenced attempt.
        | ToolRequest::Finish(_) => CanonicalDispatchEntry::InvokeRead,
        ToolRequest::Observe(_) => CanonicalDispatchEntry::SubmitObservePair,
        ToolRequest::Act(_) => CanonicalDispatchEntry::SubmitActGated {
            completion_join: "daemon-side admit_material_decision invocation over Governor owner-resolved inputs with dispatch-time revalidation through a live act claim/flight (Kernel submit gate check_act_submit_binding and bridge dispatch revalidation done; #1742 W4)",
        },
        ToolRequest::Verify(_) => CanonicalDispatchEntry::SubmitAdmitOnly {
            completion_join: "verifier-owner invocation through the existing verifier owner with not-executed/partial/unknown evidence preserved",
        },
        ToolRequest::Coordinate(_) => CanonicalDispatchEntry::SubmitAdmitOnly {
            completion_join: "execution-fabric owner join with the same durable work/attempt identity (#1740)",
        },
        ToolRequest::UserAutomation(_) => CanonicalDispatchEntry::SubmitCarryingBytes,
    }
}

/// Dispatch-time revalidation for one `eliot.act` effect dispatch (issue
/// #1742 W4 via #1739 dispatch).
///
/// Re-checks at dispatch, against live Kernel-issued facts, only what the
/// bridge owns: the tool is still the exact `eliot.act` request admitted,
/// the envelope still names the live session/fence/connection, and the
/// canonical payload digest still binds the exact tool bytes. A swapped
/// packet, forged binding, or stale fence fails closed here before any
/// submit frame is built; the material floor/lineage/authority gate itself
/// stays the Kernel admission owner's `admit_material_decision`, never a
/// bridge verdict (I01-08 external effect path; I07-08 step 7). Failures are
/// typed (I07-20): fence mismatch stays `FenceMismatch`, binding mismatches
/// stay `TransportBindingRejected`, a missing session stays `PlanGap`.
fn revalidate_act_dispatch(
    request: &HostInvocationRequest,
    envelope: &HostRequestEnvelope,
    facts: &TransportFacts,
) -> Result<(), PortFailure> {
    if !matches!(request.tool, ToolRequest::Act(_)) {
        return Err(request_failure());
    }
    if request.tool.canonical_name() != "eliot.act"
        || envelope.identity.capability != request.tool.canonical_name()
    {
        return Err(PortFailure::TransportBindingRejected {
            reason: "act dispatch capability does not match the admitted tool".to_owned(),
        });
    }
    let live_session = facts.session.clone().ok_or_else(plan_gap_no_session)?;
    if envelope.identity.session_id.as_deref() != Some(live_session.as_str()) {
        return Err(PortFailure::TransportBindingRejected {
            reason: "act dispatch session does not match the live attach session".to_owned(),
        });
    }
    if envelope.state_fence != facts.state_fence {
        return Err(PortFailure::FenceMismatch);
    }
    if envelope.connection_id != facts.connection_id {
        return Err(PortFailure::TransportBindingRejected {
            reason: "act dispatch connection does not match the live admitted connection"
                .to_owned(),
        });
    }
    let expected_payload = canonical_payload_digest(&request.tool)?;
    if expected_payload != envelope.identity.payload_sha256 {
        return Err(PortFailure::TransportBindingRejected {
            reason: "act dispatch payload does not match the admitted payload digest".to_owned(),
        });
    }
    Ok(())
}

/// Invoke-read membership for tests: true exactly when the recorded dispatch
/// map ([`canonical_dispatch_entry`]) routes the request to the linkage-checked
/// invoke-read entry (Implements #18: local read result).
#[cfg(test)]
fn invokes_local_read(request: &HostInvocationRequest) -> bool {
    matches!(
        canonical_dispatch_entry(&request.tool),
        CanonicalDispatchEntry::InvokeRead
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

/// Owner-issued dry-run preview for one invocation (issue #1939, I7.17).
///
/// Decoded from the kernel preview entry with the same connection/digest/
/// fence joins as the admitted reply: only an answer naming this exact
/// envelope, capability, payload, connection, and fence is accepted. The
/// owner never mints an operation identity here, so there is no handle
/// field; `previewed` is true only when the owner validated a serving read
/// lane (validation ran, never a simulation and never an effect).
#[derive(Clone, Debug)]
pub struct OwnerDryRunPreview {
    /// Serving read lane the owner validated (`query`, `skill`,
    /// `campaign-packet`, or `state`); `None` for unsupported tools.
    pub lane: Option<String>,
    /// True only when the owner validated a serving lane.
    pub previewed: bool,
}

/// Derives the preview request label for one host correlation.
///
/// Readable `{correlation}:preview` while it fits the envelope text ceiling;
/// a digest fallback beyond that, mirroring [`resolve_request_label`] so a
/// long-but-submittable correlation never loses its preview path.
/// Deterministic and unique per correlation, which is all the transport
/// correlation needs.
fn preview_request_label(base: &str) -> String {
    let direct = format!("{base}:preview");
    if direct.len() <= MAX_RESOLVE_LABEL_BYTES {
        direct
    } else {
        format!("preview:{}", sha256_hex(base.as_bytes()))
    }
}

/// Builds one lookup-only preview envelope over the current transport binding
/// (issue #1939, I7.17).
///
/// Mirrors [`build_resolve_envelope`]: the kind is observation-only `Status`
/// with no parent and no correlation projection (the only parentless `Status`
/// shape the envelope contract admits), capability and payload digest name
/// the exact tool bytes carried beside it, and the identity is fresh
/// (`{correlation}:preview`) so no replay cache, resolve probe, or prior
/// admission is consulted or recorded. Nothing here stages or receipts.
fn build_preview_envelope(
    request: &HostInvocationRequest,
    facts: &TransportFacts,
    session_id: &str,
    payload_digest: &str,
    now_ms: u64,
) -> Result<HostRequestEnvelope, PortFailure> {
    let label = preview_request_label(request.correlation_id.as_str());
    let deadline = now_ms.saturating_add(DEFAULT_DEADLINE_PREFERENCE_MS);
    if deadline == 0 {
        return Err(request_failure());
    }
    let identity = HostRequestIdentity {
        request_id: RequestId::new(&label).map_err(|_| request_failure())?,
        correlation_projection: None,
        idempotency_key: format!("{label}:idempotent"),
        cancellation_id: format!("{label}:cancel"),
        parent_operation_id: None,
        deadline_unix_ms: deadline,
        capability: request.tool.canonical_name().to_owned(),
        session_id: Some(session_id.to_owned()),
        task_id: None,
        work_scope_id: None,
        payload_schema_id: HOST_REQUEST_PAYLOAD_SCHEMA_ID.to_owned(),
        payload_sha256: payload_digest.to_owned(),
    };
    finish_envelope(facts, HostRequestKind::Status, identity)
}

/// Builds one preview frame carrying the exact envelope plus the exact
/// canonical tool bytes it previews.
///
/// Reuses the neutral frame identity of
/// [`host_request_frame_for_envelope`]; only the payload gains the `tool`
/// bytes the kernel linkage gate binds to the envelope digest before
/// validating. The kernel answers the exact preview or the typed unsupported
/// value; nothing is staged or receipted.
fn host_request_preview_frame(
    request: &HostInvocationRequest,
    envelope: &HostRequestEnvelope,
    facts: &TransportFacts,
) -> Result<Frame, PortFailure> {
    let mut frame =
        host_request_frame_for_envelope(AGENT_HOST_REQUEST_PREVIEW_OPERATION, envelope, facts)?;
    let tool = serde_json::to_value(&request.tool).map_err(|_| request_failure())?;
    let ProtocolPayload::Json(payload) = &mut frame.payload else {
        return Err(request_failure());
    };
    payload["tool"] = tool;
    frame.validate().map_err(|_| request_failure())?;
    Ok(frame)
}

/// Decodes one kernel preview answer after joining it to the exact preview
/// envelope, tool, connection, and fence.
///
/// Mirrors [`decode_admitted_reply`]: the frame must correlate to the sent
/// envelope and the payload must carry `status: "known"`. The value must then
/// name this exact envelope digest, capability, payload digest, connection,
/// and fence, come from the owner preview source, and carry a closed
/// disposition with its lane contract (`dry_run_preview` always names a
/// serving lane; `dry_run_unsupported` never does). Anything else fails
/// closed so the caller keeps the local static fallback.
fn decode_preview_reply(
    reply: &Frame,
    envelope: &HostRequestEnvelope,
    request: &HostInvocationRequest,
    facts: &TransportFacts,
) -> Option<OwnerDryRunPreview> {
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
    let ProtocolPayload::Json(payload) = &reply.payload else {
        return None;
    };
    if canonical_json_bytes(payload).ok()?.len() > HARD_STRUCTURED_RESPONSE_BYTES {
        return None;
    }
    if payload.get("status")?.as_str()? != "known" {
        return None;
    }
    let value = payload.get("value")?;
    if value.get("accepted")?.as_bool() != Some(true) {
        return None;
    }
    if value.get("envelope_sha256")?.as_str()? != envelope.envelope_sha256.as_str() {
        return None;
    }
    if value.get("capability")?.as_str()? != request.tool.canonical_name() {
        return None;
    }
    let expected_digest = canonical_payload_digest(&request.tool).ok()?;
    if value.get("payload_sha256")?.as_str()? != expected_digest.as_str() {
        return None;
    }
    if value.get("connection_id")?.as_str()? != facts.connection_id.as_str() {
        return None;
    }
    let fence: StateFence = serde_json::from_value(value.get("state_fence")?.clone()).ok()?;
    if fence != facts.state_fence {
        return None;
    }
    if value.get("source")?.as_str()? != OWNER_DRY_RUN_PREVIEW_SOURCE {
        return None;
    }
    match value.get("preview")?.as_str()? {
        "dry_run_preview" => {
            let lane = value.get("lane")?.as_str()?;
            if !matches!(lane, "query" | "skill" | "campaign-packet" | "state") {
                return None;
            }
            Some(OwnerDryRunPreview {
                lane: Some(lane.to_owned()),
                previewed: true,
            })
        }
        "dry_run_unsupported" => {
            if !value.get("lane")?.is_null() {
                return None;
            }
            Some(OwnerDryRunPreview {
                lane: None,
                previewed: false,
            })
        }
        _ => None,
    }
}

/// Builds one rehydrate frame carrying the exact (envelope, admission-receipt)
/// pair the kernel admitted.
///
/// Reuses the neutral frame identity of
/// [`host_request_frame_for_envelope`]; only the payload gains the `receipt`
/// bytes the kernel re-validates against the presenting envelope before
/// serving the durable record. The envelope identity is presented unchanged —
/// never rebuilt, never rebound — so the reply joins still prove the exact
/// admitted operation. No new receipt is expected, no state advances, and no
/// replay-cache entry is written: there is exactly one ledger, kernel-side.
fn host_request_rehydrate_frame(
    envelope: &HostRequestEnvelope,
    receipt: &HostRequestAdmissionReceipt,
    facts: &TransportFacts,
) -> Result<Frame, PortFailure> {
    let mut frame =
        host_request_frame_for_envelope(AGENT_HOST_REQUEST_REHYDRATE_OPERATION, envelope, facts)?;
    let receipt_value = serde_json::to_value(receipt).map_err(|_| request_failure())?;
    let ProtocolPayload::Json(payload) = &mut frame.payload else {
        return Err(request_failure());
    };
    payload["receipt"] = receipt_value;
    frame.validate().map_err(|_| request_failure())?;
    Ok(frame)
}

/// Builds the logical-key resolve query carried beside the resolve
/// envelope (issue #2571).
///
/// The owner recomputes the canonical key from the envelope session plus
/// these selectors and requires equality with the presented key before any
/// lookup, so a confused selector can never address another request's
/// history. Called on every invocation cache miss, including when no
/// earlier admission acknowledgement reached the Bridge.
fn resolve_key_query(
    logical_key: &str,
    occurrence: &str,
    capability: &str,
    payload_digest: &str,
    projection: Option<&HostCorrelationProjection>,
    parent_operation_id: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "form": "logical-key",
        "logical_key": logical_key,
        "occurrence": occurrence,
        "capability": capability,
        "payload_digest": payload_digest,
        "correlation_projection": projection,
        "parent_operation_id": parent_operation_id,
    })
}

/// Builds a presence-only query for a historical unmarked occurrence.
/// The owner can confirm ambiguity but never returns the operation row.
fn legacy_presence_query(
    logical_key: &str,
    kind: &str,
    session: &str,
    occurrence: &str,
) -> serde_json::Value {
    serde_json::json!({
        "form": "legacy-presence",
        "logical_key": logical_key,
        "kind": kind,
        "session": session,
        "occurrence": occurrence,
    })
}

/// Builds the exact-handle resolve query carried beside the resolve
/// envelope (issue #2571).
///
/// Called on every cancellation cache miss so a fresh connection can
/// cancel or observe the old handle: the owner checks exact parent
/// ownership and current rights before returning the parent commitment,
/// and answers denial exactly like absence so no foreign task or payload
/// is disclosed.
fn resolve_handle_query(operation_handle: &str) -> serde_json::Value {
    serde_json::json!({
        "form": "operation-handle",
        "operation_handle": operation_handle,
    })
}

/// Builds one resolve frame carrying the exact resolve envelope plus its
/// typed query.
///
/// Reuses the neutral frame identity of
/// [`host_request_frame_for_envelope`]; only the payload gains the `query`
/// value the owner validates before any lookup. The old envelope is never
/// resent as current authority: the resolve envelope is built fresh over
/// the current transport facts, so no receipt is rewritten, no fence is
/// copied, and no connection-echo check is weakened.
fn host_request_resolve_frame(
    query: &serde_json::Value,
    envelope: &HostRequestEnvelope,
    facts: &TransportFacts,
) -> Result<Frame, PortFailure> {
    let mut frame =
        host_request_frame_for_envelope(AGENT_HOST_REQUEST_RESOLVE_OPERATION, envelope, facts)?;
    let ProtocolPayload::Json(payload) = &mut frame.payload else {
        return Err(request_failure());
    };
    payload["query"] = query.clone();
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
    let record = decode_record_view(
        value,
        receipt.operation_id.as_str(),
        &envelope.envelope_sha256,
    )?;
    Some((receipt, record))
}

/// Recognizes the exact correlated compatibility refusal emitted by the
/// Kernel cutover gate or atomic ORS legacy-predecessor check. This is a
/// typed terminal disposition, never an admitted record or reason string.
fn is_legacy_correlation_unresolved_reply(reply: &Frame, envelope: &HostRequestEnvelope) -> bool {
    if reply.validate().is_err()
        || reply.kind != FrameKind::Response
        || reply.message_type != MessageType::Result
        || reply.connection_id != envelope.connection_id
        || reply.request_id.as_ref() != Some(&envelope.identity.request_id)
        || reply.request_identity.is_some()
    {
        return false;
    }
    let ProtocolPayload::Json(payload) = &reply.payload else {
        return false;
    };
    payload.get("status").and_then(serde_json::Value::as_str) == Some("known")
        && payload
            .get("value")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|value| {
                value.get("accepted").and_then(serde_json::Value::as_bool) == Some(false)
                    && value.get("resolve").and_then(serde_json::Value::as_str)
                        == Some("legacy_correlation_unresolved")
                    && value.get("reason_code").and_then(serde_json::Value::as_str)
                        == Some("LEGACY_CORRELATION_UNRESOLVED")
                    && value
                        .get("recovery")
                        .and_then(serde_json::Value::as_object)
                        .and_then(|recovery| recovery.get("directive"))
                        .and_then(serde_json::Value::as_str)
                        == Some("reconcile_existing_operation_no_handle_issued")
                    && !value.contains_key("receipt")
                    && !value.contains_key("record")
                    && !value.contains_key("operation_handle")
            })
}

/// Recognizes a correlated atomic owner conflict returned after another
/// submit claimed the same marked typed identity with different commitments.
/// The response grants no operation or handle and remains a typed conflict.
fn is_idempotency_conflict_reply(reply: &Frame, envelope: &HostRequestEnvelope) -> bool {
    if reply.validate().is_err()
        || reply.kind != FrameKind::Response
        || reply.message_type != MessageType::Result
        || reply.connection_id != envelope.connection_id
        || reply.request_id.as_ref() != Some(&envelope.identity.request_id)
        || reply.request_identity.is_some()
    {
        return false;
    }
    let ProtocolPayload::Json(payload) = &reply.payload else {
        return false;
    };
    payload.get("status").and_then(serde_json::Value::as_str) == Some("known")
        && payload
            .get("value")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|value| {
                value.get("accepted").and_then(serde_json::Value::as_bool) == Some(false)
                    && value.get("resolve").and_then(serde_json::Value::as_str) == Some("conflict")
                    && !value.contains_key("receipt")
                    && !value.contains_key("record")
                    && !value.contains_key("operation_handle")
            })
}

/// Strictly decodes one receipt-less rehydrate reply against the exact
/// presented envelope: response/result shape, connection and request joins,
/// closed `known`/`accepted` status, and the operation join proved against the
/// envelope-derived handle (no new receipt is issued on this entry).
/// Any mismatch is an unknown delivery (`None`), never a guessed outcome.
fn decode_rehydrated_reply(
    reply: &Frame,
    envelope: &HostRequestEnvelope,
) -> Option<AdmittedReplyView> {
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
    let expected = host_request_operation_id(envelope);
    if value.get("operation_id")?.as_str()? != expected {
        return None;
    }
    decode_record_view(value, &expected, &envelope.envelope_sha256)
}

/// What the bridge asked the resolve entry to prove (issue #2571).
enum ResolveQuery {
    /// Replay lookup: return the durable winner for this logical key, or
    /// prove it absent, conflicting, or unavailable.
    LogicalKey { key: String },
    /// Historical unmarked occurrence presence only; never returns a record.
    LegacyPresence { key: String },
    /// Parent lookup: return the durable record for this exact handle, or
    /// prove it absent (denial included, without disclosure) or unavailable.
    OperationHandle { handle: String },
}

/// The explicit owner response to one resolve (issue #2571).
///
/// Every variant is produced from the owner's typed reply, never guessed:
/// `Resolved` carries the original handle, state, and result with their
/// historical binding; `Absent` authoritatively permits staging a new
/// occurrence under admitted continuity; `Conflict` reports a changed
/// commitment under a known key; `Unavailable` is the explicit recovery
/// limitation for transport, store, or verification failure.
enum LogicalOwnerOutcome {
    /// The original handle, state, and result with their historical
    /// binding. Boxed: the record is the large variant beside the small
    /// dispositional answers.
    Resolved(Box<AdmittedReplyView>),
    /// An owner-confirmed historical occurrence that cannot be typed safely.
    LegacyUnresolved,
    Absent,
    Conflict,
    Unavailable,
}

/// Strictly decodes one resolve reply against the exact resolve envelope.
///
/// Transport joins mirror the submit family (response/result shape,
/// current connection and resolve-request joins, no request identity);
/// the resolve envelope is current transport, never authority, so no
/// receipt is expected and none is accepted. A resolved record must carry
/// its original digest for body coherence; anything else — a wrong echo,
/// a malformed handle, a missing digest — is `Unavailable`, never a
/// guessed outcome and never absence.
fn decode_resolve_reply(
    reply: &Frame,
    envelope: &HostRequestEnvelope,
    query: &ResolveQuery,
) -> LogicalOwnerOutcome {
    let payload = (|| {
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
        Some(payload)
    })();
    let Some(payload) = payload else {
        return LogicalOwnerOutcome::Unavailable;
    };
    let Some(value) = payload.get("value") else {
        return LogicalOwnerOutcome::Unavailable;
    };
    decode_resolve_value(value, query)
}

fn decode_resolve_value(value: &serde_json::Value, query: &ResolveQuery) -> LogicalOwnerOutcome {
    if value.get("accepted").and_then(serde_json::Value::as_bool) == Some(true) {
        let Some(operation_id) = value
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
        else {
            return LogicalOwnerOutcome::Unavailable;
        };
        match query {
            ResolveQuery::LogicalKey { key } => {
                let echo = value.get("logical_key").and_then(serde_json::Value::as_str);
                if echo != Some(key.as_str()) {
                    return LogicalOwnerOutcome::Unavailable;
                }
                if parse_operation_handle(operation_id).is_err() {
                    return LogicalOwnerOutcome::Unavailable;
                }
            }
            ResolveQuery::LegacyPresence { .. } => {
                return LogicalOwnerOutcome::Unavailable;
            }
            ResolveQuery::OperationHandle { handle } => {
                if operation_id != handle.as_str() {
                    return LogicalOwnerOutcome::Unavailable;
                }
            }
        }
        let Some(coherence) = value
            .get("record")
            .and_then(|record| record.get("request_digest"))
            .and_then(serde_json::Value::as_str)
        else {
            return LogicalOwnerOutcome::Unavailable;
        };
        let coherence = coherence.to_owned();
        return match decode_record_view(value, operation_id, &coherence) {
            Some(record) => LogicalOwnerOutcome::Resolved(Box::new(record)),
            None => LogicalOwnerOutcome::Unavailable,
        };
    }
    let Some(disposition) = value.get("resolve").and_then(serde_json::Value::as_str) else {
        return LogicalOwnerOutcome::Unavailable;
    };
    match (query, disposition) {
        (
            ResolveQuery::LogicalKey { key } | ResolveQuery::LegacyPresence { key },
            "legacy_correlation_unresolved",
        ) => {
            let echo = value.get("logical_key").and_then(serde_json::Value::as_str);
            if echo != Some(key.as_str()) {
                return LogicalOwnerOutcome::Unavailable;
            }
            LogicalOwnerOutcome::LegacyUnresolved
        }
        (ResolveQuery::LogicalKey { key } | ResolveQuery::LegacyPresence { key }, "absent") => {
            let echo = value.get("logical_key").and_then(serde_json::Value::as_str);
            if echo == Some(key.as_str()) {
                LogicalOwnerOutcome::Absent
            } else {
                LogicalOwnerOutcome::Unavailable
            }
        }
        (ResolveQuery::OperationHandle { .. }, "absent") => LogicalOwnerOutcome::Absent,
        (ResolveQuery::LogicalKey { .. }, "conflict") => LogicalOwnerOutcome::Conflict,
        _ => LogicalOwnerOutcome::Unavailable,
    }
}

/// Verifies that a resolved record carries the requested logical key
/// (issue #2571).
///
/// Recomputes the canonical key from the record's exact commitment fields
/// and requires equality with the requested key: the returned original
/// commitment must match the requested semantic input before its handle,
/// state, or result is adopted. A missing commitment field, an
/// unrecognized kind, or a mismatch fails closed as the explicit recovery
/// limitation — never as a conflict and never as absence.
struct ResolvedKeyCommitment<'a> {
    key: &'a str,
    occurrence: &'a str,
    session: &'a str,
    task_ref: Option<&'a str>,
    scope_ref: Option<&'a str>,
    capability: &'a str,
    payload_digest: &'a str,
    parent: Option<&'a str>,
    projection: &'a HostCorrelationProjection,
}

fn verify_resolved_key_commitment(
    record: &AdmittedReplyView,
    expected: &ResolvedKeyCommitment<'_>,
) -> Result<(), PortFailure> {
    let limitation = || unknown_resolve_outcome(expected.key);
    let Some(kind) = &record.kind else {
        return Err(limitation());
    };
    let Some(occurrence) = &record.request_id else {
        return Err(limitation());
    };
    let Some(session) = &record.session_ref else {
        return Err(limitation());
    };
    let Some(capability) = &record.capability_ref else {
        return Err(limitation());
    };
    let Some(payload) = &record.payload_digest else {
        return Err(limitation());
    };
    if record.request_digest.is_none()
        || occurrence != expected.occurrence
        || session != expected.session
        || record.task_ref.as_deref() != expected.task_ref
        || record.scope_ref.as_deref() != expected.scope_ref
        || capability != expected.capability
        || payload != expected.payload_digest
        || record.parent_operation_id.as_deref() != expected.parent
        || record.correlation_projection.as_ref() != Some(expected.projection)
    {
        return Err(limitation());
    }
    let kind = HostRequestLogicalKind::parse(kind).ok_or_else(limitation)?;
    if expected.projection.occurrence_text() != *occurrence {
        return Err(limitation());
    }
    let recomputed =
        host_request_logical_key(kind, session, expected.projection).map_err(|_| limitation())?;
    if recomputed != expected.key {
        return Err(limitation());
    }
    Ok(())
}

/// Decodes the durable record under one reply value after the caller proved
/// the operation join: exact operation identity plus the result-pair coherence
/// rules shared by the submit-family, rehydrate, and resolve answers. A result pair
/// where none belongs (or a half-present pair) fails decoding into the
/// unknown-outcome path: the bridge never guesses which half to trust.
/// `RESULT_RECEIVED` must carry both; a `TERMINAL` may carry both forward;
/// every other state must carry neither.
///
/// `coherence_request_digest` is the exact admitted envelope digest the
/// result body must bind: the presenting envelope's digest for the
/// submit-family and rehydrate answers (the presented envelope IS the
/// admitted one there), the original record's digest for resolve answers
/// (the resolve envelope is current transport, never the original
/// authority).
fn decode_record_view(
    value: &serde_json::Value,
    expected_operation_id: &str,
    coherence_request_digest: &str,
) -> Option<AdmittedReplyView> {
    let record: AdmittedReplyView = serde_json::from_value(value.get("record")?.clone()).ok()?;
    if record.operation_id != expected_operation_id {
        return None;
    }
    let carries_result = record.result_digest.is_some() || record.result_response.is_some();
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
            request_sha256: coherence_request_digest.to_owned(),
            result_digest: digest.clone(),
            response: body.clone(),
            // Readback coherence only: stored rows predate attempt ownership,
            // so no attempt is presented here. Submissions always carry the
            // current attempt, enforced by the Kernel legs.
            attempt: None,
            lineage: None,
            // Readback coherence only: stored rows predate execution evidence.
            evidence: None,
        }
        .validate()
        .ok()?;
        // The retained lineage the Kernel bound to THIS row is checked by the
        // SHARED owner rule, against the exact result pair recorded on the same
        // row. A class claimed for one result must not be adopted by another,
        // and a canonical class without its admitted receipt is refused here
        // rather than presented to a consumer as an admitted record. Both
        // comparisons below use ORIGINALLY RECORDED values; nothing is
        // recomputed over the bytes in hand.
        // An ABSENT lineage is an unknown, not a failure, so the let-chain
        // leaves the record produced: only a lineage that IS present and then
        // fails the rule refuses this read.
        if let Some(lineage) = &record.result_lineage
            && lineage.validate_retained(digest).is_err()
        {
            return None;
        }
    }
    Some(record)
}

/// Commits to the exact source record plus the live transport binding.
///
/// Versioned preimage fields are explicit so the retained token cannot be
/// mistaken for a Kernel receipt or authority. The owner record and current
/// facts are re-read and this same preimage is rebuilt before every resource
/// expansion.
fn resource_authorization_digest(
    operation_handle: &HostOperationHandle,
    facts: &TransportFacts,
    record: &AdmittedReplyView,
) -> Result<String, PortFailure> {
    let request_digest = record
        .request_digest
        .as_deref()
        .ok_or_else(resource_source_refused)?;
    let request_id = record
        .request_id
        .as_deref()
        .ok_or_else(resource_source_refused)?;
    let capability = record
        .capability_ref
        .as_deref()
        .ok_or_else(resource_source_refused)?;
    let payload_digest = record
        .payload_digest
        .as_deref()
        .ok_or_else(resource_source_refused)?;
    let result_digest = record
        .result_digest
        .as_deref()
        .ok_or_else(resource_source_refused)?;
    let result_response = record
        .result_response
        .as_ref()
        .ok_or_else(resource_source_refused)?;
    let session = record
        .session_ref
        .as_deref()
        .ok_or_else(resource_source_refused)?;
    if record.operation_id != operation_handle.as_str()
        || facts.session.as_deref() != Some(session)
        || record.kind.as_deref() != Some("INVOCATION")
    {
        return Err(resource_source_refused());
    }
    // A resource whose owner named no provenance cannot be authorized at all:
    // the caller's own check refuses that record, and spelling `UNCLASSIFIED`
    // here would let an unknown claim ride inside a binding that other checks
    // read as evidence. The spelling is the owner's recorded one.
    let recorded_class = record
        .result_lineage
        .as_ref()
        .map(|lineage| lineage.result_class)
        .ok_or_else(resource_source_refused)?;
    let result_class = result_class_wire_name(recorded_class)?;
    let preimage = ResourceAuthorizationPreimage {
        // Version 2 binds the owner-recorded result class (issue #1809 item 7).
        // A binding captured before the class was part of the preimage can no
        // longer be recomputed, so it fails the re-authorization on the read
        // leg instead of silently authorizing under a weaker commitment. There
        // is no live caller holding a version-1 binding: this digest is
        // captured and re-derived inside one bridge process.
        version: "eliot.bridge.resource-source.v2",
        operation_handle: operation_handle.as_str(),
        connection_id: facts.connection_id.as_str(),
        session_id: session,
        state_fence: &facts.state_fence,
        descriptor_sha256: facts.descriptor_sha256.as_str(),
        receipt_sha256: facts.receipt_sha256.as_str(),
        request_digest,
        request_id,
        capability,
        payload_digest,
        result_digest,
        result_response,
        result_class,
        task_ref: record.task_ref.as_deref(),
        scope_ref: record.scope_ref.as_deref(),
    };
    let bytes = canonical_json_bytes(&preimage).map_err(|_| request_failure())?;
    Ok(sha256_hex(&bytes))
}

/// Builds the typed rejection for a restore reply whose body does not bind
/// the admitted request.
fn invalid_restore(detail: &str) -> PortFailure {
    PortFailure::TransportBindingRejected {
        reason: format!("kernel restore body is not the admitted answer: {detail}"),
    }
}

/// Decodes one restore reply and checks it against the admitted request.
///
/// Mirrors `decode_stored_response` binding semantics (request/digest joins
/// against the exact sent envelope) without tool bindings: the digest must
/// bind the canonical reply bytes, and the reply must validate. Session and
/// fence echo equality against the live binding is the composition's
/// authority check, not transport's.
fn decode_restore_reply(record: &AdmittedReplyView) -> Result<ReactiveRestoreReply, PortFailure> {
    let body = record
        .result_response
        .clone()
        .ok_or_else(|| invalid_restore("a received restore must carry its bounded body"))?;
    let digest = record
        .result_digest
        .clone()
        .ok_or_else(|| invalid_restore("a received restore must carry its digest"))?;
    let bytes = canonical_json_bytes(&body).map_err(|_| invalid_restore("uncanonicalizable"))?;
    if sha256_hex(&bytes) != digest {
        return Err(invalid_restore("digest does not bind the exact body"));
    }
    let reply: ReactiveRestoreReply =
        serde_json::from_value(body).map_err(|_| invalid_restore("body is not a restore reply"))?;
    reply
        .validate()
        .map_err(|error| invalid_restore(&error.to_string()))?;
    Ok(reply)
}

/// Builds the typed rejection for a result-bearing reply whose body does not
/// bind the admitted request.
fn invalid_result(detail: &str) -> PortFailure {
    PortFailure::TransportBindingRejected {
        reason: format!("kernel result body is not the admitted answer: {detail}"),
    }
}

/// Decodes one stored bounded response and checks it against the admitted
/// request (Implements #18: local read result; #2564 item 5: the canonical
/// request digest binds the actual expected request).
///
/// Mirrors `host_gateway.rs:406-436` (bounded size, tool binding) plus the
/// `check_response_binding` semantics (request/idempotency/tool/digest joins
/// against the exact sent envelope). Any mismatch is a typed rejection, never
/// a guessed outcome and never a silent admission.
///
/// The digest check is an equality against the exact expected request
/// commitment ([`expected_canonical_request_digest`]), never a well-formedness
/// shape check: a well-formed unrelated digest is insufficient and fails
/// closed here, so a substituted request identity cannot be adopted as the
/// admitted answer.
fn decode_stored_response(
    record: &AdmittedReplyView,
    request: &HostInvocationRequest,
    envelope: &HostRequestEnvelope,
) -> Result<McpResponse, PortFailure> {
    let body = record
        .result_response
        .clone()
        .ok_or_else(|| invalid_result("a received result must carry its bounded body"))?;
    let encoded = serde_json::to_vec(&body).map_err(|_| invalid_result("unserializable body"))?;
    if encoded.len() > HARD_STRUCTURED_RESPONSE_BYTES {
        return Err(invalid_result("body exceeds the bounded ceiling"));
    }
    let response: McpResponse = serde_json::from_value(body)
        .map_err(|_| invalid_result("body is not a bounded response"))?;
    if response.request_id != envelope.identity.request_id.as_str() {
        return Err(invalid_result("request identity mismatch"));
    }
    if response.idempotency_key != envelope.identity.idempotency_key {
        return Err(invalid_result("idempotency binding mismatch"));
    }
    if response.canonical_tool_name != request.tool.canonical_name() {
        return Err(invalid_result("tool binding mismatch"));
    }
    let expected_request = expected_canonical_request_digest(envelope)?;
    if response.canonical_request_sha256 != expected_request {
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

/// Decodes one owner-resolved stored result against the original admission
/// (issue #2571).
///
/// Mirrors [`decode_stored_response`] with a different trust root: the
/// presenting resolve envelope is current transport, so the request
/// triple is rebuilt from the original record digest plus the
/// occurrence-derived request and idempotency identities (recomputed from
/// the stable correlation, never trusted from the reply). The recovered
/// result is therefore verified against the original admission with
/// current response correlation, and the original handle stays the typed
/// reconcile path.
fn decode_resolved_response(
    record: &AdmittedReplyView,
    occurrence: &str,
    tool_name: &str,
    request_digest: &str,
) -> Result<McpResponse, PortFailure> {
    let idempotency_key = format!("{occurrence}:invoke");
    let body = record
        .result_response
        .clone()
        .ok_or_else(|| invalid_result("a received result must carry its bounded body"))?;
    let encoded = serde_json::to_vec(&body).map_err(|_| invalid_result("unserializable body"))?;
    if encoded.len() > HARD_STRUCTURED_RESPONSE_BYTES {
        return Err(invalid_result("body exceeds the bounded ceiling"));
    }
    let response: McpResponse = serde_json::from_value(body)
        .map_err(|_| invalid_result("body is not a bounded response"))?;
    if response.request_id != occurrence {
        return Err(invalid_result("request identity mismatch"));
    }
    if response.idempotency_key != idempotency_key {
        return Err(invalid_result("idempotency binding mismatch"));
    }
    if response.canonical_tool_name != tool_name {
        return Err(invalid_result("tool binding mismatch"));
    }
    let expected_request =
        expected_canonical_request_digest_by_parts(request_digest, occurrence, &idempotency_key)?;
    if response.canonical_request_sha256 != expected_request {
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

/// Derives the exact canonical request digest one admitted stored result
/// must echo (#2564 item 5).
///
/// Byte-identical to the producer commitment in
/// `AuthenticatedHostSession::build_local_read_result_body`
/// (`crates/kernel/eliot-kernel-service/src/host_request_binding.rs`): the
/// SHA-256 of the canonical JSON of the `(envelope digest, request id,
/// idempotency key)` triple. The bridge holds the exact sent envelope, so
/// this is the actual expected request — computed, never guessed, and never
/// a shape-only check. The Kernel `local_read` leg is the single production
/// result producer reachable through this client's frame path, so this one
/// formula is the complete expected set; no second formula is accepted.
fn expected_canonical_request_digest(
    envelope: &HostRequestEnvelope,
) -> Result<String, PortFailure> {
    expected_canonical_request_digest_by_parts(
        envelope.envelope_sha256.as_str(),
        envelope.identity.request_id.as_str(),
        envelope.identity.idempotency_key.as_str(),
    )
}

/// Derives the expected canonical request digest from explicit parts.
///
/// The resolve path (issue #2571) holds the original digest from the
/// owner-returned record instead of the presenting envelope, so the same
/// formula is applied to caller-supplied parts. The occurrence-derived
/// request and idempotency identities are recomputed from the stable
/// correlation, never trusted from the reply.
fn expected_canonical_request_digest_by_parts(
    request_digest: &str,
    request_id: &str,
    idempotency_key: &str,
) -> Result<String, PortFailure> {
    let bytes = canonical_json_bytes(&(
        request_digest.to_owned(),
        request_id.to_owned(),
        idempotency_key.to_owned(),
    ))
    .map_err(|_| invalid_result("uncanonicalizable"))?;
    Ok(sha256_hex(&bytes))
}

/// Maps one durable terminal record that carries no servable result to its
/// typed invocation outcome (issue #1739 W6).
///
/// The Kernel-authored failure envelope (stable disposition, verbatim reason
/// code, typed directive, issue #1743) is the only producer of that triple,
/// and only the Kernel can author one — the bridge never invents it here.
/// What this preserves instead, in one stable shape rather than ad-hoc prose
/// per site: the original operation identity and the reconcile directive,
/// with the durable state (`Terminal` vs `Conflicted`) named so the two
/// stay distinguishable. A terminal record WITH a servable result never
/// reaches here: it decodes through [`decode_stored_response`] above.
fn terminal_without_result_outcome(
    operation_id: &str,
    state: HostRequestRecordState,
) -> PortFailure {
    PortFailure::TransportBindingRejected {
        reason: format!(
            "operation {operation_id} is {state:?} without a servable result; reconcile the exact operation"
        ),
    }
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
            Err(terminal_without_result_outcome(
                &receipt.operation_id,
                record.state,
            ))
        }
        HostRequestRecordState::Conflicted => Err(terminal_without_result_outcome(
            &receipt.operation_id,
            record.state,
        )),
    }
}

/// Maps one owner-resolved original record to the invocation outcome
/// (issue #2571).
///
/// Mirrors [`submit_outcome`] with the original handle, state, and result:
/// the original operation/result is returned with current response
/// correlation and no second dispatch occurs. Unresolved durable states
/// settle as admission with the original handle — the resolve read proved
/// the kernel staged the operation, so existence is certain even though
/// the bridge holds neither the original envelope nor its receipt for a
/// rehydrate. A result body is served only after it verifies against the
/// original admission triple; original expiry and cancellation survive any
/// new deadline proposal.
fn submit_outcome_for_resolved(
    record: &AdmittedReplyView,
    occurrence: &str,
    tool_name: &str,
    logical_key: &str,
) -> Result<HostInvocationPortOutcome, PortFailure> {
    let limitation = || unknown_resolve_outcome(logical_key);
    parse_operation_handle(record.operation_id.as_str()).map_err(|_| limitation())?;
    let handle = HostOperationHandle::new(record.operation_id.clone()).map_err(|_| limitation())?;
    let request_digest = record.request_digest.as_deref().ok_or_else(limitation)?;
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
        HostRequestRecordState::ResultReceived => {
            let response = decode_resolved_response(record, occurrence, tool_name, request_digest)?;
            Ok(HostInvocationPortOutcome::Responded {
                operation_handle: handle,
                response: Box::new(response),
            })
        }
        HostRequestRecordState::Expired => Err(PortFailure::DeadlineExceeded),
        HostRequestRecordState::Cancelled => Err(PortFailure::Cancelled),
        HostRequestRecordState::Terminal => {
            if record.result_digest.is_some() {
                let response =
                    decode_resolved_response(record, occurrence, tool_name, request_digest)?;
                return Ok(HostInvocationPortOutcome::Responded {
                    operation_handle: handle,
                    response: Box::new(response),
                });
            }
            Err(terminal_without_result_outcome(
                &record.operation_id,
                record.state,
            ))
        }
        HostRequestRecordState::Conflicted => Err(terminal_without_result_outcome(
            &record.operation_id,
            record.state,
        )),
    }
}

/// Maps one exact parent operation's durable owner state to its cancellation
/// disposition (issue #2571).
///
/// Only an owner-observed `CANCELLED` parent proves cancellation. A completed
/// or otherwise terminal parent is already terminal; every nonterminal or
/// unresolved state remains an exact-handle unknown outcome.
fn map_parent_cancellation_disposition(
    state: HostRequestRecordState,
    operation_handle: &str,
) -> Result<HostCancellationPortOutcome, PortFailure> {
    match state {
        HostRequestRecordState::Cancelled => Ok(HostCancellationPortOutcome::Accepted),
        HostRequestRecordState::ResultReceived
        | HostRequestRecordState::Terminal
        | HostRequestRecordState::Conflicted
        | HostRequestRecordState::Expired => Ok(HostCancellationPortOutcome::AlreadyTerminal),
        HostRequestRecordState::Requested
        | HostRequestRecordState::Admitted
        | HostRequestRecordState::Routed
        | HostRequestRecordState::Submitted
        | HostRequestRecordState::PossiblyEffected
        | HostRequestRecordState::Unknown
        | HostRequestRecordState::Reconciling => Err(unknown_cancel_outcome(operation_handle)),
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
        let now_ms = unix_ms()?;
        let facts = self
            .shared
            .try_borrow()
            .map_err(|_| request_failure())?
            .snapshot();
        let session = facts.session.clone().ok_or_else(plan_gap_no_session)?;
        let correlation = request.correlation_id.as_str().to_owned();
        let payload_digest = canonical_payload_digest(&request.tool)?;
        let envelope = match self.replay_or_build_invocation(
            &correlation,
            request,
            &facts,
            &session,
            &payload_digest,
            now_ms,
        )? {
            // The owner resolved the exact marked logical key to its durable
            // winner: return the original handle/state/result with current
            // response correlation. No second dispatch occurs, including
            // when the first admission acknowledgement was lost. Unmarked
            // legacy rows never reach this path because they lack a typed
            // projection and are reported as unresolved.
            InvocationPreparation::Recovered(record, logical_key) => {
                let occurrence = record
                    .request_id
                    .clone()
                    .unwrap_or_else(|| correlation.clone());
                return submit_outcome_for_resolved(
                    &record,
                    occurrence.as_str(),
                    request.tool.canonical_name(),
                    logical_key.as_str(),
                );
            }
            InvocationPreparation::Submit(envelope) => envelope,
        };
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
        let frame = match canonical_dispatch_entry(&request.tool) {
            CanonicalDispatchEntry::InvokeRead => {
                host_request_invoke_read_frame(request, &envelope, &facts)?
            }
            CanonicalDispatchEntry::SubmitAdmitOnly { .. } => host_request_frame_for_envelope(
                AGENT_HOST_REQUEST_SUBMIT_OPERATION,
                &envelope,
                &facts,
            )?,
            CanonicalDispatchEntry::SubmitActGated { .. } => {
                revalidate_act_dispatch(request, &envelope, &facts)?;
                host_request_frame_for_envelope(
                    AGENT_HOST_REQUEST_SUBMIT_OPERATION,
                    &envelope,
                    &facts,
                )?
            }
            CanonicalDispatchEntry::SubmitCarryingBytes => {
                host_request_user_automation_frame(request, &envelope, &facts)?
            }
            CanonicalDispatchEntry::SubmitObservePair => {
                host_request_observe_submit_frame(request, &envelope, &facts)?
            }
        };
        let reply = match self.exchange(&frame) {
            Ok(reply) => reply,
            Err(error @ PortFailure::AgentResponse { .. }) => return Err(error),
            Err(_) => return self.probe_settles_invocation(&facts, &session, &envelope, now_ms),
        };
        if is_legacy_correlation_unresolved_reply(&reply, &envelope) {
            return Err(PortFailure::LegacyCorrelationUnresolved);
        }
        if is_idempotency_conflict_reply(&reply, &envelope) {
            return Err(PortFailure::IdempotencyConflict);
        }
        match decode_admitted_reply(&reply, &envelope) {
            Some((receipt, record)) => {
                // Unresolved durable states are re-read from the Kernel-owned
                // record instead of assumed: the admitted pair is presented
                // unchanged to the rehydrate entry and the refreshed state is
                // mapped. A failed re-read keeps the admitted record the owner
                // already returned; its handle stays the typed reconcile path.
                let record = match record.state {
                    HostRequestRecordState::PossiblyEffected
                    | HostRequestRecordState::Unknown
                    | HostRequestRecordState::Reconciling => {
                        match self.rehydrate_operation(&envelope, &receipt) {
                            Ok(refreshed) => refreshed,
                            Err(error @ PortFailure::AgentResponse { .. }) => return Err(error),
                            Err(_) => record,
                        }
                    }
                    _ => record,
                };
                submit_outcome(&receipt, &record, request, &envelope)
            }
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
        // Cache first, owner on a miss: a fresh connection performs
        // authorized cancellation on the old handle through the resolve
        // entry, while denial stays indistinguishable from absence.
        let parent = self.resolve_parent_link(&digest, &facts, &session, now_ms)?;
        let envelope = build_cancellation_envelope(request, &facts, &session, &parent, now_ms)?;
        if now_ms >= envelope.identity.deadline_unix_ms {
            return Err(PortFailure::DeadlineExceeded);
        }
        let frame = host_request_frame_for_envelope(
            AGENT_HOST_REQUEST_CANCEL_OPERATION,
            &envelope,
            &facts,
        )?;
        let cancel_correlation = request.correlation_id.as_str().to_owned();
        let reply = match self.exchange(&frame) {
            Ok(reply) => reply,
            Err(error @ PortFailure::AgentResponse { .. }) => return Err(error),
            // Unknown delivery: resolve the retained cancellation identity
            // before any probe, without generating another cancellation.
            Err(_) => {
                return self.resolve_retained_cancellation(
                    &parent,
                    cancel_correlation.as_str(),
                    &envelope,
                    &facts,
                    &session,
                    now_ms,
                );
            }
        };
        if is_legacy_correlation_unresolved_reply(&reply, &envelope) {
            return Err(PortFailure::LegacyCorrelationUnresolved);
        }
        if is_idempotency_conflict_reply(&reply, &envelope) {
            return Err(PortFailure::IdempotencyConflict);
        }
        match decode_admitted_reply(&reply, &envelope) {
            Some((_, _intent_record)) => {
                self.resolve_cancellation_parent_disposition(&parent, &facts, &session)
            }
            None => self.resolve_retained_cancellation(
                &parent,
                cancel_correlation.as_str(),
                &envelope,
                &facts,
                &session,
                now_ms,
            ),
        }
    }

    fn restore_reactive_state(
        &mut self,
        query: &ReactiveRestoreQuery,
    ) -> Result<ReactiveRestoreReply, PortFailure> {
        query
            .validate()
            .map_err(|error| PortFailure::TransportBindingRejected {
                reason: format!("restore query invalid: {error}"),
            })?;
        let now_ms = unix_ms()?;
        let facts = self
            .shared
            .try_borrow()
            .map_err(|_| request_failure())?
            .snapshot();
        let session = facts.session.clone().ok_or_else(plan_gap_no_session)?;
        // Caller-text confusion checks against Kernel-issued facts: the query
        // must name the live attach session and fence, never another binding.
        if query.session_id != session {
            return Err(PortFailure::TransportBindingRejected {
                reason: "restore session does not match the live attach session".to_owned(),
            });
        }
        if query.state_fence != facts.state_fence {
            return Err(PortFailure::FenceMismatch);
        }
        let payload_digest = query.canonical_digest().map_err(|_| request_failure())?;
        let correlation = restore_correlation(&session, &facts.state_fence);
        let deadline = now_ms.saturating_add(DEFAULT_DEADLINE_PREFERENCE_MS);
        if deadline == 0 {
            return Err(request_failure());
        }
        let envelope =
            build_restore_envelope(&correlation, &facts, &session, &payload_digest, deadline)?;
        let mut frame =
            host_request_frame_for_envelope(REACTIVE_RESTORE_OPERATION, &envelope, &facts)?;
        let query_value = serde_json::to_value(query).map_err(|_| request_failure())?;
        let ProtocolPayload::Json(payload) = &mut frame.payload else {
            return Err(request_failure());
        };
        payload["restore"] = query_value;
        frame.validate().map_err(|_| request_failure())?;
        let reply = self
            .exchange(&frame)
            .map_err(|error| retain_agent_response(error, request_failure()))?;
        let (_, record) = decode_admitted_reply(&reply, &envelope).ok_or_else(|| {
            PortFailure::TransportBindingRejected {
                reason: "restore reply is not the admitted answer".to_owned(),
            }
        })?;
        decode_restore_reply(&record)
    }
}

impl KernelHostRequestClient {
    /// Rehydrates one exact previously admitted operation from the Kernel-owned
    /// durable record without resubmission.
    ///
    /// Called from [`KernelHostRequestPort::invoke`] when the admitted record
    /// arrives in an unresolved state (`PossiblyEffected`, `Unknown`,
    /// `Reconciling`): the exact admitted (envelope, admission-receipt) pair
    /// is presented unchanged and the refreshed durable state is mapped. There
    /// is no `KernelHostRequestPort` rehydrate method in `eliot-mcp`, so this
    /// stays an inherent consume method, not a trait port.
    ///
    /// Caller claims are validated against live kernel-issued facts first:
    /// envelope/receipt shape and receipt-envelope binding failures fail
    /// closed as `TransportBindingRejected`; a session or connection or
    /// descriptor claim that does not name the live attach binding fails as
    /// `TransportBindingRejected`; a fence that does not equal the live fence
    /// fails as `FenceMismatch` — mirroring `restore_reactive_state`. No host
    /// text is ever trusted for session, fence, connection, or descriptor.
    ///
    /// The frame carries the presented pair unchanged over the shared admitted
    /// transport via `self.exchange`. The admitted reply decodes through
    /// `decode_rehydrated_reply` (same joins as the submit family, minus the
    /// receipt the kernel never reissues); any undecodable or failed exchange
    /// is the typed unknown outcome keyed by the exact envelope digest — never
    /// a blind resubmit, never a second ledger, never a replay-cache write.
    pub(crate) fn rehydrate_operation(
        &mut self,
        envelope: &HostRequestEnvelope,
        receipt: &HostRequestAdmissionReceipt,
    ) -> Result<AdmittedReplyView, PortFailure> {
        envelope.validate().map_err(|_| request_failure())?;
        receipt.validate().map_err(|_| request_failure())?;
        receipt
            .validate_envelope(envelope)
            .map_err(|_| request_failure())?;
        let facts = self
            .shared
            .try_borrow()
            .map_err(|_| request_failure())?
            .snapshot();
        let session = facts.session.clone().ok_or_else(plan_gap_no_session)?;
        if envelope.connection_id != facts.connection_id {
            return Err(PortFailure::TransportBindingRejected {
                reason: "rehydrate connection does not match the live admitted connection"
                    .to_owned(),
            });
        }
        if envelope.identity.session_id.as_deref() != Some(session.as_str()) {
            return Err(PortFailure::TransportBindingRejected {
                reason: "rehydrate session does not match the live attach session".to_owned(),
            });
        }
        if envelope.state_fence != facts.state_fence {
            return Err(PortFailure::FenceMismatch);
        }
        if envelope.descriptor_sha256 != facts.descriptor_sha256 {
            return Err(PortFailure::TransportBindingRejected {
                reason: "rehydrate descriptor does not match the live admitted descriptor"
                    .to_owned(),
            });
        }
        let digest = envelope.envelope_sha256.clone();
        let frame = host_request_rehydrate_frame(envelope, receipt, &facts)?;
        let reply = self
            .exchange(&frame)
            .map_err(|error| retain_agent_response(error, unknown_outcome(&digest)))?;
        decode_rehydrated_reply(&reply, envelope).ok_or_else(|| unknown_outcome(&digest))
    }

    /// Proves the retained Kernel binding is still current before Status
    /// reports it as current or reconnect mutates local attach state.
    ///
    /// Sends one observation-only Heartbeat/Health exchange over the shared
    /// admitted transport. Kernel health is produced only after the Kernel
    /// joins the retained Session against its current front-door generation,
    /// artifact, `StateFence`, and authority epoch. This probe creates no
    /// operation identity, replay-cache entry, or durable operation, so it is
    /// also non-vacuous before the first host invocation.
    ///
    /// A failed exchange, malformed health reply, or epoch/generation mismatch
    /// fails closed as [`PortFailure::TransportBindingRejected`].
    pub fn check_kernel_binding(&mut self) -> Result<(), PortFailure> {
        let facts = self
            .shared
            .try_borrow()
            .map_err(|_| request_failure())?
            .snapshot();
        let frame = kernel_health_probe_frame(&facts)?;
        let reply = self.exchange(&frame).map_err(|_| PortFailure::TransportBindingRejected {
            reason: "live Kernel Health probe failed over the admitted transport; re-attach and activate for a new admission".to_owned(),
        })?;
        decode_kernel_health_reply(&reply, &frame, &facts).ok_or_else(|| {
            PortFailure::TransportBindingRejected {
                reason: "live Kernel Health reply did not prove the retained connection, protocol, generation, and authority epoch; re-attach and activate for a new admission".to_owned(),
            }
        })?;
        Ok(())
    }

    /// Asks the kernel preview entry to validate one invocation dry run
    /// (issue #1939, I7.17).
    ///
    /// Observation-only: builds a fresh lookup-only `Status` envelope over
    /// the current transport facts and presents the exact validated tool
    /// bytes beside it. No replay cache is consulted or recorded, no resolve
    /// probe runs, and the kernel stages nothing, so a preview can never
    /// become an admission. Any transport, decode, or owner failure is the
    /// typed error the caller maps to the local static fallback; only an
    /// exactly joined owner answer returns.
    pub fn preview_invocation(
        &mut self,
        request: &HostInvocationRequest,
    ) -> Result<OwnerDryRunPreview, PortFailure> {
        request
            .validate()
            .map_err(|error| plan_gap_bind(&error.to_string()))?;
        if let Some(projection) = request.correlation_projection.as_ref() {
            reject_kernel_operational_correlation(projection)?;
        }
        let now_ms = unix_ms()?;
        let facts = self
            .shared
            .try_borrow()
            .map_err(|_| request_failure())?
            .snapshot();
        let session = facts.session.clone().ok_or_else(plan_gap_no_session)?;
        let payload_digest = canonical_payload_digest(&request.tool)?;
        let envelope = build_preview_envelope(request, &facts, &session, &payload_digest, now_ms)?;
        let frame = host_request_preview_frame(request, &envelope, &facts)?;
        let reply = self.exchange(&frame)?;
        decode_preview_reply(&reply, &envelope, request, &facts).ok_or_else(request_failure)
    }

    /// Sends one observation-only reconcile probe for an invocation whose
    /// delivery is unknown, settling existence as admission.
    ///
    /// This is an exact real-operation probe gating per-operation settlement:
    /// it observes the one operation named by the parent handle and settles
    /// only that invocation. It is never a readiness label and introduces no
    /// readiness state.
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
            .map_err(|error| retain_agent_response(error, unknown_outcome(&digest)))?;
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
    /// This is an exact real-operation probe gating per-operation settlement:
    /// it observes the one parent named by the handle and settles only that
    /// cancellation. It is never a readiness label and introduces no
    /// readiness state.
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
            .map_err(|error| retain_agent_response(error, unknown_outcome(&digest)))?;
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
            // The fixture is a PRE-activation transport: no authenticated task
            // exists, so both members stay absent exactly as they are in
            // production before a `Resolved` activation.
            task_binding: None,
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
            "canonical_request_sha256": expected_canonical_request_digest(envelope)
                .expect("expected request digest must compute"),
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
    fn user_automation_route_binds_capability_digest_and_reconcile_selector() {
        let (base, facts, _) = test_envelope();
        let mut value = serde_json::to_value(&base).expect("base request must serialize");
        value["correlation_id"] = serde_json::json!("host-user-automation-1");
        value["tool"] = serde_json::json!({
            "name": "eliot_user_automation",
            "arguments": {
                "operation": {"kind": "list", "include_retired": false},
                "idempotency_key": "operator-retry-1"
            }
        });
        let request: HostInvocationRequest =
            serde_json::from_value(value).expect("UserAutomation request must deserialize");
        request
            .validate()
            .expect("UserAutomation request must validate");
        assert_eq!(request.tool.canonical_name(), "eliot_user_automation");

        let payload_digest = canonical_payload_digest(&request.tool)
            .expect("UserAutomation payload digest must compute");
        let envelope = build_invocation_envelope(
            &request,
            &facts,
            "kernel-session-1",
            &payload_digest,
            1_000_000,
        )
        .expect("UserAutomation envelope must build");
        assert_eq!(envelope.identity.capability, "eliot_user_automation");
        assert_eq!(envelope.identity.payload_sha256, payload_digest);

        let submit = host_request_user_automation_frame(&request, &envelope, &facts)
            .expect("UserAutomation submit frame must build");
        let submit_payload = match &submit.payload {
            ProtocolPayload::Json(payload) => payload,
            _ => panic!("submit frame must carry JSON"),
        };
        assert_eq!(
            submit_payload
                .get("operation")
                .and_then(|value| value.as_str()),
            Some(AGENT_HOST_REQUEST_SUBMIT_OPERATION)
        );
        assert_eq!(
            submit_payload
                .pointer("/envelope/identity/capability")
                .and_then(|value| value.as_str()),
            Some("eliot_user_automation")
        );
        assert_eq!(
            submit_payload
                .pointer("/envelope/identity/payload_sha256")
                .and_then(|value| value.as_str()),
            Some(payload_digest.as_str())
        );
        assert_eq!(
            submit_payload.get("tool"),
            Some(&serde_json::to_value(&request.tool).expect("tool must serialize"))
        );

        let parent = ParentLink::of(&envelope);
        let reconcile =
            build_reconciliation_envelope(&facts, "kernel-session-1", &parent, 1_000_001)
                .expect("UserAutomation reconciliation envelope must build");
        assert_eq!(reconcile.identity.capability, "eliot_user_automation");
        assert_eq!(
            reconcile.identity.payload_sha256,
            envelope.identity.payload_sha256
        );
        let reconcile_frame = host_request_frame_for_envelope(
            AGENT_HOST_REQUEST_RECONCILE_OPERATION,
            &reconcile,
            &facts,
        )
        .expect("UserAutomation reconciliation frame must build");
        let reconcile_payload = match &reconcile_frame.payload {
            ProtocolPayload::Json(payload) => payload,
            _ => panic!("reconciliation frame must carry JSON"),
        };
        assert_eq!(
            reconcile_payload
                .get("operation")
                .and_then(|value| value.as_str()),
            Some(AGENT_HOST_REQUEST_RECONCILE_OPERATION)
        );
        assert_eq!(
            reconcile.identity.parent_operation_id.as_deref(),
            Some(parent.handle.as_str())
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
            request_digest: None,
            kind: None,
            request_id: None,
            correlation_projection: None,
            parent_operation_id: None,
            session_ref: None,
            task_ref: None,
            scope_ref: None,
            capability_ref: None,
            payload_digest: None,
            result_lineage: None,
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
            request_digest: None,
            kind: None,
            request_id: None,
            correlation_projection: None,
            parent_operation_id: None,
            session_ref: None,
            task_ref: None,
            scope_ref: None,
            capability_ref: None,
            payload_digest: None,
            result_lineage: None,
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
                    "mode":"verification"
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
                payload
                    .get("operation")
                    .and_then(|operation| operation.as_str()),
                Some(AGENT_HOST_REQUEST_INVOKE_READ_OPERATION)
            );
            let tool = payload
                .get("tool")
                .expect("invoke-read frame must carry tool bytes");
            assert_eq!(
                tool.get("name").and_then(|name| name.as_str()),
                Some(read_request.tool.canonical_name())
            );
        }
    }

    #[test]
    fn skill_carriers_ride_invoke_read_with_canonical_names() {
        // Skill carriers are non-hot (no semantic profile, never advertised)
        // but ride the same linkage-checked invoke-read entry so the daemon
        // can claim and serve Hotset pairs; the tool name doubles as the
        // session capability the envelope binds.
        let (request, facts, envelope) = test_envelope();
        for (tool_json, canonical) in [
            (
                serde_json::json!({"name":"skill.inject","arguments":{
                    "contract_version": 1
                }}),
                "skill.inject",
            ),
            (
                serde_json::json!({"name":"skill.display","arguments":{
                    "contract_version": 1
                }}),
                "skill.display",
            ),
        ] {
            let mut value = serde_json::to_value(&request).expect("request must serialize");
            value["tool"] = tool_json;
            let skill_request: HostInvocationRequest =
                serde_json::from_value(value).expect("skill request must deserialize");
            skill_request
                .validate()
                .expect("skill request must validate");
            assert_eq!(skill_request.tool.canonical_name(), canonical);
            assert!(
                invokes_local_read(&skill_request),
                "skill carriers ride the invoke-read entry"
            );
            let frame = host_request_invoke_read_frame(&skill_request, &envelope, &facts)
                .expect("invoke-read frame must build");
            let payload = match &frame.payload {
                ProtocolPayload::Json(payload) => payload.clone(),
                _ => panic!("invoke-read frame must carry JSON"),
            };
            assert_eq!(
                payload
                    .get("operation")
                    .and_then(|operation| operation.as_str()),
                Some(AGENT_HOST_REQUEST_INVOKE_READ_OPERATION)
            );
            let tool = payload
                .get("tool")
                .expect("invoke-read frame must carry tool bytes");
            assert_eq!(
                tool.get("name").and_then(|name| name.as_str()),
                Some(canonical)
            );
        }
    }
}
