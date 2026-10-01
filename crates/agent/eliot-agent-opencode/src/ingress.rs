#![forbid(unsafe_code)]

//! Owner-authenticated durable `/v1/host-events` ingress (issue #2898).
//!
//! This module is the single production implementation of the shipped
//! `OpenCode` host-event contract: one bounded `POST /v1/host-events`
//! handler that joins the caller against the User Broker-owned
//! [`OpenCodeBridgeIntroduction`](eliot_user_broker_core::OpenCodeBridgeIntroduction),
//! reuses the pure `gate.rs` validators, normalizes into the existing
//! Agent Bridge → Kernel bridge-event route, joins the Governor/authority
//! `ActionGate` for `tool.execute.before`, and returns an owner-verifiable
//! versioned response.
//!
//! Authority split, enforced by construction:
//!
//! * This handler decodes, authenticates, validates, and encodes. It never
//!   decides policy, never mints principal/session/task/fence/epoch
//!   identity, and never treats `recorded` as `allow`.
//! * Event ID, sequence, task/host hints, tool, and effect bindings come
//!   from the validated request; bridge generation, Authority Epoch,
//!   `StateFence`, deadline, and `WorkScope` come from current owner state
//!   via the [`HostEventAdmission`] port, never from copied payload fields.
//! * The durable event owner is the existing bridge-event route behind
//!   [`HostEventAdmission`]; the effect-decision owner is the
//!   [`ActionGate`] port. When the gate is unconfigured the handler
//!   returns a durable-observation-only `recorded` response that cannot
//!   authorize a mutating tool.
//! * The response [`HostEventResponse::commitment`] is an HMAC-SHA256 (RFC
//!   2104, mirroring `eliot-installation`) over the canonical response
//!   fields keyed by the broker-minted request credential. The plugin
//!   verifies it with its own copy of that credential; a foreign loopback
//!   listener without the credential cannot manufacture a usable permit.
//!
//! First-contact note: plain loopback location is not server identity. The
//! introduction pins the exact endpoint and server incarnation, and the
//! handler refuses an introduction pinned to any other port than the
//! serving listener; the listener is exclusively pre-bound (a bind conflict
//! refuses the route instead of letting a squatter inherit it), and the
//! credential is short-lived, single-generation, and process-bound. The
//! User Broker owns the one-shot bootstrap authority behind the protected
//! named-pipe channel (the introduction carries `bootstrap_channel` for
//! it); the pipe transport with peer SID/process verification is not
//! implemented in this unit.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use eliot_agent_api::{
};
use eliot_contracts::{EpochId, canonical_json_bytes};
use eliot_process::SecretRef;
use eliot_user_broker_core::{
    OPENCODE_BRIDGE_CAPABILITY_MUTATION_GATE, OPENCODE_BRIDGE_CAPABILITY_OBSERVATION_SUBMIT,
    OpenCodeBridgeIntroduction, OpenCodeSessionFacts,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::endpoint::LoopbackEndpoint;
use crate::gate::{
    ValidatedMutationGate, ValidatedSkippedReceipt, validate_mutation_gate_payload,
    validate_skipped_tool_receipt,
};

/// Exact request path served by this ingress. Nothing else is routed.
pub const HOST_EVENTS_PATH: &str = "/v1/host-events";
/// Version of the owner-verifiable host-event response contract.
pub const HOST_EVENTS_RESPONSE_VERSION: &str = "eliot.opencode.host-event-response.v1";
/// Version of the typed host-event error contract (I7.20 projection).
pub const HOST_EVENTS_ERROR_VERSION: &str = "eliot.opencode.host-event-error.v1";
/// Maximum request-head bytes read before the body length is known.
pub const MAX_HOST_EVENT_HEAD_BYTES: usize = 16 * 1024;
/// Maximum header lines accepted on one request.
pub const MAX_HOST_EVENT_HEADERS: usize = 32;
/// Maximum request-body bytes. Mirrors the ORS bridge-event envelope
/// ceiling (256 KiB): larger bodies fail before large allocation.
pub const MAX_HOST_EVENT_BODY_BYTES: usize = 256 * 1024;
/// Maximum presented Bearer [REDACTED] in bytes.
pub const MAX_BEARER_BYTES: usize = 4096;
/// Maximum `Idempotency-Key` bytes.
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 512;
/// Maximum passive-observation top-level object keys.
pub const MAX_PASSIVE_EVENT_FIELDS: usize = 64;
/// Maximum event-id bytes accepted from any request.
pub const MAX_EVENT_ID_BYTES: usize = 512;
/// Per-connection head-read timeout.
pub const HOST_EVENTS_HEAD_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-connection body-read timeout.
pub const HOST_EVENTS_BODY_TIMEOUT: Duration = Duration::from_secs(10);

/// Bridge-event stream namespace for `OpenCode` host events.
pub const HOST_EVENTS_STREAM_ID: &str = "opencode.host-events.v1";
/// Bridge-event producer identity for the `OpenCode` plugin route.
pub const HOST_EVENTS_PRODUCER_ID: &str = "opencode.plugin";
/// Bridge-event payload type for normalized `OpenCode` host events.
pub const HOST_EVENTS_PAYLOAD_TYPE: &str = "eliot.opencode.host-event.v1";

/// Response decision: the owner evaluated the gate and permits the effect.
pub const DECISION_ALLOW: &str = "allow";
/// Response decision: the owner evaluated the gate and refuses the effect.
pub const DECISION_DENY: &str = "deny";
/// Response decision: durable observation only. Never a permit, even when
/// the transport succeeded. A mutating tool must fail closed on this.
pub const DECISION_RECORDED: &str = "recorded";

/// I7.20 disposition: the request is malformed or unbound.
pub const DISPOSITION_INVALID_REQUEST: &str = "INVALID_REQUEST";
/// I7.20 disposition: the owner refused authority.
pub const DISPOSITION_DENIED: &str = "DENIED";
/// I7.20 disposition: stale fence/epoch/generation or identity conflict.
pub const DISPOSITION_STALE_OR_CONFLICT: &str = "STALE_OR_CONFLICT";
/// I7.20 disposition: saturated or temporarily unavailable.
pub const DISPOSITION_UNAVAILABLE_OR_CAPACITY: &str = "UNAVAILABLE_OR_CAPACITY";
/// I7.20 disposition: the operation needs evidence-backed reconciliation.
pub const DISPOSITION_RECOVERY_REQUIRED: &str = "RECOVERY_REQUIRED";

/// I7.20 reason: authentication is required or the credential is invalid.
pub const REASON_AUTHENTICATION_REQUIRED: &str = "AUTHENTICATION_REQUIRED";
/// I7.20 reason: no current capability introduction exists for the route.
pub const REASON_CAPABILITY_INTRODUCTION_REQUIRED: &str = "CAPABILITY_INTRODUCTION_REQUIRED";
/// I7.20 reason: the capability grant was revoked or rotated.
pub const REASON_CAPABILITY_GRANT_REVOKED: &str = "CAPABILITY_GRANT_REVOKED";
/// I7.20 reason: the capability route is unavailable.
pub const REASON_CAPABILITY_UNAVAILABLE: &str = "CAPABILITY_UNAVAILABLE";
/// I7.20 reason: policy refused the effect.
pub const REASON_POLICY_DENIED: &str = "POLICY_DENIED";
/// I7.20 reason: authority is required before the effect.
pub const REASON_AUTHORITY_REQUIRED: &str = "AUTHORITY_REQUIRED";
/// I7.20 reason: the request failed closed validation.
pub const REASON_INVALID_ARGUMENT: &str = "INVALID_ARGUMENT";
/// I7.20 reason: the idempotency identity carries changed content.
pub const REASON_IDENTITY_CONFLICT: &str = "IDENTITY_CONFLICT";
/// I7.20 reason: the request scope does not match the live attach scope.
pub const REASON_SCOPE_CONFLICT: &str = "SCOPE_CONFLICT";
/// I7.20 reason: the fence is stale.
pub const REASON_STALE_STATE_FENCE: &str = "STALE_STATE_FENCE";
/// I7.20 reason: the authority epoch is stale.
pub const REASON_STALE_AUTHORITY_EPOCH: &str = "STALE_AUTHORITY_EPOCH";
/// I7.20 reason: the receiver is saturated; the caller may retry bounded.
pub const REASON_BUSY: &str = "BUSY";
/// I7.20 reason: durable write pressure; the caller must back off.
pub const REASON_STORAGE_BACKPRESSURE: &str = "STORAGE_BACKPRESSURE";
/// I7.20 reason: the durable store is unavailable.
pub const REASON_DB_UNAVAILABLE: &str = "DB_UNAVAILABLE";
/// I7.20 reason: the absolute deadline elapsed before admission.
pub const REASON_DEADLINE_EXCEEDED: &str = "DEADLINE_EXCEEDED";
/// I7.20 reason: the wire shape is not this endpoint.
pub const REASON_PROTOCOL_INCOMPATIBLE: &str = "PROTOCOL_INCOMPATIBLE";
/// I7.20 reason: the route is not served here.
pub const REASON_ROUTE_UNAVAILABLE: &str = "ROUTE_UNAVAILABLE";

/// Canonical response text for one lineage-aware authority epoch.
///
/// Format is `{lowercase-uuid-lineage}:{sequence}`. The broker projects
/// the same text into the approved child; the plugin echoes it from the
/// response binding. Opaque owner text: never parsed for authority.
#[must_use]
pub fn authority_epoch_text(epoch: &EpochId) -> String {
    let lineage = epoch.lineage_id.as_str();
    let sequence = epoch.sequence;
    format!("{lineage}:{sequence}")
}

/// Typed rejection of one host-event request: HTTP status plus the exact
/// I7.20 disposition/reason pair. Carries no secret, argument value, or
/// server prose; the plugin renders text locally from the code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostEventReject {
    /// HTTP status code.
    pub status: u16,
    /// I7.20 `AgentResponseDisposition` value.
    pub disposition: &'static str,
    /// I7.20 exact reason code.
    pub reason_code: &'static str,
}

impl HostEventReject {
    const fn new(status: u16, disposition: &'static str, reason_code: &'static str) -> Self {
        Self {
            status,
            disposition,
            reason_code,
        }
    }

    /// Encodes the bounded typed error body. `event_id` is echoed only when
    /// the request already carried that exact identity.
    #[must_use]
    pub fn error_body(&self, event_id: Option<&str>) -> serde_json::Value {
        let mut body = serde_json::Map::with_capacity(4);
        body.insert(
            "error_version".to_owned(),
            serde_json::Value::String(HOST_EVENTS_ERROR_VERSION.to_owned()),
        );
        body.insert(
            "disposition".to_owned(),
            serde_json::Value::String(self.disposition.to_owned()),
        );
        body.insert(
            "reason_code".to_owned(),
            serde_json::Value::String(self.reason_code.to_owned()),
        );
        if let Some(event_id) = event_id {
            body.insert(
                "event_id".to_owned(),
                serde_json::Value::String(event_id.to_owned()),
            );
        }
        serde_json::Value::Object(body)
    }
}

/// Validated `POST /v1/host-events` request head. Produced by
/// [`parse_http_head`] before any body byte is allocated.
#[derive(Clone, Debug)]
pub struct ParsedHostEventHead {
    /// Exact `Host` authority the request targeted.
    pub host: String,
    /// Presented request credential. Never logged or echoed.
    pub bearer: SecretString,
    /// Optional idempotency key; must equal the body `event_id` when present.
    pub idempotency_key: Option<String>,
    /// Declared body length, already bounded by [`MAX_HOST_EVENT_BODY_BYTES`].
    pub content_length: usize,
}

/// Rejects anything that is not exactly one `POST /v1/host-events` loopback
/// request.
///
/// Method, target, version, host, content type, framing, and length are all
/// checked before the caller allocates the body: unknown methods, paths,
/// hosts, content types, transfer framings, and over-limit lengths fail
/// here. `expected_port` is the bound listener port; the `Host` authority
/// must name this exact listener.
pub fn parse_http_head(
    raw: &[u8],
    expected_port: u16,
) -> Result<ParsedHostEventHead, HostEventReject> {
    if raw.len() > MAX_HOST_EVENT_HEAD_BYTES {
        return Err(HostEventReject::new(
            413,
            DISPOSITION_INVALID_REQUEST,
            REASON_INVALID_ARGUMENT,
        ));
    }
    let text = std::str::from_utf8(raw).map_err(|_| {
        HostEventReject::new(
            400,
            DISPOSITION_INVALID_REQUEST,
            REASON_PROTOCOL_INCOMPATIBLE,
        )
    })?;
    if !text.ends_with("\r\n\r\n") {
        return Err(HostEventReject::new(
            400,
            DISPOSITION_INVALID_REQUEST,
            REASON_PROTOCOL_INCOMPATIBLE,
        ));
    }
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(HostEventReject::new(
        400,
        DISPOSITION_INVALID_REQUEST,
        REASON_PROTOCOL_INCOMPATIBLE,
    ))?;
    check_request_line(request_line)?;
    let collected = collect_headers(lines)?;
    validate_collected_head(&collected, expected_port)
}

fn check_request_line(request_line: &str) -> Result<(), HostEventReject> {
    if request_line.contains('\n') {
        return Err(HostEventReject::new(
            400,
            DISPOSITION_INVALID_REQUEST,
            REASON_PROTOCOL_INCOMPATIBLE,
        ));
    }
    let mut request_parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) = (
        request_parts.next(),
        request_parts.next(),
        request_parts.next(),
        request_parts.next(),
    ) else {
        return Err(HostEventReject::new(
            400,
            DISPOSITION_INVALID_REQUEST,
            REASON_PROTOCOL_INCOMPATIBLE,
        ));
    };
    if method != "POST" {
        return Err(HostEventReject::new(
            405,
            DISPOSITION_INVALID_REQUEST,
            REASON_ROUTE_UNAVAILABLE,
        ));
    }
    if target != HOST_EVENTS_PATH {
        return Err(HostEventReject::new(
            404,
            DISPOSITION_INVALID_REQUEST,
            REASON_ROUTE_UNAVAILABLE,
        ));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(HostEventReject::new(
            505,
            DISPOSITION_INVALID_REQUEST,
            REASON_PROTOCOL_INCOMPATIBLE,
        ));
    }
    Ok(())
}

struct CollectedHead {
    host: Option<String>,
    content_type: Option<String>,
    content_length: Option<usize>,
    authorization: Option<String>,
    idempotency_key: Option<String>,
}

fn collect_headers<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> Result<CollectedHead, HostEventReject> {
    let mut collected = CollectedHead {
        host: None,
        content_type: None,
        content_length: None,
        authorization: None,
        idempotency_key: None,
    };
    let mut header_count = 0_usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.contains('\n') {
            return Err(HostEventReject::new(
                400,
                DISPOSITION_INVALID_REQUEST,
                REASON_PROTOCOL_INCOMPATIBLE,
            ));
        }
        header_count += 1;
        if header_count > MAX_HOST_EVENT_HEADERS {
            return Err(HostEventReject::new(
                400,
                DISPOSITION_INVALID_REQUEST,
                REASON_INVALID_ARGUMENT,
            ));
        }
        apply_header_line(&mut collected, line)?;
    }
    Ok(collected)
}

fn parse_content_length(value: &str) -> Result<usize, HostEventReject> {
    let digits = value.trim();
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HostEventReject::new(
            400,
            DISPOSITION_INVALID_REQUEST,
            REASON_INVALID_ARGUMENT,
        ));
    }
    let length: usize = digits.parse().map_err(|_| {
        HostEventReject::new(400, DISPOSITION_INVALID_REQUEST, REASON_INVALID_ARGUMENT)
    })?;
    if length > MAX_HOST_EVENT_BODY_BYTES {
        return Err(HostEventReject::new(
            413,
            DISPOSITION_INVALID_REQUEST,
            REASON_INVALID_ARGUMENT,
        ));
    }
    Ok(length)
}

fn apply_header_line(collected: &mut CollectedHead, line: &str) -> Result<(), HostEventReject> {
    let (name, value) = line.split_once(':').ok_or(HostEventReject::new(
        400,
        DISPOSITION_INVALID_REQUEST,
        REASON_PROTOCOL_INCOMPATIBLE,
    ))?;
    if value.len() > MAX_HOST_EVENT_HEAD_BYTES {
        return Err(HostEventReject::new(
            400,
            DISPOSITION_INVALID_REQUEST,
            REASON_INVALID_ARGUMENT,
        ));
    }
    match name.trim().to_ascii_lowercase().as_str() {
        "host" => {
            if collected.host.is_some() {
                return Err(HostEventReject::new(
                    400,
                    DISPOSITION_INVALID_REQUEST,
                    REASON_INVALID_ARGUMENT,
                ));
            }
            collected.host = Some(value.trim().to_owned());
        }
        "content-type" => {
            if collected.content_type.is_some() {
                return Err(HostEventReject::new(
                    400,
                    DISPOSITION_INVALID_REQUEST,
                    REASON_INVALID_ARGUMENT,
                ));
            }
            collected.content_type = Some(value.trim().to_owned());
        }
        "content-length" => {
            if collected.content_length.is_some() {
                return Err(HostEventReject::new(
                    400,
                    DISPOSITION_INVALID_REQUEST,
                    REASON_INVALID_ARGUMENT,
                ));
            }
            collected.content_length = Some(parse_content_length(value)?);
        }
        "authorization" => {
            if collected.authorization.is_some() {
                return Err(HostEventReject::new(
                    400,
                    DISPOSITION_INVALID_REQUEST,
                    REASON_INVALID_ARGUMENT,
                ));
            }
            collected.authorization = Some(value.trim().to_owned());
        }
        "idempotency-key" => {
            if collected.idempotency_key.is_some() {
                return Err(HostEventReject::new(
                    400,
                    DISPOSITION_INVALID_REQUEST,
                    REASON_INVALID_ARGUMENT,
                ));
            }
            let key = value.trim().to_owned();
            if key.is_empty() || key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
                return Err(HostEventReject::new(
                    400,
                    DISPOSITION_INVALID_REQUEST,
                    REASON_INVALID_ARGUMENT,
                ));
            }
            collected.idempotency_key = Some(key);
        }
        "transfer-encoding" | "expect" => {
            return Err(HostEventReject::new(
                400,
                DISPOSITION_INVALID_REQUEST,
                REASON_PROTOCOL_INCOMPATIBLE,
            ));
        }
        _ => {}
    }
    Ok(())
}

fn validate_collected_head(
    collected: &CollectedHead,
    expected_port: u16,
) -> Result<ParsedHostEventHead, HostEventReject> {
    let host = collected.host.clone().ok_or(HostEventReject::new(
        400,
        DISPOSITION_INVALID_REQUEST,
        REASON_INVALID_ARGUMENT,
    ))?;
    let endpoint = LoopbackEndpoint::parse(&format!("http://{host}")).map_err(|_| {
        HostEventReject::new(400, DISPOSITION_INVALID_REQUEST, REASON_INVALID_ARGUMENT)
    })?;
    if endpoint.port() != expected_port {
        return Err(HostEventReject::new(
            400,
            DISPOSITION_INVALID_REQUEST,
            REASON_INVALID_ARGUMENT,
        ));
    }
    let content_type = collected.content_type.clone().ok_or(HostEventReject::new(
        415,
        DISPOSITION_INVALID_REQUEST,
        REASON_INVALID_ARGUMENT,
    ))?;
    let media = content_type
        .split_once(';')
        .map_or(content_type.as_str(), |(first, _)| first)
        .trim()
        .to_ascii_lowercase();
    if media != "application/json" {
        return Err(HostEventReject::new(
            415,
            DISPOSITION_INVALID_REQUEST,
            REASON_INVALID_ARGUMENT,
        ));
    }
    let content_length = collected.content_length.ok_or(HostEventReject::new(
        400,
        DISPOSITION_INVALID_REQUEST,
        REASON_INVALID_ARGUMENT,
    ))?;
    let authorization = collected.authorization.clone().ok_or(HostEventReject::new(
        401,
        DISPOSITION_DENIED,
        REASON_AUTHENTICATION_REQUIRED,
    ))?;
    let token = authorization
        .strip_prefix("Bearer ")
        .ok_or(HostEventReject::new(
            401,
            DISPOSITION_DENIED,
            REASON_AUTHENTICATION_REQUIRED,
        ))?;
    if token.is_empty()
        || token.len() > MAX_BEARER_BYTES
        || token
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(HostEventReject::new(
            401,
            DISPOSITION_DENIED,
            REASON_AUTHENTICATION_REQUIRED,
        ));
    }
    Ok(ParsedHostEventHead {
        host,
        bearer: SecretString::from(token.to_owned()),
        idempotency_key: collected.idempotency_key.clone(),
        content_length,
    })
}

/// Current-introduction holder for the ingress join (issue #2898, step 7).
///
/// Implemented by the bridge-process composition: the User Broker mints
/// introductions, the bridge holds the current one and the live revocation
/// set. Rotation, listener death, bridge restart, logout, and revocation
/// invalidate the old introduction here before another request is admitted.
pub trait IntroductionStore: Send {
    /// Returns the current introduction, or `None` when the route is not
    /// presently introduced (ingress unconfigured: fail closed).
    fn current_introduction(&self) -> Option<OpenCodeBridgeIntroduction>;
    /// Returns whether the revocation id is retired.
    fn is_revoked(&self, revocation_id: &str) -> bool;
    /// Returns live broker-observed session facts for
    /// [`OpenCodeBridgeIntroduction::probe_current_session`].
    fn session_facts(&self) -> OpenCodeSessionFacts;
    /// Returns the current Unix-millisecond clock observation.
    fn now_ms(&self) -> u64;
}

/// Owner-side credential resolver (issue #2898, step 3).
///
/// Resolves the introduction's opaque [`SecretRef`] to the short-lived
/// request credential. Only the physical User Broker/process owner
/// implements this, introducing the secret solely to the exact approved
/// `OpenCode` process. Raw material never appears in registration, command
/// lines, logs, route profiles, model context, or ordinary launch maps.
pub trait CredentialResolver: Send {
    /// Credential resolution failure. Carries no secret material.
    type Error: std::error::Error + Send + 'static;

    /// Resolves the credential handle to its current secret bytes.
    fn resolve(&self, handle: &SecretRef) -> Result<SecretString, Self::Error>;
}

/// OS-owned identity of the process that owns one accepted loopback TCP
/// connection. Request bodies and headers cannot construct this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEventPeerProcessIdentity {
    pub process_id: u32,
    pub process_start_time_100ns: u64,
    pub image_path: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostEventPeerObservationError {
    /// The OS owner row or exact process identity could not be proven.
    Unavailable,
}

/// Platform adapter for joining accepted socket endpoints to an OS process
/// identity. Implementations must fail closed on ambiguous or racing owner
/// observations.
pub trait HostEventPeerObserver {
    fn observe(
        &mut self,
        client_local_endpoint: std::net::SocketAddr,
        peer_endpoint: std::net::SocketAddr,
    ) -> Result<HostEventPeerProcessIdentity, HostEventPeerObservationError>;
}

/// Normalized host-event submission to the durable event owner.
///
/// Request-derived facts only: event identity, sequence, task/host hints,
/// tool, and effect bindings. Bridge generation, Authority Epoch,
/// `StateFence`, deadline, and `WorkScope` are bound from current owner
/// state by the [`HostEventAdmission`] implementation, never from copied
/// payload fields. Carries digests and bounded metadata only: no argument
/// values, command text, secrets, or server prose.
#[derive(Clone, Debug)]
pub struct HostEventSubmission {
    /// Bridge-event stream namespace ([`HOST_EVENTS_STREAM_ID`]).
    pub stream_id: String,
    /// Bridge-event producer identity ([`HOST_EVENTS_PRODUCER_ID`]).
    pub producer_id: String,
    /// Stable event identity used for idempotent replay.
    pub event_id: String,
    /// Stream sequence (non-zero).
    pub sequence: u64,
    /// Classified host-event kind.
    pub kind: HostEventKind,
    /// Requested durable delivery class.
    pub delivery: HostEventDelivery,
    /// Host session hint from the payload, cross-checked by the owner.
    pub host_session_id: Option<String>,
    /// Attached task hint from the payload, cross-checked by the owner.
    pub task_id: Option<String>,
    /// Work item hint from the payload, cross-checked by the owner.
    pub work_item_id: Option<String>,
    /// Exact tool identity for gate/skipped events.
    pub tool: Option<String>,
    /// Recomputed effect digest the decision must bind to.
    pub effect_digest: Option<String>,
    /// Sorted argument names bound by the digest.
    pub argument_keys: Vec<String>,
    /// Exact SHA-256 hex transport hash of the raw request body (I7.23).
    pub transport_hash: String,
    /// Original callback object, isolated from the normalized envelope.
    /// Only the Kernel privacy owner may decide whether a separate
    /// restricted record can be retained. `None` means source unavailable.
    pub restricted_source_bytes: Option<Vec<u8>>,
    /// Normalized envelope payload: descriptor, digests, bounded metadata.
    pub envelope_json: serde_json::Value,
}

/// Classified host-event kind. Only [`HostEventKind::Gate`] may reach the
/// `ActionGate`; every other kind has an observation-only ceiling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostEventKind {
    /// `tool.execute.before`: pre-effect mutation gate candidate.
    Gate,
    /// `tool.execute.skipped`: read-only skipped observation receipt.
    Skipped,
    /// Any other bounded passive lifecycle observation.
    Passive(String),
}

/// Durable delivery class requested for the submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostEventDelivery {
    /// Pre-effect gate event: durable control, replayed until acknowledged.
    Control,
    /// Observation event: durable observation, replayed until acknowledged.
    Observation,
}

/// Durable admission receipt from the existing bridge-event route.
///
/// Returned only after the ORS event/handoff receipt says the event is
/// durable. HTTP 2xx is transport custody only; durable status comes from
/// this receipt. Carries digests and owner-state bindings, never secrets
/// or argument values.
#[derive(Clone, Debug)]
pub struct HostEventAdmissionReceipt {
    /// Admitted stream identity.
    pub stream_id: String,
    /// Admitted event identity.
    pub event_id: String,
    /// Ack phase reached (for example `DURABLE`).
    pub phase: String,
    /// Admission disposition (for example `accepted` or `duplicate`).
    pub disposition: String,
    /// Canonical envelope SHA-256 digest; the durable event commitment.
    pub envelope_digest: String,
    /// True when an exact duplicate replayed the stored outcome.
    pub replayed: bool,
    /// True when the stream cursor advanced past this event.
    pub cursor_advanced: bool,
    /// Authority epoch bound from current owner state.
    pub authority_epoch: EpochId,
    /// State fence bound from current owner state.
    pub fence_id: String,
    /// Bridge generation bound from current owner state.
    pub bridge_generation: u64,
    /// Stored effect decision when the route answered this operation identity
    /// as an already-admitted replay (issue #2898, step 10). `Some` only when
    /// the route's own ORS idempotency proved this exact operation identity
    /// already holds a persisted decision; the returned value is that stored
    /// record, which the handler compares by content against the decision this
    /// request would produce.
    pub replayed_decision: Option<EffectDecisionRecord>,
}

/// Explicit coverage gap for dropped passive pressure (step 13).
#[derive(Clone, Debug)]
pub struct HostEventGap {
    /// Stable gap identity (`{stream_id}:{event_id}` of the dropped event).
    pub gap_id: String,
    /// Stream the dropped event belonged to.
    pub stream_id: String,
    /// Dropped event identity.
    pub event_id: String,
    /// Closed reason reference (for example `STORAGE_BACKPRESSURE`).
    pub reason_ref: String,
}

/// Durable admission failure. Variants map to exact HTTP statuses and
/// I7.20 pairs; see [`HostEventAdmissionError::reject`].
#[derive(Clone, Debug)]
pub struct HostEventAdmissionError {
    /// Failure class.
    pub kind: HostEventAdmissionFailure,
    /// Stored envelope digest when a known identity carries changed content.
    pub conflict_envelope_digest: Option<String>,
}

/// Durable admission failure classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostEventAdmissionFailure {
    /// Same identity, changed content: determined conflict, no transition.
    Conflict,
    /// Durable write pressure: the caller must back off.
    Backpressure,
    /// Fence or epoch moved: stale owner-state binding.
    Fenced,
    /// Epoch moved while the fence still holds.
    StaleEpoch,
    /// Absolute deadline elapsed before admission.
    DeadlineExceeded,
    /// Request scope (task) does not match the live attach scope.
    ScopeConflict,
    /// Durable store unavailable.
    Unavailable,
}

impl HostEventAdmissionError {
    /// Builds a conflict failure binding the proven stored digest.
    #[must_use]
    pub fn conflict(stored_envelope_digest: String) -> Self {
        Self {
            kind: HostEventAdmissionFailure::Conflict,
            conflict_envelope_digest: Some(stored_envelope_digest),
        }
    }

    /// Builds a non-conflict failure.
    #[must_use]
    pub fn of(kind: HostEventAdmissionFailure) -> Self {
        Self {
            kind,
            conflict_envelope_digest: None,
        }
    }

    /// Maps the failure to its exact rejection.
    #[must_use]
    pub fn reject(&self) -> HostEventReject {
        match self.kind {
            HostEventAdmissionFailure::Conflict => {
                HostEventReject::new(409, DISPOSITION_STALE_OR_CONFLICT, REASON_IDENTITY_CONFLICT)
            }
            HostEventAdmissionFailure::Backpressure => HostEventReject::new(
                429,
                DISPOSITION_UNAVAILABLE_OR_CAPACITY,
                REASON_STORAGE_BACKPRESSURE,
            ),
            HostEventAdmissionFailure::Fenced => {
                HostEventReject::new(409, DISPOSITION_STALE_OR_CONFLICT, REASON_STALE_STATE_FENCE)
            }
            HostEventAdmissionFailure::StaleEpoch => HostEventReject::new(
                409,
                DISPOSITION_STALE_OR_CONFLICT,
                REASON_STALE_AUTHORITY_EPOCH,
            ),
            HostEventAdmissionFailure::DeadlineExceeded => HostEventReject::new(
                408,
                DISPOSITION_UNAVAILABLE_OR_CAPACITY,
                REASON_DEADLINE_EXCEEDED,
            ),
            HostEventAdmissionFailure::ScopeConflict => {
                HostEventReject::new(409, DISPOSITION_STALE_OR_CONFLICT, REASON_SCOPE_CONFLICT)
            }
            HostEventAdmissionFailure::Unavailable => HostEventReject::new(
                503,
                DISPOSITION_UNAVAILABLE_OR_CAPACITY,
                REASON_DB_UNAVAILABLE,
            ),
        }
    }
}

/// Existing Agent Bridge → Kernel bridge-event route, behind a port.
///
/// The production implementation builds the `EventEnvelope` from the
/// submission plus live owner state (attach/task/scope/fence/epoch/
/// generation) and submits it through the bridge's existing
/// `agent_bridge_event_forward` operation; gaps go through the existing
/// gap operation. No HTTP-private event journal exists: durability,
/// idempotency, handoff, and reconciliation stay with ORS.
///
/// This port is deliberately not `Send`: the `BridgeRunner` composition
/// it is implemented over is single-threaded. Drive
/// [`HostEventsListener::serve_until`] on a single-threaded runtime on the
/// bridge thread, or front the port with the main-loop channel integration
/// (named gap `OPENCODE_BRIDGE_THREAD_INTEGRATION`).
pub trait HostEventAdmission {
    /// Admits one normalized submission durably, or fails typed.
    fn admit(
        &mut self,
        introduction: &OpenCodeBridgeIntroduction,
        submission: &HostEventSubmission,
    ) -> Result<HostEventAdmissionReceipt, HostEventAdmissionError>;

    /// Persists one evaluated effect decision under its exact decision
    /// identity, through the same durable bridge-event route
    /// (issue #2898, step 10).
    ///
    /// The route's own ORS idempotency answers: the same operation identity
    /// carrying the same decision content replays the stored record
    /// (`replayed_decision` set to that stored value), and the same identity
    /// carrying changed content is a determined conflict
    /// ([`HostEventAdmissionFailure::Conflict`]) that performs no transition.
    /// An exact retry or a lost response therefore produces one durable event
    /// and one decision, never a second policy evaluation.
    fn commit_decision(
        &mut self,
        record: &EffectDecisionRecord,
    ) -> Result<HostEventAdmissionReceipt, HostEventAdmissionError>;

    /// Records one explicit coverage gap for dropped passive pressure.
    fn report_gap(
        &mut self,
        introduction: &OpenCodeBridgeIntroduction,
        gap: &HostEventGap,
    ) -> Result<(), HostEventAdmissionError>;
}

/// Pre-effect decision request: the exact retained event/effect/session/
/// fence bindings plus the current owner-state generation/epoch/fence the
/// decision must be evaluated under.
#[derive(Clone, Debug)]
pub struct ActionGateRequest {
    /// Stable logical operation identity (the gate `event_id`).
    pub operation_id: String,
    /// Canonical request hash binding event/effect/session/fence/task.
    pub request_hash: String,
    /// Gate event identity.
    pub event_id: String,
    /// Recomputed effect digest the decision must bind to.
    pub effect_digest: String,
    /// Exact mutating tool identity.
    pub tool: String,
    /// Attached task hint, owner-checked before evaluation.
    pub task_id: Option<String>,
    /// Bridge generation bound from current owner state.
    pub bridge_generation: u64,
    /// Authority epoch bound from current owner state.
    pub authority_epoch: EpochId,
    /// State fence bound from current owner state.
    pub fence_id: String,
}

/// Evaluated pre-effect decision. Binds the exact request hash, policy and
/// authority revisions, expiry, and the decision receipt commitment.
#[derive(Clone, Debug)]
pub struct ActionGateDecision {
    /// Echo of the evaluated [`ActionGateRequest::request_hash`]. The handler
    /// permits only a decision echoing the exact request it evaluated: a
    /// crossed or stale decision degrades to `recorded`, never `allow`.
    pub request_hash: String,
    /// True only when the owner permits this exact effect.
    pub allow: bool,
    /// Current policy revision the decision was evaluated under.
    pub policy_revision: String,
    /// Authority revision the decision was evaluated under.
    pub authority_revision: String,
    /// Absolute decision expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Decision receipt/result commitment reference.
    pub decision_receipt: String,
    /// Closed deny reason code; `None` only when `allow` is true.
    pub reason_code: Option<&'static str>,
}

/// `ActionGate` evaluation failure. Every variant fails closed: the handler
/// answers `recorded` (observation only) or a typed backpressure error,
/// never a permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ActionGateError {
    /// No Governor/authority evaluation is wired: the gate cannot decide.
    #[error("action gate evaluation is not configured")]
    Unconfigured,
    /// Evaluation pressure: the caller must back off without effecting.
    #[error("action gate backpressure")]
    Backpressure,
    /// Evaluation temporarily unavailable.
    #[error("action gate unavailable")]
    Unavailable,
    /// Owner state moved during evaluation.
    #[error("action gate owner state moved")]
    Fenced,
}

/// Governor/authority pre-effect decision owner, behind a port.
///
/// Invoked only for `tool.execute.before` with the exact retained
/// event/effect/session/fence and current policy revision. The handler
/// performs no policy evaluation itself: when the gate denies, is
/// unconfigured, or fails, the response carries no permit.
pub trait ActionGate: Send {
    /// Evaluates one pre-effect request under current policy.
    fn decide(
        &mut self,
        introduction: &OpenCodeBridgeIntroduction,
        receipt: &HostEventAdmissionReceipt,
        request: &ActionGateRequest,
    ) -> Result<ActionGateDecision, ActionGateError>;
}

/// Explicit fail-closed `ActionGate`: no Governor/authority evaluation is
/// wired in this unit (named gap `OPENCODE_ACTION_GATE_EVALUATION`). Every
/// call fails with [`ActionGateError::Unconfigured`], so the handler
/// answers `recorded` — a durable observation that cannot authorize a
/// mutating tool. Policy is never decided inside the HTTP handler and
/// `recorded` is never promoted to `allow`.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnconfiguredActionGate;

impl ActionGate for UnconfiguredActionGate {
    fn decide(
        &mut self,
        _introduction: &OpenCodeBridgeIntroduction,
        _receipt: &HostEventAdmissionReceipt,
        _request: &ActionGateRequest,
    ) -> Result<ActionGateDecision, ActionGateError> {
        Err(ActionGateError::Unconfigured)
    }
}

/// One persisted effect decision bound to its exact decision identity
/// (issue #2898, step 10).
///
/// Every field W10 names is carried here and is covered by the canonical
/// decision digest: the stable logical operation/event identity, the exact
/// request/effect digest, the task hint, the bridge and `OpenCode`
/// generations, the fence, the policy/authority revision, the decision
/// itself, the expiry, the receipt/result commitment, and the reconciliation
/// owner. The record is admitted through the existing bridge-event route
/// together with the retained event, so ORS owns its durability, idempotency
/// and reconciliation — there is no second decision journal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectDecisionRecord {
    /// Stable logical operation/event identity.
    pub operation_id: String,
    /// Canonical request hash over the exact bound fields.
    pub request_hash: String,
    /// Recomputed effect digest the decision binds to.
    pub effect_digest: String,
    /// Exact mutating tool identity.
    pub tool: String,
    /// Attached task hint bound from current owner state.
    pub task_id: Option<String>,
    /// Bridge generation the decision was made under.
    pub bridge_generation: u64,
    /// `OpenCode` generation (introduction digest) the decision was made
    /// under.
    pub opencode_generation: String,
    /// State fence the decision was made under.
    pub fence_id: String,
    /// Authority epoch text the decision was made under.
    pub authority_epoch: String,
    /// Policy revision the decision was evaluated under.
    pub policy_revision: String,
    /// Authority revision the decision was evaluated under.
    pub authority_revision: String,
    /// The decision itself (`allow` or `deny`).
    pub decision: String,
    /// Closed refusal reason code; empty for an `allow`. Persisted so a
    /// reconciled retry reproduces the original refusal rather than degrading
    /// it to an untyped `recorded`.
    pub reason_code: String,
    /// Absolute decision expiry in Unix milliseconds; `0` when the decision
    /// carries no expiry.
    pub expires_at_ms: u64,
    /// Durable event commitment (canonical envelope digest of the retained
    /// event this decision is bound to).
    pub event_receipt: String,
    /// Decision/result commitment.
    pub decision_receipt: String,
    /// Owner that reconciles this operation when its response is lost.
    pub reconciliation_owner: String,
}

impl EffectDecisionRecord {
    /// Computes the canonical decision-identity content digest: the exact
    /// content W10's "same identity / same content" and "same identity /
    /// changed content" rules compare. It covers every bound field above, so
    /// any change to the effect, scope, fence, generation, policy revision,
    /// decision, expiry, or commitment changes the digest.
    #[must_use]
    pub fn content_digest(&self) -> String {
        let canonical = serde_json::Value::Array(vec![
            serde_json::Value::String(HOST_EVENTS_DECISION_VERSION.to_owned()),
            serde_json::Value::String(self.operation_id.clone()),
            serde_json::Value::String(self.request_hash.clone()),
            serde_json::Value::String(self.effect_digest.clone()),
            serde_json::Value::String(self.tool.clone()),
            self.task_id
                .as_deref()
                .map_or(serde_json::Value::Null, |task| {
                    serde_json::Value::String(task.to_owned())
                }),
            serde_json::Value::Number(self.bridge_generation.into()),
            serde_json::Value::String(self.opencode_generation.clone()),
            serde_json::Value::String(self.fence_id.clone()),
            serde_json::Value::String(self.authority_epoch.clone()),
            serde_json::Value::String(self.policy_revision.clone()),
            serde_json::Value::String(self.authority_revision.clone()),
            serde_json::Value::String(self.decision.clone()),
            serde_json::Value::String(self.reason_code.clone()),
            serde_json::Value::Number(self.expires_at_ms.into()),
            serde_json::Value::String(self.event_receipt.clone()),
            serde_json::Value::String(self.decision_receipt.clone()),
            serde_json::Value::String(self.reconciliation_owner.clone()),
        ]);
        serde_json::to_vec(&canonical)
            .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
            .unwrap_or_default()
    }

    /// Encodes the record as the bounded JSON persisted with the retained
    /// event. Carries digests and owner identities only: no argument values,
    /// command text, secrets, or server prose.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// Version of the persisted effect-decision record (issue #2898, step 10).
pub const HOST_EVENTS_DECISION_VERSION: &str = "eliot.opencode.effect-decision.v1";

/// Reconciliation owner of an `OpenCode` effect decision: the existing
/// bridge-event route / ORS reconciliation owner. A lost response is
/// reconciled against this owner's stored record, never through the legacy
/// process transport.
pub const HOST_EVENTS_DECISION_RECONCILER: &str = HOST_EVENTS_STREAM_ID;

/// Replay classification for a presented decision identity against the
/// stored one: same identity with same content replays; same identity
/// with changed content conflicts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionReplay {
    /// Exact replay: return/reconcile the original decision.
    Replay,
    /// Changed content under a known identity: determined conflict.
    Conflict,
}

/// Classifies a presented decision record against the stored original.
///
/// The comparison is on **content**, not on identity existence: the stored
/// and presented `content_digest` values are computed from the two records'
/// own bound fields and compared. Equal digests mean every bound field
/// (effect, task, fence, both generations, policy/authority revision,
/// decision, expiry, and both receipt commitments) is the same, so the
/// original decision replays without a second evaluation. A different digest
/// under the same operation identity is `Conflict` and performs no
/// transition. A lost response reconciles the original operation through
/// this comparison, never through the legacy process transport or a second
/// decision evaluation.
#[must_use]
pub fn classify_decision_replay(
    stored: &EffectDecisionRecord,
    presented: &EffectDecisionRecord,
) -> Option<DecisionReplay> {
    if stored.operation_id != presented.operation_id {
        return None;
    }
    if stored.content_digest() == presented.content_digest() {
        Some(DecisionReplay::Replay)
    } else {
        Some(DecisionReplay::Conflict)
    }
}

/// Computes the canonical effect-request hash binding the exact fields a
/// gate decision must commit to: operation, event/effect identity, tool,
/// task hint, bridge generation, authority epoch, fence, and the durable
/// event commitment.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn effect_request_hash(
    operation_id: &str,
    event_id: &str,
    effect_digest: &str,
    tool: &str,
    task_id: Option<&str>,
    bridge_generation: u64,
    authority_epoch: &EpochId,
    fence_id: &str,
    envelope_digest: &str,
) -> String {
    let canonical = serde_json::Value::Array(vec![
        serde_json::Value::String(HOST_EVENTS_RESPONSE_VERSION.to_owned()),
        serde_json::Value::String(operation_id.to_owned()),
        serde_json::Value::String(event_id.to_owned()),
        serde_json::Value::String(effect_digest.to_owned()),
        serde_json::Value::String(tool.to_owned()),
        task_id.map_or(serde_json::Value::Null, |task| {
            serde_json::Value::String(task.to_owned())
        }),
        serde_json::Value::Number(bridge_generation.into()),
        serde_json::Value::String(authority_epoch_text(authority_epoch)),
        serde_json::Value::String(fence_id.to_owned()),
        serde_json::Value::String(envelope_digest.to_owned()),
    ]);
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    format!("{:x}", Sha256::digest(&bytes))
}

/// Owner-verifiable versioned host-event response fields.
///
/// Every field except `response_commitment` itself is covered by the
/// commitment, in fixed array order; see [`response_commitment_message`].
/// The plugin accepts a mutating-tool permit only after verifying the
/// commitment, the exact event/effect/session/fence bindings, and current
/// expiry. A bare `{decision}` object without these fields is
/// legacy/unverified and cannot authorize a mutating tool.
#[derive(Clone, Debug)]
pub struct HostEventResponseFields {
    /// Echo of the admitted event identity.
    pub event_id: String,
    /// Recomputed effect digest for gate/skipped events.
    pub effect_digest: Option<String>,
    /// `allow`, `deny`, or `recorded` (observation only, never a permit).
    pub decision: &'static str,
    /// I7.20 disposition; present only on `deny`.
    pub disposition: Option<String>,
    /// Closed deny reason code; present only on `deny`.
    pub reason_code: Option<String>,
    /// Installation bound from current owner state.
    pub installation_id: String,
    /// Bridge generation bound from current owner state.
    pub bridge_generation: u64,
    /// Authority epoch text bound from current owner state.
    pub authority_epoch: String,
    /// State fence bound from current owner state.
    pub state_fence: String,
    /// Policy revision; present only on evaluated (`allow`/`deny`) gates.
    pub policy_revision: Option<String>,
    /// Authority revision; present only on evaluated gates.
    pub authority_revision: Option<String>,
    /// Absolute decision expiry; present only on `allow`.
    pub expires_at_ms: Option<u64>,
    /// Durable event commitment (canonical envelope digest).
    pub event_receipt: String,
    /// Decision receipt commitment; present only on evaluated gates.
    pub decision_receipt: Option<String>,
    /// True when an exact duplicate replayed the stored outcome.
    pub replayed: bool,
}

/// Builds the canonical commitment message: one JSON array with every
/// response field in fixed order, `null` for absent optionals.
///
/// Both sides (this module via `serde_json`, the plugin via
/// `JSON.stringify`) encode the same array value to identical UTF-8:
/// strings with ECMA-404 escapes, plain integers, `null`, no whitespace.
/// Commitment-covered text fields carry owner-validated identities and
/// digests, never free prose, so encoder drift fails closed at verify.
#[must_use]
pub fn response_commitment_message(fields: &HostEventResponseFields) -> Vec<u8> {
    let opt = |value: &Option<String>| {
        value.as_deref().map_or(serde_json::Value::Null, |text| {
            serde_json::Value::String(text.to_owned())
        })
    };
    let canonical = serde_json::Value::Array(vec![
        serde_json::Value::String(HOST_EVENTS_RESPONSE_VERSION.to_owned()),
        serde_json::Value::String(fields.event_id.clone()),
        opt(&fields.effect_digest),
        serde_json::Value::String(fields.decision.to_owned()),
        opt(&fields.disposition),
        opt(&fields.reason_code),
        serde_json::Value::String(fields.installation_id.clone()),
        serde_json::Value::Number(fields.bridge_generation.into()),
        serde_json::Value::String(fields.authority_epoch.clone()),
        serde_json::Value::String(fields.state_fence.clone()),
        opt(&fields.policy_revision),
        opt(&fields.authority_revision),
        fields
            .expires_at_ms
            .map_or(serde_json::Value::Null, |expires| {
                serde_json::Value::Number(expires.into())
            }),
        serde_json::Value::String(fields.event_receipt.clone()),
        opt(&fields.decision_receipt),
        serde_json::Value::Bool(fields.replayed),
    ]);
    serde_json::to_vec(&canonical).unwrap_or_default()
}

/// HMAC-SHA256 (RFC 2104) lowercase hex, mirroring `eliot-installation`.
fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK_BYTES: usize = 64;
    let mut normalized = [0_u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; BLOCK_BYTES];
    for index in 0..BLOCK_BYTES {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    normalized.fill(0);
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    inner_pad.fill(0);
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer_pad.fill(0);
    format!("{:x}", outer.finalize())
}

/// Computes the owner/server proof for one response: HMAC-SHA256 over the
/// canonical commitment message keyed by the broker-minted request
/// credential. Only a holder of that credential — the exact approved
/// `OpenCode` process and the bridge — can mint or verify it.
#[must_use]
pub fn response_commitment(fields: &HostEventResponseFields, credential: &SecretString) -> String {
    hmac_sha256_hex(
        credential.expose_secret().as_bytes(),
        &response_commitment_message(fields),
    )
}

/// Verifies one presented commitment in constant time over its bytes.
/// Length or byte mismatch fails closed; only the boolean is reported.
#[must_use]
pub fn verify_response_commitment(
    fields: &HostEventResponseFields,
    credential: &SecretString,
    commitment: &str,
) -> bool {
    constant_time_equal(
        response_commitment(fields, credential).as_bytes(),
        commitment.as_bytes(),
    )
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        diff |= left_byte ^ right_byte;
    }
    diff == 0
}

fn insert_opt_text(
    body: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<&String>,
) {
    body.insert(
        key.to_owned(),
        value.map_or(serde_json::Value::Null, |text| {
            serde_json::Value::String(text.clone())
        }),
    );
}

/// Encodes the full versioned response body including its commitment.
#[must_use]
pub fn encode_host_event_response(
    fields: &HostEventResponseFields,
    credential: &SecretString,
) -> serde_json::Value {
    let mut body = serde_json::Map::with_capacity(17);
    body.insert(
        "response_version".to_owned(),
        serde_json::Value::String(HOST_EVENTS_RESPONSE_VERSION.to_owned()),
    );
    body.insert(
        "event_id".to_owned(),
        serde_json::Value::String(fields.event_id.clone()),
    );
    insert_opt_text(&mut body, "effect_digest", fields.effect_digest.as_ref());
    body.insert(
        "decision".to_owned(),
        serde_json::Value::String(fields.decision.to_owned()),
    );
    insert_opt_text(&mut body, "disposition", fields.disposition.as_ref());
    insert_opt_text(&mut body, "reason_code", fields.reason_code.as_ref());
    body.insert(
        "installation_id".to_owned(),
        serde_json::Value::String(fields.installation_id.clone()),
    );
    body.insert(
        "bridge_generation".to_owned(),
        serde_json::Value::Number(fields.bridge_generation.into()),
    );
    body.insert(
        "authority_epoch".to_owned(),
        serde_json::Value::String(fields.authority_epoch.clone()),
    );
    body.insert(
        "state_fence".to_owned(),
        serde_json::Value::String(fields.state_fence.clone()),
    );
    insert_opt_text(
        &mut body,
        "policy_revision",
        fields.policy_revision.as_ref(),
    );
    insert_opt_text(
        &mut body,
        "authority_revision",
        fields.authority_revision.as_ref(),
    );
    body.insert(
        "expires_at_ms".to_owned(),
        fields
            .expires_at_ms
            .map_or(serde_json::Value::Null, |expires| {
                serde_json::Value::Number(expires.into())
            }),
    );
    body.insert(
        "event_receipt".to_owned(),
        serde_json::Value::String(fields.event_receipt.clone()),
    );
    insert_opt_text(
        &mut body,
        "decision_receipt",
        fields.decision_receipt.as_ref(),
    );
    body.insert(
        "replayed".to_owned(),
        serde_json::Value::Bool(fields.replayed),
    );
    let commitment = response_commitment(fields, credential);
    body.insert(
        "response_commitment".to_owned(),
        serde_json::Value::String(commitment),
    );
    serde_json::Value::Object(body)
}

/// Composition of the ingress ports.
pub struct HostEventPorts<A, G, I, C> {
    /// Existing bridge-event durable route.
    pub admission: A,
    /// Governor/authority pre-effect decision owner.
    pub gate: G,
    /// Current-introduction holder and clock.
    pub introductions: I,
    /// Owner-side credential resolver.
    pub credentials: C,
}

/// Handler outcome: HTTP status plus the exact JSON body.
#[derive(Clone, Debug)]
pub struct HttpOutcome {
    /// HTTP status code.
    pub status: u16,
    /// Exact JSON body (versioned response or typed error).
    pub body: serde_json::Value,
}

impl HttpOutcome {
    fn ok(body: serde_json::Value) -> Self {
        Self { status: 200, body }
    }

    fn rejected(reject: HostEventReject, event_id: Option<&str>) -> Self {
        Self {
            status: reject.status,
            body: reject.error_body(event_id),
        }
    }
}

fn optional_text(value: &serde_json::Value, field: &str) -> Option<String> {
    match value.get(field) {
        Some(serde_json::Value::String(text)) if !text.is_empty() => Some(text.clone()),
        Some(_) | None => None,
    }
}

struct JoinedIntroduction {
    introduction: OpenCodeBridgeIntroduction,
    credential: SecretString,
    now_ms: u64,
}

fn join_introduction<I, C>(
    head: &ParsedHostEventHead,
    bound_port: u16,
    introductions: &I,
    credentials: &C,
) -> Result<JoinedIntroduction, HostEventReject>
where
    I: IntroductionStore,
    C: CredentialResolver,
{
    let now_ms = introductions.now_ms();
    let Some(introduction) = introductions.current_introduction() else {
        return Err(HostEventReject::new(
            503,
            DISPOSITION_UNAVAILABLE_OR_CAPACITY,
            REASON_CAPABILITY_INTRODUCTION_REQUIRED,
        ));
    };
    if let Err(error) = introduction.validate(now_ms) {
        let reject = match error {
            eliot_user_broker_core::BrokerError::LeaseExpired => {
                HostEventReject::new(401, DISPOSITION_DENIED, REASON_AUTHENTICATION_REQUIRED)
            }
            _ => HostEventReject::new(
                503,
                DISPOSITION_UNAVAILABLE_OR_CAPACITY,
                REASON_CAPABILITY_UNAVAILABLE,
            ),
        };
        return Err(reject);
    }
    let pinned_port = LoopbackEndpoint::parse(&introduction.endpoint)
        .map(|endpoint| endpoint.port())
        .ok();
    if pinned_port != Some(bound_port) {
        // The introduction pins a different bridge incarnation than this
        // listener serves: a foreign or stale listener must not admit it.
        return Err(HostEventReject::new(
            404,
            DISPOSITION_INVALID_REQUEST,
            REASON_ROUTE_UNAVAILABLE,
        ));
    }
    if introductions.is_revoked(&introduction.revocation_id) {
        return Err(HostEventReject::new(
            403,
            DISPOSITION_DENIED,
            REASON_CAPABILITY_GRANT_REVOKED,
        ));
    }
    if introduction
        .probe_current_session(&introductions.session_facts())
        .is_err()
    {
        return Err(HostEventReject::new(
            401,
            DISPOSITION_DENIED,
            REASON_AUTHENTICATION_REQUIRED,
        ));
    }
    let Ok(credential) = credentials.resolve(&introduction.credential) else {
        return Err(HostEventReject::new(
            503,
            DISPOSITION_UNAVAILABLE_OR_CAPACITY,
            REASON_CAPABILITY_UNAVAILABLE,
        ));
    };
    if !constant_time_equal(
        credential.expose_secret().as_bytes(),
        head.bearer.expose_secret().as_bytes(),
    ) {
        return Err(HostEventReject::new(
            401,
            DISPOSITION_DENIED,
            REASON_AUTHENTICATION_REQUIRED,
        ));
    }
    Ok(JoinedIntroduction {
        introduction,
        credential,
        now_ms,
    })
}

/// Handles one bounded `POST /v1/host-events` request end to end.
///
/// Pipeline: introduction join (current, valid window, endpoint pinned to
/// this listener, not revoked, live session probe) → credential resolve and
/// constant-time compare → capability check → closed payload decode with the
/// `gate.rs` validators → normalization → durable admission through the
/// existing bridge-event route → `ActionGate` join for `tool.execute.before`
/// only → owner-verified versioned response. `bound_port` is the serving
/// listener's explicit port: an introduction pinned to any other endpoint is
/// refused, so a foreign or stale listener cannot admit it. Every failure is
/// a typed rejection; no failure path emits a permit.
pub fn handle_host_event<A, G, I, C>(
    head: &ParsedHostEventHead,
    body: &[u8],
    bound_port: u16,
    ports: &mut HostEventPorts<A, G, I, C>,
) -> HttpOutcome
where
    A: HostEventAdmission,
    G: ActionGate,
    I: IntroductionStore,
    C: CredentialResolver,
{
    handle_host_event_inner(head, body, bound_port, None, ports)
}

/// Production admission entry that requires an OS-observed accepted-socket
/// peer identity and compares it to the exact PID/start/image tuple bound by
/// the current Broker introduction.
pub fn handle_host_event_from_process<A, G, I, C>(
    head: &ParsedHostEventHead,
    body: &[u8],
    bound_port: u16,
    peer: &HostEventPeerProcessIdentity,
    ports: &mut HostEventPorts<A, G, I, C>,
) -> HttpOutcome
where
    A: HostEventAdmission,
    G: ActionGate,
    I: IntroductionStore,
    C: CredentialResolver,
{
    handle_host_event_inner(head, body, bound_port, Some(peer), ports)
}

fn peer_matches_process_binding(
    peer: &HostEventPeerProcessIdentity,
    binding: &eliot_user_broker_core::OpenCodeProcessBinding,
) -> bool {
    peer.process_id == binding.process_id
        && peer.process_start_time_100ns == binding.process_start_time_100ns
        && peer.image_path == binding.image_path
}

fn handle_host_event_inner<A, G, I, C>(
    head: &ParsedHostEventHead,
    body: &[u8],
    bound_port: u16,
    peer: Option<&HostEventPeerProcessIdentity>,
    ports: &mut HostEventPorts<A, G, I, C>,
) -> HttpOutcome
where
    A: HostEventAdmission,
    G: ActionGate,
    I: IntroductionStore,
    C: CredentialResolver,
{
    let joined = match join_introduction(head, bound_port, &ports.introductions, &ports.credentials)
    {
        Ok(joined) => joined,
        Err(reject) => return HttpOutcome::rejected(reject, None),
    };
    let introduction = joined.introduction;
    if let Some(peer) = peer {
        if !peer_matches_process_binding(peer, &introduction.process_binding) {
            return HttpOutcome::rejected(
                HostEventReject::new(401, DISPOSITION_DENIED, REASON_AUTHENTICATION_REQUIRED),
                None,
            );
        }
    }
    let credential = joined.credential;
    let now_ms = joined.now_ms;

    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => {
            return HttpOutcome::rejected(
                HostEventReject::new(400, DISPOSITION_INVALID_REQUEST, REASON_INVALID_ARGUMENT),
                None,
            );
        }
    };
    if value.as_object().is_none_or(serde_json::Map::is_empty) {
        return HttpOutcome::rejected(
            HostEventReject::new(400, DISPOSITION_INVALID_REQUEST, REASON_INVALID_ARGUMENT),
            None,
        );
    }
    let event_id = match value.get("event_id").and_then(serde_json::Value::as_str) {
        Some(event_id) if !event_id.is_empty() && event_id.len() <= MAX_EVENT_ID_BYTES => event_id,
        _ => {
            return HttpOutcome::rejected(
                HostEventReject::new(400, DISPOSITION_INVALID_REQUEST, REASON_INVALID_ARGUMENT),
                None,
            );
        }
    };
    if head
        .idempotency_key
        .as_deref()
        .is_some_and(|key| key != event_id)
    {
        return HttpOutcome::rejected(
            HostEventReject::new(400, DISPOSITION_INVALID_REQUEST, REASON_INVALID_ARGUMENT),
            Some(event_id),
        );
    }
    let event_kind = value.get("event_kind").and_then(serde_json::Value::as_str);
    match event_kind {
        Some(crate::gate::OPENCODE_GATE_EVENT_KIND) => handle_gate_event(
            &introduction,
            event_id,
            body,
            &value,
            &credential,
            now_ms,
            ports,
        ),
        Some(crate::gate::OPENCODE_SKIPPED_EVENT_KIND) => {
            handle_skipped_event(&introduction, event_id, body, &value, &credential, ports)
        }
        Some(kind) => handle_passive_event(
            &introduction,
            event_id,
            kind,
            body,
            &value,
            &credential,
            ports,
        ),
        None => HttpOutcome::rejected(
            HostEventReject::new(400, DISPOSITION_INVALID_REQUEST, REASON_INVALID_ARGUMENT),
            Some(event_id),
        ),
    }
}

#[cfg(test)]
mod issue_1935_native_peer_tests {
    use super::{
        HostEventPeerProcessIdentity, base_submission, normalized_request_without_restricted_source,
        peer_matches_process_binding,
    };
    use eliot_user_broker_core::OpenCodeProcessBinding;

    fn binding() -> OpenCodeProcessBinding {
        OpenCodeProcessBinding {
            process_id: 4120,
            process_start_time_100ns: 8_811_209,
            image_path: r"C:\Users\owner\AppData\Local\Programs\OpenCode\opencode.exe".to_owned(),
            adapter_artifact_digest: "a".repeat(64),
            adapter_descriptor_digest: "b".repeat(64),
            installation_profile_digest: "c".repeat(64),
            native_event_classes: [
                "session.created",
                "session.compacted",
                "session.error",
                "session.idle",
                "permission.asked",
                "permission.replied",
                "file.edited",
                "todo.updated",
            ]
            .map(str::to_owned)
            .to_vec(),
            native_hook_classes: ["tool.execute.before", "tool.execute.after"]
                .map(str::to_owned)
                .to_vec(),
            executable_digest: "d".repeat(64),
            launch_nonce: "broker-launch-42".to_owned(),
            parent_broker_process_id: "4000".to_owned(),
        }
    }

    #[test]
    fn issue_1935_native_callback_accepts_exact_socket_process_binding() {
        let binding = binding();
        let peer = HostEventPeerProcessIdentity {
            process_id: binding.process_id,
            process_start_time_100ns: binding.process_start_time_100ns,
            image_path: binding.image_path.clone(),
        };
        assert!(peer_matches_process_binding(&peer, &binding));
    }

    #[test]
    fn issue_1935_native_callback_refuses_recycled_or_foreign_socket_process() {
        let binding = binding();
        let peer = HostEventPeerProcessIdentity {
            process_id: binding.process_id,
            process_start_time_100ns: binding.process_start_time_100ns + 1,
            image_path: binding.image_path.clone(),
        };
        assert!(!peer_matches_process_binding(&peer, &binding));
    }

    #[test]
    fn issue_1935_native_callback_keeps_exact_source_private_from_projection() {
        let source = serde_json::json!({"event":"session.idle","private":"callback bytes"});
        let request = serde_json::json!({
            "event_id":"opencode:session.idle:1",
            "sequence":1,
            "native_source":source,
            "event_kind":"session.idle"
        });
        let submission = base_submission(
            "opencode:session.idle:1",
            br#"{"native_source":{"event":"session.idle","private":"callback bytes"}}"#,
            &request,
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                submission.restricted_source_bytes.as_deref().expect("source sidecar"),
            )
            .expect("canonical source"),
            source
        );
        let normalized = normalized_request_without_restricted_source(&request);
        assert!(normalized.get("native_source").is_none());
        assert_eq!(normalized["event_kind"], "session.idle");
    }

    #[test]
    fn issue_1935_native_callback_refuses_missing_original_source_as_unavailable() {
        let request = serde_json::json!({"event_id":"opencode:session.idle:1"});
        let submission = base_submission("opencode:session.idle:1", b"{}", &request);
        assert!(submission.restricted_source_bytes.is_none());
        assert!(normalized_request_without_restricted_source(&request).get("native_source").is_none());
    }

    #[test]
    fn issue_1935_native_fingerprint_uses_broker_admitted_artifact_and_runtime_join() {
        let binding = binding();
        let projected = broker_process_binding_projection(&binding, "intro-digest");
        assert_eq!(projected["process_id"], binding.process_id);
        assert_eq!(projected["process_start_time_100ns"], binding.process_start_time_100ns);
        assert_eq!(projected["adapter_artifact_sha256"], binding.adapter_artifact_digest);
        assert_eq!(projected["adapter_descriptor_sha256"], binding.adapter_descriptor_digest);
        assert_eq!(projected["installation_profile_sha256"], binding.installation_profile_digest);
        assert_eq!(projected["native_event_classes"], serde_json::json!(binding.native_event_classes));
        assert_eq!(projected["native_hook_classes"], serde_json::json!(binding.native_hook_classes));
        assert_eq!(projected["executable_sha256"], binding.executable_digest);
        assert!(broker_admitted_native_class(&binding, "session.idle"));
        assert!(!broker_admitted_native_class(&binding, "caller.submitted"));
    }
}

fn normalized_request_without_restricted_source(value: &serde_json::Value) -> serde_json::Value {
    let mut normalized = value.clone();
    if let Some(object) = normalized.as_object_mut() {
        object.remove("native_source");
    }
    normalized
}

fn broker_process_binding_projection(
    binding: &eliot_user_broker_core::OpenCodeProcessBinding,
    introduction_digest: &str,
) -> serde_json::Value {
    serde_json::json!({
        "process_id": binding.process_id,
        "process_start_time_100ns": binding.process_start_time_100ns,
        "image_path": binding.image_path,
        "adapter_artifact_sha256": binding.adapter_artifact_digest,
        "adapter_descriptor_sha256": binding.adapter_descriptor_digest,
        "installation_profile_sha256": binding.installation_profile_digest,
        "native_event_classes": binding.native_event_classes,
        "native_hook_classes": binding.native_hook_classes,
        "executable_sha256": binding.executable_digest,
        "launch_nonce": binding.launch_nonce,
        "introduction_digest": introduction_digest,
    })
}

fn broker_admitted_native_class(
    binding: &eliot_user_broker_core::OpenCodeProcessBinding,
    kind: &str,
) -> bool {
    binding.native_event_classes.iter().any(|expected| expected == kind)
}

fn transport_hash(body: &[u8]) -> String {
    format!("{:x}", Sha256::digest(body))
}

fn base_response_fields(
    introduction: &OpenCodeBridgeIntroduction,
    receipt: &HostEventAdmissionReceipt,
    event_id: &str,
) -> HostEventResponseFields {
    HostEventResponseFields {
        event_id: event_id.to_owned(),
        effect_digest: None,
        decision: DECISION_RECORDED,
        disposition: None,
        reason_code: None,
        installation_id: introduction.installation_id.clone(),
        bridge_generation: receipt.bridge_generation,
        authority_epoch: authority_epoch_text(&receipt.authority_epoch),
        state_fence: receipt.fence_id.clone(),
        policy_revision: None,
        authority_revision: None,
        expires_at_ms: None,
        event_receipt: receipt.envelope_digest.clone(),
        decision_receipt: None,
        replayed: receipt.replayed,
    }
}

fn base_submission(event_id: &str, body: &[u8], value: &serde_json::Value) -> HostEventSubmission {
    HostEventSubmission {
        stream_id: HOST_EVENTS_STREAM_ID.to_owned(),
        producer_id: HOST_EVENTS_PRODUCER_ID.to_owned(),
        event_id: event_id.to_owned(),
        sequence: value
            .get("sequence")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default(),
        kind: HostEventKind::Passive(String::new()),
        delivery: HostEventDelivery::Observation,
        host_session_id: optional_text(value, "host_session_id"),
        task_id: optional_text(value, "task_id"),
        work_item_id: optional_text(value, "work_item_id"),
        tool: None,
        effect_digest: None,
        argument_keys: Vec::new(),
        transport_hash: transport_hash(body),
        restricted_source_bytes: value
            .get("native_source")
            .and_then(|source| canonical_json_bytes(source).ok()),
        envelope_json: serde_json::Value::Null,
    }
}

/// Returns whether one evaluated `allow` decision is well-bound to the
/// exact request it evaluated: no deny reason, a current expiry, the exact
/// request-hash echo, and non-empty policy/authority revisions plus a
/// decision receipt commitment. Anything else degrades to `recorded`.
fn gate_allow_is_well_bound(
    decision: &ActionGateDecision,
    request_hash: &str,
    now_ms: u64,
) -> bool {
    decision.reason_code.is_none()
        && decision.expires_at_ms > now_ms
        && decision.request_hash == request_hash
        && !decision.policy_revision.is_empty()
        && !decision.authority_revision.is_empty()
        && !decision.decision_receipt.is_empty()
}

/// Applies one well-bound `allow` decision to the response fields.
fn apply_gate_allow(fields: &mut HostEventResponseFields, decision: ActionGateDecision) {
    fields.decision = DECISION_ALLOW;
    fields.policy_revision = Some(decision.policy_revision);
    fields.authority_revision = Some(decision.authority_revision);
    fields.expires_at_ms = Some(decision.expires_at_ms);
    fields.decision_receipt = Some(decision.decision_receipt);
}

/// Applies one evaluated `deny` to the response fields. The owner evaluated
/// and refused, so the answer carries the typed `DENIED` disposition, the
/// closed reason code the owner returned (a `POLICY_DENIED` default when it
/// returned none), and the policy/authority revisions and decision commitment
/// the refusal was made under — never degraded to an untyped `recorded`.
fn apply_gate_deny(fields: &mut HostEventResponseFields, decision: ActionGateDecision) {
    fields.decision = DECISION_DENY;
    fields.disposition = Some(DISPOSITION_DENIED.to_owned());
    fields.reason_code = Some(
        decision
            .reason_code
            .unwrap_or(REASON_POLICY_DENIED)
            .to_owned(),
    );
    fields.policy_revision = Some(decision.policy_revision);
    fields.authority_revision = Some(decision.authority_revision);
    fields.decision_receipt = Some(decision.decision_receipt);
}

#[allow(clippy::too_many_arguments)]
fn handle_gate_event<A, G, I, C>(
    introduction: &OpenCodeBridgeIntroduction,
    event_id: &str,
    body: &[u8],
    value: &serde_json::Value,
    credential: &SecretString,
    now_ms: u64,
    ports: &mut HostEventPorts<A, G, I, C>,
) -> HttpOutcome
where
    A: HostEventAdmission,
    G: ActionGate,
    I: IntroductionStore,
    C: CredentialResolver,
{
    if !introduction.allows(OPENCODE_BRIDGE_CAPABILITY_MUTATION_GATE) {
        return HttpOutcome::rejected(
            HostEventReject::new(403, DISPOSITION_DENIED, REASON_AUTHORITY_REQUIRED),
            Some(event_id),
        );
    }
    let normalized_request = normalized_request_without_restricted_source(value);
    let validated: ValidatedMutationGate = match validate_mutation_gate_payload(&normalized_request) {
        Ok(validated) => validated,
        Err(_) => {
            return HttpOutcome::rejected(
                HostEventReject::new(400, DISPOSITION_INVALID_REQUEST, REASON_INVALID_ARGUMENT),
                Some(event_id),
            );
        }
    };
    let mut envelope = normalized_request;
    if let Some(object) = envelope.as_object_mut() {
        object.insert(
            "transport_hash".to_owned(),
            serde_json::Value::String(transport_hash(body)),
        );
    }
    let mut submission = base_submission(event_id, body, value);
    submission.kind = HostEventKind::Gate;
    submission.delivery = HostEventDelivery::Control;
    submission.tool = Some(validated.tool.clone());
    submission.effect_digest = Some(validated.effect_digest.clone());
    submission
        .argument_keys
        .clone_from(&validated.argument_keys);
    submission.envelope_json = envelope;
    // First durable admission of the retained event. The route's own ORS
    // idempotency answers here: `Duplicate` means this exact operation
    // identity already holds this exact content, and `Conflict` means the
    // same identity carries changed content. Both are decided from the stored
    // content, not from the identity's existence.
    let receipt = match ports.admission.admit(introduction, &submission) {
        Ok(receipt) => receipt,
        Err(error) => return HttpOutcome::rejected(error.reject(), Some(event_id)),
    };
    let request_hash = effect_request_hash(
        event_id,
        event_id,
        &validated.effect_digest,
        &validated.tool,
        submission.task_id.as_deref(),
        receipt.bridge_generation,
        &receipt.authority_epoch,
        &receipt.fence_id,
        &receipt.envelope_digest,
    );
    if let Some(stored) = receipt.replayed_decision.clone() {
        // A lost response reconciles the original operation: the stored
        // decision is compared with the decision this request would produce.
        // Same content replays the original answer with no second policy
        // evaluation and no process-bridge fallback; changed content is a
        // determined conflict that performs no transition.
        let presented = presented_gate_decision(
            introduction,
            event_id,
            &validated,
            &submission,
            &receipt,
            &stored,
        );
        return reconcile_stored_decision(introduction, event_id, credential, &stored, &presented);
    }
    let request = ActionGateRequest {
        operation_id: event_id.to_owned(),
        request_hash,
        event_id: event_id.to_owned(),
        effect_digest: validated.effect_digest.clone(),
        tool: validated.tool.clone(),
        task_id: submission.task_id.clone(),
        bridge_generation: receipt.bridge_generation,
        authority_epoch: receipt.authority_epoch.clone(),
        fence_id: receipt.fence_id.clone(),
    };
    let mut fields = base_response_fields(introduction, &receipt, event_id);
    fields.effect_digest = Some(validated.effect_digest.clone());
    let decision = match ports.gate.decide(introduction, &receipt, &request) {
        Ok(decision) => decision,
        Err(error) => {
            return gate_failure_outcome(error, &fields, credential, event_id);
        }
    };
    // Persist the decision with its exact decision identity before answering,
    // so the durable event and its decision are one reconciled record.
    let record = gate_decision_record(
        introduction,
        event_id,
        &validated,
        &submission,
        &receipt,
        &decision,
    );
    let committed = match ports.admission.commit_decision(&record) {
        Ok(committed) => committed,
        Err(error) => return HttpOutcome::rejected(error.reject(), Some(event_id)),
    };
    if let Some(stored) = committed.replayed_decision {
        return reconcile_stored_decision(introduction, event_id, credential, &stored, &record);
    }
    if !decision.allow {
        apply_gate_deny(&mut fields, decision);
    } else if gate_allow_is_well_bound(&decision, &request.request_hash, now_ms) {
        apply_gate_allow(&mut fields, decision);
    }
    HttpOutcome::ok(encode_host_event_response(&fields, credential))
}

/// Answers one presented decision against the stored original it was matched
/// with, by the same content comparison on both reconciliation paths: an exact
/// content replay reproduces the original answer, and changed content under a
/// known identity is a determined conflict that performs no transition.
fn reconcile_stored_decision(
    introduction: &OpenCodeBridgeIntroduction,
    event_id: &str,
    credential: &SecretString,
    stored: &EffectDecisionRecord,
    presented: &EffectDecisionRecord,
) -> HttpOutcome {
    match classify_decision_replay(stored, presented) {
        Some(DecisionReplay::Replay) => HttpOutcome::ok(encode_host_event_response(
            &replayed_response_fields(introduction, stored),
            credential,
        )),
        Some(DecisionReplay::Conflict) | None => HttpOutcome::rejected(
            HostEventReject::new(409, DISPOSITION_STALE_OR_CONFLICT, REASON_IDENTITY_CONFLICT),
            Some(event_id),
        ),
    }
}

/// Translates one pre-effect gate failure into its exact outcome. An
/// unconfigured gate is a durable observation that cannot authorize a mutating
/// tool; every other failure is a typed rejection. No failure path emits a
/// permit.
fn gate_failure_outcome(
    error: ActionGateError,
    fields: &HostEventResponseFields,
    credential: &SecretString,
    event_id: &str,
) -> HttpOutcome {
    match error {
        ActionGateError::Unconfigured => {
            HttpOutcome::ok(encode_host_event_response(fields, credential))
        }
        ActionGateError::Backpressure => HttpOutcome::rejected(
            HostEventReject::new(429, DISPOSITION_UNAVAILABLE_OR_CAPACITY, REASON_BUSY),
            Some(event_id),
        ),
        ActionGateError::Unavailable => HttpOutcome::rejected(
            HostEventReject::new(
                503,
                DISPOSITION_UNAVAILABLE_OR_CAPACITY,
                REASON_CAPABILITY_UNAVAILABLE,
            ),
            Some(event_id),
        ),
        ActionGateError::Fenced => HttpOutcome::rejected(
            HostEventReject::new(409, DISPOSITION_STALE_OR_CONFLICT, REASON_STALE_STATE_FENCE),
            Some(event_id),
        ),
    }
}

/// Projects the decision identity this request presents for the stored
/// original, without re-evaluating policy.
///
/// The request-derived bindings come from **this** request — the recomputed
/// effect digest, the tool, the task/scope, the live bridge generation, the
/// `OpenCode` generation, the fence, the authority epoch, the recomputed
/// request hash and the durable event commitment. The evaluation facts come
/// from the stored original, because a reconciled retry reuses the decision
/// that was already made instead of evaluating a second one. The result is
/// therefore the exact record this request *would* have produced for the same
/// operation: identical content for an exact retry (`Replay`), and a changed
/// effect, argument set, scope, fence, generation or event commitment under
/// the same operation identity yields different content (`Conflict`).
fn presented_gate_decision(
    introduction: &OpenCodeBridgeIntroduction,
    event_id: &str,
    validated: &ValidatedMutationGate,
    submission: &HostEventSubmission,
    receipt: &HostEventAdmissionReceipt,
    stored: &EffectDecisionRecord,
) -> EffectDecisionRecord {
    let request_hash = effect_request_hash(
        event_id,
        event_id,
        &validated.effect_digest,
        &validated.tool,
        submission.task_id.as_deref(),
        receipt.bridge_generation,
        &receipt.authority_epoch,
        &receipt.fence_id,
        &receipt.envelope_digest,
    );
    EffectDecisionRecord {
        operation_id: event_id.to_owned(),
        request_hash,
        effect_digest: validated.effect_digest.clone(),
        tool: validated.tool.clone(),
        task_id: submission.task_id.clone(),
        bridge_generation: receipt.bridge_generation,
        opencode_generation: introduction.introduction_digest.clone(),
        fence_id: receipt.fence_id.clone(),
        authority_epoch: authority_epoch_text(&receipt.authority_epoch),
        policy_revision: stored.policy_revision.clone(),
        authority_revision: stored.authority_revision.clone(),
        decision: stored.decision.clone(),
        reason_code: stored.reason_code.clone(),
        expires_at_ms: stored.expires_at_ms,
        event_receipt: receipt.envelope_digest.clone(),
        decision_receipt: stored.decision_receipt.clone(),
        reconciliation_owner: HOST_EVENTS_DECISION_RECONCILER.to_owned(),
    }
}

/// Builds the persisted effect decision for one evaluation, binding every
/// field W10 names.
fn gate_decision_record(
    introduction: &OpenCodeBridgeIntroduction,
    event_id: &str,
    validated: &ValidatedMutationGate,
    submission: &HostEventSubmission,
    receipt: &HostEventAdmissionReceipt,
    decision: &ActionGateDecision,
) -> EffectDecisionRecord {
    EffectDecisionRecord {
        operation_id: event_id.to_owned(),
        request_hash: decision.request_hash.clone(),
        effect_digest: validated.effect_digest.clone(),
        tool: validated.tool.clone(),
        task_id: submission.task_id.clone(),
        bridge_generation: receipt.bridge_generation,
        opencode_generation: introduction.introduction_digest.clone(),
        fence_id: receipt.fence_id.clone(),
        authority_epoch: authority_epoch_text(&receipt.authority_epoch),
        policy_revision: decision.policy_revision.clone(),
        authority_revision: decision.authority_revision.clone(),
        decision: if decision.allow {
            DECISION_ALLOW.to_owned()
        } else {
            DECISION_DENY.to_owned()
        },
        reason_code: decision.reason_code.unwrap_or_default().to_owned(),
        expires_at_ms: decision.expires_at_ms,
        event_receipt: receipt.envelope_digest.clone(),
        decision_receipt: decision.decision_receipt.clone(),
        reconciliation_owner: HOST_EVENTS_DECISION_RECONCILER.to_owned(),
    }
}

/// Builds the replayed response from the stored decision, so a reconciled
/// answer reproduces the original one rather than a fresh evaluation.
///
/// Only reached on an exact content match
/// ([`DecisionReplay::Replay`]), so this is the original decision: an `allow`
/// replays as the same `allow` with its original expiry and commitments, and a
/// stored refusal replays as the same typed `deny` with its original closed
/// reason code, never degraded to an untyped `recorded`.
fn replayed_response_fields(
    introduction: &OpenCodeBridgeIntroduction,
    stored: &EffectDecisionRecord,
) -> HostEventResponseFields {
    let allow = stored.decision == DECISION_ALLOW;
    let denied = !allow;
    HostEventResponseFields {
        event_id: stored.operation_id.clone(),
        effect_digest: Some(stored.effect_digest.clone()),
        decision: if allow { DECISION_ALLOW } else { DECISION_DENY },
        disposition: denied.then(|| DISPOSITION_DENIED.to_owned()),
        reason_code: denied.then(|| {
            if stored.reason_code.is_empty() {
                REASON_POLICY_DENIED.to_owned()
            } else {
                stored.reason_code.clone()
            }
        }),
        installation_id: introduction.installation_id.clone(),
        bridge_generation: stored.bridge_generation,
        authority_epoch: stored.authority_epoch.clone(),
        state_fence: stored.fence_id.clone(),
        policy_revision: Some(stored.policy_revision.clone()),
        authority_revision: Some(stored.authority_revision.clone()),
        expires_at_ms: (allow && stored.expires_at_ms > 0).then_some(stored.expires_at_ms),
        event_receipt: stored.event_receipt.clone(),
        decision_receipt: Some(stored.decision_receipt.clone()),
        replayed: true,
    }
}

fn handle_skipped_event<A, G, I, C>(
    introduction: &OpenCodeBridgeIntroduction,
    event_id: &str,
    body: &[u8],
    value: &serde_json::Value,
    credential: &SecretString,
    ports: &mut HostEventPorts<A, G, I, C>,
) -> HttpOutcome
where
    A: HostEventAdmission,
    G: ActionGate,
    I: IntroductionStore,
    C: CredentialResolver,
{
    if !introduction.allows(OPENCODE_BRIDGE_CAPABILITY_OBSERVATION_SUBMIT) {
        return HttpOutcome::rejected(
            HostEventReject::new(403, DISPOSITION_DENIED, REASON_AUTHORITY_REQUIRED),
            Some(event_id),
        );
    }
    let normalized_request = normalized_request_without_restricted_source(value);
    let validated: ValidatedSkippedReceipt = match validate_skipped_tool_receipt(&normalized_request) {
        Ok(validated) => validated,
        Err(_) => {
            return HttpOutcome::rejected(
                HostEventReject::new(400, DISPOSITION_INVALID_REQUEST, REASON_INVALID_ARGUMENT),
                Some(event_id),
            );
        }
    };
    let mut envelope = normalized_request;
    if let Some(object) = envelope.as_object_mut() {
        object.insert(
            "transport_hash".to_owned(),
            serde_json::Value::String(transport_hash(body)),
        );
    }
    let mut submission = base_submission(event_id, body, value);
    submission.kind = HostEventKind::Skipped;
    submission.delivery = HostEventDelivery::Observation;
    submission.tool = Some(validated.tool.clone());
    submission.effect_digest = Some(validated.effect_digest.clone());
    submission.argument_keys = validated.argument_keys;
    submission.envelope_json = envelope;
    let receipt = match ports.admission.admit(introduction, &submission) {
        Ok(receipt) => receipt,
        Err(error) => return HttpOutcome::rejected(error.reject(), Some(event_id)),
    };
    let mut fields = base_response_fields(introduction, &receipt, event_id);
    fields.effect_digest = Some(validated.effect_digest);
    HttpOutcome::ok(encode_host_event_response(&fields, credential))
}

fn passive_envelope(
    introduction: &OpenCodeBridgeIntroduction,
    event_id: &str,
    sequence: u64,
    body: &[u8],
    object: &serde_json::Map<String, serde_json::Value>,
) -> serde_json::Value {
    let mut envelope = serde_json::Map::with_capacity(12);
    envelope.insert(
        "event_id".to_owned(),
        serde_json::Value::String(event_id.to_owned()),
    );
    envelope.insert(
        "sequence".to_owned(),
        serde_json::Value::Number(sequence.into()),
    );
    // Every field comes from the authenticated User Broker introduction, not
    // from plugin payload claims. The Broker joined the OS-observed process
    // identity and executable digest to the exact installation-admitted
    // adapter artifact, descriptor and profile before issuing this binding.
    envelope.insert(
        "opencode_process_binding".to_owned(),
        broker_process_binding_projection(
            &introduction.process_binding,
            introduction.introduction_digest.as_str(),
        ),
    );
    for field in [
        "native_emitted_at",
        "event_kind",
        "vendor_event_kind",
        "host_session_id",
        "task_id",
        "work_item_id",
        "tool",
        "changed_path",
    ] {
        if let Some(text) = object.get(field).and_then(serde_json::Value::as_str) {
            envelope.insert(field.to_owned(), serde_json::Value::String(text.to_owned()));
        }
    }
    for field in ["native_sequence"] {
        if let Some(value) = object.get(field).filter(|value| value.is_u64()) {
            envelope.insert(field.to_owned(), value.clone());
        }
    }
    if let Some(native_event_id) = object
        .get("native_event_id")
        .and_then(serde_json::Value::as_str)
    {
        envelope.insert(
            "native_event_id".to_owned(),
            serde_json::Value::String(native_event_id.to_owned()),
        );
    }
    if let Some(keys) = object
        .get("argument_keys")
        .and_then(serde_json::Value::as_array)
    {
        let mut bounded: Vec<serde_json::Value> = Vec::new();
        for key in keys
            .iter()
            .take(crate::gate::OPENCODE_MAX_ARGUMENT_KEYS + 1)
        {
            if let Some(text) = key.as_str() {
                bounded.push(serde_json::Value::String(text.to_owned()));
            }
        }
        if bounded.len() == keys.len() {
            envelope.insert(
                "argument_keys".to_owned(),
                serde_json::Value::Array(bounded),
            );
        }
    }
    envelope.insert(
        "transport_hash".to_owned(),
        serde_json::Value::String(transport_hash(body)),
    );
    serde_json::Value::Object(envelope)
}

#[allow(clippy::too_many_arguments)]
fn handle_passive_event<A, G, I, C>(
    introduction: &OpenCodeBridgeIntroduction,
    event_id: &str,
    kind: &str,
    body: &[u8],
    value: &serde_json::Value,
    credential: &SecretString,
    ports: &mut HostEventPorts<A, G, I, C>,
) -> HttpOutcome
where
    A: HostEventAdmission,
    G: ActionGate,
    I: IntroductionStore,
    C: CredentialResolver,
{
    if !introduction.allows(OPENCODE_BRIDGE_CAPABILITY_OBSERVATION_SUBMIT) {
        return HttpOutcome::rejected(
            HostEventReject::new(403, DISPOSITION_DENIED, REASON_AUTHORITY_REQUIRED),
            Some(event_id),
        );
    }
    if kind.is_empty() || kind.len() > MAX_EVENT_ID_BYTES {
        return HttpOutcome::rejected(
            HostEventReject::new(400, DISPOSITION_INVALID_REQUEST, REASON_INVALID_ARGUMENT),
            Some(event_id),
        );
    }
    if !broker_admitted_native_class(&introduction.process_binding, kind) {
        return HttpOutcome::rejected(
            HostEventReject::new(400, DISPOSITION_INVALID_REQUEST, REASON_INVALID_ARGUMENT),
            Some(event_id),
        );
    }
    let object = match value.as_object() {
        Some(object) if object.len() <= MAX_PASSIVE_EVENT_FIELDS => object,
        _ => {
            return HttpOutcome::rejected(
                HostEventReject::new(400, DISPOSITION_INVALID_REQUEST, REASON_INVALID_ARGUMENT),
                Some(event_id),
            );
        }
    };
    let sequence = match object.get("sequence").and_then(serde_json::Value::as_u64) {
        Some(sequence) if sequence > 0 => sequence,
        _ => {
            return HttpOutcome::rejected(
                HostEventReject::new(400, DISPOSITION_INVALID_REQUEST, REASON_INVALID_ARGUMENT),
                Some(event_id),
            );
        }
    };
    let envelope = passive_envelope(introduction, event_id, sequence, body, object);
    let mut submission = base_submission(event_id, body, value);
    submission.sequence = sequence;
    submission.kind = HostEventKind::Passive(kind.to_owned());
    submission.delivery = HostEventDelivery::Observation;
    submission.envelope_json = envelope;
    let receipt = match ports.admission.admit(introduction, &submission) {
        Ok(receipt) => receipt,
        Err(error) => {
            if matches!(
                error.kind,
                HostEventAdmissionFailure::Backpressure | HostEventAdmissionFailure::Unavailable
            ) {
                let gap = HostEventGap {
                    gap_id: format!("{HOST_EVENTS_STREAM_ID}:{event_id}"),
                    stream_id: HOST_EVENTS_STREAM_ID.to_owned(),
                    event_id: event_id.to_owned(),
                    reason_ref: REASON_STORAGE_BACKPRESSURE.to_owned(),
                };
                let _ = ports.admission.report_gap(introduction, &gap);
            }
            return HttpOutcome::rejected(error.reject(), Some(event_id));
        }
    };
    let fields = base_response_fields(introduction, &receipt, event_id);
    HttpOutcome::ok(encode_host_event_response(&fields, credential))
}

/// Listener bind failure. A bind conflict refuses the route: the broker
/// must not issue an introduction when it cannot exclusively own the
/// pinned endpoint, so a squatting listener can never inherit traffic.
#[derive(Debug, Error)]
pub enum HostEventsBindError {
    /// Port zero was requested; the endpoint needs an explicit port.
    #[error("host-events listener requires an explicit non-zero port")]
    ZeroPort,
    /// The pre-bound socket is not a loopback socket.
    #[error("host-events listener requires a loopback socket")]
    NotLoopback,
    /// Underlying socket failure.
    #[error("host-events listener socket failure: {0}")]
    Socket(#[from] std::io::Error),
}

/// Listener shutdown cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostEventsShutdown {
    /// The stop signal fired.
    Stopped,
    /// The active bridge generation moved: rotation invalidated this
    /// listener before another request.
    Rotated,
}

/// One exclusively-owned loopback listener for `POST /v1/host-events`.
///
/// The listener serves exactly one path with `Connection: close` framing
/// and sequential bounded handling: no routing framework, no keep-alive
/// pipelining, no chunked framing, no upgrades. On Windows the socket is
/// exclusively owned (`SO_EXCLUSIVEADDRUSE` via `std`), so a competing
/// bind fails instead of hijacking the port.
pub struct HostEventsListener {
    listener: tokio::net::TcpListener,
    port: u16,
}

impl HostEventsListener {
    /// Binds `127.0.0.1` on the exact reserved port. A conflict errors so
    /// the owner refuses the route instead of sharing the endpoint.
    pub fn bind_loopback(port: u16) -> Result<Self, HostEventsBindError> {
        if port == 0 {
            return Err(HostEventsBindError::ZeroPort);
        }
        let socket = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
        Self::from_pre_bound(socket)
    }

    /// Adopts an owner-created, exclusively pre-bound socket. The socket
    /// must already be loopback with an explicit non-zero port; anything
    /// else is refused before serving a single byte.
    pub fn from_pre_bound(socket: std::net::TcpListener) -> Result<Self, HostEventsBindError> {
        let address = socket.local_addr()?;
        if !address.ip().is_loopback() {
            return Err(HostEventsBindError::NotLoopback);
        }
        let port = address.port();
        if port == 0 {
            return Err(HostEventsBindError::ZeroPort);
        }
        socket.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(socket)?;
        Ok(Self { listener, port })
    }

    /// Returns the bound explicit port the `Host` authority must name.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Serves until the stop signal fires or the active bridge generation
    /// moves. Connections are handled sequentially with per-connection
    /// timeouts: at most one admission is in flight, which matches the
    /// single-session narrow ingress without lock or queue machinery. The
    /// future is `Send` only when every port is; the `BridgeRunner`
    /// admission port is not, so that composition serves on a
    /// single-threaded runtime on the bridge thread.
    pub async fn serve_until<A, G, I, C>(
        &self,
        ports: &mut HostEventPorts<A, G, I, C>,
        bound_generation: u64,
        stop: tokio::sync::watch::Receiver<bool>,
        active_generation: tokio::sync::watch::Receiver<u64>,
    ) -> HostEventsShutdown
    where
        A: HostEventAdmission,
        G: ActionGate,
        I: IntroductionStore,
        C: CredentialResolver,
    {
        self.serve_inner(ports, bound_generation, stop, active_generation, None)
            .await
    }

    /// Serves only requests whose accepted socket was joined to a native
    /// process identity by `peer_observer`.
    pub async fn serve_until_with_peer_observer<A, G, I, C, O>(
        &self,
        ports: &mut HostEventPorts<A, G, I, C>,
        bound_generation: u64,
        stop: tokio::sync::watch::Receiver<bool>,
        active_generation: tokio::sync::watch::Receiver<u64>,
        peer_observer: &mut O,
    ) -> HostEventsShutdown
    where
        A: HostEventAdmission,
        G: ActionGate,
        I: IntroductionStore,
        C: CredentialResolver,
        O: HostEventPeerObserver,
    {
        self.serve_inner(
            ports,
            bound_generation,
            stop,
            active_generation,
            Some(peer_observer),
        )
        .await
    }

    async fn serve_inner<A, G, I, C>(
        &self,
        ports: &mut HostEventPorts<A, G, I, C>,
        bound_generation: u64,
        mut stop: tokio::sync::watch::Receiver<bool>,
        mut active_generation: tokio::sync::watch::Receiver<u64>,
        mut peer_observer: Option<&mut dyn HostEventPeerObserver>,
    ) -> HostEventsShutdown
    where
        A: HostEventAdmission,
        G: ActionGate,
        I: IntroductionStore,
        C: CredentialResolver,
    {
        loop {
            if *stop.borrow() {
                return HostEventsShutdown::Stopped;
            }
            if *active_generation.borrow() != bound_generation {
                return HostEventsShutdown::Rotated;
            }
            tokio::select! {
                changed = stop.changed() => {
                    match changed {
                        Ok(()) => {
                            if *stop.borrow() {
                                return HostEventsShutdown::Stopped;
                            }
                        }
                        Err(_) => return HostEventsShutdown::Stopped,
                    }
                }
                changed = active_generation.changed() => {
                    match changed {
                        Ok(()) => {
                            if *active_generation.borrow() != bound_generation {
                                return HostEventsShutdown::Rotated;
                            }
                        }
                        Err(_) => return HostEventsShutdown::Rotated,
                    }
                }
                accepted = self.listener.accept() => {
                    match accepted {
                        Ok((stream, _)) => {
                            let peer_identity = if let Some(observer) = peer_observer.as_deref_mut() {
                                let endpoints = stream.local_addr().ok().zip(stream.peer_addr().ok());
                                let Some((local, peer)) = endpoints else {
                                    continue;
                                };
                                // The accepted server socket sees its own
                                // endpoint as `local` and the connecting
                                // client's endpoint as `peer`.
                                match observer.observe(peer, local) {
                                    Ok(identity) => Some(identity),
                                    Err(HostEventPeerObservationError::Unavailable) => continue,
                                }
                            } else {
                                None
                            };
                            handle_connection(stream, self.port, peer_identity.as_ref(), ports).await;
                        }
                        Err(_) => {
                            tokio::task::yield_now().await;
                        }
                    }
                }
            }
        }
    }
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Internal Server Error",
    }
}

async fn write_outcome(writer: &mut tokio::net::tcp::OwnedWriteHalf, outcome: &HttpOutcome) {
    use tokio::io::AsyncWriteExt as _;
    let body = serde_json::to_vec(&outcome.body).unwrap_or_default();
    let status = outcome.status;
    let reason = status_reason(status);
    let length = body.len();
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
    );
    let _ = writer.write_all(head.as_bytes()).await;
    let _ = writer.write_all(&body).await;
    let _ = writer.flush().await;
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

async fn handle_connection<A, G, I, C>(
    stream: tokio::net::TcpStream,
    expected_port: u16,
    peer_identity: Option<&HostEventPeerProcessIdentity>,
    ports: &mut HostEventPorts<A, G, I, C>,
) where
    A: HostEventAdmission,
    G: ActionGate,
    I: IntroductionStore,
    C: CredentialResolver,
{
    use tokio::io::AsyncReadExt as _;
    let (mut reader, mut writer) = stream.into_split();
    let mut buffer = vec![0_u8; MAX_HOST_EVENT_HEAD_BYTES + 4];
    let mut filled = 0_usize;
    let head_end = loop {
        if filled >= buffer.len() {
            let outcome = HttpOutcome::rejected(
                HostEventReject::new(413, DISPOSITION_INVALID_REQUEST, REASON_INVALID_ARGUMENT),
                None,
            );
            write_outcome(&mut writer, &outcome).await;
            return;
        }
        let read =
            tokio::time::timeout(HOST_EVENTS_HEAD_TIMEOUT, reader.read(&mut buffer[filled..]))
                .await;
        let Ok(Ok(count)) = read else {
            return;
        };
        if count == 0 {
            return;
        }
        filled += count;
        if let Some(end) = find_head_end(&buffer[..filled]) {
            break end;
        }
        if filled > MAX_HOST_EVENT_HEAD_BYTES {
            let outcome = HttpOutcome::rejected(
                HostEventReject::new(413, DISPOSITION_INVALID_REQUEST, REASON_INVALID_ARGUMENT),
                None,
            );
            write_outcome(&mut writer, &outcome).await;
            return;
        }
    };
    let head = match parse_http_head(&buffer[..head_end], expected_port) {
        Ok(head) => head,
        Err(reject) => {
            write_outcome(&mut writer, &HttpOutcome::rejected(reject, None)).await;
            return;
        }
    };
    let mut body = vec![0_u8; head.content_length];
    let already = filled - head_end;
    if already > head.content_length {
        let outcome = HttpOutcome::rejected(
            HostEventReject::new(
                400,
                DISPOSITION_INVALID_REQUEST,
                REASON_PROTOCOL_INCOMPATIBLE,
            ),
            None,
        );
        write_outcome(&mut writer, &outcome).await;
        return;
    }
    body[..already].copy_from_slice(&buffer[head_end..filled]);
    let mut read_body = already;
    while read_body < head.content_length {
        let read = tokio::time::timeout(
            HOST_EVENTS_BODY_TIMEOUT,
            reader.read(&mut body[read_body..]),
        )
        .await;
        match read {
            Ok(Ok(count)) if count > 0 => read_body += count,
            _ => return,
        }
    }
    let outcome = match peer_identity {
        Some(peer) => handle_host_event_from_process(&head, &body, expected_port, peer, ports),
        None => handle_host_event(&head, &body, expected_port, ports),
    };
    write_outcome(&mut writer, &outcome).await;
}
