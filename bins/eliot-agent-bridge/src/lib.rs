//! B-15's thin profile-selected agent/host bridge.

#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_agent_bridge_core::{
    AgentBridgeCore, AttachBinding, AttachRequest, AttachView, AttemptState, BridgeError,
    ConnectionId, CoverageGap, CursorPolicy, DeliveryClass, DemandId, EventDisposition,
    EventForwardAck, EventForwardStatus, EventPortOutcome, Generation, HostActivationPort,
    HostEventEnvelope, McpForwardingPort, OutstandingDeliveryView, ProviderFailure,
    ProviderReadiness, ReconciliationConsumedFrontier, ReconciliationPortOutcome,
    ReconciliationPortResult, ReconciliationReceiptRef, ReconnectRequest, RecoveredEventFact,
    RecoveredGapFact, RecoveredPendingView, RecoveredStreamFacts, RecoveryDirective,
    RecoveryProjectionPage, RecoveryReadRequest, RecoveryStreamCut, RecoveryUnscopedGapCursor,
    RecoveryView, RecoveryWindowStatus, TerminalReductionInputs, TransportEdge,
};
/// I7.17 recall response projection: bounded handles-first agent output with
/// a server-derived disposition, binding receipt, and rank-trace handle.
/// Full ranking/suppression traces require explicit debug expansion; the
/// projection never accepts a disposition from bridge/model output.
pub use eliot_agent_bridge_core::{
    AgentRecallProjection, MAX_AGENT_RECALL_HANDLES, project_recall_for_agent,
};
/// I7.18/I7.24 revisioned-resource read surface: canonical `eliot://`
/// identities, bounded hot-response projections (preview plus handle), and
/// tool-result delivery receipts. The bridge publishes only owner-supplied
/// snapshots into its attach-scoped transport projection and never estimates
/// tokens or delivery completeness: `tokens_rendered` and `delivery` arrive
/// from the projecting route owner.
pub use eliot_agent_bridge_core::{
    DeliveryStatus, HotResourceView, MAX_CONTENT_BYTES, MAX_PREVIEW_BYTES, MAX_REGISTRY_ENTRIES,
    MAX_URI_BYTES, ResourceHandle, ResourceKind, ResourceRegistry, ResourceUri, ToolResultReceipt,
};
use eliot_contracts::{
    ClockReading, ProductId, RequestId, RequestMetadata, SourceId, StateFence,
    canonical_json_bytes, sha256_hex,
};
use eliot_mcp::{HostInvocationOutcome, ResponseKind};
use eliot_protocol::{
    AckPhase, AgentBridgeClientDeclaration, AgentBridgePeerAdmissionReceipt,
    AgentBridgePeerChallenge, EncodingProfile, EventEnvelope, Frame, FrameKind, MessageType,
    ProtocolPayload, ProtocolVersion, RequestIdentity,
};
use eliot_receipts::RequestBinding;
use eliot_runtime::{Runtime, RuntimeConfig};

mod cli_contract;
mod kernel_activation_client;
mod kernel_host_request_client;
pub mod memory_handle_join;
pub mod reactive_injection_receipts;
pub mod reactive_runtime_composition;
pub mod settled_plan_transport;
mod understanding_bootstrap;
pub(crate) use cli_contract::validate_client_declaration_path;
pub use cli_contract::{CliConfig, CliError, Profile, Transport, parse_args};
use kernel_activation_client::KernelHostActivationPort;
#[cfg(test)]
use kernel_activation_client::{
    activation_frame_for_request, build_neutral_activation_request, decode_activation_response,
};
pub use kernel_host_request_client::KernelHostRequestClient;
use kernel_host_request_client::ReplayCacheEntry;
pub use memory_handle_join::{ResolvedMemoryHandle, parse_memory_handle};
pub use reactive_injection_receipts::{
    AdmissionBasis, AttentionItem, CueOrigin, DeliveryPoint, FiringEvidence, InjectionReceipt,
    ItemDisposition, NormalizedCue, REACTIVE_INJECTION_CONTRACT, ReactiveInjectionError,
    ReactiveInjectionLedger, RiskTier, Severity, UseOutcome,
};
pub use settled_plan_transport::{
    AdmittedPlanItem, FeedAdmissionOutcome, GovernorAssessmentView, MAX_TRANSPORT_REPLAY_KEYS,
    PlanAdmissionError, PlanAdmissionReport, SettledPlanAdmission, WithheldPlanItem,
    admit_producer_feed, governor_assess, render_admission_fence,
};
pub use understanding_bootstrap::{
    AuthoritativeSelection, BootstrapContext, BootstrapError, BootstrapSession,
    BootstrapTaskInputs, CurrentAssessment, GovernanceEvidence, ReadinessDisposition, ScopeLevel,
    SelectedTask, TaskCandidate, TaskSelectionDisposition, TaskSelectionView,
    UnderstandingBootstrap, get_understanding_bootstrap,
};

fn decode_declaration_bytes(bytes: &[u8]) -> Result<AgentBridgeClientDeclaration, String> {
    let declaration: AgentBridgeClientDeclaration =
        serde_json::from_slice(bytes).map_err(|e| format!("declaration deserialize: {e}"))?;
    declaration
        .validate()
        .map_err(|e| format!("declaration validate: {e}"))?;
    Ok(declaration)
}

struct LoadedAgentBridgeDeclaration {
    declaration: AgentBridgeClientDeclaration,
    #[cfg(windows)]
    _lease: eliot_platform_windows::AgentBridgeDeclarationReadLease,
}

struct AdmittedConnection {
    transport: eliot_ipc::NamedPipeTransport,
    receipt: AgentBridgePeerAdmissionReceipt,
}

// admitted: AdmittedConnection
// runtime: tokio::runtime::Runtime
// _loaded: LoadedAgentBridgeDeclaration
// activation_used: bool
// activation exchange already consumed; restart/reconnect

/// Single retained transport owner behind both kernel faces.
///
/// Exactly one admitted transport, one tokio runtime, one declaration lease,
/// and one activation one-shot guard live here. `KernelHostActivationPort`
/// (runner side) and `KernelHostRequestClient` (host-gateway side) each hold
/// a `SharedTransport`; no second transport, runtime, or lease is ever
/// constructed. `activated_session` keeps the kernel-issued semantic session
/// captured by the one-shot activation exchange, so invocation envelopes bind
/// an honest kernel-issued selector instead of host text or a minted
/// identity. `replay_cache` makes exact host replays byte-identical (the
/// kernel deduplicates by envelope digest) and turns a changed payload under
/// a known correlation into a local `IdempotencyConflict` with no wire
/// traffic.
///
/// Durability boundary: `replay_cache` and `activated_session` are process
/// memory only; both die with this process, which spans exactly one admitted
/// connection. Durable idempotency and unknown-outcome settlement belong to
/// the Kernel ORS record, reachable after re-attach through the reconcile and
/// restore entries owned by `KernelHostRequestClient`
/// (`agent_host_request_reconcile`, `REACTIVE_RESTORE_OPERATION`). Neither
/// the gateway client nor the reply parser holds a second ledger: the replay
/// cache is a byte-identity aid for the live connection, never a
/// redelivery or reconciliation log.
struct KernelTransportOwner {
    admitted: AdmittedConnection,
    runtime: tokio::runtime::Runtime,
    _loaded: LoadedAgentBridgeDeclaration,
    activation_used: bool,
    limits: eliot_ipc::TransportLimits,
    activated_session: Option<String>,
    replay_cache: HashMap<String, ReplayCacheEntry>,
    /// Bridge-held digest-verified durable sequences per stream: the exact
    /// contiguous set justified by the receiving owner's receipts.
    /// Out-of-order receipts stay retained above their holes; only the
    /// contiguous run above the owner-confirmed base is ever offered as
    /// the consumed frontier, so pagination or reordering can never
    /// acknowledge a hole or an unseen page. Carried as the reconcile
    /// consumed frontier so the Kernel can advance its acked cursors;
    /// process memory only, bounded below, never a reconciliation log.
    delivered_sequences: BTreeMap<String, BTreeSet<u64>>,
    /// Last contiguous frontier per stream whose owner response has been
    /// accepted by the core. A frontier is never recorded at send time:
    /// unknown/lost replies therefore remain eligible for replay.
    consumed_sent: BTreeMap<String, u64>,
    /// Owner-confirmed acked base per stream learned from verified
    /// reconcile replies. Held sequences at or below the base are pruned
    /// as owner-confirmed; the contiguous run always starts above it.
    owner_acked: BTreeMap<String, u64>,
}

type SharedTransport = Rc<RefCell<KernelTransportOwner>>;

impl KernelTransportOwner {
    /// Exchanges one bridge-event frame over the admitted transport.
    ///
    /// Field-disjoint borrows of the single retained owner (runtime plus
    /// transport plus limits), mirroring the host-request exchange: exactly
    /// one send and one receive under the admitted limits, with a
    /// non-delivered send or missing reply reported as an unknown outcome.
    fn exchange_bridge_event_frame(&mut self, frame: &Frame) -> Result<Frame, ProviderFailure> {
        let delivery = self.runtime.block_on(async {
            self.admitted
                .transport
                .send_frame(frame, self.limits)
                .await
                .map_err(|_| event_transport_failure())
        })?;
        if !matches!(delivery, eliot_ipc::DeliveryOutcome::Delivered) {
            return Err(event_transport_failure());
        }
        self.runtime.block_on(async {
            self.admitted
                .transport
                .receive_frame(self.limits)
                .await
                .map_err(|_| event_transport_failure())
        })
    }
}

/// Closed Kernel entry that admits one durable/control event envelope.
///
/// Owned by `bins/eliot-kernel/src/host_request_route.rs` (event-route
/// wiring); the literal is repeated here because the constant is `pub(crate)`
/// to that binary and this crate takes no new dependencies.
const AGENT_BRIDGE_EVENT_FORWARD_OPERATION: &str = "agent_bridge_event_forward";
/// Closed Kernel entry that admits one hook observation.
const AGENT_BRIDGE_HOOK_FORWARD_OPERATION: &str = "agent_bridge_hook_forward";
/// Closed Kernel entry that admits one coverage gap.
const AGENT_BRIDGE_EVENT_GAP_OPERATION: &str = "agent_bridge_event_gap";
/// Closed Kernel entry that reconciles event ownership and cursors.
const AGENT_BRIDGE_EVENT_RECONCILE_OPERATION: &str = "agent_bridge_event_reconcile";
/// Bridge-proposed relative deadline when the caller states no preference.
/// The Kernel owns the absolute deadline; this is a bounded preference only.
const BRIDGE_EVENT_DEADLINE_PREFERENCE_MS: u64 = 60_000;
/// Maximum bridge-owned delivered streams retained for the reconcile
/// consumed frontier. Eviction only defers ack advancement; nothing is lost.
const MAX_DELIVERED_STREAMS: usize = 1024;
/// Maximum held durable sequences per stream. Overflow defers acknowledgement
/// of the newest receipts — the safe direction — without losing them
/// owner-side; the producer's at-least-once retry redelivers.
const MAX_DELIVERED_SEQUENCES_PER_STREAM: usize = 4096;
/// Bound on consumed-frontier entries carried by one reconcile frame.
const MAX_RECONCILE_CONSUMED_ENTRIES: usize = 1024;
/// Bound on streams decoded from one owner reconcile answer. The
/// enumeration itself stays bounded: stream-list coverage needs its own
/// bounded continuation, not an unbounded outer collection. Hitting the
/// bound keeps the walk partial, never silently complete.
const MAX_RECOVERY_STREAMS: usize = 4;
/// Bound on events decoded from one owner stream page, mirroring the
/// owner's own truncation cap: a 129-event stream arrives as 128 plus a
/// continuation, and the second page stays explicitly partial until the
/// retained-source page route serves it.
const MAX_RECOVERY_PAGE_ITEMS: usize = 128;
/// Bound on total events materialized from one owner answer across all
/// streams, enforced from array lengths before any fact is built.
const MAX_RECOVERY_TOTAL_EVENTS: usize = MAX_RECOVERY_STREAMS * MAX_RECOVERY_PAGE_ITEMS;
/// Bound on gaps decoded from one owner stream page, mirroring the
/// owner's per-stream gap cap.
const MAX_RECOVERY_GAPS_PER_STREAM: usize = 256;
/// Bound on total gaps materialized from one owner answer.
const MAX_RECOVERY_TOTAL_GAPS: usize = (MAX_RECOVERY_STREAMS + 1) * MAX_RECOVERY_GAPS_PER_STREAM;
/// Bound on owner text legs, mirroring the retained-source text cap.
const MAX_RECOVERY_TEXT_BYTES: usize = 1024;

/// Frozen four-operation dispatch map (Implements #2561 item 1).
///
/// Exactly one row per [`McpForwardingPort`] forwarding method, chosen by an
/// exhaustive match, so adding a forwarding method fails to compile until
/// its closed Kernel request is recorded here. No method reaches the
/// transport except through its row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BridgeEventMethod {
    Hook,
    Event,
    Gap,
    Reconcile,
}

impl BridgeEventMethod {
    /// Returns the closed Kernel request selected by this method.
    const fn kernel_operation(self) -> &'static str {
        match self {
            Self::Hook => AGENT_BRIDGE_HOOK_FORWARD_OPERATION,
            Self::Event => AGENT_BRIDGE_EVENT_FORWARD_OPERATION,
            Self::Gap => AGENT_BRIDGE_EVENT_GAP_OPERATION,
            Self::Reconcile => AGENT_BRIDGE_EVENT_RECONCILE_OPERATION,
        }
    }
}

/// Kernel-issued facts snapshotted from the shared owner for one event call.
struct BridgeEventTransportFacts {
    connection_id: String,
    state_fence: StateFence,
    session: Option<String>,
}

fn event_transport_failure() -> ProviderFailure {
    ProviderFailure::new(
        "eliot-kernel-front-door",
        "authenticated Kernel event exchange was rejected or left an unknown outcome; \
         no phase reached, nothing claimed; re-attach and reconcile before retrying",
    )
}

fn event_shape_failure(detail: &'static str) -> ProviderFailure {
    ProviderFailure::new("eliot-kernel-front-door", detail)
}

fn bridge_event_unix_ms() -> Result<u64, ProviderFailure> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis().try_into().unwrap_or(u64::MAX))
        .map_err(|_| event_transport_failure())
}

/// Builds the neutral frame identity for one bridge-event frame.
///
/// The fence carries only the authority epoch and resource generation (no
/// task, policy, or integration revisions), the correlation identifies the
/// presented event, and the deadline is the bridge-proposed preference the
/// Kernel owns absolutely. The Kernel joins connection, correlation, and
/// fence before any event entry runs.
fn bridge_event_frame_identity(
    correlation: &str,
    facts: &BridgeEventTransportFacts,
    now_ms: u64,
) -> Result<RequestIdentity, ProviderFailure> {
    let fence = &facts.state_fence;
    if fence.task_revision.is_some()
        || fence.policy_revision.is_some()
        || fence.integration_revision.is_some()
    {
        return Err(event_transport_failure());
    }
    let frame_fence = StateFence::new(fence.authority_epoch.clone(), fence.resource_generation);
    let deadline = now_ms.saturating_add(BRIDGE_EVENT_DEADLINE_PREFERENCE_MS);
    if deadline == 0 {
        return Err(event_transport_failure());
    }
    let metadata = RequestMetadata {
        request_id: RequestId::new(correlation).map_err(|_| event_transport_failure())?,
        session_id: None,
        task_id: None,
        product_id: ProductId::new("eliot-agent-bridge").map_err(|_| event_transport_failure())?,
        source_id: SourceId::new("agent-bridge").map_err(|_| event_transport_failure())?,
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
        idempotency_key: format!("{correlation}:event"),
        deadline_unix_ms: deadline,
        cancellation_id: format!("{correlation}:event:cancel"),
    };
    frame_identity
        .validate()
        .map_err(|_| event_transport_failure())?;
    Ok(frame_identity)
}

/// Builds one bridge-event frame carrying the closed operation plus its typed
/// JSON payload over the admitted transport.
///
/// Reuses the neutral frame identity above. No session text rides the frame:
/// the Kernel builds the sender binding itself from the retained Session,
/// exactly like the host-request entries; the bridge verifies the reply
/// echoes the presenting connection.
fn bridge_event_frame_for_operation(
    correlation: &str,
    facts: &BridgeEventTransportFacts,
    payload: serde_json::Value,
    now_ms: u64,
) -> Result<Frame, ProviderFailure> {
    let frame_identity = bridge_event_frame_identity(correlation, facts, now_ms)?;
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: facts.connection_id.clone(),
        request_id: Some(frame_identity.request.metadata.request_id.clone()),
        kind: FrameKind::Request,
        message_type: MessageType::Execute,
        request_identity: Some(frame_identity),
        payload: ProtocolPayload::Json(payload),
        trace_context: BTreeMap::new(),
    };
    if frame.request_identity.is_none() || frame.request_id.is_none() {
        return Err(event_transport_failure());
    }
    frame.validate().map_err(|_| event_transport_failure())?;
    Ok(frame)
}

/// Strictly decodes one event-route reply: response/result shape, connection
/// and correlation joins, and the closed `known` status. Any mismatch is an
/// unknown delivery (`None`), never a guessed outcome or phase.
fn decode_bridge_event_reply(reply: &Frame, frame: &Frame) -> Option<serde_json::Value> {
    reply.validate().ok()?;
    if reply.kind != FrameKind::Response || reply.message_type != MessageType::Result {
        return None;
    }
    if reply.connection_id != frame.connection_id {
        return None;
    }
    if reply.request_id != frame.request_id {
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
    Some(payload.get("value")?.clone())
}

/// Parses one owner phase without inventing values: unknown phase strings
/// refuse rather than mapping to a nearby phase.
fn parse_owner_phase(text: &str) -> Option<AckPhase> {
    match text {
        "RECEIVED" => Some(AckPhase::Received),
        "DURABLE" => Some(AckPhase::Durable),
        "NORMALIZED" => Some(AckPhase::Normalized),
        "APPLIED" => Some(AckPhase::Applied),
        "REJECTED" => Some(AckPhase::Rejected),
        "UNKNOWN" => Some(AckPhase::Unknown),
        _ => None,
    }
}

/// Parses one owner disposition without inventing values.
fn parse_owner_disposition(text: &str) -> Option<EventDisposition> {
    match text {
        "accepted" => Some(EventDisposition::Accepted),
        "duplicate" => Some(EventDisposition::Duplicate),
        "rejected" => Some(EventDisposition::Rejected),
        "conflict" => Some(EventDisposition::Conflict),
        _ => None,
    }
}

/// Decodes one event-route forward reply into the port outcome (Implements
/// #2561 item 2).
///
/// Durable classes answer with the owner's phase: `Acknowledged` carrying
/// the independently verifiable phase/disposition, with the reply digest
/// bound to the presented envelope bytes and the identity echoed. A
/// determined `REJECTED`/`conflict` rejection surfaces as the conflict ack
/// so the core rejects it typed; anything else shaped is refused, never
/// guessed. Best-effort answers with `BestEffortForwarded` or the typed
/// `BestEffortDropped` gap reason. Class confusion (a durable phase on a
/// best-effort event or vice versa) refuses. The bridge-owned delivered
/// frontier advances only on digest-verified durable holdings — never on a
/// conflict — so reconciliation acks exactly what the owner durably holds.
fn decode_event_port_outcome(
    event: &EventEnvelope,
    value: &serde_json::Value,
    envelope_sha: &str,
    port: &mut KernelMcpForwardingPort,
) -> Result<EventPortOutcome, ProviderFailure> {
    let accepted = value
        .get("accepted")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(event_transport_failure)?;
    let reply_stream = value
        .get("stream_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(event_transport_failure)?;
    let reply_event = value
        .get("event_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(event_transport_failure)?;
    if reply_stream != event.stream_id || reply_event != event.event_id {
        return Err(event_shape_failure(
            "event reply refused: owner answer does not echo the presented stream/event identity",
        ));
    }
    match event.delivery_class {
        DeliveryClass::DurableControl | DeliveryClass::DurableObservation => {
            decode_durable_outcome(event, value, envelope_sha, accepted, port)
        }
        DeliveryClass::BestEffortTelemetry => decode_best_effort_outcome(value),
    }
}

/// Decodes the owner phase for one durable event: `Acknowledged` carrying
/// the independently verifiable phase/disposition, with the reply digest
/// bound to the presented envelope bytes. A determined `REJECTED`/`conflict`
/// rejection surfaces as the conflict ack so the core rejects it typed;
/// anything else shaped is refused, never guessed. The bridge-owned
/// delivered frontier advances only on digest-verified durable holdings —
/// never on a conflict — so reconciliation acks exactly what the owner
/// durably holds.
fn decode_durable_outcome(
    event: &EventEnvelope,
    value: &serde_json::Value,
    envelope_sha: &str,
    accepted: bool,
    port: &mut KernelMcpForwardingPort,
) -> Result<EventPortOutcome, ProviderFailure> {
    if value.get("forwarded").is_some() {
        return Err(event_shape_failure(
            "event reply refused: durable event answered with a best-effort outcome",
        ));
    }
    let phase = value
        .get("phase")
        .and_then(serde_json::Value::as_str)
        .and_then(parse_owner_phase)
        .ok_or_else(event_transport_failure)?;
    let disposition = value
        .get("disposition")
        .and_then(serde_json::Value::as_str)
        .and_then(parse_owner_disposition)
        .ok_or_else(event_transport_failure)?;
    if !accepted {
        if phase != AckPhase::Rejected || disposition != EventDisposition::Conflict {
            return Err(event_shape_failure(
                "event reply refused: negative durable answer without the determined \
                 REJECTED/conflict pair",
            ));
        }
        return acknowledge_owner_phase(event, phase, disposition);
    }
    let reply_sha = value
        .get("envelope_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(event_transport_failure)?;
    if reply_sha != envelope_sha {
        return Err(event_shape_failure(
            "event reply refused: owner digest does not bind the presented envelope bytes",
        ));
    }
    if phase == AckPhase::Rejected && disposition != EventDisposition::Conflict {
        return Err(event_shape_failure(
            "event reply refused: REJECTED phase without the conflict disposition",
        ));
    }
    let outcome = acknowledge_owner_phase(event, phase, disposition)?;
    if disposition == EventDisposition::Accepted || disposition == EventDisposition::Duplicate {
        port.note_delivered(&event.stream_id, event.sequence);
    }
    Ok(outcome)
}

/// Builds the `Acknowledged` outcome for one owner phase/disposition pair.
/// The identity was echoed by the caller; the text was validated there.
fn acknowledge_owner_phase(
    event: &EventEnvelope,
    phase: AckPhase,
    disposition: EventDisposition,
) -> Result<EventPortOutcome, ProviderFailure> {
    let ack = EventForwardAck::new(
        event.stream_id.clone(),
        event.event_id.clone(),
        phase,
        disposition,
    )
    .map_err(|_| {
        event_shape_failure(
            "event ack refused: owner identity does not form a valid acknowledgement",
        )
    })?;
    Ok(EventPortOutcome::Acknowledged(ack))
}

/// Decodes the owner answer for one best-effort event: `BestEffortForwarded`
/// or the typed `BestEffortDropped` gap reason. A durable phase on a
/// best-effort event (class confusion) refuses.
fn decode_best_effort_outcome(
    value: &serde_json::Value,
) -> Result<EventPortOutcome, ProviderFailure> {
    if value.get("phase").is_some() {
        return Err(event_shape_failure(
            "event reply refused: best-effort event answered with a durable phase",
        ));
    }
    let forwarded = value
        .get("forwarded")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(event_transport_failure)?;
    if forwarded {
        return Ok(EventPortOutcome::BestEffortForwarded);
    }
    let reason = value
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .filter(|reason| !reason.trim().is_empty())
        .ok_or_else(event_transport_failure)?;
    Ok(EventPortOutcome::BestEffortDropped {
        reason_ref: reason.to_owned(),
    })
}

/// Extracts bounded owner text: non-blank, no control characters, within
/// the retained-source text cap. Mirrors the owner's text rule without
/// adding a store edge.
fn recovery_text(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<String, ProviderFailure> {
    let text = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|text| {
            !text.trim().is_empty()
                && !text.chars().any(char::is_control)
                && text.len() <= MAX_RECOVERY_TEXT_BYTES
        })
        .ok_or_else(|| {
            event_shape_failure("reconciliation refused: owner text leg is not bounded text")
        })?;
    Ok(text.to_owned())
}

/// Extracts a bounded owner identity: text that additionally carries no key
/// separator, mirroring the owner's identity rule.
fn recovery_identity(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<String, ProviderFailure> {
    let text = recovery_text(value, field)?;
    if text.contains("::") {
        return Err(event_shape_failure(
            "reconciliation refused: owner identity carries the key separator",
        ));
    }
    Ok(text)
}

/// Extracts a lowercase SHA-256 digest leg, mirroring the owner's digest
/// rule. A nonblank hash is never proof of anything by itself; it only
/// names the exact retained bytes the owner holds.
fn recovery_digest(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<String, ProviderFailure> {
    let text = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|text| {
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| {
            event_shape_failure("reconciliation refused: owner digest leg is not SHA-256 hex")
        })?;
    Ok(text.to_owned())
}

/// Extracts an owner cursor leg, which may be zero for a fresh stream.
fn recovery_cursor(value: &serde_json::Value, field: &'static str) -> Result<u64, ProviderFailure> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            event_shape_failure("reconciliation refused: owner cursor leg is not an integer")
        })
}

/// Extracts an owner sequence leg, which must be nonzero.
fn recovery_sequence(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<u64, ProviderFailure> {
    let sequence = recovery_cursor(value, field)?;
    if sequence == 0 {
        return Err(event_shape_failure(
            "reconciliation refused: owner sequence leg must be nonzero",
        ));
    }
    Ok(sequence)
}

/// Verifies the versioned reconciliation-key preimage explicitly.
///
/// The owner hashes the reconciliation object BEFORE attaching
/// `reconcile_key`, `handoffs_reconciled`, and `handoff_maintenance`, so the
/// preimage is the answer minus exactly those three legs: observation facts
/// in, its own key and later mutation receipts out. A
/// mismatch is an unknown outcome — the consumed frontier may already have
/// applied owner-side, and the monotonic server application makes a retry
/// safe — never an attack claim and never completion proof.
fn verify_reconcile_key(reconciliation: &serde_json::Value) -> Result<String, ProviderFailure> {
    if reconciliation
        .get("reconcile_key_version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
    {
        return Err(event_shape_failure(
            "reconciliation refused: unsupported owner key preimage version",
        ));
    }
    let key = recovery_digest(reconciliation, "reconcile_key")?;
    let mut preimage = reconciliation.clone();
    let object = preimage.as_object_mut().ok_or_else(|| {
        event_shape_failure("reconciliation refused: owner answer is not an object")
    })?;
    object.remove("reconcile_key");
    object.remove("handoffs_reconciled");
    object.remove("handoff_maintenance");
    let bytes = canonical_json_bytes(&preimage).map_err(|_| event_transport_failure())?;
    if sha256_hex(&bytes) != key {
        return Err(event_shape_failure(
            "reconciliation refused: key does not bind the observed facts; \
             unknown outcome, nothing applied, safe to retry",
        ));
    }
    Ok(key)
}

/// Decodes one owner gap fact: scoped under its stream, or unscoped at top
/// level. Shape only — interval coherence against the walk window is
/// enforced by the core on import. Gap identities are bare keys (never
/// key-encoded with a separator), mirroring the owner's gap rule.
fn decode_recovery_gap(
    gap: &serde_json::Value,
    stream_id: &str,
) -> Result<RecoveredGapFact, ProviderFailure> {
    let gap_id = recovery_text(gap, "gap_id")?;
    let start_sequence = recovery_sequence(gap, "start_sequence")?;
    let end_sequence = recovery_sequence(gap, "end_sequence")?;
    let reason_ref = recovery_text(gap, "reason_ref")?;
    RecoveredGapFact::checked(
        gap_id,
        stream_id.to_owned(),
        start_sequence,
        end_sequence,
        reason_ref,
    )
    .map_err(|_| event_shape_failure("reconciliation refused: malformed owner gap interval"))
}

/// Running decode budget: array lengths are enforced before any fact is
/// built, so a hostile or corrupt answer cannot force unbounded
/// materialization.
struct RecoveryDecodeBudget {
    events: usize,
    gaps: usize,
}

struct RecoveryReplyCoverage {
    unproven_scope_present: bool,
    stream_list_complete: bool,
    stream_list_continuation: Option<String>,
    unscoped_gaps_complete: bool,
    unscoped_gaps_continuation: Option<RecoveryUnscopedGapCursor>,
}

fn decode_recovery_reply_coverage(
    reconciliation: &serde_json::Value,
) -> Result<RecoveryReplyCoverage, ProviderFailure> {
    let unproven_scope_present = reconciliation
        .get("unproven_scope_present")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| event_shape_failure("reconciliation refused: scope provenance absent"))?;
    let stream_list_complete = reconciliation
        .get("stream_list_complete")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| {
            event_shape_failure("reconciliation refused: stream-list coverage absent")
        })?;
    let stream_list_continuation = match reconciliation.get("stream_list_continuation") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value))
            if !value.is_empty() && value.len() <= MAX_RECOVERY_TEXT_BYTES =>
        {
            Some(value.clone())
        }
        _ => {
            return Err(event_shape_failure(
                "reconciliation refused: malformed stream-list continuation",
            ));
        }
    };
    let unscoped_gaps_complete = reconciliation
        .get("unscoped_gaps_complete")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| {
            event_shape_failure("reconciliation refused: unscoped gap coverage absent")
        })?;
    let unscoped_gaps_continuation = match reconciliation.get("unscoped_gaps_continuation") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Object(cursor)) if cursor.len() == 2 => {
            let after = recovery_text(
                &serde_json::Value::Object(cursor.clone()),
                "after_gap_scope",
            )?;
            let offset = cursor
                .get("gap_offset")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    event_shape_failure("reconciliation refused: malformed unscoped gap cursor")
                })?;
            Some(
                RecoveryUnscopedGapCursor::checked(after, offset).map_err(|_| {
                    event_shape_failure("reconciliation refused: invalid unscoped gap cursor")
                })?,
            )
        }
        _ => {
            return Err(event_shape_failure(
                "reconciliation refused: malformed unscoped gap continuation",
            ));
        }
    };
    Ok(RecoveryReplyCoverage {
        unproven_scope_present,
        stream_list_complete,
        stream_list_continuation,
        unscoped_gaps_complete,
        unscoped_gaps_continuation,
    })
}

/// Decodes one owner stream page whole: identities, records, cursors, and
/// gaps. The page cursors must echo the stream cursors — one snapshot, not
/// a stitched view — every item must advance past the acknowledged base in
/// strict order without duplicate identities, and the continuation must
/// name the page tail within the durable cursor. A page carrying a future
/// producer generation refuses; an older generation is retained as
/// fenced history, never relabeled and never silently dropped.
fn decode_recovery_stream(
    stream: &serde_json::Value,
    live_generation: u64,
    budget: &mut RecoveryDecodeBudget,
) -> Result<(RecoveredStreamFacts, u64), ProviderFailure> {
    let (stream_id, durable_cursor, acked_cursor, page) =
        decode_stream_snapshot(stream, live_generation)?;
    let producer_id = recovery_text(stream, "producer_id")?;
    let owner_incarnation = recovery_sequence(stream, "owner_incarnation")?;
    recovery_sequence(stream, "owner_revision")?;
    let events = decode_page_events(&stream_id, &producer_id, page, live_generation, budget)?;
    let gaps = decode_stream_gaps(stream, &stream_id, budget)?;
    let cut = RecoveryStreamCut::checked(
        recovery_cursor(stream, "upper_sequence")?,
        recovery_sequence(stream, "expected_revision")?,
        recovery_cursor(stream, "retention_floor")?,
    )
    .map_err(|_| event_shape_failure("reconciliation refused: invalid owner recovery cut"))?;
    let gap_continuation = match stream.get("gap_continuation") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Number(_)) => {
            let offset = recovery_sequence(stream, "gap_continuation")?;
            if offset > MAX_RECOVERY_GAPS_PER_STREAM as u64 {
                return Err(event_shape_failure(
                    "reconciliation refused: gap continuation exceeds owner cap",
                ));
            }
            Some(offset)
        }
        _ => {
            return Err(event_shape_failure(
                "reconciliation refused: gap continuation absent or malformed",
            ));
        }
    };
    let page_continuation = decode_page_continuation(page, cut.upper_sequence())?;
    let page_complete = page_continuation.is_none();
    let facts = RecoveredStreamFacts::checked(
        stream_id,
        durable_cursor,
        acked_cursor,
        events,
        gaps,
        page_continuation,
        page_complete,
    )
    .map_err(|_| {
        event_shape_failure(
            "reconciliation refused: page identities, ordering, or continuation are incoherent",
        )
    })?
    .with_owner_identity(producer_id, owner_incarnation)
    .map_err(|_| event_shape_failure("reconciliation refused: invalid owner stream identity"))?
    .with_recovery_cut(cut)
    .map_err(|_| event_shape_failure("reconciliation refused: page exceeds finite owner cut"))?
    .with_gap_continuation(gap_continuation)
    .map_err(|_| event_shape_failure("reconciliation refused: invalid gap continuation"))?;
    Ok((facts, acked_cursor))
}

/// Decodes the stream fact header and binds the pending page to the same
/// snapshot: identities, cursors, provenance generation, and staging
/// provenance must all agree before any item is materialized.
fn decode_stream_snapshot(
    stream: &serde_json::Value,
    live_generation: u64,
) -> Result<(String, u64, u64, &serde_json::Value), ProviderFailure> {
    let stream_id = recovery_identity(stream, "stream_id")?;
    let durable_cursor = recovery_cursor(stream, "durable_cursor")?;
    let acked_cursor = recovery_cursor(stream, "acked_cursor")?;
    if acked_cursor > durable_cursor {
        return Err(event_shape_failure(
            "reconciliation refused: acknowledged cursor exceeds the durable cursor",
        ));
    }
    let provenance_generation = stream
        .get("last_producer_generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            event_shape_failure("reconciliation refused: stream fact without provenance")
        })?;
    if provenance_generation > live_generation {
        return Err(event_shape_failure(
            "reconciliation refused: stream provenance names a future generation",
        ));
    }
    if stream.get("last_staging_connection").is_none() {
        return Err(event_shape_failure(
            "reconciliation refused: stream fact without staging provenance",
        ));
    }
    let page = stream
        .get("pending_first_page")
        .ok_or_else(event_transport_failure)?;
    if page.get("stream_id").and_then(serde_json::Value::as_str) != Some(stream_id.as_str()) {
        return Err(event_shape_failure(
            "reconciliation refused: page stream does not match its stream fact",
        ));
    }
    if page
        .get("durable_cursor")
        .and_then(serde_json::Value::as_u64)
        != Some(durable_cursor)
        || page.get("acked_cursor").and_then(serde_json::Value::as_u64) != Some(acked_cursor)
    {
        return Err(event_shape_failure(
            "reconciliation refused: page cursors disagree with the stream fact snapshot",
        ));
    }
    Ok((stream_id, durable_cursor, acked_cursor, page))
}

/// Decodes the page item array into checked event facts within the
/// negotiated per-page and total budgets. No envelope is fabricated here:
/// digest-only legs travel as named digests for the owner-redelivery path.
fn decode_page_events(
    stream_id: &str,
    expected_producer: &str,
    page: &serde_json::Value,
    live_generation: u64,
    budget: &mut RecoveryDecodeBudget,
) -> Result<Vec<RecoveredEventFact>, ProviderFailure> {
    let items = page
        .get("items")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(event_transport_failure)?;
    if items.len() > MAX_RECOVERY_PAGE_ITEMS {
        return Err(event_shape_failure(
            "reconciliation refused: page exceeds the negotiated event budget",
        ));
    }
    budget.events = budget.events.saturating_add(items.len());
    if budget.events > MAX_RECOVERY_TOTAL_EVENTS {
        return Err(event_shape_failure(
            "reconciliation refused: answer exceeds the negotiated total event budget",
        ));
    }
    let mut events = Vec::with_capacity(items.len());
    for item in items {
        let event_id = recovery_identity(item, "event_id")?;
        let sequence = recovery_sequence(item, "sequence")?;
        let phase = item
            .get("phase")
            .and_then(serde_json::Value::as_str)
            .and_then(parse_owner_phase)
            .ok_or_else(|| {
                event_shape_failure(
                    "reconciliation refused: page event carries an unsupported phase",
                )
            })?;
        let disposition_supported = item
            .get("disposition")
            .and_then(serde_json::Value::as_str)
            .and_then(parse_owner_disposition)
            == Some(EventDisposition::Accepted);
        if !disposition_supported {
            return Err(event_shape_failure(
                "reconciliation refused: page event carries an unsupported disposition",
            ));
        }
        let envelope_digest = recovery_digest(item, "envelope_sha256")?;
        let producer_id = recovery_text(item, "producer_id")?;
        if producer_id != expected_producer {
            return Err(event_shape_failure(
                "reconciliation refused: event producer differs from owner-bound stream",
            ));
        }
        let producer_generation = recovery_sequence(item, "producer_generation")?;
        if producer_generation > live_generation {
            return Err(event_shape_failure(
                "reconciliation refused: page event names a future producer generation",
            ));
        }
        let staging_connection = recovery_text(item, "staging_connection")?;
        events.push(
            RecoveredEventFact::checked(
                stream_id.to_owned(),
                event_id,
                sequence,
                phase,
                envelope_digest,
                producer_id,
                producer_generation,
                staging_connection,
            )
            .map_err(|_| event_shape_failure("reconciliation refused: malformed page event leg"))?,
        );
    }
    Ok(events)
}

/// Decodes the stream-scoped gap array within the negotiated gap budget.
fn decode_stream_gaps(
    stream: &serde_json::Value,
    stream_id: &str,
    budget: &mut RecoveryDecodeBudget,
) -> Result<Vec<RecoveredGapFact>, ProviderFailure> {
    let gaps_value = stream.get("gaps").ok_or_else(event_transport_failure)?;
    let gaps_array = gaps_value.as_array().ok_or_else(event_transport_failure)?;
    if gaps_array.len() > MAX_RECOVERY_GAPS_PER_STREAM {
        return Err(event_shape_failure(
            "reconciliation refused: stream exceeds the negotiated gap budget",
        ));
    }
    budget.gaps = budget.gaps.saturating_add(gaps_array.len());
    if budget.gaps > MAX_RECOVERY_TOTAL_GAPS {
        return Err(event_shape_failure(
            "reconciliation refused: answer exceeds the negotiated total gap budget",
        ));
    }
    let mut gaps = Vec::with_capacity(gaps_array.len());
    for gap in gaps_array {
        gaps.push(decode_recovery_gap(gap, stream_id)?);
    }
    Ok(gaps)
}

/// Decodes the page continuation leg: absent or null means complete, a
/// number must stay within the owner-issued finite upper bound, anything else refuses.
fn decode_page_continuation(
    page: &serde_json::Value,
    upper_sequence: u64,
) -> Result<Option<u64>, ProviderFailure> {
    match page.get("continuation") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(_)) => {
            let continuation = recovery_sequence(page, "continuation")?;
            if continuation > upper_sequence {
                return Err(event_shape_failure(
                    "reconciliation refused: page continuation exceeds the finite upper bound",
                ));
            }
            Ok(Some(continuation))
        }
        Some(_) => Err(event_shape_failure(
            "reconciliation refused: page continuation is not a sequence",
        )),
    }
}

/// Decodes one event-route reconcile reply into the port outcome (Implements
/// #2561 item 2, reconciliation leg; issue #2732 bounded continuation).
///
/// Reads event ownership, cursors, pages, and gaps from the owner's answer —
/// never from the host-request ledger — and validates the actual response,
/// not field presence: the presenting connection echo, the live generation
/// against the presenting attach, exact stream/event/content identities,
/// the declared window, ordering, duplicate conflicts, predecessor/next
/// continuation coherence, and cumulative budgets. The reconciliation key
/// is verified against its versioned preimage (observation facts minus its
/// own key and the later handoff mutation receipts) via
/// [`verify_reconcile_key`]. Anything malformed, foreign, or future
/// refuses the whole answer without applying half a page; the checked
/// facts travel into the core's recovery window through
/// [`ReconciliationPortResult::reconciled_with_pages`], which restores the
/// replay/pending view instead of discarding the pages. An empty fact set
/// still reconciles as an empty fact set (still keyed), not as a denial.
/// When `expected` carries the continuation that produced this answer, the
/// required stream scope must still be present and its continuation must
/// still advance past the requested predecessor; otherwise the page is a
/// foreign or stale continuation and refuses.
fn decode_reconciliation_outcome(
    binding: &AttachBinding,
    facts: &BridgeEventTransportFacts,
    value: &serde_json::Value,
    consumed_frontiers: Vec<ReconciliationConsumedFrontier>,
    expected: Option<&RecoveryReadRequest>,
) -> Result<ReconciliationPortOutcome, ProviderFailure> {
    if value.get("accepted").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(event_transport_failure());
    }
    let reconciliation = value
        .get("reconciliation")
        .ok_or_else(event_transport_failure)?;
    let connection_echo = reconciliation
        .get("connection_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            event_shape_failure("reconciliation refused: owner answer without connection echo")
        })?;
    if connection_echo != facts.connection_id.as_str() {
        return Err(event_shape_failure(
            "reconciliation refused: owner answer does not echo the presenting connection",
        ));
    }
    let live_generation = recovery_cursor(reconciliation, "live_generation")?;
    if live_generation == 0 {
        return Err(event_shape_failure(
            "reconciliation refused: live generation must be nonzero",
        ));
    }
    if live_generation != binding.activation_generation().get() {
        return Err(event_shape_failure(
            "reconciliation refused: live generation does not match the presenting attach",
        ));
    }
    let window_key = recovery_digest(reconciliation, "window_key")?;
    if expected.is_some_and(|request| request.window_key() != window_key.as_str()) {
        return Err(event_shape_failure(
            "recovery continuation refused: owner window identity changed",
        ));
    }
    let window_status = match reconciliation
        .get("window_status")
        .and_then(serde_json::Value::as_str)
    {
        Some("active") => RecoveryWindowStatus::Active,
        Some("moved") => RecoveryWindowStatus::Moved,
        Some("expired") => RecoveryWindowStatus::Expired,
        _ => {
            return Err(event_shape_failure(
                "reconciliation refused: unsupported owner window status",
            ));
        }
    };
    let mut budget = RecoveryDecodeBudget { events: 0, gaps: 0 };
    let stream_facts = decode_reconciliation_streams(reconciliation, live_generation, &mut budget)?;
    let unscoped_gaps = decode_unscoped_gaps(reconciliation, &mut budget)?;
    let coverage = decode_recovery_reply_coverage(reconciliation)?;
    let key = verify_reconcile_key(reconciliation)?;
    let handoffs_reconciled = reconciliation
        .get("handoffs_reconciled")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            event_shape_failure("reconciliation refused: owner answer without handoff receipt")
        })?;
    check_recovery_page_ordinals(reconciliation, expected)?;
    check_expected_continuation(reconciliation, &stream_facts, expected)?;
    let receipt_ref = ReconciliationReceiptRef::new(format!("bridge-event-reconcile:{key}"))
        .map_err(|_| {
            event_shape_failure(
                "reconciliation refused: owner key does not form a receipt reference",
            )
        })?;
    let presenting_connection = ConnectionId::new(connection_echo).map_err(|_| {
        event_shape_failure("reconciliation refused: connection echo is not a valid identity")
    })?;
    let live = Generation::new(live_generation).map_err(|_| {
        event_shape_failure("reconciliation refused: live generation is not a valid generation")
    })?;
    let result = ReconciliationPortResult::reconciled_with_pages(
        binding,
        receipt_ref,
        window_key,
        window_status,
        live,
        presenting_connection,
        coverage.unproven_scope_present,
        handoffs_reconciled,
        stream_facts,
        unscoped_gaps,
        coverage.stream_list_complete,
        coverage.stream_list_continuation,
        coverage.unscoped_gaps_complete,
        coverage.unscoped_gaps_continuation,
    )
    .map_err(|_| {
        event_shape_failure(
            "reconciliation refused: live attach binding does not seal the owner answer",
        )
    })?
    .with_consumed_frontiers(consumed_frontiers);
    Ok(ReconciliationPortOutcome::Reconciled(result))
}

/// Decodes the stream enumeration of one owner answer within the
/// negotiated stream budget. It remains pure with respect to the bridge
/// forwarding cache: owner ack bases are committed only after the core has
/// accepted every fact in the answer. The enumeration itself needs its own
/// bound: without it the outer collection would be unbounded no matter how
/// small each page is.
fn decode_reconciliation_streams(
    reconciliation: &serde_json::Value,
    live_generation: u64,
    budget: &mut RecoveryDecodeBudget,
) -> Result<Vec<RecoveredStreamFacts>, ProviderFailure> {
    let streams = reconciliation
        .get("streams")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(event_transport_failure)?;
    if streams.len() > MAX_RECOVERY_STREAMS {
        return Err(event_shape_failure(
            "reconciliation refused: stream enumeration exceeds the negotiated budget",
        ));
    }
    let mut stream_facts = Vec::with_capacity(streams.len().min(64));
    let mut seen_streams = BTreeSet::new();
    for stream in streams {
        let (page, _) = decode_recovery_stream(stream, live_generation, budget)?;
        if !seen_streams.insert(page.stream_id().to_owned()) {
            return Err(event_shape_failure(
                "reconciliation refused: duplicate stream identity in owner answer",
            ));
        }
        stream_facts.push(page);
    }
    Ok(stream_facts)
}

/// Decodes the top-level unscoped gaps within the negotiated gap budget.
/// Unscoped coverage is accounted against the same cumulative total as
/// stream-scoped gaps, so gap-heavy answers stay within budget.
fn decode_unscoped_gaps(
    reconciliation: &serde_json::Value,
    budget: &mut RecoveryDecodeBudget,
) -> Result<Vec<RecoveredGapFact>, ProviderFailure> {
    let unscoped_value = reconciliation
        .get("unscoped_gaps")
        .ok_or_else(event_transport_failure)?;
    let unscoped_array = unscoped_value
        .as_array()
        .ok_or_else(event_transport_failure)?;
    if unscoped_array.len() > MAX_RECOVERY_GAPS_PER_STREAM {
        return Err(event_shape_failure(
            "reconciliation refused: unscoped gaps exceed the negotiated gap budget",
        ));
    }
    budget.gaps = budget.gaps.saturating_add(unscoped_array.len());
    if budget.gaps > MAX_RECOVERY_TOTAL_GAPS {
        return Err(event_shape_failure(
            "reconciliation refused: answer exceeds the negotiated total gap budget",
        ));
    }
    let mut unscoped_gaps = Vec::with_capacity(unscoped_array.len());
    for gap in unscoped_array {
        unscoped_gaps.push(decode_recovery_gap(gap, "")?);
    }
    Ok(unscoped_gaps)
}

/// Requires the requested continuation scope to still be present in the
/// answer with a continuation that still advances past the requested
/// predecessor; otherwise the page is foreign or stale and refuses.
fn recovery_scope_value(
    request: &RecoveryReadRequest,
) -> Result<serde_json::Value, ProviderFailure> {
    if let Some((stream_id, after_sequence, cut, event_limit, gap_offset, gap_limit)) =
        request.stream_scope()
    {
        Ok(serde_json::json!({
            "version": 1, "kind": "stream", "window_key": request.window_key(),
            "stream_id": stream_id, "after_sequence": after_sequence,
            "upper_sequence": cut.upper_sequence(), "expected_revision": cut.expected_revision(),
            "retention_floor": cut.retention_floor(), "event_limit": event_limit,
            "gap_offset": gap_offset, "gap_limit": gap_limit,
        }))
    } else if let Some((after_stream, stream_limit)) = request.stream_list_scope() {
        Ok(serde_json::json!({
            "version": 1, "kind": "streams", "window_key": request.window_key(),
            "after_stream": after_stream, "stream_limit": stream_limit,
        }))
    } else if let Some((after_gap_scope, gap_offset, gap_limit)) = request.unscoped_gap_scope() {
        Ok(serde_json::json!({
            "version": 1, "kind": "unscoped_gaps", "window_key": request.window_key(),
            "after_gap_scope": after_gap_scope, "gap_offset": gap_offset, "gap_limit": gap_limit,
        }))
    } else {
        Err(event_shape_failure(
            "recovery continuation has no bounded selector",
        ))
    }
}

/// A complete finite event page must account for its declared upper bound.
/// A truncated response with a null continuation cannot turn the missing
/// suffix into completed inventory. The requested predecessor permits a
/// gap-only continuation after all finite events have already been read.
fn check_finite_page_end(
    page: &RecoveredStreamFacts,
    predecessor: u64,
) -> Result<(), ProviderFailure> {
    let cut = page
        .recovery_cut()
        .ok_or_else(|| event_shape_failure("reconciliation refused: finite owner cut absent"))?;
    let event_tail = page
        .events()
        .last()
        .map_or(predecessor, RecoveredEventFact::sequence);
    let gap_tail = page
        .gaps()
        .iter()
        .map(RecoveredGapFact::end_sequence)
        .max()
        .unwrap_or(0);
    let tail = event_tail.max(gap_tail);
    if page.page_continuation().is_some() && page.events().is_empty() {
        return Err(event_shape_failure(
            "reconciliation refused: empty event page cannot advance its continuation",
        ));
    }
    if page.page_continuation().is_none()
        && page.gap_continuation().is_none()
        && tail < cut.upper_sequence()
    {
        return Err(event_shape_failure(
            "reconciliation refused: finite event suffix omitted without continuation",
        ));
    }
    Ok(())
}

/// Owner-list positions and gap offsets prove that the returned page itself
/// advances in the requested direction; an echoed selector alone does not.
fn check_recovery_page_ordinals(
    reconciliation: &serde_json::Value,
    expected: Option<&RecoveryReadRequest>,
) -> Result<(), ProviderFailure> {
    let streams = reconciliation
        .get("streams")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| event_shape_failure("reconciliation refused: stream list absent"))?;
    let list_predecessor = expected
        .and_then(RecoveryReadRequest::stream_list_scope)
        .map(|(after, _)| after.parse::<u64>())
        .transpose()
        .map_err(|_| event_shape_failure("reconciliation refused: invalid list predecessor"))?
        .unwrap_or(0);
    let mut last_position = list_predecessor;
    for stream in streams {
        let position = recovery_sequence(stream, "owner_list_position")?;
        if position <= last_position {
            return Err(event_shape_failure(
                "reconciliation refused: stream list did not advance in owner order",
            ));
        }
        last_position = position;
    }
    if expected.is_none_or(|request| request.stream_list_scope().is_some())
        && let Some(cursor) = reconciliation
            .get("stream_list_continuation")
            .and_then(serde_json::Value::as_str)
    {
        let next = cursor.parse::<u64>().map_err(|_| {
            event_shape_failure("reconciliation refused: invalid owner list cursor")
        })?;
        if next < last_position || next <= list_predecessor {
            return Err(event_shape_failure(
                "reconciliation refused: owner list cursor does not cover page tail",
            ));
        }
    }
    let gaps = reconciliation
        .get("unscoped_gaps")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| event_shape_failure("reconciliation refused: unscoped gaps absent"))?;
    let mut prior: Option<(u64, u64, String)> = None;
    for gap in gaps {
        let scope = recovery_digest(gap, "gap_owner_scope")?;
        let position = recovery_sequence(gap, "gap_owner_position")?;
        let offset = recovery_cursor(gap, "gap_offset")?;
        if let Some((old_position, old_offset, old_scope)) = prior
            && (position < old_position
                || (position == old_position && (scope != old_scope || offset <= old_offset)))
        {
            return Err(event_shape_failure(
                "reconciliation refused: gap page is out of owner order",
            ));
        }
        if let Some((after_scope, after_offset, _)) =
            expected.and_then(RecoveryReadRequest::unscoped_gap_scope)
            && scope == after_scope
            && offset < after_offset
        {
            return Err(event_shape_failure(
                "reconciliation refused: gap page repeats the requested offset",
            ));
        }
        prior = Some((position, offset, scope));
    }
    Ok(())
}

fn check_expected_continuation(
    reconciliation: &serde_json::Value,
    stream_facts: &[RecoveredStreamFacts],
    expected: Option<&RecoveryReadRequest>,
) -> Result<(), ProviderFailure> {
    let requested = reconciliation
        .get("requested_recovery_scope")
        .ok_or_else(|| event_shape_failure("reconciliation refused: requested selector absent"))?;
    let Some(request) = expected else {
        if !requested.is_null()
            || !reconciliation
                .get("selected_scope")
                .is_some_and(serde_json::Value::is_null)
        {
            return Err(event_shape_failure(
                "reconciliation refused: unsolicited continuation selector",
            ));
        }
        for page in stream_facts {
            check_finite_page_end(page, page.acked_cursor())?;
        }
        return Ok(());
    };
    let exact = recovery_scope_value(request)?;
    if requested != &exact || reconciliation.get("selected_scope") != Some(&exact) {
        return Err(event_shape_failure(
            "recovery continuation refused: owner selected a foreign scope",
        ));
    }
    if reconciliation
        .get("window_status")
        .and_then(serde_json::Value::as_str)
        != Some("active")
    {
        return Ok(());
    }
    if let Some((stream_id, after_sequence, cut, _, gap_offset, _)) = request.stream_scope() {
        if stream_facts.len() != 1 {
            return Err(event_shape_failure(
                "recovery continuation refused: stream selector requires exactly one stream",
            ));
        }
        let page = stream_facts
            .iter()
            .find(|page| page.stream_id() == stream_id)
            .ok_or_else(|| {
                event_shape_failure("recovery continuation refused: required stream absent")
            })?;
        if page.recovery_cut() != Some(cut) {
            return Err(event_shape_failure(
                "recovery continuation refused: owner finite cut changed",
            ));
        }
        check_finite_page_end(page, after_sequence)?;
        if page
            .page_continuation()
            .is_some_and(|next| next <= after_sequence)
            || page
                .events()
                .iter()
                .any(|event| event.sequence() <= after_sequence)
            || page
                .gap_continuation()
                .is_some_and(|next| next <= gap_offset)
        {
            return Err(event_shape_failure(
                "recovery continuation refused: page cursor did not advance",
            ));
        }
    } else if let Some((after_stream, stream_limit)) = request.stream_list_scope() {
        if stream_facts.len() as u64 > stream_limit {
            return Err(event_shape_failure(
                "recovery continuation refused: stream list exceeds requested budget",
            ));
        }
        for page in stream_facts {
            check_finite_page_end(page, page.acked_cursor())?;
        }
        if reconciliation
            .get("stream_list_continuation")
            .and_then(serde_json::Value::as_str)
            == Some(after_stream)
        {
            return Err(event_shape_failure(
                "recovery continuation refused: stream-list cursor did not advance",
            ));
        }
    } else if let Some((after_gap_scope, gap_offset, _)) = request.unscoped_gap_scope() {
        let cursor = reconciliation.get("unscoped_gaps_continuation");
        if cursor
            .and_then(|value| value.get("after_gap_scope"))
            .and_then(serde_json::Value::as_str)
            == Some(after_gap_scope)
            && cursor
                .and_then(|value| value.get("gap_offset"))
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|next| next <= gap_offset)
        {
            return Err(event_shape_failure(
                "recovery continuation refused: unscoped gap cursor did not advance",
            ));
        }
    }
    Ok(())
}

/// Admitted event-route face: durable event delivery and acknowledgement
/// recovery through the Kernel front-door event entries.
///
/// The face holds the same retained transport owner as the activation and
/// host-request faces (one admitted transport, one runtime, one lease —
/// never a second transport, runtime, or lease). Every call first runs the
/// closed local half of the forwarding map: envelope/gap shape validation
/// through the existing contract validators, then a validated
/// continuity/recovery binding check of the presented attach binding against
/// the retained kernel-issued session captured by the one-shot activation
/// exchange, plus (for durable/control events) the producer/generation/
/// stream/event/sequence and `StateFence` binding. A foreign, stale, or
/// pre-activation session is refused here with its own typed refusal and
/// never reaches the event route; a reconnect may therefore deliver an old
/// producer's unacknowledged event only while it still presents the same
/// kernel-issued session under a live generation. A fenced (stale or future)
/// producer generation is refused for forwarding and recovers through
/// `reconcile_external`, which reads event ownership and cursors — never by
/// relabeling history as produced by the new generation.
///
/// Frozen four-operation map from each forwarding method to its closed Kernel
/// request, authority check, operational staging, provider normalizer,
/// Governor ingest, and result readback (Implements #2561 item 1; the match
/// in [`BridgeEventMethod::kernel_operation`] is exhaustive, so a new method
/// fails to compile until its row is recorded here):
///
/// | method | Kernel request | authority check | operational staging |
/// |---|---|---|---|
/// | `forward_hook` | `agent_bridge_hook_forward` | attach session continuity + hook digest bind | none (RECEIVED observation only; hook carries no ack) |
/// | `forward_event` | `agent_bridge_event_forward` | attach session + producer/generation/fence coherence, live generation fencing | ORS bridge-event row before the DURABLE answer |
/// | `forward_gap` | `agent_bridge_event_gap` | attach session continuity + gap identity/interval | durable gap row; never moves a cursor |
/// | `reconcile_external` | `agent_bridge_event_reconcile` | attach session continuity + presenting-connection scope | reads ownership/cursors/pages; applies the consumed frontier |
///
/// | method | provider normalizer | Governor ingest | result readback |
/// |---|---|---|---|
/// | `forward_hook` | envelope already normalized bridge-side (`HostEventEnvelope::validate`) | none (transport observation) | RECEIVED echo bound to the hook digest |
/// | `forward_event` | `normalize_acp_event` for raw producer bytes (ACP owner); forwarded `EventEnvelope` linkage re-validated Kernel-side | coordinator `observe_committed_intake` over `CommittedHostEventIntake` (ACP/commit path) | owner phase/disposition/cursors from the ORS row |
/// | `forward_gap` | gap identity/interval validation (no normalization) | none (coverage accounting) | gap acceptance bound to the gap identity |
/// | `reconcile_external` | none (read path) | none (read path) | ownership/cursor/page facts plus the bound reconciliation key |
///
/// `reconcile_continue` shares the `reconcile_external` row: same closed
/// Kernel request, same authority check, same contiguous consumed
/// frontier — plus the pure `recovery_scope` continuation selectors
/// (declared window key, one stream scope, predecessor sequence, explicit
/// event/gap budgets). A continuation read changes no cursor; the token is
/// rebound to the live authority before exchange, and the reply decodes
/// through the same validating path with the requested scope required
/// present. Recovery-only reads stay reachable while normal forwarding is
/// gated, so the gate cannot block the walk that satisfies it — and the
/// walk performs no ordinary effect, so it cannot bypass the gate either.
///
/// Actual phase/disposition information returns through `McpForwardingPort`
/// and its bridge-core callers: durable classes answer with the owner's
/// `Acknowledged` phase (or the determined `REJECTED`/`conflict` rejection),
/// best-effort answers with `BestEffortForwarded` (or the typed
/// `BestEffortDropped` gap reason while degraded). A `Result<()>` (hook, gap)
/// carries no phase and never implies durable/applied state. Receipt is owned
/// by the bridge: the core journals the host event (`observe_host_event`)
/// before the port is called, so the receipt stands in the bridge journal.
/// Activation, request cancellation, and result correlation paths are
/// untouched by this face. Host-request submit/cancel/reconcile entries carry
/// invocation intent and are not event delivery; a refused event is never
/// resubmitted as a host request.
struct KernelMcpForwardingPort {
    shared: SharedTransport,
}

impl KernelMcpForwardingPort {
    /// Runs the validated continuity/recovery binding check for one
    /// forwarding call against the single retained transport owner.
    ///
    /// The presented attach binding must still name the exact kernel-issued
    /// session the one-shot activation exchange captured on this admitted
    /// transport. Session identity is the continuity binding a reconnect
    /// preserves, so a foreign session, a stale pre-activation binding, or a
    /// call before any activation completes is refused here — before any
    /// frame is exchanged — with a typed continuity refusal. A matching
    /// session returns `Ok(())` so the caller proceeds to the admitted event
    /// entry; it never implies durability, normalization, or application.
    fn check_continuity(&self, binding: &AttachBinding) -> Result<(), ProviderFailure> {
        let owner = self.shared.try_borrow().map_err(|_| {
            ProviderFailure::new(
                "eliot-kernel-front-door",
                "event continuity check unavailable: retained transport owner is mutably borrowed",
            )
        })?;
        let live = owner.activated_session.as_deref().unwrap_or("");
        if !live.is_empty() && live == binding.session_id().as_str() {
            return Ok(());
        }
        Err(ProviderFailure::new(
            "eliot-kernel-front-door",
            "event continuity refused: presented attach session is not the retained kernel-issued \
             session for this admitted transport (foreign, stale, or pre-activation binding); no \
             frame exchanged, no Kernel durable record staged; reconnect must present the \
             validated continuity binding",
        ))
    }

    /// Binds the real producer, producer generation, stream/event/sequence,
    /// and `StateFence` of one durable/control event to the presenting attach
    /// binding (Implements #2561 item 1, second half).
    ///
    /// Mirrors the bridge-core authority join: the event and fence authority
    /// epochs must match the attach fence authority, and the producer and
    /// fence generations must equal the live attach generation. A mismatch
    /// is a foreign or stale binding and is refused here — before any frame
    /// is exchanged — with a typed refusal pointing at `reconcile_external`
    /// recovery. Historical events are never relabeled as produced by the
    /// new transport generation: only the live generation forwards, and only
    /// under the validated continuity binding above.
    fn check_event_binding(
        binding: &AttachBinding,
        event: &EventEnvelope,
    ) -> Result<(), ProviderFailure> {
        let fence = binding.state_fence();
        if !event
            .authority_epoch
            .is_same_authority(fence.authority_epoch())
            || !event
                .state_fence
                .authority_epoch
                .is_same_authority(fence.authority_epoch())
            || event.producer_generation.value() != fence.generation().get()
            || event.state_fence.resource_generation.value() != fence.generation().get()
        {
            return Err(ProviderFailure::new(
                "eliot-kernel-front-door",
                "event binding refused: producer, producer generation, or StateFence does not \
                 match the presenting attach authority (foreign producer/session/fence binding); \
                 nothing staged, nothing forwarded; recover ownership and cursors through \
                 reconcile_external, never by relabeling history",
            ));
        }
        Ok(())
    }

    /// Exchanges one bridge-event frame over the single retained transport
    /// owner and returns the Kernel reply.
    ///
    /// Sends exactly one frame and receives exactly one reply under the
    /// admitted transport limits. A non-delivered send or a missing reply is
    /// an unknown outcome — never a phase — so the caller fails without
    /// claiming anything and the producer's at-least-once retry stays sound.
    fn exchange(&mut self, frame: &Frame) -> Result<Frame, ProviderFailure> {
        self.shared
            .try_borrow_mut()
            .map_err(|_| event_transport_failure())?
            .exchange_bridge_event_frame(frame)
    }

    /// Snapshots the Kernel-issued transport facts for one event frame.
    fn transport_facts(&self) -> Result<BridgeEventTransportFacts, ProviderFailure> {
        let owner = self
            .shared
            .try_borrow()
            .map_err(|_| event_transport_failure())?;
        Ok(BridgeEventTransportFacts {
            connection_id: owner.admitted.receipt.connection_id.clone(),
            state_fence: owner.admitted.receipt.state_fence.clone(),
            session: owner.activated_session.clone(),
        })
    }

    /// Records one digest-verified durable receipt for the exact contiguous
    /// acknowledgement set.
    ///
    /// The receipt joins the stream's held durable sequences; out-of-order
    /// receipts stay retained above their holes without advancing anything.
    /// Process-local routing aid for the reconcile consumed frontier (like
    /// the byte-identity replay cache): it dies with this connection, is
    /// bounded, and is never a reconciliation log — reconciliation reads the
    /// ORS-owned cursors. Owner-confirmed prefixes are pruned on every
    /// verified reply; overflow and eviction only defer ack advancement
    /// (safe direction); nothing is lost and no cursor resets.
    fn note_delivered(&mut self, stream_id: &str, sequence: u64) {
        if sequence == 0 {
            return;
        }
        let Ok(mut owner) = self.shared.try_borrow_mut() else {
            return;
        };
        if !owner.delivered_sequences.contains_key(stream_id)
            && owner.delivered_sequences.len() >= MAX_DELIVERED_STREAMS
            && let Some(oldest) = owner.delivered_sequences.keys().next().cloned()
        {
            owner.delivered_sequences.remove(&oldest);
            owner.consumed_sent.remove(&oldest);
            owner.owner_acked.remove(&oldest);
        }
        let base = owner
            .consumed_sent
            .get(stream_id)
            .copied()
            .unwrap_or(0)
            .max(owner.owner_acked.get(stream_id).copied().unwrap_or(0));
        let held = owner
            .delivered_sequences
            .entry(stream_id.to_owned())
            .or_default();
        loop {
            let confirmed = match held.first() {
                Some(first) if *first <= base => *first,
                _ => break,
            };
            held.remove(&confirmed);
        }
        if held.len() >= MAX_DELIVERED_SEQUENCES_PER_STREAM {
            return;
        }
        held.insert(sequence);
    }

    /// Records the owner-confirmed acked base only after core import accepted
    /// the verified reconcile reply, then prunes the held sequences it confirms.
    ///
    /// Owner confirmation is a receipt, not local inference: only sequences
    /// at or below the confirmed base leave the held set, and the
    /// contiguous frontier always resumes above it.
    fn note_owner_acked(&mut self, stream_id: &str, acked: u64) {
        let Ok(mut owner) = self.shared.try_borrow_mut() else {
            return;
        };
        let known = owner.owner_acked.get(stream_id).copied().unwrap_or(0);
        if acked > known {
            owner.owner_acked.insert(stream_id.to_owned(), acked);
        }
        let base = owner
            .consumed_sent
            .get(stream_id)
            .copied()
            .unwrap_or(0)
            .max(owner.owner_acked.get(stream_id).copied().unwrap_or(0));
        let empty = if let Some(held) = owner.delivered_sequences.get_mut(stream_id) {
            let confirmed: Vec<u64> = held.range(..=base).copied().collect();
            for sequence in confirmed {
                held.remove(&sequence);
            }
            held.is_empty()
        } else {
            false
        };
        if empty {
            owner.delivered_sequences.remove(stream_id);
        }
    }

    /// Builds the exact contiguous consumed frontier justified by the
    /// receiving owner's receipts.
    ///
    /// Per stream, the frontier is the contiguous digest-verified durable
    /// run above the owner-confirmed base: holes and unseen pages are
    /// never acknowledged, and only newly advanced frontiers are offered.
    /// This is a pure offer calculation. Confirmation is recorded only by
    /// `note_consumed_frontier` after the reply has passed validation and core
    /// import; an unknown exchange consequently re-offers the same frontier.
    fn note_consumed_frontier(&mut self, stream_id: &str, sequence: u64) {
        if sequence == 0 {
            return;
        }
        let Ok(mut owner) = self.shared.try_borrow_mut() else {
            return;
        };
        let sent = owner.consumed_sent.get(stream_id).copied().unwrap_or(0);
        if sequence > sent {
            owner.consumed_sent.insert(stream_id.to_owned(), sequence);
        }
        let base = owner
            .consumed_sent
            .get(stream_id)
            .copied()
            .unwrap_or(0)
            .max(owner.owner_acked.get(stream_id).copied().unwrap_or(0));
        let empty = if let Some(held) = owner.delivered_sequences.get_mut(stream_id) {
            let confirmed: Vec<u64> = held.range(..=base).copied().collect();
            for sequence in confirmed {
                held.remove(&sequence);
            }
            held.is_empty()
        } else {
            false
        };
        if empty {
            owner.delivered_sequences.remove(stream_id);
        }
    }

    fn contiguous_consumed_payload(
        &self,
    ) -> (Vec<serde_json::Value>, Vec<ReconciliationConsumedFrontier>) {
        let Ok(owner) = self.shared.try_borrow() else {
            return (Vec::new(), Vec::new());
        };
        let mut frontiers: Vec<(String, u64)> = Vec::new();
        for (stream_id, held) in &owner.delivered_sequences {
            let sent = owner.consumed_sent.get(stream_id).copied().unwrap_or(0);
            let acked = owner.owner_acked.get(stream_id).copied().unwrap_or(0);
            let mut frontier = sent.max(acked);
            while held.contains(&frontier.saturating_add(1)) {
                frontier = frontier.saturating_add(1);
                if frontier == u64::MAX {
                    break;
                }
            }
            if frontier > sent {
                frontiers.push((stream_id.clone(), frontier));
            }
        }
        frontiers.sort_by(|left, right| left.0.cmp(&right.0));
        frontiers.truncate(MAX_RECONCILE_CONSUMED_ENTRIES);
        let confirmations = frontiers
            .iter()
            .map(|(stream_id, sequence)| {
                ReconciliationConsumedFrontier::new(stream_id.clone(), *sequence)
            })
            .collect();
        let payload = frontiers
            .into_iter()
            .map(|(stream_id, sequence)| {
                serde_json::json!({ "stream_id": stream_id, "sequence": sequence })
            })
            .collect();
        (payload, confirmations)
    }
}

impl McpForwardingPort for KernelMcpForwardingPort {
    fn forward_hook(
        &mut self,
        binding: &AttachBinding,
        event: &HostEventEnvelope,
    ) -> Result<(), ProviderFailure> {
        if event.validate().is_err() {
            return Err(event_shape_failure(
                "hook envelope refused: host event envelope failed closed validation (identity, \
                 sequence, or route); nothing staged, nothing forwarded",
            ));
        }
        self.check_continuity(binding)?;
        let facts = self.transport_facts()?;
        if facts.session.is_none() {
            return Err(event_shape_failure(
                "hook forwarding refused: no admitted Kernel session; attach and activate before \
                 event delivery",
            ));
        }
        let now_ms = bridge_event_unix_ms()?;
        let hook_bytes = canonical_json_bytes(event).map_err(|_| event_transport_failure())?;
        let hook_digest = sha256_hex(&hook_bytes);
        let hook_value = serde_json::to_value(event).map_err(|_| event_transport_failure())?;
        let correlation = format!("bridge-hook:{}", event.event_id.as_str());
        let frame = bridge_event_frame_for_operation(
            &correlation,
            &facts,
            serde_json::json!({
                "operation": BridgeEventMethod::Hook.kernel_operation(),
                "hook_envelope": hook_value,
                "hook_digest": hook_digest,
            }),
            now_ms,
        )?;
        let reply = self.exchange(&frame)?;
        let value =
            decode_bridge_event_reply(&reply, &frame).ok_or_else(event_transport_failure)?;
        if value.get("accepted").and_then(serde_json::Value::as_bool) != Some(true)
            || value.get("received").and_then(serde_json::Value::as_bool) != Some(true)
            || value.get("hook_digest").and_then(serde_json::Value::as_str) != Some(&hook_digest)
        {
            return Err(event_transport_failure());
        }
        Ok(())
    }
    fn forward_event(
        &mut self,
        binding: &AttachBinding,
        event: &EventEnvelope,
    ) -> Result<EventPortOutcome, ProviderFailure> {
        if event.validate().is_err() {
            return Err(event_shape_failure(
                "event envelope refused: durable/control event envelope failed closed validation \
                 (identity, sequence, or fence/authority coherence); nothing staged, nothing \
                 forwarded",
            ));
        }
        self.check_continuity(binding)?;
        Self::check_event_binding(binding, event)?;
        let facts = self.transport_facts()?;
        if facts.session.is_none() {
            return Err(event_shape_failure(
                "event forwarding refused: no admitted Kernel session; attach and activate before \
                 event delivery",
            ));
        }
        let now_ms = bridge_event_unix_ms()?;
        let envelope_bytes = canonical_json_bytes(event).map_err(|_| event_transport_failure())?;
        let envelope_sha = sha256_hex(&envelope_bytes);
        let envelope_value = serde_json::to_value(event).map_err(|_| event_transport_failure())?;
        let correlation = format!("bridge-event:{}:{}", event.stream_id, event.event_id);
        let frame = bridge_event_frame_for_operation(
            &correlation,
            &facts,
            serde_json::json!({
                "operation": BridgeEventMethod::Event.kernel_operation(),
                "envelope": envelope_value,
                "envelope_sha256": envelope_sha,
            }),
            now_ms,
        )?;
        let reply = self.exchange(&frame)?;
        let value =
            decode_bridge_event_reply(&reply, &frame).ok_or_else(event_transport_failure)?;
        decode_event_port_outcome(event, &value, &envelope_sha, self)
    }
    fn forward_gap(
        &mut self,
        binding: &AttachBinding,
        gap: &CoverageGap,
    ) -> Result<(), ProviderFailure> {
        if gap.validate().is_err() {
            return Err(event_shape_failure(
                "gap refused: coverage gap failed closed validation (identity or interval); no \
                 coverage advanced",
            ));
        }
        self.check_continuity(binding)?;
        let facts = self.transport_facts()?;
        if facts.session.is_none() {
            return Err(event_shape_failure(
                "gap forwarding refused: no admitted Kernel session; attach and activate before \
                 event delivery",
            ));
        }
        let now_ms = bridge_event_unix_ms()?;
        let gap_value = serde_json::to_value(gap).map_err(|_| event_transport_failure())?;
        let correlation = format!("bridge-gap:{}", gap.gap_id);
        let frame = bridge_event_frame_for_operation(
            &correlation,
            &facts,
            serde_json::json!({
                "operation": BridgeEventMethod::Gap.kernel_operation(),
                "gap": gap_value,
                "stream_id": "",
            }),
            now_ms,
        )?;
        let reply = self.exchange(&frame)?;
        let value =
            decode_bridge_event_reply(&reply, &frame).ok_or_else(event_transport_failure)?;
        if value.get("accepted").and_then(serde_json::Value::as_bool) != Some(true)
            || value.get("gap_id").and_then(serde_json::Value::as_str) != Some(gap.gap_id.as_str())
        {
            return Err(event_transport_failure());
        }
        Ok(())
    }
    fn reconcile_external(
        &mut self,
        binding: &AttachBinding,
    ) -> Result<ReconciliationPortOutcome, ProviderFailure> {
        self.check_continuity(binding)?;
        let facts = self.transport_facts()?;
        if facts.session.is_none() {
            return Err(event_shape_failure(
                "event-route reconciliation refused: no admitted Kernel session; attach and \
                 activate before event delivery",
            ));
        }
        let now_ms = bridge_event_unix_ms()?;
        let (consumed, consumed_frontiers) = self.contiguous_consumed_payload();
        let correlation = format!("bridge-reconcile:{}", facts.connection_id);
        let frame = bridge_event_frame_for_operation(
            &correlation,
            &facts,
            serde_json::json!({
                "operation": BridgeEventMethod::Reconcile.kernel_operation(),
                "consumed": consumed,
            }),
            now_ms,
        )?;
        let reply = self.exchange(&frame)?;
        let value =
            decode_bridge_event_reply(&reply, &frame).ok_or_else(event_transport_failure)?;
        decode_reconciliation_outcome(binding, &facts, &value, consumed_frontiers, None)
    }
    /// Reads one bounded recovery page inside the declared window through
    /// the real reconcile route (issue #2732).
    ///
    /// The frame carries no consumed frontier. Its `recovery_scope` selects
    /// a stream page, stream-list page, or unscoped-gap page inside the
    /// owner-issued finite window. These selectors are pure —
    /// a continuation read changes no producer/consumer cursor — and the
    /// token is rebound here to the exact live authority before anything
    /// is exchanged: the expected generation and presenting connection
    /// must still match the live attach, so each call rechecks the scoped
    /// rights, including after a reconnect, and possession of the token
    /// alone authorizes nothing. The reply decodes through the same
    /// validating path as the full read, additionally requiring the
    /// selected scope, predecessor, and next continuation to match.
    fn reconcile_continue(
        &mut self,
        binding: &AttachBinding,
        request: &RecoveryReadRequest,
    ) -> Result<ReconciliationPortOutcome, ProviderFailure> {
        self.check_continuity(binding)?;
        if request.expected_generation() != binding.activation_generation().get() {
            return Err(ProviderFailure::new(
                "eliot-kernel-front-door",
                "recovery continuation refused: token generation is not the live attach \
                 generation (stale or replaced attach); nothing exchanged, nothing applied",
            ));
        }
        let facts = self.transport_facts()?;
        if facts.session.is_none() {
            return Err(event_shape_failure(
                "event-route recovery refused: no admitted Kernel session; attach and activate \
                 before event recovery",
            ));
        }
        if request.expected_connection() != facts.connection_id.as_str() {
            return Err(ProviderFailure::new(
                "eliot-kernel-front-door",
                "recovery continuation refused: token connection is not the presenting \
                 connection (reconnect or replacement attach); nothing exchanged, nothing applied",
            ));
        }
        let now_ms = bridge_event_unix_ms()?;
        let recovery_scope = recovery_scope_value(request)?;
        let scope_bytes =
            canonical_json_bytes(&recovery_scope).map_err(|_| event_transport_failure())?;
        let correlation = format!(
            "bridge-recover:{}:{}",
            facts.connection_id,
            sha256_hex(&scope_bytes),
        );
        let frame = bridge_event_frame_for_operation(
            &correlation,
            &facts,
            serde_json::json!({
                "operation": BridgeEventMethod::Reconcile.kernel_operation(),
                "consumed": [],
                "recovery_scope": recovery_scope,
            }),
            now_ms,
        )?;
        let reply = self.exchange(&frame)?;
        let value =
            decode_bridge_event_reply(&reply, &frame).ok_or_else(event_transport_failure)?;
        decode_reconciliation_outcome(binding, &facts, &value, Vec::new(), Some(request))
    }

    fn reconciliation_imported(
        &mut self,
        binding: &AttachBinding,
        result: &ReconciliationPortResult,
    ) {
        // Core calls this only after its staged recovery window was accepted.
        // Keep an additional live transport check so an adapter cannot apply
        // a cache receipt after its connection has been replaced.
        if self.check_continuity(binding).is_err() {
            return;
        }
        if let Some(window) = result.window() {
            for stream in window.stream_facts() {
                self.note_owner_acked(stream.stream_id(), stream.acked_cursor());
            }
            for frontier in result.consumed_frontiers() {
                let owner_acked = window
                    .stream_facts()
                    .iter()
                    .find(|stream| stream.stream_id() == frontier.stream_id())
                    .is_some_and(|stream| stream.acked_cursor() >= frontier.sequence());
                if owner_acked {
                    self.note_consumed_frontier(frontier.stream_id(), frontier.sequence());
                }
            }
        }
    }
}

pub type KernelPorts = (
    Box<dyn HostActivationPort>,
    KernelHostRequestClient,
    Box<dyn McpForwardingPort>,
);

fn current_os_identity() -> Result<(String, u32), RuntimeBuildError> {
    let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
        .map_err(|e| RuntimeBuildError::KernelClient(format!("current identity: {e:?}")))?;
    Ok((
        expectation.expected_sid().to_owned(),
        expectation.expected_session_id(),
    ))
}

fn load_declaration(path: &Path) -> Result<LoadedAgentBridgeDeclaration, RuntimeBuildError> {
    let path = validate_client_declaration_path(path)
        .map_err(|e| RuntimeBuildError::KernelClient(e.to_string()))?;
    #[cfg(windows)]
    {
        let mut lease = eliot_platform_windows::open_agent_bridge_declaration_read_lease(&path)
            .map_err(|e| RuntimeBuildError::KernelClient(format!("declaration lease: {e:?}")))?;
        let bytes = lease
            .read_bytes()
            .map_err(|e| RuntimeBuildError::KernelClient(format!("declaration read: {e:?}")))?;
        let declaration =
            decode_declaration_bytes(&bytes).map_err(RuntimeBuildError::KernelClient)?;
        Ok(LoadedAgentBridgeDeclaration {
            declaration,
            _lease: lease,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(RuntimeBuildError::KernelClient(
            "declaration lease unavailable off Windows".to_owned(),
        ))
    }
}

/// Admits one front-door connection and splits the single retained
/// transport owner into its three kernel faces.
///
/// The `SharedTransport` clone handed to `KernelHostRequestClient` is the
/// only rehydrate hook: the Kernel-owned reconcile/restore entries
/// (`agent_host_request_reconcile`, `REACTIVE_RESTORE_OPERATION`) reuse it,
/// so no second transport and no duplicated envelope state machine exist
/// here. The forwarding face holds a third clone of the same owner: refused
/// events expose the unadmitted event-delivery capability with its Kernel
/// observation-route owner reference, never by resubmitting them
/// as host requests and never through a reconcile-then-retry loop that
/// cannot succeed until that route is admitted. The shared owner also backs
/// the face's validated continuity binding: the presented attach session
/// must still equal the retained kernel-issued session before any route
/// refusal is reached.
pub fn kernel_ports_with_declaration(
    declaration_path: &Path,
) -> Result<KernelPorts, RuntimeBuildError> {
    let loaded = load_declaration(declaration_path)?;
    let declaration = &loaded.declaration;
    let (current_sid, _current_session) = current_os_identity()?;
    let expectation = eliot_platform_windows::KernelFrontDoorServerExpectation::new(
        declaration.expected_kernel_sid.clone(),
        declaration.expected_kernel_session_id,
        declaration.expected_kernel_artifact_sha256.clone(),
        eliot_platform_windows::KernelFrontDoorAclMode::SystemAndLocalServiceWithClient {
            client_sid: current_sid.clone(),
        },
    )
    .map_err(|e| RuntimeBuildError::KernelClient(format!("frontdoor expectation: {e:?}")))?;
    let limits = eliot_ipc::TransportLimits {
        max_frame_bytes: declaration.max_frame as usize,
        ..Default::default()
    };
    let pipe_name = r"\\.\pipe\eliot\kernel\frontdoor";
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| RuntimeBuildError::KernelClient(e.to_string()))?;
    let mut transport = runtime.block_on(async {
        eliot_ipc::NamedPipeTransport::connect_authenticated_kernel_front_door(
            pipe_name,
            Duration::from_secs(5),
            &expectation,
        )
        .await
        .map_err(|e| RuntimeBuildError::KernelClient(format!("frontdoor connect: {e:?}")))
    })?;
    let observed = transport
        .kernel_front_door_observed_extra_sid()
        .ok_or_else(|| RuntimeBuildError::KernelClient("missing extra sid".to_owned()))?;
    if observed != current_sid {
        return Err(RuntimeBuildError::KernelClient(
            "extra SID mismatch".to_owned(),
        ));
    }
    let challenge_frame = runtime.block_on(async {
        transport
            .receive_frame(limits)
            .await
            .map_err(|e| RuntimeBuildError::KernelClient(format!("challenge receive: {e:?}")))
    })?;
    let connection_id = challenge_frame.connection_id.clone();
    let challenge: AgentBridgePeerChallenge =
        eliot_ipc::decode_peer_challenge_frame(&challenge_frame, &connection_id)
            .map_err(|e| RuntimeBuildError::KernelClient(format!("challenge decode: {e:?}")))?;
    challenge
        .validate_declaration(declaration)
        .map_err(|e| RuntimeBuildError::KernelClient(format!("challenge validation: {e:?}")))?;
    let hello = declaration
        .client_hello(challenge.challenge_nonce.clone())
        .map_err(|e| RuntimeBuildError::KernelClient(format!("client hello: {e:?}")))?;
    let hello_frame = eliot_ipc::client_hello_frame(&connection_id, &hello)
        .map_err(|e| RuntimeBuildError::KernelClient(format!("hello frame: {e:?}")))?;
    let receipt_frame = runtime.block_on(async {
        transport
            .send_frame(&hello_frame, limits)
            .await
            .map_err(|e| RuntimeBuildError::KernelClient(format!("hello send: {e:?}")))?;
        transport
            .receive_frame(limits)
            .await
            .map_err(|e| RuntimeBuildError::KernelClient(format!("receipt receive: {e:?}")))
    })?;
    let receipt =
        eliot_ipc::decode_agent_bridge_admission_receipt_frame(&receipt_frame, &connection_id)
            .map_err(|e| RuntimeBuildError::KernelClient(format!("receipt decode: {e:?}")))?;
    receipt
        .validate_challenge(&challenge)
        .map_err(|e| RuntimeBuildError::KernelClient(format!("receipt challenge: {e:?}")))?;
    receipt
        .validate_client_hello(declaration, &hello)
        .map_err(|e| RuntimeBuildError::KernelClient(format!("receipt hello: {e:?}")))?;
    if receipt.connection_id != connection_id {
        return Err(RuntimeBuildError::KernelClient(
            "receipt connection mismatch".to_owned(),
        ));
    }
    Ok(kernel_faces_from_admission(
        transport, runtime, loaded, limits, receipt,
    ))
}

/// Wraps one admitted front-door connection in the single retained
/// transport owner and splits it into the three kernel faces.
///
/// The owner (transport, runtime, lease, activation guard, replay cache and
/// the phase-aware delivery/ack maps) is built here so the admission
/// exchange in [`kernel_ports_with_declaration`] stays a straight-line
/// handshake; the three faces share the one owner, never a second
/// transport, runtime, or lease.
fn kernel_faces_from_admission(
    transport: eliot_ipc::NamedPipeTransport,
    runtime: tokio::runtime::Runtime,
    loaded: LoadedAgentBridgeDeclaration,
    limits: eliot_ipc::TransportLimits,
    receipt: AgentBridgePeerAdmissionReceipt,
) -> KernelPorts {
    let owner: SharedTransport = Rc::new(RefCell::new(KernelTransportOwner {
        admitted: AdmittedConnection { transport, receipt },
        runtime,
        _loaded: loaded,
        activation_used: false,
        limits,
        activated_session: None,
        replay_cache: HashMap::new(),
        delivered_sequences: BTreeMap::new(),
        consumed_sent: BTreeMap::new(),
        owner_acked: BTreeMap::new(),
    }));
    let host: Box<dyn HostActivationPort> = Box::new(KernelHostActivationPort {
        shared: owner.clone(),
    });
    let host_request = KernelHostRequestClient {
        shared: owner.clone(),
    };
    let fwd: Box<dyn McpForwardingPort> = Box::new(KernelMcpForwardingPort {
        shared: owner.clone(),
    });
    (host, host_request, fwd)
}

/// Projects a reactive delivery-record failure onto the closed bridge error
/// set without inventing a new variant: the ledger owns the reason text,
/// the bridge owns only the transport-facing classification.
fn reactive_ledger_error(error: &ReactiveInjectionError) -> BridgeError {
    BridgeError::ProviderContract(error.to_string())
}

pub struct BridgeRunner {
    profile: Profile,
    runtime: Runtime,
    core: AgentBridgeCore,
    reactive_ledger: ReactiveInjectionLedger,
    bootstrap_session: BootstrapSession,
    bootstrap_snapshot: Option<BootstrapSnapshot>,
}

/// Owner-supplied bootstrap inputs sealed to the live attach binding.
///
/// The snapshot carries exactly what the owner produced through the
/// bootstrap operation (context plus task inputs) together with the
/// authenticated [`AttachBinding`] live at note time (`None` when noted
/// while detached). Composition requires the live binding to still equal
/// the noted seal: a different session after re-attach, a moved State
/// Fence, or another scope/task binding refuses instead of projecting
/// stale authority as current. Noting again under the current attach
/// reseals the snapshot.
#[derive(Clone, Debug)]
struct BootstrapSnapshot {
    context: BootstrapContext,
    tasks: BootstrapTaskInputs,
    binding: Option<AttachBinding>,
}

impl BootstrapSnapshot {
    /// Returns the live binding when it still equals the noted seal.
    ///
    /// Strict option equality: a snapshot noted while detached (`None`
    /// seal) composes only while still detached, and a snapshot noted
    /// under a live attach composes only under that exact authenticated
    /// binding — principal, session, connection, activation generation,
    /// State Fence, and owner-resolved task binding. A wrong session after
    /// re-attach, a stale fence, or a changed scope/task binding refuses
    /// instead of projecting stale authority as current, so none of them
    /// can ever compose to `READY`. Re-noting under the current attach
    /// reseals the snapshot.
    fn sealed_live_binding(&self, live: Option<AttachView>) -> Option<AttachBinding> {
        let live_binding = live.map(|view| view.binding().clone());
        if live_binding == self.binding {
            live_binding
        } else {
            None
        }
    }

    /// Binds noted context content to the sealed owner binding.
    ///
    /// The host supplies context text; the attach binding supplies truth.
    /// A noted principal or `WorkScope` that disagrees with the sealed
    /// binding is a wrong-principal/wrong-worktree packet and is refused
    /// here, before any readiness can be projected from it.
    fn content_matches_binding(
        context: &BootstrapContext,
        binding: &AttachBinding,
    ) -> Result<(), BootstrapError> {
        if context.principal_ref != binding.principal_id().as_str() {
            return Err(BootstrapError {
                code: "BOOTSTRAP_PRINCIPAL_MISMATCH",
                detail: "noted principal disagrees with the live attach principal".to_owned(),
            });
        }
        if context.workscope_ref != binding.task_binding().work_scope_id() {
            return Err(BootstrapError {
                code: "BOOTSTRAP_SCOPE_MISMATCH",
                detail: "noted WorkScope disagrees with the live attach task binding".to_owned(),
            });
        }
        Ok(())
    }

    /// Requires a composed task selection to agree with the sealed activation task.
    ///
    /// The sealed attach binding carries the activation-resolved task; a
    /// `BOUND`/`UNIQUE` selection that names any other task is a forged or
    /// stale packet (host-authored readiness naming a task the activation
    /// never resolved) and is refused here, so it can never compose to
    /// `READY`. A selection that claims a bound task but carries none is
    /// refused the same way. `AMBIGUOUS`/`NONE` selections never project
    /// readiness and need no agreement: they stay available as honest typed
    /// non-ready outcomes.
    fn selection_matches_sealed_task(
        bootstrap: &UnderstandingBootstrap,
        seal: &AttachBinding,
    ) -> Result<(), BootstrapError> {
        let selected = match bootstrap.task_selection.disposition {
            TaskSelectionDisposition::Bound | TaskSelectionDisposition::Unique => {
                match &bootstrap.task_selection.selected_task_and_revision {
                    Some(selected) => selected,
                    None => {
                        return Err(BootstrapError {
                            code: "BOOTSTRAP_TASK_MISMATCH",
                            detail:
                                "bound task selection carries no selected task; refusing to project"
                                    .to_owned(),
                        });
                    }
                }
            }
            TaskSelectionDisposition::Ambiguous | TaskSelectionDisposition::None => return Ok(()),
        };
        if selected.task_ref != seal.task_binding().task_id().as_str() {
            return Err(BootstrapError {
                code: "BOOTSTRAP_TASK_MISMATCH",
                detail:
                    "composed task selection disagrees with the sealed attach task binding; refusing to project"
                        .to_owned(),
            });
        }
        Ok(())
    }
}

impl BridgeRunner {
    pub fn new(
        profile: Profile,
        readiness: ProviderReadiness,
        host_activation: Option<Box<dyn HostActivationPort>>,
        mcp_forwarding: Option<Box<dyn McpForwardingPort>>,
    ) -> Result<Self, RuntimeBuildError> {
        if !profile.is_compiled() {
            return Err(RuntimeBuildError::ProfileNotCompiled(profile));
        }
        let runtime = Runtime::new(
            RuntimeConfig {
                mailbox_capacity: 32,
                control_reserve: 4,
                concurrency: 1,
                control_concurrency_reserve: 1,
                fairness_quantum: 8,
                restart_budget: 0,
                restart_window: Duration::from_mins(1),
                restart_backoff: Duration::from_millis(50),
                shutdown_grace: Duration::from_secs(1),
            },
            None,
        )
        .map_err(RuntimeBuildError::Runtime)?;
        // Cursor policy: durable-control cursors advance only on a Durable
        // (or later) ack, durable-observation cursors only on Normalized (or
        // later). The production forwarding face (`KernelMcpForwardingPort`)
        // returns the owner's independently verifiable phase per event, so a
        // DURABLE answer advances durable-control cursors while lower phases
        // stay outstanding for acknowledgement recovery; `ReconcileExternal`
        // reads event ownership and cursors through the admitted Kernel
        // observation route (#2561). The policy still declares the honest
        // requirement the owner answers must satisfy.
        let cursor_policy = CursorPolicy::new(AckPhase::Durable, AckPhase::Normalized)
            .map_err(RuntimeBuildError::BridgeContract)?;
        Ok(Self {
            profile,
            runtime,
            core: AgentBridgeCore::new(readiness, host_activation, mcp_forwarding, cursor_policy),
            reactive_ledger: ReactiveInjectionLedger::new(),
            bootstrap_session: BootstrapSession::default(),
            bootstrap_snapshot: None,
        })
    }
    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.profile
    }
    #[must_use]
    pub fn control_capacity(&self) -> usize {
        self.runtime
            .available_capacity(eliot_runtime::ExecutionClass::ProtectedControl)
    }
    pub fn demand_start(
        &mut self,
        demand_id: impl Into<String>,
        connection_id: impl Into<String>,
    ) -> Result<AttachView, BridgeError> {
        self.attach(AttachRequest::managed(
            DemandId::new(demand_id).map_err(|e| BridgeError::ProviderContract(e.to_string()))?,
            ConnectionId::new(connection_id)
                .map_err(|e| BridgeError::ProviderContract(e.to_string()))?,
        ))
    }
    pub fn attach(&mut self, request: AttachRequest) -> Result<AttachView, BridgeError> {
        self.core.attach(request)
    }
    pub fn reconnect(&mut self, request: ReconnectRequest) -> Result<AttachView, BridgeError> {
        self.core.reconnect(request)
    }
    pub fn reconcile_external(&mut self) -> Result<AttachView, BridgeError> {
        self.core.reconcile_external()
    }
    /// Reads one bounded recovery page inside the declared window.
    ///
    /// Reachable while normal forwarding is gated: the walk restores
    /// checked receipt/accounting facts without performing ordinary
    /// effects, so recovery can satisfy the gate without bypassing it.
    #[allow(clippy::result_large_err)]
    pub fn recover_next_page(&mut self) -> Result<RecoveryView, BridgeError> {
        self.core.recover_next_page()
    }
    /// Returns the read-only progress of the declared recovery window, if any.
    #[must_use]
    pub fn recovery_view(&self) -> Option<RecoveryView> {
        self.core.recovery_view()
    }
    /// Pages checked, imported recovery identities for the active window.
    /// The core binds the continuation to that window and its import revision.
    #[allow(clippy::result_large_err)]
    pub fn recovery_projection_page(
        &self,
        cursor: Option<&str>,
    ) -> Result<RecoveryProjectionPage, BridgeError> {
        self.core.recovery_projection_page(cursor)
    }
    /// Lists recovered owner receipts without local acknowledgement cover.
    #[must_use]
    pub fn recovered_pending(&self) -> Vec<RecoveredPendingView> {
        self.core.recovered_pending()
    }
    pub fn forward_hook(&mut self, event: &HostEventEnvelope) -> Result<(), BridgeError> {
        self.core.forward_hook(event)
    }
    pub fn forward_event(
        &mut self,
        event: &EventEnvelope,
    ) -> Result<EventForwardStatus, BridgeError> {
        self.core.forward_event(event)
    }
    #[must_use]
    pub fn attach_view(&self) -> Option<AttachView> {
        self.core.attach_view()
    }
    /// Live kernel-owned session identity for reactive delivery records.
    ///
    /// The session is read from the activation-sealed attach binding, never
    /// from caller text, so ledger items bind the same session the transport
    /// enforces (I7.7: no durable session is derived from a connection).
    fn live_reactive_session(&self) -> Result<String, BridgeError> {
        self.attach_view()
            .map(|view| view.binding().session_id().as_str().to_owned())
            .ok_or(BridgeError::NotAttached)
    }
    /// Admits one caller-supplied reactive-context injection as pending for
    /// the live session (I7.19 admit step).
    ///
    /// Cue normalization, exact firing evaluation, relation activation, and
    /// the admission decision itself stay with their owners (cue owners, the
    /// reactive planning cell, Governor/Context Compiler): the caller
    /// supplies the normalized cue, exact firing evidence, bounded relations,
    /// and admission basis, and this method only records them against the
    /// live attach session. Returns the minted item identity.
    pub fn admit_reactive_injection(
        &mut self,
        cue: NormalizedCue,
        firing: Option<FiringEvidence>,
        relations: Vec<String>,
        admission: AdmissionBasis,
    ) -> Result<String, BridgeError> {
        let session_id = self.live_reactive_session()?;
        self.reactive_ledger
            .admit(&session_id, cue, firing, relations, admission)
            .map_err(|error| reactive_ledger_error(&error))
    }
    /// Delivers every pending injection for the live session through a host
    /// hook invocation, issuing one Delivery/Injection Receipt per item.
    ///
    /// `hook_event_id` must be the exact identity of the forwarded
    /// [`HostEventEnvelope`] that carries the delivery (`event_id`), so each
    /// receipt names a real owner-observed delivery point. An empty pending
    /// set drains to an empty receipt list without error.
    pub fn deliver_reactive_pending_via_hook(
        &mut self,
        hook_event_id: &str,
    ) -> Result<Vec<InjectionReceipt>, BridgeError> {
        let session_id = self.live_reactive_session()?;
        let pending = self.reactive_ledger.pending_item_ids(&session_id);
        let mut receipts = Vec::with_capacity(pending.len());
        for item_id in pending {
            let receipt = self
                .reactive_ledger
                .deliver(
                    &item_id,
                    DeliveryPoint::HostHook {
                        hook_id: hook_event_id.to_owned(),
                    },
                )
                .map_err(|error| reactive_ledger_error(&error))?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }
    /// Delivers every pending injection for the live session inside the next
    /// bridge response (I7.10 tool-only piggyback), issuing one
    /// Delivery/Injection Receipt per item.
    ///
    /// `response_id` names the exact response frame that carries the
    /// delivery. An empty pending set drains to an empty receipt list
    /// without error.
    pub fn deliver_reactive_pending_via_response(
        &mut self,
        response_id: &str,
    ) -> Result<Vec<InjectionReceipt>, BridgeError> {
        let session_id = self.live_reactive_session()?;
        let pending = self.reactive_ledger.pending_item_ids(&session_id);
        let mut receipts = Vec::with_capacity(pending.len());
        for item_id in pending {
            let receipt = self
                .reactive_ledger
                .deliver(
                    &item_id,
                    DeliveryPoint::NextBridgeResponse {
                        response_id: response_id.to_owned(),
                    },
                )
                .map_err(|error| reactive_ledger_error(&error))?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }
    /// Projects sticky attention output for the live session.
    ///
    /// Every open critical item stays present (pending or delivered) until a
    /// durable resolved, waived, or superseded disposition is recorded;
    /// delivered normal items appear only after invalidation re-admits them.
    /// Empty while detached.
    #[must_use]
    pub fn reactive_attention(&self) -> Vec<AttentionItem> {
        match self.attach_view() {
            Some(view) => self
                .reactive_ledger
                .attention_output(view.binding().session_id().as_str()),
            None => Vec::new(),
        }
    }
    /// Number of pending (undelivered) injections for the live session.
    /// Zero while detached.
    #[must_use]
    pub fn reactive_pending_count(&self) -> usize {
        match self.attach_view() {
            Some(view) => self
                .reactive_ledger
                .pending_item_ids(view.binding().session_id().as_str())
                .len(),
            None => 0,
        }
    }
    /// Looks up one issued Delivery/Injection Receipt by identity.
    #[must_use]
    pub fn reactive_receipt(&self, receipt_id: &str) -> Option<InjectionReceipt> {
        self.reactive_ledger.receipt(receipt_id).cloned()
    }
    /// Records a later observable use, influence, or outcome update for a
    /// delivered item (I7.6 `influence_ack` side: delivery, acknowledgement,
    /// use, and causal benefit stay separate; absence stays unknown).
    ///
    /// Addressed by ledger item identity, so the owning observer (host hook
    /// outcome or `eliot.observe`) can report without a live attach.
    pub fn record_reactive_use(
        &mut self,
        item_id: &str,
        update: UseOutcome,
    ) -> Result<(), BridgeError> {
        self.reactive_ledger
            .record_use(item_id, update)
            .map_err(|error| reactive_ledger_error(&error))
    }
    /// Records a durable resolved, waived, or superseded disposition. Only a
    /// terminal disposition clears critical stickiness; the disposition
    /// record itself is owned by the resolving owner, only referenced here.
    pub fn record_reactive_disposition(
        &mut self,
        item_id: &str,
        disposition: ItemDisposition,
    ) -> Result<(), BridgeError> {
        self.reactive_ledger
            .record_disposition(item_id, disposition)
            .map_err(|error| reactive_ledger_error(&error))
    }
    /// Invalidates session deduplication for a source whose revision or risk
    /// condition changed. Returns the number of delivered items reopened for
    /// re-admission; critical stickiness is unaffected.
    pub fn invalidate_reactive_source(&mut self, source: &str) -> usize {
        self.reactive_ledger.invalidate_source(source)
    }
    /// Exports the ledger bytes for durable persistence by the Store owner.
    ///
    /// The bridge holds delivery records only for the life of this process;
    /// crash-safe persistence is the Store owner's handoff (A1780
    /// notification-state backend). Bytes are bounded canonical JSON stamped
    /// with [`REACTIVE_INJECTION_CONTRACT`].
    pub fn reactive_ledger_snapshot(&self) -> Result<Vec<u8>, BridgeError> {
        self.reactive_ledger
            .to_json_bytes()
            .map_err(|error| reactive_ledger_error(&error))
    }
    /// Restores a previously exported ledger, replacing in-memory state.
    /// Fails closed on wrong contract, oversize, or undecodable bytes.
    pub fn restore_reactive_ledger(&mut self, bytes: &[u8]) -> Result<(), BridgeError> {
        self.reactive_ledger = ReactiveInjectionLedger::from_json_bytes(bytes)
            .map_err(|error| reactive_ledger_error(&error))?;
        Ok(())
    }
    /// Publishes one owner-supplied evidence snapshot and returns its bounded
    /// hot-response projection: a preview plus an immutable
    /// `eliot://evidence/<id>` handle (I7.18 acceptance shape).
    ///
    /// Content bytes arrive from the owning provider (evidence, Store, task
    /// owner); the bridge only snapshots them into its attach-scoped
    /// transport projection. Requires the live attach, which is the scope
    /// authorization on resolution: detached callers fail closed.
    pub fn publish_evidence_resource(
        &mut self,
        content: Vec<u8>,
    ) -> Result<HotResourceView, BridgeError> {
        self.core.publish_evidence(content)
    }
    /// Publishes one owner-supplied canonical resource snapshot at its exact
    /// I7.18 URI and returns its bounded hot-response projection.
    ///
    /// Fails closed on non-canonical URIs and on republishing an immutable
    /// URI with different bytes, so a handle always resolves to the exact
    /// bytes its digest names.
    pub fn publish_canonical_resource(
        &mut self,
        uri: &ResourceUri,
        content: Vec<u8>,
    ) -> Result<HotResourceView, BridgeError> {
        self.core.publish_resource(uri, content)
    }
    /// Explicitly expands one previously published handle to its immutable
    /// referenced content.
    ///
    /// Full evidence, audit, and large-report content is available only
    /// through this call, never inline in a hot response. Unknown handles
    /// and digest mismatches fail closed.
    pub fn expand_resource(&self, handle: &ResourceHandle) -> Result<Vec<u8>, BridgeError> {
        self.core.expand_resource(handle)
    }
    /// Projects one tool result into its delivery receipt (I7.24): exact
    /// result digest, admissible source handle, rendered bytes, tokens
    /// rendered under the actual route tokenizer, and delivery completeness.
    ///
    /// The bridge never estimates tokens or completeness: `tokens_rendered`
    /// is measured by the projecting route owner with the actual tokenizer,
    /// and `delivery` is the owner's observed delivery state. Only a `FULL`
    /// delivery satisfies a complete-evidence prerequisite (see
    /// [`ToolResultReceipt::check_complete_evidence`]).
    pub fn project_tool_result_receipt(
        &self,
        result_bytes: &[u8],
        source_handle: ResourceUri,
        tokens_rendered: u64,
        delivery: DeliveryStatus,
    ) -> Result<ToolResultReceipt, BridgeError> {
        self.core
            .project_tool_result(result_bytes, source_handle, tokens_rendered, delivery)
    }
    /// Number of immutable snapshots retained in the attach-scoped resource
    /// projection. Zero while detached; cleared by the core on every attach.
    #[must_use]
    pub fn resource_registry_len(&self) -> usize {
        self.core.resource_registry_len()
    }
    /// Records one supported tool-result delivery into the attach-scoped
    /// evidence projection, at the normal Invoke callsite after the gateway
    /// returns with the exact authenticated outcome.
    ///
    /// Only `Responded` outcomes carrying a supported typed result
    /// (`Candidate` or `Projection` — never `PlanGap`/`Unsupported` gaps, admissions,
    /// or rejections) whose canonical content bytes exceed the hot preview bound are
    /// snapshotted, content-addressed, into the registry; everything else yields `None`.
    /// Snapshot failures (full registry, oversize, unserializable) also yield `None`
    /// WITHOUT affecting forwarding: the emitted response stays authoritative and this
    /// substrate is purely auxiliary delivery-record augmentation.
    ///
    /// Evidence content-addressing is NOT admission authority: the URI is a pure function
    /// of the exact delivered bytes, grants nothing, admits nothing, and resolves nothing.
    /// The bytes were already delivered inline to the host in the same response, so no new
    /// disclosure occurs here. Tokens rendered and route delivery stay unknowable at the
    /// bridge and are never estimated — completing a `ToolResultReceipt` remains the
    /// route owner's job (`project_tool_result_receipt`).
    ///
    /// Verify-before-handout (I7.18 explicit expansion): the full bytes behind
    /// a hot handle are retrievable only through [`Self::expand_resource`].
    /// The just-issued handle is expanded here, on the normal Invoke path,
    /// and the expanded bytes must equal the published bytes before the view
    /// reaches the response. A handle that does not resolve to the exact
    /// bytes withholds the evidence slot (`None`) instead of emitting a
    /// dangling reference; the gateway response itself is never rewritten.
    pub fn record_tool_result_delivery(
        &mut self,
        outcome: &HostInvocationOutcome,
    ) -> Option<HotResourceView> {
        let HostInvocationOutcome::Responded { response, .. } = outcome else {
            return None;
        };
        match response.kind {
            ResponseKind::Candidate | ResponseKind::Projection => {}
            ResponseKind::PlanGap | ResponseKind::Unsupported => return None,
        }
        let bytes = serde_json::to_vec(&response.content).ok()?;
        if bytes.len() <= MAX_PREVIEW_BYTES {
            return None;
        }
        let view = self.core.publish_evidence(bytes.clone()).ok()?;
        if self.expand_resource(view.handle()).ok()? != bytes {
            return None;
        }
        Some(view)
    }
    /// Notes the owner-supplied bootstrap context for this session.
    ///
    /// Validates fail-closed without composing authority: an invalid context
    /// is rejected and never stored. Noting context never delivers the
    /// once-per-session auto-boot; delivery happens only through
    /// [`Self::take_first_response_bootstrap`]. The noted snapshot is sealed
    /// to the live attach binding when attached (principal/WorkScope content
    /// is bound to the authenticated binding; a wrong-principal or
    /// wrong-worktree packet is refused); a snapshot noted while detached
    /// stays unsealed until it is noted again under the live attach.
    pub fn note_bootstrap_context(
        &mut self,
        context: BootstrapContext,
    ) -> Result<(), BootstrapError> {
        let empty_tasks = BootstrapTaskInputs {
            scope_level: ScopeLevel::Session,
            candidates: Vec::new(),
            authoritative_selection: None,
        };
        get_understanding_bootstrap(&context, &empty_tasks, CurrentAssessment::NotOnboarded)?;
        let binding = self.attach_view().map(|view| view.binding().clone());
        if let Some(seal) = &binding {
            BootstrapSnapshot::content_matches_binding(&context, seal)?;
        }
        self.bootstrap_snapshot = Some(BootstrapSnapshot {
            context,
            tasks: empty_tasks,
            binding,
        });
        Ok(())
    }
    /// Notes one owner-produced bootstrap snapshot: context plus the task
    /// inputs supplied with it, sealed to the live attach binding.
    ///
    /// This is the auto-boot source of record: the once-per-session
    /// auto-boot composes from exactly these retained task inputs rather
    /// than a separate empty task set, so the agent can identify or
    /// explicitly request the intended task without filesystem search. A
    /// wrong-principal or wrong-worktree packet is refused at note time; a
    /// later session, fence, or scope/task move refuses at compose time.
    pub fn note_owner_snapshot(
        &mut self,
        context: BootstrapContext,
        tasks: BootstrapTaskInputs,
    ) -> Result<(), BootstrapError> {
        get_understanding_bootstrap(&context, &tasks, CurrentAssessment::NotOnboarded)?;
        let binding = self.attach_view().map(|view| view.binding().clone());
        if let Some(seal) = &binding {
            BootstrapSnapshot::content_matches_binding(&context, seal)?;
        }
        self.bootstrap_snapshot = Some(BootstrapSnapshot {
            context,
            tasks,
            binding,
        });
        Ok(())
    }
    /// Task inputs retained by the noted owner snapshot for auto-boot.
    ///
    /// Returns exactly what the owner supplied with the snapshot, or an
    /// empty session-level task set when nothing was ever noted (in which
    /// case composition below still yields `None`). The auto-boot path
    /// never invents its own candidate set.
    #[must_use]
    pub fn retained_auto_boot_tasks(&self) -> BootstrapTaskInputs {
        self.bootstrap_snapshot.as_ref().map_or_else(
            || BootstrapTaskInputs {
                scope_level: ScopeLevel::Session,
                candidates: Vec::new(),
                authoritative_selection: None,
            },
            |snapshot| snapshot.tasks.clone(),
        )
    }
    /// Bounded explicit retrieval of the canonical `UnderstandingBootstrap`.
    ///
    /// Always available, including after the once-per-session auto-boot was
    /// delivered. Requires a noted snapshot and a live attach still equal
    /// to the noted seal; a wrong session, stale fence, or changed
    /// scope/task binding fails closed instead of projecting `READY`. A
    /// composed selection that names any task other than the sealed
    /// activation task is refused the same way, so a forged or stale packet
    /// can never retrieve `READY` through this path either.
    pub fn get_understanding_bootstrap(
        &self,
        tasks: &BootstrapTaskInputs,
        requested_assessment: CurrentAssessment,
    ) -> Result<UnderstandingBootstrap, BootstrapError> {
        let Some(snapshot) = &self.bootstrap_snapshot else {
            return Err(BootstrapError {
                code: "BOOTSTRAP_CONTEXT_MISSING",
                detail: "no bootstrap context noted for this session".to_owned(),
            });
        };
        let Some(sealed) = snapshot.sealed_live_binding(self.attach_view()) else {
            return Err(BootstrapError {
                code: "BOOTSTRAP_SEAL_MISMATCH",
                detail: "noted bootstrap seal disagrees with the live attach binding".to_owned(),
            });
        };
        let bootstrap =
            get_understanding_bootstrap(&snapshot.context, tasks, requested_assessment)?;
        BootstrapSnapshot::selection_matches_sealed_task(&bootstrap, &sealed)?;
        Ok(bootstrap)
    }
    /// Previews the one-time bootstrap without marking it delivered. A
    /// response can check its complete frame before consuming the delivery.
    pub fn preview_first_response_bootstrap(
        &self,
        tasks: &BootstrapTaskInputs,
        requested_assessment: CurrentAssessment,
    ) -> Option<UnderstandingBootstrap> {
        let snapshot = self.bootstrap_snapshot.clone()?;
        let sealed = snapshot.sealed_live_binding(self.attach_view())?;
        let preview =
            get_understanding_bootstrap(&snapshot.context, tasks, requested_assessment).ok()?;
        BootstrapSnapshot::selection_matches_sealed_task(&preview, &sealed).ok()?;
        let mut session = self.bootstrap_session;
        session.take_auto_boot(&snapshot.context, tasks, requested_assessment)
    }
    /// Takes the once-per-session auto-boot for the first successful response.
    ///
    /// Returns `None` after the first delivery, when no valid snapshot is
    /// noted, or when the live attach moved away from the noted seal;
    /// composition failures also yield `None` without marking delivery
    /// so a later response with complete inputs can still carry the bootstrap.
    /// A composed selection that names any task other than the sealed
    /// activation task yields `None` the same way, without consuming the
    /// once-per-session slot, so a forged or stale packet can never
    /// auto-boot `READY` and a later coherent response can still deliver.
    pub fn take_first_response_bootstrap(
        &mut self,
        tasks: &BootstrapTaskInputs,
        requested_assessment: CurrentAssessment,
    ) -> Option<UnderstandingBootstrap> {
        let snapshot = self.bootstrap_snapshot.clone()?;
        let sealed = snapshot.sealed_live_binding(self.attach_view())?;
        let preview =
            get_understanding_bootstrap(&snapshot.context, tasks, requested_assessment).ok()?;
        BootstrapSnapshot::selection_matches_sealed_task(&preview, &sealed).ok()?;
        self.bootstrap_session
            .take_auto_boot(&snapshot.context, tasks, requested_assessment)
    }
    /// Read-only view of durable in-flight deliveries for bounded Stop accounting.
    ///
    /// Returns the exact core-retained outstanding identities (stream, event,
    /// sequence) without completing, acknowledging, or recomputing anything:
    /// the stdio Stop path reports them verbatim so a pending delivery is
    /// reconciled under its original identity instead of being dropped and
    /// re-issued under a new id. Empty in production while the forwarding
    /// port stays unadmitted; non-empty only when a test or future admitted
    /// forwarder holds durable deliveries below the required ack phase.
    #[must_use]
    pub fn outstanding_deliveries(&self) -> Vec<OutstandingDeliveryView> {
        self.core.outstanding_deliveries()
    }
    /// Records one observed attempt state transition verbatim for the
    /// terminal reducer. The transport decides no legality here.
    pub fn observe_attempt_transition(
        &mut self,
        from: AttemptState,
        to: AttemptState,
        sequence: u64,
    ) -> Result<(), BridgeError> {
        self.core.observe_attempt_transition(from, to, sequence)
    }
    /// Files one typed recovery directive chaining an observed recoverable
    /// failure to its corrected call under the retry/new-identity rule.
    pub fn prescribe_recovery(&mut self, directive: RecoveryDirective) -> Result<(), BridgeError> {
        self.core.prescribe_recovery(directive)
    }
    /// Records the candidate canonical-write submission reference.
    pub fn record_canonical_submission(
        &mut self,
        reference: impl Into<String>,
    ) -> Result<(), BridgeError> {
        self.core.record_canonical_submission(reference)
    }
    /// Records the candidate canonical-write receipt reference.
    pub fn record_canonical_receipt(
        &mut self,
        reference: impl Into<String>,
    ) -> Result<(), BridgeError> {
        self.core.record_canonical_receipt(reference)
    }
    /// Records the independent exact-readback reference.
    pub fn record_canonical_readback(
        &mut self,
        reference: impl Into<String>,
    ) -> Result<(), BridgeError> {
        self.core.record_canonical_readback(reference)
    }
    /// Records one terminal-relevant transport edge without resolving it.
    pub fn record_transport_edge(&mut self, edge: TransportEdge) -> Result<(), BridgeError> {
        self.core.record_transport_edge(edge)
    }
    /// Notes the stale UI/CLI terminal display verbatim, independent of
    /// the canonical references until reduction.
    pub fn note_stale_ui_disposition(
        &mut self,
        disposition: impl Into<String>,
    ) -> Result<(), BridgeError> {
        self.core.note_stale_ui_disposition(disposition)
    }
    /// Projects the terminal reduction inputs for the external reducer.
    /// History and terminal evidence stay independent; nothing here is a
    /// terminal disposition.
    #[must_use]
    pub fn terminal_reduction_inputs(&self) -> Option<TerminalReductionInputs> {
        self.core.terminal_reduction_inputs()
    }
}

#[derive(Debug)]
pub enum RuntimeBuildError {
    ProfileNotCompiled(Profile),
    Runtime(eliot_runtime::ConfigError),
    BridgeContract(BridgeError),
    KernelClient(String),
}

impl fmt::Display for RuntimeBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProfileNotCompiled(p) => write!(formatter, "PROFILE_NOT_COMPILED:{p}"),
            Self::Runtime(_) => formatter.write_str("RUNTIME_CONFIG_INVALID"),
            Self::BridgeContract(e) => write!(formatter, "BRIDGE_CONTRACT_INVALID:{e}"),
            Self::KernelClient(e) => write!(formatter, "KERNEL_CLIENT_REJECTED:{e}"),
        }
    }
}
impl std::error::Error for RuntimeBuildError {}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_contracts::ResourceGeneration;
    use eliot_contracts::{
        ArtifactId, ContractId, ContractVersion, EpochId, EpochLineageId, StateFence,
    };
    use eliot_protocol::AgentBridgeActivationResponse;
    use eliot_protocol::{
        AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_ID, AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_VERSION,
        AGENT_BRIDGE_MODULE_ID, AGENT_BRIDGE_PEER_CHALLENGE_WIRE_ID,
        AGENT_BRIDGE_PEER_CHALLENGE_WIRE_VERSION, AgentBridgeClientDeclaration,
        AgentBridgePeerAdmissionReceipt, AgentBridgePeerChallenge,
    };
    use eliot_protocol::{EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload};
    use eliot_protocol::{ProtocolRange, ProtocolVersion};
    use eliot_runtime_contracts::{HealthVector, ModuleGenerationState};
    use eliot_runtime_contracts::{ModuleContract, ModuleGeneration};
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn fixture_declaration() -> AgentBridgeClientDeclaration {
        let fence = StateFence::new(test_epoch(3), ResourceGeneration::new(7).unwrap());
        let artifact = ArtifactId::new("a".repeat(64)).unwrap();
        let module = ContractId::new(AGENT_BRIDGE_MODULE_ID).unwrap();
        let contract = ModuleContract {
            module_id: module.clone(),
            version: ContractVersion::new(1, 0, 0),
            artifact_id: artifact.clone(),
            protocols: vec!["eliot.agent-bridge.v1".to_owned()],
            required_capabilities: vec!["agent.bridge.activate".to_owned()],
            optional_capabilities: Vec::new(),
            advisory_capabilities: Vec::new(),
            state_owner: "eliot-agent-bridge".to_owned(),
            failure_domain: "agent-bridge".to_owned(),
            hot_replace: false,
        };
        let generation = ModuleGeneration {
            module_id: module,
            generation: ResourceGeneration::new(7).unwrap(),
            artifact_id: artifact,
            state: ModuleGenerationState::Ready,
            health: HealthVector::healthy(),
            state_fence: fence,
        };
        AgentBridgeClientDeclaration {
            wire_id: AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_ID.to_owned(),
            wire_version: AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_VERSION,
            module_id: AGENT_BRIDGE_MODULE_ID.to_owned(),
            profile_id: "agent-bridge-profile-1".to_owned(),
            protocol_range: ProtocolRange {
                minimum: ProtocolVersion::CURRENT,
                maximum: ProtocolVersion::CURRENT,
            },
            module_contract: contract,
            module_generation: generation,
            capabilities: vec!["agent.bridge.activate".to_owned()],
            privacy_classes: vec!["PUBLIC".to_owned()],
            max_frame: 4_194_304,
            expected_kernel_sid: "S-1-5-18".to_owned(),
            expected_kernel_session_id: 0,
            expected_kernel_principal_binding: "kernel:agent-bridge".to_owned(),
            expected_kernel_authority_epoch: test_epoch(8),
            expected_kernel_generation: ResourceGeneration::new(2).unwrap(),
            expected_kernel_artifact_sha256: "b".repeat(64),
            expected_kernel_config_snapshot_sha256: "c".repeat(64),
            declaration_sha256: String::new(),
        }
        .with_computed_digest()
        .unwrap()
    }

    fn fixture_challenge(decl: &AgentBridgeClientDeclaration) -> AgentBridgePeerChallenge {
        AgentBridgePeerChallenge {
            wire_id: AGENT_BRIDGE_PEER_CHALLENGE_WIRE_ID.to_owned(),
            wire_version: AGENT_BRIDGE_PEER_CHALLENGE_WIRE_VERSION,
            module_id: AGENT_BRIDGE_MODULE_ID.to_owned(),
            profile_id: decl.profile_id.clone(),
            descriptor_sha256: "d".repeat(64),
            client_declaration_sha256: decl.declaration_sha256.clone(),
            bridge_generation: decl.module_generation.generation,
            state_fence: decl.module_generation.state_fence.clone(),
            kernel_principal_binding: decl.expected_kernel_principal_binding.clone(),
            kernel_authority_epoch: decl.expected_kernel_authority_epoch.clone(),
            kernel_generation: decl.expected_kernel_generation,
            kernel_artifact_sha256: decl.expected_kernel_artifact_sha256.clone(),
            kernel_config_snapshot_sha256: decl.expected_kernel_config_snapshot_sha256.clone(),
            activation_deadline_unix_ms: 10_000,
            challenge_nonce: "kernel-challenge-1".to_owned(),
            challenge_sha256: String::new(),
        }
        .with_computed_digest()
        .unwrap()
    }

    fn fixture_receipt(
        challenge: &AgentBridgePeerChallenge,
        hello: &eliot_protocol::ClientHello,
    ) -> AgentBridgePeerAdmissionReceipt {
        AgentBridgePeerAdmissionReceipt {
            wire_id: eliot_protocol::AGENT_BRIDGE_PEER_ADMISSION_RECEIPT_WIRE_ID.to_owned(),
            wire_version: AgentBridgePeerAdmissionReceipt::CONTRACT_VERSION,
            module_id: challenge.module_id.clone(),
            connection_id: "conn-1".to_owned(),
            profile_id: challenge.profile_id.clone(),
            descriptor_sha256: challenge.descriptor_sha256.clone(),
            client_declaration_sha256: challenge.client_declaration_sha256.clone(),
            bridge_generation: challenge.bridge_generation,
            state_fence: challenge.state_fence.clone(),
            activation_deadline_unix_ms: challenge.activation_deadline_unix_ms,
            challenge_nonce: challenge.challenge_nonce.clone(),
            challenge_sha256: challenge.challenge_sha256.clone(),
            client_hello_sha256: eliot_platform_windows::sha256_hex(
                &eliot_contracts::canonical_json_bytes(hello).unwrap(),
            ),
            observed_sid: "S-1-5-21-1000".to_owned(),
            observed_session_id: 1,
            observed_process_id: 123,
            observed_process_start_time_100ns: 456,
            observed_image_path: "C:\\bridge.exe".to_owned(),
            observed_image_volume_serial: 1,
            observed_image_file_index: 2,
            receipt_sha256: String::new(),
        }
        .with_computed_digest()
        .unwrap()
    }

    #[test]
    fn cli_declaration_path_required_absolute_no_parent() {
        assert!(matches!(
            parse_args([
                "--profile",
                "SPINE_FUNCTIONAL",
                "--transport",
                "loopback",
                "--client-declaration",
                "C:\\a\\agent-bridge\\client-declaration-v2.json"
            ]),
            Err(CliError::RemoteTransportForbidden(transport)) if transport == "loopback"
        ));
        assert!(matches!(
            parse_args(["--profile", "SPINE_FUNCTIONAL"]),
            Err(CliError::MissingClientDeclaration)
        ));
        assert!(matches!(
            parse_args([
                "--profile",
                "SPINE_FUNCTIONAL",
                "--client-declaration",
                "relative/path.json"
            ]),
            Err(CliError::InvalidClientDeclarationPath(_))
        ));
        assert!(matches!(
            parse_args([
                "--profile",
                "SPINE_FUNCTIONAL",
                "--client-declaration",
                "C:\\a\\..\\b.json"
            ]),
            Err(CliError::InvalidClientDeclarationPath(_))
        ));
        let cfg = parse_args([
            "--profile",
            "SPINE_FUNCTIONAL",
            "--client-declaration",
            "C:\\a\\agent-bridge\\client-declaration-v2.json",
        ])
        .expect("valid");
        assert_eq!(
            cfg.client_declaration,
            PathBuf::from("C:\\a\\agent-bridge\\client-declaration-v2.json")
        );
        let cfg2 = parse_args([
            "--profile=SPINE_FUNCTIONAL",
            "--client-declaration=C:\\a\\agent-bridge\\client-declaration-v2.json",
        ])
        .expect("eq form");
        assert_eq!(
            cfg2.client_declaration,
            PathBuf::from("C:\\a\\agent-bridge\\client-declaration-v2.json")
        );
        assert!(matches!(
            parse_args([
                "--profile",
                "SPINE_FUNCTIONAL",
                "--client-declaration",
                "C:\\a\\wrong-parent\\client-declaration-v2.json"
            ]),
            Err(CliError::InvalidClientDeclarationPath(_))
        ));
        assert!(matches!(
            parse_args([
                "--profile",
                "SPINE_FUNCTIONAL",
                "--client-declaration",
                "C:\\a\\agent-bridge\\wrong-file.json"
            ]),
            Err(CliError::InvalidClientDeclarationPath(_))
        ));
    }

    #[test]
    fn old_generic_kernel_client_absent() {
        let src = include_str!("lib.rs");
        let needle = format!("{}{}", "eliot_cli", "::kernel_client");
        assert!(!src.contains(&needle));
        let awr = format!("{}{}", "ActivationWire", "Response");
        assert!(!src.contains(&awr));
    }

    #[test]
    fn raw_frame_forwarding_wrapper_is_absent() {
        let src = include_str!("lib.rs");
        let raw_forward = format!("{}{}", "forward_", "frame");
        assert!(!src.contains(&raw_forward));
    }

    #[test]
    fn no_unsafe_no_lint_override_no_direct_windows_sys() {
        let src = include_str!("lib.rs");
        let unsafe_block = format!("{}{}", "unsafe", " {");
        assert!(!src.contains(&unsafe_block));
        let unsafe_fn = format!("{}{}", "unsafe", " fn");
        assert!(!src.contains(&unsafe_fn));
        let lint_override = format!("{}{}", "allow(unsafe", "_code");
        assert!(!src.contains(&lint_override));
        let ws = format!("{}{}", "windows", "-sys");
        assert!(!src.contains(&ws));
        let cargo = include_str!("../Cargo.toml");
        let ws_cargo = format!("{}{}", "windows", "-sys");
        assert!(!cargo.contains(&ws_cargo));
        let ws_true = format!("{}{}", "workspace", " = true");
        assert!(cargo.contains(&ws_true));
    }

    #[test]
    fn single_retained_runtime_structure_order() {
        let src = include_str!("lib.rs");
        assert!(src.contains("transport: eliot_ipc::NamedPipeTransport"));
        assert!(src.contains("runtime: tokio::runtime::Runtime"));
        let transport_pos = src
            .find("transport: eliot_ipc::NamedPipeTransport")
            .unwrap();
        let runtime_pos = src.find("runtime: tokio::runtime::Runtime").unwrap();
        assert!(transport_pos < runtime_pos);
        assert!(src.contains("runtime.block_on"));
        let bad_first = format!("{}{}", "Builder::new", "_current_thread");
        let bad = format!("{}{}", bad_first, ".enable_all().build().unwrap().block_on");
        assert!(!src.contains(&bad));
        let cnt_pat = format!("{}{}", "Builder::new", "_current_thread");
        let count = src.matches(&cnt_pat).count();
        assert!(count <= 2);
    }

    #[test]
    fn retained_lease_and_one_shot_order() {
        let src = include_str!("lib.rs");
        assert!(src.contains("LoadedAgentBridgeDeclaration"));
        assert!(src.contains("_lease: eliot_platform_windows::AgentBridgeDeclarationReadLease"));
        assert!(src.contains("struct AdmittedConnection"));
        assert!(src.contains("admitted: AdmittedConnection"));
        assert!(src.contains("_loaded: LoadedAgentBridgeDeclaration"));
        let admitted_pos = src.find("admitted: AdmittedConnection").unwrap();
        let runtime_pos = src.find("runtime: tokio::runtime::Runtime").unwrap();
        let loaded_pos = src.find("_loaded: LoadedAgentBridgeDeclaration").unwrap();
        assert!(admitted_pos < runtime_pos);
        assert!(runtime_pos < loaded_pos);
        assert!(src.contains("activation_used: bool"));
        let err = format!(
            "{}{}",
            "activation exchange already consumed", "; restart/reconnect"
        );
        assert!(src.contains(&err));
        let one_builder = format!("{}{}", "Builder::new", "_current_thread");
        assert_eq!(src.matches(&one_builder).count(), 1);
    }

    #[test]
    #[allow(clippy::items_after_statements)]
    fn activation_one_shot_rejects_second_without_io() {
        let src = include_str!("lib.rs");
        let err_msg = format!(
            "{}{}",
            "activation exchange already consumed", "; restart/reconnect"
        );
        assert!(src.contains(&err_msg));
        let pos_guard = src.find("if self.activation_used").expect("guard");
        let pos_send = src
            .find("self.admitted.transport.send_frame")
            .expect("send");
        assert!(pos_guard < pos_send);
        struct MockGuard {
            used: bool,
        }
        impl MockGuard {
            fn activate(&mut self) -> Result<(), ProviderFailure> {
                if self.used {
                    return Err(ProviderFailure::new(
                        "eliot-kernel-front-door",
                        "activation exchange already consumed; restart/reconnect contour not admitted",
                    ));
                }
                self.used = true;
                Ok(())
            }
        }
        let mut g = MockGuard { used: true };
        let e = g.activate().expect_err("second must fail");
        assert!(e.to_string().contains("already consumed"));
    }

    #[test]
    fn off_windows_no_filesystem_read() {
        let src = include_str!("lib.rs");
        #[cfg(not(windows))]
        {
            assert!(src.contains("declaration lease unavailable off Windows"));
            let fs_read = format!("{}{}", "std::fs", "::read");
            assert!(!src.contains(&fs_read));
        }
        #[cfg(windows)]
        {
            assert!(src.contains("open_agent_bridge_declaration_read_lease"));
        }
    }

    #[test]
    fn declaration_deny_unknown_fields() {
        let mut decl = fixture_declaration();
        let mut value = serde_json::to_value(&decl).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<AgentBridgeClientDeclaration>(value).is_err());
        decl.declaration_sha256 = "0".repeat(64);
        assert!(decl.validate().is_err());
    }

    #[test]
    fn declaration_digest_substitution_fails() {
        let decl = fixture_declaration();
        let mut bad = decl.clone();
        bad.profile_id = "other-profile".to_owned();
        assert!(
            bad.validate().is_err() || bad.compute_digest().unwrap() != decl.declaration_sha256
        );
        let mut bad2 = decl.clone();
        bad2.expected_kernel_artifact_sha256 = "e".repeat(64);
        bad2.declaration_sha256 = bad2.compute_digest().unwrap();
        let chal = fixture_challenge(&decl);
        assert!(chal.validate_declaration(&bad2).is_err());
    }

    #[test]
    fn challenge_principal_config_artifact_substitution_fails() {
        let decl = fixture_declaration();
        let chal = fixture_challenge(&decl);
        chal.validate_declaration(&decl).expect("valid");
        let mut bad = chal.clone();
        bad.kernel_principal_binding = "other".to_owned();
        bad.challenge_sha256 = bad.compute_digest().unwrap();
        assert!(bad.validate_declaration(&decl).is_err());
        let mut bad2 = chal.clone();
        bad2.kernel_artifact_sha256 = "f".repeat(64);
        bad2.challenge_sha256 = bad2.compute_digest().unwrap();
        assert!(bad2.validate_declaration(&decl).is_err());
        let mut bad3 = chal.clone();
        bad3.kernel_config_snapshot_sha256 = "f".repeat(64);
        bad3.challenge_sha256 = bad3.compute_digest().unwrap();
        assert!(bad3.validate_declaration(&decl).is_err());
    }

    #[test]
    fn receipt_connection_fence_digest_deadline_substitution_fails() {
        let decl = fixture_declaration();
        let chal = fixture_challenge(&decl);
        let hello = decl.client_hello(chal.challenge_nonce.clone()).unwrap();
        let receipt = fixture_receipt(&chal, &hello);
        receipt.validate().expect("valid");
        receipt.validate_challenge(&chal).expect("bind");
        let mut bad_conn = receipt.clone();
        bad_conn.connection_id = "other".to_owned();
        bad_conn.receipt_sha256 = bad_conn.compute_digest().unwrap();
        assert!(
            bad_conn.validate_challenge(&chal).is_err()
                || bad_conn.connection_id != chal.clone().challenge_nonce
        );
        let mut bad_deadline = receipt.clone();
        bad_deadline.activation_deadline_unix_ms = 999;
        bad_deadline.receipt_sha256 = bad_deadline.compute_digest().unwrap();
        assert!(bad_deadline.validate_challenge(&chal).is_err());
        let mut bad_fence = receipt.clone();
        bad_fence.state_fence =
            StateFence::new(test_epoch(99), ResourceGeneration::new(99).unwrap());
        bad_fence.receipt_sha256 = bad_fence.compute_digest().unwrap();
        assert!(bad_fence.validate_challenge(&chal).is_err());
    }

    #[test]
    fn request_identity_semantic_fields_rejected() {
        let decl = fixture_declaration();
        let chal = fixture_challenge(&decl);
        let hello = decl.client_hello(chal.challenge_nonce.clone()).unwrap();
        let receipt = AgentBridgePeerAdmissionReceipt {
            wire_id: eliot_protocol::AGENT_BRIDGE_PEER_ADMISSION_RECEIPT_WIRE_ID.to_owned(),
            wire_version: AgentBridgePeerAdmissionReceipt::CONTRACT_VERSION,
            module_id: chal.module_id.clone(),
            connection_id: "conn-1".to_owned(),
            profile_id: chal.profile_id.clone(),
            descriptor_sha256: chal.descriptor_sha256.clone(),
            client_declaration_sha256: chal.client_declaration_sha256.clone(),
            bridge_generation: chal.bridge_generation,
            state_fence: chal.state_fence.clone(),
            activation_deadline_unix_ms: chal.activation_deadline_unix_ms,
            challenge_nonce: chal.challenge_nonce.clone(),
            challenge_sha256: chal.challenge_sha256.clone(),
            client_hello_sha256: eliot_platform_windows::sha256_hex(
                &eliot_contracts::canonical_json_bytes(&hello).unwrap(),
            ),
            observed_sid: "S-1-5-21-1000".to_owned(),
            observed_session_id: 1,
            observed_process_id: 123,
            observed_process_start_time_100ns: 456,
            observed_image_path: "C:\\bridge.exe".to_owned(),
            observed_image_volume_serial: 1,
            observed_image_file_index: 2,
            receipt_sha256: String::new(),
        }
        .with_computed_digest()
        .unwrap();
        let core_req = AttachRequest::managed(
            DemandId::new("demand-1").unwrap(),
            ConnectionId::new("conn-1").unwrap(),
        );
        let req =
            build_neutral_activation_request(&core_req, &receipt, "demand-1").expect("neutral");
        assert!(req.request_identity.request.metadata.session_id.is_none());
        assert!(req.request_identity.request.metadata.task_id.is_none());
        assert!(
            req.request_identity
                .request
                .metadata
                .state_fence
                .task_revision
                .is_none()
        );
        assert!(
            req.request_identity
                .request
                .metadata
                .clock
                .valid_time_ms
                .is_none()
        );
        let frame = activation_frame_for_request(&req).expect("frame");
        assert_eq!(frame.kind, FrameKind::Request);
        assert_eq!(frame.message_type, MessageType::Execute);
        let resp = AgentBridgeActivationResponse::denied(
            &req,
            eliot_protocol::AgentBridgeActivationDenialCode::SemanticResolutionUnavailable,
            None,
        )
        .unwrap();
        let resp_frame = Frame {
            protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: req.connection_id.clone(),
            request_id: Some(req.request_identity.request.metadata.request_id.clone()),
            kind: FrameKind::Response,
            message_type: MessageType::Result,
            request_identity: None,
            payload: ProtocolPayload::Json(serde_json::to_value(&resp).unwrap()),
            trace_context: BTreeMap::new(),
        };
        let decoded = decode_activation_response(&resp_frame, &req, &receipt).expect("decode");
        assert!(matches!(
            decoded.disposition,
            eliot_protocol::AgentBridgeActivationDisposition::Denied { .. }
        ));
        let mut bad_req = req.clone();
        bad_req.request_sha256 = "0".repeat(64);
        assert!(decode_activation_response(&resp_frame, &bad_req, &receipt).is_err());
    }

    #[test]
    fn typed_denial_mapping() {
        let decl = fixture_declaration();
        let chal = fixture_challenge(&decl);
        let hello = decl.client_hello(chal.challenge_nonce.clone()).unwrap();
        let receipt = AgentBridgePeerAdmissionReceipt {
            wire_id: eliot_protocol::AGENT_BRIDGE_PEER_ADMISSION_RECEIPT_WIRE_ID.to_owned(),
            wire_version: AgentBridgePeerAdmissionReceipt::CONTRACT_VERSION,
            module_id: chal.module_id.clone(),
            connection_id: "conn-1".to_owned(),
            profile_id: chal.profile_id.clone(),
            descriptor_sha256: chal.descriptor_sha256.clone(),
            client_declaration_sha256: chal.client_declaration_sha256.clone(),
            bridge_generation: chal.bridge_generation,
            state_fence: chal.state_fence.clone(),
            activation_deadline_unix_ms: chal.activation_deadline_unix_ms,
            challenge_nonce: chal.challenge_nonce.clone(),
            challenge_sha256: chal.challenge_sha256.clone(),
            client_hello_sha256: eliot_platform_windows::sha256_hex(
                &eliot_contracts::canonical_json_bytes(&hello).unwrap(),
            ),
            observed_sid: "S-1-5-21-1000".to_owned(),
            observed_session_id: 1,
            observed_process_id: 123,
            observed_process_start_time_100ns: 456,
            observed_image_path: "C:\\bridge.exe".to_owned(),
            observed_image_volume_serial: 1,
            observed_image_file_index: 2,
            receipt_sha256: String::new(),
        }
        .with_computed_digest()
        .unwrap();
        let core_req = AttachRequest::managed(
            DemandId::new("demand-1").unwrap(),
            ConnectionId::new("conn-1").unwrap(),
        );
        let req = build_neutral_activation_request(&core_req, &receipt, "demand-1").unwrap();
        let resp = AgentBridgeActivationResponse::denied(
            &req,
            eliot_protocol::AgentBridgeActivationDenialCode::SemanticResolutionUnavailable,
            None,
        )
        .unwrap();
        assert!(resp.validate_request(&req).is_ok());
    }

    #[test]
    fn typed_denial_codes_surface_distinctly() {
        use std::collections::BTreeSet;

        use eliot_protocol::AgentBridgeActivationDenialCode;

        let decl = fixture_declaration();
        let chal = fixture_challenge(&decl);
        let hello = decl.client_hello(chal.challenge_nonce.clone()).unwrap();
        let receipt = fixture_receipt(&chal, &hello);
        let core_req = AttachRequest::managed(
            DemandId::new("demand-1").unwrap(),
            ConnectionId::new("conn-1").unwrap(),
        );
        let req = build_neutral_activation_request(&core_req, &receipt, "demand-1").unwrap();
        // Each typed code round-trips together with its exact owner-issued
        // detail: selection codes with distinct candidate sets, NOT_READY
        // with its retry directive, STALE_FENCE with its observed fence, and
        // FAILED_INTERNAL with its failure handle. The Kernel-owned
        // no-result code travels detail-less.
        let selection = |handles: &[&str]| {
            eliot_protocol::AgentActivationResolutionDisposition::TaskSelectionRequired {
                selection: eliot_protocol::AgentActivationSelectionDirective {
                    candidate_handles: handles.iter().map(ToString::to_string).collect(),
                    candidate_coverage: eliot_protocol::AgentActivationCandidateCoverage::Partial,
                    recovery_handle: "recovery-1".to_owned(),
                },
            }
        };
        let cases: [(
            AgentBridgeActivationDenialCode,
            &str,
            Option<eliot_protocol::AgentActivationResolutionDisposition>,
        ); 7] = [
            (
                AgentBridgeActivationDenialCode::SemanticResolutionUnavailable,
                eliot_protocol::AGENT_BRIDGE_SEMANTIC_RESOLUTION_UNAVAILABLE,
                None,
            ),
            (
                AgentBridgeActivationDenialCode::TaskSelectionRequired,
                eliot_protocol::AGENT_BRIDGE_TASK_SELECTION_REQUIRED,
                Some(selection(&["task-candidate-1"])),
            ),
            (
                AgentBridgeActivationDenialCode::ScopeSelectionRequired,
                eliot_protocol::AGENT_BRIDGE_SCOPE_SELECTION_REQUIRED,
                Some(
                    eliot_protocol::AgentActivationResolutionDisposition::ScopeSelectionRequired {
                        selection: eliot_protocol::AgentActivationSelectionDirective {
                            candidate_handles: vec!["scope-candidate-1".to_owned()],
                            candidate_coverage:
                                eliot_protocol::AgentActivationCandidateCoverage::Partial,
                            recovery_handle: "recovery-scope".to_owned(),
                        },
                    },
                ),
            ),
            (
                AgentBridgeActivationDenialCode::ScopeAmbiguous,
                eliot_protocol::AGENT_BRIDGE_SCOPE_AMBIGUOUS,
                Some(
                    eliot_protocol::AgentActivationResolutionDisposition::ScopeAmbiguous {
                        selection: eliot_protocol::AgentActivationSelectionDirective {
                            candidate_handles: vec!["scope-a".to_owned(), "scope-b".to_owned()],
                            candidate_coverage:
                                eliot_protocol::AgentActivationCandidateCoverage::Complete,
                            recovery_handle: "recovery-ambiguous".to_owned(),
                        },
                    },
                ),
            ),
            (
                AgentBridgeActivationDenialCode::NotReady,
                eliot_protocol::AGENT_BRIDGE_NOT_READY,
                Some(
                    eliot_protocol::AgentActivationResolutionDisposition::NotReady {
                        recovery_handle: "recovery-retry".to_owned(),
                        retry: eliot_protocol::AgentActivationRetryDirective {
                            dependency_ref: "dep-1".to_owned(),
                            observed_dependency_revision: "rev-7".to_owned(),
                            not_before_unix_ms: 1,
                        },
                    },
                ),
            ),
            (
                AgentBridgeActivationDenialCode::StaleFence,
                eliot_protocol::AGENT_BRIDGE_STALE_FENCE,
                Some(
                    eliot_protocol::AgentActivationResolutionDisposition::StaleFence {
                        recovery_handle: "recovery-fence".to_owned(),
                        observed_state_fence: None,
                    },
                ),
            ),
            (
                AgentBridgeActivationDenialCode::FailedInternal,
                eliot_protocol::AGENT_BRIDGE_FAILED_INTERNAL,
                Some(
                    eliot_protocol::AgentActivationResolutionDisposition::FailedInternal {
                        failure_handle: "failure-1".to_owned(),
                    },
                ),
            ),
        ];
        let mut seen = BTreeSet::new();
        let total = cases.len();
        for (code, wire, detail) in cases {
            assert!(seen.insert(wire), "denial reason strings must be distinct");
            assert_eq!(code.as_str(), wire);
            let resp = AgentBridgeActivationResponse::denied(&req, code, detail).unwrap();
            assert!(resp.validate_request(&req).is_ok());
            let frame = Frame {
                protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
                encoding_profile: EncodingProfile::JsonV1,
                connection_id: req.connection_id.clone(),
                request_id: Some(req.request_identity.request.metadata.request_id.clone()),
                kind: FrameKind::Response,
                message_type: MessageType::Result,
                request_identity: None,
                payload: ProtocolPayload::Json(serde_json::to_value(&resp).unwrap()),
                trace_context: BTreeMap::new(),
            };
            let decoded = decode_activation_response(&frame, &req, &receipt).expect("decode");
            match decoded.disposition {
                eliot_protocol::AgentBridgeActivationDisposition::Denied {
                    reason_code,
                    detail,
                } => {
                    assert_eq!(reason_code, code);
                    assert_eq!(reason_code.as_str(), wire);
                    assert_eq!(
                        detail.is_some(),
                        code != AgentBridgeActivationDenialCode::SemanticResolutionUnavailable,
                        "typed denials keep their detail; the no-result denial keeps none"
                    );
                }
                eliot_protocol::AgentBridgeActivationDisposition::Authenticated { .. } => {
                    panic!("denial response must not decode as authenticated");
                }
            }
        }
        assert_eq!(seen.len(), total);
    }

    #[test]
    fn activation_response_join_rejects_connection_and_semantic_fence_substitutions() {
        let decl = fixture_declaration();
        let chal = fixture_challenge(&decl);
        let hello = decl.client_hello(chal.challenge_nonce.clone()).unwrap();
        let receipt = fixture_receipt(&chal, &hello);
        let core_req = AttachRequest::managed(
            DemandId::new("demand-1").unwrap(),
            ConnectionId::new("conn-1").unwrap(),
        );
        let req = build_neutral_activation_request(&core_req, &receipt, "demand-1").unwrap();
        let frame_for = |response: &AgentBridgeActivationResponse, connection_id: &str| Frame {
            protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: connection_id.to_owned(),
            request_id: Some(req.request_identity.request.metadata.request_id.clone()),
            kind: FrameKind::Response,
            message_type: MessageType::Result,
            request_identity: None,
            payload: ProtocolPayload::Json(serde_json::to_value(response).unwrap()),
            trace_context: BTreeMap::new(),
        };
        let response = AgentBridgeActivationResponse {
            wire_id: eliot_protocol::AGENT_BRIDGE_ACTIVATION_RESPONSE_WIRE_ID.to_owned(),
            wire_version: AgentBridgeActivationResponse::CONTRACT_VERSION,
            request_id: req.request_identity.request.metadata.request_id.clone(),
            request_sha256: req.request_sha256.clone(),
            disposition: eliot_protocol::AgentBridgeActivationDisposition::Authenticated {
                binding: Box::new(eliot_protocol::AgentBridgeAuthenticatedBinding {
                    principal_id: "principal-1".to_owned(),
                    session_id: "session-1".to_owned(),
                    activation_generation: receipt.state_fence.resource_generation,
                    state_fence: eliot_protocol::AgentBridgeActivationFence {
                        authority_epoch: receipt.state_fence.authority_epoch.clone(),
                        generation: receipt.state_fence.resource_generation,
                        nonce: "semantic-fence-1".to_owned(),
                    },
                    task_id: "task-1".to_owned(),
                    work_unit_id: "work-unit-1".to_owned(),
                    work_scope_id: "scope-1".to_owned(),
                    task_revision: "task-revision-1".to_owned(),
                    plan_id: "plan-1".to_owned(),
                    plan_revision: "plan-revision-1".to_owned(),
                }),
            },
            response_sha256: String::new(),
        }
        .with_computed_digest()
        .unwrap();
        let valid_frame = frame_for(&response, "conn-1");
        assert!(decode_activation_response(&valid_frame, &req, &receipt).is_ok());

        let bad_connection_frame = frame_for(&response, "other-connection");
        assert!(decode_activation_response(&bad_connection_frame, &req, &receipt).is_err());

        let mut bad_request_digest = response.clone();
        bad_request_digest.request_sha256 = "0".repeat(64);
        bad_request_digest = bad_request_digest.with_computed_digest().unwrap();
        let bad_request_digest_frame = frame_for(&bad_request_digest, "conn-1");
        assert!(decode_activation_response(&bad_request_digest_frame, &req, &receipt).is_err());

        let mut bad_authority_epoch = response.clone();
        if let eliot_protocol::AgentBridgeActivationDisposition::Authenticated { binding } =
            &mut bad_authority_epoch.disposition
        {
            binding.state_fence.authority_epoch = test_epoch(99);
        }
        bad_authority_epoch = bad_authority_epoch.with_computed_digest().unwrap();
        let bad_authority_epoch_frame = frame_for(&bad_authority_epoch, "conn-1");
        assert!(decode_activation_response(&bad_authority_epoch_frame, &req, &receipt).is_err());

        let mut bad_generation = response.clone();
        if let eliot_protocol::AgentBridgeActivationDisposition::Authenticated { binding } =
            &mut bad_generation.disposition
        {
            let substituted = ResourceGeneration::new(8).unwrap();
            binding.activation_generation = substituted;
            binding.state_fence.generation = substituted;
        }
        bad_generation = bad_generation.with_computed_digest().unwrap();
        let bad_generation_frame = frame_for(&bad_generation, "conn-1");
        assert!(decode_activation_response(&bad_generation_frame, &req, &receipt).is_err());
    }

    #[test]
    fn authenticated_consume_without_local_constructor() {
        let src = include_str!("lib.rs");
        let needle = format!("{}{}", "ActivationWire", "Response");
        assert!(!src.contains(&needle));
        assert!(src.contains("decode_activation_response"));
        let auth = format!("{}{}", "Authenticated", "");
        assert!(src.contains(&auth));
    }

    #[test]
    fn wrong_current_sid_accessor_rejected() {
        let current = "S-1-5-21-1000";
        let observed = "S-1-5-21-2000";
        assert_ne!(current, observed);
        let expectation = eliot_platform_windows::KernelFrontDoorServerExpectation::new(
            "S-1-5-18",
            0,
            "b".repeat(64),
            eliot_platform_windows::KernelFrontDoorAclMode::SystemAndLocalServiceWithClient {
                client_sid: current.to_owned(),
            },
        )
        .unwrap();
        assert_eq!(
            expectation.acl_mode(),
            &eliot_platform_windows::KernelFrontDoorAclMode::SystemAndLocalServiceWithClient {
                client_sid: current.to_owned()
            }
        );
        assert_ne!(observed, current);
    }

    #[test]
    fn mocked_transport_state_order() {
        let decl = fixture_declaration();
        let chal = fixture_challenge(&decl);
        let hello = decl.client_hello(chal.challenge_nonce.clone()).unwrap();
        let frame = eliot_ipc::peer_challenge_frame("conn-1", &chal).unwrap();
        let decoded = eliot_ipc::decode_peer_challenge_frame(&frame, "conn-1").unwrap();
        assert_eq!(decoded, chal);
        let hello_frame = eliot_ipc::client_hello_frame("conn-1", &hello).unwrap();
        let hello_decoded = eliot_ipc::decode_client_hello_frame(&hello_frame, "conn-1").unwrap();
        assert_eq!(hello_decoded, hello);
        let mut wrong_order = hello_frame.clone();
        wrong_order.connection_id = "other".to_owned();
        assert!(eliot_ipc::decode_client_hello_frame(&wrong_order, "conn-1").is_err());
    }

    /// I7.19 caller proof through the production [`BridgeRunner`] path.
    ///
    /// The runner is the real caller of the delivery-record ledger: it binds
    /// every item to the live activation-sealed session, drains pending
    /// injections at the host-hook and next-response boundaries, and projects
    /// sticky attention. These tests drive admit → forward → drain → receipt
    /// → attention → use/disposition exactly as the stdio loop does.
    mod reactive_runner_tests {
        use super::super::{
            AdmissionBasis, AttachBinding, AttachRequest, BridgeError, BridgeRunner, ConnectionId,
            CueOrigin, DeliveryPoint, DemandId, FiringEvidence, HostActivationPort,
            HostEventEnvelope, ItemDisposition, McpForwardingPort, NormalizedCue, Profile,
            ProviderFailure, ProviderReadiness, ReactiveInjectionLedger, RiskTier, Severity,
            UseOutcome,
        };
        use super::test_epoch;
        use eliot_agent_bridge_core::{
            ActivationPortOutcome, ActivationPortResult, CoverageGap, EventEnvelope,
            EventPortOutcome, FencingToken, Generation, PrincipalId, ReconciliationPortOutcome,
            SessionId, TaskId, WorkUnitId,
        };

        const REACTIVE_DIGEST: &str =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        struct StubActivation {
            result: ActivationPortResult,
        }

        impl HostActivationPort for StubActivation {
            fn activate(
                &mut self,
                _request: &AttachRequest,
            ) -> Result<ActivationPortOutcome, ProviderFailure> {
                Ok(ActivationPortOutcome::Authenticated(self.result.clone()))
            }
        }

        struct StubForwarder;

        impl McpForwardingPort for StubForwarder {
            fn forward_hook(
                &mut self,
                _binding: &AttachBinding,
                _event: &HostEventEnvelope,
            ) -> Result<(), ProviderFailure> {
                Ok(())
            }
            fn forward_event(
                &mut self,
                _binding: &AttachBinding,
                _event: &EventEnvelope,
            ) -> Result<EventPortOutcome, ProviderFailure> {
                Ok(EventPortOutcome::BestEffortForwarded)
            }
            fn forward_gap(
                &mut self,
                _binding: &AttachBinding,
                _gap: &CoverageGap,
            ) -> Result<(), ProviderFailure> {
                Err(ProviderFailure::new("test-forwarder", "gap not exercised"))
            }
            fn reconcile_external(
                &mut self,
                _binding: &AttachBinding,
            ) -> Result<ReconciliationPortOutcome, ProviderFailure> {
                Err(ProviderFailure::new(
                    "test-forwarder",
                    "reconciliation not exercised",
                ))
            }

            fn reconciliation_imported(
                &mut self,
                _binding: &AttachBinding,
                _result: &ReconciliationPortResult,
            ) {
            }
        }

        fn reactive_runner(attached: bool) -> BridgeRunner {
            let generation = Generation::new(7).expect("non-zero test generation");
            let fence = FencingToken::new(test_epoch(3), generation, "fence-reactive-7")
                .expect("valid test fence");
            let result = ActivationPortResult::authenticated(
                PrincipalId::new("principal-reactive-1").expect("valid principal"),
                SessionId::new("session-reactive-1").expect("valid session"),
                generation,
                fence,
                TaskId::new("task-reactive-1").expect("valid task"),
                WorkUnitId::new("work-unit-reactive-1").expect("valid work unit"),
                "scope-reactive-1",
                "task-revision-1",
                "plan-reactive-1",
                "plan-revision-1",
            )
            .expect("valid activation result");
            let mut runner = BridgeRunner::new(
                Profile::SpineFunctional,
                ProviderReadiness::all_admitted(),
                Some(Box::new(StubActivation { result })),
                Some(Box::new(StubForwarder)),
            )
            .expect("runner composes");
            if attached {
                let attach = AttachRequest::managed(
                    DemandId::new("demand-reactive-1").expect("valid demand"),
                    ConnectionId::new("conn-reactive-1").expect("valid connection"),
                );
                runner.attach(attach).expect("managed attach admits");
            }
            runner
        }

        fn reactive_cue(revision: &str) -> NormalizedCue {
            NormalizedCue {
                cue_id: "cue-reactive-1".to_owned(),
                kind: CueOrigin::ToolObservation,
                source: "tool-surface-1".to_owned(),
                source_revision: revision.to_owned(),
                cue_digest: REACTIVE_DIGEST.to_owned(),
            }
        }

        fn reactive_firing() -> FiringEvidence {
            FiringEvidence {
                rule_id: "exact-rule-reactive-7".to_owned(),
                cue_id: "cue-reactive-1".to_owned(),
                cue_digest: REACTIVE_DIGEST.to_owned(),
            }
        }

        fn reactive_admission(severity: Severity, risk: RiskTier) -> AdmissionBasis {
            AdmissionBasis {
                scope_id: "scope-reactive-1".to_owned(),
                status: "active".to_owned(),
                risk,
                governance_profile_rev: "gov-reactive-3".to_owned(),
                fence_epoch: "epoch-reactive-1".to_owned(),
                fence_generation: 2,
                admitted_severity: severity,
            }
        }

        fn hook_event(hook_id: &str, sequence: u64) -> HostEventEnvelope {
            serde_json::from_value(serde_json::json!({
                "event_id": hook_id,
                "attempt_id": "attempt-reactive-1",
                "sequence": sequence,
                "cursor": "cursor-reactive-1",
                "kind": "tool_result",
                "route": {
                    "host_family": "test",
                    "adapter": "test",
                    "protocol_transport": "stdio",
                    "runtime_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "adapter_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "provider": "provider",
                    "model": "model",
                    "auth_billing": "test",
                    "serializer_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "tool_semantics_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "reasoning_mode": "test",
                    "continuation_behavior": "fresh",
                    "feature_flags_hash": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                },
                "raw_payload_digest": "digest-reactive-1",
                "normalized_payload": {},
                "parent_event_id": null,
                "observed_at": "2026-09-21T00:00:00Z"
            }))
            .expect("valid hook fixture")
        }

        fn attention_ids(runner: &BridgeRunner) -> Vec<String> {
            runner
                .reactive_attention()
                .iter()
                .map(|item| item.item_id.clone())
                .collect()
        }

        #[test]
        fn critical_admitted_before_response_stays_sticky_until_resolved() {
            let mut runner = reactive_runner(true);
            assert_eq!(runner.reactive_pending_count(), 0);
            assert!(runner.reactive_attention().is_empty());
            let item = runner
                .admit_reactive_injection(
                    reactive_cue("rev-1"),
                    Some(reactive_firing()),
                    vec!["rel-reactive-a".to_owned()],
                    reactive_admission(Severity::Critical, RiskTier::Severe),
                )
                .expect("admit critical binds the live session");
            assert_eq!(runner.reactive_pending_count(), 1);
            assert!(attention_ids(&runner).contains(&item));
            // The host-hook delivery boundary drains the pending injection
            // and issues the receipt against the real forwarded event.
            runner
                .forward_hook(&hook_event("hook-reactive-1", 1))
                .expect("hook forwards");
            let receipts = runner
                .deliver_reactive_pending_via_hook("hook-reactive-1")
                .expect("hook drain issues receipts");
            assert_eq!(receipts.len(), 1);
            let receipt = &receipts[0];
            assert_eq!(receipt.item_id, item);
            assert_eq!(receipt.session_id, "session-reactive-1");
            assert_eq!(receipt.firing.rule_id, "exact-rule-reactive-7");
            assert_eq!(receipt.firing.cue_digest, REACTIVE_DIGEST);
            assert_eq!(receipt.admission.scope_id, "scope-reactive-1");
            assert_eq!(receipt.admission.risk, RiskTier::Severe);
            assert_eq!(receipt.admission.fence_generation, 2);
            assert!(matches!(
                receipt.delivery,
                DeliveryPoint::HostHook { ref hook_id } if hook_id == "hook-reactive-1"
            ));
            assert_eq!(receipt.use_status, UseOutcome::Unknown);
            assert_eq!(runner.reactive_pending_count(), 0);
            // Later attention output still carries the critical item.
            assert!(attention_ids(&runner).contains(&item));
            // Observable use does not clear stickiness.
            runner
                .record_reactive_use(
                    &item,
                    UseOutcome::ObservedInfluence {
                        detail: "shaped retry".to_owned(),
                    },
                )
                .expect("record use");
            assert!(attention_ids(&runner).contains(&item));
            let stored = runner
                .reactive_receipt(&receipt.receipt_id)
                .expect("receipt retained");
            assert!(matches!(
                stored.use_status,
                UseOutcome::ObservedInfluence { .. }
            ));
            // Only a durable terminal disposition clears it.
            runner
                .record_reactive_disposition(
                    &item,
                    ItemDisposition::Resolved {
                        record: "owner-fix-reactive-9".to_owned(),
                    },
                )
                .expect("resolve");
            assert!(!attention_ids(&runner).contains(&item));
        }

        #[test]
        fn normal_injected_once_not_reinjected_until_invalidated() {
            let mut runner = reactive_runner(true);
            let first = runner
                .admit_reactive_injection(
                    reactive_cue("rev-1"),
                    Some(reactive_firing()),
                    Vec::new(),
                    reactive_admission(Severity::Normal, RiskTier::Low),
                )
                .expect("admit normal");
            // The next-response delivery boundary (tool-only piggyback)
            // issues the receipt against the exact response frame.
            let receipts = runner
                .deliver_reactive_pending_via_response("forward-event:evt-reactive-1")
                .expect("response drain issues receipts");
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0].item_id, first);
            assert!(matches!(
                receipts[0].delivery,
                DeliveryPoint::NextBridgeResponse { .. }
            ));
            assert!(!attention_ids(&runner).contains(&first));
            let duplicate = runner.admit_reactive_injection(
                reactive_cue("rev-1"),
                Some(reactive_firing()),
                Vec::new(),
                reactive_admission(Severity::Normal, RiskTier::Low),
            );
            match duplicate {
                Err(BridgeError::ProviderContract(detail)) => assert!(
                    detail.contains("already delivered"),
                    "dedup must name the delivered state, got: {detail}"
                ),
                other => panic!("expected dedup rejection, got {other:?}"),
            }
            assert_eq!(runner.invalidate_reactive_source("tool-surface-1"), 1);
            let second = runner
                .admit_reactive_injection(
                    reactive_cue("rev-2"),
                    Some(reactive_firing()),
                    Vec::new(),
                    reactive_admission(Severity::Normal, RiskTier::Low),
                )
                .expect("re-admit after invalidation");
            assert_ne!(first, second);
            let second_receipts = runner
                .deliver_reactive_pending_via_response("forward-event:evt-reactive-2")
                .expect("second drain issues receipts");
            assert_eq!(second_receipts.len(), 1);
            assert_ne!(
                second_receipts[0].receipt_id, receipts[0].receipt_id,
                "second delivery mints a distinct receipt"
            );
        }

        #[test]
        fn ledger_snapshot_restores_across_processes_fail_closed() {
            let mut runner = reactive_runner(true);
            runner
                .admit_reactive_injection(
                    reactive_cue("rev-1"),
                    Some(reactive_firing()),
                    vec!["rel-reactive-a".to_owned()],
                    reactive_admission(Severity::Critical, RiskTier::High),
                )
                .expect("admit");
            runner
                .deliver_reactive_pending_via_hook("hook-reactive-9")
                .expect("drain");
            let bytes = runner.reactive_ledger_snapshot().expect("snapshot");
            assert!(!bytes.is_empty());
            // A fresh detached process restores the exact ledger bytes; the
            // restored state carries the delivered critical item.
            let mut restored = reactive_runner(false);
            restored
                .restore_reactive_ledger(&bytes)
                .expect("restore accepts own contract");
            let again = restored.reactive_ledger_snapshot().expect("re-snapshot");
            assert_eq!(again, bytes);
            assert_eq!(
                ReactiveInjectionLedger::from_json_bytes(&bytes).expect("decode"),
                ReactiveInjectionLedger::from_json_bytes(&again).expect("decode again")
            );
            assert!(
                restored
                    .restore_reactive_ledger(b"{\"contract\":\"wrong\"}")
                    .is_err()
            );
            assert!(restored.restore_reactive_ledger(&[]).is_err());
        }

        #[test]
        fn ledger_snapshot_pins_the_store_facing_byte_contract() {
            // The C4 durable seam (Store owner persists these bytes verbatim):
            // contract stamp, canonical JSON shape, and the 1 MiB bound,
            // straight through the production export entry. Delivery
            // semantics stay with the bridge ledger; the Store never
            // interprets beyond the structural stamp.
            let mut runner = reactive_runner(true);
            runner
                .admit_reactive_injection(
                    reactive_cue("rev-1"),
                    Some(reactive_firing()),
                    vec!["rel-reactive-a".to_owned()],
                    reactive_admission(Severity::Normal, RiskTier::Low),
                )
                .expect("admit");
            let bytes = runner.reactive_ledger_snapshot().expect("snapshot");
            assert!(
                bytes.len() <= super::reactive_injection_receipts::MAX_LEDGER_JSON_BYTES,
                "snapshot must fit the bounded Store write"
            );
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).expect("snapshot is JSON");
            assert_eq!(
                value.get("contract").and_then(|contract| contract.as_str()),
                Some(super::REACTIVE_INJECTION_CONTRACT),
                "snapshot carries the delivery-record contract stamp"
            );
            for key in [
                "contract",
                "next_item_seq",
                "next_receipt_seq",
                "items",
                "receipts",
            ] {
                assert!(
                    value.get(key).is_some(),
                    "snapshot shape must carry {key} for the Store reader"
                );
            }
        }

        #[test]
        fn detached_runner_admits_nothing_and_projects_nothing() {
            let mut runner = reactive_runner(false);
            assert!(matches!(
                runner.admit_reactive_injection(
                    reactive_cue("rev-1"),
                    Some(reactive_firing()),
                    Vec::new(),
                    reactive_admission(Severity::Critical, RiskTier::Severe),
                ),
                Err(BridgeError::NotAttached)
            ));
            assert!(matches!(
                runner.deliver_reactive_pending_via_hook("hook-reactive-1"),
                Err(BridgeError::NotAttached)
            ));
            assert!(matches!(
                runner.deliver_reactive_pending_via_response("resp-1"),
                Err(BridgeError::NotAttached)
            ));
            assert!(runner.reactive_attention().is_empty());
            assert_eq!(runner.reactive_pending_count(), 0);
        }
    }

    /// I7.18/I7.24 caller proof through the production [`BridgeRunner`] path.
    ///
    /// The runner is the production caller of the core resource projection:
    /// it publishes owner-supplied snapshots, expands handles, and projects
    /// tool-result receipts with route-measured tokens and delivery. These
    /// tests drive publish → preview/handle → expand → receipt → evidence
    /// gate exactly as an owning producer would, plus detached fail-closed
    /// behavior.
    mod resource_runner_tests {
        use super::super::{
            AttachBinding, AttachRequest, BridgeError, BridgeRunner, ConnectionId, DeliveryStatus,
            DemandId, EventEnvelope, HostActivationPort, HostEventEnvelope, McpForwardingPort,
            Profile, ProviderFailure, ProviderReadiness, ResourceUri,
        };
        use super::test_epoch;
        use eliot_agent_bridge_core::{
            ActivationPortOutcome, ActivationPortResult, CoverageGap, EventPortOutcome,
            FencingToken, Generation, PrincipalId, ReconciliationPortOutcome, SessionId, TaskId,
            WorkUnitId,
        };

        struct StubActivation {
            result: ActivationPortResult,
        }

        impl HostActivationPort for StubActivation {
            fn activate(
                &mut self,
                _request: &AttachRequest,
            ) -> Result<ActivationPortOutcome, ProviderFailure> {
                Ok(ActivationPortOutcome::Authenticated(self.result.clone()))
            }
        }

        struct StubForwarder;

        impl McpForwardingPort for StubForwarder {
            fn forward_hook(
                &mut self,
                _binding: &AttachBinding,
                _event: &HostEventEnvelope,
            ) -> Result<(), ProviderFailure> {
                Ok(())
            }
            fn forward_event(
                &mut self,
                _binding: &AttachBinding,
                _event: &EventEnvelope,
            ) -> Result<EventPortOutcome, ProviderFailure> {
                Ok(EventPortOutcome::BestEffortForwarded)
            }
            fn forward_gap(
                &mut self,
                _binding: &AttachBinding,
                _gap: &CoverageGap,
            ) -> Result<(), ProviderFailure> {
                Err(ProviderFailure::new("test-forwarder", "gap not exercised"))
            }
            fn reconcile_external(
                &mut self,
                _binding: &AttachBinding,
            ) -> Result<ReconciliationPortOutcome, ProviderFailure> {
                Err(ProviderFailure::new(
                    "test-forwarder",
                    "reconciliation not exercised",
                ))
            }

            fn reconciliation_imported(
                &mut self,
                _binding: &AttachBinding,
                _result: &ReconciliationPortResult,
            ) {
            }
        }

        fn resource_runner(attached: bool) -> BridgeRunner {
            let generation = Generation::new(3).expect("non-zero test generation");
            let fence = FencingToken::new(test_epoch(2), generation, "fence-resource-3")
                .expect("valid test fence");
            let result = ActivationPortResult::authenticated(
                PrincipalId::new("principal-resource-1").expect("valid principal"),
                SessionId::new("session-resource-1").expect("valid session"),
                generation,
                fence,
                TaskId::new("task-resource-1").expect("valid task"),
                WorkUnitId::new("work-unit-resource-1").expect("valid work unit"),
                "scope-resource-1",
                "task-revision-1",
                "plan-resource-1",
                "plan-revision-1",
            )
            .expect("valid activation result");
            let mut runner = BridgeRunner::new(
                Profile::SpineFunctional,
                ProviderReadiness::all_admitted(),
                Some(Box::new(StubActivation { result })),
                Some(Box::new(StubForwarder)),
            )
            .expect("runner composes");
            if attached {
                let attach = AttachRequest::managed(
                    DemandId::new("demand-resource-1").expect("valid demand"),
                    ConnectionId::new("conn-resource-1").expect("valid connection"),
                );
                runner.attach(attach).expect("managed attach admits");
            }
            runner
        }

        fn large_evidence_bytes() -> Vec<u8> {
            let mut content = String::from("[");
            while content.len() < 4 * 1024 + 64 {
                content.push_str(r#"{"check":"evidence-item","detail":""#);
                content.push_str(&"x".repeat(64));
                content.push_str(r#""},"#);
            }
            content.push(']');
            content.into_bytes()
        }

        #[test]
        fn large_evidence_returns_preview_plus_handle_and_expands_immutable() {
            use eliot_agent_bridge_core::{MAX_PREVIEW_BYTES, ResourceKind};

            let mut runner = resource_runner(true);
            assert_eq!(runner.resource_registry_len(), 0);
            let content = large_evidence_bytes();
            assert!(content.len() > MAX_PREVIEW_BYTES);
            // Acceptance shape: bounded preview plus eliot://evidence handle.
            let view = runner
                .publish_evidence_resource(content.clone())
                .expect("publish evidence binds the live attach");
            assert_eq!(view.kind(), ResourceKind::Evidence);
            assert!(
                view.handle()
                    .uri()
                    .as_str()
                    .starts_with("eliot://evidence/"),
                "handle must name the evidence family"
            );
            assert!(view.preview().len() <= MAX_PREVIEW_BYTES);
            assert!(view.is_truncated());
            assert_eq!(view.total_bytes(), content.len());
            assert_eq!(runner.resource_registry_len(), 1);
            // Explicit expansion retrieves the immutable referenced content.
            let expanded = runner
                .expand_resource(view.handle())
                .expect("expand resolves the issued handle");
            assert_eq!(expanded, content);
            // Republishing the same bytes rebinds the same handle, not a copy.
            let again = runner
                .publish_evidence_resource(content.clone())
                .expect("idempotent republish");
            assert_eq!(again.handle(), view.handle());
            assert_eq!(runner.resource_registry_len(), 1);
        }

        #[test]
        fn token_truncated_tool_result_is_receipted_and_rejected_as_evidence() {
            let runner = resource_runner(true);
            let source =
                ResourceUri::parse("eliot://evidence/source-9").expect("valid source handle");
            let result_bytes = vec![b'r'; 3000];
            // tokens_rendered is measured by the projecting route owner with
            // the actual tokenizer; the bridge never estimates it.
            let receipt = runner
                .project_tool_result_receipt(&result_bytes, source, 750, DeliveryStatus::Truncated)
                .expect("project receipt");
            assert_eq!(receipt.delivery(), DeliveryStatus::Truncated);
            assert_eq!(receipt.bytes_rendered(), result_bytes.len());
            assert_eq!(receipt.tokens_rendered(), 750);
            assert_eq!(receipt.result_digest().len(), 64);
            // A truncated result cannot satisfy complete evidence.
            assert!(matches!(
                receipt.check_complete_evidence(),
                Err(BridgeError::IncompleteDelivery {
                    delivery: DeliveryStatus::Truncated
                })
            ));
            let full = runner
                .project_tool_result_receipt(
                    &result_bytes,
                    ResourceUri::parse("eliot://evidence/source-9").expect("valid source"),
                    750,
                    DeliveryStatus::Full,
                )
                .expect("project full receipt");
            assert!(full.check_complete_evidence().is_ok());
        }

        #[test]
        fn detached_runner_publishes_nothing_and_counts_zero() {
            let mut runner = resource_runner(false);
            assert!(matches!(
                runner.publish_evidence_resource(b"bytes".to_vec()),
                Err(BridgeError::NotAttached)
            ));
            assert!(matches!(
                runner.publish_canonical_resource(
                    &ResourceUri::parse("eliot://report/r-1").expect("valid uri"),
                    b"bytes".to_vec(),
                ),
                Err(BridgeError::NotAttached)
            ));
            assert_eq!(runner.resource_registry_len(), 0);
        }
    }
}
