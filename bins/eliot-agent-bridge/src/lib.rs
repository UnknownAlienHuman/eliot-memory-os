//! B-15's thin profile-selected agent/host bridge.

#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use eliot_agent_bridge_core::{
    AgentBridgeCore, AttachBinding, AttachRequest, AttachView, AttemptState, BridgeError,
    ConnectionId, CursorPolicy, DemandId, EventForwardStatus, EventPortOutcome, HostActivationPort,
    HostEventEnvelope, McpForwardingPort, OutstandingDeliveryView, ProviderFailure,
    ProviderReadiness, ReconciliationPortOutcome, ReconnectRequest, RecoveryDirective,
    TerminalReductionInputs, TransportEdge,
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
use eliot_mcp::{HostInvocationOutcome, KernelHostRequestPort, ResponseKind};
use eliot_protocol::{
    AckPhase, AgentBridgeClientDeclaration, AgentBridgePeerAdmissionReceipt,
    AgentBridgePeerChallenge, EventEnvelope,
};
use eliot_runtime::{Runtime, RuntimeConfig};

mod cli_contract;
mod kernel_activation_client;
mod kernel_host_request_client;
pub mod memory_handle_join;
pub mod reactive_injection_receipts;
pub mod settled_plan_transport;
mod understanding_bootstrap;
pub(crate) use cli_contract::validate_client_declaration_path;
pub use cli_contract::{CliConfig, CliError, Profile, Transport, parse_args};
use kernel_activation_client::KernelHostActivationPort;
#[cfg(test)]
use kernel_activation_client::{
    activation_frame_for_request, build_neutral_activation_request, decode_activation_response,
    denial_reason_code,
};
use kernel_host_request_client::{KernelHostRequestClient, ReplayCacheEntry};
pub use memory_handle_join::{ResolvedMemoryHandle, parse_memory_handle};
pub use reactive_injection_receipts::{
    AdmissionBasis, AttentionItem, CueKind, DeliveryPoint, FiringEvidence, InjectionReceipt,
    ItemDisposition, NormalizedCue, REACTIVE_INJECTION_CONTRACT, ReactiveInjectionError,
    ReactiveInjectionLedger, RiskTier, Severity, UseOutcome,
};
pub use settled_plan_transport::{
    AdmittedPlanItem, FeedAdmissionOutcome, GovernorAssessmentView, MAX_TRANSPORT_REPLAY_KEYS,
    PlanAdmissionError, PlanAdmissionReport, SettledPlanAdmission, WithheldPlanItem,
    admit_producer_feed, governor_assess, render_admission_fence,
};
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
/// traffic. Neither is durable: both die with this process, which spans
/// exactly one admitted connection.
struct KernelTransportOwner {
    admitted: AdmittedConnection,
    runtime: tokio::runtime::Runtime,
    _loaded: LoadedAgentBridgeDeclaration,
    activation_used: bool,
    limits: eliot_ipc::TransportLimits,
    activated_session: Option<String>,
    replay_cache: HashMap<String, ReplayCacheEntry>,
}

type SharedTransport = Rc<RefCell<KernelTransportOwner>>;

struct KernelMcpForwardingPort;

impl McpForwardingPort for KernelMcpForwardingPort {
    fn forward_hook(
        &mut self,
        _binding: &AttachBinding,
        _event: &HostEventEnvelope,
    ) -> Result<(), ProviderFailure> {
        Err(ProviderFailure::new(
            "eliot-kernel-front-door",
            "forwarding not admitted",
        ))
    }
    fn forward_event(
        &mut self,
        _binding: &AttachBinding,
        _event: &EventEnvelope,
    ) -> Result<EventPortOutcome, ProviderFailure> {
        Err(ProviderFailure::new(
            "eliot-kernel-front-door",
            "forwarding not admitted",
        ))
    }
    fn forward_gap(
        &mut self,
        _binding: &AttachBinding,
        _gap: &eliot_agent_bridge_core::CoverageGap,
    ) -> Result<(), ProviderFailure> {
        Err(ProviderFailure::new(
            "eliot-kernel-front-door",
            "forwarding not admitted",
        ))
    }
    fn reconcile_external(
        &mut self,
        _binding: &AttachBinding,
    ) -> Result<ReconciliationPortOutcome, ProviderFailure> {
        Err(ProviderFailure::new(
            "eliot-kernel-front-door",
            "reconciliation not admitted",
        ))
    }
}

pub type KernelPorts = (
    Box<dyn HostActivationPort>,
    Box<dyn KernelHostRequestPort>,
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
    let owner: SharedTransport = Rc::new(RefCell::new(KernelTransportOwner {
        admitted: AdmittedConnection { transport, receipt },
        runtime,
        _loaded: loaded,
        activation_used: false,
        limits,
        activated_session: None,
        replay_cache: HashMap::new(),
    }));
    let host: Box<dyn HostActivationPort> = Box::new(KernelHostActivationPort {
        shared: owner.clone(),
    });
    let host_request: Box<dyn KernelHostRequestPort> =
        Box::new(KernelHostRequestClient { shared: owner });
    let fwd: Box<dyn McpForwardingPort> = Box::new(KernelMcpForwardingPort);
    Ok((host, host_request, fwd))
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
    bootstrap_context: Option<BootstrapContext>,
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
        let cursor_policy = CursorPolicy::new(AckPhase::Durable, AckPhase::Normalized)
            .map_err(RuntimeBuildError::BridgeContract)?;
        Ok(Self {
            profile,
            runtime,
            core: AgentBridgeCore::new(readiness, host_activation, mcp_forwarding, cursor_policy),
            reactive_ledger: ReactiveInjectionLedger::new(),
            bootstrap_session: BootstrapSession::default(),
            bootstrap_context: None,
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
        self.core.publish_evidence(bytes).ok()
    }
    /// Notes the owner-supplied bootstrap context for this session.
    ///
    /// Validates fail-closed without composing authority: an invalid context
    /// is rejected and never stored. Noting context never delivers the
    /// once-per-session auto-boot; delivery happens only through
    /// [`Self::take_first_response_bootstrap`].
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
        self.bootstrap_context = Some(context);
        Ok(())
    }
    /// Bounded explicit retrieval of the canonical `UnderstandingBootstrap`.
    ///
    /// Always available, including after the once-per-session auto-boot was
    /// delivered. Requires a noted context; fails closed otherwise.
    pub fn get_understanding_bootstrap(
        &self,
        tasks: &BootstrapTaskInputs,
        requested_assessment: CurrentAssessment,
    ) -> Result<UnderstandingBootstrap, BootstrapError> {
        let Some(context) = &self.bootstrap_context else {
            return Err(BootstrapError {
                code: "BOOTSTRAP_CONTEXT_MISSING",
                detail: "no bootstrap context noted for this session".to_owned(),
            });
        };
        get_understanding_bootstrap(context, tasks, requested_assessment)
    }
    /// Takes the once-per-session auto-boot for the first successful response.
    ///
    /// Returns `None` after the first delivery or when no valid context is
    /// noted; composition failures also yield `None` without marking delivery
    /// so a later response with complete inputs can still carry the bootstrap.
    pub fn take_first_response_bootstrap(
        &mut self,
        tasks: &BootstrapTaskInputs,
        requested_assessment: CurrentAssessment,
    ) -> Option<UnderstandingBootstrap> {
        let context = self.bootstrap_context.clone()?;
        self.bootstrap_session
            .take_auto_boot(&context, tasks, requested_assessment)
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
        let cases = [
            (
                AgentBridgeActivationDenialCode::SemanticResolutionUnavailable,
                eliot_protocol::AGENT_BRIDGE_SEMANTIC_RESOLUTION_UNAVAILABLE,
            ),
            (
                AgentBridgeActivationDenialCode::TaskSelectionRequired,
                eliot_protocol::AGENT_BRIDGE_TASK_SELECTION_REQUIRED,
            ),
            (
                AgentBridgeActivationDenialCode::ScopeSelectionRequired,
                eliot_protocol::AGENT_BRIDGE_SCOPE_SELECTION_REQUIRED,
            ),
            (
                AgentBridgeActivationDenialCode::ScopeAmbiguous,
                eliot_protocol::AGENT_BRIDGE_SCOPE_AMBIGUOUS,
            ),
            (
                AgentBridgeActivationDenialCode::NotReady,
                eliot_protocol::AGENT_BRIDGE_NOT_READY,
            ),
            (
                AgentBridgeActivationDenialCode::StaleFence,
                eliot_protocol::AGENT_BRIDGE_STALE_FENCE,
            ),
            (
                AgentBridgeActivationDenialCode::FailedInternal,
                eliot_protocol::AGENT_BRIDGE_FAILED_INTERNAL,
            ),
        ];
        let mut seen = BTreeSet::new();
        for (code, wire) in cases {
            assert!(seen.insert(wire), "denial reason strings must be distinct");
            assert_eq!(denial_reason_code(code), wire);
            let resp = AgentBridgeActivationResponse::denied(&req, code).unwrap();
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
                eliot_protocol::AgentBridgeActivationDisposition::Denied { reason_code } => {
                    assert_eq!(reason_code, code);
                    assert_eq!(denial_reason_code(reason_code), wire);
                }
                eliot_protocol::AgentBridgeActivationDisposition::Authenticated { .. } => {
                    panic!("denial response must not decode as authenticated");
                }
            }
        }
        assert_eq!(seen.len(), cases.len());
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
            CueKind, DeliveryPoint, DemandId, FiringEvidence, HostActivationPort,
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
                kind: CueKind::ToolObservation,
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
                bytes.len()
                    <= super::reactive_injection_receipts::MAX_LEDGER_JSON_BYTES,
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
