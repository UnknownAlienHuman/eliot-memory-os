//! A-16 thin demand-start bridge core.
//!
//! This library owns only host-shim transport state. It has no process-spawn,
//! authentication, semantic-session, persistence, database, or completion
//! authority. All such decisions arrive through injected ports and remain
//! bound to the exact session, generation, and fence that produced them.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use eliot_agent_api::{HostEventEnvelope, SessionId};
use eliot_observation_contracts::{BlindInterval, CoverageGap, CoverageInterval, GapDisposition};
use eliot_process::{FencingToken, Generation};
use eliot_protocol::{
    AckPhase, DeliveryClass, EventAckReceipt, EventDisposition, EventEnvelope, Frame, ReplayLedger,
};
use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

/// Stable A-16 source contract identity.
pub const CONTRACT_ID: &str = "eliot.surfaces.agent-bridge-core/v1";
/// The bridge's immutable authority ceiling.
pub const AUTHORITY_CEILING: &str = "transport-only; no authentication, semantic state, process spawn, persistence, or proof promotion";
/// Stable typed reason returned when an admitted provider is unavailable.
pub const PLAN_GAP: &str = "PLAN_GAP";

macro_rules! opaque_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, BridgeError> {
                let value = value.into();
                validate_text(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

opaque_id!(DemandId, "demand_id");
opaque_id!(ConnectionId, "connection_id");
opaque_id!(PrincipalId, "principal_id");
opaque_id!(ReconciliationReceiptRef, "reconciliation_receipt_ref");

fn validate_text(value: &str, field: &'static str) -> Result<(), BridgeError> {
    if value.trim().is_empty() {
        return Err(BridgeError::InvalidContract {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(BridgeError::InvalidContract {
            field,
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

/// Internal or injected provider required by A-16.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequiredProvider {
    A01AgentApi,
    A06McpSurface,
    C07Protocol,
    C011ObservationContracts,
    P03ProcessContracts,
    HostActivationPort,
    McpForwardingPort,
}

impl RequiredProvider {
    const ALL_CONTRACTS: [Self; 5] = [
        Self::A01AgentApi,
        Self::A06McpSurface,
        Self::C07Protocol,
        Self::C011ObservationContracts,
        Self::P03ProcessContracts,
    ];

    const fn contract(self) -> &'static str {
        match self {
            Self::A01AgentApi => "crates/agent/eliot-agent-api",
            Self::A06McpSurface => "A-06 admitted MCP surface",
            Self::C07Protocol => "crates/foundation/eliot-protocol",
            Self::C011ObservationContracts => "crates/foundation/eliot-observation-contracts",
            Self::P03ProcessContracts => "crates/kernel/eliot-process",
            Self::HostActivationPort => "injected host activation port",
            Self::McpForwardingPort => "injected A-06/MCP forwarding port",
        }
    }
}

/// A typed fail-closed planning gap, never a fake provider success.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanGap {
    reason_code: &'static str,
    missing_provider: RequiredProvider,
    required_contract: &'static str,
}

impl PlanGap {
    fn missing(provider: RequiredProvider) -> Self {
        Self {
            reason_code: PLAN_GAP,
            missing_provider: provider,
            required_contract: provider.contract(),
        }
    }

    pub const fn reason_code(&self) -> &'static str {
        self.reason_code
    }

    pub const fn missing_provider(&self) -> RequiredProvider {
        self.missing_provider
    }

    pub const fn required_contract(&self) -> &'static str {
        self.required_contract
    }
}

/// Runtime readiness supplied by the composition/admission owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReadiness {
    admitted: BTreeMap<RequiredProvider, bool>,
}

impl ProviderReadiness {
    pub fn all_admitted() -> Self {
        Self {
            admitted: RequiredProvider::ALL_CONTRACTS
                .into_iter()
                .map(|provider| (provider, true))
                .collect(),
        }
    }

    #[must_use]
    pub fn with_unavailable(mut self, provider: RequiredProvider) -> Self {
        self.admitted.insert(provider, false);
        self
    }

    fn first_gap(&self) -> Option<PlanGap> {
        RequiredProvider::ALL_CONTRACTS
            .into_iter()
            .find(|provider| !self.admitted.get(provider).copied().unwrap_or(false))
            .map(PlanGap::missing)
    }
}

/// Whether the attach originated from an already governed route or externally.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttachKind {
    Managed,
    External,
}

/// Demand-start attach intent. Fields are private and deserialization re-runs
/// the constructor, so invalid blind-interval combinations cannot be created.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttachRequest {
    demand_id: DemandId,
    connection_id: ConnectionId,
    attach_kind: AttachKind,
    pre_attach_blind_interval: Option<BlindInterval>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAttachRequest {
    demand_id: DemandId,
    connection_id: ConnectionId,
    attach_kind: AttachKind,
    pre_attach_blind_interval: Option<BlindInterval>,
}

impl<'de> Deserialize<'de> for AttachRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawAttachRequest::deserialize(deserializer)?;
        Self::new(
            raw.demand_id,
            raw.connection_id,
            raw.attach_kind,
            raw.pre_attach_blind_interval,
        )
        .map_err(de::Error::custom)
    }
}

impl AttachRequest {
    pub fn managed(demand_id: DemandId, connection_id: ConnectionId) -> Self {
        Self {
            demand_id,
            connection_id,
            attach_kind: AttachKind::Managed,
            pre_attach_blind_interval: None,
        }
    }

    pub fn external(
        demand_id: DemandId,
        connection_id: ConnectionId,
        blind_interval: BlindInterval,
    ) -> Result<Self, BridgeError> {
        Self::new(
            demand_id,
            connection_id,
            AttachKind::External,
            Some(blind_interval),
        )
    }

    fn new(
        demand_id: DemandId,
        connection_id: ConnectionId,
        attach_kind: AttachKind,
        pre_attach_blind_interval: Option<BlindInterval>,
    ) -> Result<Self, BridgeError> {
        match (attach_kind, &pre_attach_blind_interval) {
            (AttachKind::Managed, None) => {}
            (AttachKind::External, Some(blind)) => {
                CoverageInterval::new(blind.interval.start, blind.interval.end)
                    .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
                blind
                    .validate()
                    .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
            }
            (AttachKind::Managed, Some(_)) => {
                return Err(BridgeError::InvalidContract {
                    field: "pre_attach_blind_interval",
                    reason: "managed attach cannot claim an external blind interval",
                });
            }
            (AttachKind::External, None) => {
                return Err(BridgeError::InvalidContract {
                    field: "pre_attach_blind_interval",
                    reason: "external attach must preserve its blind interval",
                });
            }
        }
        Ok(Self {
            demand_id,
            connection_id,
            attach_kind,
            pre_attach_blind_interval,
        })
    }

    pub const fn demand_id(&self) -> &DemandId {
        &self.demand_id
    }

    pub const fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    pub const fn attach_kind(&self) -> AttachKind {
        self.attach_kind
    }

    pub const fn pre_attach_blind_interval(&self) -> Option<&BlindInterval> {
        self.pre_attach_blind_interval.as_ref()
    }
}

/// Authenticated result emitted only by the injected host activation boundary.
/// It is inert until A-16 validates and seals it into its private grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationPortResult {
    principal_id: PrincipalId,
    session_id: SessionId,
    activation_generation: Generation,
    state_fence: FencingToken,
}

impl ActivationPortResult {
    pub fn authenticated(
        principal_id: PrincipalId,
        session_id: SessionId,
        activation_generation: Generation,
        state_fence: FencingToken,
    ) -> Result<Self, BridgeError> {
        validate_authority_binding(&session_id, activation_generation, &state_fence)?;
        Ok(Self {
            principal_id,
            session_id,
            activation_generation,
            state_fence,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActivationGrant {
    principal_id: PrincipalId,
    session_id: SessionId,
    activation_generation: Generation,
    state_fence: FencingToken,
}

impl ActivationGrant {
    fn seal(result: ActivationPortResult) -> Result<Self, BridgeError> {
        validate_authority_binding(
            &result.session_id,
            result.activation_generation,
            &result.state_fence,
        )?;
        Ok(Self {
            principal_id: result.principal_id,
            session_id: result.session_id,
            activation_generation: result.activation_generation,
            state_fence: result.state_fence,
        })
    }
}

/// Trusted activation-port disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivationPortOutcome {
    Authenticated(ActivationPortResult),
    Denied { reason_code: &'static str },
}

/// Injected demand-start boundary. The host owner, not A-16, owns process
/// activation, authentication, and compatible-trigger coalescing.
pub trait HostActivationPort {
    fn activate(
        &mut self,
        request: &AttachRequest,
    ) -> Result<ActivationPortOutcome, ProviderFailure>;
}

/// Result returned by the admitted MCP/event forwarding provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventPortOutcome {
    Acknowledged(EventForwardAck),
    BestEffortForwarded,
    BestEffortDropped { reason_ref: String },
}

/// Explicit event acknowledgement projection. It carries no persistence or
/// canonical-application authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventForwardAck {
    stream_id: String,
    event_id: String,
    phase: AckPhase,
    disposition: EventDisposition,
}

impl EventForwardAck {
    pub fn new(
        stream_id: impl Into<String>,
        event_id: impl Into<String>,
        phase: AckPhase,
        disposition: EventDisposition,
    ) -> Result<Self, BridgeError> {
        let stream_id = stream_id.into();
        let event_id = event_id.into();
        validate_text(&stream_id, "ack.stream_id")?;
        validate_text(&event_id, "ack.event_id")?;
        Ok(Self {
            stream_id,
            event_id,
            phase,
            disposition,
        })
    }

    pub const fn phase(&self) -> AckPhase {
        self.phase
    }

    pub const fn disposition(&self) -> EventDisposition {
        self.disposition
    }
}

/// Injected A-06/MCP boundary. It owns neither the bridge's local transport
/// binding nor canonical semantic state.
pub trait McpForwardingPort {
    fn forward_frame(
        &mut self,
        binding: &AttachBinding,
        frame: &Frame,
    ) -> Result<(), ProviderFailure>;

    fn forward_hook(
        &mut self,
        binding: &AttachBinding,
        event: &HostEventEnvelope,
    ) -> Result<(), ProviderFailure>;

    fn forward_event(
        &mut self,
        binding: &AttachBinding,
        event: &EventEnvelope,
    ) -> Result<EventPortOutcome, ProviderFailure>;

    fn forward_gap(
        &mut self,
        binding: &AttachBinding,
        gap: &CoverageGap,
    ) -> Result<(), ProviderFailure>;

    fn reconcile_external(
        &mut self,
        binding: &AttachBinding,
    ) -> Result<ReconciliationPortOutcome, ProviderFailure>;
}

/// Current attach binding projected by the bridge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachBinding {
    principal_id: PrincipalId,
    session_id: SessionId,
    connection_id: ConnectionId,
    activation_generation: Generation,
    state_fence: FencingToken,
}

impl AttachBinding {
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub const fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    pub const fn activation_generation(&self) -> Generation {
        self.activation_generation
    }

    pub const fn state_fence(&self) -> &FencingToken {
        &self.state_fence
    }

    fn authority_matches(
        &self,
        session_id: &SessionId,
        generation: Generation,
        fence: &FencingToken,
    ) -> bool {
        &self.session_id == session_id
            && self.activation_generation == generation
            && self.state_fence.matches(fence)
    }
}

/// Historical evidence ceiling for the pre-attach interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofCeiling {
    CandidateOnly,
}

/// Read-only current bridge status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachView {
    binding: AttachBinding,
    reconciliation_required: bool,
    pre_attach_proof_ceiling: Option<ProofCeiling>,
}

impl AttachView {
    pub const fn binding(&self) -> &AttachBinding {
        &self.binding
    }

    pub const fn reconciliation_required(&self) -> bool {
        self.reconciliation_required
    }

    pub const fn pre_attach_proof_ceiling(&self) -> Option<ProofCeiling> {
        self.pre_attach_proof_ceiling
    }
}

/// Exact old authority binding plus the replacement transport identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconnectRequest {
    session_id: SessionId,
    activation_generation: Generation,
    state_fence: FencingToken,
    new_connection_id: ConnectionId,
}

impl ReconnectRequest {
    pub fn new(
        session_id: SessionId,
        activation_generation: Generation,
        state_fence: FencingToken,
        new_connection_id: ConnectionId,
    ) -> Result<Self, BridgeError> {
        validate_authority_binding(&session_id, activation_generation, &state_fence)?;
        Ok(Self {
            session_id,
            activation_generation,
            state_fence,
            new_connection_id,
        })
    }
}

/// Trusted reconciliation result emitted only by the injected forwarding
/// boundary. It is inert until A-16 validates and seals it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationPortResult {
    session_id: SessionId,
    activation_generation: Generation,
    state_fence: FencingToken,
    receipt_ref: ReconciliationReceiptRef,
}

impl ReconciliationPortResult {
    pub fn reconciled(
        session_id: SessionId,
        activation_generation: Generation,
        state_fence: FencingToken,
        receipt_ref: ReconciliationReceiptRef,
    ) -> Result<Self, BridgeError> {
        validate_authority_binding(&session_id, activation_generation, &state_fence)?;
        Ok(Self {
            session_id,
            activation_generation,
            state_fence,
            receipt_ref,
        })
    }

    pub const fn receipt_ref(&self) -> &ReconciliationReceiptRef {
        &self.receipt_ref
    }
}

/// Trusted external-attach reconciliation disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconciliationPortOutcome {
    Reconciled(ReconciliationPortResult),
    Denied { reason_code: &'static str },
}

/// Private proof that the trusted port reconciled the exact active authority.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ReconciliationPermit {
    session_id: SessionId,
    activation_generation: Generation,
    state_fence: FencingToken,
    receipt_ref: ReconciliationReceiptRef,
}

impl ReconciliationPermit {
    fn seal(result: ReconciliationPortResult) -> Result<Self, BridgeError> {
        validate_authority_binding(
            &result.session_id,
            result.activation_generation,
            &result.state_fence,
        )?;
        Ok(Self {
            session_id: result.session_id,
            activation_generation: result.activation_generation,
            state_fence: result.state_fence,
            receipt_ref: result.receipt_ref,
        })
    }
}

/// Phase selected by the receiving provider for durable cursor advancement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CursorPolicy {
    durable_control: AckPhase,
    durable_observation: AckPhase,
}

impl CursorPolicy {
    pub fn new(
        durable_control: AckPhase,
        durable_observation: AckPhase,
    ) -> Result<Self, BridgeError> {
        for phase in [durable_control, durable_observation] {
            if matches!(phase, AckPhase::Received | AckPhase::Unknown) {
                return Err(BridgeError::InvalidContract {
                    field: "cursor_policy",
                    reason: "cursor phase must declare a durable or terminal disposition",
                });
            }
        }
        Ok(Self {
            durable_control,
            durable_observation,
        })
    }

    const fn required_for(self, class: DeliveryClass) -> Option<AckPhase> {
        match class {
            DeliveryClass::DurableControl => Some(self.durable_control),
            DeliveryClass::DurableObservation => Some(self.durable_observation),
            DeliveryClass::BestEffortTelemetry => None,
        }
    }
}

/// Event forwarding result with explicit acknowledgement and cursor facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventForwardStatus {
    Durable {
        phase: AckPhase,
        disposition: EventDisposition,
        cursor_advanced: bool,
    },
    BestEffortForwarded,
    BestEffortGapSignalled {
        gap: CoverageGap,
    },
}

/// Exact process-local outstanding delivery retained until the configured
/// acknowledgement phase is reached.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutstandingDeliveryView {
    stream_id: String,
    event_id: String,
    sequence: u64,
    highest_phase: AckPhase,
    required_phase: AckPhase,
}

impl OutstandingDeliveryView {
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn highest_phase(&self) -> AckPhase {
        self.highest_phase
    }

    pub const fn required_phase(&self) -> AckPhase {
        self.required_phase
    }
}

#[derive(Clone)]
struct PendingDelivery {
    event: EventEnvelope,
    highest_phase: AckPhase,
    required_phase: AckPhase,
}

struct ActiveAttach {
    binding: AttachBinding,
    reconciliation_required: bool,
    blind_interval: Option<BlindInterval>,
}

/// The thin, restart-empty A-16 bridge core.
pub struct AgentBridgeCore {
    readiness: ProviderReadiness,
    host_activation: Option<Box<dyn HostActivationPort>>,
    mcp_forwarding: Option<Box<dyn McpForwardingPort>>,
    cursor_policy: CursorPolicy,
    active: Option<ActiveAttach>,
    replay: ReplayLedger,
    acknowledged_phases: BTreeMap<String, AckPhase>,
    pending_deliveries: BTreeMap<String, PendingDelivery>,
    cursors: BTreeMap<String, u64>,
}

impl AgentBridgeCore {
    pub fn new(
        readiness: ProviderReadiness,
        host_activation: Option<Box<dyn HostActivationPort>>,
        mcp_forwarding: Option<Box<dyn McpForwardingPort>>,
        cursor_policy: CursorPolicy,
    ) -> Self {
        Self {
            readiness,
            host_activation,
            mcp_forwarding,
            cursor_policy,
            active: None,
            replay: ReplayLedger::new(),
            acknowledged_phases: BTreeMap::new(),
            pending_deliveries: BTreeMap::new(),
            cursors: BTreeMap::new(),
        }
    }

    pub fn attach(&mut self, request: AttachRequest) -> Result<AttachView, BridgeError> {
        self.ensure_contracts()?;
        if !self.pending_deliveries.is_empty() {
            return Err(BridgeError::OutstandingDeliveryReconciliationRequired {
                count: self.pending_deliveries.len(),
            });
        }
        let host = self.host_activation.as_mut().ok_or_else(|| {
            BridgeError::PlanGap(PlanGap::missing(RequiredProvider::HostActivationPort))
        })?;
        let activation = host.activate(&request)?;
        let grant = match activation {
            ActivationPortOutcome::Authenticated(result) => ActivationGrant::seal(result)?,
            ActivationPortOutcome::Denied { reason_code } => {
                validate_text(reason_code, "activation_denial.reason_code")?;
                return Err(BridgeError::ActivationDenied(reason_code));
            }
        };
        if let Some(current) = &self.active {
            if grant.activation_generation < current.binding.activation_generation {
                return Err(BridgeError::StaleAuthority);
            }
            if grant.activation_generation == current.binding.activation_generation {
                if !current.binding.authority_matches(
                    &grant.session_id,
                    grant.activation_generation,
                    &grant.state_fence,
                ) {
                    return Err(BridgeError::StaleAuthority);
                }
                if request.connection_id != current.binding.connection_id {
                    return Err(BridgeError::InvalidTransition(
                        "transport replacement requires reconnect",
                    ));
                }
                return self.attach_view().ok_or(BridgeError::NotAttached);
            }
        }
        let active = ActiveAttach {
            binding: AttachBinding {
                principal_id: grant.principal_id,
                session_id: grant.session_id,
                connection_id: request.connection_id,
                activation_generation: grant.activation_generation,
                state_fence: grant.state_fence,
            },
            reconciliation_required: request.attach_kind == AttachKind::External,
            blind_interval: request.pre_attach_blind_interval,
        };
        self.active = Some(active);
        self.replay = ReplayLedger::new();
        self.acknowledged_phases.clear();
        self.cursors.clear();
        self.attach_view().ok_or(BridgeError::NotAttached)
    }

    pub fn reconnect(&mut self, request: ReconnectRequest) -> Result<AttachView, BridgeError> {
        let active = self.active.as_mut().ok_or(BridgeError::NotAttached)?;
        if !active.binding.authority_matches(
            &request.session_id,
            request.activation_generation,
            &request.state_fence,
        ) {
            return Err(BridgeError::StaleAuthority);
        }
        active.binding.connection_id = request.new_connection_id;
        self.attach_view().ok_or(BridgeError::NotAttached)
    }

    pub fn reconcile_external(&mut self) -> Result<AttachView, BridgeError> {
        self.ensure_contracts()?;
        let binding = {
            let active = self.active.as_ref().ok_or(BridgeError::NotAttached)?;
            if active.blind_interval.is_none() || !active.reconciliation_required {
                return Err(BridgeError::InvalidTransition(
                    "only an unreconciled external attach accepts a reconciliation result",
                ));
            }
            active.binding.clone()
        };
        let outcome = self.forwarder()?.reconcile_external(&binding)?;
        let permit = match outcome {
            ReconciliationPortOutcome::Reconciled(result) => ReconciliationPermit::seal(result)?,
            ReconciliationPortOutcome::Denied { reason_code } => {
                validate_text(reason_code, "reconciliation_denial.reason_code")?;
                return Err(BridgeError::ExternalReconciliationDenied(reason_code));
            }
        };
        let active = self.active.as_mut().ok_or(BridgeError::NotAttached)?;
        if active.blind_interval.is_none() || !active.reconciliation_required {
            return Err(BridgeError::InvalidTransition(
                "external attach changed during reconciliation",
            ));
        }
        if !active.binding.authority_matches(
            &permit.session_id,
            permit.activation_generation,
            &permit.state_fence,
        ) {
            return Err(BridgeError::StaleAuthority);
        }
        validate_text(permit.receipt_ref.as_str(), "reconciliation_receipt_ref")?;
        active.reconciliation_required = false;
        self.attach_view().ok_or(BridgeError::NotAttached)
    }

    pub fn attach_view(&self) -> Option<AttachView> {
        self.active.as_ref().map(|active| AttachView {
            binding: active.binding.clone(),
            reconciliation_required: active.reconciliation_required,
            pre_attach_proof_ceiling: active
                .blind_interval
                .as_ref()
                .map(|_| ProofCeiling::CandidateOnly),
        })
    }

    pub fn forward_frame(&mut self, frame: &Frame) -> Result<(), BridgeError> {
        self.ensure_forwardable()?;
        frame
            .validate()
            .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
        let binding = self.binding()?.clone();
        if frame.connection_id != binding.connection_id.as_str() {
            return Err(BridgeError::StaleTransport);
        }
        self.forwarder()?.forward_frame(&binding, frame)?;
        Ok(())
    }

    pub fn forward_hook(&mut self, event: &HostEventEnvelope) -> Result<(), BridgeError> {
        self.ensure_forwardable()?;
        event
            .validate()
            .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
        let binding = self.binding()?.clone();
        self.forwarder()?.forward_hook(&binding, event)?;
        Ok(())
    }

    pub fn forward_event(
        &mut self,
        event: &EventEnvelope,
    ) -> Result<EventForwardStatus, BridgeError> {
        self.ensure_forwardable()?;
        event
            .validate()
            .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
        let binding = self.binding()?.clone();
        Self::validate_event_binding(&binding, event)?;

        match event.delivery_class {
            DeliveryClass::DurableControl | DeliveryClass::DurableObservation => {
                self.forward_durable(&binding, event)
            }
            DeliveryClass::BestEffortTelemetry => self.forward_best_effort(&binding, event),
        }
    }

    pub fn cursor(&self, stream_id: &str) -> Option<u64> {
        self.cursors.get(stream_id).copied()
    }

    pub fn outstanding_deliveries(&self) -> Vec<OutstandingDeliveryView> {
        self.pending_deliveries
            .values()
            .map(|pending| OutstandingDeliveryView {
                stream_id: pending.event.stream_id.clone(),
                event_id: pending.event.event_id.clone(),
                sequence: pending.event.sequence,
                highest_phase: pending.highest_phase,
                required_phase: pending.required_phase,
            })
            .collect()
    }

    fn forward_durable(
        &mut self,
        binding: &AttachBinding,
        event: &EventEnvelope,
    ) -> Result<EventForwardStatus, BridgeError> {
        if !event.ack_required {
            return Err(BridgeError::InvalidContract {
                field: "event.ack_required",
                reason: "durable events require an explicit acknowledgement",
            });
        }
        let replay_key = format!("{}:{}", event.stream_id, event.event_id);
        let mut completed_probe = self.replay.clone();
        match completed_probe
            .observe(event)
            .map_err(|error| BridgeError::ProviderContract(error.to_string()))?
        {
            EventDisposition::Duplicate => {
                let phase = self.acknowledged_phases.get(&replay_key).copied().ok_or(
                    BridgeError::InvalidTransition(
                        "duplicate replay has no prior explicit acknowledgement",
                    ),
                )?;
                return Ok(EventForwardStatus::Durable {
                    phase,
                    disposition: EventDisposition::Duplicate,
                    cursor_advanced: false,
                });
            }
            EventDisposition::Accepted => {}
            other => {
                return Err(BridgeError::InvalidEventDisposition(other));
            }
        }

        let required_phase = self
            .cursor_policy
            .required_for(event.delivery_class)
            .ok_or(BridgeError::InvalidTransition(
                "durable event has no configured acknowledgement phase",
            ))?;
        if let Some(pending) = self.pending_deliveries.get(&replay_key) {
            if pending.event != *event {
                return Err(BridgeError::ProviderContract(
                    "replay conflict for an outstanding event identity".to_owned(),
                ));
            }
            if pending.required_phase != required_phase {
                return Err(BridgeError::InvalidTransition(
                    "cursor policy changed while an event remained outstanding",
                ));
            }
        }

        let outcome = self.forwarder()?.forward_event(binding, event)?;
        let EventPortOutcome::Acknowledged(ack) = outcome else {
            return Err(BridgeError::MissingDurableAck);
        };
        if ack.stream_id != event.stream_id || ack.event_id != event.event_id {
            return Err(BridgeError::AckIdentityMismatch);
        }
        if ack.disposition == EventDisposition::Conflict {
            return Err(BridgeError::InvalidEventDisposition(ack.disposition));
        }
        if let Some(previous) = self.pending_deliveries.get(&replay_key) {
            EventAckReceipt::validate_advance(previous.highest_phase, ack.phase)
                .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
        }

        let cursor_advanced = phase_reaches(required_phase, ack.phase);
        if cursor_advanced {
            self.replay = completed_probe;
            self.pending_deliveries.remove(&replay_key);
            self.acknowledged_phases
                .insert(replay_key.clone(), ack.phase);
            self.cursors
                .entry(event.stream_id.clone())
                .and_modify(|cursor| *cursor = (*cursor).max(event.sequence))
                .or_insert(event.sequence);
        } else {
            self.pending_deliveries.insert(
                replay_key,
                PendingDelivery {
                    event: event.clone(),
                    highest_phase: ack.phase,
                    required_phase,
                },
            );
        }
        Ok(EventForwardStatus::Durable {
            phase: ack.phase,
            disposition: ack.disposition,
            cursor_advanced,
        })
    }

    fn forward_best_effort(
        &mut self,
        binding: &AttachBinding,
        event: &EventEnvelope,
    ) -> Result<EventForwardStatus, BridgeError> {
        match self.forwarder()?.forward_event(binding, event)? {
            EventPortOutcome::BestEffortForwarded => Ok(EventForwardStatus::BestEffortForwarded),
            EventPortOutcome::BestEffortDropped { reason_ref } => {
                validate_text(&reason_ref, "telemetry_gap.reason_ref")?;
                let gap = CoverageGap {
                    gap_id: format!("a16-telemetry-gap:{}:{}", event.stream_id, event.event_id),
                    obligation_profile_ref: "A-16:best-effort-telemetry".to_owned(),
                    reason_ref,
                    affected_interval: Some(
                        CoverageInterval::new(event.sequence, event.sequence)
                            .map_err(|error| BridgeError::ProviderContract(error.to_string()))?,
                    ),
                    disposition: GapDisposition::DegradeDependentGuarantees,
                    protected: false,
                    evidence_refs: vec![event.event_id.clone()],
                };
                gap.validate()
                    .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
                self.forwarder()?.forward_gap(binding, &gap)?;
                Ok(EventForwardStatus::BestEffortGapSignalled { gap })
            }
            EventPortOutcome::Acknowledged(_) => Err(BridgeError::InvalidTransition(
                "best-effort telemetry cannot impersonate a durable acknowledgement",
            )),
        }
    }

    fn validate_event_binding(
        binding: &AttachBinding,
        event: &EventEnvelope,
    ) -> Result<(), BridgeError> {
        let fence = binding.state_fence();
        if event.authority_epoch.value() != fence.authority_epoch()
            || event.state_fence.authority_epoch.value() != fence.authority_epoch()
            || event.producer_generation.value() != fence.generation().get()
            || event.state_fence.resource_generation.value() != fence.generation().get()
        {
            return Err(BridgeError::StaleAuthority);
        }
        Ok(())
    }

    fn ensure_contracts(&self) -> Result<(), BridgeError> {
        self.readiness
            .first_gap()
            .map_or(Ok(()), |gap| Err(BridgeError::PlanGap(gap)))
    }

    fn ensure_forwardable(&self) -> Result<(), BridgeError> {
        self.ensure_contracts()?;
        let active = self.active.as_ref().ok_or(BridgeError::NotAttached)?;
        if active.reconciliation_required {
            return Err(BridgeError::ExternalAttachReconciliationRequired);
        }
        if self.mcp_forwarding.is_none() {
            return Err(BridgeError::PlanGap(PlanGap::missing(
                RequiredProvider::McpForwardingPort,
            )));
        }
        Ok(())
    }

    fn binding(&self) -> Result<&AttachBinding, BridgeError> {
        self.active
            .as_ref()
            .map(|active| &active.binding)
            .ok_or(BridgeError::NotAttached)
    }

    fn forwarder(&mut self) -> Result<&mut (dyn McpForwardingPort + 'static), BridgeError> {
        self.mcp_forwarding.as_deref_mut().ok_or_else(|| {
            BridgeError::PlanGap(PlanGap::missing(RequiredProvider::McpForwardingPort))
        })
    }
}

fn validate_authority_binding(
    session_id: &SessionId,
    activation_generation: Generation,
    state_fence: &FencingToken,
) -> Result<(), BridgeError> {
    validate_text(session_id.as_str(), "session_id")?;
    if activation_generation.get() == 0
        || state_fence.authority_epoch() == 0
        || state_fence.generation().get() == 0
    {
        return Err(BridgeError::InvalidContract {
            field: "authority_binding",
            reason: "session generation and authority epoch must be non-zero",
        });
    }
    if state_fence.generation() != activation_generation {
        return Err(BridgeError::InvalidContract {
            field: "state_fence.generation",
            reason: "must match activation_generation",
        });
    }
    validate_text(state_fence.nonce(), "state_fence.nonce")
}

const fn phase_reaches(required: AckPhase, observed: AckPhase) -> bool {
    match required {
        AckPhase::Durable => matches!(
            observed,
            AckPhase::Durable | AckPhase::Normalized | AckPhase::Applied
        ),
        AckPhase::Normalized => matches!(observed, AckPhase::Normalized | AckPhase::Applied),
        AckPhase::Applied => matches!(observed, AckPhase::Applied),
        AckPhase::Rejected => matches!(observed, AckPhase::Rejected),
        AckPhase::Received | AckPhase::Unknown => false,
    }
}

/// Sanitized injected-provider failure. It must not contain credentials or raw
/// provider response bodies.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("provider {provider} failed: {reason}")]
pub struct ProviderFailure {
    provider: &'static str,
    reason: &'static str,
}

impl ProviderFailure {
    pub const fn new(provider: &'static str, reason: &'static str) -> Self {
        Self { provider, reason }
    }
}

/// Fail-closed bridge contract errors.
#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("{PLAN_GAP}: missing admitted provider {0:?}")]
    PlanGap(PlanGap),
    #[error("invalid bridge contract field {field}: {reason}")]
    InvalidContract {
        field: &'static str,
        reason: &'static str,
    },
    #[error("provider contract rejected input: {0}")]
    ProviderContract(String),
    #[error(transparent)]
    Provider(#[from] ProviderFailure),
    #[error("bridge is not attached")]
    NotAttached,
    #[error("activation denied by the trusted host provider: {0}")]
    ActivationDenied(&'static str),
    #[error("stale session, generation, or state fence")]
    StaleAuthority,
    #[error("frame is bound to a stale transport connection")]
    StaleTransport,
    #[error("EXTERNAL_ATTACH_RECONCILIATION_REQUIRED")]
    ExternalAttachReconciliationRequired,
    #[error("external attach reconciliation denied: {0}")]
    ExternalReconciliationDenied(&'static str),
    #[error("outstanding durable delivery reconciliation required for {count} event(s)")]
    OutstandingDeliveryReconciliationRequired { count: usize },
    #[error("invalid bridge transition: {0}")]
    InvalidTransition(&'static str),
    #[error("durable event provider did not return an explicit acknowledgement phase")]
    MissingDurableAck,
    #[error("event acknowledgement identity does not match the forwarded event")]
    AckIdentityMismatch,
    #[error("provider returned invalid event disposition {0:?}")]
    InvalidEventDisposition(EventDisposition),
}

impl fmt::Debug for AgentBridgeCore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentBridgeCore")
            .field("authority_ceiling", &AUTHORITY_CEILING)
            .field("attached", &self.active.is_some())
            .field("replay_entries", &self.replay.len())
            .field("outstanding_deliveries", &self.pending_deliveries.len())
            .finish_non_exhaustive()
    }
}
