//! A-16 thin demand-start bridge core.
//!
//! This library owns only host-shim transport state. It has no process-spawn,
//! authentication, semantic-session, persistence, database, or completion
//! authority. All such decisions arrive through injected ports and remain
//! bound to the exact session, generation, and fence that produced them.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::ops::Bound::{Excluded, Unbounded};
use std::pin::Pin;

pub use eliot_agent_api::{
    AttemptId, AttemptState, EventCursor, EventId, HostEventEnvelope, HostEventKind,
    RouteFingerprint, SessionId, TaskId, WorkUnitId,
};
use eliot_contracts::RequestMetadata;
pub use eliot_observation_contracts::{
    BlindInterval, CoverageGap, CoverageInterval, GapDisposition,
};
pub use eliot_process::{FencingToken, Generation};
pub use eliot_protocol::{AckPhase, DeliveryClass, EventDisposition, EventEnvelope};
use eliot_protocol::{EventAckReceipt, EventIdentityKey, ReplayLedger};
use eliot_skill::{
    ActivatedSkillDisplay, DependencyVersion, HotsetDeliveryAck, HotsetDeliveryReceipt,
    LifecycleAction, SkillCandidate, SkillError, SkillLifecycleView, SkillScope,
};
use serde::{Deserialize, Deserializer, Serialize, de};
use sha2::{Digest, Sha256};
use thiserror::Error;

mod resources;
pub use resources::{
    DeliveryStatus, HotResourceView, MAX_CONTENT_BYTES, MAX_PREVIEW_BYTES, MAX_REGISTRY_ENTRIES,
    MAX_URI_BYTES, ResourceHandle, ResourceKind, ResourceRegistry, ResourceUri, ToolResultReceipt,
};
mod skill_transport;
pub use skill_transport::{
    MAX_CARRY_BYTES, MAX_EXECUTION_RECORDS, MAX_INTAKE_BYTES, SKILL_ACTIVATE_TOOL,
    SKILL_DISPLAY_TOOL, SKILL_EXECUTE_TOOL, SKILL_INJECT_TOOL, SKILL_TRANSPORT_CONTRACT_ID,
    SKILL_TRANSPORT_VERSION, SkillAckPayload, SkillActivationPayload, SkillDisplayPayload,
    SkillExecutionPayload, SkillIntakePayload, SkillResultEnvelope, SkillResultOutcome,
    SkillToolKind, SkillTransportError, skill_tool_kind,
};
mod route_tokens;
pub use route_tokens::{
    MAX_MEASUREMENT_WIRE_BYTES, RouteTokenObservation, RouteTokenizer,
    TOKEN_MEASUREMENT_CONTRACT_ID, TOKEN_MEASUREMENT_VERSION, TokenMeasurementPayload,
    UnmeasuredReason, produce_route_token_observation,
};
mod terminal_inputs;
pub use terminal_inputs::{
    AttemptTransition, CanonicalWriteRefs, CoverageFlags, RecoveryDirective, RecoveryDirectiveKind,
    TERMINAL_JOURNAL_CAPACITY, TerminalReductionInputs, TransportEdge, TransportEdgeKind,
};

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
    SkillLifecyclePort,
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
            Self::SkillLifecyclePort => "injected Skill lifecycle port",
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
    /// Starts with every provider unprobed and therefore unavailable.
    ///
    /// Readiness is an observation, not a construction default. Composition
    /// owners must admit each provider only after its exact operation probe
    /// succeeds.
    pub fn unprobed() -> Self {
        Self {
            admitted: RequiredProvider::ALL_CONTRACTS
                .into_iter()
                .map(|provider| (provider, false))
                .collect(),
        }
    }

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

    /// Records one exact operation-probe result for a provider.
    #[must_use]
    pub fn with_probe_result(mut self, provider: RequiredProvider, admitted: bool) -> Self {
        self.admitted.insert(provider, admitted);
        self
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.first_gap().is_none()
    }

    #[must_use]
    pub fn first_unavailable(&self) -> Option<RequiredProvider> {
        self.first_gap().map(|gap| gap.missing_provider)
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

/// Exact task, work-scope, and admitted-plan revision resolved by the trusted
/// host activation provider. A-16 exposes this projection read-only and does
/// not offer a public constructor for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskBinding {
    task_id: TaskId,
    work_unit_id: WorkUnitId,
    work_scope_id: String,
    task_revision: String,
    plan_id: String,
    plan_revision: String,
}

impl TaskBinding {
    fn seal(
        task_id: TaskId,
        work_unit_id: WorkUnitId,
        work_scope_id: impl Into<String>,
        task_revision: impl Into<String>,
        plan_id: impl Into<String>,
        plan_revision: impl Into<String>,
    ) -> Result<Self, BridgeError> {
        let work_scope_id = work_scope_id.into();
        let task_revision = task_revision.into();
        let plan_id = plan_id.into();
        let plan_revision = plan_revision.into();
        validate_text(task_id.as_str(), "task_binding.task_id")?;
        validate_text(work_unit_id.as_str(), "task_binding.work_unit_id")?;
        validate_text(&work_scope_id, "task_binding.work_scope_id")?;
        validate_text(&task_revision, "task_binding.task_revision")?;
        validate_text(&plan_id, "task_binding.plan_id")?;
        validate_text(&plan_revision, "task_binding.plan_revision")?;
        Ok(Self {
            task_id,
            work_unit_id,
            work_scope_id,
            task_revision,
            plan_id,
            plan_revision,
        })
    }

    pub const fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub const fn work_unit_id(&self) -> &WorkUnitId {
        &self.work_unit_id
    }

    pub fn work_scope_id(&self) -> &str {
        &self.work_scope_id
    }

    pub fn task_revision(&self) -> &str {
        &self.task_revision
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn plan_revision(&self) -> &str {
        &self.plan_revision
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
    task_binding: Box<TaskBinding>,
}

impl ActivationPortResult {
    #[allow(clippy::too_many_arguments)]
    pub fn authenticated(
        principal_id: PrincipalId,
        session_id: SessionId,
        activation_generation: Generation,
        state_fence: FencingToken,
        task_id: TaskId,
        work_unit_id: WorkUnitId,
        work_scope_id: impl Into<String>,
        task_revision: impl Into<String>,
        plan_id: impl Into<String>,
        plan_revision: impl Into<String>,
    ) -> Result<Self, BridgeError> {
        validate_authority_binding(&session_id, activation_generation, &state_fence)?;
        let task_binding = TaskBinding::seal(
            task_id,
            work_unit_id,
            work_scope_id,
            task_revision,
            plan_id,
            plan_revision,
        )?;
        Ok(Self {
            principal_id,
            session_id,
            activation_generation,
            state_fence,
            task_binding: Box::new(task_binding),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActivationGrant {
    principal_id: PrincipalId,
    session_id: SessionId,
    activation_generation: Generation,
    state_fence: FencingToken,
    task_binding: TaskBinding,
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
            task_binding: *result.task_binding,
        })
    }
}

/// I7.20 agent-facing activation disposition registry (closed control layer).
///
/// Per `docs/architecture/I07-20-agent-facing-error-contract.md`, agent-facing
/// failure control has two layers: `AgentResponseDisposition` (small closed
/// control enum) and `reason_code` (open versioned registry). Bridges switch
/// on the stable disposition and MAY specialize known reason codes.
pub const ACTIVATION_DISPOSITION_INVALID_REQUEST: &str = "INVALID_REQUEST";
/// I7.20 stale/conflict disposition: retry requires a new ticket, the stale
/// fence fails closed; the bridge never auto-selects a candidate.
pub const ACTIVATION_DISPOSITION_STALE_OR_CONFLICT: &str = "STALE_OR_CONFLICT";
/// I7.20 unavailable/capacity disposition: fail-closed with a failure capsule.
pub const ACTIVATION_DISPOSITION_UNAVAILABLE_OR_CAPACITY: &str = "UNAVAILABLE_OR_CAPACITY";
/// I7.20 terminal failure disposition: fail-closed with a failure capsule.
pub const ACTIVATION_DISPOSITION_FAILED: &str = "FAILED";

/// I7.20 directive kind for candidate recovery: present candidates only, the
/// agent (never the bridge) selects; no auto-selection.
pub const ACTIVATION_DIRECTIVE_CANDIDATE_RECOVERY: &str = "candidate-recovery-no-auto-selection";
/// I7.20 directive kind for stale/conflict: the retry requires a new ticket.
pub const ACTIVATION_DIRECTIVE_RETRY_NEW_TICKET: &str = "retry-requires-new-ticket";
/// I7.20 directive kind for stale fences: fail closed, never reuse authority.
pub const ACTIVATION_DIRECTIVE_FENCE_CLOSED: &str = "stale-fence-fail-closed";
/// I7.20 directive kind for failures: carry the typed failure capsule.
pub const ACTIVATION_DIRECTIVE_FAILURE_CAPSULE: &str = "failure-capsule";

/// I7.20 agent-facing denial report: disposition + catalogue `reason_code` +
/// directive plus the exact owner-issued denial detail.
///
/// Every non-success response includes the disposition, the exact
/// `reason_code`, the applicable Recovery or Conflict Directive, and the same
/// operation identity when one exists. The bridge surfaces the report
/// read-only and fails closed; it never auto-selects among candidates and
/// never collapses distinct candidate sets, retry bounds, or failure handles
/// into one static string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationDenialReport {
    reason_code: &'static str,
    disposition: &'static str,
    directive_kind: &'static str,
    operation: String,
    detail: Option<eliot_protocol::AgentActivationResolutionDisposition>,
}

impl ActivationDenialReport {
    /// Seals one denial report. All legs are required; silence and generic
    /// internal-error prose are not normal control behavior. The `detail`
    /// carries the exact owner-issued typed disposition and is `None` only
    /// for the Kernel-owned no-result refusal, which has no daemon
    /// disposition to project. A malformed leg fails as a provider contract
    /// rejection: the legs arrive from the trusted provider projection, so a
    /// blank leg means the provider violated its contract.
    pub fn new(
        reason_code: &'static str,
        disposition: &'static str,
        directive_kind: &'static str,
        operation: String,
        detail: Option<eliot_protocol::AgentActivationResolutionDisposition>,
    ) -> Result<Self, ProviderFailure> {
        validate_text(reason_code, "activation_denial.reason_code").map_err(|_| {
            ProviderFailure::new(
                "eliot-agent-bridge-core",
                "activation denial reason must be non-blank",
            )
        })?;
        validate_text(disposition, "activation_denial.disposition").map_err(|_| {
            ProviderFailure::new(
                "eliot-agent-bridge-core",
                "activation denial disposition must be non-blank",
            )
        })?;
        validate_text(directive_kind, "activation_denial.directive_kind").map_err(|_| {
            ProviderFailure::new(
                "eliot-agent-bridge-core",
                "activation denial directive must be non-blank",
            )
        })?;
        validate_text(&operation, "activation_denial.operation").map_err(|_| {
            ProviderFailure::new(
                "eliot-agent-bridge-core",
                "activation denial operation must be non-blank",
            )
        })?;
        Ok(Self {
            reason_code,
            disposition,
            directive_kind,
            operation,
            detail,
        })
    }

    /// Catalogue `reason_code` from the I7.20 reason registry (open layer);
    /// legacy transport codes arrive already projected to their catalogue
    /// alias and unknown future codes pass through verbatim.
    pub const fn reason_code(&self) -> &'static str {
        self.reason_code
    }

    /// Closed I7.20 control disposition the bridge switches on.
    pub const fn disposition(&self) -> &'static str {
        self.disposition
    }

    /// Applicable Recovery or Conflict Directive kind; never auto-selected.
    pub const fn directive_kind(&self) -> &'static str {
        self.directive_kind
    }

    /// Operation identity (the exact demand) this denial answers.
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Exact owner-issued denial detail; `None` only for the Kernel-owned
    /// no-result refusal.
    pub const fn detail(&self) -> Option<&eliot_protocol::AgentActivationResolutionDisposition> {
        self.detail.as_ref()
    }

    /// Renders the exact agent-facing denial detail: disposition, catalogue
    /// reason, directive, operation correlation, and the differing
    /// owner-issued payload (candidate handles plus coverage plus recovery
    /// handle; retry dependency plus observed revision plus earliest-retry
    /// bound; observed fence plus recovery handle; or failure handle).
    /// Two denials with different candidate sets, retry bounds, or failure
    /// handles render differently; nothing here is reconstructed from reason
    /// text.
    pub fn agent_detail(&self) -> String {
        let payload = match &self.detail {
            None => "no-typed-result".to_owned(),
            Some(
                eliot_protocol::AgentActivationResolutionDisposition::TaskSelectionRequired {
                    selection,
                }
                | eliot_protocol::AgentActivationResolutionDisposition::ScopeSelectionRequired {
                    selection,
                }
                | eliot_protocol::AgentActivationResolutionDisposition::ScopeAmbiguous { selection },
            ) => {
                let candidates = serde_json::to_string(&selection.candidate_handles)
                    .unwrap_or_else(|_| "[]".to_owned());
                format!(
                    "candidates={} coverage={:?} recovery={}",
                    candidates, selection.candidate_coverage, selection.recovery_handle
                )
            }
            Some(eliot_protocol::AgentActivationResolutionDisposition::NotReady {
                recovery_handle,
                retry,
            }) => format!(
                "recovery={} dependency={} observed_revision={} not_before_unix_ms={}",
                recovery_handle,
                retry.dependency_ref,
                retry.observed_dependency_revision,
                retry.not_before_unix_ms
            ),
            Some(eliot_protocol::AgentActivationResolutionDisposition::StaleFence {
                recovery_handle,
                observed_state_fence,
            }) => match observed_state_fence {
                Some(fence) => format!("recovery={recovery_handle} observed_fence={fence:?}"),
                None => format!("recovery={recovery_handle} observed_fence=none"),
            },
            Some(eliot_protocol::AgentActivationResolutionDisposition::FailedInternal {
                failure_handle,
            }) => format!("failure={failure_handle}"),
            Some(eliot_protocol::AgentActivationResolutionDisposition::Resolved { .. }) => {
                "invalid-resolved-in-denial".to_owned()
            }
        };
        format!(
            "activation denied: disposition={} reason={} directive={} operation={} {}",
            self.disposition, self.reason_code, self.directive_kind, self.operation, payload
        )
    }
}

impl fmt::Display for ActivationDenialReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.agent_detail())
    }
}

/// Trusted activation-port disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivationPortOutcome {
    Authenticated(ActivationPortResult),
    /// I7.20 detailed denial carrying the disposition, the catalogue
    /// `reason_code`, and the directive triple plus the exact owner-issued
    /// denial detail. Fails closed via [`BridgeError::ActivationDenied`];
    /// the extra legs travel to the agent-facing projection instead of being
    /// discarded at the port.
    Denied(ActivationDenialReport),
    /// No valid terminal result arrived before the ticket deadline. Distinct
    /// from every typed negative: the Kernel may still hold or expire the
    /// ticket on its own leg, but this port observed the deadline pass with
    /// no terminal result.
    DeadlineExceeded {
        operation: String,
        deadline_unix_ms: u64,
    },
    /// The transport exchange ended with no terminal result while the ticket
    /// deadline had not passed, so the outcome is unknown rather than denied:
    /// never one of the known negatives, never a success, and never authority.
    UnknownOutcome {
        operation: String,
    },
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

    /// Confirms process-local cursor-cache effects only after the core has
    /// accepted the complete owner response into its recovery view.
    ///
    /// Every implementation must state how it commits those effects. The
    /// production Kernel forwarding port applies owner ack bases and only
    /// owner-confirmed offered consumed frontiers after import; fixtures with
    /// no process-local cursor cache implement this as an explicit no-op.
    fn reconciliation_imported(
        &mut self,
        binding: &AttachBinding,
        result: &ReconciliationPortResult,
    );

    /// Reads one bounded recovery page inside the declared window.
    ///
    /// A pure continuation read: it changes no producer/consumer cursor and
    /// carries the exact contiguous acknowledgement frontier derived from
    /// the receiving owner's receipts, like the full read. The default
    /// owner refuses: only a forwarding owner that speaks the bounded
    /// continuation route may answer, so stub ports keep compiling while
    /// failing closed when a walk actually needs them.
    fn reconcile_continue(
        &mut self,
        binding: &AttachBinding,
        request: &RecoveryReadRequest,
    ) -> Result<ReconciliationPortOutcome, ProviderFailure> {
        let _ = (binding, request);
        Err(ProviderFailure::new(
            "eliot-agent-bridge-core",
            "bounded recovery continuation is not admitted by this forwarding owner; \
             reconcile the full window through reconcile_external instead",
        ))
    }
}

/// Current attach binding projected by the bridge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachBinding {
    principal_id: PrincipalId,
    session_id: SessionId,
    connection_id: ConnectionId,
    activation_generation: Generation,
    state_fence: FencingToken,
    task_binding: TaskBinding,
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

    pub const fn task_binding(&self) -> &TaskBinding {
        &self.task_binding
    }

    fn authority_matches(
        &self,
        session_id: &SessionId,
        generation: Generation,
        fence: &FencingToken,
        task_binding: &TaskBinding,
    ) -> bool {
        self.transport_authority_matches(session_id, generation, fence)
            && &self.task_binding == task_binding
    }

    fn transport_authority_matches(
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

/// One stream's recovered progress inside the declared window.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveryStreamView {
    stream_id: String,
    acked_base: u64,
    durable_cursor: u64,
    contiguous_frontier: u64,
    highest_observed: u64,
    next_after: u64,
    recovered_events: u64,
    recovered_gaps: u64,
    page_complete: bool,
}

impl RecoveryStreamView {
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub const fn acked_base(&self) -> u64 {
        self.acked_base
    }

    pub const fn durable_cursor(&self) -> u64 {
        self.durable_cursor
    }

    pub const fn contiguous_frontier(&self) -> u64 {
        self.contiguous_frontier
    }

    pub const fn highest_observed(&self) -> u64 {
        self.highest_observed
    }

    pub const fn next_after(&self) -> u64 {
        self.next_after
    }

    pub const fn recovered_events(&self) -> u64 {
        self.recovered_events
    }

    pub const fn recovered_gaps(&self) -> u64 {
        self.recovered_gaps
    }

    pub const fn page_complete(&self) -> bool {
        self.page_complete
    }
}

/// Read-only progress of the declared finite recovery window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryView {
    window_key: String,
    live_generation: u64,
    streams: Vec<RecoveryStreamView>,
    unscoped_gaps: u64,
    unproven_scope_present: bool,
    stream_list_complete: bool,
    unscoped_gaps_complete: bool,
    disposition: RecoveryDisposition,
}

impl RecoveryView {
    pub fn window_key(&self) -> &str {
        &self.window_key
    }

    pub const fn live_generation(&self) -> u64 {
        self.live_generation
    }

    pub fn streams(&self) -> &[RecoveryStreamView] {
        &self.streams
    }

    pub const fn unscoped_gaps(&self) -> u64 {
        self.unscoped_gaps
    }

    pub const fn unproven_scope_present(&self) -> bool {
        self.unproven_scope_present
    }

    pub const fn stream_list_complete(&self) -> bool {
        self.stream_list_complete
    }

    pub const fn unscoped_gaps_complete(&self) -> bool {
        self.unscoped_gaps_complete
    }

    pub const fn disposition(&self) -> RecoveryDisposition {
        self.disposition
    }
}

/// One bounded read-only page through the identities retained in a recovery
/// window. The continuation is scoped to the current window, attach
/// generation, and imported-owner-page revision; importing another owner
/// page makes an earlier continuation stale instead of silently skipping
/// facts added before its keyset position.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryProjectionPage {
    /// `None` means no owner recovery window has been imported yet.
    pub summary: Option<RecoveryProjectionSummary>,
    /// At most `MAX_RECOVERY_PROJECTION_ITEMS` facts, in stream, event,
    /// scoped-gap, then unscoped-gap order.
    pub items: Vec<RecoveryProjectionRecord>,
    /// Opaque continuation for the next bounded read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Compact status for the whole imported recovery window. Fact identities
/// are available only through `RecoveryProjectionPage::items`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryProjectionSummary {
    pub live_generation: u64,
    pub stream_count: usize,
    pub unscoped_gap_count: usize,
    pub unproven_scope_present: bool,
    pub stream_list_complete: bool,
    pub unscoped_gaps_complete: bool,
    pub disposition: RecoveryDisposition,
}

/// A single checked record from the recovery window. Event records contain
/// receipt metadata and digest references only; they never synthesize an
/// `EventEnvelope` from those fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "record", rename_all = "snake_case")]
pub enum RecoveryProjectionRecord {
    Stream(RecoveryStreamView),
    Event(RecoveryProjectionEvent),
    Gap(RecoveredGapFact),
}

/// The current local obligation state for one imported checked receipt.
/// Every owner event identity remains in the page even after local coverage;
/// this label distinguishes pending work from an active delivery or a
/// receipt already covered by the bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryProjectionObligation {
    Pending,
    DeliveryInProgress,
    Covered,
}

/// One imported event receipt and its current bridge-local obligation state.
/// The receipt is still digest-only and is never converted into an event
/// envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryProjectionEvent {
    pub receipt: RecoveredEventFact,
    pub obligation: RecoveryProjectionObligation,
}

const MAX_RECOVERY_PROJECTION_ITEMS: usize = 32;
const MAX_RECOVERY_PROJECTION_SCANS: usize = 256;
const MAX_RECOVERY_PROJECTION_CURSOR_BYTES: usize = 16_384;
const MAX_RECOVERY_PROJECTION_CURSOR_GAP_KEY_BYTES: usize = 1_024;
/// Leaves room below the bridge's 512 KiB output frame for the containing
/// response and its stdio framing.
const MAX_RECOVERY_PROJECTION_PAGE_BYTES: usize = 384 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecoveryProjectionSection {
    Streams,
    Pending,
    ScopedGaps,
    UnscopedGaps,
    Done,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryProjectionCursor {
    version: u8,
    window_digest: String,
    live_generation: u64,
    import_revision: u64,
    section: RecoveryProjectionSection,
    stream_index: usize,
    after_sequence: Option<u64>,
    after_gap_id: Option<String>,
}

fn recovery_window_digest(window_key: &str) -> String {
    let digest = Sha256::digest(window_key.as_bytes());
    encode_hex(&digest)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_recovery_projection_cursor(
    cursor: &RecoveryProjectionCursor,
) -> Result<String, BridgeError> {
    if cursor
        .after_gap_id
        .as_ref()
        .is_some_and(|gap_id| gap_id.len() > MAX_RECOVERY_PROJECTION_CURSOR_GAP_KEY_BYTES)
    {
        return Err(BridgeError::InvalidTransition(
            "recovery gap identity exceeds the bounded cursor; owner index or handle required",
        ));
    }
    let claims = serde_json::to_vec(cursor).map_err(|_| {
        BridgeError::InvalidTransition("recovery projection cursor could not be encoded")
    })?;
    let encoded_len = claims.len().saturating_mul(2).saturating_add(4);
    if encoded_len > MAX_RECOVERY_PROJECTION_CURSOR_BYTES {
        return Err(BridgeError::InvalidTransition(
            "recovery projection cursor exceeds its byte bound",
        ));
    }
    let mut token = String::with_capacity(encoded_len);
    token.push_str("rp1:");
    token.push_str(&encode_hex(&claims));
    Ok(token)
}

fn decode_recovery_projection_cursor(token: &str) -> Result<RecoveryProjectionCursor, BridgeError> {
    if token.len() > MAX_RECOVERY_PROJECTION_CURSOR_BYTES {
        return Err(BridgeError::InvalidTransition(
            "invalid recovery projection cursor",
        ));
    }
    let encoded =
        token
            .strip_prefix("rp1:")
            .and_then(decode_hex)
            .ok_or(BridgeError::InvalidTransition(
                "invalid recovery projection cursor",
            ))?;
    let cursor: RecoveryProjectionCursor = serde_json::from_slice(&encoded)
        .map_err(|_| BridgeError::InvalidTransition("invalid recovery projection cursor"))?;
    if cursor.version != 1
        || cursor.window_digest.len() != 64
        || !cursor
            .window_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || cursor
            .after_gap_id
            .as_ref()
            .is_some_and(|gap_id| gap_id.len() > MAX_RECOVERY_PROJECTION_CURSOR_GAP_KEY_BYTES)
    {
        return Err(BridgeError::InvalidTransition(
            "invalid recovery projection cursor",
        ));
    }
    Ok(cursor)
}

fn next_event(
    progress: &RecoveryStreamProgress,
    after_sequence: Option<u64>,
) -> Option<&RecoveredEventFact> {
    match after_sequence {
        Some(after) => progress
            .events
            .range((Excluded(after), Unbounded))
            .next()
            .map(|(_, event)| event),
        None => progress.events.first_key_value().map(|(_, event)| event),
    }
}

fn next_gap<'a>(
    gaps: &'a BTreeMap<String, RecoveredGapFact>,
    after_gap_id: Option<&str>,
) -> Option<&'a RecoveredGapFact> {
    match after_gap_id {
        Some(after) => gaps
            .range::<str, _>((Excluded(after), Unbounded))
            .next()
            .map(|(_, gap)| gap),
        None => gaps.first_key_value().map(|(_, gap)| gap),
    }
}

struct LimitedProjectionWriter {
    size: usize,
    limit: usize,
    exceeded: bool,
}

impl LimitedProjectionWriter {
    fn new(limit: usize) -> Self {
        Self {
            size: 0,
            limit,
            exceeded: false,
        }
    }
}

impl std::io::Write for LimitedProjectionWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(next_size) = self.size.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(std::io::Error::other("projection byte count overflow"));
        };
        if next_size > self.limit {
            self.exceeded = true;
            return Err(std::io::Error::other("projection record exceeds bound"));
        }
        self.size = next_size;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn projection_record_size(
    record: &RecoveryProjectionRecord,
    remaining: usize,
) -> Result<Option<usize>, BridgeError> {
    let mut writer = LimitedProjectionWriter::new(remaining);
    match serde_json::to_writer(&mut writer, record) {
        Ok(()) => Ok(Some(writer.size)),
        Err(_) if writer.exceeded => Ok(None),
        Err(_) => Err(BridgeError::InvalidTransition(
            "recovery projection record could not be encoded",
        )),
    }
}

fn validate_recovery_projection_position(
    window: &RecoveryWindow,
    cursor: &RecoveryProjectionCursor,
) -> Result<(), BridgeError> {
    let invalid = || BridgeError::InvalidTransition("invalid recovery projection cursor position");
    match cursor.section {
        RecoveryProjectionSection::Streams => {
            if cursor.after_sequence.is_some() || cursor.after_gap_id.is_some() {
                return Err(invalid());
            }
        }
        RecoveryProjectionSection::Pending => {
            if cursor.after_gap_id.is_some() {
                return Err(invalid());
            }
            if let Some(sequence) = cursor.after_sequence {
                let stream_id = window
                    .stream_order
                    .get(cursor.stream_index)
                    .ok_or_else(invalid)?;
                if !window
                    .streams
                    .get(stream_id)
                    .is_some_and(|progress| progress.events.contains_key(&sequence))
                {
                    return Err(invalid());
                }
            }
        }
        RecoveryProjectionSection::ScopedGaps => {
            if cursor.after_sequence.is_some() {
                return Err(invalid());
            }
            if let Some(gap_id) = cursor.after_gap_id.as_deref() {
                let stream_id = window
                    .stream_order
                    .get(cursor.stream_index)
                    .ok_or_else(invalid)?;
                if !window
                    .streams
                    .get(stream_id)
                    .is_some_and(|progress| progress.gaps.contains_key(gap_id))
                {
                    return Err(invalid());
                }
            }
        }
        RecoveryProjectionSection::UnscopedGaps => {
            if cursor.stream_index != 0 || cursor.after_sequence.is_some() {
                return Err(invalid());
            }
            if cursor
                .after_gap_id
                .as_deref()
                .is_some_and(|gap_id| !window.unscoped_gaps.contains_key(gap_id))
            {
                return Err(invalid());
            }
        }
        RecoveryProjectionSection::Done => {
            if cursor.stream_index != 0
                || cursor.after_sequence.is_some()
                || cursor.after_gap_id.is_some()
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

/// One recovered-but-unforwarded obligation: a retained owner receipt the
/// bridge has not yet covered with its own acknowledgement.
///
/// These facts stay visible for the live walk while forwarding is
/// interrupted, so pending work is delayed but never erased owner-side and
/// never re-minted as a fresh event. A new attach opens a new walk: the
/// durable source stays with its owner, and the producer's at-least-once
/// redelivery re-observes anything still unacknowledged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveredPendingView {
    stream_id: String,
    event_id: String,
    sequence: u64,
    phase: AckPhase,
    envelope_digest: String,
}

impl RecoveredPendingView {
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn phase(&self) -> AckPhase {
        self.phase
    }

    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
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
///
/// A result built by [`ReconciliationPortResult::reconciled`] carries no
/// recovered facts: it attests an empty inventory through a legacy port and
/// keeps the historical gate-clearing semantics. A result built by
/// [`ReconciliationPortResult::reconciled_with_pages`] carries the checked
/// owner page facts plus the declared window binding; the core imports those
/// facts into its recovery progress and clears the gate only when the walk
/// disposition is complete (issue #2732).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationPortResult {
    session_id: SessionId,
    activation_generation: Generation,
    state_fence: FencingToken,
    task_binding: Box<TaskBinding>,
    receipt_ref: ReconciliationReceiptRef,
    window: Option<Box<RecoveryWindowFacts>>,
    consumed_frontiers: Vec<ReconciliationConsumedFrontier>,
}

/// A locally derived consumed frontier offered to the owner in a reconcile
/// request. It becomes confirmed only after the response page is imported.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationConsumedFrontier {
    stream_id: String,
    sequence: u64,
}

impl ReconciliationConsumedFrontier {
    pub fn new(stream_id: String, sequence: u64) -> Self {
        Self {
            stream_id,
            sequence,
        }
    }

    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

impl ReconciliationPortResult {
    pub fn reconciled(
        binding: &AttachBinding,
        receipt_ref: ReconciliationReceiptRef,
    ) -> Result<Self, BridgeError> {
        validate_authority_binding(
            &binding.session_id,
            binding.activation_generation,
            &binding.state_fence,
        )?;
        Ok(Self {
            session_id: binding.session_id.clone(),
            activation_generation: binding.activation_generation,
            state_fence: binding.state_fence.clone(),
            task_binding: Box::new(binding.task_binding.clone()),
            receipt_ref,
            window: None,
            consumed_frontiers: Vec::new(),
        })
    }

    /// Seals one bounded recovery read carrying checked owner page facts.
    ///
    /// The window facts bind the reply to the presenting connection, the
    /// live producer generation, and the stable owner-issued window key. The
    /// core re-validates every leg against the live attach binding on
    /// import; a late result for a replaced attach fails closed there and
    /// changes no recovery state.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::result_large_err)]
    pub fn reconciled_with_pages(
        binding: &AttachBinding,
        receipt_ref: ReconciliationReceiptRef,
        window_key: String,
        window_status: RecoveryWindowStatus,
        live_generation: Generation,
        presenting_connection: ConnectionId,
        unproven_scope_present: bool,
        handoffs_reconciled: u64,
        stream_facts: Vec<RecoveredStreamFacts>,
        unscoped_gaps: Vec<RecoveredGapFact>,
        stream_list_complete: bool,
        stream_list_continuation: Option<String>,
        unscoped_gaps_complete: bool,
        unscoped_gaps_continuation: Option<RecoveryUnscopedGapCursor>,
    ) -> Result<Self, BridgeError> {
        validate_authority_binding(
            &binding.session_id,
            binding.activation_generation,
            &binding.state_fence,
        )?;
        let window = RecoveryWindowFacts::checked(
            window_key,
            window_status,
            live_generation,
            presenting_connection,
            unproven_scope_present,
            handoffs_reconciled,
            stream_facts,
            unscoped_gaps,
            stream_list_complete,
            stream_list_continuation,
            unscoped_gaps_complete,
            unscoped_gaps_continuation,
        )?;
        Ok(Self {
            session_id: binding.session_id.clone(),
            activation_generation: binding.activation_generation,
            state_fence: binding.state_fence.clone(),
            task_binding: Box::new(binding.task_binding.clone()),
            receipt_ref,
            window: Some(Box::new(window)),
            consumed_frontiers: Vec::new(),
        })
    }

    /// Carries the exact frontiers included in the request so the real
    /// forwarding port can confirm them only after core import succeeds.
    #[must_use]
    pub fn with_consumed_frontiers(
        mut self,
        consumed_frontiers: Vec<ReconciliationConsumedFrontier>,
    ) -> Self {
        self.consumed_frontiers = consumed_frontiers;
        self
    }

    pub const fn receipt_ref(&self) -> &ReconciliationReceiptRef {
        &self.receipt_ref
    }

    pub fn window(&self) -> Option<&RecoveryWindowFacts> {
        self.window.as_deref()
    }

    pub fn consumed_frontiers(&self) -> &[ReconciliationConsumedFrontier] {
        &self.consumed_frontiers
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
    task_binding: TaskBinding,
    receipt_ref: ReconciliationReceiptRef,
    window: Option<Box<RecoveryWindowFacts>>,
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
            task_binding: *result.task_binding,
            receipt_ref: result.receipt_ref,
            window: result.window,
        })
    }
}

/// Disposition of one bounded recovery walk (issue #2732).
///
/// Inventory recovery is not task/effect completion: [`RecoveryDisposition::Complete`]
/// means the declared window's required ownership/accounting facts were
/// recovered or explicitly dispositioned under the recovery policy. A
/// complete inventory can still contain pending events and known blind
/// intervals; that is not an APPLIED stream or complete historical coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum RecoveryDisposition {
    Complete,
    Partial { reason: &'static str },
    Unavailable { reason: &'static str },
}

/// A required stream page or the stream list still has an owner continuation.
pub const RECOVERY_PARTIAL_PAGE_CONTINUATION: &str = "page-continuation-pending";
/// The owner reports material outside the proven scope; the inventory is
/// explicitly incomplete rather than silently whole.
pub const RECOVERY_PARTIAL_UNPROVEN_SCOPE: &str = "unproven-scope-present";
/// Required material inside the declared window moved (concurrent
/// stage/ack/compaction); the walk needs a refresh, never a silent stitch.
pub const RECOVERY_PARTIAL_WINDOW_MOVED: &str = "window-moved-refresh-required";
pub const RECOVERY_PARTIAL_WINDOW_EXPIRED: &str = "window-expired-refresh-required";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryWindowStatus {
    Active,
    Moved,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryUnscopedGapCursor {
    after_gap_scope: String,
    gap_offset: u64,
}

impl RecoveryUnscopedGapCursor {
    #[allow(clippy::result_large_err)]
    pub fn checked(after_gap_scope: String, gap_offset: u64) -> Result<Self, BridgeError> {
        validate_text(&after_gap_scope, "recovery_window.after_gap_scope")?;
        Ok(Self {
            after_gap_scope,
            gap_offset,
        })
    }

    pub fn after_gap_scope(&self) -> &str {
        &self.after_gap_scope
    }

    pub const fn gap_offset(&self) -> u64 {
        self.gap_offset
    }
}
/// The stream list itself reached the negotiated bound; coverage needs its
/// own bounded continuation, not an unbounded outer collection.
pub const RECOVERY_PARTIAL_STREAM_LIST_TRUNCATED: &str = "stream-list-truncated";
/// The page named a foreign scope, future continuation, or stale window and
/// was refused without applying half a page.
pub const RECOVERY_UNAVAILABLE_FOREIGN_PAGE: &str = "foreign-page-refused";

/// One checked retained-event receipt fact restored from an owner page.
///
/// Digest-only by construction: owner pages carry metadata, not the
/// original event payload, so this fact never fabricates an
/// [`EventEnvelope`]. Raw/redacted/normalized linkage is re-established
/// only through the retained source/artifact owner; the bridge keeps the
/// digest, producer, and phase legs separate instead of merging them into a
/// synthetic envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveredEventFact {
    stream_id: String,
    event_id: String,
    sequence: u64,
    phase: AckPhase,
    envelope_digest: String,
    producer_id: String,
    producer_generation: u64,
    staging_connection: String,
}

impl RecoveredEventFact {
    /// Checks one wire-decoded owner event fact before it may enter the
    /// recovery window. Exact identities, a nonzero sequence, a nonzero
    /// producer generation, and non-blank digest/producer/connection legs
    /// are required; the digest format itself is verified at the transport
    /// decode boundary.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::result_large_err)]
    pub fn checked(
        stream_id: String,
        event_id: String,
        sequence: u64,
        phase: AckPhase,
        envelope_digest: String,
        producer_id: String,
        producer_generation: u64,
        staging_connection: String,
    ) -> Result<Self, BridgeError> {
        validate_text(&stream_id, "recovered_event.stream_id")?;
        validate_text(&event_id, "recovered_event.event_id")?;
        if event_id.contains("::") || stream_id.contains("::") {
            return Err(BridgeError::InvalidContract {
                field: "recovered_event.identity",
                reason: "stream/event identity must not contain the key separator",
            });
        }
        if sequence == 0 {
            return Err(BridgeError::InvalidContract {
                field: "recovered_event.sequence",
                reason: "recovered event sequence must be nonzero",
            });
        }
        if producer_generation == 0 {
            return Err(BridgeError::InvalidContract {
                field: "recovered_event.producer_generation",
                reason: "recovered producer generation must be nonzero",
            });
        }
        validate_text(&envelope_digest, "recovered_event.envelope_digest")?;
        validate_text(&producer_id, "recovered_event.producer_id")?;
        validate_text(&staging_connection, "recovered_event.staging_connection")?;
        Ok(Self {
            stream_id,
            event_id,
            sequence,
            phase,
            envelope_digest,
            producer_id,
            producer_generation,
            staging_connection,
        })
    }

    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn phase(&self) -> AckPhase {
        self.phase
    }

    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }

    pub fn producer_id(&self) -> &str {
        &self.producer_id
    }

    pub const fn producer_generation(&self) -> u64 {
        self.producer_generation
    }

    pub fn staging_connection(&self) -> &str {
        &self.staging_connection
    }
}

/// One checked retained-gap fact restored from an owner page.
///
/// A gap accounts for missing coverage; it never moves a cursor and never
/// converts absent events into applied events.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveredGapFact {
    gap_id: String,
    stream_id: String,
    start_sequence: u64,
    end_sequence: u64,
    reason_ref: String,
}

impl RecoveredGapFact {
    /// Checks one wire-decoded owner gap fact. An empty stream scope marks
    /// an unscoped gap, which reconciles at top level; a malformed interval
    /// refuses the whole page, never half of it. Gap identities are bare
    /// keys (never key-encoded with a separator), mirroring the owner's
    /// gap rule.
    #[allow(clippy::result_large_err)]
    pub fn checked(
        gap_id: String,
        stream_id: String,
        start_sequence: u64,
        end_sequence: u64,
        reason_ref: String,
    ) -> Result<Self, BridgeError> {
        validate_text(&gap_id, "recovered_gap.gap_id")?;
        if !stream_id.is_empty() {
            validate_text(&stream_id, "recovered_gap.stream_id")?;
            if stream_id.contains("::") {
                return Err(BridgeError::InvalidContract {
                    field: "recovered_gap.stream_id",
                    reason: "gap stream scope must not contain the key separator",
                });
            }
        }
        if start_sequence == 0 || end_sequence == 0 {
            return Err(BridgeError::InvalidContract {
                field: "recovered_gap.interval",
                reason: "gap interval bounds must be nonzero",
            });
        }
        if end_sequence < start_sequence {
            return Err(BridgeError::InvalidContract {
                field: "recovered_gap.interval",
                reason: "gap interval must not end before it starts",
            });
        }
        validate_text(&reason_ref, "recovered_gap.reason_ref")?;
        Ok(Self {
            gap_id,
            stream_id,
            start_sequence,
            end_sequence,
            reason_ref,
        })
    }

    pub fn gap_id(&self) -> &str {
        &self.gap_id
    }

    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub const fn start_sequence(&self) -> u64 {
        self.start_sequence
    }

    pub const fn end_sequence(&self) -> u64 {
        self.end_sequence
    }

    pub fn reason_ref(&self) -> &str {
        &self.reason_ref
    }
}

/// One checked per-stream page: owner cursors, retained event/gap facts,
/// and the page's own bounded continuation.
///
/// The accounting derivation lives here, not at the transport boundary:
/// [`RecoveredStreamFacts::checked`] recomputes the contiguous durable
/// frontier (the contiguous DURABLE-or-later run above the acked base) and
/// the highest observed sequence from the carried facts, and refuses an
/// incoherent page. An individually durable out-of-order event may
/// legitimately exceed the contiguous frontier; it is retained above the
/// hole, never acknowledged past it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredStreamFacts {
    stream_id: String,
    durable_cursor: u64,
    acked_cursor: u64,
    contiguous_durable_frontier: u64,
    highest_observed_sequence: u64,
    events: Vec<RecoveredEventFact>,
    gaps: Vec<RecoveredGapFact>,
    page_continuation: Option<u64>,
    gap_continuation: Option<u64>,
    page_complete: bool,
    recovery_cut: Option<RecoveryStreamCut>,
    owner_identity: Option<(String, u64)>,
}

/// Owner-issued finite bound for a retained stream observation. The value is
/// checked again on every continuation; an owner revision/floor change cannot
/// silently turn a later page into part of the earlier view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryStreamCut {
    upper_sequence: u64,
    expected_revision: u64,
    retention_floor: u64,
}

impl RecoveryStreamCut {
    #[allow(clippy::result_large_err)]
    pub fn checked(
        upper_sequence: u64,
        expected_revision: u64,
        retention_floor: u64,
    ) -> Result<Self, BridgeError> {
        if expected_revision == 0 || retention_floor > upper_sequence {
            return Err(BridgeError::InvalidContract {
                field: "recovery_stream.cut",
                reason: "owner revision must be nonzero and retention floor within the finite bound",
            });
        }
        Ok(Self {
            upper_sequence,
            expected_revision,
            retention_floor,
        })
    }

    pub const fn upper_sequence(self) -> u64 {
        self.upper_sequence
    }

    pub const fn expected_revision(self) -> u64 {
        self.expected_revision
    }

    pub const fn retention_floor(self) -> u64 {
        self.retention_floor
    }
}

impl RecoveredStreamFacts {
    /// Checks one wire-decoded stream page and derives its accounting.
    /// Events must arrive strictly increasing with nonzero sequences above
    /// the acked base and without duplicate identities; `acked` must not
    /// exceed the contiguous durable cursor; a continuation must name the
    /// page's last sequence (which may exceed contiguous durable); a complete
    /// page carries no continuation.
    #[allow(clippy::result_large_err)]
    pub fn checked(
        stream_id: String,
        durable_cursor: u64,
        acked_cursor: u64,
        events: Vec<RecoveredEventFact>,
        gaps: Vec<RecoveredGapFact>,
        page_continuation: Option<u64>,
        page_complete: bool,
    ) -> Result<Self, BridgeError> {
        validate_text(&stream_id, "recovered_stream.stream_id")?;
        if stream_id.contains("::") {
            return Err(BridgeError::InvalidContract {
                field: "recovered_stream.stream_id",
                reason: "stream identity must not contain the key separator",
            });
        }
        if acked_cursor > durable_cursor {
            return Err(BridgeError::InvalidContract {
                field: "recovered_stream.acked_cursor",
                reason: "acknowledged cursor must not exceed the contiguous durable cursor",
            });
        }
        Self::check_event_run(&stream_id, acked_cursor, &events)?;
        Self::check_gap_scope(&stream_id, &gaps)?;
        Self::check_continuation(
            page_continuation,
            page_complete,
            acked_cursor,
            events.last().map(|event| event.sequence),
        )?;
        let contiguous = Self::contiguous_run(acked_cursor, &events);
        let highest = events
            .last()
            .map_or(acked_cursor, |event| event.sequence)
            .max(page_continuation.unwrap_or(acked_cursor))
            .max(durable_cursor);
        Ok(Self {
            stream_id,
            durable_cursor,
            acked_cursor,
            contiguous_durable_frontier: contiguous,
            highest_observed_sequence: highest,
            events,
            gaps,
            page_continuation,
            gap_continuation: None,
            page_complete,
            recovery_cut: None,
            owner_identity: None,
        })
    }

    #[allow(clippy::result_large_err)]
    pub fn with_owner_identity(
        mut self,
        producer_id: String,
        owner_incarnation: u64,
    ) -> Result<Self, BridgeError> {
        validate_text(&producer_id, "recovered_stream.producer_id")?;
        if owner_incarnation == 0 {
            return Err(BridgeError::InvalidContract {
                field: "recovered_stream.owner_incarnation",
                reason: "owner incarnation must be nonzero",
            });
        }
        self.owner_identity = Some((producer_id, owner_incarnation));
        Ok(self)
    }

    pub fn owner_identity(&self) -> Option<(&str, u64)> {
        self.owner_identity
            .as_ref()
            .map(|(producer, incarnation)| (producer.as_str(), *incarnation))
    }

    #[allow(clippy::result_large_err)]
    pub fn with_recovery_cut(mut self, cut: RecoveryStreamCut) -> Result<Self, BridgeError> {
        if self.highest_observed_sequence > cut.upper_sequence()
            || self
                .gaps
                .iter()
                .any(|gap| gap.end_sequence() > cut.upper_sequence())
        {
            return Err(BridgeError::InvalidContract {
                field: "recovered_stream.upper_sequence",
                reason: "observed stream facts exceed the owner-issued finite bound",
            });
        }
        self.recovery_cut = Some(cut);
        Ok(self)
    }

    pub const fn recovery_cut(&self) -> Option<RecoveryStreamCut> {
        self.recovery_cut
    }

    #[allow(clippy::result_large_err)]
    pub fn with_gap_continuation(mut self, offset: Option<u64>) -> Result<Self, BridgeError> {
        if offset == Some(0) {
            return Err(BridgeError::InvalidContract {
                field: "recovered_stream.gap_continuation",
                reason: "owner gap continuation must be a positive offset",
            });
        }
        self.gap_continuation = offset;
        self.page_complete &= offset.is_none();
        Ok(self)
    }

    pub const fn gap_continuation(&self) -> Option<u64> {
        self.gap_continuation
    }

    /// Rejects foreign-stream events, sequences at or below the acked base,
    /// non-increasing order and duplicate sequences or identities.
    #[allow(clippy::result_large_err)]
    fn check_event_run(
        stream_id: &str,
        acked_cursor: u64,
        events: &[RecoveredEventFact],
    ) -> Result<(), BridgeError> {
        let mut seen_sequences = BTreeSet::new();
        let mut seen_identities = BTreeSet::new();
        let mut previous = acked_cursor;
        for event in events {
            if event.stream_id != stream_id {
                return Err(BridgeError::InvalidContract {
                    field: "recovered_stream.event",
                    reason: "page event names a foreign stream",
                });
            }
            if event.sequence <= acked_cursor {
                return Err(BridgeError::InvalidContract {
                    field: "recovered_stream.event",
                    reason: "page event does not advance past the acknowledged base",
                });
            }
            if event.sequence <= previous {
                return Err(BridgeError::InvalidContract {
                    field: "recovered_stream.event",
                    reason: "page events must arrive strictly increasing",
                });
            }
            previous = event.sequence;
            if !seen_sequences.insert(event.sequence) {
                return Err(BridgeError::InvalidContract {
                    field: "recovered_stream.event",
                    reason: "duplicate page sequence",
                });
            }
            if !seen_identities.insert(event.event_id.clone()) {
                return Err(BridgeError::InvalidContract {
                    field: "recovered_stream.event",
                    reason: "duplicate page event identity",
                });
            }
        }
        Ok(())
    }

    /// Rejects duplicate page gap identities and scopes naming another stream.
    #[allow(clippy::result_large_err)]
    fn check_gap_scope(stream_id: &str, gaps: &[RecoveredGapFact]) -> Result<(), BridgeError> {
        let mut seen_gap_ids = BTreeSet::new();
        for gap in gaps {
            if !seen_gap_ids.insert(gap.gap_id.clone()) {
                return Err(BridgeError::InvalidContract {
                    field: "recovered_stream.gap",
                    reason: "duplicate gap identity in one stream page",
                });
            }
            if !gap.stream_id.is_empty() && gap.stream_id != stream_id {
                return Err(BridgeError::InvalidContract {
                    field: "recovered_stream.gap",
                    reason: "scoped page gap names a foreign stream",
                });
            }
        }
        Ok(())
    }

    /// Binds the continuation to the page tail: a
    /// complete page carries none, an empty page must still advance past the
    /// base, and a non-empty page names its last sequence.
    #[allow(clippy::result_large_err)]
    fn check_continuation(
        page_continuation: Option<u64>,
        page_complete: bool,
        acked_cursor: u64,
        tail_sequence: Option<u64>,
    ) -> Result<(), BridgeError> {
        match (page_continuation, page_complete, tail_sequence) {
            (None, _, _) => Ok(()),
            (Some(_), true, _) => Err(BridgeError::InvalidContract {
                field: "recovered_stream.continuation",
                reason: "a complete page carries no continuation",
            }),
            (Some(continuation), false, None) => {
                if continuation <= acked_cursor {
                    return Err(BridgeError::InvalidContract {
                        field: "recovered_stream.continuation",
                        reason: "continuation must advance past the acknowledged base",
                    });
                }
                Ok(())
            }
            (Some(continuation), false, Some(tail)) => {
                if continuation != tail {
                    return Err(BridgeError::InvalidContract {
                        field: "recovered_stream.continuation",
                        reason: "continuation must name the page tail",
                    });
                }
                Ok(())
            }
        }
    }

    /// Extends the acked base over the durable prefix of the page: only
    /// contiguous DURABLE events advance the frontier, so out-of-order
    /// receipts above it preserve their hole instead of moving
    /// acknowledgement past unseen or unnormalized material.
    fn contiguous_run(acked_cursor: u64, events: &[RecoveredEventFact]) -> u64 {
        let mut contiguous = acked_cursor;
        for event in events {
            if event.sequence == contiguous.saturating_add(1)
                && phase_reaches(AckPhase::Durable, event.phase)
            {
                contiguous = event.sequence;
            } else if event.sequence > contiguous.saturating_add(1) {
                break;
            }
        }
        contiguous
    }

    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub const fn durable_cursor(&self) -> u64 {
        self.durable_cursor
    }

    pub const fn acked_cursor(&self) -> u64 {
        self.acked_cursor
    }

    pub const fn contiguous_durable_frontier(&self) -> u64 {
        self.contiguous_durable_frontier
    }

    pub const fn highest_observed_sequence(&self) -> u64 {
        self.highest_observed_sequence
    }

    pub fn events(&self) -> &[RecoveredEventFact] {
        &self.events
    }

    pub fn gaps(&self) -> &[RecoveredGapFact] {
        &self.gaps
    }

    pub const fn page_continuation(&self) -> Option<u64> {
        self.page_continuation
    }

    pub const fn page_complete(&self) -> bool {
        self.page_complete
    }
}

/// The declared finite recovery window carried by one owner answer.
///
/// `window_key` is the stable owner-issued identity of the finite walk;
/// the per-reply reconciliation key separately binds each observed page.
/// `handoffs_reconciled` is the
/// owner's later mutation receipt count, carried as accounting and
/// explicitly excluded from the key preimage and from completion proof.
/// `stream_list_complete` is false when the stream enumeration itself hit
/// the negotiated bound: stream-list coverage needs its own bounded
/// continuation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryWindowFacts {
    window_key: String,
    window_status: RecoveryWindowStatus,
    live_generation: Generation,
    presenting_connection: ConnectionId,
    unproven_scope_present: bool,
    handoffs_reconciled: u64,
    stream_facts: Vec<RecoveredStreamFacts>,
    unscoped_gaps: Vec<RecoveredGapFact>,
    stream_list_complete: bool,
    stream_list_continuation: Option<String>,
    unscoped_gaps_complete: bool,
    unscoped_gaps_continuation: Option<RecoveryUnscopedGapCursor>,
}

impl RecoveryWindowFacts {
    /// Checks the window binding legs. Stream facts arrive pre-checked;
    /// duplicate stream scopes refuse the whole window.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::result_large_err)]
    pub fn checked(
        window_key: String,
        window_status: RecoveryWindowStatus,
        live_generation: Generation,
        presenting_connection: ConnectionId,
        unproven_scope_present: bool,
        handoffs_reconciled: u64,
        stream_facts: Vec<RecoveredStreamFacts>,
        unscoped_gaps: Vec<RecoveredGapFact>,
        stream_list_complete: bool,
        stream_list_continuation: Option<String>,
        unscoped_gaps_complete: bool,
        unscoped_gaps_continuation: Option<RecoveryUnscopedGapCursor>,
    ) -> Result<Self, BridgeError> {
        validate_text(&window_key, "recovery_window.window_key")?;
        if window_status == RecoveryWindowStatus::Active
            && (stream_list_complete != stream_list_continuation.is_none()
                || unscoped_gaps_complete != unscoped_gaps_continuation.is_none())
        {
            return Err(BridgeError::InvalidContract {
                field: "recovery_window.coverage_continuation",
                reason: "complete owner coverage carries no continuation and partial coverage carries one",
            });
        }
        if let Some(cursor) = &stream_list_continuation {
            validate_text(cursor, "recovery_window.stream_list_continuation")?;
        }
        if live_generation.get() == 0 {
            return Err(BridgeError::InvalidContract {
                field: "recovery_window.live_generation",
                reason: "live producer generation must be nonzero",
            });
        }
        let mut seen = BTreeSet::new();
        let mut seen_gap_ids = BTreeSet::new();
        for facts in &stream_facts {
            if !seen.insert(facts.stream_id.clone()) {
                return Err(BridgeError::InvalidContract {
                    field: "recovery_window.stream",
                    reason: "duplicate stream scope in one recovery window",
                });
            }
            for gap in facts.gaps() {
                if !seen_gap_ids.insert(gap.gap_id.clone()) {
                    return Err(BridgeError::InvalidContract {
                        field: "recovery_window.gap",
                        reason: "duplicate gap identity in one recovery window",
                    });
                }
            }
        }
        for gap in &unscoped_gaps {
            if !gap.stream_id.is_empty() {
                return Err(BridgeError::InvalidContract {
                    field: "recovery_window.unscoped_gap",
                    reason: "top-level gap must carry no stream scope",
                });
            }
            if !seen_gap_ids.insert(gap.gap_id.clone()) {
                return Err(BridgeError::InvalidContract {
                    field: "recovery_window.gap",
                    reason: "duplicate gap identity in one recovery window",
                });
            }
        }
        Ok(Self {
            window_key,
            window_status,
            live_generation,
            presenting_connection,
            unproven_scope_present,
            handoffs_reconciled,
            stream_facts,
            unscoped_gaps,
            stream_list_complete,
            stream_list_continuation,
            unscoped_gaps_complete,
            unscoped_gaps_continuation,
        })
    }

    pub fn window_key(&self) -> &str {
        &self.window_key
    }

    pub const fn window_status(&self) -> RecoveryWindowStatus {
        self.window_status
    }

    pub const fn live_generation(&self) -> Generation {
        self.live_generation
    }

    pub const fn presenting_connection(&self) -> &ConnectionId {
        &self.presenting_connection
    }

    pub const fn unproven_scope_present(&self) -> bool {
        self.unproven_scope_present
    }

    pub const fn handoffs_reconciled(&self) -> u64 {
        self.handoffs_reconciled
    }

    pub fn stream_facts(&self) -> &[RecoveredStreamFacts] {
        &self.stream_facts
    }

    pub fn unscoped_gaps(&self) -> &[RecoveredGapFact] {
        &self.unscoped_gaps
    }

    pub const fn stream_list_complete(&self) -> bool {
        self.stream_list_complete
    }

    pub fn stream_list_continuation(&self) -> Option<&str> {
        self.stream_list_continuation.as_deref()
    }

    pub const fn unscoped_gaps_complete(&self) -> bool {
        self.unscoped_gaps_complete
    }

    pub fn unscoped_gaps_continuation(&self) -> Option<&RecoveryUnscopedGapCursor> {
        self.unscoped_gaps_continuation.as_ref()
    }
}

/// One bounded read continuation: a pure selector, never an
/// acknowledgement.
///
/// The request names the declared window, one stream scope, the predecessor
/// sequence the next page must advance past, and explicit event/gap budgets.
/// It carries the expected live authority (generation plus presenting
/// connection) so each call rechecks the #2729 rights against the live
/// attach: possession of the token alone authorizes nothing, and a request
/// built before a reconnect fails closed instead of resuming a stale walk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReadRequest {
    window_key: String,
    selector: RecoveryReadSelector,
    expected_generation: u64,
    expected_connection: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RecoveryReadSelector {
    Stream {
        stream_id: String,
        after_sequence: u64,
        cut: RecoveryStreamCut,
        event_limit: u64,
        gap_offset: u64,
        gap_limit: u64,
    },
    Streams {
        after_stream: String,
        stream_limit: u64,
    },
    UnscopedGaps {
        after_gap_scope: String,
        gap_offset: u64,
        gap_limit: u64,
    },
}

/// Owner page budget mirrored from the retained-source page cap: one page
/// never exceeds the owner's own truncation bound.
pub const RECOVERY_PAGE_EVENT_LIMIT: u64 = 128;
/// Owner gap budget mirrored from the retained-source per-stream gap cap.
pub const RECOVERY_PAGE_GAP_LIMIT: u64 = 256;

impl RecoveryReadRequest {
    /// Builds one bounded continuation read. Limits stay within the
    /// owner's page/gap caps; larger content travels behind admitted
    /// immutable handles, never behind higher frame ceilings.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::result_large_err)]
    pub fn checked_stream(
        window_key: String,
        stream_id: String,
        after_sequence: u64,
        cut: RecoveryStreamCut,
        event_limit: u64,
        gap_offset: u64,
        gap_limit: u64,
        expected_generation: u64,
        expected_connection: String,
    ) -> Result<Self, BridgeError> {
        validate_text(&window_key, "recovery_read.window_key")?;
        validate_text(&stream_id, "recovery_read.stream_id")?;
        if stream_id.len() > 1024 {
            return Err(BridgeError::InvalidContract {
                field: "recovery_read.stream_id",
                reason: "stream identity exceeds the bounded selector length",
            });
        }
        if stream_id.contains("::") {
            return Err(BridgeError::InvalidContract {
                field: "recovery_read.stream_id",
                reason: "stream identity must not contain the key separator",
            });
        }
        if after_sequence > cut.upper_sequence() {
            return Err(BridgeError::InvalidContract {
                field: "recovery_read.after_sequence",
                reason: "continuation cannot exceed the owner-issued finite bound",
            });
        }
        if event_limit == 0 || event_limit > RECOVERY_PAGE_EVENT_LIMIT {
            return Err(BridgeError::InvalidContract {
                field: "recovery_read.event_limit",
                reason: "event budget must stay within the owner page cap",
            });
        }
        if gap_limit == 0 || gap_limit > RECOVERY_PAGE_GAP_LIMIT {
            return Err(BridgeError::InvalidContract {
                field: "recovery_read.gap_limit",
                reason: "gap budget must stay within the owner gap cap",
            });
        }
        if gap_offset.checked_add(gap_limit).is_none() {
            return Err(BridgeError::InvalidContract {
                field: "recovery_read.gap_offset",
                reason: "gap continuation offset and budget must not overflow",
            });
        }
        if expected_generation == 0 {
            return Err(BridgeError::InvalidContract {
                field: "recovery_read.expected_generation",
                reason: "expected live generation must be nonzero",
            });
        }
        validate_text(&expected_connection, "recovery_read.expected_connection")?;
        Ok(Self {
            window_key,
            selector: RecoveryReadSelector::Stream {
                stream_id,
                after_sequence,
                cut,
                event_limit,
                gap_offset,
                gap_limit,
            },
            expected_generation,
            expected_connection,
        })
    }

    #[allow(clippy::result_large_err)]
    pub fn checked_streams(
        window_key: String,
        after_stream: String,
        stream_limit: u64,
        expected_generation: u64,
        expected_connection: String,
    ) -> Result<Self, BridgeError> {
        validate_text(&window_key, "recovery_read.window_key")?;
        validate_text(&after_stream, "recovery_read.after_stream")?;
        if after_stream.len() > 1024 {
            return Err(BridgeError::InvalidContract {
                field: "recovery_read.after_stream",
                reason: "stream-list cursor exceeds the bounded selector length",
            });
        }
        validate_text(&expected_connection, "recovery_read.expected_connection")?;
        if stream_limit == 0 || stream_limit > 4 || expected_generation == 0 {
            return Err(BridgeError::InvalidContract {
                field: "recovery_read.stream_limit",
                reason: "stream-list page must use the admitted bound and live generation",
            });
        }
        Ok(Self {
            window_key,
            selector: RecoveryReadSelector::Streams {
                after_stream,
                stream_limit,
            },
            expected_generation,
            expected_connection,
        })
    }

    #[allow(clippy::result_large_err)]
    pub fn checked_unscoped_gaps(
        window_key: String,
        after_gap_scope: String,
        gap_offset: u64,
        gap_limit: u64,
        expected_generation: u64,
        expected_connection: String,
    ) -> Result<Self, BridgeError> {
        validate_text(&window_key, "recovery_read.window_key")?;
        validate_text(&after_gap_scope, "recovery_read.after_gap_scope")?;
        if after_gap_scope.len() > 1024 {
            return Err(BridgeError::InvalidContract {
                field: "recovery_read.after_gap_scope",
                reason: "unscoped-gap cursor exceeds the bounded selector length",
            });
        }
        validate_text(&expected_connection, "recovery_read.expected_connection")?;
        if gap_limit == 0
            || gap_limit > RECOVERY_PAGE_GAP_LIMIT
            || gap_offset.checked_add(gap_limit).is_none()
            || expected_generation == 0
        {
            return Err(BridgeError::InvalidContract {
                field: "recovery_read.gap_limit",
                reason: "unscoped-gap page must use the admitted bound and live generation",
            });
        }
        Ok(Self {
            window_key,
            selector: RecoveryReadSelector::UnscopedGaps {
                after_gap_scope,
                gap_offset,
                gap_limit,
            },
            expected_generation,
            expected_connection,
        })
    }

    pub fn window_key(&self) -> &str {
        &self.window_key
    }

    pub fn stream_scope(&self) -> Option<(&str, u64, RecoveryStreamCut, u64, u64, u64)> {
        match &self.selector {
            RecoveryReadSelector::Stream {
                stream_id,
                after_sequence,
                cut,
                event_limit,
                gap_offset,
                gap_limit,
            } => Some((
                stream_id,
                *after_sequence,
                *cut,
                *event_limit,
                *gap_offset,
                *gap_limit,
            )),
            _ => None,
        }
    }

    pub fn stream_list_scope(&self) -> Option<(&str, u64)> {
        match &self.selector {
            RecoveryReadSelector::Streams {
                after_stream,
                stream_limit,
            } => Some((after_stream, *stream_limit)),
            _ => None,
        }
    }

    pub fn unscoped_gap_scope(&self) -> Option<(&str, u64, u64)> {
        match &self.selector {
            RecoveryReadSelector::UnscopedGaps {
                after_gap_scope,
                gap_offset,
                gap_limit,
            } => Some((after_gap_scope, *gap_offset, *gap_limit)),
            _ => None,
        }
    }

    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }

    pub fn expected_connection(&self) -> &str {
        &self.expected_connection
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
    recovery: Option<RecoveryWindow>,
}

/// One stream's imported recovery state inside the declared window.
///
/// `acked_base` is the retention floor observed when the stream entered
/// the window: pages below it are owner-confirmed history, pages above it
/// are the walk's required material. `events` retains every checked fact
/// by sequence, including durable out-of-order events above the contiguous
/// frontier, so holes are preserved instead of excluded.
#[derive(Clone)]
struct RecoveryStreamProgress {
    cut: Option<RecoveryStreamCut>,
    owner_identity: Option<(String, u64)>,
    next_gap_offset: u64,
    acked_base: u64,
    acked_high: u64,
    durable_cursor: u64,
    contiguous_frontier: u64,
    highest_observed: u64,
    next_after: u64,
    page_complete: bool,
    events: BTreeMap<u64, RecoveredEventFact>,
    gaps: BTreeMap<String, RecoveredGapFact>,
}

impl RecoveryStreamProgress {
    fn matches_owner(&self, facts: &RecoveredStreamFacts) -> bool {
        self.cut == facts.recovery_cut()
            && self
                .owner_identity
                .as_ref()
                .map(|(producer, incarnation)| (producer.as_str(), *incarnation))
                == facts.owner_identity()
    }
}

/// The declared finite recovery window: one coherent owner observation
/// bound to the live attach authority.
///
/// Bridge process memory stays a reconstructable cache: the durable source
/// and recovery progress live with their existing owners, and this window
/// only tracks which required facts have been restored. A lost cache
/// delays acknowledgement; it never mints fresh events or erases known
/// pending work. No database transaction is held across network calls —
/// each page is validated whole against this window before anything is
/// applied.
#[derive(Clone)]
struct RecoveryWindow {
    window_key: String,
    live_generation: u64,
    import_revision: u64,
    stream_order: Vec<String>,
    streams: BTreeMap<String, RecoveryStreamProgress>,
    unscoped_gaps: BTreeMap<String, RecoveredGapFact>,
    unproven_scope_present: bool,
    stream_list_complete: bool,
    stream_list_continuation: Option<String>,
    unscoped_gaps_complete: bool,
    unscoped_gaps_continuation: Option<RecoveryUnscopedGapCursor>,
    incomplete_reason: Option<&'static str>,
}

impl RecoveryWindow {
    fn disposition(&self) -> RecoveryDisposition {
        if let Some(reason) = self.incomplete_reason {
            if reason == RECOVERY_UNAVAILABLE_FOREIGN_PAGE {
                return RecoveryDisposition::Unavailable { reason };
            }
            return RecoveryDisposition::Partial { reason };
        }
        if !self.stream_list_complete {
            return RecoveryDisposition::Partial {
                reason: RECOVERY_PARTIAL_STREAM_LIST_TRUNCATED,
            };
        }
        if !self.unscoped_gaps_complete {
            return RecoveryDisposition::Partial {
                reason: RECOVERY_PARTIAL_PAGE_CONTINUATION,
            };
        }
        if self.unproven_scope_present {
            return RecoveryDisposition::Partial {
                reason: RECOVERY_PARTIAL_UNPROVEN_SCOPE,
            };
        }
        for stream_id in &self.stream_order {
            let complete = self
                .streams
                .get(stream_id)
                .is_some_and(|progress| progress.page_complete);
            if !complete {
                return RecoveryDisposition::Partial {
                    reason: RECOVERY_PARTIAL_PAGE_CONTINUATION,
                };
            }
        }
        RecoveryDisposition::Complete
    }

    fn view(&self) -> RecoveryView {
        RecoveryView {
            window_key: self.window_key.clone(),
            live_generation: self.live_generation,
            streams: self
                .stream_order
                .iter()
                .filter_map(|stream_id| {
                    self.streams
                        .get(stream_id)
                        .map(|progress| RecoveryStreamView {
                            stream_id: stream_id.clone(),
                            acked_base: progress.acked_base,
                            durable_cursor: progress.durable_cursor,
                            contiguous_frontier: progress.contiguous_frontier,
                            highest_observed: progress.highest_observed,
                            next_after: progress.next_after,
                            recovered_events: progress.events.len() as u64,
                            recovered_gaps: progress.gaps.len() as u64,
                            page_complete: progress.page_complete,
                        })
                })
                .collect(),
            unscoped_gaps: self.unscoped_gaps.len() as u64,
            unproven_scope_present: self.unproven_scope_present,
            stream_list_complete: self.stream_list_complete,
            unscoped_gaps_complete: self.unscoped_gaps_complete,
            disposition: self.disposition(),
        }
    }

    #[allow(clippy::result_large_err)]
    fn next_request(&self, binding: &AttachBinding) -> Result<RecoveryReadRequest, BridgeError> {
        let generation = binding.activation_generation.get();
        let connection = binding.connection_id.as_str().to_owned();
        if let Some(next) = self.stream_order.iter().find(|stream_id| {
            self.streams
                .get(*stream_id)
                .is_some_and(|progress| !progress.page_complete)
        }) {
            let progress = self
                .streams
                .get(next)
                .ok_or(BridgeError::InvalidTransition(
                    "recovery window names a stream without progress",
                ))?;
            return RecoveryReadRequest::checked_stream(
                self.window_key.clone(),
                next.clone(),
                progress.next_after,
                progress.cut.ok_or(BridgeError::InvalidTransition(
                    "owner page has no finite recovery cut",
                ))?,
                RECOVERY_PAGE_EVENT_LIMIT,
                progress.next_gap_offset,
                RECOVERY_PAGE_GAP_LIMIT,
                generation,
                connection,
            );
        }
        if let Some(after_stream) = &self.stream_list_continuation {
            return RecoveryReadRequest::checked_streams(
                self.window_key.clone(),
                after_stream.clone(),
                4,
                generation,
                connection,
            );
        }
        if let Some(cursor) = &self.unscoped_gaps_continuation {
            return RecoveryReadRequest::checked_unscoped_gaps(
                self.window_key.clone(),
                cursor.after_gap_scope().to_owned(),
                cursor.gap_offset(),
                RECOVERY_PAGE_GAP_LIMIT,
                generation,
                connection,
            );
        }
        Err(BridgeError::InvalidTransition(
            "recovery window has no pending page; the walk is complete or unstarted",
        ))
    }
}

/// The thin, restart-empty A-16 bridge core.
pub struct AgentBridgeCore {
    readiness: ProviderReadiness,
    host_activation: Option<Box<dyn HostActivationPort>>,
    mcp_forwarding: Option<Box<dyn McpForwardingPort>>,
    skill_lifecycle: Option<Box<dyn SkillLifecyclePort>>,
    cursor_policy: CursorPolicy,
    active: Option<ActiveAttach>,
    replay: ReplayLedger,
    acknowledged_phases: BTreeMap<EventIdentityKey, AckPhase>,
    pending_deliveries: BTreeMap<EventIdentityKey, PendingDelivery>,
    cursors: BTreeMap<String, u64>,
    host_journal: Vec<HostEventEnvelope>,
    attempt_transitions: Vec<AttemptTransition>,
    recovery_directives: Vec<RecoveryDirective>,
    canonical_refs: CanonicalWriteRefs,
    transport_edges: Vec<TransportEdge>,
    terminal_coverage: CoverageFlags,
    stale_ui_disposition: Option<String>,
    error_event_refs: Vec<String>,
    resources: ResourceRegistry,
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
            skill_lifecycle: None,
            cursor_policy,
            active: None,
            replay: ReplayLedger::new(),
            acknowledged_phases: BTreeMap::new(),
            pending_deliveries: BTreeMap::new(),
            cursors: BTreeMap::new(),
            host_journal: Vec::new(),
            attempt_transitions: Vec::new(),
            recovery_directives: Vec::new(),
            canonical_refs: CanonicalWriteRefs::default(),
            transport_edges: Vec::new(),
            terminal_coverage: CoverageFlags::default(),
            stale_ui_disposition: None,
            error_event_refs: Vec::new(),
            resources: ResourceRegistry::new(),
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
            ActivationPortOutcome::Denied(report) => {
                return Err(BridgeError::ActivationDenied(report));
            }
            ActivationPortOutcome::DeadlineExceeded {
                operation,
                deadline_unix_ms,
            } => {
                return Err(BridgeError::ActivationDeadlineExceeded {
                    operation,
                    deadline_unix_ms,
                });
            }
            ActivationPortOutcome::UnknownOutcome { operation } => {
                return Err(BridgeError::ActivationUnknownOutcome { operation });
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
                    &grant.task_binding,
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
                task_binding: grant.task_binding,
            },
            reconciliation_required: request.attach_kind == AttachKind::External,
            blind_interval: request.pre_attach_blind_interval,
            recovery: None,
        };
        self.active = Some(active);
        self.replay = ReplayLedger::new();
        self.acknowledged_phases.clear();
        self.cursors.clear();
        self.host_journal.clear();
        self.attempt_transitions.clear();
        self.recovery_directives.clear();
        self.canonical_refs = CanonicalWriteRefs::default();
        self.transport_edges.clear();
        self.terminal_coverage = CoverageFlags::default();
        self.stale_ui_disposition = None;
        self.error_event_refs.clear();
        self.resources.clear();
        self.attach_view().ok_or(BridgeError::NotAttached)
    }

    pub fn reconnect(&mut self, request: ReconnectRequest) -> Result<AttachView, BridgeError> {
        let active = self.active.as_mut().ok_or(BridgeError::NotAttached)?;
        if !active.binding.transport_authority_matches(
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
        let (binding, reconciliation_required) = {
            let active = self.active.as_ref().ok_or(BridgeError::NotAttached)?;
            if active.reconciliation_required && active.blind_interval.is_none() {
                return Err(BridgeError::InvalidTransition(
                    "an unreconciled attach requires its declared blind interval",
                ));
            }
            (active.binding.clone(), active.reconciliation_required)
        };
        let outcome = self.forwarder()?.reconcile_external(&binding)?;
        let result = match outcome {
            ReconciliationPortOutcome::Reconciled(result) => result,
            ReconciliationPortOutcome::Denied { reason_code } => {
                validate_text(reason_code, "reconciliation_denial.reason_code")?;
                return Err(BridgeError::ExternalReconciliationDenied(reason_code));
            }
        };
        let permit = ReconciliationPermit::seal(result.clone())?;
        {
            let active = self.active.as_mut().ok_or(BridgeError::NotAttached)?;
            if active.binding != binding {
                return Err(BridgeError::StaleAuthority);
            }
            if !active.binding.authority_matches(
                &permit.session_id,
                permit.activation_generation,
                &permit.state_fence,
                &permit.task_binding,
            ) {
                return Err(BridgeError::StaleAuthority);
            }
            validate_text(permit.receipt_ref.as_str(), "reconciliation_receipt_ref")?;
            if let Some(window) = permit.window.as_deref() {
                // Validate and merge into an isolated candidate. A malformed
                // or contradictory later stream/gap cannot leave earlier
                // facts from this same page applied to the live window.
                let mut candidate = active.recovery.clone();
                let disposition =
                    Self::apply_recovery_window(&active.binding, &mut candidate, window)?;
                active.recovery = candidate;
                if reconciliation_required && disposition == RecoveryDisposition::Complete {
                    active.reconciliation_required = false;
                }
            }
        }
        // The production adapter commits its process-local ack/frontier cache
        // only after the checked window is now the live core state.
        if result.window().is_some() {
            self.forwarder()?.reconciliation_imported(&binding, &result);
        }
        self.attach_view().ok_or(BridgeError::NotAttached)
    }

    /// Reads one bounded recovery page inside the declared window without
    /// clearing the gate by itself.
    ///
    /// Recovery-only reads stay reachable while normal forwarding is gated
    /// (`ensure_forwardable` is not required here), so the gate cannot
    /// prevent the very work needed to satisfy it. The read changes no
    /// producer/consumer cursor, performs no ordinary effect, and never
    /// marks anything APPLIED: it only restores checked receipt/accounting
    /// facts. Each call rechecks the live attach authority, including after
    /// a reconnect, and a late result for a replaced attach fails closed
    /// without touching current recovery state.
    #[allow(clippy::result_large_err)]
    pub fn recover_next_page(&mut self) -> Result<RecoveryView, BridgeError> {
        self.ensure_contracts()?;
        let (binding, request) = {
            let active = self.active.as_ref().ok_or(BridgeError::NotAttached)?;
            let window = active
                .recovery
                .as_ref()
                .ok_or(BridgeError::InvalidTransition(
                    "no declared recovery window; reconcile_external opens the walk",
                ))?;
            let request = window.next_request(&active.binding)?;
            (active.binding.clone(), request)
        };
        if request.expected_generation != binding.activation_generation.get()
            || request.expected_connection != binding.connection_id.as_str()
        {
            return Err(BridgeError::StaleAuthority);
        }
        let outcome = self.forwarder()?.reconcile_continue(&binding, &request)?;
        let result = match outcome {
            ReconciliationPortOutcome::Reconciled(result) => result,
            ReconciliationPortOutcome::Denied { reason_code } => {
                validate_text(reason_code, "reconciliation_denial.reason_code")?;
                return Err(BridgeError::ExternalReconciliationDenied(reason_code));
            }
        };
        let permit = ReconciliationPermit::seal(result.clone())?;
        {
            let active = self.active.as_mut().ok_or(BridgeError::NotAttached)?;
            if active.binding != binding {
                return Err(BridgeError::StaleAuthority);
            }
            if !active.binding.authority_matches(
                &permit.session_id,
                permit.activation_generation,
                &permit.state_fence,
                &permit.task_binding,
            ) {
                return Err(BridgeError::StaleAuthority);
            }
            validate_text(permit.receipt_ref.as_str(), "reconciliation_receipt_ref")?;
            let window = permit
                .window
                .as_deref()
                .ok_or(BridgeError::InvalidTransition(
                    "bounded recovery continuation requires a windowed owner answer",
                ))?;
            // See the initial page path above: stage the entire continuation
            // before publishing any fact or acknowledging its consumed offer.
            let mut candidate = active.recovery.clone();
            let disposition = Self::apply_recovery_window(&active.binding, &mut candidate, window)?;
            active.recovery = candidate;
            if disposition == RecoveryDisposition::Complete {
                active.reconciliation_required = false;
            }
        }
        self.forwarder()?.reconciliation_imported(&binding, &result);
        self.recovery_view().ok_or(BridgeError::NotAttached)
    }

    /// Returns the read-only progress of the declared recovery window, if any.
    pub fn recovery_view(&self) -> Option<RecoveryView> {
        self.active
            .as_ref()?
            .recovery
            .as_ref()
            .map(RecoveryWindow::view)
    }

    /// Reads a bounded projection of every imported stream, pending event,
    /// and scoped or unscoped gap identity. The owner window and attach stay
    /// read-only: paging changes neither owner cursors nor delivery state.
    /// A continuation is refused if another owner page was imported after it
    /// was issued, so a keyset cannot silently omit facts inserted earlier
    /// in the walk.
    #[allow(clippy::result_large_err)]
    pub fn recovery_projection_page(
        &self,
        cursor: Option<&str>,
    ) -> Result<RecoveryProjectionPage, BridgeError> {
        let active = self.active.as_ref().ok_or(BridgeError::NotAttached)?;
        let Some(window) = active.recovery.as_ref() else {
            if cursor.is_some() {
                return Err(BridgeError::InvalidTransition(
                    "recovery projection cursor is stale because no window is active",
                ));
            }
            return Ok(RecoveryProjectionPage {
                summary: None,
                items: Vec::new(),
                next_cursor: None,
            });
        };

        let window_digest = recovery_window_digest(&window.window_key);
        let mut position = if let Some(cursor) = cursor {
            let claims = decode_recovery_projection_cursor(cursor)?;
            if claims.window_digest != window_digest
                || claims.live_generation != window.live_generation
                || claims.import_revision != window.import_revision
            {
                return Err(BridgeError::InvalidTransition(
                    "recovery projection cursor is stale for the current window revision",
                ));
            }
            if claims.stream_index > window.stream_order.len() {
                return Err(BridgeError::InvalidTransition(
                    "invalid recovery projection cursor position",
                ));
            }
            validate_recovery_projection_position(window, &claims)?;
            claims
        } else {
            RecoveryProjectionCursor {
                version: 1,
                window_digest,
                live_generation: window.live_generation,
                import_revision: window.import_revision,
                section: RecoveryProjectionSection::Streams,
                stream_index: 0,
                after_sequence: None,
                after_gap_id: None,
            }
        };

        let summary = RecoveryProjectionSummary {
            live_generation: window.live_generation,
            stream_count: window.stream_order.len(),
            unscoped_gap_count: window.unscoped_gaps.len(),
            unproven_scope_present: window.unproven_scope_present,
            stream_list_complete: window.stream_list_complete,
            unscoped_gaps_complete: window.unscoped_gaps_complete,
            disposition: window.disposition(),
        };
        let mut items = Vec::with_capacity(MAX_RECOVERY_PROJECTION_ITEMS);
        let mut content_bytes = 0usize;
        let mut scans = 0usize;

        while items.len() < MAX_RECOVERY_PROJECTION_ITEMS
            && scans < MAX_RECOVERY_PROJECTION_SCANS
            && position.section != RecoveryProjectionSection::Done
        {
            match position.section {
                RecoveryProjectionSection::Streams => {
                    if position.stream_index >= window.stream_order.len() {
                        position.section = RecoveryProjectionSection::Pending;
                        position.stream_index = 0;
                        scans += 1;
                        continue;
                    }
                    let stream_id = &window.stream_order[position.stream_index];
                    let progress =
                        window
                            .streams
                            .get(stream_id)
                            .ok_or(BridgeError::InvalidTransition(
                                "recovery stream order names missing progress",
                            ))?;
                    let record = RecoveryProjectionRecord::Stream(RecoveryStreamView {
                        stream_id: stream_id.clone(),
                        acked_base: progress.acked_base,
                        durable_cursor: progress.durable_cursor,
                        contiguous_frontier: progress.contiguous_frontier,
                        highest_observed: progress.highest_observed,
                        next_after: progress.next_after,
                        recovered_events: progress.events.len() as u64,
                        recovered_gaps: progress.gaps.len() as u64,
                        page_complete: progress.page_complete,
                    });
                    let Some(record_bytes) = projection_record_size(
                        &record,
                        MAX_RECOVERY_PROJECTION_PAGE_BYTES - content_bytes,
                    )?
                    else {
                        if items.is_empty() {
                            return Err(BridgeError::InvalidTransition(
                                "recovery projection record exceeds the bounded inline page; owner index or handle required",
                            ));
                        }
                        break;
                    };
                    content_bytes += record_bytes;
                    items.push(record);
                    position.stream_index += 1;
                    scans += 1;
                }
                RecoveryProjectionSection::Pending => {
                    if position.stream_index >= window.stream_order.len() {
                        position.section = RecoveryProjectionSection::ScopedGaps;
                        position.stream_index = 0;
                        position.after_sequence = None;
                        scans += 1;
                        continue;
                    }
                    let stream_id = &window.stream_order[position.stream_index];
                    let progress =
                        window
                            .streams
                            .get(stream_id)
                            .ok_or(BridgeError::InvalidTransition(
                                "recovery stream order names missing progress",
                            ))?;
                    let event = next_event(progress, position.after_sequence);
                    let Some(event) = event else {
                        position.stream_index += 1;
                        position.after_sequence = None;
                        scans += 1;
                        continue;
                    };
                    let event_key = EventIdentityKey::new(&event.stream_id, &event.event_id);
                    let obligation = if self.acknowledged_phases.contains_key(&event_key) {
                        RecoveryProjectionObligation::Covered
                    } else if self.pending_deliveries.contains_key(&event_key) {
                        RecoveryProjectionObligation::DeliveryInProgress
                    } else {
                        RecoveryProjectionObligation::Pending
                    };
                    let record = RecoveryProjectionRecord::Event(RecoveryProjectionEvent {
                        receipt: event.clone(),
                        obligation,
                    });
                    let Some(record_bytes) = projection_record_size(
                        &record,
                        MAX_RECOVERY_PROJECTION_PAGE_BYTES - content_bytes,
                    )?
                    else {
                        if items.is_empty() {
                            return Err(BridgeError::InvalidTransition(
                                "recovery projection record exceeds the bounded inline page; owner index or handle required",
                            ));
                        }
                        break;
                    };
                    content_bytes += record_bytes;
                    items.push(record);
                    position.after_sequence = Some(event.sequence);
                    scans += 1;
                }
                RecoveryProjectionSection::ScopedGaps => {
                    if position.stream_index >= window.stream_order.len() {
                        position.section = RecoveryProjectionSection::UnscopedGaps;
                        position.stream_index = 0;
                        position.after_gap_id = None;
                        scans += 1;
                        continue;
                    }
                    let stream_id = &window.stream_order[position.stream_index];
                    let progress =
                        window
                            .streams
                            .get(stream_id)
                            .ok_or(BridgeError::InvalidTransition(
                                "recovery stream order names missing progress",
                            ))?;
                    let gap = next_gap(&progress.gaps, position.after_gap_id.as_deref());
                    let Some(gap) = gap else {
                        position.stream_index += 1;
                        position.after_gap_id = None;
                        scans += 1;
                        continue;
                    };
                    if gap.gap_id.len() > MAX_RECOVERY_PROJECTION_CURSOR_GAP_KEY_BYTES {
                        if items.is_empty() {
                            return Err(BridgeError::InvalidTransition(
                                "recovery gap identity exceeds the bounded cursor; owner index or handle required",
                            ));
                        }
                        break;
                    }
                    let record = RecoveryProjectionRecord::Gap(gap.clone());
                    let Some(record_bytes) = projection_record_size(
                        &record,
                        MAX_RECOVERY_PROJECTION_PAGE_BYTES - content_bytes,
                    )?
                    else {
                        if items.is_empty() {
                            return Err(BridgeError::InvalidTransition(
                                "recovery projection record exceeds the bounded inline page; owner index or handle required",
                            ));
                        }
                        break;
                    };
                    content_bytes += record_bytes;
                    items.push(record);
                    position.after_gap_id = Some(gap.gap_id.clone());
                    scans += 1;
                }
                RecoveryProjectionSection::UnscopedGaps => {
                    let gap = next_gap(&window.unscoped_gaps, position.after_gap_id.as_deref());
                    let Some(gap) = gap else {
                        position.section = RecoveryProjectionSection::Done;
                        position.after_gap_id = None;
                        scans += 1;
                        continue;
                    };
                    if gap.gap_id.len() > MAX_RECOVERY_PROJECTION_CURSOR_GAP_KEY_BYTES {
                        if items.is_empty() {
                            return Err(BridgeError::InvalidTransition(
                                "recovery gap identity exceeds the bounded cursor; owner index or handle required",
                            ));
                        }
                        break;
                    }
                    let record = RecoveryProjectionRecord::Gap(gap.clone());
                    let Some(record_bytes) = projection_record_size(
                        &record,
                        MAX_RECOVERY_PROJECTION_PAGE_BYTES - content_bytes,
                    )?
                    else {
                        if items.is_empty() {
                            return Err(BridgeError::InvalidTransition(
                                "recovery projection record exceeds the bounded inline page; owner index or handle required",
                            ));
                        }
                        break;
                    };
                    content_bytes += record_bytes;
                    items.push(record);
                    position.after_gap_id = Some(gap.gap_id.clone());
                    scans += 1;
                }
                RecoveryProjectionSection::Done => break,
            }
        }

        let next_cursor = (position.section != RecoveryProjectionSection::Done)
            .then(|| encode_recovery_projection_cursor(&position))
            .transpose()?;
        Ok(RecoveryProjectionPage {
            summary: Some(summary),
            items,
            next_cursor,
        })
    }

    /// Lists recovered owner receipts the bridge has not yet covered with
    /// its own acknowledgement: the pending obligations of the walk.
    ///
    /// These facts are digest-only obligations for the owner-redelivery
    /// path; they never fabricate envelopes and never clear the gate.
    pub fn recovered_pending(&self) -> Vec<RecoveredPendingView> {
        let Some(active) = self.active.as_ref() else {
            return Vec::new();
        };
        let Some(window) = active.recovery.as_ref() else {
            return Vec::new();
        };
        let mut pending = Vec::new();
        for progress in window.streams.values() {
            for event in progress.events.values() {
                let key = EventIdentityKey::new(&event.stream_id, &event.event_id);
                if self.acknowledged_phases.contains_key(&key)
                    || self.pending_deliveries.contains_key(&key)
                {
                    continue;
                }
                pending.push(RecoveredPendingView {
                    stream_id: event.stream_id.clone(),
                    event_id: event.event_id.clone(),
                    sequence: event.sequence,
                    phase: event.phase,
                    envelope_digest: event.envelope_digest.clone(),
                });
            }
        }
        pending.sort_by(|left, right| {
            left.stream_id
                .cmp(&right.stream_id)
                .then(left.sequence.cmp(&right.sequence))
        });
        pending
    }

    /// Validates one windowed owner answer whole, then imports it.
    ///
    /// Nothing is applied until every leg passes: the presenting connection
    /// and live generation must still match the live binding (a late
    /// page/result for an earlier attach fails closed here and changes no
    /// current recovery state), and every stream page must satisfy the
    /// declared window's monotonicity. A new live generation opens a fresh
    /// window — pages are never merged across generations — while a
    /// repeated page restores the same facts idempotently without duplicate
    /// normalization or application. Concurrent movement inside the window
    /// marks the stream incomplete with an explicit reason instead of
    /// stitching a silently complete view.
    #[allow(clippy::result_large_err)]
    fn apply_recovery_window(
        binding: &AttachBinding,
        recovery: &mut Option<RecoveryWindow>,
        facts: &RecoveryWindowFacts,
    ) -> Result<RecoveryDisposition, BridgeError> {
        if facts.presenting_connection != binding.connection_id {
            return Err(BridgeError::StaleAuthority);
        }
        if facts.live_generation != binding.activation_generation {
            return Err(BridgeError::StaleAuthority);
        }
        let new_window = recovery
            .as_ref()
            .is_none_or(|window| window.live_generation != facts.live_generation.get());
        let window = match recovery {
            Some(window) if window.live_generation == facts.live_generation.get() => {
                if window.window_key != facts.window_key {
                    return Err(BridgeError::StaleAuthority);
                }
                window
            }
            _ => {
                *recovery = Some(RecoveryWindow {
                    window_key: facts.window_key.clone(),
                    live_generation: facts.live_generation.get(),
                    import_revision: 0,
                    stream_order: Vec::new(),
                    streams: BTreeMap::new(),
                    unscoped_gaps: BTreeMap::new(),
                    unproven_scope_present: false,
                    stream_list_complete: true,
                    stream_list_continuation: None,
                    unscoped_gaps_complete: true,
                    unscoped_gaps_continuation: None,
                    incomplete_reason: None,
                });
                recovery.as_mut().ok_or(BridgeError::NotAttached)?
            }
        };
        let mut changed = new_window;
        let previous_incomplete_reason = window.incomplete_reason;
        match facts.window_status {
            RecoveryWindowStatus::Active => {}
            RecoveryWindowStatus::Moved => {
                window.incomplete_reason = Some(RECOVERY_PARTIAL_WINDOW_MOVED);
                if window.incomplete_reason != previous_incomplete_reason {
                    changed = true;
                }
                Self::bump_recovery_import_revision(window, changed)?;
                return Ok(window.disposition());
            }
            RecoveryWindowStatus::Expired => {
                window.incomplete_reason = Some(RECOVERY_PARTIAL_WINDOW_EXPIRED);
                if window.incomplete_reason != previous_incomplete_reason {
                    changed = true;
                }
                Self::bump_recovery_import_revision(window, changed)?;
                return Ok(window.disposition());
            }
        }
        changed |= window.stream_list_complete != facts.stream_list_complete;
        changed |= window.stream_list_continuation != facts.stream_list_continuation;
        changed |= window.unscoped_gaps_complete != facts.unscoped_gaps_complete;
        changed |= window.unscoped_gaps_continuation != facts.unscoped_gaps_continuation;
        changed |= !window.unproven_scope_present && facts.unproven_scope_present;
        window.stream_list_complete = facts.stream_list_complete;
        window
            .stream_list_continuation
            .clone_from(&facts.stream_list_continuation);
        window.unscoped_gaps_complete = facts.unscoped_gaps_complete;
        window
            .unscoped_gaps_continuation
            .clone_from(&facts.unscoped_gaps_continuation);
        window.unproven_scope_present |= facts.unproven_scope_present;
        for stream_facts in &facts.stream_facts {
            changed |= Self::apply_recovery_stream(window, stream_facts)
                .ok_or(BridgeError::StaleAuthority)?;
        }
        for gap in &facts.unscoped_gaps {
            match window.unscoped_gaps.get(&gap.gap_id) {
                None => {
                    window.unscoped_gaps.insert(gap.gap_id.clone(), gap.clone());
                    changed = true;
                }
                Some(existing) => {
                    if existing != gap {
                        return Err(BridgeError::StaleAuthority);
                    }
                }
            }
        }
        // Streams that fall out of the enumeration keep their progress but
        // cannot prove completeness; a vanished incomplete stream holds the
        // gate with an explicit reason instead of clearing silently.
        changed |= window.incomplete_reason != previous_incomplete_reason;
        Self::bump_recovery_import_revision(window, changed)?;
        Ok(window.disposition())
    }

    fn bump_recovery_import_revision(
        window: &mut RecoveryWindow,
        changed: bool,
    ) -> Result<(), BridgeError> {
        if changed {
            window.import_revision =
                window
                    .import_revision
                    .checked_add(1)
                    .ok_or(BridgeError::InvalidTransition(
                        "recovery owner import revision overflowed",
                    ))?;
        }
        Ok(())
    }

    /// Validates one stream page against its declared progress, then merges
    /// it. Exact replays restore the same facts; conflicting content under
    /// an already-applied sequence marks movement; new facts extend the
    /// retained set, including durable out-of-order events above the
    /// contiguous frontier.
    fn apply_recovery_stream(
        window: &mut RecoveryWindow,
        facts: &RecoveredStreamFacts,
    ) -> Option<bool> {
        if let Some(progress) = window.streams.get(&facts.stream_id) {
            if !progress.matches_owner(facts) {
                let changed = window.incomplete_reason != Some(RECOVERY_PARTIAL_WINDOW_MOVED);
                window.incomplete_reason = Some(RECOVERY_PARTIAL_WINDOW_MOVED);
                return Some(changed);
            }
            if facts.durable_cursor < progress.durable_cursor
                || facts.acked_cursor < progress.acked_high
            {
                return None;
            }
            for event in facts.events() {
                if let Some(existing) = progress.events.get(&event.sequence)
                    && existing != event
                {
                    return None;
                }
                if progress.events.values().any(|existing| {
                    existing.event_id == event.event_id && existing.sequence != event.sequence
                }) {
                    return None;
                }
            }
            for gap in facts.gaps() {
                if let Some(existing) = progress.gaps.get(&gap.gap_id)
                    && existing != gap
                {
                    return None;
                }
            }
        }
        let is_new_stream = !window.streams.contains_key(&facts.stream_id);
        let previous_progress = window.streams.get(&facts.stream_id).map(|progress| {
            (
                progress.acked_high,
                progress.durable_cursor,
                progress.contiguous_frontier,
                progress.highest_observed,
                progress.next_after,
                progress.next_gap_offset,
                progress.page_complete,
                progress.events.len(),
                progress.gaps.len(),
            )
        });
        let progress = window
            .streams
            .entry(facts.stream_id.clone())
            .or_insert_with(|| RecoveryStreamProgress {
                cut: facts.recovery_cut(),
                owner_identity: facts
                    .owner_identity
                    .as_ref()
                    .map(|(producer, incarnation)| (producer.clone(), *incarnation)),
                next_gap_offset: 0,
                acked_base: facts.acked_cursor,
                acked_high: facts.acked_cursor,
                durable_cursor: facts.acked_cursor,
                contiguous_frontier: facts.acked_cursor,
                highest_observed: facts.acked_cursor,
                next_after: facts.acked_cursor,
                page_complete: false,
                events: BTreeMap::new(),
                gaps: BTreeMap::new(),
            });
        if !window.stream_order.contains(&facts.stream_id) {
            window.stream_order.push(facts.stream_id.clone());
        }
        progress.acked_high = progress.acked_high.max(facts.acked_cursor);
        for event in facts.events() {
            progress
                .events
                .entry(event.sequence)
                .or_insert_with(|| event.clone());
        }
        for gap in facts.gaps() {
            progress
                .gaps
                .entry(gap.gap_id.clone())
                .or_insert_with(|| gap.clone());
        }
        progress.durable_cursor = progress.durable_cursor.max(facts.durable_cursor);
        let acked = progress.acked_base.max(facts.acked_cursor);
        let mut contiguous = acked;
        while let Some(event) = progress.events.get(&contiguous.saturating_add(1)) {
            if phase_reaches(AckPhase::Durable, event.phase) {
                contiguous = contiguous.saturating_add(1);
            } else {
                break;
            }
        }
        progress.contiguous_frontier = contiguous;
        progress.highest_observed = progress
            .highest_observed
            .max(facts.highest_observed_sequence)
            .max(facts.durable_cursor);
        progress.next_after = progress
            .events
            .last_key_value()
            .map_or(acked, |(sequence, _)| *sequence)
            .max(facts.page_continuation.unwrap_or(0))
            .max(progress.next_after);
        if let Some(next) = facts.gap_continuation() {
            if next < progress.next_gap_offset {
                let changed = window.incomplete_reason != Some(RECOVERY_PARTIAL_WINDOW_MOVED);
                window.incomplete_reason = Some(RECOVERY_PARTIAL_WINDOW_MOVED);
                return Some(is_new_stream || changed);
            }
            progress.next_gap_offset = next;
        }
        progress.page_complete = facts.page_complete;
        let previous_progress = previous_progress.unwrap_or((
            facts.acked_cursor,
            facts.acked_cursor,
            facts.acked_cursor,
            facts.acked_cursor,
            facts.acked_cursor,
            0,
            false,
            0,
            0,
        ));
        Some(
            is_new_stream
                || progress.acked_high != previous_progress.0
                || progress.durable_cursor != previous_progress.1
                || progress.contiguous_frontier != previous_progress.2
                || progress.highest_observed != previous_progress.3
                || progress.next_after != previous_progress.4
                || progress.next_gap_offset != previous_progress.5
                || progress.page_complete != previous_progress.6
                || progress.events.len() != previous_progress.7
                || progress.gaps.len() != previous_progress.8,
        )
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

    pub fn forward_hook(&mut self, event: &HostEventEnvelope) -> Result<(), BridgeError> {
        self.ensure_forwardable()?;
        event
            .validate()
            .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
        self.observe_host_event(event)?;
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

    /// Admits one validated host event into the transport journal.
    ///
    /// The route fingerprint passes through untouched, the raw and
    /// normalized payloads stay paired on the retained envelope, and the
    /// host sequence must increase so the journal preserves observation
    /// order. The observation is journaled before port forwarding so a
    /// forwarding failure still leaves immutable diagnostic history. Error
    /// events are additionally cited in `error_event_refs` without
    /// affecting any other field.
    fn observe_host_event(&mut self, event: &HostEventEnvelope) -> Result<(), BridgeError> {
        if let Some(previous) = self.host_journal.last()
            && event.sequence <= previous.sequence
        {
            return Err(BridgeError::ProviderContract(
                "host event sequence must increase".to_owned(),
            ));
        }
        if self.host_journal.len() >= TERMINAL_JOURNAL_CAPACITY {
            self.host_journal.remove(0);
            self.terminal_coverage = self.terminal_coverage.mark_incomplete_coverage();
        }
        if event.kind == HostEventKind::Error {
            self.error_event_refs
                .push(event.event_id.as_str().to_owned());
        }
        self.host_journal.push(event.clone());
        Ok(())
    }

    fn require_attached(&self) -> Result<(), BridgeError> {
        self.active
            .as_ref()
            .map(|_| ())
            .ok_or(BridgeError::NotAttached)
    }

    /// Records one observed attempt state transition verbatim.
    ///
    /// Legality of the transition is decided by the terminal reducer, not
    /// the transport.
    pub fn observe_attempt_transition(
        &mut self,
        from: AttemptState,
        to: AttemptState,
        sequence: u64,
    ) -> Result<(), BridgeError> {
        self.require_attached()?;
        self.attempt_transitions
            .push(AttemptTransition::observe(from, to, sequence)?);
        Ok(())
    }

    /// Files one typed recovery directive chaining an observed recoverable
    /// failure to its corrected call.
    ///
    /// The directive's `for_event` must reference an already journaled host
    /// event and `corrected_event` must be a new identity absent from the
    /// journal, proving the retry/new-identity rule structurally.
    pub fn prescribe_recovery(&mut self, directive: RecoveryDirective) -> Result<(), BridgeError> {
        self.require_attached()?;
        if !self
            .host_journal
            .iter()
            .any(|event| event.event_id.as_str() == directive.for_event())
        {
            return Err(BridgeError::InvalidTransition(
                "recovery directive must reference an observed host event",
            ));
        }
        if self
            .host_journal
            .iter()
            .any(|event| event.event_id.as_str() == directive.corrected_event())
        {
            return Err(BridgeError::InvalidTransition(
                "corrected call must use a new identity not yet present in history",
            ));
        }
        self.recovery_directives.push(directive);
        Ok(())
    }

    /// Records the candidate canonical-write submission reference.
    pub fn record_canonical_submission(
        &mut self,
        reference: impl Into<String>,
    ) -> Result<(), BridgeError> {
        self.require_attached()?;
        self.canonical_refs.record_submission(reference)
    }

    /// Records the candidate canonical-write receipt reference.
    pub fn record_canonical_receipt(
        &mut self,
        reference: impl Into<String>,
    ) -> Result<(), BridgeError> {
        self.require_attached()?;
        self.canonical_refs.record_receipt(reference)
    }

    /// Records the independent exact-readback reference.
    pub fn record_canonical_readback(
        &mut self,
        reference: impl Into<String>,
    ) -> Result<(), BridgeError> {
        self.require_attached()?;
        self.canonical_refs.record_readback(reference)
    }

    /// Records one transport edge without resolving it.
    ///
    /// Unknown-commit, unconfirmed-cancel, and disconnect edges raise their
    /// explicit coverage flags; every other edge is carried verbatim.
    pub fn record_transport_edge(&mut self, edge: TransportEdge) -> Result<(), BridgeError> {
        self.require_attached()?;
        match edge.kind() {
            TransportEdgeKind::UnknownCommit => {
                self.terminal_coverage = self.terminal_coverage.mark_unknown_commit();
            }
            TransportEdgeKind::CancelRequested => {
                self.terminal_coverage = self.terminal_coverage.mark_cancel_unconfirmed();
            }
            TransportEdgeKind::Disconnect => {
                self.terminal_coverage = self.terminal_coverage.mark_incomplete_coverage();
            }
            TransportEdgeKind::Timeout
            | TransportEdgeKind::ParseFailure
            | TransportEdgeKind::LateSuccess
            | TransportEdgeKind::DuplicateCorrectedCall => {}
        }
        self.transport_edges.push(edge);
        Ok(())
    }

    /// Notes the stale UI/CLI terminal display verbatim.
    ///
    /// This is a snapshot of what the surface showed, kept independent of
    /// the canonical references until the reducer compares them.
    pub fn note_stale_ui_disposition(
        &mut self,
        disposition: impl Into<String>,
    ) -> Result<(), BridgeError> {
        self.require_attached()?;
        let disposition = disposition.into();
        validate_text(&disposition, "stale_ui_disposition")?;
        self.stale_ui_disposition = Some(disposition);
        Ok(())
    }

    /// Projects the terminal reduction inputs for the external reducer.
    ///
    /// History, stale display, error citations, canonical references,
    /// edges, cursors, and outstanding deliveries are carried as
    /// independent fields. Nothing here is a terminal disposition.
    #[must_use]
    pub fn terminal_reduction_inputs(&self) -> Option<TerminalReductionInputs> {
        self.active.as_ref().map(|_| {
            TerminalReductionInputs::new(
                self.host_journal.last().map(|event| event.route.clone()),
                self.host_journal.clone(),
                self.attempt_transitions.clone(),
                self.recovery_directives.clone(),
                self.stale_ui_disposition.clone(),
                self.error_event_refs.clone(),
                self.canonical_refs.clone(),
                self.transport_edges.clone(),
                self.terminal_coverage,
                self.cursors.clone(),
                self.outstanding_deliveries(),
            )
        })
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
        let replay_key = EventIdentityKey::new(&event.stream_id, &event.event_id);
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
    // EpochId is always a validated non-zero (lineage_id, sequence) tuple by
    // construction (Implements #64); only the generation retains a scalar
    // non-zero check here.
    if activation_generation.get() == 0 || state_fence.generation().get() == 0 {
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

/// I7.17 default bound for agent-facing recall handles.
///
/// Agent output is handles-first: at most this many top admissible handles
/// plus the rank-trace handle travel by default, regardless of how many the
/// server admitted.
pub const MAX_AGENT_RECALL_HANDLES: usize = 8;

/// I7.17 bounded agent-facing recall projection.
///
/// Default output carries the server-derived disposition, the binding
/// receipt, bounded top handles, and the rank-trace handle. Full ranking and
/// suppression traces travel only behind explicit debug expansion
/// (`debug_rank_trace`). The projection never accepts a disposition from
/// bridge/model output: both inputs are server-issued and the verdict is
/// re-validated against the response before anything is projected.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRecallProjection {
    pub disposition: eliot_types::RecallDisposition,
    pub receipt: eliot_types::RecallReceipt,
    pub rank_trace_handle: String,
    pub handles: Vec<eliot_types::MemoryHandlePreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_rank_trace: Option<eliot_types::L0RankTrace>,
}

/// Projects one server-issued recall response for the agent.
///
/// Fails closed when the verdict does not bind the response, including any
/// forged or agent-invented disposition, which invalidates the rank-trace
/// handle. Handles are truncated to [`MAX_AGENT_RECALL_HANDLES`] without
/// touching the receipt counts, which continue to describe the full
/// server-side visible/suppressed totals.
pub fn project_recall_for_agent(
    response: &eliot_types::RecallL0Response,
    verdict: &eliot_types::ServerRecallVerdict,
    debug_expand_ranking: bool,
) -> Result<AgentRecallProjection, BridgeError> {
    verdict
        .validate_for_l0_response(response)
        .map_err(BridgeError::ProviderContract)?;
    let mut handles = response.handles.clone();
    handles.truncate(MAX_AGENT_RECALL_HANDLES);
    Ok(AgentRecallProjection {
        disposition: verdict.disposition,
        receipt: verdict.receipt.clone(),
        rank_trace_handle: verdict.rank_trace_handle.clone(),
        handles,
        debug_rank_trace: debug_expand_ranking.then(|| response.rank_trace.clone()),
    })
}

/// Typed Skill candidate submission. Fields are private and deserialization
/// re-runs the constructor, so malformed digests, blank references, or
/// duplicate evidence cannot be created. The admission fence travels in the
/// caller's [`RequestMetadata`], never here: this surface mints no fence,
/// principal, session, epoch, or operation identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProposeSkillRequest {
    skill_id: String,
    candidate_package_digest: String,
    action: LifecycleAction,
    evidence_refs: Vec<String>,
    dependency_versions: Vec<DependencyVersion>,
    scope: SkillScope,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProposeSkillRequest {
    skill_id: String,
    candidate_package_digest: String,
    action: LifecycleAction,
    evidence_refs: Vec<String>,
    dependency_versions: Vec<DependencyVersion>,
    scope: SkillScope,
}

impl<'de> Deserialize<'de> for ProposeSkillRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawProposeSkillRequest::deserialize(deserializer)?;
        Self::new(
            raw.skill_id,
            raw.candidate_package_digest,
            raw.action,
            raw.evidence_refs,
            raw.dependency_versions,
            raw.scope,
        )
        .map_err(de::Error::custom)
    }
}

impl ProposeSkillRequest {
    /// Creates a typed candidate submission. Every typed rule is enforced
    /// here and re-enforced by the owning Skill lifecycle before promotion.
    pub fn new(
        skill_id: impl Into<String>,
        candidate_package_digest: impl Into<String>,
        action: LifecycleAction,
        evidence_refs: Vec<String>,
        dependency_versions: Vec<DependencyVersion>,
        scope: SkillScope,
    ) -> Result<Self, SkillError> {
        let request = Self {
            skill_id: skill_id.into(),
            candidate_package_digest: candidate_package_digest.into(),
            action,
            evidence_refs,
            dependency_versions,
            scope,
        };
        request.validate()?;
        Ok(request)
    }

    /// Re-checks every typed rule without mutating the request.
    pub fn validate(&self) -> Result<(), SkillError> {
        if self.skill_id.trim().is_empty() || self.skill_id.chars().any(char::is_control) {
            return Err(SkillError::InvalidField {
                field: "skill_id",
                reason: "must be non-blank and contain no control characters",
            });
        }
        if self.candidate_package_digest.len() != 64
            || self
                .candidate_package_digest
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(SkillError::InvalidField {
                field: "candidate.candidate_package_digest",
                reason: "must be lowercase SHA-256 hex",
            });
        }
        if self.evidence_refs.is_empty() {
            return Err(SkillError::InvalidField {
                field: "candidate.evidence_refs",
                reason: "candidate evidence is required",
            });
        }
        let mut seen = BTreeSet::new();
        for reference in &self.evidence_refs {
            validate_text(reference, "candidate.evidence_ref").map_err(|_| {
                SkillError::InvalidField {
                    field: "candidate.evidence_ref",
                    reason: "must be non-blank and contain no control characters",
                }
            })?;
            if !seen.insert(reference) {
                return Err(SkillError::Duplicate {
                    field: "candidate.evidence_refs",
                });
            }
        }
        let mut dependencies = BTreeSet::new();
        for dependency in &self.dependency_versions {
            dependency.validate()?;
            if !dependencies.insert(dependency) {
                return Err(SkillError::Duplicate {
                    field: "candidate.dependencies",
                });
            }
        }
        self.scope.validate()?;
        Ok(())
    }

    /// Returns the Skill under lifecycle review.
    pub fn skill_id(&self) -> &str {
        &self.skill_id
    }

    /// Returns the materialized candidate package digest.
    pub fn candidate_package_digest(&self) -> &str {
        &self.candidate_package_digest
    }

    /// Returns the proposed lifecycle change.
    pub const fn action(&self) -> LifecycleAction {
        self.action
    }

    /// Returns the exact evidence references.
    pub fn evidence_refs(&self) -> &[String] {
        &self.evidence_refs
    }

    /// Returns the pinned dependency versions.
    pub fn dependency_versions(&self) -> &[DependencyVersion] {
        &self.dependency_versions
    }

    /// Returns the candidate scope.
    pub const fn scope(&self) -> &SkillScope {
        &self.scope
    }
}

/// Injected Skill lifecycle boundary. The Governor skill owner, not A-16,
/// owns lifecycle evidence, conflict state, reversible proposals, and
/// evidence-gated promotion. A-16 forwards the exact admitted fence and typed
/// fields and returns only typed results.
///
/// The boxed-future shape (instead of `async fn`) keeps this trait
/// object-safe without a new async-trait dependency. No `Send` bound is
/// imposed: the Governor borrows behind a production implementation are not
/// guaranteed `Send`, and this surface holds the port thread-locally like its
/// other injected ports.
pub trait SkillLifecyclePort {
    /// Reads one immutable Skill lifecycle view at the admitted fence.
    fn skill_read<'a>(
        &'a mut self,
        ctx: &'a RequestMetadata,
        skill_id: String,
    ) -> Pin<Box<dyn Future<Output = Result<Option<SkillLifecycleView>, SkillError>> + 'a>>;

    /// Submits one typed Skill candidate at the admitted fence.
    fn propose_skill<'a>(
        &'a mut self,
        ctx: &'a RequestMetadata,
        request: ProposeSkillRequest,
    ) -> Pin<Box<dyn Future<Output = Result<SkillCandidate, SkillError>> + 'a>>;

    /// Binds one receiver ack to its exact Hotset receipt and displays the
    /// activated Skill at the admitted fence. The bridge carries the inert
    /// receipt/ack pair and returns only the typed display; tool-authority
    /// checks (admitted version, tool basis, provisional ceiling) stay with
    /// the Governor owner behind the port.
    fn display_skill<'a>(
        &'a mut self,
        ctx: &'a RequestMetadata,
        skill_id: String,
        receipt: HotsetDeliveryReceipt,
        ack: HotsetDeliveryAck,
    ) -> Pin<Box<dyn Future<Output = Result<ActivatedSkillDisplay, SkillError>> + 'a>>;
}

impl AgentBridgeCore {
    /// Injects the composition-selected Skill lifecycle owner.
    #[must_use]
    pub fn with_skill_lifecycle(mut self, port: Box<dyn SkillLifecyclePort>) -> Self {
        self.skill_lifecycle = Some(port);
        self
    }

    /// Returns one cloned Skill lifecycle view at the exact attached fence.
    pub async fn skill_view(
        &mut self,
        ctx: &RequestMetadata,
        skill_id: &str,
    ) -> Result<Option<SkillLifecycleView>, BridgeError> {
        ctx.validate()
            .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
        self.skill_authority_matches(ctx)?;
        let view = self
            .skill_port()?
            .skill_read(ctx, skill_id.to_owned())
            .await?;
        if let Some(view) = &view {
            view.validate()
                .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
        }
        Ok(view)
    }

    /// Submits one typed Skill candidate at the exact attached fence.
    pub async fn propose_skill_candidate(
        &mut self,
        ctx: &RequestMetadata,
        request: ProposeSkillRequest,
    ) -> Result<SkillCandidate, BridgeError> {
        request.validate()?;
        ctx.validate()
            .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
        self.skill_authority_matches(ctx)?;
        let candidate = self.skill_port()?.propose_skill(ctx, request).await?;
        candidate
            .validate()
            .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
        Ok(candidate)
    }

    /// Binds one receiver ack to its exact Hotset receipt and displays the
    /// activated Skill at the exact attached fence.
    pub async fn display_skill_activation(
        &mut self,
        ctx: &RequestMetadata,
        skill_id: &str,
        receipt: HotsetDeliveryReceipt,
        ack: HotsetDeliveryAck,
    ) -> Result<ActivatedSkillDisplay, BridgeError> {
        receipt.validate()?;
        ack.validate()?;
        ctx.validate()
            .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
        self.skill_authority_matches(ctx)?;
        let display = self
            .skill_port()?
            .display_skill(ctx, skill_id.to_owned(), receipt, ack)
            .await?;
        display
            .validate()
            .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
        Ok(display)
    }

    /// Fails closed unless the caller fence covers the exact attached
    /// transport authority. [`RequestMetadata`] carries the dependency-only
    /// [`eliot_contracts::StateFence`] while the attach binding carries the
    /// process [`FencingToken`], so the comparison is the shared authority
    /// epoch tuple plus the resource generation, mirroring
    /// [`AgentBridgeCore::validate_event_binding`].
    fn skill_authority_matches(&self, ctx: &RequestMetadata) -> Result<(), BridgeError> {
        let fence = self.binding()?.state_fence();
        if !ctx
            .state_fence
            .authority_epoch
            .is_same_authority(fence.authority_epoch())
            || ctx.state_fence.resource_generation.value() != fence.generation().get()
        {
            return Err(BridgeError::StaleAuthority);
        }
        Ok(())
    }

    fn skill_port(&mut self) -> Result<&mut (dyn SkillLifecyclePort + 'static), BridgeError> {
        self.skill_lifecycle.as_deref_mut().ok_or_else(|| {
            BridgeError::PlanGap(PlanGap::missing(RequiredProvider::SkillLifecyclePort))
        })
    }

    /// Publishes one large evidence snapshot and returns its bounded
    /// hot-response projection: a preview plus an immutable
    /// `eliot://evidence/<id>` handle. Requires the attached authority, which
    /// is the scope authorization on resolution: no attach, no projection.
    pub fn publish_evidence(&mut self, content: Vec<u8>) -> Result<HotResourceView, BridgeError> {
        self.require_attached()?;
        self.resources.publish_evidence(content)
    }

    /// Publishes one canonical resource snapshot at its exact I7.18 URI and
    /// returns its bounded hot-response projection. Fails closed on
    /// non-canonical URIs and on republishing an immutable URI with different
    /// bytes.
    pub fn publish_resource(
        &mut self,
        uri: &ResourceUri,
        content: Vec<u8>,
    ) -> Result<HotResourceView, BridgeError> {
        self.require_attached()?;
        self.resources.publish(uri, content)
    }

    /// Explicitly expands one previously published handle to its immutable
    /// referenced content. Full evidence, audit, and large-report content is
    /// available only through this call, never inline in a hot response.
    pub fn expand_resource(&self, handle: &ResourceHandle) -> Result<Vec<u8>, BridgeError> {
        self.require_attached()?;
        self.resources.expand(handle)
    }

    /// Projects one tool result into its delivery receipt carrying the exact
    /// result digest, the admissible source handle, the rendered
    /// bytes/tokens measured under the actual route tokenizer, and the
    /// delivery completeness.
    pub fn project_tool_result(
        &self,
        result_bytes: &[u8],
        source_handle: ResourceUri,
        tokens_rendered: u64,
        delivery: DeliveryStatus,
    ) -> Result<ToolResultReceipt, BridgeError> {
        self.require_attached()?;
        Ok(ToolResultReceipt::project(
            result_bytes,
            source_handle,
            tokens_rendered,
            delivery,
        ))
    }

    /// Projects one tool result into its delivery receipt from a live
    /// measurement wire payload: the adapter's attested count passes through
    /// byte-bound verification by [`produce_route_token_observation`] —
    /// versioned wire, admission-linked matched route, exact delivered
    /// bytes — before it may enter the receipt, unaltered. A missing
    /// payload means the route supports no measurement and withholds with
    /// [`BridgeError::UnmeasuredTokens`], as do unlinked, diverged,
    /// unobserved, or misbound payloads; the bridge never estimates the
    /// count. Delivery completeness stays the owner's observed state, as
    /// with [`Self::project_tool_result`].
    pub fn project_produced_tool_result(
        &self,
        result_bytes: &[u8],
        source_handle: ResourceUri,
        payload: Option<&TokenMeasurementPayload>,
        admission: &eliot_agent_api::AdmittedRouteReceipt,
        binding: &eliot_agent_api::ProviderExecutionBinding,
        delivery: DeliveryStatus,
    ) -> Result<ToolResultReceipt, BridgeError> {
        self.require_attached()?;
        let payload = payload.ok_or(BridgeError::UnmeasuredTokens {
            reason: UnmeasuredReason::NoObservation,
        })?;
        let produced = produce_route_token_observation(result_bytes, payload, admission, binding)?;
        Ok(ToolResultReceipt::project(
            result_bytes,
            source_handle,
            produced.tokens(),
            delivery,
        ))
    }

    /// Number of immutable snapshots retained in the attach-scoped resource
    /// projection. The registry is cleared on every new attach, so this
    /// count describes only the live attach.
    #[must_use]
    pub fn resource_registry_len(&self) -> usize {
        self.resources.len()
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
    #[error("activation denied: {0}")]
    ActivationDenied(ActivationDenialReport),
    #[error(
        "activation observed no terminal result before deadline {deadline_unix_ms} for operation {operation}"
    )]
    ActivationDeadlineExceeded {
        operation: String,
        deadline_unix_ms: u64,
    },
    #[error(
        "activation outcome unknown for operation {operation}: no terminal result, deadline not reached"
    )]
    ActivationUnknownOutcome { operation: String },
    #[error("stale session, generation, or state fence")]
    StaleAuthority,
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
    #[error("invalid eliot:// resource identity: {reason}")]
    InvalidResourceUri { reason: &'static str },
    #[error("unknown resource handle: {uri}")]
    UnknownResource { uri: String },
    #[error("resource handle digest does not match stored content")]
    ResourceDigestMismatch,
    #[error("immutable resource URI republished with different content")]
    ResourceImmutableConflict,
    #[error("attach-scoped resource projection is full (capacity {capacity})")]
    ResourceRegistryFull { capacity: usize },
    #[error("resource content of {bytes} bytes exceeds projection capacity {capacity}")]
    ResourceTooLarge { bytes: usize, capacity: usize },
    #[error("incomplete tool-result delivery {delivery:?} cannot satisfy complete evidence")]
    IncompleteDelivery { delivery: DeliveryStatus },
    #[error("tool-result token cost is unmeasured: {reason}")]
    UnmeasuredTokens { reason: UnmeasuredReason },
    #[error(transparent)]
    Skill(#[from] SkillError),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colon_pair_event_identity_keys_do_not_collide() {
        let left = EventIdentityKey::new("a:b", "c");
        let right = EventIdentityKey::new("a", "b:c");
        assert_ne!(left, right);
        assert_ne!(left.canonical_hex(), right.canonical_hex());
        assert_ne!(left.canonical_bytes(), right.canonical_bytes());
        let another_left = EventIdentityKey::new("s:e", "x");
        let another_right = EventIdentityKey::new("s", "e:x");
        assert_ne!(another_left.canonical_hex(), another_right.canonical_hex());
    }

    #[test]
    fn bridge_pending_maps_use_typed_key_without_colon_collision() {
        let mut pending: BTreeMap<EventIdentityKey, u8> = BTreeMap::new();
        let mut acked: BTreeMap<EventIdentityKey, AckPhase> = BTreeMap::new();
        let left = EventIdentityKey::new("a:b", "c");
        let right = EventIdentityKey::new("a", "b:c");
        pending.insert(left.clone(), 1);
        acked.insert(left.clone(), AckPhase::Durable);
        assert!(!pending.contains_key(&right));
        assert!(!acked.contains_key(&right));
        assert!(pending.contains_key(&left));
        assert!(acked.contains_key(&left));
        let left2 = EventIdentityKey::new("s:e", "x");
        let right2 = EventIdentityKey::new("s", "e:x");
        assert_ne!(left2.canonical_hex(), right2.canonical_hex());
    }
}
