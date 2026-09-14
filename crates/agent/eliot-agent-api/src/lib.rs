//! Provider-neutral contracts for the ELIOT agent bridge.
//!
//! This crate is deliberately a contract-only cell.  It does not start a
//! process, call a provider, own task state, or issue authority.  Coordinator
//! and Governor cells consume these immutable projections and perform the
//! corresponding lifecycle decisions.

use std::collections::BTreeSet;

pub use eliot_agent_contracts::AgentAttemptId;
pub use eliot_contracts::{
    ArtifactId, ClockReading, DecisionId, EpochId, LowercaseSha256, PolicyRevision, RequestId,
    ResourceGeneration, SessionId, StateFence, TaskId, WorkLeaseId,
};
pub use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod execution_binding;
pub mod host_event;
pub mod route_receipts;
pub use execution_binding::{
    ExecutionUnit, ExecutionUnitObservation, NativeSession, NativeSessionLocator,
    ProviderExecutionBinding, ProviderObservationLineage, SessionObservation,
    validate_execution_binding,
};
pub use host_event::{
    AssistantDeltaObservation, CancellationObservation, CandidateResultReference,
    CheckpointObservation, ErrorObservation, ExecutionStartedObservation,
    HOST_EVENT_CONTRACT_VERSION, HOST_EVENT_DIGEST_ALGORITHM, HostEventDeliveryDisposition,
    HostEventNormalizationReceipt, HostEventPrivacyClass, HostEventQuarantineReason,
    HostEventReplayDisposition, MAX_HOST_EVENT_OMITTED_FIELDS, MAX_HOST_EVENT_PREDECESSORS,
    MAX_HOST_EVENT_SAFE_TEXT_CHARS, MAX_HOST_EVENT_TEXT_CHARS, MAX_HOST_EVENT_WARNINGS,
    NormalizationCoverage, NormalizedHostEventEnvelope, NormalizedHostEventPayload,
    ProviderTerminalObservation, ProviderTerminalStatus, QualifiedSourceDigest, RawSourceRecord,
    ReasoningSummaryObservation, RestrictedRawSourceHandle, SessionLifecycleObservation,
    SessionLifecycleTransition, ToolInvocationObservation, ToolOutcomeClass,
    ToolOutcomeObservation, UnsupportedDisposition, UnsupportedEventObservation,
    UnsupportedEventReason, WarningObservation, candidate_result_digest_for,
};
pub use route_receipts::{
    AdmittedRouteReceipt, CandidateSelectionDisposition, ExecutionOutcome,
    LEGACY_CANDIDATE_SCHEMA_V5, LegacyCandidateMigration, LegacyCapabilityRouteDecisionV5,
    LegacyQuarantineReason, LegacyRouteQuarantine, MAX_EVIDENCE_REFS, MAX_REJECTED_CANDIDATES,
    MAX_ROUTE_CANDIDATES, MAX_SAFE_ERROR_CHARS, MAX_TEXT_REF_CHARS, NoRouteDisposition,
    PhysicalRouteObservationReceipt, RejectedRouteCandidate, RouteObservationState,
    RouteSelectionCandidate, candidate_digest_for, route_divergence_fields,
};

/// Wire revision v6 converges the six #369 route rows (T4 S4, T4 §5.2):
/// `CapabilityRouteDecision` is renamed to the candidate-only
/// `RouteSelectionCandidate` (explicit versioned legacy decoder, never silent
/// upgrade); the API `RoutingReceipt` migrates to `AdmittedRouteReceipt`
/// with a recomputed self digest; `ActualRouteReceipt` and
/// `PhysicalModelAttemptReceipt` merge into the single
/// `PhysicalRouteObservationReceipt` with requested/observed evidence and
/// two independent disposition axes; behavior-bearing `RouteFingerprint`
/// hashes become canonical lowercase 64-hex SHA-256. Breaking: old wires do
/// not silently upgrade (deny-unknown-fields plus digest/version checks);
/// direct consumers migrate through the sibling coordinator/wire slices.
pub const CONTRACT_VERSION: &str = "eliot-agent-api/v6";

/// Compatibility spelling retained as an exact alias of the canonical owner.
pub type AttemptId = AgentAttemptId;

/// A validated opaque identity owned by this crate for agent-local projections.
/// Remaining identities are agent-local and validated against blank, whitespace-only
/// or control-bearing values; shared identities are imported directly from
/// `eliot-contracts` with no local wrapper retained.
macro_rules! id_type {
    ($name:ident) => {
        #[derive(
            Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, JsonSchema, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates an identity, rejecting empty, whitespace-only or control-bearing values.
            pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                if value.trim().is_empty() {
                    return Err(ContractError::EmptyIdentity(stringify!($name)));
                }
                if value.chars().any(char::is_control) {
                    return Err(ContractError::EmptyIdentity(stringify!($name)));
                }
                Ok(Self(value))
            }

            /// Returns the stable textual representation.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = ContractError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

// Shared TaskId, SessionId and ArtifactId are canonical imports from
// `eliot-contracts`; retaining a local wrapper would create a duplicate owner.
id_type!(LaunchRequestId);
// WorkUnitId is agent-local and distinct from wasm-runtime WorkUnitId by
// owner and namespace; spelling alone does not imply interchangeability.
id_type!(WorkUnitId);
// WorkLeaseId is the canonical owner-neutral issuance identity from
// `eliot-contracts` (`eliot.foundation.work-lease-id`,
// `eliot.governor.work-lease` / `v1`); consumed here by re-export for
// `AuthorityEnvelope::lease` and `AgentAttempt::lease` via the #368
// OwnerIssued provenance-preserving migration. No local wrapper is retained.
id_type!(RouteFingerprintId);
id_type!(EventId);
id_type!(EventCursor);

/// Contract validation failures.  Errors are safe to expose to an external
/// provider and never contain raw provider error bodies or credentials.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContractError {
    #[error("{0} must not be empty")]
    EmptyField(&'static str),
    #[error("{0} identity must not be empty")]
    EmptyIdentity(&'static str),
    #[error("{0} must contain at least one item")]
    EmptyCollection(&'static str),
    #[error("{field} must be greater than zero")]
    ZeroLimit { field: &'static str },
    #[error("child budget exceeds parent budget at {field}")]
    ChildBudgetExceeded { field: &'static str },
    #[error("attempt {attempt} is not allowed to transition from {from:?} to {to:?}")]
    InvalidAttemptTransition {
        attempt: String,
        from: AttemptState,
        to: AttemptState,
    },
    #[error("terminal result cannot be changed")]
    TerminalResultMutation,
    #[error("observed route does not match requested route")]
    RouteMismatch,
    #[error("continuation locator is bound to a different route")]
    ContinuationRouteMismatch,
    #[error("authority is not sufficient for the proposed effect")]
    InsufficientAuthority,
    #[error("unauthorized effect must not contain an execution receipt")]
    UnauthorizedReceipt,
    #[error("work unit must declare exactly one causal property")]
    InvalidCausalProperty,
    #[error("unknown outcome requires an explicit reconciliation reason")]
    MissingUnknownReason,
    #[error("event sequence must be monotonic")]
    NonMonotonicEvent,
    #[error("state fence is invalid")]
    InvalidStateFence,
    #[error("provider execution binding does not match the admitted attempt")]
    BindingMismatch,
    #[error("{field} must be a canonical lowercase SHA-256 hex digest")]
    InvalidDigest { field: &'static str },
    #[error("receipt digest does not match its canonical payload")]
    DigestMismatch,
    #[error("clock reading has invalid observed/known ordering")]
    InvalidClock,
    #[error("route disposition contradicts its evidence")]
    InvalidRouteDisposition,
    #[error("conflicting observation for the same receipt/execution identity")]
    ConflictingObservation,
    #[error("route observation requires an explicit reason and recovery reference")]
    MissingObservationReason,
    #[error("{field} exceeds the bounded length")]
    OversizeField { field: &'static str },
    #[error("unknown route contract version")]
    UnknownContractVersion,
}

/// Whether an admission may expose only safe observations or material work.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AllowedMode {
    ReadOnlyOrientation,
    BoundedExploratory,
    Material,
}

/// Governor-owned admission disposition.  A launch surface cannot invent a
/// weaker private admission path.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionDecision {
    Admit,
    Narrow,
    NeedsScope,
    NeedsTask,
    NeedsSources,
    NeedsCapability,
    NeedsSupervision,
    Deny,
}

/// A route is a semantic fingerprint, not a model/vendor name.
///
/// Behavior-bearing hashes are canonical lowercase 64-hex SHA-256
/// ([`LowercaseSha256`], domain `eliot.agent.route-fingerprint.v6`):
/// placeholders such as `sha256:runtime` are invalid and rejected at the
/// deserialization boundary. Display names and provider locators are not
/// identity proof and remain validated non-blank strings.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteFingerprint {
    pub host_family: String,
    pub adapter: String,
    pub protocol_transport: String,
    pub runtime_hash: LowercaseSha256,
    pub adapter_hash: LowercaseSha256,
    pub provider: String,
    pub model: String,
    pub auth_billing: String,
    pub serializer_hash: LowercaseSha256,
    pub tool_semantics_hash: LowercaseSha256,
    pub reasoning_mode: String,
    pub continuation_behavior: String,
    pub feature_flags_hash: LowercaseSha256,
}

impl RouteFingerprint {
    /// Validates that all behavior-bearing identity components are present.
    /// Hash fields are proven by [`LowercaseSha256`] at the deserialization
    /// boundary; this validates the remaining display/locator components.
    pub fn validate(&self) -> Result<(), ContractError> {
        let values = [
            ("host_family", &self.host_family),
            ("adapter", &self.adapter),
            ("protocol_transport", &self.protocol_transport),
            ("provider", &self.provider),
            ("model", &self.model),
            ("auth_billing", &self.auth_billing),
            ("reasoning_mode", &self.reasoning_mode),
            ("continuation_behavior", &self.continuation_behavior),
        ];
        values
            .into_iter()
            .find(|(_, value)| value.trim().is_empty())
            .map_or(Ok(()), |(field, _)| Err(ContractError::EmptyField(field)))
    }

    /// Returns deterministic JSON suitable for a receipt digest input.
    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// External route/session continuation kind.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ContinuityKind {
    NativeResume,
    NativeFork,
    Replayed,
    Rehydrated,
    Fresh,
}

/// Opaque provider continuation state.  It is never task identity, evidence,
/// rationale, or authority and is always bound to one route fingerprint.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteContinuationLocator {
    pub route: RouteFingerprint,
    pub external_locator: String,
    pub checkpoint_digest: String,
    pub expires_at: String,
}

impl RouteContinuationLocator {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.route.validate()?;
        for (field, value) in [
            ("external_locator", &self.external_locator),
            ("checkpoint_digest", &self.checkpoint_digest),
            ("expires_at", &self.expires_at),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::EmptyField(field));
            }
        }
        Ok(())
    }
}

/// Resource and context ceilings.  Values are explicit; missing quota is not
/// encoded as zero and must instead be represented by [`QuotaKnowledge`].
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetEnvelope {
    pub context_tokens: u64,
    pub wall_time_ms: u64,
    pub output_bytes: u64,
    pub cost_microunits: u64,
    pub max_depth: u16,
    pub max_descendants: u32,
}

impl BudgetEnvelope {
    pub fn validate(&self) -> Result<(), ContractError> {
        for (field, value) in [
            ("context_tokens", self.context_tokens),
            ("wall_time_ms", self.wall_time_ms),
            ("output_bytes", self.output_bytes),
            ("cost_microunits", self.cost_microunits),
        ] {
            if value == 0 {
                return Err(ContractError::ZeroLimit { field });
            }
        }
        if self.max_depth == 0 {
            return Err(ContractError::ZeroLimit { field: "max_depth" });
        }
        Ok(())
    }

    pub fn is_within(&self, parent: &Self) -> Result<(), ContractError> {
        self.validate()?;
        parent.validate()?;
        for (field, child, upper) in [
            ("context_tokens", self.context_tokens, parent.context_tokens),
            ("wall_time_ms", self.wall_time_ms, parent.wall_time_ms),
            ("output_bytes", self.output_bytes, parent.output_bytes),
            (
                "cost_microunits",
                self.cost_microunits,
                parent.cost_microunits,
            ),
            (
                "max_depth",
                u64::from(self.max_depth),
                u64::from(parent.max_depth),
            ),
            (
                "max_descendants",
                u64::from(self.max_descendants),
                u64::from(parent.max_descendants),
            ),
        ] {
            if child > upper {
                return Err(ContractError::ChildBudgetExceeded { field });
            }
        }
        Ok(())
    }
}

/// Whether provider quota/cost information is observable.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaKnowledge {
    Known,
    Estimated,
    Unknown,
    NotExposed,
    NotApplicable,
}

/// Allowed effect classes.  The API describes ceilings; it never executes an
/// effect or promotes a model proposal to an authorized transition.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    Observe,
    ReadWorkspace,
    WriteCandidate,
    ProcessExecution,
    Network,
    CanonicalTransition,
    ExternalEffect,
}

/// A scope/effect ceiling attached to one attempt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectCeiling {
    pub scope_ref: String,
    pub allowed: BTreeSet<EffectKind>,
    pub max_external_effects: u32,
}

impl EffectCeiling {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.scope_ref.trim().is_empty() {
            return Err(ContractError::EmptyField("scope_ref"));
        }
        if self.allowed.is_empty() {
            return Err(ContractError::EmptyCollection("allowed"));
        }
        Ok(())
    }

    pub fn permits(&self, effect: EffectKind) -> bool {
        self.allowed.contains(&effect)
    }
}

/// Authority is an input projection from Governor, never minted by this cell.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEnvelope {
    pub epoch: EpochId,
    pub scope_ref: String,
    pub effect_ceiling: EffectCeiling,
    pub lease: WorkLeaseId,
    pub state_fence: StateFence,
    pub valid_until: String,
}

impl AuthorityEnvelope {
    pub fn validate(&self) -> Result<(), ContractError> {
        for (field, value) in [
            ("scope_ref", &self.scope_ref),
            ("valid_until", &self.valid_until),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::EmptyField(field));
            }
        }
        if self.effect_ceiling.scope_ref != self.scope_ref {
            return Err(ContractError::InsufficientAuthority);
        }
        self.state_fence
            .validate()
            .map_err(|_| ContractError::InvalidStateFence)?;
        if !self
            .epoch
            .is_same_authority(&self.state_fence.authority_epoch)
        {
            return Err(ContractError::InvalidStateFence);
        }
        self.effect_ceiling.validate()
    }
}

/// One causal work unit; it is intentionally narrower than a whole project.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentWorkUnitBrief {
    pub id: WorkUnitId,
    pub objective: String,
    pub causal_property: String,
    pub scope_ref: String,
    pub expected_outputs: Vec<String>,
    pub source_refs: Vec<String>,
    pub verifier_ref: String,
    pub integration_owner: String,
    pub contract_revision: String,
    pub budget: BudgetEnvelope,
    pub effect_ceiling: EffectCeiling,
    pub stop_condition: String,
}

impl AgentWorkUnitBrief {
    pub fn validate(&self) -> Result<(), ContractError> {
        for (field, value) in [
            ("objective", &self.objective),
            ("causal_property", &self.causal_property),
            ("scope_ref", &self.scope_ref),
            ("verifier_ref", &self.verifier_ref),
            ("integration_owner", &self.integration_owner),
            ("contract_revision", &self.contract_revision),
            ("stop_condition", &self.stop_condition),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::EmptyField(field));
            }
        }
        if self.causal_property.split_whitespace().count() == 0 {
            return Err(ContractError::InvalidCausalProperty);
        }
        if self.expected_outputs.is_empty() {
            return Err(ContractError::EmptyCollection("expected_outputs"));
        }
        self.budget.validate()?;
        self.effect_ceiling.validate()
    }
}

/// Admission evidence and decision for one launch request.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAdmissionReadinessDecision {
    pub request_id: LaunchRequestId,
    pub task_id: TaskId,
    pub mode: AllowedMode,
    pub decision: AdmissionDecision,
    pub scope_revision: String,
    pub task_contract_revision: Option<String>,
    pub governing_source_refs: Vec<String>,
    pub missing_inputs: Vec<String>,
    pub expiry: String,
}

impl AgentAdmissionReadinessDecision {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.scope_revision.trim().is_empty() || self.expiry.trim().is_empty() {
            return Err(ContractError::EmptyField("scope_revision/expiry"));
        }
        if matches!(
            self.decision,
            AdmissionDecision::Admit | AdmissionDecision::Narrow
        ) && self.governing_source_refs.is_empty()
        {
            return Err(ContractError::EmptyCollection("governing_source_refs"));
        }
        if self.mode == AllowedMode::Material
            && self
                .task_contract_revision
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err(ContractError::EmptyField("task_contract_revision"));
        }
        Ok(())
    }
}

/// Provider-neutral launch request.  It is a proposal to Governor/Coordinator,
/// not a command to spawn a process or invoke a provider.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLaunchRequest {
    pub id: LaunchRequestId,
    pub task_id: TaskId,
    pub parent_attempt: Option<AttemptId>,
    pub work_units: Vec<AgentWorkUnitBrief>,
    pub required_competence: Vec<String>,
    pub allowed_route_classes: Vec<String>,
    pub native_child_policy: String,
    pub root_context_revision: String,
    pub context_budget: BudgetEnvelope,
    pub evidence_capability_refs: Vec<String>,
    pub privacy_profile: String,
    pub effect_ceiling: EffectCeiling,
    pub max_depth: u16,
    pub max_fanout: u32,
    pub cumulative_descendant_budget: BudgetEnvelope,
    pub verifier_ref: String,
    pub synthesis_owner: String,
    pub integration_owner: String,
    pub cancellation_policy: String,
}

impl AgentLaunchRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.work_units.is_empty() {
            return Err(ContractError::EmptyCollection("work_units"));
        }
        for (field, value) in [
            ("native_child_policy", &self.native_child_policy),
            ("root_context_revision", &self.root_context_revision),
            ("privacy_profile", &self.privacy_profile),
            ("verifier_ref", &self.verifier_ref),
            ("synthesis_owner", &self.synthesis_owner),
            ("integration_owner", &self.integration_owner),
            ("cancellation_policy", &self.cancellation_policy),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::EmptyField(field));
            }
        }
        if self.required_competence.is_empty() || self.allowed_route_classes.is_empty() {
            return Err(ContractError::EmptyCollection("competence/routes"));
        }
        if self.max_depth == 0 || self.max_fanout == 0 {
            return Err(ContractError::ZeroLimit {
                field: "depth/fanout",
            });
        }
        self.context_budget.validate()?;
        self.cumulative_descendant_budget.validate()?;
        self.effect_ceiling.validate()?;
        for work_unit in &self.work_units {
            work_unit.validate()?;
            work_unit.budget.is_within(&self.context_budget)?;
        }
        Ok(())
    }
}

/// Lifecycle of a durable attempt.  External processes/sessions are attached
/// to this identity; they do not define it.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttemptState {
    Admitted,
    Started,
    Running,
    Cancelling,
    Checkpointed,
    Reconciling,
    Completed,
    Failed,
    UnknownOutcome,
    Cancelled,
    Quarantined,
}

impl AttemptState {
    fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Admitted, Self::Started | Self::Cancelled)
                | (
                    Self::Started,
                    Self::Running | Self::Cancelling | Self::Failed
                )
                | (
                    Self::Running,
                    Self::Cancelling
                        | Self::Checkpointed
                        | Self::Completed
                        | Self::Failed
                        | Self::UnknownOutcome
                )
                | (
                    Self::Cancelling,
                    Self::Cancelled | Self::Reconciling | Self::UnknownOutcome
                )
                | (
                    Self::Checkpointed,
                    Self::Running | Self::Reconciling | Self::Cancelled
                )
                | (
                    Self::Reconciling,
                    Self::Completed | Self::Failed | Self::UnknownOutcome | Self::Quarantined
                )
        )
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Failed
                | Self::UnknownOutcome
                | Self::Cancelled
                | Self::Quarantined
        )
    }
}

/// A cancellation request is durable and idempotent by request identity.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelReason {
    UserRequested,
    ParentCancelled,
    BudgetExceeded,
    RouteLost,
    ScopeRevoked,
    SupervisionFailure,
    StaleAttempt,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CancellationState {
    NotRequested,
    Requested,
    Acknowledged,
    CleanupPending,
    Reconciled,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRequest {
    pub attempt_id: AttemptId,
    pub reason: CancelReason,
    pub requested_at: String,
    pub state_fence: StateFence,
}

impl CancelRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        for (field, value) in [
            ("attempt_id", self.attempt_id.as_str()),
            ("requested_at", self.requested_at.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::EmptyField(field));
            }
        }
        self.state_fence
            .validate()
            .map_err(|_| ContractError::InvalidStateFence)
    }
}

/// A normalized event from a host/provider adapter.
///
/// Legacy quarantine boundary (issue #371, T4 S6): the generic
/// `normalized_payload: serde_json::Value` wire is not a closed normalized
/// contract and must not gain new policy, authority, completion, or
/// capability consumers. New producers and consumers use the closed,
/// versioned owner in [`host_event::NormalizedHostEventEnvelope`]
/// (`eliot-agent-api/host-event-v7`); old wires never deserialize as that
/// schema. This enum and [`HostEventEnvelope`] are intentionally untouched
/// (no rename, no Serde change) so existing codex/bridge consumers keep
/// compiling.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostEventKind {
    SessionStarted,
    PromptSubmitted,
    ReasoningDelta,
    AssistantDelta,
    ToolCall,
    ToolResult,
    Checkpoint,
    Usage,
    Warning,
    Error,
    CancelRequested,
    Completed,
    Failed,
    Unknown,
}

/// Legacy host-event wire retained as the quarantine boundary (issue #371,
/// T4 S6). Intentionally untouched: no rename, no Serde change, so existing
/// codex/bridge consumers keep compiling. New observations use
/// [`host_event::NormalizedHostEventEnvelope`]; a legacy wire carrying
/// `normalized_payload: serde_json::Value` never deserializes as that closed
/// schema.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEventEnvelope {
    pub event_id: EventId,
    #[deprecated(note = "use lineage; attempt_id is legacy and rejected for attribution")]
    pub attempt_id: AttemptId,
    pub sequence: u64,
    pub cursor: EventCursor,
    pub kind: HostEventKind,
    pub route: RouteFingerprint,
    pub raw_payload_digest: String,
    pub normalized_payload: serde_json::Value,
    pub parent_event_id: Option<EventId>,
    pub observed_at: String,
    /// Provenance lineage for this observation. `None` is a legacy
    /// thread-only wire: session observation only, rejected for attribution
    /// (see [`ProviderObservationLineage::attributable_binding`]).
    #[serde(default)]
    pub lineage: Option<ProviderObservationLineage>,
}

impl HostEventEnvelope {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.route.validate()?;
        if self.sequence == 0 {
            return Err(ContractError::ZeroLimit { field: "sequence" });
        }
        for (field, value) in [
            ("raw_payload_digest", &self.raw_payload_digest),
            ("observed_at", &self.observed_at),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::EmptyField(field));
            }
        }
        Ok(())
    }
}

/// Route/usage facts observed after execution.  Unknown values remain typed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageReceipt {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cost_microunits: Option<u64>,
    pub quota: QuotaKnowledge,
}

/// Durable attempt identity and its bounded projections.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAttempt {
    pub id: AttemptId,
    pub launch_request_id: LaunchRequestId,
    pub task_id: TaskId,
    pub parent_attempt: Option<AttemptId>,
    pub work_unit: AgentWorkUnitBrief,
    pub session: Option<SessionId>,
    pub lease: WorkLeaseId,
    pub state: AttemptState,
    pub continuity: ContinuityKind,
    pub route: RouteFingerprint,
    pub budget: BudgetEnvelope,
    pub authority: AuthorityEnvelope,
    pub cancellation: CancellationState,
    pub event_cursor: Option<EventCursor>,
    pub continuation: Option<RouteContinuationLocator>,
    /// Exact provider-execution binding for this attempt (issue #361 S1).
    /// `None` is an unresolved launch: representable, but never an
    /// attribution bypass — attribution requires a validated binding (see
    /// [`AgentAttempt::attributable_binding`]).
    #[serde(default)]
    pub provider_binding: Option<ProviderExecutionBinding>,
}

impl AgentAttempt {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.work_unit.validate()?;
        self.route.validate()?;
        self.budget.is_within(&self.work_unit.budget)?;
        self.authority.validate()?;
        if let Some(locator) = &self.continuation {
            locator.validate()?;
            if locator.route != self.route {
                return Err(ContractError::ContinuationRouteMismatch);
            }
        }
        if let Some(binding) = &self.provider_binding {
            binding.validate_against_attempt(self)?;
        }
        Ok(())
    }

    /// Returns the attributable provider-execution binding, failing closed
    /// when the launch is unresolved (`None`): a missing binding yields no
    /// attributable output. Fence/generation freshness against the current
    /// runtime context needs [`validate_execution_binding`], which takes the
    /// admitted attempt plus the current fence and generation explicitly.
    pub fn attributable_binding(&self) -> Result<&ProviderExecutionBinding, ContractError> {
        self.provider_binding
            .as_ref()
            .ok_or(ContractError::BindingMismatch)
    }

    pub fn transition(&mut self, next: AttemptState) -> Result<(), ContractError> {
        if self.state.is_terminal() || !self.state.can_transition_to(next) {
            return Err(ContractError::InvalidAttemptTransition {
                attempt: self.id.as_str().to_owned(),
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        Ok(())
    }
}

/// A candidate effect returned by an agent.  It has no authority and no
/// execution receipt until a separate Governor-owned transition accepts it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedEffect {
    pub effect_id: String,
    pub attempt_id: AttemptId,
    pub kind: EffectKind,
    pub scope_ref: String,
    pub payload_digest: String,
    pub rationale_ref: Option<String>,
}

impl ProposedEffect {
    pub fn validate_against(&self, ceiling: &EffectCeiling) -> Result<(), ContractError> {
        if self.scope_ref != ceiling.scope_ref || !ceiling.permits(self.kind) {
            return Err(ContractError::InsufficientAuthority);
        }
        for (field, value) in [
            ("effect_id", &self.effect_id),
            ("scope_ref", &self.scope_ref),
            ("payload_digest", &self.payload_digest),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::EmptyField(field));
            }
        }
        Ok(())
    }
}

/// Explicit Governor authorization attached to a proposed effect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedEffect {
    pub proposal: ProposedEffect,
    pub authority_epoch: EpochId,
    pub authorization_ref: String,
    pub authorized_at: String,
    pub expires_at: String,
}

impl AuthorizedEffect {
    pub fn validate(&self, authority: &AuthorityEnvelope) -> Result<(), ContractError> {
        self.proposal.validate_against(&authority.effect_ceiling)?;
        if self.authorization_ref.trim().is_empty()
            || self.authorized_at.trim().is_empty()
            || self.expires_at.trim().is_empty()
            || !self.authority_epoch.is_same_authority(&authority.epoch)
        {
            return Err(ContractError::InsufficientAuthority);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectReceipt {
    pub effect_id: String,
    pub authorization_ref: String,
    pub outcome: String,
    pub observed_at: String,
    pub artifact_refs: Vec<ArtifactId>,
}

/// Result disposition; provider output is structurally candidate-only and never
/// expresses Task completion. The strongest positive state is
/// `CandidateSucceeded`, which means only that the provider reports one bounded
/// candidate artifact for its exact execution unit.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResultDisposition {
    CandidateSucceeded,
    Partial,
    Blocked,
    FailedVerification,
    DegradedNoProof,
    Unsafe,
    CancelledObserved,
    Superseded,
    UnknownOutcome,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentResult {
    pub attempt_id: AttemptId,
    pub disposition: ResultDisposition,
    pub artifacts: Vec<ArtifactId>,
    pub evidence_refs: Vec<String>,
    pub proposed_effects: Vec<ProposedEffect>,
    /// `effect_receipts` is intentionally absent: a provider may only propose
    /// effects (`proposed_effects`); authoritative `EffectReceipt` minting is
    /// owned by the canonical effect/transition layer.
    pub unresolved_questions: Vec<String>,
    pub usage: UsageReceipt,
    /// Observed physical route/usage evidence, owned by
    /// [`PhysicalRouteObservationReceipt`]. Requested/observed divergence is
    /// preserved evidence here, never a schema error. Shape is validated
    /// with the result; linkage against the admission and execution binding
    /// is enforced at intake via
    /// [`PhysicalRouteObservationReceipt::validate_against`].
    pub actual_route: PhysicalRouteObservationReceipt,
    pub unknown_reason: Option<String>,
}

impl AgentResult {
    pub fn validate(&self, ceiling: &EffectCeiling) -> Result<(), ContractError> {
        self.actual_route.validate()?;
        for effect in &self.proposed_effects {
            effect.validate_against(ceiling)?;
        }
        if self.disposition == ResultDisposition::UnknownOutcome
            && self.unknown_reason.as_deref().is_none_or(str::is_empty)
        {
            return Err(ContractError::MissingUnknownReason);
        }
        Ok(())
    }

    /// Validates a candidate result against its live execution binding,
    /// admission, and effect ceiling (T4 S5, issue #370).
    ///
    /// Fail-closed contextual validation; it constructs no Finish state,
    /// raises no proof ceiling, mints no effect receipt, and synthesizes no
    /// `observed = requested` route. `UnknownOutcome` ownership stays with
    /// the coordinator reconciliation path; this method only enforces the
    /// linkage below plus the existing shape/ceiling checks.
    ///
    /// Enforced, in order:
    /// - (a) physical linkage via
    ///   [`PhysicalRouteObservationReceipt::validate_against`], which rejects
    ///   a forged binding and preserves `DIVERGED`/`UNOBSERVED` evidence;
    /// - (b) three-way attempt identity: `self.attempt_id`,
    ///   `binding.attempt_id`, `self.actual_route.attempt_id`, and
    ///   `admission.attempt_id` (field declared at
    ///   `src/route_receipts.rs:427`) must agree by typed `==`;
    /// - (c) lease/fence/generation/route agreement between the presented
    ///   binding and the admission, consistent with
    ///   [`validate_execution_binding`]: exact typed-object `==` on
    ///   `lease_id`, `state_fence`, `runtime_generation`, and admitted route
    ///   identity — never text matching, numeric casts, or UUID-string
    ///   comparison;
    /// - (d) per-effect attempt match: every
    ///   [`ProposedEffect::attempt_id`] equals `self.attempt_id` (the gap S5
    ///   closes);
    /// - existing shape/ceiling/unknown-reason checks via [`Self::validate`]
    ///   (per-effect ceiling/scope plus unknown-reason).
    pub fn validate_for_binding(
        &self,
        binding: &ProviderExecutionBinding,
        admission: &AdmittedRouteReceipt,
        ceiling: &EffectCeiling,
    ) -> Result<(), ContractError> {
        self.actual_route.validate_against(binding, admission)?;
        if self.attempt_id != binding.attempt_id
            || self.attempt_id != self.actual_route.attempt_id
            || self.attempt_id != admission.attempt_id
        {
            return Err(ContractError::BindingMismatch);
        }
        if binding.lease_id != admission.lease_id
            || binding.state_fence != admission.state_fence
            || binding.runtime_generation != admission.runtime_generation
            || binding.route != admission.requested_route
        {
            return Err(ContractError::BindingMismatch);
        }
        for effect in &self.proposed_effects {
            if effect.attempt_id != self.attempt_id {
                return Err(ContractError::BindingMismatch);
            }
        }
        self.validate(ceiling)
    }
}

/// Stable schema for downstream generators and fixture comparison.
pub fn contract_schema() -> schemars::Schema {
    schemars::schema_for!(AgentLaunchRequest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochLineageId};
    use std::num::NonZeroU64;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
    const TEST_LINEAGE_B: &str = "550e8400-e29b-41d4-a716-446655440001";

    fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    /// Decodes one canonical digest fixture. Fixture digests are valid-form
    /// lowercase hex; production placeholders such as `sha256:runtime` fail
    /// this same decode and are covered as negatives below.
    fn fixture_digest(value: &str) -> Result<LowercaseSha256, serde_json::Error> {
        serde_json::from_value(serde_json::json!(value))
    }

    fn route() -> Result<RouteFingerprint, serde_json::Error> {
        Ok(RouteFingerprint {
            host_family: "test-host".into(),
            adapter: "test-adapter".into(),
            protocol_transport: "loopback".into(),
            runtime_hash: fixture_digest(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )?,
            adapter_hash: fixture_digest(
                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            )?,
            provider: "provider".into(),
            model: "model".into(),
            auth_billing: "subscription".into(),
            serializer_hash: fixture_digest(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )?,
            tool_semantics_hash: fixture_digest(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )?,
            reasoning_mode: "visible".into(),
            continuation_behavior: "native_resume".into(),
            feature_flags_hash: fixture_digest(
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            )?,
        })
    }

    fn budget() -> BudgetEnvelope {
        BudgetEnvelope {
            context_tokens: 10_000,
            wall_time_ms: 60_000,
            output_bytes: 1_000_000,
            cost_microunits: 1_000,
            max_depth: 2,
            max_descendants: 4,
        }
    }

    fn ceiling() -> EffectCeiling {
        EffectCeiling {
            scope_ref: "scope:test".into(),
            allowed: [EffectKind::Observe].into_iter().collect(),
            max_external_effects: 0,
        }
    }

    fn lease(value: &str) -> Result<WorkLeaseId, serde_json::Error> {
        serde_json::from_value(serde_json::json!({
            "namespace": "eliot.governor.work-lease",
            "revision": "v1",
            "value": value,
        }))
    }

    fn zero_digest() -> Result<LowercaseSha256, serde_json::Error> {
        fixture_digest("0000000000000000000000000000000000000000000000000000000000000000")
    }

    fn observation_binding(
        attempt: &AttemptId,
        lease_id: &WorkLeaseId,
        route: &RouteFingerprint,
        fence: &StateFence,
    ) -> Result<ProviderExecutionBinding, Box<dyn std::error::Error>> {
        Ok(ProviderExecutionBinding {
            attempt_id: attempt.clone(),
            lease_id: lease_id.clone(),
            state_fence: fence.clone(),
            runtime_generation: ResourceGeneration::new(1)?,
            route: route.clone(),
            session_id: None,
            provider_scope_ref: "scope:test".into(),
            native_session: NativeSession::Native(NativeSessionLocator::new("thread-1")?),
            execution_unit: ExecutionUnit::new("test-provider", "unit-1")?,
            start_request_id: RequestId::new("req-1")?,
            start_request_sha256: eliot_contracts::sha256_hex(b"req-1"),
        })
    }

    fn admitted_fixture(
        attempt: &AttemptId,
        lease_id: &WorkLeaseId,
        route: &RouteFingerprint,
        fence: &StateFence,
    ) -> Result<AdmittedRouteReceipt, Box<dyn std::error::Error>> {
        let candidate = RouteSelectionCandidate {
            capability: "test-capability".into(),
            query_intent: "test-intent".into(),
            scope_ref: "scope:test".into(),
            policy_revision: PolicyRevision::new(3)?,
            candidates: vec![route.clone()],
            selected: Some(route.clone()),
            rejected: Vec::new(),
            selection: CandidateSelectionDisposition::Selected,
            evidence_refs: vec!["evidence-1".into()],
        };
        candidate.validate()?;
        let mut receipt = AdmittedRouteReceipt {
            schema_version: CONTRACT_VERSION.to_owned(),
            decision_id: DecisionId::new("decision-1")?,
            candidate_digest: candidate_digest_for(&candidate)?,
            attempt_id: attempt.clone(),
            lease_id: lease_id.clone(),
            state_fence: fence.clone(),
            runtime_generation: ResourceGeneration::new(1)?,
            policy_revision: PolicyRevision::new(3)?,
            requested_route: route.clone(),
            selected_route: Some(route.clone()),
            no_route: None,
            evidence_refs: vec!["evidence-1".into()],
            proof_ceiling: eliot_receipts::ProofCeiling::CandidateArtifact,
            self_digest: zero_digest()?,
        };
        receipt.self_digest = receipt.compute_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn matched_observation_fixture(
        attempt: &AttemptId,
        route: &RouteFingerprint,
        fence: &StateFence,
        admission: &AdmittedRouteReceipt,
        binding: &ProviderExecutionBinding,
    ) -> Result<PhysicalRouteObservationReceipt, Box<dyn std::error::Error>> {
        let mut observation = PhysicalRouteObservationReceipt {
            schema_version: CONTRACT_VERSION.to_owned(),
            attempt_id: attempt.clone(),
            state_fence: fence.clone(),
            runtime_generation: ResourceGeneration::new(1)?,
            admitted_route_digest: admission.self_digest.clone(),
            binding: binding.clone(),
            requested_route: route.clone(),
            observed_route: Some(route.clone()),
            route_state: RouteObservationState::Matched,
            diverged_fields: Vec::new(),
            execution_outcome: ExecutionOutcome::Observed,
            request_digest: fixture_digest(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )?,
            translation_digest: None,
            raw_evidence_digest: None,
            raw_evidence_ref: None,
            usage: UsageReceipt {
                input_tokens: None,
                output_tokens: None,
                cost_microunits: None,
                quota: QuotaKnowledge::Unknown,
            },
            started: ClockReading {
                valid_time_ms: Some(1_000),
                known_time_ms: Some(1_001),
                transaction_sequence: None,
                monotonic_ns: None,
            },
            first_byte: ClockReading::default(),
            first_semantic: ClockReading::default(),
            terminal: ClockReading {
                valid_time_ms: Some(2_000),
                known_time_ms: Some(2_001),
                transaction_sequence: None,
                monotonic_ns: None,
            },
            event_cursor: EventCursor::new("cursor-1")?,
            event_sequence: 1,
            cancellation: None,
            unobserved_reason: None,
            recovery_ref: None,
            safe_public_error: None,
            restricted_raw_error_ref: None,
            self_digest: zero_digest()?,
        };
        observation.self_digest = observation.compute_digest()?;
        observation.validate()?;
        Ok(observation)
    }

    #[test]
    fn route_identity_is_complete_and_deterministic() -> TestResult {
        let route = route()?;
        route.validate()?;
        assert_eq!(route.canonical_json()?, route.canonical_json()?);
        Ok(())
    }

    #[test]
    fn malformed_route_is_rejected() -> TestResult {
        let mut invalid = route()?;
        invalid.model.clear();
        assert_eq!(invalid.validate(), Err(ContractError::EmptyField("model")));

        // Production placeholders are labels, not canonical digests: they
        // fail at the deserialization boundary, never at a later stage.
        for placeholder in [
            "sha256:runtime",
            "sha256:adapter",
            "sha256:serializer",
            "sha256:tools",
            "sha256:features",
            "sha256:route",
        ] {
            let mut wire = serde_json::to_value(route()?)?;
            wire["runtime_hash"] = serde_json::json!(placeholder);
            assert!(
                serde_json::from_value::<RouteFingerprint>(wire).is_err(),
                "placeholder must be rejected: {placeholder}"
            );
        }
        // Malformed digest forms fail as well: empty, short, uppercase,
        // non-hex, and wrong-length inputs are not digests.
        for malformed in [
            "",
            "abc",
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "0123456789abcdef",
        ] {
            let mut wire = serde_json::to_value(route()?)?;
            wire["adapter_hash"] = serde_json::json!(malformed);
            assert!(
                serde_json::from_value::<RouteFingerprint>(wire).is_err(),
                "malformed digest must be rejected: {malformed}"
            );
        }
        Ok(())
    }

    #[test]
    fn child_budget_cannot_widen_parent() {
        let mut child = budget();
        child.context_tokens += 1;
        assert_eq!(
            child.is_within(&budget()),
            Err(ContractError::ChildBudgetExceeded {
                field: "context_tokens"
            })
        );
    }

    #[test]
    fn model_proposal_is_not_an_authorized_effect() -> TestResult {
        let proposal = ProposedEffect {
            effect_id: "effect-1".into(),
            attempt_id: AttemptId::new("attempt-1")?,
            kind: EffectKind::CanonicalTransition,
            scope_ref: "scope:test".into(),
            payload_digest: "sha256:payload".into(),
            rationale_ref: None,
        };
        assert_eq!(
            proposal.validate_against(&ceiling()),
            Err(ContractError::InsufficientAuthority)
        );
        Ok(())
    }

    #[test]
    fn unknown_result_requires_reason() -> TestResult {
        let route = route()?;
        let attempt = AttemptId::new("attempt-1")?;
        let lease_id = lease("lease-1")?;
        let fence = StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::new(1)?);
        let admission = admitted_fixture(&attempt, &lease_id, &route, &fence)?;
        let binding = observation_binding(&attempt, &lease_id, &route, &fence)?;
        let result = AgentResult {
            attempt_id: AttemptId::new("attempt-1")?,
            disposition: ResultDisposition::UnknownOutcome,
            artifacts: Vec::new(),
            evidence_refs: Vec::new(),
            proposed_effects: Vec::new(),
            unresolved_questions: Vec::new(),
            usage: UsageReceipt {
                input_tokens: None,
                output_tokens: None,
                cost_microunits: None,
                quota: QuotaKnowledge::Unknown,
            },
            actual_route: matched_observation_fixture(
                &attempt, &route, &fence, &admission, &binding,
            )?,
            unknown_reason: None,
        };
        assert_eq!(
            result.validate(&ceiling()),
            Err(ContractError::MissingUnknownReason)
        );
        Ok(())
    }

    #[test]
    fn attempt_terminal_state_is_immutable() -> TestResult {
        let mut attempt = AgentAttempt {
            id: AttemptId::new("attempt-1")?,
            launch_request_id: LaunchRequestId::new("launch-1")?,
            task_id: TaskId::new("task-1")?,
            parent_attempt: None,
            work_unit: AgentWorkUnitBrief {
                id: WorkUnitId::new("unit-1")?,
                objective: "observe".into(),
                causal_property: "route identity".into(),
                scope_ref: "scope:test".into(),
                expected_outputs: vec!["evidence".into()],
                source_refs: vec!["source".into()],
                verifier_ref: "verifier".into(),
                integration_owner: "owner".into(),
                contract_revision: "v1".into(),
                budget: budget(),
                effect_ceiling: ceiling(),
                stop_condition: "verified".into(),
            },
            session: None,
            lease: serde_json::from_value::<WorkLeaseId>(
                serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-1"}),
            )?,
            state: AttemptState::Completed,
            continuity: ContinuityKind::Fresh,
            route: route()?,
            budget: budget(),
            authority: AuthorityEnvelope {
                epoch: test_epoch(TEST_LINEAGE_A, 1),
                scope_ref: "scope:test".into(),
                effect_ceiling: ceiling(),
                lease: serde_json::from_value::<WorkLeaseId>(
                    serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-1"}),
                )?,
                state_fence: StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::new(1)?),
                valid_until: "2026-08-14T00:00:00Z".into(),
            },
            cancellation: CancellationState::NotRequested,
            event_cursor: None,
            continuation: None,
            provider_binding: None,
        };
        assert!(attempt.transition(AttemptState::Running).is_err());
        Ok(())
    }

    #[test]
    fn canonical_attempt_and_fence_wire_is_fail_closed() -> TestResult {
        assert!(AttemptId::new("attempt\ncontrol").is_err());
        let legacy = serde_json::json!({
            "epoch": "1",
            "scope_ref": "scope:test",
            "effect_ceiling": {
                "scope_ref": "scope:test",
                "allowed": ["OBSERVE"],
                "max_external_effects": 0
            },
            "lease": "lease-1",
            "state_fence": "legacy-fence",
            "valid_until": "later"
        });
        assert!(serde_json::from_value::<AuthorityEnvelope>(legacy).is_err());

        let mut authority = AuthorityEnvelope {
            epoch: test_epoch(TEST_LINEAGE_A, 1),
            scope_ref: "scope:test".into(),
            effect_ceiling: ceiling(),
            lease: serde_json::from_value::<WorkLeaseId>(
                serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-1"}),
            )?,
            state_fence: StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::new(1)?),
            valid_until: "later".into(),
        };
        assert!(authority.validate().is_ok());
        authority.epoch = test_epoch(TEST_LINEAGE_A, 2);
        assert_eq!(authority.validate(), Err(ContractError::InvalidStateFence));
        Ok(())
    }

    fn authority() -> Result<AuthorityEnvelope, Box<dyn std::error::Error>> {
        Ok(AuthorityEnvelope {
            epoch: test_epoch(TEST_LINEAGE_A, 7),
            scope_ref: "scope:test".into(),
            effect_ceiling: ceiling(),
            lease: serde_json::from_value::<WorkLeaseId>(
                serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-1"}),
            )?,
            state_fence: StateFence::new(test_epoch(TEST_LINEAGE_A, 7), ResourceGeneration::new(3)?),
            valid_until: "later".into(),
        })
    }

    #[test]
    fn api_case_01_attempt_id_is_exact_canonical_alias() -> TestResult {
        fn accepts_canonical(_: AgentAttemptId) {}
        let attempt: AttemptId = AttemptId::new("attempt-case-01")?;
        accepts_canonical(attempt.clone());
        let canonical: AgentAttemptId = attempt;
        let _: AttemptId = canonical;
        Ok(())
    }

    #[test]
    fn api_case_02_canonical_attempt_json_roundtrip_rejects_blank_control() -> TestResult {
        let attempt = AttemptId::new("attempt-case-02")?;
        let wire = serde_json::to_string(&attempt)?;
        assert_eq!(serde_json::from_str::<AttemptId>(&wire)?, attempt);
        assert!(AttemptId::new(" \t").is_err());
        assert!(AttemptId::new("attempt\ncontrol").is_err());
        assert!(serde_json::from_str::<AttemptId>(r#"""#).is_err());
        Ok(())
    }

    #[test]
    fn api_case_03_raw_string_is_not_an_authority_proof_without_canonical_construction()
    -> TestResult {
        let raw = String::from("attempt-case-03");
        assert!(!raw.is_empty());
        // A raw String is not implicitly authority. The accepted transition is
        // the canonical fallible constructor/TryFrom<String> result.
        let typed = AgentAttemptId::try_from(raw)?;
        assert_eq!(typed.as_str(), "attempt-case-03");

        // Keep this source discriminator bounded to the API surface: the
        // compatibility spelling is an exact alias, not a local owner or an
        // infallible reverse bridge. Build retired syntax from fragments so the
        // discriminator cannot match its own assertion literals.
        let source = include_str!("lib.rs");
        assert!(source.contains("pub type AttemptId = AgentAttemptId;"));
        let local_macro = ["id_type!", "(", "AttemptId", ")"].concat();
        let local_struct = ["pub ", "struct ", "AttemptId"].concat();
        let reverse_from = ["impl From<", "String> for ", "AttemptId"].concat();
        assert!(!source.contains(&local_macro));
        assert!(!source.contains(&local_struct));
        assert!(!source.contains(&reverse_from));
        Ok(())
    }

    #[test]
    fn api_case_04_authority_numeric_epoch_and_object_fence_roundtrip() -> TestResult {
        let original = authority()?;
        let wire = serde_json::to_value(&original)?;
        assert!(wire["epoch"].is_object());
        assert_eq!(wire["epoch"]["lineage_id"], TEST_LINEAGE_A);
        assert_eq!(wire["epoch"]["sequence"], 7);
        assert!(wire["state_fence"].is_object());
        assert_eq!(serde_json::from_value::<AuthorityEnvelope>(wire.clone())?, original);
        // Legacy numeric epoch never deserializes (EpochId-only, Implements #64).
        let mut numeric = wire;
        numeric["epoch"] = serde_json::json!(7);
        assert!(serde_json::from_value::<AuthorityEnvelope>(numeric).is_err());
        Ok(())
    }

    #[test]
    fn api_case_05_old_string_epoch_and_fence_are_rejected() -> TestResult {
        let mut wire = serde_json::to_value(authority()?)?;
        wire["epoch"] = serde_json::json!("7");
        assert!(serde_json::from_value::<AuthorityEnvelope>(wire).is_err());
        let mut wire = serde_json::to_value(authority()?)?;
        wire["state_fence"] = serde_json::json!("legacy-fence");
        assert!(serde_json::from_value::<AuthorityEnvelope>(wire).is_err());
        Ok(())
    }

    #[test]
    fn api_case_06_epoch_and_fence_mismatch_fails_closed() -> TestResult {
        let mut value = authority()?;
        value.epoch = test_epoch(TEST_LINEAGE_A, 8);
        assert_eq!(value.validate(), Err(ContractError::InvalidStateFence));
        Ok(())
    }

    #[test]
    fn api_case_07_zero_epoch_generation_and_fence_are_rejected() -> TestResult {
        assert!(NonZeroU64::new(0).is_none());
        assert!(ResourceGeneration::new(0).is_err());
        let zero_fence = StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            ResourceGeneration::default(),
        );
        assert!(zero_fence.validate().is_err());
        let zero = serde_json::json!({
            "authority_epoch": 0,
            "resource_generation": 0,
            "task_revision": null,
            "policy_revision": null,
            "integration_revision": null
        });
        assert!(serde_json::from_value::<StateFence>(zero).is_err());
        // Cross-lineage same sequence never authorizes (EpochId-only, Implements #64).
        let foreign = StateFence::new(
            test_epoch(TEST_LINEAGE_B, 1),
            ResourceGeneration::new(1)?,
        );
        let local = StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            ResourceGeneration::new(1)?,
        );
        assert!(!local.is_compatible_with(&foreign));
        assert!(!local
            .authority_epoch
            .is_same_authority(&foreign.authority_epoch));
        Ok(())
    }

    #[test]
    fn api_case_08_cancel_and_admitted_receipts_reject_legacy_and_zero_fences() -> TestResult {
        let zero_fence = StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            ResourceGeneration::default(),
        );
        let typed_cancel = CancelRequest {
            attempt_id: AttemptId::new("attempt-case-08")?,
            reason: CancelReason::UserRequested,
            requested_at: "later".into(),
            state_fence: zero_fence.clone(),
        };
        assert!(typed_cancel.validate().is_err());

        let route = route()?;
        let attempt = AttemptId::new("attempt-case-08")?;
        let lease_id = lease("lease-case-08")?;
        let typed_admitted = AdmittedRouteReceipt {
            schema_version: CONTRACT_VERSION.to_owned(),
            decision_id: DecisionId::new("decision-case-08-zero")?,
            candidate_digest: fixture_digest(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )?,
            attempt_id: attempt.clone(),
            lease_id: lease_id.clone(),
            state_fence: zero_fence,
            runtime_generation: ResourceGeneration::new(1)?,
            policy_revision: PolicyRevision::new(3)?,
            requested_route: route.clone(),
            selected_route: Some(route.clone()),
            no_route: None,
            evidence_refs: Vec::new(),
            proof_ceiling: eliot_receipts::ProofCeiling::CandidateArtifact,
            self_digest: zero_digest()?,
        };
        assert!(typed_admitted.validate().is_err());

        let mut cancel = serde_json::json!({
            "attempt_id": "attempt-case-08",
            "reason": "user_requested",
            "requested_at": "later",
            "state_fence": "legacy-fence"
        });
        assert!(serde_json::from_value::<CancelRequest>(cancel.clone()).is_err());
        cancel["state_fence"] = serde_json::json!({
            "authority_epoch": 0,
            "resource_generation": 0,
            "task_revision": null,
            "policy_revision": null,
            "integration_revision": null
        });
        assert!(serde_json::from_value::<CancelRequest>(cancel).is_err());

        let fence = StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::new(1)?);
        let admitted = admitted_fixture(&attempt, &lease_id, &route, &fence)?;
        let mut admitted_wire = serde_json::to_value(&admitted)?;
        admitted_wire["state_fence"] = serde_json::json!("legacy-fence");
        assert!(serde_json::from_value::<AdmittedRouteReceipt>(admitted_wire).is_err());
        let mut zero_admitted = serde_json::to_value(&admitted)?;
        zero_admitted["state_fence"] = serde_json::json!({
            "authority_epoch": 0,
            "resource_generation": 0,
            "task_revision": null,
            "policy_revision": null,
            "integration_revision": null
        });
        assert!(serde_json::from_value::<AdmittedRouteReceipt>(zero_admitted).is_err());

        // A copied unchecked digest never validates: recomputation fails.
        let mut forged = admitted.clone();
        forged.self_digest =
            fixture_digest("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")?;
        assert_eq!(forged.validate(), Err(ContractError::DigestMismatch));
        // Schema-version substitution fails: the digest binds the version.
        let mut wrong_version = admitted.clone();
        wrong_version.schema_version = "eliot-agent-api/v5".to_owned();
        assert_eq!(
            wrong_version.validate(),
            Err(ContractError::UnknownContractVersion)
        );
        // Selected route and no-route disposition are exclusive.
        let mut contradictory = admitted.clone();
        contradictory.no_route = Some(NoRouteDisposition::AdmissionDenied);
        assert_eq!(
            contradictory.validate(),
            Err(ContractError::InvalidRouteDisposition)
        );
        // Admission authorizes candidate work only, never verification.
        let mut overclaim = admitted.clone();
        overclaim.proof_ceiling = eliot_receipts::ProofCeiling::ScopedVerification;
        overclaim.self_digest = overclaim.compute_digest()?;
        assert_eq!(
            overclaim.validate(),
            Err(ContractError::InsufficientAuthority)
        );
        Ok(())
    }

    #[test]
    fn api_case_09_authority_schema_is_deterministic_numeric_and_object() -> TestResult {
        let first = serde_json::to_value(schemars::schema_for!(AuthorityEnvelope))?;
        let second = serde_json::to_value(schemars::schema_for!(AuthorityEnvelope))?;
        assert_eq!(first, second);
        assert_eq!(first["type"], "object");
        assert_eq!(first["$defs"]["EpochId"]["type"], "object");
        assert_eq!(first["$defs"]["StateFence"]["type"], "object");
        assert_ne!(first["$defs"]["StateFence"]["type"], "string");
        Ok(())
    }

    #[test]
    fn api_case_10_shared_task_artifact_session_are_canonical_imports() -> TestResult {
        fn accepts_task(_: TaskId) {}
        fn accepts_artifact(_: ArtifactId) {}
        fn accepts_session(_: SessionId) {}
        let task = TaskId::new("task-canonical-10")?;
        let artifact = ArtifactId::new("artifact-canonical-10")?;
        let session = SessionId::new("session-canonical-10")?;
        accepts_task(task.clone());
        accepts_artifact(artifact.clone());
        accepts_session(session.clone());
        // Verify they are the foundation types by round-tripping through foundation validation.
        assert_eq!(task.as_str(), "task-canonical-10");
        assert_eq!(artifact.as_str(), "artifact-canonical-10");
        assert_eq!(session.as_str(), "session-canonical-10");
        // Wire is transparent string, not an object wrapper.
        assert_eq!(
            serde_json::to_value(&task)?,
            serde_json::json!("task-canonical-10")
        );
        assert_eq!(
            serde_json::to_value(&artifact)?,
            serde_json::json!("artifact-canonical-10")
        );
        assert_eq!(
            serde_json::to_value(&session)?,
            serde_json::json!("session-canonical-10")
        );
        // Source must import canonical owners and retain no local duplicate wrappers.
        let source = include_str!("lib.rs");
        assert!(source.contains("ArtifactId, ClockReading"));
        assert!(source.contains("EpochId"));
        assert!(source.contains("SessionId, StateFence, TaskId"));
        let dup_task = ["id_type!", "(", "TaskId", ")"].concat();
        let dup_artifact = ["id_type!", "(", "ArtifactId", ")"].concat();
        let dup_session = ["id_type!", "(", "SessionId", ")"].concat();
        assert!(!source.contains(&dup_task));
        assert!(!source.contains(&dup_artifact));
        assert!(!source.contains(&dup_session));
        Ok(())
    }

    #[test]
    fn api_case_11_agent_local_ids_reject_control_and_boundary_cases() -> TestResult {
        // Agent-local identities must reject control characters, matching canonical validation.
        assert!(LaunchRequestId::new("launch\ncontrol").is_err());
        assert!(WorkUnitId::new("unit\x07control").is_err());
        assert!(RouteFingerprintId::new("route\rc").is_err());
        assert!(EventId::new("event\tcontrol").is_err());
        assert!(EventCursor::new("cursor\x1f").is_err());
        // Blank and whitespace-only are still rejected.
        assert!(LaunchRequestId::new("   ").is_err());
        // Canonical WorkLeaseId (re-exported owner) rejects control/blank via validated object wire.
        assert!(
            serde_json::from_value::<WorkLeaseId>(serde_json::json!({
                "namespace": "eliot.governor.work-lease",
                "revision": "v1",
                "value": "lease\x00control"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<WorkLeaseId>(serde_json::json!({
                "namespace": "eliot.governor.work-lease",
                "revision": "v1",
                "value": ""
            }))
            .is_err()
        );
        // Valid values round-trip as canonical object wire.
        let lease = serde_json::from_value::<WorkLeaseId>(serde_json::json!({
            "namespace": "eliot.governor.work-lease",
            "revision": "v1",
            "value": "lease-case-11"
        }))?;
        assert_eq!(
            serde_json::to_value(&lease)?,
            serde_json::json!({
                "namespace": "eliot.governor.work-lease",
                "revision": "v1",
                "value": "lease-case-11"
            })
        );
        assert_eq!(
            serde_json::from_value::<WorkLeaseId>(serde_json::json!({
                "namespace": "eliot.governor.work-lease",
                "revision": "v1",
                "value": "lease-case-11"
            }))?,
            lease
        );
        // Scalar JSON string must not deserialize as canonical WorkLeaseId (fail-closed).
        assert!(serde_json::from_str::<WorkLeaseId>(r#""lease-case-11""#).is_err());
        Ok(())
    }

    #[test]
    fn api_case_12_work_lease_string_wire_is_distinct_from_canonical_object_wire() -> TestResult {
        // The canonical WorkLeaseId is a versioned object wire with namespace/revision/value.
        let canonical_wire = serde_json::json!({
            "namespace": eliot_contracts::WORK_LEASE_NAMESPACE,
            "revision": eliot_contracts::WORK_LEASE_WIRE_REVISION,
            "value": "lease-case-12"
        });
        let canonical = serde_json::from_value::<WorkLeaseId>(canonical_wire.clone())?;
        assert_eq!(serde_json::to_value(&canonical)?, canonical_wire);
        // Same type via the owner path decodes identically (single owner, re-export never redefined).
        let via_owner =
            serde_json::from_value::<eliot_contracts::WorkLeaseId>(canonical_wire.clone())?;
        assert_eq!(canonical, via_owner);
        // A bare string cannot deserialize as the canonical object (fail-closed per
        // WORK_LEASE_LEGACY_WIRE_DISPOSITION).
        assert!(
            serde_json::from_value::<eliot_contracts::WorkLeaseId>(serde_json::json!(
                "lease-case-12"
            ))
            .is_err()
        );
        assert!(serde_json::from_str::<WorkLeaseId>(r#""lease-case-12""#).is_err());
        // Wrong namespace/revision/blank/control/too-long must err.
        assert!(
            serde_json::from_value::<WorkLeaseId>(serde_json::json!({
                "namespace": "wrong.namespace",
                "revision": "v1",
                "value": "lease-case-12"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<WorkLeaseId>(serde_json::json!({
                "namespace": eliot_contracts::WORK_LEASE_NAMESPACE,
                "revision": "v2",
                "value": "lease-case-12"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<WorkLeaseId>(serde_json::json!({
                "namespace": eliot_contracts::WORK_LEASE_NAMESPACE,
                "revision": eliot_contracts::WORK_LEASE_WIRE_REVISION,
                "value": ""
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<WorkLeaseId>(serde_json::json!({
                "namespace": eliot_contracts::WORK_LEASE_NAMESPACE,
                "revision": eliot_contracts::WORK_LEASE_WIRE_REVISION,
                "value": "lease\x00control"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<WorkLeaseId>(serde_json::json!({
                "namespace": eliot_contracts::WORK_LEASE_NAMESPACE,
                "revision": eliot_contracts::WORK_LEASE_WIRE_REVISION,
                "value": " lease-case-12"
            }))
            .is_err()
        );
        let too_long = "a".repeat(eliot_contracts::WORK_LEASE_MAX_VALUE_LENGTH + 1);
        assert!(
            serde_json::from_value::<WorkLeaseId>(serde_json::json!({
                "namespace": eliot_contracts::WORK_LEASE_NAMESPACE,
                "revision": eliot_contracts::WORK_LEASE_WIRE_REVISION,
                "value": too_long
            }))
            .is_err()
        );
        // AuthorityEnvelope using the canonical object lease must still validate with typed StateFence.
        let envelope = AuthorityEnvelope {
            epoch: test_epoch(TEST_LINEAGE_A, 1),
            scope_ref: "scope:test".into(),
            effect_ceiling: ceiling(),
            lease: serde_json::from_value::<WorkLeaseId>(serde_json::json!({
                "namespace": "eliot.governor.work-lease",
                "revision": "v1",
                "value": "lease-case-12"
            }))?,
            state_fence: StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::new(1)?),
            valid_until: "later".into(),
        };
        assert!(envelope.validate().is_ok());
        Ok(())
    }

    #[test]
    fn api_case_13_candidate_result_is_structurally_candidate_only() -> TestResult {
        // New dispositions: CANDIDATE_SUCCEEDED is the strongest positive, no
        // VERIFIED_COMPLETE / COMPLETE / DONE / FINISHED is expressible.
        let dispositions = [
            "CANDIDATE_SUCCEEDED",
            "PARTIAL",
            "BLOCKED",
            "FAILED_VERIFICATION",
            "DEGRADED_NO_PROOF",
            "UNSAFE",
            "CANCELLED_OBSERVED",
            "SUPERSEDED",
            "UNKNOWN_OUTCOME",
        ];
        for name in dispositions {
            let wire = serde_json::json!(name);
            assert!(
                serde_json::from_value::<ResultDisposition>(wire).is_ok(),
                "candidate disposition must decode: {name}"
            );
        }
        for forbidden in [
            "VERIFIED_COMPLETE",
            "verified_complete",
            "COMPLETE",
            "DONE",
            "FINISHED",
            "CANCELLED",
            "UNSAFE_TO_FINISH",
        ] {
            let wire = serde_json::json!(forbidden);
            assert!(
                serde_json::from_value::<ResultDisposition>(wire).is_err(),
                "forbidden disposition must be rejected: {forbidden}"
            );
        }
        // Legacy numeric / untagged forms are rejected because disposition is
        // a string enum with deny_unknown_fields above.
        assert!(serde_json::from_value::<ResultDisposition>(serde_json::json!(0)).is_err());
        assert!(serde_json::from_value::<ResultDisposition>(serde_json::json!(null)).is_err());
        // Provider result must not contain effect_receipts.
        let route = route()?;
        let attempt = AttemptId::new("attempt-case-10")?;
        let lease_id = lease("lease-case-10")?;
        let fence = StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::new(1)?);
        let admission = admitted_fixture(&attempt, &lease_id, &route, &fence)?;
        let binding = observation_binding(&attempt, &lease_id, &route, &fence)?;
        let api = AgentResult {
            attempt_id: AttemptId::new("attempt-case-10")?,
            disposition: ResultDisposition::CandidateSucceeded,
            artifacts: Vec::new(),
            evidence_refs: Vec::new(),
            proposed_effects: Vec::new(),
            unresolved_questions: Vec::new(),
            usage: UsageReceipt {
                input_tokens: None,
                output_tokens: None,
                cost_microunits: None,
                quota: QuotaKnowledge::Unknown,
            },
            actual_route: matched_observation_fixture(
                &attempt, &route, &fence, &admission, &binding,
            )?,
            unknown_reason: None,
        };
        api.validate(&ceiling())?;
        let wire = serde_json::to_value(&api)?;
        assert!(wire.get("effect_receipts").is_none());
        // Legacy wire containing effect_receipts must be rejected.
        let mut legacy = wire.clone();
        legacy["effect_receipts"] = serde_json::json!([]);
        assert!(serde_json::from_value::<AgentResult>(legacy).is_err());
        // Legacy wire containing VERIFIED_COMPLETE must be rejected, not migrated.
        let mut legacy_disp = wire;
        legacy_disp["disposition"] = serde_json::json!("VERIFIED_COMPLETE");
        assert!(serde_json::from_value::<AgentResult>(legacy_disp).is_err());
        // Aliases with different casing are rejected.
        let mut alias = serde_json::to_value(&api)?;
        alias["disposition"] = serde_json::json!("verified_complete");
        assert!(serde_json::from_value::<AgentResult>(alias).is_err());
        Ok(())
    }

    #[test]
    fn api_case_14_candidate_evidence_does_not_raise_proof_ceiling() -> TestResult {
        let route = route()?;
        let attempt = AttemptId::new("attempt-case-11")?;
        let lease_id = lease("lease-case-11")?;
        let fence = StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::new(1)?);
        let admission = admitted_fixture(&attempt, &lease_id, &route, &fence)?;
        let binding = observation_binding(&attempt, &lease_id, &route, &fence)?;
        let mut result = AgentResult {
            attempt_id: AttemptId::new("attempt-case-11")?,
            disposition: ResultDisposition::CandidateSucceeded,
            artifacts: Vec::new(),
            evidence_refs: vec!["evidence-1".into(), "evidence-2".into()],
            proposed_effects: Vec::new(),
            unresolved_questions: Vec::new(),
            usage: UsageReceipt {
                input_tokens: None,
                output_tokens: None,
                cost_microunits: None,
                quota: QuotaKnowledge::Unknown,
            },
            actual_route: matched_observation_fixture(
                &attempt, &route, &fence, &admission, &binding,
            )?,
            unknown_reason: None,
        };
        // Candidate success with nonempty evidence remains candidate-only; it
        // does not validate as a FinishDecision or ProofCeiling beyond
        // CandidateArtifact (checked in coordinator receipt).
        result.validate(&ceiling())?;
        // No disposition can carry completion proof; schema has no completion field.
        let schema = schemars::schema_for!(AgentResult);
        let schema_value = serde_json::to_value(schema)?;
        let schema_str = serde_json::to_string(&schema_value)?;
        assert!(!schema_str.contains("VerifiedComplete"));
        assert!(!schema_str.contains("CompletionProof"));
        assert!(!schema_str.contains("FinishDecision"));
        // Schema properties must not contain authoritative effect_receipts.
        let props = &schema_value["properties"];
        assert!(props.get("effect_receipts").is_none());
        // Even with evidence, validate does not require nonempty for candidate.
        result.evidence_refs.clear();
        result.validate(&ceiling())?;
        Ok(())
    }

    #[test]
    #[allow(clippy::unnecessary_wraps)]
    fn api_case_15_serialized_forgery_is_rejected() -> TestResult {
        // Forged legacy JSON attempting to claim completion. The embedded
        // v5 `actual_route` shape (raw string times, `route_id`, no digests)
        // is itself rejected: old wires never silently upgrade.
        let forged = serde_json::json!({
            "attempt_id": "attempt-case-12",
            "disposition": "VERIFIED_COMPLETE",
            "artifacts": [],
            "evidence_refs": ["forged-evidence"],
            "proposed_effects": [],
            "unresolved_questions": [],
            "usage": {"input_tokens": null, "output_tokens": null, "cost_microunits": null, "quota": "unknown"},
            "actual_route": {
                "requested": route()?,
                "observed": route()?,
                "route_id": "route-case-12",
                "usage": {"input_tokens": null, "output_tokens": null, "cost_microunits": null, "quota": "unknown"},
                "started_at": "2026-08-14T00:00:00Z",
                "terminal_at": null
            },
            "unknown_reason": null
        });
        assert!(serde_json::from_value::<AgentResult>(forged).is_err());
        // Lowercase alias also rejected.
        let forged_lower = serde_json::json!({
            "attempt_id": "attempt-case-12",
            "disposition": "verified_complete",
            "artifacts": [],
            "evidence_refs": [],
            "proposed_effects": [],
            "unresolved_questions": [],
            "usage": {"input_tokens": null, "output_tokens": null, "cost_microunits": null, "quota": "unknown"},
            "actual_route": {
                "requested": route()?,
                "observed": route()?,
                "route_id": "route-case-12",
                "usage": {"input_tokens": null, "output_tokens": null, "cost_microunits": null, "quota": "unknown"},
                "started_at": "2026-08-14T00:00:00Z",
                "terminal_at": null
            },
            "unknown_reason": null
        });
        assert!(serde_json::from_value::<AgentResult>(forged_lower).is_err());
        // Numeric forgery rejected.
        let forged_num = serde_json::json!({
            "attempt_id": "attempt-case-12",
            "disposition": 0,
            "artifacts": [],
            "evidence_refs": [],
            "proposed_effects": [],
            "unresolved_questions": [],
            "usage": {"input_tokens": null, "output_tokens": null, "cost_microunits": null, "quota": "unknown"},
            "actual_route": {
                "requested": route()?,
                "observed": route()?,
                "route_id": "route-case-12",
                "usage": {"input_tokens": null, "output_tokens": null, "cost_microunits": null, "quota": "unknown"},
                "started_at": "2026-08-14T00:00:00Z",
                "terminal_at": null
            },
            "unknown_reason": null
        });
        assert!(serde_json::from_value::<AgentResult>(forged_num).is_err());
        Ok(())
    }

    #[test]
    fn api_case_16_result_binding_triple_mismatch_rejected() -> TestResult {
        // S5 (a)-(b): the physical observation matches the live binding and
        // admission, but the result names a foreign attempt. Shape-only
        // `validate` would accept the observation; `validate_for_binding`
        // must reject the foreign turn with `BindingMismatch`.
        let route = route()?;
        let attempt = AttemptId::new("attempt-s5-16")?;
        let lease_id = lease("lease-s5-16")?;
        let fence = StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::new(1)?);
        let admission = admitted_fixture(&attempt, &lease_id, &route, &fence)?;
        let binding = observation_binding(&attempt, &lease_id, &route, &fence)?;
        let observation =
            matched_observation_fixture(&attempt, &route, &fence, &admission, &binding)?;
        let result = AgentResult {
            attempt_id: AttemptId::new("attempt-s5-16-foreign")?,
            disposition: ResultDisposition::CandidateSucceeded,
            artifacts: Vec::new(),
            evidence_refs: Vec::new(),
            proposed_effects: Vec::new(),
            unresolved_questions: Vec::new(),
            usage: UsageReceipt {
                input_tokens: None,
                output_tokens: None,
                cost_microunits: None,
                quota: QuotaKnowledge::Unknown,
            },
            actual_route: observation,
            unknown_reason: None,
        };
        assert_eq!(
            result.validate_for_binding(&binding, &admission, &ceiling()),
            Err(ContractError::BindingMismatch)
        );
        Ok(())
    }

    #[test]
    fn api_case_17_proposed_effect_attempt_mismatch_rejected() -> TestResult {
        // S5 (d): the result/binding/admission triple agrees, but one
        // proposed effect names a foreign attempt. The ceiling/scope check
        // alone would pass (Observe under scope:test); the per-effect
        // attempt match must reject it.
        let route = route()?;
        let attempt = AttemptId::new("attempt-s5-17")?;
        let lease_id = lease("lease-s5-17")?;
        let fence = StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::new(1)?);
        let admission = admitted_fixture(&attempt, &lease_id, &route, &fence)?;
        let binding = observation_binding(&attempt, &lease_id, &route, &fence)?;
        let observation =
            matched_observation_fixture(&attempt, &route, &fence, &admission, &binding)?;
        let foreign_effect = ProposedEffect {
            effect_id: "effect-s5-17-foreign".into(),
            attempt_id: AttemptId::new("attempt-s5-17-foreign")?,
            kind: EffectKind::Observe,
            scope_ref: "scope:test".into(),
            payload_digest: "payload-1".into(),
            rationale_ref: None,
        };
        // Sanity: the effect itself satisfies the ceiling, so only the
        // attempt linkage can fail.
        foreign_effect.validate_against(&ceiling())?;
        let result = AgentResult {
            attempt_id: attempt.clone(),
            disposition: ResultDisposition::CandidateSucceeded,
            artifacts: Vec::new(),
            evidence_refs: Vec::new(),
            proposed_effects: vec![foreign_effect],
            unresolved_questions: Vec::new(),
            usage: UsageReceipt {
                input_tokens: None,
                output_tokens: None,
                cost_microunits: None,
                quota: QuotaKnowledge::Unknown,
            },
            actual_route: observation,
            unknown_reason: None,
        };
        assert_eq!(
            result.validate_for_binding(&binding, &admission, &ceiling()),
            Err(ContractError::BindingMismatch)
        );
        Ok(())
    }

    #[test]
    fn api_case_18_result_binding_admission_ceiling_accepted() -> TestResult {
        // S5 happy path: exact binding + admission + ceiling, including one
        // ceiling-permitted effect bound to the same attempt.
        let route = route()?;
        let attempt = AttemptId::new("attempt-s5-18")?;
        let lease_id = lease("lease-s5-18")?;
        let fence = StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::new(1)?);
        let admission = admitted_fixture(&attempt, &lease_id, &route, &fence)?;
        let binding = observation_binding(&attempt, &lease_id, &route, &fence)?;
        let observation =
            matched_observation_fixture(&attempt, &route, &fence, &admission, &binding)?;
        let effect = ProposedEffect {
            effect_id: "effect-s5-18-1".into(),
            attempt_id: attempt.clone(),
            kind: EffectKind::Observe,
            scope_ref: "scope:test".into(),
            payload_digest: "payload-1".into(),
            rationale_ref: None,
        };
        let result = AgentResult {
            attempt_id: attempt.clone(),
            disposition: ResultDisposition::CandidateSucceeded,
            artifacts: Vec::new(),
            evidence_refs: Vec::new(),
            proposed_effects: vec![effect],
            unresolved_questions: Vec::new(),
            usage: UsageReceipt {
                input_tokens: None,
                output_tokens: None,
                cost_microunits: None,
                quota: QuotaKnowledge::Unknown,
            },
            actual_route: observation,
            unknown_reason: None,
        };
        assert!(
            result
                .validate_for_binding(&binding, &admission, &ceiling())
                .is_ok()
        );
        Ok(())
    }
}
