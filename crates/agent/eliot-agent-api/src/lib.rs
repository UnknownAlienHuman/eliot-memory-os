//! Provider-neutral contracts for the ELIOT agent bridge.
//!
//! This crate is deliberately a contract-only cell.  It does not start a
//! process, call a provider, own task state, or issue authority.  Coordinator
//! and Governor cells consume these immutable projections and perform the
//! corresponding lifecycle decisions.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_VERSION: &str = "eliot-agent-api/v1";

/// A validated opaque identity used by a contract projection.
macro_rules! id_type {
    ($name:ident) => {
        #[derive(
            Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, JsonSchema, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates an identity, rejecting empty or whitespace-only values.
            pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                if value.trim().is_empty() {
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

id_type!(TaskId);
id_type!(LaunchRequestId);
id_type!(AttemptId);
id_type!(WorkUnitId);
id_type!(SessionId);
id_type!(WorkLeaseId);
id_type!(AuthorityEpoch);
id_type!(RouteFingerprintId);
id_type!(EventId);
id_type!(EventCursor);
id_type!(ArtifactId);

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
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteFingerprint {
    pub host_family: String,
    pub adapter: String,
    pub protocol_transport: String,
    pub runtime_hash: String,
    pub adapter_hash: String,
    pub provider: String,
    pub model: String,
    pub auth_billing: String,
    pub serializer_hash: String,
    pub tool_semantics_hash: String,
    pub reasoning_mode: String,
    pub continuation_behavior: String,
    pub feature_flags_hash: String,
}

impl RouteFingerprint {
    /// Validates that all behavior-bearing identity components are present.
    pub fn validate(&self) -> Result<(), ContractError> {
        let values = [
            ("host_family", &self.host_family),
            ("adapter", &self.adapter),
            ("protocol_transport", &self.protocol_transport),
            ("runtime_hash", &self.runtime_hash),
            ("adapter_hash", &self.adapter_hash),
            ("provider", &self.provider),
            ("model", &self.model),
            ("auth_billing", &self.auth_billing),
            ("serializer_hash", &self.serializer_hash),
            ("tool_semantics_hash", &self.tool_semantics_hash),
            ("reasoning_mode", &self.reasoning_mode),
            ("continuation_behavior", &self.continuation_behavior),
            ("feature_flags_hash", &self.feature_flags_hash),
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
    pub epoch: AuthorityEpoch,
    pub scope_ref: String,
    pub effect_ceiling: EffectCeiling,
    pub lease: WorkLeaseId,
    pub state_fence: String,
    pub valid_until: String,
}

impl AuthorityEnvelope {
    pub fn validate(&self) -> Result<(), ContractError> {
        for (field, value) in [
            ("scope_ref", &self.scope_ref),
            ("state_fence", &self.state_fence),
            ("valid_until", &self.valid_until),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::EmptyField(field));
            }
        }
        if self.effect_ceiling.scope_ref != self.scope_ref {
            return Err(ContractError::InsufficientAuthority);
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
    pub state_fence: String,
}

/// A normalized event from a host/provider adapter.
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

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEventEnvelope {
    pub event_id: EventId,
    pub attempt_id: AttemptId,
    pub sequence: u64,
    pub cursor: EventCursor,
    pub kind: HostEventKind,
    pub route: RouteFingerprint,
    pub raw_payload_digest: String,
    pub normalized_payload: serde_json::Value,
    pub parent_event_id: Option<EventId>,
    pub observed_at: String,
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

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActualRouteReceipt {
    pub requested: RouteFingerprint,
    pub observed: Option<RouteFingerprint>,
    pub route_id: RouteFingerprintId,
    pub usage: UsageReceipt,
    pub started_at: String,
    pub terminal_at: Option<String>,
}

impl ActualRouteReceipt {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.requested.validate()?;
        if let Some(observed) = &self.observed {
            observed.validate()?;
            if observed != &self.requested {
                return Err(ContractError::RouteMismatch);
            }
        }
        if self.started_at.trim().is_empty() {
            return Err(ContractError::EmptyField("started_at"));
        }
        Ok(())
    }
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
        Ok(())
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
    pub authority_epoch: AuthorityEpoch,
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
            || self.authority_epoch != authority.epoch
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

/// Result disposition; provider “completed” is not automatically completion.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResultDisposition {
    VerifiedComplete,
    Partial,
    Blocked,
    FailedVerification,
    DegradedNoProof,
    UnsafeToFinish,
    Cancelled,
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
    pub effect_receipts: Vec<EffectReceipt>,
    pub unresolved_questions: Vec<String>,
    pub usage: UsageReceipt,
    pub actual_route: ActualRouteReceipt,
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
        if self.disposition == ResultDisposition::VerifiedComplete && self.evidence_refs.is_empty()
        {
            return Err(ContractError::EmptyCollection("evidence_refs"));
        }
        Ok(())
    }
}

/// Code-intelligence/route specialization.  It selects a capability only; it
/// is not a scheduler or policy owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRouteDecision {
    pub capability: String,
    pub query_intent: String,
    pub scope_ref: String,
    pub policy_revision: String,
    pub candidates: Vec<RouteFingerprint>,
    pub selected: Option<RouteFingerprint>,
    pub decision: AdmissionDecision,
    pub evidence_refs: Vec<String>,
}

impl CapabilityRouteDecision {
    pub fn validate(&self) -> Result<(), ContractError> {
        for (field, value) in [
            ("capability", &self.capability),
            ("query_intent", &self.query_intent),
            ("scope_ref", &self.scope_ref),
            ("policy_revision", &self.policy_revision),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::EmptyField(field));
            }
        }
        if self.candidates.is_empty() {
            return Err(ContractError::EmptyCollection("candidates"));
        }
        for candidate in &self.candidates {
            candidate.validate()?;
        }
        if let Some(selected) = &self.selected
            && !self.candidates.contains(selected)
        {
            return Err(ContractError::RouteMismatch);
        }
        Ok(())
    }
}

/// Physical provider attempt receipt, kept separate from logical routing.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalModelAttemptReceipt {
    pub attempt_id: AttemptId,
    pub logical_decision_ref: String,
    pub requested_route: RouteFingerprint,
    pub observed_route: Option<RouteFingerprint>,
    pub request_digest: String,
    pub translation_receipt: Option<String>,
    pub started_at: String,
    pub first_byte_at: Option<String>,
    pub first_semantic_at: Option<String>,
    pub terminal_at: Option<String>,
    pub cancellation_disposition: Option<String>,
    pub unknown_outcome: bool,
    pub usage: UsageReceipt,
    pub safe_public_error: Option<String>,
    pub restricted_raw_error_ref: Option<String>,
}

impl PhysicalModelAttemptReceipt {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.requested_route.validate()?;
        if let Some(observed) = &self.observed_route {
            observed.validate()?;
            if observed != &self.requested_route {
                return Err(ContractError::RouteMismatch);
            }
        }
        for (field, value) in [
            ("logical_decision_ref", &self.logical_decision_ref),
            ("request_digest", &self.request_digest),
            ("started_at", &self.started_at),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::EmptyField(field));
            }
        }
        if self.unknown_outcome && self.cancellation_disposition.is_none() {
            return Err(ContractError::MissingUnknownReason);
        }
        Ok(())
    }
}

/// Logical route choice, with no claim that a physical provider call occurred.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingReceipt {
    pub decision_id: String,
    pub requested_route: RouteFingerprint,
    pub selected_route: Option<RouteFingerprint>,
    pub alternatives: Vec<String>,
    pub decision_source: String,
    pub policy_revision: String,
    pub state_fence: String,
    pub pinned_until_boundary: String,
    pub evidence_refs: Vec<String>,
}

impl RoutingReceipt {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.requested_route.validate()?;
        for (field, value) in [
            ("decision_id", &self.decision_id),
            ("decision_source", &self.decision_source),
            ("policy_revision", &self.policy_revision),
            ("state_fence", &self.state_fence),
            ("pinned_until_boundary", &self.pinned_until_boundary),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::EmptyField(field));
            }
        }
        if let Some(route) = &self.selected_route {
            route.validate()?;
        }
        Ok(())
    }
}

/// Stable schema for downstream generators and fixture comparison.
pub fn contract_schema() -> schemars::Schema {
    schemars::schema_for!(AgentLaunchRequest)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn route() -> RouteFingerprint {
        RouteFingerprint {
            host_family: "test-host".into(),
            adapter: "test-adapter".into(),
            protocol_transport: "loopback".into(),
            runtime_hash: "sha256:runtime".into(),
            adapter_hash: "sha256:adapter".into(),
            provider: "provider".into(),
            model: "model".into(),
            auth_billing: "subscription".into(),
            serializer_hash: "sha256:serializer".into(),
            tool_semantics_hash: "sha256:tools".into(),
            reasoning_mode: "visible".into(),
            continuation_behavior: "native_resume".into(),
            feature_flags_hash: "sha256:features".into(),
        }
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

    #[test]
    fn route_identity_is_complete_and_deterministic() -> TestResult {
        let route = route();
        route.validate()?;
        assert_eq!(route.canonical_json()?, route.canonical_json()?);
        Ok(())
    }

    #[test]
    fn malformed_route_is_rejected() {
        let mut route = route();
        route.model.clear();
        assert_eq!(route.validate(), Err(ContractError::EmptyField("model")));
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
        let result = AgentResult {
            attempt_id: AttemptId::new("attempt-1")?,
            disposition: ResultDisposition::UnknownOutcome,
            artifacts: Vec::new(),
            evidence_refs: Vec::new(),
            proposed_effects: Vec::new(),
            effect_receipts: Vec::new(),
            unresolved_questions: Vec::new(),
            usage: UsageReceipt {
                input_tokens: None,
                output_tokens: None,
                cost_microunits: None,
                quota: QuotaKnowledge::Unknown,
            },
            actual_route: ActualRouteReceipt {
                requested: route(),
                observed: None,
                route_id: RouteFingerprintId::new("route-1")?,
                usage: UsageReceipt {
                    input_tokens: None,
                    output_tokens: None,
                    cost_microunits: None,
                    quota: QuotaKnowledge::Unknown,
                },
                started_at: "2026-08-14T00:00:00Z".into(),
                terminal_at: None,
            },
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
            lease: WorkLeaseId::new("lease-1")?,
            state: AttemptState::Completed,
            continuity: ContinuityKind::Fresh,
            route: route(),
            budget: budget(),
            authority: AuthorityEnvelope {
                epoch: AuthorityEpoch::new("epoch-1")?,
                scope_ref: "scope:test".into(),
                effect_ceiling: ceiling(),
                lease: WorkLeaseId::new("lease-1")?,
                state_fence: "fence-1".into(),
                valid_until: "2026-08-14T00:00:00Z".into(),
            },
            cancellation: CancellationState::NotRequested,
            event_cursor: None,
            continuation: None,
        };
        assert!(attempt.transition(AttemptState::Running).is_err());
        Ok(())
    }
}
