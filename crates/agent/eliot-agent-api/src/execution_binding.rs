//! Provider-neutral execution binding for one admitted agent attempt.
//!
//! Implements the S1 contract slice of issue #361 under owner freeze
//! `A01_PROVIDER_EXECUTION_BINDING_V1`: exactly one execution unit per agent
//! attempt; a Codex execution unit is the exact turn ID; a new turn (including
//! resume/fork) is a new agent attempt with continuity lineage; a same-turn
//! steer keeps the same binding; a thread-level event is session observation
//! only and never carries attempt authority.
//!
//! Field owner: `eliot-agent-api` (this crate). Lifecycle owner:
//! `eliot-agent-coordinator`; this module performs no lifecycle, admission,
//! storage, verification, or provider execution. In particular there is no
//! `bind_provider_execution` here (S2 owns it) and no provider SDK, process
//! handle, credential, or session-name/login/catalogue bridge.
//!
//! Canonical identities are reused, never redefined:
//! `eliot-agent-contracts::AgentAttemptId` for attempt identity and
//! `eliot-contracts::{StateFence, ResourceGeneration}` for fencing (see shards
//! I10-15 agent execution fabric, I07-15 route continuation and transfer,
//! I07-23 raw and normalized host events). A thread locator is a locator only,
//! never authority: a missing, unknown, or mismatched turn quarantines
//! (`Quarantined` / `UnknownOutcome`, owned elsewhere), never convenience
//! attribution. V1 admits no open or mutable turn set.
//!
//! Wire revision: `eliot-agent-api/v5` (see `crate::CONTRACT_VERSION`). A
//! thread-only wire without binding/lineage still deserializes (additive
//! `None`) but is rejected for attribution at validation; it is never
//! silently accepted as execution-unit evidence.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{AgentAttempt, AgentAttemptId, ContractError, EventCursor, RouteFingerprint};
use eliot_contracts::{RequestId, ResourceGeneration, SessionId, StateFence, WorkLeaseId};

/// Rejects blank, whitespace-only, or control-bearing opaque binding strings.
fn validate_opaque(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ContractError::EmptyField(field));
    }
    Ok(())
}

/// Validates an exact lowercase SHA-256 hex digest, following the repository
/// digest convention (`crates/agent/eliot-agent-api` digest fields are opaque
/// hex strings; the shared shape is lowercase hex, see
/// `eliot-contracts::sha256_hex`). A malformed digest is binding-identity
/// evidence that cannot match, so it fails as [`ContractError::BindingMismatch`].
fn validate_sha256_hex(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        return Err(ContractError::EmptyField(field));
    }
    let well_formed = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if well_formed {
        Ok(())
    } else {
        Err(ContractError::BindingMismatch)
    }
}

/// One provider execution unit bound to exactly one agent attempt.
///
/// The pair is namespaced and opaque: `namespace` scopes the unit family
/// (kept agent-local with an explicit namespace, never a second shared
/// identity) and `unit_id` is the provider's exact unit identity. The Codex
/// adapter (S3) records the exact turn ID here; this neutral contract never
/// interprets provider namespaces.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionUnit {
    pub namespace: String,
    pub unit_id: String,
}

impl ExecutionUnit {
    /// Constructs an execution unit, rejecting blank or control-bearing parts.
    pub fn new(
        namespace: impl Into<String>,
        unit_id: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let unit = Self {
            namespace: namespace.into(),
            unit_id: unit_id.into(),
        };
        unit.validate()?;
        Ok(unit)
    }

    /// Validates the namespaced unit identity without consulting any context.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_opaque(&self.namespace, "execution_unit.namespace")?;
        validate_opaque(&self.unit_id, "execution_unit.unit_id")
    }
}

/// Opaque native session locator (for example a provider thread ID).
///
/// This is a locator only: it never proves attempt identity, authority, or
/// attribution. It carries no credential and no session-name/login/catalogue
/// bridge.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionLocator {
    pub locator: String,
}

impl NativeSessionLocator {
    /// Constructs a locator, rejecting blank or control-bearing values.
    pub fn new(locator: impl Into<String>) -> Result<Self, ContractError> {
        let value = Self {
            locator: locator.into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates the locator without consulting any context.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_opaque(&self.locator, "native_session.locator")
    }
}

/// Provider-native session attachment for a binding.
///
/// `Native` carries the provider locator (Codex records the thread ID here).
/// `Sessionless` is representable only for providers with no native session
/// notion. Whether a thread is required is provider-specific (S3 adapter rule);
/// this contract never synthesizes `Sessionless` for a missing thread: a
/// missing required thread is a validation error at the adapter boundary, not
/// a silent sessionless binding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum NativeSession {
    Native(NativeSessionLocator),
    Sessionless,
}

impl NativeSession {
    /// Validates the session shape without consulting any context.
    pub fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Native(locator) => locator.validate(),
            Self::Sessionless => Ok(()),
        }
    }
}

/// Exact provider-execution binding for one admitted agent attempt (C361 S1).
///
/// Cardinality is exactly one execution unit per agent attempt: a replay or
/// same-turn steer correlates to this same binding, while a new turn
/// (including resume/fork) is a new agent attempt with continuity lineage and
/// never validates against this binding. `provider_scope_ref` is the opaque
/// authenticated scope the provider executed under; it carries no credential.
/// `start_request_id` / `start_request_sha256` pin the exact launch request
/// that started this execution unit.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderExecutionBinding {
    pub attempt_id: AgentAttemptId,
    pub lease_id: WorkLeaseId,
    pub state_fence: StateFence,
    pub runtime_generation: ResourceGeneration,
    pub route: RouteFingerprint,
    pub session_id: Option<SessionId>,
    pub provider_scope_ref: String,
    pub native_session: NativeSession,
    pub execution_unit: ExecutionUnit,
    pub start_request_id: RequestId,
    pub start_request_sha256: String,
}

impl ProviderExecutionBinding {
    /// Validates binding-internal shape only: route, fence, scope, session,
    /// unit, request identity, and digest form. No admission context is
    /// consulted; use [`validate_execution_binding`] or
    /// [`ProviderExecutionBinding::validate_against_attempt`] for
    /// attempt-context agreement.
    pub fn validate_internal(&self) -> Result<(), ContractError> {
        self.route.validate()?;
        self.state_fence
            .validate()
            .map_err(|_| ContractError::InvalidStateFence)?;
        validate_opaque(&self.provider_scope_ref, "provider_scope_ref")?;
        self.native_session.validate()?;
        self.execution_unit.validate()?;
        validate_sha256_hex(&self.start_request_sha256, "start_request_sha256")
    }

    /// Validates this binding against the admitted attempt's own identity
    /// fields: exact attempt-ID equality, exact typed lease equality, exact
    /// admitted-route identity, and session taken only from the admitted
    /// `Option<SessionId>`.
    ///
    /// Fence and generation freshness are not checked here: the attempt
    /// carries no current runtime context. Full admission-context validation
    /// (complete fence equality, exact runtime-generation equality) is
    /// [`validate_execution_binding`].
    pub fn validate_against_attempt(&self, admitted: &AgentAttempt) -> Result<(), ContractError> {
        self.validate_internal()?;
        if self.attempt_id != admitted.id
            || self.lease_id != admitted.lease
            || self.route != admitted.route
            || self.session_id != admitted.session
        {
            return Err(ContractError::BindingMismatch);
        }
        Ok(())
    }
}

/// Thread-level session observation: locator only, never attempt authority.
///
/// A thread-level event (for example a Codex thread event) observes session
/// continuity but cannot attribute output to an agent attempt. There is no
/// conversion from this shape to [`ProviderExecutionBinding`]: a missing,
/// unknown, or mismatched turn quarantines instead of attributing.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionObservation {
    pub session_id: Option<SessionId>,
    pub native: NativeSession,
}

impl SessionObservation {
    /// Validates the observation shape. Shape validity never grants attempt
    /// authority; see [`ProviderObservationLineage::attributable_binding`].
    pub fn validate(&self) -> Result<(), ContractError> {
        self.native.validate()
    }
}

/// Execution-unit observation: an exact binding plus its event cursor.
///
/// `cursor`/`sequence` order observations inside the bound execution unit;
/// `sequence` follows the [`crate::HostEventEnvelope`] convention and must be
/// nonzero. The cursor never creates a binding: it correlates to the binding
/// carried here.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionUnitObservation {
    pub binding: ProviderExecutionBinding,
    pub cursor: EventCursor,
    pub sequence: u64,
}

impl ExecutionUnitObservation {
    /// Validates binding shape, cursor presence, and nonzero sequence without
    /// consulting admission context.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.binding.validate_internal()?;
        validate_opaque(self.cursor.as_str(), "cursor")?;
        if self.sequence == 0 {
            return Err(ContractError::ZeroLimit { field: "sequence" });
        }
        Ok(())
    }
}

/// Provenance lineage for one provider observation.
///
/// A new turn (including resume/fork) is a new agent attempt whose lineage
/// records continuity with its predecessor; a same-turn steer keeps the same
/// binding. Only [`ProviderObservationLineage::ExecutionUnitObservation`]
/// carries attributable execution-unit evidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub enum ProviderObservationLineage {
    SessionObservation(SessionObservation),
    ExecutionUnitObservation(ExecutionUnitObservation),
}

impl ProviderObservationLineage {
    /// Returns the attributable binding, failing closed for session-only
    /// observations: a [`ProviderObservationLineage::SessionObservation`]
    /// carries no attempt authority and can never validate as an
    /// execution-unit observation.
    pub fn attributable_binding(&self) -> Result<&ProviderExecutionBinding, ContractError> {
        match self {
            Self::SessionObservation(_) => Err(ContractError::BindingMismatch),
            Self::ExecutionUnitObservation(observation) => Ok(&observation.binding),
        }
    }
}

/// Validates a presented binding against the admitted attempt and the current
/// runtime context (C361 S1, freeze `A01_PROVIDER_EXECUTION_BINDING_V1`).
///
/// Enforced, in order:
/// - binding-internal shape;
/// - exact attempt-ID equality (typed, never text);
/// - exact typed lease equality;
/// - complete state-fence equality with `current_fence` — field-by-field
///   `==`, never [`StateFence::is_compatible_with`], which is insufficient
///   because it wildcards absent revisions (a compatible-but-unequal fence
///   still fails closed here);
/// - exact runtime-generation equality by typed `==`; no numeric casts, no
///   process-generation bridging, no comparison against the fence generation;
/// - exact admitted-route identity (`admitted.route`); observed drift is
///   preserved separately by the caller and never synthesized as
///   `observed = requested`;
/// - session taken only from the admitted `Option<SessionId>`: a thread
///   cannot create a session, so an admitted `None` with a bound `Some`
///   fails, as does any mismatch;
/// - cardinality against the attempt's stored binding: when the admitted
///   attempt already carries a `provider_binding`, a presented binding for a
///   different execution unit is a rebind to a new turn and fails closed. A
///   new turn (including resume/fork) is a new agent attempt with continuity
///   lineage, never a silent rebind; a same-turn steer keeps the same
///   binding and passes.
///
/// The attempt's stored `provider_binding` (if any) is not consulted: replay
/// and rebind policy is lifecycle owned by `eliot-agent-coordinator` (S2).
/// Admission freshness of `admitted.authority.state_fence` against
/// `current_fence` is likewise lifecycle, not binding identity.
pub fn validate_execution_binding(
    binding: &ProviderExecutionBinding,
    admitted: &AgentAttempt,
    current_fence: &StateFence,
    runtime_generation: ResourceGeneration,
) -> Result<(), ContractError> {
    binding.validate_against_attempt(admitted)?;
    if binding.state_fence != *current_fence {
        return Err(ContractError::BindingMismatch);
    }
    if binding.runtime_generation != runtime_generation {
        return Err(ContractError::BindingMismatch);
    }
    if let Some(stored) = &admitted.provider_binding
        && stored.execution_unit != binding.execution_unit
    {
        return Err(ContractError::BindingMismatch);
    }
    Ok(())
}
